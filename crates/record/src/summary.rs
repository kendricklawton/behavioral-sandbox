//! The **model-legible projection** of the per-run [`RunRecord`]: a compact, semantically-labelled
//! summary shaped to feed back into an agent's observe-then-act loop.
//!
//! The *third face* of the one record, alongside the human trail and the full machine JSON. A **pure
//! view** with no new observation and no new machinery, so it adds a *reader* of the host-observed
//! record and never a new *authority*.
//!
//! - **How it is compact.** It drops the forensic detail (per-flow counters, per-syscall `comm`/`hits`,
//!   the transient `memory.current`, the `cpu.stat` cross-check) and keeps the decision-relevant signal:
//!   distinct destinations reached, destinations denied, the resource envelope, a bounded syscall sample,
//!   and any coverage gap. "Compact" is a **measured number**, not a claim: a size test pins the
//!   projection well under the full record.
//! - **Vocabulary is guest-centric.** The record names traffic from the *tap's* view, so the summary
//!   relabels to the guest's (`sent`/`recv`), because that is how an agent reasons about its own code.
//!   The syscall counts stay labelled `host_syscalls`, since they are the **VMM's** host-boundary
//!   footprint and not the guest's in-guest file IO.
//! - **Byte-stable**, for the same reasons as [`RunRecord::to_json`]: a fixed key order, integer
//!   nanoseconds and bytes, and every array either builder-sorted or freshly sorted here.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::Syscall;
use crate::json::{
    Position, clamped_ns, field, field_opt_u64, json_str, proto_name, rule_port, rule_proto,
    syscall_name,
};
use crate::record::{AxisGap, NetSection, NotableSyscall, RunRecord};

/// The version of the record-summary JSON schema. Versioned independently of the full record's
/// [`AUDIT_SCHEMA_VERSION`](crate::AUDIT_SCHEMA_VERSION) and the CLI run-result schema, since this is a
/// fourth surface with its own compatibility clock. Additive within a version.
pub const SUMMARY_SCHEMA_VERSION: u32 = 1;

/// The projection's own cap on notable host syscalls, tighter than the record's
/// [`MAX_NOTABLE`](crate::MAX_NOTABLE), because the summary is a context-window artifact rather than a
/// forensic one. Past it the projection sets `truncated`, so "there was more" is never silent.
const SUMMARY_NOTABLE_CAP: usize = 16;

impl RunRecord {
    /// Renders this record as the compact, model-legible **summary**: one line of deterministic JSON
    /// carrying what the run reached, what egress was denied, its resource envelope, and any coverage gap.
    /// The leading `schema` field is [`SUMMARY_SCHEMA_VERSION`].
    #[must_use]
    pub fn to_summary_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');

        // schema, first, so a consumer reads it before anything else.
        field(&mut out, "schema", SUMMARY_SCHEMA_VERSION, Position::First);

        // timing, the two durations the caller supplied, verbatim ns (no lossy rounding).
        out.push_str(",\"timing\":{");
        field(
            &mut out,
            "boot_ns",
            clamped_ns(self.timing.boot),
            Position::First,
        );
        field(
            &mut out,
            "exec_ns",
            clamped_ns(self.timing.exec_wall),
            Position::Subsequent,
        );
        out.push('}');

        // network: reached against denied, plus the guest-view byte rollup. `null` when the sandbox had
        // no NIC, the distinction the full record draws.
        out.push_str(",\"network\":");
        match &self.network {
            Some(net) => net_summary(&mut out, net),
            None => out.push_str("null"),
        }

        // host_syscalls, the VMM's host-boundary footprint, counts + a bounded notable sample.
        out.push_str(",\"host_syscalls\":");
        syscalls_summary(&mut out, self);

        // resources: eBPF CPU, peak memory, IO bytes; the transient and cross-check fields are dropped.
        out.push_str(",\"resources\":{");
        field(
            &mut out,
            "cpu_ns",
            clamped_ns(self.resources.cpu_time),
            Position::First,
        );
        field_opt_u64(
            &mut out,
            "mem_peak_bytes",
            self.resources.cgroup.memory_peak,
            Position::Subsequent,
        );
        field_opt_u64(
            &mut out,
            "io_read_bytes",
            self.resources.cgroup.io_rbytes,
            Position::Subsequent,
        );
        field_opt_u64(
            &mut out,
            "io_write_bytes",
            self.resources.cgroup.io_wbytes,
            Position::Subsequent,
        );
        out.push('}');

        // gaps, flattened to "axis: reason" strings in the record's own deterministic order.
        out.push_str(",\"gaps\":[");
        for (i, gap) in self.coverage.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            json_str(&mut out, &gap_line(gap));
        }
        out.push(']');

        out.push('}');
        out
    }
}

/// The network summary: `reached` (distinct destinations the guest actually got bytes to, flows
/// collapsed to their destination triple, minus any that were denied, sorted), `denied` (blocked
/// destinations, already dst-aggregated and sorted by the builder), and the guest-view byte rollup.
fn net_summary(out: &mut String, net: &NetSection) {
    // The tap counts a flow *before* the egress verdict runs, so a fully-denied endpoint still appears
    // among the flow destinations. Subtract the denied triples so `reached` means the guest actually got
    // bytes out, not merely attempted, or a supervising agent reads a blocked exfil endpoint as reached
    // (those endpoints still appear in `denied` below). Subtracting the whole triple is right only while
    // a denied endpoint cannot also have gotten bytes out, which holds because the policy is armed before
    // the tap goes live; a mid-session policy change would make a triple both, reported here as zero reach.
    let denied: BTreeSet<(u32, u16, u8)> = net
        .denials
        .iter()
        .map(|d| (d.dst_addr, d.dst_port, d.proto))
        .collect();
    // Collapse flows to distinct destinations (an agent cares which endpoint it reached, not the source
    // port); the BTreeSet dedups and yields them in total (dst, port, proto) order.
    let dests: BTreeSet<(u32, u16, u8)> = net
        .flows
        .iter()
        .map(|f| (f.key.dst_addr, f.key.dst_port, f.key.proto))
        .filter(|triple| !denied.contains(triple))
        .collect();
    // The IPv6 half (dual-stack), same reached-minus-denied logic keyed on the v6 destination.
    let denied6: BTreeSet<([u8; 16], u16, u8)> = net
        .denials6
        .iter()
        .map(|d| (d.dst_addr, d.dst_port, d.proto))
        .collect();
    let dests6: BTreeSet<([u8; 16], u16, u8)> = net
        .flows6
        .iter()
        .map(|f| (f.key.dst_addr, f.key.dst_port, f.key.proto))
        .filter(|triple| !denied6.contains(triple))
        .collect();
    out.push_str("{\"reached\":[");
    let mut wrote = false;
    for &(addr, port, proto) in &dests {
        if wrote {
            out.push(',');
        }
        endpoint(out, addr, port, proto);
        wrote = true;
    }
    for &(addr, port, proto) in &dests6 {
        if wrote {
            out.push(',');
        }
        endpoint6(out, addr, port, proto);
        wrote = true;
    }
    out.push_str("],\"denied\":[");
    let mut wrote = false;
    for d in &net.denials {
        if wrote {
            out.push(',');
        }
        endpoint(out, d.dst_addr, d.dst_port, d.proto);
        wrote = true;
    }
    for d in &net.denials6 {
        if wrote {
            out.push(',');
        }
        endpoint6(out, d.dst_addr, d.dst_port, d.proto);
        wrote = true;
    }
    out.push(']');
    // Guest-view bytes: the record's tap-view `ingress` is what the guest sent, `egress` what it received.
    field(
        out,
        "sent_bytes",
        net.totals.ingress_bytes,
        Position::Subsequent,
    );
    field(
        out,
        "recv_bytes",
        net.totals.egress_bytes,
        Position::Subsequent,
    );
    // A `true` here says the kernel's flow/denial tables saturated, so `reached`/`denied` are not
    // exhaustive; the counts ride the full record.
    out.push_str(",\"truncated\":");
    out.push_str(if net.truncated() { "true" } else { "false" });
    // What the sandbox *may* reach, beside what it did: `reached`/`denied` are backward-looking, so
    // `allowed` + `routed` let an agent tell "this endpoint failed, retrying is pointless" from "I never
    // tried it". All three are `null` when the posture could not be read, not the same claim as an empty
    // allow-list.
    match &net.posture {
        Some(p) => {
            out.push_str(",\"allowed\":[");
            let mut wrote = false;
            for rule in &p.allowed {
                if wrote {
                    out.push(',');
                }
                let b = rule.addr.to_be_bytes();
                let _ = write!(
                    out,
                    "\"{}.{}.{}.{}/{}:",
                    b[0], b[1], b[2], b[3], rule.prefix_len
                );
                rule_port_proto(out, rule.port, rule.proto);
                wrote = true;
            }
            for rule in &p.allowed6 {
                if wrote {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "\"[{}]/{}:",
                    std::net::Ipv6Addr::from(rule.addr),
                    rule.prefix_len
                );
                rule_port_proto(out, rule.port, rule.proto);
                wrote = true;
            }
            out.push_str("],\"routed\":");
            out.push_str(if p.gateway.is_some() { "true" } else { "false" });
            out.push_str(",\"enforcing\":");
            out.push_str(if p.enforcing { "true" } else { "false" });
        }
        None => out.push_str(",\"allowed\":null,\"routed\":null,\"enforcing\":null"),
    }
    out.push('}');
}

/// The `port/proto` tail of a summary allow-rule, closing the string. A wildcard renders as `*` so
/// it reads as one rather than as port zero / protocol zero.
fn rule_port_proto(out: &mut String, port: u16, proto: u8) {
    match rule_port(port) {
        Some(p) => {
            let _ = write!(out, "{p}");
        }
        None => out.push('*'),
    }
    out.push('/');
    match rule_proto(proto) {
        Some(p) => proto_name(out, p),
        None => out.push('*'),
    }
    out.push('"');
}

/// The host-syscall summary: the by-kind counts, a bounded `notable` sample as `"kind detail"` strings
/// with the forensic `comm`/`hits` dropped, and one `truncated` flag that is true if *either* the
/// record's own cap overflowed *or* this projection's tighter cap dropped entries. Which entries the
/// cap keeps is [`notable_sample`]'s.
fn syscalls_summary(out: &mut String, record: &RunRecord) {
    let s = &record.host_syscalls;
    out.push('{');
    field(out, "execve", s.by_kind.execve, Position::First);
    field(out, "openat", s.by_kind.openat, Position::Subsequent);
    field(out, "connect", s.by_kind.connect, Position::Subsequent);
    out.push_str(",\"notable\":[");
    for (i, &idx) in notable_sample(&s.notable, SUMMARY_NOTABLE_CAP)
        .iter()
        .enumerate()
    {
        let n = &s.notable[idx];
        if i > 0 {
            out.push(',');
        }
        // "kind detail" as one escaped string, build it, then json_str (detail may hold metacharacters).
        let mut line = String::new();
        syscall_name(&mut line, n.kind);
        line.push(' ');
        line.push_str(&n.detail);
        // No field to carry the flag, so it goes in the text: a reader skimming paths must not take a
        // prefix for the whole path. A guest naming a file `[truncated]` only over-states doubt, and the
        // JSON record carries the machine-readable flag beside it.
        if n.truncated {
            line.push_str(" [truncated]");
        }
        json_str(out, &line);
    }
    out.push(']');
    let truncated = s.notable_truncated || s.notable.len() > SUMMARY_NOTABLE_CAP;
    let _ = write!(out, ",\"truncated\":{truncated}");
    out.push('}');
}

/// Which entries of the record's `notable` this projection keeps, as indices into it, ascending.
///
/// A round-robin across kinds rather than a prefix: the record sorts `notable` by [`Syscall`]
/// discriminant, so a first-`cap` prefix would drop whole kinds from the tail, and the last-sorting kind
/// is `connect`, the one naming an outbound destination. Each kind present takes its turn instead.
/// Deterministic: the runs come out in the record's order and the result is re-sorted into it.
fn notable_sample(notable: &[NotableSyscall], cap: usize) -> Vec<usize> {
    if notable.len() <= cap {
        return (0..notable.len()).collect();
    }
    let mut runs: Vec<(Syscall, Vec<usize>)> = Vec::new();
    for (i, n) in notable.iter().enumerate() {
        match runs.last_mut() {
            Some((kind, run)) if *kind == n.kind => run.push(i),
            _ => runs.push((n.kind, vec![i])),
        }
    }

    let mut keep = Vec::with_capacity(cap);
    for round in 0.. {
        let mut dealt = false;
        for (_, run) in &runs {
            let Some(&i) = run.get(round) else { continue };
            keep.push(i);
            dealt = true;
            if keep.len() == cap {
                break;
            }
        }
        // Every run is exhausted, which the length check above already rules out, or the cap is met.
        if !dealt || keep.len() == cap {
            break;
        }
    }
    keep.sort_unstable();
    keep
}

/// One coverage gap as `"axis: reason"`, the flat, model-legible form of an [`AxisGap`].
fn gap_line(gap: &AxisGap) -> String {
    format!("{}: {}", gap.axis(), gap.reason())
}

/// A destination as one compact JSON string, `"1.1.1.1:443/tcp"`, the dotted quad, the L4 port, and
/// the protocol name (via the shared [`proto_name`]).
fn endpoint(out: &mut String, addr: u32, port: u16, proto: u8) {
    let b = addr.to_be_bytes();
    let _ = write!(out, "\"{}.{}.{}.{}:{}/", b[0], b[1], b[2], b[3], port);
    proto_name(out, proto);
    out.push('"');
}

/// The v6 twin of [`endpoint`]: `"[v6]:port/proto"`.
fn endpoint6(out: &mut String, addr: [u8; 16], port: u16, proto: u8) {
    let _ = write!(out, "\"[{}]:{}/", std::net::Ipv6Addr::from(addr), port);
    proto_name(out, proto);
    out.push('"');
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bsx_probes_common::{IPPROTO_TCP, IPPROTO_UDP, SyscallEvent};

    use super::SUMMARY_NOTABLE_CAP;
    use crate::record::{NetSection, RecordSubject, RunRecord, SyscallFootprint, Timing};
    use crate::testutil::{ev, flow, sample};
    use crate::{AxisGap, NetStats, ResourceSummary};

    #[test]
    fn a_path_cut_at_the_cap_is_marked_in_the_summary() {
        // The summary is the projection a person skims, and it has no field to carry a flag, so the
        // marker rides in the text. A prefix shown bare reads as the whole path.
        let long = vec![b'a'; bsx_probes_common::DETAIL_CAP - 1];
        let mut record = sample(vec![]);
        record.host_syscalls = SyscallFootprint::from_events(0x42, &[ev(1, 0x42, &long, "sh")]);
        let json = record.to_summary_json();
        assert!(
            json.contains("[truncated]"),
            "a cut path must be marked where a person reads it: {json}"
        );
    }

    /// The record's `notable` is a `[u8; 8]` sockaddr for a connect; this is the one the summary
    /// renders as `8.8.8.8:53`.
    const CONNECT_8888_53: [u8; 8] = [2, 0, 0, 53, 8, 8, 8, 8];

    #[test]
    fn a_lone_connect_survives_a_notable_list_full_of_opens() {
        // The record sorts `notable` by syscall discriminant, and connect sorts last, so a prefix of
        // 16 drops the one entry naming an outbound destination while keeping 16 interchangeable
        // paths. The summary exists to carry that destination.
        let mut events: Vec<SyscallEvent> = (0..20u32)
            .map(|i| ev(1, 0x42, format!("/tmp/file-{i:03}").as_bytes(), "sh"))
            .collect();
        events.push(ev(2, 0x42, &CONNECT_8888_53, "sh"));

        let mut record = sample(vec![]);
        record.host_syscalls = SyscallFootprint::from_events(0x42, &events);
        let json = record.to_summary_json();

        assert!(
            json.contains("connect 8.8.8.8:53"),
            "the destination must be in the sample, not only in the counts: {json}"
        );
        assert!(
            json.contains("\"truncated\":true}"),
            "and the reader is still told the list is partial: {json}"
        );
        assert_eq!(
            json.matches("openat /tmp/file-").count(),
            SUMMARY_NOTABLE_CAP - 1,
            "connect takes one slot, not a share proportional to nothing: {json}"
        );
    }

    #[test]
    fn every_kind_present_keeps_a_share_of_the_notable_sample() {
        // Round-robin, so the cap is spent across the kinds rather than down the sort order. With
        // all three oversubscribed the 16 slots split 6/5/5: the first kind gets the odd one because
        // the deal starts there, which is deterministic rather than fair-by-accident.
        let mut events: Vec<SyscallEvent> = Vec::new();
        for i in 0..10u32 {
            events.push(ev(0, 0x42, format!("/bin/prog-{i:03}").as_bytes(), "sh"));
            events.push(ev(1, 0x42, format!("/tmp/file-{i:03}").as_bytes(), "sh"));
            let mut addr = CONNECT_8888_53;
            addr[3] = i as u8; // a distinct destination port per event
            events.push(ev(2, 0x42, &addr, "sh"));
        }
        let mut record = sample(vec![]);
        record.host_syscalls = SyscallFootprint::from_events(0x42, &events);
        let json = record.to_summary_json();

        let (execve, openat, connect) = (
            json.matches("execve /bin/prog-").count(),
            json.matches("openat /tmp/file-").count(),
            json.matches("connect 8.8.8.8:").count(),
        );
        assert_eq!(
            (execve, openat, connect),
            (6, 5, 5),
            "16 slots dealt across three kinds: {json}"
        );
    }

    #[test]
    fn the_notable_sample_stays_in_the_records_own_order() {
        // Which entries survive changes; the order they are listed in does not. A reader comparing
        // the summary against the full record should not have to reconcile two orders.
        let mut events: Vec<SyscallEvent> = (0..20u32)
            .map(|i| ev(1, 0x42, format!("/tmp/file-{i:03}").as_bytes(), "sh"))
            .collect();
        events.push(ev(0, 0x42, b"/bin/sh", "sh"));
        events.push(ev(2, 0x42, &CONNECT_8888_53, "sh"));

        let mut record = sample(vec![]);
        record.host_syscalls = SyscallFootprint::from_events(0x42, &events);
        let json = record.to_summary_json();

        // Every entry's kind, in the order rendered, not just each kind's first appearance: the
        // round-robin deals them interleaved, so only the whole sequence tells the two apart.
        let v: serde_json::Value = serde_json::from_str(&json).expect("summary parses");
        let kinds: Vec<String> = v["host_syscalls"]["notable"]
            .as_array()
            .expect("notable is an array")
            .iter()
            .filter_map(|e| e.as_str())
            .filter_map(|line| line.split(' ').next().map(str::to_string))
            .collect();
        assert_eq!(kinds.len(), SUMMARY_NOTABLE_CAP, "a full sample: {json}");

        let rank = |k: &str| ["execve", "openat", "connect"].iter().position(|x| *x == k);
        assert!(
            kinds.windows(2).all(|w| rank(&w[0]) <= rank(&w[1])),
            "kinds run in discriminant order, as they do in the record: {kinds:?}"
        );
    }

    #[test]
    fn summary_is_the_expected_golden_bytes() {
        let record = sample(vec![
            flow([10, 200, 0, 2], 40000, [1, 1, 1, 1], 53, IPPROTO_UDP),
            flow([10, 200, 0, 2], 40001, [8, 8, 8, 8], 443, IPPROTO_TCP),
        ]);
        let json = record.to_summary_json();
        let expected = concat!(
            "{\"schema\":1,\"timing\":{\"boot_ns\":120000000,\"exec_ns\":42000000}",
            ",\"network\":{\"reached\":[\"1.1.1.1:53/udp\",\"8.8.8.8:443/tcp\"],",
            "\"denied\":[\"9.9.9.9:443/tcp\"],\"sent_bytes\":120,\"recv_bytes\":200,",
            "\"truncated\":false,\"allowed\":null,\"routed\":null,\"enforcing\":null}",
            ",\"host_syscalls\":{\"execve\":1,\"openat\":2,\"connect\":0,",
            "\"notable\":[\"execve /bin/sh\",\"openat /etc/hosts\"],\"truncated\":false}",
            ",\"resources\":{\"cpu_ns\":5000,\"mem_peak_bytes\":4096,\"io_read_bytes\":null,",
            "\"io_write_bytes\":512}",
            ",\"gaps\":[\"cpu: meter lock poisoned\"]}",
        );
        assert_eq!(json, expected);
    }

    /// The projection is hand-rolled like the record, and its golden is re-blessed the same way, so
    /// it needs the same guard a golden cannot give: a parser's verdict. See
    /// `the_rendered_record_parses_as_json` for the reasoning.
    #[test]
    fn the_rendered_summary_parses_as_json() {
        use crate::record::{EgressPosture, RecordSubject};
        use bsx_probes_common::{PolicyRule, PolicyRule6};

        let hostile = "q\"uote \\slash \u{1}ctl \n nl";
        let mut record = sample(vec![flow(
            [10, 200, 0, 2],
            40000,
            [8, 8, 8, 8],
            443,
            IPPROTO_TCP,
        )]);
        record.subject = RecordSubject::new(hostile.into(), 1);
        record.host_syscalls =
            SyscallFootprint::from_events(0x42, &[ev(1, 0x42, hostile.as_bytes(), "sh")]);
        record.coverage = vec![AxisGap::HostSyscalls(hostile.into())];
        // Posture on, so the `allowed`/`routed`/`enforcing` arm renders too rather than the nulls.
        record.network = record.network.map(|n| {
            n.with_posture(EgressPosture {
                enforcing: true,
                allowed: vec![PolicyRule::allow(0x0A00_0000, 8, 0, 0)],
                allowed6: vec![PolicyRule6::allow([0xfd; 16], 64, 443, IPPROTO_TCP)],
                gateway: Some(std::net::Ipv4Addr::new(10, 200, 0, 1)),
            })
        });

        let json = record.to_summary_json();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(
            parsed.is_ok(),
            "the summary must be parseable JSON: {parsed:?}\n{json}"
        );
        let v = parsed.expect("checked just above");

        assert_eq!(v["gaps"][0], format!("host_syscalls: {hostile}"));
        assert_eq!(v["network"]["reached"][0], "8.8.8.8:443/tcp");
        assert_eq!(v["network"]["allowed"][0], "10.0.0.0/8:*/*");
        assert!(
            v["host_syscalls"]["notable"][0]
                .as_str()
                .is_some_and(|s| s.contains(hostile)),
            "the notable line survives escaping: {v}"
        );
    }

    #[test]
    fn summary_is_byte_stable_across_input_order() {
        let a = sample(vec![
            flow([10, 200, 0, 2], 40000, [1, 1, 1, 1], 53, IPPROTO_UDP),
            flow([10, 200, 0, 2], 40001, [8, 8, 8, 8], 443, IPPROTO_TCP),
        ]);
        let b = sample(vec![
            flow([10, 200, 0, 2], 40001, [8, 8, 8, 8], 443, IPPROTO_TCP),
            flow([10, 200, 0, 2], 40000, [1, 1, 1, 1], 53, IPPROTO_UDP),
        ]);
        assert_eq!(a.to_summary_json(), b.to_summary_json());
    }

    #[test]
    fn the_summary_says_what_the_sandbox_may_reach_not_only_what_it_did() {
        use crate::record::EgressPosture;
        use crate::summary::net_summary;
        use bsx_probes_common::{PolicyRule, PolicyRule6};

        let net = NetSection::from_tap(vec![], NetStats::default(), vec![], 0, 0).with_posture(
            EgressPosture {
                enforcing: true,
                allowed: vec![
                    PolicyRule::allow(0x0AC8_0001, 32, 9000, IPPROTO_UDP),
                    // Any port, any protocol: the wildcard shape.
                    PolicyRule::allow(0x0A00_0000, 8, 0, 0),
                ],
                allowed6: vec![PolicyRule6::allow([0xfd; 16], 64, 443, IPPROTO_TCP)],
                gateway: Some(std::net::Ipv4Addr::new(10, 200, 0, 1)),
            },
        );
        let mut out = String::new();
        net_summary(&mut out, &net);

        // `reached` and `denied` are both empty: this run did nothing. Without `allowed` an agent
        // reading that cannot tell an endpoint it may retry from one it may not.
        assert!(out.contains("\"reached\":[],\"denied\":[]"), "{out}");
        assert!(
            out.contains(
                "\"allowed\":[\"10.200.0.1/32:9000/udp\",\"10.0.0.0/8:*/*\",\
                 \"[fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd]/64:443/tcp\"]"
            ),
            "wildcards read as `*`, never as port 0 / proto 0: {out}"
        );
        assert!(out.contains("\"routed\":true"), "{out}");
        assert!(out.contains("\"enforcing\":true"), "{out}");

        // A section whose posture was never read says so, rather than implying an empty allow-list.
        let mut unread = String::new();
        net_summary(
            &mut unread,
            &NetSection::from_tap(vec![], NetStats::default(), vec![], 0, 0),
        );
        assert!(
            unread.contains("\"allowed\":null,\"routed\":null,\"enforcing\":null"),
            "{unread}"
        );
    }

    #[test]
    fn reached_collapses_flows_to_distinct_destinations() {
        // Two flows to the *same* destination from different ephemeral source ports collapse to one
        // reached entry, the agent-relevant axis is the endpoint, not the source.
        let record = sample(vec![
            flow([10, 200, 0, 2], 40000, [8, 8, 8, 8], 443, IPPROTO_TCP),
            flow([10, 200, 0, 2], 55555, [8, 8, 8, 8], 443, IPPROTO_TCP),
        ]);
        let json = record.to_summary_json();
        assert!(
            json.contains("\"reached\":[\"8.8.8.8:443/tcp\"]"),
            "one distinct destination, not two: {json}"
        );
    }

    #[test]
    fn a_denied_endpoint_is_never_listed_as_reached() {
        // The tap counts a flow *before* the egress verdict, so a blocked endpoint has a flow row
        // *and* a denial row (`sample` always denies 9.9.9.9:443/tcp). `reached` must exclude it
        // (zero bytes left the host); it belongs only in `denied`. Otherwise a supervising agent
        // reads a blocked exfil target as reached.
        let record = sample(vec![
            flow([10, 200, 0, 2], 40000, [8, 8, 8, 8], 443, IPPROTO_TCP), // allowed
            flow([10, 200, 0, 2], 40001, [9, 9, 9, 9], 443, IPPROTO_TCP), // denied at the tap
        ]);
        let json = record.to_summary_json();
        // The trailing `]` pins 8.8.8.8 as the *sole* reached entry, so 9.9.9.9 is provably absent.
        assert!(
            json.contains("\"reached\":[\"8.8.8.8:443/tcp\"]"),
            "reached must list only the allowed endpoint, not the denied one: {json}"
        );
        assert!(
            json.contains("\"denied\":[\"9.9.9.9:443/tcp\"]"),
            "the blocked endpoint still appears in denied: {json}"
        );
    }

    #[test]
    fn no_network_renders_null_and_gaps_escape() {
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing::new(Duration::ZERO, Duration::ZERO),
            vec![AxisGap::Network("tab\tand \"quote\"".into())],
        );
        let json = record.to_summary_json();
        assert!(json.contains("\"network\":null"), "{json}");
        assert!(
            json.contains("\"gaps\":[\"network: tab\\tand \\\"quote\\\"\"]"),
            "{json}"
        );
    }

    #[test]
    fn summary_is_measurably_compact_against_the_full_record() {
        // "Compact" is a measured number, not a claim (invariant 4). Build a busy record, many flows
        // to distinct destinations plus a full notable set, and assert the projection is a small
        // fraction of the full JSON, and that it grows sub-linearly (the source-port and per-flow
        // detail the full record carries do not appear in the summary).
        let flows: Vec<_> = (0..40u16)
            .map(|i| {
                flow(
                    [10, 200, 0, 2],
                    40000 + i,
                    [8, 8, (i >> 8) as u8, i as u8],
                    443,
                    IPPROTO_TCP,
                )
            })
            .collect();
        // Fill the notable set past the summary cap (distinct openat paths).
        let events: Vec<SyscallEvent> = (0..40u32)
            .map(|i| {
                let detail = format!("/tmp/file-{i:03}");
                ev(1, 0x42, detail.as_bytes(), "sh")
            })
            .collect();
        let totals = NetStats {
            ingress_packets: 1,
            ingress_bytes: 999,
            egress_packets: 1,
            egress_bytes: 999,
        };
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            Some(NetSection::from_tap(flows, totals, vec![], 0, 0)),
            ResourceSummary::default(),
            SyscallFootprint::from_events(0x42, &events),
            Timing::new(Duration::from_millis(1), Duration::from_millis(1)),
            vec![],
        );
        let full = record.to_json().len();
        let summary = record.to_summary_json().len();
        // The projection is well under half the full record on a busy run, and the notable sample is
        // capped, so the summary can't grow without bound as host activity does.
        assert!(
            summary * 2 < full,
            "summary {summary}B should be < half of full {full}B"
        );
        assert!(
            record.to_summary_json().matches("/tmp/file-").count() <= SUMMARY_NOTABLE_CAP,
            "notable sample is capped at {SUMMARY_NOTABLE_CAP}"
        );
        // Two `truncated` fields exist (network and host_syscalls); this test is about the syscall
        // cap, so anchor on the notable list's closing bracket rather than on either flag alone.
        assert!(
            record.to_summary_json().contains("],\"truncated\":true}"),
            "the syscall cap being hit is flagged on the host_syscalls object"
        );
    }
}
