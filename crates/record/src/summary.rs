//! The **model-legible projection** of the per-run [`RunRecord`]: a compact, semantically-labelled
//! summary shaped to feed straight back into an agent's observe→act loop.
//!
//! This is the *third face* of the one record, alongside the human trail (`--trace`) and the full
//! machine JSON (`--record`, [`RunRecord::to_json`](crate::RunRecord::to_json)). It is a **pure view**
//! of the existing record, no new observation, no new machinery (the AI-native surface
//! adds a *reader* of the host-observed record, never a new *authority*). It answers the questions a
//! supervising agent asks between turns: *what did my sandboxed code reach, what was blocked, what did
//! it cost, and what couldn't the host see?*
//!
//! **How it is compact.** It drops the record's *forensic* detail, per-flow byte/packet counters,
//! per-syscall `comm`/`hits`, the transient `memory.current` and the `cpu.stat` cross-check, and
//! keeps the *decision-relevant* signal: the distinct destinations reached (flows collapsed to their
//! destinations, the ephemeral source dropped), the destinations **denied**, the resource envelope, a
//! bounded host-syscall sample, and any coverage gap. "Compact" is a **measured number**, not a claim:
//! a size test pins the projection well under the full record (invariant 4).
//!
//! **Vocabulary is guest-centric.** The record names traffic from the *tap's* view (ingress = what the
//! guest sent); the summary relabels to the *guest's* view (`sent`/`recv`) because that is how an agent
//! reasons about its own code. The host-syscall counts stay labelled `host_syscalls`, they are the
//! **VMM's** host-boundary footprint, not the guest's in-guest file I/O (which a microVM services
//! itself, out of host view), and the projection does not pretend otherwise.
//!
//! Byte-stable and deterministic for the same reasons as [`RunRecord::to_json`]: a fixed key order,
//! integer nanoseconds/bytes (no float wobble), and every array derived from a builder-sorted
//! collection (or freshly sorted here). A golden test pins the exact bytes.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::json::{clamped_ns, field, field_opt_u64, json_str, proto_name, syscall_name};
use crate::record::{AxisGap, NetSection, RunRecord};

/// The version of the record-summary JSON schema, emitted as the leading `schema` field of
/// [`RunRecord::to_summary_json`]. Versioned independently of the full record's
/// [`AUDIT_SCHEMA_VERSION`](crate::AUDIT_SCHEMA_VERSION) and the CLI run-result schema: this is a
/// *fourth* surface with its own compatibility clock. Within a version, changes are additive only; a
/// rename/removal or a changed meaning bumps this integer.
pub const SUMMARY_SCHEMA_VERSION: u32 = 1;

/// The projection's own cap on notable host syscalls, tighter than the record's
/// [`MAX_NOTABLE`](crate::MAX_NOTABLE) (64), because the summary is a context-window artifact, not a
/// forensic one. Beyond it the projection sets `truncated`, so "there was more" is never silent.
const SUMMARY_NOTABLE_CAP: usize = 16;

impl RunRecord {
    /// Render this record as the compact, model-legible **summary**, one line of deterministic JSON,
    /// a pure projection of the record for an agent's observe→act loop (what it reached, what egress
    /// was denied, its resource envelope, any coverage gap; the forensic detail dropped). A *view* of
    /// the record, not new machinery. The leading `schema` field is
    /// [`SUMMARY_SCHEMA_VERSION`].
    #[must_use]
    pub fn to_summary_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');

        // schema, first, so a consumer reads it before anything else.
        field(&mut out, "schema", SUMMARY_SCHEMA_VERSION, true);

        // timing, the two durations the caller supplied, verbatim ns (no lossy rounding).
        out.push_str(",\"timing\":{");
        field(&mut out, "boot_ns", clamped_ns(self.timing.boot), true);
        field(
            &mut out,
            "exec_ns",
            clamped_ns(self.timing.exec_wall),
            false,
        );
        out.push('}');

        // network, reached vs denied (the core "what it did / what was blocked"), plus the guest-view
        // byte rollup. null when the sandbox had no NIC, same distinction the full record draws.
        out.push_str(",\"network\":");
        match &self.network {
            Some(net) => net_summary(&mut out, net),
            None => out.push_str("null"),
        }

        // host_syscalls, the VMM's host-boundary footprint, counts + a bounded notable sample.
        out.push_str(",\"host_syscalls\":");
        syscalls_summary(&mut out, self);

        // resources, the envelope: eBPF CPU, peak memory, IO bytes. The transient/ cross-check fields
        // are dropped.
        out.push_str(",\"resources\":{");
        field(
            &mut out,
            "cpu_ns",
            clamped_ns(self.resources.cpu_time),
            true,
        );
        field_opt_u64(
            &mut out,
            "mem_peak_bytes",
            self.resources.cgroup.memory_peak,
            false,
        );
        field_opt_u64(
            &mut out,
            "io_read_bytes",
            self.resources.cgroup.io_rbytes,
            false,
        );
        field_opt_u64(
            &mut out,
            "io_write_bytes",
            self.resources.cgroup.io_wbytes,
            false,
        );
        out.push('}');

        // gaps, coverage flattened to "axis: reason" strings, in the record's own (deterministic) order.
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
    // The tap counts a flow *before* the egress verdict runs (`tap_ingress`: `count()` then
    // `egress_verdict()`), so a fully-denied endpoint still appears among the flow destinations even
    // though every packet was dropped. Subtract the denied triples: `reached` must mean the guest
    // actually got bytes out, not merely attempted, or a supervising agent reads a
    // blocked exfil endpoint as reached. Those endpoints still appear in `denied` below.
    let denied: BTreeSet<(u32, u16, u8)> = net
        .denials
        .iter()
        .map(|d| (d.dst_addr, d.dst_port, d.proto))
        .collect();
    // Collapse flows to distinct destinations, an agent cares *which endpoint* it reached, not the
    // ephemeral source port. A BTreeSet dedups and yields them in total (dst, port, proto) order.
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
    field(out, "sent_bytes", net.totals.ingress_bytes, false);
    field(out, "recv_bytes", net.totals.egress_bytes, false);
    // An agent reading `reached`/`denied` between turns must know when the lists are not
    // exhaustive (the kernel's flow/denial tables saturated); the counts ride the full record.
    out.push_str(",\"truncated\":");
    out.push_str(if net.truncated() { "true" } else { "false" });
    // What the sandbox *may* reach, next to what it did. `reached`/`denied` are both backward-looking,
    // so an agent planning its next turn cannot tell "this endpoint failed, retrying is pointless"
    // from "I never tried it". `allowed` + `routed` answer that before it spends a turn finding out.
    // All three are `null` when the posture could not be read, which is not the same claim as an
    // empty allow-list.
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

/// The `port/proto` tail of a summary allow-rule, closing the string. A `0` is the kernel record's
/// "any", rendered `*` so it reads as a wildcard rather than as port zero / protocol zero.
fn rule_port_proto(out: &mut String, port: u16, proto: u8) {
    if port == 0 {
        out.push('*');
    } else {
        let _ = write!(out, "{port}");
    }
    out.push('/');
    if proto == 0 {
        out.push('*');
    } else {
        proto_name(out, proto);
    }
    out.push('"');
}

/// The host-syscall summary: the by-kind counts, a bounded `notable` sample as `"kind detail"` strings
/// (the forensic `comm`/`hits` dropped), and one honest `truncated` flag that is true if *either* the
/// record's own cap overflowed *or* this projection's tighter cap dropped entries.
fn syscalls_summary(out: &mut String, record: &RunRecord) {
    let s = &record.host_syscalls;
    out.push('{');
    field(out, "execve", s.by_kind.execve, true);
    field(out, "openat", s.by_kind.openat, false);
    field(out, "connect", s.by_kind.connect, false);
    out.push_str(",\"notable\":[");
    for (i, n) in s.notable.iter().take(SUMMARY_NOTABLE_CAP).enumerate() {
        if i > 0 {
            out.push(',');
        }
        // "kind detail" as one escaped string, build it, then json_str (detail may hold metacharacters).
        let mut line = String::new();
        syscall_name(&mut line, n.kind);
        line.push(' ');
        line.push_str(&n.detail);
        // The summary has no field to carry the flag, so it goes in the text: a reader skimming
        // paths must not take a prefix for the whole path. The marker cannot be forged away by a
        // guest naming a file after it (that only over-states doubt), and the JSON record carries
        // the machine-readable `truncated` beside it.
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

/// One coverage gap as `"axis: reason"`, the flat, model-legible form of an [`AxisGap`].
fn gap_line(gap: &AxisGap) -> String {
    let axis = match gap {
        AxisGap::HostSyscalls(_) => "host_syscalls",
        AxisGap::Network(_) => "network",
        AxisGap::Cpu(_) => "cpu",
    };
    format!("{axis}: {}", gap.reason())
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

    use ekvm_probes_common::{IPPROTO_TCP, IPPROTO_UDP, SyscallEvent};

    use super::SUMMARY_NOTABLE_CAP;
    use crate::record::{NetSection, RecordSubject, RunRecord, SyscallFootprint, Timing};
    use crate::testutil::{ev, flow, sample};
    use crate::{AxisGap, NetStats, ResourceSummary};

    #[test]
    fn a_path_cut_at_the_cap_is_marked_in_the_summary() {
        // The summary is the projection a person skims, and it has no field to carry a flag, so the
        // marker rides in the text. A prefix shown bare reads as the whole path.
        let long = vec![b'a'; ekvm_probes_common::DETAIL_CAP - 1];
        let mut record = sample(vec![]);
        record.host_syscalls = SyscallFootprint::from_events(0x42, &[ev(1, 0x42, &long, "sh")]);
        let json = record.to_summary_json();
        assert!(
            json.contains("[truncated]"),
            "a cut path must be marked where a person reads it: {json}"
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
        use ekvm_probes_common::{PolicyRule, PolicyRule6};

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
            RecordSubject::new("ekvm-4242-0".into(), 1_700_000_000_000_000_000),
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
            RecordSubject::new("ekvm-4242-0".into(), 1_700_000_000_000_000_000),
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
        assert!(
            record.to_summary_json().contains("\"truncated\":true"),
            "the cap being hit is flagged"
        );
    }
}
