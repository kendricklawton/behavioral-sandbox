//! The **model-legible projection** of the per-run [`RunRecord`]: a compact, semantically-labelled
//! summary shaped to feed straight back into an agent's observe→act loop.
//!
//! This is the *third face* of the one record, alongside the human trail (`--trace`) and the full
//! machine JSON (`--record`, [`RunRecord::to_json`](crate::RunRecord::to_json)). It is a **pure view**
//! of the existing record, no new observation, no new machinery (decision 035: the AI-native surface
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
//! itself, out of host view; decision 033), and the projection does not pretend otherwise.
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
    /// the record, not new machinery (decision 035). The leading `schema` field is
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

/// The network summary: `reached` (distinct destinations the guest actually talked to, flows collapsed
/// to their destination triple and sorted), `denied` (blocked destinations, already dst-aggregated and
/// sorted by the builder), and the guest-view byte rollup.
fn net_summary(out: &mut String, net: &NetSection) {
    // Collapse flows to distinct destinations, an agent cares *which endpoint* it reached, not the
    // ephemeral source port. A BTreeSet dedups and yields them in total (dst, port, proto) order.
    let dests: BTreeSet<(u32, u16, u8)> = net
        .flows
        .iter()
        .map(|f| (f.key.dst_addr, f.key.dst_port, f.key.proto))
        .collect();
    out.push_str("{\"reached\":[");
    for (i, &(addr, port, proto)) in dests.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        endpoint(out, addr, port, proto);
    }
    out.push_str("],\"denied\":[");
    for (i, d) in net.denials.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        endpoint(out, d.dst_addr, d.dst_port, d.proto);
    }
    out.push(']');
    // Guest-view bytes: the record's tap-view `ingress` is what the guest sent, `egress` what it received.
    field(out, "sent_bytes", net.totals.ingress_bytes, false);
    field(out, "recv_bytes", net.totals.egress_bytes, false);
    out.push('}');
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
        json_str(out, &line);
    }
    out.push(']');
    let truncated = s.notable_truncated || s.notable.len() > SUMMARY_NOTABLE_CAP;
    let _ = write!(out, ",\"truncated\":{truncated}");
    out.push('}');
}

/// One coverage gap as `"axis: reason"`, the flat, model-legible form of an [`AxisGap`].
fn gap_line(gap: &AxisGap) -> String {
    match gap {
        AxisGap::HostSyscalls(r) => format!("host_syscalls: {r}"),
        AxisGap::Network(r) => format!("network: {r}"),
        AxisGap::Cpu(r) => format!("cpu: {r}"),
    }
}

/// A destination as one compact JSON string, `"1.1.1.1:443/tcp"`, the dotted quad, the L4 port, and
/// the protocol name (via the shared [`proto_name`]).
fn endpoint(out: &mut String, addr: u32, port: u16, proto: u8) {
    let b = addr.to_be_bytes();
    let _ = write!(out, "\"{}.{}.{}.{}:{}/", b[0], b[1], b[2], b[3], port);
    proto_name(out, proto);
    out.push('"');
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agent_probes_common::{FlowCounts, FlowKey, SyscallEvent, IPPROTO_TCP, IPPROTO_UDP};

    use super::SUMMARY_NOTABLE_CAP;
    use crate::record::{NetSection, RunRecord, SyscallFootprint, Timing};
    use crate::{AxisGap, CgroupStats, NetStats, ResourceSummary};

    /// A synthetic `SyscallEvent` from public fields (no eBPF), matching the other modules' helper.
    fn ev(syscall: u32, cgroup: u64, detail: &[u8], comm: &str) -> SyscallEvent {
        let mut d = [0u8; agent_probes_common::DETAIL_CAP];
        let n = detail.len().min(d.len());
        d[..n].copy_from_slice(&detail[..n]);
        let mut c = [0u8; agent_probes_common::COMM_CAP];
        let m = comm.len().min(c.len());
        c[..m].copy_from_slice(&comm.as_bytes()[..m]);
        SyscallEvent {
            cgroup_id: cgroup,
            pid: 7,
            tid: 7,
            syscall,
            detail_len: n as u32,
            comm: c,
            detail: d,
        }
    }

    fn flow(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        proto: u8,
    ) -> (FlowKey, FlowCounts) {
        (
            FlowKey::new(
                u32::from_be_bytes(src),
                u32::from_be_bytes(dst),
                sport,
                dport,
                proto,
            ),
            FlowCounts {
                ingress_packets: 2,
                ingress_bytes: 120,
                egress_packets: 3,
                egress_bytes: 200,
            },
        )
    }

    /// The same representative record `json.rs`'s golden uses, so the two faces are compared on one
    /// input.
    fn sample(flows: Vec<(FlowKey, FlowCounts)>) -> RunRecord {
        let totals = NetStats {
            ingress_packets: 2,
            ingress_bytes: 120,
            egress_packets: 3,
            egress_bytes: 200,
        };
        let denials = vec![(
            FlowKey::new(0, u32::from_be_bytes([9, 9, 9, 9]), 0, 443, IPPROTO_TCP),
            4,
        )];
        let resources = ResourceSummary {
            cpu_time: Duration::from_nanos(5_000),
            cgroup: CgroupStats {
                cpu_usage_usec: Some(6),
                memory_current: Some(1024),
                memory_peak: Some(4096),
                io_rbytes: None,
                io_wbytes: Some(512),
            },
        };
        let host_syscalls = SyscallFootprint::from_events(
            0x42,
            &[
                ev(0, 0x42, b"/bin/sh", "sh"),
                ev(1, 0x42, b"/etc/hosts", "sh"),
                ev(1, 0x42, b"/etc/hosts", "sh"),
            ],
        );
        RunRecord::from_parts(
            Some(NetSection::from_tap(flows, totals, denials)),
            resources,
            host_syscalls,
            Timing {
                boot: Duration::from_millis(120),
                exec_wall: Duration::from_millis(42),
            },
            vec![AxisGap::Cpu("meter lock poisoned".into())],
        )
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
            "\"denied\":[\"9.9.9.9:443/tcp\"],\"sent_bytes\":120,\"recv_bytes\":200}",
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
    fn no_network_renders_null_and_gaps_escape() {
        let record = RunRecord::from_parts(
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing {
                boot: Duration::ZERO,
                exec_wall: Duration::ZERO,
            },
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
            Some(NetSection::from_tap(flows, totals, vec![])),
            ResourceSummary::default(),
            SyscallFootprint::from_events(0x42, &events),
            Timing {
                boot: Duration::from_millis(1),
                exec_wall: Duration::from_millis(1),
            },
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
