//! Deterministic JSON of the per-run [`RunRecord`]: "what this run did," serialized from
//! *outside* the guest.
//!
//! Hand-rolled, dependency-free, and **compact** (no incidental whitespace), for the same reasons the
//! host↔guest wire is hand-framed (ADR 002): the audit-log format is a contract downstream SDKs
//! parse, so pinning the exact bytes here, rather than trusting a derive's field order, is the
//! point. The output is **byte-stable**: object keys are written in a fixed order and every array the
//! record carries is already sorted by its builder ([`NetSection::from_tap`](crate::NetSection),
//! [`SyscallFold::finish`](crate::SyscallFold)), so the same observations always render the same bytes.
//! A golden test pins them.
//!
//! No floats (durations are integer nanoseconds, byte counts are integers), so there is no
//! locale/precision wobble; IPv4 addresses render as dotted quads and protocols/syscalls as their
//! names, so the record reads without a decoder ring. Durations are clamped to **u64 nanoseconds**
//! (a ~584-year ceiling, the numeric bound consumers can rely on; parse these with 64-bit integers,
//! not doubles). The human-facing view (a TUI, a pretty-printer) is the live view's job; this is the
//! machine surface it and the SDKs build on.

use std::fmt::Display;
use std::fmt::Write as _;
use std::time::Duration;

use agent_probes_common::{FlowKey, FlowKey6, Syscall};

use crate::record::{AxisGap, NetSection, RunRecord, SyscallFootprint};
use crate::{CgroupStats, FlowCounts, NetStats, ResourceSummary};

/// The version of the audit-record JSON schema, emitted as the leading `schema` field of
/// [`RunRecord::to_json`]. **Compatibility policy:** within a version, changes are *additive only*
/// (a new field a consumer may ignore); renaming or removing a field, or changing a value's meaning,
/// bumps this integer. A parser keys on this to know which shape it is reading. This is the seed the
/// wire API and the language-SDK freeze harden, versioned *before* anything external parses it.
pub const AUDIT_SCHEMA_VERSION: u32 = 1;

impl RunRecord {
    /// Render this record as one line of deterministic, compact JSON, the structured output. The
    /// schema is stable and byte-for-byte reproducible across map-iteration order (see the module doc);
    /// The live view pretty-prints it for people, and the language SDKs parse it as the audit-log format.
    /// The leading `schema` field ([`AUDIT_SCHEMA_VERSION`]) versions the format.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');

        // schema version, first, so a consumer reads it before anything else.
        field(&mut out, "schema", AUDIT_SCHEMA_VERSION, true);

        out.push_str(",\"timing\":{");
        field(&mut out, "boot_ns", clamped_ns(self.timing.boot), true);
        field(
            &mut out,
            "exec_wall_ns",
            clamped_ns(self.timing.exec_wall),
            false,
        );
        out.push('}');

        // network (null when the sandbox had no NIC)
        out.push_str(",\"network\":");
        match &self.network {
            Some(net) => net_to_json(&mut out, net),
            None => out.push_str("null"),
        }

        out.push_str(",\"resources\":");
        resources_to_json(&mut out, &self.resources);

        out.push_str(",\"host_syscalls\":");
        syscalls_to_json(&mut out, &self.host_syscalls);

        out.push_str(",\"coverage\":[");
        for (i, gap) in self.coverage.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            gap_to_json(&mut out, gap);
        }
        out.push(']');

        out.push('}');
        out
    }
}

fn net_to_json(out: &mut String, net: &NetSection) {
    out.push('{');
    out.push_str("\"totals\":");
    net_stats_to_json(out, &net.totals);
    out.push_str(",\"flows\":[");
    for (i, flow) in net.flows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        endpoints(out, &flow.key);
        counts(out, &flow.counts);
        out.push('}');
    }
    out.push_str("],\"denials\":[");
    for (i, denial) in net.denials.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        // A denial is per-destination (already aggregated across guest source ports by the builder):
        // the blocked endpoint + proto, and the dropped-packet count.
        let d = denial.dst_addr.to_be_bytes();
        let _ = write!(out, "\"dst\":\"{}.{}.{}.{}\"", d[0], d[1], d[2], d[3]);
        field(out, "dst_port", denial.dst_port, false);
        out.push_str(",\"proto\":\"");
        proto_name(out, denial.proto);
        out.push('"');
        field(out, "packets", denial.count, false);
        out.push('}');
    }
    // The IPv6 flows and denials (ADR 008 dual-stack), additive `flows6`/`denials6` arrays so a v4-only
    // consumer is unaffected and the schema stays 1. Addresses render as v6 strings.
    out.push_str("],\"flows6\":[");
    for (i, flow) in net.flows6.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        endpoints6(out, &flow.key);
        counts(out, &flow.counts);
        out.push('}');
    }
    out.push_str("],\"denials6\":[");
    for (i, denial) in net.denials6.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        let _ = write!(
            out,
            "\"dst\":\"{}\"",
            std::net::Ipv6Addr::from(denial.dst_addr)
        );
        field(out, "dst_port", denial.dst_port, false);
        out.push_str(",\"proto\":\"");
        proto_name(out, denial.proto);
        out.push('"');
        field(out, "packets", denial.count, false);
        out.push('}');
    }
    out.push(']');
    // The kernel's full-map drop counters + the one flag a consumer checks before trusting the
    // flow list as exhaustive. Additive keys (schema stays 1); 0/false is the healthy shape.
    field(out, "dropped_flows", net.dropped_flows, false);
    field(out, "dropped_denials", net.dropped_denials, false);
    out.push_str(",\"truncated\":");
    out.push_str(if net.truncated() { "true" } else { "false" });
    out.push('}');
}

fn net_stats_to_json(out: &mut String, s: &NetStats) {
    out.push('{');
    field(out, "ingress_packets", s.ingress_packets, true);
    field(out, "ingress_bytes", s.ingress_bytes, false);
    field(out, "egress_packets", s.egress_packets, false);
    field(out, "egress_bytes", s.egress_bytes, false);
    out.push('}');
}

/// The 5-tuple identity fields of a flow (rendered leading, no trailing comma consumed by the caller's
/// [`counts`]). Addresses render as dotted quads via `to_be_bytes`, matching [`FlowKey`]'s `Display`.
fn endpoints(out: &mut String, key: &FlowKey) {
    let s = key.src_addr.to_be_bytes();
    let d = key.dst_addr.to_be_bytes();
    let _ = write!(out, "\"src\":\"{}.{}.{}.{}\"", s[0], s[1], s[2], s[3]);
    field(out, "src_port", key.src_port, false);
    let _ = write!(out, ",\"dst\":\"{}.{}.{}.{}\"", d[0], d[1], d[2], d[3]);
    field(out, "dst_port", key.dst_port, false);
    out.push_str(",\"proto\":\"");
    proto_name(out, key.proto);
    out.push('"');
}

/// The v6 5-tuple identity fields of a flow, the twin of [`endpoints`]. Addresses render as v6
/// strings via [`std::net::Ipv6Addr`], matching [`FlowKey6`]'s `Display`.
fn endpoints6(out: &mut String, key: &FlowKey6) {
    let _ = write!(
        out,
        "\"src\":\"{}\"",
        std::net::Ipv6Addr::from(key.src_addr)
    );
    field(out, "src_port", key.src_port, false);
    let _ = write!(
        out,
        ",\"dst\":\"{}\"",
        std::net::Ipv6Addr::from(key.dst_addr)
    );
    field(out, "dst_port", key.dst_port, false);
    out.push_str(",\"proto\":\"");
    proto_name(out, key.proto);
    out.push('"');
}

fn counts(out: &mut String, c: &FlowCounts) {
    field(out, "ingress_packets", c.ingress_packets, false);
    field(out, "ingress_bytes", c.ingress_bytes, false);
    field(out, "egress_packets", c.egress_packets, false);
    field(out, "egress_bytes", c.egress_bytes, false);
}

fn resources_to_json(out: &mut String, r: &ResourceSummary) {
    out.push('{');
    field(out, "cpu_time_ns", clamped_ns(r.cpu_time), true);
    out.push_str(",\"cgroup\":");
    cgroup_to_json(out, &r.cgroup);
    out.push('}');
}

fn cgroup_to_json(out: &mut String, c: &CgroupStats) {
    out.push('{');
    field_opt_u64(out, "cpu_usage_usec", c.cpu_usage_usec, true);
    field_opt_u64(out, "memory_current", c.memory_current, false);
    field_opt_u64(out, "memory_peak", c.memory_peak, false);
    field_opt_u64(out, "io_rbytes", c.io_rbytes, false);
    field_opt_u64(out, "io_wbytes", c.io_wbytes, false);
    out.push('}');
}

fn syscalls_to_json(out: &mut String, s: &SyscallFootprint) {
    out.push('{');
    field(out, "total", s.total, true);
    out.push_str(",\"by_kind\":{");
    field(out, "execve", s.by_kind.execve, true);
    field(out, "openat", s.by_kind.openat, false);
    field(out, "connect", s.by_kind.connect, false);
    field(out, "unknown", s.by_kind.unknown, false);
    out.push('}');
    out.push_str(",\"notable\":[");
    for (i, n) in s.notable.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"kind\":\"");
        syscall_name(out, n.kind);
        out.push_str("\",\"detail\":");
        json_str(out, &n.detail);
        out.push_str(",\"comm\":");
        json_str(out, &n.comm);
        field(out, "hits", n.hits, false);
        out.push('}');
    }
    out.push(']');
    let _ = write!(out, ",\"notable_truncated\":{}", s.notable_truncated);
    field(out, "overflow_events", s.overflow_events, false);
    out.push('}');
}

fn gap_to_json(out: &mut String, gap: &AxisGap) {
    let (axis, reason) = match gap {
        AxisGap::HostSyscalls(r) => ("host_syscalls", r),
        AxisGap::Network(r) => ("network", r),
        AxisGap::Cpu(r) => ("cpu", r),
    };
    let _ = write!(out, "{{\"axis\":\"{axis}\",\"reason\":");
    json_str(out, reason);
    out.push('}');
}

pub(crate) fn proto_name(out: &mut String, proto: u8) {
    match proto {
        agent_probes_common::IPPROTO_TCP => out.push_str("tcp"),
        agent_probes_common::IPPROTO_UDP => out.push_str("udp"),
        p => {
            let _ = write!(out, "proto {p}");
        }
    }
}

pub(crate) fn syscall_name(out: &mut String, kind: Syscall) {
    out.push_str(match kind {
        Syscall::Execve => "execve",
        Syscall::Openat => "openat",
        Syscall::Connect => "connect",
    });
}

/// Write `,"key":<value>` (or `"key":<value>` when `first`) for any unquoted-rendering value, the
/// integer fields all funnel through here, one helper instead of one per width.
pub(crate) fn field<T: Display>(out: &mut String, key: &str, value: T, first: bool) {
    if !first {
        out.push(',');
    }
    let _ = write!(out, "\"{key}\":{value}");
}

/// A duration as **u64 nanoseconds**, saturating at `u64::MAX` (~584 years), the documented numeric
/// ceiling of the JSON surface, so consumers can parse with ordinary 64-bit integers.
pub(crate) fn clamped_ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Write `,"key":<n|null>`, an absent counter (a cgroup file a kernel doesn't have) renders `null`,
/// distinct from a real `0`.
pub(crate) fn field_opt_u64(out: &mut String, key: &str, value: Option<u64>, first: bool) {
    if !first {
        out.push(',');
    }
    match value {
        Some(v) => write!(out, "\"{key}\":{v}").ok(),
        None => write!(out, "\"{key}\":null").ok(),
    };
}

/// Write a JSON string literal, escaping per RFC 8259: the two mandatory metacharacters (`"` and `\`)
/// and every control byte below 0x20 (as `\n`/`\t`/… or a `\u00XX` escape). The record's strings are
/// already lossy-UTF-8 (`detail_display`/`comm_lossy`), so this only has to make them JSON-safe, never
/// re-validate UTF-8.
pub(crate) fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agent_probes_common::{FlowCounts, FlowKey, SyscallEvent, IPPROTO_TCP, IPPROTO_UDP};

    use crate::record::{NetSection, RunRecord, SyscallFootprint, Timing};
    use crate::{AxisGap, CgroupStats, NetStats, ResourceSummary};

    /// Build a synthetic `SyscallEvent` from public fields (no eBPF), matching `record.rs`'s helper.
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

    /// A representative record with every axis populated, for the golden and stability tests.
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
        // execve once + openat twice (same path) exercises the notable de-dup + sort.
        let host_syscalls = SyscallFootprint::from_events(
            0x42,
            &[
                ev(0, 0x42, b"/bin/sh", "sh"),
                ev(1, 0x42, b"/etc/hosts", "sh"),
                ev(1, 0x42, b"/etc/hosts", "sh"),
            ],
        );
        RunRecord::from_parts(
            Some(NetSection::from_tap(flows, totals, denials, 0, 0)),
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
    fn json_is_the_expected_golden_bytes() {
        let record = sample(vec![
            flow([10, 200, 0, 2], 40000, [1, 1, 1, 1], 53, IPPROTO_UDP),
            flow([10, 200, 0, 2], 40001, [8, 8, 8, 8], 443, IPPROTO_TCP),
        ]);
        let json = record.to_json();
        let expected = concat!(
            "{\"schema\":1,\"timing\":{\"boot_ns\":120000000,\"exec_wall_ns\":42000000}",
            ",\"network\":{\"totals\":{\"ingress_packets\":2,\"ingress_bytes\":120,",
            "\"egress_packets\":3,\"egress_bytes\":200},\"flows\":[",
            "{\"src\":\"10.200.0.2\",\"src_port\":40000,\"dst\":\"1.1.1.1\",\"dst_port\":53,",
            "\"proto\":\"udp\",\"ingress_packets\":2,\"ingress_bytes\":120,\"egress_packets\":3,",
            "\"egress_bytes\":200},",
            "{\"src\":\"10.200.0.2\",\"src_port\":40001,\"dst\":\"8.8.8.8\",\"dst_port\":443,",
            "\"proto\":\"tcp\",\"ingress_packets\":2,\"ingress_bytes\":120,\"egress_packets\":3,",
            "\"egress_bytes\":200}],",
            "\"denials\":[{\"dst\":\"9.9.9.9\",\"dst_port\":443,\"proto\":\"tcp\",\"packets\":4}],",
            "\"flows6\":[],\"denials6\":[],",
            "\"dropped_flows\":0,\"dropped_denials\":0,\"truncated\":false}",
            ",\"resources\":{\"cpu_time_ns\":5000,\"cgroup\":{\"cpu_usage_usec\":6,",
            "\"memory_current\":1024,\"memory_peak\":4096,\"io_rbytes\":null,\"io_wbytes\":512}}",
            ",\"host_syscalls\":{\"total\":3,\"by_kind\":{\"execve\":1,\"openat\":2,\"connect\":0,",
            "\"unknown\":0},\"notable\":[",
            "{\"kind\":\"execve\",\"detail\":\"/bin/sh\",\"comm\":\"sh\",\"hits\":1},",
            "{\"kind\":\"openat\",\"detail\":\"/etc/hosts\",\"comm\":\"sh\",\"hits\":2}],",
            "\"notable_truncated\":false,\"overflow_events\":0}",
            ",\"coverage\":[{\"axis\":\"cpu\",\"reason\":\"meter lock poisoned\"}]}",
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn json_is_byte_stable_across_input_order() {
        let a = sample(vec![
            flow([10, 200, 0, 2], 40000, [1, 1, 1, 1], 53, IPPROTO_UDP),
            flow([10, 200, 0, 2], 40001, [8, 8, 8, 8], 443, IPPROTO_TCP),
        ]);
        let b = sample(vec![
            flow([10, 200, 0, 2], 40001, [8, 8, 8, 8], 443, IPPROTO_TCP),
            flow([10, 200, 0, 2], 40000, [1, 1, 1, 1], 53, IPPROTO_UDP),
        ]);
        assert_eq!(a.to_json(), b.to_json());
    }

    #[test]
    fn no_network_renders_null_and_control_chars_escape() {
        let record = RunRecord::from_parts(
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing {
                boot: Duration::ZERO,
                exec_wall: Duration::ZERO,
            },
            vec![AxisGap::Network("tab\tand \"quote\" and \\slash".into())],
        );
        let json = record.to_json();
        assert!(json.contains("\"network\":null"), "{json}");
        // The gap reason's control + metacharacters are escaped, keeping the line valid JSON.
        assert!(
            json.contains("\"reason\":\"tab\\tand \\\"quote\\\" and \\\\slash\""),
            "{json}"
        );
    }
}
