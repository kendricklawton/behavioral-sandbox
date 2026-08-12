//! Deterministic JSON of the per-run [`RunRecord`]: "what this run did", serialized from *outside* the
//! guest.
//!
//! - **Hand-rolled and compact**, for the same reason the host-guest wire is hand-framed: the audit-log
//!   format is a contract downstream clients parse, so pinning the exact bytes beats trusting a derive's
//!   field order.
//! - **Byte-stable.** Object keys are written in a fixed order and every array is already sorted by its
//!   builder, so the same observations always render the same bytes. A golden test pins them.
//! - **No floats.** Durations are integer nanoseconds clamped to `u64` (a ~584-year ceiling; parse with
//!   64-bit integers, not doubles) and byte counts are integers, so there is no locale or precision
//!   wobble. Addresses render as dotted quads, protocols, and syscalls as their names, so the record
//!   reads without a decoder ring.
//! - **The machine surface.** Pretty-printing for people is the live view's job.

use std::fmt::Display;
use std::fmt::Write as _;
use std::time::Duration;

use bsx_probes_common::{FlowKey, FlowKey6, Syscall};

use crate::record::{AxisGap, EgressPosture, NetSection, RunRecord, SyscallFootprint};
use crate::{CgroupStats, FlowCounts, NetStats, ResourceSummary};

/// The version of the audit-record JSON schema, emitted as the leading `schema` field of
/// [`RunRecord::to_json`]. Within a version changes are **additive only**; a rename, a removal, or a
/// changed meaning bumps this integer, so a parser keys on it to know which shape it is reading.
pub const AUDIT_SCHEMA_VERSION: u32 = 1;

impl RunRecord {
    /// Renders this record as one line of deterministic, compact JSON, byte-for-byte reproducible across
    /// map-iteration order. The leading `schema` field versions the format.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');

        // schema version, first, so a consumer reads it before anything else.
        field(&mut out, "schema", AUDIT_SCHEMA_VERSION, true);

        // Subject next: a consumer filing or correlating records needs both before it cares what the
        // sandbox did.
        out.push_str(",\"subject\":{\"sandbox_id\":");
        json_str(&mut out, &self.subject.sandbox_id);
        field(
            &mut out,
            "started_unix_ns",
            self.subject.started_unix_ns,
            false,
        );
        out.push('}');

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

        out.push_str(",\"coverage\":");
        array(&mut out, &self.coverage, gap_to_json);

        out.push('}');
        out
    }
}

fn net_to_json(out: &mut String, net: &NetSection) {
    out.push('{');
    out.push_str("\"totals\":");
    net_stats_to_json(out, &net.totals);
    out.push_str(",\"flows\":");
    array(out, &net.flows, |out, f| {
        flow_to_json(out, &f.key, &f.counts);
    });
    out.push_str(",\"denials\":");
    array(out, &net.denials, |out, d| {
        denial_to_json(out, d.dst_addr, d.dst_port, d.proto, d.count);
    });
    // Additive `flows6`/`denials6` arrays (schema stays 1), addresses as v6 strings.
    out.push_str(",\"flows6\":");
    array(out, &net.flows6, |out, f| {
        flow_to_json(out, &f.key, &f.counts);
    });
    out.push_str(",\"denials6\":");
    array(out, &net.denials6, |out, d| {
        denial_to_json(out, d.dst_addr, d.dst_port, d.proto, d.count);
    });
    // The kernel's drop counters plus the flag a consumer checks before trusting the flow list as
    // exhaustive; `0`/`false` is the healthy shape.
    field(out, "dropped_flows", net.dropped_flows, false);
    field(out, "dropped_denials", net.dropped_denials, false);
    out.push_str(",\"truncated\":");
    out.push_str(if net.truncated() { "true" } else { "false" });
    // `null` posture says it was not read, a different claim from an empty rule list, so the two render
    // differently on purpose.
    out.push_str(",\"posture\":");
    match &net.posture {
        Some(p) => posture_to_json(out, p),
        None => out.push_str("null"),
    }
    out.push('}');
}

/// The egress posture: whether the classifier was armed, the rules it holds, and the configured
/// default route. Rules render in slot order (the kernel's own), which is already deterministic.
fn posture_to_json(out: &mut String, p: &EgressPosture) {
    out.push_str("{\"enforcing\":");
    out.push_str(if p.enforcing { "true" } else { "false" });
    out.push_str(",\"gateway\":");
    match p.gateway {
        Some(gw) => {
            let _ = write!(out, "\"{gw}\"");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"allowed\":");
    array(out, &p.allowed, |out, r| {
        rule_to_json(out, r.addr, r.prefix_len, r.port, r.proto);
    });
    out.push_str(",\"allowed6\":");
    array(out, &p.allowed6, |out, r| {
        rule_to_json(out, r.addr, r.prefix_len, r.port, r.proto);
    });
    out.push('}');
}

/// Writes `[<item>,…]`, the comma-separated array shape every list in this record repeats, leaving
/// `render` to write one element.
fn array<T>(out: &mut String, items: &[T], mut render: impl FnMut(&mut String, &T)) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        render(out, item);
    }
    out.push(']');
}

/// The address width a section is keyed by, and the only difference between a section and its v6
/// twin, so naming it is what lets the two render from one body.
trait Addr: Copy {
    /// Writes the address as the record spells it: a dotted quad, or the compressed v6 form.
    fn write(self, out: &mut String);
}

impl Addr for u32 {
    fn write(self, out: &mut String) {
        let _ = write!(out, "{}", std::net::Ipv4Addr::from(self));
    }
}

impl Addr for [u8; 16] {
    fn write(self, out: &mut String) {
        let _ = write!(out, "{}", std::net::Ipv6Addr::from(self));
    }
}

/// A flow's 5-tuple at either address width. The accessor exists so the shared renderer names each
/// field rather than taking two same-typed addresses and two same-typed ports positionally.
trait FlowIdent {
    /// The width its addresses are.
    type Addr: Addr;
    /// `(src, src_port, dst, dst_port, proto)`, in the order the record writes them.
    fn parts(&self) -> (Self::Addr, u16, Self::Addr, u16, u8);
}

impl FlowIdent for FlowKey {
    type Addr = u32;
    fn parts(&self) -> (u32, u16, u32, u16, u8) {
        (
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
        )
    }
}

impl FlowIdent for FlowKey6 {
    type Addr = [u8; 16];
    fn parts(&self) -> ([u8; 16], u16, [u8; 16], u16, u8) {
        (
            self.src_addr,
            self.src_port,
            self.dst_addr,
            self.dst_port,
            self.proto,
        )
    }
}

/// One `flows`/`flows6` element: a flow's 5-tuple identity, then its per-direction counters.
fn flow_to_json<K: FlowIdent>(out: &mut String, key: &K, c: &FlowCounts) {
    let (src, src_port, dst, dst_port, proto) = key.parts();
    out.push_str("{\"src\":\"");
    src.write(out);
    out.push('"');
    field(out, "src_port", src_port, false);
    out.push_str(",\"dst\":\"");
    dst.write(out);
    out.push('"');
    field(out, "dst_port", dst_port, false);
    out.push_str(",\"proto\":\"");
    proto_name(out, proto);
    out.push('"');
    counts(out, c);
    out.push('}');
}

/// One `denials`/`denials6` element: a blocked destination and the packets dropped to it, already
/// aggregated across guest source ports by the builder.
fn denial_to_json<A: Addr>(out: &mut String, dst: A, dst_port: u16, proto: u8, packets: u64) {
    out.push_str("{\"dst\":\"");
    dst.write(out);
    out.push('"');
    field(out, "dst_port", dst_port, false);
    out.push_str(",\"proto\":\"");
    proto_name(out, proto);
    out.push('"');
    field(out, "packets", packets, false);
    out.push('}');
}

/// One `allowed`/`allowed6` element: the CIDR a rule matches, then its port and protocol.
fn rule_to_json<A: Addr>(out: &mut String, dst: A, prefix_len: u8, port: u16, proto: u8) {
    out.push_str("{\"dst\":\"");
    dst.write(out);
    let _ = write!(out, "/{prefix_len}\"");
    rule_port_proto(out, port, proto);
}

/// The `port`/`proto` tail shared by both rule renderers, closing the object. A wildcard renders as
/// `null`, since port 0 and protocol 0 are otherwise real values.
fn rule_port_proto(out: &mut String, port: u16, proto: u8) {
    out.push_str(",\"dst_port\":");
    match rule_port(port) {
        Some(p) => {
            let _ = write!(out, "{p}");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"proto\":");
    match rule_proto(proto) {
        Some(p) => {
            out.push('"');
            proto_name(out, p);
            out.push('"');
        }
        None => out.push_str("null"),
    }
    out.push('}');
}

/// The port an egress rule matches, or `None` for the `0` the kernel record writes to mean **any
/// port**. The sentinel is decoded here rather than at each renderer, which spell the wildcard
/// differently on purpose.
pub(crate) fn rule_port(port: u16) -> Option<u16> {
    (port != 0).then_some(port)
}

/// The protocol an egress rule matches, or `None` for the `0` that means **any protocol**, the
/// twin of [`rule_port`].
pub(crate) fn rule_proto(proto: u8) -> Option<u8> {
    (proto != 0).then_some(proto)
}

fn net_stats_to_json(out: &mut String, s: &NetStats) {
    out.push('{');
    field(out, "ingress_packets", s.ingress_packets, true);
    field(out, "ingress_bytes", s.ingress_bytes, false);
    field(out, "egress_packets", s.egress_packets, false);
    field(out, "egress_bytes", s.egress_bytes, false);
    out.push('}');
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
    out.push_str(",\"notable\":");
    array(out, &s.notable, |out, n| {
        out.push_str("{\"kind\":\"");
        syscall_name(out, n.kind);
        out.push_str("\",\"detail\":");
        json_str(out, &n.detail);
        out.push_str(",\"comm\":");
        json_str(out, &n.comm);
        field(out, "hits", n.hits, false);
        // Additive key (schema stays 1): a `true` `detail` is a prefix of the guest's path, not the
        // path, so a consumer treating the two alike states something that never happened.
        let _ = write!(out, ",\"truncated\":{}", n.truncated);
        out.push('}');
    });
    let _ = write!(out, ",\"notable_truncated\":{}", s.notable_truncated);
    field(out, "overflow_events", s.overflow_events, false);
    out.push('}');
}

fn gap_to_json(out: &mut String, gap: &AxisGap) {
    let _ = write!(out, "{{\"axis\":\"{}\",\"reason\":", gap.axis());
    json_str(out, gap.reason());
    out.push('}');
}

/// The shared [`bsx_probes_common::ProtoName`] rendering, written into `out`: the record names a
/// protocol exactly as the flow keys and the CLI's trail do.
pub(crate) fn proto_name(out: &mut String, proto: u8) {
    let _ = write!(out, "{}", bsx_probes_common::ProtoName(proto));
}

pub(crate) fn syscall_name(out: &mut String, kind: Syscall) {
    out.push_str(kind.name());
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

/// Writes a JSON string literal, escaping per RFC 8259: the two mandatory metacharacters and every
/// control byte below 0x20. The record's strings are already lossy-UTF-8, so this only makes them
/// JSON-safe, never re-validates UTF-8.
pub(crate) fn json_str(out: &mut String, s: &str) {
    out.push('"');
    json_escape_into(out, s);
    out.push('"');
}

/// [`json_str`] without the surrounding quotes, so the signing envelope (which embeds the whole record
/// *as* a JSON string) escapes by the same rules the record does, not a second copy. The bytes this
/// produces are the bytes that get signed.
pub(crate) fn json_escape_into(out: &mut String, s: &str) {
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
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bsx_probes_common::{IPPROTO_TCP, IPPROTO_UDP};

    use crate::record::{NetSection, RecordSubject, RunRecord, SyscallFootprint, Timing};
    use crate::testutil::{ev, flow, sample};
    use crate::{AxisGap, NetStats, ResourceSummary};

    #[test]
    fn a_path_cut_at_the_cap_is_marked_in_the_record() {
        // A path past the probe's capture buffer is recorded as its own prefix. Unflagged, the
        // record asserts an open that never happened, in the same shape as one that did, so the
        // A client parsing this format needs the flag beside the path, not a marker inside it.
        let long = vec![b'a'; bsx_probes_common::DETAIL_CAP - 1];
        let mut record = sample(vec![]);
        record.host_syscalls = SyscallFootprint::from_events(0x42, &[ev(1, 0x42, &long, "sh")]);
        let json = record.to_json();
        // The record carries two `truncated` fields, one on the network section and one per notable
        // entry, so a bare `contains` would also be satisfied by the wrong one. Name this one.
        assert!(
            json.contains("\"detail\":\"aaa"),
            "the cut path is the notable entry under test: {json}"
        );
        assert!(
            json.contains("\"hits\":1,\"truncated\":true"),
            "a cut path must be flagged on its own entry, not merely somewhere in the record: {json}"
        );
    }

    #[test]
    fn json_is_the_expected_golden_bytes() {
        let record = sample(vec![
            flow([10, 200, 0, 2], 40000, [1, 1, 1, 1], 53, IPPROTO_UDP),
            flow([10, 200, 0, 2], 40001, [8, 8, 8, 8], 443, IPPROTO_TCP),
        ]);
        let json = record.to_json();
        let expected = concat!(
            "{\"schema\":1,\"subject\":{\"sandbox_id\":\"bsx-4242-0\",\"started_unix_ns\":1700000000000000000},\"timing\":{\"boot_ns\":120000000,\"exec_wall_ns\":42000000}",
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
            "\"dropped_flows\":0,\"dropped_denials\":0,\"truncated\":false,\"posture\":null}",
            ",\"resources\":{\"cpu_time_ns\":5000,\"cgroup\":{\"cpu_usage_usec\":6,",
            "\"memory_current\":1024,\"memory_peak\":4096,\"io_rbytes\":null,\"io_wbytes\":512}}",
            ",\"host_syscalls\":{\"total\":3,\"by_kind\":{\"execve\":1,\"openat\":2,\"connect\":0,",
            "\"unknown\":0},\"notable\":[",
            "{\"kind\":\"execve\",\"detail\":\"/bin/sh\",\"comm\":\"sh\",\"hits\":1,\"truncated\":false},",
            "{\"kind\":\"openat\",\"detail\":\"/etc/hosts\",\"comm\":\"sh\",\"hits\":2,\"truncated\":false}],",
            "\"notable_truncated\":false,\"overflow_events\":0}",
            ",\"coverage\":[{\"axis\":\"cpu\",\"reason\":\"meter lock poisoned\"}]}",
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn every_v1_key_survives_in_a_fully_populated_record() {
        // The additive-only freeze as its own pin (the compatibility policy on `to_json`): within
        // schema v1, an existing key may never be renamed or removed, only new keys added. The
        // byte-golden above legitimately *changes* on an additive extension, so this list is the
        // part that must never shrink; a key vanishing here means a client built against v1 breaks
        // without a schema bump.
        let json = sample(vec![flow(
            [10, 200, 0, 2],
            40000,
            [1, 1, 1, 1],
            53,
            IPPROTO_UDP,
        )])
        .to_json();
        const REQUIRED_V1_KEYS: &[&str] = &[
            "\"schema\":",
            "\"subject\":",
            "\"sandbox_id\":",
            "\"started_unix_ns\":",
            "\"timing\":",
            "\"boot_ns\":",
            "\"exec_wall_ns\":",
            "\"network\":",
            "\"totals\":",
            "\"ingress_packets\":",
            "\"ingress_bytes\":",
            "\"egress_packets\":",
            "\"egress_bytes\":",
            "\"flows\":",
            "\"src\":",
            "\"src_port\":",
            "\"dst\":",
            "\"dst_port\":",
            "\"proto\":",
            "\"denials\":",
            "\"packets\":",
            "\"flows6\":",
            "\"denials6\":",
            "\"dropped_flows\":",
            "\"dropped_denials\":",
            "\"truncated\":",
            "\"posture\":",
            "\"resources\":",
            "\"cpu_time_ns\":",
            "\"cgroup\":",
            "\"cpu_usage_usec\":",
            "\"memory_current\":",
            "\"memory_peak\":",
            "\"io_rbytes\":",
            "\"io_wbytes\":",
            "\"host_syscalls\":",
            "\"total\":",
            "\"by_kind\":",
            "\"execve\":",
            "\"openat\":",
            "\"connect\":",
            "\"unknown\":",
            "\"notable\":",
            "\"kind\":",
            "\"detail\":",
            "\"comm\":",
            "\"hits\":",
            "\"notable_truncated\":",
            "\"overflow_events\":",
            "\"coverage\":",
            "\"axis\":",
            "\"reason\":",
        ];
        for key in REQUIRED_V1_KEYS {
            assert!(json.contains(key), "v1 key {key} missing from: {json}");
        }

        // And the other direction, so the list cannot fall behind the writer the way it already
        // had: every key the record actually emits must be named above. A key that ships without
        // being frozen here is a key nothing stops a later edit from removing.
        fn keys(v: &serde_json::Value, into: &mut std::collections::BTreeSet<String>) {
            match v {
                serde_json::Value::Object(map) => {
                    for (k, child) in map {
                        into.insert(k.clone());
                        keys(child, into);
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|i| keys(i, into)),
                _ => {}
            }
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "{parsed:?}");
        let mut emitted = std::collections::BTreeSet::new();
        keys(&parsed.expect("checked just above"), &mut emitted);
        let frozen: std::collections::BTreeSet<String> = REQUIRED_V1_KEYS
            .iter()
            .map(|k| k.trim_matches(|c| c == '"' || c == ':').to_string())
            .collect();
        let unfrozen: Vec<&String> = emitted.difference(&frozen).collect();
        assert!(
            unfrozen.is_empty(),
            "these keys ship in v1 but are not frozen in REQUIRED_V1_KEYS: {unfrozen:?}"
        );
    }

    /// Two renderings that only production reaches, so neither had a test: every gap the suite
    /// built was `Network` or `Cpu`, and every flow used TCP or UDP. Both strings land inside the
    /// signed bytes, and both are what a client matches on.
    #[test]
    fn every_gap_axis_and_an_unnamed_protocol_render() {
        // All three axes, so a typo in either renderer's arm is caught rather than two of three.
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-4242-0".into(), 1),
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing::new(Duration::ZERO, Duration::ZERO),
            vec![
                AxisGap::HostSyscalls("tracer".into()),
                AxisGap::Network("tap".into()),
                AxisGap::Cpu("meter".into()),
            ],
        );
        let json = record.to_json();
        for axis in ["host_syscalls", "network", "cpu"] {
            assert!(json.contains(&format!("{{\"axis\":\"{axis}\"")), "{json}");
        }
        assert!(
            record
                .to_summary_json()
                .contains("\"host_syscalls: tracer\""),
            "the summary flattens the same axis name: {}",
            record.to_summary_json()
        );

        // A guest ping is an IPv4 flow whose protocol is neither TCP nor UDP: `parse` keys it with
        // ports 0 and the real protocol number, so `proto_name`'s fallback is a production
        // rendering, not a defensive arm.
        const IPPROTO_ICMP: u8 = 1;
        let record = sample(vec![flow(
            [10, 200, 0, 2],
            0,
            [1, 1, 1, 1],
            0,
            IPPROTO_ICMP,
        )]);
        let json = record.to_json();
        assert!(
            json.contains("\"proto\":\"proto 1\""),
            "an unnamed protocol renders as `proto <n>`: {json}"
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "and it stays valid JSON: {parsed:?}");
        assert!(
            record.to_summary_json().contains("1.1.1.1:0/proto 1"),
            "the summary endpoint uses the same rendering: {}",
            record.to_summary_json()
        );
    }

    /// The v6 half of the network section, which no test rendered with anything in it: the byte
    /// golden carries `"flows6":[],"denials6":[]`, so the v6 row writers reached no assertion at
    /// all while the v4 ones were pinned to the byte. Both arrays are inside the signed bytes.
    #[test]
    fn a_v6_flow_and_denial_render_the_same_keys_as_their_v4_twins() {
        use crate::json::net_to_json;
        use bsx_probes_common::{FlowCounts, FlowKey6};

        let ula = |n: u8| {
            let mut a = [0u8; 16];
            (a[0], a[15]) = (0xfd, n);
            a
        };
        let counts = FlowCounts {
            ingress_packets: 2,
            ingress_bytes: 120,
            egress_packets: 3,
            egress_bytes: 200,
        };
        let net = NetSection::from_tap(vec![], NetStats::default(), vec![], 0, 0).with_v6(
            vec![(
                FlowKey6::new(ula(2), ula(1), 40000, 53, IPPROTO_UDP),
                counts,
            )],
            vec![(FlowKey6::new(ula(2), ula(7), 40001, 443, IPPROTO_TCP), 4)],
        );
        let mut out = String::new();
        net_to_json(&mut out, &net);

        assert!(
            out.contains(
                "\"flows6\":[{\"src\":\"fd00::2\",\"src_port\":40000,\"dst\":\"fd00::1\",\
                 \"dst_port\":53,\"proto\":\"udp\",\"ingress_packets\":2,\"ingress_bytes\":120,\
                 \"egress_packets\":3,\"egress_bytes\":200}]"
            ),
            "a v6 flow carries the v4 keys in the v4 order, with a v6 address: {out}"
        );
        assert!(
            out.contains(
                "\"denials6\":[{\"dst\":\"fd00::7\",\"dst_port\":443,\"proto\":\"tcp\",\
                 \"packets\":4}]"
            ),
            "and so does a v6 denial: {out}"
        );
    }

    #[test]
    fn a_dropped_row_marks_the_section_truncated_in_the_json() {
        // The honest-truncation invariant in its non-zero direction (the golden only pins the
        // zero case): kernel drop counters make the section read as incomplete, in the flag and
        // in the serialized record a consumer trusts.
        let totals = NetStats::default();
        let dropped = NetSection::from_tap(vec![], totals, vec![], 3, 0);
        assert!(
            dropped.truncated(),
            "dropped_flows > 0 must mark truncation"
        );
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            Some(dropped),
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing::new(Duration::ZERO, Duration::ZERO),
            vec![],
        );
        let json = record.to_json();
        assert!(json.contains("\"dropped_flows\":3"), "{json}");
        assert!(json.contains("\"truncated\":true"), "{json}");
    }

    /// The writer is hand-rolled: two hundred lines of `push_str` deciding its own commas and
    /// braces. The two artifacts that guard it, the byte golden above and
    /// `tests/durability.rs`'s fixture, are both **re-blessed** when the record legitimately
    /// changes, so an edit that adds a field and drops a comma passes both once they are reissued.
    /// A parser cannot be re-blessed, so it is the guard that survives that workflow.
    ///
    /// Every string-typed field carries JSON metacharacters here, since those are what a hand-rolled
    /// escaper gets wrong, and they are also the fields a guest can influence.
    #[test]
    fn the_rendered_record_parses_as_json() {
        let hostile = "q\"uote \\slash \u{1}ctl \n nl \t tab";
        let mut record = sample(vec![flow(
            [10, 200, 0, 2],
            40000,
            [1, 1, 1, 1],
            53,
            IPPROTO_UDP,
        )]);
        record.subject = RecordSubject::new(hostile.into(), 1_700_000_000_000_000_000);
        record.host_syscalls =
            SyscallFootprint::from_events(0x42, &[ev(1, 0x42, hostile.as_bytes(), "sh\"comm")]);
        record.coverage = vec![
            AxisGap::HostSyscalls(hostile.into()),
            AxisGap::Network(hostile.into()),
            AxisGap::Cpu(hostile.into()),
        ];

        let json = record.to_json();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(
            parsed.is_ok(),
            "the record must be parseable JSON: {parsed:?}\n{json}"
        );
        let v = parsed.expect("checked just above");

        // Parsed, and the values survive the escaping: parseability alone would also be satisfied
        // by a writer that dropped every string it could not render.
        assert_eq!(v["subject"]["sandbox_id"], hostile);
        assert_eq!(v["host_syscalls"]["notable"][0]["detail"], hostile);
        assert_eq!(v["host_syscalls"]["notable"][0]["comm"], "sh\"comm");
        assert_eq!(v["coverage"][0]["axis"], "host_syscalls");
        assert_eq!(v["coverage"][0]["reason"], hostile);
        assert_eq!(v["network"]["flows"][0]["dst"], "1.1.1.1");
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
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing::new(Duration::ZERO, Duration::ZERO),
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

    #[test]
    fn the_posture_distinguishes_a_sealed_run_from_a_routed_one() {
        use crate::json::net_to_json;
        use crate::record::EgressPosture;
        use bsx_probes_common::{PolicyRule, PolicyRule6};

        // Two runs whose *observations* are identical: no traffic, no denials. Without the posture
        // field they render the same bytes, and a reader cannot tell a sandbox that reached
        // nothing from one that was allowed everything and simply stayed quiet.
        let quiet = || NetSection::from_tap(vec![], NetStats::default(), vec![], 0, 0);

        let sealed = quiet().with_posture(EgressPosture {
            enforcing: true,
            allowed: vec![],
            allowed6: vec![],
            gateway: None,
        });
        let routed = quiet().with_posture(EgressPosture {
            enforcing: true,
            // `0.0.0.0/0`, any port, any protocol: the widest rule expressible.
            allowed: vec![PolicyRule::allow(0, 0, 0, 0)],
            allowed6: vec![],
            gateway: Some(std::net::Ipv4Addr::new(10, 200, 0, 1)),
        });

        let render = |net: NetSection| {
            let mut out = String::new();
            net_to_json(&mut out, &net);
            out
        };
        let sealed = render(sealed);
        let routed = render(routed);
        assert_ne!(
            sealed, routed,
            "the whole point of the field: these two runs must not render identically"
        );

        assert!(
            sealed.contains("\"posture\":{\"enforcing\":true,\"gateway\":null,\"allowed\":[]"),
            "a sealed run names no route and no allowance: {sealed}"
        );
        assert!(
            routed.contains("\"gateway\":\"10.200.0.1\""),
            "a routed run names its gateway: {routed}"
        );
        // "any port" and "any protocol" are `0` in the kernel record and must not render as port 0
        // and protocol 0, which are real and much narrower claims.
        assert!(
            routed
                .contains("\"allowed\":[{\"dst\":\"0.0.0.0/0\",\"dst_port\":null,\"proto\":null}]"),
            "an allow-all rule renders its wildcards as null: {routed}"
        );

        // The v6 half renders in the same shape, and a named port/proto is not nulled.
        let v6 = render(quiet().with_posture(EgressPosture {
            enforcing: false,
            allowed: vec![PolicyRule::allow(0x0101_0101, 32, 53, 17)],
            allowed6: vec![PolicyRule6::allow([0xfd; 16], 64, 443, 6)],
            gateway: None,
        }));
        assert!(
            v6.contains("\"enforcing\":false"),
            "observe-only is stated, not inferred from a rule list: {v6}"
        );
        assert!(
            v6.contains("{\"dst\":\"1.1.1.1/32\",\"dst_port\":53,\"proto\":\"udp\"}"),
            "{v6}"
        );
        assert!(
            v6.contains(
                "\"allowed6\":[{\"dst\":\"fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd:fdfd/64\",\
                 \"dst_port\":443,\"proto\":\"tcp\"}]"
            ),
            "{v6}"
        );
    }

    #[test]
    fn a_record_says_what_it_is_about_and_when() {
        // A signature proves a record is authentic, never what it describes. Without a subject an
        // operator holding two records cannot tell which sandbox produced which, or place either on
        // a timeline, so a record that cannot be attributed cannot settle a dispute. Both fields are
        // inside the signed bytes, which is why this is pinned rather than left to the golden test:
        // the golden test would happily be updated to a record with no subject at all.
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-777-3".into(), 1_700_000_000_123_456_789),
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing::new(Duration::from_millis(1), Duration::from_millis(1)),
            vec![],
        );
        let json = record.to_json();
        assert!(
            json.contains(r#""sandbox_id":"bsx-777-3""#),
            "a record must name its sandbox: {json}"
        );
        assert!(
            json.contains(r#""started_unix_ns":1700000000123456789"#),
            "a record must say when the run started: {json}"
        );
    }

    #[test]
    fn an_unreadable_host_clock_is_an_unstamped_record_not_a_refused_run() {
        // Fail-open, the same posture as a coverage gap: a host whose clock cannot be read still
        // gets a record, stamped 0, which reads as "unstamped" rather than as the Unix epoch. The
        // alternative (refusing to record) would lose the observation entirely, which is worse.
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-777-4".into(), 0),
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing::new(Duration::from_millis(1), Duration::from_millis(1)),
            vec![],
        );
        assert!(record.to_json().contains(r#""started_unix_ns":0"#));
    }
}
