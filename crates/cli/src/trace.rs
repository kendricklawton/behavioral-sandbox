//! The human-readable audit trail (`agent run --trace`): a pretty rendering of the per-run
//! [`RunRecord`] for people at a terminal. The **machine** surface is the record's deterministic
//! JSON (`--record`, `RunRecord::to_json`); this rendering makes no stability promise beyond
//! being deterministic for the same record, parse the JSON, read this.
//!
//! Pure `record -> String`, so it is unit-tested host-safe against a golden.

use std::fmt::Write as _;
use std::time::Duration;

use agent_probes_loader::{AxisGap, RunRecord, Syscall};

/// How many notable host syscalls the trail prints before folding the rest into a count, the
/// record itself already caps and truncation-flags the full set; this is only about screen space.
const MAX_TRAIL_NOTABLE: usize = 10;

/// Render the run's audit trail. Deterministic (the record's collections are pre-sorted by their
/// builders; the one re-sort here, notable syscalls by hits, breaks ties on the record's own
/// order), multi-line, self-labeling: every axis says what it is, absence says why (coverage).
pub fn render(record: &RunRecord) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("audit trail (host-observed, from outside the guest)\n");
    let _ = writeln!(
        out,
        "  timing     boot {} · exec {}",
        human_duration(record.timing.boot),
        human_duration(record.timing.exec_wall)
    );

    match &record.network {
        None => out.push_str("  network    none (no NIC; boot with --net to observe traffic)\n"),
        Some(net) => {
            // Tap perspective: ingress is what the guest sent, egress what it received.
            let _ = writeln!(
                out,
                "  network    guest sent {} pkts / {} · received {} pkts / {}",
                net.totals.ingress_packets,
                human_bytes(net.totals.ingress_bytes),
                net.totals.egress_packets,
                human_bytes(net.totals.egress_bytes)
            );
            for flow in &net.flows {
                let _ = writeln!(
                    out,
                    "    flow     {} · sent {} pkts / {} · received {} pkts / {}",
                    flow.key,
                    flow.counts.ingress_packets,
                    human_bytes(flow.counts.ingress_bytes),
                    flow.counts.egress_packets,
                    human_bytes(flow.counts.egress_bytes)
                );
            }
            for denial in &net.denials {
                let d = denial.dst_addr.to_be_bytes();
                let _ = writeln!(
                    out,
                    "    denied   {}.{}.{}.{}:{} {} · {} packet(s) dropped by the egress policy",
                    d[0],
                    d[1],
                    d[2],
                    d[3],
                    denial.dst_port,
                    proto_name(denial.proto),
                    denial.count
                );
            }
            // The IPv6 half (ADR 008 dual-stack): the same lines for v6 flows/denials. `FlowKey6`'s
            // `Display` already renders `[v6]:port -> [v6]:port proto`.
            for flow in &net.flows6 {
                let _ = writeln!(
                    out,
                    "    flow     {} · sent {} pkts / {} · received {} pkts / {}",
                    flow.key,
                    flow.counts.ingress_packets,
                    human_bytes(flow.counts.ingress_bytes),
                    flow.counts.egress_packets,
                    human_bytes(flow.counts.egress_bytes)
                );
            }
            for denial in &net.denials6 {
                let _ = writeln!(
                    out,
                    "    denied   [{}]:{} {} · {} packet(s) dropped by the egress policy",
                    std::net::Ipv6Addr::from(denial.dst_addr),
                    denial.dst_port,
                    proto_name(denial.proto),
                    denial.count
                );
            }
        }
    }

    let res = &record.resources;
    let _ = writeln!(
        out,
        "  resources  cpu {} · mem {} (peak {}) · io read {} / written {}",
        human_duration(res.cpu_time),
        opt_bytes(res.cgroup.memory_current),
        opt_bytes(res.cgroup.memory_peak),
        opt_bytes(res.cgroup.io_rbytes),
        opt_bytes(res.cgroup.io_wbytes)
    );

    // No guest syscalls here is the isolation working; the printed label carries the explanation.
    let sys = &record.host_syscalls;
    let _ = writeln!(
        out,
        "  syscalls   {} total · execve {} · openat {} · connect {} · unknown {}   \
         (the VMM's host footprint, not the guest's)",
        sys.total, sys.by_kind.execve, sys.by_kind.openat, sys.by_kind.connect, sys.by_kind.unknown
    );
    let mut notable: Vec<_> = sys.notable.iter().collect();
    notable.sort_by_key(|n| std::cmp::Reverse(n.hits)); // stable sort: ties keep the record's order
    for n in notable.iter().take(MAX_TRAIL_NOTABLE) {
        let _ = writeln!(
            out,
            "    {:<8} {} ({}) x{}",
            syscall_name(n.kind),
            n.detail,
            n.comm,
            n.hits
        );
    }
    let folded = notable.len().saturating_sub(MAX_TRAIL_NOTABLE);
    if folded > 0 {
        let _ = writeln!(out, "    ... and {folded} more distinct (see --record)");
    }
    if sys.notable_truncated {
        let _ = writeln!(
            out,
            "    ({} event(s) past the notable cap are counted above but not itemized)",
            sys.overflow_events
        );
    }

    for gap in &record.coverage {
        // `AxisGap` is `#[non_exhaustive]`: a new observation axis renders as a generic gap line
        // here until this renderer learns its short label, never a compile break on a pin bump.
        let line = match gap {
            AxisGap::HostSyscalls(r) => format!("syscalls: {r}"),
            AxisGap::Network(r) => format!("network: {r}"),
            AxisGap::Cpu(r) => format!("cpu: {r}"),
            other => format!("{other:?}"),
        };
        let _ = writeln!(out, "  gap        {line}");
    }
    out
}

/// A duration for humans: adaptive unit, one place so the trail and the live view agree.
pub fn human_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        format!("{:.1} us", ns as f64 / 1e3)
    } else if ns < 1_000_000_000 {
        format!("{:.1} ms", ns as f64 / 1e6)
    } else {
        format!("{:.2} s", ns as f64 / 1e9)
    }
}

/// A byte count for humans: binary units, one decimal past KiB.
pub fn human_bytes(b: u64) -> String {
    const KIB: f64 = 1024.0;
    let bf = b as f64;
    if b < 1024 {
        format!("{b} B")
    } else if bf < KIB * KIB {
        format!("{:.1} KiB", bf / KIB)
    } else if bf < KIB * KIB * KIB {
        format!("{:.1} MiB", bf / (KIB * KIB))
    } else {
        format!("{:.1} GiB", bf / (KIB * KIB * KIB))
    }
}

/// An optional counter (a cgroup file this kernel may not have): the value, or an honest `n/a`,
/// never a fake zero.
fn opt_bytes(v: Option<u64>) -> String {
    v.map_or_else(|| "n/a".to_string(), human_bytes)
}

pub(crate) fn proto_name(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        _ => "proto?",
    }
}

pub(crate) fn syscall_name(kind: Syscall) -> &'static str {
    match kind {
        Syscall::Execve => "execve",
        Syscall::Openat => "openat",
        Syscall::Connect => "connect",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_probes_loader::{
        FlowCounts, FlowKey, FlowKey6, NetSection, NetStats, ResourceSummary, SyscallEvent,
        SyscallFootprint, Timing,
    };

    /// A synthetic event from public fields, as the loader's own unit tests build them.
    fn ev(syscall: u32, cgroup: u64, detail: &[u8], comm: &str) -> SyscallEvent {
        let mut d = [0u8; agent_probes_loader::DETAIL_CAP];
        let n = detail.len().min(d.len());
        d[..n].copy_from_slice(&detail[..n]);
        let mut c = [0u8; agent_probes_loader::COMM_CAP];
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

    fn sample() -> RunRecord {
        // The record types are `#[non_exhaustive]` (they grow), so fixtures build
        // default-then-assign rather than by struct literal.
        let mut totals = NetStats::default();
        totals.ingress_packets = 5;
        totals.ingress_bytes = 470;
        let flows = vec![(
            FlowKey::new(
                u32::from_be_bytes([10, 200, 0, 2]),
                u32::from_be_bytes([10, 200, 0, 1]),
                40000,
                9999,
                17,
            ),
            FlowCounts {
                ingress_packets: 5,
                ingress_bytes: 470,
                egress_packets: 0,
                egress_bytes: 0,
            },
        )];
        let denials = vec![(
            FlowKey::new(0, u32::from_be_bytes([9, 9, 9, 9]), 0, 443, 6),
            4,
        )];
        // A v6 flow + denial (ADR 008 dual-stack): `with_v6` folds the v6 counts into `totals`.
        let ula = |n: u8| {
            let mut a = [0u8; 16];
            a[0] = 0xfd;
            a[2] = 0x02;
            a[15] = n;
            a
        };
        let flows6 = vec![(
            FlowKey6::new(ula(2), ula(1), 40000, 9999, 17),
            FlowCounts {
                ingress_packets: 3,
                ingress_bytes: 300,
                egress_packets: 1,
                egress_bytes: 100,
            },
        )];
        let denials6 = vec![(FlowKey6::new(ula(2), ula(9), 55555, 443, 6), 4)];
        let mut resources = ResourceSummary::default();
        resources.cpu_time = Duration::from_micros(5200);
        resources.cgroup.cpu_usage_usec = Some(6);
        resources.cgroup.memory_current = Some(12 * 1024 * 1024);
        resources.cgroup.memory_peak = Some(14 * 1024 * 1024);
        resources.cgroup.io_wbytes = Some(512);
        RunRecord::from_parts(
            Some(NetSection::from_tap(flows, totals, denials, 0, 0).with_v6(flows6, denials6)),
            resources,
            SyscallFootprint::from_events(
                0x42,
                &[
                    ev(0, 0x42, b"/bin/sh", "sh"),
                    ev(1, 0x42, b"/etc/hosts", "sh"),
                    ev(1, 0x42, b"/etc/hosts", "sh"),
                ],
            ),
            Timing {
                boot: Duration::from_millis(120),
                exec_wall: Duration::from_millis(42),
            },
            vec![AxisGap::Cpu("meter lock poisoned".into())],
        )
    }

    #[test]
    fn trail_is_the_expected_golden_text() {
        let expected = "\
audit trail (host-observed, from outside the guest)
  timing     boot 120.0 ms · exec 42.0 ms
  network    guest sent 8 pkts / 770 B · received 1 pkts / 100 B
    flow     10.200.0.2:40000 -> 10.200.0.1:9999 udp · sent 5 pkts / 470 B · received 0 pkts / 0 B
    denied   9.9.9.9:443 tcp · 4 packet(s) dropped by the egress policy
    flow     [fd00:200::2]:40000 -> [fd00:200::1]:9999 udp · sent 3 pkts / 300 B · received 1 pkts / 100 B
    denied   [fd00:200::9]:443 tcp · 4 packet(s) dropped by the egress policy
  resources  cpu 5.2 ms · mem 12.0 MiB (peak 14.0 MiB) · io read n/a / written 512 B
  syscalls   3 total · execve 1 · openat 2 · connect 0 · unknown 0   (the VMM's host footprint, not the guest's)
    openat   /etc/hosts (sh) x2
    execve   /bin/sh (sh) x1
  gap        cpu: meter lock poisoned
";
        assert_eq!(render(&sample()), expected);
    }

    #[test]
    fn no_network_names_the_flag_that_enables_it() {
        let record = RunRecord::from_parts(
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing {
                boot: Duration::ZERO,
                exec_wall: Duration::ZERO,
            },
            vec![],
        );
        let text = render(&record);
        assert!(text.contains("no NIC"), "{text}");
        assert!(text.contains("--net"), "{text}");
    }

    #[test]
    fn humanizers_pick_sane_units() {
        assert_eq!(human_duration(Duration::from_nanos(999)), "999 ns");
        assert_eq!(human_duration(Duration::from_micros(42)), "42.0 us");
        assert_eq!(human_duration(Duration::from_millis(120)), "120.0 ms");
        assert_eq!(human_duration(Duration::from_secs(3)), "3.00 s");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(12 * 1024 * 1024), "12.0 MiB");
    }
}
