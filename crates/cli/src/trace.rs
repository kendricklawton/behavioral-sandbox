//! The human-readable audit trail (`bsx run --trace`): a pretty rendering of the per-run
//! [`RunRecord`] for people at a terminal. The **machine** surface is the record's deterministic
//! JSON (`--record`, `RunRecord::to_json`); this rendering makes no stability promise beyond
//! being deterministic for the same record, parse the JSON, read this.
//!
//! Pure `record -> String`, so it is unit-tested host-safe against a golden.
//!
//! - **Terminal injection:** the notable-syscall lines carry `detail` and `comm`, decoded from bytes
//!   the probe captured, so they reach a terminal through [`printable`] rather than raw.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::time::Duration;

use bsx_probes_loader::{AxisGap, RunRecord};

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
                flow_line(&mut out, flow.key, &flow.counts);
            }
            for denial in &net.denials {
                let dst = std::net::Ipv4Addr::from(denial.dst_addr.to_be_bytes());
                denial_line(
                    &mut out,
                    format!("{}:{}", dst, denial.dst_port),
                    denial.proto,
                    denial.count,
                );
            }
            // The IPv6 half (dual-stack). `FlowKey6`'s `Display` already renders
            // `[v6]:port -> [v6]:port proto`.
            for flow in &net.flows6 {
                flow_line(&mut out, flow.key, &flow.counts);
            }
            for denial in &net.denials6 {
                let dst = std::net::Ipv6Addr::from(denial.dst_addr);
                denial_line(
                    &mut out,
                    format!("[{}]:{}", dst, denial.dst_port),
                    denial.proto,
                    denial.count,
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
            n.kind.name(),
            printable(&n.detail),
            printable(&n.comm),
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

/// Writes one flow line. The single writer for both address families, so the v4 and v6 halves of
/// the trail cannot drift apart.
fn flow_line(
    out: &mut String,
    key: impl std::fmt::Display,
    counts: &bsx_probes_loader::FlowCounts,
) {
    let _ = writeln!(
        out,
        "    flow     {key} · sent {} pkts / {} · received {} pkts / {}",
        counts.ingress_packets,
        human_bytes(counts.ingress_bytes),
        counts.egress_packets,
        human_bytes(counts.egress_bytes)
    );
}

/// Writes one denial line for a pre-rendered `addr:port` destination, the one part that differs
/// between the address families.
fn denial_line(out: &mut String, dst: impl std::fmt::Display, proto: u8, count: u64) {
    let _ = writeln!(
        out,
        "    denied   {dst} {} · {} packet(s) dropped by the egress policy",
        bsx_probes_loader::ProtoName(proto),
        count
    );
}

/// The 12 Unicode `Bidi_Control` code points, which reorder how the text around them renders.
/// [`char::is_control`] is category `Cc` only and returns `false` for every one of them, so a path or
/// `comm` carrying an override reorders the trail line around it (the Trojan-Source class). The twin
/// of `bsx_channel`'s predicate of the same name, which guards the other guest-authored string that
/// reaches this terminal; `the_terminal_escapers_agree_on_the_bidi_controls` pins the pair.
fn is_bidi_control(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// A probe-captured string made safe to write to a terminal: control and bidi-control characters are
/// escaped, so an `openat` path or a `comm` carrying ESC, CSI, or an RTL override cannot forge or
/// reorder lines in the audit trail. Borrowed when there is nothing to escape, which is every
/// ordinary path, since the live view renders this once per poll. Needs no length cap: `DETAIL_CAP`
/// and `COMM_CAP` bound these bytes at capture.
pub(crate) fn printable(s: &str) -> Cow<'_, str> {
    let needs_escape = |c: char| c.is_control() || is_bidi_control(c);
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if needs_escape(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bsx_probes_loader::RecordSubject;
    use bsx_probes_loader::{
        FlowCounts, FlowKey, FlowKey6, NetSection, NetStats, ResourceSummary, SyscallEvent,
        SyscallFootprint, Timing,
    };

    /// A synthetic event from public fields, from the shared builder so the renderer is exercised
    /// on the same bytes the record crate's own tests assert on.
    fn ev(syscall: u32, cgroup: u64, detail: &[u8], comm: &str) -> SyscallEvent {
        bsx_test_support::syscall_event(syscall, cgroup, detail, comm)
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
        // A v6 flow + denial (dual-stack): `with_v6` folds the v6 counts into `totals`.
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
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
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
            Timing::new(Duration::from_millis(120), Duration::from_millis(42)),
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
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            None,
            ResourceSummary::default(),
            SyscallFootprint::default(),
            Timing::new(Duration::ZERO, Duration::ZERO),
            vec![],
        );
        let text = render(&record);
        assert!(text.contains("no NIC"), "{text}");
        assert!(text.contains("--net"), "{text}");
    }

    #[test]
    fn printable_escapes_control_bytes_and_borrows_a_clean_path() {
        assert!(
            matches!(printable("/etc/hosts"), Cow::Borrowed(_)),
            "an ordinary path must not allocate; the live view renders these once per poll"
        );
        assert_eq!(printable("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(printable("a\x7fb"), "a\\u{7f}b", "DEL");
        // CSI in its 8-bit form: `char::is_control` covers C1, which a C0-only check would miss.
        assert_eq!(printable("a\u{9b}b"), "a\\u{9b}b");
        // The bidi controls are category `Cf`, so `is_control` alone passes them straight through and
        // a path carrying one reorders the trail line it lands in.
        assert_eq!(printable("a\u{202E}b"), "a\\u{202e}b", "RTL override");
        assert_eq!(printable("a\u{2066}b"), "a\\u{2066}b", "isolate");
        assert_eq!(printable("a\u{061C}b"), "a\\u{61c}b", "arabic letter mark");
    }

    #[test]
    fn a_hostile_path_cannot_forge_a_trail_line() {
        // The trail is an audit surface, so a captured path must not be able to write lines of its
        // own into it. The record keeps the bytes the probe saw; this renderer is what escapes them.
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            None,
            ResourceSummary::default(),
            SyscallFootprint::from_events(
                0x42,
                &[ev(1, 0x42, b"/tmp/\x1b]0;pwned\x07evil", "sh\x1b[2J")],
            ),
            Timing::new(Duration::ZERO, Duration::ZERO),
            vec![],
        );
        let text = render(&record);
        assert!(
            !text.contains('\x1b'),
            "no ESC reaches the terminal: {text:?}"
        );
        assert!(
            !text.contains('\x07'),
            "no BEL reaches the terminal: {text:?}"
        );
        assert_eq!(
            text.lines().count(),
            render(&{
                let mut clean = record.clone();
                clean.host_syscalls =
                    SyscallFootprint::from_events(0x42, &[ev(1, 0x42, b"/tmp/evil", "sh")]);
                clean
            })
            .lines()
            .count(),
            "the hostile detail must not add a line"
        );
        // Escaped, not swallowed: dropping the string would satisfy the assertions above too.
        assert!(text.contains("pwned"), "the text is kept, escaped: {text}");
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
