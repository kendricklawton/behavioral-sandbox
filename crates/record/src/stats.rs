//! The plain measurement values the record embeds: per-VM network totals and the per-run resource
//! summary. `bsx-probes-loader` produces them; they live here because the record's shape owns them,
//! and the two crates bridge only by plain values.

use std::path::Path;
use std::time::Duration;

/// Per-VM network **totals**: one sandbox's traffic summed across all its flows, from the tap's
/// perspective, so **ingress** is what the guest sent and **egress** what it received. The rollup
/// above `TapMonitor::flows`'s per-flow detail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetStats {
    /// Packets the guest sent (tap ingress), summed over flows.
    pub ingress_packets: u64,
    /// Bytes the guest sent, summed over flows.
    pub ingress_bytes: u64,
    /// Packets the guest received (tap egress), summed over flows.
    pub egress_packets: u64,
    /// Bytes the guest received, summed over flows.
    pub egress_bytes: u64,
}

/// A per-run **resource summary** for one sandbox: eBPF-measured CPU time plus the kernel's native
/// cgroup v2 memory/IO counters, assembled by `ResourceMeter::summary_for_pid` from a VMM pid.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceSummary {
    /// On-CPU time the VMM's cgroup accumulated while metered, from the scheduler tracepoint.
    /// [`Duration::ZERO`] if the cgroup was never a metered target.
    pub cpu_time: Duration,
    /// The cgroup's own cgroup v2 counters (memory, IO, and a cross-check on `cpu_time`).
    pub cgroup: CgroupStats,
}

/// A snapshot of a cgroup's **native cgroup v2** memory and IO counters, read from the cgroup dir's
/// files by [`read`](Self::read). Every field is best-effort: a missing or unparseable file is
/// [`None`], never an error, since accounting is a metering signal, not the isolation boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupStats {
    /// Total CPU time the kernel charged this cgroup, microseconds (`cpu.stat`'s `usage_usec`), an
    /// independent cross-check on `ResourceMeter::cpu_time`.
    pub cpu_usage_usec: Option<u64>,
    /// Current charged memory, bytes (`memory.current`).
    pub memory_current: Option<u64>,
    /// Peak charged memory, bytes (`memory.peak`), the high-water mark for a run. Absent on kernels
    /// before it landed (~5.19), hence [`Option`].
    pub memory_peak: Option<u64>,
    /// Bytes read, summed across every backing device (`io.stat`'s `rbytes=`).
    pub io_rbytes: Option<u64>,
    /// Bytes written, summed across every backing device (`io.stat`'s `wbytes=`).
    pub io_wbytes: Option<u64>,
}

impl CgroupStats {
    /// Reads the cgroup v2 counters from `cgroup_dir`, best-effort: a missing or unreadable file
    /// leaves its field [`None`], so a partial cgroup still yields what it has.
    #[must_use]
    pub fn read(cgroup_dir: &Path) -> Self {
        let read_u64 = |name: &str| {
            std::fs::read_to_string(cgroup_dir.join(name))
                .ok()
                .and_then(|s| parse_single_u64(&s))
        };
        let cpu_usage_usec = std::fs::read_to_string(cgroup_dir.join("cpu.stat"))
            .ok()
            .and_then(|s| parse_keyed_u64(&s, "usage_usec"));
        let (io_rbytes, io_wbytes) = std::fs::read_to_string(cgroup_dir.join("io.stat"))
            .ok()
            .map_or((None, None), |s| {
                let (r, w) = parse_io_bytes(&s);
                (Some(r), Some(w))
            });
        Self {
            cpu_usage_usec,
            memory_current: read_u64("memory.current"),
            memory_peak: read_u64("memory.peak"),
            io_rbytes,
            io_wbytes,
        }
    }
}

/// Parse a whole-file single unsigned integer (a `memory.current`/`memory.peak` body). A cgroup
/// `max` sentinel, or any other non-numeric body, is [`None`].
fn parse_single_u64(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// Parse the value on the `key <n>` line of a cgroup **flat-keyed** file (`cpu.stat` is
/// `usage_usec <n>`, `user_usec <n>`, …), matching the whole first token so a key that is a prefix
/// of another cannot false-match. Takes the text, so it is host-testable without a live cgroup fs.
fn parse_keyed_u64(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut it = line.split_whitespace();
        if it.next() == Some(key) {
            it.next()?.parse().ok()
        } else {
            None
        }
    })
}

/// Sum `rbytes=` and `wbytes=` across every device line of a cgroup `io.stat` file, returning
/// `(read_bytes, write_bytes)`. A device missing a field contributes 0, and the sums saturate, so a
/// pathological file cannot overflow the rollup.
fn parse_io_bytes(text: &str) -> (u64, u64) {
    let (mut r, mut w) = (0u64, 0u64);
    for line in text.lines() {
        for token in line.split_whitespace() {
            if let Some(v) = token
                .strip_prefix("rbytes=")
                .and_then(|n| n.parse::<u64>().ok())
            {
                r = r.saturating_add(v);
            } else if let Some(v) = token
                .strip_prefix("wbytes=")
                .and_then(|n| n.parse::<u64>().ok())
            {
                w = w.saturating_add(v);
            }
        }
    }
    (r, w)
}

#[cfg(test)]
mod tests {
    use bsx_test_support::ScratchDir;

    use super::*;

    #[test]
    fn cpu_stat_usage_usec_is_parsed_from_the_flat_keyed_file() {
        // The real `cpu.stat` shape: flat `key value` lines. We read `usage_usec` (total CPU).
        let cpu_stat = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n\
                        nr_periods 0\nnr_throttled 0\nthrottled_usec 0\n";
        assert_eq!(parse_keyed_u64(cpu_stat, "usage_usec"), Some(123_456));
        assert_eq!(parse_keyed_u64(cpu_stat, "system_usec"), Some(23_456));
        // A key that isn't present (a controller that didn't emit it) is None, not a wrong number.
        assert_eq!(parse_keyed_u64(cpu_stat, "nonesuch"), None);
        // A key present as a *substring* of another line's key must not false-match.
        assert_eq!(parse_keyed_u64("usage_usec_x 5\n", "usage_usec"), None);
    }

    #[test]
    fn memory_files_parse_a_single_integer_body() {
        assert_eq!(parse_single_u64("83886080\n"), Some(83_886_080));
        assert_eq!(parse_single_u64("0"), Some(0));
        // `memory.max` and friends can read "max", which is not a byte count, so the field stays absent.
        assert_eq!(parse_single_u64("max\n"), None);
        assert_eq!(parse_single_u64(""), None);
    }

    #[test]
    fn io_stat_sums_rbytes_and_wbytes_across_devices() {
        // Two backing devices, each with the full `key=value` set; we sum rbytes and wbytes.
        let io_stat = "8:0 rbytes=1000 wbytes=2000 rios=10 wios=20 dbytes=0 dios=0\n\
                       259:0 rbytes=500 wbytes=750 rios=5 wios=7 dbytes=0 dios=0\n";
        assert_eq!(parse_io_bytes(io_stat), (1500, 2750));
        // An empty (no IO yet) file is (0, 0), never a panic.
        assert_eq!(parse_io_bytes(""), (0, 0));
        // A device line missing wbytes contributes 0 for it, not a skipped read total.
        assert_eq!(parse_io_bytes("8:0 rbytes=42 rios=1\n"), (42, 0));
    }

    #[test]
    fn cgroup_stats_read_of_a_synthetic_dir_collects_present_files_and_tolerates_absent() {
        // A temp dir stands in for a cgroup dir: `read` collects the files that exist and
        // leaves the rest None (best-effort), never failing. No eBPF, no real cgroup, host-safe.
        let scratch = ScratchDir::created("cgstats");
        let dir = scratch.path();
        std::fs::write(dir.join("cpu.stat"), "usage_usec 777\nuser_usec 700\n").expect("cpu.stat");
        std::fs::write(dir.join("memory.current"), "4096\n").expect("memory.current");
        std::fs::write(
            dir.join("io.stat"),
            "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n",
        )
        .expect("io.stat");
        // memory.peak deliberately absent (older-kernel case).

        let stats = CgroupStats::read(dir);
        assert_eq!(stats.cpu_usage_usec, Some(777));
        assert_eq!(stats.memory_current, Some(4096));
        assert_eq!(
            stats.memory_peak, None,
            "absent file stays None, not an error"
        );
        assert_eq!(stats.io_rbytes, Some(10));
        assert_eq!(stats.io_wbytes, Some(20));

        // A wholly nonexistent dir yields the all-None default, still no error.
        assert_eq!(CgroupStats::read(&dir.join("gone")), CgroupStats::default());
    }
}
