//! Per-sandbox resource accounting: the shared `sched_switch` CPU meter and the cgroup v2
//! counters read alongside it.

use std::path::Path;
use std::time::Duration;

use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::TracePoint;
use aya::Ebpf;

use crate::{cgroup_dir_of_pid, cgroup_id_of_dir, check_support, load_object, ProbeError};

/// The `account_sched_switch` program's name (its `#[tracepoint] fn` symbol in `crates/probes`).
const PROG_SCHED_SWITCH: &str = "account_sched_switch";
/// The scheduler tracepoint it attaches to: category `sched`, event `sched_switch`.
const TP_SCHED: &str = "sched";
const TP_SCHED_SWITCH: &str = "sched_switch";
/// The per-cgroup on-CPU-nanoseconds map (`#[map] static CPU_NS`), keyed by cgroup id.
const CPU_NS_MAP: &str = "CPU_NS";
/// The set of cgroup ids to meter (`#[map] static METER_TARGETS`, `cgroup_id -> 1`); the loader
/// registers a sandbox's cgroup here so one shared program meters many sandboxes.
const METER_TARGETS_MAP: &str = "METER_TARGETS";
/// The meter-everything toggle (`#[map] static METER_ALL`), slot 0: `0` meters only the target set,
/// `1` meters every cgroup, the whole-host escape hatch, not the default.
const METER_ALL_MAP: &str = "METER_ALL";
/// The membership value stored for a registered target cgroup in `METER_TARGETS` (the set is a map, so
/// the value is a present/absent marker the kernel only tests for existence).
pub(crate) const TARGET_PRESENT: u8 = 1;

/// A loaded, attached **resource meter**: the `sched/sched_switch` tracepoint accumulates each
/// registered cgroup's on-CPU time into a map, which [`cpu_time`](Self::cpu_time) reads back per cgroup
/// id. This is the host CPU a sandbox's VMM burns running the guest vCPUs, attributed to the sandbox's
/// own cgroup, the metering primitive (the engine measures; the hoster bills). Owns the aya [`Ebpf`]
/// (the program, its maps, the live attachment) and pins nothing, so dropping it detaches cleanly like
/// the other loaders.
///
/// **One meter, many sandboxes.** `sched_switch` is a *global* tracepoint, so this attaches **once** and
/// meters a *set* of cgroups: [`add_target`](Self::add_target) registers a sandbox's cgroup,
/// [`remove_target`](Self::remove_target) unregisters it, and the hot path stays a single hash lookup no
/// matter how many sandboxes are metered (a program-per-sandbox would run every attached program on every
/// switch). Hold one `ResourceMeter` for the process and register each sandbox's cgroup id (what
/// [`crate::cgroup_id_of_pid`] resolves from its VMM pid).
///
/// **CPU here, memory/IO from cgroup v2.** CPU is where per-event timing earns its keep, so it rides
/// eBPF; a cgroup's memory high-water mark and IO bytes are already maintained by the kernel's native
/// cgroup v2 counters, read by [`CgroupStats::read`], the "or cgroup" half of the primitive.
/// [`summary_for_pid`](Self::summary_for_pid) rolls both into a [`ResourceSummary`] for one sandbox
/// (bridge a VMM pid → cgroup id **and** cgroup dir, then roll the summary).
#[must_use = "dropping a ResourceMeter detaches the accounting probe"]
pub struct ResourceMeter {
    ebpf: Ebpf,
}

impl ResourceMeter {
    /// Load the compiled object and load + attach the `account_sched_switch` tracepoint. From here every
    /// context switch charges the outgoing task's on-CPU time to its cgroup, **but only for registered
    /// cgroups**, so nothing accumulates until you [`add_target`](Self::add_target) a sandbox (or turn on
    /// [`meter_all`](Self::meter_all)). Attaching once and metering a set is what keeps this bounded under
    /// many concurrent sandboxes.
    ///
    /// # Errors
    /// [`ProbeError::Unsupported`] if the host can't load eBPF (BTF/caps, via [`check_support`]);
    /// [`ProbeError::Object`] if the object can't be read (build it: `cargo xtask build-probes`);
    /// [`ProbeError::Load`] if the kernel rejects the object/program; [`ProbeError::Attach`] if the
    /// tracepoint attach fails.
    pub fn load() -> Result<Self, ProbeError> {
        check_support()?;
        let mut ebpf = load_object()?;

        let program: &mut TracePoint = ebpf
            .program_mut(PROG_SCHED_SWITCH)
            .ok_or_else(|| {
                ProbeError::Load(format!("program `{PROG_SCHED_SWITCH}` not found in object"))
            })?
            .try_into()
            .map_err(|e| {
                ProbeError::Load(format!(
                    "program `{PROG_SCHED_SWITCH}` is not a tracepoint: {e}"
                ))
            })?;
        program
            .load()
            .map_err(|e| ProbeError::Load(format!("verify/load `{PROG_SCHED_SWITCH}`: {e}")))?;
        program.attach(TP_SCHED, TP_SCHED_SWITCH).map_err(|e| {
            ProbeError::Attach(format!(
                "attach `{PROG_SCHED_SWITCH}` to {TP_SCHED}/{TP_SCHED_SWITCH}: {e}"
            ))
        })?;

        Ok(Self { ebpf })
    }

    /// Register `cgroup_id` for metering: from here the tracepoint charges its on-CPU time into the
    /// `CPU_NS` map. The multi-sandbox path, register each sandbox's cgroup (via
    /// [`crate::cgroup_id_of_pid`]) with one shared meter, and the per-switch cost stays a single hash lookup
    ///. Idempotent (re-registering is harmless). Does **not** zero any prior total for this
    /// cgroup; [`reset`](Self::reset) does that if a caller wants a clean per-run baseline.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing or the write fails.
    pub fn add_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        self.targets()?
            .insert(cgroup_id, TARGET_PRESENT, 0)
            .map_err(|e| ProbeError::Map(format!("register cgroup {cgroup_id} for metering: {e}")))
    }

    /// Unregister `cgroup_id`: the tracepoint stops charging its time (the accumulated `CPU_NS` total
    /// stays readable for a final snapshot until [`reset`](Self::reset) or the meter is dropped).
    /// Removing a cgroup that was never a target is a no-op, not an error.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing, or the removal fails for a reason other than
    /// the key being absent.
    pub fn remove_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        match self.targets()?.remove(&cgroup_id) {
            Ok(()) => Ok(()),
            // Absent key (`bpf_map_delete_elem` → ENOENT): nothing to remove, so a no-op is the intended
            // outcome, don't turn "already gone" into a failure. Any *other* syscall error (a
            // permission/fd fault) still surfaces, so this only swallows the idempotent case.
            Err(aya::maps::MapError::SyscallError(e))
                if e.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Err(e) => Err(ProbeError::Map(format!(
                "unregister cgroup {cgroup_id}: {e}"
            ))),
        }
    }

    /// Zero the accumulated on-CPU total for `cgroup_id` (write a `0` entry), so a following
    /// [`cpu_time`](Self::cpu_time) measures only what accrues *after* this, the clean baseline for a
    /// per-run measurement. The kernel's accumulate path then adds onto the `0`. Independent of
    /// registration: reset before starting a run, read after.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the CPU map is missing or the write fails.
    pub fn reset(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .map_mut(CPU_NS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{CPU_NS_MAP}` not found")))?;
        let mut cpu: AyaHashMap<_, u64, u64> = AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{CPU_NS_MAP}` as a hash map: {e}")))?;
        cpu.insert(cgroup_id, 0, 0)
            .map_err(|e| ProbeError::Map(format!("reset cgroup {cgroup_id} CPU total: {e}")))
    }

    /// Delete `cgroup_id`'s `CPU_NS` row entirely (not just zero it like [`reset`](Self::reset)),
    /// freeing its slot in the fixed-capacity map. Called after a finished sandbox's final read so
    /// dead cgroups don't accumulate against `MAX_CGROUPS`: without it a long-lived meter fills the
    /// map, and once full the kernel's `CPU_NS.insert` for a *new* sandbox silently fails, so its
    /// `cpu_ns` reads back an indistinguishable `0` (a used-no-CPU lie) with no coverage gap.
    /// Removing a cgroup with no row is a no-op, not an error, mirroring
    /// [`remove_target`](Self::remove_target).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the CPU map is missing, or the removal fails for a reason other than
    /// the key being absent.
    pub fn clear(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .map_mut(CPU_NS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{CPU_NS_MAP}` not found")))?;
        let mut cpu: AyaHashMap<_, u64, u64> = AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{CPU_NS_MAP}` as a hash map: {e}")))?;
        match cpu.remove(&cgroup_id) {
            Ok(()) => Ok(()),
            // Absent key (ENOENT): the row was never created (the cgroup never ran), so a no-op is
            // the intended outcome, exactly as `remove_target` treats an already-gone target.
            Err(aya::maps::MapError::SyscallError(e))
                if e.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Err(e) => Err(ProbeError::Map(format!(
                "clear cgroup {cgroup_id} CPU total: {e}"
            ))),
        }
    }

    /// Turn the **meter-everything** toggle on or off. Off (the default) meters only the registered
    /// [`add_target`](Self::add_target) set, the multi-sandbox path. On meters every cgroup on the host
    /// (so `CPU_NS` grows toward one entry per live cgroup); the whole-host escape hatch for a snapshot or
    /// a test, not the per-sandbox path.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the toggle map is missing or the write fails.
    pub fn meter_all(&mut self, on: bool) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .map_mut(METER_ALL_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{METER_ALL_MAP}` not found")))?;
        let mut toggle: Array<_, u32> = Array::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{METER_ALL_MAP}` as an array: {e}")))?;
        toggle
            .set(0, u32::from(on), 0)
            .map_err(|e| ProbeError::Map(format!("write `{METER_ALL_MAP}`: {e}")))
    }

    /// The writable `METER_TARGETS` set handle, shared by [`add_target`](Self::add_target) /
    /// [`remove_target`](Self::remove_target).
    fn targets(&mut self) -> Result<AyaHashMap<&mut MapData, u64, u8>, ProbeError> {
        let map = self
            .ebpf
            .map_mut(METER_TARGETS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{METER_TARGETS_MAP}` not found")))?;
        AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{METER_TARGETS_MAP}` as a hash map: {e}")))
    }

    /// The accumulated on-CPU time charged to `cgroup_id` since [`load`](Self::load), as a [`Duration`].
    /// `Duration::ZERO` if the cgroup has no entry yet (never scheduled, or not the metered target). The
    /// nanosecond total the map holds, wrapped for the caller.
    ///
    /// **Charges post at switch-out.** A slice is charged when the task *leaves* its CPU (that is when
    /// `sched_switch` fires), so a task still running has its current slice pending, a pegged vCPU
    /// thread can hold a whole busy window un-posted until the guest idles and the thread blocks. For a
    /// run-scoped number, read after the workload has gone quiet (a brief settle after the exec
    /// returns); a mid-run read is a floor, not the total.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn cpu_time(&self, cgroup_id: u64) -> Result<Duration, ProbeError> {
        Ok(Duration::from_nanos(self.cpu_ns(cgroup_id)?))
    }

    /// The raw accumulated on-CPU **nanoseconds** for `cgroup_id` (0 if absent). A **keyed lookup**:
    /// aya 0.13 returns a typed `MapError::KeyNotFound`, so a missing key is an unambiguous `0` (never
    /// scheduled, or not the metered target) with no scan, distinct from a real read error. (Under
    /// `meter_all` the map can hold up to `MAX_CGROUPS` rows, which the old full scan walked every read.)
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or the read fails for a reason other than a missing key.
    pub fn cpu_ns(&self, cgroup_id: u64) -> Result<u64, ProbeError> {
        let map = self
            .ebpf
            .map(CPU_NS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{CPU_NS_MAP}` not found")))?;
        let cpu: AyaHashMap<_, u64, u64> = AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{CPU_NS_MAP}` as a hash map: {e}")))?;
        match cpu.get(&cgroup_id, 0) {
            Ok(ns) => Ok(ns),
            Err(aya::maps::MapError::KeyNotFound) => Ok(0),
            Err(e) => Err(ProbeError::Map(format!(
                "read `{CPU_NS_MAP}` for cgroup {cgroup_id}: {e}"
            ))),
        }
    }

    /// Every metered cgroup's on-CPU nanoseconds as `(cgroup_id, ns)` pairs (order unspecified), the
    /// meter-all view, for a whole-host snapshot or a test. A targeted meter yields a single pair.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn cpu_ns_all(&self) -> Result<Vec<(u64, u64)>, ProbeError> {
        let mut out = Vec::new();
        self.for_each_cpu(|id, ns| out.push((id, ns)))?;
        Ok(out)
    }

    /// Iterate the `CPU_NS` map, handing each `(cgroup_id, ns)` to `f`. The single map read
    /// [`cpu_ns`](Self::cpu_ns) and [`cpu_ns_all`](Self::cpu_ns_all) share. The key and value are plain
    /// `u64`s (aya's built-in `Pod`), so no `unsafe` map-type binding and no byte decode is needed.
    fn for_each_cpu(&self, mut f: impl FnMut(u64, u64)) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .map(CPU_NS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{CPU_NS_MAP}` not found")))?;
        let cpu: AyaHashMap<_, u64, u64> = AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{CPU_NS_MAP}` as a hash map: {e}")))?;
        for entry in cpu.iter() {
            let (id, ns) =
                entry.map_err(|e| ProbeError::Map(format!("iterate `{CPU_NS_MAP}`: {e}")))?;
            f(id, ns);
        }
        Ok(())
    }

    /// A whole [`ResourceSummary`] for the sandbox whose VMM is `pid`: resolve its cgroup
    /// once (id **and** dir, from `/proc/<pid>/cgroup`), read the eBPF CPU total for that cgroup id, and
    /// read the native cgroup v2 memory/IO counters from that cgroup dir. The per-run summary a caller
    /// ships alongside the run's [`RunResult`](https://docs.rs/vmm), the CPU figure is meaningful
    /// only if this cgroup was [`add_target`](Self::add_target)ed (or [`meter_all`](Self::meter_all) is on)
    /// while the run executed; the memory/IO figures are the kernel's regardless.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if `/proc/<pid>/cgroup` can't be read or has no unified (`0::`) line (a
    /// cgroup-v1-only host), the cgroup dir can't be stat'd for its id, or the CPU map read fails. The
    /// cgroup v2 file reads inside [`CgroupStats::read`] are best-effort and never fail the call.
    pub fn summary_for_pid(&self, pid: u32) -> Result<ResourceSummary, ProbeError> {
        let dir = cgroup_dir_of_pid(pid)?;
        let cgroup_id = cgroup_id_of_dir(&dir)?;
        Ok(ResourceSummary {
            cpu_time: self.cpu_time(cgroup_id)?,
            cgroup: CgroupStats::read(&dir),
        })
    }
}

/// A per-run **resource summary** for one sandbox: the eBPF-measured CPU time plus the kernel's
/// native cgroup v2 memory/IO counters, the two halves of the primitive rolled into one value a
/// caller ships with the run. Assembled by [`ResourceMeter::summary_for_pid`] from a VMM pid. The engine
/// *measures* this; folding it into the persisted per-run audit record (fused with the network denials
/// and the syscall trace) is the audit record's convergence, kept here, out of `vmm`, so the driver stays
/// independent of the eBPF loader (they bridge only by plain values).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceSummary {
    /// On-CPU time the VMM's cgroup accumulated while metered, the host CPU the sandbox burned running
    /// its guest, from the scheduler tracepoint (`ResourceMeter`). [`Duration::ZERO`] if the cgroup was
    /// never a metered target.
    pub cpu_time: Duration,
    /// The cgroup's native cgroup v2 counters (memory peak/current, IO bytes, and `cpu.stat`'s
    /// `usage_usec` as an independent cross-check on [`cpu_time`](Self::cpu_time)).
    pub cgroup: CgroupStats,
}

/// A snapshot of a cgroup's **native cgroup v2** resource counters, the memory and IO axes the
/// kernel already maintains per cgroup, read straight from the cgroup dir's files. The complement to
/// [`ResourceMeter`]'s eBPF CPU accounting: CPU rides a tracepoint (per-event timing earns its keep),
/// memory and IO ride the counters the kernel keeps anyway. Every field is best-effort, a missing or
/// unparseable file is [`None`], never an error, since accounting is a metering signal, not the
/// isolation boundary (it fails open, like the driver's cgroup caps).
///
/// Read one with [`read`](Self::read), pointed at the cgroup dir the Firecracker track placed the VMM in
/// (`<cgroup mount>/<path>`; the driver knows it and supplies it).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CgroupStats {
    /// Total CPU time the kernel charged this cgroup, microseconds (`cpu.stat`'s `usage_usec`). An
    /// independent cross-check on [`ResourceMeter::cpu_time`], from the scheduler's own accounting.
    pub cpu_usage_usec: Option<u64>,
    /// Current charged memory, bytes (`memory.current`).
    pub memory_current: Option<u64>,
    /// Peak charged memory, bytes (`memory.peak`), the high-water mark, the meaningful "how much did
    /// this run use" number. Absent on kernels before it landed (~5.19), hence [`Option`].
    pub memory_peak: Option<u64>,
    /// Bytes read, summed across every backing device (`io.stat`'s `rbytes=`).
    pub io_rbytes: Option<u64>,
    /// Bytes written, summed across every backing device (`io.stat`'s `wbytes=`).
    pub io_wbytes: Option<u64>,
}

impl CgroupStats {
    /// Read the cgroup v2 counters from `cgroup_dir` (e.g. `/sys/fs/cgroup/<path>`), best-effort: each
    /// missing or unreadable file leaves its field [`None`] rather than failing, so a partial cgroup
    /// (no `io` controller delegated, an older kernel without `memory.peak`) still yields what it has.
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

/// Parse a whole-file single unsigned integer (a `memory.current`/`memory.peak` body), trimming
/// trailing newline. A cgroup "max" sentinel (some files carry it) or any non-numeric body is [`None`].
fn parse_single_u64(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// Parse the value on the `key <n>` line of a cgroup **flat-keyed** file (`cpu.stat` is `usage_usec
/// <n>`, `user_usec <n>`, …). Finds the line whose first whitespace token equals `key` and parses the
/// second. Pure (takes the text) so it is host-unit-testable without a live cgroup fs.
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
/// `(read_bytes, write_bytes)`. Each line is `<maj>:<min> rbytes=<n> wbytes=<n> rios=<n> …`; a device
/// missing a field contributes 0 for it. Pure, so it is host-unit-testable. Saturating so a pathological
/// file can't overflow the rollup.
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
        // `memory.max` and friends can read "max"; that's not a byte count, so None (field stays absent).
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
        // Point `read` at a temp dir standing in for a cgroup dir: it collects the files that exist and
        // leaves the rest None (best-effort), never failing. No eBPF, no real cgroup, host-safe.
        let dir = std::env::temp_dir().join(format!(
            "ekvm-cgstats-{}-{}",
            std::process::id(),
            // vary by a fixed nonce; no clock/rng on the host path here, and one dir per test run is fine
            "t"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create synthetic cgroup dir");
        std::fs::write(dir.join("cpu.stat"), "usage_usec 777\nuser_usec 700\n").expect("cpu.stat");
        std::fs::write(dir.join("memory.current"), "4096\n").expect("memory.current");
        std::fs::write(
            dir.join("io.stat"),
            "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n",
        )
        .expect("io.stat");
        // memory.peak deliberately absent (older-kernel case).

        let stats = CgroupStats::read(&dir);
        assert_eq!(stats.cpu_usage_usec, Some(777));
        assert_eq!(stats.memory_current, Some(4096));
        assert_eq!(
            stats.memory_peak, None,
            "absent file stays None, not an error"
        );
        assert_eq!(stats.io_rbytes, Some(10));
        assert_eq!(stats.io_wbytes, Some(20));

        let _ = std::fs::remove_dir_all(&dir);

        // A wholly nonexistent dir yields the all-None default, still no error.
        assert_eq!(CgroupStats::read(&dir.join("gone")), CgroupStats::default());
    }
}
