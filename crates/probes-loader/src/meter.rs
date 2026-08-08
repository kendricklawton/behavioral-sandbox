//! Per-sandbox resource accounting: the shared `sched_switch` CPU meter and the cgroup v2
//! counters read alongside it.

use std::time::Duration;

use aya::Ebpf;
use aya::maps::{Array, HashMap as AyaHashMap, MapData};
use aya::programs::TracePoint;
use bsx_record::{CgroupStats, ResourceSummary};

use crate::{ProbeError, cgroup_dir_of_pid, cgroup_id_of_dir, check_support, load_object};

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
/// The membership value stored for a registered target cgroup in `METER_TARGETS`. The set is a map, so
/// the value is a present/absent marker the kernel only tests for existence).
pub(crate) const TARGET_PRESENT: u8 = 1;

/// A loaded, attached **resource meter**: the `sched/sched_switch` tracepoint accumulates each
/// registered cgroup's on-CPU time into a map, which [`cpu_time`](Self::cpu_time) reads back per cgroup id.
/// This is the host CPU a sandbox's VMM burns running the guest vCPUs, attributed to the sandbox's own
/// cgroup: the engine measures, the hoster bills. Owns the aya [`Ebpf`] and pins nothing, so dropping it
/// detaches cleanly like
/// the other loaders.
///
/// **One meter, many sandboxes.** `sched_switch` is a global tracepoint, so this attaches **once** and
/// meters a *set* of cgroups: [`add_target`](Self::add_target) registers a sandbox's cgroup,
/// [`remove_target`](Self::remove_target) unregisters it, and the hot path stays a single hash lookup no
/// matter how many are metered, where a program-per-sandbox would run every attached program on every
/// switch). Hold one `ResourceMeter` for the process and register each sandbox's cgroup id (what
/// [`crate::cgroup_id_of_pid`] resolves from its VMM pid).
///
/// **CPU here, memory and IO from cgroup v2.** CPU is where per-event timing earns its keep, so it rides
/// eBPF; a cgroup's memory high-water mark and IO bytes are already maintained by the kernel's native
/// cgroup v2 counters, read by [`CgroupStats::read`], the "or cgroup" half of the primitive.
/// [`summary_for_pid`](Self::summary_for_pid) rolls both into a [`ResourceSummary`] for one sandbox
/// (bridge a VMM pid → cgroup id **and** cgroup dir, then roll the summary).
#[must_use = "dropping a ResourceMeter detaches the accounting probe"]
pub struct ResourceMeter {
    ebpf: Ebpf,
}

impl ResourceMeter {
    /// Loads the compiled object and attaches the `account_sched_switch` tracepoint. From here every context
    /// switch charges the outgoing task's on-CPU time to its cgroup, **but only for registered cgroups**, so
    /// nothing accumulates until [`add_target`](Self::add_target) or [`meter_all`](Self::meter_all).
    /// Attaching once and metering a set is what keeps this bounded under
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
    /// [`crate::cgroup_id_of_pid`]) with one shared meter, and the per-switch cost stays a single
    /// hash lookup. Idempotent (re-registering is harmless). Does **not** zero any prior total for this
    /// cgroup; [`reset`](Self::reset) does that if a caller wants a clean per-run baseline.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing or the write fails.
    pub fn add_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        self.targets()?
            .insert(cgroup_id, TARGET_PRESENT, 0)
            .map_err(|e| ProbeError::Map(format!("register cgroup {cgroup_id} for metering: {e}")))
    }

    /// Unregisters `cgroup_id`, so the tracepoint stops charging its time. The accumulated `CPU_NS` total
    /// stays readable for a final snapshot until [`reset`](Self::reset) or the meter is dropped).
    /// Removing a cgroup that was never a target is a no-op, not an error.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing, or the removal fails for a reason other than
    /// the key being absent.
    pub fn remove_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        match self.targets()?.remove(&cgroup_id) {
            Ok(()) => Ok(()),
            // An absent key means nothing to remove, so a no-op is the intended
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
    /// [`add_target`](Self::add_target) set, the multi-sandbox path. On meters every cgroup on the host, so
    /// `CPU_NS` grows toward one entry per live cgroup: the whole-host escape hatch for a snapshot or
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

    /// The accumulated on-CPU time charged to `cgroup_id` since [`load`](Self::load). `Duration::ZERO` if
    /// the cgroup has no entry yet, whether never scheduled or not a metered target. The
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
    /// `meter_all` the map can hold up to `MAX_CGROUPS` rows, which a full scan would walk every
    /// read.)
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
    /// ships alongside the run's `RunResult` (no link: this crate is deliberately free of `bsx`,
    /// and nothing here is on docs.rs), the CPU figure is meaningful
    /// only if this cgroup was [`add_target`](Self::add_target)ed (or [`meter_all`](Self::meter_all) is on)
    /// while the run executed; the memory/IO figures are the kernel's regardless.
    ///
    /// # Errors
    /// [`ProbeError::Cgroup`] if the pid's cgroup can't be resolved (`/proc/<pid>/cgroup` unreadable
    /// or without a unified `0::` line on a cgroup-v1-only host, or the dir un-stat'able);
    /// [`ProbeError::Map`] if the CPU map read fails. The cgroup v2 file reads inside
    /// [`CgroupStats::read`] are best-effort and never fail the call.
    pub fn summary_for_pid(&self, pid: u32) -> Result<ResourceSummary, ProbeError> {
        let dir = cgroup_dir_of_pid(pid)?;
        let cgroup_id = cgroup_id_of_dir(&dir)?;
        // `ResourceSummary` is `#[non_exhaustive]` (defined in `bsx-record`), so it is built
        // through `Default` + field assignment rather than a struct literal.
        let mut summary = ResourceSummary::default();
        summary.cpu_time = self.cpu_time(cgroup_id)?;
        summary.cgroup = CgroupStats::read(&dir);
        Ok(summary)
    }
}
