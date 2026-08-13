//! Per-sandbox resource accounting: the shared `sched_switch` CPU meter and the cgroup v2
//! counters read alongside it.

use std::time::Duration;

use aya::Ebpf;
use aya::maps::{HashMap as AyaHashMap, MapData};
use bsx_record::{CgroupStats, ResourceSummary};

use crate::maps::{add_cgroup_key, remove_cgroup_key};
use crate::tracer::per_cpu_sum;
use crate::{ProbeError, cgroup_dir_of_pid, cgroup_id_of_dir, check_support, load_object};

/// The `account_sched_switch` program's name (its `#[tracepoint] fn` symbol in `crates/probes`).
const PROG_SCHED_SWITCH: &str = "account_sched_switch";
/// The scheduler tracepoint it attaches to: category `sched`, event `sched_switch`.
const TP_SCHED: &str = "sched";
const TP_SCHED_SWITCH: &str = "sched_switch";
/// The per-cgroup on-CPU-nanoseconds map (`#[map] static CPU_NS`), keyed by cgroup id.
const CPU_NS_MAP: &str = "CPU_NS";
/// The per-CPU counter of cgroups a full `CPU_NS` dropped (`#[map] static CPU_DROPS`).
const CPU_DROPS_MAP: &str = "CPU_DROPS";
/// The set of cgroup ids to meter (`#[map] static METER_TARGETS`, `cgroup_id -> 1`).
const METER_TARGETS_MAP: &str = "METER_TARGETS";

/// A loaded, attached resource meter: the `sched/sched_switch` tracepoint accumulates each
/// registered cgroup's on-CPU time into a map that [`cpu_time`](Self::cpu_time) reads back per
/// cgroup id. Owns the aya [`Ebpf`] and pins nothing, so dropping it detaches.
///
/// `sched_switch` is a global tracepoint, so this attaches **once** and meters a *set* of cgroups
/// ([`add_target`](Self::add_target), keyed by what [`crate::cgroup_id_of_pid`] resolves from a VMM
/// pid), where a program-per-sandbox would run every attached program on every switch. Only CPU
/// rides eBPF: memory and IO come from the kernel's native cgroup v2 counters via
/// [`CgroupStats::read`], which [`summary_for_pid`](Self::summary_for_pid) rolls in alongside.
#[must_use = "dropping a ResourceMeter detaches the accounting probe"]
pub struct ResourceMeter {
    ebpf: Ebpf,
}

impl ResourceMeter {
    /// Loads the compiled object and attaches the `account_sched_switch` tracepoint. Nothing
    /// accumulates until [`add_target`](Self::add_target): every context switch charges the
    /// outgoing task's cgroup, but only a registered one.
    ///
    /// # Errors
    /// [`ProbeError::Unsupported`] if the host can't load eBPF (BTF/caps, via [`check_support`]);
    /// [`ProbeError::Object`] if the object can't be read (build it: `cargo xtask build-probes`);
    /// [`ProbeError::Load`] on a kernel reject; [`ProbeError::Attach`] if the attach fails.
    pub fn load() -> Result<Self, ProbeError> {
        check_support()?;
        let mut ebpf = load_object()?;

        crate::maps::attach_tracepoint(&mut ebpf, PROG_SCHED_SWITCH, TP_SCHED, TP_SCHED_SWITCH)?;

        Ok(Self { ebpf })
    }

    /// Registers `cgroup_id` for metering, so the tracepoint charges its on-CPU time into `CPU_NS`.
    /// Idempotent, and does **not** zero any prior total: [`reset`](Self::reset) does that.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing or the write fails.
    pub fn add_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        add_cgroup_key(
            &mut self.targets()?,
            cgroup_id,
            &format!("register cgroup {cgroup_id} for metering"),
        )
    }

    /// Unregisters `cgroup_id`, so the tracepoint stops charging its time. The accumulated `CPU_NS`
    /// total stays readable for a final snapshot, and removing a cgroup that was never a target is
    /// a no-op, not an error.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing, or the removal fails for a reason other
    /// than the key being absent.
    pub fn remove_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        remove_cgroup_key(
            &mut self.targets()?,
            cgroup_id,
            &format!("unregister cgroup {cgroup_id}"),
        )
    }

    /// Zeroes the accumulated on-CPU total for `cgroup_id`, so a following
    /// [`cpu_time`](Self::cpu_time) measures only what accrues after it. Independent of
    /// registration: reset before a run starts, read after.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the CPU map is missing or the write fails.
    pub fn reset(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        self.cpu_totals_mut()?
            .insert(cgroup_id, 0, 0)
            .map_err(|e| ProbeError::Map(format!("reset cgroup {cgroup_id} CPU total: {e}")))
    }

    /// Deletes `cgroup_id`'s `CPU_NS` row (rather than zeroing it like [`reset`](Self::reset)),
    /// freeing its slot in the fixed-capacity map: once dead cgroups have filled `MAX_CGROUPS`, a
    /// *new* sandbox's `insert` silently fails and its `cpu_ns` reads back an indistinguishable
    /// `0`. Removing a cgroup with no row is a no-op, not an error.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the CPU map is missing, or the removal fails for a reason other than
    /// the key being absent.
    pub fn clear(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        remove_cgroup_key(
            &mut self.cpu_totals_mut()?,
            cgroup_id,
            &format!("clear cgroup {cgroup_id} CPU total"),
        )
    }

    /// The writable `METER_TARGETS` set handle.
    fn targets(&mut self) -> Result<AyaHashMap<&mut MapData, u64, u8>, ProbeError> {
        crate::maps::open_mut(&mut self.ebpf, METER_TARGETS_MAP, "a hash map")
    }

    /// The read-only `CPU_NS` handle.
    fn cpu_totals(&self) -> Result<AyaHashMap<&MapData, u64, u64>, ProbeError> {
        crate::maps::open(&self.ebpf, CPU_NS_MAP, "a hash map")
    }

    /// The writable `CPU_NS` handle.
    fn cpu_totals_mut(&mut self) -> Result<AyaHashMap<&mut MapData, u64, u64>, ProbeError> {
        crate::maps::open_mut(&mut self.ebpf, CPU_NS_MAP, "a hash map")
    }

    /// The accumulated on-CPU time charged to `cgroup_id` since [`load`](Self::load),
    /// `Duration::ZERO` if the cgroup has no entry yet. **Charges post at switch-out**, when
    /// `sched_switch` fires, so a pegged vCPU thread holds a whole busy window un-posted until the
    /// guest idles: read after the workload goes quiet, because a mid-run read is a floor.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn cpu_time(&self, cgroup_id: u64) -> Result<Duration, ProbeError> {
        Ok(Duration::from_nanos(self.cpu_ns(cgroup_id)?))
    }

    /// The raw accumulated on-CPU **nanoseconds** for `cgroup_id` (0 if absent). A keyed lookup,
    /// not a scan: aya 0.13 returns a typed `MapError::KeyNotFound`, so a missing key is an
    /// unambiguous `0` distinct from a real read error.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or the read fails for a reason other than a missing key.
    pub fn cpu_ns(&self, cgroup_id: u64) -> Result<u64, ProbeError> {
        match self.cpu_totals()?.get(&cgroup_id, 0) {
            Ok(ns) => Ok(ns),
            Err(aya::maps::MapError::KeyNotFound) => Ok(0),
            Err(e) => Err(ProbeError::Map(format!(
                "read `{CPU_NS_MAP}` for cgroup {cgroup_id}: {e}"
            ))),
        }
    }

    /// Cgroups a full `CPU_NS` map could not admit, summed across CPUs: each is a cgroup whose
    /// on-CPU time went unaccounted, so its [`cpu_ns`](Self::cpu_ns) reads back `0` and cannot be
    /// told from a sandbox that used no CPU. Monotonic since [`load`](Self::load), so a nonzero
    /// delta around a run is a coverage gap; host-global, so the attribution is approximate.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the drop-counter map is missing or unreadable.
    pub fn dropped_cgroups(&self) -> Result<u64, ProbeError> {
        per_cpu_sum(&self.ebpf, CPU_DROPS_MAP)
    }

    /// Every metered cgroup's on-CPU nanoseconds as `(cgroup_id, ns)` pairs, order unspecified.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn cpu_ns_all(&self) -> Result<Vec<(u64, u64)>, ProbeError> {
        let mut out = Vec::new();
        self.for_each_cpu(|id, ns| out.push((id, ns)))?;
        Ok(out)
    }

    /// Iterates the `CPU_NS` map, handing each `(cgroup_id, ns)` to `f`. Key and value are plain
    /// `u64`s (aya's built-in `Pod`), so no `unsafe` map-type binding and no byte decode is needed.
    fn for_each_cpu(&self, mut f: impl FnMut(u64, u64)) -> Result<(), ProbeError> {
        for entry in self.cpu_totals()?.iter() {
            let (id, ns) =
                entry.map_err(|e| ProbeError::Map(format!("iterate `{CPU_NS_MAP}`: {e}")))?;
            f(id, ns);
        }
        Ok(())
    }

    /// A whole [`ResourceSummary`] for the sandbox whose VMM is `pid`: resolves its cgroup once (id
    /// **and** dir, from `/proc/<pid>/cgroup`), then reads the eBPF CPU total and the native cgroup
    /// v2 memory/IO counters. The CPU figure is meaningful only if this cgroup was
    /// [`add_target`](Self::add_target)ed while the run executed; the memory/IO figures are the
    /// kernel's regardless.
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
