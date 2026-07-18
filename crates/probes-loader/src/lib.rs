//! `agent-probes-loader`, the userspace side of the eBPF story: load and attach the probes from
//! `crates/probes`, read their maps, and stream events into the audit log. The first probe attaches the
//! one host-global `sys_enter_execve` tracepoint (scoped to nothing); binding a program to a
//! *specific* sandbox (its cgroup, its tap device) arrives with the per-VM taps.
//!
//! **Attach + read a map.** [`ExecveCounter`] loads the compiled BPF object, attaches the
//! `count_execve` tracepoint to `syscalls/sys_enter_execve`, and reads its per-CPU counter map,
//! summing the slots into one total. Synchronous by design: aya's load/attach/array-read path takes
//! no async runtime, matching the driver's no-background-threads posture. This counts the **host's**
//! `execve` footprint (a microVM's own syscalls never trap here), the introduction
//! that proves the load → attach → read → drop path before the tap monitor binds programs to real taps.
//!
//! **CO-RE and the verifier.** The object is built against BTF, so aya relocates it
//! against the running kernel at load (Compile Once, Run Everywhere, portable across kernels). The
//! program also keeps a per-PID hash map, surfaced here as
//! [`counts_by_pid`](ExecveCounter::counts_by_pid); its lookup-or-init and bounded-loop patterns are
//! the verifier rules the eBPF side hits on purpose.
//!
//! **Drops with the loader.** [`ExecveCounter`] owns the aya [`Ebpf`], whose `Drop`
//! detaches the program (dropping the link) and frees the map. Nothing is **pinned** into
//! `/sys/fs/bpf`, so there is no kernel residue to leak: a crashed loader leaves no dangling
//! attachment, the eBPF analogue of the driver's no-leak teardown. Pinning stays opt-in, added only
//! where a program must outlive its loader (not here).
//!
//! **A per-event syscall trace, filtered to one sandbox.** [`SyscallTracer`] loads the
//! same object but attaches the three `sys_enter_{execve,openat,connect}` tracepoints, each of which
//! streams a whole [`SyscallEvent`] (pid, tid, cgroup id, `comm`, and the path or sockaddr bytes) into
//! a **ring buffer** the tracer drains with [`drain`](SyscallTracer::drain). Where [`ExecveCounter`]
//! answers "how many", the tracer answers "which, by whom, on what". Point it at one Firecracker
//! worker with [`watch_pid`](SyscallTracer::watch_pid) /
//! [`watch_cgroup`](SyscallTracer::watch_cgroup) so it records that sandbox's host footprint and not
//! the whole machine's. Still the host's footprint, not the guest's (a microVM's syscalls stay
//! in-guest).
//!
//! **A live trace, attributed to a sandbox.** [`stream`](SyscallTracer::stream) is the
//! streaming consumer: it loops, decoding each event with [`SyscallEvent::describe`] and handing it to
//! a callback as it arrives, until a caller predicate says stop. [`cgroup_id_of_pid`] closes the loop
//! with the Firecracker track: hand it a sandbox's VMM pid, `watch_cgroup` the id it returns, and the
//! trace is scoped to exactly that sandbox (the `bpf_get_current_cgroup_id` a program reads equals the
//! inode of the cgroup dir the jailer placed the VMM in).
//!
//! **Network flows on the tap.** [`TapMonitor`] attaches the two `tc`/clsact classifiers
//! (`tap_ingress`/`tap_egress`) to a VM's tap and reads their per-flow byte/packet counters with
//! [`flows`](TapMonitor::flows), or the per-VM rollup with [`totals`](TapMonitor::totals). This
//! is the guest's *own* traffic (every packet crosses the tap on the host), the strong cross-boundary
//! signal syscalls can't be. [`attach_in_netns`](TapMonitor::attach_in_netns) binds the *specific* tap
//! the driver named for one sandbox by entering that sandbox's netns (decision 017/024);
//! [`attach`](TapMonitor::attach) takes an interface in the current netns.
//!
//! **Egress enforcement.** [`set_egress_policy`](TapMonitor::set_egress_policy) installs an
//! [`EgressPolicy`] (a deny-by-default allow-list of destination CIDRs + optional port/proto) into the
//! classifier's policy map and arms enforcement, so the tap drops any guest-sent packet that matches no
//! rule and accepts those that do, per VM. It is opt-in: until set, a monitor stays observe-only (the
//! observe-only default); [`clear_egress_policy`](TapMonitor::clear_egress_policy) returns it there. Every
//! drop is recorded per destination; [`denials`](TapMonitor::denials) reads that audit trail.
//!
//! **Policy at launch, deny-by-default.** [`EgressPolicy`] is the userspace schema, built
//! from validated [`Ipv4Cidr`]s with a typed [`Protocol`] and optional port (`None` = any), whose empty
//! value ([`EgressPolicy::deny_all`], the
//! [`Default`]) allows nothing, a sandbox launched with no explicit allowance reaches nothing.
//! [`enforce_in_netns`](TapMonitor::enforce_in_netns) applies a policy *before* the tc programs go live
//! on a sandbox's tap, so there is no window where the tap is up but un-policed: enforcement is in effect
//! from the first packet.
//!
//! **Per-sandbox resource accounting.** [`ResourceMeter`] attaches the
//! `sched/sched_switch` tracepoint **once** and meters a *set* of cgroups
//! ([`add_target`](ResourceMeter::add_target) per sandbox), so one program stays cheap under many
//! sandboxes; [`cpu_time`](ResourceMeter::cpu_time) reads a cgroup's accumulated on-CPU time. That is the
//! CPU axis; a cgroup's memory high-water mark and IO bytes come from the kernel's own cgroup v2 counters
//! via [`CgroupStats::read`]. [`cgroup_id_of_pid`]/[`cgroup_dir_of_pid`] bridge a VMM pid to the cgroup id
//! (for the meter) and dir (for the stats), and [`summary_for_pid`](ResourceMeter::summary_for_pid) rolls
//! all three axes into a [`ResourceSummary`] for one sandbox. The engine *measures*, the hoster *bills*.
//!
//! **Caps + a legible support probe.** Loading needs only `CAP_BPF`+`CAP_PERFMON`, not
//! full root; [`check_support`] names a missing prerequisite (kernel BTF, or those caps) up front as a
//! typed [`ProbeError::Unsupported`], so a host that can't run the probes says so plainly instead of
//! failing with a cryptic verifier reject or `EPERM` (the eBPF analogue of the driver's dependency
//! guards).
#![forbid(unsafe_code)]

use std::fs::File;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType, TracePoint};
use aya::Ebpf;

pub use agent_probes_common::{
    FlowCounts, FlowKey, PolicyRule, Protocol, Syscall, SyscallEvent, COMM_CAP, DETAIL_CAP,
    MAX_POLICY_RULES,
};
use agent_probes_common::{FLOW_COUNTS_SIZE, FLOW_KEY_SIZE, POLICY_RULE_SIZE};

/// Deterministic JSON of the record: the machine-readable audit surface, byte-stable and
/// dependency-free (`RunRecord::to_json`). Pure, unit-tested host-safe against a golden.
mod json;
/// The attach bundle: bind the three probes to one sandbox at launch (shared tracer +
/// shared meter, per-VM tap) and roll up a record; detach + finalize on close.
mod observer;
/// The per-run audit record: the fused, deterministically-ordered view of what one run did,
/// aggregated from the three probes. Pure (no aya), so its whole aggregation is unit-tested host-safe.
mod record;
/// The model-legible projection of the record (`RunRecord::to_summary_json`): the compact, third face
/// for an agent's observe→act loop. A pure view of the record (decision 035), golden-tested host-safe.
mod summary;

pub use json::AUDIT_SCHEMA_VERSION;
pub use observer::{LiveSnapshot, SandboxProbes, SharedMeter, SharedTracer};
pub use record::{
    AxisGap, DenialRecord, FlowRecord, NetSection, NotableSyscall, RunRecord, SyscallCounts,
    SyscallFold, SyscallFootprint, Timing, MAX_NOTABLE,
};
pub use summary::SUMMARY_SCHEMA_VERSION;

/// Env override for the compiled BPF object's location, for a vendored / installed deployment where
/// the object doesn't sit in the source tree's `target/`. Defaults to the `cargo xtask build-probes`
/// output (see [`object_path`]).
const OBJECT_ENV: &str = "AGENT_PROBES_OBJECT";

/// The tracepoint program's name (its ELF section symbol, set by `#[tracepoint] fn count_execve`).
const PROGRAM: &str = "count_execve";
/// The per-CPU counter map's name (the `#[map] static EXECVE_COUNT` symbol).
const MAP: &str = "EXECVE_COUNT";
/// The per-PID hash map's name (the `#[map] static EXECVE_BY_PID` symbol).
const MAP_BY_PID: &str = "EXECVE_BY_PID";
/// The tracepoint the program attaches to: category `syscalls`, event `sys_enter_execve`.
const TP_CATEGORY: &str = "syscalls";
const TP_NAME: &str = "sys_enter_execve";

/// A typed failure from loading/attaching/reading the probes, the loader's analogue of the driver's
/// `VmmError`: a missing prerequisite, a missing object, a kernel load/verify/permission failure, an
/// attach failure, or a map read failure is a typed `Err`, never a panic (the host path never panics).
#[derive(Debug)]
pub enum ProbeError {
    /// The host can't load eBPF at all: a missing prerequisite named up front (no kernel BTF, or the
    /// `CAP_BPF`/`CAP_PERFMON` capabilities), caught by [`check_support`] *before* a load so it reads
    /// legibly instead of surfacing as a cryptic verifier reject or `EPERM`.
    Unsupported(String),
    /// The compiled BPF object couldn't be found or read (build it with `cargo xtask build-probes`).
    Object(String),
    /// Loading/verifying the object or a program into the kernel failed, a verifier reject or a
    /// kernel-feature gap the up-front [`check_support`] didn't catch.
    Load(String),
    /// Attaching a loaded program to its kernel hook failed.
    Attach(String),
    /// Reading a program's map failed.
    Map(String),
    /// The egress policy the caller asked to install is invalid (e.g. more rules than the map holds),
    /// a caller-input error, distinct from a map I/O failure. See [`PolicyError`].
    Policy(PolicyError),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(e) => write!(f, "eBPF unsupported here: {e}"),
            Self::Object(e) => write!(f, "eBPF object unavailable: {e}"),
            Self::Load(e) => write!(f, "eBPF load failed: {e}"),
            Self::Attach(e) => write!(f, "eBPF attach failed: {e}"),
            Self::Map(e) => write!(f, "eBPF map read failed: {e}"),
            Self::Policy(e) => write!(f, "invalid egress policy: {e}"),
        }
    }
}

impl From<PolicyError> for ProbeError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

/// A rejected egress-policy input, caught by construction (`parse, don't validate`) so an illegal policy
/// can't reach the kernel map: an out-of-range CIDR prefix, or more rules than the map holds. Distinct
/// from [`ProbeError`]'s eBPF-runtime failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// An IPv4 CIDR prefix length over 32 (the given value), rejected by [`Ipv4Cidr::new`].
    PrefixTooLong(u8),
    /// More allow-rules than the kernel `POLICY` map holds: the requested count and the cap.
    TooManyRules {
        /// The number of rules the caller supplied.
        got: usize,
        /// The fixed cap ([`MAX_POLICY_RULES`]).
        max: usize,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrefixTooLong(len) => {
                write!(f, "IPv4 CIDR prefix length {len} is over the /32 maximum")
            }
            Self::TooManyRules { got, max } => {
                write!(f, "egress policy has {got} rules, over the {max}-rule cap")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl std::error::Error for ProbeError {}

/// A loaded, attached `sys_enter_execve` counter. Holds the aya [`Ebpf`] that owns the
/// program, its map, and the live attachment; dropping this detaches and frees them, pinning nothing
///. Read the running total with [`count`](ExecveCounter::count).
#[must_use = "dropping an ExecveCounter detaches the probe"]
pub struct ExecveCounter {
    ebpf: Ebpf,
}

impl ExecveCounter {
    /// Load the compiled object, load + attach the `count_execve` tracepoint, and return the live
    /// counter. From here every host `execve` bumps the per-CPU map until this value is dropped.
    ///
    /// # Errors
    /// [`ProbeError::Object`] if the object can't be read (build it: `cargo xtask build-probes`);
    /// [`ProbeError::Load`] if the kernel rejects the object/program (no `CAP_BPF`, no BTF, or a
    /// verifier reject); [`ProbeError::Attach`] if the tracepoint attach fails.
    pub fn load() -> Result<Self, ProbeError> {
        // Name the missing prerequisite up front: no kernel BTF, or no CAP_BPF/CAP_PERFMON, is
        // a legible `Unsupported` error here rather than a cryptic verifier reject / `EPERM` below.
        check_support()?;
        let path = object_path();
        let bytes = std::fs::read(&path).map_err(|e| {
            ProbeError::Object(format!(
                "read BPF object {}: {e} (build it with `cargo xtask build-probes`)",
                path.display()
            ))
        })?;
        // `Ebpf::load` parses the ELF and creates the maps in the kernel (needs CAP_BPF); the program
        // is loaded (verified) and attached below. All of it is owned by `ebpf` and torn down on drop.
        let mut ebpf =
            Ebpf::load(&bytes).map_err(|e| ProbeError::Load(format!("load object: {e}")))?;

        let program: &mut TracePoint = ebpf
            .program_mut(PROGRAM)
            .ok_or_else(|| ProbeError::Load(format!("program `{PROGRAM}` not found in object")))?
            .try_into()
            .map_err(|e| {
                ProbeError::Load(format!("program `{PROGRAM}` is not a tracepoint: {e}"))
            })?;
        program
            .load()
            .map_err(|e| ProbeError::Load(format!("verify/load `{PROGRAM}`: {e}")))?;
        program.attach(TP_CATEGORY, TP_NAME).map_err(|e| {
            ProbeError::Attach(format!(
                "attach `{PROGRAM}` to {TP_CATEGORY}/{TP_NAME}: {e}"
            ))
        })?;

        Ok(Self { ebpf })
    }

    /// The running total of `sys_enter_execve` events since [`load`](ExecveCounter::load), summed
    /// across CPUs (the map is per-CPU, so each CPU's slot is read and added).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the counter map is missing or unreadable.
    pub fn count(&self) -> Result<u64, ProbeError> {
        let map = self
            .ebpf
            .map(MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{MAP}` not found")))?;
        let counter: PerCpuArray<_, u64> = PerCpuArray::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{MAP}` as a per-cpu array: {e}")))?;
        let per_cpu = counter
            .get(&0, 0)
            .map_err(|e| ProbeError::Map(format!("read `{MAP}`[0]: {e}")))?;
        Ok(per_cpu.iter().copied().sum())
    }

    /// The per-PID `execve` counts as `(pid, count)` pairs, read from the `EXECVE_BY_PID` hash map
    ///. Order is unspecified (hash-map iteration); the [`count`](ExecveCounter::count) total is
    /// authoritative, since the per-PID map is bounded and drops new keys when full.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn counts_by_pid(&self) -> Result<Vec<(u32, u64)>, ProbeError> {
        let map = self
            .ebpf
            .map(MAP_BY_PID)
            .ok_or_else(|| ProbeError::Map(format!("map `{MAP_BY_PID}` not found")))?;
        let by_pid: AyaHashMap<_, u32, u64> = AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{MAP_BY_PID}` as a hash map: {e}")))?;
        let mut out = Vec::new();
        for entry in by_pid.iter() {
            let (pid, count) =
                entry.map_err(|e| ProbeError::Map(format!("iterate `{MAP_BY_PID}`: {e}")))?;
            out.push((pid, count));
        }
        Ok(out)
    }
}

/// The tracepoint programs the syscall tracer attaches, paired with the `syscalls` event each hooks.
/// One entry per `sys_enter_*` of interest; the program names are the `#[tracepoint] fn` symbols in
/// `crates/probes`.
const TRACERS: [(&str, &str); 3] = [
    ("trace_execve", "sys_enter_execve"),
    ("trace_openat", "sys_enter_openat"),
    ("trace_connect", "sys_enter_connect"),
];
/// The `syscalls` tracepoint category all of [`TRACERS`] live under.
const TP_SYSCALLS: &str = "syscalls";
/// The ring buffer the programs stream [`SyscallEvent`]s into (`#[map] static EVENTS`).
const EVENTS_MAP: &str = "EVENTS";
/// The target filter the programs consult (`#[map] static FILTER`): slot 0 tgid, slot 1 cgroup id.
const FILTER_MAP: &str = "FILTER";
const FILTER_TGID: u32 = 0;
const FILTER_CGROUP: u32 = 1;
/// The shared tracer's cgroup target *set* (`#[map] static TRACE_TARGETS`), the analogue of
/// [`METER_TARGETS_MAP`].
const TRACE_TARGETS_MAP: &str = "TRACE_TARGETS";
/// The filter-mode toggle (`#[map] static TRACE_SET`, slot 0): `0` = single [`FILTER_MAP`], `1` = the
/// [`TRACE_TARGETS_MAP`] set.
const TRACE_SET_MAP: &str = "TRACE_SET";
const FILTER_MODE_SLOT: u32 = 0;
/// The per-CPU counter of events a full ring buffer dropped (`#[map] static EVENT_DROPS`), read by
/// [`SyscallTracer::dropped_events`] so best-effort loss is reported, never silent.
const EVENT_DROPS_MAP: &str = "EVENT_DROPS";

/// A loaded, attached syscall tracer: the `sys_enter_{execve,openat,connect}` tracepoints
/// stream per-event [`SyscallEvent`]s into a ring buffer that [`drain`](Self::drain) reads. Owns the
/// aya [`Ebpf`] (programs, maps, live attachments); dropping it detaches everything and pins nothing,
/// like [`ExecveCounter`]. Narrow the stream to one sandbox with [`watch_pid`](Self::watch_pid) /
/// [`watch_cgroup`](Self::watch_cgroup); the default (nothing set) observes the whole host.
#[must_use = "dropping a SyscallTracer detaches the probes"]
pub struct SyscallTracer {
    ebpf: Ebpf,
    /// The ring-buffer consumer, built **once** at load and reused by every [`drain`](Self::drain).
    /// This is load-bearing, not an optimization: aya tracks the consumer position and a producer-
    /// position cache *inside* this value, so a fresh `RingBuf` per drain (its cache reset to 0 while
    /// the kernel-side consumer offset is already advanced) would defeat the "caught up?" check and
    /// spin forever. Its `MapData` owns the map fd, taken out of `ebpf`; the attached programs keep
    /// writing to the same kernel map.
    events: RingBuf<MapData>,
}

impl SyscallTracer {
    /// Load the compiled object and load + attach all three `sys_enter_*` tracepoints. From here every
    /// matching host syscall that passes the filter is streamed into the ring buffer until this is
    /// dropped. Attaches unfiltered; call a `watch_*` before or after to narrow it.
    ///
    /// # Errors
    /// [`ProbeError::Unsupported`] if the host can't load eBPF (BTF/caps, via [`check_support`]);
    /// [`ProbeError::Object`] if the object can't be read (build it: `cargo xtask build-probes`);
    /// [`ProbeError::Load`] if the kernel rejects the object/a program; [`ProbeError::Attach`] if a
    /// tracepoint attach fails.
    pub fn load() -> Result<Self, ProbeError> {
        check_support()?;
        let path = object_path();
        let bytes = std::fs::read(&path).map_err(|e| {
            ProbeError::Object(format!(
                "read BPF object {}: {e} (build it with `cargo xtask build-probes`)",
                path.display()
            ))
        })?;
        let mut ebpf =
            Ebpf::load(&bytes).map_err(|e| ProbeError::Load(format!("load object: {e}")))?;

        for (program, event) in TRACERS {
            let tp: &mut TracePoint = ebpf
                .program_mut(program)
                .ok_or_else(|| {
                    ProbeError::Load(format!("program `{program}` not found in object"))
                })?
                .try_into()
                .map_err(|e| {
                    ProbeError::Load(format!("program `{program}` is not a tracepoint: {e}"))
                })?;
            tp.load()
                .map_err(|e| ProbeError::Load(format!("verify/load `{program}`: {e}")))?;
            tp.attach(TP_SYSCALLS, event).map_err(|e| {
                ProbeError::Attach(format!("attach `{program}` to {TP_SYSCALLS}/{event}: {e}"))
            })?;
        }

        // Build the ring-buffer consumer once (see the field doc). `take_map` moves the map's owned
        // handle out of `ebpf`; the kernel map stays alive (this `RingBuf` holds its fd) and the
        // attached programs keep writing to it. `FILTER` stays in `ebpf` for the `watch_*` setters.
        let events_map = ebpf
            .take_map(EVENTS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{EVENTS_MAP}` not found")))?;
        let events = RingBuf::try_from(events_map)
            .map_err(|e| ProbeError::Map(format!("open `{EVENTS_MAP}` as a ring buffer: {e}")))?;

        Ok(Self { ebpf, events })
    }

    /// Watch only the process tree with this **tgid** (the userspace pid): the programs drop events
    /// from any other tgid. Pass `0` to stop filtering on tgid. Composes with
    /// [`watch_cgroup`](Self::watch_cgroup) (both configured axes must match). **Selects single-filter
    /// mode**: like every `watch_*`, this switches the tracer off the [`add_target`](Self::add_target)
    /// set if it was on, so the two filter models can't half-apply (the mode always matches the last
    /// setter used).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the filter/mode map is missing or unwritable.
    pub fn watch_pid(&mut self, pid: u32) -> Result<(), ProbeError> {
        self.set_mode(false)?;
        self.set_filter(FILTER_TGID, u64::from(pid))
    }

    /// Watch only the process in this **cgroup id** (`bpf_get_current_cgroup_id`): the axis a
    /// sandbox's host workers are attributed on. Pass `0` to stop filtering on cgroup. Selects
    /// single-filter mode (see [`watch_pid`](Self::watch_pid)).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the filter/mode map is missing or unwritable.
    pub fn watch_cgroup(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        self.set_mode(false)?;
        self.set_filter(FILTER_CGROUP, cgroup_id)
    }

    /// Clear both filter axes: observe every process on the host again (the load-time default).
    /// Selects single-filter mode (see [`watch_pid`](Self::watch_pid)).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the filter/mode map is missing or unwritable.
    pub fn watch_all(&mut self) -> Result<(), ProbeError> {
        self.set_mode(false)?;
        self.set_filter(FILTER_TGID, 0)?;
        self.set_filter(FILTER_CGROUP, 0)
    }

    /// Switch to **set mode**: the tracepoints now pass an event iff its cgroup is a registered
    /// [`add_target`](Self::add_target) member, ignoring the single-target [`watch_pid`](Self::watch_pid)
    /// / [`watch_cgroup`](Self::watch_cgroup) filter. This is what the shared multi-sandbox tracer
    /// ([`SharedTracer`]) drives; a single-sandbox caller stays on the default `FILTER` path and never
    /// calls this. Symmetric with the `watch_*` setters, which switch back, the mode always matches
    /// the last setter used, so neither filter model can silently no-op. Idempotent.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the mode map is missing or unwritable.
    pub fn use_target_set(&mut self) -> Result<(), ProbeError> {
        self.set_mode(true)
    }

    /// Events the kernel **dropped** because the ring buffer was full, summed across CPUs, the
    /// best-effort loss made visible. A monotonic counter since [`load`](Self::load); callers snapshot
    /// it around a window and report a nonzero delta (the audit bundle turns one into a coverage gap).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the drop-counter map is missing or unreadable.
    pub fn dropped_events(&self) -> Result<u64, ProbeError> {
        let map = self
            .ebpf
            .map(EVENT_DROPS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{EVENT_DROPS_MAP}` not found")))?;
        let drops: PerCpuArray<_, u64> = PerCpuArray::try_from(map).map_err(|e| {
            ProbeError::Map(format!("open `{EVENT_DROPS_MAP}` as a per-cpu array: {e}"))
        })?;
        let per_cpu = drops
            .get(&0, 0)
            .map_err(|e| ProbeError::Map(format!("read `{EVENT_DROPS_MAP}`[0]: {e}")))?;
        Ok(per_cpu.iter().copied().sum())
    }

    /// Register `cgroup_id` in the trace target *set* and switch to set mode if not already, so from
    /// here the tracepoints emit that sandbox's host syscalls. The multi-sandbox path: one shared
    /// tracer, every sandbox's cgroup registered, the per-syscall cost a single hash lookup. Idempotent.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target/mode map is missing or the write fails.
    pub fn add_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        self.set_mode(true)?;
        self.trace_targets()?
            .insert(cgroup_id, TARGET_PRESENT, 0)
            .map_err(|e| ProbeError::Map(format!("register cgroup {cgroup_id} for tracing: {e}")))
    }

    /// Unregister `cgroup_id`: the tracepoints stop emitting its events. Removing a cgroup that was never
    /// a target is a no-op, not an error (idempotent teardown, like the meter's).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing, or the removal fails for a reason other than the
    /// key being absent.
    pub fn remove_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        match self.trace_targets()?.remove(&cgroup_id) {
            Ok(()) => Ok(()),
            // Absent key (ENOENT): already gone, so a no-op is intended, don't fail teardown on it.
            Err(aya::maps::MapError::SyscallError(e))
                if e.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(())
            }
            Err(e) => Err(ProbeError::Map(format!(
                "unregister cgroup {cgroup_id} from tracing: {e}"
            ))),
        }
    }

    /// Write the filter-mode toggle: `true` = the [`TRACE_TARGETS_MAP`] set, `false` = the single
    /// [`FILTER_MAP`].
    fn set_mode(&mut self, set_mode: bool) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .map_mut(TRACE_SET_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{TRACE_SET_MAP}` not found")))?;
        let mut toggle: Array<_, u32> = Array::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{TRACE_SET_MAP}` as an array: {e}")))?;
        toggle
            .set(FILTER_MODE_SLOT, u32::from(set_mode), 0)
            .map_err(|e| ProbeError::Map(format!("write `{TRACE_SET_MAP}`: {e}")))
    }

    /// The writable `TRACE_TARGETS` set handle, shared by [`add_target`](Self::add_target) /
    /// [`remove_target`](Self::remove_target).
    fn trace_targets(&mut self) -> Result<AyaHashMap<&mut MapData, u64, u8>, ProbeError> {
        let map = self
            .ebpf
            .map_mut(TRACE_TARGETS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{TRACE_TARGETS_MAP}` not found")))?;
        AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{TRACE_TARGETS_MAP}` as a hash map: {e}")))
    }

    /// Write one slot of the `FILTER` array (0 = tgid, 1 = cgroup id; 0 disables that axis).
    fn set_filter(&mut self, slot: u32, value: u64) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .map_mut(FILTER_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{FILTER_MAP}` not found")))?;
        let mut filter: Array<_, u64> = Array::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{FILTER_MAP}` as an array: {e}")))?;
        filter
            .set(slot, value, 0)
            .map_err(|e| ProbeError::Map(format!("set `{FILTER_MAP}`[{slot}]: {e}")))
    }

    /// Drain every event currently in the ring buffer, calling `on_event` for each, and return how
    /// many were delivered. **Non-blocking**: it returns 0 when the buffer is empty rather than
    /// waiting; [`stream`](Self::stream) wraps it in the live-trace loop. A record too short to parse
    /// is skipped, not an error.
    ///
    /// # Errors
    /// Currently infallible (the consumer was opened once at [`load`](Self::load)); the `Result` is
    /// kept for uniformity with the fallible probe surface, so the blocking consumer can add an
    /// error path without breaking callers.
    pub fn drain(&mut self, mut on_event: impl FnMut(SyscallEvent)) -> Result<usize, ProbeError> {
        let mut delivered = 0;
        // One `RingBufItem` is outstanding at a time; each is consumed (parsed to an owned, `Copy`
        // event) before the next `next()`, so the loop never holds two. `self.events` is the same
        // consumer every call, so its position/cache stay coherent (a fresh one would spin, see the
        // field doc).
        while let Some(item) = self.events.next() {
            if let Some(event) = SyscallEvent::from_bytes(&item) {
                on_event(event);
                delivered += 1;
            }
        }
        Ok(delivered)
    }

    /// Stream a **live trace**: loop, calling `on_event` for each event as it arrives, until
    /// `keep_going` returns `false`; return the total delivered. When the buffer is momentarily empty
    /// it sleeps `idle` before polling again (so an idle tracer doesn't spin), but drains greedily
    /// while events are flowing, so latency is bounded by `idle`. Decode + print with
    /// [`SyscallEvent::describe`].
    ///
    /// Kept a poll-with-sleep loop deliberately: the ring buffer's fd is available via `AsRawFd` for a
    /// zero-idle-latency `epoll` wait, but that needs an event loop or an extra dependency; this stays
    /// sync, `unsafe`-free, and dependency-light, matching the driver. `keep_going` is where a caller
    /// wires a deadline or a Ctrl-C flag.
    ///
    /// # Errors
    /// Propagates a [`drain`](Self::drain) error (currently none in practice).
    pub fn stream(
        &mut self,
        idle: Duration,
        mut keep_going: impl FnMut() -> bool,
        mut on_event: impl FnMut(SyscallEvent),
    ) -> Result<usize, ProbeError> {
        let mut total = 0;
        while keep_going() {
            let n = self.drain(&mut on_event)?;
            total += n;
            if n == 0 {
                std::thread::sleep(idle);
            }
        }
        Ok(total)
    }
}

/// The two `tc` classifier programs [`TapMonitor`] attaches (their `#[classifier] fn` symbols in
/// `crates/probes`), one per clsact hook.
const CLS_INGRESS: &str = "tap_ingress";
const CLS_EGRESS: &str = "tap_egress";
/// The per-flow counter map the classifiers write (`#[map] static FLOWS`).
const FLOWS_MAP: &str = "FLOWS";
/// The egress allow-list the ingress classifier consults (`#[map] static POLICY`), and the enforcement
/// toggle (`#[map] static ENFORCE`) that arms it, the two maps [`TapMonitor::set_egress_policy`] writes.
const POLICY_MAP: &str = "POLICY";
const ENFORCE_MAP: &str = "ENFORCE";
/// The per-destination denied-packet counters the enforcement drop path records (`#[map] static
/// DENIALS`), read back by [`TapMonitor::denials`], the audit trail of blocked endpoints.
const DENIALS_MAP: &str = "DENIALS";
/// `EEXIST`: a clsact qdisc already on the interface is not an error (the attach is idempotent).
const EEXIST: i32 = 17;
/// Where `ip netns` bind-mounts a named network namespace's handle (matches the driver's own
/// `netns_path`), so [`TapMonitor::attach_in_netns`] can open a sandbox's netns by name.
const NETNS_DIR: &str = "/run/netns";

/// Per-VM network **totals**: one sandbox's traffic summed across all its flows, from the tap's
/// perspective, **ingress** is what the guest sent, **egress** what it received. The sandbox-level
/// rollup a caller exports, above the per-flow detail [`TapMonitor::flows`] gives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// A loaded, attached network-flow monitor: `tc`/clsact classifiers on a VM's tap that count
/// bytes/packets per IPv4 flow per direction into a map [`flows`](Self::flows) / [`totals`](Self::totals)
/// read. Owns the aya [`Ebpf`] (programs, map, live attachments). Bind it to the *specific* tap the
/// driver named for one sandbox with [`attach_in_netns`](Self::attach_in_netns) (its `fc0` inside its
/// netns, decision 017), or to an interface in the current netns with [`attach`](Self::attach).
///
/// **Lifetime.** Dropping the monitor frees its userspace handles (the map and program fds). The
/// in-kernel `tc` filter it left on the tap is reclaimed by the sandbox's **netns teardown** (`ip netns
/// del` cascades the tap, its clsact qdisc, and the filters away, decision 017/023), so a torn-down
/// sandbox leaves no dangling program even if the loader is gone, and nothing is pinned (decision 020).
#[must_use = "dropping a TapMonitor frees its userspace handles and stops observing (for an interface \
              in the current netns it also detaches; a netns-attached filter goes with the netns teardown)"]
pub struct TapMonitor {
    ebpf: Ebpf,
}

impl TapMonitor {
    /// Attach both classifiers to `interface` **in the current network namespace**, adding a clsact
    /// qdisc first (which gives the device its `tc` ingress and egress hooks). From here every IPv4
    /// frame crossing that interface is counted against its flow until this is dropped. Use this for an
    /// interface in your own netns (a test veth, a host device); for a sandbox's tap, which lives in the
    /// sandbox's netns, use [`attach_in_netns`](Self::attach_in_netns).
    ///
    /// # Errors
    /// [`ProbeError::Unsupported`] if the host can't load eBPF (BTF/caps); [`ProbeError::Object`] if the
    /// object can't be read (build it: `cargo xtask build-probes`); [`ProbeError::Load`] if the kernel
    /// rejects the object/a program; [`ProbeError::Attach`] if adding the qdisc or a classifier attach
    /// fails (the clsact qdisc needs `CAP_NET_ADMIN`, and `interface` must exist).
    pub fn attach(interface: &str) -> Result<Self, ProbeError> {
        check_support()?;
        let mut ebpf = load_classifiers()?;
        attach_classifiers(&mut ebpf, interface)?;
        Ok(Self { ebpf })
    }

    /// Bind the monitor to the **specific tap the driver named for one sandbox**: that tap lives
    /// inside the sandbox's own network namespace (decision 017), so this enters that netns by name (via
    /// its `/run/netns/<netns>` handle), attaches both classifiers to `interface` there, and returns the
    /// calling thread to the caller's netns. Hand it a sandbox's netns name and tap name (typically
    /// `"fc0"`) and the trace is scoped to exactly that sandbox's traffic. The map is read afterward from
    /// the caller's netns as usual (map fds are not namespace-scoped).
    ///
    /// # Errors
    /// As [`attach`](Self::attach), plus [`ProbeError::Attach`] if the netns handle can't be opened or
    /// entered (the netns must exist and `setns` needs `CAP_SYS_ADMIN`/root).
    pub fn attach_in_netns(netns: &str, interface: &str) -> Result<Self, ProbeError> {
        check_support()?;
        // Load + verify the programs in the caller's netns (creating maps and loading programs is not
        // namespace-scoped); only the `tc` attach must run inside the sandbox's netns.
        let mut ebpf = load_classifiers()?;
        let handle = Path::new(NETNS_DIR).join(netns);
        with_netns(&handle, || attach_classifiers(&mut ebpf, interface))?;
        Ok(Self { ebpf })
    }

    /// The current per-flow counters as `(FlowKey, FlowCounts)` pairs, read from the `FLOWS` map. Order
    /// is unspecified (hash-map iteration). The map is read as raw key/value byte arrays and decoded
    /// with the shared `FlowKey::from_bytes` / `FlowCounts::from_bytes`, so the loader needs no `unsafe`
    /// map-type binding and the record stays single-sourced with the kernel writer.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn flows(&self) -> Result<Vec<(FlowKey, FlowCounts)>, ProbeError> {
        let mut out = Vec::new();
        self.for_each_flow(|key, counts| out.push((key, counts)))?;
        Ok(out)
    }

    /// Iterate the `FLOWS` map, decoding each raw key/value with the shared `from_bytes` and handing the
    /// pair to `f`. The single map read [`flows`](Self::flows) and [`totals`](Self::totals) share, so
    /// neither has to build a `Vec` the other would too: `flows` collects, `totals` folds in place. A
    /// key or value whose size can't decode is a **hard** [`ProbeError::Map`] (the kernel record drifted
    /// from [`FlowKey`]/[`FlowCounts`]), never a silent skip that would undercount the rollup.
    fn for_each_flow(&self, mut f: impl FnMut(FlowKey, FlowCounts)) -> Result<(), ProbeError> {
        let map = self
            .ebpf
            .map(FLOWS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{FLOWS_MAP}` not found")))?;
        let flows: AyaHashMap<_, [u8; FLOW_KEY_SIZE], [u8; FLOW_COUNTS_SIZE]> =
            AyaHashMap::try_from(map)
                .map_err(|e| ProbeError::Map(format!("open `{FLOWS_MAP}` as a hash map: {e}")))?;
        for entry in flows.iter() {
            let (k, v) =
                entry.map_err(|e| ProbeError::Map(format!("iterate `{FLOWS_MAP}`: {e}")))?;
            let (Some(key), Some(counts)) = (FlowKey::from_bytes(&k), FlowCounts::from_bytes(&v))
            else {
                return Err(ProbeError::Map(format!(
                    "decode a `{FLOWS_MAP}` entry: {}-byte key / {}-byte value don't match the shared record",
                    k.len(),
                    v.len()
                )));
            };
            f(key, counts);
        }
        Ok(())
    }

    /// The per-VM network **totals**: every [`flows`](Self::flows) entry summed into one
    /// [`NetStats`], the sandbox-level rollup a caller exports. Reads the map once and folds in place
    /// (no intermediate `Vec`), saturating-adding each flow's per-direction counters.
    ///
    /// # Errors
    /// As [`flows`](Self::flows).
    pub fn totals(&self) -> Result<NetStats, ProbeError> {
        let mut stats = NetStats::default();
        self.for_each_flow(|_, c| {
            stats.ingress_packets = stats.ingress_packets.saturating_add(c.ingress_packets);
            stats.ingress_bytes = stats.ingress_bytes.saturating_add(c.ingress_bytes);
            stats.egress_packets = stats.egress_packets.saturating_add(c.egress_packets);
            stats.egress_bytes = stats.egress_bytes.saturating_add(c.egress_bytes);
        })?;
        Ok(stats)
    }

    /// The **denied** guest-sent packets: `(FlowKey, count)` pairs from the `DENIALS` map, one per
    /// destination the egress policy dropped, with how many packets were blocked. Empty until enforcement
    /// drops something. The host-observed audit trail of which endpoints a sandbox was blocked from, read
    /// it after a run, log it, or fold it into the per-run record. Order is unspecified.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the `DENIALS` map is missing or a read fails mid-iteration.
    pub fn denials(&self) -> Result<Vec<(FlowKey, u64)>, ProbeError> {
        let map = self
            .ebpf
            .map(DENIALS_MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{DENIALS_MAP}` not found")))?;
        let denials: AyaHashMap<_, [u8; FLOW_KEY_SIZE], u64> = AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{DENIALS_MAP}` as a hash map: {e}")))?;
        let mut out = Vec::new();
        for entry in denials.iter() {
            let (k, count) =
                entry.map_err(|e| ProbeError::Map(format!("iterate `{DENIALS_MAP}`: {e}")))?;
            let Some(key) = FlowKey::from_bytes(&k) else {
                return Err(ProbeError::Map(format!(
                    "decode a `{DENIALS_MAP}` key: {}-byte key doesn't match the shared record",
                    k.len()
                )));
            };
            out.push((key, count));
        }
        Ok(out)
    }

    /// Install an [`EgressPolicy`] on this **already-attached** monitor: write its rules
    /// into the `POLICY` map (zeroing the unused slots so no stale rule lingers) and arm the `ENFORCE`
    /// toggle. From here the tap's ingress hook drops any guest-sent IPv4 packet whose destination matches
    /// no rule, and accepts those that do, per VM, since each monitor owns its own maps. Idempotent: call
    /// again to replace the policy. To arm a policy **at launch** with no un-enforced window, prefer
    /// [`enforce_in_netns`](Self::enforce_in_netns), which policies the maps *before* the tc programs go
    /// live on the tap.
    ///
    /// # Errors
    /// [`ProbeError::Policy`] if the policy exceeds [`MAX_POLICY_RULES`], or [`ProbeError::Map`] if a
    /// policy/enforce map is missing or a write fails.
    pub fn set_egress_policy(&mut self, policy: &EgressPolicy) -> Result<(), ProbeError> {
        apply_policy(&mut self.ebpf, policy)
    }

    /// Turn egress enforcement off again, back to observe-only (accept every packet), the pre-enforcement
    /// behavior. Leaves the `POLICY` rules in place (harmless while `ENFORCE` is 0), so re-enforcing is a
    /// single [`set_egress_policy`](Self::set_egress_policy) away.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the enforce map is missing or the write fails.
    pub fn clear_egress_policy(&mut self) -> Result<(), ProbeError> {
        set_enforce(&mut self.ebpf, false)
    }
}

/// A sandbox's **egress allow-list**, the userspace schema for what the guest may reach, built
/// from friendly [`Ipv4Addr`] CIDRs and ports and lowered to the [`PolicyRule`]s the kernel map holds.
/// **Deny-by-default:** the empty policy ([`deny_all`](Self::deny_all) / [`Default`]) allows
/// nothing, so a sandbox launched with no explicit allowance reaches nothing, you have to add each
/// endpoint. This is the eBPF, host-observed complement to the driver's deny-by-default routing
/// (decision 008): the driver gives the guest no route to the world, and this drops anything unlisted at
/// the tap, where the host can see and record it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    rules: Vec<PolicyRule>,
}

/// A validated IPv4 **CIDR**, a network address and a prefix length that is guaranteed `0..=32` by
/// construction. Parse, don't validate: an out-of-range prefix can't exist as an `Ipv4Cidr`, so it can
/// never reach the kernel policy map. Build one with [`new`](Self::new) (fallible) or [`host`](Self::host)
/// (an infallible `/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// A CIDR `network/prefix_len`, or [`PolicyError::PrefixTooLong`] if `prefix_len > 32`. The network is
    /// taken as given (the kernel matcher masks it to `prefix_len`, so unmasked host bits don't matter).
    ///
    /// # Errors
    /// [`PolicyError::PrefixTooLong`] when `prefix_len` exceeds 32.
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Result<Self, PolicyError> {
        if prefix_len > 32 {
            return Err(PolicyError::PrefixTooLong(prefix_len));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// The `/32` CIDR of a single host, infallible, since `32` is always in range.
    #[must_use]
    pub fn host(addr: Ipv4Addr) -> Self {
        Self {
            network: addr,
            prefix_len: 32,
        }
    }
}

impl EgressPolicy {
    /// The **deny-everything** policy: no rules, so every guest-sent packet is dropped once
    /// enforced. The safe default, build up from here by adding explicit allowances.
    #[must_use]
    pub fn deny_all() -> Self {
        Self { rules: Vec::new() }
    }

    /// Allow a destination [`Ipv4Cidr`] on an optional `port` and `proto` ([`None`] = any), consuming and
    /// returning `self` for chaining. `None` reads as a wildcard (the kernel's `0`), so
    /// `allow(cidr, None, None)` admits the whole CIDR on any port and protocol. The address goes in host
    /// byte order (as [`Ipv4Addr`] naturally converts), matching the kernel matcher.
    #[must_use]
    pub fn allow(mut self, cidr: Ipv4Cidr, port: Option<u16>, proto: Option<Protocol>) -> Self {
        self.rules.push(PolicyRule::allow(
            u32::from(cidr.network),
            cidr.prefix_len,
            port.unwrap_or(0),
            proto.map_or(0, Protocol::as_u8),
        ));
        self
    }

    /// Allow a single destination **host** (`/32`) on an optional `port`/`proto`, the common case, sugar
    /// over [`allow`](Self::allow) with [`Ipv4Cidr::host`].
    #[must_use]
    pub fn allow_host(self, host: Ipv4Addr, port: Option<u16>, proto: Option<Protocol>) -> Self {
        self.allow(Ipv4Cidr::host(host), port, proto)
    }

    /// The lowered [`PolicyRule`]s, as written into the kernel `POLICY` map.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Whether this policy allows nothing (deny-by-default). `true` for [`deny_all`](Self::deny_all) and
    /// the [`Default`].
    #[must_use]
    pub fn is_deny_all(&self) -> bool {
        self.rules.is_empty()
    }
}

impl TapMonitor {
    /// Attach the monitor to a sandbox's netns tap **and** install `policy`, arming enforcement in one
    /// step, the launch-time entry point. The policy is written and `ENFORCE` set *before* the
    /// tc programs are attached to the tap, so there is **no window** in which the tap is live but
    /// un-policed: the very first guest packet the classifier sees is already under policy. Pass
    /// [`EgressPolicy::deny_all`] for deny-by-default. Otherwise like
    /// [`attach_in_netns`](Self::attach_in_netns) (enters the sandbox's netns via `setns`, decision 024).
    ///
    /// # Errors
    /// As [`attach_in_netns`](Self::attach_in_netns) and [`set_egress_policy`](Self::set_egress_policy).
    pub fn enforce_in_netns(
        netns: &str,
        interface: &str,
        policy: &EgressPolicy,
    ) -> Result<Self, ProbeError> {
        check_support()?;
        // Load + policy the maps in the caller's netns, *then* attach in the sandbox's: arming before
        // attach is what closes the un-enforced window (an attached-but-unpoliced tap would accept-all).
        let mut ebpf = load_classifiers()?;
        apply_policy(&mut ebpf, policy)?;
        let handle = Path::new(NETNS_DIR).join(netns);
        with_netns(&handle, || attach_classifiers(&mut ebpf, interface))?;
        Ok(Self { ebpf })
    }
}

/// Write `policy` into an [`Ebpf`]'s `POLICY` map and arm `ENFORCE`. Works on a loaded object whether or
/// not its programs are attached yet, so it serves both the post-attach [`TapMonitor::set_egress_policy`]
/// and the pre-attach [`TapMonitor::enforce_in_netns`] (arm-before-attach, no un-enforced window).
fn apply_policy(ebpf: &mut Ebpf, policy: &EgressPolicy) -> Result<(), ProbeError> {
    let rules = policy.rules();
    if rules.len() > MAX_POLICY_RULES {
        return Err(PolicyError::TooManyRules {
            got: rules.len(),
            max: MAX_POLICY_RULES,
        }
        .into());
    }
    write_policy(ebpf, rules)?;
    set_enforce(ebpf, true)
}

/// Write every `POLICY` slot: the first `rules.len()` from `rules`, the rest zeroed (an all-zero slot is
/// `active == 0`, i.e. empty, so a shrunk policy can't leave a stale allow-rule behind). Rules go in as
/// raw native bytes via [`PolicyRule::to_bytes`], so the loader needs no `unsafe` `aya::Pod` binding,
/// the write-side twin of [`TapMonitor::flows`] reading raw bytes.
fn write_policy(ebpf: &mut Ebpf, rules: &[PolicyRule]) -> Result<(), ProbeError> {
    let map = ebpf
        .map_mut(POLICY_MAP)
        .ok_or_else(|| ProbeError::Map(format!("map `{POLICY_MAP}` not found")))?;
    let mut policy: Array<_, [u8; POLICY_RULE_SIZE]> = Array::try_from(map)
        .map_err(|e| ProbeError::Map(format!("open `{POLICY_MAP}` as an array: {e}")))?;
    for i in 0..MAX_POLICY_RULES {
        let bytes = rules
            .get(i)
            .map_or([0u8; POLICY_RULE_SIZE], PolicyRule::to_bytes);
        policy
            .set(i as u32, bytes, 0)
            .map_err(|e| ProbeError::Map(format!("write `{POLICY_MAP}`[{i}]: {e}")))?;
    }
    Ok(())
}

/// Set the `ENFORCE` toggle (slot 0): `true` = deny-by-default egress, `false` = observe-only.
fn set_enforce(ebpf: &mut Ebpf, on: bool) -> Result<(), ProbeError> {
    let map = ebpf
        .map_mut(ENFORCE_MAP)
        .ok_or_else(|| ProbeError::Map(format!("map `{ENFORCE_MAP}` not found")))?;
    let mut enforce: Array<_, u32> = Array::try_from(map)
        .map_err(|e| ProbeError::Map(format!("open `{ENFORCE_MAP}` as an array: {e}")))?;
    enforce
        .set(0, u32::from(on), 0)
        .map_err(|e| ProbeError::Map(format!("write `{ENFORCE_MAP}`: {e}")))?;
    Ok(())
}

/// Read the compiled object and load + verify both `tc` classifier programs (not yet attached to any
/// interface). Namespace-independent: creating the maps and loading the programs is global, so this
/// runs in whatever netns the caller is in.
fn load_classifiers() -> Result<Ebpf, ProbeError> {
    let path = object_path();
    let bytes = std::fs::read(&path).map_err(|e| {
        ProbeError::Object(format!(
            "read BPF object {}: {e} (build it with `cargo xtask build-probes`)",
            path.display()
        ))
    })?;
    let mut ebpf = Ebpf::load(&bytes).map_err(|e| ProbeError::Load(format!("load object: {e}")))?;
    for program in [CLS_INGRESS, CLS_EGRESS] {
        let cls: &mut SchedClassifier = ebpf
            .program_mut(program)
            .ok_or_else(|| ProbeError::Load(format!("program `{program}` not found in object")))?
            .try_into()
            .map_err(|e| {
                ProbeError::Load(format!("program `{program}` is not a classifier: {e}"))
            })?;
        cls.load()
            .map_err(|e| ProbeError::Load(format!("verify/load `{program}`: {e}")))?;
    }
    Ok(ebpf)
}

/// Attach the already-loaded classifiers to `interface`'s clsact ingress and egress hooks, adding the
/// clsact qdisc first. **Namespace-scoped**: the caller must already be in the netns that owns
/// `interface` (the current netns for [`TapMonitor::attach`], the sandbox's for
/// [`TapMonitor::attach_in_netns`]).
fn attach_classifiers(ebpf: &mut Ebpf, interface: &str) -> Result<(), ProbeError> {
    // clsact gives a device both a `tc` ingress and egress hook. Idempotent: an already-present clsact
    // (EEXIST) is fine; any other failure (no CAP_NET_ADMIN, or the interface is gone) is a typed error.
    if let Err(e) = tc::qdisc_add_clsact(interface) {
        if e.raw_os_error() != Some(EEXIST) {
            return Err(ProbeError::Attach(format!(
                "add clsact qdisc on {interface}: {e}"
            )));
        }
    }
    for (program, attach_type) in [
        (CLS_INGRESS, TcAttachType::Ingress),
        (CLS_EGRESS, TcAttachType::Egress),
    ] {
        let cls: &mut SchedClassifier = ebpf
            .program_mut(program)
            .ok_or_else(|| ProbeError::Load(format!("program `{program}` not found in object")))?
            .try_into()
            .map_err(|e| {
                ProbeError::Load(format!("program `{program}` is not a classifier: {e}"))
            })?;
        cls.attach(interface, attach_type).map_err(|e| {
            ProbeError::Attach(format!(
                "attach `{program}` to {interface} ({attach_type:?}): {e}"
            ))
        })?;
    }
    Ok(())
}

/// Run `f` with the calling thread moved into the network namespace at `netns_handle`, then move it
/// back, so a `tc` attach lands in a sandbox's netns without moving the whole process (only this
/// thread is affected, briefly). Uses nix's *safe* `setns` wrapper, so the loader stays
/// `#![forbid(unsafe_code)]`. The origin netns is captured first and **always** restored: on the normal
/// path explicitly (so a restore failure is surfaced as an error), and on an unwinding panic in `f` by
/// the [`NetnsGuard`], so no code path can strand the thread in the sandbox's netns.
fn with_netns<T>(
    netns_handle: &Path,
    f: impl FnOnce() -> Result<T, ProbeError>,
) -> Result<T, ProbeError> {
    use nix::sched::{setns, CloneFlags};
    // The *calling thread's* netns, not `/proc/self/ns/net` (which is the thread-group leader's): a
    // caller may drive the loader off a worker thread, and we must return exactly where we started.
    let origin = File::open("/proc/thread-self/ns/net")
        .map_err(|e| ProbeError::Attach(format!("open the calling thread's netns handle: {e}")))?;
    let target = File::open(netns_handle)
        .map_err(|e| ProbeError::Attach(format!("open netns {}: {e}", netns_handle.display())))?;
    setns(&target, CloneFlags::CLONE_NEWNET)
        .map_err(|e| ProbeError::Attach(format!("enter netns {}: {e}", netns_handle.display())))?;

    // Arm a guard so an unwinding panic in `f` still restores the origin netns (the sandbox's netns is
    // about to be torn down; a thread stranded there would corrupt every later operation on it). The
    // normal path disarms the guard and restores explicitly below, so a restore *failure* surfaces as
    // an error rather than being swallowed on drop.
    let mut guard = NetnsGuard {
        origin: Some(origin),
    };
    let result = f();
    // Disarm the guard (so its `Drop` won't restore a second time) and restore explicitly, so a restore
    // *failure* is surfaced as an error rather than swallowed. `origin` is `Some` until exactly here.
    if let Some(origin) = guard.origin.take() {
        setns(&origin, CloneFlags::CLONE_NEWNET)
            .map_err(|e| ProbeError::Attach(format!("restore the calling thread's netns: {e}")))?;
    }
    result
}

/// Restores a thread's origin netns if [`with_netns`] unwinds through it. Armed for the duration of
/// `f`; the normal path takes `origin` (disarming it) and restores explicitly, so this fires **only**
/// on a panic. `Drop` can't propagate, and the thread is already unwinding, so a failed restore here is
/// best-effort, attempting it is still strictly better than leaving the thread in a doomed netns.
struct NetnsGuard {
    origin: Option<File>,
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        if let Some(origin) = self.origin.take() {
            let _ = nix::sched::setns(&origin, nix::sched::CloneFlags::CLONE_NEWNET);
        }
    }
}

/// Where the compiled BPF object lives: the `AGENT_PROBES_OBJECT` override if set, else the
/// `cargo xtask build-probes` output under the source tree
/// (`crates/probes/target/bpfel-unknown-none/release/probes`). The object is a *build artifact*
/// (like the guest kernel/rootfs), built separately and loaded at runtime, not linked into this crate.
#[must_use]
pub fn object_path() -> PathBuf {
    if let Some(p) = std::env::var_os(OBJECT_ENV) {
        return PathBuf::from(p);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../probes/target/bpfel-unknown-none/release/probes")
}

/// The cgroup v2 id of process `pid`, the same `u64` `bpf_get_current_cgroup_id` reports for tasks in
/// that cgroup, so it is exactly what [`SyscallTracer::watch_cgroup`] filters on. This is the **attribution
/// bridge**: take a sandbox's VMM pid from the Firecracker track, resolve its cgroup id here, and
/// [`watch_cgroup`](SyscallTracer::watch_cgroup) it so the trace shows only that sandbox's host
/// footprint (the whole cgroup: the VMM and its threads, not just one tgid).
///
/// It reads the process's **unified** cgroup path from `/proc/<pid>/cgroup` (the `0::/…` line), then
/// returns the inode number of `/sys/fs/cgroup/<path>`, for cgroup v2 that inode *is* the kernel's
/// cgroup id. Pure `std` fs, no `unsafe`. Sugar over [`cgroup_dir_of_pid`] + a stat.
///
/// # Errors
/// [`ProbeError::Map`] if `/proc/<pid>/cgroup` can't be read, has no unified (`0::`) line (a
/// cgroup-v1-only host), or the cgroup dir can't be stat'd.
pub fn cgroup_id_of_pid(pid: u32) -> Result<u64, ProbeError> {
    cgroup_id_of_dir(&cgroup_dir_of_pid(pid)?)
}

/// The **cgroup dir** of process `pid`, `/sys/fs/cgroup/<path>`, where `<path>` is the unified (`0::`)
/// line of `/proc/<pid>/cgroup`. The path half of the bridge: [`cgroup_id_of_pid`] resolves the id
/// for the eBPF CPU meter, this resolves the dir [`CgroupStats::read`] reads the native memory/IO
/// counters from. Given a sandbox's VMM pid (the Firecracker track's `vmm_pid`), the two together scope
/// all three resource axes to that one sandbox's cgroup. Pure `std` fs, no `unsafe`.
///
/// # Errors
/// [`ProbeError::Map`] if `/proc/<pid>/cgroup` can't be read or has no unified (`0::`) line (a
/// cgroup-v1-only host).
pub fn cgroup_dir_of_pid(pid: u32) -> Result<PathBuf, ProbeError> {
    let proc_path = format!("/proc/{pid}/cgroup");
    let text = std::fs::read_to_string(&proc_path)
        .map_err(|e| ProbeError::Map(format!("read {proc_path}: {e}")))?;
    // The cgroup v2 unified controller is the `0::<path>` line; `<path>` is rooted at the cgroup mount.
    let rel = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| {
            ProbeError::Map(format!(
                "{proc_path} has no unified (0::) cgroup line — a cgroup v2 host is required"
            ))
        })?
        .trim();
    Ok(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The cgroup v2 id of a cgroup **dir**: its inode number (for cgroup v2 the dir inode *is* the id
/// `bpf_get_current_cgroup_id` reports). Shared by [`cgroup_id_of_pid`] and
/// [`ResourceMeter::summary_for_pid`], so the pid → dir → id resolution lives once.
fn cgroup_id_of_dir(dir: &Path) -> Result<u64, ProbeError> {
    let meta = std::fs::metadata(dir)
        .map_err(|e| ProbeError::Map(format!("stat cgroup dir {}: {e}", dir.display())))?;
    Ok(meta.ino())
}

/// The cgroup id of the current process ([`cgroup_id_of_pid`] of `std::process::id()`), for a
/// self-trace or a test.
///
/// # Errors
/// As [`cgroup_id_of_pid`].
pub fn cgroup_id_of_self() -> Result<u64, ProbeError> {
    cgroup_id_of_pid(std::process::id())
}

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
const TARGET_PRESENT: u8 = 1;

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
/// [`cgroup_id_of_pid`] resolves from its VMM pid).
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
        let path = object_path();
        let bytes = std::fs::read(&path).map_err(|e| {
            ProbeError::Object(format!(
                "read BPF object {}: {e} (build it with `cargo xtask build-probes`)",
                path.display()
            ))
        })?;
        let mut ebpf =
            Ebpf::load(&bytes).map_err(|e| ProbeError::Load(format!("load object: {e}")))?;

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
    /// [`cgroup_id_of_pid`]) with one shared meter, and the per-switch cost stays a single hash lookup
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

    /// The raw accumulated on-CPU **nanoseconds** for `cgroup_id` (0 if absent). Reads the map by
    /// iteration rather than a keyed lookup so a missing key is an unambiguous `0`, not a lookup error to
    /// disentangle from a real one, the map holds one entry under a targeted meter, so the scan is trivial.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn cpu_ns(&self, cgroup_id: u64) -> Result<u64, ProbeError> {
        let mut found = 0u64;
        self.for_each_cpu(|id, ns| {
            if id == cgroup_id {
                found = ns;
            }
        })?;
        Ok(found)
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
    /// ships alongside the run's [`RunResult`](https://docs.rs/agent-vmm), the CPU figure is meaningful
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
/// and the syscall trace) is the audit record's convergence, kept here, out of `agent-vmm`, so the driver stays
/// independent of the eBPF loader (they bridge only by plain values).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
/// isolation boundary (it fails open, like the driver's cgroup caps, decision 013).
///
/// Read one with [`read`](Self::read), pointed at the cgroup dir the Firecracker track placed the VMM in
/// (`<cgroup mount>/<path>`; the driver knows it and supplies it).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// Whether the host can load eBPF at all, a cheap pre-flight the CLI/`setup` can call before it
/// tries to attach anything. Checks for kernel BTF (`/sys/kernel/btf/vmlinux`), the CO-RE
/// prerequisite. [`check_support`] is the fuller gate (BTF **and** the capabilities), with a legible
/// reason.
#[must_use]
pub fn ebpf_supported() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// `CAP_PERFMON` (bit 38): attaching a program to a tracepoint goes through `perf_event_open`, which
/// this gates. `CAP_BPF` (bit 39): loading programs/maps and reading maps. The two split out of
/// `CAP_SYS_ADMIN` in Linux 5.8, so a loader needs **just these two**, not full root.
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Parse the low 64 bits of the effective-capability mask from `/proc/<pid>/status` text: the hex
/// value on the `CapEff:` line, or `None` when that line is absent or unparseable. Pure (takes the
/// text) so the bit logic is unit-testable without a live `/proc`, the same pure-parser pattern the
/// driver uses for `parse_nofile_soft`.
///
/// Only the trailing 16 hex digits (bits 0-63) are read: `CAP_BPF` (39) and `CAP_PERFMON` (38) both
/// live there, so a hypothetically wider future field can't overflow the parse into a false "no caps."
fn parse_cap_eff(status: &str) -> Option<u64> {
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))?
        .trim();
    if hex.is_empty() || !hex.is_ascii() {
        return None;
    }
    let low64 = &hex[hex.len().saturating_sub(16)..];
    u64::from_str_radix(low64, 16).ok()
}

/// Whether an effective-capability `mask` holds both caps the probes need (`CAP_BPF` + `CAP_PERFMON`).
/// Root's mask has every bit, so this is `true` for root and for a `setcap cap_bpf,cap_perfmon+ep`
/// binary alike: the point is that the second, unprivileged path works.
fn mask_has_load_caps(mask: u64) -> bool {
    (mask >> CAP_BPF) & 1 == 1 && (mask >> CAP_PERFMON) & 1 == 1
}

/// Whether this process holds the capabilities the probes need, read from the effective set in
/// `/proc/self/status` (`CapEff:`, a 64-bit hex mask), no `libc`, no `unsafe`. The standard
/// requirement is the two caps; an exotic host with only `CAP_BPF` and a permissive
/// `kernel.perf_event_paranoid` may also manage the tracepoint attach, but this pre-flight names the
/// standard path rather than probing sysctls (a conservative advisory, not the kernel's final say).
fn have_load_caps() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .is_some_and(mask_has_load_caps)
}

/// The eBPF analogue of the driver's Firecracker-version guard: check the host can actually
/// load the probes and, if not, return a **legible typed error naming the requirement**, a BTF-less
/// kernel or missing capabilities, caught here rather than as a cryptic verifier reject or `EPERM`
/// deep in the load. [`ExecveCounter::load`] runs this first; the CLI/`setup` can call it to
/// report eBPF readiness before attempting anything.
///
/// The BTF check is a deliberate engine *baseline*, not just this program's need: the shipped object
/// is built CO-RE (`--btf`) and reading kernel struct fields does need vmlinux BTF,
/// so the engine requires a BTF-enabled kernel uniformly (the modern-distro default) rather than
/// per-program. A kernel lacking it that could still load *this* relocation-free counter program is refused
/// on purpose, so the support story stays one line, not a per-probe matrix.
///
/// # Errors
/// [`ProbeError::Unsupported`] naming the first missing prerequisite (BTF, then capabilities).
pub fn check_support() -> Result<(), ProbeError> {
    // Deliberate baseline (see the fn doc): require vmlinux BTF uniformly for the CO-RE object, even
    // though this relocation-free counter program would load without it.
    if !ebpf_supported() {
        return Err(ProbeError::Unsupported(
            "kernel BTF (/sys/kernel/btf/vmlinux) is absent — CO-RE eBPF needs a BTF-enabled kernel \
             (CONFIG_DEBUG_INFO_BTF=y)"
                .into(),
        ));
    }
    if !have_load_caps() {
        return Err(ProbeError::Unsupported(
            "missing CAP_BPF and/or CAP_PERFMON — loading and attaching the probes needs both (or \
             root); grant them with `setcap cap_bpf,cap_perfmon+ep <binary>`, or run as root"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_eff_parses_the_effective_line_only() {
        // A real `/proc/self/status` has several `Cap*` rows; only `CapEff:` is the effective set.
        let status = "Name:\tthing\nCapInh:\t0000000000000000\nCapPrm:\tffffffffffffffff\n\
                      CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x0000_01ff_ffff_ffff));
    }

    #[test]
    fn cap_eff_absent_or_malformed_is_none() {
        assert_eq!(parse_cap_eff("CapPrm:\t00\n"), None); // no CapEff line at all
        assert_eq!(parse_cap_eff("CapEff:\tnothex\n"), None); // present but unparseable
        assert_eq!(parse_cap_eff("CapEff:\t\n"), None); // present but empty
        assert_eq!(parse_cap_eff(""), None);
    }

    #[test]
    fn cap_eff_reads_low_64_bits_of_a_hypothetically_wider_field() {
        // A field wider than 64 bits (>16 hex digits) must not overflow the parse to `None` and read
        // as "no caps": we take the low 64 bits, where CAP_BPF/CAP_PERFMON live.
        let both = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        let wide = format!("CapEff:\tdeadbeef{both:016x}\n"); // 8 extra high digits
        assert_eq!(parse_cap_eff(&wide), Some(both));
        assert!(mask_has_load_caps(
            parse_cap_eff(&wide).expect("parse the wide CapEff line")
        ));
    }

    #[test]
    fn load_caps_need_both_bpf_and_perfmon() {
        let both = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        assert!(mask_has_load_caps(u64::MAX)); // root: every bit
        assert!(mask_has_load_caps(both)); // exactly the two (the setcap path)
        assert!(!mask_has_load_caps(1u64 << CAP_BPF)); // CAP_PERFMON missing
        assert!(!mask_has_load_caps(1u64 << CAP_PERFMON)); // CAP_BPF missing
        assert!(!mask_has_load_caps(0)); // none
    }

    #[test]
    fn cap_logic_round_trips_through_the_status_line() {
        let both = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        let status = format!("CapEff:\t{both:016x}\n");
        assert!(mask_has_load_caps(
            parse_cap_eff(&status).expect("parse the crafted CapEff line")
        ));
    }

    #[test]
    fn cgroup_id_of_self_resolves_or_reports_v1() {
        // Host-safe (no eBPF): the resolver reads `/proc/self/cgroup` + the cgroup dir's inode.
        // On a cgroup v2 host it returns a real (nonzero) id; on a v1-only host it errors legibly.
        match cgroup_id_of_self() {
            Ok(id) => assert!(id > 0, "a real cgroup id is nonzero (got {id})"),
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("cgroup v2") || s.contains("0::"),
                    "a resolver failure must name the v2 requirement, got: {s}"
                );
            }
        }
    }

    // --- Egress policy: the userspace schema, host-testable without a live map ---
    use agent_probes_common::egress_allowed;

    /// A dotted-quad as the host-order `u32` the matcher takes.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn protocol_round_trips_and_single_sources_the_wire_numbers() {
        assert_eq!(Protocol::Tcp.as_u8(), 6);
        assert_eq!(Protocol::Udp.as_u8(), 17);
        assert_eq!(Protocol::from_u8(17), Some(Protocol::Udp));
        assert_eq!(Protocol::from_u8(6), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_u8(1), None); // ICMP: parsed for no ports, so "any / other"
    }

    #[test]
    fn ipv4_cidr_rejects_an_out_of_range_prefix() {
        // parse-don't-validate: an over-/32 prefix can't be constructed, so it never reaches the map.
        assert_eq!(
            Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 40),
            Err(PolicyError::PrefixTooLong(40))
        );
        assert!(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).is_ok());
        assert!(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 32).is_ok());
    }

    #[test]
    fn deny_all_is_the_default_and_allows_nothing() {
        // No policy = reaches nothing. The default and `deny_all` are the same empty allow-list.
        let p = EgressPolicy::default();
        assert!(p.is_deny_all());
        assert_eq!(p, EgressPolicy::deny_all());
        assert!(p.rules().is_empty());
        assert!(!egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            9999,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn allow_host_builds_a_slash32_rule() {
        let host = Ipv4Addr::new(10, 200, 0, 1);
        let p = EgressPolicy::deny_all().allow_host(host, Some(9999), Some(Protocol::Udp));
        assert!(!p.is_deny_all());
        let rule = p.rules()[0];
        assert_eq!(rule.active, 1);
        assert_eq!(rule.prefix_len, 32);
        assert_eq!(rule.addr, u32::from(host));
        assert_eq!(rule.port, 9999);
        assert_eq!(rule.proto, Protocol::Udp.as_u8());
        // Only that exact host/port/proto is admitted; everything else is denied.
        assert!(egress_allowed(
            p.rules(),
            u32::from(host),
            9999,
            Protocol::Udp.as_u8()
        ));
        assert!(!egress_allowed(
            p.rules(),
            ip(10, 200, 0, 2),
            9999,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn none_port_and_proto_lower_to_the_any_wildcard() {
        // `None` is the typed "any", lowering to the kernel's `0` sentinel, no magic 0 at the API.
        let p = EgressPolicy::deny_all().allow_host(Ipv4Addr::new(10, 200, 0, 1), None, None);
        let rule = p.rules()[0];
        assert_eq!(rule.port, 0);
        assert_eq!(rule.proto, 0);
        // Any port and any protocol to that host is admitted.
        assert!(egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            1234,
            Protocol::Tcp.as_u8()
        ));
        assert!(egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            53,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn allow_chains_cidr_and_host() {
        let p = EgressPolicy::deny_all()
            .allow(
                Ipv4Cidr::new(Ipv4Addr::new(93, 184, 216, 0), 24).expect("valid /24"),
                Some(443),
                Some(Protocol::Tcp),
            )
            .allow_host(Ipv4Addr::new(10, 200, 0, 1), None, None); // any port/proto to the gateway
        assert_eq!(p.rules().len(), 2);
        // The chained policy admits both the subnet and the gateway, and nothing else.
        assert!(egress_allowed(
            p.rules(),
            ip(93, 184, 216, 34),
            443,
            Protocol::Tcp.as_u8()
        ));
        assert!(egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            1234,
            Protocol::Udp.as_u8()
        ));
        assert!(!egress_allowed(
            p.rules(),
            ip(8, 8, 8, 8),
            53,
            Protocol::Udp.as_u8()
        ));
    }

    // --- Resource accounting: the cgroup v2 file parsers, host-testable without a live cgroup ---

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
            "agent-cgstats-{}-{}",
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
