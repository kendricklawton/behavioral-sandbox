//! `agent-probes-loader` — the userspace side of the eBPF story: load and attach the probes from
//! `crates/probes`, read their maps, and stream events into the audit log. Phase 8 attaches the
//! one host-global `sys_enter_execve` tracepoint (scoped to nothing); binding a program to a
//! *specific* sandbox (its cgroup, its tap device) arrives with the per-VM taps in Phase 10.
//!
//! **P8.3 — attach + read a map.** [`ExecveCounter`] loads the compiled BPF object, attaches the
//! `count_execve` tracepoint to `syscalls/sys_enter_execve`, and reads its per-CPU counter map,
//! summing the slots into one total. Synchronous by design: aya's load/attach/array-read path takes
//! no async runtime, matching the driver's no-background-threads posture. This counts the **host's**
//! `execve` footprint (a microVM's own syscalls never trap here; see ROADMAP Phase 9) — the introduction
//! that proves the load → attach → read → drop path before Phase 10 binds programs to real taps.
//!
//! **P8.5/P8.6 — CO-RE and the verifier.** The object is built against BTF, so aya relocates it
//! against the running kernel at load (Compile Once, Run Everywhere — portable across kernels). The
//! program also keeps a per-PID hash map, surfaced here as
//! [`counts_by_pid`](ExecveCounter::counts_by_pid); its lookup-or-init and bounded-loop patterns are
//! the verifier rules the eBPF side hits on purpose.
//!
//! **P8.4 — drops with the loader.** [`ExecveCounter`] owns the aya [`Ebpf`], whose `Drop`
//! detaches the program (dropping the link) and frees the map. Nothing is **pinned** into
//! `/sys/fs/bpf`, so there is no kernel residue to leak: a crashed loader leaves no dangling
//! attachment, the eBPF analogue of the driver's no-leak teardown. Pinning stays opt-in, added only
//! where a program must outlive its loader (not here).
//!
//! **P9.1/P9.2 — a per-event syscall trace, filtered to one sandbox.** [`SyscallTracer`] loads the
//! same object but attaches the three `sys_enter_{execve,openat,connect}` tracepoints, each of which
//! streams a whole [`SyscallEvent`] (pid, tid, cgroup id, `comm`, and the path or sockaddr bytes) into
//! a **ring buffer** the tracer drains with [`drain`](SyscallTracer::drain). Where [`ExecveCounter`]
//! answers "how many", the tracer answers "which, by whom, on what". Point it at one Firecracker
//! worker with [`watch_pid`](SyscallTracer::watch_pid) /
//! [`watch_cgroup`](SyscallTracer::watch_cgroup) so it records that sandbox's host footprint and not
//! the whole machine's. Still the host's footprint, not the guest's (a microVM's syscalls stay
//! in-guest; see ROADMAP Phase 9).
//!
//! **P9.3/P9.4 — a live trace, attributed to a sandbox.** [`stream`](SyscallTracer::stream) is the
//! streaming consumer: it loops, decoding each event with [`SyscallEvent::describe`] and handing it to
//! a callback as it arrives, until a caller predicate says stop. [`cgroup_id_of_pid`] closes the loop
//! with the Firecracker track: hand it a sandbox's VMM pid, `watch_cgroup` the id it returns, and the
//! trace is scoped to exactly that sandbox (the `bpf_get_current_cgroup_id` a program reads equals the
//! inode of the cgroup dir the jailer placed the VMM in).
//!
//! **P10 — network flows on the tap.** [`TapMonitor`] attaches the two `tc`/clsact classifiers
//! (`tap_ingress`/`tap_egress`) to a VM's tap and reads their per-flow byte/packet counters with
//! [`flows`](TapMonitor::flows), or the per-VM rollup with [`totals`](TapMonitor::totals) (P10.3). This
//! is the guest's *own* traffic (every packet crosses the tap on the host), the strong cross-boundary
//! signal syscalls can't be. [`attach_in_netns`](TapMonitor::attach_in_netns) binds the *specific* tap
//! the driver named for one sandbox by entering that sandbox's netns (P10.4, decision 017/024);
//! [`attach`](TapMonitor::attach) takes an interface in the current netns.
//!
//! **P8.8/P8.9 — caps + a legible support probe.** Loading needs only `CAP_BPF`+`CAP_PERFMON`, not
//! full root; [`check_support`] names a missing prerequisite (kernel BTF, or those caps) up front as a
//! typed [`ProbeError::Unsupported`], so a host that can't run the probes says so plainly instead of
//! failing with a cryptic verifier reject or `EPERM` (the eBPF analogue of the driver's dependency
//! guards, P6.9b).
#![forbid(unsafe_code)]

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType, TracePoint};
use aya::Ebpf;

pub use agent_probes_common::{FlowCounts, FlowKey, Syscall, SyscallEvent};
use agent_probes_common::{FLOW_COUNTS_SIZE, FLOW_KEY_SIZE};

/// Env override for the compiled BPF object's location — for a vendored / installed deployment where
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

/// A typed failure from loading/attaching/reading the probes — the loader's analogue of the driver's
/// `VmmError`: a missing prerequisite, a missing object, a kernel load/verify/permission failure, an
/// attach failure, or a map read failure is a typed `Err`, never a panic (the host path never panics).
#[derive(Debug)]
pub enum ProbeError {
    /// The host can't load eBPF at all: a missing prerequisite named up front (no kernel BTF, or the
    /// `CAP_BPF`/`CAP_PERFMON` capabilities), caught by [`check_support`] *before* a load so it reads
    /// legibly instead of surfacing as a cryptic verifier reject or `EPERM` (P8.9).
    Unsupported(String),
    /// The compiled BPF object couldn't be found or read (build it with `cargo xtask build-probes`).
    Object(String),
    /// Loading/verifying the object or a program into the kernel failed — a verifier reject or a
    /// kernel-feature gap the up-front [`check_support`] didn't catch.
    Load(String),
    /// Attaching a loaded program to its kernel hook failed.
    Attach(String),
    /// Reading a program's map failed.
    Map(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(e) => write!(f, "eBPF unsupported here: {e}"),
            Self::Object(e) => write!(f, "eBPF object unavailable: {e}"),
            Self::Load(e) => write!(f, "eBPF load failed: {e}"),
            Self::Attach(e) => write!(f, "eBPF attach failed: {e}"),
            Self::Map(e) => write!(f, "eBPF map read failed: {e}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// A loaded, attached `sys_enter_execve` counter. Holds the aya [`Ebpf`] that owns the
/// program, its map, and the live attachment; dropping this detaches and frees them, pinning nothing
/// (P8.4). Read the running total with [`count`](ExecveCounter::count).
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
        // Name the missing prerequisite up front (P8.9): no kernel BTF, or no CAP_BPF/CAP_PERFMON, is
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
    /// (P8.6). Order is unspecified (hash-map iteration); the [`count`](ExecveCounter::count) total is
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

/// A loaded, attached syscall tracer (P9.1/P9.2): the `sys_enter_{execve,openat,connect}` tracepoints
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
    /// [`watch_cgroup`](Self::watch_cgroup) (both configured axes must match).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the filter map is missing or unwritable.
    pub fn watch_pid(&mut self, pid: u32) -> Result<(), ProbeError> {
        self.set_filter(FILTER_TGID, u64::from(pid))
    }

    /// Watch only the process in this **cgroup id** (`bpf_get_current_cgroup_id`): the axis a
    /// sandbox's host workers are attributed on. Pass `0` to stop filtering on cgroup.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the filter map is missing or unwritable.
    pub fn watch_cgroup(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        self.set_filter(FILTER_CGROUP, cgroup_id)
    }

    /// Clear both filter axes: observe every process on the host again (the load-time default).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the filter map is missing or unwritable.
    pub fn watch_all(&mut self) -> Result<(), ProbeError> {
        self.set_filter(FILTER_TGID, 0)?;
        self.set_filter(FILTER_CGROUP, 0)
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
    /// kept for uniformity with the fallible probe surface, so the P9.3 blocking consumer can add an
    /// error path without breaking callers.
    pub fn drain(&mut self, mut on_event: impl FnMut(SyscallEvent)) -> Result<usize, ProbeError> {
        let mut delivered = 0;
        // One `RingBufItem` is outstanding at a time; each is consumed (parsed to an owned, `Copy`
        // event) before the next `next()`, so the loop never holds two. `self.events` is the same
        // consumer every call, so its position/cache stay coherent (a fresh one would spin — see the
        // field doc).
        while let Some(item) = self.events.next() {
            if let Some(event) = SyscallEvent::from_bytes(&item) {
                on_event(event);
                delivered += 1;
            }
        }
        Ok(delivered)
    }

    /// Stream a **live trace** (P9.3): loop, calling `on_event` for each event as it arrives, until
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
/// `EEXIST`: a clsact qdisc already on the interface is not an error (the attach is idempotent).
const EEXIST: i32 = 17;
/// Where `ip netns` bind-mounts a named network namespace's handle (matches the driver's own
/// `netns_path`), so [`TapMonitor::attach_in_netns`] can open a sandbox's netns by name.
const NETNS_DIR: &str = "/run/netns";

/// Per-VM network **totals** (P10.3): one sandbox's traffic summed across all its flows, from the tap's
/// perspective — **ingress** is what the guest sent, **egress** what it received. The sandbox-level
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

/// A loaded, attached network-flow monitor (P10): `tc`/clsact classifiers on a VM's tap that count
/// bytes/packets per IPv4 flow per direction into a map [`flows`](Self::flows) / [`totals`](Self::totals)
/// read. Owns the aya [`Ebpf`] (programs, map, live attachments). Bind it to the *specific* tap the
/// driver named for one sandbox with [`attach_in_netns`](Self::attach_in_netns) (its `fc0` inside its
/// netns, decision 017), or to an interface in the current netns with [`attach`](Self::attach).
///
/// **Lifetime.** Dropping the monitor frees its userspace handles (the map and program fds). The
/// in-kernel `tc` filter it left on the tap is reclaimed by the sandbox's **netns teardown** (`ip netns
/// del` cascades the tap, its clsact qdisc, and the filters away, decision 017/023) — so a torn-down
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

    /// Bind the monitor to the **specific tap the driver named for one sandbox** (P10.4): that tap lives
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

    /// The per-VM network **totals** (P10.3): every [`flows`](Self::flows) entry summed into one
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
/// back — so a `tc` attach lands in a sandbox's netns without moving the whole process (only this
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
/// best-effort — attempting it is still strictly better than leaving the thread in a doomed netns.
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

/// The cgroup v2 id of process `pid` — the same `u64` `bpf_get_current_cgroup_id` reports for tasks in
/// that cgroup, so it is exactly what [`SyscallTracer::watch_cgroup`] filters on. This is the **P9.4
/// bridge**: take a sandbox's VMM pid from the Firecracker track, resolve its cgroup id here, and
/// [`watch_cgroup`](SyscallTracer::watch_cgroup) it so the trace shows only that sandbox's host
/// footprint (the whole cgroup: the VMM and its threads, not just one tgid).
///
/// It reads the process's **unified** cgroup path from `/proc/<pid>/cgroup` (the `0::/…` line), then
/// returns the inode number of `/sys/fs/cgroup/<path>` — for cgroup v2 that inode *is* the kernel's
/// cgroup id. Pure `std` fs, no `unsafe`.
///
/// # Errors
/// [`ProbeError::Map`] if `/proc/<pid>/cgroup` can't be read, has no unified (`0::`) line (a
/// cgroup-v1-only host), or the cgroup dir can't be stat'd.
pub fn cgroup_id_of_pid(pid: u32) -> Result<u64, ProbeError> {
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
    let dir = format!("/sys/fs/cgroup{rel}");
    let meta = std::fs::metadata(&dir)
        .map_err(|e| ProbeError::Map(format!("stat cgroup dir {dir}: {e}")))?;
    Ok(meta.ino())
}

/// The cgroup id of the current process ([`cgroup_id_of_pid`] of `std::process::id()`) — for a
/// self-trace or a test.
///
/// # Errors
/// As [`cgroup_id_of_pid`].
pub fn cgroup_id_of_self() -> Result<u64, ProbeError> {
    cgroup_id_of_pid(std::process::id())
}

/// Whether the host can load eBPF at all — a cheap pre-flight the CLI/`setup` can call before it
/// tries to attach anything. Checks for kernel BTF (`/sys/kernel/btf/vmlinux`), the CO-RE
/// prerequisite. [`check_support`] is the fuller gate (BTF **and** the capabilities), with a legible
/// reason.
#[must_use]
pub fn ebpf_supported() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// `CAP_PERFMON` (bit 38): attaching a program to a tracepoint goes through `perf_event_open`, which
/// this gates. `CAP_BPF` (bit 39): loading programs/maps and reading maps. The two split out of
/// `CAP_SYS_ADMIN` in Linux 5.8, so a loader needs **just these two**, not full root (P8.8).
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Parse the low 64 bits of the effective-capability mask from `/proc/<pid>/status` text: the hex
/// value on the `CapEff:` line, or `None` when that line is absent or unparseable. Pure (takes the
/// text) so the bit logic is unit-testable without a live `/proc` — the same pure-parser pattern the
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
/// binary alike: the point of P8.8 is that the second, unprivileged path works.
fn mask_has_load_caps(mask: u64) -> bool {
    (mask >> CAP_BPF) & 1 == 1 && (mask >> CAP_PERFMON) & 1 == 1
}

/// Whether this process holds the capabilities the probes need, read from the effective set in
/// `/proc/self/status` (`CapEff:`, a 64-bit hex mask) — no `libc`, no `unsafe`. The standard
/// requirement is the two caps; an exotic host with only `CAP_BPF` and a permissive
/// `kernel.perf_event_paranoid` may also manage the tracepoint attach, but this pre-flight names the
/// standard path rather than probing sysctls (a conservative advisory, not the kernel's final say).
fn have_load_caps() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .is_some_and(mask_has_load_caps)
}

/// The eBPF analogue of the driver's Firecracker-version guard (P6.9b): check the host can actually
/// load the probes and, if not, return a **legible typed error naming the requirement** — a BTF-less
/// kernel or missing capabilities, caught here rather than as a cryptic verifier reject or `EPERM`
/// deep in the load (P8.9). [`ExecveCounter::load`] runs this first; the CLI/`setup` can call it to
/// report eBPF readiness before attempting anything.
///
/// The BTF check is a deliberate engine *baseline*, not just this program's need: the shipped object
/// is built CO-RE (`--btf`) and Phase 9 will read kernel struct fields, which does need vmlinux BTF,
/// so the engine requires a BTF-enabled kernel uniformly (the modern-distro default) rather than
/// per-program. A kernel lacking it that could still load *this* relocation-free P8 program is refused
/// on purpose, so the support story stays one line, not a per-probe matrix.
///
/// # Errors
/// [`ProbeError::Unsupported`] naming the first missing prerequisite (BTF, then capabilities).
pub fn check_support() -> Result<(), ProbeError> {
    // Deliberate baseline (see the fn doc): require vmlinux BTF uniformly for the CO-RE object, even
    // though this relocation-free P8 program would load without it.
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
        // Host-safe (no eBPF): the P9.4 resolver reads `/proc/self/cgroup` + the cgroup dir's inode.
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
}
