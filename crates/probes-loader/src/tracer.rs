//! The syscall tracepoints: a single-syscall counter and the multi-syscall tracer.

use std::time::Duration;

use aya::Ebpf;
use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use ekvm_probes_common::SyscallEvent;

use crate::meter::TARGET_PRESENT;
use crate::{ProbeError, check_support, load_object};

/// The tracepoint program's name (its ELF section symbol, set by `#[tracepoint] fn count_execve`).
const PROGRAM: &str = "count_execve";
/// The per-CPU counter map's name (the `#[map] static EXECVE_COUNT` symbol).
const MAP: &str = "EXECVE_COUNT";
/// The per-PID hash map's name (the `#[map] static EXECVE_BY_PID` symbol).
const MAP_BY_PID: &str = "EXECVE_BY_PID";
/// The `syscalls` tracepoint category every program in this module attaches under.
const TP_SYSCALLS: &str = "syscalls";
/// The event the counter program hooks: `syscalls/sys_enter_execve`.
const TP_NAME: &str = "sys_enter_execve";

/// A loaded, attached `sys_enter_execve` counter. Holds the aya [`Ebpf`] that owns the
/// program, its map, and the live attachment; dropping this detaches and frees them, pinning
/// nothing. Read the running total with [`count`](ExecveCounter::count).
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
        let mut ebpf = load_object()?;

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
        program.attach(TP_SYSCALLS, TP_NAME).map_err(|e| {
            ProbeError::Attach(format!(
                "attach `{PROGRAM}` to {TP_SYSCALLS}/{TP_NAME}: {e}"
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
        per_cpu_sum(&self.ebpf, MAP)
    }

    /// The per-PID `execve` counts as `(pid, count)` pairs, read from the `EXECVE_BY_PID` hash
    /// map. Order is unspecified (hash-map iteration); the [`count`](ExecveCounter::count) total is
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

/// Read a kernel-side single-slot **per-CPU** `u64` counter (the `EVENT_DROPS` shape) and sum its
/// slots into one total. Every drop/count surface in this crate reads through here, and the
/// mechanism is that this holds the crate's only `PerCpuArray::try_from`, so the map-open/read error
/// story is one story rather than one per counter. Deliberately not a list of the callers: such a
/// list is one more copy, and it drifts like every copy.
pub(crate) fn per_cpu_sum(ebpf: &Ebpf, name: &str) -> Result<u64, ProbeError> {
    let map = ebpf
        .map(name)
        .ok_or_else(|| ProbeError::Map(format!("map `{name}` not found")))?;
    let counter: PerCpuArray<_, u64> = PerCpuArray::try_from(map)
        .map_err(|e| ProbeError::Map(format!("open `{name}` as a per-cpu array: {e}")))?;
    let per_cpu = counter
        .get(&0, 0)
        .map_err(|e| ProbeError::Map(format!("read `{name}`[0]: {e}")))?;
    // Saturate, don't `.sum()`: these are adversarial kernel-written counters, and the crate's bar
    // is that a hostile guest can never wrap a large drop/event count down to a small one (the same
    // discipline `totals()`/denials use). A plain `.sum()` would also panic on overflow in a debug
    // build, which the host path forbids. Unreachable in practice (per-CPU drop slots can't sum past
    // `u64::MAX`), but kept consistent with the stated invariant rather than relying on that.
    Ok(per_cpu.iter().copied().fold(0u64, u64::saturating_add))
}

/// The tracepoint programs the syscall tracer attaches, paired with the `syscalls` event each hooks.
/// One entry per `sys_enter_*` of interest; the program names are the `#[tracepoint] fn` symbols in
/// `crates/probes`.
const TRACERS: [(&str, &str); 3] = [
    ("trace_execve", "sys_enter_execve"),
    ("trace_openat", "sys_enter_openat"),
    ("trace_connect", "sys_enter_connect"),
];
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
    /// Ring records [`drain`](Self::drain) could not decode as a [`SyscallEvent`] (the userspace
    /// twin of the kernel's `EVENT_DROPS` counter), read by
    /// [`undecodable_events`](Self::undecodable_events) so writer/reader drift surfaces as a
    /// coverage gap instead of an empty footprint reading as a quiet run.
    undecodable: u64,
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
        let mut ebpf = load_object()?;

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

        Ok(Self {
            ebpf,
            events,
            undecodable: 0,
        })
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
    /// ([`crate::SharedTracer`]) drives; a single-sandbox caller stays on the default `FILTER` path and never
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
        per_cpu_sum(&self.ebpf, EVENT_DROPS_MAP)
    }

    /// Ring records [`drain`](Self::drain) read but could not decode as a [`SyscallEvent`]: the
    /// userspace twin of [`dropped_events`](Self::dropped_events), covering writer/reader drift
    /// (a resized or reshaped kernel event record) the way that one covers a full buffer. A
    /// monotonic counter since [`load`](Self::load); callers snapshot it around a window and
    /// report a nonzero delta as a coverage gap. Zero on a healthy host: the kernel writer sizes
    /// every record it commits.
    #[must_use]
    pub fn undecodable_events(&self) -> u64 {
        self.undecodable
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
    /// waiting; [`stream`](Self::stream) wraps it in the live-trace loop. A record that does not
    /// decode is **counted** ([`undecodable_events`](Self::undecodable_events)) and skipped, never
    /// silent: an `Err` here would abandon every event still queued behind the bad record (and the
    /// shared multi-sandbox drain discards drain errors), so the loss rides a counter the collector
    /// turns into a coverage gap instead.
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
            if let Some(event) = decode_or_count(&item, &mut self.undecodable) {
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
    /// Kept a poll-with-sleep loop deliberately. A zero-idle-latency `poll`/`epoll` wait on the ring
    /// buffer's fd is possible in principle, but aya's `RingBuf` exposes only `AsRawFd`, not `AsFd`, so
    /// handing its fd to a poller needs `BorrowedFd::borrow_raw`, which is `unsafe` and this crate is
    /// `#![forbid(unsafe_code)]` (the loader stays unsafe-free by policy). The only caller that matters
    /// is a live-trace viewer, never the audit record (that uses [`drain`](Self::drain)/`collect`), so
    /// the idle sleep is immaterial. `keep_going` is where a caller wires a deadline or a Ctrl-C flag.
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

/// Decode one ring record, or count it: `Some(event)` when the bytes decode as a [`SyscallEvent`],
/// else bump `undecodable` (saturating, the adversarial-counter discipline [`per_cpu_sum`] states)
/// and `None`. Pure, so the skip branch, unreachable from a real kernel ring buffer (the writer
/// sizes every record it commits), is testable host-safe.
fn decode_or_count(bytes: &[u8], undecodable: &mut u64) -> Option<SyscallEvent> {
    match SyscallEvent::from_bytes(bytes) {
        Some(event) => Some(event),
        None => {
            *undecodable = undecodable.saturating_add(1);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    // Host-safe: the decode-or-count decision on raw bytes, no aya, no kernel.
    use super::decode_or_count;
    use ekvm_probes_common::EVENT_SIZE;

    #[test]
    fn a_short_ring_record_is_counted_not_silently_dropped() {
        let mut undecodable = 0u64;
        let short = [0u8; EVENT_SIZE - 1];
        assert!(decode_or_count(&short, &mut undecodable).is_none());
        assert_eq!(
            undecodable, 1,
            "a record that does not decode must be counted, never silently skipped"
        );
    }

    #[test]
    fn the_undecodable_counter_saturates_instead_of_wrapping() {
        // Adversarial-counter discipline: a huge count must never wrap down to a small one, and a
        // debug-build overflow panic is forbidden on the host path.
        let mut undecodable = u64::MAX;
        assert!(decode_or_count(&[], &mut undecodable).is_none());
        assert_eq!(undecodable, u64::MAX);
    }

    #[test]
    fn a_full_size_record_decodes_and_counts_nothing() {
        let mut undecodable = 0u64;
        let full = [0u8; EVENT_SIZE];
        assert!(decode_or_count(&full, &mut undecodable).is_some());
        assert_eq!(undecodable, 0, "a decoded record is not a loss");
    }
}
