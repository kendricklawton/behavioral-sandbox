//! The syscall tracepoints: a single-syscall counter and the multi-syscall tracer.

use std::time::Duration;

use aya::Ebpf;
use aya::maps::{Array, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf};
use bsx_probes_common::{
    ARG_SLOT, FILTER_CGROUP, FILTER_MODE_SLOT, FILTER_TGID, SyscallEvent, TRACEPOINT_ARGS,
};

use crate::maps::{add_cgroup_key, remove_cgroup_key};
use crate::{ProbeError, check_support, load_object};

/// The tracepoint program's name (its ELF section symbol, set by `#[tracepoint] fn count_execve`).
const PROGRAM: &str = "count_execve";
/// The per-CPU counter map's name (the `#[map] static EXECVE_COUNT` symbol).
const MAP: &str = "EXECVE_COUNT";
/// The per-PID hash map's name (the `#[map] static EXECVE_BY_PID` symbol).
const MAP_BY_PID: &str = "EXECVE_BY_PID";
/// The per-CPU counter of pids a full `EXECVE_BY_PID` dropped (`#[map] static PID_DROPS`).
const PID_DROPS_MAP: &str = "PID_DROPS";
/// The `syscalls` tracepoint category every program in this module attaches under.
const TP_SYSCALLS: &str = "syscalls";
/// The event the counter program hooks: `syscalls/sys_enter_execve`.
const TP_NAME: &str = "sys_enter_execve";

/// A loaded, attached `sys_enter_execve` counter. Owns the aya [`Ebpf`] and pins nothing, so
/// dropping it detaches; read the running total with [`count`](ExecveCounter::count).
#[must_use = "dropping an ExecveCounter detaches the probe"]
pub struct ExecveCounter {
    ebpf: Ebpf,
}

impl ExecveCounter {
    /// Loads the compiled object and attaches the `count_execve` tracepoint, so from here every
    /// host `execve` bumps the per-CPU map until this value is dropped.
    ///
    /// # Errors
    /// [`ProbeError::Object`] if the object can't be read (build it: `cargo xtask build-probes`);
    /// [`ProbeError::Load`] if the kernel rejects the object/program (no `CAP_BPF`, no BTF, or a
    /// verifier reject); [`ProbeError::Attach`] if the tracepoint attach fails.
    pub fn load() -> Result<Self, ProbeError> {
        check_support()?;
        let mut ebpf = load_object()?;

        crate::maps::attach_tracepoint(&mut ebpf, PROGRAM, TP_SYSCALLS, TP_NAME)?;

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

    /// The per-PID `execve` counts as `(pid, count)` pairs, order unspecified. The
    /// [`count`](ExecveCounter::count) total is authoritative, since the per-PID map is bounded and
    /// drops new keys when full ([`dropped_pids`](ExecveCounter::dropped_pids) says how many).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn counts_by_pid(&self) -> Result<Vec<(u32, u64)>, ProbeError> {
        let by_pid: AyaHashMap<_, u32, u64> =
            crate::maps::open(&self.ebpf, MAP_BY_PID, "a hash map")?;
        let mut out = Vec::new();
        for entry in by_pid.iter() {
            let (pid, count) =
                entry.map_err(|e| ProbeError::Map(format!("iterate `{MAP_BY_PID}`: {e}")))?;
            out.push((pid, count));
        }
        Ok(out)
    }

    /// Pids a full `EXECVE_BY_PID` could not admit, summed across CPUs and monotonic since
    /// [`load`](ExecveCounter::load). Nonzero means
    /// [`counts_by_pid`](ExecveCounter::counts_by_pid) is partial, while
    /// [`count`](ExecveCounter::count) stays exact.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the drop-counter map is missing or unreadable.
    pub fn dropped_pids(&self) -> Result<u64, ProbeError> {
        per_cpu_sum(&self.ebpf, PID_DROPS_MAP)
    }
}

/// Reads a kernel-side single-slot **per-CPU** `u64` counter and sums its slots into one total, the
/// crate's only per-CPU map open, so the map-open/read error story is one story.
pub(crate) fn per_cpu_sum(ebpf: &Ebpf, name: &str) -> Result<u64, ProbeError> {
    let counter: PerCpuArray<_, u64> = crate::maps::open(ebpf, name, "a per-cpu array")?;
    let per_cpu = counter
        .get(&0, 0)
        .map_err(|e| ProbeError::Map(format!("read `{name}`[0]: {e}")))?;
    // Saturate rather than `.sum()`: these counters are kernel-written and adversarial, so a large
    // drop count must never wrap down to a small one, and `.sum()` would also panic on overflow in
    // a debug build, which the host path forbids.
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
/// The target filter the programs consult (`#[map] static FILTER`), indexed by the shared
/// [`FILTER_TGID`]/[`FILTER_CGROUP`] slots.
const FILTER_MAP: &str = "FILTER";
/// The shared tracer's cgroup target *set* (`#[map] static TRACE_TARGETS`), the analogue of
/// [`METER_TARGETS_MAP`].
const TRACE_TARGETS_MAP: &str = "TRACE_TARGETS";
/// The filter-mode toggle (`#[map] static TRACE_SET`, at the shared [`FILTER_MODE_SLOT`]):
/// `0` = single [`FILTER_MAP`], `1` = the [`TRACE_TARGETS_MAP`] set.
const TRACE_SET_MAP: &str = "TRACE_SET";
/// The per-CPU counter of events a full ring buffer dropped (`#[map] static EVENT_DROPS`), read by
/// [`SyscallTracer::dropped_events`] so best-effort loss is reported, never silent.
const EVENT_DROPS_MAP: &str = "EVENT_DROPS";

/// Where the kernel publishes each tracepoint's field layout, in the order aya resolves them for
/// the attach itself, so verifying the layout needs no access the attach does not already need.
const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// Checks every offset in [`TRACEPOINT_ARGS`] against the kernel's own `format` file for that
/// event, before a program is loaded.
///
/// BTF relocates struct-field accesses, and reading a tracepoint's argument area is not one, so
/// those offsets are an unrelocated ABI assumption: on a kernel that laid the record out
/// differently, `read_at` returns whatever `u64` sits there and the probe follows it as a user
/// pointer, recording an empty or unrelated path with nothing erroring and no drop counter moving.
/// This makes that disagreement a typed [`ProbeError::Unsupported`], which
/// [`crate::SandboxProbes`] records as a coverage gap on the syscall axis.
fn check_tracepoint_abi() -> Result<(), ProbeError> {
    for (_, event) in TRACERS {
        let format = read_tracepoint_format(event)?;
        for arg in TRACEPOINT_ARGS.iter().filter(|arg| arg.event == event) {
            let (offset, size) = field_layout(&format, arg.field).ok_or_else(|| {
                ProbeError::Unsupported(format!(
                    "{TP_SYSCALLS}/{event} declares no `{}` field on this kernel, so the offset the \
                     probe reads its argument at cannot be verified",
                    arg.field
                ))
            })?;
            if (offset, size) != (arg.offset, ARG_SLOT) {
                return Err(ProbeError::Unsupported(format!(
                    "{TP_SYSCALLS}/{event} puts `{}` at offset {offset} size {size} on this kernel, \
                     but the probe reads an {ARG_SLOT}-byte argument at offset {}: the traced paths \
                     would be read from the wrong place",
                    arg.field, arg.offset
                )));
            }
        }
    }
    Ok(())
}

/// The `format` body the kernel publishes for one `syscalls` event, from the first tracefs root that
/// yields it.
fn read_tracepoint_format(event: &str) -> Result<String, ProbeError> {
    TRACEFS_ROOTS
        .iter()
        .find_map(|root| {
            std::fs::read_to_string(format!("{root}/events/{TP_SYSCALLS}/{event}/format")).ok()
        })
        .ok_or_else(|| {
            ProbeError::Unsupported(format!(
                "no readable {TP_SYSCALLS}/{event}/format under {}: the argument offsets the probes \
                 read cannot be verified (mount tracefs, and note the attach reads the `id` file in \
                 the same directory)",
                TRACEFS_ROOTS.join(" or ")
            ))
        })
}

/// The `(offset, size)` a tracepoint `format` body declares for `field`, or `None` when it declares
/// no such field. Pure, so the parse is tested without a readable tracefs (root-only on a normal
/// host). Each line is `field:<C declaration>;\toffset:<n>;\tsize:<n>;\tsigned:<0|1>;`, and the
/// declaration is C, so the field name is its last token once pointer stars and any array suffix
/// are stripped.
fn field_layout(format: &str, field: &str) -> Option<(usize, usize)> {
    format.lines().find_map(|line| {
        let mut parts = line.trim().strip_prefix("field:")?.split(';');
        let name = parts
            .next()?
            .trim()
            .rsplit(|c: char| c.is_whitespace() || c == '*')
            .next()?
            .split('[')
            .next()?;
        if name != field {
            return None;
        }
        let (mut offset, mut size) = (None, None);
        for part in parts {
            let part = part.trim();
            if let Some(n) = part.strip_prefix("offset:") {
                offset = n.parse().ok();
            } else if let Some(n) = part.strip_prefix("size:") {
                size = n.parse().ok();
            }
        }
        Some((offset?, size?))
    })
}

/// A loaded, attached syscall tracer: the `sys_enter_{execve,openat,connect}` tracepoints stream
/// per-event [`SyscallEvent`]s into a ring buffer that [`drain`](Self::drain) reads. Owns the aya
/// [`Ebpf`] and pins nothing, so dropping it detaches. Narrow the stream to one sandbox with
/// [`watch_pid`](Self::watch_pid) / [`watch_cgroup`](Self::watch_cgroup); the default observes the
/// whole host.
#[must_use = "dropping a SyscallTracer detaches the probes"]
pub struct SyscallTracer {
    ebpf: Ebpf,
    /// The ring-buffer consumer, built **once** at load and reused by every [`drain`](Self::drain):
    /// aya tracks the consumer position and a producer-position cache *inside* this value, so a
    /// fresh `RingBuf` per drain (its cache reset to 0 while the kernel-side consumer offset is
    /// already advanced) would defeat the "caught up?" check and spin forever. Its `MapData` owns
    /// the map fd, taken out of `ebpf`; the attached programs keep writing to the same kernel map.
    events: RingBuf<MapData>,
    /// Ring records [`drain`](Self::drain) could not decode as a [`SyscallEvent`], the userspace
    /// twin of the kernel's `EVENT_DROPS` counter, so writer/reader drift surfaces as a coverage
    /// gap rather than an empty footprint reading as a quiet run.
    undecodable: u64,
}

impl SyscallTracer {
    /// Loads the compiled object and attaches all three `sys_enter_*` tracepoints. From here every
    /// matching host syscall that passes the filter is streamed into the ring buffer until this is
    /// dropped. Attaches unfiltered; call a `watch_*` before or after to narrow it.
    ///
    /// # Errors
    /// [`ProbeError::Unsupported`] if the host can't load eBPF (BTF/caps, via [`check_support`]) or
    /// lays a tracepoint's arguments out differently than the object reads them (naming the field
    /// they disagree on); [`ProbeError::Object`] if the object can't be read (build it:
    /// `cargo xtask build-probes`); [`ProbeError::Load`] if the kernel rejects the object/a program;
    /// [`ProbeError::Attach`] if a tracepoint attach fails.
    pub fn load() -> Result<Self, ProbeError> {
        check_support()?;
        check_tracepoint_abi()?;
        let mut ebpf = load_object()?;

        for (program, event) in TRACERS {
            crate::maps::attach_tracepoint(&mut ebpf, program, TP_SYSCALLS, event)?;
        }

        // Build the ring-buffer consumer once (see the `events` field doc). `FILTER` stays in
        // `ebpf` for the `watch_*` setters.
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

    /// Watch only the process tree with this **tgid** (the userspace pid), or `0` to stop filtering
    /// on tgid. Composes with [`watch_cgroup`](Self::watch_cgroup), since both configured axes must
    /// match. **Selects single-filter mode**, switching the tracer off the
    /// [`add_target`](Self::add_target) set, so the two filter models can't half-apply.
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

    /// Switch to **set mode**: the tracepoints pass an event iff its cgroup is a registered
    /// [`add_target`](Self::add_target) member, ignoring the single-target
    /// [`watch_pid`](Self::watch_pid) / [`watch_cgroup`](Self::watch_cgroup) filter. What
    /// [`crate::SharedTracer`] drives; the `watch_*` setters switch back, so the mode always
    /// matches the last setter used and neither filter model can silently no-op. Idempotent.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the mode map is missing or unwritable.
    pub fn use_target_set(&mut self) -> Result<(), ProbeError> {
        self.set_mode(true)
    }

    /// Events the kernel **dropped** because the ring buffer was full, summed across CPUs and
    /// monotonic since [`load`](Self::load), so a nonzero delta around a window is a coverage gap.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the drop-counter map is missing or unreadable.
    pub fn dropped_events(&self) -> Result<u64, ProbeError> {
        per_cpu_sum(&self.ebpf, EVENT_DROPS_MAP)
    }

    /// Ring records [`drain`](Self::drain) read but could not decode as a [`SyscallEvent`]: the
    /// userspace twin of [`dropped_events`](Self::dropped_events), covering writer/reader drift (a
    /// resized or reshaped kernel event record) rather than a full buffer. Monotonic since
    /// [`load`](Self::load), and zero on a healthy host, since the kernel writer sizes every record
    /// it commits.
    #[must_use]
    pub fn undecodable_events(&self) -> u64 {
        self.undecodable
    }

    /// Registers `cgroup_id` in the trace target *set*, switching to set mode if needed, so from
    /// here the tracepoints emit that sandbox's host syscalls. One shared tracer serves every
    /// registered sandbox at a per-syscall cost of one hash lookup. Idempotent.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target/mode map is missing or the write fails.
    pub fn add_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        self.set_mode(true)?;
        add_cgroup_key(
            &mut self.trace_targets()?,
            cgroup_id,
            &format!("register cgroup {cgroup_id} for tracing"),
        )
    }

    /// Unregisters `cgroup_id`, so the tracepoints stop emitting its events. Removing a cgroup that
    /// was never a target is a no-op, not an error.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the target map is missing, or the removal fails for a reason other
    /// than the key being absent.
    pub fn remove_target(&mut self, cgroup_id: u64) -> Result<(), ProbeError> {
        remove_cgroup_key(
            &mut self.trace_targets()?,
            cgroup_id,
            &format!("unregister cgroup {cgroup_id} from tracing"),
        )
    }

    /// Write the filter-mode toggle: `true` = the [`TRACE_TARGETS_MAP`] set, `false` = the single
    /// [`FILTER_MAP`].
    fn set_mode(&mut self, set_mode: bool) -> Result<(), ProbeError> {
        crate::maps::set_flag(&mut self.ebpf, TRACE_SET_MAP, FILTER_MODE_SLOT, set_mode)
    }

    /// The writable `TRACE_TARGETS` set handle.
    fn trace_targets(&mut self) -> Result<AyaHashMap<&mut MapData, u64, u8>, ProbeError> {
        crate::maps::open_mut(&mut self.ebpf, TRACE_TARGETS_MAP, "a hash map")
    }

    /// Write one slot of the `FILTER` array (0 = tgid, 1 = cgroup id; 0 disables that axis).
    fn set_filter(&mut self, slot: u32, value: u64) -> Result<(), ProbeError> {
        let mut filter: Array<_, u64> =
            crate::maps::open_mut(&mut self.ebpf, FILTER_MAP, "an array")?;
        filter
            .set(slot, value, 0)
            .map_err(|e| ProbeError::Map(format!("set `{FILTER_MAP}`[{slot}]: {e}")))
    }

    /// Drains every event currently in the ring buffer, calling `on_event` for each, and returns
    /// how many were delivered. **Non-blocking**: returns 0 on an empty buffer rather than waiting.
    /// A record that does not decode is **counted**
    /// ([`undecodable_events`](Self::undecodable_events)) and skipped rather than returned as an
    /// `Err`, which would abandon every event still queued behind the bad record.
    ///
    /// # Errors
    /// Currently infallible (the consumer was opened once at [`load`](Self::load)); the `Result` is
    /// kept so a blocking consumer can add an error path without breaking callers.
    pub fn drain(&mut self, mut on_event: impl FnMut(SyscallEvent)) -> Result<usize, ProbeError> {
        let mut delivered = 0;
        // One `RingBufItem` is outstanding at a time: each is parsed to an owned `Copy` event
        // before the next `next()`, so the loop never holds two.
        while let Some(item) = self.events.next() {
            if let Some(event) = decode_or_count(&item, &mut self.undecodable) {
                on_event(event);
                delivered += 1;
            }
        }
        Ok(delivered)
    }

    /// Streams a **live trace**: calls `on_event` for each event as it arrives until `keep_going`
    /// returns `false`, sleeping `idle` when the buffer is momentarily empty and draining greedily
    /// otherwise, so latency is bounded by `idle` and `keep_going` is where a caller wires a
    /// deadline.
    ///
    /// A poll-with-sleep loop rather than a `poll`/`epoll` wait, because aya's `RingBuf` exposes
    /// only `AsRawFd` and handing its fd to a poller needs `BorrowedFd::borrow_raw`, which is
    /// `unsafe` while this crate is `#![forbid(unsafe_code)]`.
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

/// Decodes one ring record, or counts it: `Some(event)` when the bytes decode as a
/// [`SyscallEvent`], else a saturating bump of `undecodable` and `None`. Pure, so the skip branch,
/// unreachable from a real kernel ring buffer, is testable host-safe.
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
    // Host-safe: raw-byte decode and the `format` parse, no aya and no readable tracefs.
    use super::{decode_or_count, field_layout};
    use bsx_probes_common::{ARG_SLOT, EVENT_SIZE, TRACEPOINT_ARGS};

    /// A transcript of `events/syscalls/<event>/format` for the three traced events, as an
    /// `x86_64` kernel writes it: the four `common_*` header fields, then one 8-byte slot per
    /// syscall argument. A transcript is not the kernel's word, which is why the check itself runs
    /// against the live file at attach; this exercises the parse and the table host-safe.
    fn format_body(event: &str) -> String {
        let header = "name: EVENT\nID: 42\nformat:\n\
             \tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
             \tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
             \tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
             \tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
             \tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n";
        const ARGS: [(&str, &str); 3] = [
            (
                "sys_enter_execve",
                "\tfield:const char * filename;\toffset:16;\tsize:8;\tsigned:0;\n\
                 \tfield:const char *const * argv;\toffset:24;\tsize:8;\tsigned:0;\n\
                 \tfield:const char *const * envp;\toffset:32;\tsize:8;\tsigned:0;\n",
            ),
            (
                "sys_enter_openat",
                "\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;\n\
                 \tfield:const char * filename;\toffset:24;\tsize:8;\tsigned:0;\n\
                 \tfield:int flags;\toffset:32;\tsize:8;\tsigned:0;\n\
                 \tfield:umode_t mode;\toffset:40;\tsize:8;\tsigned:0;\n",
            ),
            (
                "sys_enter_connect",
                "\tfield:int fd;\toffset:16;\tsize:8;\tsigned:0;\n\
                 \tfield:struct sockaddr * uservaddr;\toffset:24;\tsize:8;\tsigned:0;\n\
                 \tfield:int addrlen;\toffset:32;\tsize:8;\tsigned:0;\n",
            ),
        ];
        let args = ARGS
            .iter()
            .find_map(|(name, args)| (*name == event).then_some(*args))
            .expect("a transcript for every event the tracer attaches to");
        format!("{header}{args}\nprint fmt: \"filename: 0x%08lx\", REC->filename\n")
    }

    #[test]
    fn every_traced_argument_sits_where_the_declared_layout_puts_it() {
        for arg in TRACEPOINT_ARGS {
            assert_eq!(
                field_layout(&format_body(arg.event), arg.field),
                Some((arg.offset, ARG_SLOT)),
                "{}/{} must be read at the offset the kernel declares for it",
                arg.event,
                arg.field
            );
        }
    }

    #[test]
    fn a_field_the_kernel_does_not_declare_has_no_layout() {
        // The refusal the loader turns into `Unsupported`: a renamed or removed argument must read
        // as absent, never as a plausible offset from some other line.
        let body = format_body("sys_enter_execve");
        assert_eq!(field_layout(&body, "pathname"), None);
        assert_eq!(field_layout(&body, ""), None);
        assert_eq!(field_layout("", "filename"), None);
    }

    #[test]
    fn the_field_name_is_read_past_the_c_declaration_it_hides_behind() {
        // Reading `* filename` as the name would match nothing and refuse a healthy kernel.
        for decl in [
            "const char * filename",
            "char *filename",
            "const char __user *filename",
            "char filename[16]",
        ] {
            let line = format!("\tfield:{decl};\toffset:16;\tsize:8;\tsigned:0;\n");
            assert_eq!(
                field_layout(&line, "filename"),
                Some((16, 8)),
                "`{decl}` declares a field named `filename`"
            );
        }
    }

    #[test]
    fn a_matching_field_without_a_parsable_offset_is_not_a_layout() {
        // Half a line must not read as a verified offset: the caller refuses on `None`, and a
        // `Some` here would pass an unchecked offset off as checked.
        assert_eq!(
            field_layout("\tfield:char * filename;\tsize:8;\n", "filename"),
            None
        );
        assert_eq!(
            field_layout(
                "\tfield:char * filename;\toffset:sixteen;\tsize:8;\n",
                "filename"
            ),
            None
        );
    }

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
