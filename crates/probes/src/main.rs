//! The eBPF programs, compiled `#![no_std]` / `#![no_main]` for `bpfel-unknown-none` and linked by
//! `bpf-linker`. This is the in-kernel, host-side half of core property 2 (observe & enforce from the
//! host): these programs run in the host kernel, out of the guest's reach, and the userspace loader
//! (`crates/probes-loader`, aya) attaches them to a specific sandbox and reads their maps.
//!
//! **P8.2 — count an event into a map.** [`count_execve`] attaches to the `sys_enter_execve`
//! tracepoint and bumps a per-CPU counter each time the host does an `execve`. This is deliberately
//! the *host's* footprint, not the guest's: a microVM services its own syscalls in-guest and they
//! never trap here (see ROADMAP Phase 9), so the strong host-side signals are network + resources
//! (Phases 10 and 12).
//!
//! **P8.5 — built against BTF (CO-RE).** The object carries a `.BTF` / `.BTF.ext` section (emitted by
//! `bpf-linker --btf` from the debug info the build keeps): aya relocates it against the *running*
//! kernel's BTF at load, so one compiled object is portable across kernels (Compile Once, Run
//! Everywhere). This program reads no kernel struct fields yet, so it needs no field-offset
//! relocations — those arrive when Phase 9 reads kernel structs; here BTF is the map typing + the
//! load-time relocation path, the portability mechanism the later phases lean on.
//!
//! **P8.6 — the verifier's rules, hit on purpose.** Two patterns the kernel BPF verifier scrutinizes:
//! a **bounded loop** (walking the fixed-size `comm` buffer — the bound is a compile-time constant, so
//! termination is provable; an unbounded `while` would be rejected), and a **map access pattern**
//! (per-PID lookup-or-init, where dereferencing the lookup result is only allowed after the `Option`
//! null-check the verifier demands).
//!
//! **P9.1 — per-event data via a ring buffer.** [`trace_execve`]/[`trace_openat`]/[`trace_connect`]
//! attach to the matching `sys_enter_*` tracepoints and push a whole [`SyscallEvent`] (pid, tid,
//! cgroup id, `comm`, and the path or sockaddr bytes) into the [`EVENTS`] **ring buffer** — a real
//! per-event stream, not just a count. The ring buffer is the modern replacement for the perf event
//! array: a single MPSC queue shared by all CPUs, so userspace reads events in order with one
//! consumer. Reading the syscall's pointer argument (a user-space `char *` path, or a `sockaddr *`)
//! uses `bpf_probe_read_user_*`, which is why Phase 9 is where BTF/CO-RE starts to earn its keep.
//!
//! **P9.2 — filter to one sandbox's footprint.** Each program consults the [`FILTER`] map first and
//! drops the event unless it matches the target tgid and/or cgroup id the loader set (a zero slot
//! means "don't filter on this axis"), so you can watch exactly one Firecracker worker's host
//! footprint instead of the whole machine's.
//!
//! `unsafe` lives here (raw map-pointer derefs), not on the host path: this crate builds for the BPF
//! target, and the driver/host code stays `#![forbid(unsafe_code)]`. The program/map/link *lifetime*
//! is the loader's (aya drops links on `Drop`; nothing is pinned), so a crashed loader leaves no
//! kernel residue — the eBPF analogue of the driver's no-leak teardown (P8.4).
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use agent_probes_common::{SyscallEvent, Syscall, DETAIL_CAP, SOCKADDR_SNAP};

/// A single-slot **per-CPU** counter of `sys_enter_execve` events. Per-CPU means each CPU increments
/// its own copy of slot 0 with no cross-CPU atomic; the loader sums the per-CPU values when it reads.
#[map]
static EXECVE_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-PID `execve` counts (keyed by tgid). Bounded at [`MAX_PIDS`] entries; a full map just drops
/// new keys (the global [`EXECVE_COUNT`] is the authoritative total). Demonstrates the hash-map
/// lookup-or-init access pattern the verifier constrains (P8.6). Best-effort: the lookup-or-init is
/// not atomic across CPUs, so two concurrent first-sightings of the same pid can each insert `1` and
/// lose one increment (a slight undercount) — another reason the per-CPU global is authoritative.
#[map]
static EXECVE_BY_PID: HashMap<u32, u64> = HashMap::with_max_entries(MAX_PIDS, 0);

/// Cap on the per-PID map — a fixed bound, since maps are sized at load. Comfortably covers the pids
/// churning through a host during one observation window; overflow drops new keys, never faults.
const MAX_PIDS: u32 = 4096;

/// Attach point: `tracepoint/syscalls/sys_enter_execve` (category/name supplied by the loader at
/// attach time). Bumps the global per-CPU total, then records a per-PID count. A tracepoint returns 0.
#[tracepoint]
pub fn count_execve(_ctx: TracePointContext) -> u32 {
    // P8.2 — global per-CPU total.
    if let Some(total) = EXECVE_COUNT.get_ptr_mut(0) {
        // SAFETY: `total` points at this CPU's own copy of the one-element per-CPU array; this
        // program is its sole writer on this CPU and the verifier has proven the pointer in-bounds.
        unsafe { *total += 1 };
    }

    // P8.6 — bounded loop: the current process's `comm` is a fixed 16-byte buffer; walk it to its NUL
    // terminator. The bound is the array length (a compile-time constant) and the `break` is
    // data-dependent, so the verifier can still prove the loop terminates — an *unbounded* `while`
    // would be rejected. `name_len` gates the per-PID record below, so this is not dead code.
    let comm = bpf_get_current_comm().unwrap_or_default();
    let mut name_len = 0u32;
    for &b in comm.iter() {
        if b == 0 {
            break;
        }
        name_len = name_len.saturating_add(1);
    }
    if name_len == 0 {
        return 0;
    }

    // P8.6 — map access pattern: per-PID counts via lookup-or-init. The verifier forbids
    // dereferencing a map lookup result without first proving it non-null; `get_ptr_mut`'s `Option`
    // makes that check mandatory (the `if let Some`), and we insert only on the miss.
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: the map helpers are the verifier-checked BPF map ops; the returned pointer is only
    // dereferenced inside the `Some` arm (the mandatory null-check), never held across a helper call.
    unsafe {
        if let Some(slot) = EXECVE_BY_PID.get_ptr_mut(&pid) {
            *slot += 1;
        } else {
            let _ = EXECVE_BY_PID.insert(&pid, &1, 0);
        }
    }
    0
}

/// A single MPSC **ring buffer** (P9.1) of per-event [`SyscallEvent`] records, shared by every CPU;
/// the loader drains it in order with one consumer. 256 KiB (a power-of-two multiple of the page size,
/// as the map type requires); when full it drops new events rather than blocking the syscall.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// The target filter (P9.2), an [`Array`] the loader writes: slot 0 is a target **tgid**, slot 1 a
/// target **cgroup id**. A zero slot means "don't filter on this axis"; a non-zero slot passes only
/// events whose tgid / cgroup id matches. Zero-initialized at load, so the default is observe-all.
#[map]
static FILTER: Array<u64> = Array::with_max_entries(2, 0);

const FILTER_TGID: u32 = 0;
const FILTER_CGROUP: u32 = 1;

/// Whether an event from `tgid` in `cgroup` passes the loader-set [`FILTER`]: each configured
/// (non-zero) axis must match. An absent/zero slot reads as "unfiltered", so the map is optional.
///
/// `#[inline(always)]`: folded into each tracepoint so a program stays a single self-contained unit
/// (no BPF-to-BPF call), matching the verifier profile P8 proved.
#[inline(always)]
fn passes_filter(tgid: u32, cgroup: u64) -> bool {
    let want_tgid = FILTER.get(FILTER_TGID).copied().unwrap_or(0);
    let want_cgroup = FILTER.get(FILTER_CGROUP).copied().unwrap_or(0);
    (want_tgid == 0 || want_tgid == u64::from(tgid)) && (want_cgroup == 0 || want_cgroup == cgroup)
}

/// Emit one [`SyscallEvent`] for the current syscall into [`EVENTS`], unless [`FILTER`] rejects it.
/// `arg_off` is the byte offset of the syscall's pointer argument in the tracepoint record (a
/// `char *` path for `execve`/`openat`, a `sockaddr *` for `connect`); `path_like` selects reading it
/// as a NUL-terminated user string or as raw leading sockaddr bytes. A tracepoint returns 0.
///
/// `#[inline(always)]`: each of the three tracepoints inlines this into a single self-contained
/// program, so there is no BPF-to-BPF call for the verifier to reason about (parity with P8's counter).
#[inline(always)]
fn record(ctx: &TracePointContext, kind: Syscall, arg_off: usize, path_like: bool) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    // SAFETY: a plain BPF helper call returning the current task's cgroup id — no pointers involved.
    let cgroup = unsafe { bpf_get_current_cgroup_id() };
    if !passes_filter(tgid, cgroup) {
        return 0;
    }

    let comm = bpf_get_current_comm().unwrap_or_default();
    let mut ev = SyscallEvent {
        cgroup_id: cgroup,
        pid: tgid,
        tid,
        syscall: kind as u32,
        detail_len: 0,
        comm,
        detail: [0u8; DETAIL_CAP],
    };

    // SAFETY: `read_at` reads the tracepoint's stable, fixed-layout argument area at a constant offset.
    if let Ok(arg) = unsafe { ctx.read_at::<u64>(arg_off) } {
        let src = arg as *const u8;
        if path_like {
            // SAFETY: copies a user-space C string into the fixed 128-byte buffer; the helper bounds
            // the copy to the destination length and returns the bytes actually read.
            if let Ok(read) = unsafe { bpf_probe_read_user_str_bytes(src, &mut ev.detail[..]) } {
                ev.detail_len = read.len() as u32;
            }
        } else {
            // SAFETY: copies a fixed, constant count of leading sockaddr bytes from user space; a
            // short or unmapped user buffer simply fails, leaving `detail_len` at 0.
            if unsafe { bpf_probe_read_user_buf(src, &mut ev.detail[..SOCKADDR_SNAP]) }.is_ok() {
                ev.detail_len = SOCKADDR_SNAP as u32;
            }
        }
    }

    // A full ring buffer drops the event — best-effort observability, never blocking the syscall.
    let _ = EVENTS.output(&ev, 0);
    0
}

/// `tracepoint/syscalls/sys_enter_execve` — records the program path (arg 0, `const char *filename`).
#[tracepoint]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    record(&ctx, Syscall::Execve, 16, true)
}

/// `tracepoint/syscalls/sys_enter_openat` — records the opened path (arg 1, `const char *filename`,
/// past the `int dfd` at arg 0).
#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    record(&ctx, Syscall::Openat, 24, true)
}

/// `tracepoint/syscalls/sys_enter_connect` — records the leading sockaddr bytes (arg 1,
/// `struct sockaddr *uservaddr`, past the `int fd` at arg 0).
#[tracepoint]
pub fn trace_connect(ctx: TracePointContext) -> u32 {
    record(&ctx, Syscall::Connect, 24, false)
}

/// eBPF has no unwinder and the verifier rejects a real panic path, so a program that panics is a
/// build/verify-time bug, never a runtime one — the conventional never-taken handler is a spin.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
