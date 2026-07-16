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
//! **P10.1/P10.2 — network flows on the tap.** [`tap_ingress`]/[`tap_egress`] are `tc`/clsact
//! classifiers on a VM's tap device: each parses the frame's IPv4 5-tuple and adds the packet to that
//! flow's per-direction byte/packet counters in the [`FLOWS`] map. Unlike the syscall tracepoints, this
//! *is* the guest's own traffic — a microVM's packets cross its tap on the host, so the host sees every
//! one (the strong cross-boundary signal core property 1 leaves intact). Observe-only: the classifiers
//! return `TC_ACT_OK` (accept); Phase 11 returns `TC_ACT_SHOT` to drop a denied flow.
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
    macros::{classifier, map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{TcContext, TracePointContext},
};
use agent_probes_common::{
    FlowCounts, FlowKey, Syscall, SyscallEvent, DETAIL_CAP, ETHERTYPE_OFFSET, ETH_HLEN, ETH_P_IP,
    IPPROTO_TCP, IPPROTO_UDP, SOCKADDR_SNAP,
};

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

/// Per-flow byte/packet counters (P10.2), keyed by the directional IPv4 [`FlowKey`]. Bounded at
/// [`MAX_FLOWS`] (maps are sized at load); a full map drops new flows, the counts already recorded stay
/// live. Best-effort like [`EXECVE_BY_PID`]: a flow's read-modify-write is not atomic across CPUs, so a
/// burst racing two CPUs on one flow can lose an update (a slight undercount). Fine for observability; a
/// per-CPU map is the accuracy upgrade if a later phase needs exactness.
#[map]
static FLOWS: HashMap<FlowKey, FlowCounts> = HashMap::with_max_entries(MAX_FLOWS, 0);

/// Cap on the flow map — a fixed load-time bound, comfortably covering the distinct 5-tuples one
/// sandbox's tap sees in an observation window; overflow drops new flows, never faults.
const MAX_FLOWS: u32 = 4096;

/// A `tc` classifier's "accept this packet" verdict. P10 is **observe-only** (both hooks always accept);
/// Phase 11 (enforcement) returns `TC_ACT_SHOT` to drop a denied flow. A literal so the classifier's
/// return type is unambiguously `i32`, independent of the binding constant's width.
const TC_ACT_OK: i32 = 0;

/// Which way a frame crossed the tap, from the tap's perspective (matching [`FlowCounts`]): `Ingress`
/// is a frame the guest sent (arriving at the tap), `Egress` a frame delivered to the guest.
#[derive(Clone, Copy)]
enum Direction {
    Ingress,
    Egress,
}

/// `tc`/clsact **ingress** on a VM's tap — a frame the guest sent. Counts it against its flow, then
/// accepts. Attached by the userspace loader's `TapMonitor` after it adds the clsact qdisc.
#[classifier]
pub fn tap_ingress(ctx: TcContext) -> i32 {
    count(&ctx, Direction::Ingress);
    TC_ACT_OK
}

/// `tc`/clsact **egress** on a VM's tap — a frame delivered to the guest.
#[classifier]
pub fn tap_egress(ctx: TcContext) -> i32 {
    count(&ctx, Direction::Egress);
    TC_ACT_OK
}

/// Add one packet to its flow's per-direction counters. A non-IPv4 or truncated frame is skipped (the
/// caller still accepts it). `#[inline(always)]` so each classifier stays one self-contained program
/// (no BPF-to-BPF call), the verifier profile P8/P9 established.
#[inline(always)]
fn count(ctx: &TcContext, dir: Direction) {
    let Some(key) = parse(ctx) else {
        return;
    };
    // `skb->len` is the full frame length — counts a GSO super-frame's real bytes, which `data_end -
    // data` (only the linear head) would undercount.
    let bytes = u64::from(ctx.skb.len());
    // SAFETY: the map helpers are the verifier-checked BPF ops; the returned pointer is dereferenced
    // only inside the `Some` arm (the mandatory null-check) and never held across a helper call.
    unsafe {
        if let Some(counts) = FLOWS.get_ptr_mut(&key) {
            match dir {
                Direction::Ingress => {
                    (*counts).ingress_packets += 1;
                    (*counts).ingress_bytes += bytes;
                }
                Direction::Egress => {
                    (*counts).egress_packets += 1;
                    (*counts).egress_bytes += bytes;
                }
            }
        } else {
            let mut init = FlowCounts::default();
            match dir {
                Direction::Ingress => {
                    init.ingress_packets = 1;
                    init.ingress_bytes = bytes;
                }
                Direction::Egress => {
                    init.egress_packets = 1;
                    init.egress_bytes = bytes;
                }
            }
            let _ = FLOWS.insert(&key, &init, 0);
        }
    }
}

/// Read the frame's IPv4 5-tuple with `ctx.load` (each a verifier-bounded `bpf_skb_load_bytes` at a
/// constant, or `ihl`-bounded, offset), or `None` if it is not IPv4-over-Ethernet or a read runs off
/// the packet. Mirrors [`agent_probes_common::parse_ipv4_5tuple`] at the same shared offsets, so the
/// in-kernel reader and the host-tested pure parser can't drift.
#[inline(always)]
fn parse(ctx: &TcContext) -> Option<FlowKey> {
    let ethertype = u16::from_be(ctx.load::<u16>(ETHERTYPE_OFFSET).ok()?);
    if ethertype != ETH_P_IP {
        return None;
    }
    let version_ihl: u8 = ctx.load(ETH_HLEN).ok()?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let proto: u8 = ctx.load(ETH_HLEN + 9).ok()?;
    let src = u32::from_be(ctx.load::<u32>(ETH_HLEN + 12).ok()?);
    let dst = u32::from_be(ctx.load::<u32>(ETH_HLEN + 16).ok()?);
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        let l4 = ETH_HLEN + ihl;
        src_port = u16::from_be(ctx.load::<u16>(l4).ok()?);
        dst_port = u16::from_be(ctx.load::<u16>(l4 + 2).ok()?);
    }
    Some(FlowKey::new(src, dst, src_port, dst_port, proto))
}

/// eBPF has no unwinder and the verifier rejects a real panic path, so a program that panics is a
/// build/verify-time bug, never a runtime one — the conventional never-taken handler is a spin.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
