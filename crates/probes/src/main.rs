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
//! one (the strong cross-boundary signal core property 1 leaves intact).
//!
//! **P11.1/P11.2/P11.5 — egress enforcement in the kernel.** The ingress hook (a frame the guest
//! *sends*) also consults a per-sandbox allow-list — the [`POLICY`] map of [`PolicyRule`]s the loader
//! fills — and, when the [`ENFORCE`] toggle is on, returns `TC_ACT_SHOT` to drop any guest-sent IPv4
//! packet whose destination matches no rule (deny-by-default), accepting the rest. A dropped packet is
//! first counted against its destination in [`DENIALS`] (P11.5), so the host can report which endpoints
//! a sandbox was blocked from — the audit trail Phase 13 folds in. Enforcement is opt-in: a monitor that
//! never sets `ENFORCE` stays observe-only (both hooks accept, the Phase 10 behavior). ARP is always
//! allowed so the guest can resolve its gateway; the egress hook (reply → guest) always accepts.
//!
//! **P12.1 — per-cgroup resource accounting from the scheduler.** [`account_sched_switch`] attaches
//! **once** to the `sched/sched_switch` tracepoint and accumulates each cgroup's on-CPU **nanoseconds**
//! into the [`CPU_NS`] map, keyed by cgroup id, for the cgroups the loader registered in
//! [`METER_TARGETS`] (a *set*, so one shared program stays O(1) per switch no matter how many sandboxes
//! are metered — P12.4). This is the host CPU a sandbox's VMM burns running the guest's vCPUs, attributed
//! to the sandbox's own cgroup — the metering primitive (the engine measures; the hoster bills). Memory
//! and IO ride the kernel's native cgroup v2 counters on the loader side, so this eBPF half is the CPU
//! axis where per-event timing earns its keep.
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
        bpf_ktime_get_ns, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{classifier, map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{TcContext, TracePointContext},
};
use agent_probes_common::{
    rule_matches, FlowCounts, FlowKey, PolicyRule, Syscall, SyscallEvent, DETAIL_CAP,
    ETHERTYPE_OFFSET, ETH_HLEN, ETH_P_ARP, ETH_P_IP, IPPROTO_TCP, IPPROTO_UDP, MAX_POLICY_RULES,
    SOCKADDR_SNAP,
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

/// The set of cgroup ids to trace (`cgroup_id -> 1`), the syscall analogue of [`METER_TARGETS`]
/// (P13.5). **One shared tracer, a target *set*** is what keeps host-syscall observation bounded under
/// many concurrent sandboxes: the three `sys_enter_*` tracepoints are global, so a tracer-per-sandbox
/// would attach (and run) *N* copies of each program on *every* matching syscall (O(sandboxes) per
/// syscall — the shape decision 026 rejects for `sched_switch`). Instead one shared tracer is attached
/// once and every sandbox registers its cgroup here; the hot path is a single hash lookup, and
/// [`EVENTS`] only ever carries the registered cgroups' events (not the whole host's). Consulted only
/// when [`TRACE_SET`] is on; empty + off is the load-time single-[`FILTER`] behaviour.
#[map]
static TRACE_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_CGROUPS, 0);

/// Selects which filter governs the tracepoints (slot 0): `0` (the load-time default) uses the
/// single-target [`FILTER`] (tgid/cgroup) — the Phase-9 single-sandbox path the tests and demos drive;
/// `1` uses the [`TRACE_TARGETS`] *set* — the shared multi-sandbox tracer (P13.5). One toggle, so the
/// two modes never interfere: a set-mode tracer ignores `FILTER`, and a `FILTER`-mode tracer ignores
/// the set.
#[map]
static TRACE_SET: Array<u32> = Array::with_max_entries(1, 0);

const FILTER_MODE_SLOT: u32 = 0;

/// Whether an event from `tgid` in `cgroup` passes the loader-set filter. In **set mode**
/// ([`TRACE_SET`] slot 0 = 1) the event passes iff its cgroup is a registered [`TRACE_TARGETS`] member
/// — the shared multi-sandbox tracer. Otherwise the single-target [`FILTER`] governs: each configured
/// (non-zero) axis must match, an absent/zero slot reads as "unfiltered".
///
/// `#[inline(always)]`: folded into each tracepoint so a program stays a single self-contained unit
/// (no BPF-to-BPF call), matching the verifier profile P8 proved.
#[inline(always)]
fn passes_filter(tgid: u32, cgroup: u64) -> bool {
    if TRACE_SET.get(FILTER_MODE_SLOT).copied().unwrap_or(0) != 0 {
        // Set mode: pass only registered cgroups. `get_ptr` is a presence check without a deref, so no
        // `unsafe` is needed (the same membership test `account_sched_switch` uses for the meter).
        return TRACE_TARGETS.get_ptr(&cgroup).is_some();
    }
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

/// Per-destination **denied**-packet counters (P11.5), keyed by the guest-sent [`FlowKey`] the egress
/// policy dropped. The audit trail of *which endpoints a sandbox was blocked from*: the loader reads it
/// and Phase 13 folds it into the per-run record. Bounded at [`MAX_FLOWS`] like [`FLOWS`]; best-effort
/// (a non-atomic lookup-or-init can undercount a burst by one). Empty until enforcement drops something.
#[map]
static DENIALS: HashMap<FlowKey, u64> = HashMap::with_max_entries(MAX_FLOWS, 0);

/// The Linux `tc` action a classifier returns to the kernel: `TC_ACT_OK` (`0`) lets the packet
/// continue, `TC_ACT_SHOT` (`2`) drops it. Named after the kernel ABI constants so the values are
/// unmistakable; [`Verdict`] is what the program's *logic* speaks, lowering to these on return.
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

/// A classifier's decision, in the program's own terms rather than a bare `i32`: [`Verdict::Pass`]
/// accepts the packet, [`Verdict::Drop`] drops it (P11.2). The functions decide in `Verdict`s and the
/// `#[classifier]` entry points lower to the `tc` ABI with [`as_tc`](Verdict::as_tc), so no magic
/// action number leaks into the logic.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Accept the packet (`TC_ACT_OK`).
    Pass,
    /// Drop the packet at the tap (`TC_ACT_SHOT`).
    Drop,
}

impl Verdict {
    /// The `tc` action number this verdict returns to the kernel.
    fn as_tc(self) -> i32 {
        match self {
            Self::Pass => TC_ACT_OK,
            Self::Drop => TC_ACT_SHOT,
        }
    }
}

/// The per-sandbox egress allow-list (P11.1): a fixed [`MAX_POLICY_RULES`] array of [`PolicyRule`] the
/// loader fills and the ingress classifier scans (P11.2). Zero-initialized at load, so every slot starts
/// `active == 0` (empty) — an un-configured monitor has an empty policy, which only matters once
/// [`ENFORCE`] is on. Sized per-object, so it is naturally **per VM** (each `TapMonitor` loads its own).
#[map]
static POLICY: Array<PolicyRule> = Array::with_max_entries(MAX_POLICY_RULES as u32, 0);

/// Enforcement toggle (P11.2): slot 0 is `0` for **observe-only** (accept every packet, the Phase 10
/// behavior) or `1` for **deny-by-default egress** (guest-sent IPv4 packets must match [`POLICY`]).
/// Zero-initialized at load, so a monitor enforces nothing until the loader opts in — existing
/// observation keeps working unchanged, and every allowance is explicit (guardrail 3).
#[map]
static ENFORCE: Array<u32> = Array::with_max_entries(1, 0);

/// Which way a frame crossed the tap, from the tap's perspective (matching [`FlowCounts`]): `Ingress`
/// is a frame the guest sent (arriving at the tap), `Egress` a frame delivered to the guest.
#[derive(Clone, Copy)]
enum Direction {
    Ingress,
    Egress,
}

/// `tc`/clsact **ingress** on a VM's tap — a frame the guest sent (egress *from the guest*). Counts it
/// against its flow, then returns the egress-policy verdict (P11.2): accept under observe-only, or under
/// enforcement accept only if the destination matches the sandbox's [`POLICY`] allow-list, else drop.
/// Attached by the userspace loader's `TapMonitor` after it adds the clsact qdisc.
#[classifier]
pub fn tap_ingress(ctx: TcContext) -> i32 {
    count(&ctx, Direction::Ingress);
    egress_verdict(&ctx).as_tc()
}

/// `tc`/clsact **egress** on a VM's tap — a frame delivered to the guest. Always accepted: egress policy
/// governs what the guest *sends* (the ingress hook), and replies to allowed traffic must come back in.
#[classifier]
pub fn tap_egress(ctx: TcContext) -> i32 {
    count(&ctx, Direction::Egress);
    Verdict::Pass.as_tc()
}

/// The allow/drop verdict for a **guest-sent** frame (P11.2). Observe-only ([`ENFORCE`] slot 0 is `0`)
/// accepts everything, preserving the Phase 10 behavior. Under enforcement, ARP is always allowed (the
/// guest must resolve its on-link gateway to reach *any* endpoint), a non-IPv4 or truncated frame is
/// dropped (deny-by-default), and an IPv4 frame is accepted only if its destination matches [`POLICY`].
/// A denied IPv4 frame is recorded in [`DENIALS`] before the drop (P11.5), so the host can report which
/// endpoint a guest was blocked from — the audit trail Phase 13 folds into the per-run record.
#[inline(always)]
fn egress_verdict(ctx: &TcContext) -> Verdict {
    if ENFORCE.get(0).copied().unwrap_or(0) == 0 {
        return Verdict::Pass;
    }
    // ARP must survive deny-by-default: without resolving 10.200.0.1 the guest can't send IP at all.
    match ctx.load::<u16>(ETHERTYPE_OFFSET).map(u16::from_be) {
        Ok(ETH_P_ARP) => return Verdict::Pass,
        Ok(ETH_P_IP) => {}
        _ => return Verdict::Drop, // non-IPv4 (or an unreadable ethertype): deny by default, no 5-tuple to log
    }
    let Some(key) = parse(ctx) else {
        return Verdict::Drop; // truncated IPv4: can't prove it's allowed (or key it), so drop
    };
    if policy_allows(key.dst_addr, key.dst_port, key.proto) {
        Verdict::Pass
    } else {
        record_denial(&key); // P11.5: log which endpoint was blocked, then drop
        Verdict::Drop
    }
}

/// Record one denied guest-sent packet against its destination flow in [`DENIALS`] (P11.5). Best-effort
/// like [`FLOWS`]: a lookup-or-init counter (the verifier's mandatory null-check on the map pointer), not
/// atomic across CPUs, so a burst can undercount by one — fine for an audit signal. A full map drops new
/// denied flows; the ones already recorded stay.
#[inline(always)]
fn record_denial(key: &FlowKey) {
    // SAFETY: the map helpers are the verifier-checked BPF ops; the returned pointer is dereferenced
    // only inside the `Some` arm (the mandatory null-check) and never held across a helper call.
    unsafe {
        if let Some(count) = DENIALS.get_ptr_mut(key) {
            *count += 1;
        } else {
            let _ = DENIALS.insert(key, &1, 0);
        }
    }
}

/// Whether the sandbox's [`POLICY`] allow-list admits destination `(addr, port, proto)` (P11.2): scan
/// the fixed rule array in a **bounded loop** (the compile-time [`MAX_POLICY_RULES`] cap the verifier
/// needs) and accept on the first active rule that matches. Deny-by-default: no match means drop. The
/// per-rule test is [`rule_matches`], single-sourced with the host-tested [`agent_probes_common`] parser.
#[inline(always)]
fn policy_allows(dst_addr: u32, dst_port: u16, proto: u8) -> bool {
    let mut i: u32 = 0;
    while i < MAX_POLICY_RULES as u32 {
        if let Some(rule) = POLICY.get(i) {
            if rule_matches(rule, dst_addr, dst_port, proto) {
                return true;
            }
        }
        i += 1;
    }
    false
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

// ---------------------------------------------------------------------------
// Resource accounting (P12.1): per-cgroup on-CPU time from the scheduler, the metering primitive
// (the engine measures; the hoster bills). Unlike the syscall/network probes this reads no packet or
// argument — it times how long each cgroup's tasks hold a CPU, which is exactly the VMM's host CPU
// footprint (running the guest vCPUs), attributed to the sandbox's own cgroup (P12.2 correlates it
// with the Firecracker track's per-VM cgroup). Memory/IO come from the kernel's native cgroup v2
// counters on the loader side (`memory.peak`, `io.stat`), the "or cgroup" half of the P12.1 box.
// ---------------------------------------------------------------------------

/// Per-cgroup accumulated on-CPU time in **nanoseconds** (P12.1), keyed by cgroup id
/// (`bpf_get_current_cgroup_id`) — the same id [`agent_probes_loader::cgroup_id_of_pid`] resolves from
/// a VMM pid, so the loader reads exactly the sandbox it means. Bounded at [`MAX_CGROUPS`]; with a
/// target cgroup set (the common case, one sandbox) it holds a single entry. Best-effort like the flow
/// counters: the read-modify-write is per-CPU-serialized by the scheduler hook but the add across CPUs
/// isn't atomic, so a heavily-parallel cgroup can undercount by a hair — fine for a metering signal.
#[map]
static CPU_NS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_CGROUPS, 0);

/// Cap on the per-cgroup CPU map — a fixed load-time bound. One entry per metered cgroup; comfortably
/// covers a host's live cgroups when metering-all, and is trivially enough for the targeted case.
const MAX_CGROUPS: u32 = 1024;

/// This CPU's timestamp at its **last** `sched_switch`, so the slice a task just ran is `now -
/// LAST_SWITCH[cpu]`. A [`PerCpuArray`] (one slot, per-CPU): each CPU reads and writes only its own
/// copy, so no cross-CPU atomic and no key math — the natural home for a per-CPU cursor. Zero-init at
/// load, so the first switch on a CPU has no prior stamp and is skipped (the guard below).
#[map]
static LAST_SWITCH: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The set of cgroup ids to meter (`cgroup_id -> 1`), written by the loader as sandboxes come and go.
/// **One shared program, a target *set*** is what keeps this sane under many concurrent sandboxes
/// (P12.4): the `sched_switch` tracepoint is global, so a program-per-sandbox would run every attached
/// program on *every* context switch (O(sandboxes) per switch). Instead one program is attached once and
/// consults this set — the hot path is a single hash lookup, and [`CPU_NS`] only ever holds the
/// registered cgroups (not every cgroup on the box). Empty by default; a cgroup is metered when it is in
/// this set **or** [`METER_ALL`] is on.
#[map]
static METER_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_CGROUPS, 0);

/// A meter-**everything** toggle (slot 0), for a whole-host view or a test: `0` (the load-time default)
/// meters only the [`METER_TARGETS`] set, `1` meters every cgroup (so [`CPU_NS`] then grows toward one
/// entry per live cgroup, bounded by [`MAX_CGROUPS`]). The targeted set is the multi-sandbox path; this
/// is the escape hatch, not the default.
#[map]
static METER_ALL: Array<u32> = Array::with_max_entries(1, 0);

/// `tracepoint/sched/sched_switch` (P12.1): close the on-CPU interval for the task leaving the CPU and
/// add it to that task's cgroup total. At this tracepoint the *current* task is still `prev` (the
/// scheduler fires it before `context_switch` swaps `current`), so `bpf_get_current_cgroup_id` is the
/// cgroup whose CPU slice just ended — exactly what to charge. `LAST_SWITCH[cpu]` is **always**
/// restamped (the next interval is measured from here regardless of who ran), but the delta is added
/// only when the ended cgroup is a registered target (or [`METER_ALL`] is on). A tracepoint returns 0.
#[tracepoint]
pub fn account_sched_switch(_ctx: TracePointContext) -> u32 {
    // SAFETY: both are plain BPF helper calls (a monotonic clock read and the current task's cgroup
    // id) — no pointers, nothing to bound; `current` is still `prev` here (see the fn doc).
    let now = unsafe { bpf_ktime_get_ns() };
    let cgroup = unsafe { bpf_get_current_cgroup_id() };

    // Read this CPU's last-switch stamp and restamp it to now, through one per-CPU pointer. Always
    // restamp: the cursor tracks "when this CPU last switched", independent of which cgroup is metered.
    // SAFETY: `get_ptr_mut(0)` returns this CPU's own slot of the one-element per-CPU array; the
    // program is its sole writer on this CPU and the pointer is only used inside the null-check.
    let last = match LAST_SWITCH.get_ptr_mut(0) {
        Some(slot) => unsafe {
            let prev = *slot;
            *slot = now;
            prev
        },
        None => return 0,
    };
    // No prior stamp (first switch on this CPU), or a non-monotonic reading: nothing to charge yet.
    if last == 0 || now <= last {
        return 0;
    }
    let delta = now - last;

    // Meter this cgroup only if it is a registered target (the multi-sandbox hot path: one hash lookup),
    // or if the meter-all toggle is on. A non-metered cgroup's slice is dropped here — the cursor above
    // was already advanced, so the *next* interval stays exact. `get_ptr` obtains the lookup pointer
    // without dereferencing it (a safe presence check), so no `unsafe` is needed for the membership test.
    let all = METER_ALL.get(0).copied().unwrap_or(0) != 0;
    if !all && METER_TARGETS.get_ptr(&cgroup).is_none() {
        return 0;
    }

    // Lookup-or-init add (the verifier's mandatory null-check on the map pointer), the same best-effort
    // accumulation pattern as the flow counters.
    // SAFETY: the map helpers are the verifier-checked BPF ops; the returned pointer is dereferenced
    // only inside the `Some` arm and never held across a helper call.
    unsafe {
        if let Some(acc) = CPU_NS.get_ptr_mut(&cgroup) {
            *acc += delta;
        } else {
            let _ = CPU_NS.insert(&cgroup, &delta, 0);
        }
    }
    0
}

/// eBPF has no unwinder and the verifier rejects a real panic path, so a program that panics is a
/// build/verify-time bug, never a runtime one — the conventional never-taken handler is a spin.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
