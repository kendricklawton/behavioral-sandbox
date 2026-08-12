//! The eBPF programs, compiled `#![no_std]` / `#![no_main]` for `bpfel-unknown-none` and linked by
//! `bpf-linker`.
//!
//! The in-kernel, host-side half of core property 2: these run in the host kernel, out of the
//! guest's reach, and the userspace loader (`crates/probes-loader`, aya) attaches them to a specific
//! sandbox and reads their maps. `unsafe` lives here (raw map-pointer derefs), not on the host path.
//! The program/map/link *lifetime* is the loader's (aya drops links on `Drop`; nothing is pinned),
//! so a crashed loader leaves no kernel residue.
//!
//! **Program set:**
//! - **Host syscalls:** [`count_execve`] counts, and [`trace_execve`]/[`trace_openat`]/
//!   [`trace_connect`] push whole [`SyscallEvent`]s into the [`EVENTS`] ring buffer. Deliberately the
//!   *host's* footprint: a microVM services its own syscalls in-guest and they never trap here.
//! - **Network flows:** [`tap_ingress`]/[`tap_egress`] are `tc`/clsact classifiers on a VM's tap,
//!   parsing each frame's 5-tuple into [`FLOWS`] (v4) or [`FLOWS6`] (v6). This *is* the guest's own
//!   traffic, since a microVM's packets cross its tap on the host.
//! - **Egress enforcement:** the ingress hook consults [`POLICY`]/[`POLICY6`] and, when [`ENFORCE`]
//!   is on, drops any guest-sent packet matching no rule (deny-by-default), counting it in
//!   [`DENIALS`]/[`DENIALS6`] first. ARP and on-link ICMPv6 are always allowed, so the guest can
//!   resolve its host end; the egress hook always accepts.
//! - **Resources:** [`account_sched_switch`] attaches **once** to `sched/sched_switch` and
//!   accumulates each registered cgroup's on-CPU nanoseconds into [`CPU_NS`]. Memory and IO ride the
//!   kernel's native cgroup v2 counters on the loader side.
//!
//! **Target filtering.** Every program that feeds an audit record consults [`FILTER`] (single
//! sandbox) or a target *set* ([`TRACE_TARGETS`], [`METER_TARGETS`]) before recording: the three
//! [`record`]-based tracers, and [`account_sched_switch`]. The global tracepoints make a
//! program-per-sandbox O(sandboxes) per event, so one shared program plus a set keeps the hot path a
//! single hash lookup. [`count_execve`] is the exception and is **host-wide on purpose**: it counts
//! every `execve` on the machine, whoever ran it, and its only consumer is
//! `bsx_probes_loader::ExecveCounter`, which never reaches a record.
//!
//! **Built against BTF (CO-RE).** The object carries `.BTF` / `.BTF.ext` (emitted by `bpf-linker
//! --btf`), which aya relocates against the running kernel's BTF at load. No program here reads a
//! kernel struct field, so what that relocation carries is the map typing and the load path, not
//! field offsets. The syscall tracers read their arguments at the fixed offsets in
//! [`bsx_probes_common::TRACEPOINT_ARGS`], which is an ABI assumption; the loader compares each one
//! against the kernel's own tracepoint `format` file before it attaches.
//!
//! **Counters, and which losses are visible.** A **per-CPU** counter is contention-free (each CPU
//! writes its own copy) and the loader sums it; a **shared** map value every CPU writes goes through
//! [`add_shared`], because a plain `+=` there loses an increment under concurrency and no drop
//! counter can see it. A full map is the other loss, and every bounded map counts what it turned
//! away, so the loader can report it as a coverage gap rather than a thinner record that looks
//! whole.
//!
//! **The verifier's rules, hit on purpose.** Loops are bounded by compile-time constants so
//! termination is provable, and a map lookup result is dereferenced only after the null-check the
//! verifier demands. Every helper is `#[inline(always)]`, so each program stays one self-contained
//! unit with no BPF-to-BPF call.
#![no_std]
#![no_main]
// The only unstable feature this crate takes, for the one thing stable `core` cannot express on this
// target: an atomic add on a shared map value. See [`add_shared`].
#![feature(core_intrinsics)]
#![allow(internal_features)]

use core::intrinsics::{AtomicOrdering, atomic_xadd};

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_ktime_get_ns, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{classifier, map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{TcContext, TracePointContext},
};
use bsx_probes_common::{
    CONNECT_ADDRLEN_ARG, CONNECT_USERVADDR_ARG, DETAIL_CAP, ETH_HLEN, ETH_P_8021Q, ETH_P_ARP,
    ETH_P_IP, ETH_P_IPV6, ETHERTYPE_OFFSET, EXECVE_FILENAME_ARG, FlowCounts, FlowKey, FlowKey6,
    IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, IPV4_DST_OFFSET, IPV4_FRAG_OFFSET, IPV4_MIN_IHL,
    IPV4_PROTO_OFFSET, IPV4_SRC_OFFSET, IPV6_DST_OFFSET, IPV6_HLEN, IPV6_NEXT_HEADER_OFFSET,
    IPV6_SRC_OFFSET, MAX_POLICY_RULES, OPENAT_FILENAME_ARG, PolicyRule, PolicyRule6, SOCKADDR_SNAP,
    SOCKADDR_SNAP_V4, Syscall, SyscallEvent, icmp6_dst_on_link, rule_matches, rule_matches6,
};

/// The object's kernel `license` section. Declaring `GPL` makes the programs GPL-compatible
/// (dual-licensable: this crate is Apache-2.0); without it the first GPL-only helper added would
/// fail to load with a cryptic "cannot call GPL-restricted function". `#[no_mangle]` plus the exact
/// section name are what the kernel loader reads.
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static _LICENSE: [u8; 4] = *b"GPL\0";

/// A single-slot **per-CPU** counter of `sys_enter_execve` events. Per-CPU means each CPU increments
/// its own copy of slot 0 with no cross-CPU atomic; the loader sums the values when it reads.
#[map]
static EXECVE_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-PID `execve` counts (keyed by tgid) for **every** pid on the host, since [`count_execve`]
/// filters on nothing, bounded at [`MAX_PIDS`]; a full map drops new keys (counted in
/// [`PID_DROPS`]). The counts accumulate through [`add_shared`], but two concurrent first-sightings
/// of one pid can each insert `1` and lose an increment, which is why [`EXECVE_COUNT`] is the
/// authoritative total.
#[map]
static EXECVE_BY_PID: HashMap<u32, u64> = HashMap::with_max_entries(MAX_PIDS, 0);

/// Cap on the per-PID map, fixed because maps are sized at load. Overflow drops new keys, never
/// faults.
const MAX_PIDS: u32 = 4096;

/// Attaches to `tracepoint/syscalls/sys_enter_execve`, bumping the global per-CPU total and then a
/// per-PID count. Consults **no target filter**: it counts every `execve` on the host, whoever ran
/// it, which is what its one consumer (`bsx_probes_loader::ExecveCounter`) reports. A tracepoint
/// returns 0.
#[tracepoint]
pub fn count_execve(_ctx: TracePointContext) -> u32 {
    if let Some(total) = EXECVE_COUNT.get_ptr_mut(0) {
        // SAFETY: `total` points at this CPU's own copy of the one-element per-CPU array; this
        // program is its sole writer on this CPU and the verifier has proven the pointer in-bounds.
        unsafe { *total += 1 };
    }

    let comm = bpf_get_current_comm().unwrap_or_default();
    if comm[0] == 0 {
        return 0;
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // SAFETY: the map helpers are the verifier-checked BPF map ops; the returned pointer is only
    // dereferenced inside the `Some` arm (the mandatory null-check), never held across a helper call.
    unsafe {
        if let Some(slot) = EXECVE_BY_PID.get_ptr_mut(pid) {
            add_shared(slot, 1);
        } else if EXECVE_BY_PID.insert(pid, 1, 0).is_err() {
            count_map_drop(&PID_DROPS);
        }
    }
    0
}

/// A single-slot **per-CPU** counter of pids a full [`EXECVE_BY_PID`] could not admit, so the
/// difference between [`EXECVE_COUNT`] and the sum of the per-pid rows has a stated cause rather
/// than reading as a shorter list of busier processes.
#[map]
static PID_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// A single MPSC **ring buffer** of per-event [`SyscallEvent`] records, shared by every CPU and
/// drained in order by one consumer. 256 KiB (a power-of-two multiple of the page size, as the map
/// type requires); when full it drops new events rather than blocking the syscall.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// The target filter the loader writes: slot 0 a target **tgid**, slot 1 a target **cgroup id**. A
/// zero slot means "don't filter on this axis". Zero-initialized at load, so the default is
/// observe-all.
#[map]
static FILTER: Array<u64> = Array::with_max_entries(2, 0);

const FILTER_TGID: u32 = 0;
const FILTER_CGROUP: u32 = 1;

/// The set of cgroup ids to trace (`cgroup_id -> 1`), the syscall analogue of [`METER_TARGETS`].
/// Consulted only when [`TRACE_SET`] is on; empty plus off is the load-time single-[`FILTER`]
/// behaviour.
#[map]
static TRACE_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_CGROUPS, 0);

/// Selects which filter governs the tracepoints: `0` (the load-time default) uses the single-target
/// [`FILTER`], `1` uses the [`TRACE_TARGETS`] set. One toggle, so the two modes never interfere.
#[map]
static TRACE_SET: Array<u32> = Array::with_max_entries(1, 0);

const FILTER_MODE_SLOT: u32 = 0;

/// A single-slot **per-CPU** counter of events a full [`EVENTS`] rejected. The loader surfaces a
/// nonzero delta as a coverage gap on the run's record, so best-effort loss is visible rather than a
/// silently thinner footprint.
#[map]
static EVENT_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Whether an event from `tgid` in `cgroup` passes the loader-set filter: in set mode iff the cgroup
/// is a registered [`TRACE_TARGETS`] member, otherwise each configured (non-zero) [`FILTER`] axis
/// must match.
#[inline(always)]
fn passes_filter(tgid: u32, cgroup: u64) -> bool {
    if TRACE_SET.get(FILTER_MODE_SLOT).copied().unwrap_or(0) != 0 {
        // `get_ptr` is a presence check without a deref, so no `unsafe` is needed.
        return TRACE_TARGETS.get_ptr(cgroup).is_some();
    }
    let want_tgid = FILTER.get(FILTER_TGID).copied().unwrap_or(0);
    let want_cgroup = FILTER.get(FILTER_CGROUP).copied().unwrap_or(0);
    (want_tgid == 0 || want_tgid == u64::from(tgid)) && (want_cgroup == 0 || want_cgroup == cgroup)
}

/// Emits one [`SyscallEvent`] for the current syscall into [`EVENTS`], unless the filter rejects it.
///
/// `arg_off` is the byte offset of the syscall's pointer argument in the tracepoint record (a
/// [`bsx_probes_common::TRACEPOINT_ARGS`] entry, which the loader checks against the kernel's own
/// `format` file before it attaches);
/// `path_like` selects reading it as a NUL-terminated user string or as raw leading sockaddr bytes,
/// and `len_off` (sockaddr only) is the offset of the companion `addrlen` that bounds the copy. A
/// tracepoint returns 0.
#[inline(always)]
fn record(
    ctx: &TracePointContext,
    kind: Syscall,
    arg_off: usize,
    path_like: bool,
    len_off: usize,
) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    // SAFETY: a plain BPF helper call returning the current task's cgroup id, no pointers involved.
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

    // SAFETY: `read_at` reads the tracepoint's own argument area at a constant offset, which
    // `check_tracepoint_abi` compared against this kernel's `format` file before the attach.
    if let Ok(arg) = unsafe { ctx.read_at::<u64>(arg_off) } {
        let src = arg as *const u8;
        if path_like {
            // SAFETY: copies a user-space C string into the fixed 128-byte buffer; the helper bounds
            // the copy to the destination length and returns the bytes actually read.
            if let Ok(read) = unsafe { bpf_probe_read_user_str_bytes(src, &mut ev.detail[..]) } {
                ev.detail_len = read.len() as u32;
            }
        } else {
            // The caller's own `addrlen` picks the snapshot size: reading the full `sockaddr_in6`
            // length unconditionally over-reads a 16-byte `sockaddr_in` by 12 bytes of whatever
            // follows it in the traced process's memory, and publishes those bytes in the event
            // stream as captured sockaddr. Both arms stay constant-size, which keeps the copies
            // simple for the verifier.
            // SAFETY: reads the tracepoint's own argument area at a constant offset. Narrowed to
            // `i32` first, because `connect`'s `addrlen` is an `int`: the raw register can carry
            // dirty upper bits or a negative the kernel truncates, and reading it as a full `u64`
            // would let a caller name a huge length and pull the 28-byte arm over a 16-byte buffer.
            let raw = unsafe { ctx.read_at::<u64>(len_off) }.unwrap_or(0);
            let addrlen = (raw as i32).max(0) as usize;
            if addrlen >= SOCKADDR_SNAP {
                // SAFETY: constant-size copy from user space, bounded by the destination slice;
                // an unmapped buffer fails the read and leaves `detail_len` at 0.
                if unsafe { bpf_probe_read_user_buf(src, &mut ev.detail[..SOCKADDR_SNAP]) }.is_ok()
                {
                    ev.detail_len = SOCKADDR_SNAP as u32;
                }
            } else if addrlen >= 8 {
                // Everything shorter than a `sockaddr_in6` reads the `sockaddr_in` size, so a
                // still-shorter family (`sockaddr_nl` is 12) keeps naming its family instead of
                // vanishing from the record. The floor is 8 because that is what
                // `bsx_probes_common::describe_sockaddr` needs to name a family at all.
                // SAFETY: as above, the shorter constant-size copy.
                if unsafe { bpf_probe_read_user_buf(src, &mut ev.detail[..SOCKADDR_SNAP_V4]) }
                    .is_ok()
                {
                    // The copy is constant-size, but the caller's `addrlen` may be shorter, so scrub
                    // what the read pulled in past it: those bytes are the traced process's adjacent
                    // memory, and the whole `detail` array rides the ring buffer whatever
                    // `detail_len` says. Constant loop bound, so the verifier can unroll it.
                    let kept = if addrlen < SOCKADDR_SNAP_V4 {
                        addrlen
                    } else {
                        SOCKADDR_SNAP_V4
                    };
                    for (i, b) in ev.detail[..SOCKADDR_SNAP_V4].iter_mut().enumerate() {
                        if i >= kept {
                            *b = 0;
                        }
                    }
                    ev.detail_len = kept as u32;
                }
            }
        }
    }

    // Turbofish since aya-ebpf 0.2: `output` became `output<T: ?Sized>(data: impl Borrow<T>, ..)`,
    // and `&ev` satisfies that bound for more than one `T`, so the element type must be named.
    if EVENTS.output::<SyscallEvent>(&ev, 0).is_err()
        && let Some(drops) = EVENT_DROPS.get_ptr_mut(0)
    {
        // SAFETY: this CPU's own slot of the one-element per-CPU array; the pointer is only used
        // inside the null-check and this program is its sole writer on this CPU.
        unsafe { *drops += 1 };
    }
    0
}

/// `tracepoint/syscalls/sys_enter_execve`, recording the program path (arg 0, `const char *filename`).
#[tracepoint]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    record(&ctx, Syscall::Execve, EXECVE_FILENAME_ARG.offset, true, 0)
}

/// `tracepoint/syscalls/sys_enter_openat`, recording the opened path (arg 1, past the `int dfd`).
#[tracepoint]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    record(&ctx, Syscall::Openat, OPENAT_FILENAME_ARG.offset, true, 0)
}

/// `tracepoint/syscalls/sys_enter_connect`, recording the leading sockaddr bytes (arg 1, past the
/// `int fd`).
#[tracepoint]
pub fn trace_connect(ctx: TracePointContext) -> u32 {
    record(
        &ctx,
        Syscall::Connect,
        CONNECT_USERVADDR_ARG.offset,
        false,
        CONNECT_ADDRLEN_ARG.offset,
    )
}

/// Per-flow byte/packet counters keyed by the directional IPv4 [`FlowKey`], bounded at
/// [`MAX_FLOWS`]; a full map drops new flows (counted in [`FLOW_DROPS`]). Accumulation goes through
/// [`add_shared`], so a burst racing two CPUs on one flow loses nothing; what remains is the
/// **first** sighting of a key, where two CPUs can both miss the lookup and each insert a fresh
/// count, losing one packet. Bounded at one per key, and never an over-count.
#[map]
static FLOWS: HashMap<FlowKey, FlowCounts> = HashMap::with_max_entries(MAX_FLOWS, 0);

/// Cap on the flow map, a fixed load-time bound. Overflow drops new flows, never faults.
const MAX_FLOWS: u32 = 4096;

/// Per-destination **denied**-packet counters, keyed by the guest-sent [`FlowKey`] the egress policy
/// dropped, which the loader folds into the per-run record. Bounded at [`MAX_FLOWS`] like [`FLOWS`];
/// empty until enforcement drops something.
#[map]
static DENIALS: HashMap<FlowKey, u64> = HashMap::with_max_entries(MAX_FLOWS, 0);

/// The IPv6 twin of [`FLOWS`], keyed by the directional [`FlowKey6`]. A separate map, not a widened
/// key, so the v4 path stays byte-for-byte unchanged. Shares [`FLOW_DROPS`] on overflow.
#[map]
static FLOWS6: HashMap<FlowKey6, FlowCounts> = HashMap::with_max_entries(MAX_FLOWS, 0);

/// The IPv6 twin of [`DENIALS`], keyed by [`FlowKey6`]. Shares [`DENIAL_DROPS`] on overflow.
#[map]
static DENIALS6: HashMap<FlowKey6, u64> = HashMap::with_max_entries(MAX_FLOWS, 0);

/// A single-slot **per-CPU** counter of new flows a full [`FLOWS`] map dropped, surfaced by the
/// loader as a truncated network section plus a coverage gap. Without it a guest could fill the map
/// with 4096 benign flows (one per ephemeral source port) and evict its real traffic from its own
/// audit record silently.
#[map]
static FLOW_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The [`FLOW_DROPS`] twin for [`DENIALS`]: denied-endpoint rows a full map could not record. The
/// packets were still dropped, since enforcement never depends on the map, so only the audit row is
/// missing.
#[map]
static DENIAL_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// A single-slot **per-CPU** counter of frames that crossed the tap but couldn't be keyed as a
/// [`FlowKey`] *or* a [`FlowKey6`] (an 802.1Q VLAN tag, a truncated frame), so they'd vanish from
/// the flow view silently. ARP is deliberately not counted (expected on-link, not a flow).
#[map]
static UNPARSED_L3: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Adds `n` to a counter inside a **shared** (not per-CPU) map value, atomically.
///
/// A plain `*slot += n` is a load, an add and a store, so two CPUs writing one key at the same
/// instant each read the same value and one of the two increments is lost. **No drop counter catches
/// that**, which is what separates it from every other loss here: the insert succeeded, the map is
/// not full, and the value is simply lower than the truth. The loss scales with contention rather
/// than being a one-off, and [`DENIALS`] is keyed by destination only, so a guest flooding one
/// blocked endpoint from many source ports has its packets spread across CPUs by the NIC and then
/// collapsed back onto that single key, which is the shape that maximizes it.
///
/// `core::sync::atomic`'s read-modify-write methods are unavailable here: rustc declares
/// `bpfel-unknown-none` as `atomic-cas: false` (BPF has the atomic add but no compare-and-swap
/// below ISA v3), so `AtomicU64` offers only load and store. The intrinsic is what reaches the
/// instruction. Its result is unused, which is what lets the backend emit the plain `lock ... +=`
/// rather than the fetching form that would need a newer ISA; there is no silent fallback to a
/// load-add-store, since the backend errors instead.
///
/// A **per-CPU** map value needs none of this and keeps its plain `+=`: each CPU writes its own copy
/// and the loader sums them.
#[inline(always)]
unsafe fn add_shared(slot: *mut u64, n: u64) {
    // SAFETY: the caller passes a pointer into a map value the verifier proved in-bounds and
    // null-checked, 8-byte aligned as every map value is, and every counter reached this way is a
    // `u64` field of a `#[repr(C)]` value made only of them.
    unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(slot, n) };
}

/// Bumps one of the per-CPU drop counters after a failed map insert.
#[inline(always)]
fn count_map_drop(counter: &PerCpuArray<u64>) {
    if let Some(drops) = counter.get_ptr_mut(0) {
        // SAFETY: this CPU's own slot of the one-element per-CPU array; the pointer is only used
        // inside the null-check and this program is its sole writer on this CPU.
        unsafe { *drops += 1 };
    }
}

/// The Linux `tc` actions a classifier returns to the kernel, named after the kernel ABI constants
/// so the values are unmistakable. [`Verdict`] is what the program's logic speaks.
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

/// A classifier's decision in the program's own terms rather than a bare `i32`, lowered to the `tc`
/// ABI by [`as_tc`](Verdict::as_tc) at the entry points, so no magic action number leaks into the
/// logic.
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

/// The per-sandbox egress allow-list the loader fills and the ingress classifier scans.
/// Zero-initialized at load, so every slot starts `active == 0` and an un-configured monitor has an
/// empty policy. Sized per-object, so it is naturally per VM.
#[map]
static POLICY: Array<PolicyRule> = Array::with_max_entries(MAX_POLICY_RULES as u32, 0);

/// The IPv6 twin of [`POLICY`], governed by the same [`ENFORCE`] toggle.
#[map]
static POLICY6: Array<PolicyRule6> = Array::with_max_entries(MAX_POLICY_RULES as u32, 0);

/// Enforcement toggle: `0` for **observe-only** (accept every packet), `1` for **deny-by-default
/// egress**. Zero-initialized at load, so a monitor enforces nothing until the loader opts in and
/// every allowance is explicit.
#[map]
static ENFORCE: Array<u32> = Array::with_max_entries(1, 0);

/// Which way a frame crossed the tap, from the tap's perspective (matching [`FlowCounts`]):
/// `Ingress` is a frame the guest sent, `Egress` one delivered to the guest.
#[derive(Clone, Copy)]
enum Direction {
    Ingress,
    Egress,
}

/// `tc`/clsact **ingress** on a VM's tap, a frame the guest sent. Counts it against its flow, then
/// returns the egress-policy verdict. Attached by the loader's `TapMonitor` after it adds the clsact
/// qdisc.
#[classifier]
pub fn tap_ingress(ctx: TcContext) -> i32 {
    // Parse the 5-tuple **once** and hand it to both the counter and the verdict: on the enforcement
    // hot path this halves the per-packet `bpf_skb_load_bytes` calls.
    if let Some(key) = parse(&ctx) {
        count(&ctx, Direction::Ingress, Some(key));
        return egress_verdict(&ctx, Some(key)).as_tc();
    }
    if let Some(key6) = parse6(&ctx) {
        count6(&ctx, Direction::Ingress, &key6);
        return egress_verdict6(&ctx, &key6).as_tc();
    }
    count(&ctx, Direction::Ingress, None);
    egress_verdict(&ctx, None).as_tc()
}

/// `tc`/clsact **egress** on a VM's tap, a frame delivered to the guest. Always accepted: egress
/// policy governs what the guest *sends*, and replies to allowed traffic must come back in.
#[classifier]
pub fn tap_egress(ctx: TcContext) -> i32 {
    if let Some(key) = parse(&ctx) {
        count(&ctx, Direction::Egress, Some(key));
    } else if let Some(key6) = parse6(&ctx) {
        count6(&ctx, Direction::Egress, &key6);
    } else {
        count(&ctx, Direction::Egress, None);
    }
    Verdict::Pass.as_tc()
}

/// The allow/drop verdict for a **guest-sent** frame: observe-only accepts everything, and under
/// enforcement an IPv4 frame is accepted only if its destination matches [`POLICY`]. A denied frame
/// is recorded in [`DENIALS`] before the drop.
#[inline(always)]
fn egress_verdict(ctx: &TcContext, key: Option<FlowKey>) -> Verdict {
    if ENFORCE.get(0).copied().unwrap_or(0) == 0 {
        return Verdict::Pass;
    }
    // Anything `parse` couldn't key needs the ethertype only to spare ARP: without it the guest
    // can't resolve its gateway and so can't send IP at all. Everything else is deny-by-default
    // (no 5-tuple to prove allowed or to log).
    let Some(key) = key else {
        return match ctx.load::<u16>(ETHERTYPE_OFFSET).map(u16::from_be) {
            Ok(ETH_P_ARP) => Verdict::Pass,
            _ => Verdict::Drop,
        };
    };
    if policy_allows(key.dst_addr, key.dst_port, key.proto) {
        Verdict::Pass
    } else {
        record_denial(&key);
        Verdict::Drop
    }
}

/// The IPv6 twin of [`egress_verdict`], accepting a v6 destination only if it matches [`POLICY6`]
/// and otherwise recording it in [`DENIALS6`] and dropping. ARP is IPv4-only, so there is no v6
/// analogue to spare.
#[inline(always)]
fn egress_verdict6(_ctx: &TcContext, key: &FlowKey6) -> Verdict {
    if ENFORCE.get(0).copied().unwrap_or(0) == 0 {
        return Verdict::Pass;
    }
    // ICMPv6 is the v6 twin of ARP, but unlike ARP (its own ethertype) it rides the IPv6 ethertype
    // and can carry a routable Echo, so spare it only to **on-link** scopes: the neighbor-discovery
    // / MLD / NUD traffic the guest needs to resolve and keep its host end, none of which routes off
    // the link. ICMPv6 to a global-unicast destination falls through to `POLICY6`, so a spared Echo
    // can't be an egress channel leaning solely on the netns having no v6 default route.
    if key.proto == IPPROTO_ICMPV6 && icmp6_dst_on_link(key.dst_addr) {
        return Verdict::Pass;
    }
    if policy_allows6(key.dst_addr, key.dst_port, key.proto) {
        Verdict::Pass
    } else {
        record_denial6(key);
        Verdict::Drop
    }
}

/// Records one denied guest-sent packet against its destination flow in [`DENIALS`]. The count
/// itself is atomic ([`add_shared`]), so the flood this exists to record is counted whole; the
/// lookup-or-init below can still lose the very first packet to a concurrent first sighting of the
/// same destination, once per key.
#[inline(always)]
fn record_denial(key: &FlowKey) {
    // Key by **destination only** (src addr/port zeroed): keying on the guest's ephemeral source
    // port would spread one blocked endpoint across a row per port, filling the map far faster and
    // diluting the "which endpoint was blocked" trail. It is also the shape the loader aggregates to.
    let dst = FlowKey::new(0, key.dst_addr, 0, key.dst_port, key.proto);
    record_denial_in(&DENIALS, &dst);
}

/// The IPv6 twin of [`record_denial`], keyed by destination only for the same per-endpoint
/// aggregation reason. Shares [`DENIAL_DROPS`] on a full map.
#[inline(always)]
fn record_denial6(key: &FlowKey6) {
    let dst = FlowKey6::new([0u8; 16], key.dst_addr, 0, key.dst_port, key.proto);
    record_denial_in(&DENIALS6, &dst);
}

/// The shared body of [`record_denial`] and [`record_denial6`]: bump `dst`'s denial count in
/// `denials`, inserting the first sighting; a refused insert (full map) is counted in
/// [`DENIAL_DROPS`]. `#[inline(always)]` monomorphizes into each caller, so the program stays
/// self-contained (no BPF-to-BPF call) and the verifier's bounds are unmoved.
#[inline(always)]
fn record_denial_in<K>(denials: &HashMap<K, u64>, dst: &K) {
    // SAFETY: the map helpers are the verifier-checked BPF ops; the returned pointer is dereferenced
    // only inside the `Some` arm (the mandatory null-check) and never held across a helper call.
    unsafe {
        if let Some(count) = denials.get_ptr_mut(dst) {
            add_shared(count, 1);
        } else if denials.insert(dst, &1, 0).is_err() {
            count_map_drop(&DENIAL_DROPS);
        }
    }
}

/// Whether [`POLICY`] admits destination `(addr, port, proto)`, scanning the fixed rule array in a
/// bounded loop (the compile-time cap the verifier needs) and accepting on the first active match.
/// Deny-by-default. The per-rule test is [`rule_matches`], single-sourced with the host-tested
/// parser.
#[inline(always)]
fn policy_allows(dst_addr: u32, dst_port: u16, proto: u8) -> bool {
    policy_admits(&POLICY, |rule| {
        rule_matches(rule, dst_addr, dst_port, proto)
    })
}

/// The IPv6 twin of [`policy_allows`], scanning [`POLICY6`] in the same bounded loop. Per-rule test
/// is [`rule_matches6`] (byte-wise, no `u128`).
#[inline(always)]
fn policy_allows6(dst_addr: [u8; 16], dst_port: u16, proto: u8) -> bool {
    policy_admits(&POLICY6, |rule| {
        rule_matches6(rule, dst_addr, dst_port, proto)
    })
}

/// The shared scan of [`policy_allows`] and [`policy_allows6`]: the fixed rule array in a bounded
/// loop (the compile-time cap the verifier needs), accepting on the first rule `admits`.
/// Deny-by-default. `#[inline(always)]` monomorphizes the closure away into each caller.
#[inline(always)]
fn policy_admits<R>(policy: &Array<R>, admits: impl Fn(&R) -> bool) -> bool {
    for i in 0..MAX_POLICY_RULES as u32 {
        if let Some(rule) = policy.get(i)
            && admits(rule)
        {
            return true;
        }
    }
    false
}

/// Adds one packet to its flow's per-direction counters. `key` is the caller's single parse of the
/// frame, `None` for one a flow can't represent (which this skips, though the caller still accepts
/// it).
#[inline(always)]
fn count(ctx: &TcContext, dir: Direction, key: Option<FlowKey>) {
    let Some(key) = key else {
        // Reached only when neither parser could key the frame: a VLAN tag, or a truncated v4/v6
        // frame. `ETH_P_IP` here is the truncated-or-malformed-IPv4 case, which `egress_verdict`
        // drops under enforcement, so leaving it uncounted would drop traffic the record then claims
        // never existed. ARP is spared (expected on-link, not a flow).
        if let Ok(ethertype) = ctx.load::<u16>(ETHERTYPE_OFFSET).map(u16::from_be)
            && (ethertype == ETH_P_IP || ethertype == ETH_P_IPV6 || ethertype == ETH_P_8021Q)
        {
            count_map_drop(&UNPARSED_L3);
        }
        return;
    };
    count_in(&FLOWS, ctx, dir, &key);
}

/// The IPv6 twin of [`count`]. Takes the key by reference, since a [`FlowKey6`] is 40 bytes rather
/// than `Copy`-cheap; the non-IP and unparsed accounting stays in [`count`].
#[inline(always)]
fn count6(ctx: &TcContext, dir: Direction, key: &FlowKey6) {
    count_in(&FLOWS6, ctx, dir, key);
}

/// The shared body of [`count`] and [`count6`]: bump `key`'s per-direction counters in `flows`,
/// inserting the first sighting; a refused insert (full map) is counted in [`FLOW_DROPS`].
/// `#[inline(always)]` monomorphizes into each caller, so the program stays self-contained (no
/// BPF-to-BPF call) and the verifier's bounds are unmoved.
#[inline(always)]
fn count_in<K>(flows: &HashMap<K, FlowCounts>, ctx: &TcContext, dir: Direction, key: &K) {
    // `skb->len` is the full frame length, counting a GSO super-frame's real bytes, which `data_end -
    // data` (only the linear head) would undercount.
    let bytes = u64::from(ctx.skb.len());
    // SAFETY: the map helpers are the verifier-checked BPF ops; the returned pointer is dereferenced
    // only inside the `Some` arm (the mandatory null-check) and never held across a helper call.
    unsafe {
        if let Some(counts) = flows.get_ptr_mut(key) {
            match dir {
                Direction::Ingress => {
                    add_shared(&raw mut (*counts).ingress_packets, 1);
                    add_shared(&raw mut (*counts).ingress_bytes, bytes);
                }
                Direction::Egress => {
                    add_shared(&raw mut (*counts).egress_packets, 1);
                    add_shared(&raw mut (*counts).egress_bytes, bytes);
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
            if flows.insert(key, &init, 0).is_err() {
                count_map_drop(&FLOW_DROPS);
            }
        }
    }
}

/// Reads the frame's IPv4 5-tuple with `ctx.load`, or `None` if it is not IPv4-over-Ethernet or a
/// read runs off the packet.
///
/// Every byte position is a `const` from [`bsx_probes_common`], the same ones
/// [`bsx_probes_common::parse_ipv4_5tuple`] reads, so the two cannot disagree on where a field
/// lives. The surrounding logic is still mirrored by hand, since this half runs only under the
/// verifier; `crates/probes-loader/tests/differential.rs` is the enforcer for that mirror.
#[inline(always)]
fn parse(ctx: &TcContext) -> Option<FlowKey> {
    let ethertype = u16::from_be(ctx.load::<u16>(ETHERTYPE_OFFSET).ok()?);
    if ethertype != ETH_P_IP {
        return None;
    }
    let version_ihl: u8 = ctx.load(ETH_HLEN).ok()?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_IHL {
        return None;
    }
    let proto: u8 = ctx.load(ETH_HLEN + IPV4_PROTO_OFFSET).ok()?;
    let src = u32::from_be(ctx.load::<u32>(ETH_HLEN + IPV4_SRC_OFFSET).ok()?);
    let dst = u32::from_be(ctx.load::<u32>(ETH_HLEN + IPV4_DST_OFFSET).ok()?);
    // The low 13 bits of the flags/fragment-offset field are the fragment offset. A non-first
    // fragment has no L4 header, so reading "ports" there would interpret payload bytes; leave them
    // zero so a guest can't mint bogus 5-tuples with fragments.
    let frag_off = u16::from_be(ctx.load::<u16>(ETH_HLEN + IPV4_FRAG_OFFSET).ok()?) & 0x1fff;
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if frag_off == 0 && (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        let l4 = ETH_HLEN + ihl;
        src_port = u16::from_be(ctx.load::<u16>(l4).ok()?);
        dst_port = u16::from_be(ctx.load::<u16>(l4 + 2).ok()?);
    }
    Some(FlowKey::new(src, dst, src_port, dst_port, proto))
}

/// Reads the frame's IPv6 5-tuple with `ctx.load`, or `None` if it is not IPv6-over-Ethernet or a
/// read runs off the packet. Mirrors [`bsx_probes_common::parse_ipv6_5tuple`], reading the same
/// offset consts. Extension headers are not walked: a next-header that isn't TCP/UDP directly after
/// the fixed 40-byte header leaves the ports 0.
#[inline(always)]
fn parse6(ctx: &TcContext) -> Option<FlowKey6> {
    let ethertype = u16::from_be(ctx.load::<u16>(ETHERTYPE_OFFSET).ok()?);
    if ethertype != ETH_P_IPV6 {
        return None;
    }
    let next_header: u8 = ctx.load(ETH_HLEN + IPV6_NEXT_HEADER_OFFSET).ok()?;
    let src: [u8; 16] = ctx.load(ETH_HLEN + IPV6_SRC_OFFSET).ok()?;
    let dst: [u8; 16] = ctx.load(ETH_HLEN + IPV6_DST_OFFSET).ok()?;
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if next_header == IPPROTO_TCP || next_header == IPPROTO_UDP {
        let l4 = ETH_HLEN + IPV6_HLEN;
        src_port = u16::from_be(ctx.load::<u16>(l4).ok()?);
        dst_port = u16::from_be(ctx.load::<u16>(l4 + 2).ok()?);
    }
    Some(FlowKey6::new(src, dst, src_port, dst_port, next_header))
}

/// Per-cgroup accumulated on-CPU time in **nanoseconds**, keyed by the same cgroup id
/// [`bsx_probes_loader::cgroup_id_of_pid`] resolves from a VMM pid, so the loader reads exactly the
/// sandbox it means. Bounded at [`MAX_CGROUPS`] (overflow counted in [`CPU_DROPS`]). Slices
/// accumulate through [`add_shared`], so a cgroup running on many CPUs at once loses none of them;
/// the first switch that creates the row can lose one slice to a concurrent first sighting.
#[map]
static CPU_NS: HashMap<u64, u64> = HashMap::with_max_entries(MAX_CGROUPS, 0);

/// Cap on the per-cgroup CPU map, a fixed load-time bound.
const MAX_CGROUPS: u32 = 1024;

/// A single-slot **per-CPU** counter of cgroups a full [`CPU_NS`] could not admit. Without it a
/// sandbox that arrives after the map fills accumulates no time and reports a `cpu_time` of zero,
/// which reads as "this run used no CPU" rather than "this was not measured"; the loader turns a
/// nonzero delta into a coverage gap on the CPU axis instead.
#[map]
static CPU_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// This CPU's timestamp at its **last** `sched_switch`, so the slice a task just ran is `now -
/// LAST_SWITCH[cpu]`. Per-CPU, so no cross-CPU atomic and no key math. Zero-init at load, so the
/// first switch on a CPU has no prior stamp and is skipped.
#[map]
static LAST_SWITCH: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// The set of cgroup ids to meter (`cgroup_id -> 1`), written by the loader as sandboxes come and
/// go. Empty by default; a cgroup is metered when it is in this set **or** [`METER_ALL`] is on.
#[map]
static METER_TARGETS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_CGROUPS, 0);

/// A meter-**everything** toggle, for a whole-host view or a test: `0` (the load-time default)
/// meters only [`METER_TARGETS`], `1` meters every cgroup. The escape hatch, not the default.
#[map]
static METER_ALL: Array<u32> = Array::with_max_entries(1, 0);

/// `tracepoint/sched/sched_switch`: closes the on-CPU interval for the task leaving the CPU and adds
/// it to that task's cgroup total.
///
/// At this tracepoint the *current* task is still `prev` (the scheduler fires it before
/// `context_switch` swaps `current`), so `bpf_get_current_cgroup_id` is the cgroup whose slice just
/// ended. `LAST_SWITCH[cpu]` is always restamped, but the delta is added only for a registered
/// target. A tracepoint returns 0.
#[tracepoint]
pub fn account_sched_switch(_ctx: TracePointContext) -> u32 {
    // SAFETY: both are plain BPF helper calls (a monotonic clock read and the current task's cgroup
    // id), no pointers, nothing to bound; `current` is still `prev` here (see the fn doc).
    let now = unsafe { bpf_ktime_get_ns() };
    let cgroup = unsafe { bpf_get_current_cgroup_id() };

    // Always restamp: the cursor tracks when this CPU last switched, independent of which cgroup is
    // metered.
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

    // A non-metered cgroup's slice is dropped here; the cursor above was already advanced, so the
    // *next* interval stays exact. `get_ptr` is a presence check without a deref, so the membership
    // test needs no `unsafe`.
    let all = METER_ALL.get(0).copied().unwrap_or(0) != 0;
    if !all && METER_TARGETS.get_ptr(cgroup).is_none() {
        return 0;
    }

    // SAFETY: the map helpers are the verifier-checked BPF ops; the returned pointer is dereferenced
    // only inside the `Some` arm and never held across a helper call.
    unsafe {
        if let Some(acc) = CPU_NS.get_ptr_mut(cgroup) {
            add_shared(acc, delta);
        } else if CPU_NS.insert(cgroup, delta, 0).is_err() {
            count_map_drop(&CPU_DROPS);
        }
    }
    0
}

/// eBPF has no unwinder and the verifier rejects a real panic path, so a program that panics is a
/// build-time bug rather than a runtime one; the conventional never-taken handler is a spin.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
