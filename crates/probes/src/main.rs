//! The eBPF programs, compiled `#![no_std]` / `#![no_main]` for `bpfel-unknown-none` and linked by
//! `bpf-linker`. This is the in-kernel, host-side half of spine #2 (observe & enforce from the
//! host): these programs run in the host kernel, out of the guest's reach, and the userspace loader
//! (`crates/probes-loader`, aya) attaches them to a specific sandbox and reads their maps.
//!
//! **P8.2 — count an event into a map.** [`count_execve`] attaches to the `sys_enter_execve`
//! tracepoint and bumps a per-CPU counter each time the host does an `execve`. Per-CPU
//! ([`PerCpuArray`]) so the increment needs no atomic (each CPU owns its own slot); the userspace
//! loader sums the slots on read. This is deliberately the *host's* footprint, not the guest's: a
//! microVM services its own syscalls in-guest and they never trap here (see ROADMAP Phase 9), so the
//! strong host-side signals are network + resources, which land in Phases 10 and 12. This program is
//! the on-ramp that proves the map read/attach/drop path end to end.
//!
//! `unsafe` lives here (a raw map-pointer deref), not on the host path: this crate builds for the
//! BPF target, and the driver/host code stays `#![forbid(unsafe_code)]`. The program/map/link
//! *lifetime* is the loader's (aya drops links on `Drop`; nothing is pinned), so a crashed loader
//! leaves no kernel residue — the eBPF analogue of the driver's no-leak teardown (P8.4).
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

/// A single-slot **per-CPU** counter of `sys_enter_execve` events. Per-CPU means each CPU increments
/// its own copy of slot 0 with no cross-CPU atomic; the loader sums the per-CPU values when it reads.
#[map]
static EXECVE_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Attach point: `tracepoint/syscalls/sys_enter_execve`. The category/name are supplied by the loader
/// at attach time; the function body just bumps this CPU's counter slot and returns success (0). A
/// tracepoint program must return 0.
#[tracepoint]
pub fn count_execve(_ctx: TracePointContext) -> u32 {
    if let Some(slot) = EXECVE_COUNT.get_ptr_mut(0) {
        // SAFETY: `slot` points at this CPU's own copy of the one-element per-CPU array; this program
        // is its sole writer on this CPU and the BPF verifier has proven the pointer in-bounds.
        unsafe { *slot += 1 };
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
