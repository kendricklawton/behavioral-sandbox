//! The eBPF programs, compiled `#![no_std]` / `#![no_main]` for `bpfel-unknown-none` and linked by
//! `bpf-linker`. This is the in-kernel, host-side half of spine #2 (observe & enforce from the
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
//! `unsafe` lives here (raw map-pointer derefs), not on the host path: this crate builds for the BPF
//! target, and the driver/host code stays `#![forbid(unsafe_code)]`. The program/map/link *lifetime*
//! is the loader's (aya drops links on `Drop`; nothing is pinned), so a crashed loader leaves no
//! kernel residue — the eBPF analogue of the driver's no-leak teardown (P8.4).
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::TracePointContext,
};

/// A single-slot **per-CPU** counter of `sys_enter_execve` events. Per-CPU means each CPU increments
/// its own copy of slot 0 with no cross-CPU atomic; the loader sums the per-CPU values when it reads.
#[map]
static EXECVE_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-PID `execve` counts (keyed by tgid). Bounded at [`MAX_PIDS`] entries; a full map just drops
/// new keys (the global [`EXECVE_COUNT`] is the authoritative total). Demonstrates the hash-map
/// lookup-or-init access pattern the verifier constrains (P8.6).
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

/// eBPF has no unwinder and the verifier rejects a real panic path, so a program that panics is a
/// build/verify-time bug, never a runtime one — the conventional never-taken handler is a spin.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
