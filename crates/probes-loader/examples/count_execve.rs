//! Demo (P8.3): load the `sys_enter_execve` counter, print the running total, sample again after a
//! moment, and print how much it moved. This is the eBPF on-ramp's "it works" demo — a Rust eBPF
//! program loads, attaches, and reports from userspace.
//!
//! Needs `CAP_BPF`+`CAP_PERFMON` (or root), a BTF kernel, and the built object
//! (`cargo xtask build-probes`). Either run as root, or grant just the two caps to the built binary
//! (P8.8):
//!
//! ```console
//! cargo xtask build-probes
//! cargo build -p agent-probes-loader --example count_execve
//! sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/count_execve
//! target/debug/examples/count_execve        # unprivileged, with just the two caps
//! ```
//!
//! Returning the typed `ProbeError` from `main` keeps this within the no-panic host discipline (no
//! `unwrap`/`expect`): a missing object or a load without `CAP_BPF` prints the typed error and exits.

use std::thread::sleep;
use std::time::Duration;

use agent_probes_loader::{ExecveCounter, ProbeError};

fn main() -> Result<(), ProbeError> {
    let counter = ExecveCounter::load()?;
    let before = counter.count()?;
    println!("host sys_enter_execve count: {before}");

    // Sample again after a beat: on any busy host the total will have moved (every process spawn is
    // an execve). This is the host's footprint, not any guest's (a microVM's syscalls stay in-guest).
    sleep(Duration::from_millis(500));
    let after = counter.count()?;
    println!("after 500ms: {after} (+{})", after.saturating_sub(before));

    // The per-PID breakdown (P8.6's hash map): the busiest execve'ers seen in the window.
    let mut by_pid = counter.counts_by_pid()?;
    by_pid.sort_by(|a, b| b.1.cmp(&a.1));
    println!("top execve'ers by pid:");
    for (pid, n) in by_pid.iter().take(5) {
        println!("  pid {pid}: {n}");
    }
    Ok(())
}
