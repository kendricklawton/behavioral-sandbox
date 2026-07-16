//! Demo (P9.3/P9.4): a **live syscall trace**. Loads the three `sys_enter_{execve,openat,connect}`
//! tracepoints and streams decoded events as they happen, until the window closes.
//!
//! With a `PID` argument it **attributes** the trace to that process's cgroup (P9.4): pass a sandbox's
//! Firecracker VMM pid to watch exactly one sandbox's host footprint. With none, it traces the whole
//! host.
//!
//! ```text
//! trace_syscalls [SECONDS] [PID]      # defaults: 5 seconds, whole host
//! ```
//!
//! Needs `CAP_BPF`+`CAP_PERFMON` (or root), a BTF kernel, and the built object
//! (`cargo xtask build-probes`). Grant just the two caps to the built example, or run as root:
//!
//! ```console
//! cargo xtask build-probes
//! cargo build -p agent-probes-loader --example trace_syscalls
//! sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/trace_syscalls
//! target/debug/examples/trace_syscalls 5           # whole host, 5s
//! target/debug/examples/trace_syscalls 5 $(pgrep -n firecracker)   # one sandbox
//! ```
//!
//! Returning a boxed error from `main` keeps this within the no-panic host discipline (no
//! `unwrap`/`expect`): a missing object or a load without the caps prints the typed error and exits.

use std::error::Error;
use std::time::{Duration, Instant};

use agent_probes_loader::{cgroup_id_of_pid, SyscallTracer};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let seconds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
    let pid: Option<u32> = args.next().and_then(|s| s.parse().ok());

    let mut tracer = SyscallTracer::load()?;
    match pid {
        // P9.4: resolve the pid's cgroup id from the Firecracker track and scope the trace to it.
        Some(p) => {
            let cgroup = cgroup_id_of_pid(p)?;
            tracer.watch_cgroup(cgroup)?;
            println!("# tracing pid {p} (cgroup id {cgroup}) for {seconds}s");
        }
        None => {
            tracer.watch_all()?;
            println!("# tracing the whole host for {seconds}s");
        }
    }
    tracer.drain(|_| {})?; // discard whatever was buffered before the window opens

    // P9.3: stream the decoded trace live until the window closes; events print within ~2 ms.
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let count = tracer.stream(
        Duration::from_millis(2),
        || Instant::now() < deadline,
        |ev| println!("{}", ev.describe()),
    )?;
    println!("# {count} events");
    Ok(())
}
