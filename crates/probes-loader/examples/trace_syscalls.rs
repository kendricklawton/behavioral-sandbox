//! Demo (P9.1/P9.2): load the three `sys_enter_{execve,openat,connect}` tracepoints, stream their
//! per-event records out of the ring buffer, and show the target filter narrowing the stream to one
//! process.
//!
//! Two phases:
//!  1. **Filtered to this process** ([`SyscallTracer::watch_pid`]): do an `openat` and a `connect`
//!     ourselves and see exactly those events, with their path / address decoded.
//!  2. **Unfiltered** ([`SyscallTracer::watch_all`]): spawn `/bin/true` and see its `execve` show up —
//!     an event that phase 1's pid filter deliberately dropped (the child runs under a different tgid).
//!
//! Needs `CAP_BPF`+`CAP_PERFMON` (or root), a BTF kernel, and the built object
//! (`cargo xtask build-probes`). Grant just the two caps to the built example, or run it as root:
//!
//! ```console
//! cargo xtask build-probes
//! cargo build -p agent-probes-loader --example trace_syscalls
//! sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/trace_syscalls
//! target/debug/examples/trace_syscalls
//! ```
//!
//! Returning a boxed error from `main` keeps this within the no-panic host discipline (no
//! `unwrap`/`expect`): a missing object or a load without the caps prints the typed error and exits.

use std::error::Error;
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use agent_probes_loader::{Syscall, SyscallEvent, SyscallTracer};

fn main() -> Result<(), Box<dyn Error>> {
    let mut tracer = SyscallTracer::load()?;

    // Phase 1: watch only this process, then make one openat and one connect of our own.
    let me = std::process::id();
    tracer.watch_pid(me)?;
    let _ = tracer.drain(|_| {})?; // discard anything buffered before we start

    let _ = std::fs::File::open("/etc/hostname"); // an openat with a known path
    if let Ok(addr) = "127.0.0.1:9".parse::<SocketAddr>() {
        // Discard port 9 (discard): the connect syscall fires whether or not it is refused.
        let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(50));
    }
    sleep(Duration::from_millis(50));

    println!("== filtered to pid {me} ==");
    let mut seen = 0usize;
    tracer.drain(|ev| {
        seen += 1;
        print_event(&ev);
    })?;
    if seen == 0 {
        println!("  (no events — is the object built and are the caps granted?)");
    }

    // Phase 2: unfilter, spawn a child, and watch its execve appear (the pid filter hid it before).
    tracer.watch_all()?;
    let _ = tracer.drain(|_| {})?;
    let _ = Command::new("true").status(); // one execve of /bin/true, in a child (different tgid)
    sleep(Duration::from_millis(50));

    println!("== unfiltered (whole host) ==");
    let mut execves = 0usize;
    tracer.drain(|ev| {
        if ev.kind() == Some(Syscall::Execve) {
            execves += 1;
            if execves <= 5 {
                print_event(&ev);
            }
        }
    })?;
    println!("  saw {execves} execve event(s) this window (the child's `true` among them)");
    Ok(())
}

/// Print one event: which syscall, from which pid/comm, with its detail decoded (a path for
/// execve/openat, an address for connect).
fn print_event(ev: &SyscallEvent) {
    let kind = match ev.kind() {
        Some(Syscall::Execve) => "execve",
        Some(Syscall::Openat) => "openat",
        Some(Syscall::Connect) => "connect",
        None => "?",
    };
    println!(
        "  {kind:<7} pid={} comm={} {}",
        ev.pid,
        ev.comm_lossy(),
        describe_detail(ev)
    );
}

/// Decode an event's detail blob for display: a path string for execve/openat, or a host:port for a
/// `connect` sockaddr (IPv4 fully; other families are reported by number).
fn describe_detail(ev: &SyscallEvent) -> String {
    let detail = ev.detail();
    match ev.kind() {
        Some(Syscall::Connect) => describe_sockaddr(detail),
        _ => String::from_utf8_lossy(detail).into_owned(),
    }
}

/// A best-effort human form of the leading sockaddr bytes: `AF_INET` yields `a.b.c.d:port`, other
/// families just name the family number.
fn describe_sockaddr(bytes: &[u8]) -> String {
    // sa_family is a native-endian u16; AF_INET == 2, its sockaddr_in is family, be16 port, 4-byte ip.
    const AF_INET: u16 = 2;
    if bytes.len() >= 8 {
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family == AF_INET {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            return format!("{}.{}.{}.{}:{port}", bytes[4], bytes[5], bytes[6], bytes[7]);
        }
        return format!("<sockaddr family {family}>");
    }
    "<sockaddr: too short>".to_string()
}
