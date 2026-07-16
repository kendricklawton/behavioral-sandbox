//! Privileged integration tests for the syscall tracer (P9.1 per-event ring buffer, P9.2 target
//! filter).
//!
//! `#[ignore]`d for the same reason as the counter tests: loading eBPF needs `CAP_BPF`+`CAP_PERFMON`
//! (or root), a BTF-capable kernel, and the built object (`cargo xtask build-probes`). Run them via
//! `cargo xtask ci-privileged` (as root), or grant the two caps to the test binary and run it
//! unprivileged (P8.8). Each self-skips when its prerequisites are absent, so an unprivileged run
//! reports a clean skip, not a failure.
#![allow(clippy::panic)]

use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use agent_probes_loader::{check_support, object_path, Syscall, SyscallTracer};

/// Why this host can't load the probe (a skip reason), or `None` when it can — so each test prints
/// *why* it skipped. Same gate the counter tests use.
fn skip_reason() -> Option<String> {
    if let Err(e) = check_support() {
        return Some(e.to_string());
    }
    if !object_path().is_file() {
        return Some(format!(
            "BPF object {} not built (run `cargo xtask build-probes`)",
            object_path().display()
        ));
    }
    None
}

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn tracer_captures_this_process_openat_with_its_path() {
    // P9.1: the ring buffer carries per-event data, not just a count. Filter to our own pid, do an
    // `openat` of a unique (nonexistent) path, and assert that exact event streams back — the path
    // proves the per-event payload, and every captured event being our pid proves the P9.2 filter.
    if let Some(why) = skip_reason() {
        eprintln!("skipping tracer_captures_this_process_openat_with_its_path: {why}");
        return;
    }
    let mut tracer = SyscallTracer::load().expect("load + attach the syscall tracer");
    let me = std::process::id();
    tracer.watch_pid(me).expect("filter to this pid");
    tracer.drain(|_| {}).expect("clear the baseline"); // discard whatever was buffered pre-filter

    // `sys_enter_openat` fires whether or not the path exists, so a unique nonexistent path is a
    // clean, collision-free needle to find in the stream.
    let marker = format!("/tmp/agent-p9-openat-{me}-marker");
    let _ = std::fs::File::open(&marker);
    sleep(Duration::from_millis(50));

    let mut events = Vec::new();
    tracer
        .drain(|ev| events.push(ev))
        .expect("drain the ring buffer");
    assert!(
        !events.is_empty(),
        "the filtered window must have captured at least our own openat"
    );
    assert!(
        events.iter().all(|e| e.pid == me),
        "with a pid filter set, every captured event must be this process's ({me}); saw {:?}",
        events.iter().map(|e| e.pid).collect::<Vec<_>>()
    );
    let found_marker = events
        .iter()
        .any(|e| e.kind() == Some(Syscall::Openat) && e.detail() == marker.as_bytes());
    assert!(
        found_marker,
        "the exact openat path must appear in the per-event data (looked for {marker:?})"
    );
}

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn filter_hides_other_pids_then_watch_all_reveals_a_child_execve() {
    // P9.2: a pid filter drops a child's events; clearing it reveals them. Spawn `/bin/true` (one
    // execve, in a child with a different tgid) under our-pid filter → not seen; then `watch_all` and
    // spawn again → its execve is seen. Proves the filter both excludes and, cleared, includes.
    if let Some(why) = skip_reason() {
        eprintln!("skipping filter_hides_other_pids_then_watch_all_reveals_a_child_execve: {why}");
        return;
    }
    let mut tracer = SyscallTracer::load().expect("load + attach the syscall tracer");
    let me = std::process::id();

    // Filtered to us: a child's execve must not appear.
    tracer.watch_pid(me).expect("filter to this pid");
    tracer.drain(|_| {}).expect("clear the baseline");
    let _ = Command::new("true")
        .status()
        .expect("spawn `true` (filtered)");
    sleep(Duration::from_millis(50));
    let mut filtered = Vec::new();
    tracer
        .drain(|ev| filtered.push(ev))
        .expect("drain filtered");
    assert!(
        filtered.iter().all(|e| e.pid == me),
        "the child `true` (a different pid) must be filtered out; saw pids {:?}",
        filtered.iter().map(|e| e.pid).collect::<Vec<_>>()
    );

    // Unfiltered: the child's execve now shows up (under a pid that is not ours).
    tracer.watch_all().expect("clear the filter");
    tracer.drain(|_| {}).expect("clear the baseline");
    let _ = Command::new("true")
        .status()
        .expect("spawn `true` (unfiltered)");
    sleep(Duration::from_millis(50));
    let mut child_execves = 0usize;
    tracer
        .drain(|ev| {
            if ev.kind() == Some(Syscall::Execve) && ev.pid != me {
                child_execves += 1;
            }
        })
        .expect("drain unfiltered");
    assert!(
        child_execves > 0,
        "unfiltered, a child process's execve must be observed (none were)"
    );
}

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn tracer_captures_a_connect_sockaddr() {
    // P9.1: the connect program copies the leading sockaddr bytes. Connect (refused is fine) to a
    // known 127.0.0.1 address and assert the captured detail decodes to that IPv4 address.
    if let Some(why) = skip_reason() {
        eprintln!("skipping tracer_captures_a_connect_sockaddr: {why}");
        return;
    }
    let mut tracer = SyscallTracer::load().expect("load + attach the syscall tracer");
    let me = std::process::id();
    tracer.watch_pid(me).expect("filter to this pid");
    tracer.drain(|_| {}).expect("clear the baseline");

    let addr: SocketAddr = "127.0.0.1:9".parse().expect("parse the discard address");
    let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(50)); // refused is fine
    sleep(Duration::from_millis(50));

    let mut events = Vec::new();
    tracer
        .drain(|ev| events.push(ev))
        .expect("drain the ring buffer");
    let found = events.iter().any(|e| {
        e.kind() == Some(Syscall::Connect) && sockaddr_is_ipv4(e.detail(), [127, 0, 0, 1], 9)
    });
    assert!(
        found,
        "the connect's 127.0.0.1:9 sockaddr must appear in the per-event data"
    );
}

/// Whether the leading sockaddr bytes decode to `AF_INET` with the given IPv4 address and port.
fn sockaddr_is_ipv4(bytes: &[u8], ip: [u8; 4], port: u16) -> bool {
    const AF_INET: u16 = 2;
    bytes.len() >= 8
        && u16::from_ne_bytes([bytes[0], bytes[1]]) == AF_INET
        && u16::from_be_bytes([bytes[2], bytes[3]]) == port
        && bytes[4..8] == ip
}
