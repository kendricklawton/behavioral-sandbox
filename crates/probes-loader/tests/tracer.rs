//! Privileged integration tests for the syscall tracer (the per-event ring buffer, the target
//! filter).
//!
//! `#[ignore]`d for the same reason as the counter tests: loading eBPF needs `CAP_BPF`+`CAP_PERFMON`
//! (or root), a BTF-capable kernel, and the built object (`cargo xtask build-probes`). Run them via
//! `cargo xtask ci-privileged` (as root), or grant the two caps to the test binary and run it
//! unprivileged. Each self-skips when its prerequisites are absent, so an unprivileged run
//! reports a clean skip, not a failure.
#![allow(clippy::panic)]

use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use agent_probes_loader::{cgroup_id_of_self, check_support, object_path, Syscall, SyscallTracer};

/// Why this host can't load the probe (a skip reason), or `None` when it can, so each test prints
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
    // The ring buffer carries per-event data, not just a count. Filter to our own pid, do an
    // `openat` of a unique (nonexistent) path, and assert that exact event streams back, the path
    // proves the per-event payload, and every captured event being our pid proves the filter.
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
    // A pid filter drops a child's events; clearing it reveals them. Spawn `/bin/true` (one
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
    // The connect program copies the leading sockaddr bytes. Connect (refused is fine) to a
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

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn attributes_events_to_this_process_cgroup() {
    // `cgroup_id_of_self` (the inode of our cgroup dir) must equal the `bpf_get_current_cgroup_id`
    // the programs stamp on our events, the whole attribution bridge. Watch that cgroup and prove our
    // own openat comes back carrying it; an empty capture would mean the two ids disagree on this host.
    if let Some(why) = skip_reason() {
        eprintln!("skipping attributes_events_to_this_process_cgroup: {why}");
        return;
    }
    let my_cgroup = match cgroup_id_of_self() {
        Ok(id) => id,
        // A cgroup-v1-only host has no unified `0::` line; skip rather than fail.
        Err(e) => {
            eprintln!("skipping attributes_events_to_this_process_cgroup: {e}");
            return;
        }
    };
    let mut tracer = SyscallTracer::load().expect("load + attach the syscall tracer");
    tracer
        .watch_cgroup(my_cgroup)
        .expect("filter to this cgroup");
    tracer.drain(|_| {}).expect("clear the baseline");

    let marker = format!("/tmp/agent-p94-cgroup-{}-marker", std::process::id());
    let _ = std::fs::File::open(&marker);
    sleep(Duration::from_millis(50));

    let mut events = Vec::new();
    tracer.drain(|ev| events.push(ev)).expect("drain");
    assert!(
        !events.is_empty(),
        "watching our own cgroup id {my_cgroup} must capture our events (an empty capture means the \
         cgroup-dir inode and bpf_get_current_cgroup_id disagree on this host)"
    );
    assert!(
        events.iter().all(|e| e.cgroup_id == my_cgroup),
        "every captured event must carry the watched cgroup id {my_cgroup}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind() == Some(Syscall::Openat) && e.detail() == marker.as_bytes()),
        "the marker openat must appear, attributed to our cgroup"
    );
}

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn a_workload_child_shows_up_attributed_to_its_cgroup() {
    // The exit gate in miniature: launch a *workload*, a child process standing in for
    // a sandbox's VMM, and assert its own `execve` and `openat` come back attributed to a cgroup id,
    // the sandbox-attribution axis. The child inherits our cgroup, so watching that id captures
    // the whole process tree (us + the workload) the way `watch_cgroup(vmm_cgroup)` captures a
    // sandbox's host footprint.
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_workload_child_shows_up_attributed_to_its_cgroup: {why}");
        return;
    }
    let my_cgroup = match cgroup_id_of_self() {
        Ok(id) => id,
        // A cgroup-v1-only host has no unified `0::` line; skip rather than fail (as the cgroup-attribution test does).
        Err(e) => {
            eprintln!("skipping a_workload_child_shows_up_attributed_to_its_cgroup: {e}");
            return;
        }
    };
    let me = std::process::id();
    let mut tracer = SyscallTracer::load().expect("load + attach the syscall tracer");
    tracer
        .watch_cgroup(my_cgroup)
        .expect("filter to this cgroup");
    tracer.drain(|_| {}).expect("clear the baseline");

    // The workload: `cat <missing>` is one child that both `execve`s (itself) and `openat`s a known
    // path (the file it tries to read). The path never exists, so the open just fails ENOENT, but
    // `sys_enter_openat` fires regardless, carrying the path, and nothing is created or left behind.
    let marker = format!("/tmp/agent-p96-workload-{me}-missing");
    let status = Command::new("cat")
        .arg(&marker)
        .status()
        .expect("spawn the `cat` workload");
    assert!(!status.success(), "cat of a missing path should fail"); // sanity: it really ran the open
    sleep(Duration::from_millis(50));

    let mut events = Vec::new();
    tracer.drain(|ev| events.push(ev)).expect("drain");
    // Attribution invariant: everything captured carries the watched cgroup id.
    assert!(
        events.iter().all(|e| e.cgroup_id == my_cgroup),
        "every captured event must carry the watched cgroup id {my_cgroup}"
    );
    // The workload's own execve (a child, so a pid other than ours) is attributed to the cgroup.
    assert!(
        events
            .iter()
            .any(|e| e.kind() == Some(Syscall::Execve) && e.pid != me),
        "the workload child's execve must show up under the watched cgroup (saw pids {:?})",
        events.iter().map(|e| e.pid).collect::<Vec<_>>()
    );
    // ...and its openat of the marker path, proving per-event data survives the whole attribution path.
    assert!(
        events
            .iter()
            .any(|e| e.kind() == Some(Syscall::Openat) && e.detail() == marker.as_bytes()),
        "the workload's openat of {marker:?} must show up attributed to the cgroup"
    );
}

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn stream_delivers_a_live_trace_over_a_window() {
    // `stream` must deliver events live and stop on the predicate. Filter to us, keep opening a
    // file from a background thread (same pid, so it passes the filter), stream for a short window, and
    // assert the callback saw events and the returned count matches.
    if let Some(why) = skip_reason() {
        eprintln!("skipping stream_delivers_a_live_trace_over_a_window: {why}");
        return;
    }
    let me = std::process::id();
    let mut tracer = SyscallTracer::load().expect("load + attach the syscall tracer");
    tracer.watch_pid(me).expect("filter to this pid");
    tracer.drain(|_| {}).expect("clear the baseline");

    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::File::open("/tmp/agent-p93-stream-probe");
                sleep(Duration::from_millis(5));
            }
        })
    };

    let deadline = Instant::now() + Duration::from_millis(300);
    let mut seen = 0usize;
    let count = tracer
        .stream(
            Duration::from_millis(2),
            || Instant::now() < deadline,
            |_| seen += 1,
        )
        .expect("stream");
    stop.store(true, Ordering::Relaxed);
    worker.join().ok();

    assert_eq!(count, seen, "stream's return must match the callback count");
    assert!(
        seen > 0,
        "the live stream must deliver the background thread's openats"
    );
}
