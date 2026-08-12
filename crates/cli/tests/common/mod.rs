//! The daemon harness shared by the cli integration suites (each declares `mod common;`): spawn
//! `bsx serve` on a private socket, wait for the bind, and SIGKILL it on drop.
// Each test binary compiles this whole module but uses only the helpers it needs, so the unused
// remainder must not fail the `-D warnings` gate.
#![allow(dead_code)]
// A test module: `panic!` in free helpers is the idiomatic assertion, which the workspace's
// `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bsx_test_support::workspace_root;

/// A spawned `bsx serve` that is SIGKILLed on drop, so a panicking assertion can't leak the daemon
/// (its session VMs are then reaped by the lifetime sentinel; the socket file it leaves is cleared
/// on the next bind).
pub struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Launch `bsx serve` on a private socket, pointed at the workspace's guest rootfs. `prewarm`
/// becomes `--prewarm N` when set (the pool path); `metrics_port` becomes
/// `--metrics 127.0.0.1:PORT`. Returns once the socket is connectable.
pub fn launch_daemon(prewarm: Option<usize>, metrics_port: Option<u16>) -> (Daemon, PathBuf) {
    launch_daemon_opts(prewarm, metrics_port, false, &[])
}

pub fn launch_daemon_opts(
    prewarm: Option<usize>,
    metrics_port: Option<u16>,
    jailed: bool,
    extra_args: &[&str],
) -> (Daemon, PathBuf) {
    let root = workspace_root();
    // A per-call sequence number, because the process id alone cannot distinguish two tests in
    // one binary: two launches with the same knobs would otherwise share a dir, and each
    // `remove_dir_all` below then deletes the *other* test's live socket, a flake that only fires
    // when the scheduler overlaps them.
    static LAUNCH_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = LAUNCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("bsx-e2e-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("create the daemon's socket dir: {e}");
    }
    let socket = dir.join("bsx.sock");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bsx"));
    cmd.arg("serve");
    if !jailed {
        cmd.arg("--unjailed");
    }
    cmd.arg("--socket").arg(&socket);
    if let Some(n) = prewarm {
        cmd.arg("--prewarm").arg(n.to_string());
    }
    if let Some(port) = metrics_port {
        cmd.arg("--metrics").arg(format!("127.0.0.1:{port}"));
    }
    cmd.args(extra_args);
    // A `$HOME` with no `.bsx.toml`: the user file is read whatever the cwd is, so without this
    // the developer's own config would supply artifact paths and ceilings to the daemon under test.
    cmd.env("HOME", &dir)
        .env("BSX_ROOTFS", root.join("artifacts/rootfs-guest.ext4"))
        // The guest rootfs signals readiness with its own marker, not a getty `login:`.
        .env("BSX_MARKER", bsx_engine::GUEST_READY_MARKER)
        // Keep the daemon's generated record-signing key inside the test's socket dir.
        .env("BSX_SIGNING_KEY", dir.join("signing.key"))
        .env("BSX_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if std::env::var_os("BSX_KERNEL").is_none() {
        cmd.env("BSX_KERNEL", root.join("artifacts/vmlinux"));
    }
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn bsx: {e}"));
    let daemon = Daemon { child, dir };

    // Wait for the daemon to bind and start accepting. A prewarmed daemon boots a source + clones
    // first, so allow it longer.
    let budget = if prewarm.is_some() { 40 } else { 10 };
    let deadline = Instant::now() + Duration::from_secs(budget);
    while Instant::now() < deadline {
        if UnixStream::connect(&socket).is_ok() {
            return (daemon, socket);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("bsx never began accepting on {}", socket.display());
}
