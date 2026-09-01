//! End-to-end tests for the user-facing verbs: each boots a real guest through the built `bsx`.
//!
//! `#[ignore]`d for the reason the supervisor's leak suite is: they need `/dev/kvm` and a guest
//! tree, and **skip with a printed reason** where a prerequisite is missing, because cargo counts
//! a skipped test as a pass. Run with `cargo test -p bsx --test e2e -- --ignored`.

// A test binary: `expect` is the idiomatic assertion in helpers outside `#[test]`.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Why this host cannot run these, or `None` when it can.
fn skip_reason() -> Option<String> {
    if let Some(why) = bsx_test_support::kvm_unusable() {
        return Some(why);
    }
    if !guest_root().is_dir() {
        return Some(format!(
            "no guest tree at {} (run `cargo xtask build-rootfs`)",
            guest_root().display()
        ));
    }
    None
}

/// Prints why a test did nothing and returns whether it should stop.
fn skipped(test: &str) -> bool {
    match skip_reason() {
        Some(why) => {
            println!("SKIPPED {test}: {why}");
            true
        }
        None => false,
    }
}

fn guest_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or(Path::new("."))
        .join("artifacts/rootfs-guest")
}

/// The `bsx` under test: the binary cargo built for this test run, never a `PATH` lookup.
fn bsx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bsx"))
}

/// The roadmap's own example: the guest's stdout is this process's stdout, unmixed with anything
/// else, and a clean run exits 0.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn run_prints_the_guests_output_and_nothing_else() {
    if skipped("run_prints_the_guests_output_and_nothing_else") {
        return;
    }
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--", "echo", "hello"])
        .output()
        .expect("run bsx");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hello\n",
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{}", out.status);
}

/// The guest command's exit code is the verb's exit code, which is what lets `bsx run` sit in a
/// script where the command itself would.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn run_exits_with_the_guest_commands_code() {
    if skipped("run_exits_with_the_guest_commands_code") {
        return;
    }
    let status = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--", "sh", "-c", "exit 7"])
        .status()
        .expect("run bsx");
    assert_eq!(status.code(), Some(7));
}

/// The shell verb without a terminal: the guest command still runs on a real guest pty of the
/// default 80x24, its output crosses the channel, and its exit code is the verb's. The
/// interactive half (raw mode, keystrokes, live resize) needs a terminal on this side and is
/// verified by hand through a pty driver; what this pins is the whole boot-agent-vsock-session
/// path.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree (with the agent baked in)"]
fn shell_runs_the_command_on_a_guest_pty_and_returns_its_exit() {
    if skipped("shell_runs_the_command_on_a_guest_pty_and_returns_its_exit") {
        return;
    }
    let out = bsx()
        .arg("shell")
        .arg("--root")
        .arg(guest_root())
        .args(["--", "/bin/sh", "-c", "tty; stty size; exit 3"])
        .output()
        .expect("run bsx shell");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("/dev/pts/"),
        "not a guest pty: {stdout:?} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("24 80"), "not the default size: {stdout:?}");
    assert_eq!(out.status.code(), Some(3), "the guest's code is the verb's");
}

/// A root that is not a directory is refused before any boot, with the message naming the fix.
#[test]
#[ignore = "spawns the built bsx (no VM boots: the refusal is the test)"]
fn run_refuses_a_missing_root_before_booting() {
    let out = bsx()
        .args(["run", "--root", "/nonexistent-bsx-root", "--", "true"])
        .output()
        .expect("run bsx");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("build-rootfs"), "names the fix: {err}");
}
