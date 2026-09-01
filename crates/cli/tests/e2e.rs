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
    // The image tree's /tmp before and after: a session's scratch lives on a guest tmpfs, so a
    // run must add nothing here. Session dirs used to land in the shared image through the rw
    // root virtiofs and survive the VM.
    let image_tmp = || -> Vec<String> {
        std::fs::read_dir(guest_root().join("tmp"))
            .map(|d| {
                d.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let tmp_before = image_tmp();
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
    assert_eq!(
        image_tmp(),
        tmp_before,
        "a session left scratch in the shared image tree; the agent's tmpfs over /tmp is gone"
    );
}

/// The 3.6 contract, and the finding behind it: by default the guest cannot reach the host's
/// network. libkrun's own default is an implicit vsock whose TSI hijacking proxies the guest's
/// sockets onto the host, so a guest with no config could reach a host-only loopback service;
/// `--net none` (the default) replaces that device with one that does no hijacking. A host HTTP
/// server on 127.0.0.1 stands in for "the host's network": a network-isolated guest's own
/// loopback has no such server, so reaching it would prove the isolation is not there.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn the_default_guest_cannot_reach_the_host_network() {
    if skipped("the_default_guest_cannot_reach_the_host_network") {
        return;
    }
    let server = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a host-only server");
    let port = server.local_addr().expect("addr").port();
    // A minimal HTTP reply in the background, because the guest probes with `wget`, which reports
    // failure on a bare connect that carries no response. So the server must actually answer for
    // a reached connection to read as REACHED; a blocked one never connects at all.
    std::thread::spawn(move || {
        use std::io::Write;
        for mut s in server.incoming().take(4).flatten() {
            let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
    });

    let probe = format!(
        "wget -T 3 -q -O /dev/null http://127.0.0.1:{port}/ && echo REACHED || echo blocked"
    );
    let reach = |net: &str| -> String {
        let out = bsx()
            .arg("run")
            .arg("--root")
            .arg(guest_root())
            .args(["--net", net, "--", "sh", "-c", &probe])
            .output()
            .expect("run bsx");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(
        reach("none"),
        "blocked",
        "the default guest reached the host network"
    );
    // The opt-in restores it, which is what proves `none` is doing the blocking rather than the
    // host simply being unreachable for other reasons.
    assert_eq!(
        reach("tsi"),
        "REACHED",
        "--net tsi should reach host loopback"
    );
}

/// The 3.5 contract: the limits in the config are the machine the guest actually gets. Asked
/// for 2 vCPUs and 256 MiB, the guest's own `nproc` says 2 and its `MemTotal` sits within a
/// kernel-overhead band of the ask (measured 271 MiB for a 256 MiB config), not at the 512 MiB
/// default and not at the host's size.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn the_configured_limits_are_what_the_guest_sees() {
    if skipped("the_configured_limits_are_what_the_guest_sees") {
        return;
    }
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--vcpus", "2", "--mem", "256"])
        .args([
            "--",
            "sh",
            "-c",
            "nproc; awk '/MemTotal/{print $2}' /proc/meminfo",
        ])
        .output()
        .expect("run bsx");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("2"),
        "nproc must be the configured 2: {stdout:?}"
    );
    let mem_kib: u64 = lines
        .next()
        .and_then(|l| l.trim().parse().ok())
        .expect("a MemTotal number");
    let asked_kib = 256 * 1024;
    assert!(
        (asked_kib - 64 * 1024..=asked_kib + 64 * 1024).contains(&mem_kib),
        "guest MemTotal {mem_kib} KiB is not within a kernel-overhead band of the 256 MiB ask"
    );
}

/// The environment layer: with no flag, `BSX_VCPUS` decides, which is the flag-then-env order
/// every layered knob here follows.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_limit_from_the_environment_reaches_the_guest() {
    if skipped("a_limit_from_the_environment_reaches_the_guest") {
        return;
    }
    let out = bsx()
        .arg("run")
        .env("BSX_VCPUS", "2")
        .arg("--root")
        .arg(guest_root())
        .args(["--", "nproc"])
        .output()
        .expect("run bsx");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "2",
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A machine larger than the host is a refusal before boot, not a guest that believes in RAM
/// nothing can back.
#[test]
#[ignore = "spawns the built bsx (no VM boots: the refusal is the test)"]
fn a_machine_larger_than_the_host_is_refused_before_boot() {
    let out = bsx()
        .args(["run", "--root", "/tmp", "--mem", "4000000", "--", "true"])
        .output()
        .expect("run bsx");
    if !Path::new("/proc/meminfo").exists() {
        println!("SKIPPED a_machine_larger_than_the_host_is_refused_before_boot: no MemTotal");
        return;
    }
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("more RAM than this host"), "{err}");
}

/// The 3.3 contract: a host directory is read-write at the guest path, and edits land on the
/// host. The `mkdir -p` mount point persisting in the image tree is the documented cost of
/// libkrun's overlay-dir primitive being unusable, so it is asserted (and cleaned) rather than
/// ignored: if it stops appearing, the mechanism changed and the docs should too.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_mounted_directory_is_read_write_and_edits_land_on_the_host() {
    if skipped("a_mounted_directory_is_read_write_and_edits_land_on_the_host") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-mount");
    std::fs::write(dir.path().join("f"), "from-host\n").expect("stage a host file");

    let mount = format!("/project={}", dir.path().display());
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--mount", &mount])
        .args([
            "--",
            "sh",
            "-c",
            "cat /project/f && echo from-guest > /project/g",
        ])
        .output()
        .expect("run bsx");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "from-host\n");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("g")).expect("the guest's edit reached the host"),
        "from-guest\n"
    );
    let leftover = guest_root().join("project");
    assert!(
        leftover.is_dir(),
        "the mkdir -p mount point lands in the image tree; if this stops, the mechanism changed"
    );
    std::fs::remove_dir(&leftover).expect("tidy the documented drift");
}

/// The crash class found while building 3.3: a byte outside printable ASCII in the workload's
/// argv aborted the whole VMM inside libkrun (SIGABRT, exit 134). It must be a typed refusal.
#[test]
#[ignore = "spawns the built bsx (no VM boots: the refusal is the test)"]
fn a_non_ascii_argument_is_refused_not_aborted_on() {
    let out = bsx()
        .args(["run", "--root", "/tmp", "--", "echo", "\u{e9}"])
        .output()
        .expect("run bsx");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a refusal, not the SIGABRT this class used to be"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("printable ASCII"), "names the rule: {err}");
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
