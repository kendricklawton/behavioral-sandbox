//! End-to-end tests for the user-facing verbs: each boots a real guest through the built `bsx`.
//!
//! `#[ignore]`d for the reason the supervisor's leak suite is: they need `/dev/kvm` and a guest
//! tree, and **skip with a printed reason** where a prerequisite is missing, because cargo counts
//! a skipped test as a pass. Run with `cargo test -p bsx --test e2e -- --ignored`.

// A test binary: `expect` is the idiomatic assertion in helpers outside `#[test]`.
#![allow(clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
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
    //
    // The request is **read before the reply is written**. Closing a socket with unread data in
    // its receive queue sends an RST, which discards the reply the guest had not read yet: the
    // connection arrives, the answer never does, and a working `tsi` reports as blocked (watched
    // happen).
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for mut s in server.incoming().take(4).flatten() {
            let _ = s.read(&mut [0u8; 4096]);
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

/// The 3.3 contract, under 3.7's read-only root: a host directory is read-write at the guest
/// path, and edits land on the host, while the image tree the mount point lives in is untouched.
/// `/mnt` because the image has it: the preamble's `mkdir -p` cannot make one through a
/// read-only root, which is what `a_mount_point_the_image_lacks_is_refused_before_boot` covers.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_mounted_directory_is_read_write_and_edits_land_on_the_host() {
    if skipped("a_mounted_directory_is_read_write_and_edits_land_on_the_host") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-mount");
    std::fs::write(dir.path().join("f"), "from-host\n").expect("stage a host file");

    let mount = format!("/mnt={}", dir.path().display());
    let image_top = || -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(guest_root())
            .expect("the image tree")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort();
        names
    };
    let before = image_top();
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--mount", &mount])
        .args(["--", "sh", "-c", "cat /mnt/f && echo from-guest > /mnt/g"])
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
    assert_eq!(
        image_top(),
        before,
        "a mounted run changed the shared image tree; 3.3 left mount points behind and 3.7's \
         read-only root is what stops it"
    );
}

/// The 3.7 contract, and the finding behind it: the image tree is shared by every sandbox this
/// host boots, so by default a guest cannot write it. Asserted by *writing*, because the posture
/// lives on the virtiofs device and the guest cannot see it: `/proc/mounts` still reports the
/// root `rw` either way (measured 2026-09-01, libkrun 1.19.4).
///
/// Both directions, because "the write failed" alone would also be true of a guest that could
/// not run `echo`: `--rootfs writable` must put the file in the image tree.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn the_default_guest_cannot_write_the_image_it_boots_from() {
    if skipped("the_default_guest_cannot_write_the_image_it_boots_from") {
        return;
    }
    let probe = guest_root().join("bsx-write-probe");
    let _ = std::fs::remove_file(&probe);
    let write = |posture: &str| -> String {
        let out = bsx()
            .arg("run")
            .arg("--root")
            .arg(guest_root())
            .args(["--rootfs", posture])
            .args([
                "--",
                "sh",
                "-c",
                "echo guest > /bsx-write-probe && echo WROTE || echo blocked",
            ])
            .output()
            .expect("run bsx");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(
        write("read-only"),
        "blocked",
        "the default root took a write"
    );
    assert!(
        !probe.exists(),
        "a refused guest write still reached the shared image tree at {}",
        probe.display()
    );

    assert_eq!(write("writable"), "WROTE", "the opt-in must restore it");
    assert_eq!(
        std::fs::read_to_string(&probe).expect("the writable root's edit reached the image tree"),
        "guest\n"
    );
    std::fs::remove_file(&probe).expect("tidy what --rootfs writable is for");
}

/// A mount point the image lacks is a typed refusal on the host, naming both ways forward,
/// rather than the preamble's exit 2 on a console the caller may not be watching. No guest tree
/// needed: the check reads the tree the VM would serve, and `/tmp` has no `/no-such-mount-point`.
#[test]
#[ignore = "spawns the built bsx (no VM boots: the refusal is the test)"]
fn a_mount_point_the_image_lacks_is_refused_before_boot() {
    let out = bsx()
        .args(["run", "--root", "/tmp"])
        .args(["--mount", "/no-such-mount-point=/tmp"])
        .args(["--", "true"])
        .output()
        .expect("run bsx");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("/no-such-mount-point"), "names it: {err}");
    assert!(
        err.contains("/mnt"),
        "names a mount point that exists: {err}"
    );
    assert!(err.contains("--rootfs writable"), "names the opt-in: {err}");
}

/// Design rule 3's other half: what is shared is visible *before* the VM starts. `--dry-run`
/// prints the posture and boots nothing, which is asserted through the control socket every
/// boot leaves behind: no socket, no VM. The second half runs the same command for real, so a
/// change that stopped the socket from appearing could not leave this passing vacuously.
#[test]
#[ignore = "the dry run boots nothing; the paired real run needs /dev/kvm and the guest tree"]
fn a_dry_run_prints_the_posture_and_boots_nothing() {
    let runtime = bsx_test_support::ScratchDir::created("e2e-dry-run");
    std::fs::set_permissions(runtime.path(), PermissionsExt::from_mode(0o700))
        .expect("a control-socket directory must be private");
    let name = format!("dryrun-{}", std::process::id());
    let socket = runtime.path().join("bsx").join(format!("{name}.sock"));

    let out = bsx()
        .arg("run")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["--root", "/tmp", "--name", &name, "--dry-run"])
        .args(["--", "true"])
        .output()
        .expect("run bsx");
    assert!(out.status.success(), "{}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in ["root     /tmp read-only", "network  none", "exec     true"] {
        assert!(stdout.contains(line), "{line:?} missing from:\n{stdout}");
    }
    assert!(
        !socket.exists(),
        "a dry run bound {}, so it booted something",
        socket.display()
    );

    if skipped("a_dry_run_prints_the_posture_and_boots_nothing (the paired real run)") {
        return;
    }
    let out = bsx()
        .arg("run")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["--root"])
        .arg(guest_root())
        .args(["--name", &name])
        .args(["--", "true"])
        .output()
        .expect("run bsx");
    assert!(out.status.success(), "{}", out.status);
    assert!(
        socket.exists(),
        "a real run leaves its control socket at {}; without that the dry-run assertion above \
         proves nothing",
        socket.display()
    );
}

/// A `--share` cannot take a tag `--mount` uses. The guest mounts by tag, so a duplicate left it
/// mounting whichever device the kernel matched first: `--share bsx-mnt-0=X --mount /mnt=Y` put
/// `X` at `/mnt` and `Y` nowhere, with `--dry-run` printing the mount that did not happen
/// (measured 2026-09-01). Refused before boot, because nothing downstream can tell.
#[test]
#[ignore = "spawns the built bsx (no VM boots: the refusal is the test)"]
fn a_share_tag_that_would_shadow_a_mount_is_refused_before_boot() {
    let out = bsx()
        .args(["run", "--root", "/tmp"])
        .args(["--share", "bsx-mnt-0=/tmp"])
        .args(["--mount", "/mnt=/tmp"])
        .args(["--", "true"])
        .output()
        .expect("run bsx");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("bsx-mnt-0"), "names the tag: {err}");
    assert!(err.contains("reserved"), "names the rule: {err}");
}

/// Roadmap 0.9 and the whole of 4.2's frame path: a guest that draws through a DRM dumb buffer
/// puts a known pattern on its scanout, and the pixels arrive on the host. The drawer needs no
/// libdrm (`drm_draw.py`, ioctls by hand), runs on the phase-3 image because `python3` is in it,
/// and paints red, green, blue and white corners on grey. The display runs headless here, so a
/// runner with no display server can read the frame too; the window is the same path with a
/// surface on the end.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_frame_the_guest_draws_reaches_the_host() {
    if skipped("a_frame_the_guest_draws_reaches_the_host") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-frame");
    std::fs::write(dir.path().join("draw.py"), include_str!("drm_draw.py"))
        .expect("stage the drawer");
    let shot = dir.path().join("frame.ppm");
    let mount = format!("/mnt={}", dir.path().display());
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--display", "320x240", "--mount", &mount])
        .arg("--screenshot")
        .arg(&shot)
        // No display server for this one: the headless branch is the one every runner has.
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["--", "python3", "/mnt/draw.py", "4"])
        .output()
        .expect("run bsx");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("DRAW setcrtc ok"),
        "the guest never got its mode set: {stderr}"
    );
    let ppm = std::fs::read(&shot).expect("a frame was written");
    let mut parts = ppm.splitn(4, |&b| b == b'\n');
    assert_eq!(parts.next(), Some(&b"P6"[..]));
    assert_eq!(
        parts.next(),
        Some(&b"320 240"[..]),
        "the scanout is the display's size"
    );
    parts.next();
    let px = parts.next().expect("pixels");
    let at = |x: usize, y: usize| &px[(y * 320 + x) * 3..(y * 320 + x) * 3 + 3];
    assert_eq!(at(2, 2), [255, 0, 0], "top-left is red");
    assert_eq!(at(317, 2), [0, 255, 0], "top-right is green");
    assert_eq!(at(2, 237), [0, 0, 255], "bottom-left is blue");
    assert_eq!(at(317, 237), [255, 255, 255], "bottom-right is white");
    assert_eq!(at(160, 120), [0x40, 0x40, 0x40], "the middle is grey");
}

/// A key on the keyboard device and a click on the pointer device arrive in the guest as the
/// evdev events a process there reads, under the names the devices were given (roadmap 0.10).
/// The events go in through the replay hook, since a runner has no window to type into; the
/// guest side is the same either way.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_synthetic_key_and_click_reach_a_guest_process() {
    use std::io::{BufRead, BufReader, Write};
    if skipped("a_synthetic_key_and_click_reach_a_guest_process") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-input");
    std::fs::write(dir.path().join("read.py"), include_str!("input_read.py"))
        .expect("stage the reader");
    let fifo = dir.path().join("events");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo")
            .success(),
        "a FIFO for the replay"
    );
    let mount = format!("/mnt={}", dir.path().display());
    let mut child = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--display", "320x240", "--mount", &mount])
        .env("BSX_INPUT_REPLAY", &fifo)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["--", "python3", "/mnt/read.py", "20"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run bsx");
    let stderr = child.stderr.take().expect("piped");
    let stderr = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut BufReader::new(stderr), &mut s);
        s
    });
    let mut stdout = BufReader::new(child.stdout.take().expect("piped"));
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if stdout.read_line(&mut line).expect("read the guest") == 0 {
            break;
        }
        let ready = line.starts_with("INPUT ready");
        lines.push(line);
        if ready {
            break;
        }
    }
    assert!(
        lines.last().is_some_and(|l| l.starts_with("INPUT ready")),
        "the guest never got to its devices: {lines:?}\nstderr: {}",
        stderr.join().unwrap_or_default()
    );
    // Only now is the guest listening. The FIFO's reader has been waiting in the helper since
    // it started, so this open completes the pair and the lines flow.
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open(&fifo)
        .expect("open the FIFO for writing");
    writer
        .write_all(
            b"kbd 1 30 1\nkbd 0 0 0\nkbd 1 30 0\nkbd 0 0 0\n\
              ptr 3 0 16384\nptr 3 1 8192\nptr 0 0 0\n\
              ptr 1 272 1\nptr 0 0 0\nptr 1 272 0\nptr 0 0 0\n",
        )
        .expect("write the events");
    drop(writer);
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut rest).expect("read the rest");
    let status = child.wait().expect("wait for bsx");
    let out = lines.concat() + &rest;
    let err = stderr.join().unwrap_or_default();
    assert!(status.success(), "stdout: {out}\nstderr: {err}");
    assert!(
        out.contains("bsx keyboard") && out.contains("bsx pointer"),
        "the guest names both devices: {out}"
    );
    let events: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("INPUT ") && l.split_whitespace().count() == 5)
        .map(|l| l.split_once(' ').map_or("", |(_, rest)| rest))
        .map(|l| l.split_once(' ').map_or("", |(_, rest)| rest))
        .collect();
    for expected in [
        "1 30 1",
        "1 30 0",
        "3 0 16384",
        "3 1 8192",
        "1 272 1",
        "1 272 0",
    ] {
        assert!(
            events.contains(&expected),
            "the guest read `{expected}`; it read {events:?}"
        );
    }
    let position = |needle: &str| events.iter().position(|e| *e == needle).expect("present");
    assert!(
        position("1 30 1") < position("1 30 0") && position("1 272 1") < position("1 272 0"),
        "presses before releases: {events:?}"
    );
}

/// The desktop image under `build-rootfs --desktop`, or `None` with the reason it cannot be used.
fn desktop_root() -> Result<PathBuf, String> {
    let root = guest_root().with_file_name("rootfs-desktop");
    if root.is_dir() {
        Ok(root)
    } else {
        Err(format!(
            "no desktop tree at {} (run `cargo xtask build-rootfs --desktop`)",
            root.display()
        ))
    }
}

/// The evdev code of a character on a US keyboard, for the few a test types.
fn scancode(ch: char) -> u16 {
    const ROW1: &str = "qwertyuiop";
    const ROW2: &str = "asdfghjkl";
    const ROW3: &str = "zxcvbnm";
    const DIGITS: &str = "1234567890";
    if let Some(i) = ROW1.find(ch) {
        return 16 + i as u16;
    }
    if let Some(i) = ROW2.find(ch) {
        return 30 + i as u16;
    }
    if let Some(i) = ROW3.find(ch) {
        return 44 + i as u16;
    }
    if let Some(i) = DIGITS.find(ch) {
        return 2 + i as u16;
    }
    match ch {
        ' ' => 57,
        '\n' => 28,
        '-' => 12,
        other => panic!("no scancode for {other:?}"),
    }
}

/// Replay lines that type `text` on the keyboard device: press, release, and a report each.
fn typed(text: &str) -> String {
    text.chars()
        .map(scancode)
        .map(|k| format!("kbd 1 {k} 1\nkbd 0 0 0\nkbd 1 {k} 0\nkbd 0 0 0\n"))
        .collect()
}

/// The desktop image boots to a Wayland session (cage) whose terminal (foot) runs a shell the
/// window's keyboard reaches (roadmap 4.5): a command typed through the replay hook writes a
/// sentinel to a mounted directory, and the `exit` that follows ends the terminal, the compositor
/// and the run. The root is read-only; the sentinel lands on the writable mount.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the desktop tree"]
fn the_desktop_image_boots_to_a_session_the_keyboard_reaches() {
    use std::io::{Read, Write};
    if skipped("the_desktop_image_boots_to_a_session_the_keyboard_reaches") {
        return;
    }
    let desktop = match desktop_root() {
        Ok(root) => root,
        Err(why) => {
            println!("SKIPPED the_desktop_image_boots_to_a_session_the_keyboard_reaches: {why}");
            return;
        }
    };
    let dir = bsx_test_support::ScratchDir::created("e2e-desktop");
    let fifo = dir.path().join("keys");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo")
            .success()
    );
    // The terminal runs a shell that reads one line and runs it: the session is the compositor,
    // and what a real user would type at foot's prompt is fed the same way. Reading one line keeps
    // the shell simple and ends it deterministically.
    let mount = format!("/mnt={}", dir.path().display());
    let mut child = bsx()
        .arg("run")
        .arg("--root")
        .arg(&desktop)
        .args(["--display", "640x480", "--mount", &mount])
        .env("BSX_INPUT_REPLAY", &fifo)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        // `timeout` bounds a session that never gets its keystrokes; the sentinel is the pass.
        .args([
            "--",
            "timeout",
            "60",
            "bsx-session",
            "foot",
            "sh",
            "-c",
            // No double-quote-space in the arg: libkrun's cmdline codec corrupts that,
            // and the sentinel word has no spaces, so it needs no quoting.
            // Signal readiness on the mount, then read one line and write it back: the wait on
            // the ready file replaces a fixed sleep, so the test types only once the shell is at
            // its read. No double-quote-space in the arg (libkrun's cmdline codec corrupts that),
            // and the words have no spaces, so they need no quoting.
            "echo ready > /mnt/ready; read word; printf %s $word > /mnt/typed",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run bsx");
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = String::new();
            let _ = pipe.read_to_string(&mut buf);
            buf
        })
    };
    let stdout = drain(Box::new(child.stdout.take().expect("piped")));
    let stderr = drain(Box::new(child.stderr.take().expect("piped")));

    // Wait for the shell to reach its read, signalled by the ready file it writes on the mount,
    // so the keys are typed into a shell that is listening rather than after a guessed delay.
    let ready = dir.path().join("ready");
    let up = std::time::Instant::now() + std::time::Duration::from_secs(40);
    while std::time::Instant::now() < up && !ready.exists() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(
        ready.exists(),
        "the session's terminal never reached its shell within 40 s\nstderr so far: (see below)"
    );
    // The FIFO handle stays open across the loop: the replay thread reads until EOF, so closing
    // it would end input after one batch. The shell reads one line and the rest buffer, so
    // retyping is safe, which is what lets the loop ride out the second or so cage needs to route
    // keyboard focus to foot's surface after the shell is already at its read.
    let sentinel = dir.path().join("typed");
    let mut keys = std::fs::OpenOptions::new()
        .write(true)
        .open(&fifo)
        .expect("open the FIFO for writing");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut landed = None;
    while std::time::Instant::now() < deadline {
        keys.write_all(typed("bsx-typed-this\n").as_bytes())
            .expect("type the command");
        keys.flush().expect("flush the keys");
        std::thread::sleep(std::time::Duration::from_secs(2));
        if let Ok(text) = std::fs::read_to_string(&sentinel) {
            landed = Some(text);
            break;
        }
    }
    drop(keys);
    let status = child.wait().expect("wait for bsx");
    let (out, err) = (
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default(),
    );
    assert_eq!(
        landed.as_deref(),
        Some("bsx-typed-this"),
        "the keys typed at the session's terminal never reached its shell\nstdout: {out}\nstderr: {err}"
    );
    assert!(
        status.success(),
        "the typed `exit`-equivalent (the read loop ending) tears the session down: {status}\n\
         stdout: {out}\nstderr: {err}"
    );
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
