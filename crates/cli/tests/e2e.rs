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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bsx"));
    // The records these tests write go under the temp dir, not the operator's notebook.
    cmd.env("BSX_RUNS_DIR", runs_dir());
    cmd
}

/// A runs directory for this test process alone.
fn runs_dir() -> PathBuf {
    std::env::temp_dir().join(format!("bsx-e2e-runs-{}", std::process::id()))
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

/// The shell verb without a terminal: the command still runs on a guest pty at 80x24, its output
/// crosses the channel, and its exit code is the verb's. Pins the whole boot-agent-vsock path.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree (with the agent baked in)"]
fn shell_runs_the_command_on_a_guest_pty_and_returns_its_exit() {
    if skipped("shell_runs_the_command_on_a_guest_pty_and_returns_its_exit") {
        return;
    }
    // A session's scratch lives on a guest tmpfs, so a run must add nothing to the image /tmp.
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

/// The 3.6 contract: by default the guest cannot reach the host's network. libkrun's implicit
/// vsock proxies guest sockets onto the host, which `--net none` replaces. A host server on
/// 127.0.0.1 stands in for the host's network, which an isolated guest's own loopback lacks.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn the_default_guest_cannot_reach_the_host_network() {
    if skipped("the_default_guest_cannot_reach_the_host_network") {
        return;
    }
    let server = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a host-only server");
    let port = server.local_addr().expect("addr").port();
    // `wget` fails on a connect carrying no response, so the server answers. The request is read
    // before the reply is written, or an RST discards it.
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

/// The 3.5 contract: the configured limits are the machine the guest gets. Its own `nproc` and
/// `MemTotal` answer the ask within a kernel-overhead band, not the default and not the host.
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

/// The 3.3 contract under a read-only root: a host directory is read-write at the guest path and
/// edits land on the host, with the image tree untouched. `/mnt` because the image has it.
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

/// The 0.8 contract: a host directory reaches the guest under a **second virtiofs tag**, which
/// `--share` hands over as a device the guest mounts itself. Both tags in one boot, since two
/// sharing one would leave the kernel matching whichever it saw first.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_second_virtiofs_tag_carries_a_directory_the_guest_mounts_itself() {
    if skipped("a_second_virtiofs_tag_carries_a_directory_the_guest_mounts_itself") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-share");
    let mounted = dir.path().join("mounted");
    let shared = dir.path().join("shared");
    std::fs::create_dir(&mounted).expect("a directory for the helper's tag");
    std::fs::create_dir(&shared).expect("a directory for the caller's tag");
    std::fs::write(mounted.join("f"), "in-mount\n").expect("stage the mount's file");
    std::fs::write(shared.join("f"), "in-share\n").expect("stage the share's file");

    let image_top = || -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(guest_root())
            .expect("the image tree")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort();
        names
    };
    let before = image_top();
    // `/opt` because the image has it and nothing else uses it: under the default read-only root
    // the guest cannot create a mount point, which is the same constraint `--mount` has.
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--mount", &format!("/mnt={}", mounted.display())])
        .args(["--share", &format!("work={}", shared.display())])
        .args([
            "--",
            "sh",
            "-c",
            "mount -t virtiofs work /opt && cat /mnt/f /opt/f &&              echo from-the-mount > /mnt/g && echo from-the-share > /opt/g",
        ])
        .output()
        .expect("run bsx");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "in-mount\nin-share\n",
        "each tag carried its own host directory into the guest"
    );
    assert_eq!(
        std::fs::read_to_string(shared.join("g")).expect("the guest's write reached the host"),
        "from-the-share\n",
        "a file written under the caller's tag is on the host"
    );
    assert_eq!(
        std::fs::read_to_string(mounted.join("g")).expect("the mount still carries writes"),
        "from-the-mount\n",
        "the helper's own tag is unaffected by the caller's"
    );
    assert!(
        !shared.join("f").metadata().expect("still there").is_dir(),
        "the staged file is still a file"
    );
    assert_eq!(
        image_top(),
        before,
        "mounting over an image directory does not write the shared image tree"
    );
}

/// The 3.7 contract: the image tree is shared by every sandbox, so by default a guest cannot
/// write it. Asserted by writing, since `/proc/mounts` reports the root `rw` either way.
///
/// Both directions, or "the write failed" would also hold for a guest that cannot run `echo`.
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

/// Design rule 3's other half: the posture is visible *before* the VM starts. `--dry-run` boots
/// nothing, asserted through the control socket every boot leaves. The same command runs for
/// real after, so a socket that stopped appearing could not leave this vacuous.
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

/// A `--share` cannot take a tag `--mount` uses: the guest mounts by tag, so a duplicate leaves
/// the kernel matching whichever device it saw first. Refused before boot, since nothing
/// downstream can tell.
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

/// Roadmap 0.9 and 4.2's frame path: a guest drawing through a DRM dumb buffer puts a known
/// pattern on its scanout and the pixels arrive on the host. Headless, so a runner with no
/// display server reads the frame too; the window is the same path with a surface on the end.
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

/// Roadmap 0.11, the guest half: a `--display` guest is offered `virtio_gpu` with a render node
/// and 3D capsets, none of it reachable without a Mesa driver. The offer and the absence are
/// pinned together, because they move independently.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_display_guest_is_offered_a_3d_virtio_gpu_it_has_no_driver_for() {
    if skipped("a_display_guest_is_offered_a_3d_virtio_gpu_it_has_no_driver_for") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-gpu");
    std::fs::write(dir.path().join("probe.py"), include_str!("gpu_probe.py"))
        .expect("stage the probe");
    let mount = format!("/mnt={}", dir.path().display());
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--display", "320x240", "--mount", &mount])
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["--", "python3", "/mnt/probe.py"])
        .output()
        .expect("run bsx");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    let report = String::from_utf8_lossy(&out.stdout);
    let says = |line: &str| {
        assert!(
            report.lines().any(|l| l == line),
            "expected {line:?} in:\n{report}"
        );
    };
    says("PROBE render_node yes");
    says("PROBE card0_driver virtio_gpu 0.1.0 (virtio GPU)");
    says("PROBE card0_param_3D_FEATURES 1");
    says("PROBE card0_param_CONTEXT_INIT 1");
    // Answered by the host renderer, not decoded from the SUPPORTED_CAPSET_IDs bitmask.
    let capsets = report
        .lines()
        .find_map(|l| l.strip_prefix("PROBE card0_capsets_answered "))
        .unwrap_or_else(|| panic!("no capset line in:\n{report}"));
    for want in ["VIRGL(1)", "VIRGL2(2)", "VENUS(4)"] {
        assert!(capsets.contains(want), "{want} missing from {capsets:?}");
    }
    // The other half of the answer: nothing in guest userspace can use any of it.
    says("PROBE mesa_dri (absent)");
    says("PROBE libgl (absent)");
    says("PROBE libvulkan (absent)");
}

/// A key and a click arrive in the guest as the evdev events a process there reads, under the
/// names the devices were given (roadmap 0.10). Through the replay hook, a runner having no
/// window to type into.
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

/// The desktop image boots to a Wayland session whose terminal runs a shell the window's keyboard
/// reaches (roadmap 4.5): a typed command writes a sentinel to the writable mount, and the `exit`
/// after it ends the terminal, the compositor and the run.
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
    // A shell reading one line and running it: what a user would type at foot's prompt, fed the
    // same way, and deterministic.
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
            // Readiness on the mount replaces a fixed sleep, so the test types only once the
            // shell is at its read. No double-quote-space: the cmdline codec corrupts it.
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
    // The FIFO stays open across the loop, since the replay thread reads to EOF. Retyping is
    // safe, which rides out the second cage needs to route focus to foot.
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

/// `--sound` gives the guest a virtio-snd card and nothing else does (roadmap 4.7), the card
/// being present exactly when the flag is. Two-way (`playback 1 : capture 1`), which is why it is
/// opt-in. Read from `/proc/asound`, so a runner with no sound server still decides it.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn sound_gives_the_guest_a_card_and_nothing_else_does() {
    if skipped("sound_gives_the_guest_a_card_and_nothing_else_does") {
        return;
    }
    let cards = |flags: &[&str]| -> String {
        let out = bsx()
            .arg("run")
            .arg("--root")
            .arg(guest_root())
            .args(flags)
            .args(["--", "sh", "-c", "cat /proc/asound/cards"])
            .output()
            .expect("run bsx");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let without = cards(&[]);
    assert!(
        without.contains("no soundcards"),
        "a guest with no --sound has no card: {without:?}"
    );
    let with = cards(&["--sound"]);
    assert!(
        with.to_lowercase().contains("virtio"),
        "a guest with --sound has a virtio-snd card: {with:?}"
    );
}

/// `--frame-log` records each frame the display thread saw as it landed (roadmap 4.8): a guest
/// that flushes five times leaves five ascending ids with non-decreasing times, because delivery
/// is woken per present rather than polled and the flushes are half a second apart.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_frame_log_records_each_frame_the_guest_flushed() {
    if skipped("a_frame_log_records_each_frame_the_guest_flushed") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-frame-log");
    std::fs::write(dir.path().join("draw.py"), include_str!("drm_draw.py"))
        .expect("stage the drawer");
    let log = dir.path().join("frames.tsv");
    let mount = format!("/mnt={}", dir.path().display());
    let out = bsx()
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--display", "320x240@60", "--mount", &mount])
        .arg("--frame-log")
        .arg(&log)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["--", "python3", "/mnt/draw.py", "4"])
        .output()
        .expect("run bsx");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&log).expect("the frame log was written");
    let rows: Vec<(u64, u64)> = text
        .lines()
        .map(|l| {
            let (id, ns) = l.split_once('\t').expect("id, tab, ns");
            (id.parse().expect("id"), ns.parse().expect("ns"))
        })
        .collect();
    // The mode set paints once and each of the four DIRTYFB flushes once more.
    assert!(
        rows.len() >= 5,
        "five flushes half a second apart are five frames seen: {text:?}"
    );
    assert!(
        rows.windows(2).all(|w| w[1].0 > w[0].0 && w[1].1 >= w[0].1),
        "ids ascend and time does not run backwards: {text:?}"
    );
}

/// A second process sees the frames a guest draws without a copy (roadmap 4.9): it leases the
/// display, maps the memfd the answer carries, and reads the pattern out of the slot it is told.
/// Its frame log names the helper's own frame ids, on the same clock.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_second_process_maps_the_frames_the_guest_draws() {
    if skipped("a_second_process_maps_the_frames_the_guest_draws") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-boundary");
    let rt = dir.path().join("rt");
    std::fs::create_dir(&rt).expect("a runtime dir");
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).expect("private");
    let mount_dir = dir.path().join("m");
    std::fs::create_dir(&mount_dir).expect("a mount dir");
    std::fs::write(mount_dir.join("draw.py"), include_str!("drm_draw.py")).expect("stage");
    let helper_log = dir.path().join("helper.tsv");
    let client_log = dir.path().join("client.tsv");
    let shot = dir.path().join("shot.ppm");
    let mount = format!("/mnt={}", mount_dir.display());

    let up = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["up", "--root"])
        .arg(guest_root())
        .args([
            "--name",
            "boundary",
            "--display",
            "320x240",
            "--mount",
            &mount,
        ])
        .arg("--frame-log")
        .arg(&helper_log)
        .output()
        .expect("run bsx up");
    assert!(
        up.status.success(),
        "up: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    // Stopped however this ends, so a failed assertion leaves no guest behind.
    struct Stop(PathBuf);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = bsx()
                .env("XDG_RUNTIME_DIR", &self.0)
                .args(["stop", "boundary"])
                .output();
        }
    }
    let _stop = Stop(rt.clone());

    // The reader first, so it holds the lease while the guest draws, and reads until the stop
    // below: a late lease misses the first frames, so no count is safe.
    let reader = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .args(["__frames", "boundary"])
        .arg("--log")
        .arg(&client_log)
        .arg("--screenshot")
        .arg(&shot)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run the reader");
    let drew = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .args(["exec", "boundary", "--", "python3", "/mnt/draw.py", "4"])
        .output()
        .expect("run bsx exec");
    assert!(
        String::from_utf8_lossy(&drew.stdout).contains("DRAW setcrtc ok"),
        "the guest drew: {}",
        String::from_utf8_lossy(&drew.stderr)
    );
    let stopped = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .args(["stop", "boundary"])
        .output()
        .expect("run bsx stop");
    assert!(
        stopped.status.success(),
        "stop: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    let status = reader.wait_with_output().expect("wait for the reader");
    assert!(
        status.status.success(),
        "the reader ends when the lease does: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    // The pixels crossed: the pattern draw.py paints, read out of the mapped slot.
    let ppm = std::fs::read(&shot).expect("the reader's screenshot");
    let mut parts = ppm.splitn(4, |&b| b == b'\n');
    assert_eq!(parts.next(), Some(&b"P6"[..]));
    assert_eq!(parts.next(), Some(&b"320 240"[..]));
    parts.next();
    let px = parts.next().expect("pixels");
    let at = |x: usize, y: usize| &px[(y * 320 + x) * 3..(y * 320 + x) * 3 + 3];
    assert_eq!(at(2, 2), [255, 0, 0], "top-left is red");
    assert_eq!(at(317, 237), [255, 255, 255], "bottom-right is white");
    assert_eq!(at(160, 120), [0x40, 0x40, 0x40], "the middle is grey");

    // The same frames on the same clock, within the wake's latency either way: the record is
    // written under the lock before the helper's own thread wakes.
    let rows = |path: &Path| -> Vec<(u64, u128)> {
        std::fs::read_to_string(path)
            .expect("a log")
            .lines()
            .map(|l| {
                let (id, ns) = l.split_once('\t').expect("id, tab, ns");
                (id.parse().expect("id"), ns.parse().expect("ns"))
            })
            .collect()
    };
    let helper = rows(&helper_log);
    let client = rows(&client_log);
    assert!(
        client.len() >= 3,
        "the flushes after the lease, at least three of four: {client:?}"
    );
    for (id, seen_by_client) in &client {
        let (_, seen_by_helper) = helper
            .iter()
            .find(|(h, _)| h == id)
            .unwrap_or_else(|| panic!("frame {id} is in the helper's log too: {helper:?}"));
        let apart = seen_by_client.abs_diff(*seen_by_helper);
        assert!(
            apart < 20_000_000,
            "frame {id}: the two processes saw it {apart} ns apart, more than a wake should cost"
        );
    }
}

/// The crash class found while building 3.3: a byte outside printable ASCII in the workload's
/// argv aborted the whole VMM inside libkrun (SIGABRT, exit 134). It must be a typed refusal.
#[test]
#[ignore = "spawns the built bsx (no VM boots: the refusal is the test)"]
fn a_non_ascii_argument_is_refused_not_aborted_on() {
    let out = bsx()
        // `/tmp` is no image, so the results mount point it lacks would be refused first.
        .args([
            "run",
            "--root",
            "/tmp",
            "--no-results",
            "--",
            "echo",
            "\u{e9}",
        ])
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

/// A key and a click sent down an `input` session on the control socket arrive in the guest as
/// the evdev events a process there reads (roadmap 4.11), and a session that ends with a button
/// down is followed by its release, so a client that dies mid-drag leaves nothing held.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_key_and_click_over_the_control_socket_reach_a_guest_process() {
    use std::io::{BufRead, BufReader};
    if skipped("a_key_and_click_over_the_control_socket_reach_a_guest_process") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-wire-input");
    let rt = dir.path().join("rt");
    std::fs::create_dir(&rt).expect("a runtime dir");
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).expect("private");
    let mount_dir = dir.path().join("m");
    std::fs::create_dir(&mount_dir).expect("a mount dir");
    std::fs::write(mount_dir.join("read.py"), include_str!("input_read.py")).expect("stage");
    let mount = format!("/mnt={}", mount_dir.display());
    let up = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["up", "--root"])
        .arg(guest_root())
        .args(["--name", "wired", "--display", "320x240", "--mount", &mount])
        .output()
        .expect("run bsx up");
    assert!(
        up.status.success(),
        "up: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    struct Stop(PathBuf);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = bsx()
                .env("XDG_RUNTIME_DIR", &self.0)
                .args(["stop", "wired"])
                .output();
        }
    }
    let _stop = Stop(rt.clone());

    let mut reader = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .args(["exec", "wired", "--", "python3", "/mnt/read.py", "20"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run the reader through exec");
    let mut stdout = BufReader::new(reader.stdout.take().expect("piped"));
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
        "the guest never got to its devices: {lines:?}"
    );
    // Only now is the guest listening. The button left down is what the helper must release
    // when the session goes.
    let socket = bsx_supervisor::socket::path_in(&rt, "wired").expect("a socket path");
    let mut session = bsx_supervisor::control::input(&socket).expect("an input session");
    for line in [
        "kbd 1 30 1",
        "kbd 0 0 0",
        "kbd 1 30 0",
        "kbd 0 0 0",
        "ptr 3 0 16384",
        "ptr 3 1 8192",
        "ptr 0 0 0",
        "ptr 1 272 1",
        "ptr 0 0 0",
    ] {
        session.send(line).expect("send a line");
    }
    drop(session);
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut rest).expect("read the rest");
    let status = reader.wait().expect("wait for exec");
    let out = lines.concat() + &rest;
    assert!(status.success(), "the reader: {out}");
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
        position("1 272 1") < position("1 272 0"),
        "the release the session's end sent comes after the press: {events:?}"
    );
}

/// A `run` leaves a record (roadmap 4.12): the posture as settled, the command's stdout and
/// stderr as the caller also got them, the exit as the run's end, and what the guest wrote to
/// `/results` in the record's own directory; `bsx show` reads it back and `bsx rm` removes it.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_run_leaves_its_record_output_and_results() {
    if skipped("a_run_leaves_its_record_output_and_results") {
        return;
    }
    let runs = runs_dir().join("run-record");
    let out = bsx()
        .env("BSX_RUNS_DIR", &runs)
        .args(["run", "--root"])
        .arg(guest_root())
        .args(["--name", "recorded", "--"])
        .args([
            "sh",
            "-c",
            "echo out; echo err >&2; echo data > /results/file.txt; exit 3",
        ])
        .output()
        .expect("run bsx");
    assert_eq!(
        out.status.code(),
        Some(3),
        "the guest's code passes through"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "out\n",
        "stdout still reaches the caller"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("err"),
        "stderr too"
    );

    let store = bsx_record::Store::at(runs.clone()).expect("the store");
    let record = store
        .find("recorded")
        .expect("read")
        .expect("a record for the run");
    assert_eq!(record.verb, bsx_record::Verb::Run);
    assert_eq!(record.end, Some(bsx_record::End::Exit(3)));
    assert!(record.posture.results, "results on by default");
    assert_eq!(record.posture.network, "none");
    assert!(record.ended_ms >= Some(record.started_ms));
    let dir = store.dir_of(&record.id);
    assert_eq!(
        std::fs::read_to_string(dir.stdout()).expect("stdout kept"),
        "out\n"
    );
    assert!(
        std::fs::read_to_string(dir.stderr())
            .expect("stderr kept")
            .contains("err")
    );
    assert_eq!(
        std::fs::read_to_string(dir.results().join("file.txt")).expect("the guest wrote it"),
        "data\n"
    );
    let shown = bsx()
        .env("BSX_RUNS_DIR", &runs)
        .args(["show", &record.id])
        .output()
        .expect("run bsx show");
    let text = String::from_utf8_lossy(&shown.stdout);
    assert!(
        text.contains("end exit 3") && text.contains("result file.txt 5 bytes"),
        "{text}"
    );
    let removed = bsx()
        .env("BSX_RUNS_DIR", &runs)
        .args(["rm", "recorded"])
        .output()
        .expect("run bsx rm");
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(
        store.find("recorded").expect("read").is_none(),
        "gone from the notebook"
    );
}

/// An `up` sandbox's record is open while it runs, each `exec` appends what it printed under
/// its command, `ls --all` lists it, and `stop` writes the end.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn an_up_sandbox_records_its_execs_and_its_stop() {
    if skipped("an_up_sandbox_records_its_execs_and_its_stop") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-up-record");
    let rt = dir.path().join("rt");
    std::fs::create_dir(&rt).expect("a runtime dir");
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).expect("private");
    let runs = dir.path().join("runs");
    let up = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env("BSX_RUNS_DIR", &runs)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["up", "--root"])
        .arg(guest_root())
        .args(["--name", "kept"])
        .output()
        .expect("run bsx up");
    assert!(
        up.status.success(),
        "up: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    struct Stop(PathBuf);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = bsx()
                .env("XDG_RUNTIME_DIR", &self.0)
                .args(["stop", "kept"])
                .output();
        }
    }
    let _stop = Stop(rt.clone());
    let store = bsx_record::Store::at(runs.clone()).expect("the store");
    let open = store
        .open_run("kept")
        .expect("read")
        .expect("an open record");
    assert!(open.pid.is_some(), "the VM's pid is recorded");

    let ran = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env("BSX_RUNS_DIR", &runs)
        .args([
            "exec",
            "kept",
            "--",
            "sh",
            "-c",
            "echo hello-from-exec; echo to-err >&2",
        ])
        .output()
        .expect("run bsx exec");
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let log = std::fs::read_to_string(store.dir_of(&open.id).exec_log()).expect("exec.log");
    assert!(
        log.contains("echo hello-from-exec")
            && log.contains("hello-from-exec\n")
            && log.contains("to-err"),
        "{log}"
    );

    let listed = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env("BSX_RUNS_DIR", &runs)
        .args(["ls", "--all"])
        .output()
        .expect("run bsx ls");
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.lines().any(|l| l.starts_with("kept ")), "live: {text}");
    assert!(
        store.open_run("kept").expect("read").is_some(),
        "listing does not end a run whose VM answers"
    );

    let stopped = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env("BSX_RUNS_DIR", &runs)
        .args(["stop", "kept"])
        .output()
        .expect("run bsx stop");
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    let ended = store.find("kept").expect("read").expect("still there");
    assert_eq!(ended.end, Some(bsx_record::End::Stopped));
    let listed = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env("BSX_RUNS_DIR", &runs)
        .args(["ls", "--all"])
        .output()
        .expect("run bsx ls");
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("stopped") && text.contains(&ended.id),
        "past: {text}"
    );
}

/// A guest that sets a new mode (roadmap 4.4) is followed on the host: the old lease ends with a
/// reconfigure record and the next is at the new size. The driver keeps every mode the EDID
/// lists; only the preferred one is pinned to `--display`.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn a_guest_that_sets_a_new_mode_is_followed_by_the_next_lease() {
    if skipped("a_guest_that_sets_a_new_mode_is_followed_by_the_next_lease") {
        return;
    }
    let dir = bsx_test_support::ScratchDir::created("e2e-mode");
    let rt = dir.path().join("rt");
    std::fs::create_dir(&rt).expect("a runtime dir");
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).expect("private");
    let mount_dir = dir.path().join("m");
    std::fs::create_dir(&mount_dir).expect("a mount dir");
    std::fs::write(mount_dir.join("mode.py"), include_str!("drm_mode.py")).expect("stage");
    let shot = dir.path().join("shot.ppm");
    let mount = format!("/mnt={}", mount_dir.display());
    let up = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .args(["up", "--root"])
        .arg(guest_root())
        .args(["--name", "moded", "--display", "640x480", "--mount", &mount])
        .output()
        .expect("run bsx up");
    assert!(
        up.status.success(),
        "up: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    struct Stop(PathBuf);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = bsx()
                .env("XDG_RUNTIME_DIR", &self.0)
                .args(["stop", "moded"])
                .output();
        }
    }
    let _stop = Stop(rt.clone());
    // The reader holds a lease across the switch and re-leases after it; the screenshot is the
    // last frame of the last lease.
    let reader = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .args(["__frames", "moded"])
        .arg("--screenshot")
        .arg(&shot)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run the reader");
    // Mode 0 is the preferred 640x480; mode 8 is the EDID's 800x500, the smallest other one.
    let switched = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .args([
            "exec",
            "moded",
            "--",
            "python3",
            "/mnt/mode.py",
            "0",
            "2",
            "8",
            "3",
        ])
        .output()
        .expect("run the mode setter");
    let out = String::from_utf8_lossy(&switched.stdout);
    assert!(
        out.contains("SETCRTC ok 640x480") && out.contains("SETCRTC ok 800x500"),
        "the guest set both modes: {out}\n{}",
        String::from_utf8_lossy(&switched.stderr)
    );
    let stopped = bsx()
        .env("XDG_RUNTIME_DIR", &rt)
        .args(["stop", "moded"])
        .output()
        .expect("run bsx stop");
    assert!(stopped.status.success());
    let read = reader.wait_with_output().expect("wait for the reader");
    let err = String::from_utf8_lossy(&read.stderr);
    assert!(read.status.success(), "the reader: {err}");
    assert!(
        err.contains("leasing again"),
        "the first lease ended on the switch: {err}"
    );
    let ppm = std::fs::read(&shot).expect("the screenshot");
    let mut parts = ppm.splitn(4, |&b| b == b'\n');
    assert_eq!(parts.next(), Some(&b"P6"[..]));
    assert_eq!(
        parts.next(),
        Some(&b"800 500"[..]),
        "the last lease is at the new size"
    );
    let _ = parts.next();
    let pixels = parts.next().expect("pixels");
    assert_eq!(
        &pixels[..3],
        &[255, 0, 0],
        "the guest's red block at the top-left, as drawn"
    );
    assert_eq!(
        &pixels[400 * 3..400 * 3 + 3],
        &[0x40, 0x40, 0x40],
        "the grey elsewhere"
    );
}
