//! End-to-end tests for a sandbox that outlives the command that started it, and for the verbs
//! that reach one: `bsx up`, `ls`, `exec`, `stop`.
//!
//! Every one of these is a **separate process** from the one that started the VM, which is the
//! property under test: there is no daemon and no handle, only a socket in the runtime directory.
//! `#[ignore]`d like the rest of the suites that boot a guest, and each **prints why** when it
//! skips, because cargo counts a skipped test as a pass.
//!
//! Each test is given its own `XDG_RUNTIME_DIR`, so a run neither lists nor stops the VMs the
//! person running it has open.

// A test binary: `expect` is the idiomatic assertion in helpers outside `#[test]`.
#![allow(clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bsx_test_support::ScratchDir;

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

/// A private runtime directory, `0700` because the supervisor refuses a control-socket directory
/// anyone else could read.
fn runtime(tag: &str) -> ScratchDir {
    let dir = ScratchDir::created(tag);
    std::fs::set_permissions(dir.path(), PermissionsExt::from_mode(0o700))
        .expect("a control-socket directory must be private");
    dir
}

/// The `bsx` cargo built for this run, pointed at `rt` rather than the operator's own VMs.
fn bsx(rt: &ScratchDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bsx"));
    cmd.env("XDG_RUNTIME_DIR", rt.path());
    cmd
}

/// A VM stopped on the way out however the test ends, so a failed assertion does not leave a
/// guest running on the machine that ran the suite.
struct Started<'a> {
    rt: &'a ScratchDir,
    name: String,
}

impl Started<'_> {
    fn pid(&self) -> Option<u32> {
        let out = bsx(self.rt).arg("ls").output().expect("run bsx ls");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find(|l| l.starts_with(&self.name))
            .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
    }
}

impl Drop for Started<'_> {
    fn drop(&mut self) {
        let _ = bsx(self.rt).args(["stop", &self.name]).output();
    }
}

/// Boots a long-lived sandbox and returns the guard that will stop it.
fn up<'a>(rt: &'a ScratchDir, name: &str) -> Started<'a> {
    let out = bsx(rt)
        .arg("up")
        .arg("--root")
        .arg(guest_root())
        .args(["--name", name])
        .output()
        .expect("run bsx up");
    assert!(
        out.status.success(),
        "bsx up failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        name,
        "the name is the verb's result"
    );
    Started {
        rt,
        name: name.to_string(),
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Whether a process is running and not a zombie, read from `/proc` rather than by signalling,
/// since these tests are not the VM's parent and have nothing to `wait` on.
fn pid_is_live(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|status| {
        !status
            .lines()
            .any(|l| l.starts_with("State:") && l.contains('Z'))
    })
}

/// The 3.9 contract: `bsx up` returns and the VM is still there. Every `bsx run` pays a cold boot
/// because libkrun has no snapshot surface, and this is the only way to stop paying it per
/// command: the process that started the VM is gone and the VM is not.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree (with the agent baked in)"]
fn a_sandbox_started_by_up_outlives_the_command_that_started_it() {
    if skipped("a_sandbox_started_by_up_outlives_the_command_that_started_it") {
        return;
    }
    let rt = runtime("lifecycle-up");
    let vm = up(&rt, "outlives");

    let pid = vm.pid().expect("the VM is listed with a pid");
    assert!(
        pid_is_live(pid),
        "the VM ended with the command that started it, which is the whole of 3.9"
    );
    // Its stderr is the log beside its sockets, not the caller's. Read directly off the process,
    // because this is the mechanism and not a side effect: with the caller's stderr inherited, a
    // detached VM holds that pipe open forever and `bsx up | anything` never returns (watched
    // happen, and it hung this suite).
    let log = rt.path().join("bsx/outlives.log");
    assert_eq!(
        std::fs::read_link(format!("/proc/{pid}/fd/2")).expect("the VM's stderr"),
        log,
        "the VM kept the caller's stderr"
    );
    assert!(
        log.is_file(),
        "the log the boot would report into is missing"
    );

    // The `up` process is gone: `output()` waited for it. So the VM has no parent holding it, and
    // it is still answering.
    let out = bsx(&rt)
        .args(["exec", "outlives", "--", "echo", "still-here"])
        .output()
        .expect("run bsx exec");
    assert_eq!(stdout_of(&out), "still-here");
}

/// The 3.8 contract: `ls`, `exec` and `stop` all reach a VM this process did not start. Each
/// `bsx` here is its own process, holding no handle to the VM, which is what the control socket
/// in the runtime directory exists for.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree (with the agent baked in)"]
fn the_lifecycle_verbs_reach_a_vm_this_process_did_not_start() {
    if skipped("the_lifecycle_verbs_reach_a_vm_this_process_did_not_start") {
        return;
    }
    let rt = runtime("lifecycle-verbs");
    let vm = up(&rt, "verbs");
    let pid = vm.pid().expect("the VM is listed with a pid");

    // `ls` names it and reports the posture the VM itself answers with, not one the lister
    // guessed: the row comes from the VM's own process.
    let listed = stdout_of(&bsx(&rt).arg("ls").output().expect("run bsx ls"));
    let row = listed
        .lines()
        .find(|l| l.starts_with("verbs"))
        .expect("the VM is listed");
    for cell in ["none", "read-only", "present"] {
        assert!(row.contains(cell), "{cell:?} missing from {row:?}");
    }

    // `exec` runs in it and hands back the guest's own exit code.
    let out = bsx(&rt)
        .args(["exec", "verbs", "--", "sh", "-c", "echo out; exit 9"])
        .output()
        .expect("run bsx exec");
    assert_eq!(stdout_of(&out), "out");
    assert_eq!(out.status.code(), Some(9), "the guest's code is the verb's");

    // Sessions compose: the agent serves every connection from one working directory, so a second
    // exec sees what the first left. This is what makes a long-lived VM worth having.
    assert!(
        bsx(&rt)
            .args(["exec", "verbs", "--", "sh", "-c", "echo kept > state"])
            .status()
            .expect("run bsx exec")
            .success()
    );
    let out = bsx(&rt)
        .args(["exec", "verbs", "--", "cat", "state"])
        .output()
        .expect("run bsx exec");
    assert_eq!(stdout_of(&out), "kept");

    // `stop` ends it, and the VM is gone rather than merely unlisted.
    let out = bsx(&rt)
        .args(["stop", "verbs"])
        .output()
        .expect("run bsx stop");
    assert!(
        out.status.success(),
        "bsx stop failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!pid_is_live(pid), "the stopped VM's process is still there");
    let listed = stdout_of(&bsx(&rt).arg("ls").output().expect("run bsx ls"));
    assert!(!listed.contains("verbs"), "a stopped VM is still listed");
    // Its sockets went with it: a channel left behind is one `exec` would connect to and wait on
    // forever.
    for leftover in ["verbs.sock", "verbs.agent"] {
        assert!(
            !rt.path().join("bsx").join(leftover).exists(),
            "{leftover} outlived the VM"
        );
    }
}

/// A VM booted straight into a workload has nothing to ask, and says so. Named because the
/// alternative is `exec` connecting to a socket that does not exist and reporting the path.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree"]
fn exec_names_a_vm_with_no_agent_channel_rather_than_dialling_nothing() {
    if skipped("exec_names_a_vm_with_no_agent_channel_rather_than_dialling_nothing") {
        return;
    }
    let rt = runtime("lifecycle-nochannel");
    let mut plain = bsx(&rt)
        .arg("run")
        .arg("--root")
        .arg(guest_root())
        .args(["--name", "plain", "--", "sleep", "10"])
        .spawn()
        .expect("run bsx run");
    // The VM is up once it is listed; polling beats a fixed sleep under a loaded gate.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !stdout_of(&bsx(&rt).arg("ls").output().expect("run bsx ls")).contains("plain") {
        assert!(
            std::time::Instant::now() < deadline,
            "the VM never appeared"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    let out = bsx(&rt)
        .args(["exec", "plain", "--", "true"])
        .output()
        .expect("run bsx exec");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no agent channel"), "{err}");
    assert!(err.contains("bsx up"), "names what starts one: {err}");
    let _ = plain.kill();
    let _ = plain.wait();
}

/// A name nothing is running under is a refusal naming the verb that would have listed it, not a
/// connection error about a socket path the caller never typed.
#[test]
#[ignore = "spawns the built bsx (no VM boots: the refusal is the test)"]
fn the_verbs_refuse_a_name_nothing_is_running_under() {
    let rt = runtime("lifecycle-absent");
    for verb in ["exec", "stop"] {
        let mut cmd = bsx(&rt);
        cmd.args([verb, "no-such-vm"]);
        if verb == "exec" {
            cmd.args(["--", "true"]);
        }
        let out = cmd.output().expect("run bsx");
        assert_eq!(out.status.code(), Some(2), "{verb}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("no VM named"), "{verb}: {err}");
        assert!(err.contains("bsx ls"), "{verb} names the lister: {err}");
    }
}

/// Two VMs cannot hold one name: the second is refused before it boots, rather than racing the
/// first for its control socket.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm and the guest tree (with the agent baked in)"]
fn a_name_already_running_is_refused_before_a_second_vm_boots() {
    if skipped("a_name_already_running_is_refused_before_a_second_vm_boots") {
        return;
    }
    let rt = runtime("lifecycle-name");
    let _vm = up(&rt, "taken");

    let out = bsx(&rt)
        .arg("up")
        .arg("--root")
        .arg(guest_root())
        .args(["--name", "taken"])
        .output()
        .expect("run bsx up");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("already running"), "{err}");
    let listed = stdout_of(&bsx(&rt).arg("ls").output().expect("run bsx ls"));
    assert_eq!(
        listed.lines().filter(|l| l.starts_with("taken")).count(),
        1,
        "the refused second VM must not be running too"
    );
}
