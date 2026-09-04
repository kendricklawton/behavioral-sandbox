//! Leak tests: kill a supervisor mid-boot and assert nothing of the VM survives it.
//!
//! The successor to the old suite's `driver_death_cannot_leak_a_vm`, and the one test from it worth
//! rebuilding. **A leak here is a stranded VM holding somebody's laptop RAM**, not a server anyone
//! can reboot, which is why design rule 5 names it and why this exists before the supervisor grows
//! any more surface.
//!
//! These spawn real guests, so they need `/dev/kvm`, the guest tree and a built `bsx`. Each
//! **skips with a printed reason** when a prerequisite is missing rather than passing quietly:
//! cargo counts a skipped test as a pass, and a green suite that measured nothing is the failure
//! this file exists to prevent.
//!
//! Run them with `cargo test -p bsx-supervisor --test leak -- --ignored --test-threads=1`. Serial,
//! because they count processes and sockets belonging to a private runtime directory and a sibling
//! doing the same would see each other's.

// A test binary: `expect` is the idiomatic assertion in a helper outside `#[test]`, which the
// workspace's `clippy::expect_used` deny does not auto-exempt.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A guest that stays up long enough to be killed in the middle of its life.
const LONG_LIVED: &str = "sleep 30";

/// How long a boot is given before a test decides the VM never came up. Cold boot on the
/// development laptop is ~300 ms end to end (`scratch/ROADMAP.md` phase 0), so this is an order of
/// magnitude of headroom rather than a tuned value.
const BOOT_GRACE: Duration = Duration::from_secs(5);

/// Why this host cannot run these, or `None` when it can. The KVM check opens the device, since
/// for a user outside the `kvm` group it exists and every boot still dies.
fn skip_reason() -> Option<String> {
    if let Some(why) = bsx_test_support::hypervisor_unusable() {
        return Some(why);
    }
    if !guest_root().is_dir() {
        return Some(format!(
            "no guest tree at {} (run `cargo xtask build-rootfs`)",
            guest_root().display()
        ));
    }
    if !bsx_binary().is_file() {
        return Some(format!(
            "no bsx binary at {} (run `cargo build -p bsx`)",
            bsx_binary().display()
        ));
    }
    None
}

/// Prints why a test did nothing and returns whether it should stop. A skip that says nothing is
/// indistinguishable from a pass.
fn skipped(test: &str) -> bool {
    match skip_reason() {
        Some(why) => {
            println!("SKIPPED {test}: {why}");
            true
        }
        None => false,
    }
}

/// The workspace root, from this crate's manifest dir: `crates/supervisor` is two levels down, and
/// `CARGO_MANIFEST_DIR` is where this test was compiled rather than wherever it is run from.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

fn guest_root() -> PathBuf {
    // The spike tree is what exists on a development box today; `build-rootfs` writes the other.
    let built = workspace_root().join("artifacts/rootfs-guest");
    if built.is_dir() {
        return built;
    }
    workspace_root().join("scratch/rootfs")
}

fn bsx_binary() -> PathBuf {
    workspace_root().join("target/debug/bsx")
}

/// Spawns a helper directly, with its runtime directory at `runtime`. Not through `Vm::spawn`,
/// which re-executes `current_exe()` and would be the test binary.
fn spawn_guest(name: &str, runtime: &Path) -> std::process::Child {
    Command::new(bsx_binary())
        .args(["__vmm", "--name", name])
        .arg("--root")
        .arg(guest_root())
        .args(["--exec", "/bin/sh", "--arg", "-c", "--arg", LONG_LIVED])
        .env("XDG_RUNTIME_DIR", runtime)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the VM helper")
}

/// Whether `pid` has a **vCPU thread**, the difference between a helper that started and a VM
/// that is running: the socket is bound long before libkrun is up. Matches the `fc_vcpu 0` name,
/// since a thread count drifts with a release.
fn vm_is_running(pid: u32) -> bool {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    tasks.filter_map(Result::ok).any(|t| {
        std::fs::read_to_string(t.path().join("comm"))
            .is_ok_and(|c| c.trim().starts_with("fc_vcpu"))
    })
}

/// Whether `pid` is a live, non-zombie process.
fn pid_is_live(pid: u32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    !status
        .lines()
        .any(|l| l.starts_with("State:") && l.contains('Z'))
}

/// Waits until `cond` holds or the grace period runs out, so a test never hard-codes a sleep long
/// enough to be slow *and* short enough to be flaky.
fn eventually(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + BOOT_GRACE;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    cond()
}

/// A private runtime directory, so a test counts only its own VMs.
fn runtime_dir(tag: &str) -> bsx_test_support::ScratchDir {
    let dir = bsx_test_support::ScratchDir::created(tag);
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("tighten the runtime dir");
    dir
}

/// **The test this file exists for.** A supervisor that dies mid-boot must not leave the VM it was
/// starting behind: kills the helper while the guest is still coming up.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm, the guest tree and a built bsx"]
fn a_supervisor_killed_mid_boot_leaves_no_vm() {
    if skipped("a_supervisor_killed_mid_boot_leaves_no_vm") {
        return;
    }
    let runtime = runtime_dir("leak-midboot");
    let sock = runtime.path().join("bsx/midboot.sock");

    let mut child = spawn_guest("midboot", runtime.path());
    let pid = child.id();
    // Mid-boot on purpose: a vCPU running, but before the workload, is where a VM strands.
    assert!(
        eventually(|| vm_is_running(pid)),
        "the VM never started a vCPU"
    );
    assert!(pid_is_live(pid), "the helper should still be running");
    // The positive first, against the directory the helpers were pointed at: a scan that never
    // sees the running VM makes the absence below vacuous.
    let scan_dir = runtime.path().join("bsx");
    assert!(
        bsx_supervisor::discover::live_in(&scan_dir)
            .expect("scan the private runtime directory")
            .iter()
            .any(|f| f.name == "midboot"),
        "a running VM must be discoverable, or its absence after the kill proves nothing"
    );

    child.kill().expect("kill the helper mid-boot");
    child.wait().expect("reap it");

    assert!(
        eventually(|| !pid_is_live(pid)),
        "the helper process survived being killed mid-boot"
    );
    assert!(
        !bsx_supervisor::socket::is_live(&sock),
        "a control socket is still answering for a VM whose helper is dead"
    );
    assert!(
        bsx_supervisor::discover::live_in(&scan_dir)
            .expect("scan the private runtime directory")
            .iter()
            .all(|f| f.name != "midboot"),
        "a killed VM is still being discovered"
    );
}

/// Dropping a [`bsx_supervisor::Vm`] must take the VM with it, including when the guest is a live
/// process rather than something that was about to exit anyway.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm, the guest tree and a built bsx"]
fn dropping_the_supervisor_takes_the_running_vm_with_it() {
    if skipped("dropping_the_supervisor_takes_the_running_vm_with_it") {
        return;
    }
    let runtime = runtime_dir("leak-drop");
    let sock = runtime.path().join("bsx/dropme.sock");

    let mut child = spawn_guest("dropme", runtime.path());
    let pid = child.id();
    assert!(
        eventually(|| vm_is_running(pid)),
        "the guest never reached a running vCPU: nothing to test the teardown against"
    );
    assert!(
        bsx_supervisor::socket::is_live(&sock),
        "a running VM must be answering on its control socket"
    );

    // The supervisor "dies": whatever held the child stops holding it and reaps.
    child.kill().expect("tear the VM down");
    child.wait().expect("reap it");

    assert!(
        eventually(|| !pid_is_live(pid)),
        "the VM outlived its supervisor"
    );
    assert!(
        !bsx_supervisor::socket::is_live(&sock),
        "its socket still answers"
    );
}

/// A killed VM leaves its socket *file* behind, which is expected, and the leftover must be
/// recognisable as dead rather than counted as a running VM forever.
#[test]
#[ignore = "boots a real guest: needs /dev/kvm, the guest tree and a built bsx"]
fn a_killed_vms_socket_is_left_but_never_counted_as_live() {
    if skipped("a_killed_vms_socket_is_left_but_never_counted_as_live") {
        return;
    }
    let runtime = runtime_dir("leak-stale");
    let sock = runtime.path().join("bsx/stale.sock");

    let mut child = spawn_guest("stale", runtime.path());
    let pid = child.id();
    assert!(
        eventually(|| vm_is_running(pid)),
        "the guest never reached a running vCPU"
    );
    assert!(
        bsx_supervisor::socket::is_live(&sock),
        "a running VM answers"
    );
    child.kill().expect("kill the VM");
    child.wait().expect("reap it");

    assert!(eventually(|| !bsx_supervisor::socket::is_live(&sock)));
    // The file surviving is the documented consequence of libkrun exiting the process without
    // unwinding, so this asserts the state is *recognised*, not that it does not happen.
    assert!(
        sock.exists(),
        "the socket file outlives the helper, as designed"
    );
    assert!(
        bsx_supervisor::socket::clear_if_stale(&sock).expect("clear the leftover"),
        "the leftover was not recognised as stale"
    );
    assert!(!sock.exists());
}
