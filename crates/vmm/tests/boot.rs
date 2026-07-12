//! Privileged boot integration test: boot a real Firecracker microVM to userspace and tear it
//! down, repeatably and without leaks.
//!
//! `#[ignore]`d because it needs `/dev/kvm` and the fetched artifacts. Run it with
//! `cargo xtask ci-privileged` (which guards on both) or `cargo test -p agent-vmm -- --ignored`.

use std::path::PathBuf;
use std::time::Duration;

use agent_vmm::{BootConfig, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};

/// A boot config pointed at the workspace's fetched artifacts (absolute, so it's cwd-independent).
/// Explicit `AGENT_KERNEL`/`AGENT_ROOTFS` overrides still win — they're the documented escape
/// hatch for hosts without the pinned artifacts (e.g. non-x86_64).
fn config() -> BootConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    if std::env::var_os("AGENT_ROOTFS").is_none() {
        cfg.rootfs = root.join("artifacts/rootfs.ext4");
    }
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn boots_to_userspace_and_shuts_down() {
    let cfg = config();
    let marker = cfg.userspace_marker.clone();
    let vm = Vm::boot(cfg).expect("microVM should boot to userspace");

    // Boot returns only after the marker is seen, so this is guaranteed — but assert it anyway to
    // document what "reached userspace" means, and that the console was actually captured.
    assert!(
        vm.console().contains(&marker),
        "console should show the userspace marker {marker:?}; got:\n{}",
        vm.console()
    );

    let latency = vm.boot_latency();
    assert!(latency > Duration::ZERO, "boot latency should be measured");
    assert!(
        latency < Duration::from_secs(30),
        "boot latency {latency:?} should be well under the deadline"
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn boots_with_a_vsock_device() {
    // Real Firecracker must accept `PUT /vsock` and boot to userspace with the device configured.
    // (This proves just the config path on the stock Ubuntu rootfs; the full host→guest-agent
    // round trip is `execs_a_command_in_the_microvm`, against the agent rootfs.)
    let mut cfg = config();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    let marker = cfg.userspace_marker.clone();

    let vm = Vm::boot(cfg).expect("microVM with vsock should boot to userspace");
    assert!(
        vm.console().contains(&marker),
        "guest should still reach userspace with vsock configured"
    );
    vm.shutdown().expect("shutdown should succeed");
}

/// A boot config pointed at the **agent rootfs** (`cargo xtask build-rootfs`): readiness is the
/// agent's post-bind marker, and vsock is on. Deliberately not `AGENT_ROOTFS`-overridable — the
/// in-VM exec tests are about *that* image specifically.
fn agent_rootfs_config() -> BootConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    cfg.rootfs = root.join("artifacts/rootfs-agent.ext4");
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn execs_a_command_in_the_microvm() {
    // Closes Phase 2's provisional "in a microVM" gate: the agent baked into `rootfs-agent.ext4`
    // actually binds vsock in a real guest, so `exec` round-trips end to end — not against a faked
    // socket. Boot returns once the agent's readiness marker reaches the console, so the connect
    // can't race the bind.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");
    let out = vm
        .exec(&["echo".into(), "hi".into()], b"")
        .expect("exec `echo hi` in the guest");
    assert_eq!(
        out.stdout,
        b"hi\n",
        "guest stdout should be `hi`; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0, "`echo hi` should exit 0");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn execs_python_in_the_microvm() {
    // The reference language runtime: `build-rootfs` installs python3 from the pinned Alpine
    // branch, and a real interpreter (dynamic musl binary + its stdlib, not a shell builtin) runs
    // in the guest and computes — proving the image carries a working userland, not just busybox.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");
    let out = vm
        .exec(&["python3".into(), "-c".into(), "print(2+2)".into()], b"")
        .expect("exec python in the guest");
    assert_eq!(
        out.stdout,
        b"4\n",
        "python should print 4; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0, "python should exit 0");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn repeated_boots_leave_no_leaks() {
    // Two full cycles back to back; the second only works if the first was fully reclaimed.
    for i in 0..2 {
        let vm = Vm::boot(config()).unwrap_or_else(|e| panic!("boot {i} failed: {e}"));
        vm.shutdown()
            .unwrap_or_else(|e| panic!("shutdown {i} failed: {e}"));
    }

    // This process's per-VM scratch dirs (`/tmp/agent-<pid>-<n>`) must all be gone.
    let prefix = format!("agent-{}-", std::process::id());
    let leftovers = std::fs::read_dir("/tmp")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "per-VM scratch dirs should be cleaned up");
}
