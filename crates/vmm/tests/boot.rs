//! Privileged integration tests for the raw microVM lifecycle: boot to userspace, the vsock device,
//! the read-only base + overlay, and the no-leak guarantee across repeated boots.
//!
//! `#[ignore]`d because they need `/dev/kvm` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::path::PathBuf;
use std::time::Duration;

use agent_vmm::{Vm, DEFAULT_GUEST_CID};

use common::{agent_rootfs_config, config, have_net_admin};

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

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn overlay_is_writable_and_base_is_untouched() {
    // P3.3 acceptance: the read-only base is shared (no copy), a per-run tmpfs overlay makes `/`
    // writable in-guest, and the base file on the host is never mutated.
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/rootfs-agent.ext4");
    let before = std::fs::metadata(&base).expect("stat base");
    let (before_len, before_mtime) = (before.len(), before.modified().expect("base mtime"));

    // Boot twice: writing to `/etc` (a path that lives on the read-only base) succeeds only because
    // the overlay redirects the write to the tmpfs upper. A fresh tmpfs per boot, so each is clean.
    for i in 0..2 {
        let vm = Vm::boot(agent_rootfs_config())
            .unwrap_or_else(|e| panic!("overlay microVM boot {i} failed: {e}"));
        let out = vm
            .exec(
                &[
                    "sh".into(),
                    "-c".into(),
                    "echo overlaid > /etc/p3_3 && cat /etc/p3_3".into(),
                ],
                b"",
            )
            .expect("write+read a normally-read-only path via the overlay");
        assert_eq!(
            out.stdout,
            b"overlaid\n",
            "overlay `/etc` should be writable; console:\n{}",
            vm.console()
        );
        assert_eq!(out.exit_code, 0);
        vm.shutdown().expect("shutdown should succeed");
    }

    // The read-only block device makes this a guarantee, not a hope: the guest opened the base
    // `O_RDONLY`, so it cannot have changed size or been rewritten.
    let after = std::fs::metadata(&base).expect("stat base again");
    assert_eq!(after.len(), before_len, "base image size must not change");
    assert_eq!(
        after.modified().expect("base mtime after"),
        before_mtime,
        "base image must not be rewritten"
    );
}

/// Host tap interfaces currently present (`fc*`), for the leak assertion below.
fn fc_interfaces() -> std::collections::BTreeSet<String> {
    std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("fc"))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `pid` is still a live `firecracker` process. A reaped child leaves `/proc` entirely, so a
/// `firecracker` still present at a VMM pid we booted means teardown failed to kill+reap it. Keyed on
/// the *specific* pid (via `comm`), not a scan, so it can't be confused by other parallel tests' VMMs
/// (they have different pids); a reaped-then-recycled pid running something else reads as gone.
fn is_firecracker(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "firecracker")
        .unwrap_or(false)
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + artifacts (run via `cargo xtask ci-privileged`)"]
fn repeated_boots_leave_no_leaks() {
    // After two boot/teardown cycles, nothing this test spawned may survive: no per-VM scratch dir,
    // no orphaned firecracker VMM process, and (with CAP_NET_ADMIN) no per-VM tap. The tap is the
    // one resource outside the scratch dir, so it's reclaimed separately from `remove_dir_all`;
    // without the capability, networking is off and this still covers the scratch-dir + process paths.
    let net = have_net_admin();
    let taps_before = fc_interfaces();
    let mut vmm_pids = Vec::new();

    // Two full cycles back to back; the second only works if the first was fully reclaimed.
    for i in 0..2 {
        let mut cfg = config();
        cfg.enable_network = net;
        let vm = Vm::boot(cfg).unwrap_or_else(|e| panic!("boot {i} failed: {e}"));
        vmm_pids.push(vm.vmm_pid());
        // `shutdown` consumes the VM, so its `Drop` (kill + reap + reclaim) has run by the time it
        // returns — the leak checks below therefore observe the fully-torn-down state.
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

    // Every firecracker VMM we booted must have been killed and reaped — no orphaned process.
    let orphans: Vec<_> = vmm_pids
        .iter()
        .copied()
        .filter(|&p| is_firecracker(p))
        .collect();
    assert!(orphans.is_empty(), "orphaned firecracker VMMs: {orphans:?}");

    // No tap interface survived the cycles either (only asserted when networking was enabled).
    if net {
        let leaked: Vec<_> = fc_interfaces().difference(&taps_before).cloned().collect();
        assert!(leaked.is_empty(), "leaked tap interfaces: {leaked:?}");
    }
}
