//! Helpers shared by this crate's privileged integration-test binaries (each declares `mod common;`):
//! the skip predicates and the boot configs pointed at the pinned artifacts.
//!
//! **Why here and not in `bsx-test-support`.** The host predicates that need nothing but `std`
//! (`workspace_root`, `vm_skip_reason`) do live there, and this module builds on them. These do not:
//! they call `check_support`/`object_path` from `bsx-probes-loader` itself, which dev-depends on
//! `bsx-test-support`, so a helper crate reaching back for them would be a dependency cycle.
// Each test binary compiles this whole module but uses only the helpers it needs, so the unused
// remainder must not fail the `-D warnings` gate.
#![allow(dead_code)]
// A test module: `panic!` in free helpers is the idiomatic assertion, which the workspace's
// `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::time::Duration;

use bsx_engine::{BootConfig, DEFAULT_GUEST_CID, GUEST_READY_MARKER};
use bsx_probes_loader::{check_support, object_path};
use bsx_test_support::{vm_skip_reason, workspace_root};

/// Why this host cannot load the eBPF programs, or `None` when it can.
pub fn probe_skip_reason() -> Option<String> {
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

/// Why this host cannot run a test that boots a guest **and** attaches probes, or `None`. The probe
/// half is reported first, since it is the cheaper thing to fix.
pub fn probe_and_vm_skip_reason() -> Option<String> {
    probe_skip_reason().or_else(vm_skip_reason)
}

/// An agent-rootfs boot config pointed at the workspace artifacts (absolute paths, so it is
/// cwd-independent). Read-only shared base + tmpfs overlay, vsock exec on, **no** networking.
pub fn agent_config() -> BootConfig {
    let root = workspace_root();
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("BSX_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    cfg.rootfs = root.join("artifacts/rootfs-guest.ext4");
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.read_only_root = true;
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

/// [`agent_config`] with a NIC, for the tests that need guest egress to observe or enforce on.
/// Built by mutation rather than struct-update syntax, since `BootConfig` is `#[non_exhaustive]`.
pub fn networked_agent_config() -> BootConfig {
    let mut cfg = agent_config();
    cfg.enable_network = true;
    cfg
}
