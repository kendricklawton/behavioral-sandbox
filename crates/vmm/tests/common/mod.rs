//! Helpers shared by the privileged integration-test binaries (each declares `mod common;`):
//! scratch dirs, the boot configs pointed at the pinned artifacts, and the prewarmed-snapshot builder.
// Each test binary compiles this whole module but uses only the helpers it needs, so the unused
// remainder must not fail the `-D warnings` gate.
#![allow(dead_code)]
// A test module: `panic!` in free helpers is the idiomatic assertion, which the workspace's
// `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use agent_vmm::{BootConfig, Jail, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};

/// A host scratch dir removed on drop, so a panicking assertion can't leak it. (The unit tests have
/// their own copy; the integration crate is separate, so it needs one too.)
pub struct TmpDir(PathBuf);
impl TmpDir {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("agent-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The hex sha256 of `bytes`, via the host `sha256sum` (no crate dep, mirrors the input test's
/// host-side hash of the injected payload). A free helper (not a `#[test]` fn), so it uses explicit
/// panics rather than `expect`, which the workspace lints only re-allow inside test functions.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::io::Write as _;
    let mut child = match std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("spawn sha256sum: {e}"),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(bytes);
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => panic!("host sha256: {e}"),
    };
    match String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
    {
        Some(h) => h.to_string(),
        None => panic!("empty sha256sum output"),
    }
}

/// A boot config pointed at the workspace's fetched artifacts (absolute, so it's cwd-independent).
/// Explicit `AGENT_KERNEL`/`AGENT_ROOTFS` overrides still win, they're the documented escape
/// hatch for hosts without the pinned artifacts (e.g. non-x86_64).
pub fn config() -> BootConfig {
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

/// A boot config pointed at the **agent rootfs** (`cargo xtask build-rootfs`): readiness is the
/// agent's post-bind marker, and vsock is on. Deliberately not `AGENT_ROOTFS`-overridable, the
/// in-VM exec tests are about *that* image specifically.
pub fn agent_rootfs_config() -> BootConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    cfg.rootfs = root.join("artifacts/rootfs-agent.ext4");
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    // Read-only shared base + a per-run tmpfs overlay: `/` is writable in-guest but the base
    // file is never mutated. This is what makes the agent's `/tmp` working dir usable, so the exec
    // tests below exercise the overlay end to end.
    cfg.read_only_root = true;
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

/// The agent rootfs booted **under the jailer**, with the vsock exec channel: the convergence of
/// the jail with a code channel (a jailed VM that can actually run code). Deliberately *not*
/// `read_only_root`, the jailer refuses the overlay for now (a later step stages a read-only base +
/// per-run tmpfs into the chroot), so this boots a plain read-write rootfs copy inside the chroot,
/// which is enough to reach the agent's readiness marker and serve an exec. Needs real root (see
/// [`have_jailer_privileges`]).
pub fn jailed_agent_config() -> BootConfig {
    let mut cfg = agent_rootfs_config();
    cfg.read_only_root = false;
    cfg.jail = Some(Jail::default());
    cfg
}

/// The agent rootfs booted **under the jailer** on the **shared-base path**: `read_only_root` (the shared
/// base bind-mounted into the chroot, guest tmpfs overlay) plus the vsock exec channel. This is the
/// jailed counterpart of [`agent_rootfs_config`], which it inherits `read_only_root = true` from, only
/// adding the jail. Needs real root (see [`have_jailer_privileges`]).
pub fn jailed_overlay_config() -> BootConfig {
    let mut cfg = agent_rootfs_config();
    cfg.jail = Some(Jail::default());
    cfg
}

/// Boot the agent rootfs, prewarmed the Python runtime (so the interpreter + stdlib are page-cache-hot in
/// the guest's memory), and take a snapshot of *that* prewarmed state. Returns the source's cold-boot
/// latency alongside the bundle so callers can compare it to restore.
// A free helper (not a `#[test]` fn), so it uses explicit `panic!` rather than `.expect()`, which the
// workspace lints only re-allow inside test functions.
pub fn prewarmed_python_snapshot(bundle: &TmpDir) -> (agent_vmm::Snapshot, Duration) {
    let source = match Vm::boot(agent_rootfs_config()) {
        Ok(vm) => vm,
        Err(e) => panic!("agent microVM should boot: {e}"),
    };
    let cold_boot = source.boot_latency();
    // "Runtime loaded": run Python once so the snapshot captures a guest with the interpreter and its
    // imports already resident, not a bare boot.
    let prewarmed = ["python3", "-c", "import json, os, sys"].map(String::from);
    match source.exec(&prewarmed, &[]) {
        Ok(out) if out.exit_code == 0 => {}
        Ok(out) => panic!("warm-up python should exit 0, got {}", out.exit_code),
        Err(e) => panic!("warm-up exec should run: {e}"),
    }
    let snap = match source.snapshot(bundle.path()) {
        Ok(s) => s,
        Err(e) => panic!("prewarmed snapshot (read_only_root + vsock) should succeed: {e}"),
    };
    if let Err(e) = source.shutdown() {
        panic!("source shutdown should succeed: {e}");
    }
    (snap, cold_boot)
}

/// The cgroup v2 dir `pid` currently lives in (`/sys/fs/cgroup` + its `0::` line), or `None` for
/// the root cgroup or an unreadable entry. Shared by the confinement suite (the sentinel watches
/// this dir) and the snapshot suite (the restored clone's re-applied caps are read from it).
pub fn cgroup_of(pid: u32) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    if rel.is_empty() || rel == "/" {
        return None;
    }
    Some(PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Whether this process holds `CAP_NET_ADMIN` (effective), needed to create a tap. Creating a tap
/// is privileged (unlike the rootless block-device builds), so the NIC tests skip without it rather
/// than fail on a box that can do KVM but not net-admin. Delegates to `agent-test-support`'s
/// audited `CapEff` parse (which reads only the low 64 bits, so a wider future field can't read a
/// capable host as incapable and silently skip these tests).
pub fn have_net_admin() -> bool {
    agent_test_support::have_cap(agent_test_support::CAP_NET_ADMIN)
}

/// Whether this process can run the **jailer**: effective uid 0 **in the initial user namespace**.
/// The jailer `mknod`s device nodes, which `EPERM`s in a non-initial userns even with `CAP_MKNOD`, so
/// the `unshare -Urn --map-root-user` trick that carries the other privileged tests is not enough,
/// the jailer test needs real root (or a privileged container). Skips otherwise, like
/// [`have_net_admin`].
pub fn have_jailer_privileges() -> bool {
    let euid0 = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:").map(|v| v.trim().to_string()))
        })
        // `Uid:` is real/effective/saved/fs; the effective uid is the second field.
        .and_then(|v| {
            v.split_whitespace()
                .nth(1)
                .and_then(|e| e.parse::<u32>().ok())
        })
        .is_some_and(|euid| euid == 0);
    // The initial user namespace maps the full uid range (`0 0 4294967295`); a `--map-root-user`
    // userns maps a single id, so its map differs and this reads false.
    let init_userns = std::fs::read_to_string("/proc/self/uid_map")
        .ok()
        .is_some_and(|m| m.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"]);
    euid0 && init_userns
}
