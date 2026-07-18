//! Host readiness check: does this machine have what the engine needs to boot and confine a
//! sandbox? The **single implementation** behind two entry points — the `agent doctor` subcommand an
//! operator runs on a fresh host, and `cargo xtask setup` for a dev box — so the two can't drift on
//! what "ready" means.
//!
//! Each [`Check`] is one prerequisite with a [`CheckStatus`]: [`Ok`](CheckStatus::Ok) present,
//! [`Warn`](CheckStatus::Warn) a *degradation* (the run still works, but something fails open —
//! decision 013), or [`Fail`](CheckStatus::Fail) a *hard* requirement (a boot can't happen without
//! it, or the host is off the supported platform). The split mirrors the engine's own error
//! discipline: the isolation boundary is never a degradation, so `/dev/kvm`, the boot artifacts, and
//! the **supported-platform floor** (architecture + a security-maintained host-kernel LTS, decision
//! 036) are hard, while the jailer, resource caps, and networking tools fail open with a named
//! consequence.
//!
//! The eBPF-observability capability check (`CAP_BPF`/`CAP_PERFMON` + kernel BTF) lives in the probe
//! loader, out of this crate (decisions 024/026); each entry point appends it. This module is
//! `unsafe`-free std-only detection — nothing here boots a VM.

use std::path::Path;

use crate::BootConfig;

/// The **supported host-kernel floor** (`major.minor`), a hard requirement: the engine refuses to
/// certify a host below a security-maintained LTS, because running untrusted code on an unpatched
/// kernel is a threat-model hole, not a convenience gap (decision 036). 5.15 is a maintained LTS that
/// also guarantees `cgroup.kill` (5.14, decision 014); bump it here to tighten the floor.
const MIN_KERNEL: (u64, u64) = (5, 15);

/// The **supported CPU architectures** — Firecracker's two (decision 036). The engine builds for no
/// others, so for a shipped binary this is decided at compile time; the check names an unsupported
/// cross-compile rather than letting it fail obscurely at first boot.
const SUPPORTED_ARCHES: [&str; 2] = ["x86_64", "aarch64"];

/// The outcome of one host [`Check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The prerequisite is present.
    Ok,
    /// Absent, but the engine **degrades** rather than refusing: the run still works, minus the
    /// capability the `note` names (a fail-open item, decision 013).
    Warn,
    /// Absent and **hard**: a boot cannot happen without it (the isolation boundary, the artifacts).
    Fail,
}

/// One host prerequisite: a human label, its [`CheckStatus`], and a note on what its absence costs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// What was checked, e.g. "`/dev/kvm` present".
    pub label: String,
    /// Present, a degradation, or a hard miss.
    pub status: CheckStatus,
    /// What its absence means at runtime (shown when not [`Ok`](CheckStatus::Ok)).
    pub note: Option<String>,
}

impl Check {
    fn new(label: &str, ok: bool, warn_not_fail: bool, note: &str) -> Self {
        let status = if ok {
            CheckStatus::Ok
        } else if warn_not_fail {
            CheckStatus::Warn
        } else {
            CheckStatus::Fail
        };
        Check {
            label: label.to_string(),
            status,
            note: (status != CheckStatus::Ok).then(|| note.to_string()),
        }
    }
}

/// Run the engine-runtime host checks against `config` (whose `firecracker`/`kernel`/`rootfs` paths
/// are the resolved ones a boot would use). The eBPF-capability row is appended by the caller. Pure
/// detection: reads `/proc`, `/sys`, `/dev`, `PATH`, and runs `firecracker --version`; boots nothing.
#[must_use]
pub fn checks(config: &BootConfig) -> Vec<Check> {
    let fc = config.firecracker.to_string_lossy();
    vec![
        // The supported platform — hard: off it, the engine is not certified to isolate (decision 036).
        Check::new(
            &format!(
                "architecture is {} (x86_64 or aarch64)",
                std::env::consts::ARCH
            ),
            SUPPORTED_ARCHES.contains(&std::env::consts::ARCH),
            false,
            "unsupported architecture: the engine builds and is tested only for x86_64 and aarch64 (decision 036)",
        ),
        Check::new(
            &format!(
                "host kernel >= {}.{} (security-maintained LTS floor)",
                MIN_KERNEL.0, MIN_KERNEL.1
            ),
            kernel_at_least(MIN_KERNEL.0, MIN_KERNEL.1),
            false,
            "unsupported kernel: below the security-maintained LTS floor the engine requires for \
             running untrusted code (decision 036); it also provides cgroup.kill for crash-safe \
             teardown (decision 014)",
        ),
        // The hardware isolation boundary — never a degradation.
        Check::new(
            "/dev/kvm present",
            Path::new("/dev/kvm").exists(),
            false,
            "every boot fails (NoKvm): isolation is hardware, there is no software fallback",
        ),
        Check::new(
            "/dev/kvm writable (kvm group or root)",
            kvm_writable(),
            false,
            "every boot fails (NoKvm): add your user to the `kvm` group, or run as root",
        ),
        // The boot artifacts — hard: nothing boots without a kernel + rootfs at the configured paths.
        Check::new(
            "guest kernel present (AGENT_KERNEL)",
            config.kernel.is_file(),
            false,
            "no kernel to boot: `cargo xtask fetch-artifacts`, or point AGENT_KERNEL at one",
        ),
        Check::new(
            "guest rootfs present (AGENT_ROOTFS)",
            config.rootfs.is_file(),
            false,
            "no rootfs to boot: build one (`cargo xtask build-rootfs`) or set AGENT_ROOTFS",
        ),
        Check::new(
            &format!("firecracker on PATH ({fc})"),
            command_on_path(&fc),
            false,
            "no VMM to launch: install Firecracker v1.9, or set AGENT_FIRECRACKER",
        ),
        // The jailer path — fails open: `--unjailed` still boots (behind the KVM boundary).
        Check::new(
            "firecracker is the pinned v1.9 (decision 001)",
            firecracker_version(&fc) == Some((1, 9)),
            true,
            "boots continue with a warning; API request bodies may not match another version",
        ),
        Check::new(
            "real root (euid 0 — the jailer mknod's device nodes)",
            geteuid() == Some(0),
            true,
            "jailed boot (the default) fails; `--unjailed` still runs behind the KVM boundary",
        ),
        Check::new(
            "jailer on PATH",
            command_on_path("jailer"),
            true,
            "jailed boot (the default) fails; `--unjailed` still runs behind the KVM boundary",
        ),
        Check::new(
            "cgroup v2 cpu+memory delegated (jailer resource caps)",
            cgroup_controllers_delegated(),
            true,
            "jailed VMs run WITHOUT cpu/memory caps (decision 013) — a fail-open DoS mitigation",
        ),
        // Networking + bulk-I/O tooling — fails open: only the runs that use them need them.
        Check::new(
            "ip (iproute2 — the per-VM tap for --net)",
            command_on_path("ip"),
            true,
            "a `--net` run fails to build its tap; runs without networking are unaffected",
        ),
        Check::new(
            "mke2fs (e2fsprogs — bulk input device / rootfs build)",
            command_on_path("mke2fs"),
            true,
            "bulk `input_dir` and `cargo xtask build-rootfs` fail; per-frame files are unaffected",
        ),
        Check::new(
            "e2fsck + debugfs (e2fsprogs — bulk output readback)",
            command_on_path("e2fsck") && command_on_path("debugfs"),
            true,
            "bulk `output_dir` readback fails; per-frame `--get` artifacts are unaffected",
        ),
    ]
}

/// The degradation matrix as lines — the same fails-open-vs-hard split the checks carry, stated once
/// for the report footer so both entry points render an identical summary.
#[must_use]
pub fn matrix() -> Vec<&'static str> {
    vec![
        "fails open (a warning, still runs):",
        "  firecracker not v1.9         -> boots continue; API bodies may not match (decision 001)",
        "  no real root / no jailer     -> the jailed default fails; --unjailed runs unconfined",
        "  cgroup v2 not delegated      -> jailed VMs run WITHOUT cpu/memory caps (decision 013)",
        "  ip / mke2fs / e2fsprogs      -> only --net or bulk-I/O runs fail; others are unaffected",
        "  no eBPF caps / BTF           -> --trace/--watch degrade to a gap; --allow enforcement refuses",
        "hard errors (typed, never a silent half-measure):",
        "  unsupported arch / kernel    -> off the supported platform: refused (decision 036)",
        "  /dev/kvm missing/unwritable  -> every boot fails: NoKvm (isolation is hardware)",
        "  kernel or rootfs missing     -> nothing to boot: fetch/build the artifacts first",
        "  firecracker missing          -> no VMM to launch: a typed Vmm error",
    ]
}

/// Whether every hard ([`Fail`](CheckStatus::Fail)) prerequisite in `checks` is satisfied — the
/// engine can boot *something* (jailed or not). A caller turns this into an exit code.
#[must_use]
pub fn can_boot(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.status != CheckStatus::Fail)
}

/// `/dev/kvm` opens read-write (root, or the `kvm` group).
fn kvm_writable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// `bin` resolves to a file on `PATH` (or is an absolute/relative path that exists).
fn command_on_path(bin: &str) -> bool {
    let p = Path::new(bin);
    if p.components().count() > 1 {
        return p.is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(bin).is_file()))
}

/// The effective uid from `/proc/self/status` (`Uid:` line, fields real/effective/…), or `None` if
/// it can't be read — std-only, no `libc`.
fn geteuid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2).and_then(|s| s.parse().ok())
}

/// `(major, minor)` of `<fc> --version` (first line `Firecracker v1.9.1`), or `None` if missing or
/// unparseable — the same parse the driver runs to warn on an unpinned binary.
fn firecracker_version(fc: &str) -> Option<(u64, u64)> {
    let out = std::process::Command::new(fc)
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let rest = text.split("Firecracker v").nth(1)?;
    let mut parts = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Whether the running kernel is at least `major.minor`, from `/proc/sys/kernel/osrelease`.
fn kernel_at_least(major: u64, minor: u64) -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|s| {
            let mut it = s
                .split(|c: char| !c.is_ascii_digit())
                .filter(|t| !t.is_empty());
            Some((
                it.next()?.parse::<u64>().ok()?,
                it.next()?.parse::<u64>().ok()?,
            ))
        })
        .is_some_and(|v| v >= (major, minor))
}

/// Whether cgroup v2 `cpu`+`memory` are delegated at the root (a systemd host does this by default),
/// so the jailer can cap a jailed VM's CPU/memory.
fn cgroup_controllers_delegated() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .map(|s| {
            let toks: Vec<&str> = s.split_whitespace().collect();
            toks.contains(&"cpu") && toks.contains(&"memory")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classifies_hard_vs_degradation() {
        let hard = Check::new("kvm", false, false, "no boot");
        assert_eq!(hard.status, CheckStatus::Fail);
        assert_eq!(hard.note.as_deref(), Some("no boot"));
        let soft = Check::new("jailer", false, true, "unjailed still runs");
        assert_eq!(soft.status, CheckStatus::Warn);
        let good = Check::new("ip", true, true, "n/a");
        assert_eq!(good.status, CheckStatus::Ok);
        assert_eq!(good.note, None, "a satisfied check carries no note");
    }

    #[test]
    fn can_boot_is_false_only_on_a_hard_miss() {
        let ok = vec![
            Check::new("a", true, false, ""),
            Check::new("b", false, true, ""),
        ];
        assert!(can_boot(&ok), "a degradation still boots");
        let bad = vec![Check::new("kvm", false, false, "")];
        assert!(!can_boot(&bad), "a hard miss cannot boot");
    }

    #[test]
    fn command_on_path_finds_a_ubiquitous_binary() {
        // `sh` is on PATH on any host the test runs on; a nonsense name is not.
        assert!(command_on_path("sh"));
        assert!(!command_on_path("definitely-not-a-real-binary-xyzzy"));
    }

    #[test]
    fn checks_cover_the_engine_prerequisites() {
        let cfg = BootConfig::default();
        let checks = checks(&cfg);
        // The isolation boundary and the artifacts are present as hard checks.
        assert!(checks.iter().any(|c| c.label.contains("/dev/kvm present")));
        assert!(checks
            .iter()
            .any(|c| c.label.contains("kernel") && c.status != CheckStatus::Warn));
        // The jailer path is a degradation, not hard (unjailed exists).
        let jailer = checks
            .iter()
            .find(|c| c.label.contains("jailer"))
            .expect("a jailer check");
        assert!(matches!(jailer.status, CheckStatus::Ok | CheckStatus::Warn));
        // The supported-platform floor (decision 036) is present and **hard** — architecture and a
        // kernel LTS are never degradations, so an off-platform host is refused, not warned.
        let arch = checks
            .iter()
            .find(|c| c.label.contains("architecture"))
            .expect("an architecture check");
        assert_ne!(
            arch.status,
            CheckStatus::Warn,
            "the platform floor is hard, never a degradation"
        );
        assert!(
            checks.iter().any(|c| c.label.contains("LTS floor")),
            "the host-kernel LTS floor is a stated check"
        );
    }
}
