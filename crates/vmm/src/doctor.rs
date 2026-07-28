//! Host readiness check: does this machine have what the engine needs to boot and confine a
//! sandbox? The **single implementation** behind two entry points, the `ekvm doctor` subcommand an
//! operator runs on a fresh host, and `cargo xtask setup` for a dev box, so the two can't drift on
//! what "ready" means.
//!
//! Each [`Check`] is one prerequisite with a [`CheckStatus`]: [`Ok`](CheckStatus::Ok) present,
//! [`Warn`](CheckStatus::Warn) a *degradation* (the run still works, but something fails open), or [`Fail`](CheckStatus::Fail) a *hard* requirement (a boot can't happen without
//! it, or the host is off the supported platform). The split mirrors the engine's own error
//! discipline: the isolation boundary is never a degradation, so `/dev/kvm`, the boot artifacts, and
//! the **supported-platform floor** (architecture + a security-maintained host-kernel LTS) are hard, while the jailer, resource caps, and networking tools fail open with a named
//! consequence.
//!
//! The host-hardening posture rows reuse [`Warn`](CheckStatus::Warn) for a second kind
//! of advice: not a capability the engine loses, but a side-channel exposure the layer *beneath*
//! the engine carries when mutually-distrusting tenants share the hardware. Advisory by design, a
//! single-tenant dev box tripping them is fine (`docs/threat-model.md` is the baseline).
//!
//! The eBPF-observability capability check (`CAP_BPF`/`CAP_PERFMON` + kernel BTF) lives in the probe
//! loader, out of this crate; each entry point appends it. This module is
//! `unsafe`-free std-only detection, nothing here boots a VM.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

use crate::BootConfig;

/// The **supported host-kernel floor** (`major.minor`), a hard requirement: the engine refuses to
/// certify a host below a security-maintained LTS, because running untrusted code on an unpatched
/// kernel is a threat-model hole, not a convenience gap. 5.15 is a maintained LTS that
/// also guarantees `cgroup.kill` (5.14); bump it here to tighten the floor.
const MIN_KERNEL: (u64, u64) = (5, 15);

/// The **supported CPU architectures** (narrowed to `x86_64`-only: aarch64 has no
/// hardware or CI lane to test its privileged path on, and an untested isolation boundary is not
/// a supported one). The engine builds for no others, so for a shipped binary this is decided at
/// compile time; the check names an unsupported cross-compile rather than letting it fail
/// obscurely at first boot.
const SUPPORTED_ARCHES: [&str; 1] = ["x86_64"];

/// The outcome of one host [`Check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The prerequisite is present.
    Ok,
    /// Absent, but the engine **degrades** rather than refusing: the run still works, minus the
    /// capability the `note` names (a fail-open item).
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
    let fc_present = command_on_path(&fc);
    let exposed = vulnerable_entries(Path::new(SYS_CPU_VULNERABILITIES));
    vec![
        // The supported platform, hard: off it, the engine is not certified to isolate.
        Check::new(
            &format!("architecture is {} (x86_64)", std::env::consts::ARCH),
            SUPPORTED_ARCHES.contains(&std::env::consts::ARCH),
            false,
            "unsupported architecture: the engine is built and tested only for x86_64",
        ),
        Check::new(
            &format!(
                "host kernel >= {}.{} (security-maintained LTS floor)",
                MIN_KERNEL.0, MIN_KERNEL.1
            ),
            kernel_at_least(MIN_KERNEL.0, MIN_KERNEL.1),
            false,
            "unsupported kernel: below the security-maintained LTS floor the engine requires for \
             running untrusted code; it also provides cgroup.kill for crash-safe \
             teardown",
        ),
        // The hardware isolation boundary, never a degradation.
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
            "every boot fails (NoKvm): join the `kvm` group (`sudo usermod -aG kvm $USER`, then a \
             fresh login) or run as root; already in the group? check the device mode \
             (`ls -l /dev/kvm`)",
        ),
        // The boot artifacts, hard: nothing boots without a kernel + rootfs at the configured paths.
        Check::new(
            "guest kernel present (EKVM_KERNEL)",
            config.kernel.is_file(),
            false,
            "no kernel to boot: `cargo xtask fetch-artifacts`, or point EKVM_KERNEL at one",
        ),
        Check::new(
            "guest rootfs present (EKVM_ROOTFS)",
            config.rootfs.is_file(),
            false,
            "no rootfs to boot: build one (`cargo xtask build-rootfs`) or set EKVM_ROOTFS",
        ),
        Check::new(
            &format!("firecracker on PATH ({fc})"),
            fc_present,
            false,
            &format!(
                "no VMM to launch: install firecracker + jailer ({}) from \
                 https://github.com/firecracker-microvm/firecracker/releases, or set \
                 EKVM_FIRECRACKER",
                supported_range()
            ),
        ),
        // The two rows below judge the binary the row above found; with no binary they must not
        // pretend to have judged one ("custom or unpinned" about nothing misleads an operator),
        // so their note collapses to a deferral instead.
        Check::new(
            &format!("firecracker is a supported release ({})", supported_range()),
            fc_present
                && firecracker_version(&fc).is_some_and(|v| {
                    (crate::spawn::MIN_SUPPORTED_FC_VERSION..=crate::spawn::PINNED_FC_VERSION)
                        .contains(&v)
                }),
            true,
            if fc_present {
                "boots continue with a warning; outside this range request bodies and snapshot \
                 semantics are untested, and below it upstream no longer ships security patches"
            } else {
                "not checked: no firecracker binary found (fix the missing row above first)"
            },
        ),
        Check::new(
            "firecracker binary sha256 matches pinned release",
            fc_present && firecracker_hash_matches(&fc),
            true,
            if fc_present {
                "custom or unpinned Firecracker binary on host; verify binary provenance out of band"
            } else {
                "not checked: no firecracker binary found (fix the missing row above first)"
            },
        ),
        // The jailer path, fails open: `--unjailed` still boots (behind the KVM boundary).
        Check::new(
            "real root (euid 0: the jailer mknod's device nodes)",
            geteuid() == Some(0),
            true,
            "jailed chroot boot requires root (sudo); `--unjailed` mode runs unconfined using hardware KVM isolation",
        ),
        Check::new(
            "jailer on PATH",
            command_on_path("jailer"),
            true,
            "jailed boot requires jailer binary; `--unjailed` mode runs unconfined using hardware KVM isolation",
        ),
        Check::new(
            "cgroup v2 cpu+memory delegated (jailer resource caps)",
            cgroup_controllers_delegated(),
            true,
            "jailed VMs run WITHOUT cpu/memory caps: a fail-open DoS mitigation",
        ),
        // The jailer mknods /dev/kvm inside its chroot (under the scratch dir), and a `nodev` mount
        // makes that node inert, so an owned-and-readable /dev/kvm still fails to open. The default
        // scratch base is /tmp, which modern systemd hosts mount `nodev`, so this catches a jailed
        // boot that would otherwise fail at InstanceStart with a misleading "/dev/kvm ACL" error.
        Check::new(
            "scratch dir is not nodev (the jailer's /dev/kvm lives there)",
            !scratch_is_nodev(&config.scratch_dir).unwrap_or(false),
            true,
            "jailed boot fails: scratch filesystem is mounted `nodev`; use default `/var/tmp` or `--unjailed`",
        ),
        // Networking + bulk-I/O tooling, fails open: only the runs that use them need them.
        Check::new(
            "ip (iproute2: the per-VM tap for --net)",
            command_on_path("ip"),
            true,
            "a `--net` run fails to build its tap; runs without networking are unaffected",
        ),
        Check::new(
            "mke2fs (e2fsprogs: bulk input device / rootfs build)",
            command_on_path("mke2fs"),
            true,
            "bulk `input_dir` and `cargo xtask build-rootfs` fail; per-frame files are unaffected",
        ),
        Check::new(
            "e2fsck + debugfs (e2fsprogs: bulk output readback)",
            command_on_path("e2fsck") && command_on_path("debugfs"),
            true,
            "bulk `output_dir` readback fails; per-frame `--get` artifacts are unaffected",
        ),
        // Host hardening, advisory: micro-architectural side channels between
        // co-resident guests live in the layer beneath the engine, so doctor advises the
        // multi-tenant baseline (`docs/threat-model.md`) and never refuses.
        Check::new(
            "CPU vulnerability mitigations in effect",
            exposed.is_empty(),
            true,
            &format!(
                "exposed: {}; co-resident guests can probe unmitigated CPU side channels; do not \
                 boot with mitigations=off, and keep microcode current",
                exposed.join(", ")
            ),
        ),
        Check::new(
            "SMT off (cross-thread side channels)",
            !sys_toggle_at(Path::new(SYS_SMT_ACTIVE)),
            true,
            "sibling hyperthreads share micro-architectural state: multi-tenant recommendation; \
             for mutually-distrusting tenants, disable SMT or use core scheduling",
        ),
        Check::new(
            "KSM off (cross-VM page merging)",
            !sys_toggle_at(Path::new(SYS_KSM_RUN)),
            true,
            "kernel same-page merging across guests is a timing side channel the engine does not \
             need: cross-clone memory sharing already comes from the snapshot COW",
        ),
    ]
}

/// The degradation matrix as lines, the same fails-open-vs-hard split the checks carry, stated once
/// for the report footer so both entry points render an identical summary.
#[must_use]
pub fn matrix() -> Vec<&'static str> {
    vec![
        "fails open (a warning, still runs):",
        "  firecracker out of range     -> boots continue; below the floor upstream ships no patches",
        "  firecracker sha256 unpinned  -> boots continue; verify custom binary out of band",
        "  no real root / no jailer     -> the jailed default fails; --unjailed runs unconfined",
        "  cgroup v2 not delegated      -> jailed VMs run WITHOUT cpu/memory caps",
        "  scratch dir is nodev         -> jailed /dev/kvm can't open; point EKVM_SCRATCH_DIR off nodev",
        "  ip / mke2fs / e2fsprogs      -> only --net or bulk-I/O runs fail; others are unaffected",
        "  SMT / KSM / CPU vulns        -> advisory hardening baseline: docs/threat-model.md",
        "  no eBPF caps / BTF           -> --trace/--watch degrade to a gap; --allow enforcement refuses",
        "hard errors (typed, never a silent half-measure):",
        "  unsupported arch / kernel    -> off the supported platform: refused",
        "  /dev/kvm missing/unwritable  -> every boot fails: NoKvm (isolation is hardware)",
        "  kernel or rootfs missing     -> nothing to boot: fetch/build the artifacts first",
        "  firecracker missing          -> no VMM to launch: a typed Vmm error",
    ]
}

/// Whether every hard ([`Fail`](CheckStatus::Fail)) prerequisite in `checks` is satisfied, the
/// engine can boot *something* (jailed or not). A caller turns this into an exit code.
#[must_use]
pub fn can_boot(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.status != CheckStatus::Fail)
}

/// Whether a **jailed** run (the default) can work on this host as invoked right now:
/// real root *and* the `jailer` binary. Not a readiness check (an unjailed run is still a valid boot,
/// which is why the two rows above only warn); it exists so a caller can suggest a first-run command
/// that actually works here instead of one that fails.
#[must_use]
pub fn jailed_run_available() -> bool {
    geteuid() == Some(0) && command_on_path("jailer")
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
/// it can't be read, std-only, no `libc`.
fn geteuid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2).and_then(|s| s.parse().ok())
}

/// The supported Firecracker range as an operator-facing string (`v1.14..=v1.16`), rendered from
/// the two constants so the report can never name a range the driver does not actually accept.
fn supported_range() -> String {
    let (lo_maj, lo_min) = crate::spawn::MIN_SUPPORTED_FC_VERSION;
    let (hi_maj, hi_min) = crate::spawn::PINNED_FC_VERSION;
    format!("v{lo_maj}.{lo_min}..=v{hi_maj}.{hi_min}, tested on v{hi_maj}.{hi_min}")
}

/// `(major, minor)` of `<fc> --version` (first line `Firecracker v1.16.1`), or `None` if missing or
/// unparseable, the same parse the driver runs to warn on an unpinned binary.
fn firecracker_version(fc: &str) -> Option<(u64, u64)> {
    let out = std::process::Command::new(fc)
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    crate::spawn::fc_version_of(&text)
}

/// sha256 of the pinned release's `firecracker` binary (not the tarball: the check hashes the
/// resolved binary on `PATH`). Only supported releases belong here; an older hash left in place
/// would bless a VMM upstream no longer patches.
const PINNED_FIRECRACKER_SHA256: &[&str] = &[
    "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7", // v1.16.1
];

fn resolve_binary_path(bin: &str) -> Option<PathBuf> {
    let p = Path::new(bin);
    if p.components().count() > 1 {
        return p.is_file().then(|| p.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(bin))
            .find(|p| p.is_file())
    })
}

fn firecracker_hash_matches(fc: &str) -> bool {
    let Some(path) = resolve_binary_path(fc) else {
        return false;
    };
    file_sha256(&path).is_some_and(|hash| PINNED_FIRECRACKER_SHA256.contains(&hash.as_str()))
}

fn file_sha256(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
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

/// The sysfs facts behind the host-hardening advisory rows: the per-vulnerability
/// mitigation files, whether SMT is active, and whether KSM is merging.
const SYS_CPU_VULNERABILITIES: &str = "/sys/devices/system/cpu/vulnerabilities";
const SYS_SMT_ACTIVE: &str = "/sys/devices/system/cpu/smt/active";
const SYS_KSM_RUN: &str = "/sys/kernel/mm/ksm/run";

/// The entries under `dir` (one file per CPU vulnerability) whose content reports `Vulnerable`,
/// sorted so the advisory note is stable. A missing or unreadable dir reads as no exposure: an
/// absent fact never raises a guessed warning (the [`scratch_is_nodev`] posture).
fn vulnerable_entries(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let s = std::fs::read_to_string(e.path()).ok()?;
            if s.trim_start().starts_with("Vulnerable") {
                Some(e.file_name().to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out
}

/// Whether the one-line `/sys` toggle at `path` reads as on. Missing or unreadable reads as off,
/// never a guessed warning.
fn sys_toggle_at(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|s| sys_toggle_on(&s))
}

/// The pure parse behind [`sys_toggle_at`]: nonzero covers both SMT's `active` (`0`/`1`) and KSM's
/// `run` (`0` off, `1` merging, `2` unmerging with the machinery still enabled).
fn sys_toggle_on(content: &str) -> bool {
    let t = content.trim();
    !t.is_empty() && t != "0"
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

/// Whether the filesystem holding `dir` is mounted `nodev` (so device nodes there are inert and the
/// jailer's chroot `/dev/kvm` cannot be opened). `None` when it can't be determined (no readable
/// `/proc/self/mountinfo`, or the path doesn't resolve), so the check reads "unknown" as "assume
/// fine" rather than raising a false alarm.
/// Public so the guided install (`install.sh`, `cargo xtask self-host`) can pre-empt the failure by
/// writing a non-`nodev` `scratch_dir` instead of the operator hitting it (P20.16a): a diagnostic
/// helper, not part of the pinned `Sandbox`/`Limits`/`RunResult` surface.
pub fn scratch_is_nodev(dir: &Path) -> Option<bool> {
    // The scratch dir may not exist yet; its nearest existing ancestor is on the same filesystem the
    // jailer's chroot will be created on (mkdir does not cross a mount), so that is what to classify.
    let target = nearest_existing(dir)?.canonicalize().ok()?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    mount_nodev_in(&mountinfo, &target)
}

/// The `nodev` flag of the longest mount point in `mountinfo` that is an ancestor of `target` (the
/// filesystem that actually holds it). Pure, so the `/proc/self/mountinfo` parse is unit-tested
/// without a real `/proc`. `None` if no line covers `target` (an absolute path is always covered by
/// `/`, so this only happens on malformed input).
fn mount_nodev_in(mountinfo: &str, target: &Path) -> Option<bool> {
    let mut best: Option<(usize, bool)> = None;
    for line in mountinfo.lines() {
        // mountinfo fields: id parent major:minor root MOUNT_POINT OPTIONS <optional...> - fstype ...
        // Mount point (index 4) and the per-mount VFS options (index 5) sit before the variable
        // optional fields, so their positions are fixed.
        let mut fields = line.split(' ');
        let Some(mount_point) = fields.nth(4).map(unescape_octal) else {
            continue;
        };
        let Some(options) = fields.next() else {
            continue;
        };
        if target.starts_with(&mount_point) {
            let len = mount_point.as_os_str().len();
            if best.is_none_or(|(best_len, _)| len > best_len) {
                best = Some((len, options.split(',').any(|opt| opt == "nodev")));
            }
        }
    }
    best.map(|(_, nodev)| nodev)
}

/// The nearest existing ancestor of `dir` (possibly `dir` itself), walking up until one exists.
fn nearest_existing(dir: &Path) -> Option<PathBuf> {
    let mut cur = dir;
    loop {
        if cur.exists() {
            return Some(cur.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

/// Decode a mountinfo path's octal escapes (`\040` space, `\011` tab, `\012` newline, `\134`
/// backslash) so a mount point with a space still prefix-matches correctly.
fn unescape_octal(s: &str) -> PathBuf {
    if !s.contains('\\') {
        return PathBuf::from(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    PathBuf::from(OsString::from_vec(out))
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
    fn a_missing_firecracker_defers_the_rows_that_would_judge_it() {
        // Field-found on a fresh host: with no binary at all, the version and sha256 rows used to
        // warn "custom or unpinned binary; verify provenance", judging a binary that does not
        // exist. They must defer to the FAIL row instead of pretending to have checked something.
        let cfg = BootConfig {
            firecracker: "definitely-not-a-real-binary-xyzzy".into(),
            ..Default::default()
        };
        let checks = checks(&cfg);

        let row = |needle: &str| {
            checks
                .iter()
                .find(|c| c.label.contains(needle))
                .expect("a firecracker row matching the needle")
        };
        let on_path = row("firecracker on PATH");
        assert_eq!(on_path.status, CheckStatus::Fail);
        assert!(
            on_path
                .note
                .as_deref()
                .is_some_and(|n| n.contains("https://")),
            "the FAIL row itself says where to get a release, not `see ekvm doctor` circularly"
        );
        for needle in ["supported release", "binary sha256"] {
            let dependent = row(needle);
            assert_eq!(dependent.status, CheckStatus::Warn, "{needle}");
            assert!(
                dependent
                    .note
                    .as_deref()
                    .is_some_and(|n| n.contains("not checked")),
                "`{needle}` must defer, not judge a binary that does not exist"
            );
        }
    }

    #[test]
    fn nodev_scratch_is_detected_from_mountinfo() {
        // A minimal mountinfo: `/` is a normal fs, `/tmp` is tmpfs mounted `nodev` (the modern
        // systemd default that breaks a jailed boot), and `/home` allows device nodes.
        let mi = "\
21 30 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
30 21 0:21 / /tmp rw,nosuid,nodev shared:2 - tmpfs tmpfs rw
40 21 0:22 / /home rw,relatime shared:3 - btrfs /dev/sda2 rw";
        // The jailer's chroot /dev/kvm under /tmp is on the nodev fs, the exact failure case.
        assert_eq!(
            mount_nodev_in(mi, Path::new("/tmp/ekvm-1/root/dev/kvm")),
            Some(true)
        );
        // A scratch dir under $HOME is not nodev, the recommended fix.
        assert_eq!(mount_nodev_in(mi, Path::new("/home/k/.ekvm")), Some(false));
        // Longest-prefix wins: `/tmp` (nodev), not the `/` root it also sits under.
        assert_eq!(mount_nodev_in(mi, Path::new("/tmp")), Some(true));
        // An `nodev`-free path falls through to the non-nodev root.
        assert_eq!(mount_nodev_in(mi, Path::new("/var/lib/ekvm")), Some(false));
    }

    #[test]
    fn mountinfo_octal_escapes_decode() {
        // A mount point with a space is octal-escaped in mountinfo; it must still prefix-match.
        let mi = "50 21 0:23 / /mnt/my\\040scratch rw,nodev shared:4 - ext4 /dev/sdb rw\n\
                  21 30 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw";
        assert_eq!(
            mount_nodev_in(mi, Path::new("/mnt/my scratch/ekvm-1")),
            Some(true)
        );
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
        // The supported-platform floor is present and **hard**, architecture and a
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
        // The host-hardening posture and Firecracker pin are present and advisory:
        // whatever this host's state, those rows never read Fail.
        for needle in ["CPU vulnerability", "SMT", "KSM", "binary sha256"] {
            let row = checks
                .iter()
                .find(|c| c.label.contains(needle))
                .expect("an advisory row");
            assert_ne!(
                row.status,
                CheckStatus::Fail,
                "advisory, never hard: {}",
                row.label
            );
        }
    }

    #[test]
    fn vulnerable_entries_reports_only_files_that_say_vulnerable() {
        let dir = test_support::ScratchDir::created("vulns");
        let write = |name: &str, content: &str| {
            std::fs::write(dir.path().join(name), content).expect("write fixture");
        };
        write("meltdown", "Mitigation: PTI\n");
        write("l1tf", "Not affected\n");
        write(
            "mds",
            "Vulnerable: Clear CPU buffers attempted, no microcode\n",
        );
        write("retbleed", "Vulnerable\n");
        assert_eq!(vulnerable_entries(dir.path()), vec!["mds", "retbleed"]);
    }

    #[test]
    fn a_missing_hardening_fact_reads_as_ok_not_a_guessed_warning() {
        let ghost = Path::new("/definitely/not/a/real/sysfs/dir/xyzzy");
        assert!(vulnerable_entries(ghost).is_empty());
        assert!(!sys_toggle_at(ghost));
    }

    #[test]
    fn a_sys_toggle_reads_nonzero_as_on() {
        assert!(sys_toggle_on("1\n"));
        assert!(sys_toggle_on("2\n"), "KSM run=2 still has KSM enabled");
        assert!(!sys_toggle_on("0\n"));
        assert!(!sys_toggle_on(""));
    }
}
