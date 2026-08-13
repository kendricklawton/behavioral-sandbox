//! Host readiness: does this machine have what the engine needs to boot and confine a sandbox?
//!
//! - **One implementation, two entry points.** `bsx doctor` and `cargo xtask setup` both render
//!   [`checks`], so they ask the host the same questions. Each appends the eBPF row itself, since
//!   that check lives in the probe loader.
//! - **Three states per [`Check`].** [`Ok`](CheckStatus::Ok) present, [`Warn`](CheckStatus::Warn) a
//!   degradation that fails open with a named consequence, [`Fail`](CheckStatus::Fail) a hard
//!   requirement. The isolation boundary, the boot artifacts and the platform floor are never
//!   degradations.
//! - **The hardening rows are advisory.** They name a side-channel exposure the layer *beneath* the
//!   engine carries, not a capability the engine loses, so a single-tenant dev box tripping them is
//!   fine.
//!
//! `unsafe`-free std-only detection; nothing here boots a VM.

use std::path::{Path, PathBuf};

use crate::BootConfig;
use crate::spawn::FcProbe;

/// The version fallback floor (`major.minor`), used only where [`cgroup_kill_under`]'s capability
/// probe cannot run. A version is the wrong proxy on an enterprise kernel: RHEL 9 ships
/// `5.14.0-*.el9` with a decade of backports, which a bare `>= 5.15` test refuses for no safety
/// gain. Neither signal establishes that a kernel is *patched*, so [`KernelVerdict`] names the one
/// it used.
const MIN_KERNEL: (u64, u64) = (5, 15);

/// How a host's kernel qualified, so the [`Check`] note can name the signal it used rather than
/// implying a guarantee it does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelVerdict {
    /// `cgroup.kill` was found in a live cgroup, so the teardown primitive this engine needs is
    /// present, whatever the version string says. Admits RHEL 9's `5.14.0-*.el9`.
    CapabilityVerified,
    /// No cgroup v2 hierarchy to probe, but the version is at or above [`MIN_KERNEL`].
    VersionVerified,
    /// Neither signal qualified.
    Unqualified,
}

/// The supported CPU architectures, `x86_64` only: aarch64 has no hardware or CI lane to test its
/// privileged path on, so this row names an unsupported cross-compile rather than letting it fail
/// obscurely at first boot.
const SUPPORTED_ARCHES: [&str; 1] = ["x86_64"];

/// The consequence line every firecracker-derived row shares when the binary is missing, so they
/// all point at the same first fix.
const NOT_CHECKED_NO_FIRECRACKER: &str =
    "not checked: no firecracker binary found (fix the missing row above first)";

/// The outcome of one host [`Check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The prerequisite is present.
    Ok,
    /// Absent, but the engine degrades rather than refusing: the run works minus what `note` names.
    Warn,
    /// Absent and hard: no boot without it (the isolation boundary, the artifacts).
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
/// detection: reads `/proc`, `/sys`, `/dev`, `PATH` and runs `firecracker --version`, booting
/// nothing.
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
            &match kernel_verdict(Path::new(SYS_CGROUP_ROOT)) {
                KernelVerdict::CapabilityVerified => "host kernel provides cgroup.kill".to_string(),
                _ => format!(
                    "host kernel >= {}.{} (cgroup.kill unprobed)",
                    MIN_KERNEL.0, MIN_KERNEL.1
                ),
            },
            kernel_verdict(Path::new(SYS_CGROUP_ROOT)) != KernelVerdict::Unqualified,
            false,
            &format!(
                "unsupported kernel: no cgroup.kill (the crash-safe teardown primitive, kernel \
                 5.14+) and below the {}.{} fallback floor. Note this checks capability, not patch \
                 level: keeping the kernel patched is the operator's",
                MIN_KERNEL.0, MIN_KERNEL.1
            ),
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
        // The boot artifacts, hard: no kernel or rootfs at the configured paths, no boot.
        Check::new(
            "guest kernel present (BSX_KERNEL)",
            config.kernel.is_file(),
            false,
            "no kernel to boot: `cargo xtask fetch-artifacts`, or point BSX_KERNEL at one",
        ),
        Check::new(
            "guest rootfs present (BSX_ROOTFS)",
            config.rootfs.is_file(),
            false,
            "no rootfs to boot: build one (`cargo xtask build-rootfs`) or set BSX_ROOTFS",
        ),
        Check::new(
            &format!("firecracker on PATH ({fc})"),
            fc_present,
            false,
            &format!(
                "no VMM to launch: install firecracker + jailer ({}) from \
                 https://github.com/firecracker-microvm/firecracker/releases, or set \
                 BSX_FIRECRACKER",
                supported_range()
            ),
        ),
        // With no binary these two have judged nothing, so their note collapses to a deferral:
        // "custom or unpinned" about a binary that is absent misleads.
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
                NOT_CHECKED_NO_FIRECRACKER
            },
        ),
        Check::new(
            "firecracker binary sha256 matches pinned release",
            fc_present && firecracker_hash_matches(&fc),
            true,
            if fc_present {
                "custom or unpinned Firecracker binary on host; verify binary provenance out of band"
            } else {
                NOT_CHECKED_NO_FIRECRACKER
            },
        ),
        // The jailer path, fails open: `--unjailed` still boots (behind the KVM boundary).
        Check::new(
            "real root (euid 0: the jailer mknod's device nodes)",
            crate::sweep::own_euid() == Some(0),
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
        // Informational, never a warning: a MAC is the normal posture. It earns a row because its
        // denials surface as a bare EPERM naming no LSM, which reads as an engine bug, and
        // `matrix()` carries the "check the audit log first" pointer.
        Check::new(
            &match mac_posture(Path::new(SYS_LSM), Path::new(SYS_SELINUX_ENFORCE)) {
                Some(active) => format!("mandatory access control: {active}"),
                None => "mandatory access control: none loaded".to_string(),
            },
            true,
            true,
            "",
        ),
        // Systemd hosts mount /tmp `nodev` by default, so this catches a jailed boot that would
        // otherwise fail deep in InstanceStart.
        Check::new(
            "scratch dir is not nodev/noexec (the jailer's chroot /dev/kvm and VMM binary live there)",
            !scratch_mount_flags(&config.scratch_dir).is_some_and(MountFlags::blocks_jail),
            true,
            "jailed boot fails: scratch filesystem is mounted `nodev` or `noexec`; use default `/var/tmp` or `--unjailed`",
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
        // Host hardening, advisory: the multi-tenant baseline is `docs/security-threat-model.md`.
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
        Check::new(
            "yama ptrace_scope restricts same-uid ptrace",
            ptrace_scope_restricts_at(Path::new(PROC_YAMA_PTRACE_SCOPE)),
            true,
            "concurrent sandboxes share one jail uid, so a guest that escapes into its own VMM \
             could attach to a co-resident sandbox's VMM and read its guest memory: \
             `sysctl -w kernel.yama.ptrace_scope=1`. Signalling between them is not gated by this \
             and is bounded only by giving each sandbox its own id (docs/embedding-scope.md)",
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
        "  scratch dir nodev/noexec     -> jailed chroot can't open /dev/kvm or exec the VMM; repoint BSX_SCRATCH_DIR",
        "  ip / mke2fs / e2fsprogs      -> only --net or bulk-I/O runs fail; others are unaffected",
        "  SMT / KSM / CPU vulns        -> advisory hardening baseline: docs/security-threat-model.md",
        "  a MAC LSM is loaded          -> selinux/apparmor denials arrive as a bare EPERM naming",
        "                                  no LSM, so a jailed boot that fails oddly reads as an",
        "                                  engine bug. Check the audit log first:",
        "                                  ausearch -m AVC -ts recent   (selinux)",
        "                                  dmesg | grep -i apparmor     (apparmor)",
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

/// Whether a jailed run (the default) works on this host as invoked right now: real root *and* the
/// `jailer` binary. Not a readiness check, since an unjailed run is still a valid boot: a caller
/// uses it to suggest a first-run command that works here.
#[must_use]
pub fn jailed_run_available() -> bool {
    crate::sweep::own_euid() == Some(0) && command_on_path("jailer")
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
    resolve_binary_path(bin).is_some()
}

/// The supported Firecracker range as an operator-facing string (`v1.14..=v1.16`), rendered from
/// the two constants so the report can never name a range the driver does not actually accept.
fn supported_range() -> String {
    let (lo_maj, lo_min) = crate::spawn::MIN_SUPPORTED_FC_VERSION;
    let (hi_maj, hi_min) = crate::spawn::PINNED_FC_VERSION;
    format!("v{lo_maj}.{lo_min}..=v{hi_maj}.{hi_min}, tested on v{hi_maj}.{hi_min}")
}

/// `(major, minor)` of `<fc> --version`, or `None` if the binary is missing, wedged, or prints
/// something that does not parse. The driver's own probe, not a second copy, so this reports the
/// version the driver validates against and inherits its wall and its file-not-pipe stdout.
fn firecracker_version(fc: &str) -> Option<(u64, u64)> {
    match crate::spawn::probe_fc_version(Path::new(fc)) {
        FcProbe::Version(v) => Some(v),
        FcProbe::Unavailable | FcProbe::Unparseable => None,
    }
}

/// sha256 of the pinned release's `firecracker` binary, not the tarball: the check hashes the
/// resolved binary on `PATH`. Only supported releases belong here, since a stale hash would bless a
/// VMM upstream no longer patches.
const PINNED_FIRECRACKER_SHA256: &[&str] = &[
    "2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7", // v1.16.1
];

/// Where `bin` resolves: a path with a directory component is judged as that path, a bare name is
/// searched along `PATH` in order. The one resolution behind both this and [`command_on_path`], so
/// the row reporting a binary present and the row hashing it cannot mean different files.
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
    // sha2 0.11 returns RustCrypto's `Array` rather than `GenericArray`, and that type does not
    // implement `LowerHex`, so the digest is formatted byte by byte instead of with `{:x}`.
    Some(hasher.finalize().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    }))
}

/// The mandatory-access-control LSMs named in `lsm_list` (the contents of [`SYS_LSM`]), in the
/// kernel's own order. Filtered to [`MAC_LSMS`], so the row names only modules that can deny a
/// jailer operation.
fn mac_lsms_in(lsm_list: &str) -> Vec<String> {
    lsm_list
        .trim()
        .split(',')
        .map(str::trim)
        .filter(|m| MAC_LSMS.contains(m))
        .map(str::to_string)
        .collect()
}

/// A human phrase for the active MAC posture, or `None` when no MAC LSM is loaded. SELinux alone
/// distinguishes enforcing from permissive, which decides whether a denial blocks or is only
/// logged.
fn mac_posture(lsm_path: &Path, selinux_enforce_path: &Path) -> Option<String> {
    let list = std::fs::read_to_string(lsm_path).ok()?;
    let active = mac_lsms_in(&list);
    if active.is_empty() {
        return None;
    }
    let mode = if active.iter().any(|m| m == "selinux") {
        match std::fs::read_to_string(selinux_enforce_path)
            .ok()
            .map(|s| s.trim().to_string())
            .as_deref()
        {
            Some("1") => " (enforcing)",
            Some("0") => " (permissive)",
            _ => "",
        }
    } else {
        ""
    };
    Some(format!("{}{mode}", active.join(", ")))
}

/// `major.minor` from a `/proc/sys/kernel/osrelease` string. Split out from the read so the
/// enterprise-kernel shapes (`5.14.0-427.el9_4.x86_64`) are testable without that host.
fn parse_osrelease(s: &str) -> Option<(u64, u64)> {
    let mut it = s
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty());
    Some((
        it.next()?.parse::<u64>().ok()?,
        it.next()?.parse::<u64>().ok()?,
    ))
}

/// Whether the running kernel is at least `major.minor`, from `/proc/sys/kernel/osrelease`.
fn kernel_at_least(major: u64, minor: u64) -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|s| parse_osrelease(&s))
        .is_some_and(|v| v >= (major, minor))
}

/// Whether any cgroup under `root` exposes `cgroup.kill`, the crash-safe teardown primitive
/// `lifetime.rs` depends on. Scanned one level down because it is a non-root interface file, so
/// `<root>/cgroup.kill` reports absent on a host that has it.
fn cgroup_kill_under(root: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.path().join("cgroup.kill").exists())
}

/// Which signal, if any, qualifies this host's kernel. Capability first: a probed `cgroup.kill`
/// beats a version string, which is what admits a patched enterprise kernel below [`MIN_KERNEL`].
fn kernel_verdict(cgroup_root: &Path) -> KernelVerdict {
    if cgroup_kill_under(cgroup_root) {
        KernelVerdict::CapabilityVerified
    } else if kernel_at_least(MIN_KERNEL.0, MIN_KERNEL.1) {
        KernelVerdict::VersionVerified
    } else {
        KernelVerdict::Unqualified
    }
}

/// The cgroup v2 root, scanned one level down for `cgroup.kill` by [`cgroup_kill_under`].
const SYS_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The kernel's list of active LSMs, comma-separated. Asking the kernel which modules are loaded
/// is the distro-independent form of "will something deny the jailer".
const SYS_LSM: &str = "/sys/kernel/security/lsm";

/// SELinux's enforcing toggle: `1` blocks and logs, `0` only logs. Absent when SELinux is not the
/// active LSM.
const SYS_SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";

/// The LSMs applying mandatory access control to what the jailer does (chroot, `mknod`, bind
/// mounts, uid drop). The rest of the kernel's list does not arbitrate those, so naming them would
/// be noise.
const MAC_LSMS: [&str; 4] = ["selinux", "apparmor", "smack", "tomoyo"];

/// The sysfs facts behind the host-hardening advisory rows: the per-vulnerability mitigation files,
/// whether SMT is active, whether KSM is merging, and Yama's `ptrace` scope.
const SYS_CPU_VULNERABILITIES: &str = "/sys/devices/system/cpu/vulnerabilities";
const SYS_SMT_ACTIVE: &str = "/sys/devices/system/cpu/smt/active";
const SYS_KSM_RUN: &str = "/sys/kernel/mm/ksm/run";
const PROC_YAMA_PTRACE_SCOPE: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// The entries under `dir` (one file per CPU vulnerability) whose content reports `Vulnerable`,
/// sorted so the advisory note is stable. A missing or unreadable dir reads as no exposure: an
/// absent fact never raises a guessed warning (the [`scratch_mount_flags`] posture).
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

/// Whether Yama restricts `ptrace` between processes that share a uid but no ancestry.
fn ptrace_scope_restricts_at(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|s| ptrace_scope_restricts(&s))
}

/// The pure parse behind [`ptrace_scope_restricts_at`]: `0` lets any same-uid process attach, while
/// `1`, `2` and `3` all deny a sibling. Unparseable reads as unrestricted, so an absent fact raises
/// the advisory rather than clearing it.
fn ptrace_scope_restricts(content: &str) -> bool {
    content.trim().parse::<u32>().is_ok_and(|level| level >= 1)
}

/// Whether cgroup v2 `cpu`+`memory` are delegated at the root (a systemd host does this by
/// default), so the jailer can cap a jailed VM's CPU/memory.
fn cgroup_controllers_delegated() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .map(|s| {
            let toks: Vec<&str> = s.split_whitespace().collect();
            toks.contains(&"cpu") && toks.contains(&"memory")
        })
        .unwrap_or(false)
}

/// The two mount flags that make a scratch filesystem unusable for a jailed boot: `nodev` makes the
/// jailer's chroot `/dev/kvm` inert, `noexec` makes its firecracker copy unrunnable. One probe for
/// both, since they share a mountinfo field and fail the same boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountFlags {
    pub nodev: bool,
    pub noexec: bool,
}

impl MountFlags {
    /// Whether either flag would fail a jailed boot.
    #[must_use]
    pub fn blocks_jail(self) -> bool {
        self.nodev || self.noexec
    }
}

/// The jail-relevant [`MountFlags`] of the filesystem holding `dir`, or `None` when they can't be
/// determined, so "unknown" reads as "assume fine" rather than a false alarm. Public for the guided
/// install; a diagnostic helper, not part of the pinned `Sandbox`/`Limits`/`RunResult` surface.
pub fn scratch_mount_flags(dir: &Path) -> Option<MountFlags> {
    // The scratch dir may not exist yet, and its nearest existing ancestor is on the same
    // filesystem the chroot will be created on, since mkdir does not cross a mount.
    let target = nearest_existing(dir)?.canonicalize().ok()?;
    let mountinfo = crate::mountinfo::self_text()?;
    mount_flags_in(&mountinfo, &target)
}

/// The [`MountFlags`] of the mount holding `target`, selected by [`crate::mountinfo::covering`],
/// the same selection the jailed boot judges by. `None` only on malformed input, since an absolute
/// path is always covered by `/`.
fn mount_flags_in(mountinfo: &str, target: &Path) -> Option<MountFlags> {
    let mount = crate::mountinfo::covering(mountinfo, target)?;
    Some(MountFlags {
        nodev: mount.options.split(',').any(|opt| opt == "nodev"),
        noexec: mount.options.split(',').any(|opt| opt == "noexec"),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `BSX_FIRECRACKER` may name a wrapper script, and a wrapper that backgrounds anything
    /// inheriting its stdout keeps the pipe's write end open after the wrapper is reaped: a read
    /// blocks for as long as the background process lives, which is why the probe hands the child
    /// a file.
    #[test]
    fn a_firecracker_wrapper_that_backgrounds_a_child_does_not_stall_the_report() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::Duration;

        let dir = bsx_test_support::ScratchDir::created("doctor-fcver");
        let fc = dir.path().join("fc-background");
        // Prints its version and exits 0 at once, having handed its stdout to a process that
        // outlives it by half a minute.
        std::fs::write(
            &fc,
            "#!/bin/sh\nsleep 30 &\necho 'Firecracker v1.16.1'\nexit 0\n",
        )
        .expect("write the wrapper");
        std::fs::set_permissions(&fc, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let fc = fc.to_str().expect("a utf-8 scratch path").to_string();

        // A stall is not a test failure unless the test bounds it: the probe runs on its own
        // thread and this receive is the bound, three seconds being well under the background
        // child's thirty and well over the milliseconds a wrapper that exits takes.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(firecracker_version(&fc));
        });
        let probed = rx.recv_timeout(Duration::from_secs(3)).expect(
            "the report must be back while the wrapper's background child still holds its stdout",
        );
        assert_eq!(
            probed,
            Some((1, 16)),
            "the version is read from the file the wrapper wrote, not from a pipe nothing closes"
        );
    }

    /// The kernel reports every loaded LSM, most of which never arbitrate a jailer operation.
    /// Naming those would make the row noise.
    #[test]
    fn only_the_mandatory_access_control_lsms_are_named() {
        // This host's actual list (measured 2026-07-29): no MAC module at all.
        assert!(mac_lsms_in("capability,landlock,lockdown,yama,bpf").is_empty());
        // RHEL and Ubuntu shapes.
        assert_eq!(mac_lsms_in("capability,selinux"), vec!["selinux"]);
        assert_eq!(
            mac_lsms_in("capability,landlock,lockdown,yama,apparmor"),
            vec!["apparmor"]
        );
        assert_eq!(mac_lsms_in(""), Vec::<String>::new());
    }

    /// SELinux permissive logs without blocking, which is a materially different thing to tell an
    /// operator staring at a failed boot, so the row distinguishes them.
    #[test]
    fn selinux_reports_enforcing_separately_from_permissive() {
        let tmp = bsx_test_support::ScratchDir::created("doctor-lsm");
        let lsm = tmp.path().join("lsm");
        let enforce = tmp.path().join("enforce");

        std::fs::write(&lsm, "capability,selinux\n").expect("write");
        std::fs::write(&enforce, "1\n").expect("write");
        assert_eq!(
            mac_posture(&lsm, &enforce).as_deref(),
            Some("selinux (enforcing)")
        );

        std::fs::write(&enforce, "0\n").expect("write");
        assert_eq!(
            mac_posture(&lsm, &enforce).as_deref(),
            Some("selinux (permissive)")
        );

        // AppArmor has no equivalent toggle here, so it reports presence only, and the missing
        // selinux file must not be read as permissive.
        std::fs::write(&lsm, "capability,apparmor\n").expect("write");
        assert_eq!(
            mac_posture(&lsm, Path::new("/nonexistent")).as_deref(),
            Some("apparmor")
        );

        // No MAC loaded is None, not an empty string: the row says "none loaded" rather than
        // rendering a blank.
        std::fs::write(&lsm, "capability,yama\n").expect("write");
        assert_eq!(mac_posture(&lsm, &enforce), None);
        assert_eq!(mac_posture(Path::new("/nonexistent"), &enforce), None);
    }

    /// The shapes that motivated the capability probe: RHEL 9 parses *below* the fallback floor,
    /// so a version-only check refuses a kernel Red Hat patches until 2032.
    #[test]
    fn osrelease_parses_the_enterprise_kernel_shapes() {
        assert_eq!(parse_osrelease("5.14.0-427.el9_4.x86_64"), Some((5, 14)));
        assert_eq!(parse_osrelease("6.12.0-55.el10_0.x86_64"), Some((6, 12)));
        assert_eq!(parse_osrelease("4.18.0-553.el8_10.x86_64"), Some((4, 18)));
        assert_eq!(parse_osrelease("6.8.0-51-generic"), Some((6, 8)));
        assert_eq!(parse_osrelease("7.0.11-arch1-1"), Some((7, 0)));
        assert_eq!(parse_osrelease("not-a-version"), None);

        assert!(
            parse_osrelease("5.14.0-427.el9_4.x86_64").unwrap() < MIN_KERNEL,
            "RHEL 9 must sit below the fallback floor, else this test guards nothing"
        );
    }

    /// `cgroup.kill` is a **non-root** interface file. A probe that looked at `<root>/cgroup.kill`
    /// would report absent on every host that has it.
    #[test]
    fn cgroup_kill_is_found_one_level_down_not_at_the_root() {
        let tmp = bsx_test_support::ScratchDir::created("doctor-cgkill");
        let root = tmp.path();
        assert!(!cgroup_kill_under(root), "empty root must not qualify");

        std::fs::write(root.join("cgroup.kill"), "").expect("write");
        assert!(
            !cgroup_kill_under(root),
            "a file at the root is not the probe's subject; the kernel never puts one there"
        );

        let scope = root.join("init.scope");
        std::fs::create_dir(&scope).expect("mkdir");
        std::fs::write(scope.join("cgroup.kill"), "").expect("write");
        assert!(cgroup_kill_under(root), "a non-root cgroup must qualify");
    }

    /// A probed capability outranks the version string: that is what admits RHEL 9.
    #[test]
    fn a_probed_cgroup_kill_qualifies_a_kernel_below_the_fallback_floor() {
        let tmp = bsx_test_support::ScratchDir::created("doctor-verdict");
        let scope = tmp.path().join("init.scope");
        std::fs::create_dir(&scope).expect("mkdir");
        std::fs::write(scope.join("cgroup.kill"), "").expect("write");

        assert_eq!(
            kernel_verdict(tmp.path()),
            KernelVerdict::CapabilityVerified,
            "cgroup.kill present must qualify without consulting the version"
        );

        // With nothing to probe, the verdict falls back to the version floor. This host is above
        // it, so the assertion is that the fallback *ran*, not that any host passes.
        let empty = bsx_test_support::ScratchDir::created("doctor-empty");
        assert_ne!(
            kernel_verdict(empty.path()),
            KernelVerdict::CapabilityVerified,
            "an unprobeable root must not report a capability it never saw"
        );
    }

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

        // The other branch: a name carrying a directory component is judged as a path rather than
        // searched for, covered here because the presence rows and the sha256 row must resolve
        // through the same function.
        let resolved = resolve_binary_path("sh").expect("sh resolves to a path");
        assert!(
            resolved.is_absolute(),
            "PATH entries are absolute: {resolved:?}"
        );
        assert!(command_on_path(&resolved.to_string_lossy()));
        assert!(!command_on_path("./definitely-not-a-real-binary-xyzzy"));
    }

    #[test]
    fn a_missing_firecracker_defers_the_rows_that_would_judge_it() {
        // With no binary at all, "custom or unpinned binary; verify provenance" would be a verdict
        // on a binary that does not exist, so both rows must defer to the FAIL row.
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
            "the FAIL row itself says where to get a release, not `see bsx doctor` circularly"
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
    fn jail_blocking_mount_flags_are_detected_from_mountinfo() {
        const CLEAR: MountFlags = MountFlags {
            nodev: false,
            noexec: false,
        };
        // `/tmp` is tmpfs mounted `nodev` (the modern systemd default), and `/srv` carries both
        // flags where `/opt` carries `noexec` alone, so each flag must read independently.
        let mi = "\
21 30 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
30 21 0:21 / /tmp rw,nosuid,nodev shared:2 - tmpfs tmpfs rw
40 21 0:22 / /home rw,relatime shared:3 - btrfs /dev/sda2 rw
41 21 0:23 / /srv rw,nosuid,nodev,noexec shared:4 - ext4 /dev/sda3 rw
42 21 0:24 / /opt rw,nosuid,noexec shared:5 - ext4 /dev/sda4 rw";
        // The jailer's chroot /dev/kvm under /tmp is on the nodev fs, the exact failure case.
        assert_eq!(
            mount_flags_in(mi, Path::new("/tmp/bsx-1/root/dev/kvm")),
            Some(MountFlags {
                nodev: true,
                noexec: false
            })
        );
        // A scratch dir under $HOME carries neither flag, the recommended fix.
        assert_eq!(mount_flags_in(mi, Path::new("/home/k/.bsx")), Some(CLEAR));
        // Longest-prefix wins: `/tmp` (nodev), not the `/` root it also sits under.
        assert!(mount_flags_in(mi, Path::new("/tmp")).is_some_and(MountFlags::blocks_jail));
        // A flag-free path falls through to the unrestricted root.
        assert_eq!(mount_flags_in(mi, Path::new("/var/lib/bsx")), Some(CLEAR));
        // `noexec` alone blocks a jail (the chrooted firecracker copy can't exec), and both
        // flags together read as both.
        assert_eq!(
            mount_flags_in(mi, Path::new("/opt/bsx")),
            Some(MountFlags {
                nodev: false,
                noexec: true
            })
        );
        assert_eq!(
            mount_flags_in(mi, Path::new("/srv/bsx")),
            Some(MountFlags {
                nodev: true,
                noexec: true
            })
        );
    }

    #[test]
    fn an_overmount_reports_the_topmost_entrys_flags() {
        // With two mounts at one point the visible filesystem is the topmost, the *last* mountinfo
        // line, and reporting the buried line lets doctor bless a scratch base the jailed boot
        // then refuses (or the reverse).
        let restrictive_buried = "\
21 30 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
30 21 0:24 / /scratch rw,nodev,noexec shared:2 - tmpfs a rw
31 21 0:25 / /scratch rw,relatime shared:3 - ext4 /dev/sdb rw";
        assert_eq!(
            mount_flags_in(restrictive_buried, Path::new("/scratch/bsx-1")),
            Some(MountFlags {
                nodev: false,
                noexec: false
            }),
            "the topmost overmount is clear, so the flags read clear"
        );
        let clear_buried = "\
21 30 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
30 21 0:24 / /scratch rw,relatime shared:2 - ext4 /dev/sdb rw
31 21 0:25 / /scratch rw,nodev,noexec shared:3 - tmpfs a rw";
        assert!(
            mount_flags_in(clear_buried, Path::new("/scratch/bsx-1"))
                .is_some_and(MountFlags::blocks_jail),
            "the topmost overmount carries the flags, so they read set"
        );
    }

    #[test]
    fn mountinfo_octal_escapes_decode() {
        // A mount point with a space is octal-escaped in mountinfo; it must still prefix-match.
        let mi = "50 21 0:23 / /mnt/my\\040scratch rw,nodev shared:4 - ext4 /dev/sdb rw\n\
                  21 30 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw";
        assert!(
            mount_flags_in(mi, Path::new("/mnt/my scratch/bsx-1"))
                .is_some_and(|f| f.nodev && !f.noexec)
        );
    }

    #[test]
    fn checks_cover_the_engine_prerequisites() {
        let cfg = BootConfig::default();
        let checks = checks(&cfg);
        // The isolation boundary and the artifacts are present as hard checks.
        assert!(checks.iter().any(|c| c.label.contains("/dev/kvm present")));
        assert!(
            checks
                .iter()
                .any(|c| c.label.contains("kernel") && c.status != CheckStatus::Warn)
        );
        // The jailer path is a degradation, not hard (unjailed exists).
        let jailer = checks
            .iter()
            .find(|c| c.label.contains("jailer"))
            .expect("a jailer check");
        assert!(matches!(jailer.status, CheckStatus::Ok | CheckStatus::Warn));
        // The supported-platform floor is **hard**: an off-platform host is refused, not warned.
        let arch = checks
            .iter()
            .find(|c| c.label.contains("architecture"))
            .expect("an architecture check");
        assert_ne!(
            arch.status,
            CheckStatus::Warn,
            "the platform floor is hard, never a degradation"
        );
        // The row states whichever signal qualified the host, so match either wording rather than
        // pinning the one this host happens to produce. "host kernel", not "kernel": the latter
        // also matches "guest kernel present", and a `find` that silently takes the wrong row is
        // how a test passes on something other than its subject.
        let kernel = checks
            .iter()
            .find(|c| c.label.starts_with("host kernel"))
            .expect("a host-kernel check");
        assert!(
            kernel.label.contains("cgroup.kill") || kernel.label.contains("host kernel >="),
            "the kernel row must name its signal, got {:?}",
            kernel.label
        );
        assert_ne!(
            kernel.status,
            CheckStatus::Warn,
            "the kernel floor is hard, never a degradation"
        );
        // The host-hardening posture and the Firecracker pin are advisory: whatever this host's
        // state, those rows never read Fail.
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
        let dir = bsx_test_support::ScratchDir::created("vulns");
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
    fn ptrace_scope_reads_every_documented_level_and_fails_toward_the_warning() {
        // 0 is the classic same-uid-may-attach behavior; 1 (descendants), 2 (admin) and 3 (nobody)
        // each deny a sibling, which is the whole question this check asks.
        assert!(!ptrace_scope_restricts("0\n"));
        for level in ["1\n", "2\n", "3\n"] {
            assert!(ptrace_scope_restricts(level), "{level:?} denies a sibling");
        }
        // A kernel built without Yama has no file at all, which is scope-0 behavior, so unreadable
        // and unparseable must warn rather than clear an advisory on a fact nobody established.
        assert!(!ptrace_scope_restricts(""));
        assert!(!ptrace_scope_restricts("banana\n"));
        assert!(!ptrace_scope_restricts_at(Path::new(
            "/definitely/not/a/real/sysctl/xyzzy"
        )));
    }

    #[test]
    fn a_sys_toggle_reads_nonzero_as_on() {
        assert!(sys_toggle_on("1\n"));
        assert!(sys_toggle_on("2\n"), "KSM run=2 still has KSM enabled");
        assert!(!sys_toggle_on("0\n"));
        assert!(!sys_toggle_on(""));
    }
}
