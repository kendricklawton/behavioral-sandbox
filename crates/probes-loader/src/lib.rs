//! `bsx-probes-loader`, the userspace side of the eBPF story: load and attach the probes from
//! `crates/probes`, read their maps, and stream events into the audit log.
//!
//! Synchronous by design, since aya's load/attach/read path takes no async runtime, matching the
//! driver's no-background-threads posture. Nothing is **pinned** into `/sys/fs/bpf`, so a crashed
//! loader leaves no dangling attachment: each type owns its aya [`Ebpf`], whose `Drop` detaches the
//! program and frees the map.
//!
//! **The four probes, and what each answers:**
//! - **[`ExecveCounter`]** counts the host's `execve` footprint from a per-CPU map. "How many."
//! - **[`SyscallTracer`]** streams whole [`SyscallEvent`]s (pid, tid, cgroup id, `comm`, and the path
//!   or sockaddr bytes) through a ring buffer, drained by [`drain`](SyscallTracer::drain) or followed
//!   live by [`stream`](SyscallTracer::stream). "Which, by whom, on what."
//! - **[`TapMonitor`]** attaches the two `tc`/clsact classifiers to a VM's tap and reads its per-flow
//!   counters ([`flows`](TapMonitor::flows)) or per-VM rollup ([`totals`](TapMonitor::totals)). This is
//!   the guest's *own* traffic, the strong cross-boundary signal syscalls can't be.
//! - **[`ResourceMeter`]** attaches `sched/sched_switch` **once** and meters a *set* of cgroups, so one
//!   program stays cheap under many sandboxes. Memory and IO come from the kernel's own cgroup v2
//!   counters via [`CgroupStats::read`]; [`summary_for_pid`](ResourceMeter::summary_for_pid) rolls all
//!   three axes into a [`ResourceSummary`]. The engine measures, the hoster bills.
//!
//! **Host, not guest.** Every syscall figure here is the VMM's own footprint, since a microVM services
//! its guest's syscalls in-guest and they never trap on the host.
//!
//! **Scoping to one sandbox.** [`cgroup_id_of_pid`] and [`cgroup_dir_of_pid`] bridge a VMM pid to the
//! cgroup id the meter and tracer filter on and the dir the stats read, so a probe records one
//! sandbox's footprint rather than the whole machine's.
//! [`attach_in_netns`](TapMonitor::attach_in_netns) does the same for a tap by entering that sandbox's
//! netns.
//!
//! **Egress enforcement, deny-by-default.** [`EgressPolicy`] is the userspace schema, built from
//! validated [`Ipv4Cidr`]s with a typed [`Protocol`] and optional port, whose empty value allows
//! nothing. [`set_egress_policy`](TapMonitor::set_egress_policy) installs it and arms the classifier,
//! and [`enforce_in_netns`](TapMonitor::enforce_in_netns) applies a policy *before* the tc programs go
//! live, so there is no window where the tap is up but un-policed. Opt-in: until set, a monitor stays
//! observe-only. Every drop is recorded per destination, read back by
//! [`denials`](TapMonitor::denials).
//!
//! **CO-RE.** The object is built against BTF, so aya relocates it against the running kernel at load
//! and one compiled object is portable across kernels.
//!
//! **Caps and a legible support probe.** Loading needs `CAP_BPF` and `CAP_PERFMON` rather than full
//! root, and [`check_support`] names a missing prerequisite up front as a typed
//! [`ProbeError::Unsupported`], so a host that can't run the probes says so plainly instead of failing
//! with a cryptic verifier reject or `EPERM`.
#![forbid(unsafe_code)]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use aya::Ebpf;

pub use bsx_probes_common::{
    COMM_CAP, DETAIL_CAP, FlowCounts, FlowKey, FlowKey6, MAX_POLICY_RULES, PolicyRule, PolicyRule6,
    Protocol, Syscall, SyscallEvent,
};

/// The egress policy and its address types: what an `--allow` string parses into, before any map
/// is touched. No aya, so the policy vocabulary is unit-tested and fuzzed host-safe.
mod egress;
/// Per-sandbox resource accounting: the shared `sched_switch` CPU meter and the cgroup v2 counters
/// read alongside it.
mod meter;
/// The per-VM tap monitor: the tc classifiers on the VM's network device, the flow and denial maps
/// they populate, and the netns join needed to attach inside the VM's namespace.
mod tap;
/// The syscall tracepoints: a single-syscall counter and the multi-syscall tracer.
mod tracer;

pub use egress::{EgressPolicy, Ipv4Cidr, Ipv6Cidr, PolicyError};
pub use meter::ResourceMeter;
pub use tap::TapMonitor;
pub use tracer::{ExecveCounter, SyscallTracer};

/// The attach bundle: binds the probes to one sandbox at launch, rolls up a record, and detaches on
/// close.
mod observer;

pub use observer::{AttachParams, LiveSnapshot, Nic, SandboxProbes, SharedMeter, SharedTracer};

// The record itself lives in `bsx-record`, aya-free so a consumer can verify one off-host without
// linking this loader. Re-exported because these types appear in the attach surface's own signatures, so
// a caller needs them in scope without a second dependency.
pub use bsx_record::{
    AUDIT_SCHEMA_VERSION, AxisGap, CgroupStats, ChainError, DenialRecord, DenialRecord6,
    EgressPosture, FlowRecord, FlowRecord6, HostKey, KeyError, MAX_ENVELOPE_BYTES, MAX_NOTABLE,
    NetSection, NetStats, NotableSyscall, RecordSubject, ResourceSummary, RunRecord,
    SIGNED_RECORD_SCHEMA_VERSION, SUMMARY_SCHEMA_VERSION, SyscallCounts, SyscallFold,
    SyscallFootprint, Timing, TrustedKey, VerifyError, default_key_path, record_hash, verify,
    verify_chain,
};

/// Env override for the compiled BPF object's location, for a vendored / installed deployment where
/// the object doesn't sit in the source tree's `target/`. Defaults to the `cargo xtask build-probes`
/// output (see [`object_path`]).
const OBJECT_ENV: &str = "BSX_PROBES_OBJECT";

/// A typed failure from loading, attaching, or reading the probes, the loader's analogue of the driver's
/// `VmmError`. Every failure class is a typed `Err` rather than a panic.
///
/// `#[non_exhaustive]`, so a new probe or attach mode adds a variant without breaking a downstream
/// `match`.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProbeError {
    /// The host can't load eBPF at all: no kernel BTF, or missing `CAP_BPF`/`CAP_PERFMON`. Caught by
    /// [`check_support`] *before* a load, so it reads legibly instead of as a verifier reject or `EPERM`.
    Unsupported(String),
    /// The compiled BPF object couldn't be found or read (build it with `cargo xtask build-probes`).
    Object(String),
    /// Loading or verifying the object or a program into the kernel failed: a verifier reject, or a
    /// kernel-feature gap the up-front [`check_support`] didn't catch.
    Load(String),
    /// Attaching a loaded program to its kernel hook failed.
    Attach(String),
    /// Reading a program's map failed.
    Map(String),
    /// Resolving a process's cgroup failed, the pid-to-cgroup attribution bridge rather than an eBPF map
    /// read. Includes the cgroup-v1-only host, which has no `0::` line to resolve.
    Cgroup(String),
    /// A shared probe's lock was poisoned by a panic in another thread, reported as a typed error rather
    /// than propagated.
    Poisoned(String),
    /// The egress policy the caller asked to install is invalid, a caller-input error distinct from a map
    /// IO failure. See [`PolicyError`].
    Policy(PolicyError),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(e) => write!(f, "eBPF unsupported here: {e}"),
            Self::Object(e) => write!(f, "eBPF object unavailable: {e}"),
            Self::Load(e) => write!(f, "eBPF load failed: {e}"),
            Self::Attach(e) => write!(f, "eBPF attach failed: {e}"),
            Self::Map(e) => write!(f, "eBPF map read failed: {e}"),
            Self::Cgroup(e) => write!(f, "cgroup resolution failed: {e}"),
            Self::Poisoned(e) => write!(f, "shared probe state poisoned: {e}"),
            Self::Policy(e) => write!(f, "invalid egress policy: {e}"),
        }
    }
}

impl From<PolicyError> for ProbeError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

impl std::error::Error for ProbeError {
    /// Preserves the chain, so a caller walking `.source()` reaches the [`PolicyError`] rather than a dead
    /// end.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            _ => None,
        }
    }
}

/// Where the compiled BPF object lives, in precedence order: the `BSX_PROBES_OBJECT` override, the
/// `cargo xtask build-probes` output under the source tree, then the installed copy under the per-host
/// data dir. The object is a *build artifact* like the guest kernel and rootfs, built separately and
/// loaded at runtime rather than linked into this crate.
///
/// The data-dir fallback is what makes a packaged install work with no configuration, and the
/// source-tree path is baked at compile time so it does not exist on an operator's host. A developer
/// working in the tree still wins, since their built object is checked first.
#[must_use]
pub fn object_path() -> PathBuf {
    let built = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../probes/target/bpfel-unknown-none/release/probes");
    let installed = bsx_record::data_dir().join("probes");
    pick_object_path(
        std::env::var_os(OBJECT_ENV).map(PathBuf::from),
        built.is_file().then_some(built.as_path()),
        installed.is_file().then_some(installed.as_path()),
        &built,
    )
}

/// The pure precedence rule behind [`object_path`]. `built` and `installed` are `Some` only when that
/// candidate exists, and `fallback` is returned when none do, so the resulting read error names the
/// source-tree path and its build hint.
fn pick_object_path(
    env_override: Option<PathBuf>,
    built: Option<&Path>,
    installed: Option<&Path>,
    fallback: &Path,
) -> PathBuf {
    env_override
        .or_else(|| built.map(Path::to_path_buf))
        .or_else(|| installed.map(Path::to_path_buf))
        .unwrap_or_else(|| fallback.to_path_buf())
}

/// Reads the compiled BPF object and loads it into the kernel, parsing the ELF and creating the maps.
/// Each probe pulls its typed program handle out of the returned `Ebpf`, which owns everything and tears
/// it down on drop. Shared by every probe's `load`, so the read and load errors read the same
/// everywhere.
fn load_object() -> Result<Ebpf, ProbeError> {
    let path = object_path();
    let bytes = std::fs::read(&path).map_err(|e| {
        ProbeError::Object(format!(
            "read BPF object {}: {e} (build it with `cargo xtask build-probes`)",
            path.display()
        ))
    })?;
    Ebpf::load(&bytes).map_err(|e| ProbeError::Load(format!("load object: {e}")))
}

/// The cgroup v2 id of process `pid`, the same `u64` `bpf_get_current_cgroup_id` reports, so it is what
/// [`SyscallTracer::watch_cgroup`] filters on. The **attribution bridge**: resolve a sandbox's VMM pid to
/// its cgroup id and watch that, so the trace covers the whole cgroup rather than one tgid.
///
/// Reads the process's unified cgroup path from `/proc/<pid>/cgroup`, then returns the inode number of
/// the cgroup dir, which for cgroup v2 *is* the kernel's cgroup id. Pure `std` fs.
///
/// # Errors
/// [`ProbeError::Cgroup`] if `/proc/<pid>/cgroup` can't be read, has no unified (`0::`) line (a
/// cgroup-v1-only host), or the cgroup dir can't be stat'd.
pub fn cgroup_id_of_pid(pid: u32) -> Result<u64, ProbeError> {
    cgroup_id_of_dir(&cgroup_dir_of_pid(pid)?)
}

/// The **cgroup dir** of process `pid`, `/sys/fs/cgroup/<path>`, where `<path>` is the unified (`0::`)
/// line of `/proc/<pid>/cgroup`. The path half of the bridge: [`cgroup_id_of_pid`] resolves the id
/// for the eBPF CPU meter, this resolves the dir [`CgroupStats::read`] reads the native memory/IO
/// counters from. Given a sandbox's VMM pid (the Firecracker track's `vmm_pid`), the two together scope
/// all three resource axes to that one sandbox's cgroup. Pure `std` fs, no `unsafe`.
///
/// # Errors
/// [`ProbeError::Cgroup`] if `/proc/<pid>/cgroup` can't be read or has no unified (`0::`) line (a
/// cgroup-v1-only host).
pub fn cgroup_dir_of_pid(pid: u32) -> Result<PathBuf, ProbeError> {
    let proc_path = format!("/proc/{pid}/cgroup");
    let text = std::fs::read_to_string(&proc_path)
        .map_err(|e| ProbeError::Cgroup(format!("read {proc_path}: {e}")))?;
    // The cgroup v2 unified controller is the `0::<path>` line, rooted at the cgroup mount.
    let rel = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| {
            ProbeError::Cgroup(format!(
                "{proc_path} has no unified (0::) cgroup line — a cgroup v2 host is required"
            ))
        })?
        .trim();
    Ok(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The cgroup v2 id of a cgroup **dir**, its inode number. Shared by [`cgroup_id_of_pid`] and
/// [`ResourceMeter::summary_for_pid`], so the resolution lives once.
fn cgroup_id_of_dir(dir: &Path) -> Result<u64, ProbeError> {
    let meta = std::fs::metadata(dir)
        .map_err(|e| ProbeError::Cgroup(format!("stat cgroup dir {}: {e}", dir.display())))?;
    Ok(meta.ino())
}

/// The cgroup id of the current process, for a self-trace or a test.
///
/// # Errors
/// As [`cgroup_id_of_pid`].
pub fn cgroup_id_of_self() -> Result<u64, ProbeError> {
    cgroup_id_of_pid(std::process::id())
}

/// Whether the host has kernel BTF, the CO-RE prerequisite, as a cheap pre-flight before attaching
/// anything. [`check_support`] is the fuller gate, BTF **and** the capabilities, with a legible reason.
#[must_use]
pub fn ebpf_supported() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// `CAP_PERFMON` (bit 38): attaching a program to a tracepoint goes through `perf_event_open`, which
/// this gates. `CAP_BPF` (bit 39): loading programs/maps and reading maps. The two split out of
/// `CAP_SYS_ADMIN` in Linux 5.8, so a loader needs **just these two**, not full root.
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Parses the low 64 bits of the effective-capability mask from `/proc/<pid>/status` text, or `None` when
/// the `CapEff:` line is absent or unparseable. Pure, so the bit logic is unit-testable without a live
/// `/proc`.
///
/// Only the trailing 16 hex digits are read: both caps the probes need live there, so a wider future
/// field can't overflow the parse into a false "no caps".
fn parse_cap_eff(status: &str) -> Option<u64> {
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))?
        .trim();
    if hex.is_empty() || !hex.is_ascii() {
        return None;
    }
    let low64 = &hex[hex.len().saturating_sub(16)..];
    u64::from_str_radix(low64, 16).ok()
}

/// Whether an effective-capability `mask` holds both caps the probes need. Root's mask has every bit, so
/// this is `true` for root and for a `setcap cap_bpf,cap_perfmon+ep` binary alike; the point is that the
/// second, unprivileged path works.
fn mask_has_load_caps(mask: u64) -> bool {
    (mask >> CAP_BPF) & 1 == 1 && (mask >> CAP_PERFMON) & 1 == 1
}

/// Whether this process holds the capabilities the probes need, read from `CapEff:` in
/// `/proc/self/status` with no `libc` and no `unsafe`. A host with only `CAP_BPF` and a permissive
/// `kernel.perf_event_paranoid` may also manage the tracepoint attach, so this is a conservative
/// advisory naming the standard path rather than the kernel's final say.
fn have_load_caps() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .is_some_and(mask_has_load_caps)
}

/// Checks the host can load the probes and, if not, returns a **typed error naming the requirement**, so
/// a BTF-less kernel or missing capability is caught here rather than as a verifier reject or `EPERM` deep
/// in the load.
///
/// The BTF check is an engine *baseline* rather than one program's need: the shipped object is built
/// CO-RE, so a BTF-enabled kernel is required uniformly. A kernel lacking it that could still load the
/// relocation-free counter program is refused on purpose, so the support story stays one line rather than
/// a per-probe matrix.
///
/// # Errors
/// [`ProbeError::Unsupported`] naming the first missing prerequisite (BTF, then capabilities).
pub fn check_support() -> Result<(), ProbeError> {
    // The baseline: vmlinux BTF is required uniformly for the CO-RE object, even though the
    // relocation-free counter program would load without it.
    if !ebpf_supported() {
        return Err(ProbeError::Unsupported(
            "kernel BTF (/sys/kernel/btf/vmlinux) is absent — CO-RE eBPF needs a BTF-enabled kernel \
             (CONFIG_DEBUG_INFO_BTF=y)"
                .into(),
        ));
    }
    if !have_load_caps() {
        return Err(ProbeError::Unsupported(
            "missing CAP_BPF and/or CAP_PERFMON — loading and attaching the probes needs both (or \
             root); grant them with `setcap cap_bpf,cap_perfmon+ep <binary>`, or run as root"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_eff_parses_the_effective_line_only() {
        // A real `/proc/self/status` has several `Cap*` rows; only `CapEff:` is the effective set.
        let status = "Name:\tthing\nCapInh:\t0000000000000000\nCapPrm:\tffffffffffffffff\n\
                      CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x0000_01ff_ffff_ffff));
    }

    #[test]
    fn cap_eff_absent_or_malformed_is_none() {
        assert_eq!(parse_cap_eff("CapPrm:\t00\n"), None); // no CapEff line at all
        assert_eq!(parse_cap_eff("CapEff:\tnothex\n"), None); // present but unparseable
        assert_eq!(parse_cap_eff("CapEff:\t\n"), None); // present but empty
        assert_eq!(parse_cap_eff(""), None);
    }

    #[test]
    fn cap_eff_reads_low_64_bits_of_a_hypothetically_wider_field() {
        // A field wider than 64 bits must not overflow the parse to `None` and read as "no caps".
        let both = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        let wide = format!("CapEff:\tdeadbeef{both:016x}\n"); // 8 extra high digits
        assert_eq!(parse_cap_eff(&wide), Some(both));
        assert!(mask_has_load_caps(
            parse_cap_eff(&wide).expect("parse the wide CapEff line")
        ));
    }

    #[test]
    fn load_caps_need_both_bpf_and_perfmon() {
        let both = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        assert!(mask_has_load_caps(u64::MAX)); // root: every bit
        assert!(mask_has_load_caps(both)); // exactly the two (the setcap path)
        assert!(!mask_has_load_caps(1u64 << CAP_BPF)); // CAP_PERFMON missing
        assert!(!mask_has_load_caps(1u64 << CAP_PERFMON)); // CAP_BPF missing
        assert!(!mask_has_load_caps(0)); // none
    }

    #[test]
    fn cap_logic_round_trips_through_the_status_line() {
        let both = (1u64 << CAP_BPF) | (1u64 << CAP_PERFMON);
        let status = format!("CapEff:\t{both:016x}\n");
        assert!(mask_has_load_caps(
            parse_cap_eff(&status).expect("parse the crafted CapEff line")
        ));
    }

    #[test]
    fn cgroup_id_of_self_resolves_or_reports_v1() {
        // Host-safe: the resolver reads `/proc/self/cgroup` and the cgroup dir's inode, so a v2 host
        // returns a nonzero id and a v1-only host errors legibly.
        match cgroup_id_of_self() {
            Ok(id) => assert!(id > 0, "a real cgroup id is nonzero (got {id})"),
            Err(e) => {
                assert!(
                    matches!(e, ProbeError::Cgroup(_)),
                    "a resolver failure is a Cgroup error, got: {e:?}"
                );
                let s = e.to_string();
                assert!(
                    s.contains("cgroup v2") || s.contains("0::"),
                    "a resolver failure must name the v2 requirement, got: {s}"
                );
            }
        }
    }

    #[test]
    fn a_missing_pid_is_a_cgroup_error_not_a_map_error() {
        // `u32::MAX` can never be a live pid, so the resolver's `/proc` read fails as the attribution
        // bridge's error rather than a map read's.
        let err = cgroup_id_of_pid(u32::MAX).expect_err("no /proc entry for a pid past pid_max");
        assert!(
            matches!(err, ProbeError::Cgroup(_)),
            "cgroup resolution failures carry their own variant, got: {err:?}"
        );
        assert!(
            err.to_string()
                .contains(&format!("/proc/{}/cgroup", u32::MAX)),
            "the error names the proc path it read, got: {err}"
        );
    }

    #[test]
    fn object_path_precedence_lets_a_packaged_install_work_unconfigured() {
        let built = Path::new("/src/probes");
        let installed = Path::new("/data/probes");
        let env = PathBuf::from("/env/probes");

        // The env override wins even when both candidates exist.
        assert_eq!(
            pick_object_path(Some(env.clone()), Some(built), Some(installed), built),
            env
        );
        // A developer in the tree gets their freshly built object rather than a stale installed one.
        assert_eq!(
            pick_object_path(None, Some(built), Some(installed), built),
            built
        );
        // The packaged case: no source tree on the host, so the installed copy is found with no
        // BSX_PROBES_OBJECT set. This is what makes an install work unconfigured.
        assert_eq!(
            pick_object_path(None, None, Some(installed), built),
            installed
        );
        // Nothing present: fall back to the source-tree path, whose read error is the actionable one.
        assert_eq!(pick_object_path(None, None, None, built), built);
    }
}
