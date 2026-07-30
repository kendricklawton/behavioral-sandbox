//! `probes-loader`, the userspace side of the eBPF story: load and attach the probes from
//! `crates/probes`, read their maps, and stream events into the audit log. The first probe attaches the
//! one host-global `sys_enter_execve` tracepoint (scoped to nothing); binding a program to a
//! *specific* sandbox (its cgroup, its tap device) arrives with the per-VM taps.
//!
//! **Attach + read a map.** [`ExecveCounter`] loads the compiled BPF object, attaches the
//! `count_execve` tracepoint to `syscalls/sys_enter_execve`, and reads its per-CPU counter map,
//! summing the slots into one total. Synchronous by design: aya's load/attach/array-read path takes
//! no async runtime, matching the driver's no-background-threads posture. This counts the **host's**
//! `execve` footprint (a microVM's own syscalls never trap here), the introduction
//! that proves the load → attach → read → drop path before the tap monitor binds programs to real taps.
//!
//! **CO-RE and the verifier.** The object is built against BTF, so aya relocates it
//! against the running kernel at load (Compile Once, Run Everywhere, portable across kernels). The
//! program also keeps a per-PID hash map, surfaced here as
//! [`counts_by_pid`](ExecveCounter::counts_by_pid); its lookup-or-init and bounded-loop patterns are
//! the verifier rules the eBPF side hits on purpose.
//!
//! **Drops with the loader.** [`ExecveCounter`] owns the aya [`Ebpf`], whose `Drop`
//! detaches the program (dropping the link) and frees the map. Nothing is **pinned** into
//! `/sys/fs/bpf`, so there is no kernel residue to leak: a crashed loader leaves no dangling
//! attachment, the eBPF analogue of the driver's no-leak teardown. Pinning stays opt-in, added only
//! where a program must outlive its loader (not here).
//!
//! **A per-event syscall trace, filtered to one sandbox.** [`SyscallTracer`] loads the
//! same object but attaches the three `sys_enter_{execve,openat,connect}` tracepoints, each of which
//! streams a whole [`SyscallEvent`] (pid, tid, cgroup id, `comm`, and the path or sockaddr bytes) into
//! a **ring buffer** the tracer drains with [`drain`](SyscallTracer::drain). Where [`ExecveCounter`]
//! answers "how many", the tracer answers "which, by whom, on what". Point it at one Firecracker
//! worker with [`watch_pid`](SyscallTracer::watch_pid) /
//! [`watch_cgroup`](SyscallTracer::watch_cgroup) so it records that sandbox's host footprint and not
//! the whole machine's. Still the host's footprint, not the guest's (a microVM's syscalls stay
//! in-guest).
//!
//! **A live trace, attributed to a sandbox.** [`stream`](SyscallTracer::stream) is the
//! streaming consumer: it loops, decoding each event with [`SyscallEvent::describe`] and handing it to
//! a callback as it arrives, until a caller predicate says stop. [`cgroup_id_of_pid`] closes the loop
//! with the Firecracker track: hand it a sandbox's VMM pid, `watch_cgroup` the id it returns, and the
//! trace is scoped to exactly that sandbox (the `bpf_get_current_cgroup_id` a program reads equals the
//! inode of the cgroup dir the jailer placed the VMM in).
//!
//! **Network flows on the tap.** [`TapMonitor`] attaches the two `tc`/clsact classifiers
//! (`tap_ingress`/`tap_egress`) to a VM's tap and reads their per-flow byte/packet counters with
//! [`flows`](TapMonitor::flows), or the per-VM rollup with [`totals`](TapMonitor::totals). This
//! is the guest's *own* traffic (every packet crosses the tap on the host), the strong cross-boundary
//! signal syscalls can't be. [`attach_in_netns`](TapMonitor::attach_in_netns) binds the *specific* tap
//! the driver named for one sandbox by entering that sandbox's netns;
//! [`attach`](TapMonitor::attach) takes an interface in the current netns.
//!
//! **Egress enforcement.** [`set_egress_policy`](TapMonitor::set_egress_policy) installs an
//! [`EgressPolicy`] (a deny-by-default allow-list of destination CIDRs + optional port/proto) into the
//! classifier's policy map and arms enforcement, so the tap drops any guest-sent packet that matches no
//! rule and accepts those that do, per VM. It is opt-in: until set, a monitor stays observe-only (the
//! observe-only default); [`clear_egress_policy`](TapMonitor::clear_egress_policy) returns it there. Every
//! drop is recorded per destination; [`denials`](TapMonitor::denials) reads that audit trail.
//!
//! **Policy at launch, deny-by-default.** [`EgressPolicy`] is the userspace schema, built
//! from validated [`Ipv4Cidr`]s with a typed [`Protocol`] and optional port (`None` = any), whose empty
//! value ([`EgressPolicy::deny_all`], the
//! [`Default`]) allows nothing, a sandbox launched with no explicit allowance reaches nothing.
//! [`enforce_in_netns`](TapMonitor::enforce_in_netns) applies a policy *before* the tc programs go live
//! on a sandbox's tap, so there is no window where the tap is up but un-policed: enforcement is in effect
//! from the first packet.
//!
//! **Per-sandbox resource accounting.** [`ResourceMeter`] attaches the
//! `sched/sched_switch` tracepoint **once** and meters a *set* of cgroups
//! ([`add_target`](ResourceMeter::add_target) per sandbox), so one program stays cheap under many
//! sandboxes; [`cpu_time`](ResourceMeter::cpu_time) reads a cgroup's accumulated on-CPU time. That is the
//! CPU axis; a cgroup's memory high-water mark and IO bytes come from the kernel's own cgroup v2 counters
//! via [`CgroupStats::read`]. [`cgroup_id_of_pid`]/[`cgroup_dir_of_pid`] bridge a VMM pid to the cgroup id
//! (for the meter) and dir (for the stats), and [`summary_for_pid`](ResourceMeter::summary_for_pid) rolls
//! all three axes into a [`ResourceSummary`] for one sandbox. The engine *measures*, the hoster *bills*.
//!
//! **Caps + a legible support probe.** Loading needs only `CAP_BPF`+`CAP_PERFMON`, not
//! full root; [`check_support`] names a missing prerequisite (kernel BTF, or those caps) up front as a
//! typed [`ProbeError::Unsupported`], so a host that can't run the probes says so plainly instead of
//! failing with a cryptic verifier reject or `EPERM` (the eBPF analogue of the driver's dependency
//! guards).
#![forbid(unsafe_code)]

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use aya::Ebpf;

pub use probes_common::{
    FlowCounts, FlowKey, FlowKey6, PolicyRule, PolicyRule6, Protocol, Syscall, SyscallEvent,
    COMM_CAP, DETAIL_CAP, MAX_POLICY_RULES,
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
pub use meter::{CgroupStats, ResourceMeter, ResourceSummary};
pub use tap::{NetStats, TapMonitor};
pub use tracer::{ExecveCounter, SyscallTracer};

/// Deterministic JSON of the record: the machine-readable audit surface, byte-stable and
/// dependency-free (`RunRecord::to_json`). Pure, unit-tested host-safe against a golden.
mod json;
/// The attach bundle: bind the three probes to one sandbox at launch (shared tracer +
/// shared meter, per-VM tap) and roll up a record; detach + finalize on close.
mod observer;
/// The per-run audit record: the fused, deterministically-ordered view of what one run did,
/// aggregated from the three probes. Pure (no aya), so its whole aggregation is unit-tested host-safe.
mod record;
/// Record integrity: an `ed25519` detached signature over the canonical record bytes, so alteration
/// after the producing host is detectable. Host-side key; the guest never sees it.
mod signing;
/// The model-legible projection of the record (`RunRecord::to_summary_json`): the compact, third face
/// for an agent's observe→act loop. A pure view of the record, golden-tested host-safe.
mod summary;

pub use json::AUDIT_SCHEMA_VERSION;
pub use observer::{LiveSnapshot, SandboxProbes, SharedMeter, SharedTracer};
pub use record::{
    AxisGap, DenialRecord, DenialRecord6, FlowRecord, FlowRecord6, NetSection, NotableSyscall,
    RecordSubject, RunRecord, SyscallCounts, SyscallFold, SyscallFootprint, Timing, MAX_NOTABLE,
};
pub use signing::{
    default_key_path, record_hash, verify, verify_chain, ChainError, HostKey, KeyError, TrustedKey,
    VerifyError, MAX_ENVELOPE_BYTES, SIGNED_RECORD_SCHEMA_VERSION,
};
pub use summary::SUMMARY_SCHEMA_VERSION;

/// Env override for the compiled BPF object's location, for a vendored / installed deployment where
/// the object doesn't sit in the source tree's `target/`. Defaults to the `cargo xtask build-probes`
/// output (see [`object_path`]).
const OBJECT_ENV: &str = "EKVM_PROBES_OBJECT";

/// A typed failure from loading/attaching/reading the probes, the loader's analogue of the driver's
/// `VmmError`: a missing prerequisite, a missing object, a kernel load/verify/permission failure, an
/// attach failure, or a map read failure is a typed `Err`, never a panic (the host path never panics).
///
/// `#[non_exhaustive]` like `VmmError`: a new probe or attach mode adds a new failure class as a new
/// variant without breaking a downstream `match` (the crate is pinned by git rev downstream).
#[derive(Debug)]
#[non_exhaustive]
pub enum ProbeError {
    /// The host can't load eBPF at all: a missing prerequisite named up front (no kernel BTF, or the
    /// `CAP_BPF`/`CAP_PERFMON` capabilities), caught by [`check_support`] *before* a load so it reads
    /// legibly instead of surfacing as a cryptic verifier reject or `EPERM`.
    Unsupported(String),
    /// The compiled BPF object couldn't be found or read (build it with `cargo xtask build-probes`).
    Object(String),
    /// Loading/verifying the object or a program into the kernel failed, a verifier reject or a
    /// kernel-feature gap the up-front [`check_support`] didn't catch.
    Load(String),
    /// Attaching a loaded program to its kernel hook failed.
    Attach(String),
    /// Reading a program's map failed.
    Map(String),
    /// The egress policy the caller asked to install is invalid (e.g. more rules than the map holds),
    /// a caller-input error, distinct from a map I/O failure. See [`PolicyError`].
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
    /// Preserve the chain: [`ProbeError::Policy`] wraps a real error, so a caller walking
    /// `.source()` (or downcasting) reaches the [`PolicyError`] instead of a dead end, the same
    /// contract `VmmError` keeps for its wrapped causes.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            _ => None,
        }
    }
}

/// Where the compiled BPF object lives, in precedence order: the `EKVM_PROBES_OBJECT` override, the
/// `cargo xtask build-probes` output under the source tree
/// (`crates/probes/target/bpfel-unknown-none/release/probes`), then the installed copy under the
/// per-host data dir. The object is a *build artifact* (like the guest kernel/rootfs), built
/// separately and loaded at runtime, not linked into this crate.
///
/// The data-dir fallback is what makes a **packaged install** work with no configuration: `install.sh`
/// puts the object there, and the source-tree path is baked at compile time so it simply does not
/// exist on an operator's host. A developer working in the tree still wins, because their built
/// object is checked first.
#[must_use]
pub fn object_path() -> PathBuf {
    let built = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../probes/target/bpfel-unknown-none/release/probes");
    let installed = signing::data_dir().join("probes");
    pick_object_path(
        std::env::var_os(OBJECT_ENV).map(PathBuf::from),
        built.is_file().then_some(built.as_path()),
        installed.is_file().then_some(installed.as_path()),
        &built,
    )
}

/// The pure precedence rule behind [`object_path`]. `built`/`installed` are `Some` only when that
/// candidate actually exists; `fallback` is returned when none do, so the resulting read error names
/// the source-tree path and its "build it with `cargo xtask build-probes`" hint.
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

/// Read the compiled BPF object (from [`object_path`]) and load it into the kernel: `Ebpf::load`
/// parses the ELF and creates the maps (needs `CAP_BPF`). Each probe pulls its typed program handle
/// out of the returned `Ebpf` and loads/attaches it; the `Ebpf` owns everything and tears it down on
/// drop. Shared by every probe's `load`, so the object-read and load errors read the same everywhere.
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

/// The cgroup v2 id of process `pid`, the same `u64` `bpf_get_current_cgroup_id` reports for tasks in
/// that cgroup, so it is exactly what [`SyscallTracer::watch_cgroup`] filters on. This is the **attribution
/// bridge**: take a sandbox's VMM pid from the Firecracker track, resolve its cgroup id here, and
/// [`watch_cgroup`](SyscallTracer::watch_cgroup) it so the trace shows only that sandbox's host
/// footprint (the whole cgroup: the VMM and its threads, not just one tgid).
///
/// It reads the process's **unified** cgroup path from `/proc/<pid>/cgroup` (the `0::/…` line), then
/// returns the inode number of `/sys/fs/cgroup/<path>`, for cgroup v2 that inode *is* the kernel's
/// cgroup id. Pure `std` fs, no `unsafe`. Sugar over [`cgroup_dir_of_pid`] + a stat.
///
/// # Errors
/// [`ProbeError::Map`] if `/proc/<pid>/cgroup` can't be read, has no unified (`0::`) line (a
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
/// [`ProbeError::Map`] if `/proc/<pid>/cgroup` can't be read or has no unified (`0::`) line (a
/// cgroup-v1-only host).
pub fn cgroup_dir_of_pid(pid: u32) -> Result<PathBuf, ProbeError> {
    let proc_path = format!("/proc/{pid}/cgroup");
    let text = std::fs::read_to_string(&proc_path)
        .map_err(|e| ProbeError::Map(format!("read {proc_path}: {e}")))?;
    // The cgroup v2 unified controller is the `0::<path>` line; `<path>` is rooted at the cgroup mount.
    let rel = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| {
            ProbeError::Map(format!(
                "{proc_path} has no unified (0::) cgroup line — a cgroup v2 host is required"
            ))
        })?
        .trim();
    Ok(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// The cgroup v2 id of a cgroup **dir**: its inode number (for cgroup v2 the dir inode *is* the id
/// `bpf_get_current_cgroup_id` reports). Shared by [`cgroup_id_of_pid`] and
/// [`ResourceMeter::summary_for_pid`], so the pid → dir → id resolution lives once.
fn cgroup_id_of_dir(dir: &Path) -> Result<u64, ProbeError> {
    let meta = std::fs::metadata(dir)
        .map_err(|e| ProbeError::Map(format!("stat cgroup dir {}: {e}", dir.display())))?;
    Ok(meta.ino())
}

/// The cgroup id of the current process ([`cgroup_id_of_pid`] of `std::process::id()`), for a
/// self-trace or a test.
///
/// # Errors
/// As [`cgroup_id_of_pid`].
pub fn cgroup_id_of_self() -> Result<u64, ProbeError> {
    cgroup_id_of_pid(std::process::id())
}

/// Whether the host can load eBPF at all, a cheap pre-flight the CLI/`setup` can call before it
/// tries to attach anything. Checks for kernel BTF (`/sys/kernel/btf/vmlinux`), the CO-RE
/// prerequisite. [`check_support`] is the fuller gate (BTF **and** the capabilities), with a legible
/// reason.
#[must_use]
pub fn ebpf_supported() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// `CAP_PERFMON` (bit 38): attaching a program to a tracepoint goes through `perf_event_open`, which
/// this gates. `CAP_BPF` (bit 39): loading programs/maps and reading maps. The two split out of
/// `CAP_SYS_ADMIN` in Linux 5.8, so a loader needs **just these two**, not full root.
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Parse the low 64 bits of the effective-capability mask from `/proc/<pid>/status` text: the hex
/// value on the `CapEff:` line, or `None` when that line is absent or unparseable. Pure (takes the
/// text) so the bit logic is unit-testable without a live `/proc`, the same pure-parser pattern the
/// driver uses for `parse_nofile_soft`.
///
/// Only the trailing 16 hex digits (bits 0-63) are read: `CAP_BPF` (39) and `CAP_PERFMON` (38) both
/// live there, so a hypothetically wider future field can't overflow the parse into a false "no caps."
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

/// Whether an effective-capability `mask` holds both caps the probes need (`CAP_BPF` + `CAP_PERFMON`).
/// Root's mask has every bit, so this is `true` for root and for a `setcap cap_bpf,cap_perfmon+ep`
/// binary alike: the point is that the second, unprivileged path works.
fn mask_has_load_caps(mask: u64) -> bool {
    (mask >> CAP_BPF) & 1 == 1 && (mask >> CAP_PERFMON) & 1 == 1
}

/// Whether this process holds the capabilities the probes need, read from the effective set in
/// `/proc/self/status` (`CapEff:`, a 64-bit hex mask), no `libc`, no `unsafe`. The standard
/// requirement is the two caps; an exotic host with only `CAP_BPF` and a permissive
/// `kernel.perf_event_paranoid` may also manage the tracepoint attach, but this pre-flight names the
/// standard path rather than probing sysctls (a conservative advisory, not the kernel's final say).
fn have_load_caps() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .is_some_and(mask_has_load_caps)
}

/// The eBPF analogue of the driver's Firecracker-version guard: check the host can actually
/// load the probes and, if not, return a **legible typed error naming the requirement**, a BTF-less
/// kernel or missing capabilities, caught here rather than as a cryptic verifier reject or `EPERM`
/// deep in the load. [`ExecveCounter::load`] runs this first; the CLI/`setup` can call it to
/// report eBPF readiness before attempting anything.
///
/// The BTF check is a deliberate engine *baseline*, not just this program's need: the shipped object
/// is built CO-RE (`--btf`) and reading kernel struct fields does need vmlinux BTF,
/// so the engine requires a BTF-enabled kernel uniformly (the modern-distro default) rather than
/// per-program. A kernel lacking it that could still load *this* relocation-free counter program is refused
/// on purpose, so the support story stays one line, not a per-probe matrix.
///
/// # Errors
/// [`ProbeError::Unsupported`] naming the first missing prerequisite (BTF, then capabilities).
pub fn check_support() -> Result<(), ProbeError> {
    // Deliberate baseline (see the fn doc): require vmlinux BTF uniformly for the CO-RE object, even
    // though this relocation-free counter program would load without it.
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
        // A field wider than 64 bits (>16 hex digits) must not overflow the parse to `None` and read
        // as "no caps": we take the low 64 bits, where CAP_BPF/CAP_PERFMON live.
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
        // Host-safe (no eBPF): the resolver reads `/proc/self/cgroup` + the cgroup dir's inode.
        // On a cgroup v2 host it returns a real (nonzero) id; on a v1-only host it errors legibly.
        match cgroup_id_of_self() {
            Ok(id) => assert!(id > 0, "a real cgroup id is nonzero (got {id})"),
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("cgroup v2") || s.contains("0::"),
                    "a resolver failure must name the v2 requirement, got: {s}"
                );
            }
        }
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
        // A developer in the tree gets their freshly built object, not a stale installed one.
        assert_eq!(
            pick_object_path(None, Some(built), Some(installed), built),
            built
        );
        // The packaged case: no source tree on the host, so the installed copy is found with no
        // EKVM_PROBES_OBJECT set. This is what makes an install work unconfigured.
        assert_eq!(
            pick_object_path(None, None, Some(installed), built),
            installed
        );
        // Nothing present: fall back to the source-tree path, whose read error is the actionable one.
        assert_eq!(pick_object_path(None, None, None, built), built);
    }
}
