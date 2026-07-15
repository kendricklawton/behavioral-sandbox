//! `agent-probes-loader` — the userspace side of the eBPF story: load and attach the probes from
//! `crates/probes` to a *specific* sandbox (its cgroup, its tap device), read their maps, and
//! stream events into the flight recorder.
//!
//! **P8.3 — attach + read a map.** [`ExecveCounter`] loads the compiled BPF object, attaches the
//! `count_execve` tracepoint to `syscalls/sys_enter_execve`, and reads its per-CPU counter map,
//! summing the slots into one total. Synchronous by design: aya's load/attach/array-read path takes
//! no async runtime, matching the driver's no-background-threads posture. This counts the **host's**
//! `execve` footprint (a microVM's own syscalls never trap here; see ROADMAP Phase 9) — the on-ramp
//! that proves the load → attach → read → drop path before Phase 10 binds programs to real taps.
//!
//! **P8.5/P8.6 — CO-RE and the verifier.** The object is built against BTF, so aya relocates it
//! against the running kernel at load (Compile Once, Run Everywhere — portable across kernels). The
//! program also keeps a per-PID hash map, surfaced here as
//! [`counts_by_pid`](ExecveCounter::counts_by_pid); its lookup-or-init and bounded-loop patterns are
//! the verifier rules the eBPF side hits on purpose.
//!
//! **P8.4 — drops with the loader.** [`ExecveCounter`] owns the aya [`Ebpf`], whose `Drop`
//! detaches the program (dropping the link) and frees the map. Nothing is **pinned** into
//! `/sys/fs/bpf`, so there is no kernel residue to leak: a crashed loader leaves no dangling
//! attachment, the eBPF analogue of the driver's no-leak teardown. Pinning stays opt-in, added only
//! where a program must outlive its loader (not here).
//!
//! **P8.8/P8.9 — caps + a legible support probe.** Loading needs only `CAP_BPF`+`CAP_PERFMON`, not
//! full root; [`check_support`] names a missing prerequisite (kernel BTF, or those caps) up front as a
//! typed [`ProbeError::Unsupported`], so a host that can't run the probes says so plainly instead of
//! failing with a cryptic verifier reject or `EPERM` (the eBPF analogue of the driver's dependency
//! guards, P6.9b).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use aya::maps::{HashMap as AyaHashMap, PerCpuArray};
use aya::programs::TracePoint;
use aya::Ebpf;

/// Env override for the compiled BPF object's location — for a vendored / installed deployment where
/// the object doesn't sit in the source tree's `target/`. Defaults to the `cargo xtask build-probes`
/// output (see [`object_path`]).
const OBJECT_ENV: &str = "AGENT_PROBES_OBJECT";

/// The tracepoint program's name (its ELF section symbol, set by `#[tracepoint] fn count_execve`).
const PROGRAM: &str = "count_execve";
/// The per-CPU counter map's name (the `#[map] static EXECVE_COUNT` symbol).
const MAP: &str = "EXECVE_COUNT";
/// The per-PID hash map's name (the `#[map] static EXECVE_BY_PID` symbol).
const MAP_BY_PID: &str = "EXECVE_BY_PID";
/// The tracepoint the program attaches to: category `syscalls`, event `sys_enter_execve`.
const TP_CATEGORY: &str = "syscalls";
const TP_NAME: &str = "sys_enter_execve";

/// A typed failure from loading/attaching/reading the probes — the loader's analogue of the driver's
/// `VmmError`: a missing prerequisite, a missing object, a kernel load/verify/permission failure, an
/// attach failure, or a map read failure is a typed `Err`, never a panic (the host path never panics).
#[derive(Debug)]
pub enum ProbeError {
    /// The host can't load eBPF at all: a missing prerequisite named up front (no kernel BTF, or the
    /// `CAP_BPF`/`CAP_PERFMON` capabilities), caught by [`check_support`] *before* a load so it reads
    /// legibly instead of surfacing as a cryptic verifier reject or `EPERM` (P8.9).
    Unsupported(String),
    /// The compiled BPF object couldn't be found or read (build it with `cargo xtask build-probes`).
    Object(String),
    /// Loading/verifying the object or a program into the kernel failed — a verifier reject or a
    /// kernel-feature gap the up-front [`check_support`] didn't catch.
    Load(String),
    /// Attaching a loaded program to its kernel hook failed.
    Attach(String),
    /// Reading a program's map failed.
    Map(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(e) => write!(f, "eBPF unsupported here: {e}"),
            Self::Object(e) => write!(f, "eBPF object unavailable: {e}"),
            Self::Load(e) => write!(f, "eBPF load failed: {e}"),
            Self::Attach(e) => write!(f, "eBPF attach failed: {e}"),
            Self::Map(e) => write!(f, "eBPF map read failed: {e}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// A loaded, attached `sys_enter_execve` counter. Holds the aya [`Ebpf`] that owns the
/// program, its map, and the live attachment; dropping this detaches and frees them, pinning nothing
/// (P8.4). Read the running total with [`count`](ExecveCounter::count).
#[must_use = "dropping an ExecveCounter detaches the probe"]
pub struct ExecveCounter {
    ebpf: Ebpf,
}

impl ExecveCounter {
    /// Load the compiled object, load + attach the `count_execve` tracepoint, and return the live
    /// counter. From here every host `execve` bumps the per-CPU map until this value is dropped.
    ///
    /// # Errors
    /// [`ProbeError::Object`] if the object can't be read (build it: `cargo xtask build-probes`);
    /// [`ProbeError::Load`] if the kernel rejects the object/program (no `CAP_BPF`, no BTF, or a
    /// verifier reject); [`ProbeError::Attach`] if the tracepoint attach fails.
    pub fn load() -> Result<Self, ProbeError> {
        // Name the missing prerequisite up front (P8.9): no kernel BTF, or no CAP_BPF/CAP_PERFMON, is
        // a legible `Unsupported` error here rather than a cryptic verifier reject / `EPERM` below.
        check_support()?;
        let path = object_path();
        let bytes = std::fs::read(&path).map_err(|e| {
            ProbeError::Object(format!(
                "read BPF object {}: {e} (build it with `cargo xtask build-probes`)",
                path.display()
            ))
        })?;
        // `Ebpf::load` parses the ELF and creates the maps in the kernel (needs CAP_BPF); the program
        // is loaded (verified) and attached below. All of it is owned by `ebpf` and torn down on drop.
        let mut ebpf =
            Ebpf::load(&bytes).map_err(|e| ProbeError::Load(format!("load object: {e}")))?;

        let program: &mut TracePoint = ebpf
            .program_mut(PROGRAM)
            .ok_or_else(|| ProbeError::Load(format!("program `{PROGRAM}` not found in object")))?
            .try_into()
            .map_err(|e| {
                ProbeError::Load(format!("program `{PROGRAM}` is not a tracepoint: {e}"))
            })?;
        program
            .load()
            .map_err(|e| ProbeError::Load(format!("verify/load `{PROGRAM}`: {e}")))?;
        program.attach(TP_CATEGORY, TP_NAME).map_err(|e| {
            ProbeError::Attach(format!(
                "attach `{PROGRAM}` to {TP_CATEGORY}/{TP_NAME}: {e}"
            ))
        })?;

        Ok(Self { ebpf })
    }

    /// The running total of `sys_enter_execve` events since [`load`](ExecveCounter::load), summed
    /// across CPUs (the map is per-CPU, so each CPU's slot is read and added).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the counter map is missing or unreadable.
    pub fn count(&self) -> Result<u64, ProbeError> {
        let map = self
            .ebpf
            .map(MAP)
            .ok_or_else(|| ProbeError::Map(format!("map `{MAP}` not found")))?;
        let counter: PerCpuArray<_, u64> = PerCpuArray::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{MAP}` as a per-cpu array: {e}")))?;
        let per_cpu = counter
            .get(&0, 0)
            .map_err(|e| ProbeError::Map(format!("read `{MAP}`[0]: {e}")))?;
        Ok(per_cpu.iter().copied().sum())
    }

    /// The per-PID `execve` counts as `(pid, count)` pairs, read from the `EXECVE_BY_PID` hash map
    /// (P8.6). Order is unspecified (hash-map iteration); the [`count`](ExecveCounter::count) total is
    /// authoritative, since the per-PID map is bounded and drops new keys when full.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn counts_by_pid(&self) -> Result<Vec<(u32, u64)>, ProbeError> {
        let map = self
            .ebpf
            .map(MAP_BY_PID)
            .ok_or_else(|| ProbeError::Map(format!("map `{MAP_BY_PID}` not found")))?;
        let by_pid: AyaHashMap<_, u32, u64> = AyaHashMap::try_from(map)
            .map_err(|e| ProbeError::Map(format!("open `{MAP_BY_PID}` as a hash map: {e}")))?;
        let mut out = Vec::new();
        for entry in by_pid.iter() {
            let (pid, count) =
                entry.map_err(|e| ProbeError::Map(format!("iterate `{MAP_BY_PID}`: {e}")))?;
            out.push((pid, count));
        }
        Ok(out)
    }
}

/// Where the compiled BPF object lives: the `AGENT_PROBES_OBJECT` override if set, else the
/// `cargo xtask build-probes` output under the source tree
/// (`crates/probes/target/bpfel-unknown-none/release/probes`). The object is a *build artifact*
/// (like the guest kernel/rootfs), built separately and loaded at runtime, not linked into this crate.
#[must_use]
pub fn object_path() -> PathBuf {
    if let Some(p) = std::env::var_os(OBJECT_ENV) {
        return PathBuf::from(p);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../probes/target/bpfel-unknown-none/release/probes")
}

/// Whether the host can load eBPF at all — a cheap pre-flight the CLI/`setup` can call before it
/// tries to attach anything. Checks for kernel BTF (`/sys/kernel/btf/vmlinux`), the CO-RE
/// prerequisite. [`check_support`] is the fuller gate (BTF **and** the capabilities), with a legible
/// reason.
#[must_use]
pub fn ebpf_supported() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// `CAP_PERFMON` (bit 38): attaching a program to a tracepoint goes through `perf_event_open`, which
/// this gates. `CAP_BPF` (bit 39): loading programs/maps and reading maps. The two split out of
/// `CAP_SYS_ADMIN` in Linux 5.8, so a loader needs **just these two**, not full root (P8.8).
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Whether this process holds the capabilities the probes need (`CAP_BPF` + `CAP_PERFMON`), read from
/// the effective set in `/proc/self/status` (`CapEff:`, a 64-bit hex mask) — no `libc`, no `unsafe`.
/// Root's effective set has every bit, so this is `true` for root and for a `setcap cap_bpf,cap_perfmon+ep`
/// binary alike: the point of P8.8 is that the second, unprivileged path works.
fn have_load_caps() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(hex) = status.lines().find_map(|l| l.strip_prefix("CapEff:")) else {
        return false;
    };
    let Ok(mask) = u64::from_str_radix(hex.trim(), 16) else {
        return false;
    };
    (mask >> CAP_BPF) & 1 == 1 && (mask >> CAP_PERFMON) & 1 == 1
}

/// The eBPF analogue of the driver's Firecracker-version guard (P6.9b): check the host can actually
/// load the probes and, if not, return a **legible typed error naming the requirement** — a BTF-less
/// kernel or missing capabilities, caught here rather than as a cryptic verifier reject or `EPERM`
/// deep in the load (P8.9). [`ExecveCounter::load`] runs this first; the CLI/`setup` can call it to
/// report eBPF readiness before attempting anything.
///
/// # Errors
/// [`ProbeError::Unsupported`] naming the first missing prerequisite (BTF, then capabilities).
pub fn check_support() -> Result<(), ProbeError> {
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
