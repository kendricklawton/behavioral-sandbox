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
//! **P8.4 — drops with the loader.** [`ExecveCounter`] owns the aya [`Ebpf`], whose `Drop`
//! detaches the program (dropping the link) and frees the map. Nothing is **pinned** into
//! `/sys/fs/bpf`, so there is no kernel residue to leak: a crashed loader leaves no dangling
//! attachment, the eBPF analogue of the driver's no-leak teardown. Pinning stays opt-in, added only
//! where a program must outlive its loader (not here).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use aya::maps::PerCpuArray;
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
/// The tracepoint the program attaches to: category `syscalls`, event `sys_enter_execve`.
const TP_CATEGORY: &str = "syscalls";
const TP_NAME: &str = "sys_enter_execve";

/// A typed failure from loading/attaching/reading the probes — the loader's analogue of the driver's
/// `VmmError`: a missing object, a kernel load/verify/permission failure, an attach failure, or a map
/// read failure is a typed `Err`, never a panic (the host path never panics).
#[derive(Debug)]
pub enum ProbeError {
    /// The compiled BPF object couldn't be found or read (build it with `cargo xtask build-probes`).
    Object(String),
    /// Loading/verifying the object or a program into the kernel failed — needs `CAP_BPF` (or root),
    /// a BTF-capable kernel, and a verifier-clean program.
    Load(String),
    /// Attaching a loaded program to its kernel hook failed.
    Attach(String),
    /// Reading a program's map failed.
    Map(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
/// tries to attach anything. Today it checks for kernel BTF (`/sys/kernel/btf/vmlinux`), the CO-RE
/// prerequisite; richer capability/verifier detection arrives with the loader hardening (P8.9).
#[must_use]
pub fn ebpf_supported() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}
