//! `agent-vmm` — the Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, and the
//! [`Sandbox`] lifecycle API.
//!
//! The host path is `unsafe`-free; a hostile or crashing guest is a typed [`VmmError`], never a
//! panic, hang, or leak. **Skeleton only** — the API surface is sketched so the CLI compiles
//! against it; the real boot/exec/networking land in ROADMAP Phase 1+.
#![forbid(unsafe_code)]

use std::time::Duration;

/// Every way driving a microVM can fail, as a typed value.
#[derive(Debug)]
#[non_exhaustive]
pub enum VmmError {
    /// Not implemented yet — the driver is a Phase-0 skeleton. Names the surface + its phase.
    Unimplemented(&'static str),
    /// The host can't do KVM (`/dev/kvm` missing or not permitted).
    NoKvm,
    /// A Firecracker API, boot, or host↔guest channel failure.
    Vmm(String),
}

impl std::fmt::Display for VmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmmError::Unimplemented(what) => write!(f, "not implemented yet: {what}"),
            VmmError::NoKvm => f.write_str("KVM unavailable: /dev/kvm missing or not permitted"),
            VmmError::Vmm(e) => write!(f, "vmm error: {e}"),
        }
    }
}

impl std::error::Error for VmmError {}

/// A per-sandbox resource budget. The engine exposes these knobs; the *hoster* sets policy.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Limits {
    /// Guest vCPUs.
    pub vcpus: u32,
    /// Guest memory, MiB.
    pub mem_mib: u32,
    /// Wall-clock budget for a run.
    pub wall: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            vcpus: 1,
            mem_mib: 256,
            wall: Duration::from_secs(30),
        }
    }
}

/// What a run produced: the guest exit code and everything it wrote.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunResult {
    /// The guest command's exit code.
    pub exit_code: i32,
    /// Bytes the guest wrote to stdout.
    pub stdout: Vec<u8>,
    /// Bytes the guest wrote to stderr.
    pub stderr: Vec<u8>,
}

/// A microVM sandbox. `boot` lands in Phase 1, `exec` in Phase 2.
#[derive(Debug)]
#[non_exhaustive]
pub struct Sandbox {}

impl Sandbox {
    /// Boot a microVM under `limits`, ready to run code. **ROADMAP Phase 1.**
    ///
    /// # Errors
    /// [`VmmError`] on any boot failure (no KVM, a Firecracker error).
    pub fn boot(limits: Limits) -> Result<Self, VmmError> {
        let _ = limits;
        Err(VmmError::Unimplemented("Sandbox::boot (ROADMAP Phase 1)"))
    }

    /// Run `argv` in the guest and capture its output. **ROADMAP Phase 2.**
    ///
    /// # Errors
    /// [`VmmError`] on any exec/channel failure.
    pub fn exec(&self, argv: &[String]) -> Result<RunResult, VmmError> {
        let _ = argv;
        Err(VmmError::Unimplemented("Sandbox::exec (ROADMAP Phase 2)"))
    }

    /// Shut the microVM down and reclaim its resources.
    ///
    /// # Errors
    /// [`VmmError`] if teardown fails.
    pub fn shutdown(self) -> Result<(), VmmError> {
        Err(VmmError::Unimplemented(
            "Sandbox::shutdown (ROADMAP Phase 1)",
        ))
    }
}
