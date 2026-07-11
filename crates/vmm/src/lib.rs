//! `agent-vmm` — the Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, and the
//! [`Sandbox`] lifecycle API.
//!
//! The host path is `unsafe`-free; a hostile or crashing guest is a typed [`VmmError`], never a
//! panic, hang, or leak. Phase 1 makes [`Vm::boot`] real — it boots a Firecracker microVM and
//! reads its serial console; [`exec`](Sandbox::exec) and networking land in later phases.
//!
//! Two layers:
//! - [`Vm`] / [`RunningVm`] — the raw microVM: boot to userspace, read the console, shut down.
//! - [`Sandbox`] — the CLI-facing lifecycle wrapper (grows `exec`/files/policy in later phases).
#![forbid(unsafe_code)]

mod firecracker;
mod vm;

use std::time::Duration;

use agent_channel::ChannelError;

pub use agent_channel::{ClientConnection, Request, Response};
pub use vm::{BootConfig, RunningVm, Vm, AGENT_VSOCK_PORT, DEFAULT_GUEST_CID};

/// Every way driving a microVM can fail, as a typed value.
#[derive(Debug)]
#[non_exhaustive]
pub enum VmmError {
    /// Not implemented yet — names the surface and the phase that lands it.
    Unimplemented(&'static str),
    /// The host can't do KVM (`/dev/kvm` missing or not permitted).
    NoKvm,
    /// A required input is missing: the `firecracker` binary, the kernel, or the rootfs image.
    Artifact(String),
    /// A bounded wait expired (API socket readiness, boot-to-userspace, a wedged API call).
    Timeout(String),
    /// The host↔guest exec **channel** failed — a transport or protocol fault. Distinct from a
    /// guest command that merely exits non-zero (a normal [`RunResult`]) or fails to spawn
    /// ([`GuestExec`](VmmError::GuestExec)). Preserves the [`ChannelError`] source.
    Channel(ChannelError),
    /// The **guest agent** could not run the command (e.g. no such binary in the guest, permission
    /// denied) — a user fault on a healthy channel, not an infra failure.
    GuestExec(String),
    /// A command's captured output exceeded the host's `limit`-byte cap.
    OutputCap { limit: usize },
    /// A Firecracker API, boot, or process failure.
    Vmm(String),
}

impl std::fmt::Display for VmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmmError::Unimplemented(what) => write!(f, "not implemented yet: {what}"),
            VmmError::NoKvm => f.write_str("KVM unavailable: /dev/kvm missing or not permitted"),
            VmmError::Artifact(e) => write!(f, "missing artifact: {e}"),
            VmmError::Timeout(e) => write!(f, "timed out: {e}"),
            VmmError::Channel(e) => write!(f, "exec channel: {e}"),
            VmmError::GuestExec(e) => write!(f, "guest could not run the command: {e}"),
            VmmError::OutputCap { limit } => {
                write!(f, "guest output exceeded the {limit}-byte cap")
            }
            VmmError::Vmm(e) => write!(f, "vmm error: {e}"),
        }
    }
}

impl std::error::Error for VmmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VmmError::Channel(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ChannelError> for VmmError {
    fn from(e: ChannelError) -> Self {
        VmmError::Channel(e)
    }
}

/// A per-sandbox resource budget. The engine exposes these knobs; the *hoster* sets policy.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Limits {
    /// Guest vCPUs.
    pub vcpus: u32,
    /// Guest memory, MiB.
    pub mem_mib: u32,
    /// Wall-clock budget for a run (also the boot-to-userspace deadline).
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

/// A microVM sandbox: the CLI-facing lifecycle type, backed by a [`RunningVm`]. Boots with the
/// vsock exec channel enabled, so [`exec`](Sandbox::exec) can reach the in-guest agent.
#[derive(Debug)]
#[must_use = "dropping a Sandbox kills its microVM"]
pub struct Sandbox {
    vm: RunningVm,
}

impl Sandbox {
    /// Boot a microVM under `limits`, ready to run code (vsock exec channel enabled).
    ///
    /// # Errors
    /// [`VmmError`] on any boot failure (no KVM, a missing artifact, a Firecracker error, or a
    /// boot-to-userspace timeout).
    pub fn boot(limits: Limits) -> Result<Self, VmmError> {
        let mut config = BootConfig::from_env().with_limits(limits);
        config.guest_cid = Some(DEFAULT_GUEST_CID);
        let vm = Vm::boot(config)?;
        Ok(Self { vm })
    }

    /// Run `argv` in the guest, feeding it `stdin`, and capture its stdout/stderr/exit.
    ///
    /// Requires the in-guest agent to be listening on vsock; until it is baked into the rootfs the
    /// call surfaces a clear "guest agent not listening" error.
    ///
    /// # Errors
    /// [`VmmError`] on any exec/channel failure (a non-zero command exit is a normal [`RunResult`]).
    pub fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<RunResult, VmmError> {
        self.vm.exec(argv, stdin)
    }

    /// Boot-to-userspace latency of this sandbox's microVM.
    #[must_use]
    pub fn boot_latency(&self) -> Duration {
        self.vm.boot_latency()
    }

    /// A UTF-8-lossy snapshot of the guest serial console captured so far.
    #[must_use]
    pub fn console(&self) -> String {
        self.vm.console()
    }

    /// Shut the microVM down and reclaim its resources.
    ///
    /// # Errors
    /// Currently never returns `Err` — teardown is best-effort and the guarantee lives in `Drop`
    /// (see [`RunningVm::shutdown`]) — but the signature stays fallible for the jailed/cgroup
    /// teardown of later phases.
    pub fn shutdown(self) -> Result<(), VmmError> {
        self.vm.shutdown()
    }
}
