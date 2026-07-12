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

pub use agent_channel::{ClientConnection, Request, Response, GUEST_READY_MARKER};
pub use vm::{BootConfig, RunningVm, Snapshot, Vm, AGENT_VSOCK_PORT, DEFAULT_GUEST_CID};

#[cfg(test)]
mod tests {
    use super::{ErrorKind, VmmError};
    use agent_channel::ChannelError;
    use std::time::Duration;

    #[test]
    fn kind_buckets_every_variant() {
        // Pins the public bucket contract: each variant maps to exactly one `ErrorKind`. This is the
        // list a `#[non_exhaustive]` new variant must extend (the wildcard-free match in `kind` won't
        // compile until it does), so a drift here is a deliberate contract change, not an accident.
        let cases = [
            (VmmError::Unimplemented("x"), ErrorKind::Infra),
            (VmmError::NoKvm, ErrorKind::Infra),
            (VmmError::Artifact("x".into()), ErrorKind::Infra),
            (VmmError::Timeout("x".into()), ErrorKind::Infra),
            (VmmError::Vmm("x".into()), ErrorKind::Infra),
            (
                VmmError::Channel(ChannelError::Io(std::io::Error::from(
                    std::io::ErrorKind::BrokenPipe,
                ))),
                ErrorKind::Transport,
            ),
            (VmmError::GuestExec("x".into()), ErrorKind::Guest),
            (VmmError::OutputCap { limit: 1 }, ErrorKind::Guest),
            (
                VmmError::ExecTimeout {
                    limit: Duration::from_secs(1),
                },
                ErrorKind::Guest,
            ),
            (
                VmmError::ExecUnresponsive {
                    limit: Duration::from_secs(1),
                },
                ErrorKind::Guest,
            ),
        ];
        for (err, want) in cases {
            assert_eq!(err.kind(), want, "wrong bucket for {err:?}");
        }
    }
}

/// Every way driving a microVM can fail, as a typed value — the driver's **error taxonomy**.
///
/// A hostile or crashing guest is one of these, never a host panic/hang/leak (the host path is
/// `#![forbid(unsafe_code)]` and the CI gate denies `unwrap`/`expect` outside tests). The variants
/// fall in three buckets:
///
/// - **Boot / infra** — [`NoKvm`](VmmError::NoKvm), [`Artifact`](VmmError::Artifact),
///   [`Timeout`](VmmError::Timeout), [`Vmm`](VmmError::Vmm): the host couldn't stand the microVM up
///   (or a bounded wait expired). This bucket also holds vsock **establishment** failures — the
///   socket connect, the `CONNECT <port>` ack, *and the channel handshake* surface here (as
///   `Vmm`/`Timeout`) even though the handshake is protocol-layer. Establishment is infra, and it's
///   where "the guest agent isn't listening yet" shows up.
/// - **Channel / transport** — [`Channel`](VmmError::Channel): a **steady-state** framing/IO fault
///   on an already-established connection (a `send_request`/`recv_response` mid-exec). Preserves the
///   [`ChannelError`] source. Distinct from a guest command that merely exits non-zero (a normal
///   [`RunResult`]) or fails to spawn ([`GuestExec`](VmmError::GuestExec)).
/// - **Guest fault** — [`GuestExec`](VmmError::GuestExec) (the agent couldn't run the command),
///   [`ExecTimeout`](VmmError::ExecTimeout) (the command outran its wall-clock budget and was killed
///   *by the guest*, which reported it), [`OutputCap`](VmmError::OutputCap) (it flooded output past
///   the host cap), [`ExecUnresponsive`](VmmError::ExecUnresponsive) (the guest never reported the
///   command's end and the *host* gave up on its own deadline — a liveness/trust fault the host
///   enforces because the guest can't be trusted to bound itself).
///
/// **Not an error.** A command that merely exits non-zero — *including dying by signal*, which the
/// guest agent reports as exit code `128 + signal` — is a faithful [`RunResult`], not a `VmmError`.
/// Typed errors are reserved for infra, transport, and guest-agent faults; a crash *inside* the
/// sandbox is a normal result the caller inspects.
///
/// Callers that must **branch** on bucket (retry infra, retire the VM on a transport fault, surface a
/// guest fault to the user) use [`kind`](VmmError::kind), whose mapping is a pinned public contract.
///
/// Deliberately deferred (safe to add later — this enum is `#[non_exhaustive]`):
/// - A dedicated `GuestUnavailable` variant splitting "peer closed before ack / nothing listening"
///   out of `Vmm`. Add it for the first retry/warm-pool caller (~Phase 5) that must tell "agent not
///   up yet / transient" from "infra broken." Today the only caller renders the error to a human.
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
    /// A command exceeded its exec wall-clock budget and was killed by the guest — a *user* fault
    /// (the code ran too long), distinct from a transport/boot [`Timeout`](VmmError::Timeout).
    ExecTimeout { limit: Duration },
    /// The **host** gave up on an exec after `limit` because the guest never reported the command's
    /// end (no `Exit`/`TimedOut`) while keeping the channel's idle timer alive — a *liveness/trust*
    /// fault (the guest went silent or hostile), distinct from [`ExecTimeout`](VmmError::ExecTimeout),
    /// where the guest cooperatively reported the timeout. A caller should retire the VM, not blame
    /// the user's command.
    ExecUnresponsive { limit: Duration },
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
            VmmError::ExecTimeout { limit } => {
                write!(f, "guest command exceeded its {limit:?} deadline")
            }
            VmmError::ExecUnresponsive { limit } => {
                write!(f, "guest went unresponsive; host gave up after {limit:?}")
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

/// The three buckets a [`VmmError`] falls into, for a caller that must **branch** on the class of
/// failure rather than render it: **infra** (retry/rebuild), **transport** (retire the VM), or
/// **guest** (surface to the user). A small, closed set (this enum, unlike [`VmmError`], is *not*
/// `#[non_exhaustive]` — the buckets are the stable contract; new `VmmError` variants slot into an
/// existing bucket, they don't add a new one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Boot / infra: the host couldn't stand the microVM up, or a bounded wait expired — including
    /// vsock **establishment** (connect + `CONNECT` ack + handshake, where "the agent isn't up yet"
    /// shows up). Not the guest's fault; a retry or a fixed host is the response.
    Infra,
    /// Channel / transport: a steady-state framing/IO fault on an already-established exec connection.
    /// The channel is unreliable, so a caller should retire the VM rather than blame the command.
    Transport,
    /// Guest fault: the agent couldn't run the command, it outran its budget, flooded output, or went
    /// unresponsive. The run is at fault, not the engine.
    Guest,
}

impl VmmError {
    /// Classify this error into an [`ErrorKind`] bucket. The mapping is a **public contract** an
    /// embedder can branch on, pinned by a test.
    ///
    /// The match is deliberately **wildcard-free**: [`VmmError`] is `#[non_exhaustive]`, so a future
    /// variant would otherwise fall into a catch-all arm with a silent, likely-wrong bucket. With no
    /// `_` arm, adding a variant fails to compile here until it's given a deliberate bucket — that's
    /// what keeps the contract honest.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            VmmError::Unimplemented(_)
            | VmmError::NoKvm
            | VmmError::Artifact(_)
            | VmmError::Timeout(_)
            | VmmError::Vmm(_) => ErrorKind::Infra,
            VmmError::Channel(_) => ErrorKind::Transport,
            VmmError::GuestExec(_)
            | VmmError::OutputCap { .. }
            | VmmError::ExecTimeout { .. }
            | VmmError::ExecUnresponsive { .. } => ErrorKind::Guest,
        }
    }
}

impl From<ChannelError> for VmmError {
    fn from(e: ChannelError) -> Self {
        VmmError::Channel(e)
    }
}

/// A per-sandbox resource budget. The engine exposes these knobs; the *hoster* sets policy.
///
/// The [`default`](Limits::default) values are **deliberately conservative and load-bearing for
/// embedders**: they cap what a run gets by default, so an embedder that pins this crate and calls
/// `Limits::default()` relies on them staying small. Raising one (more vCPUs, more memory, a longer
/// wall) hands every default run more resource and is a **breaking change worth a changelog line and
/// a public-seam commit subject**, not a quiet bump. Lowering one, or adding a new field (the struct
/// is `#[non_exhaustive]`), is safe.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Limits {
    /// Guest vCPUs.
    pub vcpus: u32,
    /// Guest memory, MiB.
    pub mem_mib: u32,
    /// The boot-to-userspace deadline. (It does **not** yet bound a command's exec runtime — that
    /// has its own default budget until the per-run resource policy makes it a knob.)
    pub wall: Duration,
}

impl Default for Limits {
    /// Conservative defaults (see the type doc): 1 vCPU, 256 MiB, a 30 s boot deadline. Treat these
    /// as a stable floor, raising any of them is a breaking change for embedders.
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
    /// Requested artifact files the guest returned, as `(path, contents)`. A requested artifact
    /// that didn't exist is simply absent.
    pub files: Vec<(String, Vec<u8>)>,
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
