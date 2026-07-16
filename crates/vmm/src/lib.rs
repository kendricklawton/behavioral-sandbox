//! `agent-vmm` — the Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, and the
//! [`Sandbox`] lifecycle API.
//!
//! The host path is `unsafe`-free; a hostile or crashing guest is a typed [`VmmError`], never a
//! panic, hang, or leak.
//!
//! Two layers:
//! - [`Vm`] / [`RunningVm`] — the raw microVM: boot/restore, exec over vsock, console, networking,
//!   snapshots, teardown.
//! - [`Sandbox`] — the embedder-facing lifecycle wrapper (`open → exec → outputs → snapshot →
//!   close`), **jailed by default** (decision 015) with per-exec files + env at the public API.
#![forbid(unsafe_code)]

mod console;
mod drives;
mod exec;
mod firecracker;
mod jail;
mod lifetime;
mod net;
mod paths;
mod pool;
mod snapshot;
mod spawn;
mod sweep;
#[cfg(test)]
mod test_util;
mod vm;

use std::num::{NonZeroU32, NonZeroU8};
use std::time::Duration;

use agent_channel::ChannelError;

pub use agent_channel::{ClientConnection, Request, Response, GUEST_READY_MARKER, MAX_PAYLOAD};
pub use jail::{Jail, DEFAULT_JAIL_GID, DEFAULT_JAIL_UID};
pub use lifetime::KillHandle;
pub use pool::Pool;
pub use sweep::{sweep_orphans, SweepReport};
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
            (VmmError::GuestUnavailable("x".into()), ErrorKind::Infra),
            (VmmError::Vmm("x".into()), ErrorKind::Infra),
            (
                VmmError::Channel(ChannelError::Io(std::io::Error::from(
                    std::io::ErrorKind::BrokenPipe,
                ))),
                ErrorKind::Transport,
            ),
            (VmmError::GuestExec("x".into()), ErrorKind::Guest),
            (VmmError::GuestProtocol("x".into()), ErrorKind::Guest),
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
///   [`Timeout`](VmmError::Timeout), [`Vmm`](VmmError::Vmm),
///   [`GuestUnavailable`](VmmError::GuestUnavailable): the host couldn't stand the microVM up (or a
///   bounded wait expired). This bucket also holds vsock **establishment** failures — the socket
///   connect, the `CONNECT <port>` ack, *and the channel handshake* surface here even though the
///   handshake is protocol-layer. Establishment is infra; the specific "nothing is listening"
///   establishment failures (nothing accepting on the guest port, a dead VMM's stale socket) are the
///   dedicated `GuestUnavailable`, so a retry/pool caller can tell **transient, retry or discard this
///   VM** from "infra broken" without string-matching `Vmm`.
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
/// (The `GuestUnavailable` variant and `kind()` were both deferred at first — "add them for the first
/// caller that needs them" — and landed with that caller: the classifier for the embedder that
/// branches on bucket, the variant for the prewarmed [`Pool`], which discards a dead pooled clone and
/// serves the next instead of surfacing an infra failure.)
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
    /// Nothing is accepting on the guest's exec channel: Firecracker closed (or refused) the vsock
    /// `CONNECT` because no listener holds the guest port, or the vsock socket itself refused
    /// (a dead VMM's stale socket). **Transient/retryable by contract**: the agent may not be up
    /// *yet* (mid-boot, mid-resume) or not *anymore* (a pooled clone died) — a retry/pool caller
    /// retries or discards this VM and takes another, rather than treating it as broken infra.
    /// Distinct from [`Timeout`](VmmError::Timeout) (a bounded wait expired while the peer stayed
    /// silent) and from [`Vmm`](VmmError::Vmm) (a protocol-violating or otherwise broken peer).
    GuestUnavailable(String),
    /// The host↔guest exec **channel** failed — a transport or protocol fault. Distinct from a
    /// guest command that merely exits non-zero (a normal [`RunResult`]) or fails to spawn
    /// ([`GuestExec`](VmmError::GuestExec)). Preserves the [`ChannelError`] source.
    Channel(ChannelError),
    /// The **guest agent** could not run the command (e.g. no such binary in the guest, permission
    /// denied) — a user fault on a healthy channel, not an infra failure.
    GuestExec(String),
    /// The guest **violated the wire contract** on an otherwise-healthy channel: a returned artifact
    /// path that is absolute or climbs out of the working tree, or a well-framed response the exec
    /// loop never expects there. The guest agent is not the trust boundary, so the host rejects the
    /// misbehaving guest rather than trusting it — a guest fault, distinct from a command that merely
    /// failed to run ([`GuestExec`](VmmError::GuestExec)) or a transport-level [`Channel`](VmmError::Channel) break.
    GuestProtocol(String),
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
            VmmError::GuestUnavailable(e) => write!(f, "guest agent unavailable: {e}"),
            VmmError::Channel(e) => write!(f, "exec channel: {e}"),
            VmmError::GuestExec(e) => write!(f, "guest could not run the command: {e}"),
            VmmError::GuestProtocol(e) => write!(f, "guest violated the exec protocol: {e}"),
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
            // `GuestUnavailable` is Infra by the taxonomy (establishment is infra), and Infra's
            // contract — "a retry or a fixed host is the response" — is exactly its semantics; the
            // variant itself carries the finer "this specific VM: retry/discard" signal.
            VmmError::Unimplemented(_)
            | VmmError::NoKvm
            | VmmError::Artifact(_)
            | VmmError::Timeout(_)
            | VmmError::GuestUnavailable(_)
            | VmmError::Vmm(_) => ErrorKind::Infra,
            VmmError::Channel(_) => ErrorKind::Transport,
            VmmError::GuestExec(_)
            | VmmError::GuestProtocol(_)
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

/// The driver-side file-descriptor budget of **one live microVM**, across every start path (cold
/// boot, snapshot restore, prewarmed-pool clone, networked) — the number to size concurrency against
/// `ulimit -n`: N concurrent sandboxes hold up to `N × FDS_PER_VM` fds on top of the process
/// baseline, and a bound (like [`Pool`]'s target) must keep that under the soft limit with
/// headroom, or the failure is an illegible mid-boot `EMFILE` in whatever syscall lands first.
///
/// Measured steady state is **2 on every start path** — cold, networked, prewarmed restore (dev box,
/// pinned by `fd_footprint_per_vm_stays_within_budget_and_never_leaks`): the console reader's pipe
/// and the lifetime sentinel's pipe write end; exec and API calls open and close transiently, and
/// teardown returns to the exact baseline (no per-run fd leak). The budget is deliberately above
/// the measurement — an fd added for cause is a visible bump of this constant (the pinning test
/// fails otherwise), never silent growth.
pub const FDS_PER_VM: usize = 8;

/// A per-sandbox resource budget. The engine exposes these knobs; the *hoster* sets policy. This is
/// the per-run resource-policy surface whose shape is fixed by docs/architecture.md decision 013: one
/// options struct of **quantities** (vCPUs, memory, deadlines, an output cap), not capabilities,
/// enforced host-side (the VMM cgroup for cpu/memory; the exec channel's bounds for the rest).
///
/// The [`default`](Limits::default) values are **deliberately conservative and load-bearing for
/// embedders**: they cap what a run gets by default, so an embedder that pins this crate and calls
/// `Limits::default()` relies on them staying small. Raising one (more vCPUs, more memory, a longer
/// wall) hands every default run more resource and is a **breaking change worth a changelog line and
/// a public-API commit subject**, not a quiet bump. Lowering one, or adding a new field (the struct
/// is `#[non_exhaustive]`), is safe.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Limits {
    /// Guest vCPUs. Typed [`NonZeroU8`]: a zero-vCPU guest is not a small budget but an
    /// unbootable one, so the illegal value is unrepresentable rather than a late Firecracker API
    /// error, and the width states the realistic domain (the pinned v1.9 caps a microVM at 32).
    pub vcpus: NonZeroU8,
    /// Guest memory, MiB. Typed [`NonZeroU32`] for the same reason as [`vcpus`](Limits::vcpus):
    /// zero is not a budget, so it can't be constructed.
    pub mem_mib: NonZeroU32,
    /// The wall-clock budget: the boot-to-userspace deadline **and** each command's exec budget —
    /// one `wall` for the whole run, not just boot (decision 013). On the exec side it is sent to
    /// the guest agent, which kills the command past it (the cooperative
    /// [`ExecTimeout`](VmmError::ExecTimeout)); the host's own give-up deadline — the
    /// [`ExecUnresponsive`](VmmError::ExecUnresponsive) liveness backstop — is derived from it
    /// (budget + kill slack), so raising the budget moves both together and a long quiet command is
    /// never cut off by the transport. Should be a realistic duration: it is also the boot deadline,
    /// and on the exec side a zero or sub-millisecond wall is floored to a **1 ms** command budget on
    /// the wire (the guest reads a truncated-to-zero `timeout_ms` as its 1 h ceiling, so the floor
    /// keeps a tiny wall meaning "very short", never "unlimited"). (A caller that genuinely needs
    /// different boot and exec ceilings sets [`BootConfig::boot_timeout`] / [`BootConfig::exec_wall`]
    /// under the public API.)
    pub wall: Duration,
    /// Aggregate cap, in bytes, on what the host buffers for one exec — stdout + stderr + returned
    /// artifacts (plus a small per-frame accounting floor) — so a flooding guest can't grow host
    /// memory without bound. Breach is the typed [`OutputCap`](VmmError::OutputCap).
    pub output_cap: usize,
}

impl Default for Limits {
    /// Conservative defaults (see the type doc): 1 vCPU, 256 MiB, a 30 s wall (boot deadline and
    /// exec budget alike — 30 s was both fixed values before they were knobs), a 16 MiB output
    /// cap. Treat these as a stable floor, raising any of them is a breaking change for embedders.
    fn default() -> Self {
        Self {
            vcpus: NonZeroU8::MIN, // 1
            // 256; the fallback arm can't fire (256 is nonzero) — spelled without `unwrap`
            // because the host path denies it (guardrail 5).
            mem_mib: NonZeroU32::new(256).unwrap_or(NonZeroU32::MIN),
            wall: exec::DEFAULT_EXEC_TIMEOUT,
            output_cap: exec::MAX_EXEC_OUTPUT,
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
    /// What the run cost, host-measured (see [`ExecMetrics`]).
    pub metrics: ExecMetrics,
}

/// Host-measured metrics for one exec — the **metrics** leg of the structured run result. Measured
/// by the driver, not reported by the guest, so a hostile guest can't lie about them.
/// `#[non_exhaustive]`: richer measurements (guest cpu time from the cgroup, per-stream byte
/// counts, the audit log's numbers) land as new fields without a breaking change.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ExecMetrics {
    /// Wall-clock time of the exec as the host observed it: request sent to terminal frame
    /// received. Includes guest spawn/teardown overhead, so it is an embedder's billing-grade
    /// number, not the command's own runtime.
    pub wall: Duration,
}

/// A microVM sandbox: the embedder-facing lifecycle type, backed by a [`RunningVm`]. The lifecycle
/// is `open → exec (with files + env) → collect outputs → snapshot → close`, every step synchronous
/// and every failure a typed [`VmmError`]. Repeated `exec`s form a **stateful session** (decision
/// 019): the VM is the session, every exec shares its persistent working directory and overlay, and
/// closing the sandbox discards the state.
///
/// **Confined by default (decision 015).** [`open`](Sandbox::open) and [`boot`](Sandbox::boot) run
/// the VMM **under the jailer** — chroot, uid/gid drop, seccomp, its own mount and network
/// namespaces — on top of the KVM hardware boundary, so the headline "run untrusted code" path is
/// the double-walled one. That needs real root and the `jailer` binary; the opt-out is
/// [`open_unjailed`](Sandbox::open_unjailed), deliberately a *differently-named constructor* so an
/// unconfined sandbox can never happen by a forgotten flag — only by writing "unjailed".
///
/// **Inputs at the public API.** Per-exec files and env ride [`exec_with_files`](Sandbox::exec_with_files)
/// under the secret-hygiene contract pinned on [`RunningVm::exec_with_files`]; bulk directories ride
/// [`BootConfig::input_dir`]/[`BootConfig::output_dir`] into [`open`](Sandbox::open), and
/// [`collect_outputs`](Sandbox::collect_outputs) pulls the guest's `/output` tree back. An embedder
/// never needs to reach the [`RunningVm`] layer.
#[derive(Debug)]
#[must_use = "dropping a Sandbox kills its microVM"]
pub struct Sandbox {
    vm: RunningVm,
}

impl Sandbox {
    /// Open a sandbox on `config`, ready to run code — **jailed by default**: if `config.jail` is
    /// unset it becomes [`Jail::default`], and the vsock exec channel is enabled (an unset
    /// `config.guest_cid` becomes [`DEFAULT_GUEST_CID`]). Everything else in `config` — artifacts,
    /// resource knobs (see [`BootConfig::with_limits`]), `input_dir`/`output_dir`, networking — is
    /// honored as given.
    ///
    /// Needs real root and the `jailer` binary (the confinement is the point); a host that can't
    /// jail gets a typed error, never a silently unconfined boot. The explicit opt-out for dev
    /// hosts is [`open_unjailed`](Sandbox::open_unjailed).
    ///
    /// # Errors
    /// [`VmmError`] on any boot failure (no KVM, a missing artifact, a jailer/Firecracker error, or
    /// a boot-to-userspace timeout).
    pub fn open(mut config: BootConfig) -> Result<Self, VmmError> {
        config.jail = Some(config.jail.unwrap_or_default());
        Self::open_inner(config)
    }

    /// [`open`](Sandbox::open) **without the jailer** — the explicit opt-out (decision 015) for
    /// hosts that can't run it (no root, no `jailer`): the guest still sits behind the KVM hardware
    /// boundary, but the VMM process itself runs unconfined. The opt-out is this constructor's
    /// *name* rather than a flag so it is greppable and can't be reached by accident; any `jail`
    /// set on `config` is cleared (the name wins).
    ///
    /// # Errors
    /// As [`open`](Sandbox::open).
    pub fn open_unjailed(mut config: BootConfig) -> Result<Self, VmmError> {
        config.jail = None;
        Self::open_inner(config)
    }

    /// The shared tail of the constructors: force the exec channel on (a `Sandbox` is for running
    /// code) and boot.
    fn open_inner(mut config: BootConfig) -> Result<Self, VmmError> {
        if config.guest_cid.is_none() {
            config.guest_cid = Some(DEFAULT_GUEST_CID);
        }
        let vm = Vm::boot(config)?;
        Ok(Self { vm })
    }

    /// Boot a sandbox under `limits` with the environment-layered defaults ([`BootConfig::from_env`])
    /// — the convenience form of [`open`](Sandbox::open), and like it **jailed by default**.
    ///
    /// # Errors
    /// As [`open`](Sandbox::open).
    pub fn boot(limits: Limits) -> Result<Self, VmmError> {
        Self::open(BootConfig::from_env().with_limits(limits))
    }

    /// Run `argv` in the guest, feeding it `stdin`, and capture its stdout/stderr/exit.
    ///
    /// # Errors
    /// [`VmmError`] on any exec/channel failure (a non-zero command exit is a normal [`RunResult`]).
    pub fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<RunResult, VmmError> {
        self.vm.exec(argv, stdin)
    }

    /// Run `argv` with per-exec **inputs**: `stdin`, `files_in` injected into the run's working
    /// directory, and `env` set on the spawned command (only — never the guest agent's own process);
    /// the files named in `artifacts` come back in [`RunResult::files`]. Synchronous, same
    /// [`RunResult`] shape as [`exec`](Sandbox::exec).
    ///
    /// Injected file contents and env **values** are covered by the **secret-hygiene contract**
    /// (they never reach an engine log, a [`VmmError`] rendering, or [`console`](Sandbox::console);
    /// wire copies are wiped after send) — see [`RunningVm::exec_with_files`], which this wraps,
    /// for the full statement.
    ///
    /// # Errors
    /// As [`exec`](Sandbox::exec).
    pub fn exec_with_files(
        &self,
        argv: &[String],
        stdin: &[u8],
        files_in: &[(String, Vec<u8>)],
        env: &[(String, String)],
        artifacts: &[String],
    ) -> Result<RunResult, VmmError> {
        self.vm
            .exec_with_files(argv, stdin, files_in, env, artifacts)
    }

    /// Pull the guest's `/output` tree back to the host directory given as
    /// [`BootConfig::output_dir`] at [`open`](Sandbox::open), returning the captured paths.
    /// Consumes the sandbox — the VMM is stopped first so the image is quiescent (see
    /// [`RunningVm::collect_outputs`], which this wraps).
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the sandbox was opened without `output_dir`; otherwise as
    /// [`RunningVm::collect_outputs`].
    pub fn collect_outputs(self) -> Result<Vec<String>, VmmError> {
        self.vm.collect_outputs()
    }

    /// Pause the microVM and write a portable [`Snapshot`] bundle into `dir`, then resume (see
    /// [`RunningVm::snapshot`]). Note the interplay with the jailed default: snapshotting a
    /// **jailed** sandbox is a typed refusal (its disk lives in the chroot) — take the snapshot
    /// from an [`open_unjailed`](Sandbox::open_unjailed) prewarmed source that runs only the embedder's
    /// own warm-up, then [`Vm::restore`]/[`Pool`] the clones **with a jail**, which is where the
    /// untrusted code runs.
    ///
    /// # Errors
    /// As [`RunningVm::snapshot`].
    pub fn snapshot(&self, dir: &std::path::Path) -> Result<Snapshot, VmmError> {
        self.vm.snapshot(dir)
    }

    /// A cheap, cloneable [`KillHandle`] that force-kills this sandbox from any thread — the
    /// host-gave-up path (see [`RunningVm::kill_handle`]): a caller blocked in
    /// [`exec`](Sandbox::exec) gets a typed error and teardown still reclaims everything.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        self.vm.kill_handle()
    }

    /// The PID of the VMM process, for out-of-band supervision and the host-side observers (the
    /// Phase-8 eBPF track); valid only while the sandbox lives. See [`RunningVm::vmm_pid`].
    #[must_use]
    pub fn vmm_pid(&self) -> u32 {
        self.vm.vmm_pid()
    }

    /// The host **tap** interface backing this sandbox's NIC, or `None` if it was opened without
    /// networking ([`BootConfig::enable_network`]). Paired with [`netns`](Sandbox::netns), this is what
    /// the host-side eBPF network track binds to: the tap lives *inside* the sandbox's netns, so a
    /// loader attaches its `tc` programs to this interface **within that namespace**. See
    /// [`RunningVm::tap_name`].
    #[must_use]
    pub fn tap_name(&self) -> Option<&str> {
        self.vm.tap_name()
    }

    /// The per-VM **network namespace** name backing this sandbox's NIC, or `None` without networking.
    /// Its handle is `/run/netns/<name>`; a host-side network observer enters it to reach
    /// [`tap_name`](Sandbox::tap_name), which is isolated from the host and every other VM. See
    /// [`RunningVm::netns`].
    #[must_use]
    pub fn netns(&self) -> Option<&str> {
        self.vm.netns()
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

    /// Close the sandbox: shut the microVM down and reclaim its resources.
    ///
    /// # Errors
    /// Currently never returns `Err` — teardown is best-effort and the guarantee lives in `Drop`
    /// (see [`RunningVm::shutdown`]) — but the signature stays fallible for the jailed/cgroup
    /// teardown of later phases.
    pub fn shutdown(self) -> Result<(), VmmError> {
        self.vm.shutdown()
    }
}
