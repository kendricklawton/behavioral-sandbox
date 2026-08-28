//! `bsx-engine`, the Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, and the
//! [`Sandbox`] lifecycle API.
//!
//! The host path is `unsafe`-free; a hostile or crashing guest is a typed [`VmmError`], never a
//! panic, hang, or leak.
//!
//! Two layers:
//! - [`Vm`] / [`RunningVm`], the raw microVM: boot/restore, exec over vsock, console, networking,
//!   snapshots, teardown.
//! - [`Sandbox`], the embedder-facing lifecycle wrapper (`open → exec → outputs → snapshot →
//!   close`), **jailed by default** with per-exec files + env at the public API.
#![forbid(unsafe_code)]

mod console;
mod deadline;
pub mod doctor;
mod drives;
mod exec;
mod firecracker;
mod jail;
mod lifetime;
mod mountinfo;
mod net;
mod paths;
mod pool;
mod proc;
mod snapshot;
mod spawn;
mod sweep;
mod vm;

use std::num::{NonZeroU8, NonZeroU32};
use std::time::Duration;

use bsx_channel::ChannelError;

pub use bsx_channel::{ClientConnection, GUEST_READY_MARKER, MAX_PAYLOAD, Request, Response};
pub use jail::{DEFAULT_JAIL_GID, DEFAULT_JAIL_UID, Jail, JailIdentity, JailIds, VMM_PIDS_MAX};

/// The output-image bound the readback applies before parsing, for the fuzz target only.
#[cfg(feature = "fuzzing")]
pub use drives::fuzz;
pub use lifetime::KillHandle;
pub use net::{GuestEgress, GuestLink};
pub use pool::Pool;
pub use sweep::{SweepReport, sweep_orphans};
pub use vm::{BootConfig, DEFAULT_GUEST_CID, RunningVm, Snapshot, VSOCK_PORT, Vm};

/// A [`Duration`] as whole milliseconds, saturating rather than wrapping, for the latency fields the
/// engine logs.
pub(crate) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{ErrorKind, VmmError};
    use bsx_channel::ChannelError;
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
                ErrorKind::Transport,
            ),
        ];
        for (err, want) in cases {
            assert_eq!(err.kind(), want, "wrong bucket for {err:?}");
        }
    }
}

/// Every way driving a microVM can fail, as a typed value, the driver's **error taxonomy**.
///
/// A hostile or crashing guest is one of these, never a host panic/hang/leak (the crate is
/// `#![forbid(unsafe_code)]` and the CI gate denies `unwrap`/`expect` outside tests).
///
/// **Not an error.** A command that merely exits non-zero, *including dying by signal*, which the
/// guest agent reports as exit code `128 + signal`, is a faithful [`RunResult`]. Typed errors are
/// reserved for infra, transport, and guest-agent faults; a crash *inside* the sandbox is a normal
/// result the caller inspects.
///
/// To branch on the class of failure rather than render it, use [`kind`](VmmError::kind): that
/// mapping is the pinned contract, and each variant's own doc says which bucket it lands in and
/// why.
#[derive(Debug)]
#[non_exhaustive]
pub enum VmmError {
    /// Not implemented yet, names the surface ahead of the implementation that lands it.
    Unimplemented(&'static str),
    /// The host can't do KVM (`/dev/kvm` missing or not permitted).
    NoKvm,
    /// A required input is missing: the `firecracker` binary, the kernel, or the rootfs image.
    Artifact(String),
    /// A bounded wait expired (API socket readiness, boot-to-userspace, a wedged API call).
    Timeout(String),
    /// Nothing is accepting on the guest's exec channel: no listener holds the guest port, or the
    /// vsock socket refused. **Retryable by contract**, since the agent may not be up yet (mid-boot,
    /// mid-resume) or not any more (a dead pooled clone): retry or discard this VM and take
    /// another. Distinct from [`Timeout`](VmmError::Timeout), a bounded wait against a silent peer,
    /// and [`Vmm`](VmmError::Vmm), a broken one.
    GuestUnavailable(String),
    /// The host↔guest exec **channel** failed, a transport or protocol fault. Distinct from a
    /// guest command that merely exits non-zero (a normal [`RunResult`]) or fails to spawn
    /// ([`GuestExec`](VmmError::GuestExec)). Preserves the [`ChannelError`] source.
    Channel(ChannelError),
    /// The **guest agent** could not run the command (e.g. no such binary in the guest, permission
    /// denied), a user fault on a healthy channel, not an infra failure.
    GuestExec(String),
    /// The guest violated the wire contract on a healthy channel: an artifact path that is absolute
    /// or climbs out of the working tree, or a well-framed response the exec loop never expects
    /// there. A guest fault, distinct from a command that failed to run
    /// ([`GuestExec`](VmmError::GuestExec)) and from a transport break
    /// ([`Channel`](VmmError::Channel)).
    GuestProtocol(String),
    /// A command's captured output exceeded the host's `limit`-byte cap.
    OutputCap { limit: usize },
    /// A command exceeded its exec wall-clock budget and was killed by the guest, a *user* fault
    /// (the code ran too long), distinct from a transport/boot [`Timeout`](VmmError::Timeout).
    ExecTimeout { limit: Duration },
    /// The host gave up on an exec after `limit`: the guest never reported the command's end while
    /// keeping the channel's idle timer alive. A liveness fault, so retire the VM rather than blame
    /// the command, unlike [`ExecTimeout`](VmmError::ExecTimeout), which the guest reported
    /// cooperatively.
    ExecUnresponsive { limit: Duration },
    /// A Firecracker API, boot, or process failure.
    Vmm(String),
    /// `require_limits` was set and the cpu/memory cgroup caps cannot be applied, so the boot is
    /// refused rather than run uncapped. Either the cgroup v2 controllers are not delegated to the
    /// cgroup root, or the boot is unjailed and the caps have no cgroup to live on. The opt-in
    /// inverse of the fail-open default. [`Infra`](ErrorKind::Infra): fix the host and retry.
    LimitsUnavailable(String),
    /// A jailed boot was asked for and `BSX_SCRATCH_DIR` is on a `nodev` mount, so the `/dev/kvm`
    /// node the jailer mknods in its chroot is inert. Caught before the spawn, so the fix is named
    /// rather than surfacing as a raw Firecracker permission error deep in boot.
    /// [`Infra`](ErrorKind::Infra); unjailed boots have no chroot and are unaffected.
    ScratchDirNodev(std::path::PathBuf),
    /// [`ScratchDirNodev`](Self::ScratchDirNodev) one mount flag over: `noexec`, so the firecracker
    /// copy in the jailer's chroot cannot be exec'd. A hardened-baseline `/tmp` carries both. Also
    /// caught before the spawn, also [`Infra`](ErrorKind::Infra), also unjailed-safe.
    ScratchDirNoexec(std::path::PathBuf),
    /// [`Limits::vcpus`] is outside what the pinned Firecracker accepts: `vcpu_count` is `[1, 32]`
    /// and must be 1 or an even number. Caught before the spawn, so no VMM is started and torn down
    /// to learn it. [`Infra`](ErrorKind::Infra): pick a legal count and retry.
    UnsupportedVcpus(u8),
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
            VmmError::LimitsUnavailable(e) => write!(f, "resource limits unavailable: {e}"),
            VmmError::ScratchDirNodev(dir) => write!(
                f,
                "scratch dir {} is on a nodev mount: the jailer's chroot /dev/kvm can't be opened \
                 there, so a jailed boot fails; set BSX_SCRATCH_DIR to a path off a nodev mount",
                dir.display()
            ),
            VmmError::ScratchDirNoexec(dir) => write!(
                f,
                "scratch dir {} is on a noexec mount: the firecracker copy in the jailer's chroot \
                 can't be exec'd there, so a jailed boot fails; set BSX_SCRATCH_DIR to a path off \
                 a noexec mount",
                dir.display()
            ),
            VmmError::UnsupportedVcpus(n) => write!(
                f,
                "{n} vCPUs is not a count Firecracker accepts: vcpu_count must be 1 or an even \
                 number in [1, 32]"
            ),
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

/// The three buckets a [`VmmError`] falls into, for a caller that must **branch** rather than
/// render: `Infra` retry or fix the host, `Transport` retire the VM, `Guest` surface to the user.
///
/// Deliberately not `#[non_exhaustive]`: the buckets are the stable contract, and a new
/// `VmmError` variant slots into an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Includes vsock *establishment* (connect, `CONNECT` ack, handshake): "the agent isn't up yet"
    /// lands here, not in `Transport`.
    Infra,
    /// A fault on an *already-established* channel, and
    /// [`ExecUnresponsive`](VmmError::ExecUnresponsive): a guest gone silent is unreliable, not at
    /// fault.
    Transport,
    Guest,
}

impl VmmError {
    /// Classify this error into an [`ErrorKind`] bucket, a public contract an embedder can branch
    /// on, pinned by `kind_buckets_every_variant`. The match is wildcard-free on purpose: with no
    /// `_` arm, a new `#[non_exhaustive]` variant fails to compile here until it is given a
    /// deliberate bucket rather than a silent, likely-wrong one.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            // `GuestUnavailable` is Infra because establishment is infra, and Infra's "retry or fix
            // the host" is its semantics; the variant carries the finer per-VM retry/discard signal.
            VmmError::Unimplemented(_)
            | VmmError::NoKvm
            | VmmError::Artifact(_)
            | VmmError::Timeout(_)
            | VmmError::GuestUnavailable(_)
            | VmmError::Vmm(_)
            // Host- or caller-configuration faults, not the guest's: fix the delegation, the jail
            // posture, the scratch path or the count, then retry.
            | VmmError::LimitsUnavailable(_)
            | VmmError::ScratchDirNodev(_)
            | VmmError::ScratchDirNoexec(_)
            | VmmError::UnsupportedVcpus(_) => ErrorKind::Infra,
            // `ExecUnresponsive` is a liveness fault, so it buckets with `Channel`: "retire the VM,
            // not blame the command" is Transport's contract, not Guest's.
            VmmError::Channel(_) | VmmError::ExecUnresponsive { .. } => ErrorKind::Transport,
            VmmError::GuestExec(_)
            | VmmError::GuestProtocol(_)
            | VmmError::OutputCap { .. }
            | VmmError::ExecTimeout { .. } => ErrorKind::Guest,
        }
    }
}

impl From<ChannelError> for VmmError {
    fn from(e: ChannelError) -> Self {
        VmmError::Channel(e)
    }
}

/// The driver-side file-descriptor budget of one live microVM, the number to size concurrency
/// against `ulimit -n`: N sandboxes hold up to `N × FDS_PER_VM` fds over the process baseline, and a
/// bound like [`Pool`]'s target must stay under the soft limit or the failure is an illegible
/// mid-boot `EMFILE`.
///
/// Measured steady state is 2 on every start path (the console reader's pipe and the sentinel's
/// write end), pinned by `fd_footprint_per_vm_stays_within_budget_and_never_leaks`. The budget sits
/// deliberately above it, so an fd added for cause is a visible bump of this constant rather than
/// silent growth.
pub const FDS_PER_VM: usize = 8;

/// The largest `vcpu_count` the pinned Firecracker accepts. Public because the CLI and the daemon
/// both bound a caller's request at their own edge, and a second copy of this number is how a pin
/// drifts: they read it from here.
pub const MAX_VCPUS: u8 = 32;

/// Whether `vcpus` is a count the pinned Firecracker will boot: `[1, MAX_VCPUS]` and either 1 or
/// even, so `3` and `64` are out and only `0` is unrepresentable in [`Limits::vcpus`]. Exposed so an
/// embedder can check a user-supplied count before building a [`Limits`]; [`Vm::boot`] applies the
/// same predicate, so this is a convenience, never the enforcement.
#[must_use]
pub const fn vcpus_supported(vcpus: u8) -> bool {
    vcpus != 0 && vcpus <= MAX_VCPUS && (vcpus == 1 || vcpus.is_multiple_of(2))
}

/// A per-sandbox resource budget: quantities (vCPUs, memory, deadlines, an output cap), never
/// capabilities, enforced host-side by the VMM cgroup and the exec channel's bounds. The engine
/// exposes the knobs; the hoster sets policy.
///
/// The [`default`](Limits::default) values are load-bearing for embedders, since anyone calling
/// `Limits::default()` relies on them staying small. **Raising one is a breaking change** worth a
/// changelog line and a public-API commit subject; lowering one, or adding a field, is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Guest vCPUs. Typed [`NonZeroU8`] because a zero-vCPU guest is unbootable rather than small,
    /// so the illegal value cannot be constructed. The type cannot express the rest of the domain
    /// (`[1, 32]`, and 1 or even), so `3` and `64` are refused with
    /// [`UnsupportedVcpus`](VmmError::UnsupportedVcpus) before any VMM is spawned.
    pub vcpus: NonZeroU8,
    /// Guest memory, MiB. Typed [`NonZeroU32`] for the same reason as [`vcpus`](Limits::vcpus):
    /// zero is not a budget, so it can't be constructed.
    pub mem_mib: NonZeroU32,
    /// The wall-clock budget for the whole run: the boot-to-userspace deadline and each command's
    /// exec budget.
    ///
    /// The guest agent kills a command past it (the cooperative
    /// [`ExecTimeout`](VmmError::ExecTimeout)), and the host's
    /// [`ExecUnresponsive`](VmmError::ExecUnresponsive) backstop derives from it plus kill slack, so
    /// raising the budget moves both and the transport never cuts off a long quiet command.
    ///
    /// Floored to a 1 ms command budget on the wire and clamped by the agent to 1 h, so the effective
    /// budget is `min(wall, 1 h)` even though [`ExecTimeout`](VmmError::ExecTimeout) names the
    /// configured `wall`. Separate boot and exec ceilings are [`BootConfig::boot_timeout`] and
    /// [`BootConfig::exec_wall`].
    pub wall: Duration,
    /// Aggregate cap, in bytes, on what the host buffers for one exec, stdout + stderr + returned
    /// artifacts (plus a small per-frame accounting floor), so a flooding guest can't grow host
    /// memory without bound. Breach is the typed [`OutputCap`](VmmError::OutputCap).
    pub output_cap: usize,
}

impl Default for Limits {
    /// Conservative defaults (see the type doc): 1 vCPU, 256 MiB, a 30 s wall (boot deadline and
    /// exec budget alike), a 16 MiB output
    /// cap. Treat these as a stable floor, raising any of them is a breaking change for embedders.
    fn default() -> Self {
        Self {
            vcpus: NonZeroU8::MIN, // 1
            // 256; the fallback arm can't fire (256 is nonzero), spelled without `unwrap`
            // because the host path denies it.
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
    /// Requested [`Artifact`] files the guest returned. A requested artifact that didn't exist is
    /// simply absent.
    pub files: Vec<Artifact>,
    /// What the run cost, host-measured (see [`ExecMetrics`]).
    pub metrics: ExecMetrics,
}

/// One returned artifact: a working-directory file the run asked for back, named plus its bytes. A
/// named `#[non_exhaustive]` struct rather than a pair, so a mode or a truncation flag can arrive
/// without a shape break. The `path` is relative and non-climbing, checked by the exec layer, so
/// every embedder writing artifacts to disk inherits that containment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Artifact {
    /// The artifact's path, relative to the run's working directory (validated non-climbing).
    pub path: String,
    /// The file's bytes, exactly as the guest returned them.
    pub data: Vec<u8>,
}

impl Artifact {
    /// Construct an artifact (the struct is `#[non_exhaustive]`, so this is the seam callers and
    /// tests build one through).
    #[must_use]
    pub fn new(path: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            data,
        }
    }
}

/// Host-measured metrics for one exec, the **metrics** leg of the structured run result. Measured
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

/// A microVM sandbox: the embedder-facing lifecycle type over a [`RunningVm`]. The lifecycle is
/// `open → exec (with files + env) → collect outputs → snapshot → close`, every step synchronous and
/// every failure a typed [`VmmError`].
///
/// - **A sandbox is a stateful session.** Repeated `exec`s share the VM's persistent working
///   directory and overlay, which is why `exec` takes `&mut self`: two in flight would read and
///   write each other's files. Run concurrent work in separate sandboxes, the unit of isolation.
/// - **Confined by default.** [`open`](Sandbox::open) and [`boot`](Sandbox::boot) run the VMM under
///   the jailer (chroot, uid/gid drop, seccomp, its own mount and network namespaces) on top of the
///   KVM boundary, which needs real root and `jailer`. The opt-out is a differently-named
///   constructor, [`open_unjailed`](Sandbox::open_unjailed), so it cannot happen by a forgotten flag.
/// - **Inputs arrive at this layer.** Per-exec files and env ride
///   [`exec_with_files`](Sandbox::exec_with_files) under the secret-hygiene contract pinned on
///   [`RunningVm::exec_with_files`]; bulk directories ride [`BootConfig::input_dir`] and
///   [`BootConfig::output_dir`]. An embedder never needs the [`RunningVm`] layer.
#[derive(Debug)]
#[must_use = "dropping a Sandbox kills its microVM"]
pub struct Sandbox {
    vm: RunningVm,
}

impl Sandbox {
    /// Open a sandbox on `config`, ready to run code, **jailed by default**: if `config.jail` is
    /// unset it becomes [`Jail::default`], and the vsock exec channel is enabled (an unset
    /// `config.guest_cid` becomes [`DEFAULT_GUEST_CID`]). Everything else in `config`, artifacts,
    /// resource knobs (see [`BootConfig::with_limits`]), `input_dir`/`output_dir`, networking, is
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

    /// [`open`](Sandbox::open) **without the jailer**, the explicit opt-out for
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

    /// Boot a sandbox under `limits` with the environment-layered defaults ([`BootConfig::from_env`]),
    /// the convenience form of [`open`](Sandbox::open), and like it **jailed by default**.
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
    pub fn exec(&mut self, argv: &[String], stdin: &[u8]) -> Result<RunResult, VmmError> {
        self.vm.exec(argv, stdin)
    }

    /// Run `argv` with per-exec **inputs**: `stdin`, `files_in` injected into the run's working
    /// directory, and `env` set on the spawned command (only, never the guest agent's own process);
    /// the files named in `artifacts` come back in [`RunResult::files`]. Synchronous, same
    /// [`RunResult`] shape as [`exec`](Sandbox::exec).
    ///
    /// Injected file contents and env **values** are covered by the **secret-hygiene contract**
    /// (they never reach an engine log, a [`VmmError`] rendering, or [`console`](Sandbox::console);
    /// wire copies are wiped after send), see [`RunningVm::exec_with_files`], which this wraps,
    /// for the full statement.
    ///
    /// # Errors
    /// As [`exec`](Sandbox::exec).
    pub fn exec_with_files(
        &mut self,
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
    /// Consumes the sandbox, the VMM is stopped first so the image is quiescent (see
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
    /// **jailed** sandbox is a typed refusal (its disk lives in the chroot), take the snapshot
    /// from an [`open_unjailed`](Sandbox::open_unjailed) prewarmed source that runs only the embedder's
    /// own warm-up, then [`Vm::restore`]/[`Pool`] the clones **with a jail**, which is where the
    /// untrusted code runs.
    ///
    /// # Errors
    /// As [`RunningVm::snapshot`].
    pub fn snapshot(&mut self, dir: &std::path::Path) -> Result<Snapshot, VmmError> {
        self.vm.snapshot(dir)
    }

    /// A cheap, cloneable [`KillHandle`] that force-kills this sandbox from any thread, the
    /// host-gave-up path (see [`RunningVm::kill_handle`]): a caller blocked in
    /// [`exec`](Sandbox::exec) gets a typed error and teardown still reclaims everything.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        self.vm.kill_handle()
    }

    /// This sandbox's **name**, unique among live sandboxes on the host, and the handle its scratch
    /// dir, netns, and log lines already share. An audit record naming it can be correlated with
    /// on-disk residue and with the host's own view. See [`RunningVm::name`].
    #[must_use]
    pub fn name(&self) -> &str {
        self.vm.name()
    }

    /// The PID of the VMM process, for out-of-band supervision and the host-side observers (the
    /// eBPF track); valid only while the sandbox lives. See [`RunningVm::vmm_pid`].
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

    /// Whether the VM-lifetime sentinel is armed for this sandbox. See [`RunningVm::sentinel_armed`].
    #[must_use]
    pub fn sentinel_armed(&self) -> bool {
        self.vm.sentinel_armed()
    }

    /// Whether this sandbox fell back to Drop-only cleanup (sentinel could not be armed). See
    /// [`RunningVm::sentinel_degraded`].
    #[must_use]
    pub fn sentinel_degraded(&self) -> bool {
        self.vm.sentinel_degraded()
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
    /// Currently never returns `Err`: teardown is best-effort and the killing lives in `Drop`
    /// (see [`RunningVm::shutdown`]). The signature stays fallible so a teardown step that can
    /// report failure is an additive change rather than a breaking one.
    pub fn shutdown(self) -> Result<(), VmmError> {
        self.vm.shutdown()
    }
}

/// Compiles the book's embedding recipes as doctests of this crate, so a page an embedder copies
/// from cannot stop compiling. Every `rust` block in `docs/embedding-recipes.md` goes through
/// rustdoc with this crate's real dependency graph on the existing `cargo test --workspace` step.
///
/// `mdbook test` cannot do this: it passes only `-L`, never `--extern`, so a 2018-edition
/// `use bsx_engine::…` does not resolve. The book keeps `mdbook test` in `docs.yml` for its other
/// blocks, which is what catches an untagged fence being compiled as Rust.
///
/// `#[cfg(doctest)]` keeps this out of the built library and the rendered docs.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/embedding-recipes.md")]
struct EmbeddingRecipes;
