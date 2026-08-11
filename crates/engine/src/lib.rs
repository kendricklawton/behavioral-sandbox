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
pub use jail::{DEFAULT_JAIL_GID, DEFAULT_JAIL_UID, Jail, JailIds, VMM_PIDS_MAX};

/// The output-image bound the readback applies before parsing, for the fuzz target only.
#[cfg(feature = "fuzzing")]
pub use drives::fuzz;
pub use lifetime::KillHandle;
pub use net::{GuestEgress, GuestLink};
pub use pool::Pool;
pub use sweep::{SweepReport, sweep_orphans};
pub use vm::{BootConfig, DEFAULT_GUEST_CID, RunningVm, Snapshot, VSOCK_PORT, Vm};

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
    /// Nothing is accepting on the guest's exec channel: Firecracker closed (or refused) the vsock
    /// `CONNECT` because no listener holds the guest port, or the vsock socket itself refused
    /// (a dead VMM's stale socket). **Transient/retryable by contract**: the agent may not be up
    /// *yet* (mid-boot, mid-resume) or not *anymore* (a pooled clone died), a retry/pool caller
    /// retries or discards this VM and takes another, rather than treating it as broken infra.
    /// Distinct from [`Timeout`](VmmError::Timeout) (a bounded wait expired while the peer stayed
    /// silent) and from [`Vmm`](VmmError::Vmm) (a protocol-violating or otherwise broken peer).
    GuestUnavailable(String),
    /// The host↔guest exec **channel** failed, a transport or protocol fault. Distinct from a
    /// guest command that merely exits non-zero (a normal [`RunResult`]) or fails to spawn
    /// ([`GuestExec`](VmmError::GuestExec)). Preserves the [`ChannelError`] source.
    Channel(ChannelError),
    /// The **guest agent** could not run the command (e.g. no such binary in the guest, permission
    /// denied), a user fault on a healthy channel, not an infra failure.
    GuestExec(String),
    /// The guest **violated the wire contract** on an otherwise-healthy channel: a returned artifact
    /// path that is absolute or climbs out of the working tree, or a well-framed response the exec
    /// loop never expects there. The host rejects the misbehaving guest rather than trusting it, a
    /// guest fault, distinct from a command that merely failed to run
    /// ([`GuestExec`](VmmError::GuestExec)) or a transport-level [`Channel`](VmmError::Channel) break.
    GuestProtocol(String),
    /// A command's captured output exceeded the host's `limit`-byte cap.
    OutputCap { limit: usize },
    /// A command exceeded its exec wall-clock budget and was killed by the guest, a *user* fault
    /// (the code ran too long), distinct from a transport/boot [`Timeout`](VmmError::Timeout).
    ExecTimeout { limit: Duration },
    /// The **host** gave up on an exec after `limit` because the guest never reported the command's
    /// end (no `Exit`/`TimedOut`) while keeping the channel's idle timer alive, a *liveness/trust*
    /// fault (the guest went silent or hostile), distinct from [`ExecTimeout`](VmmError::ExecTimeout),
    /// where the guest cooperatively reported the timeout. A caller should retire the VM, not blame
    /// the user's command.
    ExecUnresponsive { limit: Duration },
    /// A Firecracker API, boot, or process failure.
    Vmm(String),
    /// `require_limits` was set, but the host can't apply the cpu/memory cgroup caps that would
    /// bound this run, so the boot is **refused** rather than run uncapped. Two ways the caps go
    /// missing: the cgroup v2 cpu/memory controllers aren't delegated to the cgroup root, or the
    /// boot is **unjailed** (the caps live on the jailed VMM's cgroup, so there is nothing to
    /// enforce them). The inverse of the default fail-open posture (caps are DoS
    /// mitigation, not the isolation boundary): a hoster opts in to make the resource envelope
    /// load-bearing. A host-configuration fault, not the guest's, so it buckets [`Infra`](ErrorKind::Infra):
    /// fix the delegation (or drop the jail-less boot) and retry.
    LimitsUnavailable(String),
    /// A **jailed** boot was asked for, but the scratch dir (`BSX_SCRATCH_DIR`) is on a `nodev`
    /// mount, so the `/dev/kvm` device node the jailer mknods inside its chroot is inert and
    /// Firecracker cannot open KVM. Caught **before** the spawn, so the boot fails with this typed
    /// pointer at the fix instead of a raw Firecracker "creating KVM object: Permission denied" deep
    /// in boot. A host-configuration fault (repoint the scratch dir), so it buckets
    /// [`Infra`](ErrorKind::Infra); unjailed boots have no jailer chroot and are never affected.
    ScratchDirNodev(std::path::PathBuf),
    /// A **jailed** boot was asked for, but the scratch dir (`BSX_SCRATCH_DIR`) is on a `noexec`
    /// mount, so the firecracker copy the jailer places inside its chroot cannot be exec'd: the
    /// same jailed-boot killer as [`ScratchDirNodev`](Self::ScratchDirNodev), one mount flag over
    /// (a hardened-baseline `/tmp` carries both). Caught **before** the spawn, a
    /// host-configuration fault (repoint the scratch dir), so it buckets
    /// [`Infra`](ErrorKind::Infra); unjailed boots exec firecracker from `PATH` and are never
    /// affected.
    ScratchDirNoexec(std::path::PathBuf),
    /// [`Limits::vcpus`] is outside what the pinned Firecracker accepts: its `vcpu_count` is
    /// documented `[1, 32]` and must be **1 or an even number**. Caught **before** the spawn, so the
    /// refusal names the constraint instead of a cryptic `PUT /machine-config` fault arriving
    /// mid-boot, after a VMM has already been started and has to be torn down again. A
    /// caller-configuration fault (pick a legal count and retry), so it buckets
    /// [`Infra`](ErrorKind::Infra) with the other "fix the config, then retry" refusals.
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
    /// Classify this error into an [`ErrorKind`] bucket. The mapping is a **public contract** an
    /// embedder can branch on, pinned by a test.
    ///
    /// The match is deliberately **wildcard-free**: [`VmmError`] is `#[non_exhaustive]`, so a future
    /// variant would otherwise fall into a catch-all arm with a silent, likely-wrong bucket. With no
    /// `_` arm, adding a variant fails to compile here until it's given a deliberate bucket, that's
    /// what keeps the contract honest.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            // `GuestUnavailable` is Infra by the taxonomy (establishment is infra), and Infra's
            // contract, "a retry or a fixed host is the response", is exactly its semantics; the
            // variant itself carries the finer "this specific VM: retry/discard" signal.
            VmmError::Unimplemented(_)
            | VmmError::NoKvm
            | VmmError::Artifact(_)
            | VmmError::Timeout(_)
            | VmmError::GuestUnavailable(_)
            | VmmError::Vmm(_)
            // Host- or caller-configuration faults (caps can't be applied; the scratch dir is
            // nodev or noexec; the vCPU count isn't one the VMM accepts), not the guest's: retry
            // after fixing the delegation, the jail posture, the scratch path, or the count,
            // exactly Infra's "fix the host" contract.
            | VmmError::LimitsUnavailable(_)
            | VmmError::ScratchDirNodev(_)
            | VmmError::ScratchDirNoexec(_)
            | VmmError::UnsupportedVcpus(_) => ErrorKind::Infra,
            // `ExecUnresponsive` is a *liveness* fault (the guest went silent/hostile mid-exec), so
            // it buckets with `Channel` as Transport: its own contract is "retire the VM, not blame
            // the command", which is Transport's, not Guest's.
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

/// The driver-side file-descriptor budget of **one live microVM**, across every start path (cold
/// boot, snapshot restore, prewarmed-pool clone, networked), the number to size concurrency against
/// `ulimit -n`: N concurrent sandboxes hold up to `N × FDS_PER_VM` fds on top of the process
/// baseline, and a bound (like [`Pool`]'s target) must keep that under the soft limit with
/// headroom, or the failure is an illegible mid-boot `EMFILE` in whatever syscall lands first.
///
/// Measured steady state is **2 on every start path**, cold, networked, prewarmed restore (dev box,
/// pinned by `fd_footprint_per_vm_stays_within_budget_and_never_leaks`): the console reader's pipe
/// and the lifetime sentinel's pipe write end; exec and API calls open and close transiently, and
/// teardown returns to the exact baseline (no per-run fd leak). The budget is deliberately above
/// the measurement, an fd added for cause is a visible bump of this constant (the pinning test
/// fails otherwise), never silent growth.
pub const FDS_PER_VM: usize = 8;

/// The largest `vcpu_count` the pinned Firecracker accepts. Public because the CLI and the daemon
/// both bound a caller's request at their own edge, and a second copy of this number is how a pin
/// drifts: they read it from here.
pub const MAX_VCPUS: u8 = 32;

/// Whether `vcpus` is a count the pinned Firecracker will actually boot. Its `vcpu_count` is
/// documented as `[1, MAX_VCPUS]` and "either 1 or an even number", so `0`, `3`, and `64` are all
/// out, and only the first of those is unrepresentable in [`Limits::vcpus`]'s `NonZeroU8`.
///
/// Exposed so an embedder can validate a user-supplied count *before* building a [`Limits`] and
/// eating a [`VmmError::UnsupportedVcpus`] at boot; [`Vm::boot`] applies the same predicate itself,
/// so this is a convenience, never the enforcement.
#[must_use]
pub const fn vcpus_supported(vcpus: u8) -> bool {
    vcpus != 0 && vcpus <= MAX_VCPUS && (vcpus == 1 || vcpus.is_multiple_of(2))
}

/// A per-sandbox resource budget. The engine exposes these knobs; the *hoster* sets policy. This is
/// the per-run resource-policy surface: one
/// options struct of **quantities** (vCPUs, memory, deadlines, an output cap), not capabilities,
/// enforced host-side (the VMM cgroup for cpu/memory; the exec channel's bounds for the rest).
///
/// The [`default`](Limits::default) values are **deliberately conservative and load-bearing for
/// embedders**: they cap what a run gets by default, so an embedder that pins this crate and calls
/// `Limits::default()` relies on them staying small. Raising one (more vCPUs, more memory, a longer
/// wall) hands every default run more resource and is a **breaking change worth a changelog line and
/// a public-API commit subject**, not a quiet bump. Lowering one, or adding a new field (the struct
/// is `#[non_exhaustive]`), is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Guest vCPUs. Typed [`NonZeroU8`]: a zero-vCPU guest is not a small budget but an
    /// unbootable one, so the illegal value is unrepresentable rather than a late Firecracker API
    /// error, and the width states the realistic domain.
    ///
    /// The type can't express the rest of the pinned VMM's domain: `vcpu_count` is `[1, 32]` and
    /// must be **1 or an even number**, so `3` and `64` are refused with
    /// [`UnsupportedVcpus`](VmmError::UnsupportedVcpus) *before* any VMM is spawned rather than
    /// surfacing as a mid-boot API fault.
    pub vcpus: NonZeroU8,
    /// Guest memory, MiB. Typed [`NonZeroU32`] for the same reason as [`vcpus`](Limits::vcpus):
    /// zero is not a budget, so it can't be constructed.
    pub mem_mib: NonZeroU32,
    /// The wall-clock budget: the boot-to-userspace deadline **and** each command's exec budget, one
    /// `wall` for the whole run rather than just boot.
    ///
    /// On the exec side it is sent to the guest agent, which kills the command past it (the cooperative
    /// [`ExecTimeout`](VmmError::ExecTimeout)). The host's own give-up deadline, the
    /// [`ExecUnresponsive`](VmmError::ExecUnresponsive) liveness backstop, derives from it plus kill
    /// slack, so raising the budget moves both together and a long quiet command is never cut off by the
    /// transport.
    ///
    /// A zero or sub-millisecond wall is floored to a **1 ms** command budget on the wire, so a tiny wall
    /// still means "very short" rather than nothing. At the top end the guest agent clamps any exec budget
    /// to **1 h**, so the effective budget is `min(wall, 1 h)` even though the reported
    /// [`ExecTimeout`](VmmError::ExecTimeout) names the configured `wall`. A caller needing different boot
    /// and exec ceilings sets [`BootConfig::boot_timeout`] and [`BootConfig::exec_wall`].
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

/// One returned artifact: a working-directory file the run asked for back, named + its bytes. A
/// named struct (not a `(String, Vec<u8>)` pair) so the public seam documents itself and can grow
/// (a mode, a truncation flag) without a tuple-shape break; `#[non_exhaustive]` for the same
/// reason, with [`new`](Self::new) as the construction seam. The `path` is relative and
/// non-climbing, checked by the exec layer, so every embedder that writes artifacts to disk
/// inherits that containment.
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

/// A microVM sandbox: the embedder-facing lifecycle type, backed by a [`RunningVm`]. The lifecycle
/// is `open → exec (with files + env) → collect outputs → snapshot → close`, every step synchronous
/// and every failure a typed [`VmmError`]. Repeated `exec`s form a **stateful session**:
/// the VM is the session, every exec shares its persistent working directory and overlay, and
/// closing the sandbox discards the state.
///
/// **Confined by default.** [`open`](Sandbox::open) and [`boot`](Sandbox::boot) run the VMM **under the
/// jailer**, adding a chroot, a uid/gid drop, seccomp, and its own mount and network namespaces on top of
/// the KVM boundary. That needs real root and the `jailer` binary, and the opt-out is
/// [`open_unjailed`](Sandbox::open_unjailed), deliberately a *differently-named constructor* so an
/// unconfined sandbox cannot happen by a forgotten flag.
///
/// **Inputs at the public API.** Per-exec files and env ride
/// [`exec_with_files`](Sandbox::exec_with_files) under the secret-hygiene contract pinned on
/// [`RunningVm::exec_with_files`]; bulk directories ride [`BootConfig::input_dir`] and
/// [`BootConfig::output_dir`], and [`collect_outputs`](Sandbox::collect_outputs) pulls the guest's
/// `/output` tree back. An embedder never needs to reach the [`RunningVm`] layer.
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
    pub fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<RunResult, VmmError> {
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
    pub fn snapshot(&self, dir: &std::path::Path) -> Result<Snapshot, VmmError> {
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

/// Compile the book's embedding recipes as doctests of this crate.
///
/// `docs/embedding-recipes.md` is the page an embedder copies from, so a recipe that does not
/// compile is worse than no recipe. Pulling the page in here puts every `rust` block in it through
/// rustdoc with this crate's real dependency graph, on the existing `cargo test --workspace` step:
/// no new tool in the gate, and `--extern` handled by cargo rather than by hand.
///
/// `mdbook test` cannot do this job. It passes only `-L`, never `--extern`, so a 2018-edition
/// `use bsx_engine::…` does not resolve; making it work at all needs a hidden `extern crate` line in each
/// block plus a library path with exactly one candidate rlib. The book still gets `mdbook test` in
/// `docs.yml` for the rest of its blocks, which is what catches an untagged fence (an ASCII
/// diagram, say) being compiled as Rust.
///
/// `#[cfg(doctest)]` keeps this out of the built library and out of the rendered docs; it exists
/// only while rustdoc is collecting tests.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/embedding-recipes.md")]
struct EmbeddingRecipes;
