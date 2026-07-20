//! Boot a Firecracker microVM and read its serial console, the raw VM lifecycle beneath
//! [`crate::Sandbox`].
//!
//! [`Vm::boot`] spawns a `firecracker` child, drives its API socket through the boot sequence
//! (boot-source → root drive → machine-config → `InstanceStart`), and waits until the guest's
//! serial console shows it reached userspace. [`RunningVm`] owns the running child; dropping it,
//! or calling [`RunningVm::shutdown`], kills the VMM and reclaims its scratch dir, so a run can
//! never leak a process or socket.
//!
//! **Host path only, `unsafe`-free.** Firecracker wires the guest's `ttyS0` to its own stdout, so
//! "read the child's stdout" is "read the guest console". The jailer ([`Jail`],
//! [`BootConfig::jail`]) preserves this: it is not run with `--daemonize`, so Firecracker keeps the
//! piped stdout and the console still reaches [`Console`].

use std::net::Ipv4Addr;
use std::num::{NonZeroU32, NonZeroU8};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use agent_channel::ClientConnection;

use crate::console::Console;
use crate::drives::{collect_output_image, OutputDevice};
use crate::exec::{
    connect_agent_at, run_exec, ExecBounds, EXEC_KILL_SLACK, PROBE_TIMEOUT, VSOCK_TIMEOUT,
};
use crate::firecracker::{Action, ApiClient};
use crate::jail::{remove_cgroup, Chroot, Jail};
use crate::lifetime::{KillHandle, VmLifetime};
use crate::net::Tap;
use crate::spawn::Spawned;
use crate::{Limits, RunResult, VmmError};

/// Kernel command line for the guest. `console=ttyS0` puts its console on the serial port (which
/// Firecracker hands to our stdout); `reboot=k panic=1` make a guest panic/reboot exit the VMM
/// promptly; `pci=off` trims an unused bus; `random.trust_cpu=on` avoids an entropy stall at boot.
/// `ipv6.disable=1` because the sandbox's network world is IPv4-only (ADR 008): a boot-time
/// disable means the guest never emits IPv6 link-up chatter (MLD, duplicate-address detection)
/// that the tap monitor would honestly flag as a non-IPv4 coverage gap, and a hostile guest
/// cannot re-enable what its kernel never started. The host side of the same stance is
/// `net::disable_ipv6_in_ns`. Firecracker adds `root=/dev/vda` itself from the root drive, so it
/// is not listed here.
const DEFAULT_BOOT_ARGS: &str =
    "console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=on ipv6.disable=1";

/// Substring that marks the guest reached userspace. The default is the **agent rootfs's** ready
/// sentinel, printed by `agent-guest` once its vsock listener accepts: that image is what the
/// engine builds, what `Sandbox` needs (exec requires the in-guest agent), and what every product
/// path boots, so the default must match it, a caller pointing at it must not need to also know a
/// marker. The exception is the pinned Ubuntu CI rootfs (raw boot tests only), whose readiness is
/// its getty prompt: those callers set `login:` explicitly (or via `AGENT_MARKER`).
const DEFAULT_USERSPACE_MARKER: &str = agent_channel::GUEST_READY_MARKER;

/// Names the next per-VM scratch dir uniquely within this process (paired with the PID).
pub(crate) static VM_SEQ: AtomicU64 = AtomicU64::new(0);

/// Firecracker's own stderr, captured to a file in the scratch dir (see `Spawned::launch`).
pub(crate) const FC_STDERR: &str = "fc.stderr";

/// The vsock context id the guest gets (the host is always cid 2). The default when a boot enables
/// the exec channel; overridable per-VM via [`BootConfig::guest_cid`].
pub const DEFAULT_GUEST_CID: u32 = 3;

/// The vsock port the in-guest agent listens on for exec connections, defined in `agent-channel`
/// (it's a host↔guest contract value: the rootfs build writes it into the guest's init line, and
/// the host dials it through Firecracker's vsock unix socket). Re-exported here for callers.
pub use agent_channel::AGENT_VSOCK_PORT;

/// The vsock unix socket Firecracker creates in the scratch dir; the host connects here and speaks
/// the `CONNECT <port>` handshake to reach a guest port.
pub(crate) const VSOCK_UDS: &str = "v.sock";

/// The Firecracker id for the guest's single virtio-net device. `PUT /network-interfaces/{id}` must
/// carry the same id in its path and body, so both come from here. (The guest kernel independently
/// names the resulting NIC `eth0` by enumeration; that literal in the `ip=` boot arg is that other
/// namespace, so it's intentionally not sourced from this constant.)
pub(crate) const IFACE_ID: &str = "eth0";

/// How long a graceful `SendCtrlAltDel` power-off is given to land before teardown stops waiting
/// (the guaranteed kill in `Drop`/`stop_and_reap` takes over), and how often that wait polls.
pub(crate) const POWER_OFF_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const POWER_OFF_POLL: Duration = Duration::from_millis(50);

/// Everything needed to boot one microVM. [`default`](BootConfig::default) is the pure pinned
/// baseline, [`from_env`](BootConfig::from_env) layers the `AGENT_*` overrides on top, and
/// [`with_limits`](BootConfig::with_limits) folds a [`Limits`] budget onto the resource knobs.
/// `#[non_exhaustive]`: construct via [`from_env`](BootConfig::from_env) /
/// [`default`](BootConfig::default) and mutate fields, new features add knobs (tap, jailer,
/// snapshots) without breaking downstream literals.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BootConfig {
    /// The `firecracker` binary (name resolved via `PATH`, or an absolute path).
    pub firecracker: PathBuf,
    /// Uncompressed guest kernel image (an ELF/PVH `vmlinux`, not a `bzImage`).
    pub kernel: PathBuf,
    /// The base rootfs. A read-write boot runs against a fresh per-VM copy; a
    /// [`read_only_root`](BootConfig::read_only_root) boot shares it directly (see [`Vm::boot`]).
    pub rootfs: PathBuf,
    /// Guest vCPUs. Typed [`NonZeroU8`] like [`Limits::vcpus`], so a zero-vCPU boot can't be
    /// configured.
    pub vcpus: NonZeroU8,
    /// Guest memory, MiB. Typed [`NonZeroU32`] like [`Limits::mem_mib`].
    pub mem_mib: NonZeroU32,
    /// The guest kernel command line.
    pub boot_args: String,
    /// Console substring that signals userspace was reached.
    pub userspace_marker: String,
    /// Upper bound on boot-to-userspace before the boot is a typed timeout.
    pub boot_timeout: Duration,
    /// Wall-clock budget for each command run through this VM's `exec`: the guest agent kills the
    /// command past it, and the host's own give-up deadline is derived from it. At the public API this is
    /// [`Limits::wall`], one wall for the whole run (ADR 013), which
    /// [`with_limits`](BootConfig::with_limits) folds into both `boot_timeout` and this; the split
    /// exists at this layer so a driver-level caller can give boot and exec different ceilings.
    /// See [`Limits::wall`] for the semantics (including the nonzero requirement).
    pub exec_wall: Duration,
    /// Aggregate byte cap on what the host buffers per exec (stdout + stderr + artifacts), folded
    /// from [`Limits::output_cap`]. See [`Limits::output_cap`].
    pub output_cap: usize,
    /// Configure a virtio-vsock device with this guest context id, enabling the exec channel
    /// ([`RunningVm::connect_agent`]). `None` (the default) boots with no vsock, the boot-only
    /// demo path. Set to `Some(`[`DEFAULT_GUEST_CID`]`)` to enable exec.
    pub guest_cid: Option<u32>,
    /// Boot the base rootfs **read-only and shared** (no per-VM copy) under a per-run **tmpfs
    /// overlay**, so `/` is writable but the base is never mutated and many VMs share one
    /// page-cache-deduped base. Requires a rootfs whose `/sbin/overlay-init` builds the overlay
    /// (the agent image from `cargo xtask build-rootfs`); the driver appends
    /// `init=/sbin/overlay-init overlay_size=<mem/2>M` to the kernel command line. `false` (the
    /// default) keeps the copy-then-boot-read-write path. One concept, not two knobs: a read-only
    /// base *implies* the overlay (without it a read-only `/` would break the agent's `/tmp` workdir).
    pub read_only_root: bool,
    /// A host directory to inject as **bulk read-only input**: the driver builds an ext4 from
    /// it and attaches it as a second block device (`/dev/vdb`, `O_RDONLY`); the agent rootfs mounts
    /// it at `/input`, so a command reads it as `/input/...`. This is the whole-working-dir /
    /// large-file path, the vsock channel's [`Request::PutFile`](agent_channel::Request::PutFile) carries only small per-frame files.
    /// `None` (the default) attaches no input device. Building the image needs `mke2fs` + `truncate`.
    pub input_dir: Option<PathBuf>,
    /// A host directory to receive **bulk output**: the driver attaches a blank, **writable**
    /// ext4 as a third block device (`/dev/vd?`, labelled `agent-output`); the agent rootfs mounts it
    /// read-write at `/output`, so a command's files under `/output/...` are pulled back here by
    /// [`RunningVm::collect_outputs`]. This is the whole-working-dir / large-file counterpart to the
    /// vsock channel's per-frame [`Response::File`](agent_channel::Response::File) artifacts. `None` (the default) attaches no output
    /// device. Readback needs `e2fsck` + `debugfs` (e2fsprogs) on the host; the directory is created
    /// if missing and receives the guest's `/output` tree (host-escaping symlinks are dropped).
    pub output_dir: Option<PathBuf>,
    /// Give the guest a **virtio-net** interface backed by a per-VM host **tap** device. The
    /// driver creates the tap (`ip tuntap`, needs `CAP_NET_ADMIN`), attaches it via
    /// `PUT /network-interfaces`, and deletes it on teardown. `false` (the default) boots with **no
    /// NIC**, deny-by-default. Even when `true`, the guest gets an *unconfigured* `eth0`: this box
    /// adds no address, route, or masquerade (ADR 008), so the guest reaches nothing until
    /// addressing lands. Needs `ip` (iproute2) on the host.
    pub enable_network: bool,
    /// Run Firecracker under its **jailer**: a chroot, a uid/gid drop, and the jailer's mount
    /// namespace confine the VMM process itself (see [`Jail`]). `None` (the default) spawns
    /// Firecracker directly. Setting it needs **real root** (the jailer `mknod`s device nodes, which
    /// `EPERM` in a non-initial user namespace) and the `jailer` binary. Composes with every other
    /// boot feature: `guest_cid` (the vsock exec channel is staged chroot-relative under
    /// the dropped uid), `read_only_root` (the shared base is bind-mounted into the chroot),
    /// `enable_network` (the tap lives in a per-VM netns the jailer joins via `--netns`), and
    /// `input_dir`/`output_dir` (the images are built in place inside the chroot).
    pub jail: Option<Jail>,
    /// Base directory for per-VM **scratch** dirs (`<scratch_dir>/agent-<pid>-<n>`), holding the
    /// read-write rootfs copy, the jail chroot, block-device images, and sockets. Defaults to `/tmp`
    /// (overridable via `AGENT_SCRATCH_DIR`). **This matters on constrained hardware:** `/tmp` is
    /// often `tmpfs` (host RAM), so a read-write boot's full-rootfs copy is charged to RAM, on a
    /// small box that alone can exhaust memory (or `ENOSPC` a small tmpfs) and fail the boot. Point
    /// this at real disk to bound RAM use, or prefer [`read_only_root`](BootConfig::read_only_root),
    /// which shares the base with **no** copy. The base must already exist; each VM's own subdir is
    /// created (and reclaimed) by the driver.
    pub scratch_dir: PathBuf,
}

impl BootConfig {
    /// Layer the environment overrides, `AGENT_FIRECRACKER`, `AGENT_KERNEL`, `AGENT_ROOTFS`,
    /// `AGENT_MARKER`, onto [`BootConfig::default`]. The resource knobs (`vcpus`, `mem_mib`,
    /// `boot_timeout`) have no env key; they come from [`Limits`] via
    /// [`with_limits`](BootConfig::with_limits).
    pub fn from_env() -> Self {
        Self::from_env_with(|key| std::env::var_os(key))
    }

    /// The composable core of [`from_env`](BootConfig::from_env): every override comes through
    /// `lookup`, keyed by the `AGENT_*` env name. Two uses: precedence is unit-testable without
    /// mutating the process environment (which races under the parallel runner and is `unsafe` from
    /// edition 2024); and a caller can **layer another source under the environment** by returning
    /// the real env var if set, else its own value, e.g. the CLI's `.agent.toml` file layer resolves
    /// `env > file > defaults` by composing `std::env::var_os(key).or_else(|| file.get(key))`.
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = lookup("AGENT_FIRECRACKER") {
            cfg.firecracker = PathBuf::from(v);
        }
        if let Some(v) = lookup("AGENT_KERNEL") {
            cfg.kernel = PathBuf::from(v);
        }
        if let Some(v) = lookup("AGENT_ROOTFS") {
            cfg.rootfs = PathBuf::from(v);
        }
        // Strict UTF-8 like `env::var`: a non-UTF-8 marker can't be searched for anyway.
        if let Some(v) = lookup("AGENT_MARKER").and_then(|v| v.into_string().ok()) {
            cfg.userspace_marker = v;
        }
        if let Some(v) = lookup("AGENT_SCRATCH_DIR") {
            cfg.scratch_dir = PathBuf::from(v);
        }
        cfg
    }

    /// Fold a per-sandbox [`Limits`] budget onto the config: vCPUs, memory, the wall (one wall for
    /// the whole run, ADR 013, it becomes both the boot deadline *and* the per-exec budget),
    /// and the output cap.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.vcpus = limits.vcpus;
        self.mem_mib = limits.mem_mib;
        self.boot_timeout = limits.wall;
        self.exec_wall = limits.wall;
        self.output_cap = limits.output_cap;
        self
    }
}

impl Default for BootConfig {
    /// The pure pinned defaults, no environment reads (that's [`BootConfig::from_env`]), so
    /// `default()` is deterministic. The resource knobs mirror [`Limits::default`] so the two
    /// baselines cannot silently diverge.
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            firecracker: PathBuf::from("firecracker"),
            kernel: PathBuf::from("artifacts/vmlinux"),
            // The agent image (`cargo xtask build-rootfs` / `self-host`): the one every product
            // path boots, and the one the default marker matches. The Ubuntu CI image
            // (`artifacts/rootfs.ext4`) is a raw-boot-test fixture, named explicitly there.
            rootfs: PathBuf::from("artifacts/rootfs-agent.ext4"),
            vcpus: limits.vcpus,
            mem_mib: limits.mem_mib,
            boot_args: DEFAULT_BOOT_ARGS.to_string(),
            userspace_marker: DEFAULT_USERSPACE_MARKER.to_string(),
            boot_timeout: limits.wall,
            exec_wall: limits.wall,
            output_cap: limits.output_cap,
            guest_cid: None,
            read_only_root: false,
            input_dir: None,
            output_dir: None,
            enable_network: false,
            jail: None,
            scratch_dir: PathBuf::from("/tmp"),
        }
    }
}

/// A booted-and-ready microVM: the `firecracker` child, its API socket, scratch dir, and the
/// captured console. Guaranteed teardown lives in `Drop`, so losing this value can't leak the VMM,
/// and the cgroup-owned lifetime (the sentinel behind [`KillHandle`]) covers the paths `Drop`
/// can't: losing the whole *process* (Ctrl-C, SIGKILL, OOM) can't leak it either.
#[derive(Debug)]
#[must_use = "dropping a RunningVm kills its microVM"]
pub struct RunningVm {
    pub(crate) child: Child,
    pub(crate) workdir: PathBuf,
    pub(crate) console: Console,
    pub(crate) api: ApiClient,
    pub(crate) boot_latency: Duration,
    /// The active root-disk backing file: a per-VM copy for a read-write boot, the shared read-only
    /// base for a `read_only_root` boot, or the snapshot bundle's private copy for a restore. Held so
    /// [`snapshot`](RunningVm::snapshot) can bundle it into a portable snapshot.
    pub(crate) rootfs: PathBuf,
    /// This VM was produced by [`Vm::restore`], so [`rootfs`](Self::rootfs) is a placeholder (the live
    /// disk is an anonymous inode with no host path) and re-snapshotting it is refused.
    pub(crate) restored: bool,
    /// This VM has a bulk **input** block device (from `input_dir`), whose image lives in the scratch
    /// dir. A snapshot bakes in that path, but the scratch dir is gone after teardown, so the VM can't
    /// be restored, `snapshot` refuses it. (The input image itself is reclaimed with the workdir.)
    pub(crate) has_input: bool,
    /// The vsock unix socket Firecracker created, if this VM was booted with a `guest_cid`.
    pub(crate) vsock_uds: Option<PathBuf>,
    /// The writable output image (in `workdir`) and the host directory to extract it into, when the
    /// boot config set `output_dir`; `None` otherwise. Read back by [`RunningVm::collect_outputs`].
    pub(crate) output: Option<OutputDevice>,
    /// The per-VM host tap backing the guest's virtio-net, when the boot config set
    /// `enable_network`. Lives **outside** `workdir`, so teardown must delete it explicitly.
    pub(crate) tap: Option<Tap>,
    /// The jail this VMM runs in, when the boot config set `jail`. Its chroot lives under
    /// `workdir` (reclaimed with it), but the jailer's cgroup is outside, so teardown removes it
    /// explicitly, like the tap.
    pub(crate) chroot: Option<Chroot>,
    /// The cgroup-owned lifetime machinery: the VM's lifetime cgroup, the armed sentinel
    /// that reaps the VM if this *process* dies, and the [`KillHandle`] state. Torn down with the
    /// VM on every path.
    pub(crate) lifetime: VmLifetime,
    /// Per-exec wall-clock budget, from [`BootConfig::exec_wall`] at boot/restore time; every
    /// `exec` on this VM runs under it (the host backstop is derived from it plus kill slack).
    pub(crate) exec_wall: Duration,
    /// Per-exec aggregate output cap in bytes, from [`BootConfig::output_cap`].
    pub(crate) output_cap: usize,
    /// The guest's vCPU count as configured at boot ([`BootConfig::vcpus`], what
    /// `PUT /machine-config` set), recorded into a [`Snapshot`]'s envelope so a jailed restore can
    /// derive its `cpu.max` from the clone's *true* parallelism. On a restore this mirrors the
    /// restoring `config` and is never read, a restored VM refuses snapshotting.
    pub(crate) vcpus: NonZeroU8,
    /// The guest's RAM as configured at boot ([`BootConfig::mem_mib`]). Used to scale the
    /// `/snapshot/create` socket timeout: that call blocks until Firecracker writes the whole
    /// memory file, so a multi-GiB guest must not be bounded by the instant-reply default.
    pub(crate) mem_mib: NonZeroU32,
}

/// A microVM snapshot written by [`RunningVm::snapshot`]: the device + vCPU **state** file, the guest
/// **memory** file (roughly the guest's RAM size), and the **root disk**. [`Vm::restore`] rebuilds a
/// VM from these on a fresh VMM.
///
/// The disk is one of two shapes. A **read-write** boot bundles a private, point-in-time copy that
/// restore stages back, so the clone shares no writable backing with its source (which may be gone). A
/// **`read_only_root`** boot (a "prewarmed" snapshot) references the shared, persistent base in place, so N
/// clones restored from one bundle share it read-only (page-cache-deduped) while each gets its own
/// in-RAM overlay. A **prewarmed** snapshot also carries the vsock exec channel, so a restored clone can
/// run code immediately.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub(crate) state: PathBuf,
    pub(crate) mem: PathBuf,
    /// The bundle's point-in-time copy of the root disk (a read-write boot), or the shared read-only
    /// base itself (a `read_only_root` boot, where [`shared_base`](Self::shared_base) is set).
    pub(crate) root_drive: PathBuf,
    /// The host path the snapshot baked in for the root disk (where the source VM booted it).
    /// Firecracker opens the disk *here* during `PUT /snapshot/load`.
    pub(crate) root_backing: PathBuf,
    /// The root disk is a **read-only shared base** at a persistent path (a `read_only_root` boot):
    /// restore references it in place (no copy, no staging), and many clones share it read-only. When
    /// unset, the disk is a private per-VM copy that restore stages at `root_backing`.
    pub(crate) shared_base: bool,
    /// The source ran the vsock exec channel, so restored clones can be `exec`'d. The socket path was
    /// baked in **relative** (`v.sock`), so Firecracker re-binds it in each restored VMM's own scratch
    /// dir (its cwd) rather than on one shared absolute path, letting concurrent clones coexist.
    pub(crate) has_vsock: bool,
    /// The source had a NIC, and the snapshot baked in this host tap name (`host_dev_name`). The
    /// pinned Firecracker (v1.9) has no `network_overrides` on load (probed: "unknown field"), so
    /// restore must recreate a tap with **exactly this name**, trivially satisfied by the netns
    /// model (ADR 017): each clone recreates the fixed-name tap inside its **own per-VM network
    /// namespace**, so any number of networked clones coexist (no name collision across namespaces)
    /// and the snapshot's baked-in guest address/MAC/routes are already correct in each, with no
    /// re-addressing needed. (This retired ADR 011's one-live-networked-clone limit.)
    pub(crate) tap_name: Option<String>,
    /// The source's vCPU count, the restored clone's **true** parallelism, since the vCPUs come
    /// from the snapshot state (restore issues no `PUT /machine-config`) and nothing forces the
    /// restoring `config` to agree. A jailed restore derives its `cpu.max` from this, the CPU
    /// analogue of deriving `memory.max` from the memory file's true size: the cap tracks what the
    /// clone actually runs, so a `config` mis-declaring the envelope can neither throttle nor
    /// over-grant a legitimate clone.
    pub(crate) vcpus: NonZeroU8,
}

impl Snapshot {
    /// The device + vCPU state file.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state
    }

    /// The guest memory file (roughly the guest's RAM size).
    #[must_use]
    pub fn mem_path(&self) -> &Path {
        &self.mem
    }

    /// The root disk restore uses: the bundle's private copy (a read-write snapshot), or the shared
    /// read-only base referenced in place (a `read_only_root` prewarmed snapshot).
    #[must_use]
    pub fn root_drive_path(&self) -> &Path {
        &self.root_drive
    }

    /// The source's vCPU count, what a clone restored from this bundle actually runs (the vCPUs
    /// come from the snapshot state, not the restoring config). A jailed restore's `cpu.max` is
    /// derived from this; exposed so an embedder sizing a pool can read a bundle's CPU envelope.
    #[must_use]
    pub fn vcpus(&self) -> NonZeroU8 {
        self.vcpus
    }
}

/// Boot entry point, `Vm::boot(config) -> RunningVm`.
#[derive(Debug)]
pub struct Vm;

impl Vm {
    /// Boot a microVM under `config` and return once the guest reaches userspace.
    ///
    /// By default copies the base rootfs into a fresh per-VM scratch dir and boots the copy
    /// read-write, so repeated runs stay independent and the pinned base is never mutated. With
    /// [`read_only_root`](BootConfig::read_only_root) it instead shares the base read-only (no copy)
    /// and the guest layers a per-run tmpfs overlay over it, same "base never mutated" guarantee,
    /// far less per-VM cost.
    ///
    /// # Errors
    /// [`VmmError::NoKvm`] without `/dev/kvm`, [`VmmError::Artifact`] for a missing kernel/rootfs
    /// /binary, [`VmmError::Timeout`] if boot-to-userspace exceeds `boot_timeout`, and
    /// [`VmmError::Vmm`] for any Firecracker API or process failure. On any error the child is
    /// killed and the scratch dir removed before returning.
    pub fn boot(config: BootConfig) -> Result<RunningVm, VmmError> {
        // The jail composes with every boot feature now: vsock (socket staged
        // chroot-relative under the dropped uid), the read-only overlay (shared base bind-mounted
        // into the chroot), a NIC (the tap lives in a per-VM netns the jailer joins), and bulk I/O
        // (images built in place inside the chroot). The ADR-013 deny-by-default refusal that
        // stood here while combinations were unjailed retired with its last member; a new
        // not-yet-jailed feature must reinstate it rather than boot half-confined.
        //
        // KVM checked here, not in `launch`, so the launch/boot-failure machinery stays unit-testable
        // on hosts without KVM (a fake "firecracker" needs no VM).
        if !Path::new("/dev/kvm").exists() {
            return Err(VmmError::NoKvm);
        }
        // One deadline for the whole boot: host-side staging (`launch`) and the API boot (`run_boot`)
        // share it, so a slow rootfs copy can't run unbounded before the boot's own timeout starts
        // (ADR 013).
        let deadline = crate::spawn::boot_deadline(config.boot_timeout);
        let mut spawned = Spawned::launch(&config, deadline)?;
        let boot_latency = match spawned.run_boot(&config, deadline) {
            Ok(latency) => latency,
            Err(e) => return Err(spawned.abort(e)),
        };
        spawned.into_running(boot_latency, &config)
    }
}

impl RunningVm {
    /// Boot-to-userspace latency, the number that matters (measured from `InstanceStart`).
    #[must_use]
    pub fn boot_latency(&self) -> Duration {
        self.boot_latency
    }

    /// A UTF-8-lossy snapshot of the serial console captured so far.
    #[must_use]
    pub fn console(&self) -> String {
        self.console.snapshot()
    }

    /// The PID of the `firecracker` VMM process. Useful for out-of-band supervision, putting the VMM
    /// in a cgroup, attaching host-side observers to it, or asserting it was reaped on
    /// teardown. The process is killed and reaped when this `RunningVm` is dropped, so the PID is only
    /// valid for the VM's lifetime.
    #[must_use]
    pub fn vmm_pid(&self) -> u32 {
        self.child.id()
    }

    /// Whether this VM's VMM process is still running, reaping it if it has exited. Unlike a
    /// `/proc/<pid>` existence probe, this can't be fooled by an **unreaped zombie**: a pooled clone's
    /// VMM is nobody's `wait()` until it's taken, and a zombie keeps its `/proc/<pid>` entry, so the
    /// probe would read a dead clone as alive. `try_wait` sees the real exit (and reaps it). An
    /// unexpected `try_wait` error is treated as not-alive: a clone we can't even query is not worth
    /// handing out.
    pub(crate) fn vmm_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// A cheap, cloneable, `Send + Sync` [`KillHandle`] that force-kills this VM from any thread,
    /// the **host-gave-up path**. `exec` borrows `&self` and `shutdown` consumes `self`, so
    /// a caller blocked in `exec` can't otherwise be stopped; killing through the handle makes the
    /// VMM's vsock peer close, and the blocked call returns a typed error. The exec deadline covers
    /// the common timeout case; this covers the host abandoning the run entirely. After a kill,
    /// this VM's `Drop`/`shutdown` still reclaims all host residue, exactly as for a crashed guest.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        self.lifetime.kill_handle()
    }

    /// The host end of the per-VM point-to-point link, when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise. The guest can reach this
    /// address over its `eth0` (and nothing beyond it, deny-by-default).
    #[must_use]
    pub fn host_ip(&self) -> Option<Ipv4Addr> {
        self.tap.as_ref().map(|t| t.host_ip)
    }

    /// The guest's `eth0` address, when booted with [`enable_network`](BootConfig::enable_network);
    /// `None` otherwise. Reachable from the host over the tap.
    #[must_use]
    pub fn guest_ip(&self) -> Option<Ipv4Addr> {
        self.tap.as_ref().map(|t| t.guest_ip)
    }

    /// The host tap interface backing this VM's NIC, when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise. This is the handle the
    /// host-side eBPF track binds policy to. The tap lives **inside** this VM's network
    /// namespace ([`netns`](Self::netns)), so the loader resolves it to an ifindex and attaches
    /// `tc`/XDP programs to *this* sandbox's traffic **within that netns**, pair it with `netns()`.
    #[must_use]
    pub fn tap_name(&self) -> Option<&str> {
        self.tap.as_ref().map(|t| t.name.as_str())
    }

    /// The per-VM **network namespace** name backing this VM's NIC, when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise. The tap the guest's virtio-net
    /// rides ([`tap_name`](Self::tap_name)) lives inside it, isolated from the host and every other VM,
    /// so the eBPF loader enters this netns (its handle is `/run/netns/<name>`) to attach to
    /// the tap. Also the unit of isolation that replaces the per-VM /30 reservation.
    #[must_use]
    pub fn netns(&self) -> Option<&str> {
        self.tap.as_ref().map(|t| t.netns.as_str())
    }

    /// Connect to the in-guest agent over vsock and complete the channel handshake, returning a
    /// protocol-ready [`ClientConnection`]. This is the host side of the exec path (`exec` builds
    /// `exec` on top): it dials Firecracker's vsock socket, speaks the `CONNECT <port>` handshake,
    /// sets read/write deadlines, then does the channel handshake.
    ///
    /// # Errors
    /// [`VmmError::GuestUnavailable`] if nothing is listening on `port` in the guest (not up yet, or
    /// not anymore), the retryable case; [`VmmError::Vmm`] if the VM was booted without a
    /// `guest_cid` or on any other I/O or channel failure; [`VmmError::Timeout`] if the connect
    /// exceeds the deadline.
    pub fn connect_agent(&self, port: u32) -> Result<ClientConnection<UnixStream>, VmmError> {
        connect_agent_at(self.require_vsock()?, port, VSOCK_TIMEOUT)
    }

    /// Probe the exec channel: connect to the guest agent and complete the handshakes, discarding
    /// the connection (the agent serves one connection then loops back to accept, so a
    /// connect-and-close just cycles it). The prewarmed [`Pool`](crate::Pool)'s health check on a clone
    /// that has been sitting idle: a dead or wedged clone surfaces as a typed error, most
    /// specifically [`VmmError::GuestUnavailable`], so the pool can discard it and serve another.
    /// Deliberately short-deadlined: an idle, healthy agent accepts immediately.
    pub(crate) fn probe_agent(&self) -> Result<(), VmmError> {
        connect_agent_at(self.require_vsock()?, AGENT_VSOCK_PORT, PROBE_TIMEOUT).map(|_| ())
    }

    /// The Firecracker vsock socket, or a typed error naming the fix if the VM was booted without a
    /// `guest_cid`. Shared by [`connect_agent`](Self::connect_agent) and
    /// [`exec_with_files`](Self::exec_with_files) so the guard and its message live once.
    fn require_vsock(&self) -> Result<&Path, VmmError> {
        self.vsock_uds.as_deref().ok_or_else(|| {
            VmmError::Vmm("this microVM was booted without vsock (set BootConfig.guest_cid)".into())
        })
    }

    /// Run `argv` in the guest, feeding it `stdin`, and collect its stdout/stderr/exit.
    ///
    /// Connects to the in-guest agent over vsock ([`connect_agent`](Self::connect_agent)) and speaks
    /// the exec protocol. The captured output is bounded ([`BootConfig::output_cap`]); a command
    /// that exits non-zero is a normal [`RunResult`], not an error. Each call opens a fresh
    /// connection (the guest agent serves one command per connection and loops), and repeated
    /// `exec`s **compose into a stateful session** (ADR 019): the agent serves every one from
    /// the same persistent working directory, so files injected or written by one command are
    /// visible to the next, until the VM (and its overlay) is torn down.
    ///
    /// # Errors
    /// A typed [`VmmError`] across the taxonomy's three buckets: **establishment**,
    /// [`VmmError::GuestUnavailable`] if the agent isn't listening (retryable), [`VmmError::Vmm`] if
    /// the VM has no vsock, [`VmmError::Timeout`]
    /// on a stalled connect/ack; **steady-state transport**, [`VmmError::Channel`] on a mid-exec
    /// framing/IO fault; **guest fault**, [`VmmError::GuestExec`] if the agent couldn't run the
    /// command, [`VmmError::ExecTimeout`] if it outran its budget, [`VmmError::OutputCap`] if it
    /// flooded output. A command that merely exits non-zero (even by signal) is a normal
    /// [`RunResult`], not an error.
    pub fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<RunResult, VmmError> {
        self.exec_with_files(argv, stdin, &[], &[], &[])
    }

    /// Run `argv` with `stdin`, first injecting `files_in` into the run's working directory and
    /// `env` into the spawned command's environment, then returning the files named in `artifacts`
    /// (paths relative to that directory) in [`RunResult::files`]. The richer form of
    /// [`exec`](Self::exec); the injected files and env ride the exec request's frames, so each is
    /// bounded by the channel's per-frame cap, and the total captured output+artifacts is bounded
    /// by this VM's [`BootConfig::output_cap`] (default 16 MiB).
    ///
    /// **Env scope.** The variables are set on the **spawned command only**, the guest agent
    /// applies them via `Command::env`, never its own process, so one run's environment can't
    /// bleed into the agent or a later run.
    ///
    /// **Secret hygiene (pinned contract).** Injected file contents and env *values* are treated as
    /// secrets: they never appear in an engine log line, in any [`VmmError`]'s `Display`/`Debug`, or
    /// on the serial console ([`console`](Self::console)), an error path may name a file *path* or
    /// an env *key*, never a value, and the wire copies the driver builds are zero-wiped after
    /// send, not just freed (best-effort: the caller's own buffers and the kernel's socket buffers
    /// are out of the engine's reach). What the *command* does with its inputs (echo them to stdout,
    /// write them to `/output`) is the run's own data in [`RunResult`], not an engine surface. The
    /// audit log will record *that* inputs were injected, paths/keys/sizes or
    /// hashes, never contents.
    ///
    /// # Errors
    /// As [`exec`](Self::exec).
    pub fn exec_with_files(
        &self,
        argv: &[String],
        stdin: &[u8],
        files_in: &[(String, Vec<u8>)],
        env: &[(String, String)],
        artifacts: &[String],
    ) -> Result<RunResult, VmmError> {
        let uds = self.require_vsock()?;
        // The host's total patience: the command's own budget (the `Limits::exec_wall` knob this VM
        // booted with) plus the agent's kill+report margin. Derived from the *actual* budget so a
        // raised budget can't leave the socket idle timeout cutting off a long quiet command. Used
        // both as the socket's per-read idle timeout and, inside `run_exec`, as the wall-clock
        // deadline on the loop, so the agent's `TimedOut` (at `budget`) reaches us first, and a
        // silent guest can't park us.
        let budget = self.exec_wall;
        let wall = budget.saturating_add(EXEC_KILL_SLACK);
        let mut conn = connect_agent_at(uds, AGENT_VSOCK_PORT, wall)?;
        run_exec(
            &mut conn,
            argv,
            stdin,
            files_in,
            env,
            artifacts,
            ExecBounds {
                timeout: budget,
                wall,
                max_output: self.output_cap,
            },
        )
    }

    /// Pull the guest's `/output` tree back to the host directory set as [`BootConfig::output_dir`],
    /// returning the captured paths (relative to that directory, sorted).
    ///
    /// The bulk counterpart to the per-file [`RunResult::files`] channel path: the guest wrote to a
    /// writable block device (mounted at `/output`), and here the driver reads that image back. It
    /// **consumes the VM**, the VMM is stopped first (a cooperative power-off, then a hard kill) so
    /// it has released the image and flushed the guest's writes; reading a live, VMM-held image would
    /// race the guest and corrupt the ext4 journal `e2fsck` replays. Read-back is fully **rootless**:
    /// `e2fsck` recovers the journal, then `debugfs rdump` extracts the tree, no loopback, no
    /// `mount`, no `sudo`.
    ///
    /// Guest-controlled contents are sanitised: `lost+found` is dropped; symlinks whose target
    /// escapes the destination (absolute, or `..` climbing out) are removed, so a later host read of
    /// the results can't be redirected onto the host filesystem; and the extraction is bounded in
    /// both real bytes and wall-clock time, so a sparse-file or
    /// pathological image can't exhaust host disk or hang teardown. Dropping the consumed VM reclaims
    /// the scratch dir, the image included.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the VM was booted without an output device (no `output_dir`), or on a
    /// host-side readback failure; [`VmmError::Artifact`] if `e2fsck`/`debugfs` are missing;
    /// [`VmmError::OutputCap`] if the extracted tree exceeds the byte cap; [`VmmError::Timeout`] if
    /// readback outruns its deadline.
    pub fn collect_outputs(mut self) -> Result<Vec<String>, VmmError> {
        let output = self.output.clone().ok_or_else(|| {
            VmmError::Vmm(
                "this microVM was booted without an output device (set BootConfig.output_dir)"
                    .into(),
            )
        })?;
        // Stop the VMM so it releases the image fd and the on-disk ext4 is consistent *before* we
        // read it. `self` drops at the end of this method → `Drop` reclaims the scratch dir.
        self.stop_and_reap();
        collect_output_image(&output.image, &output.dest)
    }

    /// Issue the cooperative power-off ask (`SendCtrlAltDel`) **without waiting** for the guest to
    /// act, so a batch caller ([`Pool::shutdown`](crate::Pool::shutdown)) can ask every clone first
    /// and then poll them all against one shared grace, paying one [`POWER_OFF_TIMEOUT`], not one per
    /// VM. Marks teardown begun (so a `KillHandle` no-ops on the soon-to-be-reaped pid), like
    /// [`power_off_and_wait`](Self::power_off_and_wait). A guest still alive at the caller's deadline
    /// is hard-killed by `Drop`, the same guaranteed teardown, just without the wait.
    pub(crate) fn request_power_off(&mut self) {
        self.lifetime.mark_down();
        let _ = self.api.put("/actions", &Action::SendCtrlAltDel);
    }

    /// Ask the guest to power off (best-effort `SendCtrlAltDel`, an x86 ACPI-ish nicety over i8042),
    /// then poll for the VMM to exit until `deadline`. Returns `true` if it exited on its own. The
    /// shared core of `shutdown` and `stop_and_reap`, so the action and the poll cadence live once;
    /// the *guaranteed* kill is the caller's (or `Drop`'s), never this.
    fn power_off_and_wait(&mut self, deadline: Instant) -> bool {
        // Flag teardown before any reap below (this loop's `try_wait`, or the caller's kill). A
        // degraded-host `KillHandle` falls back to signalling a raw pid, and `collect_outputs` reaps
        // the VMM here then runs a multi-second image readback before this VM drops into `teardown`,
        // so without marking down now, the reaped (recyclable) pid stays "killable" for that whole
        // window and a fired handle could `kill -9` an unrelated process. Idempotent with the later
        // `teardown`/`abort` calls.
        self.lifetime.mark_down();
        // `SendCtrlAltDel` is an x86 i8042 action; Firecracker rejects it on aarch64, and any API
        // error means the guest was never asked to power off. Polling for a clean exit would then
        // just burn the whole grace before the caller's hard kill, so skip straight to that.
        if self.api.put("/actions", &Action::SendCtrlAltDel).is_err() {
            return false;
        }
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return true, // clean power-off (guest ran its umount on shutdown)
                Ok(None) if Instant::now() >= deadline => return false,
                Ok(None) => std::thread::sleep(POWER_OFF_POLL),
                Err(_) => return false, // `try_wait` failed (near-impossible): let the caller force it
            }
        }
    }

    /// Best-effort power-off, then **guarantee** the VMM is dead and reaped, so its fd to the output
    /// image is released before readback. Idempotent with `Drop`'s teardown (a second kill/wait on an
    /// already-reaped child is a harmless no-op).
    fn stop_and_reap(&mut self) {
        if !self.power_off_and_wait(Instant::now() + POWER_OFF_TIMEOUT) {
            // A wedged (or unwaitable) guest: hard-kill so the fd to the output image is released
            // before readback rather than trusting a later `Drop`. The `-o sync` mount means the
            // command's completed writes are already on the image; `e2fsck` recovers the journal.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.console.join();
    }

    /// Shut the microVM down and reclaim its resources.
    ///
    /// Asks the guest to power off (`SendCtrlAltDel`) and waits briefly; the guaranteed teardown
    /// (kill + scratch-dir removal) then runs in `Drop`, so this is best-effort and infallible.
    ///
    /// # Errors
    /// Currently never returns `Err`, teardown is best-effort, but the signature stays fallible
    /// for the jailed/cgroup teardown that lands later.
    pub fn shutdown(mut self) -> Result<(), VmmError> {
        // The kill in `Drop` is what actually guarantees no leak; this is just the polite ask.
        let _ = self.power_off_and_wait(Instant::now() + POWER_OFF_TIMEOUT);
        Ok(()) // `Drop` finishes the teardown.
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        teardown(
            &mut self.child,
            &mut self.console,
            &self.workdir,
            self.tap.as_ref(),
            self.chroot.as_ref(),
            &mut self.lifetime,
        );
    }
}

/// Guaranteed, best-effort teardown shared by both `Drop`s: kill the VMM, join the console reader
/// (which ends once the killed child's stdout closes), delete the per-VM tap and the jailer's cgroup
/// (both live outside the scratch dir, so `remove_dir_all` can't reclaim them), then remove the
/// scratch dir (which reclaims the chroot, since its base is `workdir`).
pub(crate) fn teardown(
    child: &mut Child,
    console: &mut Console,
    workdir: &Path,
    tap: Option<&Tap>,
    chroot: Option<&Chroot>,
    lifetime: &mut VmLifetime,
) {
    // Flag teardown *before* the reap: from here every outstanding `KillHandle` no-ops, so a
    // late `kill` can never signal a pid the `wait` below has just made recyclable.
    lifetime.mark_down();
    let _ = child.kill();
    let _ = child.wait();
    console.join();
    // The VMM is reaped above, so its cgroup is now empty and removable. Do this before the scratch
    // dir so a slow `remove_dir_all` can't widen the window a leaked cgroup lives in.
    if let Some(cgroup) = chroot.and_then(|c| c.cgroup_dir.as_deref()) {
        remove_cgroup(cgroup);
    }
    // Reclaim the lifetime cgroup and disarm the sentinel (it wakes to already-gone dirs).
    lifetime.teardown();
    // A jailed VM may hold read-only bind mounts in its chroot (the shared rootfs base; a restore's
    // memory file + base disk); unmount each (lazy, so a still-open fd can't block us) before
    // `remove_dir_all`, or the mount point `EBUSY`s and the whole chroot leaks. A read-write boot or
    // the copy fallback records no mounts, so this is a no-op.
    if let Some(chroot) = chroot {
        chroot.unmount_all();
    }
    // Delete the netns and reclaim the scratch dir, gated so a lingering netns keeps its dir.
    reclaim_scratch(workdir, tap);
}

/// Delete the VM's netns (cascading its tap away), then reclaim the scratch dir **only once the netns
/// is confirmed gone**. A transient `ip netns del` failure would otherwise leave a netns with no
/// scratch dir: invisible to the dir-keyed orphan sweep, and a permanent `netns add` collision once
/// the pid is recycled. Keeping the dir when the netns lingers keeps the pair together and sweepable.
/// One home for the invariant, shared by [`teardown`] and [`Spawned::abort`](crate::spawn) so the two
/// teardown paths reclaim identically (a failed boot must not leak a dir-less netns either).
pub(crate) fn reclaim_scratch(workdir: &Path, tap: Option<&Tap>) {
    let netns_gone = match tap {
        Some(tap) => {
            tap.delete();
            !tap.netns_exists()
        }
        None => true,
    };
    if netns_gone {
        let _ = std::fs::remove_dir_all(workdir);
    } else {
        tracing::warn!(
            workdir = %workdir.display(),
            "netns outlived teardown; keeping the scratch dir so the orphan sweep can reclaim both"
        );
    }
}

/// Reclaim the scratch dir after a **tap-creation** failure, where the half-built netns was already
/// best-effort deleted by [`Tap::create`](crate::net::Tap::create) but that delete may itself have
/// failed. The netns is named after the scratch dir (its basename), so if one lingers we keep the dir
/// (like [`reclaim_scratch`]) so the dir-keyed orphan sweep can reclaim the pair, never stranding a
/// dir-less netns. Shared by the three `Tap::create` call sites in [`spawn`](crate::spawn), which have
/// no [`Tap`] to hand [`reclaim_scratch`].
pub(crate) fn reclaim_scratch_after_tap_failure(workdir: &Path) {
    let netns = workdir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !netns.is_empty() && crate::net::netns_exists(netns) {
        tracing::warn!(
            workdir = %workdir.display(),
            %netns,
            "netns survived a failed tap create; keeping the scratch dir so the orphan sweep can reclaim both"
        );
    } else {
        let _ = std::fs::remove_dir_all(workdir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_test_support::ScratchDir;

    #[test]
    fn reclaim_scratch_removes_the_dir_when_there_is_no_netns() {
        // The no-tap path: nothing gates the reclaim, so the scratch dir goes. Both `teardown` and
        // `abort` now route through this one helper, so a failed boot reclaims exactly as a drop does.
        // (The netns-lingers branch needs CAP_NET_ADMIN to make `netns_exists` meaningful; the
        // privileged suite covers the sweep reclaiming a stranded netns+dir pair.)
        let base = ScratchDir::created("agent-reclaim");
        let workdir = base.path().join("agent-1-0");
        std::fs::create_dir(&workdir).expect("create workdir");
        reclaim_scratch(&workdir, None);
        assert!(
            !workdir.exists(),
            "no netns to gate on, so the dir is reclaimed"
        );
    }

    #[test]
    fn with_limits_folds_budget() {
        let cfg = BootConfig::from_env().with_limits(Limits {
            vcpus: NonZeroU8::new(4).unwrap(),
            mem_mib: NonZeroU32::new(1024).unwrap(),
            wall: Duration::from_secs(60),
            output_cap: 4096,
        });
        assert_eq!(cfg.vcpus.get(), 4);
        assert_eq!(cfg.mem_mib.get(), 1024);
        // One wall for the whole run (ADR 013): the fold sets the boot deadline *and* the
        // per-exec budget from it; the output cap rides alongside.
        assert_eq!(cfg.boot_timeout, Duration::from_secs(60));
        assert_eq!(cfg.exec_wall, Duration::from_secs(60));
        assert_eq!(cfg.output_cap, 4096);
    }

    // (`jail_refuses_half_confined_boots` lived here while some boot features were not yet jailed;
    // it retired once the jail composed with every feature, so there is nothing left to
    // refuse. If a future feature ships unjailed, reinstate the refusal in `Vm::boot` and this test.)

    #[test]
    fn default_is_pure_and_matches_limits_defaults() {
        let (cfg, limits) = (BootConfig::default(), Limits::default());
        assert_eq!(cfg.vcpus, limits.vcpus);
        assert_eq!(cfg.mem_mib, limits.mem_mib);
        assert_eq!(cfg.boot_timeout, limits.wall);
        assert_eq!(cfg.exec_wall, limits.wall);
        assert_eq!(cfg.output_cap, limits.output_cap);
    }

    #[test]
    fn from_env_layers_overrides_onto_defaults() {
        // Injected lookup, not `set_var`: no process-global mutation, no parallel-test race.
        let cfg = BootConfig::from_env_with(|key| match key {
            "AGENT_KERNEL" => Some("/elsewhere/vmlinux".into()),
            "AGENT_MARKER" => Some("guest-ready".into()),
            _ => None,
        });
        assert_eq!(cfg.kernel, PathBuf::from("/elsewhere/vmlinux"));
        assert_eq!(cfg.userspace_marker, "guest-ready");
        let default = BootConfig::default();
        assert_eq!(cfg.rootfs, default.rootfs, "unset keys keep the default");
        assert_eq!(cfg.firecracker, default.firecracker);
    }

    #[test]
    fn scratch_dir_defaults_to_tmp_and_honors_the_env_override() {
        assert_eq!(BootConfig::default().scratch_dir, PathBuf::from("/tmp"));
        let cfg = BootConfig::from_env_with(|k| {
            (k == "AGENT_SCRATCH_DIR").then(|| "/mnt/disk/scratch".into())
        });
        assert_eq!(cfg.scratch_dir, PathBuf::from("/mnt/disk/scratch"));
    }
}
