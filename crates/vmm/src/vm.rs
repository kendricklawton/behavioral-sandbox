//! Boot a Firecracker microVM and read its serial console — the raw VM lifecycle beneath
//! [`crate::Sandbox`].
//!
//! [`Vm::boot`] spawns a `firecracker` child, drives its API socket through the boot sequence
//! (boot-source → root drive → machine-config → `InstanceStart`), and waits until the guest's
//! serial console shows it reached userspace. [`RunningVm`] owns the running child; dropping it —
//! or calling [`RunningVm::shutdown`] — kills the VMM and reclaims its scratch dir, so a run can
//! never leak a process or socket.
//!
//! **Host path only, `unsafe`-free.** Firecracker wires the guest's `ttyS0` to its own stdout, so
//! "read the child's stdout" is "read the guest console". The jailer ([`Jail`],
//! [`BootConfig::jail`]) preserves this: it is not run with `--daemonize`, so Firecracker keeps the
//! piped stdout and the console still reaches [`Console`].

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use agent_channel::ClientConnection;

use crate::console::Console;
use crate::drives::{collect_output_image, OutputDevice};
use crate::exec::{
    connect_agent_at, run_exec, ExecBounds, DEFAULT_EXEC_TIMEOUT, EXEC_KILL_SLACK, MAX_EXEC_OUTPUT,
    PROBE_TIMEOUT, VSOCK_TIMEOUT,
};
use crate::firecracker::{Action, ApiClient};
use crate::jail::{remove_cgroup, unmount_base, Chroot, Jail};
use crate::lifetime::{KillHandle, VmLifetime};
use crate::net::Tap;
use crate::spawn::Spawned;
use crate::{Limits, RunResult, VmmError};

/// Kernel command line for the guest. `console=ttyS0` puts its console on the serial port (which
/// Firecracker hands to our stdout); `reboot=k panic=1` make a guest panic/reboot exit the VMM
/// promptly; `pci=off` trims an unused bus; `random.trust_cpu=on` avoids an entropy stall at boot.
/// Firecracker adds `root=/dev/vda` itself from the root drive, so it is not listed here.
const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=on";

/// Substring that marks the guest reached userspace. The pinned Ubuntu rootfs prints its getty
/// prompt (`ubuntu-fc-uvm login:`) once init is up; no earlier boot line contains `login:`. This
/// is tied to the pinned rootfs — a new rootfs pin may need a new marker (overridable via env).
const DEFAULT_USERSPACE_MARKER: &str = "login:";

/// Names the next per-VM scratch dir uniquely within this process (paired with the PID).
pub(crate) static VM_SEQ: AtomicU64 = AtomicU64::new(0);

/// Firecracker's own stderr, captured to a file in the scratch dir (see `Spawned::launch`).
pub(crate) const FC_STDERR: &str = "fc.stderr";

/// The vsock context id the guest gets (the host is always cid 2). The default when a boot enables
/// the exec channel; overridable per-VM via [`BootConfig::guest_cid`].
pub const DEFAULT_GUEST_CID: u32 = 3;

/// The vsock port the in-guest agent listens on for exec connections — defined in `agent-channel`
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
const POWER_OFF_TIMEOUT: Duration = Duration::from_secs(3);
const POWER_OFF_POLL: Duration = Duration::from_millis(50);

/// Everything needed to boot one microVM. [`default`](BootConfig::default) is the pure pinned
/// baseline, [`from_env`](BootConfig::from_env) layers the `AGENT_*` overrides on top, and
/// [`with_limits`](BootConfig::with_limits) folds a [`Limits`] budget onto the resource knobs.
/// `#[non_exhaustive]`: construct via [`from_env`](BootConfig::from_env) /
/// [`default`](BootConfig::default) and mutate fields — later phases add knobs (tap, jailer,
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
    /// Guest vCPUs.
    pub vcpus: u32,
    /// Guest memory, MiB.
    pub mem_mib: u32,
    /// The guest kernel command line.
    pub boot_args: String,
    /// Console substring that signals userspace was reached.
    pub userspace_marker: String,
    /// Upper bound on boot-to-userspace before the boot is a typed timeout.
    pub boot_timeout: Duration,
    /// Configure a virtio-vsock device with this guest context id, enabling the exec channel
    /// ([`RunningVm::connect_agent`]). `None` (the default) boots with no vsock — the Phase 1
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
    /// A host directory to inject as **bulk read-only input** (P3.4): the driver builds an ext4 from
    /// it and attaches it as a second block device (`/dev/vdb`, `O_RDONLY`); the agent rootfs mounts
    /// it at `/input`, so a command reads it as `/input/...`. This is the whole-working-dir /
    /// large-file path — the vsock channel's [`Request::PutFile`](agent_channel::Request::PutFile) carries only small per-frame files.
    /// `None` (the default) attaches no input device. Building the image needs `mke2fs` + `truncate`.
    pub input_dir: Option<PathBuf>,
    /// A host directory to receive **bulk output** (P3.5): the driver attaches a blank, **writable**
    /// ext4 as a third block device (`/dev/vd?`, labelled `agent-output`); the agent rootfs mounts it
    /// read-write at `/output`, so a command's files under `/output/...` are pulled back here by
    /// [`RunningVm::collect_outputs`]. This is the whole-working-dir / large-file counterpart to the
    /// vsock channel's per-frame [`Response::File`](agent_channel::Response::File) artifacts. `None` (the default) attaches no output
    /// device. Readback needs `e2fsck` + `debugfs` (e2fsprogs) on the host; the directory is created
    /// if missing and receives the guest's `/output` tree (host-escaping symlinks are dropped).
    pub output_dir: Option<PathBuf>,
    /// Give the guest a **virtio-net** interface backed by a per-VM host **tap** device (P4.1). The
    /// driver creates the tap (`ip tuntap`, needs `CAP_NET_ADMIN`), attaches it via
    /// `PUT /network-interfaces`, and deletes it on teardown. `false` (the default) boots with **no
    /// NIC** — deny-by-default. Even when `true`, the guest gets an *unconfigured* `eth0`: this box
    /// adds no address, route, or masquerade (decision 008), so the guest reaches nothing until
    /// addressing lands. Needs `ip` (iproute2) on the host.
    pub enable_network: bool,
    /// Run Firecracker under its **jailer** (P6.1): a chroot, a uid/gid drop, and the jailer's mount
    /// namespace confine the VMM process itself (see [`Jail`]). `None` (the default) spawns
    /// Firecracker directly. Setting it needs **real root** (the jailer `mknod`s device nodes, which
    /// `EPERM` in a non-initial user namespace) and the `jailer` binary. Composes with `guest_cid`
    /// (the vsock exec channel is staged chroot-relative under the dropped uid), `read_only_root` (the
    /// shared base is bind-mounted into the chroot), and `enable_network` (the tap lives in a per-VM
    /// netns the jailer joins via `--netns`), so a jailed VM can run networked code on the density
    /// path; combining `jail` with `input_dir` or `output_dir` is still a typed error for now (those
    /// need chroot staging a later step adds).
    pub jail: Option<Jail>,
    /// Base directory for per-VM **scratch** dirs (`<scratch_dir>/agent-<pid>-<n>`), holding the
    /// read-write rootfs copy, the jail chroot, block-device images, and sockets. Defaults to `/tmp`
    /// (overridable via `AGENT_SCRATCH_DIR`). **This matters on constrained hardware:** `/tmp` is
    /// often `tmpfs` (host RAM), so a read-write boot's full-rootfs copy is charged to RAM — on a
    /// small box that alone can exhaust memory (or `ENOSPC` a small tmpfs) and fail the boot. Point
    /// this at real disk to bound RAM use, or prefer [`read_only_root`](BootConfig::read_only_root),
    /// which shares the base with **no** copy. The base must already exist; each VM's own subdir is
    /// created (and reclaimed) by the driver.
    pub scratch_dir: PathBuf,
}

impl BootConfig {
    /// Layer the environment overrides — `AGENT_FIRECRACKER`, `AGENT_KERNEL`, `AGENT_ROOTFS`,
    /// `AGENT_MARKER` — onto [`BootConfig::default`]. The resource knobs (`vcpus`, `mem_mib`,
    /// `boot_timeout`) have no env key; they come from [`Limits`] via
    /// [`with_limits`](BootConfig::with_limits).
    pub fn from_env() -> Self {
        Self::from_env_with(|key| std::env::var_os(key))
    }

    /// The testable core of [`from_env`](BootConfig::from_env): overrides come through `lookup`,
    /// so precedence is unit-testable without mutating the process environment (which races
    /// under the parallel test runner and is `unsafe` from edition 2024).
    fn from_env_with(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> Self {
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

    /// Fold a per-sandbox [`Limits`] budget onto the config (vCPUs, memory, and the boot deadline).
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.vcpus = limits.vcpus;
        self.mem_mib = limits.mem_mib;
        self.boot_timeout = limits.wall;
        self
    }
}

impl Default for BootConfig {
    /// The pure pinned defaults — no environment reads (that's [`BootConfig::from_env`]), so
    /// `default()` is deterministic. The resource knobs mirror [`Limits::default`] so the two
    /// baselines cannot silently diverge.
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            firecracker: PathBuf::from("firecracker"),
            kernel: PathBuf::from("artifacts/vmlinux"),
            rootfs: PathBuf::from("artifacts/rootfs.ext4"),
            vcpus: limits.vcpus,
            mem_mib: limits.mem_mib,
            boot_args: DEFAULT_BOOT_ARGS.to_string(),
            userspace_marker: DEFAULT_USERSPACE_MARKER.to_string(),
            boot_timeout: limits.wall,
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
/// captured console. Guaranteed teardown lives in `Drop`, so losing this value can't leak the VMM —
/// and the cgroup-owned lifetime (the sentinel behind [`KillHandle`], P6.7) covers the paths `Drop`
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
    /// be restored — `snapshot` refuses it. (The input image itself is reclaimed with the workdir.)
    pub(crate) has_input: bool,
    /// The vsock unix socket Firecracker created, if this VM was booted with a `guest_cid`.
    pub(crate) vsock_uds: Option<PathBuf>,
    /// The writable output image (in `workdir`) and the host directory to extract it into, when the
    /// boot config set `output_dir`; `None` otherwise. Read back by [`RunningVm::collect_outputs`].
    pub(crate) output: Option<OutputDevice>,
    /// The per-VM host tap backing the guest's virtio-net, when the boot config set
    /// `enable_network`. Lives **outside** `workdir`, so teardown must delete it explicitly.
    pub(crate) tap: Option<Tap>,
    /// The jail this VMM runs in, when the boot config set `jail` (P6.1). Its chroot lives under
    /// `workdir` (reclaimed with it), but the jailer's cgroup is outside, so teardown removes it
    /// explicitly, like the tap.
    pub(crate) chroot: Option<Chroot>,
    /// The cgroup-owned lifetime machinery (P6.7): the VM's lifetime cgroup, the armed sentinel
    /// that reaps the VM if this *process* dies, and the [`KillHandle`] state. Torn down with the
    /// VM on every path.
    pub(crate) lifetime: VmLifetime,
}

/// A microVM snapshot written by [`RunningVm::snapshot`]: the device + vCPU **state** file, the guest
/// **memory** file (roughly the guest's RAM size), and the **root disk**. [`Vm::restore`] rebuilds a
/// VM from these on a fresh VMM.
///
/// The disk is one of two shapes. A **read-write** boot bundles a private, point-in-time copy that
/// restore stages back, so the clone shares no writable backing with its source (which may be gone). A
/// **`read_only_root`** boot (a "warm" snapshot) references the shared, persistent base in place, so N
/// clones restored from one bundle share it read-only (page-cache-deduped) while each gets its own
/// in-RAM overlay. A **warm** snapshot also carries the vsock exec channel, so a restored clone can
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
    /// restore must recreate a tap with **exactly this name** — which also means only one networked
    /// clone can be live at a time (two taps can't share a name; decision 011's tombstone). The
    /// recreated tap gets a fresh /30, and the guest's stale in-memory address is replaced by the
    /// agent over vsock after resume.
    pub(crate) tap_name: Option<String>,
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
    /// read-only base referenced in place (a `read_only_root` warm snapshot).
    #[must_use]
    pub fn root_drive_path(&self) -> &Path {
        &self.root_drive
    }
}

/// Boot entry point — `Vm::boot(config) -> RunningVm`.
#[derive(Debug)]
pub struct Vm;

impl Vm {
    /// Boot a microVM under `config` and return once the guest reaches userspace.
    ///
    /// By default copies the base rootfs into a fresh per-VM scratch dir and boots the copy
    /// read-write, so repeated runs stay independent and the pinned base is never mutated. With
    /// [`read_only_root`](BootConfig::read_only_root) it instead shares the base read-only (no copy)
    /// and the guest layers a per-run tmpfs overlay over it — same "base never mutated" guarantee,
    /// far less per-VM cost.
    ///
    /// # Errors
    /// [`VmmError::NoKvm`] without `/dev/kvm`, [`VmmError::Artifact`] for a missing kernel/rootfs
    /// /binary, [`VmmError::Timeout`] if boot-to-userspace exceeds `boot_timeout`, and
    /// [`VmmError::Vmm`] for any Firecracker API or process failure. On any error the child is
    /// killed and the scratch dir removed before returning.
    pub fn boot(config: BootConfig) -> Result<RunningVm, VmmError> {
        // Config validation before environment probing, so this deny-by-default refusal is reachable
        // (and unit-testable) on any host, with KVM or not. The jailer now composes with the vsock
        // exec channel (socket staged chroot-relative under the dropped uid), the read-only overlay
        // (shared base bind-mounted into the chroot), and a NIC (the tap lives in a per-VM netns the
        // jailer joins), but bulk I/O still needs staging into the chroot, so refuse it rather than
        // boot a half-confined VM. The isolation boundary never half-degrades (decision 013): a jail we
        // can't fully build is a hard error, not a quiet drop to a weaker confinement.
        if config.jail.is_some() && (config.input_dir.is_some() || config.output_dir.is_some()) {
            return Err(VmmError::Vmm(
                "the jailer currently supports a read-write or read-only-overlay boot with the vsock \
                 exec channel and a NIC; bulk input/output devices under the jailer are a later step"
                    .into(),
            ));
        }
        // Checked here, not in `launch`, so the launch/boot-failure machinery stays unit-testable
        // on hosts without KVM (a fake "firecracker" needs no VM).
        if !Path::new("/dev/kvm").exists() {
            return Err(VmmError::NoKvm);
        }
        let mut spawned = Spawned::launch(&config)?;
        let boot_latency = match spawned.run_boot(&config) {
            Ok(latency) => latency,
            Err(e) => return Err(spawned.abort(e)),
        };
        spawned.into_running(boot_latency)
    }
}

impl RunningVm {
    /// Boot-to-userspace latency — the number that matters (measured from `InstanceStart`).
    #[must_use]
    pub fn boot_latency(&self) -> Duration {
        self.boot_latency
    }

    /// A UTF-8-lossy snapshot of the serial console captured so far.
    #[must_use]
    pub fn console(&self) -> String {
        self.console.snapshot()
    }

    /// The PID of the `firecracker` VMM process. Useful for out-of-band supervision — putting the VMM
    /// in a cgroup (Phase 6), attaching host-side observers to it, or asserting it was reaped on
    /// teardown. The process is killed and reaped when this `RunningVm` is dropped, so the PID is only
    /// valid for the VM's lifetime.
    #[must_use]
    pub fn vmm_pid(&self) -> u32 {
        self.child.id()
    }

    /// A cheap, cloneable, `Send + Sync` [`KillHandle`] that force-kills this VM from any thread —
    /// the **host-gave-up path** (P6.7). `exec` borrows `&self` and `shutdown` consumes `self`, so
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
    /// address over its `eth0` (and nothing beyond it — deny-by-default).
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
    /// host-side eBPF track (Phase 8) binds policy to. The tap lives **inside** this VM's network
    /// namespace ([`netns`](Self::netns)), so the loader resolves it to an ifindex and attaches
    /// `tc`/XDP programs to *this* sandbox's traffic **within that netns** — pair it with `netns()`.
    #[must_use]
    pub fn tap_name(&self) -> Option<&str> {
        self.tap.as_ref().map(|t| t.name.as_str())
    }

    /// The per-VM **network namespace** name backing this VM's NIC, when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise. The tap the guest's virtio-net
    /// rides ([`tap_name`](Self::tap_name)) lives inside it, isolated from the host and every other VM,
    /// so the Phase-8 eBPF loader enters this netns (its handle is `/run/netns/<name>`) to attach to
    /// the tap. Also the unit of isolation that replaces P4.4's per-VM /30 reservation.
    #[must_use]
    pub fn netns(&self) -> Option<&str> {
        self.tap.as_ref().map(|t| t.netns.as_str())
    }

    /// Connect to the in-guest agent over vsock and complete the channel handshake, returning a
    /// protocol-ready [`ClientConnection`]. This is the host side of the exec path (P2.4 builds
    /// `exec` on top): it dials Firecracker's vsock socket, speaks the `CONNECT <port>` handshake,
    /// sets read/write deadlines, then does the channel handshake.
    ///
    /// # Errors
    /// [`VmmError::GuestUnavailable`] if nothing is listening on `port` in the guest (not up yet, or
    /// not anymore) — the retryable case; [`VmmError::Vmm`] if the VM was booted without a
    /// `guest_cid` or on any other I/O or channel failure; [`VmmError::Timeout`] if the connect
    /// exceeds the deadline.
    pub fn connect_agent(&self, port: u32) -> Result<ClientConnection<UnixStream>, VmmError> {
        connect_agent_at(self.require_vsock()?, port, VSOCK_TIMEOUT)
    }

    /// Probe the exec channel: connect to the guest agent and complete the handshakes, discarding
    /// the connection (the agent serves one connection then loops back to accept, so a
    /// connect-and-close just cycles it). The warm [`Pool`](crate::Pool)'s health check on a clone
    /// that has been sitting idle: a dead or wedged clone surfaces as a typed error — most
    /// specifically [`VmmError::GuestUnavailable`] — so the pool can discard it and serve another.
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
    /// the exec protocol. The captured output is bounded (16 MiB); a command that exits non-zero is
    /// a normal [`RunResult`], not an error. Each call opens a fresh connection (the guest agent
    /// serves one command per connection and loops), so repeated `exec` calls are fine.
    ///
    /// # Errors
    /// A typed [`VmmError`] across the taxonomy's three buckets: **establishment** —
    /// [`VmmError::GuestUnavailable`] if the agent isn't listening (retryable), [`VmmError::Vmm`] if
    /// the VM has no vsock, [`VmmError::Timeout`]
    /// on a stalled connect/ack; **steady-state transport** — [`VmmError::Channel`] on a mid-exec
    /// framing/IO fault; **guest fault** — [`VmmError::GuestExec`] if the agent couldn't run the
    /// command, [`VmmError::ExecTimeout`] if it outran its budget, [`VmmError::OutputCap`] if it
    /// flooded output. A command that merely exits non-zero (even by signal) is a normal
    /// [`RunResult`], not an error.
    pub fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<RunResult, VmmError> {
        self.exec_with_files(argv, stdin, &[], &[])
    }

    /// Run `argv` with `stdin`, first injecting `files_in` into the run's working directory, then
    /// returning the files named in `artifacts` (paths relative to that directory) in
    /// [`RunResult::files`]. The richer form of [`exec`](Self::exec); each file is bounded to the
    /// channel's per-frame cap, and the total captured output+artifacts is bounded (16 MiB).
    ///
    /// # Errors
    /// As [`exec`](Self::exec).
    pub fn exec_with_files(
        &self,
        argv: &[String],
        stdin: &[u8],
        files_in: &[(String, Vec<u8>)],
        artifacts: &[String],
    ) -> Result<RunResult, VmmError> {
        let uds = self.require_vsock()?;
        // The host's total patience: the command's own budget plus the agent's kill+report margin.
        // Derived from the *actual* budget (not a fixed const) so raising the budget later can't
        // leave the socket idle timeout cutting off a long quiet command. Used both as the socket's
        // per-read idle timeout and, inside `run_exec`, as the wall-clock deadline on the loop — so
        // the agent's `TimedOut` (at `budget`) reaches us first, and a silent guest can't park us.
        let budget = DEFAULT_EXEC_TIMEOUT;
        let wall = budget.saturating_add(EXEC_KILL_SLACK);
        let mut conn = connect_agent_at(uds, AGENT_VSOCK_PORT, wall)?;
        run_exec(
            &mut conn,
            argv,
            stdin,
            files_in,
            artifacts,
            ExecBounds {
                timeout: budget,
                wall,
                max_output: MAX_EXEC_OUTPUT,
            },
        )
    }

    /// Pull the guest's `/output` tree back to the host directory set as [`BootConfig::output_dir`],
    /// returning the captured paths (relative to that directory, sorted).
    ///
    /// The bulk counterpart to the per-file [`RunResult::files`] channel path: the guest wrote to a
    /// writable block device (mounted at `/output`), and here the driver reads that image back. It
    /// **consumes the VM** — the VMM is stopped first (a cooperative power-off, then a hard kill) so
    /// it has released the image and flushed the guest's writes; reading a live, VMM-held image would
    /// race the guest and corrupt the ext4 journal `e2fsck` replays. Read-back is fully **rootless**:
    /// `e2fsck` recovers the journal, then `debugfs rdump` extracts the tree — no loopback, no
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

    /// Ask the guest to power off (best-effort `SendCtrlAltDel`, an x86 ACPI-ish nicety over i8042),
    /// then poll for the VMM to exit until `deadline`. Returns `true` if it exited on its own. The
    /// shared core of `shutdown` and `stop_and_reap`, so the action and the poll cadence live once;
    /// the *guaranteed* kill is the caller's (or `Drop`'s), never this.
    fn power_off_and_wait(&mut self, deadline: Instant) -> bool {
        let _ = self.api.put("/actions", &Action::SendCtrlAltDel);
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
    /// Currently never returns `Err` — teardown is best-effort — but the signature stays fallible
    /// for the jailed/cgroup teardown of later phases.
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
    if let Some(tap) = tap {
        tap.delete();
    }
    // The VMM is reaped above, so its cgroup is now empty and removable. Do this before the scratch
    // dir so a slow `remove_dir_all` can't widen the window a leaked cgroup lives in.
    if let Some(cgroup) = chroot.and_then(|c| c.cgroup_dir.as_deref()) {
        remove_cgroup(cgroup);
    }
    // Reclaim the lifetime cgroup and disarm the sentinel (it wakes to already-gone dirs).
    lifetime.teardown();
    // A `read_only_root` jailed boot bind-mounts the shared base into the chroot; unmount it (lazy,
    // so a still-open fd can't block us) before `remove_dir_all`, or the mount point `EBUSY`s and the
    // whole chroot leaks. A read-write boot or the copy fallback records no mount, so this is a no-op.
    if let Some(base) = chroot.and_then(|c| c.base_mount.as_deref()) {
        unmount_base(base);
    }
    let _ = std::fs::remove_dir_all(workdir);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_limits_folds_budget() {
        let cfg = BootConfig::from_env().with_limits(Limits {
            vcpus: 4,
            mem_mib: 1024,
            wall: Duration::from_secs(60),
        });
        assert_eq!(cfg.vcpus, 4);
        assert_eq!(cfg.mem_mib, 1024);
        assert_eq!(cfg.boot_timeout, Duration::from_secs(60));
    }

    #[test]
    fn jail_refuses_half_confined_boots() {
        // Deny-by-default: the jailer supports a read-write or read-only-overlay boot plus the vsock
        // exec channel and a NIC, so any config that would run a *half*-jailed VM (a feature not yet
        // staged into the chroot) is a typed error, never a quiet weaker confinement. This is a pure
        // config check, refused before the /dev/kvm probe, so it holds on any host (no KVM, no root
        // needed). Each mutation flips one not-yet-jailed feature on; all must be refused. `guest_cid`,
        // `read_only_root`, and `enable_network` are absent here on purpose: jail + vsock, jail +
        // overlay, and jail + NIC are supported now (see the jailed integration tests).
        let mutations: [fn(&mut BootConfig); 2] = [
            |c| c.input_dir = Some(PathBuf::from("/tmp/in")),
            |c| c.output_dir = Some(PathBuf::from("/tmp/out")),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut cfg = BootConfig {
                jail: Some(Jail::default()),
                ..BootConfig::default()
            };
            mutate(&mut cfg);
            let err = Vm::boot(cfg).expect_err("a half-jailed config must be refused");
            assert!(
                matches!(err, VmmError::Vmm(_)),
                "mutation {i} should be a typed refusal, got {err:?}"
            );
        }
    }

    #[test]
    fn default_is_pure_and_matches_limits_defaults() {
        let (cfg, limits) = (BootConfig::default(), Limits::default());
        assert_eq!(cfg.vcpus, limits.vcpus);
        assert_eq!(cfg.mem_mib, limits.mem_mib);
        assert_eq!(cfg.boot_timeout, limits.wall);
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
