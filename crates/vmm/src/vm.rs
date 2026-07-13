//! Boot a Firecracker microVM and read its serial console — the raw VM lifecycle beneath
//! [`crate::Sandbox`].
//!
//! [`Vm::boot`] spawns a `firecracker` child, drives its API socket through the boot sequence
//! (boot-source → root drive → machine-config → `InstanceStart`), and waits until the guest's
//! serial console shows it reached userspace. [`RunningVm`] owns the running child; dropping it —
//! or calling [`RunningVm::shutdown`] — kills the VMM and reclaims its scratch dir, so a run can
//! never leak a process or socket.
//!
//! **Host path only, `unsafe`-free.** Firecracker wires the guest's `ttyS0` to its own stdout
//! when unjailed, so "read the child's stdout" is "read the guest console" — a coupling the
//! jailer (Phase 6) will break, hence the console capture sits behind [`Console`].

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use agent_channel::ClientConnection;

use crate::console::{last_lines, Console};
use crate::drives::{build_input_image, build_output_image, collect_output_image, OutputDevice};
use crate::exec::{
    connect_agent_at, run_exec, ExecBounds, DEFAULT_EXEC_TIMEOUT, EXEC_KILL_SLACK, MAX_EXEC_OUTPUT,
    PROBE_TIMEOUT, VSOCK_TIMEOUT,
};
use crate::firecracker::{
    Action, ApiClient, BootSource, Drive, MachineConfig, MemBackend, MemBackendType,
    NetworkInterface, SnapshotCreate, SnapshotLoad, SnapshotType, VmState, VmStateKind, Vsock,
};
use crate::net::{apply_guest_net_identity, Tap};
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
static VM_SEQ: AtomicU64 = AtomicU64::new(0);

/// Firecracker's own stderr, captured to a file in the scratch dir (see `Spawned::launch`).
const FC_STDERR: &str = "fc.stderr";

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
const IFACE_ID: &str = "eth0";

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
        }
    }
}

/// A booted-and-ready microVM: the `firecracker` child, its API socket, scratch dir, and the
/// captured console. Guaranteed teardown lives in `Drop`, so losing this value can't leak the VMM.
#[derive(Debug)]
#[must_use = "dropping a RunningVm kills its microVM"]
pub struct RunningVm {
    child: Child,
    workdir: PathBuf,
    console: Console,
    api: ApiClient,
    boot_latency: Duration,
    /// The active root-disk backing file: a per-VM copy for a read-write boot, the shared read-only
    /// base for a `read_only_root` boot, or the snapshot bundle's private copy for a restore. Held so
    /// [`snapshot`](RunningVm::snapshot) can bundle it into a portable snapshot.
    rootfs: PathBuf,
    /// This VM was produced by [`Vm::restore`], so [`rootfs`](Self::rootfs) is a placeholder (the live
    /// disk is an anonymous inode with no host path) and re-snapshotting it is refused.
    restored: bool,
    /// This VM has a bulk **input** block device (from `input_dir`), whose image lives in the scratch
    /// dir. A snapshot bakes in that path, but the scratch dir is gone after teardown, so the VM can't
    /// be restored — `snapshot` refuses it. (The input image itself is reclaimed with the workdir.)
    has_input: bool,
    /// The vsock unix socket Firecracker created, if this VM was booted with a `guest_cid`.
    vsock_uds: Option<PathBuf>,
    /// The writable output image (in `workdir`) and the host directory to extract it into, when the
    /// boot config set `output_dir`; `None` otherwise. Read back by [`RunningVm::collect_outputs`].
    output: Option<OutputDevice>,
    /// The per-VM host tap backing the guest's virtio-net, when the boot config set
    /// `enable_network`. Lives **outside** `workdir`, so teardown must delete it explicitly.
    tap: Option<Tap>,
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
    state: PathBuf,
    mem: PathBuf,
    /// The bundle's point-in-time copy of the root disk (a read-write boot), or the shared read-only
    /// base itself (a `read_only_root` boot, where [`shared_base`](Self::shared_base) is set).
    root_drive: PathBuf,
    /// The host path the snapshot baked in for the root disk (where the source VM booted it).
    /// Firecracker opens the disk *here* during `PUT /snapshot/load`.
    root_backing: PathBuf,
    /// The root disk is a **read-only shared base** at a persistent path (a `read_only_root` boot):
    /// restore references it in place (no copy, no staging), and many clones share it read-only. When
    /// unset, the disk is a private per-VM copy that restore stages at `root_backing`.
    shared_base: bool,
    /// The source ran the vsock exec channel, so restored clones can be `exec`'d. The socket path was
    /// baked in **relative** (`v.sock`), so Firecracker re-binds it in each restored VMM's own scratch
    /// dir (its cwd) rather than on one shared absolute path, letting concurrent clones coexist.
    has_vsock: bool,
    /// The source had a NIC, and the snapshot baked in this host tap name (`host_dev_name`). The
    /// pinned Firecracker (v1.9) has no `network_overrides` on load (probed: "unknown field"), so
    /// restore must recreate a tap with **exactly this name** — which also means only one networked
    /// clone can be live at a time (two taps can't share a name; decision 011's tombstone). The
    /// recreated tap gets a fresh /30, and the guest's stale in-memory address is replaced by the
    /// agent over vsock after resume.
    tap_name: Option<String>,
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

    /// Restore a microVM from a [`Snapshot`] on a fresh VMM and resume it, returning once it's
    /// running and (if the snapshot carried the exec channel) exec-ready. Reuses only the
    /// `firecracker` binary and `boot_timeout` from `config` (the guest's kernel, memory, and devices
    /// all come from the snapshot).
    ///
    /// A **read-write** snapshot's private disk copy is staged at its baked-in path; a **read-only
    /// shared base** is referenced in place, so many clones restored from one warm snapshot share it
    /// (page-cache-deduped) while each gets its own in-RAM overlay. A **warm** snapshot (one taken with
    /// the vsock exec channel) restores exec-ready: its socket was baked in relative, so each clone
    /// re-binds its own socket in its own scratch dir and concurrent clones don't collide. If the
    /// snapshot carried vsock, restore waits until the guest agent is reachable before returning, so
    /// the VM can [`exec`](RunningVm::exec) immediately.
    ///
    /// A **networked** snapshot restores with a **fresh network identity** (decision 011): the driver
    /// recreates the snapshot's recorded tap (the pinned Firecracker has no `network_overrides`, so
    /// the name must match — which also means only one networked clone can be live at a time; a taken
    /// name is a typed error), assigns its host end a fresh /30, and the guest agent replaces the
    /// baked-in `eth0` address with the new one over vsock. Entropy is reseeded via VMGenID
    /// (Firecracker bumps the generation on restore and the guest kernel reseeds its CRNG — proven by
    /// test, not assumed), so clones don't share RNG state. The guest's **wall clock is not fixed
    /// up**: it lags by the snapshot's age until the workload resyncs it.
    ///
    /// Restore latency (load + resume) is [`RunningVm::boot_latency`] on the returned VM, for the
    /// cold-boot-vs-restore comparison.
    ///
    /// # Errors
    /// [`VmmError::NoKvm`] without `/dev/kvm`; [`VmmError::Artifact`] if a bundle file is missing or
    /// `firecracker` isn't found; [`VmmError::Timeout`] if the VMM never becomes ready; and
    /// [`VmmError::Vmm`] on any load/rebase/resume failure. On error the VMM is killed and the fresh
    /// scratch dir removed before returning.
    pub fn restore(snapshot: &Snapshot, config: &BootConfig) -> Result<RunningVm, VmmError> {
        if !Path::new("/dev/kvm").exists() {
            return Err(VmmError::NoKvm);
        }
        require_file(&snapshot.state, "snapshot state file")?;
        require_file(&snapshot.mem, "snapshot memory file")?;
        require_file(&snapshot.root_drive, "snapshot root disk")?;

        let mut spawned = Spawned::launch_for_restore(config, snapshot)?;
        let latency = match spawned.run_restore(snapshot, config.boot_timeout) {
            Ok(latency) => latency,
            Err(e) => return Err(spawned.abort(e)),
        };
        spawned.into_running(latency)
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

    /// The host tap interface backing this VM's NIC (`fc<hex>`), when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise. This is the handle the
    /// host-side eBPF track (Phase 8) binds policy to: the name is host-globally reserved for the VM's
    /// lifetime, so the loader can resolve it to an ifindex (`if_nametoindex`) and attach `tc`/XDP
    /// programs to *this* sandbox's traffic. Names, unlike ifindexes, don't churn if the interface is
    /// recreated, so the driver hands out the name and lets the loader resolve the index at attach.
    #[must_use]
    pub fn tap_name(&self) -> Option<&str> {
        self.tap.as_ref().map(|t| t.name.as_str())
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

    /// Pause the VM, write a [`Snapshot`] bundle (device + vCPU state, guest memory, and the root
    /// disk) into `dir`, then resume — the VM keeps running and can be shut down or snapshotted again.
    ///
    /// A **read-write** boot's disk is copied into the bundle **inside the paused window**, so the copy
    /// agrees with the memory image; a **`read_only_root`** boot (a warm snapshot) references the shared
    /// base in place (no copy). The **vsock exec channel is supported** — restore re-binds its socket —
    /// so a warm snapshot restores exec-ready.
    ///
    /// Refused (a typed error, never an unrestorable bundle): a VM with an **output** or **input**
    /// block device (per-clone images a restore can't yet recreate), a VM with a **NIC but no vsock**
    /// (restore applies the clone's fresh network identity through the exec channel, so a networked
    /// snapshot without one couldn't be re-addressed — decision 011), and an **already-restored** VM
    /// (its `rootfs` is a placeholder; the live disk is an anonymous inode with no host path to
    /// bundle). A NIC *with* vsock is supported: the bundle records the tap name and restore rebuilds
    /// the link (see [`Vm::restore`]).
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the VM is unsupported for snapshotting, or on any API or file-copy failure.
    /// A create failure still falls through to the resume, so a failed snapshot never leaves the guest
    /// frozen.
    pub fn snapshot(&self, dir: &Path) -> Result<Snapshot, VmmError> {
        // A restored VM's `rootfs` is a placeholder (its live disk is an anonymous inode), so the
        // shared-base classifier below would misread it and bundle a stale, shared-writable disk.
        // Refuse it outright, the way the pre-warm-snapshot guard did.
        if self.restored {
            return Err(VmmError::Vmm(
                "snapshot of an already-restored VM is not supported (its live disk has no host path)"
                    .into(),
            ));
        }
        // An output or input device carries a per-clone image a restore can't yet recreate (and the
        // input image lives at the gone source scratch path), so those stay refused. The vsock exec
        // channel is supported (restore re-binds its baked-in relative socket), and a NIC is supported
        // *through* it: restore recreates the recorded tap and the agent applies the clone's fresh
        // address over vsock (decision 011) — so a networked snapshot without vsock is refused too,
        // since its clone could never be re-addressed.
        if self.output.is_some() || self.has_input {
            return Err(VmmError::Vmm(
                "snapshot of a VM with an input/output device is not yet supported (P5.4/P5.5)"
                    .into(),
            ));
        }
        if self.tap.is_some() && self.vsock_uds.is_none() {
            return Err(VmmError::Vmm(
                "snapshot of a networked VM requires the vsock exec channel (restore re-addresses the \
                 clone through it); boot with BootConfig.guest_cid set"
                    .into(),
            ));
        }
        // The root disk is either a **private per-VM copy** (a read-write boot, whose backing lives
        // inside this VM's scratch dir: the bundle owns a point-in-time copy that restore stages back)
        // or a **read-only shared base** (a `read_only_root` boot: the base is a persistent pinned file
        // outside the scratch dir, so the bundle references it in place and clones share it read-only).
        // The structural test is which side of the scratch dir the backing lives on.
        let shared_base = !self.rootfs.starts_with(&self.workdir);
        std::fs::create_dir_all(dir)
            .map_err(|e| VmmError::Vmm(format!("create snapshot dir {}: {e}", dir.display())))?;
        // Absolute bundle paths: `restore` hands these to Firecracker, whose cwd is its own scratch
        // dir, so a relative bundle path would resolve there instead of where the caller put it.
        let dir = absolute(dir)?;
        let state = dir.join("snapshot.state");
        let mem = dir.join("snapshot.mem");
        // A private copy is bundled under `dir`; a shared base is referenced at its own path.
        let root_drive = if shared_base {
            self.rootfs.clone()
        } else {
            dir.join("rootfs.ext4")
        };

        // Pause → create → copy the (now-quiescent) disk → resume. Pausing freezes the vCPUs so the
        // memory image is a consistent point-in-time; copying the disk in the same window keeps it in
        // step with that memory. `create` failing still falls through to `resume` below, so the guest
        // is never left frozen.
        self.api.patch(
            "/vm",
            &VmState {
                state: VmStateKind::Paused,
            },
        )?;
        let created = self.write_snapshot_bundle(&state, &mem, &root_drive, shared_base);
        let resumed = self.api.patch(
            "/vm",
            &VmState {
                state: VmStateKind::Resumed,
            },
        );
        created?;
        resumed?;
        tracing::info!(dir = %dir.display(), shared_base, "wrote microVM snapshot bundle");
        Ok(Snapshot {
            state,
            mem,
            root_drive,
            root_backing: self.rootfs.clone(),
            shared_base,
            has_vsock: self.vsock_uds.is_some(),
            tap_name: self.tap.as_ref().map(|t| t.name.clone()),
        })
    }

    /// Write the snapshot state + memory files, and (for a private-copy disk) copy the root disk into
    /// the bundle. Split out so `snapshot` can run it between the pause and the guaranteed resume
    /// without an early return skipping the resume. A shared read-only base is referenced in place, so
    /// there is nothing to copy.
    fn write_snapshot_bundle(
        &self,
        state: &Path,
        mem: &Path,
        root_drive: &Path,
        shared_base: bool,
    ) -> Result<(), VmmError> {
        self.api.put(
            "/snapshot/create",
            &SnapshotCreate {
                snapshot_type: SnapshotType::Full,
                snapshot_path: path_str(state)?,
                mem_file_path: path_str(mem)?,
            },
        )?;
        if !shared_base {
            std::fs::copy(&self.rootfs, root_drive)
                .map_err(|e| VmmError::Vmm(format!("copy root disk into snapshot bundle: {e}")))?;
        }
        Ok(())
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
        );
    }
}

/// A spawned-but-not-yet-ready VMM. Kept distinct from [`RunningVm`] so the boot sequence can fail
/// and clean up without ever constructing a half-booted `RunningVm`. Its `Drop` is the panic
/// safety net: if anything unwinds between `launch` and `abort`/`into_running` (a panicking
/// `tracing` subscriber, a future bug), the VMM still dies and the scratch dir is still reclaimed.
struct Spawned {
    /// `Some` until `abort`/`into_running` disarm the guard by taking it.
    child: Option<Child>,
    console: Console,
    workdir: PathBuf,
    rootfs: PathBuf,
    /// Set by [`launch_for_restore`](Spawned::launch_for_restore): the `rootfs` is a placeholder, so
    /// the resulting VM is marked restored and can't be re-snapshotted.
    restored: bool,
    api: ApiClient,
    /// The vsock socket path (in `workdir`) when the boot config enables vsock, else `None`.
    vsock_uds: Option<PathBuf>,
    /// The built bulk-input image (in `workdir`) when `input_dir` was set, attached read-only as a
    /// second block device; `None` otherwise. Reclaimed with `workdir` on teardown.
    input_image: Option<PathBuf>,
    /// The blank writable output image (in `workdir`) + its host destination, when `output_dir` was
    /// set; `None` otherwise. Attached read-write; extracted by `collect_outputs`, then reclaimed.
    output: Option<OutputDevice>,
    /// The per-VM host tap backing the guest's virtio-net, when `enable_network` was set. Lives
    /// **outside** `workdir`, so every teardown path must delete it explicitly.
    tap: Option<Tap>,
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            teardown(
                &mut child,
                &mut self.console,
                &self.workdir,
                self.tap.as_ref(),
            );
        }
    }
}

impl Spawned {
    /// Validate the inputs, lay out the scratch dir, and spawn `firecracker --api-sock`.
    fn launch(config: &BootConfig) -> Result<Self, VmmError> {
        require_file(&config.kernel, "kernel image")?;
        require_file(&config.rootfs, "rootfs image")?;

        let workdir = create_workdir()?;

        // Read-only boot shares the pinned base directly (no per-VM copy): Firecracker opens it
        // `O_RDONLY` so the guest can't mutate it, and the writable layer comes from the guest's
        // tmpfs overlay (see `BootConfig::read_only_root`). Read-write boot copies the base instead,
        // so the guest's writes stay per-VM and the base stays pinned.
        let rootfs = if config.read_only_root {
            // The shared base is handed to Firecracker as-is and recorded as the snapshot's disk path,
            // so resolve it to absolute now (each VMM's cwd is its scratch dir; a relative base path
            // would resolve there instead).
            match absolute(&config.rootfs) {
                Ok(p) => p,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            }
        } else {
            let copy = workdir.join("rootfs.ext4");
            if let Err(e) = std::fs::copy(&config.rootfs, &copy) {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(VmmError::Vmm(format!(
                    "copy rootfs to {}: {e}",
                    copy.display()
                )));
            }
            // `fs::copy` propagates the source's mode; a read-only pinned base (0444) would make the
            // read-write root drive unopenable. The copy is ours alone — force owner read-write.
            if let Err(e) = std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600))
            {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(VmmError::Vmm(format!("chmod rootfs copy: {e}")));
            }
            copy
        };

        // Bulk read-only input (P3.4): build an ext4 from the host `input_dir` and attach it as a
        // second block device (`/dev/vdb`). Lives in the scratch dir, so teardown reclaims it too.
        let input_image = match &config.input_dir {
            None => None,
            Some(dir) => match build_input_image(dir, &workdir) {
                Ok(img) => Some(img),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            },
        };

        // Bulk writable output (P3.5): build a blank ext4 the guest mounts read-write at `/output`,
        // attached as another block device. Its host destination rides along for `collect_outputs`.
        let output = match &config.output_dir {
            None => None,
            Some(dest) => match build_output_image(&workdir) {
                Ok(image) => Some(OutputDevice {
                    image,
                    dest: dest.clone(),
                }),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            },
        };

        // Spawn `firecracker --api-sock`, wiring its serial console + stderr log (see `spawn_fc`). On
        // any failure the child is already reaped; we still own the scratch dir, so reclaim it.
        let socket = workdir.join("fc.sock");
        let (mut child, console) = match spawn_fc(&config.firecracker, &workdir, &socket) {
            Ok(pair) => pair,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
        };
        // Per-VM tap for the guest's virtio-net (P4.1), when enabled. Created here — after the child
        // is spawned but before `Spawned` owns it — with the same inline cleanup as its neighbours, so
        // a failed create can't leak a tap; once `Spawned` holds it, every teardown path deletes it.
        let tap = if config.enable_network {
            match Tap::create() {
                Ok(tap) => Some(tap),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            }
        } else {
            None
        };

        // Firecracker creates the vsock socket here on `PUT /vsock`; the host dials it post-boot.
        let vsock_uds = config.guest_cid.map(|_| workdir.join(VSOCK_UDS));
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            rootfs,
            restored: false,
            api: ApiClient::new(socket),
            vsock_uds,
            input_image,
            output,
            tap,
        })
    }

    /// Spawn a bare `firecracker` for a snapshot restore: a fresh scratch dir + process + console,
    /// with **no** boot-time device configuration (the guest's devices are recreated from the
    /// snapshot on `PUT /snapshot/load`). The root drive is the bundle's private copy, held so the
    /// restored VM's teardown accounting matches a cold boot. Reuses the same `Spawned` guard, so a
    /// failed restore tears the VMM down through the same paths as a failed boot.
    fn launch_for_restore(config: &BootConfig, snapshot: &Snapshot) -> Result<Self, VmmError> {
        let workdir = create_workdir()?;
        let socket = workdir.join("fc.sock");
        let (child, console) = match spawn_fc(&config.firecracker, &workdir, &socket) {
            Ok(pair) => pair,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
        };
        // A warm snapshot carries the vsock exec channel. Its socket path was baked in relative, so
        // Firecracker re-binds it in *this* restore's cwd (its scratch dir): the restored VM reaches
        // the guest agent through its own `v.sock`, and concurrent clones don't collide. Computed
        // before `workdir` is moved into the struct.
        let vsock_uds = snapshot.has_vsock.then(|| workdir.join(VSOCK_UDS));
        // A networked snapshot baked in its tap's `host_dev_name`, which Firecracker will open at
        // load — so a tap with **that exact name** must exist first (v1.9 has no `network_overrides`;
        // decision 011). Recreate it with a fresh /30 on the host end; the guest side is re-addressed
        // by the agent after resume. Same inline-cleanup discipline as `launch`'s tap: once `Spawned`
        // holds the handle, every teardown path deletes it.
        let tap = match snapshot.tap_name.as_deref() {
            None => None,
            Some(name) => match Tap::create_named(name) {
                Ok(tap) => Some(tap),
                Err(e) => {
                    let mut child = child;
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            },
        };
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            // The restored VM's live disk is an anonymous inode (a private copy is staged at load then
            // unlinked; a shared base is referenced in place). This field holds the bundle path only as
            // a placeholder — it isn't a device this scratch dir owns, and re-snapshotting is refused.
            rootfs: snapshot.root_drive.clone(),
            restored: true,
            api: ApiClient::new(socket),
            vsock_uds,
            input_image: None,
            output: None,
            tap,
        })
    }

    /// The scratch-dir name, used to tag the per-VM tracing span so interleaved logs from concurrent
    /// VMs stay attributable. Shared by [`run_boot`](Self::run_boot) and
    /// [`run_restore`](Self::run_restore).
    fn vm_name(&self) -> String {
        self.workdir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }

    /// Load `snapshot` on this fresh VMM and resume it, returning the restore latency (the load +
    /// resume call). Firecracker opens the root disk **at load** from the path baked into the
    /// snapshot, so we first stage the bundle's private copy there, then unlink it once the VMM holds
    /// the fd: a restored clone gets its own disk inode (sharing no writable backing with its source),
    /// and nothing lingers outside this VM's scratch dir.
    fn run_restore(
        &mut self,
        snapshot: &Snapshot,
        timeout: Duration,
    ) -> Result<Duration, VmmError> {
        let span = tracing::info_span!("restore", vm = %self.vm_name());
        let _span = span.enter();

        // `Instant + Duration` panics on overflow; a caller's `Duration::MAX` must stay a bounded
        // wait, not a panic — clamp to a day (as `run_boot` does).
        let now = Instant::now();
        let deadline = now
            .checked_add(timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86_400));
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Resolve every fallible input (the deadline, the snapshot paths) *before* staging the disk,
        // so that once the ~disk-sized copy is on disk there is no `?` between the stage and the
        // matching unstage — a mid-restore early return can't leak the staged file outside our reach.
        still_before(deadline, "PUT /snapshot/load")?;
        let snapshot_path = path_str(&snapshot.state)?;
        let mem_path = path_str(&snapshot.mem)?;

        // The vsock socket path was baked in relative, so Firecracker re-binds it in this VMM's cwd
        // (its scratch dir, which already exists): no host-side path recreation is needed, and the
        // socket lands in our own workdir where teardown reclaims it.

        // A private per-VM disk is staged at its baked-in path so Firecracker can open it at load; a
        // read-only shared base already exists there (and is shared across clones), so it's left alone.
        let staged = !snapshot.shared_base;
        if staged {
            stage_restore_disk(&snapshot.root_drive, &snapshot.root_backing)?;
        }
        let started = Instant::now();
        let loaded = self.api.put(
            "/snapshot/load",
            &SnapshotLoad {
                snapshot_path,
                mem_backend: MemBackend {
                    backend_type: MemBackendType::File,
                    backend_path: mem_path,
                },
                resume_vm: true,
            },
        );
        // The restore latency is the load + resume call itself, measured before host-side cleanup.
        let latency = started.elapsed();
        // Firecracker now holds the disk's fd (or the load failed); either way remove a staged copy so
        // it never outlives this restore. The open fd keeps the inode alive for the VM's lifetime.
        if staged {
            unstage_restore_disk(&snapshot.root_backing);
        }
        loaded?;

        // A snapshot that loads but immediately dies (a corrupt bundle, an incompatible host) must be
        // a typed error, not a "successful" restore of a dead VMM.
        if let Some(status) = self.exited()? {
            return Err(VmmError::Vmm(format!(
                "firecracker exited after restore ({status})"
            )));
        }

        // If the snapshot carried the exec channel, the guest agent needs a brief moment after resume
        // before Firecracker's vsock backend is forwarding to it again. Poll until a connect succeeds
        // (bounded by the deadline), so `restore` hands back a VM that's actually ready to `exec`,
        // never one mid-resume (this is restore's analogue of boot's userspace-marker wait).
        if let Some(uds) = self.vsock_uds.clone() {
            self.await_agent_ready(&uds, deadline)?;
            // Fresh network identity (decision 011): the clone woke with the snapshot's baked-in
            // address, which no longer matches the recreated tap's fresh /30 (and would collide with
            // the source's if it were kept). The kernel `ip=` config ran once at the source's boot and
            // can't re-fire, so the **agent** applies the new address through the exec channel — the
            // runtime counterpart of boot-time `ip=`. Network *configuration* rides the agent; network
            // *enforcement* stays host-side (decision 008/spine #2).
            if let Some(guest_ip) = self.tap.as_ref().map(|t| t.guest_ip) {
                apply_guest_net_identity(&uds, guest_ip)?;
                tracing::debug!(%guest_ip, "restored clone re-addressed");
            }
        }

        tracing::info!(
            restore_ms = latency.as_millis() as u64,
            "microVM restored from snapshot"
        );
        Ok(latency)
    }

    /// Poll the guest agent's vsock port until a connect + handshake succeeds, so a restored VM is
    /// exec-ready when it's handed back. The probe connection is dropped immediately (the agent serves
    /// one connection then loops back to accept, so a connect-and-close just cycles it).
    fn await_agent_ready(&mut self, uds: &Path, deadline: Instant) -> Result<(), VmmError> {
        loop {
            match connect_agent_at(uds, AGENT_VSOCK_PORT, Duration::from_millis(200)) {
                Ok(_probe) => return Ok(()),
                Err(e) => {
                    if let Some(status) = self.exited()? {
                        return Err(VmmError::Vmm(format!(
                            "firecracker exited after restore ({status})"
                        )));
                    }
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// `PUT /drives/{id}` — attach a virtio-block device, deriving the API path from `id` so the URL
    /// and the body's `drive_id` are the same token and can't drift apart. `still_before` first, so a
    /// boot already past its deadline fails fast with this drive named.
    fn put_drive(
        &self,
        id: &str,
        path_on_host: &str,
        is_root_device: bool,
        is_read_only: bool,
        deadline: Instant,
    ) -> Result<(), VmmError> {
        still_before(deadline, &format!("PUT /drives/{id}"))?;
        self.api.put(
            &format!("/drives/{id}"),
            &Drive {
                drive_id: id,
                path_on_host,
                is_root_device,
                is_read_only,
            },
        )
    }

    /// Drive the API through the boot sequence and wait for the userspace marker; returns the
    /// boot-to-userspace latency.
    fn run_boot(&mut self, config: &BootConfig) -> Result<Duration, VmmError> {
        // One span per boot, keyed by the scratch-dir name, so interleaved logs from concurrent
        // VMs (the warm pool, Phase 5) stay attributable to their sandbox.
        let span = tracing::info_span!("boot", vm = %self.vm_name());
        let _span = span.enter();

        // `Instant + Duration` panics on overflow, and `boot_timeout` is caller-set (a
        // `Duration::MAX` "no limit" must stay a *bounded* wait, not a panic) — clamp to a day.
        let now = Instant::now();
        let deadline = now
            .checked_add(config.boot_timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86_400));
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Absolute paths for Firecracker (its cwd is the scratch dir); `self.rootfs` is already
        // absolute from `launch`.
        let kernel = absolute(&config.kernel)?;
        let kernel = path_str(&kernel)?;
        let rootfs = path_str(&self.rootfs)?;
        // A read-only root hands off to the overlay init, which stacks a size-capped tmpfs over the
        // RO base so `/` is writable per-run. The cap is half of guest RAM — the guest has no swap,
        // so a tmpfs sized near RAM would OOM the guest rather than bound a runaway write. It rides
        // the kernel command line as a `key=value` token, which the kernel routes into PID 1's
        // environment (so `overlay-init` reads `$overlay_size` without mounting `/proc` first).
        let mut boot_args = if config.read_only_root {
            format!(
                "{} init=/sbin/overlay-init overlay_size={}M",
                config.boot_args,
                config.mem_mib / 2
            )
        } else {
            config.boot_args.clone()
        };
        // Static guest addressing (P4.2) when a NIC is attached: the kernel configures `eth0` before
        // userspace via `CONFIG_IP_PNP`. The gateway field is **empty**, so the kernel installs only
        // the connected /30 route (guest ⇄ host over the tap) and **no default route** — the guest
        // reaches the host and nothing else (deny-by-default, decision 008). Netmask is a /30.
        if let Some(tap) = self.tap.as_ref() {
            boot_args = format!(
                "{boot_args} ip={}:::255.255.255.252::eth0:off",
                tap.guest_ip
            );
        }
        still_before(deadline, "PUT /boot-source")?;
        self.api.put(
            "/boot-source",
            &BootSource {
                kernel_image_path: kernel,
                boot_args: &boot_args,
            },
        )?;
        self.put_drive("rootfs", rootfs, true, config.read_only_root, deadline)?;
        // Bulk read-only input (P3.4): attach the built image as `/dev/vdb`. `is_read_only` is what
        // makes the input provably immutable (Firecracker opens it `O_RDONLY`) and sidesteps the
        // read-back-a-dirty-ext4 hazard that a writable device would carry into P3.5.
        if let Some(image) = self.input_image.as_ref() {
            let input = path_str(image)?;
            self.put_drive("input", input, false, true, deadline)?;
        }
        // Bulk writable output (P3.5): attach the blank image read-write. The guest mounts it by
        // label (`agent-output`), so the `/dev/vdX` letter this lands on doesn't matter — a boot may
        // attach input, output, both, or neither. Durability of the guest's writes is the guest's
        // `-o sync` mount plus a clean unmount on shutdown; `collect_outputs` reads it after the VMM
        // exits (never while it holds the file open — see `RunningVm::collect_outputs`).
        if let Some(out) = self.output.as_ref() {
            let output = path_str(&out.image)?;
            self.put_drive("output", output, false, false, deadline)?;
        }
        still_before(deadline, "PUT /machine-config")?;
        self.api.put(
            "/machine-config",
            &MachineConfig {
                vcpu_count: config.vcpus,
                mem_size_mib: config.mem_mib,
            },
        )?;

        if let Some(cid) = config.guest_cid {
            still_before(deadline, "PUT /vsock")?;
            // Bind the socket at the **relative** name `v.sock`, resolved against the VMM's cwd (its
            // scratch dir — see `spawn_fc`). The host still connects via the absolute `self.vsock_uds`
            // (same file), but baking a *relative* path into the snapshot is what lets warm clones
            // restored from it each bind their own socket in their own scratch dir, instead of all
            // colliding on one absolute path.
            self.api.put(
                "/vsock",
                &Vsock {
                    guest_cid: cid,
                    uds_path: VSOCK_UDS,
                },
            )?;
            tracing::debug!(guest_cid = cid, uds = VSOCK_UDS, "vsock device configured");
        }

        // Per-VM virtio-net (P4.1), backed by the host tap created in `launch`. Deny-by-default: the
        // guest gets an *unconfigured* `eth0` (no `ip=` boot arg, no host route or masquerade), so it
        // reaches nothing until addressing lands. The tap is deleted on every teardown path.
        if let Some(tap) = self.tap.as_ref() {
            still_before(deadline, "PUT /network-interfaces")?;
            self.api.put(
                &format!("/network-interfaces/{IFACE_ID}"),
                &NetworkInterface {
                    iface_id: IFACE_ID,
                    host_dev_name: &tap.name,
                    guest_mac: &tap.mac,
                },
            )?;
            tracing::debug!(tap = %tap.name, mac = %tap.mac, "virtio-net device configured");
        }

        tracing::debug!(
            vcpus = config.vcpus,
            mem_mib = config.mem_mib,
            "boot source, root drive, and machine config set"
        );

        still_before(deadline, "InstanceStart")?;
        // The number that matters is measured from InstanceStart to the userspace marker.
        let started = Instant::now();
        self.api.put("/actions", &Action::InstanceStart)?;
        self.await_userspace(&config.userspace_marker, deadline)?;
        let latency = started.elapsed();
        tracing::info!(
            boot_ms = latency.as_millis() as u64,
            "microVM reached userspace"
        );
        Ok(latency)
    }

    /// Poll `connect()` (not path-existence — the file can appear before `listen()`) until the API
    /// answers, failing fast if Firecracker already exited.
    fn await_api_socket(&mut self, deadline: Instant) -> Result<(), VmmError> {
        loop {
            if let Some(status) = self.exited()? {
                return Err(VmmError::Vmm(format!(
                    "firecracker exited before boot ({status})"
                )));
            }
            if std::os::unix::net::UnixStream::connect(self.api.socket()).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(VmmError::Timeout(
                    "firecracker API socket never became ready".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wait for the console to show the userspace marker, bounded by `deadline` and by the child
    /// exiting early (a guest that panics before userspace).
    fn await_userspace(&mut self, marker: &str, deadline: Instant) -> Result<(), VmmError> {
        loop {
            if self.console.contains(marker) {
                return Ok(());
            }
            if let Some(status) = self.exited()? {
                return Err(VmmError::Vmm(format!(
                    "firecracker exited before userspace ({status})"
                )));
            }
            if Instant::now() >= deadline {
                return Err(VmmError::Timeout(format!(
                    "guest did not reach userspace (marker {marker:?}) within the boot deadline"
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// `Some(status)` if the child has already exited, mapping the wait error to a typed value.
    fn exited(&mut self) -> Result<Option<std::process::ExitStatus>, VmmError> {
        match self.child.as_mut() {
            Some(child) => child
                .try_wait()
                .map_err(|e| VmmError::Vmm(format!("wait on firecracker: {e}"))),
            // Unreachable while the guard is armed; a typed error beats lying about liveness.
            None => Err(VmmError::Vmm("VMM child already reclaimed".into())),
        }
    }

    /// Boot failed: kill the VMM, then enrich the cause with the two diagnostics that explain
    /// most boot failures — Firecracker's stderr tail and the guest console tail (the kernel's
    /// last words are exactly what a pre-marker hang needs) — then reclaim the scratch dir, in
    /// that order, because the stderr log lives *in* the scratch dir.
    fn abort(mut self, cause: VmmError) -> VmmError {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // The tap lives outside the scratch dir, so `remove_dir_all` below won't reclaim it — delete
        // it explicitly (best-effort) on this boot-failure path too, or a failed boot leaks a tap.
        if let Some(tap) = self.tap.take() {
            tap.delete();
        }
        self.console.join();
        let fc_log = std::fs::read_to_string(self.workdir.join(FC_STDERR)).unwrap_or_default();
        let console = self.console.snapshot();
        let _ = std::fs::remove_dir_all(&self.workdir);

        let mut detail = String::new();
        if let Some(tail) = last_lines(&fc_log, 3) {
            detail.push_str(&format!(" [firecracker: {tail}]"));
        }
        if let Some(tail) = last_lines(&console, 3) {
            detail.push_str(&format!(" [console: {tail}]"));
        }
        if detail.is_empty() {
            return cause;
        }
        match cause {
            VmmError::Vmm(m) => VmmError::Vmm(format!("{m}{detail}")),
            VmmError::Timeout(m) => VmmError::Timeout(format!("{m}{detail}")),
            other => other,
        }
    }

    /// Promote a successfully-booted VMM to a [`RunningVm`], disarming this guard's `Drop`
    /// (hence the `mem::take`s — a `Drop` type can't be destructured).
    fn into_running(mut self, boot_latency: Duration) -> Result<RunningVm, VmmError> {
        let Some(child) = self.child.take() else {
            // Unreachable: `boot` only promotes a still-armed guard.
            return Err(VmmError::Vmm("VMM child already reclaimed".into()));
        };
        Ok(RunningVm {
            child,
            workdir: std::mem::take(&mut self.workdir),
            console: std::mem::take(&mut self.console),
            // `ApiClient` is a cheap-to-clone handle (just the socket path); the other fields can't
            // clone (a `Child`, owned buffers), so they `take()`. `self` still `Drop`s afterward.
            api: self.api.clone(),
            boot_latency,
            rootfs: std::mem::take(&mut self.rootfs),
            restored: self.restored,
            has_input: self.input_image.is_some(),
            vsock_uds: self.vsock_uds.take(),
            output: self.output.take(),
            tap: self.tap.take(),
        })
    }
}

/// Place the snapshot bundle's private root-disk copy at `backing` — the path Firecracker opens the
/// drive from during `PUT /snapshot/load` — creating parent dirs as needed. Refuses to overwrite an
/// existing file, so a still-live source VM's disk is never clobbered (drop the source first).
fn stage_restore_disk(copy: &Path, backing: &Path) -> Result<(), VmmError> {
    if let Some(parent) = backing.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            VmmError::Vmm(format!("stage restore disk dir {}: {e}", parent.display()))
        })?;
    }
    // `create_new` reserves the path **atomically**: if it already exists (a still-live source's
    // disk) the open fails rather than clobbering it — the "never overwrite" guarantee, race-free,
    // not a check-then-copy TOCTOU. A missing parent or any other error is surfaced as-is.
    let mut dst = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(backing)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(VmmError::Vmm(format!(
                "root disk path {} already exists; drop the source VM before restoring its snapshot",
                backing.display()
            )));
        }
        Err(e) => {
            return Err(VmmError::Vmm(format!(
                "stage restore disk {}: {e}",
                backing.display()
            )));
        }
    };
    let copy_bytes =
        std::fs::File::open(copy).and_then(|mut src| std::io::copy(&mut src, &mut dst).map(|_| ()));
    if let Err(e) = copy_bytes {
        // A partial copy (e.g. disk full mid-write) must leave nothing behind: drop the handle and
        // undo the file + the dir we may have just created, so staging is all-or-nothing.
        drop(dst);
        unstage_restore_disk(backing);
        return Err(VmmError::Vmm(format!(
            "stage restore disk {}: {e}",
            backing.display()
        )));
    }
    Ok(())
}

/// Remove the staged restore disk (and its parent dir if now empty), once Firecracker holds the fd.
/// Best-effort: the open fd keeps the inode alive for the VM's lifetime, so a failure here leaks at
/// most an empty file/dir under `/tmp`, never the VM's disk. `remove_dir` only succeeds on an empty
/// dir, so it never touches a directory that still holds a live VM's files.
fn unstage_restore_disk(backing: &Path) {
    let _ = std::fs::remove_file(backing);
    if let Some(parent) = backing.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

/// Spawn `firecracker --api-sock <socket>`, wiring its serial console to a [`Console`] and its stderr
/// to `<workdir>/fc.stderr`. Shared by a cold boot ([`Spawned::launch`]) and a snapshot restore
/// ([`Spawned::launch_for_restore`]).
///
/// Firecracker's own logs go to a *file* (not our stderr, which is the host's tracing; and not a
/// pipe, which back-pressures a chatty VMM or feeds it EPIPE when dropped) — `abort` reads it back for
/// diagnostics. On a spawn/console failure the child (if any) is reaped so nothing leaks; the caller
/// owns `workdir` cleanup.
fn spawn_fc(
    firecracker: &Path,
    workdir: &Path,
    socket: &Path,
) -> Result<(Child, Console), VmmError> {
    let fc_stderr = std::fs::File::create(workdir.join(FC_STDERR))
        .map_err(|e| VmmError::Vmm(format!("create firecracker stderr log: {e}")))?;
    let mut child = Command::new(firecracker)
        .arg("--api-sock")
        .arg(socket)
        // Run each VMM with its scratch dir as cwd, so a **relative** vsock socket path (`v.sock`)
        // resolves per-VM. That's what lets N warm clones restored from one snapshot each bind their
        // own socket instead of colliding on the source's absolute path (see `run_boot`'s `PUT /vsock`).
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped()) // guest serial console
        .stderr(Stdio::from(fc_stderr))
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VmmError::Artifact(format!("firecracker not found: {}", firecracker.display()))
            } else {
                VmmError::Vmm(format!("spawn firecracker: {e}"))
            }
        })?;
    let stdout = child.stdout.take();
    match Console::spawn(stdout) {
        Ok(console) => Ok((child, console)),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}

/// Create the per-VM scratch dir. Two constraints shape it:
/// - **Short path** (`/tmp/agent-<pid>-<n>`): the API socket lives here and
///   `sockaddr_un.sun_path` caps at ~108 bytes, so a deep `TMPDIR`-based path would make
///   Firecracker's `bind()` fail with EINVAL.
/// - **Fail-if-exists, mode `0700`**: `/tmp` is world-writable and PIDs recycle, so a
///   pre-existing path (squatted by another user, or stale from a killed run) must never be
///   silently adopted — the rootfs copy and socket go here. A collision just advances to the
///   next sequence number.
fn create_workdir() -> Result<PathBuf, VmmError> {
    use std::os::unix::fs::DirBuilderExt;
    for _ in 0..1024 {
        let workdir = PathBuf::from(format!(
            "/tmp/agent-{}-{}",
            std::process::id(),
            VM_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::DirBuilder::new().mode(0o700).create(&workdir) {
            Ok(()) => {
                // mkdir's mode is masked by the umask; an explicit chmod after the
                // fail-if-exists create makes 0700 unconditional (and race-free — the dir is
                // already exclusively ours).
                if let Err(e) =
                    std::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o700))
                {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(VmmError::Vmm(format!("chmod {}: {e}", workdir.display())));
                }
                return Ok(workdir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(VmmError::Vmm(format!("create {}: {e}", workdir.display()))),
        }
    }
    Err(VmmError::Vmm(
        "no fresh scratch dir under /tmp after 1024 attempts (stale agent-* dirs?)".into(),
    ))
}

/// Guaranteed, best-effort teardown shared by both `Drop`s: kill the VMM, join the console reader
/// (which ends once the killed child's stdout closes), delete the per-VM tap (it lives outside the
/// scratch dir, so `remove_dir_all` can't reclaim it), and remove the scratch dir.
fn teardown(child: &mut Child, console: &mut Console, workdir: &Path, tap: Option<&Tap>) {
    let _ = child.kill();
    let _ = child.wait();
    console.join();
    if let Some(tap) = tap {
        tap.delete();
    }
    let _ = std::fs::remove_dir_all(workdir);
}

/// A path as `&str`, or a typed error — Firecracker's JSON API can't carry non-UTF-8 paths.
pub(crate) fn path_str(p: &Path) -> Result<&str, VmmError> {
    p.to_str()
        .ok_or_else(|| VmmError::Vmm(format!("path is not valid UTF-8: {}", p.display())))
}

/// Resolve `p` to an absolute path against the **driver's** cwd (where a relative artifact path is
/// meant to resolve). Every *file* path handed to Firecracker must be absolute, because each VMM runs
/// with its scratch dir as cwd (so a relative vsock socket resolves per-VM — see `spawn_fc`); a
/// relative file path would otherwise resolve against that scratch dir instead. Lexical only (no
/// symlink resolution, no existence requirement), so it's safe on a path that doesn't exist yet.
fn absolute(p: &Path) -> Result<PathBuf, VmmError> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .map_err(|e| VmmError::Vmm(format!("resolve {}: {e}", p.display())))
    }
}

/// Fail fast if the boot deadline has already passed before the next step (`what`). Each API call is
/// individually time-capped by the client, but their *sum* must also respect the boot deadline, or a
/// slow VMM could stretch `boot` well past `wall`.
fn still_before(deadline: Instant, what: &str) -> Result<(), VmmError> {
    if Instant::now() >= deadline {
        return Err(VmmError::Timeout(format!(
            "boot deadline expired before {what}"
        )));
    }
    Ok(())
}

/// Require a file to exist, mapping absence to a clear [`VmmError::Artifact`].
fn require_file(path: &Path, what: &str) -> Result<(), VmmError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(VmmError::Artifact(format!(
            "{what} not found at {} (run `cargo xtask fetch-artifacts`)",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TestDir;

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
    fn missing_artifact_is_typed_error() {
        let err = require_file(Path::new("/no/such/vmlinux"), "kernel image").unwrap_err();
        assert!(matches!(err, VmmError::Artifact(_)));
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
    fn dead_vmm_fails_fast_with_its_stderr_tail() {
        // A "firecracker" that exits immediately, complaining on stderr: `sh --api-sock <path>`
        // rejects the flag. Boot must fail fast with the exit surfaced — not wait out the whole
        // deadline — and carry the stderr tail. Needs no KVM, so it runs in the host gate.
        let dir = TestDir::new("agent-fake-fc");
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&kernel, b"not a kernel").expect("fake kernel");
        std::fs::write(&rootfs, b"not a rootfs").expect("fake rootfs");

        let cfg = BootConfig {
            firecracker: PathBuf::from("sh"),
            kernel,
            rootfs,
            boot_timeout: Duration::from_secs(10),
            ..BootConfig::default()
        };
        let started = Instant::now();
        let mut spawned = Spawned::launch(&cfg).expect("launch the fake vmm");
        let err = spawned.run_boot(&cfg).expect_err("a dead vmm cannot boot");
        let msg = spawned.abort(err).to_string();

        assert!(msg.contains("exited before boot"), "fail fast, got: {msg}");
        assert!(msg.contains("[firecracker:"), "stderr tail attached: {msg}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must not wait out the boot deadline"
        );
    }

    #[test]
    fn workdirs_are_fresh_private_and_distinct() {
        let a = TestDir::adopt(create_workdir().expect("first workdir"));
        let b = TestDir::adopt(create_workdir().expect("second workdir"));
        assert_ne!(a.path(), b.path(), "each VM gets its own scratch dir");
        let mode = std::fs::metadata(a.path())
            .expect("stat workdir")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "scratch dir must be private to us");
    }
}
