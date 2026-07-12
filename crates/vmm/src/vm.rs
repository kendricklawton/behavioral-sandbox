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

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use agent_channel::{ClientConnection, Request, Response};

use crate::firecracker::{
    Action, ApiClient, BootSource, Drive, MachineConfig, NetworkInterface, Vsock,
};
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

/// Cap on the captured console (the most recent bytes are kept). A guest that floods its serial
/// port must not grow host memory without bound — a hostile guest never causes a leak. Boot output
/// is tens of KiB, so the userspace marker is never dropped while it still matters.
const CONSOLE_CAP: usize = 1 << 20; // 1 MiB

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
const VSOCK_UDS: &str = "v.sock";

/// Size of the blank writable output image (P3.5). A fixed cap for now — it's the natural bulk-output
/// bound (the guest can't write more than the filesystem holds), mirroring the channel path's
/// [`MAX_EXEC_OUTPUT`]. Built with `lazy_itable_init=0` so the guest kernel never balloons the
/// metadata: a fresh image is ~a few MiB of real host blocks, growing only with what's written.
const OUTPUT_IMAGE_MIB: u32 = 256;

/// Hard ceiling on the **real host bytes** [`RunningVm::collect_outputs`] will write while extracting
/// the output image. `debugfs rdump` materialises filesystem holes as zeros, so a hostile guest could
/// stage a sparse file with a huge logical size inside the capped image and inflate the readback — a
/// watcher aborts once the extracted tree's allocated blocks pass this bound. Generous headroom over
/// [`OUTPUT_IMAGE_MIB`] (a legitimate tree's real bytes can't exceed the image), so only abuse trips.
const OUTPUT_EXTRACT_CAP: u64 = 2 * (OUTPUT_IMAGE_MIB as u64) * 1024 * 1024; // 512 MiB

/// Wall-clock bound on the output readback (`e2fsck` + `debugfs rdump`), so a pathological image can
/// never hang the host teardown. Read-back is off the boot path; generous is fine.
const OUTPUT_READBACK_TIMEOUT: Duration = Duration::from_secs(120);

/// The filesystem labels the driver stamps on the data devices so the guest mounts them by label,
/// not by enumeration-order `/dev/vdX` (a boot may attach input, output, both, or neither). Defined
/// in `agent-channel` — the one host↔guest contract both the driver and the rootfs build consume.
use agent_channel::{INPUT_LABEL, OUTPUT_LABEL};

/// Deadline for the vsock connect + `CONNECT` handshake, and the read/write timeout the exec
/// connection carries — so a dead-or-stalled guest is a typed timeout, never a host hang
/// (decision 002: liveness is the transport's job).
const VSOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the stdout+stderr+artifacts the host buffers for one `exec`. Each frame is already
/// `≤ MAX_PAYLOAD`, but a guest can send *unboundedly many* frames (`yes`), so the aggregate is
/// capped too — a hostile guest never grows host memory without bound. (A command's *runtime* is a
/// separate axis, bounded by the exec wall-timeout below.) A fixed default for now — it joins the
/// hoster-tunable per-run resource policy (cpu/mem/wall/output) once that shape is decided.
const MAX_EXEC_OUTPUT: usize = 16 << 20; // 16 MiB

/// Per-frame overhead charged toward the output cap, so a flood of empty (or all-`path`, no-`data`)
/// frames can't spin the collect loop or grow the artifact list without advancing the cap.
const FRAME_FLOOR: usize = 64;

/// Default wall-clock budget for one command, sent to the guest agent, which kills the command past
/// it. A fixed default for now — it joins the hoster-tunable per-run resource policy later. (The
/// guest clamps a host-sent budget to its own 1 h ceiling. When the budget becomes a policy knob,
/// both the socket idle timeout *and* the host deadline must be derived from the *requested* value —
/// `budget + EXEC_KILL_SLACK` — not from this const, or a long quiet command is cut off early.)
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// Slack past a command's own budget before the *host* gives up on the exec connection: the margin
/// for the guest agent to notice its deadline, SIGKILL the command, and get its `TimedOut` frame
/// back. The host's total patience is `budget + EXEC_KILL_SLACK`, used both as the exec socket's
/// per-read idle timeout (so a legitimately long-but-quiet command isn't cut off by the transport)
/// and as the wall-clock deadline on the collect loop (so a silent-or-hostile guest that never
/// self-reports can't park `exec` forever — decision 002: liveness is the transport's job, not the
/// guest's). Ordered so the guest's cooperative `TimedOut` (fired at `budget`) always beats the host
/// deadline for a legitimate timeout; the host fires only when the guest fails to report.
const EXEC_KILL_SLACK: Duration = Duration::from_secs(5);

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
    /// large-file path — the vsock channel's [`Request::PutFile`] carries only small per-frame files.
    /// `None` (the default) attaches no input device. Building the image needs `mke2fs` + `truncate`.
    pub input_dir: Option<PathBuf>,
    /// A host directory to receive **bulk output** (P3.5): the driver attaches a blank, **writable**
    /// ext4 as a third block device (`/dev/vd?`, labelled `agent-output`); the agent rootfs mounts it
    /// read-write at `/output`, so a command's files under `/output/...` are pulled back here by
    /// [`RunningVm::collect_outputs`]. This is the whole-working-dir / large-file counterpart to the
    /// vsock channel's per-frame [`Response::File`] artifacts. `None` (the default) attaches no output
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
    /// The vsock unix socket Firecracker created, if this VM was booted with a `guest_cid`.
    vsock_uds: Option<PathBuf>,
    /// The writable output image (in `workdir`) and the host directory to extract it into, when the
    /// boot config set `output_dir`; `None` otherwise. Read back by [`RunningVm::collect_outputs`].
    output: Option<OutputDevice>,
    /// The per-VM host tap backing the guest's virtio-net, when the boot config set
    /// `enable_network`. Lives **outside** `workdir`, so teardown must delete it explicitly.
    tap: Option<Tap>,
}

/// A booted VM's writable output device: the ext4 image the guest mounts at `/output`, and the host
/// directory its tree is extracted into on [`RunningVm::collect_outputs`].
#[derive(Debug, Clone)]
struct OutputDevice {
    image: PathBuf,
    dest: PathBuf,
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

    /// Connect to the in-guest agent over vsock and complete the channel handshake, returning a
    /// protocol-ready [`ClientConnection`]. This is the host side of the exec path (P2.4 builds
    /// `exec` on top): it dials Firecracker's vsock socket, speaks the `CONNECT <port>` handshake,
    /// sets read/write deadlines, then does the channel handshake.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the VM was booted without a `guest_cid`, if the `CONNECT` handshake is
    /// refused (e.g. nothing is listening on `port` in the guest yet), or on any I/O or channel
    /// failure; [`VmmError::Timeout`] if the connect exceeds the deadline.
    pub fn connect_agent(&self, port: u32) -> Result<ClientConnection<UnixStream>, VmmError> {
        let uds = self.vsock_uds.as_ref().ok_or_else(|| {
            VmmError::Vmm("this microVM was booted without vsock (set BootConfig.guest_cid)".into())
        })?;
        connect_agent_at(uds, port, VSOCK_TIMEOUT)
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
    /// [`VmmError::Vmm`] if the VM has no vsock or the agent isn't listening, [`VmmError::Timeout`]
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
        let uds = self.vsock_uds.as_ref().ok_or_else(|| {
            VmmError::Vmm("this microVM was booted without vsock (set BootConfig.guest_cid)".into())
        })?;
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

    /// Best-effort power-off, then **guarantee** the VMM is dead and reaped, so its fd to the output
    /// image is released before readback. Idempotent with `Drop`'s teardown (a second kill/wait on an
    /// already-reaped child is a harmless no-op).
    fn stop_and_reap(&mut self) {
        let _ = self.api.put(
            "/actions",
            &Action {
                action_type: "SendCtrlAltDel",
            },
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                // Clean power-off: the guest ran `::shutdown:/bin/umount -a -r`, so `/output` is
                // flushed and cleanly unmounted.
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() >= deadline => {
                    // A wedged guest: hard-kill it. The `-o sync` mount means the command's completed
                    // writes are already on the image; `e2fsck` will recover the unclean journal.
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                // `try_wait` itself failed (near-impossible): still force the kill/wait so the fd to
                // the output image is released before readback, rather than trusting a later `Drop`.
                Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
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
        // `SendCtrlAltDel` is an x86-only ACPI-ish nicety (i8042); the kill in `Drop` is what
        // actually guarantees no leak. Ignore its result — the guest may already be gone.
        let _ = self.api.put(
            "/actions",
            &Action {
                action_type: "SendCtrlAltDel",
            },
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
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
            config.rootfs.clone()
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

        // Firecracker's own logs go to a *file* in the scratch dir: not our stderr (that's the
        // host's tracing), and not a pipe — an unread pipe back-pressures a chatty VMM, and a
        // dropped one would feed it EPIPE mid-run. `abort` reads the file back for diagnostics.
        let socket = workdir.join("fc.sock");
        let fc_stderr = match std::fs::File::create(workdir.join(FC_STDERR)) {
            Ok(f) => f,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(VmmError::Vmm(format!("create firecracker stderr log: {e}")));
            }
        };
        let mut child = match Command::new(&config.firecracker)
            .arg("--api-sock")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped()) // guest serial console
            .stderr(Stdio::from(fc_stderr))
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&workdir);
                let kind = if e.kind() == std::io::ErrorKind::NotFound {
                    VmmError::Artifact(format!(
                        "firecracker not found: {}",
                        config.firecracker.display()
                    ))
                } else {
                    VmmError::Vmm(format!("spawn firecracker: {e}"))
                };
                return Err(kind);
            }
        };

        let stdout = child.stdout.take();
        let console = match Console::spawn(stdout) {
            Ok(console) => console,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
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
            api: ApiClient::new(socket),
            vsock_uds,
            input_image,
            output,
            tap,
        })
    }

    /// Drive the API through the boot sequence and wait for the userspace marker; returns the
    /// boot-to-userspace latency.
    fn run_boot(&mut self, config: &BootConfig) -> Result<Duration, VmmError> {
        // One span per boot, keyed by the scratch-dir name, so interleaved logs from concurrent
        // VMs (the warm pool, Phase 5) stay attributable to their sandbox.
        let vm = self
            .workdir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let span = tracing::info_span!("boot", vm = %vm);
        let _span = span.enter();

        // `Instant + Duration` panics on overflow, and `boot_timeout` is caller-set (a
        // `Duration::MAX` "no limit" must stay a *bounded* wait, not a panic) — clamp to a day.
        let now = Instant::now();
        let deadline = now
            .checked_add(config.boot_timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86_400));
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Each API call is individually time-capped by the client, but their *sum* must also
        // respect the boot deadline — otherwise a slow VMM could stretch `boot` well past `wall`.
        fn still_before(deadline: Instant, what: &str) -> Result<(), VmmError> {
            if Instant::now() >= deadline {
                return Err(VmmError::Timeout(format!(
                    "boot deadline expired before {what}"
                )));
            }
            Ok(())
        }

        let kernel = path_str(&config.kernel)?;
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
        still_before(deadline, "PUT /drives/rootfs")?;
        self.api.put(
            "/drives/rootfs",
            &Drive {
                drive_id: "rootfs",
                path_on_host: rootfs,
                is_root_device: true,
                is_read_only: config.read_only_root,
            },
        )?;
        // Bulk read-only input (P3.4): attach the built image as `/dev/vdb`. `is_read_only` is what
        // makes the input provably immutable (Firecracker opens it `O_RDONLY`) and sidesteps the
        // read-back-a-dirty-ext4 hazard that a writable device would carry into P3.5.
        if let Some(image) = self.input_image.as_ref() {
            let input = path_str(image)?;
            still_before(deadline, "PUT /drives/input")?;
            self.api.put(
                "/drives/input",
                &Drive {
                    drive_id: "input",
                    path_on_host: input,
                    is_root_device: false,
                    is_read_only: true,
                },
            )?;
        }
        // Bulk writable output (P3.5): attach the blank image read-write. The guest mounts it by
        // label (`agent-output`), so the `/dev/vdX` letter this lands on doesn't matter — a boot may
        // attach input, output, both, or neither. Durability of the guest's writes is the guest's
        // `-o sync` mount plus a clean unmount on shutdown; `collect_outputs` reads it after the VMM
        // exits (never while it holds the file open — see `RunningVm::collect_outputs`).
        if let Some(out) = self.output.as_ref() {
            let output = path_str(&out.image)?;
            still_before(deadline, "PUT /drives/output")?;
            self.api.put(
                "/drives/output",
                &Drive {
                    drive_id: "output",
                    path_on_host: output,
                    is_root_device: false,
                    is_read_only: false,
                },
            )?;
        }
        still_before(deadline, "PUT /machine-config")?;
        self.api.put(
            "/machine-config",
            &MachineConfig {
                vcpu_count: config.vcpus,
                mem_size_mib: config.mem_mib,
            },
        )?;

        if let (Some(cid), Some(uds)) = (config.guest_cid, self.vsock_uds.as_ref()) {
            still_before(deadline, "PUT /vsock")?;
            let uds_path = path_str(uds)?;
            self.api.put(
                "/vsock",
                &Vsock {
                    guest_cid: cid,
                    uds_path,
                },
            )?;
            tracing::debug!(guest_cid = cid, uds = uds_path, "vsock device configured");
        }

        // Per-VM virtio-net (P4.1), backed by the host tap created in `launch`. Deny-by-default: the
        // guest gets an *unconfigured* `eth0` (no `ip=` boot arg, no host route or masquerade), so it
        // reaches nothing until addressing lands. The tap is deleted on every teardown path.
        if let Some(tap) = self.tap.as_ref() {
            still_before(deadline, "PUT /network-interfaces/eth0")?;
            self.api.put(
                "/network-interfaces/eth0",
                &NetworkInterface {
                    iface_id: "eth0",
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
        self.api.put(
            "/actions",
            &Action {
                action_type: "InstanceStart",
            },
        )?;
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
            api: self.api.clone(),
            boot_latency,
            vsock_uds: self.vsock_uds.take(),
            output: self.output.take(),
            tap: self.tap.take(),
        })
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

/// Names the next per-VM tap/MAC within this process. Host-global uniqueness rests on `ip tuntap
/// add` failing on an already-taken name as an atomic reservation (like [`create_workdir`]); this counter,
/// mixed with the PID, just keeps candidates distinct so a cross-process collision is rare.
static NET_SEQ: AtomicU64 = AtomicU64::new(0);

/// A per-VM host **tap** backing the guest's virtio-net (P4.1) with the host end of a point-to-point
/// /30 assigned (P4.2). The driver creates it (`ip tuntap`, needs `CAP_NET_ADMIN`), names it on the
/// `PUT /network-interfaces`, addresses the host end, and deletes it on every teardown path — it
/// lives **outside** the scratch dir, so `remove_dir_all` can't reclaim it (and `ip link del`
/// cascades away its address + connected route, so addressing adds no teardown burden).
#[derive(Debug, Clone)]
struct Tap {
    /// Host interface name (`fc<hex>`, ≤ `IFNAMSIZ`-1 = 15 bytes).
    name: String,
    /// The guest NIC's MAC: a locally-administered unicast address, distinct per VM.
    mac: String,
    /// The host end of the point-to-point /30 (assigned to the tap).
    host_ip: Ipv4Addr,
    /// The guest end of the /30 (configured on the guest's `eth0` via the kernel `ip=` param).
    guest_ip: Ipv4Addr,
}

impl Tap {
    /// Create a uniquely-named tap, bring it up, and assign the host end of the per-VM /30. Shells
    /// out to `ip` (iproute2), consistent with the driver's other host-tool calls (`mke2fs`/`e2fsck`);
    /// needs `CAP_NET_ADMIN`, so this only succeeds under the privileged test/runtime tier.
    fn create() -> Result<Tap, VmmError> {
        for _ in 0..1024 {
            // Mix the PID in so two driver processes rarely pick the same name/MAC/subnet; the `ip
            // tuntap add` name-taken retry below is the real cross-process reservation for the name.
            let token =
                (u64::from(std::process::id()) << 20) ^ NET_SEQ.fetch_add(1, Ordering::Relaxed);
            let name = tap_name(token);
            match tap_add(&name)? {
                TapAdd::Exists => continue, // raced or stale — try the next candidate name
                TapAdd::Created => {}
            }
            // A half-configured tap must not leak if bring-up or addressing fails.
            let (host_ip, guest_ip, prefix) = subnet_for(token);
            let setup = run_ip(&["link", "set", "dev", &name, "up"]).and_then(|()| {
                // Assign the host end of the /30. This auto-installs the connected route so the host
                // reaches the guest — the only route on the link. Deny-by-default (decision 008): no
                // default route, no masquerade, no ip_forward; `ip link del` removes this on teardown.
                run_ip(&["addr", "add", &format!("{host_ip}/{prefix}"), "dev", &name])
            });
            if let Err(e) = setup {
                let _ = run_ip(&["link", "del", "dev", &name]);
                return Err(e);
            }
            #[allow(clippy::cast_possible_truncation)]
            let mac = mac_for(token as u32);
            return Ok(Tap {
                name,
                mac,
                host_ip,
                guest_ip,
            });
        }
        Err(VmmError::Vmm(
            "could not allocate a unique tap name after 1024 attempts".into(),
        ))
    }

    /// Best-effort delete for teardown/`Drop` context: a failure is logged, never propagated or
    /// panicked (the host path is `#![forbid(unsafe_code)]` and must not panic on teardown). Removing
    /// the interface also removes its address and connected route.
    fn delete(&self) {
        if let Err(e) = run_ip(&["link", "del", "dev", &self.name]) {
            tracing::warn!(tap = %self.name, error = %e, "failed to delete tap on teardown");
        }
    }
}

/// The tap name for a token: `fc` + up to 12 hex digits (48 bits) = ≤ 14 bytes, within the 15-byte
/// `IFNAMSIZ` limit. Factored out so the length bound is unit-testable.
fn tap_name(token: u64) -> String {
    format!("fc{:x}", token & 0xffff_ffff_ffff)
}

/// A locally-administered **unicast** MAC derived from a per-VM value. The first octet `0x02` sets
/// the locally-administered bit (`0x02`) and clears the multicast bit (`0x01`); the low four bytes
/// carry the value, so each VM gets a distinct, valid NIC address.
fn mac_for(v: u32) -> String {
    let b = v.to_be_bytes();
    format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3])
}

/// The two high octets of the per-VM address space: `10.200.0.0/16`, carved into 16384 point-to-point
/// /30 blocks. An RFC1918 range chosen to dodge the defaults a host is likely to already route
/// (Docker `172.17+`, libvirt `192.168.122`, home routers `192.168.0/1`, plain `10.0.0/24`).
const NET_BASE: [u8; 2] = [10, 200];

/// Fold a 64-bit token down to a 14-bit /30 index. The token is `(pid << 20) ^ NET_SEQ`, so its PID
/// entropy lives in bits ≥ 20; a plain `token & 0x3fff` would drop all of it and collapse to
/// `NET_SEQ & 0x3fff`, making two driver processes both at `NET_SEQ = 0` pick the *same* /30 in the
/// shared host netns. XOR-folding the high bits down mixes the PID back into the index.
fn subnet_index(token: u64) -> u16 {
    ((token ^ (token >> 14) ^ (token >> 28) ^ (token >> 42)) & 0x3fff) as u16
}

/// The `(host_ip, guest_ip, prefix)` of the per-VM point-to-point /30 for `token`, derived from the
/// same token that won the tap name/MAC so a VM's identity is consistent. Within the 4-address block
/// (`index * 4`): `+1` is the host end, `+2` the guest end, so it's a /30 (netmask `255.255.255.252`).
/// `index ∈ [0, 16383]` ⇒ `block ∈ {0, 4, …, 65532}` ⇒ the low octet is a multiple of 4 in `[0, 252]`,
/// so `+1`/`+2` never overflow an octet.
fn subnet_for(token: u64) -> (Ipv4Addr, Ipv4Addr, u8) {
    let block = u32::from(subnet_index(token)) << 2; // index * 4
    let o3 = (block >> 8) as u8;
    let o4 = (block & 0xff) as u8;
    let host = Ipv4Addr::new(NET_BASE[0], NET_BASE[1], o3, o4 + 1);
    let guest = Ipv4Addr::new(NET_BASE[0], NET_BASE[1], o3, o4 + 2);
    (host, guest, 30)
}

/// Outcome of `ip tuntap add`: a taken name is the retryable case (another VM or a stale tap holds
/// it), distinct from a real failure.
enum TapAdd {
    Created,
    Exists,
}

/// `ip tuntap add <name> mode tap`, classifying a name already taken (retry) apart from a real error.
/// The name-taken case *is* the atomic host-global reservation across concurrent processes. We
/// classify it by *asking netlink whether the interface now exists* rather than parsing the error
/// string: `ip tuntap` creates via the `TUNSETIFF` ioctl, which fails with `EBUSY` ("Device or
/// resource busy") on a collision — not the RTNETLINK `EEXIST` ("File exists") — so a message match
/// would be both wrong and locale-fragile. The existence probe is exit-code- and namespace-based.
fn tap_add(name: &str) -> Result<TapAdd, VmmError> {
    let out = Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tap"])
        .output()
        .map_err(|e| tool_spawn_error("ip", e))?;
    if out.status.success() {
        return Ok(TapAdd::Created);
    }
    // A failure whose cause is "the name is taken" leaves the interface present; anything else
    // (e.g. EPERM without CAP_NET_ADMIN) does not, and must surface — never retry it.
    if iface_exists(name) {
        return Ok(TapAdd::Exists);
    }
    Err(VmmError::Vmm(format!(
        "ip tuntap add {name}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

/// Whether a network interface named `name` exists in the current network namespace, via
/// `ip link show` (exit 0 = present). Netlink-based, so it's correct inside a network namespace where
/// `/sys/class/net` may reflect a different one, and it keys on the exit code, not a localized string.
fn iface_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `ip <args>`, mapping a missing binary or a nonzero exit to a typed error. Used for tap
/// bring-up and delete; tap *creation* is [`tap_add`] (it must classify the retryable name-taken case).
fn run_ip(args: &[&str]) -> Result<(), VmmError> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| tool_spawn_error("ip", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(VmmError::Vmm(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Dial Firecracker's vsock socket, speak the `CONNECT <port>` handshake, and complete the channel
/// handshake — the whole host side of reaching the guest agent. Factored out of
/// [`RunningVm::connect_agent`] so it can be tested against a fake vsock socket without a VM.
fn connect_agent_at(
    uds: &Path,
    port: u32,
    timeout: Duration,
) -> Result<ClientConnection<UnixStream>, VmmError> {
    let stream = vsock_connect(uds, port, timeout)?;
    ClientConnection::connect(stream)
        .map_err(|e| VmmError::Vmm(format!("channel handshake over vsock: {e}")))
}

/// Drive one exec over an established [`ClientConnection`]: send the request, then aggregate the
/// response stream into a [`RunResult`]. Bounded on two axes so a flooding *or* dribbling guest can't
/// hurt the host: `max_output` caps buffered bytes, and `wall` is the host's own wall-clock deadline
/// on the collect loop (`timeout` is the guest's command budget; `wall` = `timeout` + kill slack).
/// A guest that keeps the per-read idle timer alive by dribbling tiny frames — never sending its
/// terminal `Exit`/`TimedOut` — trips `wall` and yields [`VmmError::ExecUnresponsive`], rather than
/// parking the caller indefinitely. Factored out of [`RunningVm::exec`] so it can be tested without a VM.
/// The host-enforced bounds on one exec, bundled so they travel together (and to keep `run_exec`
/// under the argument-count limit). Seeds the hoster-tunable per-run resource policy the timeout
/// constants above anticipate.
struct ExecBounds {
    /// The guest's command wall-clock budget, sent to the agent as `timeout_ms`; the agent kills the
    /// command past it and reports `TimedOut`.
    timeout: Duration,
    /// The *host's* own deadline on the collect loop — `timeout` + kill slack — so a guest that never
    /// reports the command's end can't park `exec` forever. Trips [`VmmError::ExecUnresponsive`].
    wall: Duration,
    /// Aggregate cap on buffered stdout+stderr+artifacts, so a flooding guest can't grow host memory.
    max_output: usize,
}

fn run_exec<S: Read + Write>(
    conn: &mut ClientConnection<S>,
    argv: &[String],
    stdin: &[u8],
    files_in: &[(String, Vec<u8>)],
    artifacts: &[String],
    bounds: ExecBounds,
) -> Result<RunResult, VmmError> {
    // Host-side trace of the exec (the guest's own `exec` span goes to the serial console, not the
    // operator's stderr), keyed by argv so `agent run` failures are diagnosable host-side.
    let span = tracing::info_span!("exec", argv = ?argv);
    let _span = span.enter();
    let started = Instant::now();
    // The host's own deadline, independent of the socket's per-read idle timeout. A `Duration::MAX`
    // "no limit" must stay a *bounded* wait, not an `Instant + Duration` overflow panic — clamp to a
    // day (mirrors the boot deadline).
    let deadline = started
        .checked_add(bounds.wall)
        .unwrap_or_else(|| started + Duration::from_secs(86_400));

    // Inject input files first, then the terminal exec request.
    // `?` on channel calls yields `VmmError::Channel(..)`, preserving the `ChannelError` source.
    for (path, data) in files_in {
        conn.send_request(&Request::PutFile {
            path: path.clone(),
            data: data.clone(),
        })?;
    }
    conn.send_request(&Request::Exec {
        argv: argv.to_vec(),
        stdin: stdin.to_vec(),
        artifacts: artifacts.to_vec(),
        timeout_ms: u32::try_from(bounds.timeout.as_millis()).unwrap_or(u32::MAX),
    })?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    // Bound stdout + stderr + artifact *names and bytes* together. `FRAME_FLOOR` is charged per
    // frame so a flood of empty frames (or `File` frames whose budget is spent on `path`, not
    // `data`) can't spin the loop or grow `files` without advancing the cap.
    let mut captured = 0usize;
    loop {
        // The host's own wall-clock deadline, checked *before* each blocking read. The socket's
        // per-read idle timeout is reset by every frame, so a guest that dribbles tiny well-formed
        // frames — never sending its terminal `Exit`/`TimedOut` — would otherwise keep this loop
        // alive indefinitely under the output cap. `wall` outlasts the guest's own `TimedOut`, so a
        // legitimate timeout still arrives as `ExecTimeout`; this only fires for a non-reporting
        // guest. Worst case the loop is parked in `recv_response` when the deadline passes, so the
        // real bound is `deadline + one idle period` — bounded, not a hang.
        if Instant::now() >= deadline {
            return Err(VmmError::ExecUnresponsive { limit: bounds.wall });
        }
        match conn.recv_response()? {
            Response::Stdout(b) => {
                captured += b.len() + FRAME_FLOOR;
                stdout.extend_from_slice(&b);
            }
            Response::Stderr(b) => {
                captured += b.len() + FRAME_FLOOR;
                stderr.extend_from_slice(&b);
            }
            Response::File { path, data } => {
                captured += path.len() + data.len() + FRAME_FLOOR;
                files.push((path, data));
            }
            Response::Exit { code } => {
                tracing::info!(
                    exit_code = code,
                    stdout_bytes = stdout.len(),
                    stderr_bytes = stderr.len(),
                    artifacts = files.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "guest command finished"
                );
                return Ok(RunResult {
                    exit_code: code,
                    stdout,
                    stderr,
                    files,
                });
            }
            // The guest killed the command at its wall-clock deadline. Distinct typed error, and
            // logged host-side (the guest's own log goes to the serial console, not the operator).
            // NOTE: the partial stdout/stderr streamed before the kill is discarded here; carrying
            // it on the error (or a `timed_out` RunResult) is a future enhancement.
            Response::TimedOut { elapsed_ms } => {
                tracing::warn!(
                    limit_ms = bounds.timeout.as_millis() as u64,
                    elapsed_ms,
                    "guest command timed out"
                );
                return Err(VmmError::ExecTimeout {
                    limit: bounds.timeout,
                });
            }
            // A guest-side fault on a healthy channel — distinct from a transport failure.
            Response::Error(msg) => return Err(VmmError::GuestExec(msg)),
            _ => {
                return Err(VmmError::Vmm(
                    "unexpected response frame from guest agent".into(),
                ))
            }
        }
        if captured > bounds.max_output {
            return Err(VmmError::OutputCap {
                limit: bounds.max_output,
            });
        }
    }
}

/// Connect to `uds` and perform Firecracker's host-initiated vsock handshake: send
/// `CONNECT <port>\n`, expect `OK <host_port>\n`. Returns the stream positioned right after the
/// ack, with read/write deadlines set.
fn vsock_connect(uds: &Path, port: u32, timeout: Duration) -> Result<UnixStream, VmmError> {
    // `connect` is the one step without a deadline (std has no `UnixStream::connect_timeout`), but
    // the peer is Firecracker's own vsock socket — created pre-`InstanceStart` and accepting
    // promptly — so it returns or refuses at once; every step after this is deadline-bounded.
    let mut stream = UnixStream::connect(uds)
        .map_err(|e| VmmError::Vmm(format!("connect vsock socket {}: {e}", uds.display())))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| VmmError::Vmm(format!("set vsock timeouts: {e}")))?;

    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .map_err(|e| VmmError::Vmm(format!("vsock CONNECT {port}: {e}")))?;
    read_connect_ack(&mut stream, port)?;
    Ok(stream)
}

/// Read Firecracker's `OK <port>\n` ack **one byte at a time**: the guest agent sends its channel
/// handshake immediately after the connection is established, so a buffered read here would swallow
/// those bytes and desync the protocol.
fn read_connect_ack(stream: &mut UnixStream, port: u32) -> Result<(), VmmError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                // Firecracker closes the connection with no ack when nothing is listening on the
                // guest port — the common case until the agent is in the rootfs.
                return Err(VmmError::Vmm(format!(
                    "vsock CONNECT {port}: peer closed before ack (is the guest agent listening?)"
                )));
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > 64 {
                    return Err(VmmError::Vmm(format!(
                        "vsock CONNECT {port}: ack line too long"
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(VmmError::Timeout(format!(
                    "vsock CONNECT {port}: no ack before deadline"
                )))
            }
            Err(e) => return Err(VmmError::Vmm(format!("vsock CONNECT {port}: {e}"))),
        }
    }
    let ack = String::from_utf8_lossy(&line);
    if ack.starts_with("OK ") {
        Ok(())
    } else {
        Err(VmmError::Vmm(format!(
            "vsock CONNECT {port} refused: {ack:?} (is the guest agent listening?)"
        )))
    }
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

/// The captured serial console: a background thread appends the child's stdout into a shared
/// buffer that the boot loop scans for the userspace marker.
#[derive(Debug, Default)]
struct Console {
    buf: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl Console {
    /// Start draining `stdout` immediately (before `InstanceStart`): the OS pipe buffer is ~64 KiB
    /// and a chatty boot would deadlock the guest if we only read after starting it.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the OS refuses a new thread (`thread::spawn` would *panic* on that —
    /// EAGAIN is a real state under many-sandbox load, so it must stay a typed error).
    fn spawn(stdout: Option<ChildStdout>) -> Result<Self, VmmError> {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::default();
        let reader = match stdout {
            None => None,
            Some(mut out) => {
                let sink = Arc::clone(&buf);
                let handle = std::thread::Builder::new()
                    .name("agent-console".into())
                    .spawn(move || {
                        let mut chunk = [0u8; 4096];
                        loop {
                            match out.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if let Ok(mut g) = sink.lock() {
                                        append_capped(&mut g, &chunk[..n]);
                                    }
                                }
                            }
                        }
                    })
                    .map_err(|e| VmmError::Vmm(format!("spawn console reader: {e}")))?;
                Some(handle)
            }
        };
        Ok(Self { buf, reader })
    }

    /// Whether the console captured so far contains `marker`.
    fn contains(&self, marker: &str) -> bool {
        self.buf
            .lock()
            .map(|g| find(&g, marker.as_bytes()))
            .unwrap_or(false)
    }

    /// A UTF-8-lossy snapshot of the console captured so far.
    fn snapshot(&self) -> String {
        self.buf
            .lock()
            .map(|g| String::from_utf8_lossy(&g).into_owned())
            .unwrap_or_default()
    }

    /// Join the reader thread; it exits on its own once the child's stdout closes.
    fn join(&mut self) {
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// The last `n` non-empty lines of `text`, oldest first, joined with ` | ` — `None` if there are
/// none. Diagnostic tails for error enrichment.
fn last_lines(text: &str, n: usize) -> Option<String> {
    let tail: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .rev()
        .take(n)
        .collect();
    if tail.is_empty() {
        return None;
    }
    Some(tail.into_iter().rev().collect::<Vec<_>>().join(" | "))
}

/// Append a console chunk, dropping the oldest bytes once the buffer exceeds [`CONSOLE_CAP`].
fn append_capped(buf: &mut Vec<u8>, chunk: &[u8]) {
    buf.extend_from_slice(chunk);
    if buf.len() > CONSOLE_CAP {
        let excess = buf.len() - CONSOLE_CAP;
        buf.drain(..excess);
    }
}

/// Whether `haystack` contains the contiguous byte sequence `needle`.
fn find(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A path as `&str`, or a typed error — Firecracker's JSON API can't carry non-UTF-8 paths.
fn path_str(p: &Path) -> Result<&str, VmmError> {
    p.to_str()
        .ok_or_else(|| VmmError::Vmm(format!("path is not valid UTF-8: {}", p.display())))
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

/// Build a read-only ext4 from `src_dir` for the bulk-input block device (P3.4), populated
/// **rootless** via `mke2fs -d` (no loopback, no `sudo`). Sized from the tree's byte total with
/// slack and given enough inodes for its file count; the image lands in `workdir` (the per-VM
/// scratch dir) so teardown reclaims it. Returns the image path.
fn build_input_image(src_dir: &Path, workdir: &Path) -> Result<PathBuf, VmmError> {
    require_dir(src_dir, "input directory")?;
    let (bytes, files) = measure_tree(src_dir)?;
    // ext4 has a small floor and `mke2fs` needs metadata headroom; over-sizing only wastes scratch
    // (reclaimed on teardown) while under-sizing fails the build, so size up generously. `-N` gives
    // enough inodes that many tiny files exhaust bytes before inodes.
    let size_mib = (bytes / (1024 * 1024) * 3 / 2).max(8) + 8;
    let inodes = files + 256;

    let image = workdir.join("input.ext4");
    run_host_tool(
        "truncate",
        &[
            OsStr::new("-s"),
            OsStr::new(&format!("{size_mib}M")),
            image.as_os_str(),
        ],
    )?;
    run_host_tool(
        "mke2fs",
        &[
            OsStr::new("-F"),
            OsStr::new("-q"),
            OsStr::new("-t"),
            OsStr::new("ext4"),
            OsStr::new("-m"),
            OsStr::new("0"),
            OsStr::new("-N"),
            OsStr::new(&inodes.to_string()),
            // Label so the guest mounts by label, not `/dev/vdX` order (see `INPUT_LABEL`).
            OsStr::new("-L"),
            OsStr::new(INPUT_LABEL),
            OsStr::new("-d"),
            src_dir.as_os_str(),
            image.as_os_str(),
        ],
    )?;
    Ok(image)
}

/// Build a **blank, writable** ext4 for the bulk-output block device (P3.5), rootless via `mke2fs`.
/// No `-d` (nothing to seed) and `lazy_itable_init=0`/`lazy_journal_init=0` so the guest kernel never
/// lazily zeroes the inode table at runtime — that would balloon the sparse image toward its full
/// [`OUTPUT_IMAGE_MIB`] on the host regardless of how little the command writes. Labelled
/// [`OUTPUT_LABEL`] so the guest mounts it by label. The image lands in `workdir` (reclaimed on
/// teardown); [`RunningVm::collect_outputs`] reads it back after the VMM exits.
fn build_output_image(workdir: &Path) -> Result<PathBuf, VmmError> {
    let image = workdir.join("output.ext4");
    run_host_tool(
        "truncate",
        &[
            OsStr::new("-s"),
            OsStr::new(&format!("{OUTPUT_IMAGE_MIB}M")),
            image.as_os_str(),
        ],
    )?;
    run_host_tool(
        "mke2fs",
        &[
            OsStr::new("-F"),
            OsStr::new("-q"),
            OsStr::new("-t"),
            OsStr::new("ext4"),
            OsStr::new("-m"),
            OsStr::new("0"),
            OsStr::new("-L"),
            OsStr::new(OUTPUT_LABEL),
            OsStr::new("-E"),
            OsStr::new("lazy_itable_init=0,lazy_journal_init=0"),
            image.as_os_str(),
        ],
    )?;
    Ok(image)
}

/// One walk of `dir` for `(total_bytes, file_count)`, to size the input image. Bounded: an input
/// past a sane ceiling is a typed error, not a giant image. Symlinks are counted (each is an inode)
/// but not descended — `mke2fs -d` copies them verbatim, so a link resolves inside the *guest* fs,
/// never the host's, and there's no symlink-loop or host-escape via traversal.
fn measure_tree(dir: &Path) -> Result<(u64, u64), VmmError> {
    const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB bulk-input ceiling
    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| VmmError::Artifact(format!("read input dir {}: {e}", d.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| VmmError::Artifact(format!("read input entry: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| VmmError::Artifact(format!("stat input entry: {e}")))?;
            if ft.is_dir() {
                stack.push(entry.path());
            } else {
                files += 1;
                if let Ok(meta) = entry.metadata() {
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
        if bytes > MAX_INPUT_BYTES {
            return Err(VmmError::Artifact(format!(
                "input directory exceeds the {MAX_INPUT_BYTES}-byte bulk-input ceiling"
            )));
        }
    }
    Ok((bytes, files))
}

/// Like [`require_file`] but for a directory.
fn require_dir(path: &Path, what: &str) -> Result<(), VmmError> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(VmmError::Artifact(format!(
            "{what} not found or not a directory: {}",
            path.display()
        )))
    }
}

/// Run a host build tool (`truncate`/`mke2fs`) for a data block device. A missing tool is a typed
/// [`VmmError::Artifact`] — the driver's only other external process is `firecracker`, so these are
/// real new runtime dependencies, surfaced clearly rather than as a cryptic spawn failure.
fn run_host_tool(program: &str, args: &[&OsStr]) -> Result<(), VmmError> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| tool_spawn_error(program, e))?;
    if !status.success() {
        return Err(VmmError::Vmm(format!(
            "{program} failed building a block device image"
        )));
    }
    Ok(())
}

/// Map a failure to spawn one of the driver's host helpers (`mke2fs`/`truncate`/`e2fsck`/`debugfs`
/// for the block devices, `ip` for the tap) to a typed error: a missing binary is a clear
/// [`VmmError::Artifact`] (install hint), anything else a [`VmmError::Vmm`].
fn tool_spawn_error(program: &str, e: std::io::Error) -> VmmError {
    if e.kind() == std::io::ErrorKind::NotFound {
        VmmError::Artifact(format!(
            "{program} not found (a host tool the driver shells out to — install e2fsprogs/coreutils/iproute2)"
        ))
    } else {
        VmmError::Vmm(format!("run {program}: {e}"))
    }
}

/// Read the writable output image back into the host `dest` directory, rootless. Ordered so the tree
/// is consistent and safe before it's returned: recover the journal (`e2fsck`), extract under a
/// byte/time cap (`debugfs rdump`), drop `lost+found`, neutralise host-escaping symlinks, then list
/// what survived. Called only after the VMM has exited (see [`RunningVm::collect_outputs`]).
fn collect_output_image(image: &Path, dest: &Path) -> Result<Vec<String>, VmmError> {
    std::fs::create_dir_all(dest)
        .map_err(|e| VmmError::Vmm(format!("create output dir {}: {e}", dest.display())))?;
    fsck_output_image(image)?;
    rdump_capped(image, dest, OUTPUT_EXTRACT_CAP, OUTPUT_READBACK_TIMEOUT)?;
    // Guest-controlled tree: drop the ext4 housekeeping dir and any symlink that would redirect a
    // later host read onto the host filesystem, before the caller (or its tooling) touches the files.
    let _ = std::fs::remove_dir_all(dest.join("lost+found"));
    sanitize_symlinks(dest)?;
    collect_paths(dest)
}

/// `e2fsck -fy` the image: force a full check and auto-answer, recovering the journal and clearing the
/// "not cleanly unmounted" state a hard-killed guest leaves, so `debugfs` sees a consistent tree. The
/// exit status is a bitmask — 0 clean, 1 errors corrected, 2 corrected + reboot advised (moot for an
/// image file); `>= 4` means errors left uncorrected or an operational failure, which is a real error.
fn fsck_output_image(image: &Path) -> Result<(), VmmError> {
    let status = Command::new("e2fsck")
        .arg("-fy")
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| tool_spawn_error("e2fsck", e))?;
    match status.code() {
        Some(0) => Ok(()),
        // Errors were found and corrected (1) or corrected + reboot-advised (2): the tree is now
        // consistent, but a hard-killed guest's in-flight writes may have been rolled back with the
        // journal. Record it so a recovered output shows up in the flight recorder, not as pristine.
        Some(code) if code < 4 => {
            tracing::warn!(
                exit = code,
                "e2fsck corrected the output image before readback; captured artifacts may be missing the guest's last writes"
            );
            Ok(())
        }
        Some(code) => Err(VmmError::Vmm(format!(
            "e2fsck could not repair the output image (exit {code})"
        ))),
        None => Err(VmmError::Vmm("e2fsck terminated by a signal".into())),
    }
}

/// Extract the image tree into `dest` with `debugfs rdump`, bounded so a hostile guest can't blow up
/// the host. `debugfs` materialises filesystem holes as real zeros, so a sparse file staged in the
/// capped image could still inflate the readback — a poll loop aborts the extraction once `dest`'s
/// **allocated** bytes pass `byte_cap`, or once it outruns `timeout`. rdump prints benign
/// "changing ownership" warnings when run non-root (it can't chown to the guest's uids) and still
/// exits 0; those are ignored — only a non-zero exit or a tripped bound is an error.
fn rdump_capped(
    image: &Path,
    dest: &Path,
    byte_cap: u64,
    timeout: Duration,
) -> Result<(), VmmError> {
    // debugfs parses its `-R` request by whitespace, with no quoting — reject a whitespace dest
    // rather than silently truncate the path (the dest is operator-set, so this is a clear config
    // error, not a guest-reachable one).
    let dest_str = path_str(dest)?;
    if dest_str.chars().any(char::is_whitespace) {
        return Err(VmmError::Vmm(format!(
            "output dir path must not contain whitespace (debugfs -R limitation): {dest_str}"
        )));
    }
    let mut child = Command::new("debugfs")
        .arg("-R")
        .arg(format!("rdump / {dest_str}"))
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| tool_spawn_error("debugfs", e))?;

    let deadline = Instant::now() + timeout;
    loop {
        match child
            .try_wait()
            .map_err(|e| VmmError::Vmm(format!("wait on debugfs: {e}")))?
        {
            Some(status) => {
                return match status.code() {
                    Some(0) => Ok(()),
                    Some(code) => Err(VmmError::Vmm(format!("debugfs rdump failed (exit {code})"))),
                    None => Err(VmmError::Vmm("debugfs rdump terminated by a signal".into())),
                };
            }
            None => {
                if dir_alloc_bytes(dest) > byte_cap {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VmmError::OutputCap {
                        limit: byte_cap.min(usize::MAX as u64) as usize,
                    });
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VmmError::Timeout(
                        "output readback exceeded its deadline".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Sum of **allocated** bytes (`blocks * 512`, real host disk, not logical size) under `dir`. Walks
/// with `file_type`/`DirEntry::metadata` (both `lstat`-like), so a guest symlink is counted as the
/// link itself and never followed — the walk can't be lured onto the host filesystem while sizing.
fn dir_alloc_bytes(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(entry.path()),
                Ok(_) => {
                    if let Ok(meta) = entry.metadata() {
                        total = total.saturating_add(meta.blocks().saturating_mul(512));
                    }
                }
                Err(_) => {}
            }
        }
    }
    total
}

/// Remove every symlink under `dest` whose target escapes `dest`. `debugfs rdump` recreates a guest
/// symlink verbatim as a **host** symlink, so an un-sanitised `link -> /etc/shadow` (or one that
/// climbs out with `..`) would make a later host read of the results read host files — the inverse of
/// the input side, where `mke2fs -d` resolves links inside the guest image. In-tree links (e.g.
/// `a -> sub/b`) are kept.
///
/// Containment is checked by **canonical resolution**, not lexically: a lexical `..`-depth count is
/// unsound because a kept in-tree symlink makes a `Normal` path component *not* descend a real level
/// — a guest can chain `d -> .` with `evil -> d/../../etc/shadow` to pass a lexical check while
/// resolving above `dest`. `Path::canonicalize` follows every intermediate link to the real target,
/// which we require to sit under the canonical `dest`; a target that doesn't resolve (dangling, or
/// pointing outside to a nonexistent path) can't be proven in-tree, so it's dropped. Safe from
/// TOCTOU: the VMM is already reaped and `dest` is host-private, so nothing mutates the tree
/// concurrently. The walk itself never traverses a symlink (`lstat`-like `file_type`), so it can't be
/// redirected onto the host mid-scan.
fn sanitize_symlinks(dest: &Path) -> Result<(), VmmError> {
    let root = dest
        .canonicalize()
        .map_err(|e| VmmError::Vmm(format!("canonicalize output dir {}: {e}", dest.display())))?;
    let mut stack = vec![dest.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| VmmError::Vmm(format!("scan output dir {}: {e}", d.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| VmmError::Vmm(format!("read output entry: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| VmmError::Vmm(format!("stat output entry: {e}")))?;
            let path = entry.path();
            if ft.is_symlink() {
                // Follow the link (and any intermediate links) to a real path; keep only if it
                // stays within the canonical destination.
                let contained = path
                    .canonicalize()
                    .map(|real| real.starts_with(&root))
                    .unwrap_or(false);
                if !contained {
                    let target = std::fs::read_link(&path).unwrap_or_default();
                    std::fs::remove_file(&path).map_err(|e| {
                        VmmError::Vmm(format!("drop escaping symlink {}: {e}", path.display()))
                    })?;
                    tracing::warn!(
                        link = %path.display(),
                        target = %target.display(),
                        "dropped output symlink escaping the destination"
                    );
                }
            } else if ft.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// The captured tree as relative-path strings (files and surviving symlinks, directories descended),
/// sorted for a deterministic result. Purely a manifest of what `collect_outputs` produced.
fn collect_paths(dest: &Path) -> Result<Vec<String>, VmmError> {
    let mut out = Vec::new();
    let mut stack = vec![dest.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| VmmError::Vmm(format!("list output dir {}: {e}", d.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| VmmError::Vmm(format!("read output entry: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| VmmError::Vmm(format!("stat output entry: {e}")))?;
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
            } else if let Ok(rel) = path.strip_prefix(dest) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test scratch dir that is removed even when an assertion fails first.
    struct TestDir(PathBuf);
    impl TestDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("test scratch dir");
            Self(dir)
        }
        /// Own an existing dir (e.g. one `create_workdir` made) so it's reclaimed on drop.
        fn adopt(dir: PathBuf) -> Self {
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn find_locates_substring() {
        assert!(find(b"ubuntu-fc-uvm login: root", b"login:"));
        assert!(!find(b"Reached target Login Prompts", b"login:"));
        assert!(find(b"anything", b""));
        assert!(!find(b"hi", b"longer-than-haystack"));
    }

    #[test]
    fn sanitize_symlinks_drops_escapes_including_chained_intermediate_links() {
        use std::os::unix::fs::symlink;
        let dir = TestDir::new("agent-sanitize");
        let dest = dir.path();

        // A real file + a legitimate in-tree symlink to it: must survive.
        std::fs::write(dest.join("real.txt"), b"hi").expect("write real file");
        symlink("real.txt", dest.join("good")).expect("in-tree link");

        // A direct absolute escape (`link -> /etc/passwd`): must be dropped.
        symlink("/etc/passwd", dest.join("abs")).expect("absolute link");

        // The chained bypass that defeats a *lexical* check: `d -> .` makes `d` a `Normal` component
        // that doesn't descend a real level, so `evil -> d/../../…/etc/passwd` climbs above `dest` on
        // disk while a lexical `..`-depth count never goes negative. Must be dropped.
        symlink(".", dest.join("d")).expect("self link");
        symlink("d/../../../../../../etc/passwd", dest.join("evil")).expect("chained link");

        sanitize_symlinks(dest).expect("sanitize");

        assert!(dest.join("real.txt").exists(), "real file untouched");
        assert!(
            dest.join("good").symlink_metadata().is_ok(),
            "in-tree symlink should be kept"
        );
        assert!(
            dest.join("abs").symlink_metadata().is_err(),
            "absolute escape must be dropped"
        );
        assert!(
            dest.join("evil").symlink_metadata().is_err(),
            "chained intermediate-symlink escape must be dropped"
        );
    }

    #[test]
    fn output_dir_with_whitespace_is_rejected_before_debugfs() {
        // A whitespace dest would be split by debugfs's `-R` parser; catch it as a typed error rather
        // than silently truncating the extraction path. (No debugfs is spawned — the guard fires first.)
        let err = rdump_capped(
            Path::new("/nonexistent/img.ext4"),
            Path::new("/tmp/has a space"),
            OUTPUT_EXTRACT_CAP,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(ref m) if m.contains("whitespace")),
            "got {err:?}"
        );
    }

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
    fn console_captures_and_scans() {
        // No stdout: the buffer stays empty but the API works.
        let console = Console::spawn(None).expect("no thread needed");
        assert!(!console.contains("login:"));
        assert_eq!(console.snapshot(), "");
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
    fn tap_name_fits_ifnamsiz_and_is_prefixed() {
        // The name must stay within IFNAMSIZ-1 (15 bytes) for any token, including the max, and be
        // distinct per token so the create-and-retry loop actually advances.
        for token in [0u64, 1, 42, 0xffff_ffff, u64::MAX] {
            let name = tap_name(token);
            assert!(name.starts_with("fc"), "{name}");
            assert!(name.len() <= 15, "{name} is {} bytes", name.len());
        }
        assert_ne!(tap_name(0), tap_name(1));
    }

    #[test]
    fn mac_for_is_locally_administered_unicast_and_unique() {
        let mac = mac_for(0x0102_0304);
        assert_eq!(mac, "02:00:01:02:03:04");
        // First octet 0x02: locally-administered bit (0x02) set, multicast bit (0x01) clear.
        assert_eq!(0x02 & 0x02, 0x02);
        assert_eq!(0x02 & 0x01, 0x00);
        assert_ne!(mac_for(0), mac_for(1), "distinct values → distinct MACs");
    }

    #[test]
    fn subnet_for_carves_a_point_to_point_30() {
        let (host, guest, prefix) = subnet_for(0);
        assert_eq!(prefix, 30);
        // Both ends live in 10.200.0.0/16, and the guest is the host's neighbour (host + 1).
        assert_eq!(host.octets()[0..2], [10, 200]);
        assert_eq!(guest.octets()[0..2], [10, 200]);
        assert_eq!(u32::from(guest), u32::from(host) + 1);
        // The block base is a multiple of 4, so host/guest are the .1/.2 of their /30 (never the
        // network .0 or broadcast .3) and the low octet can't overflow.
        assert_eq!(u32::from(host) % 4, 1);
        for token in [1u64, 42, 0xffff_ffff, u64::MAX] {
            let (_h, _g, p) = subnet_for(token);
            assert_eq!(p, 30);
        }
    }

    #[test]
    fn subnet_index_folds_pid_bits_so_processes_dont_collide_at_seq_zero() {
        // The real token is `(pid << 20) ^ seq`. Two processes both at seq 0 must land on different
        // /30s — a plain low-bit mask would collapse to `seq & mask` (identical). The fold mixes the
        // PID (bits ≥ 20) back into the 14-bit index.
        let token = |pid: u64, seq: u64| (pid << 20) ^ seq;
        assert_ne!(
            subnet_index(token(1234, 0)),
            subnet_index(token(5678, 0)),
            "distinct PIDs → distinct blocks at seq 0"
        );
        // Successive sequence numbers within one process also differ.
        assert_ne!(subnet_index(token(1234, 0)), subnet_index(token(1234, 1)));
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
    fn console_buffer_is_capped_keeping_the_tail() {
        let mut buf = vec![b'a'; CONSOLE_CAP];
        append_capped(&mut buf, b"login:");
        assert_eq!(buf.len(), CONSOLE_CAP, "buffer must not grow past the cap");
        assert!(
            find(&buf, b"login:"),
            "the newest bytes (where the marker lands) must be kept"
        );
        assert_eq!(&buf[..1], b"a", "only the oldest bytes are dropped");
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

    /// Stand up a fake Firecracker vsock socket: accept, answer the `CONNECT <port>` handshake, then
    /// hand the same stream to the *real* guest agent. Lets us exercise the entire host exec path
    /// (vsock connect + `CONNECT` ack + channel handshake + exec round trip) with no VM.
    fn fake_vsock_agent(tag: &str) -> (TestDir, PathBuf, std::thread::JoinHandle<()>) {
        use std::os::unix::net::UnixListener;
        let dir = TestDir::new(tag);
        let uds = dir.path().join("v.sock");
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Read `CONNECT <port>\n` one byte at a time — mustn't over-read the client handshake.
            let mut b = [0u8; 1];
            loop {
                stream.read_exact(&mut b).expect("read CONNECT");
                if b[0] == b'\n' {
                    break;
                }
            }
            stream.write_all(b"OK 10000\n").expect("write ack");
            let _ = agent_guest::serve(stream);
        });
        (dir, uds, handle)
    }

    #[test]
    fn exec_over_fake_vsock_runs_a_command() {
        // P2.8 happy path: `exec("echo hi")` → `hi`, exit 0 — through the *real* agent (only the
        // Firecracker vsock UDS is faked).
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-echo");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["echo".into(), "hi".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("exec");
        assert_eq!(result.stdout, b"hi\n");
        assert!(result.stderr.is_empty());
        assert_eq!(result.exit_code, 0);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_over_fake_vsock_feeds_stdin() {
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-stdin");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["cat".into()],
            b"from the host\n",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("exec");
        assert_eq!(result.stdout, b"from the host\n");
        assert_eq!(result.exit_code, 0);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_injects_files_and_returns_artifacts() {
        // Put a file in, run a command that reads it and writes an output file, pull the artifact
        // back. Exercises PutFile + working-dir cwd + artifact return end to end against the agent.
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-files");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &[
                "sh".into(),
                "-c".into(),
                "mkdir -p out && tr a-z A-Z < in.txt > out/up.txt".into(),
            ],
            b"",
            &[("in.txt".into(), b"hello\n".to_vec())],
            &["out/up.txt".into(), "missing.txt".into()],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("exec");
        assert_eq!(result.exit_code, 0);
        // The one artifact that exists comes back; the missing one is simply omitted.
        assert_eq!(
            result.files,
            vec![("out/up.txt".to_string(), b"HELLO\n".to_vec())]
        );
        server.join().expect("server thread");
    }

    #[test]
    fn exec_crashing_command_is_a_typed_error() {
        // P2.8: a command the guest can't run ("crashing" in the agent-fault sense) comes back as a
        // terminal `Error` frame → the typed `VmmError::GuestExec`, end to end through the real
        // agent (which reports the spawn failure), not via a hand-crafted `Error` response.
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-crash");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["definitely-not-a-real-binary-zzz".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::GuestExec(_)), "got {err:?}");
        server.join().expect("server thread");
    }

    #[test]
    fn exec_signal_death_is_a_faithful_result_not_an_error() {
        // The load-bearing taxonomy semantic: a command that *runs and crashes* (here SIGKILL via
        // `kill -9 $$`) is NOT a `VmmError` — the agent maps signal death to `128+sig` and the host
        // returns a faithful `RunResult{exit_code: 137}`. This pins the *host*-side mapping in
        // `run_exec`; the guest-agent-layer version lives in crates/guest-agent/tests/exec.rs.
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-signal");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["sh".into(), "-c".into(), "kill -9 $$".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("signal death is a result, not an error");
        assert_eq!(result.exit_code, 137, "128 + SIGKILL(9)");
        server.join().expect("server thread");
    }

    /// A fake vsock peer that answers `CONNECT`, does the channel handshake, then hands the
    /// [`ServerConnection`](agent_channel::ServerConnection) to `handler` — so a test can craft the
    /// exact response stream (unlike `fake_vsock_agent`, which runs the real agent).
    fn fake_vsock_server<F>(
        tag: &str,
        handler: F,
    ) -> (TestDir, PathBuf, std::thread::JoinHandle<()>)
    where
        F: FnOnce(agent_channel::ServerConnection<std::os::unix::net::UnixStream>) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let dir = TestDir::new(tag);
        let uds = dir.path().join("v.sock");
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut b = [0u8; 1];
            loop {
                stream.read_exact(&mut b).expect("read CONNECT");
                if b[0] == b'\n' {
                    break;
                }
            }
            stream.write_all(b"OK 10000\n").expect("write ack");
            let conn = agent_channel::ServerConnection::accept(stream).expect("server handshake");
            handler(conn);
        });
        (dir, uds, handle)
    }

    #[test]
    fn exec_surfaces_a_guest_error_as_typed_error() {
        // The agent reports a spawn failure with a terminal `Error` frame → `VmmError::GuestExec`,
        // distinct from a transport fault.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-err", |mut conn| {
            let _ = conn.recv_request();
            let _ = conn.send_response(&Response::Error("no such binary".into()));
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["nope".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::GuestExec(_)), "got {err:?}");
        server.join().expect("server thread");
    }

    #[test]
    fn exec_channel_drop_mid_exec_is_a_typed_channel_error() {
        // The channel/transport bucket end to end: a guest that accepts the request then drops the
        // connection makes `recv_response` hit EOF → `ChannelError::Io(UnexpectedEof)` →
        // `VmmError::Channel`. Every *other* channel-ish fault is at connect time (→ `Vmm`), so this
        // is the only test that exercises the steady-state `Channel` arm and the `From<ChannelError>`
        // conversion at the vmm layer.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-drop", |mut conn| {
            let _ = conn.recv_request();
            drop(conn); // no response frames — the host's next read sees a clean EOF
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["echo".into(), "hi".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::Channel(ref e) if e.is_disconnect()),
            "got {err:?}"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn exec_output_cap_is_enforced() {
        // A guest that floods stdout must trip the cap as a typed error, not grow host memory.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-flood", |mut conn| {
            let _ = conn.recv_request();
            // Keep sending until the host drops the connection (cap exceeded → our writes error).
            while conn
                .send_response(&Response::Stdout(vec![b'x'; 500]))
                .is_ok()
            {}
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["flood".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: 1000,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::OutputCap { limit: 1000 }),
            "got {err:?}"
        );
        // Close the connection so the flooding server's next write errors and its loop ends.
        drop(conn);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_maps_guest_timeout_to_typed_timeout() {
        // The agent's terminal `TimedOut` (command killed at its deadline) becomes the distinct
        // VmmError::ExecTimeout — not conflated with a channel/transport timeout.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-timeout", |mut conn| {
            let _ = conn.recv_request();
            let _ = conn.send_response(&Response::TimedOut { elapsed_ms: 1000 });
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["sleep".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(1),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::ExecTimeout { .. }), "got {err:?}");
        server.join().expect("server thread");
    }

    #[test]
    fn output_cap_counts_file_path_bytes_not_just_data() {
        // Regression: a guest flooding File frames whose budget is spent on `path` (empty `data`)
        // must still trip the cap — path bytes and a per-frame floor count toward it.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-pathflood", |mut conn| {
            let _ = conn.recv_request();
            let big_path = "p".repeat(4096);
            while conn
                .send_response(&Response::File {
                    path: big_path.clone(),
                    data: Vec::new(),
                })
                .is_ok()
            {}
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["flood".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: 10_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::OutputCap { .. }), "got {err:?}");
        drop(conn);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_dribbling_guest_trips_the_host_wall_deadline() {
        // A guest that keeps the per-read idle timer alive with tiny well-formed frames but never
        // sends its terminal Exit/TimedOut would, without a host wall deadline, park exec forever
        // under the output cap. The host's own `wall` must give up with `ExecUnresponsive`, fast.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-dribble", |mut conn| {
            let _ = conn.recv_request();
            // Dribble every 50 ms — well under the 200 ms idle timeout, so the idle timer never
            // fires; only the host's wall deadline can end this.
            while conn.send_response(&Response::Stdout(vec![b'x'; 8])).is_ok() {
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        // Idle (200 ms) > dribble interval (50 ms), so the socket idle timeout can't fire; wall
        // (150 ms) is the thing under test. All sub-second so the suite stays fast.
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_millis(200)).expect("connect");
        let started = std::time::Instant::now();
        let err = run_exec(
            &mut conn,
            &["dribble".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_millis(100), // guest budget (the fake server ignores it)
                wall: Duration::from_millis(150),    // host wall deadline — under test
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::ExecUnresponsive { .. }),
            "got {err:?}"
        );
        // Loose upper bound only (never a tight lower bound): it must fail fast, not hang the suite.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should fail fast, took {:?}",
            started.elapsed()
        );
        drop(conn);
        server.join().expect("server thread");
    }

    /// A fake `CONNECT` target: answer nothing but the ack `handler` chooses, so the connect-ack
    /// paths can be tested without the channel layer.
    fn fake_connect_target<F>(
        tag: &str,
        handler: F,
    ) -> (TestDir, PathBuf, std::thread::JoinHandle<()>)
    where
        F: FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let dir = TestDir::new(tag);
        let uds = dir.path().join("v.sock");
        let listener = UnixListener::bind(&uds).expect("bind");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut b = [0u8; 1];
            loop {
                if stream.read_exact(&mut b).is_err() || b[0] == b'\n' {
                    break;
                }
            }
            handler(stream);
        });
        (dir, uds, handle)
    }

    #[test]
    fn connect_ack_refused_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-refuse", |mut s| {
            let _ = s.write_all(b"NOPE\n");
        });
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(m) if m.contains("refused")),
            "wrong error"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_peer_close_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-close", drop);
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(m) if m.contains("closed")),
            "wrong error"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_too_long_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-long", |mut s| {
            let _ = s.write_all(&[b'x'; 100]); // 100 bytes, no newline
            std::thread::sleep(Duration::from_millis(200)); // keep the stream open past the read
        });
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(m) if m.contains("too long")),
            "wrong error"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_timeout_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-timeout", |s| {
            std::thread::sleep(Duration::from_millis(300)); // never send; outlive the client deadline
            drop(s);
        });
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, VmmError::Timeout(_)), "got {err:?}");
        server.join().expect("server");
    }
}
