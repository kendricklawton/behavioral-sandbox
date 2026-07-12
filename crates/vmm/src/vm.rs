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

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use agent_channel::{ClientConnection, Request, Response};

use crate::firecracker::{Action, ApiClient, BootSource, Drive, MachineConfig, Vsock};
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
/// guest clamps a host-sent budget to its own 1 h ceiling; when the budget becomes a policy knob,
/// [`EXEC_IO_TIMEOUT`] must be derived from the *requested* value, not this const.)
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// The exec connection's read/write timeout: **derived** to outlast [`DEFAULT_EXEC_TIMEOUT`] so a
/// legitimately long-but-quiet command isn't cut off by the transport before its own deadline, and
/// so the host outlasts the agent's kill and receives its `TimedOut` reply. Derived (not a second
/// magic number) so the two can't silently drift out of order.
const EXEC_IO_TIMEOUT: Duration = DEFAULT_EXEC_TIMEOUT.saturating_add(Duration::from_secs(5));

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
    /// The read-only base rootfs; each boot runs against a fresh copy (see [`Vm::boot`]).
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
}

/// Boot entry point — `Vm::boot(config) -> RunningVm`.
#[derive(Debug)]
pub struct Vm;

impl Vm {
    /// Boot a microVM under `config` and return once the guest reaches userspace.
    ///
    /// Copies the base rootfs into a fresh per-VM scratch dir and boots the copy read-write, so
    /// repeated runs stay independent and the pinned base image is never mutated.
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
        // Use the longer exec I/O timeout so a quiet-but-running command isn't cut off and the
        // agent's `TimedOut` (at DEFAULT_EXEC_TIMEOUT) reaches us first.
        let mut conn = connect_agent_at(uds, AGENT_VSOCK_PORT, EXEC_IO_TIMEOUT)?;
        run_exec(
            &mut conn,
            argv,
            stdin,
            files_in,
            artifacts,
            DEFAULT_EXEC_TIMEOUT,
            MAX_EXEC_OUTPUT,
        )
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
        teardown(&mut self.child, &mut self.console, &self.workdir);
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
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            teardown(&mut child, &mut self.console, &self.workdir);
        }
    }
}

impl Spawned {
    /// Validate the inputs, lay out the scratch dir, and spawn `firecracker --api-sock`.
    fn launch(config: &BootConfig) -> Result<Self, VmmError> {
        require_file(&config.kernel, "kernel image")?;
        require_file(&config.rootfs, "rootfs image")?;

        let workdir = create_workdir()?;

        // Boot a *copy* rw, never the pinned base image — runs stay independent, base stays pinned.
        let rootfs = workdir.join("rootfs.ext4");
        std::fs::copy(&config.rootfs, &rootfs).map_err(|e| {
            let _ = std::fs::remove_dir_all(&workdir);
            VmmError::Vmm(format!("copy rootfs to {}: {e}", rootfs.display()))
        })?;
        // `fs::copy` propagates the source's mode; a read-only pinned base (0444) would make the
        // read-write root drive unopenable. The copy is ours alone — force owner read-write.
        if let Err(e) = std::fs::set_permissions(&rootfs, std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_dir_all(&workdir);
            return Err(VmmError::Vmm(format!("chmod rootfs copy: {e}")));
        }

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
        // Firecracker creates the vsock socket here on `PUT /vsock`; the host dials it post-boot.
        let vsock_uds = config.guest_cid.map(|_| workdir.join(VSOCK_UDS));
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            rootfs,
            api: ApiClient::new(socket),
            vsock_uds,
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
        still_before(deadline, "PUT /boot-source")?;
        self.api.put(
            "/boot-source",
            &BootSource {
                kernel_image_path: kernel,
                boot_args: &config.boot_args,
            },
        )?;
        still_before(deadline, "PUT /drives/rootfs")?;
        self.api.put(
            "/drives/rootfs",
            &Drive {
                drive_id: "rootfs",
                path_on_host: rootfs,
                is_root_device: true,
                is_read_only: false,
            },
        )?;
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
/// response stream into a [`RunResult`]. Bounded by `max_output` so a flooding guest can't grow host
/// memory without limit. Factored out of [`RunningVm::exec`] so it can be tested without a VM.
fn run_exec<S: Read + Write>(
    conn: &mut ClientConnection<S>,
    argv: &[String],
    stdin: &[u8],
    files_in: &[(String, Vec<u8>)],
    artifacts: &[String],
    timeout: Duration,
    max_output: usize,
) -> Result<RunResult, VmmError> {
    // Host-side trace of the exec (the guest's own `exec` span goes to the serial console, not the
    // operator's stderr), keyed by argv so `agent run` failures are diagnosable host-side.
    let span = tracing::info_span!("exec", argv = ?argv);
    let _span = span.enter();
    let started = Instant::now();

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
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
    })?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    // Bound stdout + stderr + artifact *names and bytes* together. `FRAME_FLOOR` is charged per
    // frame so a flood of empty frames (or `File` frames whose budget is spent on `path`, not
    // `data`) can't spin the loop or grow `files` without advancing the cap.
    let mut captured = 0usize;
    loop {
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
                    limit_ms = timeout.as_millis() as u64,
                    elapsed_ms,
                    "guest command timed out"
                );
                return Err(VmmError::ExecTimeout { limit: timeout });
            }
            // A guest-side fault on a healthy channel — distinct from a transport failure.
            Response::Error(msg) => return Err(VmmError::GuestExec(msg)),
            _ => {
                return Err(VmmError::Vmm(
                    "unexpected response frame from guest agent".into(),
                ))
            }
        }
        if captured > max_output {
            return Err(VmmError::OutputCap { limit: max_output });
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

/// Guaranteed, best-effort teardown shared by `abort` and `Drop`: kill the VMM, join the console
/// reader (which ends once the killed child's stdout closes), and remove the scratch dir.
fn teardown(child: &mut Child, console: &mut Console, workdir: &Path) {
    let _ = child.kill();
    let _ = child.wait();
    console.join();
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
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            1000,
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
            Duration::from_secs(1),
            MAX_EXEC_OUTPUT,
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
            Duration::from_secs(5),
            10_000,
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::OutputCap { .. }), "got {err:?}");
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
