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

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::firecracker::{Action, ApiClient, BootSource, Drive, MachineConfig};
use crate::{Limits, VmmError};

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
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            rootfs,
            api: ApiClient::new(socket),
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
}
