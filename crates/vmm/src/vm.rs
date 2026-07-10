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

/// Everything needed to boot one microVM. `from_env` resolves each field from `AGENT_*` env then a
/// default; [`with_limits`](BootConfig::with_limits) folds a [`Limits`] budget on top.
#[derive(Debug, Clone)]
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
    /// Resolve from the environment: `AGENT_FIRECRACKER`, `AGENT_KERNEL`, `AGENT_ROOTFS`,
    /// `AGENT_MARKER`, else the pinned-artifact defaults under `artifacts/`.
    pub fn from_env() -> Self {
        let env_path = |key: &str, default: &str| {
            PathBuf::from(std::env::var_os(key).unwrap_or_else(|| default.into()))
        };
        Self {
            firecracker: env_path("AGENT_FIRECRACKER", "firecracker"),
            kernel: env_path("AGENT_KERNEL", "artifacts/vmlinux"),
            rootfs: env_path("AGENT_ROOTFS", "artifacts/rootfs.ext4"),
            vcpus: 1,
            mem_mib: 256,
            boot_args: DEFAULT_BOOT_ARGS.to_string(),
            userspace_marker: std::env::var("AGENT_MARKER")
                .unwrap_or_else(|_| DEFAULT_USERSPACE_MARKER.to_string()),
            boot_timeout: Duration::from_secs(30),
        }
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
    fn default() -> Self {
        Self::from_env()
    }
}

/// A booted-and-ready microVM: the `firecracker` child, its API socket, scratch dir, and the
/// captured console. Guaranteed teardown lives in `Drop`, so losing this value can't leak the VMM.
#[derive(Debug)]
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
        let mut spawned = Spawned::launch(&config)?;
        let boot_latency = match spawned.run_boot(&config) {
            Ok(latency) => latency,
            Err(e) => return Err(spawned.abort(e)),
        };
        Ok(spawned.into_running(boot_latency))
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
/// and clean up without ever constructing a half-booted `RunningVm`.
struct Spawned {
    child: Child,
    stderr: Option<std::process::ChildStderr>,
    console: Console,
    workdir: PathBuf,
    rootfs: PathBuf,
    api: ApiClient,
}

impl Spawned {
    /// Validate prerequisites, lay out the scratch dir, and spawn `firecracker --api-sock`.
    fn launch(config: &BootConfig) -> Result<Self, VmmError> {
        if !Path::new("/dev/kvm").exists() {
            return Err(VmmError::NoKvm);
        }
        require_file(&config.kernel, "kernel image")?;
        require_file(&config.rootfs, "rootfs image")?;

        let workdir = create_workdir()?;

        // Boot a *copy* rw, never the pinned base image — runs stay independent, base stays pinned.
        let rootfs = workdir.join("rootfs.ext4");
        std::fs::copy(&config.rootfs, &rootfs).map_err(|e| {
            let _ = std::fs::remove_dir_all(&workdir);
            VmmError::Vmm(format!("copy rootfs to {}: {e}", rootfs.display()))
        })?;

        let socket = workdir.join("fc.sock");
        let mut child = match Command::new(&config.firecracker)
            .arg("--api-sock")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped()) // guest serial console
            .stderr(Stdio::piped()) // Firecracker's own logs, kept off our stderr
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
        let stderr = child.stderr.take();
        let console = Console::spawn(stdout);
        Ok(Self {
            child,
            stderr,
            console,
            workdir,
            rootfs,
            api: ApiClient::new(socket),
        })
    }

    /// Drive the API through the boot sequence and wait for the userspace marker; returns the
    /// boot-to-userspace latency.
    fn run_boot(&mut self, config: &BootConfig) -> Result<Duration, VmmError> {
        // `Instant + Duration` panics on overflow, and `boot_timeout` is caller-set (a
        // `Duration::MAX` "no limit" must stay a *bounded* wait, not a panic) — clamp to a day.
        let now = Instant::now();
        let deadline = now
            .checked_add(config.boot_timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86_400));
        self.await_api_socket(deadline)?;

        let kernel = path_str(&config.kernel)?;
        let rootfs = path_str(&self.rootfs)?;
        self.api.put(
            "/boot-source",
            &BootSource {
                kernel_image_path: kernel,
                boot_args: &config.boot_args,
            },
        )?;
        self.api.put(
            "/drives/rootfs",
            &Drive {
                drive_id: "rootfs",
                path_on_host: rootfs,
                is_root_device: true,
                is_read_only: false,
            },
        )?;
        self.api.put(
            "/machine-config",
            &MachineConfig {
                vcpu_count: config.vcpus,
                mem_size_mib: config.mem_mib,
            },
        )?;

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
        self.child
            .try_wait()
            .map_err(|e| VmmError::Vmm(format!("wait on firecracker: {e}")))
    }

    /// Boot failed: tear the VMM down and enrich the cause with Firecracker's stderr tail.
    fn abort(mut self, cause: VmmError) -> VmmError {
        teardown(&mut self.child, &mut self.console, &self.workdir);
        let mut detail = String::new();
        if let Some(mut stderr) = self.stderr.take() {
            // The child is dead, so this reads to EOF and cannot block.
            let _ = stderr.read_to_string(&mut detail);
        }
        let tail = detail.lines().rev().take(3).collect::<Vec<_>>();
        if tail.is_empty() {
            return cause;
        }
        let tail = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
        match cause {
            VmmError::Vmm(m) => VmmError::Vmm(format!("{m} [firecracker: {tail}]")),
            VmmError::Timeout(m) => VmmError::Timeout(format!("{m} [firecracker: {tail}]")),
            other => other,
        }
    }

    /// Promote a successfully-booted VMM to a [`RunningVm`]. The stderr pipe is dropped: past boot
    /// it's noise, and leaving it unread could back-pressure a chatty VMM.
    fn into_running(mut self, boot_latency: Duration) -> RunningVm {
        RunningVm {
            child: self.child,
            workdir: std::mem::take(&mut self.workdir),
            console: std::mem::take(&mut self.console),
            api: self.api.clone(),
            boot_latency,
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
            Ok(()) => return Ok(workdir),
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
    if !workdir.as_os_str().is_empty() {
        let _ = std::fs::remove_dir_all(workdir);
    }
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
    fn spawn(stdout: Option<ChildStdout>) -> Self {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::default();
        let reader = stdout.map(|mut out| {
            let sink = Arc::clone(&buf);
            std::thread::spawn(move || {
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
        });
        Self { buf, reader }
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
        let console = Console::spawn(None); // no stdout: buffer stays empty but the API works
        assert!(!console.contains("login:"));
        assert_eq!(console.snapshot(), "");
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
        use std::os::unix::fs::PermissionsExt;
        let a = create_workdir().expect("first workdir");
        let b = create_workdir().expect("second workdir");
        assert_ne!(a, b, "each VM gets its own scratch dir");
        let mode = std::fs::metadata(&a)
            .expect("stat workdir")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "scratch dir must be private to us");
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }
}
