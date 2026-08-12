//! Minting the per-VM scratch dir, and the two path constraints on it.
//!
//! The name is short because the jailer nests it **twice** inside the API socket path, which must
//! fit `sun_path`; the dir is created fail-if-exists at `0700` because the scratch base is
//! world-writable and the name is predictable. Both live here so the constraints sit together.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use crate::VmmError;
use crate::vm::VM_SEQ;

/// Linux caps `sockaddr_un.sun_path` at 108 bytes including the trailing NUL. Firecracker binds the
/// API and vsock sockets *inside* the scratch dir, so a long scratch base (a relocated
/// `BSX_SCRATCH_DIR`, or the jailer's deep chroot path) can overflow it, and the `bind()` then
/// fails deep inside Firecracker, surfacing to us as a cryptic "socket never appeared" boot timeout.
pub(crate) const SUN_PATH_MAX: usize = 108;

/// Fail fast with an actionable error if `socket` wouldn't fit in `sun_path` (see [`SUN_PATH_MAX`]),
/// instead of letting the bind fail obscurely mid-boot. Names the scratch-dir knob as the fix.
pub(crate) fn check_sun_path(socket: &Path) -> Result<(), VmmError> {
    let len = socket.as_os_str().len();
    if len + 1 > SUN_PATH_MAX {
        return Err(VmmError::Vmm(format!(
            "unix socket path {} is too long ({len} bytes; the kernel's limit is {}); \
             use a shorter scratch dir via BSX_SCRATCH_DIR",
            socket.display(),
            SUN_PATH_MAX - 1
        )));
    }
    Ok(())
}

/// The per-VM scratch/jail dir name prefix. Deliberately **short**, not the crate name: the jailer
/// embeds this dir name **twice** in the API socket path
/// (`<scratch>/<name>/firecracker/<name>/root/run/firecracker.socket`), which must fit `sun_path`
/// (~108 bytes, [`SUN_PATH_MAX`]); a long prefix plus a real scratch dir overflows it.
/// Single-sourced with the sweep's `owner_pid`,
/// which parses it back to find residue, so mint and match can't drift.
pub(crate) const VM_DIR_PREFIX: &str = "bsx";

/// Create the per-VM scratch dir. Two constraints shape it:
/// - **Short path** (`<scratch>/bsx-<pid>-<n>`, [`VM_DIR_PREFIX`]): the API socket lives here and
///   `sockaddr_un.sun_path` caps at ~108 bytes, so a deep or long-named path would make
///   Firecracker's `bind()` fail with EINVAL (`check_sun_path` refuses first, with the fix).
/// - **Fail-if-exists, mode `0700`**: `/tmp` is world-writable and PIDs recycle, so a
///   pre-existing path (squatted by another user, or stale from a killed run) must never be
///   silently adopted, the rootfs copy and socket go here. A collision just advances to the
///   next sequence number.
pub(crate) fn create_workdir(base: &Path) -> Result<PathBuf, VmmError> {
    for _ in 0..1024 {
        let workdir = base.join(format!(
            "{}-{}-{}",
            VM_DIR_PREFIX,
            std::process::id(),
            VM_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        match create_private_dir(&workdir) {
            Ok(()) => return Ok(workdir),
            Err(PrivateDirError::Chmod(e)) => {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(VmmError::Vmm(format!("chmod {}: {e}", workdir.display())));
            }
            Err(PrivateDirError::Create(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            // A missing/unwritable scratch base is the operator's to fix (e.g. `BSX_SCRATCH_DIR`
            // points nowhere): name it in the error rather than failing cryptically deep in boot.
            Err(PrivateDirError::Create(e)) => {
                return Err(VmmError::Vmm(format!(
                    "create scratch dir {} (is {} present and writable?): {e}",
                    workdir.display(),
                    base.display()
                )));
            }
        }
    }
    Err(VmmError::Vmm(format!(
        "no fresh scratch dir under {} after 1024 attempts (stale {}-* dirs?)",
        base.display(),
        VM_DIR_PREFIX
    )))
}

/// Which step of [`create_private_dir`] failed: the caller's branch points differ (an
/// `AlreadyExists` create is a retry or an ownership check; a chmod failure is a cleanup).
pub(crate) enum PrivateDirError {
    Create(std::io::Error),
    Chmod(std::io::Error),
}

/// Creates `dir` fail-if-exists and makes it `0700` unconditionally: mkdir's mode is masked by
/// the umask, so the explicit chmod after the create is what defeats it, race-free because the
/// dir is already exclusively ours.
pub(crate) fn create_private_dir(dir: &Path) -> Result<(), PrivateDirError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(PrivateDirError::Create)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(PrivateDirError::Chmod)
}

/// RAII guard for the boot's scratch dir during the pre-VMM staging window (rootfs copy, bulk-I/O
/// image builds): `Drop` removes the dir on every scope exit, an error return *or* an unwinding
/// panic, so a failed stage leaves no orphan. [`disarm`](Self::disarm) hands the path
/// back once a netns may exist, from where a plain removal could strand a dir-less netns and the
/// netns-gated `reclaim_scratch*` helpers own cleanup instead.
pub(crate) struct WorkdirGuard {
    path: PathBuf,
    armed: bool,
}

impl WorkdirGuard {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn disarm(mut self) -> PathBuf {
        self.armed = false;
        std::mem::take(&mut self.path)
    }
}

impl Drop for WorkdirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// The scratch dir's basename, the VM's process-unique identity, shared by its tracing span, its
/// jail id, and its lifetime cgroup, so one name finds all of a VM's residue.
pub(crate) fn workdir_name(workdir: &Path) -> String {
    workdir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}
