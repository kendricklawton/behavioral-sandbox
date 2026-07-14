//! Run Firecracker under its **jailer** (P6.1): the other half of the isolation story. Hardware
//! isolation (KVM) contains the *guest*; the jailer contains the *VMM process* on the host, so a
//! Firecracker bug or a hostile guest that breaks out into the VMM still lands in a chroot, under a
//! dropped uid/gid, in the jailer's mount namespace, reaching almost nothing.
//!
//! The jailer is a separate Firecracker binary that, given `--exec-file firecracker --id <id>
//! --uid/--gid --chroot-base-dir <base>`, builds a chroot at `<base>/firecracker/<id>/root/`, mknods
//! the device nodes the VMM needs (`/dev/kvm`, `/dev/net/tun`), places the process in a cgroup,
//! `chroot`s in, drops privileges, and `exec`s Firecracker with its API socket at the
//! chroot-relative `/run/firecracker.socket`. Every resource the VMM opens (kernel, rootfs) must
//! therefore live **inside** the chroot and be named by its chroot-relative path in the API.
//!
//! **What this costs, and why the layout is what it is.** The chroot base is the VM's own scratch
//! dir under `/tmp`, so teardown's `remove_dir_all` reclaims the whole jail; the cgroup the jailer
//! creates lives outside it and is removed explicitly (like the tap). We don't `--daemonize`, so
//! Firecracker keeps our piped stdout and the serial console still reaches [`crate::console`]. We
//! don't mknod anything ourselves (the jailer does, which is why it needs real root — mknod of a
//! device node is `EPERM` in a non-initial user namespace even with `CAP_MKNOD`).
//!
//! **Scope (P6.1).** This lands the jailed **cold boot** only. A jailed boot that also wants vsock,
//! a NIC, the overlay, or bulk I/O devices is refused with a typed error (staging those into the
//! chroot, and a per-VM netns for concurrent networked clones, are later Phase-6 steps). cgroup
//! *limits* are P6.2; leak-proof, cgroup-owned teardown is P6.7.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::console::Console;
use crate::vm::{absolute, FC_STDERR};
use crate::VmmError;

/// The default unprivileged uid/gid the jailer drops Firecracker to. Deliberately high and unlikely
/// to collide with a real account; the resources the VMM touches live in a chroot we chown to this
/// id, so it need not exist in `/etc/passwd`. A hoster embedding the engine should override
/// [`Jail::uid`]/[`Jail::gid`] to a dedicated service account.
pub const DEFAULT_JAIL_UID: u32 = 10_000;
/// See [`DEFAULT_JAIL_UID`].
pub const DEFAULT_JAIL_GID: u32 = 10_000;

/// The chroot-relative path Firecracker binds its API socket at (its cwd is the chroot root). The
/// host reaches the same socket at `<chroot_root>/run/firecracker.socket`.
const JAILED_API_SOCKET: &str = "/run/firecracker.socket";

/// Confine the VMM under Firecracker's jailer. Opt-in via [`crate::BootConfig::jail`]; `None` (the
/// default) boots Firecracker directly, as every phase before this one did.
///
/// `#[non_exhaustive]`: construct via [`Jail::new`] / [`Jail::default`] and set fields, so later
/// Phase-6 knobs (a netns, cgroup limits, seccomp level) can be added without breaking callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Jail {
    /// The `jailer` binary (a bare name resolved via `PATH`, or an absolute path). Ships alongside
    /// `firecracker`.
    pub jailer: PathBuf,
    /// The uid the jailer switches to after building the chroot.
    pub uid: u32,
    /// The gid the jailer switches to after building the chroot.
    pub gid: u32,
}

impl Jail {
    /// A jail with the pinned defaults ([`DEFAULT_JAIL_UID`]/[`DEFAULT_JAIL_GID`], `jailer` on
    /// `PATH`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Jail {
    fn default() -> Self {
        Self {
            jailer: PathBuf::from("jailer"),
            uid: DEFAULT_JAIL_UID,
            gid: DEFAULT_JAIL_GID,
        }
    }
}

/// The live jail backing a running VMM: where its chroot root is (files are staged in, and the whole
/// tree is reclaimed with the scratch dir), the id it dropped to (to chown staged resources), and the
/// cgroup the jailer created (removed on teardown, since it lives outside the scratch dir).
#[derive(Debug)]
pub(crate) struct Chroot {
    /// The chroot `root/` dir on the host (`<base>/firecracker/<id>/root`). Firecracker's cwd; a
    /// chroot-relative `/x` names `<root>/x`.
    pub(crate) root: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The cgroup dir the jailer created for this VMM (`/sys/fs/cgroup/<...>`), learned from
    /// `/proc/<pid>/cgroup` once the VMM is up. Removed (best-effort) on teardown; `None` until read.
    pub(crate) cgroup_dir: Option<PathBuf>,
}

/// Spawn the **jailer**, which builds the chroot and `exec`s Firecracker inside it. Returns the child
/// (whose pid is Firecracker's, since the jailer `exec`s rather than forks), its console, the host
/// path of the API socket, and the chroot root (where resources are staged before boot).
///
/// The jailer's own stderr and Firecracker's share `<workdir>/fc.stderr` (so `abort` can surface a
/// jail-setup failure like a failed mknod); Firecracker's stdout stays piped for the serial console.
/// On a spawn failure nothing is left running; the caller owns `workdir` cleanup.
pub(crate) fn spawn_jailer(
    jail: &Jail,
    firecracker: &Path,
    workdir: &Path,
    id: &str,
) -> Result<(Child, Console, PathBuf, PathBuf), VmmError> {
    // `--exec-file` must be an absolute path to a real binary: the jailer copies it into the chroot,
    // and derives the chroot subdir from its file name (so `.../firecracker/<id>/root`).
    let exec = resolve_exec(firecracker)?;
    let exec_name = exec.file_name().ok_or_else(|| {
        VmmError::Vmm(format!(
            "firecracker path has no file name: {}",
            exec.display()
        ))
    })?;
    let chroot_root = workdir.join(exec_name).join(id).join("root");
    // Firecracker binds `/run/firecracker.socket` relative to its cwd (the chroot root), so on the
    // host the socket is `<chroot_root>/run/firecracker.socket`.
    let socket = chroot_root.join("run/firecracker.socket");

    let fc_stderr = std::fs::File::create(workdir.join(FC_STDERR))
        .map_err(|e| VmmError::Vmm(format!("create firecracker stderr log: {e}")))?;
    let mut child = Command::new(&jail.jailer)
        .arg("--id")
        .arg(id)
        .arg("--exec-file")
        .arg(&exec)
        .arg("--uid")
        .arg(jail.uid.to_string())
        .arg("--gid")
        .arg(jail.gid.to_string())
        .arg("--chroot-base-dir")
        .arg(workdir)
        // This host is cgroup v2 only; the jailer defaults to v1 and would fail to find the
        // hierarchy. We set no cgroup *values* here — resource limits are P6.2 — but the jailer
        // always creates the microVM's cgroup, which teardown removes.
        .arg("--cgroup-version")
        .arg("2")
        // Everything after `--` is Firecracker's. No `--daemonize`: we keep its stdout so the guest
        // serial console still reaches the host.
        .arg("--")
        .arg("--api-sock")
        .arg(JAILED_API_SOCKET)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(fc_stderr))
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VmmError::Artifact(format!("jailer not found: {}", jail.jailer.display()))
            } else {
                VmmError::Vmm(format!("spawn jailer: {e}"))
            }
        })?;
    let stdout = child.stdout.take();
    match Console::spawn(stdout) {
        Ok(console) => Ok((child, console, socket, chroot_root)),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}

/// Copy `src` into the chroot as `<root>/<name>`, give it `mode`, and chown it to the jailed uid/gid
/// so the dropped-privilege Firecracker can open it. Returns the **chroot-relative** path (`/<name>`)
/// to name it by in the API. Called once the chroot exists (after the VMM's API socket is up), so it
/// never races the jailer's chroot construction.
///
/// The copy is the honest cost of the jail on this path: the kernel and rootfs live outside the
/// chroot, and hardlinking across the `/tmp` (tmpfs) boundary would `EXDEV`. Zero-copy staging (a
/// shared read-only base bind-mounted in) rides with the overlay under the jailer, a later step.
pub(crate) fn stage_into_chroot(
    root: &Path,
    name: &str,
    src: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<String, VmmError> {
    use std::os::unix::fs::PermissionsExt;

    let dst = root.join(name);
    std::fs::copy(src, &dst)
        .map_err(|e| VmmError::Vmm(format!("stage {} into jail: {e}", src.display())))?;
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(mode))
        .map_err(|e| VmmError::Vmm(format!("chmod staged {}: {e}", dst.display())))?;
    // `std::os::unix::fs::chown` is a safe wrapper (no `unsafe` on the host path). Firecracker runs
    // as `uid:gid` after the drop, so a root-owned resource would be unreadable to it.
    std::os::unix::fs::chown(&dst, Some(uid), Some(gid)).map_err(|e| {
        VmmError::Vmm(format!(
            "chown staged {} to {uid}:{gid}: {e}",
            dst.display()
        ))
    })?;
    Ok(format!("/{name}"))
}

/// Resolve `firecracker` to an absolute path for `--exec-file`: an absolute path as-is, a path with a
/// directory component against the driver's cwd, and a bare name via `PATH` (mirroring how spawning
/// it directly would resolve it).
fn resolve_exec(firecracker: &Path) -> Result<PathBuf, VmmError> {
    if firecracker.is_absolute() {
        return Ok(firecracker.to_path_buf());
    }
    if firecracker.components().count() > 1 {
        return absolute(firecracker);
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join(firecracker);
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    Err(VmmError::Artifact(format!(
        "firecracker not found in PATH: {}",
        firecracker.display()
    )))
}

/// The cgroup dir the jailer placed `pid` in, read from `/proc/<pid>/cgroup` (version-independent, so
/// no assumption about the jailer's parent-cgroup layout). Unified cgroup v2 shows one `0::<path>`
/// line; the dir is `/sys/fs/cgroup<path>`. `None` for the root cgroup or an unreadable/empty entry.
pub(crate) fn read_cgroup_dir(pid: u32) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    if rel.is_empty() || rel == "/" {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Remove the jailer's cgroup for a torn-down VMM (best-effort). The VMM must already be reaped, so
/// its cgroup is empty and `rmdir`-able; `remove_dir` only removes an empty dir, so this never
/// disturbs a sibling VM sharing the parent. Tries the leaf then its parent (the shared
/// `.../firecracker` dir), the latter succeeding only once the last VM under it is gone.
pub(crate) fn remove_cgroup(dir: &Path) {
    let _ = std::fs::remove_dir(dir);
    if let Some(parent) = dir.parent() {
        // Guard against walking up to the cgroup mount root; only reap the jailer's own subtree.
        if parent != Path::new("/sys/fs/cgroup") {
            let _ = std::fs::remove_dir(parent);
        }
    }
}
