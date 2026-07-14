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
//! **Scope.** This confines a jailed **cold boot**: the chroot + uid/gid drop + the jailer's mount
//! namespace, cgroup **cpu/memory limits** derived from the guest's envelope (applied when the host
//! delegates the cgroup v2 controllers), and Firecracker's built-in **seccomp** filters (on by
//! default; we never pass `--no-seccomp`). A jailed boot that also wants vsock, a NIC, the overlay,
//! or bulk I/O devices is refused with a typed error (staging those into the chroot, and a per-VM
//! netns for concurrent networked clones, are later steps). Leak-proof, cgroup-owned teardown lives
//! in [`crate::lifetime`] (P6.7): the jailed VM's sentinel watches the jailer's cgroup at its
//! precomputed path, so host death can't leak a jailed VMM either.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::console::Console;
use crate::paths::absolute;
use crate::spawn::check_sun_path;
use crate::vm::FC_STDERR;
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

/// The cgroup v2 `cpu.max` accounting period, in microseconds (the kernel default). A cpu quota of
/// `n * CPU_PERIOD_US` per period means `n` cores' worth of CPU.
const CPU_PERIOD_US: u64 = 100_000;

/// Host-side memory headroom above the guest's RAM for the VMM's own footprint (heap, page tables,
/// slack), in MiB. The guest RAM is the hard floor a full-guest workload needs; the rootfs page cache
/// above it is reclaimable, so `mem_mib + this` caps the VMM without OOM-killing a legitimate boot.
/// Measured: a 256 MiB guest booting to userspace peaks ~82 MiB, far under `mem_mib + overhead`.
const MEMORY_OVERHEAD_MIB: u32 = 128;

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
    cgroup_args: &[String],
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
    // The jailer's chroot nests the socket deep under the scratch dir, so this is the path most
    // likely to overflow `sun_path` — fail clearly now, not as a cryptic bind failure mid-boot.
    check_sun_path(&socket)?;

    let fc_stderr = std::fs::File::create(workdir.join(FC_STDERR))
        .map_err(|e| VmmError::Vmm(format!("create firecracker stderr log: {e}")))?;
    let mut cmd = Command::new(&jail.jailer);
    cmd.arg("--id")
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
        // hierarchy. The jailer always creates the microVM's cgroup (teardown removes it).
        .arg("--cgroup-version")
        .arg("2");
    // CPU/memory limits (P6.2): the jailer writes each `<file>=<value>` into that cgroup. Empty when
    // the host doesn't delegate the cgroup v2 controllers (see `cgroup_limit_args`), so a jailed boot
    // still runs there, just without limits.
    for arg in cgroup_args {
        cmd.arg("--cgroup").arg(arg);
    }
    // Everything after `--` is Firecracker's. No `--daemonize` (keep its stdout so the guest serial
    // console still reaches the host) and no `--no-seccomp` (P6.3): Firecracker installs its built-in
    // per-thread seccomp filters by default, and we deliberately never disable them.
    cmd.arg("--")
        .arg("--api-sock")
        .arg(JAILED_API_SOCKET)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(fc_stderr));
    let mut child = cmd.spawn().map_err(|e| {
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

/// The cgroup dir the jailer will create for a VM, computed **before** the jailer is spawned:
/// `--cgroup-version 2` with no `--parent-cgroup` places the VMM at
/// `<cgroup root>/<exec-file name>/<id>` (the jailer requires the exec-file name to contain
/// "firecracker", so the component is stable). Precomputing it lets the lifetime sentinel (P6.7)
/// watch the cgroup from the moment the jailer is spawned instead of after boot; `run_boot` still
/// learns the *actual* dir from `/proc` and warns if they ever disagree.
pub(crate) fn jailer_cgroup_dir(firecracker: &Path, id: &str) -> Option<PathBuf> {
    let exec = resolve_exec(firecracker).ok()?;
    let name = exec.file_name()?.to_owned();
    Some(Path::new("/sys/fs/cgroup").join(name).join(id))
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

/// The `--cgroup <file>=<value>` limits (P6.2) that cap the jailed VMM at the guest's own resource
/// envelope: `cpu.max` bounds total CPU to `vcpus` cores, and `memory.max` to the guest's RAM plus a
/// fixed host-side overhead. Returns empty when the host can't apply them (see
/// [`cgroup_limits_available`]), so the caller passes no `--cgroup` and the jailed boot still runs.
pub(crate) fn cgroup_limit_args(vcpus: u32, mem_mib: u32) -> Vec<String> {
    if !cgroup_limits_available() {
        tracing::warn!(
            "cgroup v2 cpu/memory controllers are not delegated to the cgroup root; the jailed \
             microVM runs without CPU/memory limits (a systemd host delegates them by default)"
        );
        return Vec::new();
    }
    let quota = u64::from(vcpus) * CPU_PERIOD_US;
    let memory_max = (u64::from(mem_mib) + u64::from(MEMORY_OVERHEAD_MIB)) * 1024 * 1024;
    vec![
        format!("memory.max={memory_max}"),
        format!("cpu.max={quota} {CPU_PERIOD_US}"),
    ]
}

/// Whether the jailer can set cgroup limits here: the cgroup v2 `cpu` and `memory` controllers must be
/// enabled in the root's `subtree_control` (a systemd host does this out of the box). The jailer sets
/// limits by enabling controllers down from the root, which only works when they're already delegated
/// there and the root has no internal processes; if they aren't, passing `--cgroup` would make the
/// jailer fail, so we detect and skip. A bare container (controllers not delegated) reads false.
fn cgroup_limits_available() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .map(|s| {
            let toks: Vec<&str> = s.split_whitespace().collect();
            toks.contains(&"cpu") && toks.contains(&"memory")
        })
        .unwrap_or(false)
}
