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
//! default; we never pass `--no-seccomp`). The **vsock exec channel** composes with the jail (its
//! unix socket is bound chroot-relative under the dropped uid, see [`JAILED_VSOCK_UDS`]), so a jailed
//! VM runs code, and the **read-only overlay** composes too (the shared base is bind-mounted into the
//! chroot, [`stage_ro_base_into_chroot`], so a jailed boot runs the density path, not a full rootfs
//! copy); a jailed boot that also wants a NIC or bulk I/O devices is still refused with a typed error
//! (staging those into the chroot, and a per-VM netns for concurrent networked clones, are later
//! steps). Leak-proof, cgroup-owned teardown lives
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

/// The chroot-relative path Firecracker binds the **vsock** exec-channel socket at, placed under
/// `/run` beside the API socket because the jailer makes that dir writable by the dropped uid (so the
/// unprivileged VMM can create the socket there). The host dials the same file at its absolute path
/// `<chroot_root>/run/v.sock`. Strictly shorter than [`JAILED_API_SOCKET`], so if that path cleared
/// `check_sun_path` in [`spawn_jailer`], this one does too.
pub(crate) const JAILED_VSOCK_UDS: &str = "/run/v.sock";

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
    /// The host path of the read-only base **bind mount** staged into the chroot for a
    /// `read_only_root` jailed boot (the density path, [`stage_ro_base_into_chroot`]). Must be
    /// unmounted before the scratch dir's `remove_dir_all`, or the mount point `EBUSY`s and leaks the
    /// chroot. `None` for a read-write boot (a plain copy) or the copy fallback on a non-shared scratch.
    pub(crate) base_mount: Option<PathBuf>,
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
    netns: Option<&Path>,
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
    // Networked boot (P7.0c): the jailer opens this netns handle and `setns`es into it (as root,
    // before dropping privileges) so the confined Firecracker runs in the VM's own network namespace,
    // where its tap lives. The tap was created owned by the jailed uid, so the unprivileged VMM can
    // attach it.
    if let Some(netns) = netns {
        cmd.arg("--netns").arg(netns);
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
/// The copy is the honest cost of the jail on a **read-write** boot: the kernel and rootfs live
/// outside the chroot, and hardlinking across the `/tmp` (tmpfs) boundary would `EXDEV`. A
/// `read_only_root` boot instead bind-mounts the shared base zero-copy ([`stage_ro_base_into_chroot`]).
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

/// Stage the **read-only shared base** into the chroot for a `read_only_root` jailed boot — the
/// density path, the jailed counterpart of the unjailed read-only boot that references one base in
/// place. Instead of a full per-VM copy ([`stage_into_chroot`]), **bind-mount** the one base file
/// into the chroot, so every jailed VM shares its inode (and page cache); the guest layers a per-run
/// tmpfs overlay over it (`overlay-init`), so `/` is writable but the base is never mutated.
///
/// The bind mount is made in the driver's (host) mount namespace, yet the jailer runs the VMM in an
/// `MS_SLAVE` mount namespace: a mount created under a **shared** host mount propagates *in*, so the
/// jailed Firecracker sees it. When the scratch base is **not** a shared mount (a hoster pointed
/// `scratch_dir` at a private mount, so the propagation can't reach the slave namespace), fall back
/// to a read-only **copy** — correct and still base-immutable, just not page-cache-deduped. Density is
/// a best-effort property; the isolation is not (decision 013/014), and the copy confines identically.
///
/// Returns the chroot-relative path to name in the API, and `Some(host_mount_path)` when a bind mount
/// was made — so teardown unmounts it before reclaiming the scratch dir (`None` for the copy fallback,
/// which needs no unmount). Base perms must let the dropped uid read it (the pinned base is `0644`); a
/// bind mount exposes the source's mode, so no chown is applied to a shared inode.
pub(crate) fn stage_ro_base_into_chroot(
    root: &Path,
    name: &str,
    src: &Path,
    scratch_dir: &Path,
    uid: u32,
    gid: u32,
) -> Result<(String, Option<PathBuf>), VmmError> {
    let rel = format!("/{name}");
    if !scratch_is_shared_mount(scratch_dir) {
        tracing::warn!(
            scratch = %scratch_dir.display(),
            "jailed read-only base: the scratch dir is not a shared mount, so a bind mount would not \
             reach the jailer's mount namespace; falling back to a per-VM read-only copy (correct, \
             but not page-cache-deduped). Put the scratch dir on a shared mount for the density path."
        );
        // Read-only copy fallback (0444, chowned so the dropped uid can open it).
        stage_into_chroot(root, name, src, uid, gid, 0o444)?;
        return Ok((rel, None));
    }
    let src = absolute(src)?;
    let dst = root.join(name);
    // The bind-mount target must exist; create an empty placeholder the mount then shadows.
    std::fs::File::create(&dst)
        .map_err(|e| VmmError::Vmm(format!("create bind target {}: {e}", dst.display())))?;
    bind_ro(&src, &dst)?;
    Ok((rel, Some(dst)))
}

/// Bind-mount `src` onto `dst` **read-only**. Two steps on purpose: a bind mount is read-write
/// regardless of a `-o ro` on the initial call, so a second `remount,ro,bind` is what actually drops
/// write access — the base then can't be mutated through the chroot even before Firecracker opens it
/// `O_RDONLY`. Shells out to `mount` (as the tap path shells out to `ip`), keeping the host path
/// `unsafe`-free. If the remount fails, the half-made bind mount is detached before returning, so a
/// failure never leaks a mount.
fn bind_ro(src: &Path, dst: &Path) -> Result<(), VmmError> {
    match Command::new("mount")
        .arg("--bind")
        .arg(src)
        .arg(dst)
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return Err(VmmError::Vmm(format!(
                "bind-mount {} -> {}: mount exited {s}",
                src.display(),
                dst.display()
            )))
        }
        Err(e) => return Err(VmmError::Vmm(format!("spawn `mount --bind`: {e}"))),
    }
    match Command::new("mount")
        .arg("-o")
        .arg("remount,ro,bind")
        .arg(dst)
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => {
            unmount_base(dst);
            Err(VmmError::Vmm(format!(
                "remount read-only {}: mount exited {s}",
                dst.display()
            )))
        }
        Err(e) => {
            unmount_base(dst);
            Err(VmmError::Vmm(format!(
                "spawn `mount -o remount,ro,bind`: {e}"
            )))
        }
    }
}

/// Detach a base bind mount (best-effort, **lazy**). `umount -l` never blocks on a busy mount: by
/// teardown the VMM is already reaped, but a lazy detach also means a mount left by a crashed-mid-boot
/// driver can always be cleared, so the scratch dir's `remove_dir_all` never `EBUSY`s. Failures are
/// ignored: a path that isn't a mount (the copy fallback, or one already gone) is a harmless no-op.
pub(crate) fn unmount_base(path: &Path) {
    let _ = Command::new("umount").arg("-l").arg(path).status();
}

/// Whether the filesystem mount backing `path` is a **shared** mount (carries a `shared:N` peer-group
/// tag in `/proc/self/mountinfo`). Only a mount made under a shared host mount propagates into the
/// jailer's `MS_SLAVE` namespace, so this gates the bind-mount density path against the copy fallback.
/// Resolves `path` to the longest mount point that is a path-prefix of it (the mount it lives on).
fn scratch_is_shared_mount(path: &Path) -> bool {
    let Ok(target) = absolute(path) else {
        return false;
    };
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mount_is_shared(&info, &target)
}

/// Whether the longest mount point that is a path-prefix of `target` carries a `shared:N` tag, given
/// the raw `/proc/self/mountinfo` text. Split from the I/O so the field-walk is unit-testable: a
/// mountinfo line is `id pid maj:min root MOUNTPOINT opts [optional tags...] - fstype src super`, and
/// the optional tags (where `shared:N` lives) run from field 6 up to a standalone `-`.
fn mount_is_shared(mountinfo: &str, target: &Path) -> bool {
    let mut best: Option<(usize, bool)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 7 {
            continue;
        }
        let mount_point = Path::new(fields[4]);
        if !target.starts_with(mount_point) {
            continue;
        }
        let shared = fields[6..]
            .iter()
            .take_while(|f| **f != "-")
            .any(|f| f.starts_with("shared:"));
        let depth = mount_point.components().count();
        if best.map(|(d, _)| depth > d).unwrap_or(true) {
            best = Some((depth, shared));
        }
    }
    best.map(|(_, shared)| shared).unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;

    // A slice of real `/proc/self/mountinfo`: `/` and `/tmp` are shared peers, `/mnt/private` is a
    // private mount (no `shared:` tag), and `/mnt/slave` receives from a master but is not itself
    // shared. Only a *shared* mount propagates a later bind mount into the jailer's slave namespace.
    const MOUNTINFO: &str = "\
21 1 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
30 21 0:24 / /tmp rw,nosuid,nodev shared:128 - tmpfs tmpfs rw
40 21 0:30 / /mnt/private rw,relatime - ext4 /dev/sdb rw
50 21 0:31 / /mnt/slave rw,relatime master:9 - ext4 /dev/sdc rw
";

    #[test]
    fn shared_mount_gates_the_density_path() {
        // A scratch dir on a shared mount (`/tmp`, or nested under it) takes the bind-mount density
        // path; the longest matching mount point wins, so a file under `/tmp` reads `/tmp`'s tag.
        assert!(mount_is_shared(MOUNTINFO, Path::new("/tmp")));
        assert!(mount_is_shared(
            MOUNTINFO,
            Path::new("/tmp/agent-42-0/firecracker")
        ));
        // The root is shared, so a path on no more-specific mount inherits its propagation.
        assert!(mount_is_shared(MOUNTINFO, Path::new("/var/lib/agent")));
    }

    #[test]
    fn private_or_slave_scratch_falls_back_to_copy() {
        // Neither a private mount nor a pure slave propagates a later bind mount into the jailer's
        // namespace, so both must read false (the copy fallback, not a broken density path).
        assert!(!mount_is_shared(
            MOUNTINFO,
            Path::new("/mnt/private/scratch")
        ));
        assert!(!mount_is_shared(MOUNTINFO, Path::new("/mnt/slave/scratch")));
    }

    #[test]
    fn unparseable_mountinfo_is_not_shared() {
        // A truncated or empty table can't prove a mount is shared, so default to the safe copy path.
        assert!(!mount_is_shared("", Path::new("/tmp")));
        assert!(!mount_is_shared(
            "garbage line with too few",
            Path::new("/tmp")
        ));
    }
}
