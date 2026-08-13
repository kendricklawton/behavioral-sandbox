//! Restoring a snapshot into a VMM: the jailed and unjailed constructors, the API restore
//! sequence, and the out-of-workdir disk staging it needs (with the guard that unstages on unwind).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::fcversion::{clock_realtime_arg, warn_on_unpinned_firecracker};
use super::workdir::{create_workdir, workdir_name};
use super::{Spawned, still_before};
use crate::VmmError;
use crate::firecracker::{
    ApiClient, MemBackend, MemBackendType, SnapshotLoad, snapshot_api_timeout,
};
use crate::jail::{
    Chroot, Jail, cgroup_limit_args, give_to_jail, restore_mem_mib, stage_into_chroot,
    stage_ro_base_into_chroot,
};
use crate::paths::path_str;
use crate::vm::{BootConfig, Snapshot, VSOCK_UDS};

impl Spawned {
    /// Spawn a bare `firecracker` for a snapshot restore: a fresh scratch dir + process + console,
    /// with **no** boot-time device configuration, since the guest's devices are recreated from the
    /// snapshot on `PUT /snapshot/load`. Reuses the same `Spawned` guard, so a failed restore tears
    /// the VMM down through the same paths as a failed boot.
    pub(crate) fn launch_for_restore(
        config: &BootConfig,
        snapshot: &Snapshot,
    ) -> Result<Self, VmmError> {
        warn_on_unpinned_firecracker(&config.firecracker);
        if let Some(jail) = config.jail.as_ref() {
            return Self::launch_jailed_for_restore(config, snapshot, jail);
        }
        let workdir = create_workdir(&config.scratch_dir)?;
        // A networked snapshot baked in its tap's `host_dev_name`, so restore must present a tap
        // with that name (`net.rs` records why a fresh netns beats renaming through the pin's
        // `network_overrides`). `spawn_unjailed`'s fixed-name tap in a **fresh per-VM netns**
        // satisfies it, and the clone's baked-in address/MAC/routes are correct in its own netns.
        let s = Self::spawn_unjailed(config, workdir, snapshot.tap_name.is_some())?;
        // The snapshot's vsock socket path was baked in relative, so Firecracker re-binds it in
        // *this* restore's cwd (its scratch dir) and concurrent clones don't collide. Computed
        // before `workdir` is moved into the struct.
        let vsock_uds = snapshot.has_vsock.then(|| s.workdir.join(VSOCK_UDS));
        Ok(Self {
            child: Some(s.child),
            console: s.console,
            workdir: s.workdir,
            // A placeholder, not a device this scratch dir owns: the restored VM's live disk is an
            // anonymous inode (a private copy is staged at load then unlinked, a shared base is
            // referenced in place), and re-snapshotting is refused.
            rootfs: snapshot.root_drive.clone(),
            restored: true,
            api: ApiClient::new(s.socket),
            vsock_uds,
            input_image: None,
            output: None,
            tap: s.tap,
            chroot: None,
            lifetime: s.lifetime,
        })
    }

    /// The jailed counterpart of [`launch_for_restore`](Self::launch_for_restore): spawn the
    /// **jailer** for a snapshot restore, so a prewarmed clone runs confined from its first
    /// instruction. The bundle (state, memory, disk) is staged into the chroot in
    /// [`run_restore`](Self::run_restore), once the API socket proves the chroot exists.
    ///
    /// The cgroup **resource caps** are re-applied here and derived from the *clone's true
    /// envelope*, never `config`: restore issues no `PUT /machine-config`, so the guest's vCPUs and
    /// RAM come from the snapshot and caps derived from a mis-declaring `config` would throttle or
    /// OOM-kill a legitimate clone. `memory.max` comes from the memory file's true size
    /// (`restore_mem_mib`, never below what the clone uses), `cpu.max` from the bundle's recorded
    /// vCPU count, and `pids.max` is a constant. Fail-open like a cold boot's caps (empty without
    /// delegated controllers), since the isolation walls (chroot, uid drop, seccomp, netns) are all
    /// present either way.
    fn launch_jailed_for_restore(
        config: &BootConfig,
        snapshot: &Snapshot,
        jail: &Jail,
    ) -> Result<Self, VmmError> {
        let mem_len = std::fs::metadata(&snapshot.mem)
            .map(|m| m.len())
            .unwrap_or(0);
        let cgroup_args = cgroup_limit_args(
            config.require_limits,
            snapshot.vcpus,
            restore_mem_mib(config.mem_mib, mem_len),
        )?;
        let s = Self::spawn_jailed(config, jail, snapshot.tap_name.is_some(), &cgroup_args)?;
        // Every snapshot source is unjailed (a jailed VM refuses snapshotting) so the `v.sock` was
        // baked in relative, and the jailed clone's cwd is the chroot root: Firecracker re-binds it
        // there and the host dials the same file at its absolute path under the chroot.
        let vsock_uds = snapshot.has_vsock.then(|| s.chroot_root.join(VSOCK_UDS));
        Ok(Self {
            child: Some(s.child),
            console: s.console,
            workdir: s.workdir,
            // Placeholder, as in `launch_for_restore`: a restored VM's live disk is an anonymous
            // inode, and re-snapshotting is refused.
            rootfs: snapshot.root_drive.clone(),
            restored: true,
            api: ApiClient::new(s.socket),
            vsock_uds,
            input_image: None,
            output: None,
            tap: s.tap,
            chroot: Some(Chroot::new(s.chroot_root, s.lease)),
            lifetime: s.lifetime,
        })
    }

    /// The scratch-dir name, used to tag the per-VM tracing span so interleaved logs from
    /// concurrent VMs stay attributable.
    pub(crate) fn vm_name(&self) -> String {
        workdir_name(&self.workdir)
    }

    /// Load `snapshot` on this fresh VMM and resume it, returning the restore latency (the load +
    /// resume call). Firecracker opens the root disk **at load** from the path baked into the
    /// snapshot, so the bundle's private copy is staged there first and unlinked once the VMM holds
    /// the fd: the clone gets its own disk inode and nothing lingers outside its scratch dir.
    pub(crate) fn run_restore(
        &mut self,
        snapshot: &Snapshot,
        deadline: Instant,
    ) -> Result<Duration, VmmError> {
        let span = tracing::info_span!("restore", vm = %self.vm_name());
        let _span = span.enter();

        // The deadline is computed once by the caller (`boot_deadline`) so it spans the pre-spawn
        // staging (`launch_for_restore`) and this restore together, one wall.
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Resolve every fallible input *before* staging the disk, so that once the ~disk-sized
        // copy exists there is no `?` between the stage and the matching unstage: the unjailed
        // baked path lives outside this VM's workdir, where no `Drop` reclaims it. (Jailed staging
        // is inside the chroot, which the workdir's `remove_dir_all` reclaims on any abort.)
        still_before(deadline, "restore staging")?;

        // Stage the bundle where this VMM can open it, and name it for the load call. Unjailed: the
        // bundle files are named by absolute host paths, and only a private per-VM disk needs
        // staging. Jailed: everything goes into the chroot, with the guest **memory bind-mounted
        // read-only** (a copy of hundreds of MiB per clone would erase the prewarmed-restore
        // latency win and the clones' shared page cache) and the disk at the **baked-in path
        // resolved inside the chroot**, since Firecracker reopens the drive from the path recorded
        // in the state file. `disk_unstage` is the private copy to remove once Firecracker has
        // its fd.
        let state_arg: String;
        let mem_arg: String;
        // Guards the staged private disk copy: unstaged explicitly after the load, but also on any
        // unwind in between, since the unjailed copy lives outside the workdir.
        let mut disk_unstage = StagedDisk::none();
        if let Some(chroot) = self.chroot.as_ref() {
            let (root, uid, gid) = (chroot.root.clone(), chroot.uid, chroot.gid);
            let workdir = self.workdir.clone();
            // The jailed Firecracker re-binds the baked-in relative `v.sock` at its cwd, the
            // chroot root, so that dir must be writable by the dropped uid.
            std::os::unix::fs::chown(&root, Some(uid), Some(gid))
                .map_err(|e| VmmError::Vmm(format!("chown chroot root to {uid}:{gid}: {e}")))?;
            // Re-check the shared wall before each staging copy: the memory stage can fall back to
            // copying the whole guest-RAM-sized file, so a copy that blows the budget must surface
            // as a typed Timeout rather than silently run the deadline out.
            still_before(deadline, "stage snapshot state")?;
            state_arg =
                stage_into_chroot(&root, "snapshot.state", &snapshot.state, uid, gid, 0o444)?;
            still_before(deadline, "stage snapshot memory")?;
            let (mem_rel, mem_mount) = stage_ro_base_into_chroot(
                &root,
                "snapshot.mem",
                &snapshot.mem,
                &workdir,
                uid,
                gid,
                deadline,
            )?;
            mem_arg = mem_rel;
            // Record the bind mount into `chroot.mounts` *now*, before the fallible steps below:
            // an early error returns straight to `abort`, which unmounts only what `chroot.mounts`
            // holds, and a mount recorded lazily at the end would leave `remove_dir_all(workdir)`
            // to `EBUSY` and leak the chroot.
            if let Some(chroot) = self.chroot.as_mut() {
                chroot.mounts.extend(mem_mount);
            }
            // The disk, at `<chroot>/<baked path>`; the baked path is absolute, so re-rooting it
            // is a strip + join. The traversal chain is created root-owned 0755 (the jailed uid can
            // walk it), but for a private disk the *leaf* dir is `stage_restore_disk`'s to create:
            // its contract refuses a pre-existing dir that is not 0700 and owner-euid, so
            // pre-creating the leaf here would refuse every jailed private-disk restore.
            let baked_rel = snapshot.root_backing.strip_prefix("/").map_err(|_| {
                VmmError::Vmm(format!(
                    "snapshot's baked-in disk path is not absolute: {}",
                    snapshot.root_backing.display()
                ))
            })?;
            let disk_target = root.join(baked_rel);
            let staging_parent = disk_target.parent();
            if let Some(parent) = staging_parent {
                let chain = if snapshot.shared_base {
                    // A bind-mount target needs its full parent chain; the mount covers the leaf.
                    Some(parent)
                } else {
                    parent.parent()
                };
                if let Some(chain) = chain {
                    std::fs::create_dir_all(chain).map_err(|e| {
                        VmmError::Vmm(format!("create chroot disk dirs {}: {e}", chain.display()))
                    })?;
                }
            }
            still_before(deadline, "stage restore disk")?;
            if snapshot.shared_base {
                let rel = baked_rel.to_string_lossy();
                let (_, disk_mount) = stage_ro_base_into_chroot(
                    &root,
                    &rel,
                    &snapshot.root_drive,
                    &workdir,
                    uid,
                    gid,
                    deadline,
                )?;
                // Same eager recording as the memory mount above: the shared-base disk bind must be
                // detachable by teardown/abort the instant it exists, not only if we reach the end.
                if let Some(chroot) = self.chroot.as_mut() {
                    chroot.mounts.extend(disk_mount);
                }
            } else {
                stage_restore_disk(&snapshot.root_drive, &disk_target)?;
                give_to_jail(&disk_target, uid, gid, 0o600)?;
                // The dropped uid opens the disk *through* the staging dir, so hand the dir over
                // with the file (0700, jail-owned) to match the process that must traverse it.
                if let Some(parent) = staging_parent {
                    give_to_jail(parent, uid, gid, 0o700)?;
                }
                disk_unstage = StagedDisk::armed(disk_target);
            }
            // Learn the jailer's cgroup so teardown can remove it too.
            self.learn_jailer_cgroup();
        } else {
            state_arg = path_str(&snapshot.state)?.to_string();
            mem_arg = path_str(&snapshot.mem)?.to_string();
            if !snapshot.shared_base {
                still_before(deadline, "stage restore disk")?;
                stage_restore_disk(&snapshot.root_drive, &snapshot.root_backing)?;
                disk_unstage = StagedDisk::armed(snapshot.root_backing.clone());
            }
        }
        // `/snapshot/load` blocks until Firecracker reads the whole memory file back, so scale its
        // socket timeout by that file's true size, never the restoring `config`'s declaration.
        let mem_mib = std::fs::metadata(&snapshot.mem)
            .map(|m| u32::try_from(m.len() >> 20).unwrap_or(u32::MAX))
            .unwrap_or(0);
        // Clamp that mem-scaled ceiling to the wall's remaining budget: the ceiling is slow-disk
        // headroom, but the run's one wall is the hard bound. `still_before` keeps the remainder
        // positive, because a zero socket timeout means "block forever".
        still_before(deadline, "PUT /snapshot/load")?;
        let load_timeout =
            snapshot_api_timeout(mem_mib).min(deadline.saturating_duration_since(Instant::now()));
        let started = Instant::now();
        let loaded = self.api.put_with_timeout(
            "/snapshot/load",
            &SnapshotLoad {
                snapshot_path: &state_arg,
                mem_backend: MemBackend {
                    backend_type: MemBackendType::File,
                    backend_path: &mem_arg,
                },
                resume_vm: true,
                // Advance the guest's kvmclock across the snapshot's age rather than resuming it
                // frozen, since a pooled clone can sit minutes between snapshot and take. Omitted
                // on a binary that predates the field, which keeps an older release restoring.
                clock_realtime: clock_realtime_arg(),
            },
            load_timeout,
        );
        // The restore latency is the load + resume call itself, measured before host-side cleanup.
        let latency = started.elapsed();
        // Firecracker now holds the disk's fd (or the load failed); either way remove a staged
        // private copy, since the open fd keeps the inode alive for the VM's lifetime.
        if let Some(target) = disk_unstage.take() {
            unstage_restore_disk(&target);
        }
        loaded?;

        // A snapshot that loads but immediately dies (a corrupt bundle, an incompatible host) is a
        // typed error, not a "successful" restore of a dead VMM.
        if let Some(status) = self.exited()? {
            return Err(VmmError::Vmm(format!(
                "firecracker exited after restore ({status})"
            )));
        }

        // Firecracker's vsock backend needs a moment after resume before it forwards to the guest
        // agent again, so poll until a connect succeeds (bounded by the deadline) and `restore`
        // hands back a VM ready to `exec` rather than one mid-resume.
        if let Some(uds) = self.vsock_uds.clone() {
            self.await_guest_ready(&uds, deadline)?;
        }
        // No in-guest re-addressing on restore: each clone owns a private netns, so the snapshot's
        // baked-in `eth0` address/MAC/routes are already correct and collision-free in it.

        tracing::info!(
            restore_ms = crate::ms(latency),
            "microVM restored from snapshot"
        );
        Ok(latency)
    }
}

/// Place the snapshot bundle's private root-disk copy at `backing`, the path Firecracker opens the
/// drive from during `PUT /snapshot/load`, creating parent dirs as needed. Refuses to overwrite an
/// existing file, so a still-live source VM's disk (or a concurrent restore targeting the identical
/// baked-in path) is never clobbered: this is why an unjailed read-write restore is single-flight,
/// while a jailed restore re-roots the path per chroot and is not.
pub(crate) fn stage_restore_disk(copy: &Path, backing: &Path) -> Result<(), VmmError> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = backing.parent() {
        ensure_private_staging_dir(parent)?;
    }
    // `create_new` reserves the path **atomically**, not as a check-then-copy TOCTOU: an existing
    // path (a still-live source's disk) fails the open rather than being clobbered. `mode(0o600)`
    // keeps the staged disk unreadable to other local users during the copy→`PUT /snapshot/load`
    // window, defense in depth behind the private-0700 parent.
    let mut dst = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(backing)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(VmmError::Vmm(format!(
                "root disk path {} already exists: a concurrent restore of this snapshot, or a live \
                 source VM still holding it. An unjailed restore of a read-write snapshot is \
                 single-flight (Firecracker reopens the disk at this baked-in path, and no release \
                 offers a drive-path override on load); restore clones \
                 sequentially, or use a jailed or read_only_root snapshot for concurrent clones, or \
                 drop the source first.",
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
    // With the path reserved above, drop the stager's pid marker the orphan sweep checks before
    // reclaiming a dead-source-pid dir (`sweep::RESTORE_STAGING_MARKER`): while this pid is alive
    // the sweep defers the dir, so the copy→`PUT /snapshot/load` window is never `remove_dir_all`'d
    // from under us. A failed marker write aborts the stage, since an unmarked copy is
    // sweep-raceable.
    if let Some(parent) = backing.parent() {
        let marker = parent.join(crate::sweep::RESTORE_STAGING_MARKER);
        if let Err(e) = std::fs::write(&marker, std::process::id().to_string()) {
            drop(dst);
            unstage_restore_disk(backing);
            return Err(VmmError::Vmm(format!(
                "write restore-staging marker {}: {e}",
                marker.display()
            )));
        }
    }
    let copy_bytes =
        std::fs::File::open(copy).and_then(|mut src| std::io::copy(&mut src, &mut dst).map(|_| ()));
    if let Err(e) = copy_bytes {
        // Staging is all-or-nothing: a partial copy (disk full mid-write) undoes the file and the
        // dir this call may have just created.
        drop(dst);
        unstage_restore_disk(backing);
        return Err(VmmError::Vmm(format!(
            "stage restore disk {}: {e}",
            backing.display()
        )));
    }
    Ok(())
}

/// Create the restore-disk staging dir private (mode `0700`, owned by us), or adopt an existing one
/// only after verifying it is ours and `0700`. The baked-in path is predictable
/// (`/tmp/bsx-<srcpid>-<seq>`, from the snapshot's source) and `/tmp` is world-writable, so a blind
/// `create_dir_all` would adopt an attacker-planted world-writable dir and let a local user
/// rename-swap the staged disk before `PUT /snapshot/load` opens it. The one pre-existing dir it
/// may legitimately meet is a lingering-empty one from a prior restore of the same snapshot.
pub(crate) fn ensure_private_staging_dir(dir: &Path) -> Result<(), VmmError> {
    use super::workdir::{PrivateDirError, create_private_dir};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match create_private_dir(dir) {
        Ok(()) => Ok(()),
        Err(PrivateDirError::Chmod(e)) => Err(VmmError::Vmm(format!(
            "chmod staging dir {}: {e}",
            dir.display()
        ))),
        Err(PrivateDirError::Create(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let md = std::fs::metadata(dir)
                .map_err(|e| VmmError::Vmm(format!("stat staging dir {}: {e}", dir.display())))?;
            let me = crate::sweep::own_euid().ok_or_else(|| {
                VmmError::Vmm("cannot read own euid to verify the staging dir owner".into())
            })?;
            if md.uid() != me || md.permissions().mode() & 0o777 != 0o700 {
                return Err(VmmError::Vmm(format!(
                    "restore staging dir {} exists but is not a private (mode 0700, owner {me}) \
                     directory; refusing to stage the root disk into a possibly-squatted path",
                    dir.display()
                )));
            }
            Ok(())
        }
        Err(PrivateDirError::Create(e)) => Err(VmmError::Vmm(format!(
            "create staging dir {}: {e}",
            dir.display()
        ))),
    }
}

/// Remove the staged restore disk, its staging marker, and the parent dir if now empty, once
/// Firecracker holds the fd. Best-effort, since the open fd keeps the inode alive for the VM's
/// lifetime, so a failure here leaks at most an empty file or dir under `/tmp`. `remove_dir` only
/// succeeds on an empty dir, so it never touches one still holding a live VM's files.
fn unstage_restore_disk(backing: &Path) {
    let _ = std::fs::remove_file(backing);
    if let Some(parent) = backing.parent() {
        let _ = std::fs::remove_file(parent.join(crate::sweep::RESTORE_STAGING_MARKER));
        let _ = std::fs::remove_dir(parent);
    }
}

/// RAII guard for the unjailed restore's staged root-disk copy, which lives at the snapshot's
/// baked-in path **outside** this VM's workdir, where no `Spawned::Drop` reclaims it. `run_restore`
/// unstages it explicitly once Firecracker holds the fd ([`take`](Self::take)); this guard covers a
/// **panic-unwind** between the stage and that point, which would otherwise leak a rootfs-sized
/// file. (A jailed restore's staged disk is inside the chroot and already reclaimed.)
pub(crate) struct StagedDisk(Option<PathBuf>);

impl StagedDisk {
    /// Disarmed: nothing staged yet.
    fn none() -> Self {
        Self(None)
    }

    /// Armed on `path`: unstage on drop unless [`take`](Self::take)n first.
    pub(crate) fn armed(path: PathBuf) -> Self {
        Self(Some(path))
    }

    /// Disarm and hand back the path, for the deliberate post-load unstage.
    pub(crate) fn take(&mut self) -> Option<PathBuf> {
        self.0.take()
    }
}

impl Drop for StagedDisk {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            unstage_restore_disk(&path);
        }
    }
}
