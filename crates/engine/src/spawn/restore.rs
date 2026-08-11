//! Restoring a snapshot into a VMM: the jailed and unjailed constructors, the API restore
//! sequence, and the out-of-workdir disk staging it needs (with the guard that unstages on unwind).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::fcversion::{clock_realtime_arg, warn_on_unpinned_firecracker};
use super::workdir::{create_workdir, workdir_name};
use super::{Spawned, spawn_fc, still_before};
use crate::VmmError;
use crate::firecracker::{
    ApiClient, MemBackend, MemBackendType, SnapshotLoad, snapshot_api_timeout,
};
use crate::jail::{
    Chroot, Jail, cgroup_limit_args, give_to_jail, restore_mem_mib, stage_into_chroot,
    stage_ro_base_into_chroot,
};
use crate::lifetime::VmLifetime;
use crate::net::Tap;
use crate::paths::path_str;
use crate::vm::{
    BootConfig, Snapshot, VSOCK_UDS, reclaim_scratch, reclaim_scratch_after_tap_failure,
};

impl Spawned {
    /// Spawn a bare `firecracker` for a snapshot restore: a fresh scratch dir + process + console,
    /// with **no** boot-time device configuration (the guest's devices are recreated from the
    /// snapshot on `PUT /snapshot/load`). The root drive is the bundle's private copy, held so the
    /// restored VM's teardown accounting matches a cold boot. Reuses the same `Spawned` guard, so a
    /// failed restore tears the VMM down through the same paths as a failed boot.
    pub(crate) fn launch_for_restore(
        config: &BootConfig,
        snapshot: &Snapshot,
    ) -> Result<Self, VmmError> {
        warn_on_unpinned_firecracker(&config.firecracker);
        // Jailed restore spawns the jailer instead, so a prewarmed clone is confined from its
        // first instruction; the unjailed path below is untouched.
        if let Some(jail) = config.jail.as_ref() {
            return Self::launch_jailed_for_restore(config, snapshot, jail);
        }
        let workdir = create_workdir(&config.scratch_dir)?;
        // A networked snapshot baked in its tap's `host_dev_name`, so restore must present a tap with
        // that name (the pin's `network_overrides` could rename it instead; `net.rs` records why the
        // namespace is the better answer). Trivially satisfied here: recreate the fixed-name tap in a
        // **fresh per-VM netns** (named after this restore's scratch dir). The clone wakes with the
        // snapshot's baked-in address/MAC/routes, which are already correct in its own isolated netns,
        // so no re-addressing is needed and any number of clones coexist. A direct boot runs Firecracker with the
        // driver's own privilege, so the tap needs no per-uid owner. Created before Firecracker so it
        // can join the netns; a failed create reclaims its own netns, and we still own the workdir.
        let tap = if snapshot.tap_name.is_some() {
            match Tap::create(&workdir_name(&workdir), None) {
                Ok(tap) => Some(tap),
                Err(e) => {
                    // Gate the dir removal on the netns actually being gone (a failed create's own
                    // best-effort delete may have failed), so a dir-less netns is never stranded.
                    reclaim_scratch_after_tap_failure(&workdir);
                    return Err(e);
                }
            }
        } else {
            None
        };
        let socket = workdir.join("fc.sock");
        let (child, console) = match spawn_fc(
            &config.firecracker,
            &workdir,
            &socket,
            tap.as_ref().map(|t| t.netns.as_str()),
        ) {
            Ok(pair) => pair,
            Err(e) => {
                // Route through `reclaim_scratch` (not a bare `tap.delete()` + `remove_dir_all`) so
                // the dir is kept if the netns delete fails: a failed boot must not strand a
                // dir-less netns any more than teardown may (the invariant `reclaim_scratch` owns).
                // Unjailed, so no chroot is chowned to a leased pair and there is none to withhold.
                let _ = reclaim_scratch(&workdir, tap.as_ref());
                return Err(e);
            }
        };
        // A prewarmed snapshot carries the vsock exec channel. Its socket path was baked in relative, so
        // Firecracker re-binds it in *this* restore's cwd (its scratch dir): the restored VM reaches
        // the guest agent through its own `v.sock`, and concurrent clones don't collide. Computed
        // before `workdir` is moved into the struct.
        let vsock_uds = snapshot.has_vsock.then(|| workdir.join(VSOCK_UDS));
        // Cgroup-owned lifetime: a restored clone (and every prewarmed-pool VM riding restore) is
        // as leakable as a cold boot, so it gets the same enrollment + sentinel.
        let lifetime = VmLifetime::adopt(child.id(), &workdir_name(&workdir));
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            // The restored VM's live disk is an anonymous inode (a private copy is staged at load then
            // unlinked; a shared base is referenced in place). This field holds the bundle path only as
            // a placeholder, it isn't a device this scratch dir owns, and re-snapshotting is refused.
            rootfs: snapshot.root_drive.clone(),
            restored: true,
            api: ApiClient::new(socket),
            vsock_uds,
            input_image: None,
            output: None,
            tap,
            chroot: None,
            lifetime,
        })
    }

    /// The jailed counterpart of [`launch_for_restore`](Self::launch_for_restore): spawn the
    /// **jailer** for a snapshot restore, so a prewarmed clone runs confined from its first instruction.
    /// The bundle (state, memory, disk) is staged into the chroot in
    /// [`run_restore`](Self::run_restore), once the API socket proves the chroot exists. A networked
    /// snapshot's baked-in tap is recreated in a fresh per-VM netns the jailer joins,
    /// owned by the jailed uid.
    ///
    /// The cgroup **resource caps** are re-applied here, derived from the *clone's true envelope*
    /// rather than `config`, the guest's vCPUs and RAM come from the snapshot (restore issues no
    /// `PUT /machine-config`, and nothing forces `config` to agree with the source), so caps derived
    /// from a mis-declaring `config` would throttle or OOM-kill a legitimate clone. `cpu.max` uses the
    /// snapshot's recorded vCPU count and `memory.max` the memory file's true guest RAM; `pids.max`
    /// is a constant. Fail-open like a cold boot's caps (empty without delegated controllers),
    /// the isolation walls (chroot, uid drop, seccomp, netns) are all present either way.
    fn launch_jailed_for_restore(
        config: &BootConfig,
        snapshot: &Snapshot,
        jail: &Jail,
    ) -> Result<Self, VmmError> {
        // Re-apply the resource caps a cold jailed boot gets, so a restored clone (where the
        // untrusted code runs) is confined too, not just isolated, the co-resident-safety property.
        // Both caps derive from the snapshot's true envelope, never `config`'s declaration:
        // `memory.max` from the memory file's true size (`restore_mem_mib`, never below what the
        // clone actually uses, so the cap cannot OOM it), `cpu.max` from the
        // vCPU count recorded in the bundle (the clone's real parallelism; a `config` defaulting to
        // fewer vCPUs than the source must not silently throttle it), and `pids.max` is a constant.
        // A networked clone gets the fixed-name tap in a fresh netns; its baked-in guest identity is
        // already correct there.
        let mem_len = std::fs::metadata(&snapshot.mem)
            .map(|m| m.len())
            .unwrap_or(0);
        let cgroup_args = cgroup_limit_args(
            config.require_limits,
            snapshot.vcpus,
            restore_mem_mib(config.mem_mib, mem_len),
        )?;
        let s = Self::spawn_jailed(config, jail, snapshot.tap_name.is_some(), &cgroup_args)?;
        // A prewarmed snapshot baked the **relative** `v.sock` (every snapshot source is unjailed, a
        // jailed VM refuses snapshotting), and the jailed clone's cwd is the chroot root, so
        // Firecracker re-binds it there; the host dials the same file at its absolute path under the
        // chroot. Strictly shorter than the API socket the jailer bounds-checked.
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

    /// The scratch-dir name, used to tag the per-VM tracing span so interleaved logs from concurrent
    /// VMs stay attributable. Shared by [`run_boot`](Self::run_boot) and
    /// [`run_restore`](Self::run_restore).
    pub(crate) fn vm_name(&self) -> String {
        workdir_name(&self.workdir)
    }

    /// Load `snapshot` on this fresh VMM and resume it, returning the restore latency (the load +
    /// resume call). Firecracker opens the root disk **at load** from the path baked into the
    /// snapshot, so we first stage the bundle's private copy there, then unlink it once the VMM holds
    /// the fd: a restored clone gets its own disk inode (sharing no writable backing with its source),
    /// and nothing lingers outside this VM's scratch dir.
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

        // Resolve every fallible input (the deadline, the snapshot paths) *before* staging the disk,
        // so that once the ~disk-sized copy is on disk there is no `?` between the stage and the
        // matching unstage that could leak the staged file *outside our reach*, the unjailed baked
        // path lives outside this VM's workdir. (Jailed staging is all inside the chroot, which the
        // workdir's `remove_dir_all` reclaims on any abort, so the discipline holds structurally.)
        still_before(deadline, "restore staging")?;

        // The vsock socket path was baked in relative, so Firecracker re-binds it in this VMM's cwd,
        // its scratch dir unjailed, the chroot root jailed (`launch_jailed_for_restore` set
        // `vsock_uds` to match): no host-side path recreation is needed, and the socket lands under
        // our own workdir where teardown reclaims it.

        // Stage the bundle where this VMM can open it, and name it for the load call. Unjailed: the
        // bundle files are named by their absolute host paths, and only a private per-VM disk needs
        // staging (at its baked-in path; a shared base already exists there). Jailed: everything is
        // staged into the chroot, the state file copied in (small), the guest **memory bind-mounted
        // read-only** (hundreds of MiB per clone; a copy would erase the prewarmed-restore latency win and
        // the clones' shared page cache), and the disk placed at the **baked-in path resolved inside
        // the chroot** (Firecracker reopens the drive from the path recorded in the state file): a
        // shared base is bind-mounted there read-only, a private copy staged and handed to the jailed
        // uid. `disk_unstage` is the staged private copy to remove once Firecracker holds its fd.
        let state_arg: String;
        let mem_arg: String;
        // Guards the staged private disk copy: unstaged explicitly after the load, but also on any
        // unwind in between (the unjailed copy lives outside the workdir, so no `Drop` else covers it).
        let mut disk_unstage = StagedDisk::none();
        if let Some(chroot) = self.chroot.as_ref() {
            let (root, uid, gid) = (chroot.root.clone(), chroot.uid, chroot.gid);
            let workdir = self.workdir.clone();
            // The jailed Firecracker re-binds the baked-in relative `v.sock` at its cwd, the chroot
            // root, so that dir must be writable by the dropped uid; chown it explicitly rather than
            // relying on the jailer's own layout choices.
            std::os::unix::fs::chown(&root, Some(uid), Some(gid))
                .map_err(|e| VmmError::Vmm(format!("chown chroot root to {uid}:{gid}: {e}")))?;
            // Re-check the shared wall before each staging copy, as `run_boot` does before each PUT:
            // the memory stage can fall back to copying the whole guest-RAM-sized file, so a copy that
            // blows the budget must surface as a typed Timeout, not silently run the deadline out.
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
            // Record the bind mount into `chroot.mounts` *now*, before the fallible steps below: an
            // early error (a strip/create_dir_all/disk-stage failure) returns straight to `abort`,
            // which unmounts only what `chroot.mounts` holds, a mount recorded lazily at the end
            // would be orphaned, and `remove_dir_all(workdir)` would then `EBUSY` and leak the chroot.
            // (`run_boot` records each mount the same eager way.)
            if let Some(chroot) = self.chroot.as_mut() {
                chroot.mounts.extend(mem_mount);
            }
            // The disk, at `<chroot>/<baked path>`. The baked path is absolute (the source resolved
            // it), so re-rooting it is a strip + join. The traversal chain is created root-owned
            // 0755 (the jailed uid can walk it), but for a private disk the *leaf* dir is
            // `stage_restore_disk`'s to create: its staging contract (0700, owner euid, refuse a
            // pre-existing dir that isn't) means pre-creating the leaf here would refuse every
            // jailed private-disk restore, the daemon's whole `--prewarm` path.
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
                // with the file (0700, jail-owned): the privacy contract already held (the dir was
                // created fresh by `stage_restore_disk` just above), and ownership now matches the
                // process that must traverse it.
                if let Some(parent) = staging_parent {
                    give_to_jail(parent, uid, gid, 0o700)?;
                }
                disk_unstage = StagedDisk::armed(disk_target);
            }
            // Mounts were recorded eagerly above; here just learn the jailer's cgroup so teardown
            // can remove it too.
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
        // socket timeout by that file's true size (the bundle's, never the restoring `config`'s,
        // which may under-declare) rather than the instant-reply default.
        let mem_mib = std::fs::metadata(&snapshot.mem)
            .map(|m| u32::try_from(m.len() >> 20).unwrap_or(u32::MAX))
            .unwrap_or(0);
        // Clamp that mem-scaled ceiling to the wall's remaining budget: the ceiling is slow-disk
        // headroom, but the run's one wall is the hard bound, a load that would outrun it is
        // a Timeout, never an overrun that returns minutes past the wall. `still_before` keeps the
        // remainder positive (a zero socket timeout means "block forever").
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
                // frozen; a pooled clone can sit minutes between snapshot and take, so the skew is
                // the normal case there. Omitted on a binary that predates the field, which is what
                // keeps a supported-but-older release restoring at all.
                clock_realtime: clock_realtime_arg(),
            },
            load_timeout,
        );
        // The restore latency is the load + resume call itself, measured before host-side cleanup.
        let latency = started.elapsed();
        // Firecracker now holds the disk's fd (or the load failed); either way remove a staged private
        // copy so it never outlives this restore. The open fd keeps the inode alive for the VM's
        // lifetime.
        if let Some(target) = disk_unstage.take() {
            unstage_restore_disk(&target);
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
            self.await_guest_ready(&uds, deadline)?;
        }
        // No in-guest re-addressing on restore: under the netns model each clone owns a
        // private network namespace, so the snapshot's baked-in `eth0` address/MAC/routes are
        // already correct and collision-free in it. The guest's network identity is untouched; the
        // tap it enforces on stays host-side, in the clone's own netns.

        tracing::info!(
            restore_ms = latency.as_millis() as u64,
            "microVM restored from snapshot"
        );
        Ok(latency)
    }
}

/// Place the snapshot bundle's private root-disk copy at `backing`, the path Firecracker opens the
/// drive from during `PUT /snapshot/load`, creating parent dirs as needed. Refuses to overwrite an
/// existing file, so a still-live source VM's disk (or a concurrent restore of the same snapshot,
/// which would target the identical baked-in path) is never clobbered. This is why an unjailed
/// read-write restore is single-flight; a jailed restore re-roots the path per chroot, so it isn't.
pub(crate) fn stage_restore_disk(copy: &Path, backing: &Path) -> Result<(), VmmError> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = backing.parent() {
        ensure_private_staging_dir(parent)?;
    }
    // `create_new` reserves the path **atomically**: if it already exists (a still-live source's
    // disk) the open fails rather than clobbering it: atomic, not a check-then-copy TOCTOU. `mode(0o600)` keeps the staged disk unreadable to other local
    // users during the copy→`PUT /snapshot/load` window (the private-0700 parent already blocks a
    // rename-swap; this is defense in depth on the file itself). A missing parent or any other
    // error is surfaced as-is.
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
    // With the path reserved (`create_new` above, so a concurrent restore's marker is never
    // clobbered), drop the stager's pid marker the orphan sweep checks before reclaiming a
    // dead-source-pid dir (`sweep::RESTORE_STAGING_MARKER`): while this pid is alive the sweep
    // defers the dir, so the copy→`PUT /snapshot/load` window is never `remove_dir_all`'d out from
    // under us. A failed marker write aborts the stage: an unmarked copy would be sweep-raceable.
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

/// Create the restore-disk staging dir private (mode `0700`, owned by us), or, if it already exists,
/// adopt it only after verifying it is ours and `0700`. The baked-in path is predictable
/// (`/tmp/bsx-<srcpid>-<seq>`, from the snapshot's source) and `/tmp` is world-writable, so a
/// blind `create_dir_all` would silently adopt an attacker-planted world-writable dir, letting a
/// local user rename-swap the staged disk before `PUT /snapshot/load` opens it (guest boots an
/// attacker's rootfs). This mirrors `create_workdir`'s posture; the only pre-existing dir it may
/// legitimately meet is a lingering-empty one from a prior restore of the same snapshot (still ours,
/// still `0700`), and the disk's own `create_new` keeps that case single-flight.
pub(crate) fn ensure_private_staging_dir(dir: &Path) -> Result<(), VmmError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {
            // mkdir's mode is umask-masked; make 0700 unconditional now that the dir is exclusively
            // ours (race-free, we just created it fail-if-exists).
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| VmmError::Vmm(format!("chmod staging dir {}: {e}", dir.display())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
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
        Err(e) => Err(VmmError::Vmm(format!(
            "create staging dir {}: {e}",
            dir.display()
        ))),
    }
}

/// Remove the staged restore disk, its staging marker, and the parent dir if now empty, once
/// Firecracker holds the fd. Best-effort: the open fd keeps the inode alive for the VM's lifetime,
/// so a failure here leaks at most an empty file/dir under `/tmp`, never the VM's disk.
/// `remove_dir` only succeeds on an empty dir, so it never touches a directory that still holds a
/// live VM's files.
fn unstage_restore_disk(backing: &Path) {
    let _ = std::fs::remove_file(backing);
    if let Some(parent) = backing.parent() {
        let _ = std::fs::remove_file(parent.join(crate::sweep::RESTORE_STAGING_MARKER));
        let _ = std::fs::remove_dir(parent);
    }
}

/// RAII guard for the unjailed restore's staged root-disk copy. That copy lives at the snapshot's
/// baked-in path **outside** this VM's workdir, so no `Spawned::Drop` reclaims it: `run_restore`
/// unstages it explicitly once Firecracker holds the fd ([`take`](Self::take)), but a **panic-unwind**
/// between the stage and that point would otherwise leak a rootfs-sized file. This guard unstages on
/// drop unless disarmed, the structural cover the one out-of-workdir stage/unstage pair lacked. (A
/// jailed restore's staged disk is inside the chroot, already reclaimed by `Spawned::Drop`; guarding
/// it too is a harmless extra `remove_file`.)
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
