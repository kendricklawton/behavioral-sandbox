//! The boot/restore state machine beneath [`Vm`](crate::Vm): [`Spawned`] spawns a `firecracker`
//! child (directly, jailed, or for a snapshot restore), drives it through the boot sequence, and
//! either promotes it to a [`RunningVm`] or tears it down on failure — so a half-booted VM is never
//! observable. Split out of `vm.rs` to keep that module the public surface (config + `Vm`/`RunningVm`
//! API) while this holds the ~700-line orchestration.
//!
//! `Spawned`'s `Drop` is the panic safety net: anything that unwinds between `launch` and
//! `abort`/`into_running` still kills the VMM and reclaims its scratch dir. Every free helper here
//! (scratch-dir creation, the `sun_path` guard, the shared `teardown`) serves that lifecycle.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use agent_channel::AGENT_VSOCK_PORT;

use crate::console::{last_lines, Console};
use crate::drives::{build_input_image, build_output_image, OutputDevice};
use crate::exec::connect_agent_at;
use crate::firecracker::{
    Action, ApiClient, BootSource, Drive, MachineConfig, MemBackend, MemBackendType,
    NetworkInterface, SnapshotLoad, Vsock,
};
use crate::jail::{
    cgroup_limit_args, give_to_jail, jailer_cgroup_dir, read_cgroup_dir, remove_cgroup,
    spawn_jailer, stage_into_chroot, stage_ro_base_into_chroot, unmount_base, Chroot, Jail,
    JAILED_VSOCK_UDS,
};
use crate::lifetime::VmLifetime;
use crate::net::Tap;
use crate::paths::{absolute, path_str, require_file};
use crate::vm::{
    teardown, BootConfig, RunningVm, Snapshot, FC_STDERR, IFACE_ID, VM_SEQ, VSOCK_UDS,
};
use crate::VmmError;

/// A spawned-but-not-yet-ready VMM. Kept distinct from [`RunningVm`] so the boot sequence can fail
/// and clean up without ever constructing a half-booted `RunningVm`. Its `Drop` is the panic
/// safety net: if anything unwinds between `launch` and `abort`/`into_running` (a panicking
/// `tracing` subscriber, a future bug), the VMM still dies and the scratch dir is still reclaimed.
pub(crate) struct Spawned {
    /// `Some` until `abort`/`into_running` disarm the guard by taking it.
    child: Option<Child>,
    console: Console,
    workdir: PathBuf,
    rootfs: PathBuf,
    /// Set by [`launch_for_restore`](Spawned::launch_for_restore): the `rootfs` is a placeholder, so
    /// the resulting VM is marked restored and can't be re-snapshotted.
    restored: bool,
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
    /// The jail (chroot + dropped uid/gid + cgroup) when `jail` was set (P6.1); `None` for a direct
    /// boot. Its cgroup lives outside `workdir`, so every teardown path removes it explicitly.
    chroot: Option<Chroot>,
    /// The cgroup-owned lifetime machinery (P6.7), armed at spawn so the crash-safety window is as
    /// small as possible; moved onto the [`RunningVm`] by `into_running`.
    lifetime: VmLifetime,
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            teardown(
                &mut child,
                &mut self.console,
                &self.workdir,
                self.tap.as_ref(),
                self.chroot.as_ref(),
                &mut self.lifetime,
            );
        }
    }
}

impl Spawned {
    /// Validate the inputs, lay out the scratch dir, and spawn `firecracker --api-sock`.
    pub(crate) fn launch(config: &BootConfig) -> Result<Self, VmmError> {
        require_file(&config.kernel, "kernel image")?;
        require_file(&config.rootfs, "rootfs image")?;
        warn_on_unpinned_firecracker(&config.firecracker);

        // Jailed boot spawns the jailer (not firecracker directly) and stages resources into the
        // chroot later; the unjailed setup below is untouched. Every boot feature composes with the
        // jail (P7.0a-d), so there is no combination to refuse first.
        if let Some(jail) = config.jail.as_ref() {
            return Self::launch_jailed(config, jail);
        }

        let workdir = create_workdir(&config.scratch_dir)?;

        // Read-only boot shares the pinned base directly (no per-VM copy): Firecracker opens it
        // `O_RDONLY` so the guest can't mutate it, and the writable layer comes from the guest's
        // tmpfs overlay (see `BootConfig::read_only_root`). Read-write boot copies the base instead,
        // so the guest's writes stay per-VM and the base stays pinned.
        let rootfs = if config.read_only_root {
            // The shared base is handed to Firecracker as-is and recorded as the snapshot's disk path,
            // so resolve it to absolute now (each VMM's cwd is its scratch dir; a relative base path
            // would resolve there instead).
            match absolute(&config.rootfs) {
                Ok(p) => p,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            }
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

        // Per-VM network namespace + tap for the guest's virtio-net (P4.1, netns model), when enabled.
        // Created **before** Firecracker so it can join the netns; named after the scratch dir, so a
        // crashed driver's netns is reclaimable by the same dir-keyed sweep. A direct boot runs
        // Firecracker with the driver's own privilege, so the tap needs no per-uid owner. A failed
        // create reclaims its own half-built netns; we still own the workdir, so reclaim it.
        let tap = if config.enable_network {
            match Tap::create(&workdir_name(&workdir), None) {
                Ok(tap) => Some(tap),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            }
        } else {
            None
        };
        // Spawn `firecracker --api-sock`, inside the VM's netns when networked (`ip netns exec`), wiring
        // its serial console + stderr log (see `spawn_fc`). On any failure the child is already reaped;
        // delete the netns (best-effort) and reclaim the scratch dir.
        let socket = workdir.join("fc.sock");
        let (child, console) = match spawn_fc(
            &config.firecracker,
            &workdir,
            &socket,
            tap.as_ref().map(|t| t.netns.as_str()),
        ) {
            Ok(pair) => pair,
            Err(e) => {
                if let Some(tap) = tap.as_ref() {
                    tap.delete();
                }
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
        };

        // Cgroup-owned lifetime (P6.7): enroll the VMM in a per-VM lifetime cgroup and arm the
        // sentinel, so from here even a SIGKILLed driver can't leak it. Named by the scratch dir,
        // so a VM's cgroup and scratch identities match.
        let lifetime = VmLifetime::adopt(child.id(), &workdir_name(&workdir));

        // Firecracker creates the vsock socket here on `PUT /vsock`; the host dials it post-boot.
        let vsock_uds = config.guest_cid.map(|_| workdir.join(VSOCK_UDS));
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            rootfs,
            restored: false,
            api: ApiClient::new(socket),
            vsock_uds,
            input_image,
            output,
            tap,
            chroot: None,
            lifetime,
        })
    }

    /// The jailed cold-boot counterpart of [`launch`](Self::launch) (P6.1): spawn the **jailer**,
    /// which builds the chroot, `mknod`s the device nodes, places the VMM in a cgroup, and drops
    /// privileges before `exec`ing Firecracker. Resources (kernel, rootfs) are staged into the chroot
    /// in [`run_boot`](Self::run_boot), once the API socket proves the chroot exists — so no staging
    /// races the jailer's construction. The vsock exec channel composes (its host-side socket path is
    /// set here, the device configured in `run_boot`); a NIC composes (the tap lives in a per-VM
    /// netns the jailer joins via `--netns`); and the bulk-I/O images are built in place **inside
    /// the chroot** in `run_boot` (they can't exist before the jailer builds it).
    fn launch_jailed(config: &BootConfig, jail: &Jail) -> Result<Self, VmmError> {
        let workdir = create_workdir(&config.scratch_dir)?;
        // The jail id is the scratch-dir name: unique per VM within this process and a valid jailer id
        // (alphanumeric + `-`). The jailer nests the chroot under `<workdir>/firecracker/<id>/root`.
        let id = workdir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "agent-vm".to_string());
        // Networked jailed boot: create the per-VM netns + tap **before** the jailer, so the jailer can
        // join it (`--netns`). The tap is owned by the jailed uid/gid because a jailed Firecracker is
        // unprivileged (no `CAP_NET_ADMIN`) and can only attach a tap it owns. The netns is named after
        // the scratch dir (= `id`). A failed create reclaims its own netns; we still own the workdir.
        let tap = if config.enable_network {
            match Tap::create(&id, Some((jail.uid, jail.gid))) {
                Ok(tap) => Some(tap),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            }
        } else {
            None
        };
        // CPU/memory limits (P6.2) derived from the guest's own resource envelope (vcpus, mem_mib);
        // empty when the host doesn't delegate the cgroup controllers, so the jailed boot still runs.
        let cgroup_args = cgroup_limit_args(config.vcpus, config.mem_mib);
        let netns = tap.as_ref().map(|t| t.netns_path());
        let (child, console, socket, chroot_root) = match spawn_jailer(
            jail,
            &config.firecracker,
            &workdir,
            &id,
            &cgroup_args,
            netns.as_deref(),
        ) {
            Ok(t) => t,
            Err(e) => {
                if let Some(tap) = tap.as_ref() {
                    tap.delete();
                }
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
        };
        // Cgroup-owned lifetime (P6.7), jailed flavour: the jailer creates the VM's cgroup and
        // moves the VMM into it itself, so enrolling the pid in a driver cgroup would race that
        // placement (last write wins membership and could yank the VMM out of its limits). The
        // sentinel instead watches the jailer's cgroup at its precomputed path; the unprotected
        // window is spawn → the jailer's self-placement (milliseconds).
        let lifetime = VmLifetime::watch(
            child.id(),
            jailer_cgroup_dir(&config.firecracker, &id)
                .into_iter()
                .collect(),
        );
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            // Staged into the chroot in `run_boot` and named by its chroot-relative path; this
            // placeholder is not a host device path (a jailed VM refuses snapshotting).
            rootfs: PathBuf::from("/rootfs.ext4"),
            restored: false,
            api: ApiClient::new(socket),
            // The exec channel's vsock socket, when enabled: Firecracker (cwd = chroot root after
            // the jailer chroots) binds it at the chroot-relative `JAILED_VSOCK_UDS`, and the host
            // dials the same file at its absolute path under the chroot. That path is strictly
            // shorter than the API socket `spawn_jailer` already bounds-checked, so no separate
            // `check_sun_path` is needed here.
            vsock_uds: config
                .guest_cid
                .map(|_| chroot_root.join(JAILED_VSOCK_UDS.trim_start_matches('/'))),
            input_image: None,
            output: None,
            tap,
            chroot: Some(Chroot {
                root: chroot_root,
                uid: jail.uid,
                gid: jail.gid,
                cgroup_dir: None,
                // Filled in `run_boot` when a `read_only_root` jailed boot bind-mounts the shared base.
                mounts: Vec::new(),
            }),
            lifetime,
        })
    }

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
        // Jailed restore (P7.0e) spawns the jailer instead, so a warm clone is confined from its
        // first instruction; the unjailed path below is untouched.
        if let Some(jail) = config.jail.as_ref() {
            return Self::launch_jailed_for_restore(config, snapshot, jail);
        }
        let workdir = create_workdir(&config.scratch_dir)?;
        // A networked snapshot baked in its tap's `host_dev_name` (v1.9 has no `network_overrides`), so
        // restore must present a tap with that name — trivially satisfied by the netns model: recreate
        // the fixed-name tap in a **fresh per-VM netns** (named after this restore's scratch dir). The
        // clone wakes with the snapshot's baked-in address/MAC/routes, which are already correct in its
        // own isolated netns, so no re-addressing is needed and any number of clones coexist (netns
        // retires the v1.9 one-live-networked-clone limit). A direct boot runs Firecracker with the
        // driver's own privilege, so the tap needs no per-uid owner. Created before Firecracker so it
        // can join the netns; a failed create reclaims its own netns, and we still own the workdir.
        let tap = if snapshot.tap_name.is_some() {
            match Tap::create(&workdir_name(&workdir), None) {
                Ok(tap) => Some(tap),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
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
                if let Some(tap) = tap.as_ref() {
                    tap.delete();
                }
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
        };
        // A warm snapshot carries the vsock exec channel. Its socket path was baked in relative, so
        // Firecracker re-binds it in *this* restore's cwd (its scratch dir): the restored VM reaches
        // the guest agent through its own `v.sock`, and concurrent clones don't collide. Computed
        // before `workdir` is moved into the struct.
        let vsock_uds = snapshot.has_vsock.then(|| workdir.join(VSOCK_UDS));
        // Cgroup-owned lifetime (P6.7): a restored clone (and every warm-pool VM riding restore) is
        // as leakable as a cold boot, so it gets the same enrollment + sentinel.
        let lifetime = VmLifetime::adopt(child.id(), &workdir_name(&workdir));
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            // The restored VM's live disk is an anonymous inode (a private copy is staged at load then
            // unlinked; a shared base is referenced in place). This field holds the bundle path only as
            // a placeholder — it isn't a device this scratch dir owns, and re-snapshotting is refused.
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

    /// The jailed counterpart of [`launch_for_restore`](Self::launch_for_restore) (P7.0e): spawn the
    /// **jailer** for a snapshot restore, so a warm clone runs confined from its first instruction.
    /// The bundle (state, memory, disk) is staged into the chroot in
    /// [`run_restore`](Self::run_restore), once the API socket proves the chroot exists. A networked
    /// snapshot's baked-in tap is recreated in a fresh per-VM netns the jailer joins (decision 017),
    /// owned by the jailed uid.
    ///
    /// No `--cgroup` limits are passed: the guest's resource envelope lives in the snapshot, not in
    /// `config` (which contributes only the binary and timeout on restore), so deriving caps from
    /// `config` could contradict the restored guest and OOM-kill a legitimate clone. The jailer still
    /// creates the cgroup (the lifetime sentinel watches it; the kill handle works); the caps join
    /// when P7.1's `Limits` ride the snapshot. A documented fail-open on the resource-cap side only
    /// (decisions 013/014) — the isolation walls (chroot, uid drop, seccomp, netns) are all present.
    fn launch_jailed_for_restore(
        config: &BootConfig,
        snapshot: &Snapshot,
        jail: &Jail,
    ) -> Result<Self, VmmError> {
        let workdir = create_workdir(&config.scratch_dir)?;
        // The jail id is the scratch-dir name, as in `launch_jailed`; the netns shares it.
        let id = workdir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "agent-vm".to_string());
        // Networked clone: the fixed-name tap in a fresh netns, owned by the jailed uid (an
        // unprivileged Firecracker can only attach a tap it owns). The baked-in guest identity is
        // already correct in the private netns — no re-addressing (decision 017).
        let tap = if snapshot.tap_name.is_some() {
            match Tap::create(&id, Some((jail.uid, jail.gid))) {
                Ok(tap) => Some(tap),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
            }
        } else {
            None
        };
        let netns = tap.as_ref().map(|t| t.netns_path());
        let (child, console, socket, chroot_root) = match spawn_jailer(
            jail,
            &config.firecracker,
            &workdir,
            &id,
            &[],
            netns.as_deref(),
        ) {
            Ok(t) => t,
            Err(e) => {
                if let Some(tap) = tap.as_ref() {
                    tap.delete();
                }
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
        };
        // Cgroup-owned lifetime (P6.7), jailed flavour: the sentinel watches the jailer's cgroup at
        // its precomputed path (enrolling the pid ourselves would race the jailer's own placement).
        let lifetime = VmLifetime::watch(
            child.id(),
            jailer_cgroup_dir(&config.firecracker, &id)
                .into_iter()
                .collect(),
        );
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            // Placeholder, as in `launch_for_restore`: a restored VM's live disk is an anonymous
            // inode, and re-snapshotting is refused.
            rootfs: snapshot.root_drive.clone(),
            restored: true,
            api: ApiClient::new(socket),
            // A warm snapshot baked the **relative** `v.sock` (every snapshot source is unjailed —
            // a jailed VM refuses snapshotting), and the jailed clone's cwd is the chroot root, so
            // Firecracker re-binds it there; the host dials the same file at its absolute path under
            // the chroot. Strictly shorter than the API socket the jailer bounds-checked.
            vsock_uds: snapshot.has_vsock.then(|| chroot_root.join(VSOCK_UDS)),
            input_image: None,
            output: None,
            tap,
            chroot: Some(Chroot {
                root: chroot_root,
                uid: jail.uid,
                gid: jail.gid,
                cgroup_dir: None,
                // Filled by `run_restore`'s staging (the memory file, and a shared base disk).
                mounts: Vec::new(),
            }),
            lifetime,
        })
    }

    /// The scratch-dir name, used to tag the per-VM tracing span so interleaved logs from concurrent
    /// VMs stay attributable. Shared by [`run_boot`](Self::run_boot) and
    /// [`run_restore`](Self::run_restore).
    fn vm_name(&self) -> String {
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
        timeout: Duration,
    ) -> Result<Duration, VmmError> {
        let span = tracing::info_span!("restore", vm = %self.vm_name());
        let _span = span.enter();

        // `Instant + Duration` panics on overflow; a caller's `Duration::MAX` must stay a bounded
        // wait, not a panic — clamp to a day (as `run_boot` does).
        let now = Instant::now();
        let deadline = now
            .checked_add(timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86_400));
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Resolve every fallible input (the deadline, the snapshot paths) *before* staging the disk,
        // so that once the ~disk-sized copy is on disk there is no `?` between the stage and the
        // matching unstage that could leak the staged file *outside our reach* — the unjailed baked
        // path lives outside this VM's workdir. (Jailed staging is all inside the chroot, which the
        // workdir's `remove_dir_all` reclaims on any abort, so the discipline holds structurally.)
        still_before(deadline, "PUT /snapshot/load")?;

        // The vsock socket path was baked in relative, so Firecracker re-binds it in this VMM's cwd —
        // its scratch dir unjailed, the chroot root jailed (`launch_jailed_for_restore` set
        // `vsock_uds` to match): no host-side path recreation is needed, and the socket lands under
        // our own workdir where teardown reclaims it.

        // Stage the bundle where this VMM can open it, and name it for the load call. Unjailed: the
        // bundle files are named by their absolute host paths, and only a private per-VM disk needs
        // staging (at its baked-in path; a shared base already exists there). Jailed: everything is
        // staged into the chroot — the state file copied in (small), the guest **memory bind-mounted
        // read-only** (hundreds of MiB per clone; a copy would erase the warm-restore latency win and
        // the clones' shared page cache), and the disk placed at the **baked-in path resolved inside
        // the chroot** (Firecracker reopens the drive from the path recorded in the state file): a
        // shared base is bind-mounted there read-only, a private copy staged and handed to the jailed
        // uid. `disk_unstage` is the staged private copy to remove once Firecracker holds its fd.
        let state_arg: String;
        let mem_arg: String;
        let mut disk_unstage: Option<PathBuf> = None;
        if let Some(chroot) = self.chroot.as_ref() {
            let (root, uid, gid) = (chroot.root.clone(), chroot.uid, chroot.gid);
            let workdir = self.workdir.clone();
            let mut mounts = Vec::new();
            // The jailed Firecracker re-binds the baked-in relative `v.sock` at its cwd — the chroot
            // root — so that dir must be writable by the dropped uid; chown it explicitly rather than
            // relying on the jailer's own layout choices.
            std::os::unix::fs::chown(&root, Some(uid), Some(gid))
                .map_err(|e| VmmError::Vmm(format!("chown chroot root to {uid}:{gid}: {e}")))?;
            state_arg =
                stage_into_chroot(&root, "snapshot.state", &snapshot.state, uid, gid, 0o444)?;
            let (mem_rel, mem_mount) = stage_ro_base_into_chroot(
                &root,
                "snapshot.mem",
                &snapshot.mem,
                &workdir,
                uid,
                gid,
            )?;
            mem_arg = mem_rel;
            mounts.extend(mem_mount);
            // The disk, at `<chroot>/<baked path>`. The baked path is absolute (the source resolved
            // it), so re-rooting it is a strip + join; its parent dirs are created root-owned 0755,
            // which the jailed uid can traverse.
            let baked_rel = snapshot.root_backing.strip_prefix("/").map_err(|_| {
                VmmError::Vmm(format!(
                    "snapshot's baked-in disk path is not absolute: {}",
                    snapshot.root_backing.display()
                ))
            })?;
            let disk_target = root.join(baked_rel);
            if let Some(parent) = disk_target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    VmmError::Vmm(format!("create chroot disk dirs {}: {e}", parent.display()))
                })?;
            }
            if snapshot.shared_base {
                let rel = baked_rel.to_string_lossy();
                let (_, disk_mount) = stage_ro_base_into_chroot(
                    &root,
                    &rel,
                    &snapshot.root_drive,
                    &workdir,
                    uid,
                    gid,
                )?;
                mounts.extend(disk_mount);
            } else {
                stage_restore_disk(&snapshot.root_drive, &disk_target)?;
                give_to_jail(&disk_target, uid, gid, 0o600)?;
                disk_unstage = Some(disk_target);
            }
            // Record the mounts for teardown, and learn the jailer's cgroup (mirroring `run_boot`) so
            // teardown can remove it too.
            if let Some(chroot) = self.chroot.as_mut() {
                chroot.mounts.extend(mounts);
            }
            if let Some(pid) = self.child.as_ref().map(|c| c.id()) {
                let actual = read_cgroup_dir(pid);
                if let Some(dir) = actual.as_deref() {
                    if !self.lifetime.watches(dir) {
                        tracing::warn!(
                            cgroup = %dir.display(),
                            "jailer placed the VMM outside the precomputed cgroup; the lifetime \
                             sentinel is not guarding it (driver death would leak this VMM)"
                        );
                    }
                }
                if let Some(chroot) = self.chroot.as_mut() {
                    chroot.cgroup_dir = actual;
                }
            }
        } else {
            state_arg = path_str(&snapshot.state)?.to_string();
            mem_arg = path_str(&snapshot.mem)?.to_string();
            if !snapshot.shared_base {
                stage_restore_disk(&snapshot.root_drive, &snapshot.root_backing)?;
                disk_unstage = Some(snapshot.root_backing.clone());
            }
        }
        let started = Instant::now();
        let loaded = self.api.put(
            "/snapshot/load",
            &SnapshotLoad {
                snapshot_path: &state_arg,
                mem_backend: MemBackend {
                    backend_type: MemBackendType::File,
                    backend_path: &mem_arg,
                },
                resume_vm: true,
            },
        );
        // The restore latency is the load + resume call itself, measured before host-side cleanup.
        let latency = started.elapsed();
        // Firecracker now holds the disk's fd (or the load failed); either way remove a staged private
        // copy so it never outlives this restore. The open fd keeps the inode alive for the VM's
        // lifetime.
        if let Some(target) = disk_unstage {
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
            self.await_agent_ready(&uds, deadline)?;
        }
        // No in-guest re-addressing on restore (was decision 011's `apply_guest_net_identity`): under
        // the netns model each clone owns a private network namespace, so the snapshot's baked-in
        // `eth0` address/MAC/routes are already correct and collision-free in it. The guest's network
        // identity is untouched; the tap it enforces on stays host-side, in the clone's own netns.

        tracing::info!(
            restore_ms = latency.as_millis() as u64,
            "microVM restored from snapshot"
        );
        Ok(latency)
    }

    /// Poll the guest agent's vsock port until a connect + handshake succeeds, so a restored VM is
    /// exec-ready when it's handed back. The probe connection is dropped immediately (the agent serves
    /// one connection then loops back to accept, so a connect-and-close just cycles it).
    fn await_agent_ready(&mut self, uds: &Path, deadline: Instant) -> Result<(), VmmError> {
        loop {
            match connect_agent_at(uds, AGENT_VSOCK_PORT, Duration::from_millis(200)) {
                Ok(_probe) => return Ok(()),
                Err(e) => {
                    if let Some(status) = self.exited()? {
                        return Err(VmmError::Vmm(format!(
                            "firecracker exited after restore ({status})"
                        )));
                    }
                    if Instant::now() >= deadline {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// `PUT /drives/{id}` — attach a virtio-block device, deriving the API path from `id` so the URL
    /// and the body's `drive_id` are the same token and can't drift apart. `still_before` first, so a
    /// boot already past its deadline fails fast with this drive named.
    fn put_drive(
        &self,
        id: &str,
        path_on_host: &str,
        is_root_device: bool,
        is_read_only: bool,
        deadline: Instant,
    ) -> Result<(), VmmError> {
        still_before(deadline, &format!("PUT /drives/{id}"))?;
        self.api.put(
            &format!("/drives/{id}"),
            &Drive {
                drive_id: id,
                path_on_host,
                is_root_device,
                is_read_only,
            },
        )
    }

    /// Drive the API through the boot sequence and wait for the userspace marker; returns the
    /// boot-to-userspace latency.
    pub(crate) fn run_boot(&mut self, config: &BootConfig) -> Result<Duration, VmmError> {
        // One span per boot, keyed by the scratch-dir name, so interleaved logs from concurrent
        // VMs (the warm pool, Phase 5) stay attributable to their sandbox.
        let span = tracing::info_span!("boot", vm = %self.vm_name());
        let _span = span.enter();

        // `Instant + Duration` panics on overflow, and `boot_timeout` is caller-set (a
        // `Duration::MAX` "no limit" must stay a *bounded* wait, not a panic) — clamp to a day.
        let now = Instant::now();
        let deadline = now
            .checked_add(config.boot_timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86_400));
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Kernel + rootfs paths as Firecracker will name them. Unjailed: absolute host paths (its cwd
        // is the scratch dir); `self.rootfs` is already absolute from `launch`. Jailed: stage each into
        // the chroot (safe now that the API socket proved the chroot exists — no race with the jailer's
        // construction) and name it by its chroot-relative path, and record the jailer's cgroup for
        // teardown. A `read_only_root` jailed boot bind-mounts the shared base zero-copy (the density
        // path); a read-write boot stages a private copy.
        let kernel_arg: String;
        let rootfs_arg: String;
        if let Some(chroot) = self.chroot.as_ref() {
            let (root, uid, gid) = (chroot.root.clone(), chroot.uid, chroot.gid);
            // Read-only kernel (0444), chowned to the jailed uid so the dropped-privilege Firecracker
            // can open it.
            kernel_arg = stage_into_chroot(&root, "kernel", &config.kernel, uid, gid, 0o444)?;
            // The root disk: bind-mount the shared read-only base (density path) when `read_only_root`,
            // else a read-write private copy (0600). The bind mount, if made, is recorded on the chroot
            // so teardown unmounts it before reclaiming the scratch dir.
            if config.read_only_root {
                let (arg, mount) = stage_ro_base_into_chroot(
                    &root,
                    "rootfs.ext4",
                    &config.rootfs,
                    &config.scratch_dir,
                    uid,
                    gid,
                )?;
                rootfs_arg = arg;
                if let (Some(chroot), Some(mount)) = (self.chroot.as_mut(), mount) {
                    chroot.mounts.push(mount);
                }
            } else {
                rootfs_arg =
                    stage_into_chroot(&root, "rootfs.ext4", &config.rootfs, uid, gid, 0o600)?;
            }
            // Bulk I/O under the jail (P7.0d): build the input/output ext4 images **in place inside
            // the chroot** — the builders are rootless `mke2fs` runs that take a target dir, so no
            // copy or mount is needed, just handing the finished image to the jailed uid. Built here
            // (not in `launch_jailed`) because the chroot only exists once the jailer has run; the
            // API socket answering above is the proof it does. Input is read-only (0444, Firecracker
            // opens it `O_RDONLY`); output is read-write (0600). Both live under the workdir (the
            // chroot nests in it), so teardown's `remove_dir_all` reclaims them as before, and
            // `collect_outputs` reads the output image at its host-side path after the VMM exits.
            if let Some(dir) = config.input_dir.as_ref() {
                let image = build_input_image(dir, &root)?;
                give_to_jail(&image, uid, gid, 0o444)?;
                self.input_image = Some(image);
            }
            if let Some(dest) = config.output_dir.as_ref() {
                let image = build_output_image(&root)?;
                give_to_jail(&image, uid, gid, 0o600)?;
                self.output = Some(OutputDevice {
                    image,
                    dest: dest.clone(),
                });
            }
            // Learn the cgroup the jailer placed the VMM in (from `/proc/<pid>/cgroup`, now that
            // Firecracker is running in its final cgroup), so teardown can remove it. The lifetime
            // sentinel (P6.7) watches the *precomputed* jailer cgroup path from spawn; if the
            // jailer put the VMM somewhere else, the sentinel isn't guarding it — warn, don't hide.
            if let Some(pid) = self.child.as_ref().map(|c| c.id()) {
                let actual = read_cgroup_dir(pid);
                if let Some(dir) = actual.as_deref() {
                    if !self.lifetime.watches(dir) {
                        tracing::warn!(
                            cgroup = %dir.display(),
                            "jailer placed the VMM outside the precomputed cgroup; the lifetime \
                             sentinel is not guarding it (driver death would leak this VMM)"
                        );
                    }
                }
                if let Some(chroot) = self.chroot.as_mut() {
                    chroot.cgroup_dir = actual;
                }
            }
        } else {
            let kernel = absolute(&config.kernel)?;
            kernel_arg = path_str(&kernel)?.to_string();
            rootfs_arg = path_str(&self.rootfs)?.to_string();
        }
        let kernel = kernel_arg.as_str();
        let rootfs = rootfs_arg.as_str();
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
        self.put_drive("rootfs", rootfs, true, config.read_only_root, deadline)?;
        // Bulk read-only input (P3.4): attach the built image as `/dev/vdb`. `is_read_only` is what
        // makes the input provably immutable (Firecracker opens it `O_RDONLY`) and sidesteps the
        // read-back-a-dirty-ext4 hazard that a writable device would carry into P3.5. Jailed, the
        // image sits at the chroot root, so its API name is the fixed chroot-relative path; unjailed
        // it is the absolute workdir path (self.input_image holds the host-side path either way).
        if let Some(image) = self.input_image.as_ref() {
            let input = if self.chroot.is_some() {
                "/input.ext4".to_string()
            } else {
                path_str(image)?.to_string()
            };
            self.put_drive("input", &input, false, true, deadline)?;
        }
        // Bulk writable output (P3.5): attach the blank image read-write. The guest mounts it by
        // label (`agent-output`), so the `/dev/vdX` letter this lands on doesn't matter — a boot may
        // attach input, output, both, or neither. Durability of the guest's writes is the guest's
        // `-o sync` mount plus a clean unmount on shutdown; `collect_outputs` reads it after the VMM
        // exits (never while it holds the file open — see `RunningVm::collect_outputs`).
        if let Some(out) = self.output.as_ref() {
            let output = if self.chroot.is_some() {
                "/output.ext4".to_string()
            } else {
                path_str(&out.image)?.to_string()
            };
            self.put_drive("output", &output, false, false, deadline)?;
        }
        still_before(deadline, "PUT /machine-config")?;
        self.api.put(
            "/machine-config",
            &MachineConfig {
                vcpu_count: config.vcpus,
                mem_size_mib: config.mem_mib,
            },
        )?;

        if let Some(cid) = config.guest_cid {
            still_before(deadline, "PUT /vsock")?;
            // Bind the socket relative to the VMM's cwd. Unjailed: the **relative** name `v.sock` in
            // the scratch dir — baking a relative path into the snapshot is what lets warm clones
            // restored from it each bind their own socket instead of colliding on one absolute path.
            // Jailed: `/run/v.sock` inside the chroot (cwd = chroot root, `/run` writable by the
            // dropped uid). Either way the host dials the same file via the absolute `self.vsock_uds`.
            let uds_path = if self.chroot.is_some() {
                JAILED_VSOCK_UDS
            } else {
                VSOCK_UDS
            };
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
            still_before(deadline, "PUT /network-interfaces")?;
            self.api.put(
                &format!("/network-interfaces/{IFACE_ID}"),
                &NetworkInterface {
                    iface_id: IFACE_ID,
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
        self.api.put("/actions", &Action::InstanceStart)?;
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
    pub(crate) fn abort(mut self, cause: VmmError) -> VmmError {
        // If jailed, learn the cgroup from the still-live child before killing it, so a boot that
        // failed *after* the VMM came up (past `run_boot`'s cgroup read, or before it) still reaps the
        // cgroup the jailer created — it lives outside the scratch dir `remove_dir_all` reclaims.
        let cgroup = self.chroot.as_ref().and_then(|c| {
            c.cgroup_dir
                .clone()
                .or_else(|| self.child.as_ref().and_then(|ch| read_cgroup_dir(ch.id())))
        });
        // Flag before the reap, so an outstanding `KillHandle` can't signal a recycled pid.
        self.lifetime.mark_down();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // The tap lives outside the scratch dir, so `remove_dir_all` below won't reclaim it — delete
        // it explicitly (best-effort) on this boot-failure path too, or a failed boot leaks a tap.
        if let Some(tap) = self.tap.take() {
            tap.delete();
        }
        if let Some(cgroup) = cgroup {
            remove_cgroup(&cgroup);
        }
        self.lifetime.teardown();
        self.console.join();
        let fc_log = std::fs::read_to_string(self.workdir.join(FC_STDERR)).unwrap_or_default();
        let console = self.console.snapshot();
        // A jailed VM may hold read-only bind mounts in its chroot (shared base, restore mem/disk);
        // unmount each (lazy) before reclaiming the scratch dir, or `remove_dir_all` `EBUSY`s on the
        // mount point.
        for mount in self
            .chroot
            .as_ref()
            .map(|c| c.mounts.as_slice())
            .unwrap_or_default()
        {
            unmount_base(mount);
        }
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
    /// (hence the `mem::take`s — a `Drop` type can't be destructured). `config` supplies the
    /// host-side per-exec budgets (`exec_wall`, `output_cap`) the VM will enforce — on the restore
    /// path too, where everything guest-side comes from the snapshot but these bounds are the
    /// *host's*, so they follow the restoring caller's config, not the source's.
    pub(crate) fn into_running(
        mut self,
        boot_latency: Duration,
        config: &BootConfig,
    ) -> Result<RunningVm, VmmError> {
        let Some(child) = self.child.take() else {
            // Unreachable: `boot` only promotes a still-armed guard.
            return Err(VmmError::Vmm("VMM child already reclaimed".into()));
        };
        Ok(RunningVm {
            exec_wall: config.exec_wall,
            output_cap: config.output_cap,
            child,
            workdir: std::mem::take(&mut self.workdir),
            console: std::mem::take(&mut self.console),
            // `ApiClient` is a cheap-to-clone handle (just the socket path); the other fields can't
            // clone (a `Child`, owned buffers), so they `take()`. `self` still `Drop`s afterward.
            api: self.api.clone(),
            boot_latency,
            rootfs: std::mem::take(&mut self.rootfs),
            restored: self.restored,
            has_input: self.input_image.is_some(),
            vsock_uds: self.vsock_uds.take(),
            output: self.output.take(),
            tap: self.tap.take(),
            chroot: self.chroot.take(),
            // The armed machinery moves to the `RunningVm`; the guard keeps an inert placeholder
            // (its `Drop` skips teardown anyway once `child` is `None`).
            lifetime: std::mem::replace(&mut self.lifetime, VmLifetime::disarmed()),
        })
    }
}

/// Place the snapshot bundle's private root-disk copy at `backing` — the path Firecracker opens the
/// drive from during `PUT /snapshot/load` — creating parent dirs as needed. Refuses to overwrite an
/// existing file, so a still-live source VM's disk is never clobbered (drop the source first).
fn stage_restore_disk(copy: &Path, backing: &Path) -> Result<(), VmmError> {
    if let Some(parent) = backing.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            VmmError::Vmm(format!("stage restore disk dir {}: {e}", parent.display()))
        })?;
    }
    // `create_new` reserves the path **atomically**: if it already exists (a still-live source's
    // disk) the open fails rather than clobbering it — the "never overwrite" guarantee, race-free,
    // not a check-then-copy TOCTOU. A missing parent or any other error is surfaced as-is.
    let mut dst = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(backing)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(VmmError::Vmm(format!(
                "root disk path {} already exists; drop the source VM before restoring its snapshot",
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

/// Remove the staged restore disk (and its parent dir if now empty), once Firecracker holds the fd.
/// Best-effort: the open fd keeps the inode alive for the VM's lifetime, so a failure here leaks at
/// most an empty file/dir under `/tmp`, never the VM's disk. `remove_dir` only succeeds on an empty
/// dir, so it never touches a directory that still holds a live VM's files.
fn unstage_restore_disk(backing: &Path) {
    let _ = std::fs::remove_file(backing);
    if let Some(parent) = backing.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

/// The Firecracker `(major, minor)` the driver's API bodies are written against (decision 001).
/// Field names have drifted across releases and behavior genuinely changes (v1.9 rejects
/// `network_overrides` on snapshot load, decision 011), so an unexpected binary means cryptic
/// mid-boot API errors or silently different semantics — the runtime-validates-its-VMM guard,
/// the way containerd validates its runc (P6.9b).
const PINNED_FC_VERSION: (u64, u64) = (1, 9);

/// Arms [`warn_on_unpinned_firecracker`] exactly once per process: the pin is process-wide and the
/// probe costs a child spawn, so one loud warning at the first boot is the right dose.
static FC_VERSION_PROBE: std::sync::Once = std::sync::Once::new();

/// Warn — once per process, loudly, but never refuse — when `firecracker --version` reports a
/// different major/minor than [`PINNED_FC_VERSION`]. A warning rather than a typed error because an
/// embedder may knowingly run a compatible build; a *missing* or unrunnable binary stays silent
/// here, since the spawn itself fails with the legible typed error moments later.
fn warn_on_unpinned_firecracker(firecracker: &Path) {
    FC_VERSION_PROBE.call_once(|| {
        let Ok(out) = Command::new(firecracker).arg("--version").output() else {
            return;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let (pin_maj, pin_min) = PINNED_FC_VERSION;
        match fc_version_of(&text) {
            Some(v) if v == PINNED_FC_VERSION => {}
            Some((maj, min)) => tracing::warn!(
                found = %format!("v{maj}.{min}"),
                pinned = %format!("v{pin_maj}.{pin_min}"),
                "firecracker differs from the version the driver's API schema is pinned to \
                 (decision 001): request bodies and snapshot semantics may not match"
            ),
            None => tracing::warn!(
                binary = %firecracker.display(),
                "could not parse `firecracker --version`; the driver's API schema is pinned to \
                 v{pin_maj}.{pin_min} (decision 001)"
            ),
        }
    });
}

/// The `(major, minor)` out of `firecracker --version` output (first line `Firecracker v1.9.1`).
fn fc_version_of(text: &str) -> Option<(u64, u64)> {
    let rest = text.split("Firecracker v").nth(1)?;
    let mut parts = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Spawn `firecracker --api-sock <socket>`, wiring its serial console to a [`Console`] and its stderr
/// to `<workdir>/fc.stderr`. Shared by a cold boot ([`Spawned::launch`]) and a snapshot restore
/// ([`Spawned::launch_for_restore`]).
///
/// Firecracker's own logs go to a *file* (not our stderr, which is the host's tracing; and not a
/// pipe, which back-pressures a chatty VMM or feeds it EPIPE when dropped) — `abort` reads it back for
/// diagnostics. On a spawn/console failure the child (if any) is reaped so nothing leaks; the caller
/// owns `workdir` cleanup.
fn spawn_fc(
    firecracker: &Path,
    workdir: &Path,
    socket: &Path,
    netns: Option<&str>,
) -> Result<(Child, Console), VmmError> {
    // Firecracker binds the API socket (and the relative `v.sock`) here; both live under `workdir`,
    // and the API socket is the longer of the two, so checking it up front covers both.
    check_sun_path(socket)?;
    let fc_stderr = std::fs::File::create(workdir.join(FC_STDERR))
        .map_err(|e| VmmError::Vmm(format!("create firecracker stderr log: {e}")))?;
    // A networked VM runs Firecracker **inside its netns**: `ip netns exec <ns> firecracker …`
    // `setns`es into the namespace then execs firecracker, so the child pid *is* firecracker (the
    // piped stdout, cwd, and stderr redirect all carry through the exec) and its tap lives in the ns.
    let mut cmd = match netns {
        Some(ns) => {
            let mut c = Command::new("ip");
            c.arg("netns").arg("exec").arg(ns).arg(firecracker);
            c
        }
        None => Command::new(firecracker),
    };
    let mut child = cmd
        .arg("--api-sock")
        .arg(socket)
        // Run each VMM with its scratch dir as cwd, so a **relative** vsock socket path (`v.sock`)
        // resolves per-VM. That's what lets N warm clones restored from one snapshot each bind their
        // own socket instead of colliding on the source's absolute path (see `run_boot`'s `PUT /vsock`).
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped()) // guest serial console
        .stderr(Stdio::from(fc_stderr))
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // Without a netns the missing binary is firecracker; with one it's `ip` (already used
                // to build the tap, so this is unlikely) — name the one actually invoked.
                let missing = if netns.is_some() {
                    "ip (iproute2)".to_string()
                } else {
                    firecracker.display().to_string()
                };
                VmmError::Artifact(format!("not found: {missing}"))
            } else {
                VmmError::Vmm(format!("spawn firecracker: {e}"))
            }
        })?;
    let stdout = child.stdout.take();
    match Console::spawn(stdout) {
        Ok(console) => Ok((child, console)),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}

/// Linux caps `sockaddr_un.sun_path` at 108 bytes including the trailing NUL. Firecracker binds the
/// API and vsock sockets *inside* the scratch dir, so a long scratch base (a relocated
/// `AGENT_SCRATCH_DIR`, or the jailer's deep chroot path) can overflow it — and the `bind()` then
/// fails deep inside Firecracker, surfacing to us as a cryptic "socket never appeared" boot timeout.
const SUN_PATH_MAX: usize = 108;

/// Fail fast with an actionable error if `socket` wouldn't fit in `sun_path` (see [`SUN_PATH_MAX`]),
/// instead of letting the bind fail obscurely mid-boot. Names the scratch-dir knob as the fix.
pub(crate) fn check_sun_path(socket: &Path) -> Result<(), VmmError> {
    let len = socket.as_os_str().len();
    if len + 1 > SUN_PATH_MAX {
        return Err(VmmError::Vmm(format!(
            "unix socket path {} is too long ({len} bytes; the kernel's limit is {}); \
             use a shorter scratch dir via AGENT_SCRATCH_DIR",
            socket.display(),
            SUN_PATH_MAX - 1
        )));
    }
    Ok(())
}

/// Create the per-VM scratch dir. Two constraints shape it:
/// - **Short path** (`/tmp/agent-<pid>-<n>`): the API socket lives here and
///   `sockaddr_un.sun_path` caps at ~108 bytes, so a deep `TMPDIR`-based path would make
///   Firecracker's `bind()` fail with EINVAL.
/// - **Fail-if-exists, mode `0700`**: `/tmp` is world-writable and PIDs recycle, so a
///   pre-existing path (squatted by another user, or stale from a killed run) must never be
///   silently adopted — the rootfs copy and socket go here. A collision just advances to the
///   next sequence number.
fn create_workdir(base: &Path) -> Result<PathBuf, VmmError> {
    use std::os::unix::fs::DirBuilderExt;
    for _ in 0..1024 {
        let workdir = base.join(format!(
            "agent-{}-{}",
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
            // A missing/unwritable scratch base is the operator's to fix (e.g. `AGENT_SCRATCH_DIR`
            // points nowhere): name it in the error rather than failing cryptically deep in boot.
            Err(e) => {
                return Err(VmmError::Vmm(format!(
                    "create scratch dir {} (is {} present and writable?): {e}",
                    workdir.display(),
                    base.display()
                )))
            }
        }
    }
    Err(VmmError::Vmm(format!(
        "no fresh scratch dir under {} after 1024 attempts (stale agent-* dirs?)",
        base.display()
    )))
}

/// The scratch dir's basename — the VM's process-unique identity, shared by its tracing span, its
/// jail id, and its lifetime cgroup, so one name finds all of a VM's residue.
fn workdir_name(workdir: &Path) -> String {
    workdir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Fail fast if the boot deadline has already passed before the next step (`what`). Each API call is
/// individually time-capped by the client, but their *sum* must also respect the boot deadline, or a
/// slow VMM could stretch `boot` well past `wall`.
fn still_before(deadline: Instant, what: &str) -> Result<(), VmmError> {
    if Instant::now() >= deadline {
        return Err(VmmError::Timeout(format!(
            "boot deadline expired before {what}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod version_tests {
    use super::fc_version_of;

    #[test]
    fn fc_version_parses_the_real_output_shape() {
        assert_eq!(fc_version_of("Firecracker v1.9.1"), Some((1, 9)));
        assert_eq!(
            fc_version_of("Firecracker v1.9.1\nmore lines"),
            Some((1, 9))
        );
        assert_eq!(fc_version_of("Firecracker v1.13.0"), Some((1, 13)));
        for garbage in ["", "garbage", "Firecracker v", "Firecracker vX.Y"] {
            assert_eq!(fc_version_of(garbage), None, "{garbage:?} must not parse");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TestDir;

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
    fn workdirs_are_fresh_private_and_distinct() {
        let base = Path::new("/tmp");
        let a = TestDir::adopt(create_workdir(base).expect("first workdir"));
        let b = TestDir::adopt(create_workdir(base).expect("second workdir"));
        assert_ne!(a.path(), b.path(), "each VM gets its own scratch dir");
        let mode = std::fs::metadata(a.path())
            .expect("stat workdir")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "scratch dir must be private to us");
    }

    #[test]
    fn create_workdir_names_a_missing_base_in_its_error() {
        let err = create_workdir(Path::new("/no/such/scratch/base")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/no/such/scratch/base"),
            "error names the base: {msg}"
        );
    }

    #[test]
    fn overlong_socket_path_is_a_clear_error_not_a_cryptic_bind_failure() {
        // A short path is fine; a path past the kernel's sun_path limit is rejected up front with an
        // actionable message (name the knob), not a bind failure surfacing as a boot timeout.
        assert!(check_sun_path(Path::new("/tmp/agent-1-0/fc.sock")).is_ok());
        let long = PathBuf::from(format!("/{}/fc.sock", "x".repeat(SUN_PATH_MAX)));
        let err = check_sun_path(&long).unwrap_err().to_string();
        assert!(err.contains("too long"), "explains the limit: {err}");
        assert!(err.contains("AGENT_SCRATCH_DIR"), "names the fix: {err}");
    }
}
