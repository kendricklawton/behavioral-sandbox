//! The boot/restore state machine beneath [`Vm`](crate::Vm): [`Spawned`] spawns a `firecracker`
//! child (directly, jailed, or for a snapshot restore), drives it through the boot sequence, and
//! either promotes it to a [`RunningVm`] or tears it down on failure, so a half-booted VM is never
//! observable. Split out of `vm.rs` to keep that module the public surface (config + `Vm`/`RunningVm`
//! API) while this holds the ~700-line orchestration.
//!
//! `Spawned`'s `Drop` is the panic safety net: anything that unwinds between `launch` and
//! `abort`/`into_running` still kills the VMM and reclaims its scratch dir. Every free helper here
//! (scratch-dir creation, the `sun_path` guard, the shared `teardown`) serves that lifecycle.

use std::num::NonZeroU32;
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
    snapshot_api_timeout, Action, ApiClient, BootSource, Drive, MachineConfig, MemBackend,
    MemBackendType, NetworkInterface, RateLimiter, SnapshotLoad, Vsock,
};
use crate::jail::{
    cgroup_limit_args, give_to_jail, jailer_cgroup_dir, read_cgroup_dir, remove_cgroup,
    restore_mem_mib, spawn_jailer, stage_into_chroot, stage_ro_base_into_chroot, Chroot, Jail,
    JAILED_VSOCK_UDS,
};
use crate::lifetime::VmLifetime;
use crate::net::Tap;
use crate::paths::{absolute, path_str, require_file};
use crate::vm::{
    reclaim_scratch, teardown, BootConfig, RunningVm, Snapshot, FC_STDERR, IFACE_ID, VM_SEQ,
    VSOCK_UDS,
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
    /// The jail (chroot + dropped uid/gid + cgroup) when `jail` was set; `None` for a direct
    /// boot. Its cgroup lives outside `workdir`, so every teardown path removes it explicitly.
    chroot: Option<Chroot>,
    /// The cgroup-owned lifetime machinery, armed at spawn so the crash-safety window is as
    /// small as possible; moved onto the [`RunningVm`] by `into_running`.
    lifetime: VmLifetime,
}

/// Whether a `PUT /drives/{id}` attaches the boot disk or a data device, one half of the typed
/// pair `put_drive` takes in place of Firecracker's two positional booleans (`is_root_device`,
/// `is_read_only`), whose bare `true`/`false` call sites were silently swappable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DriveKind {
    Root,
    Data,
}

/// Whether the guest may write the attached device, the other half of the [`DriveKind`] pair.
/// `ReadOnly` is what makes the bulk-input device provably immutable (Firecracker opens it
/// `O_RDONLY`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DriveAccess {
    ReadOnly,
    ReadWrite,
}

/// The common product of a jailed spawn, everything [`launch_jailed`](Spawned::launch_jailed) and
/// [`launch_jailed_for_restore`](Spawned::launch_jailed_for_restore) build a [`Spawned`] from
/// identically. Each caller adds only the values the two paths differ in (rootfs, `restored`, the
/// vsock path); this carries the rest so [`spawn_jailed`](Spawned::spawn_jailed) owns the skeleton.
struct JailedSpawn {
    child: Child,
    console: Console,
    workdir: PathBuf,
    /// The API socket path, for [`ApiClient::new`].
    socket: PathBuf,
    /// The chroot root the caller derives its vsock path from and moves into the [`Chroot`].
    chroot_root: PathBuf,
    tap: Option<Tap>,
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
    pub(crate) fn launch(config: &BootConfig, deadline: Instant) -> Result<Self, VmmError> {
        let fetch = Some("run `cargo xtask fetch-artifacts`");
        require_file(&config.kernel, "kernel image", fetch)?;
        require_file(&config.rootfs, "rootfs image", fetch)?;
        warn_on_unpinned_firecracker(&config.firecracker);

        // Jailed boot spawns the jailer (not firecracker directly) and stages resources into the
        // chroot later, under `run_boot`'s deadline checks; the unjailed setup below is untouched.
        // Every boot feature composes with the jail, so there is no combination to refuse first.
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
            // The whole-rootfs copy is the heaviest host-side step and unbounded on its own (a
            // multi-GiB image on slow storage), so it runs under the shared boot deadline: check
            // before it, and each later staging step re-checks, so a copy that blows the budget
            // surfaces as a typed `Timeout` instead of an unbounded host hang.
            if let Err(e) = still_before(deadline, "rootfs copy") {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(e);
            }
            let copy = workdir.join("rootfs.ext4");
            if let Err(e) = std::fs::copy(&config.rootfs, &copy) {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(VmmError::Vmm(format!(
                    "copy rootfs to {}: {e}",
                    copy.display()
                )));
            }
            // `fs::copy` propagates the source's mode; a read-only pinned base (0444) would make the
            // read-write root drive unopenable. The copy is ours alone, force owner read-write.
            if let Err(e) = std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600))
            {
                let _ = std::fs::remove_dir_all(&workdir);
                return Err(VmmError::Vmm(format!("chmod rootfs copy: {e}")));
            }
            copy
        };

        // Bulk read-only input: build an ext4 from the host `input_dir` and attach it as a
        // second block device (`/dev/vdb`). Lives in the scratch dir, so teardown reclaims it too.
        let input_image = match &config.input_dir {
            None => None,
            Some(dir) => {
                if let Err(e) = still_before(deadline, "input image build") {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
                match build_input_image(dir, &workdir) {
                    Ok(img) => Some(img),
                    Err(e) => {
                        let _ = std::fs::remove_dir_all(&workdir);
                        return Err(e);
                    }
                }
            }
        };

        // Bulk writable output: build a blank ext4 the guest mounts read-write at `/output`,
        // attached as another block device. Its host destination rides along for `collect_outputs`.
        let output = match &config.output_dir {
            None => None,
            Some(dest) => {
                if let Err(e) = still_before(deadline, "output image build") {
                    let _ = std::fs::remove_dir_all(&workdir);
                    return Err(e);
                }
                match build_output_image(&workdir) {
                    Ok(image) => Some(OutputDevice {
                        image,
                        dest: dest.clone(),
                    }),
                    Err(e) => {
                        let _ = std::fs::remove_dir_all(&workdir);
                        return Err(e);
                    }
                }
            }
        };

        // Per-VM network namespace + tap for the guest's virtio-net (netns model), when enabled.
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
                // Route through `reclaim_scratch` (not a bare `tap.delete()` + `remove_dir_all`) so
                // the dir is kept if the netns delete fails: a failed boot must not strand a
                // dir-less netns any more than teardown may (the invariant `reclaim_scratch` owns).
                reclaim_scratch(&workdir, tap.as_ref());
                return Err(e);
            }
        };

        // Cgroup-owned lifetime: enroll the VMM in a per-VM lifetime cgroup and arm the
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

    /// The jailed cold-boot counterpart of [`launch`](Self::launch): spawn the **jailer**,
    /// which builds the chroot, `mknod`s the device nodes, places the VMM in a cgroup, and drops
    /// privileges before `exec`ing Firecracker. Resources (kernel, rootfs) are staged into the chroot
    /// in [`run_boot`](Self::run_boot), once the API socket proves the chroot exists, so no staging
    /// races the jailer's construction. The vsock exec channel composes (its host-side socket path is
    /// set here, the device configured in `run_boot`); a NIC composes (the tap lives in a per-VM
    /// netns the jailer joins via `--netns`); and the bulk-I/O images are built in place **inside
    /// the chroot** in `run_boot` (they can't exist before the jailer builds it).
    fn launch_jailed(config: &BootConfig, jail: &Jail) -> Result<Self, VmmError> {
        // CPU/memory limits derived from the guest's own resource envelope (vcpus, mem_mib);
        // empty when the host doesn't delegate the cgroup controllers, so the jailed boot still runs.
        let cgroup_args = cgroup_limit_args(config.vcpus, config.mem_mib);
        let s = Self::spawn_jailed(config, jail, config.enable_network, &cgroup_args)?;
        // The exec channel's vsock socket, when enabled: Firecracker (cwd = chroot root after the
        // jailer chroots) binds it at the chroot-relative `JAILED_VSOCK_UDS`, and the host dials the
        // same file at its absolute path under the chroot. That path is strictly shorter than the API
        // socket `spawn_jailer` already bounds-checked, so no separate `check_sun_path` is needed.
        let vsock_uds = config
            .guest_cid
            .map(|_| s.chroot_root.join(JAILED_VSOCK_UDS.trim_start_matches('/')));
        Ok(Self {
            child: Some(s.child),
            console: s.console,
            workdir: s.workdir,
            // Staged into the chroot in `run_boot` and named by its chroot-relative path; this
            // placeholder is not a host device path (a jailed VM refuses snapshotting).
            rootfs: PathBuf::from("/rootfs.ext4"),
            restored: false,
            api: ApiClient::new(s.socket),
            vsock_uds,
            input_image: None,
            output: None,
            tap: s.tap,
            chroot: Some(Chroot::new(s.chroot_root, jail)),
            lifetime: s.lifetime,
        })
    }

    /// The shared skeleton of the two jailed launch paths ([`launch_jailed`](Self::launch_jailed) and
    /// [`launch_jailed_for_restore`](Self::launch_jailed_for_restore)): a fresh scratch dir, the per-VM
    /// netns + tap when `networked`, the **jailer** (whose `cgroup_args` differ, real caps on a cold
    /// boot, none on a restore whose envelope rides the snapshot), and the cgroup-watching lifetime.
    /// Owns the inline cleanup, so a failure at any step reclaims the tap and workdir. Each caller adds
    /// only the three values the two paths differ in (rootfs, `restored`, and the vsock path), so a
    /// change to jailed spawning is made once here rather than kept in sync across two copies.
    fn spawn_jailed(
        config: &BootConfig,
        jail: &Jail,
        networked: bool,
        cgroup_args: &[String],
    ) -> Result<JailedSpawn, VmmError> {
        let workdir = create_workdir(&config.scratch_dir)?;
        // The jail id is the scratch-dir name: process-unique, a valid jailer id (alphanumeric + `-`),
        // and the netns name, one name finds all of a VM's residue. The jailer nests the chroot under
        // `<workdir>/firecracker/<id>/root`.
        let id = workdir_name(&workdir);
        // Networked jailed VM: create the per-VM netns + tap **before** the jailer so it can join
        // (`--netns`). The tap is owned by the jailed uid/gid because a jailed Firecracker is
        // unprivileged (no `CAP_NET_ADMIN`) and can only attach a tap it owns. A failed create reclaims
        // its own netns; we still own the workdir.
        let tap = if networked {
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
            cgroup_args,
            netns.as_deref(),
        ) {
            Ok(t) => t,
            Err(e) => {
                // Route through `reclaim_scratch` (not a bare `tap.delete()` + `remove_dir_all`) so
                // the dir is kept if the netns delete fails: a failed boot must not strand a
                // dir-less netns any more than teardown may (the invariant `reclaim_scratch` owns).
                reclaim_scratch(&workdir, tap.as_ref());
                return Err(e);
            }
        };
        // Cgroup-owned lifetime, jailed flavour: the jailer creates the VM's cgroup and moves
        // the VMM into it itself, so enrolling the pid in a driver cgroup would race that placement
        // (last write wins membership and could yank the VMM out of its limits). The sentinel instead
        // watches the jailer's cgroup at its precomputed path; the unprotected window is
        // spawn → the jailer's self-placement (milliseconds).
        let lifetime = VmLifetime::watch(
            child.id(),
            jailer_cgroup_dir(&config.firecracker, &id)
                .into_iter()
                .collect(),
        );
        Ok(JailedSpawn {
            child,
            console,
            workdir,
            socket,
            chroot_root,
            tap,
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
        // Jailed restore spawns the jailer instead, so a prewarmed clone is confined from its
        // first instruction; the unjailed path below is untouched.
        if let Some(jail) = config.jail.as_ref() {
            return Self::launch_jailed_for_restore(config, snapshot, jail);
        }
        let workdir = create_workdir(&config.scratch_dir)?;
        // A networked snapshot baked in its tap's `host_dev_name` (v1.9 has no `network_overrides`), so
        // restore must present a tap with that name, trivially satisfied by the netns model: recreate
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
                // Route through `reclaim_scratch` (not a bare `tap.delete()` + `remove_dir_all`) so
                // the dir is kept if the netns delete fails: a failed boot must not strand a
                // dir-less netns any more than teardown may (the invariant `reclaim_scratch` owns).
                reclaim_scratch(&workdir, tap.as_ref());
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
    /// snapshot's baked-in tap is recreated in a fresh per-VM netns the jailer joins (decision 017),
    /// owned by the jailed uid.
    ///
    /// The cgroup **resource caps** are re-applied here, derived from the *clone's true envelope*
    /// rather than `config`, the guest's vCPUs and RAM come from the snapshot (restore issues no
    /// `PUT /machine-config`, and nothing forces `config` to agree with the source), so caps derived
    /// from a mis-declaring `config` would throttle or OOM-kill a legitimate clone. `cpu.max` uses the
    /// snapshot's recorded vCPU count and `memory.max` the memory file's true guest RAM; `pids.max`
    /// is a constant. Fail-open like a cold boot's caps (empty without delegated controllers,
    /// decision 013), the isolation walls (chroot, uid drop, seccomp, netns) are all present either way.
    fn launch_jailed_for_restore(
        config: &BootConfig,
        snapshot: &Snapshot,
        jail: &Jail,
    ) -> Result<Self, VmmError> {
        // Re-apply the resource caps a cold jailed boot gets, so a restored clone (where the
        // untrusted code runs) is confined too, not just isolated, the co-resident-safety property
        // (P15.8). Both caps derive from the snapshot's true envelope, never `config`'s declaration:
        // `memory.max` from the memory file's true size (`restore_mem_mib`, never below what the
        // clone actually uses, the OOM hazard that once kept restore uncapped), `cpu.max` from the
        // vCPU count recorded in the bundle (the clone's real parallelism; a `config` defaulting to
        // fewer vCPUs than the source must not silently throttle it), and `pids.max` is a constant.
        // A networked clone gets the fixed-name tap in a fresh netns; its baked-in guest identity is
        // already correct there (decision 017).
        let mem_len = std::fs::metadata(&snapshot.mem)
            .map(|m| m.len())
            .unwrap_or(0);
        let cgroup_args =
            cgroup_limit_args(snapshot.vcpus, restore_mem_mib(config.mem_mib, mem_len));
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
            chroot: Some(Chroot::new(s.chroot_root, jail)),
            lifetime: s.lifetime,
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
        deadline: Instant,
    ) -> Result<Duration, VmmError> {
        let span = tracing::info_span!("restore", vm = %self.vm_name());
        let _span = span.enter();

        // The deadline is computed once by the caller (`boot_deadline`) so it spans the pre-spawn
        // staging (`launch_for_restore`) and this restore together, one wall (decision 013).
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Resolve every fallible input (the deadline, the snapshot paths) *before* staging the disk,
        // so that once the ~disk-sized copy is on disk there is no `?` between the stage and the
        // matching unstage that could leak the staged file *outside our reach*, the unjailed baked
        // path lives outside this VM's workdir. (Jailed staging is all inside the chroot, which the
        // workdir's `remove_dir_all` reclaims on any abort, so the discipline holds structurally.)
        still_before(deadline, "PUT /snapshot/load")?;

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
        let mut disk_unstage: Option<PathBuf> = None;
        if let Some(chroot) = self.chroot.as_ref() {
            let (root, uid, gid) = (chroot.root.clone(), chroot.uid, chroot.gid);
            let workdir = self.workdir.clone();
            // The jailed Firecracker re-binds the baked-in relative `v.sock` at its cwd, the chroot
            // root, so that dir must be writable by the dropped uid; chown it explicitly rather than
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
            // Record the bind mount into `chroot.mounts` *now*, before the fallible steps below: an
            // early error (a strip/create_dir_all/disk-stage failure) returns straight to `abort`,
            // which unmounts only what `chroot.mounts` holds, a mount recorded lazily at the end
            // would be orphaned, and `remove_dir_all(workdir)` would then `EBUSY` and leak the chroot.
            // (`run_boot` records each mount the same eager way.)
            if let Some(chroot) = self.chroot.as_mut() {
                chroot.mounts.extend(mem_mount);
            }
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
                // Same eager recording as the memory mount above: the shared-base disk bind must be
                // detachable by teardown/abort the instant it exists, not only if we reach the end.
                if let Some(chroot) = self.chroot.as_mut() {
                    chroot.mounts.extend(disk_mount);
                }
            } else {
                stage_restore_disk(&snapshot.root_drive, &disk_target)?;
                give_to_jail(&disk_target, uid, gid, 0o600)?;
                disk_unstage = Some(disk_target);
            }
            // Mounts were recorded eagerly above; here just learn the jailer's cgroup so teardown
            // can remove it too.
            self.learn_jailer_cgroup();
        } else {
            state_arg = path_str(&snapshot.state)?.to_string();
            mem_arg = path_str(&snapshot.mem)?.to_string();
            if !snapshot.shared_base {
                stage_restore_disk(&snapshot.root_drive, &snapshot.root_backing)?;
                disk_unstage = Some(snapshot.root_backing.clone());
            }
        }
        // `/snapshot/load` blocks until Firecracker reads the whole memory file back, so scale its
        // socket timeout by that file's true size (the bundle's, never the restoring `config`'s,
        // which may under-declare) rather than the instant-reply default.
        let mem_mib = std::fs::metadata(&snapshot.mem)
            .map(|m| u32::try_from(m.len() >> 20).unwrap_or(u32::MAX))
            .unwrap_or(0);
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
            },
            snapshot_api_timeout(mem_mib),
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
        let mut backoff = PollBackoff::new();
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
                        // Deadline expired: a **timeout** (the documented `Vm::restore` contract,
                        // whose `kind()` is `Infra`), not the retryable `GuestUnavailable` that `e`
                        // typically is; keep `e` as detail so the last failure stays legible.
                        return Err(VmmError::Timeout(format!(
                            "guest agent not ready before the restore deadline: {e}"
                        )));
                    }
                    backoff.sleep();
                }
            }
        }
    }

    /// `PUT /drives/{id}`, attach a virtio-block device, deriving the API path from `id` so the URL
    /// and the body's `drive_id` are the same token and can't drift apart. `still_before` first, so a
    /// boot already past its deadline fails fast with this drive named. Takes the typed
    /// [`DriveKind`]/[`DriveAccess`] pair rather than two bare `bool`s a call site could silently
    /// swap; the booleans reappear only in the wire [`Drive`] body, whose serde field names pin them.
    fn put_drive(
        &self,
        id: &str,
        path_on_host: &str,
        kind: DriveKind,
        access: DriveAccess,
        deadline: Instant,
    ) -> Result<(), VmmError> {
        still_before(deadline, &format!("PUT /drives/{id}"))?;
        self.api.put(
            &format!("/drives/{id}"),
            &Drive {
                drive_id: id,
                path_on_host,
                is_root_device: kind == DriveKind::Root,
                is_read_only: access == DriveAccess::ReadOnly,
                // Bound the guest's IO to every drive with the derived default (defense in depth: a
                // disk-thrashing guest can't starve a co-resident run). Set once at cold boot, but it
                // *rides restore*: a clone reopens the drive from the snapshot state file, which
                // carries this rate limiter (unlike the cgroup caps, which a restore does not
                // re-apply). A boot-sized burst keeps normal boot/exec unthrottled.
                rate_limiter: Some(RateLimiter::default_guest_io()),
            },
        )
    }

    /// Learn the cgroup the jailer actually placed the VMM in (from `/proc/<pid>/cgroup`, now that
    /// Firecracker runs in its final cgroup) so teardown can remove it. The lifetime sentinel watches
    /// the *precomputed* jailer path from spawn; if the jailer put the VMM somewhere else, the
    /// sentinel is not guarding it, warn (driver death would leak this VMM), never hide it. Shared by
    /// the cold boot and the snapshot restore, which learn it at the same point.
    fn learn_jailer_cgroup(&mut self) {
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
    }

    /// Drive the API through the boot sequence and wait for the userspace marker; returns the
    /// boot-to-userspace latency.
    pub(crate) fn run_boot(
        &mut self,
        config: &BootConfig,
        deadline: Instant,
    ) -> Result<Duration, VmmError> {
        // One span per boot, keyed by the scratch-dir name, so interleaved logs from concurrent
        // VMs (the prewarmed pool) stay attributable to their sandbox.
        let span = tracing::info_span!("boot", vm = %self.vm_name());
        let _span = span.enter();

        // The deadline spans host-side staging (`launch`) *and* this API boot: it's computed once by
        // the caller (`boot_deadline`) and threaded in, so both share one wall (decision 013).
        self.await_api_socket(deadline)?;
        tracing::debug!("api socket ready");

        // Kernel + rootfs paths as Firecracker will name them. Unjailed: absolute host paths (its cwd
        // is the scratch dir); `self.rootfs` is already absolute from `launch`. Jailed: stage each into
        // the chroot (safe now that the API socket proved the chroot exists, no race with the jailer's
        // construction) and name it by its chroot-relative path, and record the jailer's cgroup for
        // teardown. A `read_only_root` jailed boot bind-mounts the shared base zero-copy (the memory-sharing
        // path); a read-write boot stages a private copy.
        let kernel_arg: String;
        let rootfs_arg: String;
        if let Some(chroot) = self.chroot.as_ref() {
            let (root, uid, gid) = (chroot.root.clone(), chroot.uid, chroot.gid);
            // Read-only kernel (0444), chowned to the jailed uid so the dropped-privilege Firecracker
            // can open it.
            kernel_arg = stage_into_chroot(&root, "kernel", &config.kernel, uid, gid, 0o444)?;
            // The root disk: bind-mount the shared read-only base (shared-base path) when `read_only_root`,
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
            // Bulk I/O under the jail: build the input/output ext4 images **in place inside
            // the chroot**, the builders are rootless `mke2fs` runs that take a target dir, so no
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
            self.learn_jailer_cgroup();
        } else {
            let kernel = absolute(&config.kernel)?;
            kernel_arg = path_str(&kernel)?.to_string();
            rootfs_arg = path_str(&self.rootfs)?.to_string();
        }
        let kernel = kernel_arg.as_str();
        let rootfs = rootfs_arg.as_str();
        // A read-only root hands off to the overlay init, which stacks a size-capped tmpfs over the
        // RO base so `/` is writable per-run (the cap's derivation lives in `overlay_size_mib`). It
        // rides the kernel command line as a `key=value` token, which the kernel routes into PID 1's
        // environment (so `overlay-init` reads `$overlay_size` without mounting `/proc` first).
        let mut boot_args = if config.read_only_root {
            format!(
                "{} init=/sbin/overlay-init overlay_size={}M",
                config.boot_args,
                overlay_size_mib(config.mem_mib)
            )
        } else {
            config.boot_args.clone()
        };
        // Static guest addressing when a NIC is attached: the kernel configures `eth0` before
        // userspace via `CONFIG_IP_PNP`. The gateway field is **empty**, so the kernel installs only
        // the connected /30 route (guest ⇄ host over the tap) and **no default route**, the guest
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
        let root_access = if config.read_only_root {
            DriveAccess::ReadOnly
        } else {
            DriveAccess::ReadWrite
        };
        self.put_drive("rootfs", rootfs, DriveKind::Root, root_access, deadline)?;
        // Bulk read-only input: attach the built image as `/dev/vdb`. `is_read_only` is what
        // makes the input provably immutable (Firecracker opens it `O_RDONLY`) and sidesteps the
        // read-back-a-dirty-ext4 hazard that a writable device would carry into the bulk-output path. Jailed, the
        // image sits at the chroot root, so its API name is the fixed chroot-relative path; unjailed
        // it is the absolute workdir path (self.input_image holds the host-side path either way).
        if let Some(image) = self.input_image.as_ref() {
            let input = if self.chroot.is_some() {
                "/input.ext4".to_string()
            } else {
                path_str(image)?.to_string()
            };
            self.put_drive(
                "input",
                &input,
                DriveKind::Data,
                DriveAccess::ReadOnly,
                deadline,
            )?;
        }
        // Bulk writable output: attach the blank image read-write. The guest mounts it by
        // label (`agent-output`), so the `/dev/vdX` letter this lands on doesn't matter, a boot may
        // attach input, output, both, or neither. Durability of the guest's writes is the guest's
        // `-o sync` mount plus a clean unmount on shutdown; `collect_outputs` reads it after the VMM
        // exits (never while it holds the file open, see `RunningVm::collect_outputs`).
        if let Some(out) = self.output.as_ref() {
            let output = if self.chroot.is_some() {
                "/output.ext4".to_string()
            } else {
                path_str(&out.image)?.to_string()
            };
            self.put_drive(
                "output",
                &output,
                DriveKind::Data,
                DriveAccess::ReadWrite,
                deadline,
            )?;
        }
        still_before(deadline, "PUT /machine-config")?;
        self.api.put(
            "/machine-config",
            &MachineConfig {
                vcpu_count: u32::from(config.vcpus.get()),
                mem_size_mib: config.mem_mib.get(),
            },
        )?;

        if let Some(cid) = config.guest_cid {
            still_before(deadline, "PUT /vsock")?;
            // Bind the socket relative to the VMM's cwd. Unjailed: the **relative** name `v.sock` in
            // the scratch dir, baking a relative path into the snapshot is what lets prewarmed clones
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

        // Per-VM virtio-net, backed by the host tap created in `launch`. Deny-by-default: the
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
            vcpus = config.vcpus.get(),
            mem_mib = config.mem_mib.get(),
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

    /// Poll `connect()` (not path-existence, the file can appear before `listen()`) until the API
    /// answers, failing fast if Firecracker already exited.
    fn await_api_socket(&mut self, deadline: Instant) -> Result<(), VmmError> {
        let mut backoff = PollBackoff::new();
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
            backoff.sleep();
        }
    }

    /// Wait for the console to show the userspace marker, bounded by `deadline` and by the child
    /// exiting early (a guest that panics before userspace).
    fn await_userspace(&mut self, marker: &str, deadline: Instant) -> Result<(), VmmError> {
        let mut backoff = PollBackoff::new();
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
            backoff.sleep();
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
    /// most boot failures, Firecracker's stderr tail and the guest console tail (the kernel's
    /// last words are exactly what a pre-marker hang needs), then reclaim the scratch dir, in
    /// that order, because the stderr log lives *in* the scratch dir.
    pub(crate) fn abort(mut self, cause: VmmError) -> VmmError {
        // If jailed, learn the cgroup from the still-live child before killing it, so a boot that
        // failed *after* the VMM came up (past `run_boot`'s cgroup read, or before it) still reaps the
        // cgroup the jailer created, it lives outside the scratch dir `remove_dir_all` reclaims.
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
        if let Some(chroot) = self.chroot.as_ref() {
            chroot.unmount_all();
        }
        // Delete the tap/netns and reclaim the scratch dir through the *same* gated path as
        // `teardown`: a transient `ip netns del` failure keeps the dir so the orphan sweep can
        // reclaim the pair, instead of leaking a dir-less netns a failed boot could otherwise strand.
        reclaim_scratch(&self.workdir, self.tap.as_ref());

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
    /// (hence the `mem::take`s, a `Drop` type can't be destructured). `config` supplies the
    /// host-side per-exec budgets (`exec_wall`, `output_cap`) the VM will enforce, on the restore
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
            // On a cold boot this is the true guest envelope (`PUT /machine-config` set it); on a
            // restore it merely mirrors `config` and is never read (a restored VM refuses
            // snapshotting, the field's one consumer).
            vcpus: config.vcpus,
            mem_mib: config.mem_mib,
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

/// Place the snapshot bundle's private root-disk copy at `backing`, the path Firecracker opens the
/// drive from during `PUT /snapshot/load`, creating parent dirs as needed. Refuses to overwrite an
/// existing file, so a still-live source VM's disk (or a concurrent restore of the same snapshot,
/// which would target the identical baked-in path) is never clobbered. This is why an unjailed
/// read-write restore is single-flight; a jailed restore re-roots the path per chroot, so it isn't.
fn stage_restore_disk(copy: &Path, backing: &Path) -> Result<(), VmmError> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = backing.parent() {
        ensure_private_staging_dir(parent)?;
    }
    // `create_new` reserves the path **atomically**: if it already exists (a still-live source's
    // disk) the open fails rather than clobbering it, the "never overwrite" guarantee, race-free,
    // not a check-then-copy TOCTOU. `mode(0o600)` keeps the staged disk unreadable to other local
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
                 single-flight (v1.9 reopens the disk at this baked-in path); restore clones \
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
/// (`/tmp/agent-<srcpid>-<seq>`, from the snapshot's source) and `/tmp` is world-writable, so a
/// blind `create_dir_all` would silently adopt an attacker-planted world-writable dir, letting a
/// local user rename-swap the staged disk before `PUT /snapshot/load` opens it (guest boots an
/// attacker's rootfs). This mirrors `create_workdir`'s posture; the only pre-existing dir it may
/// legitimately meet is a lingering-empty one from a prior restore of the same snapshot (still ours,
/// still `0700`), and the disk's own `create_new` keeps that case single-flight.
fn ensure_private_staging_dir(dir: &Path) -> Result<(), VmmError> {
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
/// mid-boot API errors or silently different semantics, the runtime-validates-its-VMM guard: a
/// runtime pinning and checking the version of the lower-level binary it drives.
const PINNED_FC_VERSION: (u64, u64) = (1, 9);

/// Arms [`warn_on_unpinned_firecracker`] exactly once per process: the pin is process-wide and the
/// probe costs a child spawn, so one loud warning at the first boot is the right dose.
static FC_VERSION_PROBE: std::sync::Once = std::sync::Once::new();

/// Warn, once per process, loudly, but never refuse, when `firecracker --version` reports a
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
/// Single-sourced here (the driver's own boot-time pin check) so `doctor`'s readiness probe reports
/// the exact same version the driver validates against, the two surfaces can't drift.
pub(crate) fn fc_version_of(text: &str) -> Option<(u64, u64)> {
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
/// pipe, which back-pressures a chatty VMM or feeds it EPIPE when dropped), `abort` reads it back for
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
        // resolves per-VM. That's what lets N prewarmed clones restored from one snapshot each bind their
        // own socket instead of colliding on the source's absolute path (see `run_boot`'s `PUT /vsock`).
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped()) // guest serial console
        .stderr(Stdio::from(fc_stderr))
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // Without a netns the missing binary is firecracker; with one it's `ip` (already used
                // to build the tap, so this is unlikely), name the one actually invoked.
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
/// `AGENT_SCRATCH_DIR`, or the jailer's deep chroot path) can overflow it, and the `bind()` then
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
///   silently adopted, the rootfs copy and socket go here. A collision just advances to the
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
                // fail-if-exists create makes 0700 unconditional (and race-free, the dir is
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

/// The scratch dir's basename, the VM's process-unique identity, shared by its tracing span, its
/// jail id, and its lifetime cgroup, so one name finds all of a VM's residue.
fn workdir_name(workdir: &Path) -> String {
    workdir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// The read-only-root overlay's tmpfs cap, in MiB: **half of guest RAM**, the guest has no swap,
/// so a tmpfs sized near RAM would OOM the guest rather than bound a runaway write, **floored at
/// 1 MiB**, so the integer division can never hand the overlay a size of `0M` (a zero-sized tmpfs
/// would leave the guest's `/` read-only and unwritable). The floor only fires at `mem_mib == 1`,
/// which can't boot Linux anyway; it exists so the derivation has no degenerate value at all.
/// Pure, so the arithmetic is unit-tested without a boot.
fn overlay_size_mib(mem_mib: NonZeroU32) -> u32 {
    (mem_mib.get() / 2).max(1)
}

/// A readiness-poll interval that starts tight and backs off to a cap. A wait that resolves quickly (a
/// snapshot resume whose agent is already reachable, an API socket already up) is caught within ~a
/// millisecond of becoming ready instead of being quantized to a coarse fixed interval; a long wait (a
/// cold boot to userspace) settles at the cap and keeps polling cheaply. Motivated by the latency
/// decomposition: a flat 20 ms poll adds up to 20 ms (~10 ms on average) of pure quantization to every
/// start, a large slice of a ~40 ms restore, and needless jitter on the boot tail. The `contains`/
/// `connect` check each tick is cheap, so a finer interval near readiness costs nothing that matters.
struct PollBackoff {
    next: Duration,
}

impl PollBackoff {
    /// The first interval: tight enough to catch near-immediate readiness within ~a millisecond.
    const INITIAL: Duration = Duration::from_millis(1);
    /// The interval cap: coarse enough to poll cheaply through the long waits (a cold boot to
    /// userspace), still 4x finer than the fixed 20 ms tick it replaced.
    const CAP: Duration = Duration::from_millis(5);

    /// Start at [`INITIAL`](Self::INITIAL), so a near-immediate readiness is caught almost at once.
    fn new() -> Self {
        Self {
            next: Self::INITIAL,
        }
    }

    /// Return the current interval, then double it toward the [`CAP`](Self::CAP). Split from
    /// [`sleep`](Self::sleep) so the progression is unit-testable without spending wall-clock.
    fn bump(&mut self) -> Duration {
        let current = self.next;
        self.next = (self.next * 2).min(Self::CAP);
        current
    }

    /// Sleep the current interval, then advance toward the cap.
    fn sleep(&mut self) {
        std::thread::sleep(self.bump());
    }
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

/// The wall-clock deadline for one whole boot/restore, `now + timeout`, computed **once** by
/// `Vm::boot`/`Vm::restore` and threaded through host-side staging (`launch`) *and* the API boot
/// (`run_boot`) so the two share one budget (decision 013: one wall for the run, not one per phase).
/// `Instant + Duration` panics on overflow, and `timeout` is caller-set, so a `Duration::MAX`
/// "no limit" clamps to a day rather than panicking.
pub(crate) fn boot_deadline(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + Duration::from_secs(86_400))
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
    use agent_test_support::ScratchDir;

    #[test]
    fn poll_backoff_starts_tight_and_caps() {
        // Starts at 1 ms so near-immediate readiness is caught almost at once, doubles, and never
        // exceeds the 5 ms cap no matter how long the wait runs, the property the readiness polls
        // rely on to stay both responsive and cheap. `bump` returns the current interval and advances.
        let mut b = PollBackoff::new();
        let ms = |n| Duration::from_millis(n);
        assert_eq!(b.bump(), ms(1));
        assert_eq!(b.bump(), ms(2));
        assert_eq!(b.bump(), ms(4));
        // 4 → 8 clamps to the 5 ms cap, and stays there for every subsequent poll.
        assert_eq!(b.bump(), ms(5));
        assert_eq!(b.bump(), ms(5), "the cap holds");
    }

    #[test]
    fn dead_vmm_fails_fast_with_its_stderr_tail() {
        // A "firecracker" that exits immediately, complaining on stderr: `sh --api-sock <path>`
        // rejects the flag. Boot must fail fast with the exit surfaced, not wait out the whole
        // deadline, and carry the stderr tail. Needs no KVM, so it runs in the host gate.
        let dir = ScratchDir::created("agent-fake-fc");
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
        let deadline = boot_deadline(cfg.boot_timeout);
        let mut spawned = Spawned::launch(&cfg, deadline).expect("launch the fake vmm");
        let err = spawned
            .run_boot(&cfg, deadline)
            .expect_err("a dead vmm cannot boot");
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
        let a = ScratchDir::adopt(create_workdir(base).expect("first workdir"));
        let b = ScratchDir::adopt(create_workdir(base).expect("second workdir"));
        assert_ne!(a.path(), b.path(), "each VM gets its own scratch dir");
        let mode = std::fs::metadata(a.path())
            .expect("stat workdir")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "scratch dir must be private to us");
    }

    #[test]
    fn staging_dir_is_created_private_and_adopts_only_its_own() {
        use std::os::unix::fs::PermissionsExt;
        let base = ScratchDir::created("agent-stage-priv");
        let dir = base.path().join("agent-99999-0");
        // Fresh create: private 0700, regardless of umask.
        ensure_private_staging_dir(&dir).expect("create the staging dir");
        let mode = std::fs::metadata(&dir).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "staging dir must be private to us");
        // A second call adopts our own 0700 dir (the lingering-empty-from-a-prior-restore case).
        ensure_private_staging_dir(&dir).expect("adopt our own private dir");
        // A world-writable pre-existing dir (an attacker's plant) is refused.
        let squatted = base.path().join("agent-88888-0");
        std::fs::create_dir(&squatted).expect("create squatted dir");
        std::fs::set_permissions(&squatted, std::fs::Permissions::from_mode(0o777))
            .expect("widen mode");
        assert!(
            ensure_private_staging_dir(&squatted).is_err(),
            "a non-0700 pre-existing dir must be refused, not adopted"
        );
    }

    #[test]
    fn a_staged_restore_disk_is_private_and_never_clobbers() {
        use std::os::unix::fs::PermissionsExt;
        let base = ScratchDir::created("agent-stage-disk");
        let src = base.path().join("bundle-disk");
        std::fs::write(&src, b"snapshot disk bytes").expect("write source disk");
        let backing = base.path().join("agent-77777-0/rootfs.ext4");
        stage_restore_disk(&src, &backing).expect("stage the disk");
        assert_eq!(
            std::fs::read(&backing).expect("read staged disk"),
            b"snapshot disk bytes"
        );
        let mode = std::fs::metadata(&backing)
            .expect("stat staged disk")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "staged disk must be owner-only");
        // A second stage to the same baked-in path must not clobber (the single-flight guarantee).
        assert!(
            stage_restore_disk(&src, &backing).is_err(),
            "re-staging over an existing disk must fail, not overwrite"
        );
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
    fn overlay_size_is_half_ram_floored_at_one_mib() {
        let mib = |n: u32| NonZeroU32::new(n).expect("nonzero test value");
        // The working range: half of guest RAM (the default 256 gives 128M).
        assert_eq!(overlay_size_mib(mib(256)), 128);
        assert_eq!(overlay_size_mib(mib(2)), 1);
        assert_eq!(overlay_size_mib(mib(3)), 1);
        // The degenerate edge the floor exists for: `1 / 2` must not hand the overlay `0M` (a
        // zero-sized tmpfs would leave `/` read-only and unwritable).
        assert_eq!(overlay_size_mib(mib(1)), 1);
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
