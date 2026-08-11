//! The boot/restore state machine beneath [`Vm`](crate::Vm): [`Spawned`] spawns a `firecracker`
//! child (directly, jailed, or for a snapshot restore), drives it through the boot sequence, and
//! either promotes it to a [`RunningVm`] or tears it down on failure, so a half-booted VM is never
//! observable. Split out of `vm.rs` to keep that module the public surface (config + `Vm`/`RunningVm`
//! API) while this holds the ~700-line orchestration.
//!
//! `Spawned`'s `Drop` is the panic safety net: anything that unwinds between `launch` and
//! `abort`/`into_running` still kills the VMM and reclaims its scratch dir. Every free helper here
//! (scratch-dir creation, the `sun_path` guard, the shared `teardown`) serves that lifecycle.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bsx_channel::VSOCK_PORT;

use crate::VmmError;
use crate::console::{Console, last_lines};
use crate::drives::{OutputDevice, build_input_image, build_output_image};
use crate::exec::connect_agent_at;
use crate::firecracker::{
    Action, ApiClient, BootSource, Drive, MachineConfig, NetworkInterface, RateLimiter, Vsock,
};
use crate::jail::{
    Chroot, JAILED_VSOCK_UDS, Jail, JailLease, cgroup_limit_args, give_to_jail, jailer_cgroup_dir,
    read_cgroup_dir, remove_cgroup, spawn_jailer, stage_into_chroot, stage_ro_base_into_chroot,
};
use crate::lifetime::VmLifetime;
use crate::net::{GuestEgress, GuestLink, Tap};
use crate::paths::{absolute, path_str, require_file};
use crate::vm::{
    BootConfig, FC_STDERR, IFACE_ID, RunningVm, VSOCK_UDS, reclaim_scratch,
    reclaim_scratch_after_tap_failure, teardown,
};

mod fcversion;
mod restore;
mod workdir;

#[cfg(test)]
use fcversion::FC_CLOCK_REALTIME_SINCE;
use fcversion::warn_on_unpinned_firecracker;
pub(crate) use fcversion::{
    FcProbe, MIN_SUPPORTED_FC_VERSION, PINNED_FC_VERSION, probe_fc_version,
};
#[cfg(test)]
use fcversion::{VERSION_HEAD_CAP, fc_version_of, probe_fc_version_within};
#[cfg(test)]
use restore::{StagedDisk, ensure_private_staging_dir, stage_restore_disk};
#[cfg(test)]
use workdir::SUN_PATH_MAX;
pub(crate) use workdir::{VM_DIR_PREFIX, check_sun_path};
use workdir::{WorkdirGuard, create_workdir, workdir_name};

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
/// `is_read_only`), whose bare `true`/`false` call sites are silently swappable.
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
    /// The pair this VMM was jailed under, moved into the [`Chroot`] so it is held for the VM's
    /// whole life. Dropping it on an error path inside `spawn_jailed` returns the id at once.
    lease: JailLease,
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

        // The staging window: the guard removes the scratch dir on every exit from here, an error
        // `?` or an unwinding panic in the copy/image builds alike, so a failed stage leaves no
        // orphan. Disarmed just before the tap exists: from there a plain removal
        // could strand a dir-less netns, so the netns-gated `reclaim_scratch*` helpers own cleanup.
        let staged = WorkdirGuard::new(create_workdir(&config.scratch_dir)?);

        // Read-only boot shares the pinned base directly (no per-VM copy): Firecracker opens it
        // `O_RDONLY` so the guest can't mutate it, and the writable layer comes from the guest's
        // tmpfs overlay (see `BootConfig::read_only_root`). Read-write boot copies the base instead,
        // so the guest's writes stay per-VM and the base stays pinned.
        let rootfs = if config.read_only_root {
            // The shared base is handed to Firecracker as-is and recorded as the snapshot's disk path,
            // so resolve it to absolute now (each VMM's cwd is its scratch dir; a relative base path
            // would resolve there instead).
            absolute(&config.rootfs)?
        } else {
            // The whole-rootfs copy is the heaviest host-side step and unbounded on its own (a
            // multi-GiB image on slow storage), so it runs under the shared boot deadline: check
            // before it, and each later staging step re-checks, so a copy that blows the budget
            // surfaces as a typed `Timeout` instead of an unbounded host hang.
            still_before(deadline, "rootfs copy")?;
            let copy = staged.path().join("rootfs.ext4");
            std::fs::copy(&config.rootfs, &copy)
                .map_err(|e| VmmError::Vmm(format!("copy rootfs to {}: {e}", copy.display())))?;
            // `fs::copy` propagates the source's mode; a read-only pinned base (0444) would make the
            // read-write root drive unopenable. The copy is ours alone, force owner read-write.
            std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| VmmError::Vmm(format!("chmod rootfs copy: {e}")))?;
            std::borrow::Cow::Owned(copy)
        };

        // Bulk read-only input: build an ext4 from the host `input_dir` and attach it as a
        // second block device (`/dev/vdb`). Lives in the scratch dir, so teardown reclaims it too.
        let input_image = match &config.input_dir {
            None => None,
            Some(dir) => {
                still_before(deadline, "input image build")?;
                Some(build_input_image(dir, staged.path(), deadline)?)
            }
        };

        // Bulk writable output: build a blank ext4 the guest mounts read-write at `/output`,
        // attached as another block device. Its host destination rides along for `collect_outputs`.
        let output = match &config.output_dir {
            None => None,
            Some(dest) => {
                still_before(deadline, "output image build")?;
                Some(OutputDevice {
                    image: build_output_image(staged.path(), deadline)?,
                    dest: dest.clone(),
                })
            }
        };

        // Cleanup ownership passes to the netns-aware path below.
        let workdir = staged.disarm();

        // Per-VM network namespace + tap for the guest's virtio-net (netns model), when enabled.
        // Created **before** Firecracker so it can join the netns; named after the scratch dir, so a
        // crashed driver's netns is reclaimable by the same dir-keyed sweep. A direct boot runs
        // Firecracker with the driver's own privilege, so the tap needs no per-uid owner. A failed
        // create reclaims its own half-built netns; we still own the workdir, so reclaim it.
        let tap = if config.enable_network {
            match Tap::create(&workdir_name(&workdir), None) {
                Ok(tap) => Some(tap),
                Err(e) => {
                    // A failed create best-effort-deletes its own netns, but if that delete failed
                    // the netns lingers, so gate the dir removal on it (never strand a dir-less netns).
                    reclaim_scratch_after_tap_failure(&workdir);
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
        // sentinel, so from here a SIGKILLed driver's death wakes the sentinel instead. Named by the
        // scratch dir, so a VM's cgroup and scratch identities match.
        let lifetime = VmLifetime::adopt(child.id(), &workdir_name(&workdir));

        // Firecracker creates the vsock socket here on `PUT /vsock`; the host dials it post-boot.
        let vsock_uds = config.guest_cid.map(|_| workdir.join(VSOCK_UDS));
        Ok(Self {
            child: Some(child),
            console,
            workdir,
            rootfs: rootfs.into_owned(),

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
        let cgroup_args = cgroup_limit_args(config.require_limits, config.vcpus, config.mem_mib)?;
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
            chroot: Some(Chroot::new(s.chroot_root, s.lease)),
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
        // One lease for this sandbox, taken before anything is chowned to it: the tap owner, the
        // jailer's `--uid`/`--gid`, and every staged file must name the *same* pair, so it is
        // resolved once here rather than re-read from `jail` at each site.
        let lease = jail.lease()?;
        let (uid, gid) = (lease.uid(), lease.gid());
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
            match Tap::create(&id, Some((uid, gid))) {
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
        let netns = tap.as_ref().map(|t| t.netns_path());
        let (child, console, socket, chroot_root) = match spawn_jailer(
            jail,
            (uid, gid),
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
            lease,
        })
    }

    /// Poll the guest agent's vsock port until a connect + handshake succeeds, so a restored VM is
    /// exec-ready when it's handed back. The probe connection is dropped immediately (the agent serves
    /// one connection then loops back to accept, so a connect-and-close just cycles it).
    fn await_guest_ready(&mut self, uds: &Path, deadline: Instant) -> Result<(), VmmError> {
        let mut backoff = PollBackoff::new();
        loop {
            match connect_agent_at(uds, VSOCK_PORT, Duration::from_millis(200)) {
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
            if let Some(dir) = actual.as_deref()
                && !self.lifetime.watches(dir)
            {
                tracing::warn!(
                    cgroup = %dir.display(),
                    "jailer placed the VMM outside the precomputed cgroup; the lifetime \
                     sentinel is not guarding it (driver death would leak this VMM)"
                );
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
        // the caller (`boot_deadline`) and threaded in, so both share one wall.
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
                    deadline,
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
                let image = build_input_image(dir, &root, deadline)?;
                give_to_jail(&image, uid, gid, 0o444)?;
                self.input_image = Some(image);
            }
            if let Some(dest) = config.output_dir.as_ref() {
                let image = build_output_image(&root, deadline)?;
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
        let mut boot_args = overlay_boot_args(config);
        if let Some(tap) = self.tap.as_ref() {
            boot_args = format!(
                "{boot_args} {}",
                network_boot_args(&tap.v4, tap.v6, config.egress)
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
        // label (`bsx-output`), so the `/dev/vdX` letter this lands on doesn't matter, a boot may
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

        // Per-VM virtio-net, backed by the host tap created in `launch`. Deny-by-default: the guest
        // reaches only the connected host end over this tap, the v4 `/30` and the v6 `/64` each carry
        // a connected-prefix route and no default route (no masquerade, no forwarding), from the
        // `ip=`/`guest_ip6=` addressing set above. The tap is deleted on every teardown path.
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
            if crate::firecracker::connect_with_timeout(
                self.api.socket(),
                std::time::Duration::from_millis(50),
            )
            .is_ok()
            {
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

/// The read-only-root overlay's tmpfs cap, in MiB: **half of guest RAM**, the guest has no swap,
/// so a tmpfs sized near RAM would OOM the guest rather than bound a runaway write, **floored at
/// 1 MiB**, so the integer division can never hand the overlay a size of `0M` (a zero-sized tmpfs
/// would leave the guest's `/` read-only and unwritable). The floor only fires at `mem_mib == 1`,
/// which can't boot Linux anyway; it exists so the derivation has no degenerate value at all.
/// Pure, so the arithmetic is unit-tested without a boot.
fn overlay_size_mib(mem_mib: NonZeroU32) -> u32 {
    (mem_mib.get() / 2).max(1)
}

/// The caller's boot args, plus the overlay hand-off when the root is read-only. A read-only root
/// hands off to the overlay init, which stacks a size-capped tmpfs over the RO base so `/` is
/// writable per-run (the cap's derivation lives in [`overlay_size_mib`]). Both ride the kernel
/// command line as `key=value` tokens, which the kernel routes into PID 1's environment, so
/// `overlay-init` reads `$overlay_size` without mounting `/proc` first.
///
/// Split out of the boot sequence so the one line naming a *guest* path is testable without a VM:
/// [`bsx_channel::GUEST_OVERLAY_INIT`] is written here and by the rootfs build, and a boot into a path
/// nothing occupies reads as a kernel panic rather than as a mismatch.
fn overlay_boot_args(config: &BootConfig) -> String {
    if config.read_only_root {
        format!(
            "{} init={} overlay_size={}M",
            config.boot_args,
            bsx_channel::GUEST_OVERLAY_INIT,
            overlay_size_mib(config.mem_mib)
        )
    } else {
        config.boot_args.clone()
    }
}

/// The guest's addressing tokens for the kernel command line, rendered from the link the host just
/// configured on the tap. The kernel brings `eth0` up before userspace from `ip=` (`CONFIG_IP_PNP`),
/// and `off` is the autoconf method, so the guest never probes DHCP.
///
/// The mask comes from the link's own prefix ([`GuestLink::netmask`]) rather than being written
/// out, so the guest's mask and the host tap's prefix cannot disagree.
///
/// **The gateway and DNS fields are empty unless `egress` names them**, the shipped default: the guest
/// installs the connected route and no default route, so an off-link destination fails with
/// `ENETUNREACH` inside the guest. A [`GuestEgress`] fills them, which lets the guest *emit* those
/// packets so the tap's classifier can police them, without making them arrive, since nothing here
/// builds a path. A resolver is unrepresentable without a gateway, so the DNS field can never name a host
/// the guest has no route to.
///
/// IPv6 rides alongside as a `guest_ip6=<addr>/<plen>` token, since `ip=` has no v6 form, and is emitted
/// only when the v6 link is live, so an IPv6-disabled host leaves no dangling guest address. v6 gets a
/// connected `/64` and no default route in every case, since `--allow` parses v4 only and a v6 route
/// would be one no CLI-authored policy could bound.
///
/// Split out of the boot sequence so the rendering is exercised without a VM.
fn network_boot_args(
    v4: &GuestLink<Ipv4Addr>,
    v6: Option<GuestLink<Ipv6Addr>>,
    egress: Option<GuestEgress>,
) -> String {
    // Both render empty when unset, which is what keeps the sealed string byte-identical when no
    // gateway is configured.
    let gateway = egress.map(|e| e.gateway().to_string()).unwrap_or_default();
    let dns = egress
        .and_then(|e| e.resolver())
        .map(|r| format!(":{r}"))
        .unwrap_or_default();
    let args = format!("ip={}::{gateway}:{}::eth0:off{dns}", v4.guest, v4.netmask());
    match v6 {
        Some(v6) => format!(
            "{args} {}={}/{}",
            bsx_channel::GUEST_IP6_CMDLINE_KEY,
            v6.guest,
            v6.prefix_len
        ),
        None => args,
    }
}

/// A readiness-poll interval that starts tight and backs off to a cap. A wait that resolves quickly (a
/// snapshot resume whose agent is already reachable, an API socket already up) is caught within ~a
/// millisecond of becoming ready instead of being quantized to a coarse fixed interval; a long wait (a
/// cold boot to userspace) settles at the cap and keeps polling cheaply. Motivated by the latency
/// decomposition: a flat 20 ms poll adds up to 20 ms (~10 ms on average) of pure quantization to every
/// start, a large slice of a ~40 ms restore, and needless jitter on the boot tail. The `contains`/
/// `connect` check each tick is cheap, so a finer interval near readiness costs nothing that matters.
pub(crate) struct PollBackoff {
    next: Duration,
}

impl PollBackoff {
    /// The first interval: tight enough to catch near-immediate readiness within ~a millisecond.
    const INITIAL: Duration = Duration::from_millis(1);
    /// The interval cap: coarse enough to poll cheaply through the long waits (a cold boot to
    /// userspace), still fine enough that a fast boot is not rounded up.
    const CAP: Duration = Duration::from_millis(5);

    /// Start at [`INITIAL`](Self::INITIAL), so a near-immediate readiness is caught almost at once.
    pub(crate) fn new() -> Self {
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
    pub(crate) fn sleep(&mut self) {
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
/// (`run_boot`) so the two share one budget (one wall for the run, not one per phase).
/// `Instant + Duration` panics on overflow, and `timeout` is caller-set, so a `Duration::MAX`
/// "no limit" clamps to a day rather than panicking.
pub(crate) fn boot_deadline(timeout: Duration) -> Instant {
    deadline_after(timeout)
}

/// `Instant::now() + timeout`, minus the overflow panic: a caller-controlled `Duration::MAX`
/// "no limit" clamps to a day. The **only** way a caller-flowing duration may become a deadline
/// (`Limits::wall` reaches the exec dial and the API client unclamped; the bare `+` panicking
/// there was a host panic on the no-panic path).
pub(crate) fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + Duration::from_secs(86_400))
}

#[cfg(test)]
mod version_tests {
    use super::{
        FC_CLOCK_REALTIME_SINCE, MIN_SUPPORTED_FC_VERSION, PINNED_FC_VERSION, fc_version_of,
    };

    #[test]
    fn the_supported_range_covers_every_release_upstream_still_patches() {
        // Upstream's release-status table currently marks v1.15 and v1.16 "Supported" (v1.14 ended
        // the day v1.16 shipped). The floor must not sit *above* the oldest of those: refusing a
        // release upstream still fixes would push operators onto an unpatched VMM to satisfy us,
        // inverting the reason the floor exists. `firecracker-pin.yml` re-checks this against the
        // live table weekly, because the answer changes without any commit here.
        assert!(
            MIN_SUPPORTED_FC_VERSION <= (1, 15),
            "the floor has risen above a release upstream still patches"
        );
        assert!(
            MIN_SUPPORTED_FC_VERSION < PINNED_FC_VERSION,
            "the supported range must be a range, not a single version"
        );
    }

    #[test]
    fn the_clock_fixup_is_gated_above_the_floor_not_at_it() {
        // The whole point of gating `clock_realtime`: the field arrived *after* the floor, so an
        // ungated send would drag the effective floor up to v1.16 and break v1.15, the older
        // supported release. If a future bump ever makes the floor meet the gate, this assertion is the
        // reminder that the conditional has become dead code and can be simplified away.
        assert!(
            FC_CLOCK_REALTIME_SINCE > MIN_SUPPORTED_FC_VERSION,
            "clock_realtime is available on every supported release; the gate is now dead code"
        );
        assert!(
            FC_CLOCK_REALTIME_SINCE <= PINNED_FC_VERSION,
            "the tested version must be new enough to exercise the field at all"
        );
    }

    #[test]
    fn the_supported_range_classifies_each_version_the_way_the_warning_does() {
        // The three buckets the boot-time warning renders, checked as plain comparisons so the
        // policy is pinned independently of the log strings.
        let supported = |v: (u64, u64)| (MIN_SUPPORTED_FC_VERSION..=PINNED_FC_VERSION).contains(&v);
        for v in [(1, 15), (1, 16)] {
            assert!(supported(v), "v{}.{} is upstream-supported", v.0, v.1);
        }
        // v1.14 belongs here, not above: its support ended the day v1.16 shipped.
        for v in [(1, 9), (1, 13), (1, 14)] {
            assert!(!supported(v), "v{}.{} is past upstream support", v.0, v.1);
        }
        assert!(!supported((1, 17)), "an untested newer release still warns");
    }

    #[test]
    fn fc_version_parses_the_real_output_shape() {
        assert_eq!(fc_version_of("Firecracker v1.9.1"), Some((1, 9)));
        assert_eq!(
            fc_version_of("Firecracker v1.9.1\nmore lines"),
            Some((1, 9))
        );
        assert_eq!(fc_version_of("Firecracker v1.13.0"), Some((1, 13)));
        // The current pin, so the parser is exercised on the version actually shipped against.
        assert_eq!(fc_version_of("Firecracker v1.16.1"), Some((1, 16)));
        for garbage in ["", "garbage", "Firecracker v", "Firecracker vX.Y"] {
            assert_eq!(fc_version_of(garbage), None, "{garbage:?} must not parse");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsx_test_support::ScratchDir;

    /// Write an executable shell script into the scratch dir and hand back its path. Stands in for
    /// an `BSX_FIRECRACKER` pointed at a wrapper, which is the whole reason the probe is bounded.
    fn script(dir: &ScratchDir, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.path().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[test]
    fn a_firecracker_that_hangs_on_version_does_not_hang_the_boot() {
        // This probe runs before any boot deadline exists, so an unbounded one hung *every* boot
        // with nothing to report. A wedged probe is `Unavailable` (the silent case): the spawn that
        // follows produces the legible typed error.
        //
        // Run against a short injected wall, not the production five seconds. What is under test is
        // that the probe gives up *at its wall*, which a 100 ms wall demonstrates exactly as well
        // and in 1/50th the time. The
        // shipped default is the wrapper's business, and it is named in exactly one place.
        let dir = ScratchDir::created("fcver-hang");
        let hang = script(&dir, "fc-hang", "sleep 60");
        let wall = Duration::from_millis(100);
        let started = Instant::now();
        let probed = probe_fc_version_within(&hang, wall);
        assert!(matches!(probed, FcProbe::Unavailable), "got {probed:?}");
        // Generous slack over the wall, since what would make this flake is a slow spawn or a
        // descheduled poll, neither of which is the property under test. It still fails loudly if
        // the wall stops being honoured at all, which is the failure that matters: `sleep 60`
        // would take a full minute.
        assert!(
            started.elapsed() < wall + Duration::from_secs(3),
            "the probe must give up at its wall: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_flooding_firecracker_still_parses_from_the_head() {
        // The end-to-end half: a wrapper that floods stdout still yields its version, spawn and
        // wait and read included. The *bound* itself is asserted in `proc`
        // (`read_head_stops_at_the_cap_however_long_the_file_is`), because this test cannot see it:
        // it would pass just as well if the whole 3 MB were pulled into host RAM first.
        let dir = ScratchDir::created("fcver-flood");
        let flood = script(
            &dir,
            "fc-flood",
            "echo 'Firecracker v1.16.1'\nyes bsx-flood | head -c 3000000",
        );
        // Bound and printed, like the hang test above. The message names the variant, because that is
        // what a failure here needs to distinguish: `Unparseable` means the parse broke, `Unavailable`
        // means the spawn or wait did (a fork under a loaded gate can fail with EAGAIN).
        let probed = probe_fc_version(&flood);
        assert!(
            matches!(probed, FcProbe::Version((1, 16))),
            "got {probed:?}"
        );
    }

    #[test]
    fn the_version_probes_scratch_file_never_exists_on_disk() {
        // `create_new` + an immediate unlink: a predictable name in a world-writable temp dir,
        // opened with a following truncating `create`, is a symlink hijack against a driver running
        // as root. Nothing may be left behind for one to be aimed at, on any exit path.
        let before = temp_scratch_files();
        let (sink, back) = crate::proc::scratch_pair("fcver").expect("a scratch pair");
        assert_eq!(
            temp_scratch_files(),
            before,
            "the file is unlinked at creation, so it is never visible by name"
        );
        // Still a working pair despite having no name: written through one handle, read via the
        // other (they share an open file description, hence `read_head`'s seek).
        use std::io::Write as _;
        (&sink).write_all(b"Firecracker v1.16.1\n").expect("write");
        let head = crate::proc::read_head(back, VERSION_HEAD_CAP).expect("read back");
        assert!(head.contains("v1.16.1"), "got {head:?}");
    }

    /// How many of the probe's scratch files are visible in the temp dir right now.
    fn temp_scratch_files() -> usize {
        std::fs::read_dir(std::env::temp_dir())
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().starts_with("bsx-fcver-"))
                    .count()
            })
            .unwrap_or(0)
    }

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
        let dir = ScratchDir::created("bsx-fake-fc");
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
    fn a_vmm_that_dies_mid_boot_is_reported_and_reclaimed() {
        // Distinct from `dead_vmm_fails_fast_with_its_stderr_tail`, which covers a VMM that never starts:
        // here one comes up, is polled for a while, and *then* dies, the shape of an OOM kill landing
        // during boot. This is the one path that reaches `abort` with a child that died on its own, so it
        // is the cleanup that matters: a scratch dir left behind per failed boot is a slow leak nothing
        // reclaims until the next `sweep_orphans`.
        let dir = ScratchDir::created("bsx-dying-fc");
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&kernel, b"not a kernel").expect("fake kernel");
        std::fs::write(&rootfs, b"not a rootfs").expect("fake rootfs");
        // Outlive at least a few poll ticks (the backoff caps at 5 ms), then die non-zero.
        let dying = script(&dir, "fc-dying", "sleep 0.2\necho 'gone' 1>&2\nexit 3");

        let cfg = BootConfig {
            firecracker: dying,
            kernel,
            rootfs,
            scratch_dir: dir.path().to_path_buf(),
            boot_timeout: Duration::from_secs(10),
            ..BootConfig::default()
        };
        let deadline = boot_deadline(cfg.boot_timeout);
        let mut spawned = Spawned::launch(&cfg, deadline).expect("launch the dying vmm");
        let workdir = spawned.workdir.clone();
        assert!(workdir.is_dir(), "the boot staged a scratch dir to reclaim");
        let err = spawned
            .run_boot(&cfg, deadline)
            .expect_err("a vmm that died cannot boot");
        let msg = spawned.abort(err).to_string();

        assert!(
            msg.contains("exited before boot"),
            "a death before the API socket is reported as such, not as a timeout: {msg}"
        );
        assert!(
            !workdir.exists(),
            "abort must reclaim the scratch dir of a VMM that died mid-boot: {} survived",
            workdir.display()
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
        let base = ScratchDir::created("bsx-stage-priv");
        let dir = base.path().join("bsx-99999-0");
        // Fresh create: private 0700, regardless of umask.
        ensure_private_staging_dir(&dir).expect("create the staging dir");
        let mode = std::fs::metadata(&dir).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "staging dir must be private to us");
        // A second call adopts our own 0700 dir (the lingering-empty-from-a-prior-restore case).
        ensure_private_staging_dir(&dir).expect("adopt our own private dir");
        // A world-writable pre-existing dir (an attacker's plant) is refused.
        let squatted = base.path().join("bsx-88888-0");
        std::fs::create_dir(&squatted).expect("create squatted dir");
        std::fs::set_permissions(&squatted, std::fs::Permissions::from_mode(0o777))
            .expect("widen mode");
        assert!(
            ensure_private_staging_dir(&squatted).is_err(),
            "a non-0700 pre-existing dir must be refused, not adopted"
        );
    }

    #[test]
    fn a_squatted_workdir_name_is_skipped_never_adopted() {
        use std::os::unix::fs::PermissionsExt;
        // The workdir name is predictable (`bsx-<pid>-<seq>`: the pid is public, the seq counts
        // up), and the scratch base is world-writable, so a hostile local user can pre-create the
        // names a boot is about to mint. The mint must advance past every plant, never adopt one:
        // the rootfs copy and API socket go into this dir.
        let base = ScratchDir::created("bsx-squat");
        let first = ScratchDir::adopt(create_workdir(base.path()).expect("first workdir"));
        let name = first
            .path()
            .file_name()
            .expect("workdir has a name")
            .to_string_lossy()
            .into_owned();
        let seq: u64 = name
            .rsplit('-')
            .next()
            .expect("dashed name")
            .parse()
            .expect("trailing sequence number");
        // Plant a window of upcoming names, wide enough that concurrent tests in this binary
        // (which share the global sequence counter but mint under other bases) cannot step the
        // counter past it between our two calls.
        let pid = std::process::id();
        let planted: Vec<std::path::PathBuf> = (seq + 1..=seq + 8)
            .map(|n| base.path().join(format!("{VM_DIR_PREFIX}-{pid}-{n}")))
            .collect();
        for p in &planted {
            std::fs::create_dir(p).expect("plant the squatted dir");
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o777))
                .expect("attacker-open mode");
            std::fs::write(p.join("attacker-canary"), b"planted").expect("write the canary");
        }
        let minted =
            ScratchDir::adopt(create_workdir(base.path()).expect("mint must advance, not fail"));
        assert!(
            !planted.iter().any(|p| p == minted.path()),
            "the mint adopted a squatted dir: {}",
            minted.path().display()
        );
        let mode = std::fs::metadata(minted.path())
            .expect("stat the minted workdir")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "the minted dir must be freshly ours");
        assert_eq!(
            std::fs::read_dir(minted.path())
                .expect("read minted")
                .count(),
            0,
            "the minted dir must be empty, not an adopted plant"
        );
        // The plants themselves are untouched: skipped, not cleaned, certainly not written into.
        for p in &planted {
            assert_eq!(
                std::fs::read(p.join("attacker-canary")).expect("canary survives"),
                b"planted",
                "the mint must not touch a squatted dir's contents"
            );
        }
    }

    #[test]
    #[ignore = "chowns a dir to another uid; needs real root (run via `cargo xtask ci-privileged`)"]
    fn an_attacker_owned_staging_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        // The mode-mismatch refusal is host-safe-tested above; the *ownership* half of the check
        // needs a dir this euid does not own, which only root can fabricate. Mode stays 0700 so
        // ownership is the one thing wrong: a squatter who guessed the baked-in staging path and
        // even matched the expected mode is still refused.
        if crate::sweep::own_euid() != Some(0) {
            eprintln!("skipping an_attacker_owned_staging_dir_is_refused: needs real root");
            return;
        }
        let base = ScratchDir::created("bsx-stage-owner");
        let dir = base.path().join("bsx-66666-0");
        std::fs::create_dir(&dir).expect("create the dir to disown");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("set the expected mode");
        std::os::unix::fs::chown(&dir, Some(65534), Some(65534)).expect("chown to nobody");
        assert!(
            ensure_private_staging_dir(&dir).is_err(),
            "a staging dir owned by another uid must be refused even at mode 0700"
        );
    }

    #[test]
    fn a_staged_restore_disk_is_private_and_never_clobbers() {
        use std::os::unix::fs::PermissionsExt;
        let base = ScratchDir::created("bsx-stage-disk");
        let src = base.path().join("bundle-disk");
        std::fs::write(&src, b"snapshot disk bytes").expect("write source disk");
        let backing = base.path().join("bsx-77777-0/rootfs.ext4");
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
        // A second stage to the same baked-in path must not clobber (the single-flight rule).
        assert!(
            stage_restore_disk(&src, &backing).is_err(),
            "re-staging over an existing disk must fail, not overwrite"
        );
    }

    #[test]
    #[ignore = "mounts a tmpfs; needs real root (run via `cargo xtask ci-privileged`)"]
    fn a_disk_full_mid_stage_leaves_nothing_behind() {
        // `stage_restore_disk` promises all-or-nothing staging, and the disk-full case is the whole
        // reason it does: the copy is rootfs-sized, so it is the one write here that can fail
        // *partway*, after the path was reserved and the sweep marker written. A partial disk left
        // at the snapshot's baked-in path is worse than a failed restore: `create_new` would then
        // refuse every later restore of that snapshot, reporting a concurrent restore that is not
        // happening.
        let Some(fs) = bsx_test_support::SmallFs::create(8, "stage-full") else {
            eprintln!("skipping a_disk_full_mid_stage_leaves_nothing_behind: needs real root");
            return;
        };
        // Headroom for the staging dir and the marker, far under the source's size, so the failure
        // is the copy and not an earlier step.
        fs.fill_leaving(64 * 1024);

        // The source lives on the host filesystem; only the destination is out of space.
        let host = ScratchDir::created("stage-full-src");
        let src = host.path().join("rootfs.ext4");
        std::fs::write(&src, vec![b'x'; 4 * 1024 * 1024]).expect("write the oversized source");

        let backing = fs.path().join("staging/rootfs.ext4");
        let err = stage_restore_disk(&src, &backing)
            .expect_err("a 4 MiB copy cannot fit in 64 KiB of headroom");
        assert!(
            matches!(err, VmmError::Vmm(ref m) if m.contains("stage restore disk")),
            "got {err:?}"
        );

        let parent = backing.parent().expect("staging dir");
        assert!(
            !backing.exists(),
            "a partial staged disk must not survive: it would make `create_new` refuse every later \
             restore of this snapshot"
        );
        assert!(
            !parent.join(crate::sweep::RESTORE_STAGING_MARKER).exists(),
            "the sweep marker must go with the disk it was defending"
        );
        assert!(
            !parent.exists(),
            "the staging dir this call created must be removed with its contents"
        );
    }

    #[test]
    #[ignore = "mounts a tmpfs; needs real root (run via `cargo xtask ci-privileged`)"]
    fn a_full_scratch_dir_fails_the_boot_without_stranding_a_partial_rootfs() {
        // A read-write boot copies the whole rootfs into the scratch dir before Firecracker is
        // spawned, which is the largest write on the boot path and the one `BootConfig::scratch_dir`
        // warns about (a tmpfs `/tmp` charges it to host RAM). The copy fails before any spawn, so
        // this needs no KVM; what must hold is that `WorkdirGuard` reclaims the half-written copy
        // rather than leaving scratch to accumulate one per failed boot.
        let Some(fs) = bsx_test_support::SmallFs::create(8, "boot-full") else {
            eprintln!(
                "skipping a_full_scratch_dir_fails_the_boot_without_stranding_a_partial_rootfs: \
                 needs real root"
            );
            return;
        };
        fs.fill_leaving(64 * 1024);

        let host = ScratchDir::created("boot-full-src");
        let kernel = host.path().join("vmlinux");
        let rootfs = host.path().join("rootfs.ext4");
        std::fs::write(&kernel, b"not a kernel").expect("fake kernel");
        std::fs::write(&rootfs, vec![b'x'; 4 * 1024 * 1024]).expect("oversized fake rootfs");

        let cfg = BootConfig {
            firecracker: PathBuf::from("sh"),
            kernel,
            rootfs,
            scratch_dir: fs.path().to_path_buf(),
            boot_timeout: Duration::from_secs(10),
            ..BootConfig::default()
        };
        // `.err()` rather than `expect_err`: `Spawned` holds a live child and is not `Debug`.
        let err = Spawned::launch(&cfg, boot_deadline(cfg.boot_timeout))
            .err()
            .expect("a 4 MiB rootfs cannot be copied into 64 KiB of headroom");
        assert!(
            matches!(err, VmmError::Vmm(ref m) if m.contains("copy rootfs")),
            "got {err:?}"
        );

        // Everything the failed launch made is gone; only the filler this test wrote remains.
        let leftovers: Vec<_> = std::fs::read_dir(fs.path())
            .expect("read the fixture")
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|n| n != "bsx-filler")
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed launch must strand no scratch dir; found {leftovers:?}"
        );
    }

    #[test]
    fn jailed_disk_staging_leaves_the_leaf_to_the_privacy_contract() {
        // The jailed-restore sequence for a private disk, host-safe (own uid stands in for the
        // jail's): the traversal chain is pre-created, but the staging *leaf* must be left for
        // `stage_restore_disk` to create 0700. A pre-created leaf (default 0755) fails the 0700
        // privacy check, refusing every jailed private-disk restore and so the daemon's whole
        // `--prewarm` path.
        use std::os::unix::fs::PermissionsExt;
        let base = ScratchDir::created("bsx-stage-jail");
        let root = base.path().join("chroot-root"); // stands in for <jail>/root
        let src = base.path().join("bundle-disk");
        std::fs::write(&src, b"private disk bytes").expect("write source disk");

        // Baked-in path /var/tmp/bsx-66666-0/rootfs.ext4, re-rooted into the chroot.
        let disk_target = root.join("var/tmp/bsx-66666-0/rootfs.ext4");
        let parent = disk_target.parent().expect("leaf dir");
        let chain = parent.parent().expect("traversal chain");
        std::fs::create_dir_all(chain).expect("create traversal chain");

        stage_restore_disk(&src, &disk_target).expect("stage into the fresh leaf");
        let mode = std::fs::metadata(parent)
            .expect("stat leaf")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "the staging leaf is private");
        // The ownership handoff to the (here: own) uid the confined VMM runs as.
        let uid = crate::sweep::own_euid().expect("own euid");
        give_to_jail(parent, uid, uid, 0o700).expect("hand the leaf to the jail uid");
        assert_eq!(
            std::fs::read(&disk_target).expect("staged disk readable"),
            b"private disk bytes"
        );

        // A pre-created (0755) leaf is not adoptable.
        let pre_created = root.join("var/tmp/bsx-55555-0/rootfs.ext4");
        let bad_leaf = pre_created.parent().expect("leaf");
        std::fs::create_dir_all(bad_leaf).expect("pre-create leaf");
        // Pin the mode explicitly so the assertion doesn't depend on the runner's umask.
        std::fs::set_permissions(bad_leaf, std::fs::Permissions::from_mode(0o755))
            .expect("widen leaf");
        assert!(
            stage_restore_disk(&src, &pre_created).is_err(),
            "a leaf this code did not create 0700 must be refused, not adopted"
        );
    }

    #[test]
    #[allow(clippy::panic)] // the deliberate panic *is* the unwind this test exercises
    fn the_workdir_guard_removes_the_dir_even_when_the_scope_unwinds() {
        // The leak the guard closes: a panic mid-staging (rootfs copy, an image build) must not
        // strand the scratch dir. And the disarm half: a dir handed off to the netns-aware path
        // must survive the guard's drop.
        let base = std::env::temp_dir().join(format!("bsx-workdir-unwind-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("mkdir");

        let doomed = base.join("staging");
        std::fs::create_dir(&doomed).expect("stage dir");
        std::fs::write(doomed.join("rootfs.ext4"), b"x").expect("stage file");
        let doomed_for_panic = doomed.clone();
        let caught = std::panic::catch_unwind(move || {
            let _guard = WorkdirGuard::new(doomed_for_panic);
            panic!("boom mid-staging");
        });
        assert!(caught.is_err(), "the panic propagated");
        assert!(
            !doomed.exists(),
            "the staged workdir must be removed as the guard drops on unwind"
        );

        let kept = base.join("handed-off");
        std::fs::create_dir(&kept).expect("stage dir");
        let handed = WorkdirGuard::new(kept.clone()).disarm();
        assert_eq!(handed, kept, "disarm hands the same path back");
        assert!(kept.exists(), "a disarmed workdir must survive the guard");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    #[allow(clippy::panic)] // the deliberate panic *is* the unwind this test exercises
    fn the_staged_disk_is_unstaged_even_when_the_scope_unwinds() {
        // `StagedDisk`'s rustdoc promises the panic-unwind cover for the out-of-workdir staged
        // restore disk; pin it: an armed guard dropped by an unwind unstages the file (and its
        // staging marker + now-empty parent), a `take`n one leaves the disk alone.
        let base = std::env::temp_dir().join(format!("bsx-disk-unwind-{}", std::process::id()));
        let staging = base.join("stage");
        std::fs::create_dir_all(&staging).expect("mkdir");
        let disk = staging.join("rootfs.ext4");
        std::fs::write(&disk, b"x").expect("stage disk");
        let disk_for_panic = disk.clone();
        let caught = std::panic::catch_unwind(move || {
            let _guard = StagedDisk::armed(disk_for_panic);
            panic!("boom mid-restore");
        });
        assert!(caught.is_err(), "the panic propagated");
        assert!(
            !disk.exists(),
            "the staged disk must be unstaged as the guard drops on unwind"
        );

        std::fs::create_dir_all(&staging).expect("mkdir again");
        std::fs::write(&disk, b"x").expect("stage disk again");
        let mut guard = StagedDisk::armed(disk.clone());
        assert_eq!(guard.take(), Some(disk.clone()));
        drop(guard);
        assert!(disk.exists(), "a taken disk must survive the guard");

        let _ = std::fs::remove_dir_all(&base);
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

    /// The one boot-arg that names a **guest** path. The rootfs build writes the file at
    /// `bsx_channel::GUEST_OVERLAY_INIT` and this puts `init=` on the command line, so the two are one
    /// constant; a boot into a path nothing occupies reads as a kernel panic, not as a mismatch.
    /// Host-safe, since the overlay itself is only reachable through a jailed boot (real root).
    #[test]
    fn a_read_only_root_hands_off_to_the_shared_overlay_init_path() {
        let mut config = BootConfig {
            boot_args: "console=ttyS0".to_string(),
            mem_mib: NonZeroU32::new(256).expect("nonzero test value"),
            ..Default::default()
        };

        // Off by default: nothing is appended, so a plain boot's args are the caller's verbatim.
        assert_eq!(overlay_boot_args(&config), "console=ttyS0");

        config.read_only_root = true;
        let args = overlay_boot_args(&config);
        assert_eq!(
            args,
            format!(
                "console=ttyS0 init={} overlay_size=128M",
                bsx_channel::GUEST_OVERLAY_INIT
            )
        );
        // Spelled out too: the assertion above would still pass if the constant became empty or
        // relative, and the kernel needs an absolute path to an executable.
        assert!(bsx_channel::GUEST_OVERLAY_INIT.starts_with('/'));
    }

    /// The guest's mask and the host tap's prefix are one value: `net.rs` owns the prefix, the link
    /// carries it, and this renders it. The `/24` case is what tells a derivation from a literal,
    /// since a hardcoded `255.255.255.252` satisfies the `/30` assertion on its own, and the `/0`
    /// case is the shift that must not overflow. Neither is a supported link.
    #[test]
    fn the_guest_netmask_follows_the_host_link_prefix() {
        let link = |prefix_len| {
            GuestLink::new(
                Ipv4Addr::new(10, 200, 0, 1),
                Ipv4Addr::new(10, 200, 0, 2),
                prefix_len,
            )
        };
        // The shipped /30, unchanged: guest end, mask, empty gateway field, static autoconf.
        assert_eq!(
            network_boot_args(&link(30), None, None),
            "ip=10.200.0.2:::255.255.255.252::eth0:off"
        );
        assert_eq!(
            network_boot_args(&link(24), None, None),
            "ip=10.200.0.2:::255.255.255.0::eth0:off"
        );
        assert_eq!(
            network_boot_args(&link(0), None, None),
            "ip=10.200.0.2:::0.0.0.0::eth0:off"
        );

        // A live v6 link appends its token; an absent one leaves no trace.
        let v6 = GuestLink::new(
            Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 2),
            64,
        );
        assert_eq!(
            network_boot_args(&link(30), Some(v6), None),
            format!(
                "ip=10.200.0.2:::255.255.255.252::eth0:off {}=fd00:200::2/64",
                bsx_channel::GUEST_IP6_CMDLINE_KEY
            )
        );
    }

    #[test]
    fn egress_fills_the_gateway_and_dns_fields_the_sealed_boot_leaves_empty() {
        let link = GuestLink::new(
            Ipv4Addr::new(10, 200, 0, 1),
            Ipv4Addr::new(10, 200, 0, 2),
            30,
        );
        let gw = Ipv4Addr::new(10, 200, 0, 1);

        // A gateway fills the third `ip=` field, which is what installs a default route. The DNS
        // field stays empty, so the guest is routed but told no resolver.
        assert_eq!(
            network_boot_args(&link, None, Some(GuestEgress::via(gw))),
            "ip=10.200.0.2::10.200.0.1:255.255.255.252::eth0:off"
        );

        // A resolver appends the DNS field. Unrepresentable without a gateway (the builder starts
        // from `via`), so the guest is never told to resolve at a host it has no route to.
        assert_eq!(
            network_boot_args(
                &link,
                None,
                Some(GuestEgress::via(gw).with_resolver(Ipv4Addr::new(1, 1, 1, 1)))
            ),
            "ip=10.200.0.2::10.200.0.1:255.255.255.252::eth0:off:1.1.1.1"
        );

        // v6 is unaffected: it rides its own token and gets no gateway either way, since `--allow`
        // parses v4 only and a v6 route would be one no CLI-authored policy could bound.
        let v6 = GuestLink::new(
            Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 2),
            64,
        );
        assert_eq!(
            network_boot_args(&link, Some(v6), Some(GuestEgress::via(gw))),
            format!(
                "ip=10.200.0.2::10.200.0.1:255.255.255.252::eth0:off {}=fd00:200::2/64",
                bsx_channel::GUEST_IP6_CMDLINE_KEY
            )
        );
    }

    #[test]
    fn overlong_socket_path_is_a_clear_error_not_a_cryptic_bind_failure() {
        // A short path is fine; a path past the kernel's sun_path limit is rejected up front with an
        // actionable message (name the knob), not a bind failure surfacing as a boot timeout.
        assert!(check_sun_path(Path::new("/tmp/bsx-1-0/fc.sock")).is_ok());
        let long = PathBuf::from(format!("/{}/fc.sock", "x".repeat(SUN_PATH_MAX)));
        let err = check_sun_path(&long).unwrap_err().to_string();
        assert!(err.contains("too long"), "explains the limit: {err}");
        assert!(err.contains("BSX_SCRATCH_DIR"), "names the fix: {err}");
    }

    #[test]
    fn the_default_scratch_dirs_leave_room_for_the_jailer_socket_path() {
        // The `sun_path` budget: the jailer nests the
        // per-VM dir name **twice** (`<scratch>/<name>/firecracker/<name>/root/run/firecracker.socket`),
        // so a long VM_DIR_PREFIX plus a real scratch dir overflows `sun_path`. Pin that the prefix and
        // the shipped scratch defaults (the ci-privileged wrapper's and the guided install's) fit, even
        // at the widest pid and a long-lived daemon's high sequence. A much longer $HOME can still
        // exceed it, by design: `check_sun_path` then refuses with the fix.
        let name = format!("{VM_DIR_PREFIX}-{}-{}", u32::MAX, 99_999);
        for scratch in ["/var/tmp/bsx", "/home/operator/.bsx"] {
            let socket = Path::new(scratch)
                .join(&name)
                .join("firecracker")
                .join(&name)
                .join("root/run/firecracker.socket");
            assert!(
                check_sun_path(&socket).is_ok(),
                "default scratch {scratch} overflows sun_path: {} bytes for {}",
                socket.as_os_str().len(),
                socket.display()
            );
        }
    }
}
