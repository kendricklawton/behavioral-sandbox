//! Snapshot and restore — the point-in-time-copy half of the VM lifecycle, split out of `vm.rs`.
//! [`RunningVm::snapshot`] pauses a VM and writes a portable [`Snapshot`](crate::Snapshot) bundle
//! (device + vCPU state, guest memory, root disk); [`Vm::restore`] rebuilds a VM from one on a fresh
//! VMM. The [`Snapshot`] type itself stays in `vm.rs` with the other public surface; this module
//! holds only the orchestration, the way `spawn.rs` holds the boot sequence.

use std::path::Path;

use crate::firecracker::{SnapshotCreate, SnapshotType, VmState, VmStateKind};
use crate::paths::{absolute, path_str, require_file};
use crate::spawn::Spawned;
use crate::vm::{BootConfig, RunningVm, Snapshot, Vm};
use crate::VmmError;

impl Vm {
    /// Restore a microVM from a [`Snapshot`] on a fresh VMM and resume it, returning once it's
    /// running and (if the snapshot carried the exec channel) exec-ready. Reuses only the
    /// `firecracker` binary and `boot_timeout` from `config` (the guest's kernel, memory, and devices
    /// all come from the snapshot).
    ///
    /// A **read-write** snapshot's private disk copy is staged at its baked-in path; a **read-only
    /// shared base** is referenced in place, so many clones restored from one warm snapshot share it
    /// (page-cache-deduped) while each gets its own in-RAM overlay. A **warm** snapshot (one taken with
    /// the vsock exec channel) restores exec-ready: its socket was baked in relative, so each clone
    /// re-binds its own socket in its own scratch dir and concurrent clones don't collide. If the
    /// snapshot carried vsock, restore waits until the guest agent is reachable before returning, so
    /// the VM can [`exec`](RunningVm::exec) immediately.
    ///
    /// A **networked** snapshot restores with a **fresh network identity** (decision 011): the driver
    /// recreates the snapshot's recorded tap (the pinned Firecracker has no `network_overrides`, so
    /// the name must match — which also means only one networked clone can be live at a time; a taken
    /// name is a typed error), assigns its host end a fresh /30, and the guest agent replaces the
    /// baked-in `eth0` address with the new one over vsock. Entropy is reseeded via VMGenID
    /// (Firecracker bumps the generation on restore and the guest kernel reseeds its CRNG — proven by
    /// test, not assumed), so clones don't share RNG state. The guest's **wall clock is not fixed
    /// up**: it lags by the snapshot's age until the workload resyncs it.
    ///
    /// Restore latency (load + resume) is [`RunningVm::boot_latency`] on the returned VM, for the
    /// cold-boot-vs-restore comparison.
    ///
    /// # Errors
    /// [`VmmError::NoKvm`] without `/dev/kvm`; [`VmmError::Artifact`] if a bundle file is missing or
    /// `firecracker` isn't found; [`VmmError::Timeout`] if the VMM never becomes ready; and
    /// [`VmmError::Vmm`] on any load/rebase/resume failure. On error the VMM is killed and the fresh
    /// scratch dir removed before returning.
    pub fn restore(snapshot: &Snapshot, config: &BootConfig) -> Result<RunningVm, VmmError> {
        if !Path::new("/dev/kvm").exists() {
            return Err(VmmError::NoKvm);
        }
        require_file(&snapshot.state, "snapshot state file")?;
        require_file(&snapshot.mem, "snapshot memory file")?;
        require_file(&snapshot.root_drive, "snapshot root disk")?;

        let mut spawned = Spawned::launch_for_restore(config, snapshot)?;
        let latency = match spawned.run_restore(snapshot, config.boot_timeout) {
            Ok(latency) => latency,
            Err(e) => return Err(spawned.abort(e)),
        };
        spawned.into_running(latency)
    }
}

impl RunningVm {
    /// Pause the VM, write a [`Snapshot`] bundle (device + vCPU state, guest memory, and the root
    /// disk) into `dir`, then resume — the VM keeps running and can be shut down or snapshotted again.
    ///
    /// A **read-write** boot's disk is copied into the bundle **inside the paused window**, so the copy
    /// agrees with the memory image; a **`read_only_root`** boot (a warm snapshot) references the shared
    /// base in place (no copy). The **vsock exec channel is supported** — restore re-binds its socket —
    /// so a warm snapshot restores exec-ready.
    ///
    /// Refused (a typed error, never an unrestorable bundle): a VM with an **output** or **input**
    /// block device (per-clone images a restore can't yet recreate), a VM with a **NIC but no vsock**
    /// (restore applies the clone's fresh network identity through the exec channel, so a networked
    /// snapshot without one couldn't be re-addressed — decision 011), and an **already-restored** VM
    /// (its `rootfs` is a placeholder; the live disk is an anonymous inode with no host path to
    /// bundle). A NIC *with* vsock is supported: the bundle records the tap name and restore rebuilds
    /// the link (see [`Vm::restore`]).
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the VM is unsupported for snapshotting, or on any API or file-copy failure.
    /// A create failure still falls through to the resume, so a failed snapshot never leaves the guest
    /// frozen.
    pub fn snapshot(&self, dir: &Path) -> Result<Snapshot, VmmError> {
        // A restored VM's `rootfs` is a placeholder (its live disk is an anonymous inode), so the
        // shared-base classifier below would misread it and bundle a stale, shared-writable disk.
        // Refuse it outright, the way the pre-warm-snapshot guard did.
        if self.restored {
            return Err(VmmError::Vmm(
                "snapshot of an already-restored VM is not supported (its live disk has no host path)"
                    .into(),
            ));
        }
        // A jailed VM's root disk lives inside the chroot (torn down with the scratch dir) and its
        // path is chroot-relative, so a bundle would record an unrestorable backing. Jailed
        // snapshot/restore is a later Phase-6 step.
        if self.chroot.is_some() {
            return Err(VmmError::Vmm(
                "snapshot of a jailed VM is not yet supported (its disk lives in the chroot)"
                    .into(),
            ));
        }
        // An output or input device carries a per-clone image a restore can't yet recreate (and the
        // input image lives at the gone source scratch path), so those stay refused. The vsock exec
        // channel is supported (restore re-binds its baked-in relative socket), and a NIC is supported
        // *through* it: restore recreates the recorded tap and the agent applies the clone's fresh
        // address over vsock (decision 011) — so a networked snapshot without vsock is refused too,
        // since its clone could never be re-addressed.
        if self.output.is_some() || self.has_input {
            return Err(VmmError::Vmm(
                "snapshot of a VM with an input/output device is not yet supported (P5.4/P5.5)"
                    .into(),
            ));
        }
        if self.tap.is_some() && self.vsock_uds.is_none() {
            return Err(VmmError::Vmm(
                "snapshot of a networked VM requires the vsock exec channel (restore re-addresses the \
                 clone through it); boot with BootConfig.guest_cid set"
                    .into(),
            ));
        }
        // The root disk is either a **private per-VM copy** (a read-write boot, whose backing lives
        // inside this VM's scratch dir: the bundle owns a point-in-time copy that restore stages back)
        // or a **read-only shared base** (a `read_only_root` boot: the base is a persistent pinned file
        // outside the scratch dir, so the bundle references it in place and clones share it read-only).
        // The structural test is which side of the scratch dir the backing lives on.
        let shared_base = !self.rootfs.starts_with(&self.workdir);
        std::fs::create_dir_all(dir)
            .map_err(|e| VmmError::Vmm(format!("create snapshot dir {}: {e}", dir.display())))?;
        // Absolute bundle paths: `restore` hands these to Firecracker, whose cwd is its own scratch
        // dir, so a relative bundle path would resolve there instead of where the caller put it.
        let dir = absolute(dir)?;
        let state = dir.join("snapshot.state");
        let mem = dir.join("snapshot.mem");
        // A private copy is bundled under `dir`; a shared base is referenced at its own path.
        let root_drive = if shared_base {
            self.rootfs.clone()
        } else {
            dir.join("rootfs.ext4")
        };

        // Pause → create → copy the (now-quiescent) disk → resume. Pausing freezes the vCPUs so the
        // memory image is a consistent point-in-time; copying the disk in the same window keeps it in
        // step with that memory. `create` failing still falls through to `resume` below, so the guest
        // is never left frozen.
        self.api.patch(
            "/vm",
            &VmState {
                state: VmStateKind::Paused,
            },
        )?;
        let created = self.write_snapshot_bundle(&state, &mem, &root_drive, shared_base);
        let resumed = self.api.patch(
            "/vm",
            &VmState {
                state: VmStateKind::Resumed,
            },
        );
        created?;
        resumed?;
        tracing::info!(dir = %dir.display(), shared_base, "wrote microVM snapshot bundle");
        Ok(Snapshot {
            state,
            mem,
            root_drive,
            root_backing: self.rootfs.clone(),
            shared_base,
            has_vsock: self.vsock_uds.is_some(),
            tap_name: self.tap.as_ref().map(|t| t.name.clone()),
        })
    }

    /// Write the snapshot state + memory files, and (for a private-copy disk) copy the root disk into
    /// the bundle. Split out so `snapshot` can run it between the pause and the guaranteed resume
    /// without an early return skipping the resume. A shared read-only base is referenced in place, so
    /// there is nothing to copy.
    fn write_snapshot_bundle(
        &self,
        state: &Path,
        mem: &Path,
        root_drive: &Path,
        shared_base: bool,
    ) -> Result<(), VmmError> {
        self.api.put(
            "/snapshot/create",
            &SnapshotCreate {
                snapshot_type: SnapshotType::Full,
                snapshot_path: path_str(state)?,
                mem_file_path: path_str(mem)?,
            },
        )?;
        if !shared_base {
            std::fs::copy(&self.rootfs, root_drive)
                .map_err(|e| VmmError::Vmm(format!("copy root disk into snapshot bundle: {e}")))?;
        }
        Ok(())
    }
}
