//! Snapshot and restore, the point-in-time-copy half of the VM lifecycle. [`RunningVm::snapshot`]
//! pauses a VM and writes a portable [`Snapshot`](crate::Snapshot) bundle (device + vCPU state,
//! guest memory, root disk); [`Vm::restore`] rebuilds a VM from one on a fresh VMM.
//!
//! - **CPU portability.** Firecracker snapshots preserve the producing host's CPUID features
//!   (`cpu_template` is unset by default), so restoring on a different CPU model, or on a host
//!   lacking a produced feature, can fault the guest with an illegal instruction. Cross-host
//!   restore requires identical CPU models or a matching CPU template.

use std::path::Path;
use std::time::Duration;

use crate::VmmError;
use crate::firecracker::{
    SnapshotCreate, SnapshotType, VmState, VmStateKind, snapshot_api_timeout,
};
use crate::paths::{absolute, path_str, require_file};
use crate::spawn::Spawned;
use crate::vm::{BootConfig, RunningVm, Snapshot, Vm};

/// How long a snapshot waits for the guest agent to answer again after the resume. The guest
/// re-arms its vsock listener within milliseconds of resuming; this bound exists so a guest that
/// died under the pause surfaces as a typed timeout, not an exec that burns its whole wall.
const AGENT_RESUME_WAIT: Duration = Duration::from_secs(10);

impl Vm {
    /// Restore a microVM from a [`Snapshot`] on a fresh VMM and resume it, returning once it's
    /// running and (if the snapshot carried the exec channel) exec-ready. Reuses only the
    /// `firecracker` binary, `boot_timeout`, the per-exec budgets
    /// ([`exec_wall`](BootConfig::exec_wall)/[`output_cap`](BootConfig::output_cap), the restoring
    /// host's bounds, not the source's), and [`jail`](BootConfig::jail) from `config`; the kernel,
    /// memory, and devices come from the snapshot. Restore latency is
    /// [`RunningVm::boot_latency`] on the returned VM.
    ///
    /// **Disk.** A read-write snapshot's private copy is staged at its baked-in path; a read-only
    /// shared base is referenced in place, page-cache-deduped across clones that each get their own
    /// in-RAM overlay. `PUT /snapshot/load` carries no drive-path override, so unjailed restores of
    /// a read-write snapshot are **single-flight**: sequence them as the [`Pool`](crate::Pool)
    /// does, or use a jailed restore or a `read_only_root` snapshot for concurrent clones.
    ///
    /// **Exec.** A snapshot's vsock socket was baked in relative, so each clone re-binds its own in
    /// its own scratch dir, and restore waits until the guest agent is reachable before returning.
    ///
    /// **Network.** A networked snapshot restores into a fresh per-VM netns where the baked-in
    /// guest address, MAC, and routes are already correct and collision-free, so clones coexist
    /// with no re-addressing. Entropy is reseeded via VMGenID (proven by test) and the clock is
    /// advanced across the snapshot's age at load: the host's measure of elapsed time, not a sync.
    ///
    /// **Jailed.** With [`jail`](BootConfig::jail) set the bundle is staged into the chroot, the
    /// memory file and a shared base disk bind-mounted read-only, a private disk copy handed to the
    /// jailed uid, and a networked clone's netns joined via `--netns`. Needs real root. The cgroup
    /// caps come from the *snapshot's* true envelope, not `config`'s declaration (`memory.max` from
    /// the memory file's size, `cpu.max` from [`Snapshot::vcpus`], a constant `pids.max`), and
    /// restore issues no `PUT /machine-config`, so a `config` under-declaring the guest cannot OOM
    /// or throttle a legitimate clone.
    ///
    /// # Errors
    /// [`VmmError::LimitsUnavailable`] if [`require_limits`](BootConfig::require_limits) is set on
    /// an unjailed restore; [`VmmError::NoKvm`] without `/dev/kvm`; [`VmmError::Artifact`] if a
    /// bundle file is missing or `firecracker` isn't found; [`VmmError::Timeout`] if the VMM never
    /// becomes ready; and [`VmmError::Vmm`] on any load/rebase/resume failure. On error the VMM is
    /// killed and the fresh scratch dir removed before returning.
    pub fn restore(snapshot: &Snapshot, config: &BootConfig) -> Result<RunningVm, VmmError> {
        // The cold boot's guards, run before the KVM probe so a posture contradiction fails fast
        // and host-safe. A restore-into-jail uses the same chroot, so the scratch guard applies.
        crate::vm::refuse_uncappable_boot(config)?;
        crate::vm::refuse_unusable_scratch(config)?;
        if !Path::new("/dev/kvm").exists() {
            return Err(VmmError::NoKvm);
        }
        // No `fetch-artifacts` hint: a snapshot bundle is the embedder's own, no xtask produces it.
        require_file(&snapshot.state, "snapshot state file", None)?;
        require_file(&snapshot.mem, "snapshot memory file", None)?;
        require_file(&snapshot.root_drive, "snapshot root disk", None)?;

        // One deadline for the whole restore, computed before the pre-spawn staging so both share
        // it; `run_restore` enforces it around the disk stage and every API step.
        let deadline = crate::spawn::boot_deadline(config.boot_timeout);
        let mut spawned = Spawned::launch_for_restore(config, snapshot)?;
        let latency = match spawned.run_restore(snapshot, deadline) {
            Ok(latency) => latency,
            Err(e) => return Err(spawned.abort(e)),
        };
        spawned.into_running(latency, config)
    }
}

impl RunningVm {
    /// Pause the VM, write a [`Snapshot`] bundle (device + vCPU state, guest memory, and the root
    /// disk) into `dir`, then resume: the VM keeps running and can be snapshotted again. For a
    /// vsock VM, returning also means the guest agent answers again (Firecracker drops every vsock
    /// connection at create, and the guest re-arms its listener only after the resume), so the next
    /// `exec` cannot race that window.
    ///
    /// A **read-write** boot's disk is copied into the bundle **inside the paused window**, so the
    /// copy agrees with the memory image; a **`read_only_root`** boot (a prewarmed snapshot)
    /// references the shared base in place. Restore re-binds the vsock socket, so a prewarmed
    /// snapshot restores exec-ready.
    ///
    /// Refused with a typed error, never an unrestorable bundle: a VM with an **output** or
    /// **input** block device (per-clone images a restore cannot yet recreate), a **jailed** VM
    /// (its disk lives at a chroot-relative path, so a bundle records an unrestorable backing), and
    /// an **already-restored** VM (its live disk is an anonymous inode, no host path). The clone
    /// story is to snapshot an *unjailed* prewarmed source and restore **jailed** clones from it,
    /// which is where the untrusted code runs. A NIC is supported: the bundle records the tap name
    /// and restore recreates it in each clone's own netns.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the VM is unsupported for snapshotting, or on any API or file-copy
    /// failure. A **create** failure still falls through to the resume, so it never leaves the
    /// guest frozen. A **resume** failure (the VMM went unresponsive after a good create) may leave
    /// the guest paused and returns the error: drop the VM (its teardown reaps it), never reuse it.
    pub fn snapshot(&mut self, dir: &Path) -> Result<Snapshot, VmmError> {
        // A restored VM's `rootfs` is a placeholder, so the shared-base classifier below would
        // misread it and bundle a stale, shared-writable disk.
        if self.restored {
            return Err(VmmError::Vmm(
                "snapshot of an already-restored VM is not supported (its live disk has no host path)"
                    .into(),
            ));
        }
        if self.chroot.is_some() {
            return Err(VmmError::Vmm(
                "snapshot of a jailed VM is not supported (its disk lives in the chroot); snapshot \
                 an unjailed prewarmed source and restore jailed clones from it"
                    .into(),
            ));
        }
        // The input image also lives at the source scratch path, which is gone after teardown.
        if self.output.is_some() || self.has_input {
            return Err(VmmError::Vmm(
                "snapshot of a VM with an input/output device is not yet supported".into(),
            ));
        }
        // Which side of the scratch dir the backing lives on is the structural test: inside it is a
        // read-write boot's private per-VM copy, outside it the persistent read-only shared base.
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

        // Pause → create → copy the now-quiescent disk → resume: the pause freezes the vCPUs so the
        // memory image is a consistent point-in-time, and copying the disk in the same window keeps
        // it in step. `create` failing still falls through to `resume` below.
        self.api.patch(
            "/vm",
            &VmState {
                state: VmStateKind::Paused,
            },
        )?;
        // Armed across the create window, because a later `Vm::restore` would pass its
        // file-existence checks on a torn bundle and fail only deep in the load.
        let sweep = PartialBundle {
            state: &state,
            mem: &mem,
            private_disk: (!shared_base).then_some(&root_drive),
            armed: true,
        };
        let created = self.write_snapshot_bundle(&state, &mem, &root_drive, shared_base);
        let resumed = self.api.patch(
            "/vm",
            &VmState {
                state: VmStateKind::Resumed,
            },
        );
        created?;
        sweep.disarm();
        // There is no public un-pause, and a later `exec` would burn its whole wall against a
        // frozen guest, so a failed resume has to say the VM is unusable.
        if let Err(e) = resumed {
            tracing::warn!(
                error = %e,
                "snapshot created but resume failed; the VM is likely left paused and unusable, \
                 drop it (teardown reaps it) rather than reusing this handle"
            );
            return Err(e);
        }
        // An exec issued the instant this returns can race the listener's re-arm and die
        // mid-handshake, so wait for the agent as `Vm::restore` does. The bundle on disk is
        // complete either way, so a timeout here is the *session* wedged and the error says so.
        if self.vsock_uds.is_some() {
            let deadline = std::time::Instant::now() + AGENT_RESUME_WAIT;
            let mut backoff = crate::spawn::PollBackoff::new();
            loop {
                match self.probe_agent() {
                    Ok(()) => break,
                    Err(e) => {
                        // Liveness before the clock, as `await_guest_ready` does: a VMM that died
                        // under the pause is a dead session now, not a wedged one in ten seconds.
                        if let Some(status) = self.child.try_wait().ok().flatten() {
                            return Err(VmmError::Vmm(format!(
                                "firecracker exited during the snapshot resume ({status}); the \
                                 bundle at {} is complete, but this session VM is gone",
                                dir.display()
                            )));
                        }
                        if std::time::Instant::now() >= deadline {
                            return Err(VmmError::Timeout(format!(
                                "guest agent not reachable after snapshot resume (the bundle at {} \
                                 is complete; this session VM is wedged): {e}",
                                dir.display()
                            )));
                        }
                        backoff.sleep();
                    }
                }
            }
        }
        tracing::info!(dir = %dir.display(), shared_base, "wrote microVM snapshot bundle");
        Ok(Snapshot {
            state,
            mem,
            root_drive,
            root_backing: self.rootfs.clone(),
            shared_base,
            has_vsock: self.vsock_uds.is_some(),
            tap_name: self.tap.as_ref().map(|t| t.name.clone()),
            // The source's true envelope: a restored VM was refused above, so this boot-time value
            // is what `PUT /machine-config` really set; a jailed restore reads `cpu.max` off it.
            vcpus: self.vcpus,
        })
    }

    /// Write the snapshot state + memory files, and (for a private-copy disk) copy the root disk
    /// into the bundle. Split out so `snapshot` can run it between the pause and the unconditional
    /// resume without an early return skipping the resume.
    fn write_snapshot_bundle(
        &self,
        state: &Path,
        mem: &Path,
        root_drive: &Path,
        shared_base: bool,
    ) -> Result<(), VmmError> {
        // `/snapshot/create` replies only after Firecracker writes the whole `mem_mib`-sized memory
        // file, so its socket timeout scales with guest RAM, not the instant-reply default.
        self.api.put_with_timeout(
            "/snapshot/create",
            &SnapshotCreate {
                snapshot_type: SnapshotType::Full,
                snapshot_path: path_str(state)?,
                mem_file_path: path_str(mem)?,
            },
            snapshot_api_timeout(self.mem_mib.get()),
        )?;
        if !shared_base {
            std::fs::copy(&self.rootfs, root_drive)
                .map_err(|e| VmmError::Vmm(format!("copy root disk into snapshot bundle: {e}")))?;
        }
        Ok(())
    }
}

/// RAII sweep of a possibly-partial snapshot bundle: the state file, the memory file, and (for a
/// private-copy disk) the bundled root disk, a shared read-only base riding as `None` because it is
/// referenced in place. `Drop` removes them best-effort on every exit from the create window, an
/// error return *or* an unwinding panic, until [`disarm`](Self::disarm) marks the bundle complete.
struct PartialBundle<'a> {
    state: &'a Path,
    mem: &'a Path,
    private_disk: Option<&'a Path>,
    armed: bool,
}

impl PartialBundle<'_> {
    /// The create succeeded: the bundle is complete, nothing to sweep.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for PartialBundle<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(self.state);
            let _ = std::fs::remove_file(self.mem);
            if let Some(disk) = self.private_disk {
                let _ = std::fs::remove_file(disk);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::panic)] // the deliberate panic *is* the unwind this test exercises
    fn a_partial_bundle_is_swept_even_when_the_scope_unwinds() {
        // A panic between the snapshot-create call and the disarm must not strand torn bundle files
        // a later restore would half-open; and a disarmed, completed bundle must survive the guard.
        let scratch = bsx_test_support::ScratchDir::created("bundle-unwind");
        let dir = scratch.path();
        let state = dir.join("snapshot.state");
        let mem = dir.join("snapshot.mem");
        let disk = dir.join("rootfs.ext4");
        for f in [&state, &mem, &disk] {
            std::fs::write(f, b"partial").expect("stage");
        }

        let (s, m, d) = (state.clone(), mem.clone(), disk.clone());
        let caught = std::panic::catch_unwind(move || {
            let _sweep = PartialBundle {
                state: &s,
                mem: &m,
                private_disk: Some(&d),
                armed: true,
            };
            panic!("boom mid-create");
        });
        assert!(caught.is_err(), "the panic propagated");
        for f in [&state, &mem, &disk] {
            assert!(!f.exists(), "{} must be swept on unwind", f.display());
        }

        for f in [&state, &mem] {
            std::fs::write(f, b"complete").expect("stage again");
        }
        PartialBundle {
            state: &state,
            mem: &mem,
            private_disk: None,
            armed: true,
        }
        .disarm();
        for f in [&state, &mem] {
            assert!(f.exists(), "a disarmed bundle must survive the guard");
        }
    }
}
