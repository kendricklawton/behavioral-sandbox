//! Snapshot and restore, the point-in-time-copy half of the VM lifecycle, split out of `vm.rs`.
//! [`RunningVm::snapshot`] pauses a VM and writes a portable [`Snapshot`](crate::Snapshot) bundle
//! (device + vCPU state, guest memory, root disk); [`Vm::restore`] rebuilds a VM from one on a fresh
//! VMM. The [`Snapshot`] type itself stays in `vm.rs` with the other public surface; this module
//! holds only the orchestration, the way `spawn.rs` holds the boot sequence.
//!
//! **CPU Portability:** Firecracker snapshots preserve the producing host's CPUID features (`cpu_template`
//! is unset by default). Restoring a snapshot on a different CPU model or host lacking produced CPUID
//! features can fault the guest with an illegal instruction. Cross-host restore requires identical CPU
//! models or a matching CPU template.

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
    /// ([`exec_wall`](BootConfig::exec_wall)/[`output_cap`](BootConfig::output_cap), they are the
    /// restoring host's bounds, not the source's), and [`jail`](BootConfig::jail) from `config`
    /// (the guest's kernel, memory, and devices all come from the snapshot).
    ///
    /// **Disk.** A read-write snapshot's private copy is staged at its baked-in path; a read-only shared
    /// base is referenced in place, so many clones share it page-cache-deduped while each gets its own
    /// in-RAM overlay. `PUT /snapshot/load` carries no drive-path override, so unjailed restores of a
    /// read-write snapshot are **single-flight**: run them sequentially, as the [`Pool`](crate::Pool)
    /// does, or use a jailed restore or a `read_only_root` snapshot for concurrent clones.
    ///
    /// **Exec.** A snapshot taken with the vsock exec channel restores exec-ready: its socket was baked
    /// in relative, so each clone re-binds its own in its own scratch dir, and restore waits until the
    /// guest agent is reachable before returning.
    ///
    /// **Network.** A networked snapshot restores into a fresh per-VM netns where the baked-in guest
    /// address, MAC, and routes are already correct and collision-free, so any number of clones coexist
    /// with no re-addressing. Entropy is reseeded via VMGenID (proven by test), so clones do not share
    /// RNG state, and the guest's clock is advanced across the snapshot's age at load: the host's
    /// measure of elapsed time, not a time sync.
    ///
    /// **Jailed.** With [`jail`](BootConfig::jail) set the bundle is staged into the chroot, the memory
    /// file and a shared base disk bind-mounted read-only, a private disk copy handed to the jailed uid,
    /// and a networked clone's netns joined via `--netns`. Needs real root. The cgroup caps are
    /// re-applied from the *snapshot's* true envelope rather than `config`'s declaration (`memory.max`
    /// from the memory file's size, `cpu.max` from [`Snapshot::vcpus`], a constant `pids.max`), and
    /// restore issues no `PUT /machine-config`, so a `config` under-declaring the guest cannot OOM or
    /// throttle a legitimate clone.
    ///
    /// Restore latency is [`RunningVm::boot_latency`] on the returned VM.
    ///
    /// # Errors
    /// [`VmmError::LimitsUnavailable`] if [`require_limits`](BootConfig::require_limits) is set on an
    /// unjailed restore; [`VmmError::NoKvm`] without `/dev/kvm`; [`VmmError::Artifact`] if a bundle
    /// file is missing or `firecracker` isn't found; [`VmmError::Timeout`] if the VMM never becomes
    /// ready; and [`VmmError::Vmm`] on any load/rebase/resume failure. On error the VMM is killed and
    /// the fresh scratch dir removed before returning.
    pub fn restore(snapshot: &Snapshot, config: &BootConfig) -> Result<RunningVm, VmmError> {
        // Same posture guard as a cold boot: a require_limits restore into an unjailed clone can't be
        // capped, so refuse it (a jailed clone's delegation is checked deeper, in the jailer cgroup
        // args). Before the KVM probe so the contradiction fails fast and host-safe.
        crate::vm::refuse_uncappable_boot(config)?;
        // A restore-into-jail uses the same chroot (its /dev/kvm and firecracker copy), so the
        // nodev/noexec scratch guard applies here too, failing fast with the typed pointer before
        // the KVM probe.
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
    /// disk) into `dir`, then resume, the VM keeps running and can be shut down or snapshotted again.
    /// For a vsock VM, returning also means the guest agent answers again (Firecracker drops every
    /// vsock connection at create, and the guest re-arms its listener only after the resume), so
    /// the next `exec` cannot race that window.
    ///
    /// A **read-write** boot's disk is copied into the bundle **inside the paused window**, so the copy
    /// agrees with the memory image; a **`read_only_root`** boot (a prewarmed snapshot) references the shared
    /// base in place (no copy). The **vsock exec channel is supported**, restore re-binds its socket,
    /// so a prewarmed snapshot restores exec-ready.
    ///
    /// Refused (a typed error, never an unrestorable bundle): a VM with an **output** or **input**
    /// block device (per-clone images a restore cannot yet recreate), a **jailed** VM (its disk lives
    /// inside the chroot at a chroot-relative path, so a bundle would record an unrestorable backing),
    /// and an **already-restored** VM (its `rootfs` is a placeholder; the live disk is an anonymous
    /// inode with no host path to bundle). The clone story is to snapshot an *unjailed* prewarmed
    /// source and restore **jailed** clones from it, which is where the untrusted code runs. A NIC is
    /// supported: the bundle records the tap name and restore recreates it in each clone's own netns.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the VM is unsupported for snapshotting, or on any API or file-copy failure.
    /// A **create** failure still falls through to the resume, so it never leaves the guest frozen. A
    /// **resume** failure (the VMM went unresponsive after a good create) is the exception: it may
    /// leave the guest paused and returns the error, drop the VM in that case (its teardown reaps it)
    /// rather than reusing the handle.
    pub fn snapshot(&self, dir: &Path) -> Result<Snapshot, VmmError> {
        // A restored VM's `rootfs` is a placeholder (its live disk is an anonymous inode), so the
        // shared-base classifier below would misread it and bundle a stale, shared-writable disk.
        if self.restored {
            return Err(VmmError::Vmm(
                "snapshot of an already-restored VM is not supported (its live disk has no host path)"
                    .into(),
            ));
        }
        // A jailed VM's root disk lives inside the chroot (torn down with the scratch dir) and its
        // path is chroot-relative, so a bundle would record an unrestorable backing. Deliberate, not
        // just deferred: the clone story is snapshot an *unjailed* prewarmed source (it runs only
        // the embedder's warm-up), then restore **jailed** clones from it, the untrusted code runs
        // confined; the source needs no jail to protect the host from itself.
        if self.chroot.is_some() {
            return Err(VmmError::Vmm(
                "snapshot of a jailed VM is not supported (its disk lives in the chroot); snapshot \
                 an unjailed prewarmed source and restore jailed clones from it"
                    .into(),
            ));
        }
        // An output or input device carries a per-clone image a restore can't yet recreate (and the
        // input image lives at the gone source scratch path), so those stay refused. The vsock exec
        // channel is supported (restore re-binds its baked-in relative socket), and a NIC is supported
        // too: under the netns model restore recreates the recorded tap in a fresh per-VM
        // netns, where the snapshot's baked-in identity is already correct, no re-addressing, so a
        // networked snapshot does not need vsock.
        if self.output.is_some() || self.has_input {
            return Err(VmmError::Vmm(
                "snapshot of a VM with an input/output device is not yet supported".into(),
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
        // Armed across the create window: a failed create *or* a panic unwinding out of it sweeps
        // the partial, guest-RAM-sized bundle files (a later `Vm::restore` would pass its
        // file-existence checks on a torn bundle and fail only deep in the load), so the caller's
        // dir holds a bundle or nothing. Disarmed once the create is known good.
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
        // Resume failing after a successful create is the one path that can leave the guest paused
        // (the VMM is unresponsive, since the resume PATCH is otherwise instant). There is no public
        // un-pause, and a later `exec` would just burn its whole wall against a frozen guest, so say
        // so: the VM is unusable and should be dropped (its teardown reaps it), not reused.
        if let Err(e) = resumed {
            tracing::warn!(
                error = %e,
                "snapshot created but resume failed; the VM is likely left paused and unusable, \
                 drop it (teardown reaps it) rather than reusing this handle"
            );
            return Err(e);
        }
        // Firecracker closes every vsock connection at snapshot creation, and the guest re-arms
        // its listener only after the resume: an exec issued the instant this returns can race
        // that window and die mid-handshake. Wait until the agent answers again (the promise
        // `Vm::restore` already keeps), so returning means the session is still exec-ready. The
        // bundle on disk is complete either way; a timeout here is the *session* wedged, and the
        // error says so.
        if self.vsock_uds.is_some() {
            let deadline = std::time::Instant::now() + AGENT_RESUME_WAIT;
            let mut backoff = crate::spawn::PollBackoff::new();
            loop {
                match self.probe_agent() {
                    Ok(()) => break,
                    Err(e) if std::time::Instant::now() >= deadline => {
                        return Err(VmmError::Timeout(format!(
                            "guest agent not reachable after snapshot resume (the bundle at {} is \
                             complete; this session VM is wedged): {e}",
                            dir.display()
                        )));
                    }
                    Err(_) => backoff.sleep(),
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
            // The source's true envelope (this VM is boot-originated, a restored VM was refused
            // above, so the boot-time config value is what `PUT /machine-config` really set): a
            // jailed restore derives its `cpu.max` from this, not from the restoring config.
            vcpus: self.vcpus,
        })
    }

    /// Write the snapshot state + memory files, and (for a private-copy disk) copy the root disk into
    /// the bundle. Split out so `snapshot` can run it between the pause and the unconditional resume
    /// without an early return skipping the resume. A shared read-only base is referenced in place, so
    /// there is nothing to copy.
    fn write_snapshot_bundle(
        &self,
        state: &Path,
        mem: &Path,
        root_drive: &Path,
        shared_base: bool,
    ) -> Result<(), VmmError> {
        // `/snapshot/create` replies only after Firecracker writes the whole `mem_mib`-sized memory
        // file, so its socket timeout scales with guest RAM, not the instant-reply default (a
        // multi-GiB guest on a slow disk would otherwise spuriously time out a valid snapshot).
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

/// RAII sweep of a possibly-partial snapshot bundle: the state file, the guest-RAM-sized memory
/// file, and (for a private-copy disk) the bundled root disk; a shared read-only base is referenced
/// in place, never copied, so it rides as `None` and is left untouched. `Drop` removes the files,
/// best-effort, on every exit from the create window, an error return *or* an unwinding panic,
/// until [`disarm`](Self::disarm) marks the bundle complete, so the caller's dir holds a bundle or
/// nothing and a later `Vm::restore` can't half-open a torn one.
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
        // The leak the guard closes: a panic between the snapshot-create API call and the disarm
        // must not strand torn, guest-RAM-sized bundle files a later restore would half-open. And
        // the disarm half: a completed bundle survives the guard.
        let dir = std::env::temp_dir().join(format!("bsx-bundle-unwind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
