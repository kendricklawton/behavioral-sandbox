//! Cgroup-owned VM lifetime: make **host-process death unable to leak a VM**, and give the
//! embedder a **kill handle** that forces teardown from outside a blocked call.
//!
//! Until this module, teardown was `Drop`-based: correct on every path the driver *survives*, but a
//! `SIGKILL`ed / OOM-killed / Ctrl-C'd driver never runs `Drop`, and the Firecracker child lived on.
//! No in-process mechanism can fix that (a signal handler can't catch `SIGKILL`), so the fix is
//! crash-only design: the VM's lifetime is owned by things that survive the driver's death.
//!
//! - **A per-VM lifetime cgroup.** Each directly-spawned VMM is enrolled in a fresh child cgroup of
//!   the driver's own cgroup (`cgroup.procs`; no controllers enabled, so the cgroup v2
//!   "no internal processes" rule never applies). The cgroup gives the whole VMM tree one kernel
//!   handle: writing `1` to `cgroup.kill` SIGKILLs every member atomically, no pid races. A jailed
//!   VMM instead lives in the cgroup its jailer creates; the driver precomputes that path rather
//!   than duplicating a cgroup.
//! - **A sentinel that outlives the driver.** A tiny `sh` child, in its own process group (so a
//!   terminal Ctrl-C aimed at the driver's group misses it), blocks reading a pipe whose write end
//!   only the driver holds. The kernel closes that write end on *any* driver death, clean exit,
//!   `SIGKILL`, OOM, so the sentinel wakes exactly then, kills the VM's cgroup(s), and removes
//!   them. On a clean teardown the cgroups are already gone and the sentinel exits without acting.
//! - **A [`KillHandle`].** Cheap to clone, `Send + Sync`, and detached from the `RunningVm` borrow:
//!   it kills via the same `cgroup.kill` file, so a thread blocked in `exec` is unblocked (the VMM
//!   dies, the vsock peer closes) by another thread that holds no reference to the VM at all.
//!
//! **Honest limits.** The unprotected window is spawn → cgroup enrollment (microseconds; a driver
//! killed inside it leaks that one VMM, as before). A host that offers no writable cgroup v2 (no
//! `/sys/fs/cgroup`, or an unwritable one) degrades to `Drop`-only teardown with a warning, the
//! caps here are leak-proofing, not the isolation boundary, so they fail open (ADR 010). And
//! the sentinel reclaims the VM *process tree* and its cgroups; scratch dirs and taps left by a
//! `SIGKILL`ed driver are inert residue (no CPU, no RAM, no KVM), reclaimed by the next boot's leak
//! checks or a reboot, not by the sentinel.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::jail::read_cgroup_dir;
use crate::VmmError;

/// What the sentinel runs, verbatim (POSIX `sh`; the watched cgroup dirs arrive as `"$@"`).
///
/// `read` blocks until the driver dies (the kernel closes the pipe's write end on any exit path,
/// so EOF *is* the death notification, no polling, no signals). `trap ''` first, so a Ctrl-C
/// SIGINT that raced the new process group can't kill the sentinel before it has done its job.
/// Everything after the `read` is best-effort and idempotent: on a clean teardown the dirs are
/// already gone and both loops fall through instantly.
const SENTINEL_SCRIPT: &str = r#"
trap '' INT TERM HUP
read _ || :
for d in "$@"; do
  [ -d "$d" ] && { echo 1 > "$d/cgroup.kill"; } 2>/dev/null
done
n=0
while [ "$n" -lt 40 ]; do
  left=0
  for d in "$@"; do
    if [ -d "$d" ]; then rmdir "$d" 2>/dev/null || left=1; fi
  done
  [ "$left" -eq 0 ] && exit 0
  n=$((n+1))
  sleep 0.05 2>/dev/null || sleep 1
done
"#;

/// How long teardown waits for a disarmed sentinel to exit before hard-killing it. The sentinel's
/// own worst case is its bounded rmdir retry loop (~2 s); the driver must never hang on it.
const SENTINEL_REAP_TIMEOUT: Duration = Duration::from_secs(3);

/// A cloneable, `Send + Sync` handle that force-kills one VM from *outside* its owning borrow, the
/// host-gave-up path. `exec` blocks on the vsock socket; killing the VMM closes the peer, so the
/// blocked call returns a typed error instead of waiting out its budget.
///
/// The kill is the cgroup: writing `1` to the VM's `cgroup.kill` SIGKILLs the whole VMM tree with no
/// pid math, which is why this handle is safe to hold and fire from any thread at any time. Where
/// the VM has no cgroup (a degraded host), it falls back to signalling the VMM's pid, safe while
/// the VM exists (an unreaped child's pid can't be recycled) and a no-op once teardown has begun.
///
/// Killing is not tearing down: host residue (scratch dir, cgroup dirs) is still reclaimed by the
/// owner's `Drop`/`shutdown`, which is unblocked by exactly the death this handle causes.
#[derive(Debug, Clone)]
pub struct KillHandle {
    /// The cgroup dirs whose `cgroup.kill` reaches the VMM (usually one; a jailed VM lists the
    /// jailer's). Empty on a degraded host.
    cgroups: Arc<[PathBuf]>,
    /// The VMM child's pid, for the no-cgroup fallback.
    pid: u32,
    /// Set when teardown begins: the VM is already being reclaimed, so `kill` becomes a no-op (and
    /// the pid may be reaped, never signal it again).
    torn_down: Arc<AtomicBool>,
}

impl KillHandle {
    /// Force-kill the VM. Idempotent; `Ok(())` if the VM is already dead or torn down.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] only when the VM should still be alive and *no* kill path worked (no
    /// cgroup accepted the kill and the pid signal failed), the one case the caller must not
    /// mistake for a dead VM.
    pub fn kill(&self) -> Result<(), VmmError> {
        if self.torn_down.load(Ordering::Acquire) {
            return Ok(());
        }
        // `cgroup.kill` first: it takes the whole VMM tree in one write and races nothing (an
        // already-removed dir just fails the write, covered by the fallback or the flag).
        for dir in self.cgroups.iter() {
            if std::fs::write(dir.join("cgroup.kill"), "1").is_ok() {
                return Ok(());
            }
        }
        if self.torn_down.load(Ordering::Acquire) {
            return Ok(());
        }
        // Degraded-host fallback (no cgroup accepted the kill): signal the pid via `sh`'s builtin
        // `kill` (the host path is `unsafe`-free, so no direct `kill(2)` and no `pidfd`; `sh` is
        // already this module's dependency). Every reap path marks teardown down *before* it waits
        // the child (`teardown`/`abort`, and `power_off_and_wait` for the `collect_outputs` readback,
        // which reaps the VMM seconds before its owning `RunningVm` drops), so `torn_down` is already
        // set by the time a pid could be recycled and the checks above short-circuit, the
        // seconds-long readback window is closed. What remains is only the inherent microsecond
        // check-then-act TOCTOU of an *actively racing* teardown between the re-check just above and
        // the `kill` below; closing that fully needs a `pidfd` captured at spawn, which the
        // no-`unsafe` host path can't take without a new dep. Best-effort by construction.
        let killed = Command::new("sh")
            .arg("-c")
            .arg(format!("kill -9 {}", self.pid))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if killed || self.torn_down.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(VmmError::Vmm(format!(
                "kill handle could not reach VMM pid {} (no cgroup, and the pid signal failed)",
                self.pid
            )))
        }
    }
}

/// The lifetime machinery riding one VM: its lifetime cgroup (if this driver created one), the
/// watched cgroup set, the armed sentinel, and the shared teardown flag. Owned by the VM's guard
/// (`Spawned`, then `RunningVm`) and torn down with it.
#[derive(Debug)]
pub(crate) struct VmLifetime {
    /// The lifetime cgroup this driver created and enrolled the VMM in (unjailed VMs); removed on
    /// teardown. `None` for jailed VMs (the jailer owns the cgroup) and degraded hosts.
    own_cgroup: Option<PathBuf>,
    /// Every cgroup dir the sentinel and the kill handle act on.
    watched: Arc<[PathBuf]>,
    /// The armed sentinel child; its piped stdin is the death-notification write end.
    sentinel: Option<Child>,
    torn_down: Arc<AtomicBool>,
    pid: u32,
}

impl VmLifetime {
    /// Adopt a directly-spawned VMM: enroll `pid` in a fresh lifetime cgroup named `name` under the
    /// driver's own cgroup, and arm the sentinel on it. Best-effort, a host without writable
    /// cgroup v2 gets a warning and `Drop`-only teardown (never an error: leak-proofing fails open,
    /// ADR 010).
    pub(crate) fn adopt(pid: u32, name: &str) -> Self {
        let own_cgroup = match create_lifetime_cgroup(pid, name) {
            Ok(dir) => Some(dir),
            Err(reason) => {
                tracing::warn!(
                    pid,
                    %reason,
                    "no lifetime cgroup for this VM; teardown is Drop-only (driver death would \
                     leak the VMM)"
                );
                None
            }
        };
        let watched: Arc<[PathBuf]> = own_cgroup.iter().cloned().collect();
        Self {
            sentinel: arm_sentinel(&watched),
            own_cgroup,
            watched,
            torn_down: Arc::new(AtomicBool::new(false)),
            pid,
        }
    }

    /// Adopt a **jailed** VMM: the jailer creates (and moves the VMM into) its own cgroup, so
    /// enrolling the pid in a driver cgroup would *race the jailer's placement*, whichever write
    /// lands last would win membership and could yank the VMM out of its limits. Instead the
    /// sentinel and kill handle watch the jailer's (precomputed) cgroup dir. The unprotected window
    /// is spawn → the jailer's self-placement (milliseconds).
    pub(crate) fn watch(pid: u32, dirs: Vec<PathBuf>) -> Self {
        let watched: Arc<[PathBuf]> = dirs.into();
        Self {
            sentinel: arm_sentinel(&watched),
            own_cgroup: None,
            watched,
            torn_down: Arc::new(AtomicBool::new(false)),
            pid,
        }
    }

    /// A placeholder that owns nothing and does nothing, what `into_running` leaves behind in the
    /// `Spawned` guard so the real machinery moves to the `RunningVm` unmolested.
    pub(crate) fn disarmed() -> Self {
        Self {
            own_cgroup: None,
            watched: Arc::from([]),
            sentinel: None,
            torn_down: Arc::new(AtomicBool::new(true)),
            pid: 0,
        }
    }

    /// Whether `dir` is one of the cgroups the sentinel guards, the boot path cross-checks the
    /// jailer's *actual* cgroup against the precomputed one and warns on a mismatch (an unguarded
    /// VM is a recorded degradation, not a silent one).
    pub(crate) fn watches(&self, dir: &Path) -> bool {
        self.watched.iter().any(|w| w == dir)
    }

    /// The embedder's force-kill handle for this VM.
    pub(crate) fn kill_handle(&self) -> KillHandle {
        KillHandle {
            cgroups: Arc::clone(&self.watched),
            pid: self.pid,
            torn_down: Arc::clone(&self.torn_down),
        }
    }

    /// Mark teardown as begun, **before** the VMM child is reaped: from here every `KillHandle`
    /// no-ops, so a late `kill` can never signal a reaped (recyclable) pid.
    pub(crate) fn mark_down(&self) {
        self.torn_down.store(true, Ordering::Release);
    }

    /// Clean-path teardown, after the VMM is killed and reaped: remove the lifetime cgroup (now
    /// empty), then disarm the sentinel, dropping its stdin delivers the same EOF a driver death
    /// would, the sentinel finds the dirs already gone and exits, and a bounded reap keeps a
    /// wedged sentinel from ever hanging the driver (kill it instead; best-effort throughout).
    ///
    /// Idempotent: it takes both owned handles, so a second call (or the [`Drop`] net below) is a
    /// no-op. Callers invoke it explicitly to get the bounded sentinel reap *before* the scratch dir
    /// is removed; the `Drop` impl is only the safety net for a drop that skipped it.
    pub(crate) fn teardown(&mut self) {
        self.mark_down();
        if let Some(dir) = self.own_cgroup.take() {
            let _ = std::fs::remove_dir(&dir);
        }
        if let Some(mut sentinel) = self.sentinel.take() {
            drop(sentinel.stdin.take());
            let deadline = Instant::now() + SENTINEL_REAP_TIMEOUT;
            loop {
                match sentinel.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    // Timed out or unwaitable: no-hang beats politeness.
                    _ => {
                        let _ = sentinel.kill();
                        let _ = sentinel.wait();
                        break;
                    }
                }
            }
        }
    }
}

impl Drop for VmLifetime {
    /// The safety net that makes leak-freedom structural, not a manual invariant (mirroring
    /// [`Spawned`](crate::vm)'s and [`RunningVm`](crate::RunningVm)'s own `Drop` guards): any path
    /// that drops a live `VmLifetime` without an explicit [`teardown`](Self::teardown) still reaps
    /// the sentinel `sh` and its cgroup, so a dropped-but-not-torn-down VM can never leak a zombie
    /// sentinel or a cgroup dir. A no-op after an explicit teardown (both handles already taken).
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Create the per-VM lifetime cgroup as a child of the **driver's own** cgroup (the one place an
/// unprivileged driver is guaranteed write access when anything is, e.g. its delegated systemd
/// session scope) and enroll `pid`. No controllers are enabled, so this works with zero delegation
/// (like the guest agent's exec cgroups) and never trips the no-internal-processes rule.
fn create_lifetime_cgroup(pid: u32, name: &str) -> Result<PathBuf, String> {
    let own = read_cgroup_dir(std::process::id())
        .ok_or_else(|| "no cgroup v2 entry for this process".to_string())?;
    let dir = own.join(name);
    std::fs::create_dir(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    if let Err(e) = std::fs::write(dir.join("cgroup.procs"), pid.to_string()) {
        let _ = std::fs::remove_dir(&dir);
        return Err(format!("enroll pid {pid} in {}: {e}", dir.display()));
    }
    Ok(dir)
}

/// Arm the sentinel over `dirs`: `sh` in its **own process group** (a terminal Ctrl-C signals the
/// driver's group; the sentinel must survive it to do its job), stdin piped (the write end, held
/// only by the driver, is the death notification), stdout/stderr discarded. `None` (with a warning)
/// if there is nothing to watch or `sh` can't spawn, degraded, never fatal.
pub(crate) fn arm_sentinel(dirs: &[PathBuf]) -> Option<Child> {
    use std::os::unix::process::CommandExt as _;

    if dirs.is_empty() {
        return None;
    }
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(SENTINEL_SCRIPT)
        .arg("sentinel") // $0
        .args(dirs)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match cmd.spawn() {
        Ok(child) => Some(child),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not arm the VM-lifetime sentinel; driver death would leak this VMM's cgroup"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_test_support::ScratchDir;

    /// The core crash-safety mechanism, without a VM or privileges: the sentinel acts on pipe EOF.
    /// A plain directory stands in for the cgroup, `echo 1 > cgroup.kill` creates the file there
    /// (a real cgroup already has it), so "the kill was written" is observable as file content.
    #[test]
    fn sentinel_kills_watched_cgroups_on_driver_death() {
        let dir = ScratchDir::created("agent-sentinel");
        let cg = dir.path().join("cg");
        std::fs::create_dir(&cg).expect("create fake cgroup");

        let mut sentinel = arm_sentinel(std::slice::from_ref(&cg)).expect("arm sentinel");
        // Simulate driver death: the only write end of the sentinel's stdin closes.
        drop(sentinel.stdin.take());

        let deadline = Instant::now() + Duration::from_secs(5);
        let kill_file = cg.join("cgroup.kill");
        while !kill_file.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let written = std::fs::read_to_string(&kill_file).expect("sentinel wrote cgroup.kill");
        assert_eq!(written.trim(), "1", "sentinel must write the kill byte");

        let _ = sentinel.kill();
        let _ = sentinel.wait();
    }

    /// A clean teardown disarms the sentinel without it acting: the watched dir is already gone
    /// when EOF arrives, so nothing is written anywhere and the sentinel exits promptly.
    #[test]
    fn teardown_disarms_the_sentinel_without_a_kill() {
        let dir = ScratchDir::created("agent-sentinel-disarm");
        let cg = dir.path().join("cg");
        std::fs::create_dir(&cg).expect("create fake cgroup");

        let mut lt = VmLifetime {
            own_cgroup: Some(cg.clone()),
            watched: Arc::from([cg.clone()]),
            sentinel: arm_sentinel(std::slice::from_ref(&cg)),
            torn_down: Arc::new(AtomicBool::new(false)),
            pid: 0,
        };
        lt.teardown();
        assert!(!cg.exists(), "teardown removes the lifetime cgroup");
        assert!(lt.sentinel.is_none(), "teardown reaps the sentinel");
    }

    /// The `Drop` safety net: a `VmLifetime` dropped *without* an explicit `teardown()` must still
    /// reap its sentinel `sh` (no zombie), so no drop path can leak one. Capture the sentinel's pid,
    /// drop the lifetime, and assert the process is gone, not lingering as our zombie child.
    #[test]
    fn drop_reaps_the_sentinel_without_an_explicit_teardown() {
        let dir = ScratchDir::created("agent-sentinel-drop");
        let cg = dir.path().join("cg");
        std::fs::create_dir(&cg).expect("create fake cgroup");

        let lt = VmLifetime {
            own_cgroup: Some(cg.clone()),
            watched: Arc::from([cg.clone()]),
            sentinel: arm_sentinel(std::slice::from_ref(&cg)),
            torn_down: Arc::new(AtomicBool::new(false)),
            pid: 0,
        };
        let sentinel_pid = lt.sentinel.as_ref().expect("sentinel armed").id();
        drop(lt); // no teardown() call, the Drop net must still reap.

        // A reaped child leaves `/proc/<pid>` entirely; a leaked one lingers as a zombie (state `Z`).
        // Poll briefly since the kernel removes the entry a hair after `wait()` returns.
        let deadline = Instant::now() + Duration::from_secs(2);
        let reaped = loop {
            match std::fs::read_to_string(format!("/proc/{sentinel_pid}/stat")) {
                Err(_) => break true, // gone: fully reaped
                Ok(stat)
                    if stat.split(") ").nth(1).and_then(|s| s.split(' ').next()) == Some("Z") =>
                {
                    break false; // still a zombie child of ours: leaked
                }
                Ok(_) if Instant::now() >= deadline => break false,
                Ok(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        assert!(reaped, "Drop must reap the sentinel, leaving no zombie");
    }

    /// The kill handle's cgroup path: one write to `cgroup.kill`, observable on a stand-in dir.
    /// After teardown it must no-op (never signal a possibly-recycled pid).
    #[test]
    fn kill_handle_writes_cgroup_kill_then_noops_after_teardown() {
        let dir = ScratchDir::created("agent-killhandle");
        let cg = dir.path().join("cg");
        std::fs::create_dir(&cg).expect("create fake cgroup");

        let torn_down = Arc::new(AtomicBool::new(false));
        let handle = KillHandle {
            cgroups: Arc::from([cg.clone()]),
            pid: u32::MAX, // a pid that must never be signalled: the cgroup path must win
            torn_down: Arc::clone(&torn_down),
        };
        let clone = handle.clone(); // cheap, Send + Sync: the embedder's detached handle
        clone.kill().expect("cgroup-path kill succeeds");
        let written =
            std::fs::read_to_string(cg.join("cgroup.kill")).expect("kill handle wrote the file");
        assert_eq!(written, "1");

        torn_down.store(true, Ordering::Release);
        std::fs::remove_dir_all(&cg).expect("remove fake cgroup");
        handle.kill().expect("post-teardown kill is a no-op Ok");
    }
}
