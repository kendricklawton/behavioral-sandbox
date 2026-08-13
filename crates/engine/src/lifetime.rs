//! Cgroup-owned VM lifetime: reclaim the VM process tree on **host-process death**, and give the
//! embedder a **kill handle** that forces teardown from outside a blocked call.
//!
//! `Drop` covers every path the driver survives, but a `SIGKILL`ed, OOM-killed or Ctrl-C'd driver
//! never runs it and its Firecracker child lives on, so the VM's lifetime is owned by things that
//! outlive the driver.
//!
//! - **A per-VM lifetime cgroup.** Each directly-spawned VMM is enrolled in a fresh child cgroup of
//!   the driver's own cgroup (`cgroup.procs`; no controllers enabled, so the cgroup v2 "no internal
//!   processes" rule never applies), which gives the whole VMM tree one kernel handle: writing `1`
//!   to `cgroup.kill` SIGKILLs every member atomically, no pid races. A jailed VMM instead lives in
//!   the cgroup its jailer creates, whose path the driver precomputes.
//! - **A sentinel that outlives the driver.** A tiny `sh` child, in its own process group (so a
//!   terminal Ctrl-C aimed at the driver's group misses it), blocks reading a pipe whose write end
//!   only the driver holds. The kernel closes that write end on *any* driver death, so the sentinel
//!   wakes exactly then, kills the VM's cgroup(s), and removes them.
//! - **A [`KillHandle`].** Detached from the `RunningVm` borrow and firing that same `cgroup.kill`,
//!   so a thread blocked in `exec` is unblocked by one holding no reference to the VM.
//!
//! **Limits.** Spawn → cgroup enrollment is unprotected. A host with no writable cgroup v2 degrades
//! to `Drop`-only teardown with a warning, because this is leak-proofing rather than the isolation
//! boundary. Closing the pid fallback's check-then-act window needs a `pidfd` taken at spawn, which
//! the `unsafe`-free host path cannot take. The sentinel reclaims the process tree and its cgroups
//! only: scratch dirs and taps are inert residue for the next boot's leak checks.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::VmmError;
use crate::jail::read_cgroup_dir;

/// What the sentinel runs, verbatim (POSIX `sh`; the watched cgroup dirs arrive as `"$@"`). `read`
/// blocks until the driver dies, since the kernel closes the pipe's write end on any exit path, so
/// EOF *is* the notification. `trap ''` comes first, so a Ctrl-C that raced the new process group
/// cannot kill the sentinel before it acts. Everything after the `read` is idempotent.
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

/// A cloneable, `Send + Sync` handle that force-kills one VM from *outside* its owning borrow, via
/// `cgroup.kill` and falling back to signalling the VMM's pid on a cgroup-less host. Killing is not
/// tearing down: host residue goes with the owner's `Drop`/`shutdown`, which this kill unblocks.
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
        // `cgroup.kill` first: one write takes the whole VMM tree and races nothing (an
        // already-removed dir just fails the write, covered by the fallback or the flag).
        for dir in self.cgroups.iter() {
            if std::fs::write(dir.join("cgroup.kill"), "1").is_ok() {
                return Ok(());
            }
        }
        if self.torn_down.load(Ordering::Acquire) {
            return Ok(());
        }
        // No cgroup accepted the kill: signal the pid through `sh`'s builtin, since an
        // `unsafe`-free host path has neither `kill(2)` nor `pidfd`. Every reap path marks teardown
        // *before* waiting the child, so a recyclable pid is already short-circuited above.
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

/// The lifetime machinery riding one VM, owned by the VM's guard (`Spawned`, then `RunningVm`) and
/// torn down with it.
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
    /// driver's own, and arm the sentinel on it. Never an error, since leak-proofing fails open: a
    /// host without writable cgroup v2 gets a warning and `Drop`-only teardown.
    pub(crate) fn adopt(pid: u32, name: &str) -> Self {
        let own_cgroup = match create_lifetime_cgroup(pid, name) {
            Ok(dir) => Some(dir),
            Err(reason) => {
                tracing::warn!(
                    pid,
                    %reason,
                    "no lifetime cgroup for this VM; teardown is Drop-only (driver death would \
                     leak the VMM); if the denied path is another user's session scope, this \
                     shell came from `su`/`sudo -s`: log in as this user directly for a \
                     delegated cgroup"
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

    /// Adopt a jailed VMM by watching the jailer's precomputed cgroup dirs: enrolling the pid in a
    /// driver cgroup instead would race the jailer's own placement and could yank the VMM out of
    /// its limits. Spawn → that self-placement is unprotected.
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

    /// A placeholder owning nothing, left in the `Spawned` guard by `into_running` so the real
    /// machinery moves to the `RunningVm` untouched.
    pub(crate) fn disarmed() -> Self {
        Self {
            own_cgroup: None,
            watched: Arc::from([]),
            sentinel: None,
            torn_down: Arc::new(AtomicBool::new(true)),
            pid: 0,
        }
    }

    /// Whether `dir` is one of the cgroups the sentinel guards. The boot path cross-checks the
    /// jailer's actual cgroup against the precomputed one, so an unguarded VM is a recorded
    /// degradation rather than a silent one.
    pub(crate) fn watches(&self, dir: &Path) -> bool {
        self.watched.iter().any(|w| w == dir)
    }

    /// Whether the sentinel is armed; `false` means teardown is `Drop`-only.
    pub(crate) fn sentinel_armed(&self) -> bool {
        self.sentinel.is_some()
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

    /// Clean-path teardown, after the VMM is killed and reaped: remove the now-empty lifetime
    /// cgroup, then disarm the sentinel by dropping its stdin, the same EOF a driver death
    /// delivers. Idempotent, since it takes both owned handles. Call it explicitly to get the
    /// bounded reap *before* the scratch dir is removed; [`Drop`] is only the net for a path that
    /// skipped it.
    pub(crate) fn teardown(&mut self) {
        self.mark_down();
        if let Some(dir) = self.own_cgroup.take() {
            let _ = std::fs::remove_dir(&dir);
        }
        if let Some(mut sentinel) = self.sentinel.take() {
            drop(sentinel.stdin.take());
            // The grace matches the wall, not `HELPER_REAP_GRACE`: the sentinel's own rmdir retry
            // loop runs ~2s, and a 200ms grace would detach one that was about to exit cleanly.
            if let Err(e) = crate::drives::wait_bounded(
                &mut sentinel,
                Instant::now() + SENTINEL_REAP_TIMEOUT,
                "lifetime sentinel",
                Duration::from_millis(10),
                SENTINEL_REAP_TIMEOUT,
            ) {
                // Nothing to act on (the kill already landed and teardown cannot fail), but the
                // typed error separates a wedged sentinel from a `try_wait` that could not answer.
                tracing::debug!(error = %e, "the lifetime sentinel did not exit cleanly");
            }
        }
    }
}

impl Drop for VmLifetime {
    /// The net for a drop that skipped [`teardown`](Self::teardown), and a no-op after one:
    /// `drop_reaps_the_sentinel_without_an_explicit_teardown` asserts it leaves no zombie.
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Create the per-VM lifetime cgroup under the driver's own, the path an unprivileged driver is
/// likeliest to be able to write, and enroll `pid`. Enables no controllers, so it needs no
/// delegation.
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

/// Arm the sentinel over `dirs`: `sh` in its own process group, so a terminal Ctrl-C aimed at the
/// driver's group misses it, with stdin piped as the death notification. `None` with a warning if
/// there is nothing to watch or `sh` cannot spawn: degraded, never fatal.
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
    use bsx_test_support::ScratchDir;

    /// The core crash-safety mechanism, without a VM or privileges: the sentinel acts on pipe EOF.
    /// A plain directory stands in for the cgroup, so `echo 1 > cgroup.kill` creates the file (a
    /// real cgroup already has it) and the kill is observable as file content.
    #[test]
    fn sentinel_kills_watched_cgroups_on_driver_death() {
        let dir = ScratchDir::created("bsx-sentinel");
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
        let dir = ScratchDir::created("bsx-sentinel-disarm");
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
    /// reap its sentinel `sh`, asserted as the pid being gone rather than lingering as our zombie.
    #[test]
    fn drop_reaps_the_sentinel_without_an_explicit_teardown() {
        let dir = ScratchDir::created("bsx-sentinel-drop");
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

        // A reaped child leaves `/proc/<pid>` entirely, a leaked one lingers as a zombie (`Z`).
        // Poll briefly since the kernel removes the entry a hair after `wait()` returns.
        let deadline = Instant::now() + Duration::from_secs(2);
        let reaped = loop {
            match bsx_test_support::process_state(sentinel_pid).as_deref() {
                None => break true,       // gone: fully reaped
                Some("Z") => break false, // still a zombie child of ours: leaked
                Some(_) if Instant::now() >= deadline => break false,
                Some(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        assert!(reaped, "Drop must reap the sentinel, leaving no zombie");
    }

    /// The kill handle's cgroup path: one write to `cgroup.kill`, observable on a stand-in dir.
    /// After teardown it must no-op (never signal a possibly-recycled pid).
    #[test]
    fn kill_handle_writes_cgroup_kill_then_noops_after_teardown() {
        let dir = ScratchDir::created("bsx-killhandle");
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

    /// On a degraded host (cgroup v2 unavailable/unwritable or sentinel unarmable), VmLifetime
    /// degrades to Drop-only teardown and KillHandle falls back to signaling the VMM pid directly.
    #[test]
    fn degraded_host_drop_only_teardown_and_pid_fallback_kill() {
        let mut dummy = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dummy process");
        let pid = dummy.id();

        let mut lt = VmLifetime {
            own_cgroup: None,
            watched: Arc::from([]),
            sentinel: None,
            torn_down: Arc::new(AtomicBool::new(false)),
            pid,
        };

        assert!(!lt.sentinel_armed(), "degraded host has no armed sentinel");

        let handle = lt.kill_handle();
        handle
            .kill()
            .expect("pid fallback kill succeeds on degraded host");

        let status = dummy.wait().expect("wait for killed dummy process");
        assert!(
            !status.success(),
            "dummy process was killed by pid fallback"
        );

        lt.teardown();
        assert!(
            lt.sentinel.is_none(),
            "teardown on degraded lifetime completes cleanly"
        );
    }
}
