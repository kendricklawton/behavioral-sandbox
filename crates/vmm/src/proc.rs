//! Bounded external-helper execution: [`run_bounded`] for the **teardown path**, where a hung child
//! would hang `Drop` itself, and [`output_bounded`] for the **boot path**, where one gives the
//! caller a typed error instead of an unbounded stall.
//!
//! Firecracker aside, the driver shells out to a few host tools (`ip`, `umount`, `mke2fs`, ...). Most
//! run on the boot path, where the boot deadline gates them and a stall fails the *run*, which the
//! caller sees. But `ip netns del` and `umount -l` run inside teardown/`Drop`, and both can wedge in
//! uninterruptible kernel sleep (D state): `ip netns del` behind the rtnl lock or a device that won't
//! release its refcount, `umount` behind a busy mount. A D-state child **cannot be killed or waited**
//! without hanging the very thread we are protecting (a `SIGKILL` just pends until the kernel op
//! finishes, and `wait` blocks on the same). So teardown helpers run under [`run_bounded`], which
//! detaches on timeout: it converts a rare, unrecoverable `Drop` **hang** into a rare **leak** (one
//! stuck kernel process, no CPU, reclaimed when the kernel unblocks or at reboot), which the engine's
//! existing recovery already digests, a failed `netns_del` keeps the scratch dir for the sweep, a
//! failed unmount is retried by the next sweep. No-hang beats politeness (the same rule the lifetime
//! sentinel's bounded reap follows).

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The wall a teardown helper gets before it is declared wedged and detached. `ip netns del` /
/// `umount -l` normally return in milliseconds, so this is pure headroom for a briefly-busy kernel,
/// not a budget a healthy helper ever spends.
pub(crate) const TEARDOWN_HELPER_TIMEOUT: Duration = Duration::from_secs(5);

/// The wall a **boot-path** `ip` invocation gets ([`output_bounded`]). The same rtnl-lock wedge that
/// motivated bounding `ip netns del` on teardown reaches `netns add` / `tuntap add` too; healthy
/// runs are milliseconds.
pub(crate) const IP_TIMEOUT: Duration = Duration::from_secs(10);

/// The wall a block-device build tool (`truncate`/`mke2fs`) gets. Generous: `mke2fs -d` on a large
/// bulk-input tree legitimately takes seconds, so this bounds a hung scratch filesystem, not a busy
/// one.
pub(crate) const IMAGE_TOOL_TIMEOUT: Duration = Duration::from_secs(120);

/// The wall the one-shot `firecracker --version` probe gets. Without it, an `EKVM_FIRECRACKER`
/// pointed at a binary that hangs on `--version` hangs **every** boot with no typed error, since
/// the probe runs before any deadline is consulted.
pub(crate) const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How a failed helper reads in an error: its own stderr when it wrote one, else its exit status.
/// A tool killed by a signal (a deadline kill, an operator's `kill`, the OOM killer) writes
/// nothing at all, and an error message ending in a bare colon names no cause: the status is then
/// the only fact there is. Callers name the tool themselves, so this carries only the "why".
pub(crate) fn failure_detail(status: std::process::ExitStatus, stderr: &str) -> String {
    let line = stderr.trim();
    if line.is_empty() {
        status.to_string()
    } else {
        line.to_string()
    }
}

/// Run `cmd` with a hard wall, returning its exit status and captured stderr, for a **boot-path**
/// helper whose caller wants a typed error rather than a stall. Unlike [`run_bounded`] (teardown:
/// detach and carry on), a timeout here is an `Err` the run surfaces; the child is killed and
/// briefly reaped, then detached if it cannot be (the D-state case, where waiting is the hang this
/// exists to prevent). The status comes back rather than a bare success flag so a signal-killed
/// (silent) helper can still be described, see [`failure_detail`].
///
/// stderr is read **after** the child exits, which terminates because these particular helpers
/// (`ip`, `truncate`, `mke2fs`) do not background a child that would inherit the pipe: reaping the
/// child closes the last write end. A helper that flooded more than a pipe buffer would block and
/// be caught by the wall instead, so the unbounded case is a timeout, never a deadlock. Do not
/// point this at an arbitrary operator-supplied program (`firecracker --version` deliberately uses
/// a file instead, see `spawn::probe_fc_version`).
pub(crate) fn output_bounded(
    mut cmd: Command,
    timeout: Duration,
    label: &str,
) -> Result<(std::process::ExitStatus, String), crate::VmmError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| crate::drives::tool_spawn_error(label, e))?;
    let deadline = Instant::now() + timeout;
    let status = crate::drives::wait_bounded(
        &mut child,
        deadline,
        label,
        Duration::from_millis(5),
        || None,
    )?;
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Ok((status, stderr))
}

/// What a bounded helper run produced: it exited within the wall (with its success flag and captured
/// stderr), or it outran the wall and was **detached** (left running, unreaped), never waited.
pub(crate) enum Bounded {
    /// The helper exited within the wall. `success` is its exit status; `stderr` is its captured
    /// standard error (for a failure log).
    Exited { success: bool, stderr: String },
    /// The helper did not finish within the wall (or could not be spawned/polled) and was detached to
    /// keep teardown from hanging. Nothing was reclaimed by this call.
    Detached,
}

/// Run `cmd` with a hard wall (stdin/stdout null, stderr captured), returning [`Bounded`]. On timeout
/// it **detaches** the child (does not `kill`/`wait` it, which a D-state helper would hang on) so
/// `Drop` can never block. See the module doc for why the leak-over-hang trade is correct here.
pub(crate) fn run_bounded(mut cmd: Command, timeout: Duration, label: &str) -> Bounded {
    let mut child = match cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(helper = label, error = %e, "could not spawn teardown helper");
            return Bounded::Detached;
        }
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Safe to read only now the child has exited: the pipe can't back-pressure a live
                // helper into blocking (if it ever filled the pipe unread it would stall and hit the
                // timeout below instead). Helper stderr is a line or two.
                let mut stderr = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut stderr);
                }
                return Bounded::Exited {
                    success: status.success(),
                    stderr,
                };
            }
            Ok(None) if Instant::now() >= deadline => {
                tracing::warn!(
                    helper = label,
                    "teardown helper did not finish within its wall; detaching to keep teardown \
                     from hanging (the stuck process is left for the kernel to release)"
                );
                return Bounded::Detached; // do NOT kill/wait: a D-state child would hang us here
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                tracing::warn!(helper = label, error = %e, "wait on teardown helper failed; detaching");
                return Bounded::Detached;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silent_failure_is_described_by_its_status() {
        // The regression this exists to hold: a helper killed by a signal writes no stderr, and
        // an error built from stderr alone ends in a bare colon, naming no cause at all.
        let killed = Command::new("sh")
            .args(["-c", "kill -9 $$"])
            .output()
            .expect("run a self-killing shell");
        assert!(killed.stderr.is_empty(), "the signal path writes no stderr");
        let detail = failure_detail(killed.status, "");
        assert!(
            !detail.trim().is_empty(),
            "a silent helper must still be described, got {detail:?}"
        );
        // Its own diagnosis wins when it wrote one.
        let failed = Command::new("false").status().expect("run `false`");
        assert_eq!(
            failure_detail(failed, "  mount: only root can do that\n"),
            "mount: only root can do that"
        );
    }

    #[test]
    fn a_fast_helper_exits_within_the_wall() {
        assert!(matches!(
            run_bounded(Command::new("true"), Duration::from_secs(5), "true"),
            Bounded::Exited { success: true, .. }
        ));
        assert!(matches!(
            run_bounded(Command::new("false"), Duration::from_secs(5), "false"),
            Bounded::Exited { success: false, .. }
        ));
    }

    #[test]
    fn a_wedged_helper_detaches_promptly_instead_of_hanging() {
        // Stands in for an `ip netns del`/`umount` stuck in the kernel: the call must give up at its
        // wall and detach, never wait the child out (which for a real D-state helper would hang Drop).
        let started = Instant::now();
        let mut cmd = Command::new("sleep");
        cmd.arg("10");
        assert!(
            matches!(
                run_bounded(cmd, Duration::from_millis(100), "sleep"),
                Bounded::Detached
            ),
            "a helper past its wall must detach"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "detach must fire at the wall, not wait the child out: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_unspawnable_helper_detaches() {
        assert!(matches!(
            run_bounded(
                Command::new("definitely-not-a-real-binary-xyzzy"),
                Duration::from_secs(1),
                "missing"
            ),
            Bounded::Detached
        ));
    }
}
