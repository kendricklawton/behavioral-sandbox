//! Bounded external-helper execution for the **teardown path**, where a hung child would hang `Drop`
//! itself, the one place the driver must never block.
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
