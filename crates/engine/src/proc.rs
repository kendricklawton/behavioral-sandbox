//! Bounded external-helper execution: [`run_bounded`] for the **teardown path**, where a hung child
//! would hang `Drop` itself, and [`output_bounded`] for the **boot path**, where one gives the caller a
//! typed error instead of an unbounded stall.
//!
//! Most host tools the driver shells out to run on the boot path, where the boot deadline gates them
//! and a stall fails the *run*. But `ip netns del` and `umount -l` run inside teardown, and both can
//! wedge in uninterruptible kernel sleep: behind the rtnl lock, a device that won't release its
//! refcount, or a busy mount. A D-state child **cannot be killed or waited** without hanging the very
//! thread being protected, since a `SIGKILL` pends until the kernel op finishes and `wait` blocks on
//! the same.
//!
//! So teardown helpers run under [`run_bounded`], which detaches on timeout: it converts a rare,
//! unrecoverable `Drop` **hang** into a rare **leak** of one stuck kernel process holding no CPU, which
//! the engine's existing recovery already digests. A failed `netns_del` keeps the scratch dir for the
//! sweep, and a failed unmount is retried by the next sweep. No-hang beats politeness.

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

/// The wall the one-shot `firecracker --version` probe gets. Without it, an `BSX_FIRECRACKER`
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

/// A private scratch file for a child's output: `(the child's write handle, our read-back handle)`,
/// both onto the same **already-unlinked** file.
///
/// `create_new` (`O_CREAT|O_EXCL`) and 0600, not `File::create`: the driver usually runs as root and
/// the temp dir is world-writable, so a predictable name opened with plain `create` is a symlink
/// hijack, a local user pre-creating the path aims the truncating open at any file root can write.
/// `O_EXCL` refuses to follow a symlink at all, and the retry loop covers a name that already
/// exists. Unlinking straight away means nothing is left behind on any exit path (including a
/// panic elsewhere) and the read-back can't be pointed at a different file than the one written.
pub(crate) fn scratch_pair(tag: &str) -> std::io::Result<(std::fs::File, std::fs::File)> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = std::env::temp_dir();
    let mut last = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no unique scratch name");
    for attempt in 0..8u32 {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path = dir.join(format!(
            "bsx-{tag}-{}-{stamp}-{attempt}",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(sink) => {
                // Unlink before the `?`, so even a failed clone (out of fds) leaves nothing on
                // disk: the file exists on the filesystem only for these two lines.
                let cloned = sink.try_clone();
                let _ = std::fs::remove_file(&path);
                return Ok((sink, cloned?));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Read at most `cap` bytes from the start of `file`, lossily as text. `take` before the read, not
/// a truncation after: `fs::read` would pull a flooding child's whole output into host RAM and only
/// then throw it away. The seek is required because the handle shares its file offset with the
/// child's (both are dups of one open file description), so it sits at end-of-write.
pub(crate) fn read_head(mut file: std::fs::File, cap: u64) -> std::io::Result<String> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::new();
    file.take(cap).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound the version probe and the stderr tail both rely on, asserted where it lives.
    /// `spawn`'s flooding-wrapper test names this property but cannot observe it: it checks that a
    /// version still parses, which holds whether 4 KiB or 3 MB was read. This is the assertion that
    /// fails if the `take(cap)` is dropped, and it needs no subprocess, so it cannot flake.
    #[test]
    fn read_head_stops_at_the_cap_however_long_the_file_is() {
        use std::io::Write as _;

        let (sink, back) = scratch_pair("readhead").expect("a scratch pair");
        let cap = 4096u64;
        (&sink).write_all(b"Firecracker v1.16.1\n").expect("head");
        // Well past the cap, and past any plausible buffer: a read that ignores the cap returns
        // this whole thing.
        let filler = vec![b'x'; 64 * 1024];
        for _ in 0..16 {
            (&sink).write_all(&filler).expect("flood");
        }
        let on_disk = sink.metadata().expect("stat").len();
        assert!(
            on_disk > cap * 100,
            "the file must dwarf the cap: {on_disk}"
        );

        let head = read_head(back, cap).expect("read back");
        assert_eq!(
            head.len() as u64,
            cap,
            "a file larger than the cap must read back at exactly the cap"
        );
        assert!(
            head.starts_with("Firecracker v1.16.1"),
            "the cap takes the head, not an arbitrary window: {:?}",
            &head[..head.len().min(40)]
        );
    }

    /// The other side of the same bound: a file *under* the cap is not padded or truncated, so the
    /// cap is a ceiling rather than a fixed-size read.
    #[test]
    fn read_head_returns_a_short_file_whole() {
        use std::io::Write as _;

        let (sink, back) = scratch_pair("readhead-short").expect("a scratch pair");
        (&sink).write_all(b"Firecracker v1.16.1\n").expect("write");
        let head = read_head(back, 4096).expect("read back");
        assert_eq!(head, "Firecracker v1.16.1\n");
    }

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
