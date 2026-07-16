//! `agent-guest` — the in-guest agent that runs a command and reports its result over the channel.
//!
//! [`serve`] handles **one connection**: it accepts a [`ServerConnection`], reads a single
//! [`Request::Exec`], runs the command, streams its `stdout`/`stderr` back as they arrive, and ends
//! with the exit code. It is generic over the byte stream, so the same logic runs over **vsock** in
//! a real guest (P2.3) and over a **unix socket** in tests and the `main` harness here — the driver
//! is unit-testable without a VM. [`serve_session`] is the same one-command-per-connection loop
//! body with a **stable working directory**, which is what turns a sequence of execs against one
//! agent into a stateful session (the in-VM binary uses it; the VM is the session).
//!
//! **The load-bearing subtlety** (the Phase-1 pipe-deadlock hazard, again): the child's `stdout`
//! and `stderr` are drained by two threads that keep reading **even after forwarding to the host
//! fails** — on the first forward error they switch to read-and-discard, so the child's ~64 KiB
//! pipe can never fill and block `wait()`. This is what stops a *dead* host from wedging a live
//! guest. A merely *stalled* (open but not-reading) host only becomes a forward error if the
//! connection has a **write deadline** — without one, `write` blocks indefinitely and the drain
//! stalls. So the guarantee is: **given a stream with read/write deadlines set** (the caller's job —
//! see [`ServerConnection`]), any dead-or-stalled host is a bounded, typed error, never a hang.
//!
//! The agent carries exec/IO only — it is a convenience inside the isolation boundary, never part of
//! the trust boundary (core property 2). Containment is the microVM, not this code.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use agent_channel::{ChannelError, Request, Response, ServerConnection};

/// Agent-side ceiling on a command's runtime: a host-requested timeout is clamped to this, so a
/// buggy host can't ask the agent to wait effectively forever.
const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour

/// How often the reaper polls for the child's exit while waiting toward the deadline.
const WAIT_POLL: Duration = Duration::from_millis(20);

/// `serve`'s return value for a timed-out (SIGKILL'd) command — the shell convention for SIGKILL.
const TIMED_OUT_CODE: i32 = 137;

/// Everything running one command over the channel can fail with, as a typed value.
#[derive(Debug)]
#[non_exhaustive]
pub enum AgentError {
    /// The channel handshake, request read, or response write failed.
    Channel(ChannelError),
    /// The request carried an empty argv — there is no program to run.
    EmptyCommand,
    /// The host asked for something this agent version doesn't implement.
    UnsupportedRequest,
    /// A rejected file path (absolute, or escaping the working dir with `..`).
    BadPath(String),
    /// Creating the working dir or writing an injected file failed.
    WorkDir(std::io::Error),
    /// The command could not be spawned (e.g. no such binary, permission denied).
    Spawn(std::io::Error),
    /// Reaping the finished child failed.
    Wait(std::io::Error),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::Channel(e) => write!(f, "channel: {e}"),
            AgentError::EmptyCommand => f.write_str("empty command (no argv)"),
            AgentError::UnsupportedRequest => f.write_str("unsupported request type"),
            AgentError::BadPath(p) => write!(f, "unsafe file path: {p}"),
            AgentError::WorkDir(e) => write!(f, "working dir: {e}"),
            AgentError::Spawn(e) => write!(f, "spawn command: {e}"),
            AgentError::Wait(e) => write!(f, "wait for command: {e}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentError::Channel(e) => Some(e),
            AgentError::WorkDir(e) | AgentError::Spawn(e) | AgentError::Wait(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ChannelError> for AgentError {
    fn from(e: ChannelError) -> Self {
        AgentError::Channel(e)
    }
}

/// Serve one exec request over `stream` and return the command's exit code. The run gets a
/// **fresh working directory**, removed afterwards — the stateless one-shot form; a stateful
/// session server uses [`serve_session`].
///
/// The handshake is done by [`ServerConnection::accept`]; on a spawn failure the agent sends a
/// terminal [`Response::Error`] to the host *and* returns [`AgentError::Spawn`], so both sides learn
/// the command never ran. Emits a `tracing` span (`exec`) carrying the argv, exit code, and elapsed
/// time, so a guest-side failure is diagnosable from the log.
///
/// The no-hang guarantee holds **only if `stream` carries read/write deadlines** (see the module
/// note). A hung *command* is bounded separately by its `timeout_ms` wall-clock budget: past the
/// deadline the agent SIGKILLs it and replies [`Response::TimedOut`].
///
/// # Errors
/// [`AgentError`] on any channel, spawn, or wait failure. Note a command that runs and exits
/// non-zero is **not** an error here — that's a normal [`Response::Exit`] with a non-zero code.
pub fn serve<S>(stream: S) -> Result<i32, AgentError>
where
    S: Read + Write + Send,
{
    serve_with(stream, RunDir::fresh())
}

/// [`serve`], but with the run's working directory at `dir` — **created if missing, kept
/// afterwards**. This is the building block for **stateful sessions**: a server that passes the
/// same `dir` to every connection gives a sequence of execs one shared, persistent working
/// directory, so a file injected or written by one command is visible to the next. The in-VM
/// binary does exactly that with a single per-process dir — the VM *is* the session, and its
/// lifetime (or its overlay's) bounds the state.
///
/// # Errors
/// As [`serve`].
pub fn serve_session<S>(stream: S, dir: &Path) -> Result<i32, AgentError>
where
    S: Read + Write + Send,
{
    serve_with(stream, RunDir::at(dir))
}

/// The shared body of [`serve`]/[`serve_session`]: `workdir` is where injected files land, the
/// command's cwd, and where artifacts are read back from — the two entry points differ only in how
/// it was made (fresh-and-removed vs. stable-and-kept). Taken as a `Result` so a creation failure
/// is still reported to the host over the accepted connection.
fn serve_with<S>(stream: S, workdir: std::io::Result<RunDir>) -> Result<i32, AgentError>
where
    S: Read + Write + Send,
{
    let mut conn = ServerConnection::accept(stream)?;

    let workdir = match workdir {
        Ok(dir) => dir,
        Err(e) => {
            let _ = conn.send_response(&Response::Error(format!("create working dir: {e}")));
            return Err(AgentError::WorkDir(e));
        }
    };

    // Zero or more `PutFile`s, then the terminal `Exec`.
    let (argv, stdin, env, artifacts, timeout_ms) = loop {
        match conn.recv_request()? {
            Request::PutFile { path, data } => {
                if let Err(e) = workdir.put(&path, &data) {
                    conn.send_response(&Response::Error(format!("put file {path:?}: {e}")))?;
                    return Err(e);
                }
            }
            Request::Exec {
                argv,
                stdin,
                env,
                artifacts,
                timeout_ms,
            } => break (argv, stdin, env, artifacts, timeout_ms),
            // A newer host's request type we don't implement — reply gracefully, don't drop the link.
            Request::Unknown { tag } => {
                conn.send_response(&Response::Error(format!("unsupported request (tag {tag})")))?;
                return Err(AgentError::UnsupportedRequest);
            }
            _ => {
                conn.send_response(&Response::Error("unsupported request".into()))?;
                return Err(AgentError::UnsupportedRequest);
            }
        }
    };

    // The span carries argv and the env *count*, never an env value or key list — env values are
    // secrets by presumption (the host's secret-hygiene contract), and this log reaches the serial
    // console, which the host exposes verbatim.
    let span = tracing::info_span!("exec", argv = ?argv, env_vars = env.len());
    let _enter = span.enter();

    let Some((program, args)) = argv.split_first() else {
        conn.send_response(&Response::Error("empty command".into()))?;
        return Err(AgentError::EmptyCommand);
    };

    let budget = budget_from(timeout_ms);
    let started = Instant::now();
    let deadline = started + budget;
    // Run the command in its own cgroup (P6.4) so its whole process tree can be reaped at once.
    // Created before spawn; the child *enrolls itself* via the trampoline below, so every process
    // the command ever forks inherits membership. Best-effort: `None` on a guest without cgroup v2,
    // and the agent falls back to the direct-child kill (the pre-P6.4 behaviour).
    let cgroup = ExecCgroup::create();

    // Resolve the program up front so "no such binary" stays the typed spawn error the host knows
    // (`Response::Error` → `VmmError::GuestExec`): with the trampoline, the real `execvp` happens
    // inside the child, where a failure can only surface as a shell-style 127 on stderr.
    if let Err(e) = resolve_program(program) {
        let _ = conn.send_response(&Response::Error(format!("could not run {program}: {e}")));
        return Err(AgentError::Spawn(e));
    }

    // Spawn through the cgroup **trampoline**: a tiny `sh` leg that enrolls *itself* in the
    // per-exec cgroup and then `exec`s the real command (same pid, so wait/kill are untouched).
    // Self-placement, not a parent-side `cgroup.procs` write after `spawn`: that write raced the
    // already-running child, and anything it forked before the write landed — a daemon, a fork
    // storm; on one vCPU the child usually runs first — escaped the cgroup, survived `cgroup.kill`,
    // and wedged the connection by holding the output pipes open. In the child, enrollment strictly
    // precedes the `exec`, so the race cannot exist.
    let mut cmd = match cgroup.as_ref() {
        Some(cg) => {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg(TRAMPOLINE_SCRIPT)
                .arg("agent-exec-trampoline") // $0
                .arg(&cg.path)
                .arg(program)
                .args(args);
            cmd
        }
        None => {
            let mut cmd = Command::new(program);
            cmd.args(args);
            cmd
        }
    };
    // Injected environment lands on the **spawned command only** (`Command::env`, inherited across
    // the trampoline's `exec`) — never `std::env::set_var`: the agent's own process outlives this
    // run and serves the next connection, so mutating it would leak one run's secrets into another.
    for (key, value) in &env {
        cmd.env(key, value);
    }
    let mut child = match cmd
        .current_dir(workdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            // Report to the host if we can; the local `Spawn` error is the salient one either way,
            // so a failed report (a broken socket) is intentionally dropped.
            let _ = conn.send_response(&Response::Error(format!("could not run {program}: {e}")));
            return Err(AgentError::Spawn(e));
        }
    };

    let child_stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // The connection is now write-only (streaming stdin is a later phase); share it across the pump
    // threads. `first_err` records the first forward failure without stopping the drain.
    let conn = Mutex::new(conn);
    let first_err: Mutex<Option<ChannelError>> = Mutex::new(None);

    let waited = std::thread::scope(|scope| {
        // Feed stdin on its own thread and close it (EOF) — concurrently with the output pumps, so
        // a command that writes before draining its stdin can't deadlock against us.
        if let Some(mut sink) = child_stdin {
            scope.spawn(move || {
                let _ = sink.write_all(&stdin);
                // `sink` drops here, closing the child's stdin so it sees EOF.
            });
        }
        if let Some(out) = stdout {
            scope.spawn(|| pump(out, Kind::Stdout, &conn, &first_err));
        }
        if let Some(err) = stderr {
            scope.spawn(|| pump(err, Kind::Stderr, &conn, &first_err));
        }
        // Reap in the scope's own thread while the pumps drain in parallel — this is what keeps the
        // child from blocking on a full pipe. Bounded by the deadline: past it we SIGKILL the child
        // (which unblocks the pumps at EOF) and report a timeout instead of an exit.
        let result = wait_bounded(&mut child, deadline);
        // Then reap the *whole tree* (P6.4): a double-forked grandchild or a `setsid` daemon that
        // inherited the stdout/stderr pipe would otherwise keep its write end open, so the pumps
        // never see EOF and this scope could not join them — wedging the agent on both the exit and
        // timeout paths. `cgroup.kill` SIGKILLs every process in the cgroup at once, which the
        // direct-child kill in `wait_bounded` (and even a `killpg`) cannot reach.
        if let Some(cg) = cgroup.as_ref() {
            cg.kill_all();
        }
        result
    });

    if let Some(e) = first_err
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    {
        return Err(AgentError::Channel(e));
    }

    let mut guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
    let status = match waited.map_err(AgentError::Wait)? {
        Waited::Exited(status) => status,
        Waited::TimedOut => {
            let elapsed_ms = started.elapsed().as_millis() as u32;
            guard.send_response(&Response::TimedOut { elapsed_ms })?;
            tracing::info!(
                budget_ms = budget.as_millis() as u64,
                elapsed_ms,
                "command timed out and killed"
            );
            return Ok(TIMED_OUT_CODE);
        }
    };
    let code = exit_code(&status);

    // Return the requested artifacts before the terminal Exit. A missing one is omitted; an
    // unreadable or over-the-frame-cap one is logged and skipped — never fail a successful run over
    // an artifact, so the host always gets the exit code.
    for path in &artifacts {
        match workdir.get(path) {
            Ok(Some(data)) => {
                let resp = Response::File {
                    path: path.clone(),
                    data,
                };
                if let Err(e) = guard.send_response(&resp) {
                    if matches!(e, ChannelError::PayloadTooLarge { .. }) {
                        tracing::warn!("artifact {path:?} exceeds the frame cap; skipped");
                    } else {
                        return Err(AgentError::Channel(e));
                    }
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("skipping artifact {path:?}: {e}"),
        }
    }
    guard.send_response(&Response::Exit { code })?;
    tracing::info!(
        exit_code = code,
        artifacts = artifacts.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "command finished"
    );
    Ok(code)
}

/// The outcome of a bounded wait on the child.
enum Waited {
    Exited(ExitStatus),
    TimedOut,
}

/// The command's wall-clock budget from the host's `timeout_ms`, clamped to [`MAX_EXEC_TIMEOUT`] so
/// a buggy host can't ask the agent to wait effectively forever. `0` means "use the ceiling".
fn budget_from(timeout_ms: u32) -> Duration {
    match timeout_ms {
        0 => MAX_EXEC_TIMEOUT,
        ms => Duration::from_millis(u64::from(ms)).min(MAX_EXEC_TIMEOUT),
    }
}

/// Wait for the child, but no longer than `deadline`. Polls `try_wait` (so the output pumps keep
/// draining in parallel — a full pipe never wedges us), and past the deadline SIGKILLs the direct
/// child and reaps it, so a hung command is bounded and leaves no zombie.
///
/// This kills only the *direct* child; the command's wider process tree (double-forked grandchildren,
/// `setsid` daemons that would otherwise keep the output pipes open) is reaped by [`serve`] through
/// the per-exec [`ExecCgroup`] after this returns, on both the exit and timeout paths (P6.4). So a
/// hung or double-forking command can no longer wedge the agent's connection.
fn wait_bounded(child: &mut Child, deadline: Instant) -> std::io::Result<Waited> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Waited::Exited(status));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            child.wait()?; // reap the SIGKILL'd child
            return Ok(Waited::TimedOut);
        }
        std::thread::sleep(WAIT_POLL);
    }
}

/// The cgroup v2 unified-hierarchy mount inside the guest (mounted by the rootfs `inittab`).
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The trampoline `sh` leg that spawns a command *inside* its per-exec cgroup: enroll self
/// (`$$` — the shell's own pid — into `$1/cgroup.procs`), drop the cgroup arg, then `exec` the
/// real command, which keeps the same pid, so the agent's wait/kill handles are untouched. The
/// command and its arguments arrive as real argv entries (`"$@"`), never interpolated into the
/// script, so they can't inject into it. The enrollment is best-effort (`2>/dev/null`, matching
/// the rest of the cgroup machinery) and, crucially, **sequenced before the `exec` in the child
/// itself** — the property a parent-side `cgroup.procs` write can never have.
const TRAMPOLINE_SCRIPT: &str = r#"{ echo $$ > "$1/cgroup.procs"; } 2>/dev/null; shift; exec "$@""#;

/// Mirror `execvp`'s lookup (a path with a `/` as-is, else a `PATH` search) just enough to report a
/// missing or non-executable program as the typed spawn error before the trampoline runs.
/// TOCTOU-tolerant: a program that vanishes between this check and the child's `exec` surfaces as
/// the trampoline's shell-style 127 instead.
fn resolve_program(program: &str) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let executable = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    let found = if program.contains('/') {
        executable(Path::new(program))
    } else {
        std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| executable(&dir.join(program))))
            .unwrap_or(false)
    };
    if found {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No such file or directory",
        ))
    }
}

/// Names the next per-exec cgroup uniquely within this agent process.
static CGROUP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A per-exec cgroup whose only job is to **kill the whole process tree** a command spawns (P6.4).
/// cgroup v2 membership is inherited by every child the command forks and cannot be escaped by
/// `setsid`, so writing `cgroup.kill` SIGKILLs the entire tree at once — the definitive fix for the
/// double-fork / daemon wedge that a direct-child `kill` (and even a `killpg`) miss.
///
/// Best-effort throughout: if the guest has no cgroup v2, [`create`](Self::create) returns `None` and
/// the agent falls back to the direct-child kill (no worse than before). No controllers are enabled,
/// so it works even though the guest's root cgroup holds processes (the no-internal-process rule only
/// bites when enabling controllers in `subtree_control`), and it needs no host-side delegation.
struct ExecCgroup {
    path: PathBuf,
}

impl ExecCgroup {
    /// Create a fresh per-exec cgroup, or `None` if `/sys/fs/cgroup` isn't a cgroup v2 mount.
    fn create() -> Option<Self> {
        let path = PathBuf::from(CGROUP_ROOT).join(format!(
            "agent-exec-{}-{}",
            std::process::id(),
            CGROUP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).ok()?;
        Some(Self { path })
    }

    /// SIGKILL every process in the cgroup and its descendants, atomically (guest kernel >= 5.14).
    fn kill_all(&self) {
        let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
    }
}

impl Drop for ExecCgroup {
    fn drop(&mut self) {
        // Ensure the tree is dead (idempotent with `serve`'s explicit kill), then remove the now-empty
        // cgroup. `remove_dir` needs it empty, and SIGKILL'd processes are reaped by init
        // asynchronously, so retry briefly rather than leak a dir on a long-lived guest (the prewarmed pool).
        self.kill_all();
        for _ in 0..50 {
            if std::fs::remove_dir(&self.path).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// Names the next per-run working dir uniquely within this agent process.
static RUN_SEQ: AtomicU64 = AtomicU64::new(0);

/// The run's working directory. Injected files are written in and artifacts read out through
/// path-checked helpers so a host path can't escape the directory. Two shapes: a
/// [`fresh`](RunDir::fresh) one is private to its run and removed on drop; an [`at`](RunDir::at)
/// one is the caller's stable **session** dir, created if missing and deliberately kept — session
/// state belongs to the session, not to any one exec.
struct RunDir {
    path: PathBuf,
    /// `false` for a fresh per-run dir (removed on drop); `true` for a session dir (kept).
    keep: bool,
}

impl RunDir {
    /// A fresh, uniquely-named per-run dir under `/tmp`, removed on drop.
    fn fresh() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "agent-run-{}-{}",
            std::process::id(),
            RUN_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path, keep: false })
    }

    /// The caller's stable session dir: created if missing, never removed by this handle.
    fn at(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            path: dir.to_path_buf(),
            keep: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Resolve a host-supplied relative path safely under the working dir, rejecting absolute paths
    /// and any `..` that would climb out.
    fn resolve(&self, rel: &str) -> Result<PathBuf, AgentError> {
        let rel = Path::new(rel);
        for comp in rel.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                _ => return Err(AgentError::BadPath(rel.display().to_string())),
            }
        }
        Ok(self.path.join(rel))
    }

    /// Write an injected file (creating parent dirs).
    fn put(&self, rel: &str, data: &[u8]) -> Result<(), AgentError> {
        let dest = self.resolve(rel)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(AgentError::WorkDir)?;
        }
        std::fs::write(&dest, data).map_err(AgentError::WorkDir)
    }

    /// Read an artifact back: `Ok(None)` if it doesn't exist, `Err` on a bad path or read failure.
    ///
    /// The command ran *before* this read and may have planted a symlink inside the run dir pointing
    /// outside it (`ln -s /etc/passwd out`); a bare `fs::read` would follow it and hand the host an
    /// out-of-tree file. So require the link-resolved real path to stay within the run dir, treating
    /// an escape as "no such artifact" (omitted, not fatal). The agent is not the security boundary,
    /// but this keeps it from leaking files a de-privileged command couldn't otherwise reach.
    fn get(&self, rel: &str) -> Result<Option<Vec<u8>>, AgentError> {
        let src = self.resolve(rel)?;
        let (real, root) = match (src.canonicalize(), self.path.canonicalize()) {
            (Ok(real), Ok(root)) => (real, root),
            // Doesn't resolve (absent or dangling) → simply "no such artifact".
            _ => return Ok(None),
        };
        if !real.starts_with(&root) {
            return Ok(None);
        }
        match std::fs::read(&real) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AgentError::WorkDir(e)),
        }
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Which stream a pump is forwarding.
#[derive(Clone, Copy)]
enum Kind {
    Stdout,
    Stderr,
}

/// Drain one child pipe to the host, in chunks well under `MAX_PAYLOAD`. Reads to EOF
/// **unconditionally** (see the module note): once a forward fails, the first error is recorded and
/// later chunks are dropped, but the pipe is still drained so the child can exit.
fn pump<R, S>(
    mut src: R,
    kind: Kind,
    conn: &Mutex<ServerConnection<S>>,
    first_err: &Mutex<Option<ChannelError>>,
) where
    R: Read,
    S: Read + Write,
{
    let mut buf = [0u8; 16 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // Best-effort skip once a forward has failed — keep looping to drain regardless.
                // NOTE: this lock is a *temporary* whose guard drops at the end of the `if`
                // condition; it must NOT be bound to a local, or it would still be held when
                // `conn.lock()` is taken below and the two pump threads could deadlock.
                if first_err
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    continue;
                }
                let chunk = buf[..n].to_vec();
                let resp = match kind {
                    Kind::Stdout => Response::Stdout(chunk),
                    Kind::Stderr => Response::Stderr(chunk),
                };
                let mut w = conn.lock().unwrap_or_else(PoisonError::into_inner);
                if let Err(e) = w.send_response(&resp) {
                    drop(w); // release `conn` before taking `first_err` — consistent lock order
                    let mut slot = first_err.lock().unwrap_or_else(PoisonError::into_inner);
                    if slot.is_none() {
                        *slot = Some(e);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

/// A command's exit code, mapping signal death to the shell convention `128 + signal` so the host
/// always gets a meaningful number.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::{budget_from, MAX_EXEC_TIMEOUT};
    use std::time::Duration;

    #[test]
    fn budget_clamps_and_treats_zero_as_ceiling() {
        assert_eq!(budget_from(1500), Duration::from_millis(1500));
        assert_eq!(
            budget_from(0),
            MAX_EXEC_TIMEOUT,
            "0 means the ceiling, not no-time"
        );
        assert_eq!(
            budget_from(u32::MAX),
            MAX_EXEC_TIMEOUT,
            "an over-ceiling ask is clamped"
        );
    }
}
