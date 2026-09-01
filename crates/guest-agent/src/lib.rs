//! `bsx-guest-agent`, the in-guest agent that runs a command and reports its result over the channel.
//!
//! The agent carries exec and IO only. It is a convenience inside the isolation boundary, never part
//! of the trust boundary: containment is the microVM, not this code.
//!
//! - **One connection, one command.** [`serve`] accepts a [`ServerConnection`], reads a single
//!   [`Request::Exec`], runs it, streams `stdout`/`stderr` back as they arrive, and ends with the exit
//!   code. [`serve_session`] is the same body with a **stable working directory**, which is what turns
//!   a sequence of execs against one agent into a stateful session.
//! - **Generic over the byte stream**, so the same logic runs over vsock in a real guest and over a
//!   unix socket in tests, and the driver is unit-testable without a VM.
//! - **The pipe-deadlock hazard.** The child's `stdout` and `stderr` are drained by two threads that
//!   keep reading even after forwarding to the host fails, switching to read-and-discard, so the
//!   child's pipe can never fill and block `wait()`. A merely *stalled* host only becomes a forward
//!   error if the connection carries a **write deadline**, so the bound holds only for a stream with
//!   read/write deadlines set (the caller's job).
//! - **A pty session is the interactive path.** A [`Request::ExecPty`] runs the command on a
//!   guest pseudo-terminal instead of pipes: output streams back as `Stdout`, keystrokes arrive as
//!   `Stdin`, and `Resize` follows the host terminal. The two directions run concurrently, which
//!   is why serving takes a stream that can be duplicated ([`SplitStream`]).
//! - **Tree reaping (best-effort).** A command runs in a per-exec cgroup where the guest has a
//!   writable cgroup v2 mount, so a double-forked grandchild or `setsid` daemon holding the output
//!   pipes open is killed with the rest. Where the cgroup cannot be made the agent warns and falls
//!   back to killing the direct child only, which such a daemon survives.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bsx_channel::{ChannelError, Request, Response, ServerConnection};

/// Agent-side ceiling on a command's runtime: a host-requested timeout is clamped to this, so a
/// buggy host can't ask the agent to wait effectively forever.
const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour

/// Exponential backoff for the child-exit poll, starting tight and widening toward a cap. Local
/// rather than shared with `bsx`'s `PollBackoff`, because this crate is the static musl guest
/// binary and takes no `bsx` dependency.
struct WaitBackoff {
    next: Duration,
}

impl WaitBackoff {
    const INITIAL: Duration = Duration::from_millis(1);
    const CAP: Duration = Duration::from_millis(5);

    fn new() -> Self {
        Self {
            next: Self::INITIAL,
        }
    }

    /// Sleeps the current interval, then doubles it toward the cap.
    fn sleep(&mut self) {
        let current = self.next;
        self.next = (self.next * 2).min(Self::CAP);
        std::thread::sleep(current);
    }
}

/// `serve`'s return value for a timed-out (SIGKILL'd) command, the shell convention for SIGKILL.
const TIMED_OUT_CODE: i32 = 137;

/// Everything running one command over the channel can fail with, as a typed value.
#[derive(Debug)]
pub enum AgentError {
    /// The channel handshake, request read, or response write failed.
    Channel(ChannelError),
    /// The request carried an empty argv, there is no program to run.
    EmptyCommand,
    /// The host asked for something this agent version doesn't implement.
    UnsupportedRequest,
    /// A rejected file path (absolute, or escaping the working dir with `..`).
    BadPath(String),
    /// Creating the working dir or writing an injected file failed.
    WorkDir(std::io::Error),
    /// The command could not be spawned (e.g. no such binary, permission denied).
    Spawn(std::io::Error),
    /// Allocating the pseudo-terminal, duplicating the stream, or driving the pty failed.
    Pty(std::io::Error),
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
            AgentError::Pty(e) => write!(f, "pty session: {e}"),
            AgentError::Wait(e) => write!(f, "wait for command: {e}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentError::Channel(e) => Some(e),
            AgentError::WorkDir(e)
            | AgentError::Spawn(e)
            | AgentError::Wait(e)
            | AgentError::Pty(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ChannelError> for AgentError {
    fn from(e: ChannelError) -> Self {
        AgentError::Channel(e)
    }
}

/// A byte stream that can be duplicated into a second, independently owned handle over the same
/// connection, and whose read deadline can be changed after the fact.
///
/// The pty session needs both: its output pump writes responses while the request loop reads, so
/// each direction takes its own handle; and an interactive session idles for as long as a human
/// thinks, so the accept loop's anti-hang read deadline has to come off once one starts. Both
/// transports the agent serves are a raw fd underneath, where `try_clone` is a `dup`.
pub trait SplitStream: Read + Write + Send + Sized {
    /// A second handle over the same underlying connection.
    fn try_clone_stream(&self) -> std::io::Result<Self>;
    /// Sets or clears the read deadline on the underlying connection, shared by every handle.
    fn set_read_deadline(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl SplitStream for std::os::unix::net::UnixStream {
    fn try_clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn set_read_deadline(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

impl SplitStream for vsock::VsockStream {
    fn try_clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn set_read_deadline(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

/// Serves one exec request over `stream` and returns the command's exit code, in a **fresh working
/// directory** removed afterwards. A stateful session server uses [`serve_session`].
///
/// A spawn failure sends a terminal [`Response::Error`] *and* returns [`AgentError::Spawn`], so
/// both sides learn the command never ran. A hung command is bounded by its `timeout_ms` budget:
/// past the deadline the agent SIGKILLs it and replies [`Response::TimedOut`].
///
/// # Errors
/// [`AgentError`] on any channel, spawn, or wait failure. A command that runs and exits non-zero is
/// **not** an error here, just a [`Response::Exit`] with a non-zero code.
pub fn serve<S>(stream: S) -> Result<i32, AgentError>
where
    S: SplitStream + 'static,
{
    serve_with(stream, RunDir::fresh())
}

/// [`serve`], but with the run's working directory at `dir`, **created if missing and kept
/// afterwards**, so a server passing the same `dir` to every connection gives a sequence of execs one
/// shared working directory. The VM's lifetime (or its overlay's) bounds that state.
///
/// # Errors
/// As [`serve`].
pub fn serve_session<S>(stream: S, dir: &Path) -> Result<i32, AgentError>
where
    S: SplitStream + 'static,
{
    serve_with(stream, RunDir::at(dir))
}

/// Reports a spawn failure to the host and returns it as the typed error. The local `Spawn` error
/// is the salient one either way, so a failed report is dropped.
fn refuse_spawn<S: Read + Write>(
    conn: &mut ServerConnection<S>,
    program: &str,
    e: std::io::Error,
) -> AgentError {
    let _ = conn.send_response(&Response::Error(format!("could not run {program}: {e}")));
    AgentError::Spawn(e)
}

/// The shared body of [`serve`]/[`serve_session`]: `workdir` is where injected files land, the
/// command's cwd, and where artifacts are read back from. Taken as a `Result` so a creation failure
/// is still reported to the host over the accepted connection.
fn serve_with<S>(stream: S, workdir: std::io::Result<RunDir>) -> Result<i32, AgentError>
where
    S: SplitStream + 'static,
{
    // Duplicated before the connection consumes the stream: an `ExecPty` needs a second handle,
    // and by the time one arrives there is no stream left to clone.
    let dup = stream.try_clone_stream().map_err(AgentError::Pty)?;
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
            Request::ExecPty {
                argv,
                env,
                cols,
                rows,
            } => {
                return serve_pty(conn, dup, workdir.path(), &argv, &env, cols, rows);
            }
            // A newer host's request type: reply gracefully rather than dropping the link.
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

    // argv and the env *count*, never a value or key list: env values are secrets by presumption,
    // and this log reaches the serial console, which the host exposes verbatim.
    let span = tracing::info_span!("exec", argv = ?argv, env_vars = env.len());
    let _enter = span.enter();

    let Some((program, args)) = argv.split_first() else {
        conn.send_response(&Response::Error("empty command".into()))?;
        return Err(AgentError::EmptyCommand);
    };

    let budget = budget_from(timeout_ms);
    let started = Instant::now();
    let deadline = started + budget;
    // Before spawn, so the child enrolls itself via the trampoline and every process the command
    // forks inherits membership.
    let cgroup = ExecCgroup::create();

    // Resolved up front so "no such binary" stays the typed spawn error the host knows: with the
    // trampoline, the real `execvp` happens inside the child, where a failure can only surface as a
    // shell-style 127 on stderr.
    if let Err(e) = resolve_program(program, workdir.path(), effective_path(&env).as_deref()) {
        return Err(refuse_spawn(&mut conn, program, e));
    }

    // Self-placement through the trampoline rather than a parent-side `cgroup.procs` write after
    // `spawn`: that write races the already-running child and anything it forks first, which would
    // escape the cgroup, survive `cgroup.kill`, and wedge the connection holding the output pipes
    // open. Enrollment in the child strictly precedes its `exec`, so the ordering admits no race.
    let mut cmd = match cgroup.as_ref() {
        Some(cg) => {
            let mut cmd = Command::new("sh");
            cmd.arg("-c")
                .arg(TRAMPOLINE_SCRIPT)
                .arg("bsx-exec-trampoline") // $0
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
    // The **spawned command only**, never `std::env::set_var`: the agent's own process outlives
    // this run and serves the next connection, so mutating it would leak one run's secrets into
    // another.
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
        Err(e) => return Err(refuse_spawn(&mut conn, program, e)),
    };

    let child_stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // `first_err` records the first forward failure without stopping the drain.
    let conn = Mutex::new(conn);
    let first_err: Mutex<Option<ChannelError>> = Mutex::new(None);

    let waited = std::thread::scope(|scope| {
        // Concurrently with the output pumps, so a command that writes before draining its stdin
        // cannot deadlock against this.
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
        // In the scope's own thread while the pumps drain in parallel, which is what keeps the
        // child from blocking on a full pipe.
        let result = wait_bounded(&mut child, deadline);
        // Then the *whole tree*: a double-forked grandchild or `setsid` daemon that inherited the
        // output pipes keeps its write end open, so the pumps never see EOF and this scope cannot
        // join them. `cgroup.kill` reaches every process at once; a direct-child kill cannot.
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

    // A missing artifact is omitted and an unreadable or oversized one is skipped, so a successful run
    // never fails over an artifact and the host always gets the exit code.
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

/// The command's wall-clock budget from the host's `timeout_ms`, clamped to [`MAX_EXEC_TIMEOUT`].
/// [`None`] asks for that ceiling rather than naming a limit; the wire spells it `0`, and
/// [`NonZeroU32`] keeps it from colliding with a real budget.
fn budget_from(timeout_ms: Option<NonZeroU32>) -> Duration {
    timeout_ms.map_or(MAX_EXEC_TIMEOUT, |ms| {
        Duration::from_millis(u64::from(ms.get())).min(MAX_EXEC_TIMEOUT)
    })
}

/// Waits for the child, but no longer than `deadline`, polling `try_wait` so the output pumps keep
/// draining in parallel and a full pipe never wedges us. Past the deadline it SIGKILLs the direct child
/// and reaps it, so a hung command leaves no zombie.
///
/// Only the *direct* child: the wider process tree is reaped by [`serve`] through the per-exec
/// [`ExecCgroup`] after this returns, on both the exit and timeout paths.
fn wait_bounded(child: &mut Child, deadline: Instant) -> std::io::Result<Waited> {
    let mut backoff = WaitBackoff::new();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Waited::Exited(status));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            child.wait()?; // reap the SIGKILL'd child
            return Ok(Waited::TimedOut);
        }
        backoff.sleep();
    }
}

/// The cgroup v2 unified-hierarchy mount inside the guest.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The trampoline `sh` leg that spawns a command *inside* its per-exec cgroup: enroll self, drop
/// the cgroup arg, then `exec` the real command, keeping the same pid so the agent's wait/kill
/// handles are untouched. The command and its arguments arrive as real argv entries (`"$@"`), never
/// interpolated into the script, so they cannot inject into it. Enrollment is best-effort and
/// **sequenced before the `exec` in the child itself**, which a parent-side write cannot be.
const TRAMPOLINE_SCRIPT: &str = r#"{ echo $$ > "$1/cgroup.procs"; } 2>/dev/null; shift; exec "$@""#;

/// The `PATH` the spawned command will resolve against: the injected environment's entry if it names
/// one, the agent's own otherwise, which is what [`Command::env`] leaves the child holding.
///
/// The **last** duplicate wins, because that is what the `cmd.env(key, value)` loop applying these
/// pairs leaves behind, and a check that disagreed with the spawn it gates is the defect this exists
/// to close.
fn effective_path(env: &[(String, String)]) -> Option<std::ffi::OsString> {
    env.iter()
        .rev()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| std::ffi::OsString::from(value))
        .or_else(|| std::env::var_os("PATH"))
}

/// Mirrors `execvp`'s lookup just enough to report a missing or non-executable program as the typed
/// spawn error before the trampoline runs. TOCTOU-tolerant: a program vanishing between this check
/// and the child's `exec` surfaces as the trampoline's shell-style 127 instead.
///
/// Judged where the child will resolve it, on both axes: `path` is the **command's** `PATH`
/// ([`effective_path`]), not the agent's, and every candidate is rooted at `workdir` (the child's
/// cwd), which `join` leaves alone when it is already absolute. The agent's own environment or cwd
/// would falsely reject a program injected via `--put`, built by an earlier exec, or on a caller's
/// `PATH`.
fn resolve_program(
    program: &str,
    workdir: &Path,
    path: Option<&std::ffi::OsStr>,
) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let executable = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    let found = if program.contains('/') {
        executable(&workdir.join(program))
    } else {
        path.is_some_and(|paths| {
            // An empty `PATH` entry means the cwd, which for the child is `workdir`, and that is
            // the same rooting the `/`-bearing branch above does.
            std::env::split_paths(paths).any(|dir| executable(&workdir.join(dir).join(program)))
        })
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

/// A `bsx-<what>-<pid>-<n>` name, unique within this agent process: the pid separates two agents
/// sharing a guest, `seq` separates two names from one agent.
fn unique_name(what: &str, seq: &AtomicU64) -> String {
    format!(
        "bsx-{what}-{}-{}",
        std::process::id(),
        seq.fetch_add(1, Ordering::Relaxed)
    )
}

/// Names the next per-exec cgroup uniquely within this agent process.
static CGROUP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Set once the agent has warned that it cannot make a per-exec cgroup, so the report is one line
/// per process rather than one per exec.
static CGROUP_LOSS_REPORTED: AtomicBool = AtomicBool::new(false);

/// A per-exec cgroup whose only job is to **kill the whole process tree** a command spawns: cgroup
/// v2 membership is inherited by every child and cannot be escaped by `setsid`, so `cgroup.kill`
/// reaches the double-fork and daemon cases a direct-child `kill` (or a `killpg`) misses.
///
/// Best-effort: [`create`](Self::create) returns `None` on a guest without cgroup v2, and the agent
/// falls back to the direct-child kill. No controllers are enabled, so it works even though the
/// guest's root cgroup holds processes (the no-internal-process rule bites only when enabling
/// controllers in `subtree_control`), and it needs no host-side delegation.
struct ExecCgroup {
    path: PathBuf,
}

impl ExecCgroup {
    /// Creates a fresh per-exec cgroup, or `None` if `/sys/fs/cgroup` isn't a writable cgroup v2
    /// mount, warning once per agent process on the way so the degradation is not silent.
    fn create() -> Option<Self> {
        let path = PathBuf::from(CGROUP_ROOT).join(unique_name("exec", &CGROUP_SEQ));
        match std::fs::create_dir(&path) {
            Ok(()) => Some(Self { path }),
            Err(e) => {
                // Once, not per exec: this is a property of the guest image, so every later exec
                // repeats it and buries the command's own output on the console the host reads.
                if !CGROUP_LOSS_REPORTED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        cgroup_root = CGROUP_ROOT,
                        error = %e,
                        "no per-exec cgroup: whole-tree reaping is off, so a command that \
                         double-forks a daemon holding its output pipes parks this session until \
                         that daemon exits (the host's exec deadline is the backstop)"
                    );
                }
                None
            }
        }
    }

    /// SIGKILLs every process in the cgroup and its descendants, atomically (guest kernel >= 5.14).
    fn kill_all(&self) {
        let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
    }
}

impl Drop for ExecCgroup {
    fn drop(&mut self) {
        // `remove_dir` needs the cgroup empty and SIGKILL'd processes are reaped by init
        // asynchronously, so retry briefly rather than leak a dir on a long-lived guest.
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

/// The persistence mode of a run's working directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunDirMode {
    /// A fresh per-run directory, removed on drop.
    EphemeralTemp,
    /// A stable session directory, preserved across runs.
    PersistentSession,
}

/// The run's working directory. Injected files are written in and artifacts read out through
/// path-checked helpers, so a host path cannot escape the directory. A [`fresh`](RunDir::fresh) one
/// is private to its run and removed on drop; an [`at`](RunDir::at) one is the caller's stable
/// **session** dir, created if missing and kept.
struct RunDir {
    path: PathBuf,
    mode: RunDirMode,
}

impl RunDir {
    /// A fresh, uniquely-named per-run dir under `/tmp`, removed on drop.
    fn fresh() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(unique_name("run", &RUN_SEQ));
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            mode: RunDirMode::EphemeralTemp,
        })
    }

    /// The caller's stable session dir: created if missing, never removed by this handle.
    fn at(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            path: dir.to_path_buf(),
            mode: RunDirMode::PersistentSession,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Resolves a host-supplied relative path under the working dir, rejecting absolute paths and any
    /// `..` that would climb out.
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

    /// Writes an injected file, creating parent dirs.
    fn put(&self, rel: &str, data: &[u8]) -> Result<(), AgentError> {
        let dest = self.resolve(rel)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(AgentError::WorkDir)?;
        }
        std::fs::write(&dest, data).map_err(AgentError::WorkDir)
    }

    /// Reads an artifact back: `Ok(None)` if it doesn't exist, `Err` on a bad path or read failure.
    ///
    /// The command ran *before* this read and may have planted a symlink pointing outside the run dir,
    /// which a bare `fs::read` would follow, so the link-resolved real path must stay within the run
    /// dir and an escape reads as "no such artifact". Defense-in-depth; the microVM stays the boundary.
    fn get(&self, rel: &str) -> Result<Option<Vec<u8>>, AgentError> {
        let src = self.resolve(rel)?;
        let (real, root) = match (src.canonicalize(), self.path.canonicalize()) {
            (Ok(real), Ok(root)) => (real, root),
            _ => return Ok(None), // absent or dangling: no such artifact
        };
        if !real.starts_with(&root) {
            return Ok(None);
        }
        // Checked *before* the read: `fs::read` would slurp a multi-GiB (even sparse) file whole
        // and OOM-kill the agent, taking the session down instead of skipping one artifact. The
        // send side's `PayloadTooLarge` catch is the precise-boundary and TOCTOU backstop.
        match std::fs::metadata(&real) {
            Ok(md) if md.len() > bsx_channel::MAX_PAYLOAD as u64 => {
                tracing::warn!(
                    "artifact {rel:?} exceeds the frame cap ({} bytes); skipped",
                    md.len()
                );
                return Ok(None);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AgentError::WorkDir(e)),
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
        if self.mode == RunDirMode::EphemeralTemp {
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

/// Drains one child pipe to the host, in chunks well under `MAX_PAYLOAD`. Reads to EOF
/// **unconditionally**: once a forward fails the first error is recorded and later chunks are dropped,
/// but the pipe is still drained so the child can exit.
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
                // A *temporary* whose guard drops at the end of the `if` condition; bound to a
                // local it would still be held at the `conn.lock()` below, and the two pump threads
                // could deadlock.
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
                    drop(w); // release `conn` before taking `first_err`, consistent lock order
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

/// Serves one interactive pty session: runs `argv` on a fresh guest pseudo-terminal and pumps it
/// until the command exits or the host goes away.
///
/// - **Two handles, two directions.** `conn` keeps reading requests (`Stdin` bytes into the pty,
///   `Resize` onto it); a pump thread owns the duplicate and streams the pty's output back as
///   `Stdout`, then reaps the child and sends `Exit`. A pty has one output stream, the terminal,
///   so nothing here is `Stderr`.
/// - **The controlling terminal is acquired by `setsid -c`**, the guest's own util, because the
///   session/ctty dance happens between fork and exec, where this crate's `#![forbid(unsafe_code)]`
///   cannot reach (`pre_exec` is `unsafe`). The rootfs contract pins the binary's presence.
/// - **A host that vanishes does not strand the command.** The request loop's exit kills the child
///   (unless the pump already reaped it), the pump then sees the pty close, and the session ends.
fn serve_pty<S: SplitStream + 'static>(
    mut conn: ServerConnection<S>,
    dup: S,
    workdir: &Path,
    argv: &[String],
    env: &[(String, String)],
    cols: u16,
    rows: u16,
) -> Result<i32, AgentError> {
    use std::os::unix::ffi::OsStringExt;

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use rustix::termios::{Winsize, tcsetwinsize};

    let Some((program, args)) = argv.split_first() else {
        conn.send_response(&Response::Error("empty command".into()))?;
        return Err(AgentError::EmptyCommand);
    };
    let span = tracing::info_span!("exec_pty", argv = ?argv, env_vars = env.len());
    let _enter = span.enter();

    // An interactive session idles for as long as a human thinks, so the accept loop's anti-hang
    // read deadline comes off. The write deadline stays: a host that stops draining output for
    // that long is gone, and the write error is what tears the session down.
    dup.set_read_deadline(None).map_err(AgentError::Pty)?;

    let pty = (|| {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        grantpt(&master)?;
        unlockpt(&master)?;
        let name = ptsname(&master, Vec::new())?;
        Ok::<_, rustix::io::Errno>((master, name))
    })();
    let (master, pts_name) = match pty {
        Ok(pair) => pair,
        Err(e) => {
            let e = std::io::Error::from(e);
            conn.send_response(&Response::Error(format!("allocate a pty: {e}")))?;
            return Err(AgentError::Pty(e));
        }
    };
    let winsize = |cols: u16, rows: u16| Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // On the master before the child exists, so the command's very first `TIOCGWINSZ` sees the
    // host's real size rather than 0x0 (which full-screen programs read as "not a terminal").
    let _ = tcsetwinsize(&master, winsize(cols, rows));

    let pts_path = std::path::PathBuf::from(std::ffi::OsString::from_vec(pts_name.into_bytes()));
    let slave = match std::fs::File::options()
        .read(true)
        .write(true)
        .open(&pts_path)
    {
        Ok(f) => f,
        Err(e) => {
            conn.send_response(&Response::Error(format!(
                "open the pty slave {}: {e}",
                pts_path.display()
            )))?;
            return Err(AgentError::Pty(e));
        }
    };

    // `setsid -c`: new session, and the slave (the child's stdin) becomes its controlling
    // terminal, which is what routes `^C` typed on the host to the command's process group.
    //
    // The `Command` lives only inside this closure, deliberately: it retains the cloned slave
    // handles in its stdio slots for as long as it exists, and a slave fd still open in the
    // parent is a master that never reads EOF, which is a pump that never reaps. Watched hang.
    let stdio = |f: &std::fs::File| f.try_clone().map(Stdio::from);
    let child = (|| {
        let mut cmd = Command::new("setsid");
        cmd.arg("-c").arg(program).args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.current_dir(workdir)
            .stdin(stdio(&slave)?)
            .stdout(stdio(&slave)?)
            .stderr(stdio(&slave)?)
            .spawn()
    })();
    // The parent's last slave handle closes here either way, so the master reads EOF exactly
    // when the command (and whatever it left behind holding the terminal) is gone.
    drop(slave);
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return Err(refuse_spawn(&mut conn, program, e)),
    };
    let child_pid = child.id();

    let master_read = std::fs::File::from(master.try_clone().map_err(AgentError::Pty)?);
    let mut master_write = std::fs::File::from(master);
    let mut writer = ServerConnection::resume(dup);
    let pump = std::thread::spawn(move || pump_pty(master_read, &mut child, &mut writer));

    // The request loop: bytes into the pty, size changes onto it, anything else refused. It ends
    // when the host closes (the normal case, after it saw `Exit`) or errors.
    loop {
        match conn.recv_request() {
            Ok(Request::Stdin(bytes)) => {
                if master_write.write_all(&bytes).is_err() {
                    // The pty is gone because the command is: the pump is reporting the exit.
                    break;
                }
            }
            Ok(Request::Resize { cols, rows }) => {
                let _ = tcsetwinsize(&master_write, winsize(cols, rows));
            }
            Ok(_) => {
                let _ =
                    conn.send_response(&Response::Error("one pty session per connection".into()));
            }
            Err(_) => break,
        }
    }

    // A vanished host must not strand the command on a terminal nobody reads. Only while the pump
    // still runs: once it has reaped, the pid is free for the kernel to reuse and must not be
    // signalled.
    if !pump.is_finished()
        && let Some(pid) = rustix::process::Pid::from_raw(child_pid as i32)
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    }
    pump.join().unwrap_or_else(|_| {
        Err(AgentError::Pty(std::io::Error::other(
            "the pty pump panicked",
        )))
    })
}

/// The pty session's output half: streams the master's bytes to the host until the terminal
/// closes, then reaps the command and reports how it ended. Runs on its own thread with its own
/// connection handle, concurrently with the request loop.
fn pump_pty<S: SplitStream>(
    mut master: std::fs::File,
    child: &mut Child,
    writer: &mut ServerConnection<S>,
) -> Result<i32, AgentError> {
    let mut buf = [0u8; 8192];
    loop {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if writer
                    .send_response(&Response::Stdout(buf[..n].to_vec()))
                    .is_err()
                {
                    // The host is gone; stop pumping and reap. The kill belongs to the request
                    // loop, which is also unblocking about now for the same reason.
                    break;
                }
            }
            // EIO is the pty's EOF: the last slave handle closed. Anything else ends the pump the
            // same way, with the wait below still reporting how the command ended.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let status = child.wait().map_err(AgentError::Wait)?;
    let code = exit_code(&status);
    writer.send_response(&Response::Exit { code })?;
    tracing::info!(code, "pty session ended");
    Ok(code)
}

/// A command's exit code, mapping signal death to the shell convention `128 + signal` so the host
/// always gets a number.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::{
        AtomicU64, MAX_EXEC_TIMEOUT, budget_from, effective_path, resolve_program, unique_name,
    };
    use bsx_test_support::ScratchDir;
    use std::num::NonZeroU32;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::time::Duration;

    /// Writes an executable no-op at `path`, creating its parent.
    fn tool_at(path: &Path) {
        std::fs::create_dir_all(path.parent().expect("a tool has a parent dir")).expect("mkdir");
        std::fs::write(path, "#!/bin/sh\ntrue\n").expect("write the tool");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    fn env_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// The check reads the `PATH` the **child** gets, not the agent's. The two disagree exactly
    /// when a caller injects `PATH`, which is wire-reachable through `ExecParams.env`, and the gate
    /// would then refuse a program the `spawn` below it finds and runs.
    #[test]
    fn the_program_is_resolved_against_the_commands_path_not_the_agents() {
        let scratch = ScratchDir::created("agent-path");
        let bin = scratch.path().join("bin");
        let work = scratch.path().join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        tool_at(&bin.join("mytool"));
        let bin = bin.to_str().expect("a utf-8 scratch path");

        assert!(
            resolve_program("mytool", &work, std::env::var_os("PATH").as_deref()).is_err(),
            "precondition: `mytool` must not be on this host's own PATH"
        );

        let with = |pairs: &[(&str, &str)]| {
            resolve_program("mytool", &work, effective_path(&env_of(pairs)).as_deref())
        };
        assert!(with(&[("PATH", bin)]).is_ok(), "the injected PATH is read");
        assert!(
            with(&[]).is_err(),
            "no injected PATH falls back to the agent's"
        );
        assert!(
            with(&[("OTHER", bin)]).is_err(),
            "an unrelated variable must not stand in for PATH"
        );
        // `cmd.env` applies the pairs in order, so the last duplicate is what the child holds and
        // the only one this may agree with.
        assert!(with(&[("PATH", "/nonexistent"), ("PATH", bin)]).is_ok());
        assert!(with(&[("PATH", bin), ("PATH", "/nonexistent")]).is_err());
    }

    /// A non-absolute `PATH` entry is rooted at the child's cwd, matching `execvp` on an empty
    /// entry and the `/`-bearing branch.
    #[test]
    fn a_relative_path_entry_is_rooted_at_the_childs_working_dir() {
        let scratch = ScratchDir::created("agent-relpath");
        let work = scratch.path();
        tool_at(&work.join("tools/mytool"));
        tool_at(&work.join("here"));

        let path = |p: &str| resolve_program("mytool", work, Some(std::ffi::OsStr::new(p)));
        assert!(path("tools").is_ok(), "a relative entry sits under the cwd");
        assert!(path("/tools").is_err(), "an absolute entry is left alone");
        assert!(
            resolve_program("here", work, Some(std::ffi::OsStr::new(""))).is_ok(),
            "an empty entry means the cwd"
        );
    }

    #[test]
    fn budget_clamps_and_treats_none_as_ceiling() {
        let nz = |n: u32| NonZeroU32::new(n).expect("a nonzero budget");
        assert_eq!(budget_from(Some(nz(1500))), Duration::from_millis(1500));
        assert_eq!(
            budget_from(None),
            MAX_EXEC_TIMEOUT,
            "no named budget means the ceiling, not no-time"
        );
        assert_eq!(
            budget_from(Some(nz(u32::MAX))),
            MAX_EXEC_TIMEOUT,
            "an over-ceiling ask is clamped"
        );
    }

    /// Two names from one process never collide: a reused per-run dir hands one exec another's
    /// working directory, and a reused per-exec cgroup makes one command's kill reach another's
    /// processes. Nothing else in the suite reports either as more than flakiness.
    #[test]
    fn a_unique_name_never_repeats_within_this_process() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let names: std::collections::BTreeSet<String> =
            (0..64).map(|_| unique_name("probe", &SEQ)).collect();
        assert_eq!(
            names.len(),
            64,
            "every call names a different path: {names:?}"
        );
        let pid = std::process::id().to_string();
        assert!(
            names.iter().all(|n| n.contains(&pid)),
            "and carries this process's pid, so two agents on one guest cannot collide: {names:?}"
        );
    }
}
