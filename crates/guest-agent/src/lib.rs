//! `agent-guest` — the in-guest agent that runs a command and reports its result over the channel.
//!
//! [`serve`] handles **one connection**: it accepts a [`ServerConnection`], reads a single
//! [`Request::Exec`], runs the command, streams its `stdout`/`stderr` back as they arrive, and ends
//! with the exit code. It is generic over the byte stream, so the same logic runs over **vsock** in
//! a real guest (P2.3) and over a **unix socket** in tests and the `main` harness here — the driver
//! is unit-testable without a VM.
//!
//! **The load-bearing subtlety** (the Phase-1 pipe-deadlock lesson, again): the child's `stdout`
//! and `stderr` are drained by two threads that keep reading **even after forwarding to the host
//! fails** — on the first forward error they switch to read-and-discard, so the child's ~64 KiB
//! pipe can never fill and block `wait()`. This is what stops a *dead* host from wedging a live
//! guest. A merely *stalled* (open but not-reading) host only becomes a forward error if the
//! connection has a **write deadline** — without one, `write` blocks indefinitely and the drain
//! stalls. So the guarantee is: **given a stream with read/write deadlines set** (the caller's job —
//! see [`ServerConnection`]), any dead-or-stalled host is a bounded, typed error, never a hang.
//!
//! The agent carries exec/IO only — it is a convenience inside the isolation boundary, never part of
//! the trust boundary (spine property 2). Containment is the microVM, not this code.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use agent_channel::{ChannelError, Request, Response, ServerConnection};

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
            AgentError::Spawn(e) => write!(f, "spawn command: {e}"),
            AgentError::Wait(e) => write!(f, "wait for command: {e}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentError::Channel(e) => Some(e),
            AgentError::Spawn(e) | AgentError::Wait(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ChannelError> for AgentError {
    fn from(e: ChannelError) -> Self {
        AgentError::Channel(e)
    }
}

/// Serve one exec request over `stream` and return the command's exit code.
///
/// The handshake is done by [`ServerConnection::accept`]; on a spawn failure the agent sends a
/// terminal [`Response::Error`] to the host *and* returns [`AgentError::Spawn`], so both sides learn
/// the command never ran. Emits a `tracing` span (`exec`) carrying the argv, exit code, and elapsed
/// time, so a guest-side failure is diagnosable from the log.
///
/// The no-hang guarantee holds **only if `stream` carries read/write deadlines** (see the module
/// note); a silent hung *command* (`sleep infinity`, no output) is a different matter, bounded by
/// the exec wall-timeout in a later phase (P2.6), not here.
///
/// # Errors
/// [`AgentError`] on any channel, spawn, or wait failure. Note a command that runs and exits
/// non-zero is **not** an error here — that's a normal [`Response::Exit`] with a non-zero code.
pub fn serve<S>(stream: S) -> Result<i32, AgentError>
where
    S: Read + Write + Send,
{
    let mut conn = ServerConnection::accept(stream)?;

    let (argv, stdin) = match conn.recv_request()? {
        Request::Exec { argv, stdin } => (argv, stdin),
        // `Request` is `#[non_exhaustive]`: a newer host may send a type we don't know yet.
        _ => {
            conn.send_response(&Response::Error("unsupported request".into()))?;
            return Err(AgentError::UnsupportedRequest);
        }
    };

    let span = tracing::info_span!("exec", argv = ?argv);
    let _enter = span.enter();

    let Some((program, args)) = argv.split_first() else {
        conn.send_response(&Response::Error("empty command".into()))?;
        return Err(AgentError::EmptyCommand);
    };

    let started = Instant::now();
    let mut child = match Command::new(program)
        .args(args)
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

    let status = std::thread::scope(|scope| {
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
        // child from blocking on a full pipe. (A silent hung command still blocks here; bounding
        // that is the exec wall-timeout in a later phase.)
        child.wait()
    });

    if let Some(e) = first_err
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    {
        return Err(AgentError::Channel(e));
    }
    let status = status.map_err(AgentError::Wait)?;
    let code = exit_code(&status);

    let mut guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
    guard.send_response(&Response::Exit { code })?;
    tracing::info!(
        exit_code = code,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "command finished"
    );
    Ok(code)
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
