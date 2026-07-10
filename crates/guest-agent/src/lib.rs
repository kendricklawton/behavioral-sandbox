//! `agent-guest` — the in-guest agent that runs a command and reports its result over the channel.
//!
//! [`serve`] handles **one connection**: it does the [`agent_channel`] handshake, reads a single
//! [`Request::Exec`], runs the command, streams its `stdout`/`stderr` back as they arrive, and ends
//! with the exit code. It is generic over the byte stream, so the same logic runs over **vsock** in
//! a real guest (P2.3) and over a **unix socket** in tests and the `main` harness here — the driver
//! is unit-testable without a VM.
//!
//! **The load-bearing subtlety** (the Phase-1 pipe-deadlock lesson, again): the child's `stdout`
//! and `stderr` are drained by two threads that **keep reading even if forwarding to the host
//! fails**. If a pump stopped on a broken connection, the child's ~64 KiB pipe would fill, the child
//! would block writing, and `wait()` would hang forever — so a dead host would wedge a live guest
//! process. Draining unconditionally guarantees the child can always finish; the first forward error
//! is recorded and returned after the child is reaped.
//!
//! The agent carries exec/IO only — it is a convenience inside the isolation boundary, never part of
//! the trust boundary (spine property 2). Containment is the microVM, not this code.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

use agent_channel::{ChannelError, Request, Response};

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

/// Serve one exec request over `conn` and return the command's exit code.
///
/// Both peers send-then-receive the handshake, so this never deadlocks against a well-behaved host.
/// On a spawn failure the agent sends a terminal [`Response::Error`] to the host *and* returns
/// [`AgentError::Spawn`], so both sides learn the command never ran.
///
/// # Errors
/// [`AgentError`] on any channel, spawn, or wait failure. Note a command that runs and exits
/// non-zero is **not** an error here — that's a normal [`Response::Exit`] with a non-zero code.
pub fn serve<S>(mut conn: S) -> Result<i32, AgentError>
where
    S: Read + Write + Send,
{
    agent_channel::write_handshake(&mut conn)?;
    agent_channel::read_handshake(&mut conn)?;

    let argv = match agent_channel::read_request(&mut conn)? {
        Request::Exec { argv } => argv,
        // `Request` is `#[non_exhaustive]`: a newer host may send a type we don't know yet.
        _ => {
            agent_channel::write_response(
                &mut conn,
                &Response::Error("unsupported request".into()),
            )?;
            return Err(AgentError::UnsupportedRequest);
        }
    };

    let Some((program, args)) = argv.split_first() else {
        agent_channel::write_response(&mut conn, &Response::Error("empty command".into()))?;
        return Err(AgentError::EmptyCommand);
    };

    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let _ = agent_channel::write_response(
                &mut conn,
                &Response::Error(format!("could not run {program}: {e}")),
            );
            return Err(AgentError::Spawn(e));
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    // The connection is now write-only (P2.5 adds stdin streaming); share it across the pump
    // threads. `first_err` records the first forward failure without stopping the drain.
    let conn = Mutex::new(conn);
    let first_err: Mutex<Option<ChannelError>> = Mutex::new(None);

    let status = std::thread::scope(|scope| {
        if let Some(out) = stdout {
            scope.spawn(|| pump(out, Kind::Stdout, &conn, &first_err));
        }
        if let Some(err) = stderr {
            scope.spawn(|| pump(err, Kind::Stderr, &conn, &first_err));
        }
        // Reap in the scope's own thread while the pumps drain in parallel — this is what keeps the
        // child from blocking on a full pipe.
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
    agent_channel::write_response(&mut *guard, &Response::Exit(code))?;
    Ok(code)
}

/// Which stream a pump is forwarding.
#[derive(Clone, Copy)]
enum Kind {
    Stdout,
    Stderr,
}

/// Drain one child pipe to the host, in chunks under `MAX_PAYLOAD`. Reads to EOF **unconditionally**
/// (see the module note): once a forward fails, the first error is recorded and later chunks are
/// discarded, but the pipe is still drained so the child can exit.
fn pump<R, S>(mut src: R, kind: Kind, conn: &Mutex<S>, first_err: &Mutex<Option<ChannelError>>)
where
    R: Read,
    S: Write,
{
    let mut buf = [0u8; 16 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // Skip the forward once something has already failed — but keep looping to drain.
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
                if let Err(e) = agent_channel::write_response(&mut *w, &resp) {
                    drop(w);
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
