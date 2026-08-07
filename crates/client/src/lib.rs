//! The reference **Rust client** for the `ekvm` wire API: drive a sandbox **session**
//! over a unix socket, `open` → (`exec` | `put` | `get` | `snapshot` | `trace`)\* → `close`, using
//! nothing but the shared wire contract ([`ekvm_protocol`]) and a JSON value for the opaque trace
//! record.
//!
//! **This is the proof.** The proof: it links **no `ekvm`**, so it demonstrates
//! that a caller drives the daemon with only a JSON library and a unix socket, the exact surface a
//! caller in any language has.

//!
//! **Synchronous and blocking**, matching the daemon: one [`Client`] owns one connection (one
//! session), each call sends a request line and blocks for the one response line. Errors are typed
//! ([`ClientError`]), a decode fault, a remote [`Error`](ekvm_protocol::Response::Error), or an
//! unexpected reply, never a panic.
//!
//! ```no_run
//! use ekvm_client::Client;
//! let mut client = Client::connect("/run/ekvm/ekvm.sock")?;
//! client.open(Default::default())?;                 // boot the session's sandbox
//! let run = client.exec(&["echo".into(), "hi".into()], "")?;
//! assert_eq!(run.stdout, "hi\n");
//! client.put("input.txt", "payload\n")?;            // stage a file for a later exec
//! let record = client.trace()?;                     // the host-observed audit record
//! client.close()?;                                  // tear the sandbox down
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use ekvm_protocol::{
    ExecParams, FaultKind, GetParams, ProtocolError, PutParams, Request, Response, read_response,
    write_request,
};

// The session-knobs struct is the protocol's, re-exported so a caller of this client names one
// type and a new knob is written once (it lives in `ekvm-protocol`, where the wire shape and
// the Rust shape can't drift apart).
pub use ekvm_protocol::OpenParams;

/// Everything a client call can fail with, typed, never a panic.
#[derive(Debug)]
pub enum ClientError {
    /// The wire framing/decoding failed (I/O, a malformed line, a schema mismatch, an over-cap line).
    Protocol(ProtocolError),
    /// The daemon answered with an [`Error`](Response::Error): the request could not be served.
    /// `fatal` mirrors the daemon's meaning, `true` means the session is gone (reconnect), `false`
    /// is a per-request fault the session survived.
    Remote {
        /// The daemon's human-readable reason. For display and logs; branch on `kind`.
        message: String,
        /// Whether the session ended (the sandbox is gone).
        fatal: bool,
        /// Which layer faulted, so a caller decides what to do without parsing `message`.
        kind: FaultKind,
    },
    /// The daemon refused because it is **at capacity** (an [`AtCapacity`](Response::AtCapacity)
    /// reply): backpressure, distinct from a request fault, so a dispatcher fails over to another host
    /// rather than treating it as terminal. Always session-ending.
    AtCapacity {
        /// The daemon's suggested backoff before retrying, milliseconds. A hint only.
        retry_after_ms: u64,
    },
    /// The daemon sent a well-formed reply, but not the one this call awaited (a protocol desync).
    Unexpected(Response),
    /// The daemon closed the connection without replying.
    Closed,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Protocol(e) => write!(f, "{e}"),
            ClientError::Remote {
                message,
                fatal,
                kind,
            } => {
                write!(f, "daemon error ({kind:?}, fatal={fatal}): {message}")
            }
            ClientError::AtCapacity { retry_after_ms } => {
                write!(f, "daemon at capacity (retry after {retry_after_ms}ms)")
            }
            ClientError::Unexpected(resp) => write!(f, "unexpected reply from daemon: {resp:?}"),
            ClientError::Closed => write!(f, "daemon closed the connection without replying"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ProtocolError> for ClientError {
    fn from(e: ProtocolError) -> Self {
        ClientError::Protocol(e)
    }
}

/// What [`Client::open`] returns: the sandbox booted.
#[derive(Debug, Clone, Copy)]
pub struct Opened {
    /// Boot-to-userspace latency, milliseconds.
    pub boot_ms: u64,
    /// `true` if the daemon served this from its pre-warmed pool (a fast open).
    pub pooled: bool,
}

/// What [`Client::exec`] returns: one command's result. A non-zero [`exit_code`](Self::exit_code) is
/// a normal result, not an error.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// The guest command's exit code (`128 + signal` on signal death).
    pub exit_code: i32,
    /// The command's stdout, lossy UTF-8.
    pub stdout: String,
    /// The command's stderr, lossy UTF-8.
    pub stderr: String,
    /// Host-observed wall-clock of the exec, milliseconds.
    pub exec_wall_ms: u64,
}

/// One connection to a running `ekvm serve`, i.e. one sandbox session. Dropping it hangs up the
/// connection, which tears the session's sandbox down daemon-side (the same as [`close`](Self::close)
/// without the acknowledgement).
#[derive(Debug)]
pub struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    /// Connect to the daemon listening at `socket`. Does not open a session yet, call
    /// [`open`](Self::open) first.
    /// # Errors
    /// The underlying connect error if the socket is absent or not accepting.
    pub fn connect(socket: impl AsRef<Path>) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let writer = stream.try_clone()?;
        Ok(Self {
            writer,
            reader: BufReader::new(stream),
        })
    }

    /// Bound how long a call blocks waiting for a reply, so a wedged daemon can't hang the caller
    /// forever. `None` blocks indefinitely (the default). A boot can take seconds, so set this
    /// generously if you set it at all.
    /// # Errors
    /// The underlying `setsockopt` error.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.reader.get_ref().set_read_timeout(timeout)
    }

    /// Bound how long a call blocks *writing* a request, so a daemon that stops reading can't hang
    /// the caller forever: without it a large `put`/`exec` fills the socket buffer and blocks in
    /// `write_request` with no opt-out. `None` blocks indefinitely (the default). Set it generously
    /// (a big `put` is real bytes over the socket), like the read timeout.
    /// # Errors
    /// The underlying `setsockopt` error.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.writer.set_write_timeout(timeout)
    }

    /// Open the session's sandbox. Must be the first call; the daemon boots a microVM and reports
    /// its latency (and whether it came from the warm pool).
    /// # Errors
    /// [`ClientError`] on a decode fault, a remote error (e.g. a boot failure), or an unexpected
    /// reply.
    pub fn open(&mut self, params: OpenParams) -> Result<Opened, ClientError> {
        self.send(&Request::Open(params))?;
        match self.recv()? {
            Response::Opened {
                boot_ms, pooled, ..
            } => Ok(Opened { boot_ms, pooled }),
            other => Err(unexpected(other)),
        }
    }

    /// Run one command in the open session, feeding `stdin`. Repeated calls share the session's
    /// working directory (the VM is the session).
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error (a command that couldn't spawn is a
    /// non-fatal [`Remote`](ClientError::Remote); the session survives it).
    pub fn exec(&mut self, argv: &[String], stdin: &str) -> Result<ExecOutcome, ClientError> {
        self.exec_with_env(argv, stdin, &[])
    }

    /// Run one command with `env` set on the **spawned command only**, the richer form of
    /// [`exec`](Self::exec). The guest agent applies the variables via `Command::env`, never to its
    /// own process, so they cannot bleed into a later exec on the same session.
    ///
    /// Values are secrets by contract: they are never logged by the daemon and never rendered by
    /// [`Request`]'s `Debug`. What the *command* does with them is the run's own output.
    /// # Errors
    /// As [`exec`](Self::exec).
    pub fn exec_with_env(
        &mut self,
        argv: &[String],
        stdin: &str,
        env: &[(String, String)],
    ) -> Result<ExecOutcome, ClientError> {
        let mut params = ExecParams::new(argv.to_vec());
        params.stdin = (!stdin.is_empty()).then(|| stdin.to_string());
        // Absent rather than an empty list, so the common case stays off the wire entirely.
        params.env = (!env.is_empty()).then(|| env.to_vec());
        self.send(&Request::Exec(params))?;
        match self.recv()? {
            Response::Result {
                exit_code,
                stdout,
                stderr,
                exec_wall_ms,
                ..
            } => Ok(ExecOutcome {
                exit_code,
                stdout,
                stderr,
                exec_wall_ms,
            }),
            other => Err(unexpected(other)),
        }
    }

    /// Write `content` (UTF-8 text) to `path` in the session's working directory, so a later
    /// [`exec`](Self::exec) sees it.
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error.
    pub fn put(&mut self, path: &str, content: &str) -> Result<(), ClientError> {
        self.send(&Request::Put(PutParams::new(
            path.to_string(),
            content.to_string(),
        )))?;
        match self.recv()? {
            Response::Put { .. } => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Read `path` back from the session's working directory. `Ok(None)` is a missing file (not an
    /// error); `Ok(Some(content))` is its lossy-UTF-8 contents.
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error.
    ///
    /// The reply's `lossy` flag (non-UTF-8 bytes were replaced in `content`) is dropped by this
    /// text-convenience signature; a caller that must detect substitution reads
    /// [`Response::Got`] itself.
    pub fn get(&mut self, path: &str) -> Result<Option<String>, ClientError> {
        self.send(&Request::Get(GetParams::new(path.to_string())))?;
        match self.recv()? {
            Response::Got {
                content, present, ..
            } => Ok(present.then_some(content)),
            other => Err(unexpected(other)),
        }
    }

    /// Snapshot the session's VM, returning the **daemon-host** path of the bundle. A jailed session
    /// is a typed remote refusal (its disk is in the chroot).
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error (including the jailed refusal).
    pub fn snapshot(&mut self) -> Result<String, ClientError> {
        self.send(&Request::Snapshot)?;
        match self.recv()? {
            Response::Snapshotted { dir, .. } => Ok(dir),
            other => Err(unexpected(other)),
        }
    }

    /// Fetch the session's host-observed audit record so far, as the `RunRecord` JSON object. Carried
    /// opaquely so this client stays free of the `ekvm-probes-loader` types; parse it with `serde_json`.
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error.
    pub fn trace(&mut self) -> Result<serde_json::Value, ClientError> {
        self.send(&Request::Trace)?;
        match self.recv()? {
            Response::Trace { record, .. } => Ok(record),
            other => Err(unexpected(other)),
        }
    }

    /// Fetch the session's model-legible **summary** so far, as the projection JSON object, the same
    /// compact face the CLI's `--record-summary` writes, shaped for an agent's observe→act loop.
    /// Carried opaquely like [`trace`](Self::trace); parse it with `serde_json`.
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error.
    pub fn trace_summary(&mut self) -> Result<serde_json::Value, ClientError> {
        self.send(&Request::TraceSummary)?;
        match self.recv()? {
            Response::TraceSummary { summary, .. } => Ok(summary),
            other => Err(unexpected(other)),
        }
    }

    /// End the session: ask the daemon to tear the sandbox down and acknowledge. Dropping the client
    /// does the same teardown without the acknowledgement.
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error.
    pub fn close(&mut self) -> Result<(), ClientError> {
        self.send(&Request::Close)?;
        match self.recv()? {
            Response::Closed => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Abandon an in-flight request and end the session, acknowledged with `Cancelled`.
    ///
    /// The only verb legal while another request is outstanding, which means the only one worth
    /// sending from a *second* thread: a caller blocked in [`exec`](Self::exec) holds `&mut self`,
    /// so cancelling a running command means writing to a cloned socket handle rather than calling
    /// this. Called between requests it is a protocol error, since nothing is in flight.
    ///
    /// **This ends the session; it does not abort one command.** Cancelling kills the sandbox, so
    /// session state is gone. Snapshot first if it matters.
    ///
    /// # Errors
    /// [`ClientError`] on a decode fault or a remote error.
    pub fn cancel(&mut self) -> Result<(), ClientError> {
        self.send(&Request::Cancel)?;
        match self.recv()? {
            Response::Cancelled => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Send one request line, stamped with the wire schema.
    fn send(&mut self, req: &Request) -> Result<(), ClientError> {
        write_request(&mut self.writer, req).map_err(ClientError::Protocol)
    }

    /// Read one response line, mapping a clean EOF to [`ClientError::Closed`], a remote
    /// [`Error`](Response::Error) to [`ClientError::Remote`], and an
    /// [`AtCapacity`](Response::AtCapacity) refusal to [`ClientError::AtCapacity`], so callers only
    /// match the replies they expect and see backpressure as its own class.
    fn recv(&mut self) -> Result<Response, ClientError> {
        match read_response(&mut self.reader)? {
            None => Err(ClientError::Closed),
            Some(Response::Error {
                message,
                fatal,
                kind,
                ..
            }) => Err(ClientError::Remote {
                message,
                fatal,
                kind,
            }),
            Some(Response::AtCapacity { retry_after_ms, .. }) => {
                Err(ClientError::AtCapacity { retry_after_ms })
            }
            Some(resp) => Ok(resp),
        }
    }
}

/// A well-formed reply that wasn't the one a call awaited.
fn unexpected(resp: Response) -> ClientError {
    ClientError::Unexpected(resp)
}
