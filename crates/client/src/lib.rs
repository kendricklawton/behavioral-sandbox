//! The reference **Rust client** for the `bsx` wire API.
//! Drives a sandbox session over a unix socket.
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bsx_protocol::{ExecParams, GetParams, PutParams, Request, read_response, write_request};

mod deadline;
use deadline::DeadlineStream;

/// Re-exported so a caller can name everything this crate's surface carries ([`ClientError`]'s
/// variants hold the last three) without adding `bsx-protocol` to its own manifest.
pub use bsx_protocol::{FaultKind, OpenParams, ProtocolError, Response};

/// Everything a client call can fail with, typed and never panics.
#[derive(Debug)]
pub enum ClientError {
    /// Wire framing or decoding failed.
    Protocol(ProtocolError),
    /// The daemon answered with an error.
    Remote {
        message: String,
        fatal: bool,
        kind: FaultKind,
    },
    /// The daemon is at capacity; backpressure suggestion included.
    AtCapacity { retry_after_ms: u64 },
    /// Protocol desync: well-formed reply, but unexpected for the call.
    Unexpected(Response),
    /// The daemon closed the connection without replying.
    Closed,
    /// The in-flight request was cancelled from a [`Canceller`]. The daemon tears the session down
    /// after this reply, so the client is done either way.
    Cancelled,
    /// The session's request/reply pairing can no longer be trusted; drop this client and
    /// reconnect. Refusing here is what keeps a stale reply from returning as another call's `Ok`.
    Desynced {
        /// What broke the pairing.
        cause: &'static str,
    },
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
                write!(f, "daemon error ({kind}, fatal={fatal}): {message}")
            }
            ClientError::AtCapacity { retry_after_ms } => {
                write!(f, "daemon at capacity (retry after {retry_after_ms}ms)")
            }
            ClientError::Unexpected(resp) => {
                write!(f, "unexpected reply from daemon: {}", describe(resp))
            }
            ClientError::Closed => write!(f, "daemon closed the connection without replying"),
            ClientError::Cancelled => {
                write!(f, "the request was cancelled; the session is over")
            }
            ClientError::Desynced { cause } => {
                write!(
                    f,
                    "session out of sync ({cause}); drop this client and reconnect"
                )
            }
        }
    }
}

/// A **bounded** rendering of a reply: its wire tag, and sizes rather than contents.
///
/// A mismatched reply is carried whole in [`ClientError::Unexpected`] so a caller can inspect it, but
/// the `Display` a caller prints must not grow with it. `Result` and `Got` carry payloads bounded only
/// by the daemon's `output_cap` and `MAX_RESPONSE_BYTES` (33 MiB), and `{:?}` escapes a `String`, so a
/// payload dense in control bytes renders about **5x** its own size (measured 2026-08-11). Sizes are
/// in bytes of UTF-8, which is what the wire cap counts.
///
/// The wildcard arm is the safe default on purpose: [`Response`] is `#[non_exhaustive]`, so a variant
/// a newer daemon adds renders as a name here rather than falling back to dumping itself.
fn describe(resp: &Response) -> String {
    match resp {
        Response::Opened {
            boot_ms, pooled, ..
        } => {
            format!("opened (boot {boot_ms}ms, pooled={pooled})")
        }
        Response::Result {
            exit_code,
            stdout,
            stderr,
            ..
        } => format!(
            "result (exit {exit_code}, {}B stdout, {}B stderr)",
            stdout.len(),
            stderr.len()
        ),
        Response::Put { .. } => "put".to_string(),
        Response::Got {
            content, present, ..
        } => format!("got ({}B, present={present})", content.len()),
        Response::Snapshotted { .. } => "snapshotted".to_string(),
        Response::Trace { .. } => "trace".to_string(),
        Response::TraceSummary { .. } => "trace_summary".to_string(),
        Response::Closed => "closed".to_string(),
        Response::Cancelled => "cancelled".to_string(),
        Response::Error { kind, fatal, .. } => {
            // An `Unknown` kind carries daemon-sent text of any length, and this rendering is
            // bounded by contract, so the kind is cut like the payloads are elided.
            let kind: String = kind.to_string().chars().take(32).collect();
            format!("error ({kind}, fatal={fatal})")
        }
        Response::AtCapacity { .. } => "at_capacity".to_string(),
        _ => "unrecognised reply".to_string(),
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

/// What [`Client::open`] returns.
#[derive(Debug, Clone, Copy)]
pub struct Opened {
    /// Boot-to-userspace latency in milliseconds.
    pub boot_ms: u64,
    /// `true` if served from the pre-warmed pool.
    pub pooled: bool,
}

/// What [`Client::get`] returns for a present file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The file's contents as UTF-8.
    pub content: String,
    /// `true` when `content` is a lossy rendering: the file's bytes were not valid UTF-8 and the
    /// originals are not recoverable from this reply. Only the daemon saw the bytes, so this flag
    /// is what keeps the substitution from being silent.
    pub lossy: bool,
}

/// What [`Client::exec`] returns.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// The guest command's exit code.
    pub exit_code: i32,
    /// Command stdout (lossy UTF-8).
    pub stdout: String,
    /// Command stderr (lossy UTF-8).
    pub stderr: String,
    /// Host-observed wall-clock duration in milliseconds.
    pub exec_wall_ms: u64,
}

/// One connection to a running `bsx serve` session.
///
/// - **A failed read is the end of the session, not a retry point.** Once a reply is lost (a fired
///   timeout, a decode failure, a mismatched shape, a hang-up), the request/reply pairing is gone
///   and the next reply on the wire belongs to an earlier call. The client poisons itself and every
///   later call returns [`ClientError::Desynced`]: a typed refusal, where reusing the stream would
///   return another command's result as a plain `Ok`.
#[derive(Debug)]
pub struct Client {
    /// Behind a lock shared with every [`Canceller`], so a cancel line can never land inside
    /// another request's frame.
    writer: Arc<Mutex<DeadlineStream>>,
    reader: BufReader<DeadlineStream>,
    /// The first cause that broke the session, shared so every handle refuses together.
    poisoned: Arc<OnceLock<&'static str>>,
}

impl Client {
    /// Connect to the daemon listening at `socket`.
    pub fn connect(socket: impl AsRef<Path>) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let writer = Arc::new(Mutex::new(DeadlineStream::new(
            stream.try_clone()?,
            "the request outran the call's write budget",
        )));
        Ok(Self {
            writer,
            reader: BufReader::new(DeadlineStream::new(
                stream,
                "the reply outran the call's read budget",
            )),
            poisoned: Arc::new(OnceLock::new()),
        })
    }

    /// Bound each call by one **absolute** read budget: the whole reply must arrive within it, so
    /// a daemon dribbling a byte at a time inside the interval cannot stretch a call past the
    /// bound. A budget that lapses surfaces as a `TimedOut` io error, costs that reply, and
    /// poisons the session ([`ClientError::Desynced`] from then on); reconnect.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.reader.get_mut().set_budget(timeout)
    }

    /// The write-side twin of [`set_read_timeout`](Self::set_read_timeout): one absolute budget
    /// per request, so a daemon draining one byte at a time cannot stretch a send past it.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        lock(&self.writer).set_budget(timeout)
    }

    /// A handle that can cancel this session while a call is in flight; see [`Canceller`].
    pub fn canceller(&self) -> Canceller {
        Canceller {
            writer: Arc::clone(&self.writer),
            poisoned: Arc::clone(&self.poisoned),
        }
    }

    /// Open the session's sandbox.
    pub fn open(&mut self, params: OpenParams) -> Result<Opened, ClientError> {
        self.send(&Request::Open(params))?;
        match self.recv()? {
            Response::Opened {
                boot_ms, pooled, ..
            } => Ok(Opened { boot_ms, pooled }),
            other => Err(self.unexpected(other)),
        }
    }

    /// Run one command in the open session.
    pub fn exec(&mut self, argv: &[String], stdin: &str) -> Result<ExecOutcome, ClientError> {
        self.exec_with_env(argv, stdin, &[])
    }

    /// Run one command with custom environment variables set on the spawned command only.
    pub fn exec_with_env(
        &mut self,
        argv: &[String],
        stdin: &str,
        env: &[(String, String)],
    ) -> Result<ExecOutcome, ClientError> {
        let mut params = ExecParams::new(argv.to_vec());
        params.stdin = (!stdin.is_empty()).then(|| stdin.to_string());
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
            other => Err(self.unexpected(other)),
        }
    }

    /// Write content to a path in the session's working directory.
    pub fn put(&mut self, path: &str, content: &str) -> Result<(), ClientError> {
        self.send(&Request::Put(PutParams::new(
            path.to_string(),
            content.to_string(),
        )))?;
        match self.recv()? {
            Response::Put { .. } => Ok(()),
            other => Err(self.unexpected(other)),
        }
    }

    /// Read a file back from the session's working directory. `None` is a missing file, not an
    /// error; [`Fetched::lossy`] says whether the contents survived UTF-8 intact.
    pub fn get(&mut self, path: &str) -> Result<Option<Fetched>, ClientError> {
        self.send(&Request::Get(GetParams::new(path.to_string())))?;
        match self.recv()? {
            Response::Got {
                content,
                present,
                lossy,
                ..
            } => Ok(present.then_some(Fetched { content, lossy })),
            other => Err(self.unexpected(other)),
        }
    }

    /// Snapshot the session's VM, returning the host path of the bundle.
    pub fn snapshot(&mut self) -> Result<String, ClientError> {
        self.send(&Request::Snapshot)?;
        match self.recv()? {
            Response::Snapshotted { dir, .. } => Ok(dir),
            other => Err(self.unexpected(other)),
        }
    }

    /// Fetch the session's host-observed audit record as a JSON object.
    pub fn trace(&mut self) -> Result<serde_json::Value, ClientError> {
        self.send(&Request::Trace)?;
        match self.recv()? {
            Response::Trace { record, .. } => Ok(record),
            other => Err(self.unexpected(other)),
        }
    }

    /// Fetch the session's model-legible summary as a JSON object.
    pub fn trace_summary(&mut self) -> Result<serde_json::Value, ClientError> {
        self.send(&Request::TraceSummary)?;
        match self.recv()? {
            Response::TraceSummary { summary, .. } => Ok(summary),
            other => Err(self.unexpected(other)),
        }
    }

    /// End the session and tear down the sandbox.
    pub fn close(&mut self) -> Result<(), ClientError> {
        self.send(&Request::Close)?;
        match self.recv()? {
            Response::Closed => Ok(()),
            other => Err(self.unexpected(other)),
        }
    }

    fn send(&mut self, req: &Request) -> Result<(), ClientError> {
        if let Some(cause) = self.poisoned.get() {
            return Err(ClientError::Desynced { cause });
        }
        let mut writer = lock(&self.writer);
        writer.rearm();
        write_request(&mut *writer, req).map_err(|e| {
            // Only an io failure can leave part of the frame on the wire; everything else
            // (`TooLarge`, an encode refusal) errs before any byte moves and the stream stays
            // clean, so poisoning there would cost a healthy session.
            if let ProtocolError::Io(io) = &e {
                self.poison(if io.kind() == std::io::ErrorKind::BrokenPipe {
                    "the daemon closed the connection"
                } else {
                    "a request may be half-written"
                });
            }
            ClientError::Protocol(e)
        })
    }

    fn recv(&mut self) -> Result<Response, ClientError> {
        self.reader.get_mut().rearm();
        // `Remote` and `AtCapacity` are real replies: the pairing is intact and the session stays
        // usable. Everything below the early returns lost a reply, and poisons.
        let err = match read_response(&mut self.reader) {
            Ok(Some(Response::Error {
                message,
                fatal,
                kind,
                ..
            })) => {
                return Err(ClientError::Remote {
                    message,
                    fatal,
                    kind,
                });
            }
            Ok(Some(Response::AtCapacity { retry_after_ms, .. })) => {
                return Err(ClientError::AtCapacity { retry_after_ms });
            }
            // The ack of a `Canceller`'s cancel, surfacing in the call it interrupted. The wire
            // says `cancelled` is the connection's last reply, so the session is over.
            Ok(Some(Response::Cancelled)) => ClientError::Cancelled,
            Ok(Some(resp)) => return Ok(resp),
            Ok(None) => ClientError::Closed,
            Err(e) => ClientError::Protocol(e),
        };
        self.poison(match err {
            ClientError::Closed => "the daemon closed the connection",
            ClientError::Cancelled => "the session was cancelled",
            _ => "a read failed with a reply outstanding",
        });
        Err(err)
    }

    /// Marks the session unusable; the first cause wins and every later call refuses with it.
    fn poison(&self, cause: &'static str) {
        let _ = self.poisoned.set(cause);
    }

    /// A well-formed reply that is not the shape this call sent for: proof the pairing is already
    /// off, so it poisons as well as erring.
    fn unexpected(&self, resp: Response) -> ClientError {
        self.poison("a reply arrived for a different request");
        ClientError::Unexpected(resp)
    }
}

/// The shared writer, with a poisoned lock recovered: the stream has no invariant a panicked
/// holder could have broken that the session poison does not already cover.
fn lock(writer: &Mutex<DeadlineStream>) -> std::sync::MutexGuard<'_, DeadlineStream> {
    writer.lock().unwrap_or_else(|e| e.into_inner())
}

/// Cancels a session while a call is in flight, which is the one thing [`Client`]'s `&mut self`
/// methods cannot express: a caller blocked in a long `exec` holds the borrow for the whole call.
/// Hold one of these before the call, and cancel from another thread once the call is blocked
/// awaiting its reply; the blocked call returns [`ClientError::Cancelled`] when the ack arrives.
///
/// - **After any cancel the `Client` is done**, whatever the blocked call returned. The daemon
///   tears the session down after acking, and if the call's own reply won the race to the wire,
///   the ack is still queued behind it; cancelling poisons the shared session state up front, so
///   the pending replies are reported and everything after them is refused.
/// - The write lock is shared with the `Client`, so a cancel line cannot land inside another
///   request's frame; a cancel during a blocked `send` waits for that write's own timeout.
#[derive(Debug)]
pub struct Canceller {
    writer: Arc<Mutex<DeadlineStream>>,
    poisoned: Arc<OnceLock<&'static str>>,
}

impl Canceller {
    /// Abandon the in-flight request and kill the sandbox session.
    pub fn cancel(&mut self) -> Result<(), ClientError> {
        // Poisoned before the line is written: the session is over from this point whether the
        // cancel or the in-flight call's reply wins the race to the daemon.
        let _ = self.poisoned.set("the session was cancelled");
        let mut writer = lock(&self.writer);
        // Its own call, so its own budget clock: the cancel must not inherit a spent deadline.
        writer.rearm();
        write_request(&mut *writer, &Request::Cancel).map_err(ClientError::Protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mismatched reply renders its **shape**, never its payload.
    ///
    /// `Unexpected` keeps the whole `Response` so a caller can still inspect it, but the `Display` a
    /// caller prints must not scale with it. `Result` and `Got` carry up to the wire's 33 MiB, and
    /// `{:?}` escapes a `String`, so a control-byte payload renders at about 5x its own size: the
    /// rendering, on an error path, would be the largest allocation in the process.
    #[test]
    fn an_unexpected_reply_renders_its_shape_not_its_payload() {
        const MIB: usize = 1024 * 1024;
        // `\u{1}` is one UTF-8 byte and the worst case for `{:?}`, which escapes it to six.
        let worst = "\u{1}".repeat(MIB);
        let reply = Response::result(3, worst.clone(), worst, 42);
        let rendered = ClientError::Unexpected(reply.clone()).to_string();

        assert!(
            rendered.len() < 200,
            "the message must not carry the payload, got {} bytes",
            rendered.len()
        );
        assert!(
            rendered.contains("result") && rendered.contains("exit 3"),
            "it still names the shape that was wrong: {rendered}"
        );
        assert!(
            rendered.contains(&MIB.to_string()),
            "and the size, which is the useful half of the payload: {rendered}"
        );

        // The value itself is untouched: bounding the rendering must not cost a caller the reply.
        assert!(matches!(
            ClientError::Unexpected(reply),
            ClientError::Unexpected(Response::Result { stdout, .. }) if stdout.len() == MIB
        ));
    }

    /// Every variant renders small, including the other payload-carrying one and the unknown case.
    #[test]
    fn every_reply_shape_renders_within_a_line() {
        const MIB: usize = 1024 * 1024;
        let big = "\u{1}".repeat(MIB);
        for reply in [
            Response::opened(12, true),
            Response::result(0, big.clone(), big.clone(), 1),
            Response::put("p".into()),
            Response::got("p".into(), big.clone(), true, true),
            Response::snapshotted("d".into()),
            Response::trace(serde_json::Value::Null),
            Response::trace_summary(serde_json::Value::Null),
            Response::error("m".into(), true, FaultKind::Protocol),
            Response::error("m".into(), true, FaultKind::Unknown(big.clone())),
            Response::at_capacity(5),
            Response::Closed,
            Response::Cancelled,
        ] {
            let rendered = ClientError::Unexpected(reply).to_string();
            assert!(
                rendered.len() < 200,
                "every shape renders within a line, got {} bytes: {rendered:.80}",
                rendered.len()
            );
        }
    }
}
