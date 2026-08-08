//! The reference **Rust client** for the `bsx` wire API.
//! Drives a sandbox session over a unix socket.
#![forbid(unsafe_code)]

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use bsx_protocol::{
    ExecParams, FaultKind, GetParams, ProtocolError, PutParams, Request, Response, read_response,
    write_request,
};

pub use bsx_protocol::OpenParams;

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

/// What [`Client::open`] returns.
#[derive(Debug, Clone, Copy)]
pub struct Opened {
    /// Boot-to-userspace latency in milliseconds.
    pub boot_ms: u64,
    /// `true` if served from the pre-warmed pool.
    pub pooled: bool,
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
#[derive(Debug)]
pub struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    /// Connect to the daemon listening at `socket`.
    pub fn connect(socket: impl AsRef<Path>) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let writer = stream.try_clone()?;
        Ok(Self {
            writer,
            reader: BufReader::new(stream),
        })
    }

    /// Bound how long a call blocks waiting for a reply.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.reader.get_ref().set_read_timeout(timeout)
    }

    /// Bound how long a call blocks writing a request.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.writer.set_write_timeout(timeout)
    }

    /// Open the session's sandbox.
    pub fn open(&mut self, params: OpenParams) -> Result<Opened, ClientError> {
        self.send(&Request::Open(params))?;
        match self.recv()? {
            Response::Opened {
                boot_ms, pooled, ..
            } => Ok(Opened { boot_ms, pooled }),
            other => Err(unexpected(other)),
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
            other => Err(unexpected(other)),
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
            other => Err(unexpected(other)),
        }
    }

    /// Read a file back from the session's working directory.
    pub fn get(&mut self, path: &str) -> Result<Option<String>, ClientError> {
        self.send(&Request::Get(GetParams::new(path.to_string())))?;
        match self.recv()? {
            Response::Got {
                content, present, ..
            } => Ok(present.then_some(content)),
            other => Err(unexpected(other)),
        }
    }

    /// Snapshot the session's VM, returning the host path of the bundle.
    pub fn snapshot(&mut self) -> Result<String, ClientError> {
        self.send(&Request::Snapshot)?;
        match self.recv()? {
            Response::Snapshotted { dir, .. } => Ok(dir),
            other => Err(unexpected(other)),
        }
    }

    /// Fetch the session's host-observed audit record as a JSON object.
    pub fn trace(&mut self) -> Result<serde_json::Value, ClientError> {
        self.send(&Request::Trace)?;
        match self.recv()? {
            Response::Trace { record, .. } => Ok(record),
            other => Err(unexpected(other)),
        }
    }

    /// Fetch the session's model-legible summary as a JSON object.
    pub fn trace_summary(&mut self) -> Result<serde_json::Value, ClientError> {
        self.send(&Request::TraceSummary)?;
        match self.recv()? {
            Response::TraceSummary { summary, .. } => Ok(summary),
            other => Err(unexpected(other)),
        }
    }

    /// End the session and tear down the sandbox.
    pub fn close(&mut self) -> Result<(), ClientError> {
        self.send(&Request::Close)?;
        match self.recv()? {
            Response::Closed => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Abandon an in-flight request and kill the sandbox session.
    pub fn cancel(&mut self) -> Result<(), ClientError> {
        self.send(&Request::Cancel)?;
        match self.recv()? {
            Response::Cancelled => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn send(&mut self, req: &Request) -> Result<(), ClientError> {
        write_request(&mut self.writer, req).map_err(ClientError::Protocol)
    }

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

fn unexpected(resp: Response) -> ClientError {
    ClientError::Unexpected(resp)
}
