//! `bsx-channel`, the host↔guest wire protocol for the exec channel.
//!
//! Handles command execution framing over a single bidirectional byte stream (vsock or unix socket).
//! Nearly dependency-free (`zeroize` only) and unit-testable without a VM.
//!
//! **Wire Protocol Design:**
//! - **Handshake:** Starts with 4-byte magic (`AGCH`) + `u16` version. Both peers send then receive.
//!   Version mismatch rejects immediately. An unknown request decodes as [`Request::Unknown`] for
//!   graceful degradation; any other schema change requires a [`PROTOCOL_VERSION`] bump.
//! - **Framing:** Length-prefixed frames: `tag(u8) · len(u32-le) · payload`. `len` is validated against
//!   [`MAX_PAYLOAD`] before allocation to prevent memory exhaustion attacks.
//! - **Role-split API:** [`ClientConnection`] (host) and [`ServerConnection`] (guest) each expose
//!   only their own side of the wire, so sending a frame in the wrong direction is a missing method,
//!   not a runtime error.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::num::NonZeroU32;

use zeroize::Zeroizing;

/// Connection framing magic header bytes ("AGCH").
pub(crate) const MAGIC: [u8; 4] = *b"AGCH";

/// Wire-protocol version. Must bump on breaking framing or schema changes.
pub const PROTOCOL_VERSION: u16 = 3;

/// Maximum payload size for a single frame (1 MiB) to prevent unbounded allocations.
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Maximum length of guest error messages to prevent terminal/log flooding (4 KiB).
const ERROR_MSG_CAP: usize = 4 << 10;

/// The 12 Unicode `Bidi_Control` code points, which reorder how the text around them renders.
/// [`char::is_control`] is category `Cc` only and returns `false` for every one of them, so a guest
/// error string carrying an override reorders the operator's line around it (the Trojan-Source
/// class). Spelled out rather than taken from a Unicode table crate, because this crate carries one
/// dependency on purpose and the property is 12 stable code points.
fn is_bidi_control(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Escapes control and bidi-control characters and truncates guest error messages to prevent
/// terminal injection.
fn sanitize_error_msg(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len().min(ERROR_MSG_CAP));
    for c in msg.chars() {
        if out.len() >= ERROR_MSG_CAP {
            out.push('…');
            break;
        }
        if c.is_control() || is_bidi_control(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Sentinel string emitted by the guest agent on stdout post-`bind` to signal boot readiness.
pub const GUEST_READY_MARKER: &str = "GUEST-READY";

/// The vsock port used for host↔guest agent communication.
pub const VSOCK_PORT: u32 = 1024;

/// The guest path the rootfs build bakes the agent binary in at, and the path a host boots as the
/// VM's workload when it wants an agent to talk to. One definition, because the builder and the
/// dialer live in different crates and a drifted copy boots a machine that runs nothing.
pub const GUEST_AGENT_PATH: &str = "/usr/local/bin/guest-agent";

/// The guest `PATH` a sandbox runs with, shared by the host that sets it and the agent that falls
/// back to it, so a bare program name resolves the same either way.
///
/// libkrun's init resolves a *workload's* bare program name against `/sbin:/usr/sbin:/bin:/usr/bin`
/// (measured, `scratch/ROADMAP.md` 3.1) and exports nothing, so a guest process resolving one for
/// itself starts with no `PATH` at all. `/usr/local` leads, because that is where the image
/// installs the agent ([`GUEST_AGENT_PATH`]).
pub const GUEST_DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin";

/// Scheme prefix for the vsock listener spec (`vsock`).
pub const VSOCK_SCHEME: &str = "vsock";

/// Frame discriminants representing wire message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Tag {
    Exec = 1,
    Stdout = 2,
    Stderr = 3,
    Exit = 4,
    Error = 5,
    PutFile = 6,
    File = 7,
    TimedOut = 8,
    ExecPty = 9,
    Stdin = 10,
    Resize = 11,
}

impl Tag {
    fn from_u8(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Exec),
            2 => Some(Self::Stdout),
            3 => Some(Self::Stderr),
            4 => Some(Self::Exit),
            5 => Some(Self::Error),
            6 => Some(Self::PutFile),
            7 => Some(Self::File),
            8 => Some(Self::TimedOut),
            9 => Some(Self::ExecPty),
            10 => Some(Self::Stdin),
            11 => Some(Self::Resize),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Host-to-guest request message. Uses custom `Debug` to redact secret data.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// Stage a file in the working directory before execution.
    PutFile { path: String, data: Vec<u8> },
    /// Execute a command in the guest. Secret values (`stdin`, `env`) are redacted in logs.
    Exec {
        argv: Vec<String>,
        stdin: Vec<u8>,
        env: Vec<(String, String)>,
        artifacts: Vec<String>,
        timeout_ms: Option<NonZeroU32>,
    },
    /// Execute a command on a pseudo-terminal in the guest and stream it interactively: output
    /// arrives as [`Response::Stdout`] (a pty has one stream, the terminal), input as
    /// [`Request::Stdin`], size changes as [`Request::Resize`], and the end as [`Response::Exit`].
    ExecPty {
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cols: u16,
        rows: u16,
    },
    /// Bytes for the running pty command's input: keystrokes, so redacted in logs.
    Stdin(Vec<u8>),
    /// The host terminal changed size; the guest pty follows it.
    Resize { cols: u16, rows: u16 },
    /// Unrecognized request tag from a newer host; handled gracefully by the guest agent.
    Unknown { tag: u8 },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PutFile { path, data } => f
                .debug_struct("PutFile")
                .field("path", path)
                .field("data", &format_args!("<redacted; {} byte(s)>", data.len()))
                .finish(),
            Self::Exec {
                argv,
                stdin,
                env,
                artifacts,
                timeout_ms,
            } => {
                let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
                f.debug_struct("Exec")
                    .field("argv", argv)
                    .field(
                        "stdin",
                        &format_args!("<redacted; {} byte(s)>", stdin.len()),
                    )
                    .field(
                        "env",
                        &format_args!("<{} var(s), values redacted; keys: {keys:?}>", env.len()),
                    )
                    .field("artifacts", artifacts)
                    .field("timeout_ms", timeout_ms)
                    .finish()
            }
            Self::ExecPty {
                argv,
                env,
                cols,
                rows,
            } => {
                let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
                f.debug_struct("ExecPty")
                    .field("argv", argv)
                    .field(
                        "env",
                        &format_args!("<{} var(s), values redacted; keys: {keys:?}>", env.len()),
                    )
                    .field("cols", cols)
                    .field("rows", rows)
                    .finish()
            }
            Self::Stdin(bytes) => f
                .debug_tuple("Stdin")
                .field(&format_args!("<redacted; {} byte(s)>", bytes.len()))
                .finish(),
            Self::Resize { cols, rows } => f
                .debug_struct("Resize")
                .field("cols", cols)
                .field("rows", rows)
                .finish(),
            Self::Unknown { tag } => f.debug_struct("Unknown").field("tag", tag).finish(),
        }
    }
}

/// Guest-to-host response message stream.
///
/// The derived `Debug` renders payload bytes in full, up to [`MAX_PAYLOAD`] a frame, so a caller that
/// logs one abbreviates it rather than handing `{:?}` a whole response. [`Request`] redacts instead,
/// because its payloads are the host's secrets where these are the guest's own output.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response {
    /// Command stdout chunk.
    Stdout(Vec<u8>),
    /// Command stderr chunk.
    Stderr(Vec<u8>),
    /// Retrieved output artifact.
    File { path: String, data: Vec<u8> },
    /// Terminal execution exit status.
    Exit { code: i32 },
    /// Execution killed due to exceeding wall-clock timeout.
    TimedOut { elapsed_ms: u32 },
    /// Fatal agent or execution startup error.
    Error(String),
}

/// Typed channel error variants preserving underlying I/O errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChannelError {
    /// Stream read/write or EOF failure.
    Io(std::io::Error),
    /// Protocol violation (bad magic, version mismatch, non-UTF-8 payload).
    Protocol(String),
    /// Payload header exceeded [`MAX_PAYLOAD`].
    PayloadTooLarge { tag: u8, len: usize },
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Io(e) => write!(f, "channel io: {e}"),
            ChannelError::Protocol(m) => write!(f, "channel protocol error: {m}"),
            ChannelError::PayloadTooLarge { tag, len } => match Tag::from_u8(*tag) {
                Some(known) => write!(
                    f,
                    "channel frame (tag {tag}/{known:?}) length {len} exceeds {MAX_PAYLOAD}"
                ),
                None => write!(
                    f,
                    "channel frame (tag {tag}) length {len} exceeds {MAX_PAYLOAD}"
                ),
            },
        }
    }
}

impl std::error::Error for ChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChannelError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ChannelError {
    fn from(e: std::io::Error) -> Self {
        ChannelError::Io(e)
    }
}

impl ChannelError {
    /// Returns `true` only for a clean read-side EOF (`UnexpectedEof`): the peer closed between
    /// frames. A send-path close (`BrokenPipe`/`ConnectionReset`, a peer gone mid-write) is
    /// deliberately not one, so a caller that needs the wider "peer is gone" set classifies the
    /// `io::ErrorKind` itself rather than reaching for this. Pinned by `is_disconnect_flags_eof_only`.
    #[must_use]
    pub fn is_disconnect(&self) -> bool {
        matches!(self, ChannelError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    }
}

/// Writes handshake header (`MAGIC` + `PROTOCOL_VERSION`).
pub(crate) fn write_handshake(w: &mut impl Write) -> Result<(), ChannelError> {
    let mut buf = [0u8; 6];
    buf[..4].copy_from_slice(&MAGIC);
    buf[4..].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Reads and validates peer handshake header.
pub(crate) fn read_handshake(r: &mut impl Read) -> Result<(), ChannelError> {
    let mut buf = [0u8; 6];
    r.read_exact(&mut buf)?;
    if buf[..4] != MAGIC {
        return Err(ChannelError::Protocol(
            "bad magic (not an agent channel)".into(),
        ));
    }
    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != PROTOCOL_VERSION {
        return Err(ChannelError::Protocol(format!(
            "unsupported protocol version {version} (this build speaks {PROTOCOL_VERSION})"
        )));
    }
    Ok(())
}

/// Writes a single length-prefixed protocol frame.
fn write_frame(w: &mut impl Write, tag: u8, payload: &[u8]) -> Result<(), ChannelError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge {
            tag,
            len: payload.len(),
        });
    }
    let mut header = [0u8; 5];
    header[0] = tag;
    header[1..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    w.write_all(&header)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Reads a single frame payload, bounded by [`MAX_PAYLOAD`].
fn read_frame(r: &mut impl Read) -> Result<(u8, Vec<u8>), ChannelError> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header)?;
    let tag = header[0];
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge { tag, len });
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok((tag, payload))
}

fn put_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

fn put_blob(payload: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(payload, bytes.len() as u32);
    payload.extend_from_slice(bytes);
}

fn blob_len(bytes: &[u8]) -> usize {
    4 + bytes.len()
}

/// The size of a `blob(path) · blob(data)` frame body, refused past [`MAX_PAYLOAD`] with `tag`
/// named. The shape `PutFile` and `File` share, so the bound is decided once for both.
fn path_blob_len(tag: Tag, path: &str, data: &[u8]) -> Result<usize, ChannelError> {
    let cap = blob_len(path.as_bytes()) + blob_len(data);
    if cap > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge {
            tag: tag.as_u8(),
            len: cap,
        });
    }
    Ok(cap)
}

/// Writes a `blob(path) · blob(data)` body into the caller's buffer. The buffer is the caller's
/// because the `PutFile` side stages a secret and needs a `Zeroizing` one.
fn put_path_blob(payload: &mut Vec<u8>, path: &str, data: &[u8]) {
    put_blob(payload, path.as_bytes());
    put_blob(payload, data);
}

/// Reads a `blob(path) · blob(data)` body, refusing any trailing byte.
fn read_path_blob(payload: &[u8]) -> Result<(String, Vec<u8>), ChannelError> {
    let mut body = Body::new(payload);
    let path = body.string()?;
    let data = body.blob()?.to_vec();
    body.finish()?;
    Ok((path, data))
}

pub(crate) fn write_request(w: &mut impl Write, req: &Request) -> Result<(), ChannelError> {
    match req {
        Request::PutFile { path, data } => write_put_file(w, path, data),
        Request::Exec {
            argv,
            stdin,
            env,
            artifacts,
            timeout_ms,
        } => write_exec(w, argv, stdin, env, artifacts, *timeout_ms),
        Request::ExecPty {
            argv,
            env,
            cols,
            rows,
        } => write_exec_pty(w, argv, env, *cols, *rows),
        Request::Stdin(bytes) => write_stdin(w, bytes),
        Request::Resize { cols, rows } => {
            let mut payload = [0u8; 4];
            payload[..2].copy_from_slice(&cols.to_le_bytes());
            payload[2..].copy_from_slice(&rows.to_le_bytes());
            write_frame(w, Tag::Resize.as_u8(), &payload)
        }
        Request::Unknown { tag } => Err(ChannelError::Protocol(format!(
            "Request::Unknown (tag {tag}) is read-only and cannot be sent"
        ))),
    }
}

/// Serializes and sends an `ExecPty` request. The env values travel in a wiped buffer for
/// [`write_exec`]'s reason: they are secrets by presumption.
fn write_exec_pty(
    w: &mut impl Write,
    argv: &[String],
    env: &[(String, String)],
    cols: u16,
    rows: u16,
) -> Result<(), ChannelError> {
    let cap = 4
        + argv.iter().map(|a| blob_len(a.as_bytes())).sum::<usize>()
        + 4
        + env
            .iter()
            .map(|(k, v)| blob_len(k.as_bytes()) + blob_len(v.as_bytes()))
            .sum::<usize>()
        + 4;
    if cap > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge {
            tag: Tag::ExecPty.as_u8(),
            len: cap,
        });
    }
    let mut payload = Zeroizing::new(Vec::with_capacity(cap));
    put_u32(&mut payload, argv.len() as u32);
    for arg in argv {
        put_blob(&mut payload, arg.as_bytes());
    }
    put_u32(&mut payload, env.len() as u32);
    for (key, value) in env {
        put_blob(&mut payload, key.as_bytes());
        put_blob(&mut payload, value.as_bytes());
    }
    payload.extend_from_slice(&cols.to_le_bytes());
    payload.extend_from_slice(&rows.to_le_bytes());
    write_frame(w, Tag::ExecPty.as_u8(), &payload)
}

/// Serializes and sends a `Stdin` frame from the caller's slice, staged in a wiped buffer:
/// keystrokes are what passwords are typed as.
fn write_stdin(w: &mut impl Write, bytes: &[u8]) -> Result<(), ChannelError> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge {
            tag: Tag::Stdin.as_u8(),
            len: bytes.len(),
        });
    }
    let payload = Zeroizing::new(bytes.to_vec());
    write_frame(w, Tag::Stdin.as_u8(), &payload)
}

/// Serializes and sends a `PutFile` request, wiping the secret-bearing payload on every exit.
pub(crate) fn write_put_file(
    w: &mut impl Write,
    path: &str,
    data: &[u8],
) -> Result<(), ChannelError> {
    let cap = path_blob_len(Tag::PutFile, path, data)?;
    // `Zeroizing`, not a wipe after the send: a caller-supplied `Write` that unwinds would skip an
    // explicit call and drop the staged bytes un-wiped. It scrubs only the buffer it drops, so the
    // exact `cap` above stays load-bearing (`secret_payload_is_exactly_sized_so_one_buffer_holds_it`).
    let mut payload = Zeroizing::new(Vec::with_capacity(cap));
    put_path_blob(&mut payload, path, data);
    write_frame(w, Tag::PutFile.as_u8(), &payload)
}

/// The exact size of an `Exec` frame body: the counts, the argv blobs, stdin, the artifact blobs,
/// the timeout, and the env pairs. A function rather than an expression inside
/// [`write_exec`] so the buffer it sizes and the test asserting that size read the *same*
/// arithmetic; a test with its own copy holds only against itself
/// (`the_exec_buffer_is_sized_by_what_the_encoder_writes`).
fn exec_payload_len<A: AsRef<str>, K: AsRef<str>, V: AsRef<str>, R: AsRef<str>>(
    argv: &[A],
    stdin: &[u8],
    env: &[(K, V)],
    artifacts: &[R],
) -> usize {
    4 + argv
        .iter()
        .map(|a| blob_len(a.as_ref().as_bytes()))
        .sum::<usize>()
        + blob_len(stdin)
        + 4
        + artifacts
            .iter()
            .map(|p| blob_len(p.as_ref().as_bytes()))
            .sum::<usize>()
        + 4
        + 4
        + env
            .iter()
            .map(|(k, v)| blob_len(k.as_ref().as_bytes()) + blob_len(v.as_ref().as_bytes()))
            .sum::<usize>()
}

/// Serializes and sends an `Exec` request, zeroizing buffers post-send.
pub(crate) fn write_exec<A: AsRef<str>, K: AsRef<str>, V: AsRef<str>, R: AsRef<str>>(
    w: &mut impl Write,
    argv: &[A],
    stdin: &[u8],
    env: &[(K, V)],
    artifacts: &[R],
    timeout_ms: Option<NonZeroU32>,
) -> Result<(), ChannelError> {
    let cap = exec_payload_len(argv, stdin, env, artifacts);

    if cap > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge {
            tag: Tag::Exec.as_u8(),
            len: cap,
        });
    }
    // See `write_put_file`: `Zeroizing` wipes on the unwind path too, where an explicit call after
    // the send does not.
    let mut payload = Zeroizing::new(Vec::with_capacity(cap));
    put_u32(&mut payload, argv.len() as u32);
    for arg in argv {
        put_blob(&mut payload, arg.as_ref().as_bytes());
    }
    put_blob(&mut payload, stdin);
    put_u32(&mut payload, artifacts.len() as u32);
    for path in artifacts {
        put_blob(&mut payload, path.as_ref().as_bytes());
    }
    put_u32(&mut payload, timeout_ms.map_or(0, NonZeroU32::get));
    put_u32(&mut payload, env.len() as u32);
    for (key, value) in env {
        put_blob(&mut payload, key.as_ref().as_bytes());
        put_blob(&mut payload, value.as_ref().as_bytes());
    }
    write_frame(w, Tag::Exec.as_u8(), &payload)
}

pub(crate) fn read_request(r: &mut impl Read) -> Result<Request, ChannelError> {
    let (tag, payload) = read_frame(r)?;
    let mut body = Body::new(&payload);
    match Tag::from_u8(tag) {
        Some(Tag::Exec) => {
            let argc = body.u32()? as usize;
            let mut argv = Vec::new();
            for _ in 0..argc {
                argv.push(body.string()?);
            }
            let stdin = body.blob()?.to_vec();
            let artc = body.u32()? as usize;
            let mut artifacts = Vec::new();
            for _ in 0..artc {
                artifacts.push(body.string()?);
            }
            let timeout_ms = NonZeroU32::new(body.u32()?);
            let envc = body.u32()? as usize;
            let mut env = Vec::new();
            for _ in 0..envc {
                env.push((body.string()?, body.string()?));
            }
            body.finish()?;
            Ok(Request::Exec {
                argv,
                stdin,
                env,
                artifacts,
                timeout_ms,
            })
        }
        Some(Tag::PutFile) => {
            let (path, data) = read_path_blob(&payload)?;
            Ok(Request::PutFile { path, data })
        }
        Some(Tag::ExecPty) => {
            let argc = body.u32()? as usize;
            let mut argv = Vec::new();
            for _ in 0..argc {
                argv.push(body.string()?);
            }
            let envc = body.u32()? as usize;
            let mut env = Vec::new();
            for _ in 0..envc {
                env.push((body.string()?, body.string()?));
            }
            let cols = body.u16()?;
            let rows = body.u16()?;
            body.finish()?;
            Ok(Request::ExecPty {
                argv,
                env,
                cols,
                rows,
            })
        }
        Some(Tag::Stdin) => Ok(Request::Stdin(payload)),
        Some(Tag::Resize) => {
            let mut body = Body::new(&payload);
            let cols = body.u16()?;
            let rows = body.u16()?;
            body.finish()?;
            Ok(Request::Resize { cols, rows })
        }
        _ => Ok(Request::Unknown { tag }),
    }
}

pub(crate) fn write_response(w: &mut impl Write, resp: &Response) -> Result<(), ChannelError> {
    match resp {
        Response::Stdout(b) => write_frame(w, Tag::Stdout.as_u8(), b),
        Response::Stderr(b) => write_frame(w, Tag::Stderr.as_u8(), b),
        Response::File { path, data } => {
            let cap = path_blob_len(Tag::File, path, data)?;
            let mut payload = Vec::with_capacity(cap);
            put_path_blob(&mut payload, path, data);
            write_frame(w, Tag::File.as_u8(), &payload)
        }
        Response::Exit { code } => write_frame(w, Tag::Exit.as_u8(), &code.to_le_bytes()),
        Response::TimedOut { elapsed_ms } => {
            write_frame(w, Tag::TimedOut.as_u8(), &elapsed_ms.to_le_bytes())
        }
        Response::Error(msg) => write_frame(w, Tag::Error.as_u8(), msg.as_bytes()),
    }
}

pub(crate) fn read_response(r: &mut impl Read) -> Result<Response, ChannelError> {
    let (tag, payload) = read_frame(r)?;
    match Tag::from_u8(tag) {
        Some(Tag::Stdout) => Ok(Response::Stdout(payload)),
        Some(Tag::Stderr) => Ok(Response::Stderr(payload)),
        Some(Tag::File) => {
            let (path, data) = read_path_blob(&payload)?;
            Ok(Response::File { path, data })
        }
        Some(Tag::Exit) => {
            let bytes: [u8; 4] = payload
                .as_slice()
                .try_into()
                .map_err(|_| ChannelError::Protocol("exit frame is not 4 bytes".into()))?;
            Ok(Response::Exit {
                code: i32::from_le_bytes(bytes),
            })
        }
        Some(Tag::TimedOut) => {
            let bytes: [u8; 4] = payload
                .as_slice()
                .try_into()
                .map_err(|_| ChannelError::Protocol("timed-out frame is not 4 bytes".into()))?;
            Ok(Response::TimedOut {
                elapsed_ms: u32::from_le_bytes(bytes),
            })
        }
        Some(Tag::Error) => {
            let msg = String::from_utf8(payload)
                .map_err(|_| ChannelError::Protocol("error frame is not valid UTF-8".into()))?;
            Ok(Response::Error(sanitize_error_msg(&msg)))
        }
        _ => Err(ChannelError::Protocol(format!(
            "unknown response tag {tag}"
        ))),
    }
}

fn handshake<S: Read + Write>(stream: &mut S) -> Result<(), ChannelError> {
    write_handshake(stream)?;
    read_handshake(stream)
}

/// Host-side connection handle for issuing requests and consuming response streams.
///
/// **A send error retires the connection.** A frame is a header followed by its payload, so a write
/// that fails between them leaves the peer mid-frame: the next frame sent on the same stream is
/// read as the unfinished one's payload, and the send that spliced it still reports `Ok`
/// (`a_send_error_leaves_the_stream_mid_frame`). [`ChannelError::PayloadTooLarge`] is the one
/// exception, raised before a byte is written.
#[derive(Debug)]
pub struct ClientConnection<S> {
    stream: S,
}

impl<S: Read + Write> ClientConnection<S> {
    /// Opens the host side: sends this build's handshake header and validates the peer's.
    pub fn connect(mut stream: S) -> Result<Self, ChannelError> {
        handshake(&mut stream)?;
        Ok(Self { stream })
    }

    /// Sends one already-built request. [`send_exec`](Self::send_exec) and
    /// [`send_put_file`](Self::send_put_file) reach the same wire bytes from the caller's own
    /// slices, so they stage no second copy of a secret.
    pub fn send_request(&mut self, req: &Request) -> Result<(), ChannelError> {
        write_request(&mut self.stream, req)
    }

    /// Stages `data` at `path` in the guest's working directory, serialized straight from the
    /// caller's slice into a buffer wiped on every scope exit.
    pub fn send_put_file(&mut self, path: &str, data: &[u8]) -> Result<(), ChannelError> {
        write_put_file(&mut self.stream, path, data)
    }

    /// Sends the exec request, serialized straight from the caller's slices into a buffer wiped on
    /// every scope exit. `timeout_ms` of `None` asks for the agent's own ceiling.
    pub fn send_exec<A: AsRef<str>, K: AsRef<str>, V: AsRef<str>, R: AsRef<str>>(
        &mut self,
        argv: &[A],
        stdin: &[u8],
        env: &[(K, V)],
        artifacts: &[R],
        timeout_ms: Option<NonZeroU32>,
    ) -> Result<(), ChannelError> {
        write_exec(&mut self.stream, argv, stdin, env, artifacts, timeout_ms)
    }

    /// Reads one response frame. A guest [`Error`](Response::Error) arrives escaped and
    /// length-capped, because it reaches the operator's terminal unquoted.
    pub fn recv_response(&mut self) -> Result<Response, ChannelError> {
        read_response(&mut self.stream)
    }

    /// Wraps a stream **without a handshake**, for the second half of a duplicated connection: an
    /// interactive session sends input and reads output concurrently, which takes one handle per
    /// direction over one already-handshaken stream. On a fresh stream this skips the version
    /// check that [`connect`](Self::connect) exists to make.
    pub fn resume(stream: S) -> Self {
        Self { stream }
    }
}

/// Guest-side connection handle for serving requests and emitting responses.
///
/// Retire it on a send error, for [`ClientConnection`]'s reason: the framing tears the same way in
/// this direction.
#[derive(Debug)]
pub struct ServerConnection<S> {
    stream: S,
}

impl<S: Read + Write> ServerConnection<S> {
    /// Opens the guest side: sends this build's handshake header and validates the peer's.
    pub fn accept(mut stream: S) -> Result<Self, ChannelError> {
        handshake(&mut stream)?;
        Ok(Self { stream })
    }

    /// Reads one request frame. A tag this build does not know arrives as
    /// [`Request::Unknown`] rather than an error, so a host that added a request type does not
    /// drop the link.
    pub fn recv_request(&mut self) -> Result<Request, ChannelError> {
        read_request(&mut self.stream)
    }

    /// Sends one response frame.
    pub fn send_response(&mut self, resp: &Response) -> Result<(), ChannelError> {
        write_response(&mut self.stream, resp)
    }

    /// Wraps a stream **without a handshake**, for [`ClientConnection::resume`]'s reason on the
    /// guest side: the pty session's output pump writes responses while the request loop reads.
    pub fn resume(stream: S) -> Self {
        Self { stream }
    }
}

/// Bounds-checked payload deserialization cursor.
struct Body<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Body<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn u32(&mut self) -> Result<u32, ChannelError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u16(&mut self) -> Result<u16, ChannelError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn blob(&mut self) -> Result<&'a [u8], ChannelError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, ChannelError> {
        let bytes = self.blob()?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| ChannelError::Protocol("field is not valid UTF-8".into()))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ChannelError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| {
                ChannelError::Protocol("frame body ended mid-field (truncated)".into())
            })?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn finish(&self) -> Result<(), ChannelError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(ChannelError::Protocol(format!(
                "frame body has {} unparsed trailing byte(s)",
                self.buf.len() - self.pos
            )))
        }
    }
}

/// The internal decoders, exposed to the `cargo fuzz` targets in `fuzz/` behind the off-by-default
/// `fuzzing` feature so a target drives the shipped parser rather than a copy of it. Each entry
/// discards its result: the property under test is that the decoder returns at all.
///
/// The `_wellformed` pair wraps its input in a valid `tag · len · payload` header, so a target
/// spends its budget inside the body parsers instead of bouncing off the length check.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    use super::{MAGIC, read_frame, read_handshake, read_request, read_response};

    /// Decodes arbitrary bytes as a request frame.
    pub fn decode_request(mut data: &[u8]) {
        let _ = read_request(&mut data);
    }

    /// Decodes arbitrary bytes as a response frame.
    pub fn decode_response(mut data: &[u8]) {
        let _ = read_response(&mut data);
    }

    /// Decodes arbitrary bytes as a bare frame header plus payload.
    pub fn decode_frame(mut data: &[u8]) {
        let _ = read_frame(&mut data);
    }

    /// Decodes arbitrary bytes as a handshake header.
    pub fn decode_handshake(mut data: &[u8]) {
        let _ = read_handshake(&mut data);
    }

    /// Decodes an arbitrary body as a request, past a valid frame header.
    pub fn decode_request_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_request(&mut framed);
        });
    }

    /// Decodes an arbitrary body as a response, past a valid frame header.
    pub fn decode_response_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_response(&mut framed);
        });
    }

    fn frame_and(data: &[u8], f: impl FnOnce(&[u8])) {
        let Some((&tag, payload)) = data.split_first() else {
            return;
        };
        let Ok(len) = u32::try_from(payload.len()) else {
            return;
        };
        let mut framed = Vec::with_capacity(5 + payload.len());
        framed.push(tag);
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(payload);
        f(framed.as_slice());
    }

    /// Decodes an arbitrary body as a frame, past a valid frame header.
    pub fn decode_frame_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_frame(&mut framed);
        });
    }

    /// Decodes arbitrary bytes as the version half of a handshake, past the magic.
    pub fn decode_handshake_after_magic(data: &[u8]) {
        let mut framed = Vec::with_capacity(MAGIC.len() + data.len());
        framed.extend_from_slice(&MAGIC);
        framed.extend_from_slice(data);
        let mut slice = framed.as_slice();
        let _ = read_handshake(&mut slice);
    }
}

#[cfg(test)]
mod fuzz_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Write` that records whether any nonempty buffer was ever handed to it, so a test can pin
    /// that an over-cap encode refuses *before* a byte reaches the stream.
    #[derive(Default)]
    struct ProbeWriter {
        touched: bool,
    }

    impl Write for ProbeWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.touched |= !buf.is_empty();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn handshake_round_trips() {
        let mut buf = Vec::new();
        write_handshake(&mut buf).unwrap();
        read_handshake(&mut buf.as_slice()).unwrap();
    }

    #[test]
    fn request_debug_redacts_secrets_by_construction() {
        let exec = format!(
            "{:?}",
            Request::Exec {
                argv: vec!["deploy".into()],
                stdin: b"stdin-secret-material".to_vec(),
                env: vec![("API_KEY".into(), "hunter2-value".into())],
                artifacts: vec!["out.txt".into()],
                timeout_ms: NonZeroU32::new(1_000),
            }
        );
        assert!(!exec.contains("hunter2-value"), "env value leaked: {exec}");
        assert!(!exec.contains("stdin-secret"), "stdin leaked: {exec}");
        assert!(exec.contains("API_KEY"), "key name should render: {exec}");
        assert!(
            exec.contains("deploy") && exec.contains("redacted"),
            "{exec}"
        );

        let put = format!(
            "{:?}",
            Request::PutFile {
                path: "cfg.toml".into(),
                data: b"file-secret-material".to_vec(),
            }
        );
        assert!(!put.contains("file-secret"), "file bytes leaked: {put}");
        assert!(
            put.contains("cfg.toml") && put.contains("20 byte(s)"),
            "{put}"
        );
    }

    #[test]
    fn handshake_rejects_bad_magic_and_version() {
        let bad_magic = b"XXXX\x01\x00";
        assert!(matches!(
            read_handshake(&mut &bad_magic[..]),
            Err(ChannelError::Protocol(_))
        ));
        let bad_version = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], 0xFF, 0xFF];
        assert!(matches!(
            read_handshake(&mut &bad_version[..]),
            Err(ChannelError::Protocol(_))
        ));
    }

    /// The interactive frames: an `ExecPty` with everything set, an empty-env one, keystrokes
    /// with every byte value's worth of shape, and a resize. Exactness matters double here: a
    /// mis-framed `Stdin` byte lands inside a shell as a keystroke nobody typed.
    #[test]
    fn interactive_requests_round_trip() {
        for req in [
            Request::ExecPty {
                argv: vec!["/bin/sh".into()],
                env: vec![("TERM".into(), "xterm-256color".into())],
                cols: 120,
                rows: 40,
            },
            Request::ExecPty {
                argv: vec!["top".into(), "-d".into(), "1".into()],
                env: vec![],
                cols: 80,
                rows: 24,
            },
            Request::Stdin(b"ls -la\r".to_vec()),
            Request::Stdin(vec![0u8, 3, 4, 27, 255]),
            Request::Stdin(vec![]),
            Request::Resize { cols: 1, rows: 1 },
            Request::Resize {
                cols: u16::MAX,
                rows: u16::MAX,
            },
        ] {
            let mut buf = Vec::new();
            write_request(&mut buf, &req).unwrap();
            assert_eq!(read_request(&mut buf.as_slice()).unwrap(), req);
        }
    }

    /// Keystrokes are what passwords are typed as, so `Stdin`'s debug form must never carry the
    /// bytes; `ExecPty` redacts its env values for `Exec`'s reason.
    #[test]
    fn interactive_secrets_are_redacted_in_debug() {
        let dbg = format!("{:?}", Request::Stdin(b"hunter2".to_vec()));
        assert!(!dbg.contains("hunter2"), "{dbg}");
        assert!(dbg.contains("7 byte(s)"), "{dbg}");

        let dbg = format!(
            "{:?}",
            Request::ExecPty {
                argv: vec!["sh".into()],
                env: vec![("API_KEY".into(), "s3cr3t".into())],
                cols: 80,
                rows: 24,
            }
        );
        assert!(!dbg.contains("s3cr3t"), "{dbg}");
        assert!(dbg.contains("API_KEY"), "keys stay visible: {dbg}");
    }

    /// A resize frame with trailing bytes is refused, not read: the trailing byte is the next
    /// frame's header being eaten.
    #[test]
    fn a_resize_frame_with_trailing_bytes_is_refused() {
        let mut buf = Vec::new();
        write_request(&mut buf, &Request::Resize { cols: 80, rows: 24 }).unwrap();
        buf.push(0);
        // Rebuild the length prefix to cover the extra byte, so the frame reads but the body
        // does not parse.
        let len = (buf.len() - 5) as u32;
        buf[1..5].copy_from_slice(&len.to_le_bytes());
        assert!(read_request(&mut buf.as_slice()).is_err());
    }

    #[test]
    fn request_round_trips_including_unicode_and_empty() {
        for req in [
            Request::Exec {
                argv: vec!["echo".into(), "hi".into()],
                stdin: vec![],
                env: vec![],
                artifacts: vec![],
                timeout_ms: NonZeroU32::new(30_000),
            },
            Request::Exec {
                argv: vec!["/bin/π".into(), "a b\tc".into(), String::new()],
                stdin: b"piped input\n".to_vec(),
                env: vec![
                    ("API_KEY".into(), "s3cr3t=with=equals".into()),
                    ("EMPTY".into(), String::new()),
                    ("UNICODE_π".into(), "väl ue".into()),
                ],
                artifacts: vec!["out.txt".into(), "sub/dir.bin".into()],
                timeout_ms: NonZeroU32::new(1),
            },
            Request::Exec {
                argv: vec![],
                stdin: vec![0u8, 1, 2, 255],
                env: vec![],
                artifacts: vec![],
                timeout_ms: None,
            },
            Request::PutFile {
                path: "in/data.csv".into(),
                data: b"a,b,c\n".to_vec(),
            },
            Request::PutFile {
                path: "empty".into(),
                data: vec![],
            },
        ] {
            let mut buf = Vec::new();
            write_request(&mut buf, &req).unwrap();
            assert_eq!(read_request(&mut buf.as_slice()).unwrap(), req);
        }
    }

    #[test]
    fn tag_discriminants_are_the_wire_numbers() {
        for (tag, wire) in [
            (Tag::Exec, 1u8),
            (Tag::Stdout, 2),
            (Tag::Stderr, 3),
            (Tag::Exit, 4),
            (Tag::Error, 5),
            (Tag::PutFile, 6),
            (Tag::File, 7),
            (Tag::TimedOut, 8),
            (Tag::ExecPty, 9),
            (Tag::Stdin, 10),
            (Tag::Resize, 11),
        ] {
            assert_eq!(tag.as_u8(), wire, "{tag:?} moved on the wire");
            assert_eq!(Tag::from_u8(wire), Some(tag), "{wire} no longer decodes");
        }
        assert_eq!(Tag::from_u8(0), None);
        assert_eq!(Tag::from_u8(12), None);
        assert_eq!(Tag::from_u8(255), None);
    }

    #[test]
    fn the_ceiling_sentinel_is_none_on_both_sides() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let mut framed = vec![Tag::Exec.as_u8()];
        framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        framed.extend_from_slice(&body);

        let decoded = read_request(&mut framed.as_slice()).unwrap();
        assert_eq!(
            decoded,
            Request::Exec {
                argv: vec![],
                stdin: vec![],
                env: vec![],
                artifacts: vec![],
                timeout_ms: None,
            }
        );

        let mut written = Vec::new();
        write_request(&mut written, &decoded).unwrap();
        assert_eq!(written, framed);
    }

    #[test]
    fn a_frame_body_with_trailing_bytes_is_rejected() {
        let append_trailing = |buf: &mut Vec<u8>| {
            let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            buf[1..5].copy_from_slice(&(len + 1).to_le_bytes());
            buf.push(0xEE);
        };

        let mut req = Vec::new();
        write_request(
            &mut req,
            &Request::PutFile {
                path: "a".into(),
                data: b"x".to_vec(),
            },
        )
        .unwrap();
        append_trailing(&mut req);
        assert!(matches!(
            read_request(&mut req.as_slice()),
            Err(ChannelError::Protocol(_))
        ));

        let mut resp = Vec::new();
        write_response(
            &mut resp,
            &Response::File {
                path: "r".into(),
                data: b"y".to_vec(),
            },
        )
        .unwrap();
        append_trailing(&mut resp);
        assert!(matches!(
            read_response(&mut resp.as_slice()),
            Err(ChannelError::Protocol(_))
        ));
    }

    #[test]
    fn unknown_request_tag_is_graceful_not_fatal() {
        let mut framed = vec![99u8];
        framed.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            read_request(&mut framed.as_slice()).unwrap(),
            Request::Unknown { tag: 99 }
        );
        let mut buf = Vec::new();
        assert!(matches!(
            write_request(&mut buf, &Request::Unknown { tag: 99 }),
            Err(ChannelError::Protocol(_))
        ));
    }

    #[test]
    fn responses_round_trip() {
        for resp in [
            Response::Stdout(b"out".to_vec()),
            Response::Stderr(vec![0, 1, 2, 255]),
            Response::File {
                path: "result.json".into(),
                data: b"{}".to_vec(),
            },
            Response::Exit { code: -1 },
            Response::Exit { code: 3 },
            Response::TimedOut { elapsed_ms: 30_000 },
            Response::Error("could not spawn".to_string()),
        ] {
            let mut buf = Vec::new();
            write_response(&mut buf, &resp).unwrap();
            assert_eq!(read_response(&mut buf.as_slice()).unwrap(), resp);
        }
    }

    #[test]
    fn guest_error_control_chars_are_escaped_and_length_capped() {
        let sanitized = sanitize_error_msg("boom\x1b[2J\nsplit");
        assert!(!sanitized.contains('\x1b'), "ESC escaped: {sanitized:?}");
        assert!(!sanitized.contains('\n'), "newline escaped: {sanitized:?}");
        assert!(
            sanitized.contains("boom") && sanitized.contains("split"),
            "text kept: {sanitized:?}"
        );
        // A bidi override is escaped too, and it is what sets the overshoot bound below: the loop
        // tests the cap *before* each push, so the worst case is a full buffer one byte under the cap
        // plus one escape plus the ellipsis. `\u{202e}` is 8 bytes where a C0 escape is 6.
        let bidi = sanitize_error_msg("safe\u{202E}txet_desrever");
        assert!(
            !bidi.contains('\u{202E}') && bidi.contains("\\u{202e}"),
            "the RTL override is escaped, not passed through: {bidi:?}"
        );

        for filler in ["x", "\u{202E}"] {
            let capped = sanitize_error_msg(&filler.repeat(MAX_PAYLOAD / 4));
            assert!(
                capped.len() <= ERROR_MSG_CAP + 10,
                "capped near {ERROR_MSG_CAP} for {filler:?}, got {}",
                capped.len()
            );
        }
    }

    #[test]
    fn decoded_guest_error_is_sanitized() {
        let evil = "x\x1by";
        let mut framed = vec![Tag::Error.as_u8()];
        framed.extend_from_slice(&(evil.len() as u32).to_le_bytes());
        framed.extend_from_slice(evil.as_bytes());
        assert_eq!(
            read_response(&mut framed.as_slice()).unwrap(),
            Response::Error(sanitize_error_msg(evil))
        );
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let mut framed = vec![Tag::Stdout.as_u8()];
        framed.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            read_response(&mut framed.as_slice()),
            Err(ChannelError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn truncated_frame_is_typed_error() {
        let mut framed = vec![Tag::Stdout.as_u8()];
        framed.extend_from_slice(&10u32.to_le_bytes());
        framed.extend_from_slice(b"abc");
        assert!(matches!(
            read_response(&mut framed.as_slice()),
            Err(ChannelError::Io(_))
        ));
    }

    #[test]
    fn malformed_argv_body_does_not_panic() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&99u32.to_le_bytes());
        let mut framed = vec![Tag::Exec.as_u8()];
        framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        framed.extend_from_slice(&body);
        assert!(matches!(
            read_request(&mut framed.as_slice()),
            Err(ChannelError::Protocol(_))
        ));
    }

    #[test]
    fn connection_pair_handshakes_and_exchanges() {
        use std::os::unix::net::UnixStream;
        let (host, guest) = UnixStream::pair().unwrap();
        let req = Request::Exec {
            argv: vec!["true".into()],
            stdin: vec![],
            env: vec![("HOME".into(), "/tmp".into())],
            artifacts: vec![],
            timeout_ms: NonZeroU32::new(30_000),
        };
        let expected = req.clone();
        let server = std::thread::spawn(move || {
            let mut conn = ServerConnection::accept(guest).unwrap();
            assert_eq!(conn.recv_request().unwrap(), expected);
            conn.send_response(&Response::Exit { code: 0 }).unwrap();
        });
        let mut client = ClientConnection::connect(host).unwrap();
        client.send_request(&req).unwrap();
        assert_eq!(client.recv_response().unwrap(), Response::Exit { code: 0 });
        server.join().unwrap();
    }

    #[test]
    fn borrowed_send_matches_owned_and_round_trips() {
        use std::os::unix::net::UnixStream;
        let cases = [
            Request::Exec {
                argv: vec!["sh".into(), "-c".into(), "echo hi".into()],
                stdin: b"input".to_vec(),
                env: vec![("SECRET".into(), "s3kr1t".into())],
                artifacts: vec!["out.txt".into()],
                timeout_ms: NonZeroU32::new(1234),
            },
            Request::PutFile {
                path: "in.txt".into(),
                data: b"file body".to_vec(),
            },
        ];
        for req in cases {
            let (host, guest) = UnixStream::pair().unwrap();
            let expected = req.clone();
            let server = std::thread::spawn(move || {
                let mut conn = ServerConnection::accept(guest).unwrap();
                conn.recv_request().unwrap()
            });
            let mut client = ClientConnection::connect(host).unwrap();
            match &req {
                Request::Exec {
                    argv,
                    stdin,
                    env,
                    artifacts,
                    timeout_ms,
                } => client
                    .send_exec(argv, stdin, env, artifacts, *timeout_ms)
                    .unwrap(),
                Request::PutFile { path, data } => client.send_put_file(path, data).unwrap(),
                _ => {}
            }
            drop(client);
            assert_eq!(server.join().unwrap(), expected);
        }
    }

    /// The `Zeroizing` buffer wipes only the allocation it drops, so a payload that outgrows its
    /// preallocation leaves the reallocated-away copy of a secret un-wiped. The property is
    /// therefore "the encoder writes exactly what it reserved", and it has to be read off the
    /// **encoder**: a test that reserves and writes with its own arithmetic proves that its own two
    /// copies agree, which stays true no matter what `write_exec` does.
    ///
    /// Frame layout is `tag(1) · len(4) · payload`, so the bytes the real encoder emitted, less the
    /// 5-byte header, are what it actually wrote.
    #[test]
    fn the_exec_buffer_is_sized_by_what_the_encoder_writes() {
        const HEADER: usize = 5;

        let argv = [String::from("cat")];
        let stdin = vec![0xCD; 8192];
        let env = [(String::from("K"), "v".repeat(1000))];
        let artifacts = [String::from("a"), String::from("b/c")];

        let mut framed = Vec::new();
        write_exec(
            &mut framed,
            &argv,
            &stdin,
            &env,
            &artifacts,
            NonZeroU32::new(30_000),
        )
        .expect("an in-cap exec encodes");
        assert_eq!(
            exec_payload_len(&argv, &stdin, &env, &artifacts),
            framed.len() - HEADER,
            "the reserved capacity must equal the bytes `write_exec` emitted, or the staged \
             secret is reallocated away from the buffer that wipes it"
        );

        // The empty shape too: the four length prefixes are the floor, and an off-by-one there
        // reallocates on the very first push.
        let none: [String; 0] = [];
        let no_env: [(String, String); 0] = [];
        let mut framed = Vec::new();
        write_exec(&mut framed, &none, b"", &no_env, &none, None).expect("an empty exec encodes");
        assert_eq!(
            exec_payload_len(&none, b"", &no_env, &none),
            framed.len() - HEADER
        );
    }

    /// The `PutFile` twin, whose size is already a named function: the same "reserved equals
    /// written" property, read off `write_put_file` rather than re-derived.
    #[test]
    fn the_put_file_buffer_is_sized_by_what_the_encoder_writes() {
        const HEADER: usize = 5;
        let path = "big.bin";
        let data = vec![0xAB; 4096];

        let mut framed = Vec::new();
        write_put_file(&mut framed, path, &data).expect("an in-cap put encodes");
        assert_eq!(
            path_blob_len(Tag::PutFile, path, &data).expect("in cap"),
            framed.len() - HEADER,
            "the reserved capacity must equal the bytes `write_put_file` emitted"
        );
    }

    /// A write that fails between a frame's header and its payload leaves the peer mid-frame, and
    /// the *next* send reports `Ok` while its bytes are read as the unfinished frame's payload.
    /// This is what the connection types' retire-on-send-error contract rests on: nothing in the
    /// type refuses the reuse, so the caller has to drop the connection.
    #[test]
    fn a_send_error_leaves_the_stream_mid_frame() {
        /// Accepts every write but the second, which is the one carrying a frame's payload.
        /// Failing by call index rather than by byte count keeps the tear on the payload write even
        /// if the header's own write is ever resized.
        struct TearOnce {
            sink: Vec<u8>,
            calls: usize,
        }

        impl Read for TearOnce {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(0)
            }
        }

        impl Write for TearOnce {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.calls += 1;
                if self.calls == 2 {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "tear"));
                }
                self.sink.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut conn = ClientConnection {
            stream: TearOnce {
                sink: Vec::new(),
                calls: 0,
            },
        };
        assert!(
            matches!(conn.send_put_file("a", b"SECRET"), Err(ChannelError::Io(_))),
            "the torn send must surface"
        );
        // The premise: the header did reach the peer. Without this the encode never tore and
        // everything below would pass against nothing.
        assert_eq!(
            conn.stream.sink.len(),
            5,
            "the header must be on the wire for the peer to be mid-frame"
        );

        conn.send_put_file("b", b"ok")
            .expect("the stream accepts the second frame, and the send reports success");

        // But the peer cannot read it: the first header's length claim runs across the second
        // frame's own header, so the tags and lengths after the tear are payload bytes.
        let sent = conn.stream.sink;
        assert!(
            read_request(&mut sent.as_slice()).is_err(),
            "a frame sent after a tear must not decode as itself: {sent:?}"
        );
    }

    #[test]
    fn an_over_cap_encode_refuses_before_any_byte_reaches_the_stream() {
        // The write-side cap is checked before a byte is written; the engine's send-recovery relies
        // on it (`send_was_disconnect` reads a `PayloadTooLarge` as "wrote nothing to the socket" and
        // skips the recovery `recv_response` that would otherwise park for the read timeout). Pin it
        // at every over-cap-capable site. Stdout/Stderr/Error carry no pre-build check, so
        // `write_frame`'s cap is their only one and a reordered check bites here; File/PutFile/Exec
        // are additionally pre-checked before their (secret-bearing) payload is even built.
        fn refuse_untouched(label: &str, sent: Result<(), ChannelError>, touched: bool) {
            assert!(
                matches!(sent, Err(ChannelError::PayloadTooLarge { .. })),
                "{label}: expected PayloadTooLarge, got {sent:?}"
            );
            assert!(
                !touched,
                "{label}: an over-cap encode wrote a byte before refusing"
            );
        }

        let over = MAX_PAYLOAD + 1;
        let big = "x".repeat(over);

        // Stdout/Stderr/Error: `write_frame`'s cap is the only one, so an over-cap payload alone
        // trips it.
        for (label, resp) in [
            ("Stdout", Response::Stdout(vec![0u8; over])),
            ("Stderr", Response::Stderr(vec![0u8; over])),
            ("Error", Response::Error(big.clone())),
        ] {
            let mut probe = ProbeWriter::default();
            let sent = write_response(&mut probe, &resp);
            refuse_untouched(label, sent, probe.touched);
        }

        // File/PutFile/Exec: pre-checked before the payload is built, so a payload at the cap plus
        // its blob framing is over it.
        let payload = vec![0u8; MAX_PAYLOAD];

        let mut probe = ProbeWriter::default();
        let sent = write_response(
            &mut probe,
            &Response::File {
                path: "a".into(),
                data: payload.clone(),
            },
        );
        refuse_untouched("File", sent, probe.touched);

        let mut probe = ProbeWriter::default();
        let sent = write_put_file(&mut probe, "a", &payload);
        refuse_untouched("PutFile", sent, probe.touched);

        let mut probe = ProbeWriter::default();
        let sent = write_exec(
            &mut probe,
            std::slice::from_ref(&big),
            b"",
            &[] as &[(String, String)],
            &[] as &[String],
            None,
        );
        refuse_untouched("Exec", sent, probe.touched);
    }
}
