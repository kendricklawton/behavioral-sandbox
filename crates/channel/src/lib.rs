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
//! - **Type-State API:** [`ClientConnection`] (host) and [`ServerConnection`] (guest) enforce strict
//!   role-based state transitions post-handshake.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::num::NonZeroU32;

use zeroize::Zeroize;

/// Connection framing magic header bytes ("AGCH").
pub(crate) const MAGIC: [u8; 4] = *b"AGCH";

/// Wire-protocol version. Must bump on breaking framing or schema changes.
pub const PROTOCOL_VERSION: u16 = 2;

/// Maximum payload size for a single frame (1 MiB) to prevent unbounded allocations.
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Maximum length of guest error messages to prevent terminal/log flooding (4 KiB).
const ERROR_MSG_CAP: usize = 4 << 10;

/// Escapes control characters and truncates guest error messages to prevent terminal injection.
fn sanitize_error_msg(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len().min(ERROR_MSG_CAP));
    for c in msg.chars() {
        if out.len() >= ERROR_MSG_CAP {
            out.push('…');
            break;
        }
        if c.is_control() {
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

/// Scheme prefix for the vsock listener spec (`vsock`).
pub const VSOCK_SCHEME: &str = "vsock";

/// Ext4 volume labels for bulk disk mounts. Must fit within ext4's 16-byte limit.
pub const INPUT_LABEL: &str = "bsx-input";
/// See [`INPUT_LABEL`]. Mounted read-write at `/output`.
pub const OUTPUT_LABEL: &str = "bsx-output";

/// Guest binary path for overlay init.
pub const GUEST_OVERLAY_INIT: &str = "/sbin/overlay-init";

/// Kernel command-line key for passing the guest IPv6 configuration.
pub const GUEST_IP6_CMDLINE_KEY: &str = "guest_ip6";

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
            Self::Unknown { tag } => f.debug_struct("Unknown").field("tag", tag).finish(),
        }
    }
}

/// Guest-to-host response message stream.
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
    /// Returns `true` if the failure was caused by clean EOF/disconnect.
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
        Request::Unknown { tag } => Err(ChannelError::Protocol(format!(
            "Request::Unknown (tag {tag}) is read-only and cannot be sent"
        ))),
    }
}

/// Serializes and sends a `PutFile` request, zeroizing buffers post-send.
pub(crate) fn write_put_file(
    w: &mut impl Write,
    path: &str,
    data: &[u8],
) -> Result<(), ChannelError> {
    let cap = blob_len(path.as_bytes()) + blob_len(data);
    if cap > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge {
            tag: Tag::PutFile.as_u8(),
            len: cap,
        });
    }
    let mut payload = Vec::with_capacity(cap);
    put_blob(&mut payload, path.as_bytes());
    put_blob(&mut payload, data);
    let sent = write_frame(w, Tag::PutFile.as_u8(), &payload);
    payload.zeroize();
    sent
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
    let cap = 4
        + argv
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
            .sum::<usize>();

    if cap > MAX_PAYLOAD {
        return Err(ChannelError::PayloadTooLarge {
            tag: Tag::Exec.as_u8(),
            len: cap,
        });
    }
    let mut payload = Vec::with_capacity(cap);
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
    let sent = write_frame(w, Tag::Exec.as_u8(), &payload);
    payload.zeroize();
    sent
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
            let path = body.string()?;
            let data = body.blob()?.to_vec();
            body.finish()?;
            Ok(Request::PutFile { path, data })
        }
        _ => Ok(Request::Unknown { tag }),
    }
}

pub(crate) fn write_response(w: &mut impl Write, resp: &Response) -> Result<(), ChannelError> {
    match resp {
        Response::Stdout(b) => write_frame(w, Tag::Stdout.as_u8(), b),
        Response::Stderr(b) => write_frame(w, Tag::Stderr.as_u8(), b),
        Response::File { path, data } => {
            let cap = blob_len(path.as_bytes()) + blob_len(data);
            if cap > MAX_PAYLOAD {
                return Err(ChannelError::PayloadTooLarge {
                    tag: Tag::File.as_u8(),
                    len: cap,
                });
            }
            let mut payload = Vec::with_capacity(cap);
            put_blob(&mut payload, path.as_bytes());
            put_blob(&mut payload, data);
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
            let mut body = Body::new(&payload);
            let path = body.string()?;
            let data = body.blob()?.to_vec();
            body.finish()?;
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
#[derive(Debug)]
pub struct ClientConnection<S> {
    stream: S,
}

impl<S: Read + Write> ClientConnection<S> {
    pub fn connect(mut stream: S) -> Result<Self, ChannelError> {
        handshake(&mut stream)?;
        Ok(Self { stream })
    }

    pub fn send_request(&mut self, req: &Request) -> Result<(), ChannelError> {
        write_request(&mut self.stream, req)
    }

    pub fn send_put_file(&mut self, path: &str, data: &[u8]) -> Result<(), ChannelError> {
        write_put_file(&mut self.stream, path, data)
    }

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

    pub fn recv_response(&mut self) -> Result<Response, ChannelError> {
        read_response(&mut self.stream)
    }
}

/// Guest-side connection handle for serving requests and emitting responses.
#[derive(Debug)]
pub struct ServerConnection<S> {
    stream: S,
}

impl<S: Read + Write> ServerConnection<S> {
    pub fn accept(mut stream: S) -> Result<Self, ChannelError> {
        handshake(&mut stream)?;
        Ok(Self { stream })
    }

    pub fn recv_request(&mut self) -> Result<Request, ChannelError> {
        read_request(&mut self.stream)
    }

    pub fn send_response(&mut self, resp: &Response) -> Result<(), ChannelError> {
        write_response(&mut self.stream, resp)
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

#[cfg(feature = "fuzzing")]
pub mod fuzz {
    use super::{MAGIC, read_frame, read_handshake, read_request, read_response};

    pub fn decode_request(mut data: &[u8]) {
        let _ = read_request(&mut data);
    }

    pub fn decode_response(mut data: &[u8]) {
        let _ = read_response(&mut data);
    }

    pub fn decode_frame(mut data: &[u8]) {
        let _ = read_frame(&mut data);
    }

    pub fn decode_handshake(mut data: &[u8]) {
        let _ = read_handshake(&mut data);
    }

    pub fn decode_request_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_request(&mut framed);
        });
    }

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

    pub fn decode_frame_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_frame(&mut framed);
        });
    }

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

    #[test]
    fn handshake_round_trips() {
        let mut buf = Vec::new();
        write_handshake(&mut buf).unwrap();
        read_handshake(&mut buf.as_slice()).unwrap();
    }

    #[test]
    fn bulk_device_labels_fit_ext4_and_stay_distinct() {
        const EXT4_LABEL_MAX: usize = 16;
        assert!(INPUT_LABEL.len() <= EXT4_LABEL_MAX, "{INPUT_LABEL}");
        assert!(OUTPUT_LABEL.len() <= EXT4_LABEL_MAX, "{OUTPUT_LABEL}");
        assert_ne!(INPUT_LABEL, OUTPUT_LABEL);
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
        ] {
            assert_eq!(tag.as_u8(), wire, "{tag:?} moved on the wire");
            assert_eq!(Tag::from_u8(wire), Some(tag), "{wire} no longer decodes");
        }
        assert_eq!(Tag::from_u8(0), None);
        assert_eq!(Tag::from_u8(9), None);
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
        let capped = sanitize_error_msg(&"x".repeat(MAX_PAYLOAD));
        assert!(
            capped.len() <= ERROR_MSG_CAP + 8,
            "capped near {ERROR_MSG_CAP}, got {}",
            capped.len()
        );
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

    #[test]
    fn secret_payload_is_exactly_sized_so_one_buffer_holds_it() {
        let path = "big.bin";
        let data = vec![0xAB; 4096];
        let mut payload = Vec::with_capacity(blob_len(path.as_bytes()) + blob_len(&data));
        put_blob(&mut payload, path.as_bytes());
        put_blob(&mut payload, &data);
        assert_eq!(payload.len(), payload.capacity(), "PutFile payload grew");

        let argv = [String::from("cat")];
        let stdin = vec![0xCD; 8192];
        let env = [(String::from("K"), "v".repeat(1000))];
        let artifacts = [String::from("a"), String::from("b/c")];
        let cap = 4
            + argv.iter().map(|a| blob_len(a.as_bytes())).sum::<usize>()
            + blob_len(&stdin)
            + 4
            + artifacts
                .iter()
                .map(|p| blob_len(p.as_bytes()))
                .sum::<usize>()
            + 4
            + 4
            + env
                .iter()
                .map(|(k, v)| blob_len(k.as_bytes()) + blob_len(v.as_bytes()))
                .sum::<usize>();
        let mut payload = Vec::with_capacity(cap);
        put_u32(&mut payload, argv.len() as u32);
        for a in &argv {
            put_blob(&mut payload, a.as_bytes());
        }
        put_blob(&mut payload, &stdin);
        put_u32(&mut payload, artifacts.len() as u32);
        for p in &artifacts {
            put_blob(&mut payload, p.as_bytes());
        }
        put_u32(&mut payload, 30_000);
        put_u32(&mut payload, env.len() as u32);
        for (k, v) in &env {
            put_blob(&mut payload, k.as_bytes());
            put_blob(&mut payload, v.as_bytes());
        }
        assert_eq!(payload.len(), payload.capacity(), "Exec payload grew");
    }

    #[test]
    fn is_disconnect_flags_eof_only() {
        let eof = ChannelError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        assert!(eof.is_disconnect());
        let other = ChannelError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert!(!other.is_disconnect());
        assert!(!ChannelError::Protocol("x".into()).is_disconnect());
    }
}
