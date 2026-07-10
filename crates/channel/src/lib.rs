//! `agent-channel` — the host↔guest wire protocol for the exec channel.
//!
//! One command in, its `stdout`/`stderr`/exit out, over a single bidirectional byte stream (vsock
//! in the guest, a unix socket in tests — the protocol doesn't care). The transport is chosen in
//! [`ARCHITECTURE.md` decision 002]; this crate is only the framing, so it stays dependency-free
//! and unit-testable without a VM.
//!
//! **Shape (why it's built this way).**
//! - A **handshake** first: a 4-byte magic + a `u16` version. Both peers *send then receive*, so a
//!   version skew between a separately-built host and guest agent fails fast and clearly instead of
//!   mis-parsing later. New message types are added as new tags (the enums are `#[non_exhaustive]`),
//!   so the two halves can evolve without a lockstep release.
//! - Every message is a **length-prefixed frame** — `tag(u8) · len(u32-le) · payload` — never a
//!   read-to-EOF or a delimiter scan. `len` is checked against [`MAX_PAYLOAD`] *before* allocating,
//!   so a hostile or buggy peer cannot drive an unbounded read (the same discipline as the HTTP
//!   client in `agent-vmm`). Every failure is a typed [`ChannelError`] carrying its `io::Error`
//!   source; nothing here panics.
//!
//! The host is the **client** (sends [`Request`], reads a stream of [`Response`] ending in
//! [`Response::Exit`] or [`Response::Error`]); the guest agent is the **server** (the mirror).
#![forbid(unsafe_code)]

use std::io::{Read, Write};

/// Frames the start of a connection so a mismatched peer is rejected before any message. "AGCH".
pub const MAGIC: [u8; 4] = *b"AGCH";

/// The wire-protocol version. Bump on any breaking framing/message change; the handshake rejects a
/// peer that doesn't match.
pub const PROTOCOL_VERSION: u16 = 1;

/// Upper bound on a single frame's payload. Output is streamed in chunks well under this; the cap
/// exists so a broken `len` header is a typed error, not a huge allocation.
pub const MAX_PAYLOAD: usize = 1 << 20; // 1 MiB

const TAG_EXEC: u8 = 1;
const TAG_STDOUT: u8 = 2;
const TAG_STDERR: u8 = 3;
const TAG_EXIT: u8 = 4;
const TAG_ERROR: u8 = 5;

/// A host→guest message. `#[non_exhaustive]`: later phases add stdin/file frames (P2.5) without
/// breaking a guest agent built against an older version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// Run `argv` in the guest (`argv[0]` is the program). Empty argv is rejected by the agent.
    Exec { argv: Vec<String> },
}

/// A guest→host message. The host reads these until a terminal [`Exit`](Response::Exit) or
/// [`Error`](Response::Error). `#[non_exhaustive]` for the same forward-compat reason as [`Request`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response {
    /// A chunk of the command's stdout.
    Stdout(Vec<u8>),
    /// A chunk of the command's stderr.
    Stderr(Vec<u8>),
    /// The command finished with this exit code (signal death is reported as `128 + signal`).
    Exit(i32),
    /// The agent could not run the command at all (e.g. spawn failed) — terminal, no exit follows.
    Error(String),
}

/// Every way the channel can fail, as a typed value. The `io::Error` source is preserved (via
/// [`std::error::Error::source`]) rather than flattened to a string, so callers can inspect it.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChannelError {
    /// The underlying stream failed (includes a truncated frame: EOF mid-read).
    Io(std::io::Error),
    /// The peer violated the protocol: bad magic, an unsupported version, an unknown tag, a
    /// malformed body, or non-UTF-8 where text was required.
    Protocol(String),
    /// A frame's declared length exceeds [`MAX_PAYLOAD`] — rejected before allocating.
    PayloadTooLarge { tag: u8, len: usize },
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Io(e) => write!(f, "channel io: {e}"),
            ChannelError::Protocol(m) => write!(f, "channel protocol error: {m}"),
            ChannelError::PayloadTooLarge { tag, len } => {
                write!(
                    f,
                    "channel frame (tag {tag}) length {len} exceeds {MAX_PAYLOAD}"
                )
            }
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

/// Send our magic + version. Both peers call this *before* [`read_handshake`], so the small fixed
/// header always fits the socket buffer and the exchange can't deadlock.
///
/// # Errors
/// [`ChannelError::Io`] if the stream write fails.
pub fn write_handshake(w: &mut impl Write) -> Result<(), ChannelError> {
    let mut buf = [0u8; 6];
    buf[..4].copy_from_slice(&MAGIC);
    buf[4..].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Read and validate the peer's magic + version. Call *after* [`write_handshake`].
///
/// # Errors
/// [`ChannelError::Protocol`] on a bad magic or an unsupported version; [`ChannelError::Io`] on a
/// short read (including a peer that closed before sending a full handshake).
pub fn read_handshake(r: &mut impl Read) -> Result<(), ChannelError> {
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

/// Write one framed message.
///
/// # Errors
/// [`ChannelError::PayloadTooLarge`] if `payload` exceeds [`MAX_PAYLOAD`]; [`ChannelError::Io`] on
/// a write failure. The caller holds any shared-writer lock across this whole call, so a frame is
/// never interleaved with another.
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

/// Read one framed message as `(tag, payload)`, bounding the allocation by [`MAX_PAYLOAD`].
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

/// Send a [`Request`].
///
/// # Errors
/// [`ChannelError::PayloadTooLarge`] if the encoded argv exceeds [`MAX_PAYLOAD`]; [`ChannelError::Io`]
/// on a write failure.
pub fn write_request(w: &mut impl Write, req: &Request) -> Result<(), ChannelError> {
    match req {
        Request::Exec { argv } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(argv.len() as u32).to_le_bytes());
            for arg in argv {
                let bytes = arg.as_bytes();
                payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bytes);
                if payload.len() > MAX_PAYLOAD {
                    return Err(ChannelError::PayloadTooLarge {
                        tag: TAG_EXEC,
                        len: payload.len(),
                    });
                }
            }
            write_frame(w, TAG_EXEC, &payload)
        }
    }
}

/// Read a [`Request`].
///
/// # Errors
/// [`ChannelError::Protocol`] on an unexpected tag or a malformed/non-UTF-8 body; otherwise the
/// framing errors from reading the frame.
pub fn read_request(r: &mut impl Read) -> Result<Request, ChannelError> {
    let (tag, payload) = read_frame(r)?;
    if tag != TAG_EXEC {
        return Err(ChannelError::Protocol(format!(
            "expected an exec request, got tag {tag}"
        )));
    }
    let mut body = Body::new(&payload);
    let argc = body.u32()? as usize;
    // Don't pre-size from the peer's count: `argc` is attacker-controlled, but each arg still costs
    // real bytes we must read, so a lie just runs the loop dry and errors.
    let mut argv = Vec::new();
    for _ in 0..argc {
        let len = body.u32()? as usize;
        let bytes = body.take(len)?;
        let arg = String::from_utf8(bytes.to_vec())
            .map_err(|_| ChannelError::Protocol("argv entry is not valid UTF-8".into()))?;
        argv.push(arg);
    }
    Ok(Request::Exec { argv })
}

/// Send a [`Response`].
///
/// # Errors
/// [`ChannelError::PayloadTooLarge`] if the payload exceeds [`MAX_PAYLOAD`]; [`ChannelError::Io`]
/// on a write failure.
pub fn write_response(w: &mut impl Write, resp: &Response) -> Result<(), ChannelError> {
    match resp {
        Response::Stdout(b) => write_frame(w, TAG_STDOUT, b),
        Response::Stderr(b) => write_frame(w, TAG_STDERR, b),
        Response::Exit(code) => write_frame(w, TAG_EXIT, &code.to_le_bytes()),
        Response::Error(msg) => write_frame(w, TAG_ERROR, msg.as_bytes()),
    }
}

/// Read a [`Response`].
///
/// # Errors
/// [`ChannelError::Protocol`] on an unknown tag or a malformed body; otherwise the framing errors
/// from reading the frame.
pub fn read_response(r: &mut impl Read) -> Result<Response, ChannelError> {
    let (tag, payload) = read_frame(r)?;
    match tag {
        TAG_STDOUT => Ok(Response::Stdout(payload)),
        TAG_STDERR => Ok(Response::Stderr(payload)),
        TAG_EXIT => {
            let bytes: [u8; 4] = payload
                .as_slice()
                .try_into()
                .map_err(|_| ChannelError::Protocol("exit frame is not 4 bytes".into()))?;
            Ok(Response::Exit(i32::from_le_bytes(bytes)))
        }
        TAG_ERROR => {
            let msg = String::from_utf8(payload)
                .map_err(|_| ChannelError::Protocol("error frame is not valid UTF-8".into()))?;
            Ok(Response::Error(msg))
        }
        other => Err(ChannelError::Protocol(format!(
            "unknown response tag {other}"
        ))),
    }
}

/// A bounds-checked cursor over a frame payload — every read is guarded, so a truncated or lying
/// body is a typed `Protocol` error, never a panic.
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
}

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
        for argv in [
            vec!["echo".to_string(), "hi".to_string()],
            vec!["/bin/π".to_string(), "a b\tc".to_string(), String::new()],
            vec![],
        ] {
            let mut buf = Vec::new();
            write_request(&mut buf, &Request::Exec { argv: argv.clone() }).unwrap();
            let got = read_request(&mut buf.as_slice()).unwrap();
            assert_eq!(got, Request::Exec { argv });
        }
    }

    #[test]
    fn responses_round_trip() {
        for resp in [
            Response::Stdout(b"out".to_vec()),
            Response::Stderr(vec![0, 1, 2, 255]),
            Response::Exit(-1),
            Response::Exit(3),
            Response::Error("could not spawn".to_string()),
        ] {
            let mut buf = Vec::new();
            write_response(&mut buf, &resp).unwrap();
            assert_eq!(read_response(&mut buf.as_slice()).unwrap(), resp);
        }
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        // A frame header claiming ~4 GiB: must be a typed error, not a 4 GiB `vec![0; len]`.
        let mut framed = vec![TAG_STDOUT];
        framed.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            read_response(&mut framed.as_slice()),
            Err(ChannelError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn truncated_frame_is_typed_error() {
        // Header promises 10 bytes; only 3 follow.
        let mut framed = vec![TAG_STDOUT];
        framed.extend_from_slice(&10u32.to_le_bytes());
        framed.extend_from_slice(b"abc");
        assert!(matches!(
            read_response(&mut framed.as_slice()),
            Err(ChannelError::Io(_))
        ));
    }

    #[test]
    fn malformed_argv_body_does_not_panic() {
        // A valid exec frame whose body lies about its inner lengths → Protocol, not a panic.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes()); // argc = 1
        body.extend_from_slice(&99u32.to_le_bytes()); // arg len = 99, but no bytes follow
        let mut framed = vec![TAG_EXEC];
        framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        framed.extend_from_slice(&body);
        assert!(matches!(
            read_request(&mut framed.as_slice()),
            Err(ChannelError::Protocol(_))
        ));
    }

    #[test]
    fn wrong_tag_for_request_is_rejected() {
        let mut buf = Vec::new();
        write_response(&mut buf, &Response::Exit(0)).unwrap();
        assert!(matches!(
            read_request(&mut buf.as_slice()),
            Err(ChannelError::Protocol(_))
        ));
    }
}
