//! `agent-channel` — the host↔guest wire protocol for the exec channel.
//!
//! One command in, its `stdout`/`stderr`/exit out, over a single bidirectional byte stream (vsock
//! in the guest, a unix socket in tests — the protocol doesn't care). The transport is chosen in
//! `docs/architecture.md` decision 002; this crate is only the framing, so it stays dependency-free
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
//! **The API is type-state, not free functions.** [`ClientConnection`] (host) and
//! [`ServerConnection`] (guest) each perform the handshake on construction and then expose only
//! their role's operations — a client sends a [`Request`] and reads [`Response`]s ending in
//! [`Response::Exit`]/[`Response::Error`]; a server does the mirror. You cannot send a message
//! before the handshake, and a client cannot `recv_request`; the raw codec is internal. **Liveness
//! is the transport's job**: set read/write deadlines on the stream before constructing, so a
//! stalled peer becomes a typed [`ChannelError::Io`] timeout rather than a hang.
#![forbid(unsafe_code)]

use std::io::{Read, Write};

/// Frames the start of a connection so a mismatched peer is rejected before any message. "AGCH".
/// Internal: callers go through [`ClientConnection`]/[`ServerConnection`], which handle the magic.
pub(crate) const MAGIC: [u8; 4] = *b"AGCH";

/// The wire-protocol version. Bump on any breaking framing/message change; the handshake rejects a
/// peer that doesn't match. v2 added `env` to [`Request::Exec`] — a mismatched peer would otherwise
/// silently run the command *without* its environment (an old agent's parser ignores trailing
/// bytes), which for injected secrets/config is a correctness failure, so the skew must fail the
/// handshake, not degrade.
pub const PROTOCOL_VERSION: u16 = 2;

/// Upper bound on a single frame's payload. Output is streamed in chunks well under this; the cap
/// exists so a broken `len` header is a typed error, not a huge allocation.
pub const MAX_PAYLOAD: usize = 1 << 20; // 1 MiB

/// The boot-readiness sentinel: the in-guest agent prints this to its stdout (the serial console)
/// **after** it has bound its vsock listener, and the host scans the console for it to know the
/// agent is accepting connections. It's the pre-connection half of the host↔guest contract —
/// emitting it post-`bind` (not from init before the agent starts) is what removes the
/// connect-before-listen race. Both the guest agent (which prints it) and the driver (which waits
/// for it) reference this one constant.
pub const GUEST_READY_MARKER: &str = "AGENT-GUEST-READY";

/// The vsock port the guest agent listens on and the host dials. Like [`GUEST_READY_MARKER`],
/// it's a pre-connection half of the host↔guest contract, so it lives here where **both** sides
/// (the driver that connects, and the rootfs build that writes the guest's init line) consume the
/// one definition — a drifted copy would strand the host dialing a port nobody binds.
pub const AGENT_VSOCK_PORT: u32 = 1024;

/// Filesystem labels the driver stamps on the data block devices it attaches, and the guest mounts
/// by. A boot may attach a bulk-input device, a bulk-output device, both, or neither, which shifts
/// the `/dev/vdX` letters — so the guest resolves each device by **label** (`findfs LABEL=…`) rather
/// than by enumeration order. Like the vsock port above, these are a host↔guest contract: the driver
/// (which builds the images) and the rootfs build (whose `mount-drives` mounts them) share the one
/// definition, so a drifted copy can't leave the guest silently skipping a mount.
pub const INPUT_LABEL: &str = "agent-input";
/// See [`INPUT_LABEL`]. The output device is writable; the guest mounts it read-write at `/output`.
pub const OUTPUT_LABEL: &str = "agent-output";

const TAG_EXEC: u8 = 1;
const TAG_STDOUT: u8 = 2;
const TAG_STDERR: u8 = 3;
const TAG_EXIT: u8 = 4;
const TAG_ERROR: u8 = 5;
const TAG_PUTFILE: u8 = 6;
const TAG_FILE: u8 = 7;
const TAG_TIMEDOUT: u8 = 8;

/// A host→guest message. `#[non_exhaustive]`: new request types are added as new tags without
/// breaking an older guest agent — an unknown tag becomes [`Unknown`](Request::Unknown), which the
/// agent answers with a typed "unsupported" rather than a fatal protocol error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// Write a file into the run's working directory *before* the command runs. Sent zero or more
    /// times ahead of [`Exec`](Request::Exec); each file is one `≤ MAX_PAYLOAD` frame. `path` is
    /// relative to the working dir; the agent rejects absolute or `..`-escaping paths.
    PutFile { path: String, data: Vec<u8> },
    /// Run `argv` in the guest (`argv[0]` is the program), feeding `stdin` to it, then return the
    /// files named in `artifacts` (paths relative to the working dir). `stdin` is a bounded up-front
    /// buffer — larger/streaming input goes via the block-device path. `env` is set on the **spawned
    /// command only**, never the agent's own process, and is bounded like `stdin` (the whole request
    /// is one `≤ MAX_PAYLOAD` frame); values are secrets by presumption — neither peer may log one
    /// or echo one into an error (an error may name a *key*). `timeout_ms` bounds the
    /// command's wall-clock runtime — the agent kills it and replies [`Response::TimedOut`] past
    /// the deadline; **`0` means "use the agent's ceiling"**, not "no time". Empty argv is rejected.
    Exec {
        argv: Vec<String>,
        stdin: Vec<u8>,
        env: Vec<(String, String)>,
        artifacts: Vec<String>,
        timeout_ms: u32,
    },
    /// A well-framed request whose tag this build doesn't know — a *newer* host speaking a request
    /// type we don't implement. Not a protocol error; the agent replies with a typed "unsupported".
    Unknown { tag: u8 },
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
    /// A requested artifact read back from the working dir (sent before [`Exit`](Response::Exit)).
    /// A missing artifact is simply omitted. Each file is one `≤ MAX_PAYLOAD` frame.
    File { path: String, data: Vec<u8> },
    /// The command finished. Struct-form so a later phase can add a field (e.g. a separate
    /// `signal`) without a breaking change; `code` is `128 + signal` on signal death today.
    Exit { code: i32 },
    /// The command exceeded its `timeout_ms` deadline and was killed by the agent — terminal, no
    /// exit follows. Distinct from a channel timeout: the command ran, it just ran too long.
    /// Struct-form (like [`Exit`](Response::Exit)) so fields can be added without a break; carries
    /// the actual runtime the agent measured.
    TimedOut { elapsed_ms: u32 },
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

impl ChannelError {
    /// Whether this is the peer going away (EOF) rather than a live protocol/IO fault — so a caller
    /// can treat a clean hang-up as normal shutdown. Note a mid-frame truncation also reports EOF,
    /// so this means "peer closed, possibly mid-message," not "closed exactly on a frame boundary."
    #[must_use]
    pub fn is_disconnect(&self) -> bool {
        matches!(self, ChannelError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    }
}

/// Send our magic + version. Both peers call this *before* [`read_handshake`], so the small fixed
/// header always fits the socket buffer and the exchange can't deadlock.
///
/// # Errors
/// [`ChannelError::Io`] if the stream write fails.
pub(crate) fn write_handshake(w: &mut impl Write) -> Result<(), ChannelError> {
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

/// Append a little-endian `u32` to `payload` — the write-side counterpart of [`Body::u32`], so both
/// halves of the framing keep their integer encoding in one place.
fn put_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

/// Append a `u32`-length-prefixed blob to `payload`.
fn put_blob(payload: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(payload, bytes.len() as u32);
    payload.extend_from_slice(bytes);
}

/// The encoded size of one [`put_blob`] (its 4-byte length prefix + the bytes). Used to size the
/// payload buffer *exactly* up front (see [`write_exec`]/[`write_put_file`]): a secret-bearing
/// payload must live in **one** buffer so the post-send `fill(0)` wipes every copy — a `Vec` that
/// grew would strand unwiped plaintext prefixes in the reallocations it freed (decision 018).
fn blob_len(bytes: &[u8]) -> usize {
    4 + bytes.len()
}

/// Send a [`Request`].
///
/// # Errors
/// [`ChannelError::PayloadTooLarge`] if the encoded request exceeds [`MAX_PAYLOAD`];
/// [`ChannelError::Protocol`] if asked to send a [`Request::Unknown`] (a read-only variant);
/// [`ChannelError::Io`] on a write failure.
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

/// Serialize and send a `PutFile` from **borrowed** parts — no owned [`Request`] to clone the
/// secret bytes into first. The payload is sized exactly (one buffer, no growth) so the post-send
/// `fill(0)` wipes the engine's only copy of the injected bytes before it returns to the allocator
/// (decision 018; the kernel socket buffer is out of reach, best-effort by design).
pub(crate) fn write_put_file(
    w: &mut impl Write,
    path: &str,
    data: &[u8],
) -> Result<(), ChannelError> {
    let mut payload = Vec::with_capacity(blob_len(path.as_bytes()) + blob_len(data));
    put_blob(&mut payload, path.as_bytes());
    put_blob(&mut payload, data);
    let sent = write_frame(w, TAG_PUTFILE, &payload);
    payload.fill(0);
    sent
}

/// Serialize and send an `Exec` from **borrowed** parts. Like [`write_put_file`], the payload is
/// preallocated to its exact encoded size so the serialized stdin + env values live in one buffer
/// the post-send `fill(0)` fully wipes.
pub(crate) fn write_exec(
    w: &mut impl Write,
    argv: &[String],
    stdin: &[u8],
    env: &[(String, String)],
    artifacts: &[String],
    timeout_ms: u32,
) -> Result<(), ChannelError> {
    let cap = 4 // argv count
        + argv.iter().map(|a| blob_len(a.as_bytes())).sum::<usize>()
        + blob_len(stdin)
        + 4 // artifacts count
        + artifacts.iter().map(|p| blob_len(p.as_bytes())).sum::<usize>()
        + 4 // timeout_ms
        + 4 // env count
        + env
            .iter()
            .map(|(k, v)| blob_len(k.as_bytes()) + blob_len(v.as_bytes()))
            .sum::<usize>();
    let mut payload = Vec::with_capacity(cap);
    put_u32(&mut payload, argv.len() as u32);
    for arg in argv {
        put_blob(&mut payload, arg.as_bytes());
    }
    put_blob(&mut payload, stdin);
    put_u32(&mut payload, artifacts.len() as u32);
    for path in artifacts {
        put_blob(&mut payload, path.as_bytes());
    }
    put_u32(&mut payload, timeout_ms);
    put_u32(&mut payload, env.len() as u32);
    for (key, value) in env {
        put_blob(&mut payload, key.as_bytes());
        put_blob(&mut payload, value.as_bytes());
    }
    let sent = write_frame(w, TAG_EXEC, &payload);
    payload.fill(0);
    sent
}

/// Read a [`Request`]. An unknown-but-well-framed tag becomes [`Request::Unknown`] (not an error),
/// so a newer host's request type degrades to a graceful "unsupported" rather than a dropped
/// connection.
///
/// # Errors
/// [`ChannelError::Protocol`] on a malformed/non-UTF-8 body; otherwise the framing errors.
pub(crate) fn read_request(r: &mut impl Read) -> Result<Request, ChannelError> {
    let (tag, payload) = read_frame(r)?;
    let mut body = Body::new(&payload);
    match tag {
        TAG_EXEC => {
            let argc = body.u32()? as usize;
            // Don't pre-size from the peer's count: each entry still costs real bytes to read, so a
            // lying count just runs the body dry and errors.
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
            let timeout_ms = body.u32()?;
            let envc = body.u32()? as usize;
            let mut env = Vec::new();
            for _ in 0..envc {
                env.push((body.string()?, body.string()?));
            }
            Ok(Request::Exec {
                argv,
                stdin,
                env,
                artifacts,
                timeout_ms,
            })
        }
        TAG_PUTFILE => {
            let path = body.string()?;
            let data = body.blob()?.to_vec();
            Ok(Request::PutFile { path, data })
        }
        other => Ok(Request::Unknown { tag: other }),
    }
}

/// Send a [`Response`].
///
/// # Errors
/// [`ChannelError::PayloadTooLarge`] if the payload exceeds [`MAX_PAYLOAD`]; [`ChannelError::Io`]
/// on a write failure.
pub(crate) fn write_response(w: &mut impl Write, resp: &Response) -> Result<(), ChannelError> {
    match resp {
        Response::Stdout(b) => write_frame(w, TAG_STDOUT, b),
        Response::Stderr(b) => write_frame(w, TAG_STDERR, b),
        Response::File { path, data } => {
            let mut payload = Vec::new();
            put_blob(&mut payload, path.as_bytes());
            put_blob(&mut payload, data);
            write_frame(w, TAG_FILE, &payload)
        }
        Response::Exit { code } => write_frame(w, TAG_EXIT, &code.to_le_bytes()),
        Response::TimedOut { elapsed_ms } => {
            write_frame(w, TAG_TIMEDOUT, &elapsed_ms.to_le_bytes())
        }
        Response::Error(msg) => write_frame(w, TAG_ERROR, msg.as_bytes()),
    }
}

/// Read a [`Response`].
///
/// # Errors
/// [`ChannelError::Protocol`] on an unknown tag or a malformed body; otherwise the framing errors
/// from reading the frame.
pub(crate) fn read_response(r: &mut impl Read) -> Result<Response, ChannelError> {
    let (tag, payload) = read_frame(r)?;
    match tag {
        TAG_STDOUT => Ok(Response::Stdout(payload)),
        TAG_STDERR => Ok(Response::Stderr(payload)),
        TAG_FILE => {
            let mut body = Body::new(&payload);
            let path = body.string()?;
            let data = body.blob()?.to_vec();
            Ok(Response::File { path, data })
        }
        TAG_EXIT => {
            let bytes: [u8; 4] = payload
                .as_slice()
                .try_into()
                .map_err(|_| ChannelError::Protocol("exit frame is not 4 bytes".into()))?;
            Ok(Response::Exit {
                code: i32::from_le_bytes(bytes),
            })
        }
        TAG_TIMEDOUT => {
            let bytes: [u8; 4] = payload
                .as_slice()
                .try_into()
                .map_err(|_| ChannelError::Protocol("timed-out frame is not 4 bytes".into()))?;
            Ok(Response::TimedOut {
                elapsed_ms: u32::from_le_bytes(bytes),
            })
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

/// Exchange the handshake on a fresh stream: send ours, then read the peer's. Both roles do this
/// identically, and both *send before receiving*, so the fixed 6-byte headers always fit the
/// socket buffer and the exchange can't deadlock.
fn handshake<S: Read + Write>(stream: &mut S) -> Result<(), ChannelError> {
    write_handshake(stream)?;
    read_handshake(stream)
}

/// The **host** side of a handshaken connection: send one [`Request`], then read [`Response`]s
/// until a terminal [`Response::Exit`]/[`Response::Error`].
///
/// Type-state, not convention: you can only reach these methods *after* [`connect`](Self::connect)
/// has completed the handshake, and the role split means a client can never accidentally
/// `recv_request`. Set any read/write deadlines on the stream **before** constructing — liveness is
/// the transport's responsibility (a stalled peer then surfaces as a [`ChannelError::Io`] timeout,
/// not a hang), and this wrapper can't set transport-specific socket timeouts itself.
#[derive(Debug)]
pub struct ClientConnection<S> {
    stream: S,
}

impl<S: Read + Write> ClientConnection<S> {
    /// Establish the connection by exchanging the handshake.
    ///
    /// # Errors
    /// [`ChannelError`] if the handshake write/read fails or the peer's magic/version is wrong.
    pub fn connect(mut stream: S) -> Result<Self, ChannelError> {
        handshake(&mut stream)?;
        Ok(Self { stream })
    }

    /// Send a request, cloning the caller's data into an owned [`Request`] first. For secret-bearing
    /// requests (`PutFile`/`Exec`) prefer [`send_put_file`](Self::send_put_file) /
    /// [`send_exec`](Self::send_exec), which serialize from borrowed slices — no extra owned copy of
    /// the secret to wipe.
    ///
    /// # Errors
    /// [`ChannelError`] on a framing or write failure.
    pub fn send_request(&mut self, req: &Request) -> Result<(), ChannelError> {
        write_request(&mut self.stream, req)
    }

    /// Send a `PutFile` from borrowed parts — the injected bytes are serialized (and the wire buffer
    /// wiped) without an intermediate owned copy the caller would have to wipe too.
    ///
    /// # Errors
    /// [`ChannelError`] on a framing or write failure.
    pub fn send_put_file(&mut self, path: &str, data: &[u8]) -> Result<(), ChannelError> {
        write_put_file(&mut self.stream, path, data)
    }

    /// Send an `Exec` from borrowed parts. Like [`send_put_file`](Self::send_put_file), the secret
    /// stdin/env live only in the single wire buffer, which is wiped after the send.
    ///
    /// # Errors
    /// [`ChannelError`] on a framing or write failure.
    pub fn send_exec(
        &mut self,
        argv: &[String],
        stdin: &[u8],
        env: &[(String, String)],
        artifacts: &[String],
        timeout_ms: u32,
    ) -> Result<(), ChannelError> {
        write_exec(&mut self.stream, argv, stdin, env, artifacts, timeout_ms)
    }

    /// Read the next response frame.
    ///
    /// # Errors
    /// [`ChannelError`] on a framing/protocol violation or an I/O failure; use
    /// [`ChannelError::is_disconnect`] to tell a clean peer hang-up from a fault.
    pub fn recv_response(&mut self) -> Result<Response, ChannelError> {
        read_response(&mut self.stream)
    }
}

/// The **guest** side of a handshaken connection: read the [`Request`], then send [`Response`]s.
/// The mirror of [`ClientConnection`]; the same type-state and deadline notes apply.
#[derive(Debug)]
pub struct ServerConnection<S> {
    stream: S,
}

impl<S: Read + Write> ServerConnection<S> {
    /// Accept a connection by exchanging the handshake.
    ///
    /// # Errors
    /// [`ChannelError`] if the handshake fails or the peer's magic/version is wrong.
    pub fn accept(mut stream: S) -> Result<Self, ChannelError> {
        handshake(&mut stream)?;
        Ok(Self { stream })
    }

    /// Read the request.
    ///
    /// # Errors
    /// [`ChannelError`] on a framing/protocol violation or an I/O failure.
    pub fn recv_request(&mut self) -> Result<Request, ChannelError> {
        read_request(&mut self.stream)
    }

    /// Send one response frame.
    ///
    /// # Errors
    /// [`ChannelError`] on a framing or write failure (a write timeout, if the stream has one set,
    /// surfaces here as [`ChannelError::Io`]).
    pub fn send_response(&mut self, resp: &Response) -> Result<(), ChannelError> {
        write_response(&mut self.stream, resp)
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

    /// A `u32`-length-prefixed byte blob.
    fn blob(&mut self) -> Result<&'a [u8], ChannelError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A `u32`-length-prefixed UTF-8 string.
    fn string(&mut self) -> Result<String, ChannelError> {
        let bytes = self.blob()?;
        String::from_utf8(bytes.to_vec())
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
        for req in [
            Request::Exec {
                argv: vec!["echo".into(), "hi".into()],
                stdin: vec![],
                env: vec![],
                artifacts: vec![],
                timeout_ms: 30_000,
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
                timeout_ms: 1,
            },
            Request::Exec {
                argv: vec![],
                stdin: vec![0u8, 1, 2, 255],
                env: vec![],
                artifacts: vec![],
                timeout_ms: 0,
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
    fn unknown_request_tag_is_graceful_not_fatal() {
        // A well-framed frame with an unknown tag → Request::Unknown, so the agent can reply
        // "unsupported" instead of the connection dying. (Forward-compat for newer request types.)
        let mut framed = vec![99u8]; // unknown tag
        framed.extend_from_slice(&0u32.to_le_bytes()); // empty body
        assert_eq!(
            read_request(&mut framed.as_slice()).unwrap(),
            Request::Unknown { tag: 99 }
        );
        // ...and it's read-only: you can't send one.
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
    fn connection_pair_handshakes_and_exchanges() {
        use std::os::unix::net::UnixStream;
        let (host, guest) = UnixStream::pair().unwrap();
        let req = Request::Exec {
            argv: vec!["true".into()],
            stdin: vec![],
            env: vec![("HOME".into(), "/tmp".into())],
            artifacts: vec![],
            timeout_ms: 30_000,
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
        // The borrowed `send_exec`/`send_put_file` must serialize byte-identically to the owned
        // `send_request` path (same wire protocol), and decode back to the same `Request`.
        use std::os::unix::net::UnixStream;
        let cases = [
            Request::Exec {
                argv: vec!["sh".into(), "-c".into(), "echo hi".into()],
                stdin: b"input".to_vec(),
                env: vec![("SECRET".into(), "s3kr1t".into())],
                artifacts: vec!["out.txt".into()],
                timeout_ms: 1234,
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
                _ => {} // no other variants in `cases`
            }
            drop(client);
            assert_eq!(server.join().unwrap(), expected);
        }
    }

    #[test]
    fn secret_payload_is_exactly_sized_so_one_buffer_holds_it() {
        // Secret hygiene (decision 018): the payload must be preallocated to its exact encoded size,
        // so it never reallocates and strands an unwiped plaintext prefix on the heap. Build the
        // payloads the same way the serializers do and assert `len == capacity` (no growth headroom).
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
