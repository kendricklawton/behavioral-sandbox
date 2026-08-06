//! `ekvm-channel`, the host↔guest wire protocol for the exec channel.
//!
//! One command in, its `stdout`/`stderr`/exit out, over a single bidirectional byte stream (vsock
//! in the guest, a unix socket in tests, the protocol doesn't care). This crate is only the framing, so it stays near dependency-free (one `no_std` crate,
//! `zeroize`, for an elision-proof secret wipe) and unit-testable without a VM.
//!
//! **Shape (why it's built this way).**
//! - A **handshake** first: a 4-byte magic + a `u16` version. Both peers *send then receive*, so a
//!   version skew between a separately-built host and guest agent fails fast and clearly instead of
//!   mis-parsing later. A new *request* tag is the one change an older peer absorbs on its own: it
//!   decodes as [`Request::Unknown`] and the agent answers "unsupported". Everything else, a new
//!   response tag or a new field on an existing message, is a [`PROTOCOL_VERSION`] bump, since the
//!   host deliberately refuses a response it cannot interpret (see [`Response`]).
//! - Every message is a **length-prefixed frame**, `tag(u8) · len(u32-le) · payload`, never a
//!   read-to-EOF or a delimiter scan. `len` is checked against [`MAX_PAYLOAD`] *before* allocating,
//!   so a hostile or buggy peer cannot drive an unbounded read (the same discipline as the HTTP
//!   client in `ekvm`). Every failure is a typed [`ChannelError`] carrying its `io::Error`
//!   source; nothing here panics.
//!
//! **The API is type-state, not free functions.** [`ClientConnection`] (host) and
//! [`ServerConnection`] (guest) each perform the handshake on construction and then expose only
//! their role's operations, a client sends a [`Request`] and reads [`Response`]s ending in
//! [`Response::Exit`]/[`Response::Error`]; a server does the mirror. You cannot send a message
//! before the handshake, and a client cannot `recv_request`; the raw codec is internal. **Liveness
//! is the transport's job**: set read/write deadlines on the stream before constructing, so a
//! stalled peer becomes a typed [`ChannelError::Io`] timeout rather than a hang.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::num::NonZeroU32;

use zeroize::Zeroize;

/// Frames the start of a connection so a mismatched peer is rejected before any message. "AGCH".
/// Internal: callers go through [`ClientConnection`]/[`ServerConnection`], which handle the magic.
pub(crate) const MAGIC: [u8; 4] = *b"AGCH";

/// The wire-protocol version. Bump on any breaking framing/message change; the handshake rejects a
/// peer that doesn't match. v2 added `env` to [`Request::Exec`], a mismatched peer would otherwise
/// silently run the command *without* its environment (an old agent's parser ignores trailing
/// bytes), which for injected secrets/config is a correctness failure, so the skew must fail the
/// handshake, not degrade.
pub const PROTOCOL_VERSION: u16 = 2;

/// Upper bound on a single frame's payload. Output is streamed in chunks well under this; the cap
/// exists so a broken `len` header is a typed error, not a huge allocation.
pub const MAX_PAYLOAD: usize = 1 << 20; // 1 MiB

/// Cap on a decoded guest error message ([`Response::Error`]). The message is *guest-chosen* and
/// reaches the operator's terminal and audit log unquoted (via the host's error `Display`), so it is
/// truncated here so a 1 MiB blob can't flood those surfaces. Well under the frame cap; a real error
/// is a short line.
const ERROR_MSG_CAP: usize = 4 << 10; // 4 KiB

/// Sanitize a guest-sent error message before it becomes a [`Response::Error`]: escape control
/// characters and truncate to [`ERROR_MSG_CAP`]. The guest is untrusted and this string is the one
/// host surface guest-chosen bytes hit unquoted, so raw ANSI escapes / control codes (terminal
/// injection, log-line splitting) must never pass through.
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

/// The boot-readiness sentinel: the in-guest agent prints this to its stdout (the serial console)
/// **after** it has bound its vsock listener, and the host scans the console for it to know the
/// agent is accepting connections. It's the pre-connection half of the host↔guest contract,
/// emitting it post-`bind` (not from init before the agent starts) is what removes the
/// connect-before-listen race. Both the guest agent (which prints it) and the driver (which waits
/// for it) reference this one constant.
pub const GUEST_READY_MARKER: &str = "GUEST-READY";

/// The vsock port the guest agent listens on and the host dials. Like [`GUEST_READY_MARKER`],
/// it's a pre-connection half of the host↔guest contract, so it lives here where **both** sides
/// (the driver that connects, and the rootfs build that writes the guest's init line) consume the
/// one definition, a drifted copy would strand the host dialing a port nobody binds.
pub const VSOCK_PORT: u32 = 1024;

/// The scheme half of the agent's listen spec, so the init line the rootfs build writes
/// (`vsock:<port>`) and the spec the agent parses are one definition rather than two spellings.
/// [`VSOCK_PORT`] alone was not enough: the port was shared while the word in front of it was a
/// literal on the build side and a private const in the agent, so a rename on either side left the
/// guest booting into an agent that refuses its own command line, and the first thing to notice
/// would have been a boot timeout under the privileged gate.
pub const VSOCK_SCHEME: &str = "vsock";

/// Filesystem labels the driver stamps on the data block devices it attaches, and the guest mounts
/// by. A boot may attach a bulk-input device, a bulk-output device, both, or neither, which shifts
/// the `/dev/vdX` letters, so the guest resolves each device by **label** (`findfs LABEL=…`) rather
/// than by enumeration order. Like the vsock port above, these are a host↔guest contract: the driver
/// (which builds the images) and the rootfs build (whose `mount-drives` mounts them) share the one
/// definition, so a drifted copy can't leave the guest silently skipping a mount.
///
/// **Both labels must fit ext4's 16-byte volume-label field.** `mke2fs -L` silently *truncates* a
/// longer one (exit 0, a warning on stderr nobody reads), so the on-disk label stops matching this
/// constant and the guest's `findfs` finds nothing: every bulk mount silently vanishes. A test below
/// pins the limit, and that the two stay distinct even so.
pub const INPUT_LABEL: &str = "ekvm-input";
/// See [`INPUT_LABEL`]. The output device is writable; the guest mounts it read-write at `/output`.
pub const OUTPUT_LABEL: &str = "ekvm-output";

/// The guest path of the **overlay init**, the PID 1 a read-only-root boot hands off to (it stacks
/// a per-run tmpfs over the shared read-only base, then execs the real init). Like the vsock port
/// above, this is a pre-connection host↔guest contract with two writers: the driver appends
/// `init=<this>` to the kernel command line (`crates/engine/src/spawn.rs`), and the rootfs build writes
/// the script there (`xtask/src/rootfs.rs`). A drifted copy is worse than a mismatched port, since
/// the kernel would boot into a path nothing occupies and the failure arrives as a boot timeout
/// rather than as a build error.
pub const GUEST_OVERLAY_INIT: &str = "/sbin/overlay-init";

/// The kernel-cmdline token key the driver uses to hand the guest its static IPv6 address, as
/// `guest_ip6=<addr>/<plen>`. The kernel `ip=`/`CONFIG_IP_PNP` param configures the guest's v4
/// `eth0` before userspace but has no IPv6 form, so v6 rides this token instead: the driver appends
/// it to the boot args and the guest's net-up script reads it back from `/proc/cmdline` and assigns
/// it. Like the labels and the vsock port above, this is a host↔guest contract single-sourced here so
/// the driver's writer and the guest's reader can't drift.
pub const GUEST_IP6_CMDLINE_KEY: &str = "guest_ip6";

/// The frame tags, in one enum so the wire numbers have a single home and the compiler owns their
/// uniqueness: two variants sharing a discriminant is `E0081`, where two `const`s sharing a value
/// was something only a round-trip test would notice, and only for the messages it covered. The
/// discriminants **are** the wire bytes, so reordering the variants is free and renumbering them
/// is a protocol change (`tag_discriminants_are_the_wire_numbers` pins each one).
///
/// Requests and responses share the one numbering space they already shared as constants. Each
/// direction still decodes only its own subset, so an unrecognized tag is handled per direction
/// (gracefully for requests, fatally for responses; see [`Response`]).
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
    /// The tag a frame header's byte names, or `None` if this build doesn't know it (a peer
    /// speaking a message type we don't implement, or a corrupt/hostile frame).
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

    /// The wire byte for this tag.
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A host→guest message. `#[non_exhaustive]`: new request types are added as new tags without
/// breaking an older guest agent, an unknown tag becomes [`Unknown`](Request::Unknown), which the
/// agent answers with a typed "unsupported" rather than a fatal protocol error.
///
/// `Debug` is **hand-written and redacting** (below), not derived: `Exec`'s `stdin`/`env` values and
/// `PutFile`'s `data` are secrets by presumption, so the doc rule "neither peer may log one" is
/// enforced by construction, a future `tracing::debug!(?req)` or `format!("{req:?}")` prints sizes
/// and key names, never the bytes. A test pins it.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// Write a file into the run's working directory *before* the command runs. Sent zero or more
    /// times ahead of [`Exec`](Request::Exec); each file is one `≤ MAX_PAYLOAD` frame. `path` is
    /// relative to the working dir; the agent rejects absolute or `..`-escaping paths.
    PutFile { path: String, data: Vec<u8> },
    /// Run `argv` in the guest (`argv[0]` is the program), feeding `stdin` to it, then return the
    /// files named in `artifacts` (paths relative to the working dir). `stdin` is a bounded up-front
    /// buffer, larger/streaming input goes via the block-device path. `env` is set on the **spawned
    /// command only**, never the agent's own process, and is bounded like `stdin` (the whole request
    /// is one `≤ MAX_PAYLOAD` frame); values are secrets by presumption, neither peer may log one
    /// or echo one into an error (an error may name a *key*). `timeout_ms` bounds the
    /// command's wall-clock runtime, the agent kills it and replies [`Response::TimedOut`] past
    /// the deadline; [`None`] asks for the agent's own ceiling instead of naming a limit. The
    /// wire spells that request as `0`, and [`NonZeroU32`] is what keeps the two apart: a caller
    /// cannot write a budget that means "no time" and have it arrive as "as long as you like".
    /// Empty argv is rejected.
    Exec {
        argv: Vec<String>,
        stdin: Vec<u8>,
        env: Vec<(String, String)>,
        artifacts: Vec<String>,
        timeout_ms: Option<NonZeroU32>,
    },
    /// A well-framed request whose tag this build doesn't know, a *newer* host speaking a request
    /// type we don't implement. Not a protocol error; the agent replies with a typed "unsupported".
    Unknown { tag: u8 },
}

impl std::fmt::Debug for Request {
    /// The redacting `Debug` (see the type doc): secret-bearing payloads (`PutFile::data`,
    /// `Exec::stdin`, `Exec::env` *values*) render as byte counts / key lists only, so no
    /// formatting path, log line, or panic message can leak them. Everything non-secret (paths,
    /// argv, artifact names, timeouts) renders normally, the variant stays legible for debugging.
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
                // Keys are loggable by contract (an error may name a key); values never are.
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

/// A guest→host message. The host reads these until a terminal [`Exit`](Response::Exit) or
/// [`Error`](Response::Error).
///
/// `#[non_exhaustive]` here buys **Rust** match-site compatibility, not the wire forward-compat
/// [`Request`]'s does: this decoder is deliberately the stricter of the two. An unknown *request*
/// tag becomes [`Request::Unknown`], because the agent can answer a host it doesn't understand
/// with a typed "unsupported"; an unknown *response* tag is a fatal [`ChannelError::Protocol`],
/// because responses arrive from an untrusted guest and continuing to read a stream the host
/// cannot interpret is worse than ending the run.
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
    /// The command finished. `code` is `128 + signal` on signal death today. Struct-form leaves
    /// room to *name* a second field later (a separate `signal`), but adding one would not be
    /// free: this frame's body decodes as exactly 4 bytes, so a new field is a wire change and a
    /// [`PROTOCOL_VERSION`] bump like any other, and the variant's readers destructure it by name.
    Exit { code: i32 },
    /// The command exceeded its `timeout_ms` deadline and was killed by the agent, terminal, no
    /// exit follows. Distinct from a channel timeout: the command ran, it just ran too long.
    /// Carries the actual runtime the agent measured. Struct-form on the same terms as
    /// [`Exit`](Response::Exit): room to name a field, not a free one.
    TimedOut { elapsed_ms: u32 },
    /// The agent could not run the command at all (e.g. spawn failed), terminal, no exit follows.
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
    /// A frame's declared length exceeds [`MAX_PAYLOAD`], rejected before allocating.
    PayloadTooLarge { tag: u8, len: usize },
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Io(e) => write!(f, "channel io: {e}"),
            ChannelError::Protocol(m) => write!(f, "channel protocol error: {m}"),
            ChannelError::PayloadTooLarge { tag, len } => {
                // Name the tag when this build knows it, so an operator reads "tag 6/PutFile"
                // rather than grepping the source for what 6 was. A hostile or newer peer's tag
                // may be none of ours, hence the bare number as the fallback.
                match Tag::from_u8(*tag) {
                    Some(known) => write!(
                        f,
                        "channel frame (tag {tag}/{known:?}) length {len} exceeds {MAX_PAYLOAD}"
                    ),
                    None => write!(
                        f,
                        "channel frame (tag {tag}) length {len} exceeds {MAX_PAYLOAD}"
                    ),
                }
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
    /// Whether this is the peer going away (EOF) rather than a live protocol/IO fault, so a caller
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

/// Append a little-endian `u32` to `payload`, the write-side counterpart of [`Body::u32`], so both
/// halves of the framing keep their integer encoding in one place.
fn put_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

/// Append a `u32`-length-prefixed blob to `payload`. The `as u32` cannot truncate: every caller
/// pre-checks its whole encoded payload against [`MAX_PAYLOAD`] (1 MiB) before building, so no
/// single blob can approach `u32::MAX`.
fn put_blob(payload: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(payload, bytes.len() as u32);
    payload.extend_from_slice(bytes);
}

/// The encoded size of one [`put_blob`] (its 4-byte length prefix + the bytes). Used to size the
/// payload buffer *exactly* up front (see [`write_exec`]/[`write_put_file`]): a secret-bearing
/// payload must live in **one** buffer so the post-send `zeroize` wipes every copy, a `Vec` that
/// grew would strand unwiped plaintext prefixes in the reallocations it freed.
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

/// Serialize and send a `PutFile` from **borrowed** parts, no owned [`Request`] to clone the
/// secret bytes into first. The payload is sized exactly (one buffer, no growth) so the post-send
/// `zeroize` wipes the engine's only copy of the injected bytes before it returns to the allocator
/// (a volatile store the optimizer cannot elide, unlike a plain `fill(0)`. The kernel
/// socket buffer is out of reach, best-effort by design).
pub(crate) fn write_put_file(
    w: &mut impl Write,
    path: &str,
    data: &[u8],
) -> Result<(), ChannelError> {
    // Rejected on the computed size, *before* allocating: `write_frame` would refuse the built
    // payload anyway, but only after a multi-GiB `data` had been copied (and then zeroized) in
    // full. The early check also makes `put_blob`'s `as u32` provably lossless here.
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

/// Serialize and send an `Exec` from **borrowed** parts. Like [`write_put_file`], the payload is
/// preallocated to its exact encoded size so the serialized stdin + env values live in one buffer
/// the post-send `zeroize` fully wipes.
pub(crate) fn write_exec<A: AsRef<str>, K: AsRef<str>, V: AsRef<str>, R: AsRef<str>>(
    w: &mut impl Write,
    argv: &[A],
    stdin: &[u8],
    env: &[(K, V)],
    artifacts: &[R],
    timeout_ms: Option<NonZeroU32>,
) -> Result<(), ChannelError> {
    let cap = 4 // argv count
        + argv.iter().map(|a| blob_len(a.as_ref().as_bytes())).sum::<usize>()
        + blob_len(stdin)
        + 4 // artifacts count
        + artifacts.iter().map(|p| blob_len(p.as_ref().as_bytes())).sum::<usize>()
        + 4 // timeout_ms
        + 4 // env count
        + env
            .iter()
            .map(|(k, v)| blob_len(k.as_ref().as_bytes()) + blob_len(v.as_ref().as_bytes()))
            .sum::<usize>();
    // Same early rejection as `write_put_file`: refuse on the computed size before staging a
    // copy of stdin + every env value that would only be built to be thrown away.
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
    // `None` (use the agent's ceiling) is the wire's `0`; `NonZeroU32` is why no real budget can
    // land on that value. `budget_from` in the guest agent reads the other end of this.
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

/// Read a [`Request`]. An unknown-but-well-framed tag becomes [`Request::Unknown`] (not an error),
/// so a newer host's request type degrades to a graceful "unsupported" rather than a dropped
/// connection.
///
/// # Errors
/// [`ChannelError::Protocol`] on a malformed/non-UTF-8 body; otherwise the framing errors.
pub(crate) fn read_request(r: &mut impl Read) -> Result<Request, ChannelError> {
    let (tag, payload) = read_frame(r)?;
    let mut body = Body::new(&payload);
    match Tag::from_u8(tag) {
        Some(Tag::Exec) => {
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
            // The wire's `0` decodes to `None` (the agent's ceiling), so the sentinel never
            // reaches a caller as a number it could mistake for a budget.
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
        // Unknown to this build, or a tag that only travels the other way: not a protocol error,
        // the agent answers it with a typed "unsupported" (see [`Request::Unknown`]).
        _ => Ok(Request::Unknown { tag }),
    }
}

/// Send a [`Response`].
///
/// # Errors
/// [`ChannelError::PayloadTooLarge`] if the payload exceeds [`MAX_PAYLOAD`]; [`ChannelError::Io`]
/// on a write failure.
pub(crate) fn write_response(w: &mut impl Write, resp: &Response) -> Result<(), ChannelError> {
    match resp {
        Response::Stdout(b) => write_frame(w, Tag::Stdout.as_u8(), b),
        Response::Stderr(b) => write_frame(w, Tag::Stderr.as_u8(), b),
        Response::File { path, data } => {
            // Sized and size-checked before building, like the request writers: an oversize
            // artifact is refused without first copying it into a growing buffer.
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

/// Read a [`Response`].
///
/// # Errors
/// [`ChannelError::Protocol`] on an unknown tag or a malformed body; otherwise the framing errors
/// from reading the frame.
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
        // Unknown to this build, or a tag that only travels the other way. Fatal on purpose: see
        // the asymmetry note on [`Response`].
        _ => Err(ChannelError::Protocol(format!(
            "unknown response tag {tag}"
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
/// `recv_request`. Set any read/write deadlines on the stream **before** constructing, liveness is
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
    /// [`send_exec`](Self::send_exec), which serialize from borrowed slices, no extra owned copy of
    /// the secret to wipe.
    ///
    /// # Errors
    /// [`ChannelError`] on a framing or write failure.
    pub fn send_request(&mut self, req: &Request) -> Result<(), ChannelError> {
        write_request(&mut self.stream, req)
    }

    /// Send a `PutFile` from borrowed parts, the injected bytes are serialized (and the wire buffer
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

/// A bounds-checked cursor over a frame payload, every read is guarded, so a truncated or lying
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
        // Validate the borrowed slice before allocating: a hostile peer sending an oversize
        // invalid-UTF-8 field is rejected without a throwaway heap copy first.
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

    /// Assert the body is fully consumed after the last parsed field. Trailing bytes mean the peer
    /// encoded a field this version doesn't parse, an additive change whose `PROTOCOL_VERSION` bump
    /// was forgotten (the handshake should have rejected the skew, this is the loud backstop for when
    /// it wasn't). Failing here beats silently dropping the field, the exact degradation the v1→v2
    /// `env` addition would have been (see `PROTOCOL_VERSION`).
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

/// Fuzzing entry points behind the off-by-default `fuzzing` feature: they hand attacker-controlled
/// bytes straight to the internal wire decoders so a `cargo fuzz` (libFuzzer) target can explore
/// them. A panic, hang, or unbounded allocation on any input is the bug being hunted.
/// Not built by default and not part of the wire contract, the harness lives in `fuzz/` (excluded
/// from the workspace). The in-gate, dependency-free counterpart
/// is [`fuzz_tests`].
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    use super::{MAGIC, read_frame, read_handshake, read_request, read_response};

    /// Decode one host→guest [`Request`](crate::Request) from `data` (the *guest agent's* view of
    /// host bytes).
    pub fn decode_request(mut data: &[u8]) {
        let _ = read_request(&mut data);
    }

    /// Decode one guest→host [`Response`](crate::Response) from `data`, the highest-value target,
    /// since a hostile guest chooses these bytes and the host parses them.
    pub fn decode_response(mut data: &[u8]) {
        let _ = read_response(&mut data);
    }

    /// Decode one raw frame header + payload from `data` (the framing both directions share).
    pub fn decode_frame(mut data: &[u8]) {
        let _ = read_frame(&mut data);
    }

    /// Validate a peer handshake from `data`.
    pub fn decode_handshake(mut data: &[u8]) {
        let _ = read_handshake(&mut data);
    }

    /// [`decode_request`] on a self-consistent frame built from `data` (first byte the tag, the
    /// rest the payload, `len` computed), so mutation explores the per-tag `Body` parsing, the
    /// nested counts, strings, and blobs, instead of only length-preserving flips of seeded
    /// frames: any insertion or deletion in a raw frame falsifies its `len` header and dies at
    /// the gate.
    pub fn decode_request_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_request(&mut framed);
        });
    }

    /// [`decode_response`]'s twin of [`decode_request_wellformed`], for the host-side parser (the
    /// highest-value surface: a hostile guest chooses these bytes).
    pub fn decode_response_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_response(&mut framed);
        });
    }

    /// Build the self-consistent frame the `*_wellformed` entry points share and hand it to `f`.
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

    /// Decode a **self-consistent** frame built from `data`: first byte the tag, the rest the
    /// payload, with the `len` header set to match.
    ///
    /// [`decode_frame`] alone cannot reach past the bounds check. Its `len` is a `u32` read
    /// straight from fuzz bytes, so it exceeds [`MAX_PAYLOAD`] for all but ~0.02% of inputs and
    /// exceeds the input's own remaining length for all but ~0.0001%. Mutation therefore explores
    /// two reject branches and never the payload read, which is what left this target's coverage
    /// flat across 19.7M executions.
    pub fn decode_frame_wellformed(data: &[u8]) {
        frame_and(data, |mut framed| {
            let _ = read_frame(&mut framed);
        });
    }

    /// Validate a handshake whose 4-byte magic is already correct, so the version check and the
    /// accept path are reachable at all: random bytes match the magic with probability 2^-32, so
    /// [`decode_handshake`] alone only ever exercises the reject branches.
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
        // ext4's volume label is 16 bytes; `mke2fs -L` silently truncates past it (exit 0), so a
        // longer constant here means the on-disk label never matches and the guest's mount-by-label
        // silently skips every bulk device. Regression guard: the de-brand once grew both labels
        // past the limit, and their truncations *collided* into one identical 16-byte prefix.
        const EXT4_LABEL_MAX: usize = 16;
        assert!(INPUT_LABEL.len() <= EXT4_LABEL_MAX, "{INPUT_LABEL}");
        assert!(OUTPUT_LABEL.len() <= EXT4_LABEL_MAX, "{OUTPUT_LABEL}");
        assert_ne!(INPUT_LABEL, OUTPUT_LABEL);
    }

    #[test]
    fn request_debug_redacts_secrets_by_construction() {
        // The type-level guarantee behind "neither peer may log one": no `{:?}` of a `Request`
        // can print an env value, stdin bytes, or injected file bytes, however the format call
        // is reached (a debug log, an error interpolation, a panic message).
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
        // The non-secret shape stays legible: the key name (loggable by contract), argv, sizes.
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
        // The enum's discriminants are the bytes on the wire, and the peer on the other end of a
        // vsock may be a separately built binary, so renumbering one is a protocol change, not a
        // refactor. Pinned here rather than left to the round-trip tests, which would only catch
        // a collision among the messages they happen to cover.
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
        // Nothing outside the assigned range decodes; 0 and 255 are the fuzz corpus's probes.
        assert_eq!(Tag::from_u8(0), None);
        assert_eq!(Tag::from_u8(9), None);
        assert_eq!(Tag::from_u8(255), None);
    }

    #[test]
    fn the_ceiling_sentinel_is_none_on_both_sides() {
        // The wire asks for the agent's ceiling with a zero `timeout_ms`, which is the byte
        // `budget_from` reads in the guest agent. Pin both directions on the exact bytes so
        // neither half can start spelling the request as a budget the other would misread.
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // argc
        body.extend_from_slice(&0u32.to_le_bytes()); // stdin length
        body.extend_from_slice(&0u32.to_le_bytes()); // artifact count
        body.extend_from_slice(&0u32.to_le_bytes()); // timeout_ms: the ceiling sentinel
        body.extend_from_slice(&0u32.to_le_bytes()); // env count
        let mut framed = vec![Tag::Exec.as_u8()];
        framed.extend_from_slice(&(body.len() as u32).to_le_bytes());
        framed.extend_from_slice(&body);

        // Decoding: the zero arrives as `None`, never as a number a caller could read as a budget.
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

        // Encoding: `None` writes that same zero back, so what the host asked for is what the
        // agent's ceiling arm sees.
        let mut written = Vec::new();
        write_request(&mut written, &decoded).unwrap();
        assert_eq!(written, framed);
    }

    #[test]
    fn a_frame_body_with_trailing_bytes_is_rejected() {
        // Trailing bytes after the last parsed field mean an additive field a forgotten
        // `PROTOCOL_VERSION` bump would have introduced: it must fail loudly, not be silently
        // dropped (the v1→v2 `env` degradation). Encode a valid message, bump the frame length, and
        // append a stray byte.
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
    fn guest_error_control_chars_are_escaped_and_length_capped() {
        // A hostile guest's error with an ANSI escape + newline must never render raw (terminal
        // injection / log-line splitting); the sanitizer escapes both and keeps the surrounding text.
        let sanitized = sanitize_error_msg("boom\x1b[2J\nsplit");
        assert!(!sanitized.contains('\x1b'), "ESC escaped: {sanitized:?}");
        assert!(!sanitized.contains('\n'), "newline escaped: {sanitized:?}");
        assert!(
            sanitized.contains("boom") && sanitized.contains("split"),
            "text kept: {sanitized:?}"
        );
        // A blob far past the cap is truncated so it can't flood the terminal/log.
        let capped = sanitize_error_msg(&"x".repeat(MAX_PAYLOAD));
        assert!(
            capped.len() <= ERROR_MSG_CAP + 8,
            "capped near {ERROR_MSG_CAP}, got {}",
            capped.len()
        );
    }

    #[test]
    fn decoded_guest_error_is_sanitized() {
        // The decode path applies the sanitizer, so a control-char message never reaches a caller raw.
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
        // A frame header claiming ~4 GiB: must be a typed error, not a 4 GiB `vec![0; len]`.
        let mut framed = vec![Tag::Stdout.as_u8()];
        framed.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            read_response(&mut framed.as_slice()),
            Err(ChannelError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn truncated_frame_is_typed_error() {
        // Header promises 10 bytes; only 3 follow.
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
        // A valid exec frame whose body lies about its inner lengths → Protocol, not a panic.
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes()); // argc = 1
        body.extend_from_slice(&99u32.to_le_bytes()); // arg len = 99, but no bytes follow
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
        // The borrowed `send_exec`/`send_put_file` must serialize byte-identically to the owned
        // `send_request` path (same wire protocol), and decode back to the same `Request`.
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
                _ => {} // no other variants in `cases`
            }
            drop(client);
            assert_eq!(server.join().unwrap(), expected);
        }
    }

    #[test]
    fn secret_payload_is_exactly_sized_so_one_buffer_holds_it() {
        // Secret hygiene: the payload must be preallocated to its exact encoded size,
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
