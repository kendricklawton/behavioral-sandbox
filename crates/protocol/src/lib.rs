//! The bsx wire protocol: a **versioned, newline-delimited JSON** contract.
//!
//! A client sends one [`Request`] line and the daemon answers with one or more [`Response`] lines,
//! each carrying a leading [`schema`](Envelope::schema) field, so the two sides agree on the shape
//! before either trusts the other's bytes. This is the one artifact the daemon, the reference client,
//! and any non-Rust client share, so it lives in its own **engine-free** crate.
//!
//! **Compatibility: fields grow, values grow, replies do not.** Stated here because each client
//! reimplements these shapes without serde (`docs/daemon-protocol.md` says the same for a non-Rust
//! reader):
//!
//! 1. **Unknown fields are ignored**, which is how the wire evolves without a version bump, and why no
//!    message type here sets `deny_unknown_fields`.
//! 2. **An unknown `reply` is a hard error**, deliberately the opposite of rule 1: the protocol is
//!    strict request/response, so a reply that cannot be interpreted means the client has lost track of
//!    what is being answered, and skipping it would desynchronize the session rather than lose one
//!    message.
//! 3. **An unknown enumerated *value* degrades.** A value carries no framing, so an unfamiliar one can
//!    map to a conservative default without losing sync. [`FaultKind`] is the case that exists.
//!
//! **JSON, not gRPC.** The daemon is synchronous and thread-per-connection with no async runtime on
//! the host path, which gRPC would drag `tonic`/`prost` and a `tokio` stack into. The peer is a local
//! client the hoster runs, so hand-debuggability (`socat`, `nc`) matters more than a compact wire. The
//! adversarial concern that remains is the decoder's contract: every line is bounded before it is
//! decoded and every failure is a typed [`ProtocolError`], never a panic.
//!
//! **The two directions carry different bounds**, [`MAX_REQUEST_BYTES`] and [`MAX_RESPONSE_BYTES`],
//! because a request is an untrusted peer's line while a response is the daemon's own output under an
//! `output_cap` an operator already controls. The read side is direction-typed, so a call site cannot
//! pick the wrong number.
//!
//! **Text, not binary.** `stdin`, `put`/`get` `content`, and the returned `stdout`/`stderr` are
//! **UTF-8 strings**, lossy on the way out exactly like `bsx run --json`. Bulk or binary IO is the
//! block-device path, an embedding-API concern, never this per-message line.
//!
//! **Non-goals: this is the *engine's* wire, not a *platform's*.** No tenant, credential, quota,
//! price, or host to schedule onto: no identity field, no auth handshake, no billing token, no request
//! routing. One connection drives one sandbox on the one host the daemon runs on, and the daemon
//! trusts whoever can reach its socket. Access control is the unix socket's directory permissions, and
//! a schema bump adds a verb rather than a tenancy field.
#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The wire-protocol version. Every message carries it (see [`Envelope`]); a peer that stamps a
/// different number is a [`ProtocolError::Schema`], reported before its body is trusted, so a client
/// built against a future revision fails loudly instead of being half-understood. Bumped whenever a
/// request/response shape changes in a non-additive way.
pub const WIRE_SCHEMA: u32 = 1;

/// Upper bound on one **request** line before decoding, so a client that never sends a newline is a
/// typed [`ProtocolError::TooLarge`] rather than an unbounded read. A DoS bound on untrusted input, not
/// the input-size contract: the exec channel still enforces `bsx_engine::MAX_PAYLOAD` on the bytes that
/// reach the guest.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Upper bound on one **response** line, larger than [`MAX_REQUEST_BYTES`] because bounding a reply by
/// the client-DoS number makes a legitimate `result` undeliverable.
///
/// Twice the engine's default `output_cap` so a cap's worth of quotes or newlines still fits at its 2x
/// escape, **plus a MiB** for the envelope, which is what puts a quote-dense reply over. It
/// deliberately does not cover the worst case: a C0 control byte escapes to six bytes and invalid UTF-8
/// renders as three, so output dense in either is *reported* as a flooded-output error rather than
/// designed around, since covering it would mean a bound six times the operator's cap.
/// `the_wire_can_carry_the_default_output_cap` holds this number against `Limits::default()`, since
/// this crate is engine-free and cannot read that default itself.
pub const MAX_RESPONSE_BYTES: usize = 33 * 1024 * 1024;

/// The ordering the two bounds exist for, checked at compile time: a reply the daemon produced under an
/// operator's `output_cap` must not be bounded by the cap on an untrusted client's line.
const _: () = assert!(MAX_RESPONSE_BYTES > MAX_REQUEST_BYTES);

/// A schema-stamped message: the leading `schema` field plus the flattened [`Request`]/[`Response`]
/// body, so a line reads `{"schema":1,"op":"exec",...}` and the version is legible before the body.
///
/// **The decode side never builds one.** The read side checks the stamp on the parsed value before the
/// body is trusted, so an `Envelope` that could carry a foreign stamp would be a second, ungated way in.
/// `Serialize` with no `Deserialize` is what keeps the type one-way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Envelope<T> {
    /// The [`WIRE_SCHEMA`] the sender speaks.
    pub schema: u32,
    /// The message body, flattened so its own tag (`op`/`reply`) sits beside `schema`.
    #[serde(flatten)]
    pub body: T,
}

impl<T> Envelope<T> {
    /// Stamps `body` with the one schema this crate speaks. No other number can be minted here, and a
    /// foreign stamp exists only on the decode side, where the read functions refuse it.
    #[must_use]
    pub fn new(body: T) -> Self {
        Self {
            schema: WIRE_SCHEMA,
            body,
        }
    }
}

/// A client → daemon message, internally tagged by an `op` field so a line reads
/// `{"schema":1,"op":"exec","argv":["echo","hi"]}`, self-describing and hand-writable. The verb set is
/// the lifecycle `open` → (`exec` | `put` | `get` | `snapshot` | `trace` | `trace_summary`)\* → `close`.
///
/// `#[non_exhaustive]` keeps a new verb from being a source break for a Rust peer. That says nothing
/// about the *wire*, where an unknown `op` is still a hard decode error.
///
/// Each payload-carrying verb holds a params struct whose fields inline on the wire beside `op`, so the
/// JSON is identical to inline fields (`the_wire_bytes_of_every_message_shape_are_pinned` holds that).
/// Those structs are `#[non_exhaustive]` and built from [`Default`]/`new` plus field assignment, so an
/// additive wire field is additive for a Rust caller too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Request {
    /// Open the connection's sandbox, the first message of a session (the VM *is* the session).
    /// Carries **resource** knobs and the session's network request ([`OpenParams`]). The confinement
    /// posture is the daemon's launch-time choice, never a client's, so a caller can't downgrade the
    /// jail or route itself out. Any omitted field keeps the conservative default.
    Open(OpenParams),
    /// Run one command in the open sandbox ([`ExecParams`]), feeding `stdin` (UTF-8 text) to it.
    /// Repeated `exec`s share the session's working directory.
    Exec(ExecParams),
    /// Write a UTF-8 file into the session's working directory ([`PutParams`]), so a later `exec` sees
    /// it. A relative path resolves against that directory, and the file persists for the session's
    /// life.
    Put(PutParams),
    /// Read a file back from the session's working directory ([`GetParams`]). A missing file is not an
    /// error; the [`Response::Got`] reports `present: false`.
    Get(GetParams),
    /// Snapshot the session's live VM into a daemon-side bundle, answered with the bundle's host path
    /// ([`Response::Snapshotted`]). Snapshotting a **jailed** session is a typed refusal, since its disk
    /// lives in the chroot.
    Snapshot,
    /// Ask for the session's **host-observed audit record** so far ([`Response::Trace`]): the same
    /// `RunRecord` shape `--record` writes, but sampled **live** and non-destructively, so it is
    /// repeatable mid-session.
    ///
    /// Its `coverage` reflects attach time, so an absent axis may be a *transient* read rather than a
    /// finalized gap, unlike `--record`, which finalizes at session end. Fail-open: a host that couldn't
    /// attach the probes answers a coverage-gapped record, never an error.
    Trace,
    /// Ask for the session's **model-legible summary** so far ([`Response::TraceSummary`]): the compact
    /// projection `--record-summary` writes, sampled live like [`Trace`](Self::Trace), so the wire
    /// exposes the projection and not just the full record. Fail-open, same as `trace`.
    TraceSummary,
    /// End the session: tear the sandbox down and close the connection. Dropping the connection does the
    /// same teardown; `close` makes it explicit and acknowledged.
    Close,
    /// Abandon an **in-flight** request and end the session now, answered with
    /// [`Response::Cancelled`].
    ///
    /// The one verb legal while another request is outstanding, since a client blocked on a long
    /// [`Exec`](Self::Exec) has no other way to reach the daemon.
    ///
    /// **This ends the session, it does not abort one command.** The engine cancels a running exec by
    /// killing the sandbox, so there is no "stop this command, keep my VM" to expose, and session state
    /// dies with it. Hanging up lands in the same place, since the daemon treats EOF like a `cancel`;
    /// what `cancel` adds is the acknowledgement.
    Cancel,
}

/// What a session asks for, carried by [`Request::Open`]: its resource envelope and its network request.
/// Every field is optional, and `None` keeps the daemon's conservative default.
///
/// Build it from [`default`](Default::default) and set the fields you want, so a new knob lands for a
/// Rust caller as additively as it lands on the wire. No field carries a secret, so `Debug` derives: an
/// operator reading a log needs to see which egress a session asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct OpenParams {
    /// Guest vCPUs (1..=32); omitted keeps the default 1.
    #[serde(default)]
    pub vcpus: Option<u8>,
    /// Guest memory in MiB (>= 1); omitted keeps the default 256.
    #[serde(default)]
    pub mem_mib: Option<u32>,
    /// Wall-clock budget in seconds (>= 1): the boot deadline and each exec's budget; omitted
    /// keeps the default 30.
    #[serde(default)]
    pub wall_secs: Option<u64>,
    /// Aggregate captured-output cap in bytes; omitted keeps the default 16 MiB. `u64` rather than
    /// `usize`, because a 32-bit client and a 64-bit daemon must agree on this width.
    #[serde(default)]
    pub output_cap: Option<u64>,
    /// Give the session's guest a NIC (a per-VM tap the host-side probes observe); omitted is the sealed
    /// default. A NIC alone reaches nothing beyond the host end of its /30: whether a route out exists is
    /// the daemon's launch-time choice, so a client can bound what crosses the tap but never conjure a
    /// path, and the daemon may refuse the NIC outright.
    #[serde(default)]
    pub net: Option<bool>,
    /// Egress allowances for the session, each `IP[/CIDR][:PORT][/PROTO]`, building a deny-by-default
    /// policy armed before the tap goes live; omitted is deny-all. Requires [`net`](Self::net).
    ///
    /// Strings rather than a structured type, so the wire spells a rule exactly as `bsx run --allow` does
    /// and one parser serves both. The daemon refuses the session if enforcement cannot be armed, since
    /// egress policy is a security control and does not fail open.
    #[serde(default)]
    pub allow: Option<Vec<String>>,
}

/// One command to run, carried by [`Request::Exec`]. Build with [`new`](Self::new) (the required
/// `argv`), then set the optional fields; they and any future knob stay additive
/// (`#[non_exhaustive]`, like [`OpenParams`]).
///
/// `Debug` is **hand-written and redacting**, not derived, for the same reason
/// `bsx_channel::Request`'s is: `stdin` and the `env` *values* are secret-bearing, and the daemon
/// does log a request on its unhandled-verb path. A derived `Debug` would put them in that log
/// line; this one renders sizes, env keys, and argv only, mirroring the engine's stated contract
/// (an error may name a file *path* or an env *key*, never a value).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecParams {
    /// The command and its arguments (`argv[0]` is the program). Empty is a guest fault.
    pub argv: Vec<String>,
    /// Text piped to the command's stdin; omitted is empty. Bulk/binary input is the
    /// block-device path, not this field.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Environment variables for the **spawned command only**, as `KEY=VALUE` pairs. The guest agent
    /// applies them via `Command::env` and never to its own process, so one exec's environment cannot
    /// bleed into the agent or into a later exec.
    ///
    /// **Values are secrets by contract**, absent from every log line, error, and this type's `Debug`. A
    /// caller can still leak them by having the command print them, which is the run's own output.
    #[serde(default)]
    pub env: Option<Vec<(String, String)>>,
}

impl ExecParams {
    /// The command to run; the optional fields start empty and are set on the value.
    #[must_use]
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            stdin: None,
            env: None,
        }
    }
}

impl std::fmt::Debug for ExecParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<&str> = self.env.iter().flatten().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("ExecParams")
            .field("argv", &self.argv)
            .field(
                "stdin",
                &format_args!(
                    "<redacted; {} byte(s)>",
                    self.stdin.as_deref().map_or(0, str::len)
                ),
            )
            .field(
                "env",
                &format_args!(
                    "<{} var(s), values redacted; keys: {keys:?}>",
                    self.env.as_ref().map_or(0, Vec::len)
                ),
            )
            .finish()
    }
}

/// One file to write, carried by [`Request::Put`]. `Debug` redacts `content` (file contents are
/// secrets under the engine's contract, exactly like [`ExecParams`]'s payloads); the path stays
/// legible, an error may name one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PutParams {
    /// Where in the working directory to write, relative (e.g. `input.txt`).
    pub path: String,
    /// The file's UTF-8 contents. Bulk/binary is the block-device path, not this verb.
    pub content: String,
}

impl PutParams {
    /// The path to write and the contents to put there.
    #[must_use]
    pub fn new(path: String, content: String) -> Self {
        Self { path, content }
    }
}

impl std::fmt::Debug for PutParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutParams")
            .field("path", &self.path)
            .field(
                "content",
                &format_args!("<redacted; {} byte(s)>", self.content.len()),
            )
            .finish()
    }
}

/// One file to read back, carried by [`Request::Get`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GetParams {
    /// Which file in the working directory to read back, relative.
    pub path: String,
}

impl GetParams {
    /// The path to read.
    #[must_use]
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

/// A daemon → client message, internally tagged by a `reply` field.
///
/// `#[non_exhaustive]` keeps a new reply from being a source break for a Rust client. The *wire* is
/// stricter: an unknown `reply` is a hard decode error, unlike [`FaultKind`], which degrades on purpose.
///
/// Every payload-carrying variant is itself `#[non_exhaustive]`, so a foreign match must carry `..` and
/// keeps compiling when a field lands. Construction goes through the constructor fns below, whose
/// signatures take only each variant's required fields, so an additive wire field never moves them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Response {
    /// The sandbox booted, carrying its boot-to-userspace latency and whether it came from the
    /// pre-warmed pool or a cold boot.
    #[non_exhaustive]
    Opened {
        /// Boot-to-userspace latency, milliseconds.
        boot_ms: u64,
        /// `true` if served from the daemon's pre-warmed pool, `false` for a cold boot (a custom resource
        /// profile, or a daemon launched without `--prewarm`).
        pooled: bool,
    },
    /// A command finished. `exit_code` is the guest command's own code, so non-zero is a *result* rather
    /// than an error.
    #[non_exhaustive]
    Result {
        /// The guest command's exit code (`128 + signal` on signal death).
        exit_code: i32,
        /// The command's stdout, lossy UTF-8.
        stdout: String,
        /// The command's stderr, lossy UTF-8.
        stderr: String,
        /// Host-observed wall-clock of the exec, milliseconds.
        exec_wall_ms: u64,
    },
    /// A [`Request::Put`] landed: the file was written to the working directory.
    #[non_exhaustive]
    Put {
        /// The path written, echoed back for correlation.
        path: String,
    },
    /// The result of a [`Request::Get`]. `present: false` (with an empty `content`) is a missing
    /// file, not an error.
    #[non_exhaustive]
    Got {
        /// The path read, echoed back.
        path: String,
        /// The file's contents, lossy UTF-8; empty when `present` is `false`.
        content: String,
        /// Whether the file existed.
        present: bool,
        /// Whether `content` is a **lossy** rendering, meaning the file's bytes were not valid UTF-8 and
        /// the originals are not recoverable from this reply. The flag is what keeps that substitution
        /// from being silent; absent reads as `false`.
        #[serde(default)]
        lossy: bool,
    },
    /// A [`Request::Snapshot`] wrote a bundle. `dir` is a **daemon-host** path: the bundle's device state
    /// and guest memory live on the daemon's filesystem, not on this line.
    #[non_exhaustive]
    Snapshotted {
        /// The host directory holding the snapshot bundle.
        dir: String,
    },
    /// The session's audit record (answering [`Request::Trace`]), as the **signed record envelope**,
    /// carried opaquely here so this crate stays free of the `bsx-probes-loader` types.
    #[non_exhaustive]
    Trace {
        /// The signed envelope as a JSON object: `{schema, key_id, signature, record}`, where `record` is
        /// the canonical `RunRecord` JSON carried as a string, so its signed bytes survive this
        /// re-serialization. Its `schema` is the delivery-surface version, distinct from
        /// [`WIRE_SCHEMA`].
        record: serde_json::Value,
    },
    /// The session's model-legible summary (answering [`Request::TraceSummary`]), as the projection's
    /// JSON object, carried opaquely, same as [`Trace`](Self::Trace).
    #[non_exhaustive]
    TraceSummary {
        /// The record summary as a JSON object (its own leading `schema` is the *summary* schema,
        /// distinct from the record schema and this wire [`WIRE_SCHEMA`]).
        summary: serde_json::Value,
    },
    /// The session ended cleanly (acknowledging a [`Request::Close`]).
    Closed,
    /// The in-flight request was abandoned and the sandbox torn down, acknowledging a
    /// [`Request::Cancel`]. Always the connection's last message, and whatever the cancelled request had
    /// produced is discarded, so there is no partial [`Result`](Self::Result).
    Cancelled,
    /// The request could not be served: a malformed message, a boot or channel failure, or a guest fault.
    /// `fatal` distinguishes a session-ending failure from a per-request one the session survives.
    #[non_exhaustive]
    Error {
        /// A human-readable reason, which may name a path or an env *key* but never a value. For display
        /// and logs; branch on [`kind`](Self::Error::kind) rather than on this text.
        message: String,
        /// `true` if the session is over (the connection will close); `false` if the client may send
        /// another request.
        fatal: bool,
        /// Which layer faulted, so a caller can decide what to do without parsing `message`. Defaults to
        /// [`FaultKind::Unknown`] when absent, so a peer predating this field decodes rather than
        /// failing.
        #[serde(default = "unknown_fault")]
        kind: FaultKind,
    },
    /// The daemon refused because it is **at capacity**, either the `--max-sessions` count ceiling or an
    /// aggregate resource ceiling. Distinct from [`Error`](Self::Error) so a dispatcher can branch on
    /// backpressure without string-matching a message; always session-ending. `retry_after_ms` is a hint,
    /// since the daemon cannot know when a slot frees.
    #[non_exhaustive]
    AtCapacity {
        /// Suggested backoff before retrying, in milliseconds. A hint only.
        retry_after_ms: u64,
    },
}

/// The construction surface for the `#[non_exhaustive]` variants above. Each fn takes only the
/// variant's **required** fields, so these signatures move only when the wire itself breaks.
impl Response {
    /// The sandbox booted: its boot-to-userspace latency and whether the pool served it.
    #[must_use]
    pub fn opened(boot_ms: u64, pooled: bool) -> Self {
        Self::Opened { boot_ms, pooled }
    }

    /// A command finished with `exit_code`, its captured streams, and its host-observed wall time.
    #[must_use]
    pub fn result(exit_code: i32, stdout: String, stderr: String, exec_wall_ms: u64) -> Self {
        Self::Result {
            exit_code,
            stdout,
            stderr,
            exec_wall_ms,
        }
    }

    /// A `put` landed at `path`.
    #[must_use]
    pub fn put(path: String) -> Self {
        Self::Put { path }
    }

    /// A `get`'s answer: the file at `path`, or its absence (`present: false`, empty `content`).
    #[must_use]
    pub fn got(path: String, content: String, present: bool, lossy: bool) -> Self {
        Self::Got {
            path,
            content,
            present,
            lossy,
        }
    }

    /// A snapshot bundle was written at the daemon-host path `dir`.
    #[must_use]
    pub fn snapshotted(dir: String) -> Self {
        Self::Snapshotted { dir }
    }

    /// The session's signed audit-record envelope, carried opaquely.
    #[must_use]
    pub fn trace(record: serde_json::Value) -> Self {
        Self::Trace { record }
    }

    /// The session's model-legible summary projection, carried opaquely.
    #[must_use]
    pub fn trace_summary(summary: serde_json::Value) -> Self {
        Self::TraceSummary { summary }
    }

    /// The request could not be served; `fatal` says whether the session died with it.
    #[must_use]
    pub fn error(message: String, fatal: bool, kind: FaultKind) -> Self {
        Self::Error {
            message,
            fatal,
            kind,
        }
    }

    /// The daemon is at capacity; `retry_after_ms` is a backoff hint, not a promise.
    #[must_use]
    pub fn at_capacity(retry_after_ms: u64) -> Self {
        Self::AtCapacity { retry_after_ms }
    }
}

/// The `kind` a [`Response::Error`] decodes to when the peer omitted the field. Conservative on purpose:
/// an unclassified fault is not the caller's to fix.
fn unknown_fault() -> FaultKind {
    FaultKind::Unknown(String::new())
}

/// Declares [`FaultKind`] once: each variant's doc, its **wire string**, the `wire_str` encoder, and the
/// `NAMED` table the decoder walks all come from this one list. Written out by hand, a variant missing
/// from `NAMED` would still compile, still serialize, and silently decode as
/// [`FaultKind::Unknown`]. The enum's own rustdoc lives inside the expansion, since a doc comment out
/// here would document the macro instead.
macro_rules! fault_kinds {
    ($( $(#[$doc:meta])* $variant:ident => $wire:literal ),+ $(,)?) => {
        /// Which layer faulted, so a client branches on a **value** rather than on the prose in
        /// [`Response::Error`]'s `message`. The wire form of `bsx_engine::ErrorKind`, restated here
        /// because this crate stays `bsx`-free; a test pins the daemon's mapping between them.
        ///
        /// Where `fatal` answers "is this session over?", this answers "whose fault, and what should I
        /// do?": a different host may serve an [`Infra`](Self::Infra) fault, and a retry never fixes a
        /// [`Guest`](Self::Guest) one.
        ///
        /// **Unknown kinds degrade rather than fail.** A kind added later decodes as
        /// [`Unknown`](Self::Unknown) carrying the raw string, so the enum can grow without breaking
        /// existing clients. Treat `Unknown` like [`Infra`](Self::Infra).
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        #[non_exhaustive]
        pub enum FaultKind {
            $(
                $(#[$doc])*
                #[serde(rename = $wire)]
                $variant,
            )+
            /// A kind this client predates, carrying the raw wire string so it can still be logged.
            #[serde(untagged)]
            Unknown(String),
        }

        impl FaultKind {
            /// This kind's wire string, or `None` for [`Unknown`](Self::Unknown), which carries its own.
            /// The same literal the `Serialize` derive renames to, so encode and decode cannot
            /// disagree.
            fn wire_str(&self) -> Option<&'static str> {
                match self {
                    $( FaultKind::$variant => Some($wire), )+
                    FaultKind::Unknown(_) => None,
                }
            }

            /// Every named kind in declaration order, what the decoder searches. Generated, so it cannot
            /// fall behind the enum.
            const NAMED: &'static [FaultKind] = &[ $( FaultKind::$variant, )+ ];
        }
    };
}

fault_kinds! {
    /// The host couldn't stand the sandbox up, or a bounded wait expired. Not the caller's fault, so
    /// retry or try another host.
    Infra => "infra",
    /// A framing or IO fault on an established exec channel, or a guest silent past its deadline. The
    /// sandbox is unreliable, so retire it rather than blame the command.
    Transport => "transport",
    /// The run is at fault: the command couldn't be spawned, outran its budget, or flooded output.
    /// Retrying it unchanged gets the same answer.
    Guest => "guest",
    /// The client's own message was the problem: wrong [`WIRE_SCHEMA`], undecodable, oversize, or
    /// out of order (an `open` on an already-open session). Fix the client.
    Protocol => "protocol",
    /// The daemon understood the request and declined to serve it: a posture the operator chose
    /// (snapshotting a jailed session) or a capability this session lacks (no probes attached).
    /// Not a failure, and not retryable as-is.
    Refused => "refused",
}

/// Hand-written so the degrade-don't-fail promise above holds for **any** JSON, not just strings.
/// The derived `untagged` `Unknown(String)` only catches strings, so a `kind` that is a number,
/// `null`, or an object would fail the whole error reply as `Malformed`: the client would lose the
/// daemon's `message` and, per this crate's rule that an undecodable reply desyncs the session,
/// throw away a session over a field that exists purely to be advisory.
impl<'de> Deserialize<'de> for FaultKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = serde_json::Value::deserialize(d)?;
        let Some(s) = raw.as_str() else {
            return Ok(FaultKind::Unknown(raw.to_string()));
        };
        Ok(FaultKind::NAMED
            .iter()
            .find(|k| k.wire_str() == Some(s))
            .cloned()
            .unwrap_or_else(|| FaultKind::Unknown(s.to_string())))
    }
}

/// Every way the line protocol can fail to decode a peer's message, as a typed value, so a hostile or
/// buggy peer is answered or dropped rather than panicking.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProtocolError {
    /// The underlying stream failed.
    Io(std::io::Error),
    /// A line whose `schema` is not [`WIRE_SCHEMA`], reported before the body is trusted. Carries the
    /// number the peer sent.
    Schema(u64),
    /// A line that isn't valid UTF-8 JSON for the expected message.
    Malformed(String),
    /// A line exceeded the bound for its direction, rejected before it can grow host memory without
    /// bound. Carries the bound it broke, so a caller names the number that applied rather than guessing
    /// which direction it was reading.
    TooLarge {
        /// The bound this line exceeded.
        limit: usize,
    },
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Io(e) => write!(f, "protocol io: {e}"),
            ProtocolError::Schema(got) => {
                // "this build", not "this daemon": `read_message` is shared by both ends, so naming a
                // role would state the mismatch backwards when a client renders a daemon's stamp.
                // `a_schema_mismatch_names_the_speaker_not_a_role` pins it.
                write!(
                    f,
                    "unsupported wire schema {got} (this build speaks {WIRE_SCHEMA})"
                )
            }
            ProtocolError::Malformed(m) => write!(f, "malformed message: {m}"),
            ProtocolError::TooLarge { limit } => {
                write!(f, "message line exceeds the {limit}-byte cap")
            }
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Reads one [`Request`] (the daemon's side of the wire), bounded by [`MAX_REQUEST_BYTES`].
///
/// # Errors
/// [`ProtocolError`] on an IO failure, an over-cap line, a wrong `schema`, or an undecodable body.
pub fn read_request(reader: &mut impl BufRead) -> Result<Option<Request>, ProtocolError> {
    read_message(reader, MAX_REQUEST_BYTES)
}

/// Reads one [`Response`] (a client's side of the wire), bounded by [`MAX_RESPONSE_BYTES`].
///
/// # Errors
/// [`ProtocolError`] on an IO failure, an over-cap line, a wrong `schema`, or an undecodable body.
pub fn read_response(reader: &mut impl BufRead) -> Result<Option<Response>, ProtocolError> {
    read_message(reader, MAX_RESPONSE_BYTES)
}

/// Reads one schema-stamped message of type `T` from `reader`, bounded by `cap`. `Ok(None)` on a clean
/// EOF, and blank lines are skipped so a stray newline isn't a protocol fault.
///
/// The order of checks is load-bearing: over-cap before decoding, then JSON well-formed, then **schema
/// match** before the body is trusted, then body decode. One decode serves both ends, so the framing and
/// the schema gate can't drift between them, while `cap` comes from the direction-typed wrappers, since
/// the bound is the one thing that must differ.
fn read_message<T: DeserializeOwned>(
    reader: &mut impl BufRead,
    cap: usize,
) -> Result<Option<T>, ProtocolError> {
    loop {
        let mut buf = Vec::new();
        let eof = read_line_capped(reader, cap, &mut buf)?;
        if eof && buf.is_empty() {
            return Ok(None); // clean EOF, nothing buffered
        }
        let line = std::str::from_utf8(&buf)
            .map_err(|e| ProtocolError::Malformed(format!("not UTF-8: {e}")))?
            .trim();
        if line.is_empty() {
            if eof {
                return Ok(None); // trailing whitespace, then EOF
            }
            continue; // a blank line is not a message; wait for the next one
        }
        return decode_message(line).map(Some);
    }
}

/// Decodes one already-framed line into a `T`, enforcing the schema gate. Split out so the framing and
/// the decoding are each unit-testable in isolation.
///
/// The direction's cap bounds the **line**, not the decode, which costs a multiple of it. **Up to 40x**,
/// measured 2026-08-10 on an `x86_64` host against a counting allocator, decoding a line at
/// [`MAX_REQUEST_BYTES`]: 81 MiB for a valid `exec` whose `argv` fills the cap, 160 MiB for an array of
/// empty arrays or of integers, 59 MiB for an object of many short keys. So a daemon's peak is
/// `--max-sessions` times that, ~2.5 GiB at the default 16, transient and reachable with nothing but
/// well-formed, legally-sized lines. Bounded on both axes, and a number an operator sizing a host has to
/// hold.
///
/// **Two DOMs, and only one of them is this function's.** `Request`/`Response` are internally tagged
/// (`#[serde(tag = "op")]`), so serde buffers the whole message into its own `Content` before it can
/// dispatch on the tag. Checking the schema against a peek struct and then decoding the line directly
/// was measured and does **not** help: 80.7 MiB against this path's 81.0 for that valid `exec`, since it
/// trades `serde_json::Value` for `Content` and adds a second parse. The DOM follows from an internally
/// tagged wire, not from the order of operations here.
///
/// Depth is bounded separately by `serde_json`'s 128-deep recursion limit, which is what makes a line of
/// nothing but `[` a [`ProtocolError::Malformed`] rather than a stack overflow
/// (`nesting_past_the_json_recursion_limit_is_a_typed_error` holds that).
fn decode_message<T: DeserializeOwned>(line: &str) -> Result<T, ProtocolError> {
    // Parse once to a generic value so the `schema` is checked *before* the body is trusted: a
    // wrong-version peer is then a clean `Schema` error even if its body is an unknown shape.
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    match value.get("schema").and_then(serde_json::Value::as_u64) {
        Some(s) if s == u64::from(WIRE_SCHEMA) => {}
        Some(other) => return Err(ProtocolError::Schema(other)),
        None => {
            return Err(ProtocolError::Malformed(
                "missing or non-integer `schema` field".to_string(),
            ));
        }
    }
    // The body ignores the extra `schema` key, since the message enums aren't `deny_unknown_fields`.
    serde_json::from_value::<T>(value).map_err(|e| ProtocolError::Malformed(e.to_string()))
}

/// Reads one `\n`-terminated line into `out`, bounded at `cap` bytes, so a lying or never-terminating
/// peer can't grow host memory without bound. Returns `Ok(true)` if it stopped at EOF, `Ok(false)` on a
/// newline. Reads through the `BufRead`'s own buffer, so it is byte-precise without a syscall per byte.
///
/// On the over-cap path it drains the rest of the offending line before returning
/// [`ProtocolError::TooLarge`], leaving the stream at a clean line boundary. Without that, a caller
/// treating `TooLarge` as per-request and reading on would resume mid-line and emit a cascade of
/// spurious errors for one oversize message.
fn read_line_capped(
    reader: &mut impl BufRead,
    cap: usize,
    out: &mut Vec<u8>,
) -> Result<bool, ProtocolError> {
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProtocolError::Io(e)),
        };
        if available.is_empty() {
            return Ok(true); // EOF
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                if out.len() + i > cap {
                    // The newline is already in view, so consume through it before reporting.
                    reader.consume(i + 1);
                    return Err(ProtocolError::TooLarge { limit: cap });
                }
                out.extend_from_slice(&available[..i]);
                reader.consume(i + 1); // consume through the newline, which we drop
                return Ok(false);
            }
            None => {
                let used = available.len();
                if out.len() + used > cap {
                    // Over cap with no newline yet: drain to the line's end so the stream resyncs.
                    reader.consume(used);
                    discard_to_newline(reader)?;
                    return Err(ProtocolError::TooLarge { limit: cap });
                }
                out.extend_from_slice(available);
                reader.consume(used);
            }
        }
    }
}

/// Consumes and discards bytes through the next `\n` (or to EOF), leaving `reader` at a fresh line
/// boundary, so a surviving session parses the following message cleanly. Bounded in memory, since
/// nothing is buffered and it reads only what the peer already sent.
fn discard_to_newline(reader: &mut impl BufRead) -> Result<(), ProtocolError> {
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProtocolError::Io(e)),
        };
        if available.is_empty() {
            return Ok(()); // EOF: nothing left to resync to
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                reader.consume(i + 1); // through the newline
                return Ok(());
            }
            None => {
                let used = available.len();
                reader.consume(used);
            }
        }
    }
}

/// Write one [`Request`] (a client's side of the wire), bounded by [`MAX_REQUEST_BYTES`].
/// # Errors
/// [`ProtocolError::Io`] on a write failure; [`ProtocolError::TooLarge`] if the line would exceed
/// the bound the daemon reads it under.
pub fn write_request(w: &mut impl Write, req: &Request) -> Result<(), ProtocolError> {
    write_message(w, req, MAX_REQUEST_BYTES)
}

/// Write one [`Response`] (the daemon's side of the wire), bounded by [`MAX_RESPONSE_BYTES`].
/// # Errors
/// [`ProtocolError::Io`] on a write failure; [`ProtocolError::TooLarge`] if the line would exceed
/// the bound a client reads it under, which for a `result` means the run's output outgrew what this
/// wire carries and the caller owes the client a flooded-output error instead of this reply.
pub fn write_response(w: &mut impl Write, resp: &Response) -> Result<(), ProtocolError> {
    write_message(w, resp, MAX_RESPONSE_BYTES)
}

/// Write one message `body` as a single schema-stamped `\n`-terminated JSON line and flush it,
/// bounded by `cap` (the direction's bound, from the wrappers above).
fn write_message<T: Serialize>(
    w: &mut impl Write,
    body: &T,
    cap: usize,
) -> Result<(), ProtocolError> {
    let envelope = Envelope::new(body);
    // These types always serialize (no maps with non-string keys, no failing custom impls), so a
    // serialize error is a bug, not a runtime state, fold it into `Io` rather than a new variant.
    let mut line = serde_json::to_string(&envelope)
        .map_err(|e| ProtocolError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
    // The encode side honors the same envelope the peer's read side will: a line that peer would
    // reject as `TooLarge` is refused *here*, typed, before any byte moves, so an undeliverable
    // reply is a value the daemon can answer rather than a half-written line.
    // Checked before the newline is appended, since the read side's cap is on the line's content
    // (`read_line_capped` excludes the terminator), so the two bounds name one number.
    if line.len() > cap {
        return Err(ProtocolError::TooLarge { limit: cap });
    }
    line.push('\n');
    w.write_all(line.as_bytes()).map_err(ProtocolError::Io)?;
    w.flush().map_err(ProtocolError::Io)
}

/// Read until EOF **the way the daemon does**: answer an error and read on, rather than stopping at
/// the first one. `session.rs` treats a malformed or over-cap line as per-request and continues, so a
/// harness that stopped would leave everything reachable only *after* a recovered error outside what
/// it explores, the [`discard_to_newline`] resync most of all.
///
/// It terminates because every error path consumes at least through its line and a spent reader
/// answers `Ok(None)`: a `TooLarge` consumes or drains to the newline, and a `Malformed`/`Schema`
/// follows a line `read_line_capped` already took.
#[cfg(any(test, feature = "fuzzing"))]
fn drain_like_the_daemon<R: BufRead, T>(
    reader: &mut R,
    read: fn(&mut R) -> Result<Option<T>, ProtocolError>,
) {
    loop {
        match read(reader) {
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => return,
        }
    }
}

/// Fuzzing entry points behind the off-by-default `fuzzing` feature: they hand attacker-controlled
/// bytes to the daemon's untrusted-client parse path (the hand-rolled line reader + schema gate,
/// then `serde_json`) so a `cargo fuzz` (libFuzzer) target can explore it. The daemon (`bsx serve`)
/// reads exactly these bytes off its socket from any client, so a panic, hang, or unbounded
/// allocation on any input is the bug being hunted. Not built by default; the harness
/// lives in `fuzz/` (excluded from the workspace). The in-gate, dependency-light counterpart is
/// [`fuzz_tests`].
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    use std::io::Cursor;

    use crate::{read_request, read_response};

    /// Read a stream of `Request`s from `data` (the daemon's view of a client's bytes), the
    /// highest-value target: `bsx serve` decodes exactly this off its socket. Drains to EOF so a
    /// lying length, a blank-line flood, or a mid-line truncation are all exercised.
    pub fn read_requests(data: &[u8]) {
        crate::drain_like_the_daemon(&mut Cursor::new(data), read_request);
    }

    /// Read a stream of `Response`s from `data` (a client decoding a hostile/garbled daemon).
    pub fn read_responses(data: &[u8]) {
        crate::drain_like_the_daemon(&mut Cursor::new(data), read_response);
    }
}

#[cfg(test)]
mod fuzz_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a request through [`write_request`] and decode it back through [`read_request`], the
    /// exact round trip the daemon and a client make across the socket.
    fn roundtrip_request(req: &Request) -> Request {
        let mut wire = Vec::new();
        write_request(&mut wire, req).expect("encode");
        read_request(&mut wire.as_slice())
            .expect("decode ok")
            .expect("a message, not EOF")
    }

    #[test]
    fn requests_round_trip_through_the_versioned_line_codec() {
        for req in [
            Request::Open(OpenParams {
                vcpus: Some(2),
                mem_mib: Some(512),
                wall_secs: Some(60),
                output_cap: None,
                net: None,
                allow: None,
            }),
            Request::Open(OpenParams {
                vcpus: None,
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
                net: None,
                allow: None,
            }),
            Request::Exec(ExecParams {
                argv: vec!["echo".into(), "hi".into()],
                stdin: Some("piped\n".into()),
                env: None,
            }),
            Request::Exec(ExecParams {
                argv: vec!["env".into()],
                stdin: None,
                env: Some(vec![("TOKEN".into(), "s3cret".into())]),
            }),
            Request::Put(PutParams {
                path: "input.txt".into(),
                content: "hello\n".into(),
            }),
            Request::Get(GetParams {
                path: "out.txt".into(),
            }),
            Request::Snapshot,
            Request::Trace,
            Request::TraceSummary,
            Request::Close,
            Request::Cancel,
        ] {
            assert_eq!(roundtrip_request(&req), req);
        }
    }

    #[test]
    fn responses_round_trip() {
        for resp in [
            Response::Opened {
                boot_ms: 120,
                pooled: true,
            },
            Response::Result {
                exit_code: 0,
                stdout: "hi\n".into(),
                stderr: String::new(),
                exec_wall_ms: 5,
            },
            Response::Put {
                path: "input.txt".into(),
            },
            Response::Got {
                path: "out.txt".into(),
                content: "data\n".into(),
                present: true,
                lossy: false,
            },
            Response::Snapshotted {
                dir: "/var/lib/bsx/snap-1".into(),
            },
            Response::Trace {
                record: serde_json::json!({"schema": 1, "timing": {}}),
            },
            Response::TraceSummary {
                summary: serde_json::json!({"schema": 1, "network": null}),
            },
            Response::Closed,
            Response::Error {
                message: "no such binary".into(),
                fatal: false,
                kind: FaultKind::Guest,
            },
            Response::AtCapacity {
                retry_after_ms: 1000,
            },
        ] {
            let mut wire = Vec::new();
            write_response(&mut wire, &resp).expect("encode");
            let back: Response = read_response(&mut wire.as_slice())
                .expect("decode")
                .expect("a message");
            assert_eq!(back, resp);
        }
    }

    #[test]
    fn a_got_reply_without_the_lossy_field_decodes_as_not_lossy() {
        // The additive-field contract: a daemon older than `lossy` omits it, and a client on this
        // crate must read that as `false` (`#[serde(default)]`), not a decode error, so the field
        // lands without a schema bump.
        let line = b"{\"schema\":1,\"reply\":\"got\",\"path\":\"x\",\"content\":\"hi\",\"present\":true}\n";
        let back: Response = read_response(&mut line.as_slice())
            .expect("an old daemon's got decodes")
            .expect("a message");
        assert_eq!(
            back,
            Response::Got {
                path: "x".into(),
                content: "hi".into(),
                present: true,
                lossy: false,
            }
        );
    }

    /// The wire's compatibility contract, as bytes: the exact line every message shape serializes
    /// to, fully populated (plus the all-omitted `open`, whose absent knobs render as `null`s).
    /// This is what "the wire does not change" means mechanically, so a red assertion here is a
    /// **wire change**: either revert it, or bump [`WIRE_SCHEMA`] and update every client, never
    /// re-bless the string. The Rust-side shape of these types is free to move (params structs,
    /// constructors, variant attributes) exactly as long as this test cannot tell.
    #[test]
    fn the_wire_bytes_of_every_message_shape_are_pinned() {
        // Generic over both directions because this pins *bytes*, which the direction's bound has
        // no say in; the larger cap keeps a pinned shape from tripping it.
        fn line<T: serde::Serialize>(msg: &T) -> String {
            let mut wire = Vec::new();
            write_message(&mut wire, msg, MAX_RESPONSE_BYTES).expect("every pinned shape encodes");
            String::from_utf8(wire).expect("the wire is UTF-8")
        }

        // Requests: every verb, payload-carrying ones fully populated.
        for (msg, want) in [
            (
                Request::Open(OpenParams {
                    vcpus: Some(2),
                    mem_mib: Some(512),
                    wall_secs: Some(60),
                    output_cap: Some(16_777_216),
                    net: Some(true),
                    allow: Some(vec!["1.1.1.1:443/tcp".into()]),
                }),
                "{\"schema\":1,\"op\":\"open\",\"vcpus\":2,\"mem_mib\":512,\"wall_secs\":60,\
                 \"output_cap\":16777216,\"net\":true,\"allow\":[\"1.1.1.1:443/tcp\"]}\n",
            ),
            (
                // Every knob omitted: the conservative default an old client sends.
                Request::Open(OpenParams {
                    vcpus: None,
                    mem_mib: None,
                    wall_secs: None,
                    output_cap: None,
                    net: None,
                    allow: None,
                }),
                "{\"schema\":1,\"op\":\"open\",\"vcpus\":null,\"mem_mib\":null,\"wall_secs\":null,\
                 \"output_cap\":null,\"net\":null,\"allow\":null}\n",
            ),
            (
                Request::Exec(ExecParams {
                    argv: vec!["echo".into(), "hi".into()],
                    stdin: Some("in\n".into()),
                    env: Some(vec![("K".into(), "V".into())]),
                }),
                "{\"schema\":1,\"op\":\"exec\",\"argv\":[\"echo\",\"hi\"],\"stdin\":\"in\\n\",\
                 \"env\":[[\"K\",\"V\"]]}\n",
            ),
            (
                Request::Put(PutParams {
                    path: "in.txt".into(),
                    content: "data\n".into(),
                }),
                "{\"schema\":1,\"op\":\"put\",\"path\":\"in.txt\",\"content\":\"data\\n\"}\n",
            ),
            (
                Request::Get(GetParams {
                    path: "out.txt".into(),
                }),
                "{\"schema\":1,\"op\":\"get\",\"path\":\"out.txt\"}\n",
            ),
            (Request::Snapshot, "{\"schema\":1,\"op\":\"snapshot\"}\n"),
            (Request::Trace, "{\"schema\":1,\"op\":\"trace\"}\n"),
            (
                Request::TraceSummary,
                "{\"schema\":1,\"op\":\"trace_summary\"}\n",
            ),
            (Request::Close, "{\"schema\":1,\"op\":\"close\"}\n"),
            (Request::Cancel, "{\"schema\":1,\"op\":\"cancel\"}\n"),
        ] {
            assert_eq!(line(&msg), want, "request wire bytes moved");
        }

        // Responses: every reply, payload-carrying ones fully populated.
        for (msg, want) in [
            (
                Response::Opened {
                    boot_ms: 120,
                    pooled: true,
                },
                "{\"schema\":1,\"reply\":\"opened\",\"boot_ms\":120,\"pooled\":true}\n",
            ),
            (
                Response::Result {
                    exit_code: 3,
                    stdout: "out".into(),
                    stderr: "err".into(),
                    exec_wall_ms: 5,
                },
                "{\"schema\":1,\"reply\":\"result\",\"exit_code\":3,\"stdout\":\"out\",\
                 \"stderr\":\"err\",\"exec_wall_ms\":5}\n",
            ),
            (
                Response::Put {
                    path: "in.txt".into(),
                },
                "{\"schema\":1,\"reply\":\"put\",\"path\":\"in.txt\"}\n",
            ),
            (
                Response::Got {
                    path: "out.txt".into(),
                    content: "data".into(),
                    present: true,
                    lossy: true,
                },
                "{\"schema\":1,\"reply\":\"got\",\"path\":\"out.txt\",\"content\":\"data\",\
                 \"present\":true,\"lossy\":true}\n",
            ),
            (
                Response::Snapshotted {
                    dir: "/var/lib/bsx/snap-1".into(),
                },
                "{\"schema\":1,\"reply\":\"snapshotted\",\"dir\":\"/var/lib/bsx/snap-1\"}\n",
            ),
            (
                Response::Trace {
                    record: serde_json::json!({"schema": 1}),
                },
                "{\"schema\":1,\"reply\":\"trace\",\"record\":{\"schema\":1}}\n",
            ),
            (
                Response::TraceSummary {
                    summary: serde_json::json!({"schema": 1}),
                },
                "{\"schema\":1,\"reply\":\"trace_summary\",\"summary\":{\"schema\":1}}\n",
            ),
            (Response::Closed, "{\"schema\":1,\"reply\":\"closed\"}\n"),
            (
                Response::Cancelled,
                "{\"schema\":1,\"reply\":\"cancelled\"}\n",
            ),
            (
                Response::Error {
                    message: "boom".into(),
                    fatal: true,
                    kind: FaultKind::Guest,
                },
                "{\"schema\":1,\"reply\":\"error\",\"message\":\"boom\",\"fatal\":true,\
                 \"kind\":\"guest\"}\n",
            ),
            (
                Response::AtCapacity {
                    retry_after_ms: 1000,
                },
                "{\"schema\":1,\"reply\":\"at_capacity\",\"retry_after_ms\":1000}\n",
            ),
        ] {
            assert_eq!(line(&msg), want, "response wire bytes moved");
        }
    }

    /// The response constructors are positional, and three of them take arguments a compiler
    /// cannot tell apart (`result`'s two streams, `got`'s two strings, `error`'s message). Pin
    /// what lands where, so a swapped pair inside a constructor is a red test, not a record whose
    /// stdout is its stderr.
    #[test]
    fn constructors_place_arguments_in_the_documented_fields() {
        assert_eq!(
            Response::result(3, "out".into(), "err".into(), 5),
            Response::Result {
                exit_code: 3,
                stdout: "out".into(),
                stderr: "err".into(),
                exec_wall_ms: 5,
            }
        );
        assert_eq!(
            Response::got("p".into(), "c".into(), true, false),
            Response::Got {
                path: "p".into(),
                content: "c".into(),
                present: true,
                lossy: false,
            }
        );
        assert_eq!(
            Response::error("boom".into(), true, FaultKind::Guest),
            Response::Error {
                message: "boom".into(),
                fatal: true,
                kind: FaultKind::Guest,
            }
        );
        assert_eq!(
            Response::opened(7, true),
            Response::Opened {
                boot_ms: 7,
                pooled: true
            }
        );
    }

    /// [`Envelope::new`] is the only mint, so pin what it stamps: the crate's own
    /// [`WIRE_SCHEMA`], not a number a caller could get wrong. (`every_message_carries_the_schema`
    /// pins the same fact at the byte level; this pins it at the type level, where a foreign
    /// stamp is representable for the decode side but must never be minted.)
    #[test]
    fn a_minted_envelope_carries_the_wire_schema() {
        let envelope = Envelope::new(Request::Close);
        assert_eq!(envelope.schema, WIRE_SCHEMA);
        assert_eq!(envelope.body, Request::Close);
    }

    #[test]
    fn every_message_carries_the_schema() {
        // The stamp is present and legible on both directions of the wire.
        let mut req_wire = Vec::new();
        write_request(&mut req_wire, &Request::Close).expect("encode");
        assert_eq!(req_wire, b"{\"schema\":1,\"op\":\"close\"}\n");

        let mut resp_wire = Vec::new();
        write_response(&mut resp_wire, &Response::Closed).expect("encode");
        assert_eq!(resp_wire, b"{\"schema\":1,\"reply\":\"closed\"}\n");
    }

    #[test]
    fn a_wrong_schema_is_a_typed_error_before_the_body_is_trusted() {
        // A future/foreign schema is rejected as `Schema`, even when the body is an op we do know...
        assert!(matches!(
            read_request(&mut b"{\"schema\":2,\"op\":\"close\"}\n".as_slice()),
            Err(ProtocolError::Schema(2))
        ));
        // ...and even when the body is a shape this version has never seen.
        assert!(matches!(
            read_request(&mut b"{\"schema\":99,\"op\":\"teleport\"}\n".as_slice()),
            Err(ProtocolError::Schema(99))
        ));
        // A message with no schema at all is malformed, not silently accepted.
        assert!(matches!(
            read_request(&mut b"{\"op\":\"close\"}\n".as_slice()),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn a_schema_mismatch_names_the_speaker_not_a_role() {
        // One `read_message` serves both ends, so this error renders on a client decoding a
        // daemon's reply as readily as on the daemon decoding a client's request. A rendering that
        // named either role would state the mismatch backwards for the other one: a client meeting
        // a schema-2 daemon would be told "this daemon speaks 1" by the very line reporting that
        // the daemon speaks 2.
        let rendered = ProtocolError::Schema(2).to_string();
        for role in ["daemon", "client", "server", "peer"] {
            assert!(
                !rendered.contains(role),
                "the rendering names a role ({role}), so it is wrong at one end: {rendered}"
            );
        }
        // Both numbers stay legible: what arrived, and what this build speaks.
        assert!(rendered.contains('2'), "{rendered}");
        assert!(
            rendered.contains(&WIRE_SCHEMA.to_string()),
            "the local schema should render: {rendered}"
        );
    }

    #[test]
    fn omitted_open_fields_default_to_none() {
        // A minimal `open` (no knobs) decodes, so a client can take every default. This is also what
        // makes each new `open` field additive: a client written before `net`/`allow` existed sends
        // exactly these bytes, and they still decode to the conservative posture.
        let req: Request = read_request(&mut b"{\"schema\":1,\"op\":\"open\"}\n".as_slice())
            .expect("decode")
            .expect("a message");
        assert_eq!(
            req,
            Request::Open(OpenParams {
                vcpus: None,
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
                net: None,
                allow: None,
            })
        );
    }

    #[test]
    fn blank_lines_are_skipped_and_eof_is_none() {
        // Leading blank lines are tolerated; a stream with only whitespace is a clean EOF.
        let req: Request = read_request(&mut b"\n\n{\"schema\":1,\"op\":\"close\"}\n".as_slice())
            .expect("decode")
            .expect("a message past the blanks");
        assert_eq!(req, Request::Close);
        assert!(
            read_request(&mut b"\n  \n".as_slice())
                .expect("decode")
                .is_none()
        );
        assert!(read_request(&mut b"".as_slice()).expect("decode").is_none());
    }

    #[test]
    fn malformed_and_unknown_ops_are_typed_errors_not_panics() {
        // Non-JSON, valid JSON with no known `op`, and a wrong-typed field each fail typed (all at
        // the correct schema, so the failure is the body, not the version).
        for bad in [
            "not json at all\n",
            "{\"schema\":1,\"op\":\"teleport\"}\n",
            "{\"schema\":1,\"op\":\"exec\"}\n", // missing required argv
            "{\"schema\":1,\"op\":\"open\",\"vcpus\":\"x\"}\n", // vcpus not a number
        ] {
            assert!(
                matches!(
                    read_request(&mut bad.as_bytes()),
                    Err(ProtocolError::Malformed(_))
                ),
                "{bad:?} should be a typed Malformed error"
            );
        }
    }

    #[test]
    fn a_request_at_its_cap_encodes_and_decodes_and_one_byte_more_does_not() {
        // The bound is the line's content, the newline excluded, on the write side exactly as on
        // the read side (`read_line_capped` drops the terminator before counting): a message whose
        // line is exactly [`MAX_REQUEST_BYTES`] encodes and decodes, one more byte is refused by
        // the writer before any byte moves. Pinned so the writer cannot start counting the
        // newline too and refuse an at-cap line its own peer accepts.
        let overhead = {
            let mut w = Vec::new();
            write_request(
                &mut w,
                &Request::Put(PutParams {
                    path: "p".into(),
                    content: String::new(),
                }),
            )
            .expect("encode");
            w.len() - 1 // the line's content: everything but the newline
        };
        let at_cap = Request::Put(PutParams {
            path: "p".into(),
            content: "x".repeat(MAX_REQUEST_BYTES - overhead),
        });
        let mut wire = Vec::new();
        write_request(&mut wire, &at_cap).expect("an at-cap line encodes");
        assert_eq!(
            wire.len(),
            MAX_REQUEST_BYTES + 1,
            "content at the cap, plus the newline"
        );
        let back: Request = read_request(&mut wire.as_slice())
            .expect("the peer accepts an at-cap line")
            .expect("a message");
        assert_eq!(back, at_cap);

        let over = Request::Put(PutParams {
            path: "p".into(),
            content: "x".repeat(MAX_REQUEST_BYTES - overhead + 1),
        });
        let mut wire = Vec::new();
        assert!(matches!(
            write_request(&mut wire, &over),
            Err(ProtocolError::TooLarge { .. })
        ));
        assert!(wire.is_empty(), "refused before any byte moved");
    }

    #[test]
    fn nesting_past_the_json_recursion_limit_is_a_typed_error() {
        // The decode allocates a `Value` DOM before it builds a `T`, so depth is a separate axis
        // from the line cap: 100k open brackets is a small line. `serde_json`'s default recursion
        // limit is what keeps it a value rather than a blown stack, and this crate relies on that
        // default (the `unbounded_depth` feature is off), which is worth a test rather than a
        // footnote.
        // Balanced on both sides, and carried in a field the message ignores, so **only** the depth
        // differs between the two halves: an unbalanced line would be malformed at any depth and
        // this would pass without touching the limit at all.
        let nest = |depth: usize| {
            format!(
                "{{\"schema\":1,\"op\":\"open\",\"deep\":{}{}}}\n",
                "[".repeat(depth),
                "]".repeat(depth)
            )
        };
        let shallow = nest(8);
        assert!(
            matches!(read_request(&mut shallow.as_bytes()), Ok(Some(_))),
            "the same shape inside the limit decodes, so the deep case below is about depth"
        );
        let deep = nest(100_000);
        assert!(matches!(
            read_request(&mut deep.as_bytes()),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn a_reply_may_carry_what_a_request_may_not() {
        // The asymmetry as behavior, where the `const` assertion above the constants states it as
        // an ordering: an exec whose output is larger than a client is allowed to *send* still
        // reaches that client, because the two directions bound different things.
        let big = "x".repeat(MAX_REQUEST_BYTES + 1);
        let reply = Response::result(0, big.clone(), String::new(), 5);
        let mut wire = Vec::new();
        write_response(&mut wire, &reply).expect("a reply past the request cap still encodes");
        let back = read_response(&mut wire.as_slice())
            .expect("and its reader accepts it")
            .expect("a message");
        assert_eq!(back, reply);

        // The same size going the other way is still refused: widening the reply bound must not
        // have widened what a client may send.
        let mut wire = Vec::new();
        assert!(matches!(
            write_request(&mut wire, &Request::Put(PutParams::new("p".into(), big))),
            Err(ProtocolError::TooLarge {
                limit: MAX_REQUEST_BYTES
            })
        ));
    }

    #[test]
    fn an_overlong_line_is_rejected_before_allocating_unboundedly() {
        // A line that never terminates (no newline, past the cap) is a typed TooLarge, not an
        // unbounded read that grows host memory.
        let flood = vec![b'x'; MAX_REQUEST_BYTES + 1];
        assert!(matches!(
            read_request(&mut flood.as_slice()),
            Err(ProtocolError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_fuzz_drain_reads_past_a_refusal_like_the_daemon_does() {
        // A refused line followed by a good one. A drain that stopped at the first error would leave
        // the second unread, which is what put the resync path (and anything else reachable only
        // past a refusal) outside what the fuzz harnesses explore.
        let wire: &[u8] = b"{not json}\n{\"schema\":1,\"op\":\"close\"}\n";
        let mut cur = std::io::Cursor::new(wire);
        drain_like_the_daemon(&mut cur, read_request);
        assert_eq!(
            usize::try_from(cur.position()).expect("a test-sized stream"),
            wire.len(),
            "the drain stopped at the refusal instead of reading on, as the daemon does"
        );
    }

    #[test]
    fn the_drain_finds_the_newline_across_buffer_refills() {
        // `read_line_capped` has two over-cap exits, and only one of them reaches
        // [`discard_to_newline`] with work to do. Over a `&[u8]` or a `Cursor`, `fill_buf` hands back
        // the whole remainder, so the newline is always already in view and the inline branch takes
        // it: every test that reads that way exercises the wrong half.
        //
        // The daemon reads through a `BufReader`, whose buffer is finite, so an over-cap line fills
        // it many times with no newline in sight. That is this: a cap and a buffer small enough that
        // the drain must span several refills before it finds the terminator.
        let stream: &[u8] = b"0123456789abcdefghij\nNEXT\n";
        let mut reader = std::io::BufReader::with_capacity(4, stream);

        let mut out = Vec::new();
        let err = read_line_capped(&mut reader, 8, &mut out)
            .expect_err("a 20-byte line is over an 8-byte cap");
        assert!(
            matches!(err, ProtocolError::TooLarge { limit: 8 }),
            "{err:?}"
        );
        assert!(
            out.len() <= 8,
            "buffered {} bytes past the cap it was told to stop at",
            out.len()
        );

        // The drain is the point: the reader must be left exactly on the next line, so a session
        // that treats `TooLarge` as per-request reads a whole message and not the tail of the one
        // it just refused.
        let mut next = Vec::new();
        let eof =
            read_line_capped(&mut reader, 8, &mut next).expect("the next line is under the cap");
        assert_eq!(next, b"NEXT", "resumed mid-line instead of at the next one");
        assert!(!eof);
    }

    #[test]
    fn an_overlong_line_through_a_buffered_reader_resyncs_like_the_daemons() {
        // The same property at the real cap and through the reader shape the daemon uses, so the
        // production path is covered end to end and not only the small-cap unit above.
        // Well past the cap, not one byte past it: a line that ends just over the bound puts its
        // newline in view before the accumulation trips, so the inline branch takes it and the drain
        // is skipped. The overrun has to outlast the reader's buffer for the drain to be the exit.
        let mut wire = vec![b'x'; MAX_REQUEST_BYTES + 4096];
        wire.push(b'\n');
        wire.extend_from_slice(b"{\"schema\":1,\"op\":\"close\"}\n");
        let mut reader = std::io::BufReader::with_capacity(64, wire.as_slice());

        assert!(matches!(
            read_request(&mut reader),
            Err(ProtocolError::TooLarge { .. })
        ));
        assert!(matches!(
            read_request(&mut reader),
            Ok(Some(Request::Close))
        ));
        assert!(matches!(read_request(&mut reader), Ok(None)));
    }

    #[test]
    fn an_overlong_line_resyncs_so_the_next_message_parses() {
        // An over-cap line is drained through its newline, so a session that treats `TooLarge` as
        // per-request never resumes mid-line: exactly one `TooLarge` is reported and the very next
        // line decodes normally.
        let mut wire = vec![b'x'; MAX_REQUEST_BYTES + 1];
        wire.push(b'\n'); // the oversize line *is* newline-terminated
        wire.extend_from_slice(b"{\"schema\":1,\"op\":\"close\"}\n"); // a valid message right after
        let mut cursor = wire.as_slice();

        // First read: the oversize line, one clean `TooLarge`.
        assert!(matches!(
            read_request(&mut cursor),
            Err(ProtocolError::TooLarge { .. })
        ));
        // Second read: the stream resynced, so the following message parses (no mid-line garbage).
        assert!(matches!(
            read_request(&mut cursor),
            Ok(Some(Request::Close))
        ));
        // Third read: clean EOF, nothing stranded.
        assert!(matches!(read_request(&mut cursor), Ok(None)));
    }

    #[test]
    fn a_fault_kind_this_client_predates_decodes_instead_of_failing() {
        // The whole point of `Unknown`: a daemon that grows a new kind must not break every client
        // built before it. The raw string survives so the fault is still loggable.
        let line = br#"{"schema":1,"reply":"error","message":"x","fatal":true,"kind":"quota"}"#;
        let resp: Response = read_response(&mut &line[..])
            .expect("a future kind decodes")
            .expect("one message");
        assert!(
            matches!(&resp, Response::Error { kind: FaultKind::Unknown(k), .. } if k == "quota"),
            "a future kind should decode as Unknown carrying its raw string, got {resp:?}"
        );
    }

    #[test]
    fn an_error_without_a_kind_decodes_as_unknown() {
        // A peer predating the field at all: absent `kind` must not be a decode failure.
        let line = br#"{"schema":1,"reply":"error","message":"x","fatal":false}"#;
        let resp: Response = read_response(&mut &line[..])
            .expect("a kind-less error decodes")
            .expect("one message");
        assert!(
            matches!(
                &resp,
                Response::Error {
                    kind: FaultKind::Unknown(_),
                    ..
                }
            ),
            "an absent kind should decode as Unknown, not fail, got {resp:?}"
        );
    }

    #[test]
    fn the_known_fault_kinds_are_snake_case_on_the_wire() {
        // The wire spelling is the client contract: these strings are what a non-Rust decoder matches on.
        for (kind, want) in [
            (FaultKind::Infra, "infra"),
            (FaultKind::Transport, "transport"),
            (FaultKind::Guest, "guest"),
            (FaultKind::Protocol, "protocol"),
            (FaultKind::Refused, "refused"),
        ] {
            assert_eq!(
                serde_json::to_value(&kind).unwrap(),
                serde_json::json!(want)
            );
        }
    }

    #[test]
    fn every_named_kind_round_trips() {
        // `NAMED`, `wire_str`, and the enum are all generated from the one `fault_kinds!` list, so
        // a new variant is in this loop by construction: it cannot be spelled for encoding and
        // forgotten for decoding.
        for kind in FaultKind::NAMED {
            let json = serde_json::to_value(kind).expect("serialize");
            let back: FaultKind = serde_json::from_value(json).expect("deserialize");
            assert_eq!(&back, kind, "{kind:?} must survive a wire round trip");
        }
        // A serde-shaped variant object from a generic encoder degrades rather than failing.
        let odd: FaultKind = serde_json::from_value(serde_json::json!({ "infra": null })).unwrap();
        assert!(matches!(odd, FaultKind::Unknown(_)));
    }

    #[test]
    fn a_non_string_kind_degrades_instead_of_failing_the_reply() {
        // The whole point of the hand-written decoder: an advisory field must never cost the
        // client the daemon's `message` (and, per the desync rule, its session).
        for raw in [
            serde_json::json!(5),
            serde_json::json!(null),
            serde_json::json!(["infra"]),
        ] {
            let decoded: FaultKind = serde_json::from_value(raw).expect("degrades, never fails");
            assert!(matches!(decoded, FaultKind::Unknown(_)));
        }
    }

    #[test]
    fn a_known_name_in_unknown_decodes_as_the_known_kind() {
        // `Unknown` is untagged, so it is the *decoder's* fallback, not a distinct wire value: a
        // peer that sends "guest" gets `Guest`, which is the point. The consequence worth pinning
        // is that `Unknown` does not round-trip for names that collide with known variants, so
        // nothing (a generator, a client) should construct one that way.
        let shadowed = serde_json::to_string(&FaultKind::Unknown("guest".into()))
            .expect("a fault kind serializes");
        assert_eq!(
            shadowed, "\"guest\"",
            "Unknown serializes as its bare payload"
        );
        let decoded: FaultKind = serde_json::from_str(&shadowed).expect("it decodes");
        assert_eq!(
            decoded,
            FaultKind::Guest,
            "a known name decodes as the known variant, never back into Unknown"
        );
    }

    #[test]
    fn output_cap_is_fixed_width_on_the_wire() {
        // A 32-bit client and a 64-bit daemon must agree on this number, so it cannot be `usize`.
        // A value above `u32::MAX` has to survive the round trip on a 32-bit peer.
        let over_32_bits = u64::from(u32::MAX) + 1;
        let req = Request::Open(OpenParams {
            vcpus: None,
            mem_mib: None,
            wall_secs: None,
            output_cap: Some(over_32_bits),
            net: None,
            allow: None,
        });
        let mut wire = Vec::new();
        write_request(&mut wire, &req).expect("an open serializes");
        let back: Request = read_request(&mut &wire[..])
            .expect("it decodes")
            .expect("one message");
        assert_eq!(back, req, "a >32-bit output_cap must survive the wire");
    }

    #[test]
    fn an_unknown_field_is_ignored_so_the_wire_can_grow_additively() {
        // Compatibility rule 1, and the only one that is currently a serde *default* rather than
        // an explicit attribute: nothing here sets `deny_unknown_fields`, so a client predating a
        // field the daemon added still decodes the message. Pinned because turning that default
        // around is a one-character change that would silently break every deployed client on the
        // next daemon upgrade.
        let line =
            br#"{"schema":1,"reply":"opened","boot_ms":7,"pooled":true,"cpu_model":"future"}"#;
        let resp: Response = read_response(&mut &line[..])
            .expect("an unknown field must not fail the decode")
            .expect("one message");
        assert_eq!(
            resp,
            Response::Opened {
                boot_ms: 7,
                pooled: true
            },
            "the known fields decode; the unknown one is ignored"
        );

        // The same rule on the request side, which the daemon relies on to accept a newer client.
        let line = br#"{"schema":1,"op":"exec","argv":["echo"],"nice":10}"#;
        let req: Request = read_request(&mut &line[..])
            .expect("an unknown field must not fail the decode")
            .expect("one message");
        assert_eq!(
            req,
            Request::Exec(ExecParams {
                argv: vec!["echo".to_string()],
                stdin: None,
                env: None,
            })
        );
    }

    #[test]
    fn debug_redacts_secrets_but_keeps_the_request_legible() {
        // The daemon logs a request on its unhandled-verb path (`tracing::error!(request = ?other)`),
        // so `Debug` is a live leak path, not a theoretical one. Env *values* and file *content* must
        // never render; keys, paths, and argv must, or the log line is useless for debugging.
        let exec = Request::Exec(ExecParams {
            argv: vec!["env".into()],
            stdin: Some("stdin-secret".into()),
            env: Some(vec![
                ("AWS_SECRET_ACCESS_KEY".into(), "leaked-value".into()),
                ("TOKEN".into(), "another-secret".into()),
            ]),
        });
        let rendered = format!("{exec:?}");
        for secret in ["leaked-value", "another-secret", "stdin-secret"] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked a secret value ({secret}): {rendered}"
            );
        }
        // Loggable by contract: an error may name an env key or an argv, never a value.
        assert!(rendered.contains("AWS_SECRET_ACCESS_KEY"), "{rendered}");
        assert!(rendered.contains("TOKEN"), "{rendered}");
        assert!(rendered.contains("env"), "{rendered}");
        // The counts survive, so a reader can still tell how much was carried.
        assert!(
            rendered.contains('2'),
            "var count should render: {rendered}"
        );

        // `put` carries file content, which the engine's contract treats as a secret too. A derived `Debug`
        // would print it.
        let put = Request::Put(PutParams {
            path: "creds.json".into(),
            content: "very-secret-file-body".into(),
        });
        let rendered = format!("{put:?}");
        assert!(
            !rendered.contains("very-secret-file-body"),
            "Debug leaked file content: {rendered}"
        );
        assert!(
            rendered.contains("creds.json"),
            "a path is loggable: {rendered}"
        );

        // A variant with nothing secret still renders its fields, so redaction did not cost
        // legibility across the board.
        let open = Request::Open(OpenParams {
            vcpus: Some(2),
            mem_mib: Some(512),
            wall_secs: None,
            output_cap: None,
            net: None,
            allow: None,
        });
        let rendered = format!("{open:?}");
        assert!(rendered.contains("vcpus"), "{rendered}");
        assert!(rendered.contains('2'), "{rendered}");
    }

    #[test]
    fn an_unknown_reply_is_a_hard_error_not_a_skipped_message() {
        // Compatibility rule 2, the deliberate opposite of rule 1. A reply this client cannot
        // interpret means it has lost track of what the daemon is answering, so it must surface
        // rather than be skipped: silently continuing would misattribute every later reply to the
        // wrong request. Growing the reply set is a schema bump, and this test is what makes that
        // a promise instead of a preference.
        let line = br#"{"schema":1,"reply":"streamed","chunk":"partial output"}"#;
        let err = read_response(&mut &line[..])
            .map(|_| ())
            .expect_err("an unknown reply must not decode");
        assert!(
            matches!(err, ProtocolError::Malformed(_)),
            "expected a typed malformed error, got {err:?}"
        );
    }
}
