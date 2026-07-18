//! The `agentd` wire protocol: a **versioned, newline-delimited JSON** contract. A client sends one
//! [`Request`] line, the daemon answers with one or more [`Response`] lines; every message carries a
//! leading [`schema`](Envelope::schema) field, so the two sides agree on the shape before either
//! trusts the other's bytes.
//!
//! **This is the SDK contract seed (decision 034).** It is the one artifact the daemon
//! ([`agentd`](../agent_cli/index.html)), the reference client (`agentd-client`), and the eventual
//! polyglot SDKs all share, so it lives in its own **`agent-vmm`-free** crate: the wire is the
//! contract, not shared Rust internals, and a non-Rust caller reimplements these JSON shapes without
//! linking the engine. Phase 20 freezes and formally specs it; until then the shape may still change,
//! which is exactly why [`WIRE_SCHEMA`] is stamped on every message and mismatches are rejected up
//! front rather than silently mis-decoded.
//!
//! **Why JSON, not gRPC (decision 034).** The daemon is synchronous, thread-per-connection, with no
//! async runtime on the host path; gRPC would drag `tonic`/`prost` and a `tokio` stack into that
//! posture. The peer is a **local, trusted-ish client** the hoster runs, so hand-debuggability
//! (`socat`, `nc`) matters more than a compact wire, and any language can drive a line of JSON over a
//! unix socket with only a JSON library. The one adversarial concern that still applies is guardrail
//! 5 (no host panic/hang/unbounded allocation on any input): every decode is bounded by
//! [`MAX_MESSAGE_BYTES`] and returns a typed [`ProtocolError`], never a panic.
//!
//! **Text, not binary.** `stdin`, `put`/`get` `content`, and the returned `stdout`/`stderr` are
//! **UTF-8 strings**, lossy on the way out exactly like `agent run --json` (so the daemon and the CLI
//! render a run identically). Bulk or binary I/O is the block-device path
//! (`BootConfig::input_dir`/`output_dir`), an embedding-API concern, never this per-message line.
//!
//! **Non-goals: this is the *engine's* wire, not a *platform's* (guardrail 4).** The protocol
//! deliberately carries **no** notion of a *tenant*, a *credential*, a *quota*, a *price*, or a
//! *host to schedule onto*: there is no identity field, no auth handshake, no account or billing
//! token, no request routing. One connection drives one sandbox on the one host the daemon runs on,
//! and the daemon trusts whoever can reach its socket completely. That absence is a design
//! commitment, not a gap to fill: the moment the wire grew a tenant id or an auth token it would
//! stop being an embeddable engine and start being a PaaS, and multi-tenant identity, authorization,
//! quotas, billing, and fleet scheduling all belong to the **hoster** layered *above* this, never in
//! these shapes. Access control is the unix socket's directory permissions; a schema bump adds a
//! verb, never a tenancy field. (The embedding-side statement of the same line is
//! `docs/embedding.md` "Where the engine ends".)

use std::io::{BufRead, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The wire-protocol version. Every message carries it (see [`Envelope`]); a peer that stamps a
/// different number is a [`ProtocolError::Schema`], reported before its body is trusted, so a client
/// built against a future revision fails loudly instead of being half-understood. Bumped whenever a
/// request/response shape changes in a non-additive way.
pub const WIRE_SCHEMA: u32 = 1;

/// Upper bound on one protocol line, before decoding, the guardrail-5 allocation cap so a peer that
/// never sends a newline (or sends a huge one) is a typed [`ProtocolError::TooLarge`], not an
/// unbounded read. Generous: a per-message `stdin`/`content` string plus its JSON envelope fits,
/// while the exec channel still enforces the real `agent_vmm::MAX_PAYLOAD` on the bytes that reach
/// the guest, so this is a DoS bound, not the input-size contract.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// A schema-stamped message. Every line on the wire, request or response, is an `Envelope`: the
/// leading `schema` field plus the flattened [`Request`]/[`Response`] body, so a line reads
/// `{"schema":1,"op":"exec",...}` and the version is legible before the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// The [`WIRE_SCHEMA`] the sender speaks.
    pub schema: u32,
    /// The message body, flattened so its own tag (`op`/`reply`) sits beside `schema`.
    #[serde(flatten)]
    pub body: T,
}

/// A client → daemon message. Internally tagged by an `op` field, so a line reads
/// `{"schema":1,"op":"exec","argv":["echo","hi"]}`, self-describing and hand-writable. The verb set
/// is the versioned lifecycle:
/// `open` → (`exec` | `put` | `get` | `snapshot` | `trace` | `trace_summary`)\* → `close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Open the connection's sandbox, the first message of a session (the VM *is* the session,
    /// decision 019). Carries only **resource** knobs; the confinement posture (jailed vs unjailed)
    /// is the daemon's launch-time choice, never a client's, so a caller can't downgrade the jail.
    /// Any omitted field keeps the conservative `agent_vmm::Limits` default.
    Open {
        /// Guest vCPUs (1..=32); omitted keeps the default 1.
        #[serde(default)]
        vcpus: Option<u8>,
        /// Guest memory in MiB (>= 1); omitted keeps the default 256.
        #[serde(default)]
        mem_mib: Option<u32>,
        /// Wall-clock budget in seconds (>= 1): the boot deadline and each exec's budget; omitted
        /// keeps the default 30.
        #[serde(default)]
        wall_secs: Option<u64>,
        /// Aggregate captured-output cap in bytes; omitted keeps the default 16 MiB.
        #[serde(default)]
        output_cap: Option<usize>,
    },
    /// Run one command in the open sandbox, feeding `stdin` (UTF-8 text) to it. Repeated `exec`s
    /// share the session's working directory (decision 019).
    Exec {
        /// The command and its arguments (`argv[0]` is the program). Empty is a guest fault.
        argv: Vec<String>,
        /// Text piped to the command's stdin; omitted is empty. Bulk/binary input is the
        /// block-device path, not this field.
        #[serde(default)]
        stdin: Option<String>,
    },
    /// Write `content` (UTF-8 text) to `path` in the session's working directory, so a later `exec`
    /// sees it. A relative `path` is resolved against that working directory; the file persists for
    /// the life of the session (the VM is the session).
    Put {
        /// Where in the working directory to write, relative (e.g. `input.txt`).
        path: String,
        /// The file's UTF-8 contents. Bulk/binary is the block-device path, not this verb.
        content: String,
    },
    /// Read `path` back from the session's working directory. A missing file is not an error, the
    /// [`Response::Got`] simply reports `present: false`.
    Get {
        /// Which file in the working directory to read back, relative.
        path: String,
    },
    /// Snapshot the session's live VM into a daemon-side bundle, answered with the bundle's host
    /// path ([`Response::Snapshotted`]). Snapshotting a **jailed** session is a typed refusal (its
    /// disk lives in the chroot), the prewarm-source flow is unjailed, mirroring the engine API.
    Snapshot,
    /// Ask for the session's **host-observed audit record** so far ([`Response::Trace`]): the same
    /// `RunRecord` shape the CLI's `--record` writes, as a JSON object, but sampled **live**, a
    /// non-destructive snapshot, repeatable mid-session. So its `coverage` reflects **attach time**,
    /// and an axis that is absent may be a *transient* read (a momentary tap/meter miss) rather than a
    /// finalized gap, unlike the CLI's `--record`, which finalizes the record at session end and
    /// records read failures as gaps. Fail-open, a host that couldn't attach the probes answers a
    /// coverage-gapped record, never an error.
    Trace,
    /// Ask for the session's **model-legible summary** so far ([`Response::TraceSummary`]): the same
    /// compact projection the CLI's `--record-summary` writes (what it reached, what egress was denied,
    /// its resource envelope, any coverage gap), sampled **live** and non-destructively like
    /// [`Trace`](Self::Trace), the face an agent driving `agentd` reads between turns, so the wire
    /// exposes the projection, not just the full record. Fail-open, same as `trace`.
    TraceSummary,
    /// End the session: tear the sandbox down and close the connection. Dropping the connection
    /// without this does the same teardown; `close` just makes it explicit and acknowledged.
    Close,
}

/// A daemon → client message. Internally tagged by a `reply` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Response {
    /// The sandbox booted; carries its boot-to-userspace latency and whether it came from the
    /// pre-warmed pool (a fast `open`) or a cold boot.
    Opened {
        /// Boot-to-userspace latency, milliseconds (a warm-pool restore is a small fraction of a
        /// cold boot).
        boot_ms: u64,
        /// `true` if served from the daemon's pre-warmed pool, `false` for a cold boot (a custom
        /// resource profile, or a daemon launched without `--prewarm`).
        pooled: bool,
    },
    /// A command finished. `exit_code` is the guest command's own code (non-zero is a *result*, not
    /// an error); `stdout`/`stderr` are lossy UTF-8 like `agent run --json`.
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
    Put {
        /// The path written, echoed back for correlation.
        path: String,
    },
    /// The result of a [`Request::Get`]. `present: false` (with an empty `content`) is a missing
    /// file, not an error.
    Got {
        /// The path read, echoed back.
        path: String,
        /// The file's contents, lossy UTF-8; empty when `present` is `false`.
        content: String,
        /// Whether the file existed.
        present: bool,
    },
    /// A [`Request::Snapshot`] wrote a bundle. `dir` is a **daemon-host** path (the bundle's device
    /// state + guest memory live on the daemon's filesystem, not sent over this line).
    Snapshotted {
        /// The host directory holding the snapshot bundle.
        dir: String,
    },
    /// The session's audit record (answering [`Request::Trace`]), as the `RunRecord` JSON object,
    /// carried opaquely here so this crate stays free of the probes-loader types.
    Trace {
        /// The `RunRecord` as a JSON object (its own `schema` field is the *record* schema, distinct
        /// from this wire [`WIRE_SCHEMA`]).
        record: serde_json::Value,
    },
    /// The session's model-legible summary (answering [`Request::TraceSummary`]), as the projection's
    /// JSON object, carried opaquely, same as [`Trace`](Self::Trace).
    TraceSummary {
        /// The record summary as a JSON object (its own leading `schema` is the *summary* schema,
        /// distinct from the record schema and this wire [`WIRE_SCHEMA`]).
        summary: serde_json::Value,
    },
    /// The session ended cleanly (acknowledging a [`Request::Close`]).
    Closed,
    /// The request could not be served: a malformed message, a boot/channel failure, or a guest
    /// fault. `fatal` distinguishes a session-ending failure (the sandbox is gone, reconnect) from
    /// a per-request one the session survives (e.g. a command that couldn't spawn).
    Error {
        /// A human-readable reason (never carries injected secrets, an engine `VmmError` rendering
        /// may name a path or an env *key*, never a value).
        message: String,
        /// `true` if the session is over (the connection will close); `false` if the client may send
        /// another request.
        fatal: bool,
    },
}

/// Every way the line protocol can fail to decode a peer's message, as a typed value, so a hostile
/// or buggy peer is a typed error the daemon answers or drops, never a panic (guardrail 5).
#[derive(Debug)]
pub enum ProtocolError {
    /// The underlying stream failed.
    Io(std::io::Error),
    /// A line whose `schema` is not [`WIRE_SCHEMA`], a version mismatch, reported before the body
    /// is trusted. Carries the number the peer sent.
    Schema(u64),
    /// A line that isn't valid UTF-8 JSON for the expected message.
    Malformed(String),
    /// A line exceeded [`MAX_MESSAGE_BYTES`] before a newline arrived, rejected before it can grow
    /// host memory without bound.
    TooLarge,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Io(e) => write!(f, "protocol io: {e}"),
            ProtocolError::Schema(got) => {
                write!(
                    f,
                    "unsupported wire schema {got} (this daemon speaks {WIRE_SCHEMA})"
                )
            }
            ProtocolError::Malformed(m) => write!(f, "malformed message: {m}"),
            ProtocolError::TooLarge => {
                write!(f, "message line exceeds the {MAX_MESSAGE_BYTES}-byte cap")
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

/// Read one schema-stamped message of type `T` from `reader`, bounded by [`MAX_MESSAGE_BYTES`].
/// `Ok(None)` on a clean EOF (the peer hung up); blank lines are skipped so a stray newline isn't a
/// protocol fault. The order of checks is deliberate: over-cap (before decoding) → JSON well-formed
/// → **schema match** (before the body is trusted) → body decode.
///
/// This is the one decode both ends use, the daemon with `T = Request`, a client with
/// `T = Response`, so the framing, the cap, and the schema gate can't drift between them.
///
/// # Errors
/// [`ProtocolError`] on an I/O failure, an over-cap line, a wrong `schema`, or a body that isn't a
/// valid `T`.
pub fn read_message<T: DeserializeOwned>(
    reader: &mut impl BufRead,
) -> Result<Option<T>, ProtocolError> {
    loop {
        let mut buf = Vec::new();
        let eof = read_line_capped(reader, MAX_MESSAGE_BYTES, &mut buf)?;
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

/// Decode one already-framed line into a `T`, enforcing the schema gate. Split out so the framing
/// (bounded line read) and the decoding (schema + body) are each unit-testable in isolation.
fn decode_message<T: DeserializeOwned>(line: &str) -> Result<T, ProtocolError> {
    // Parse once to a generic value so the `schema` can be checked *before* the body is trusted,
    // a wrong-version peer is a clean `Schema` error even if its body is a shape we don't know yet.
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    match value.get("schema").and_then(serde_json::Value::as_u64) {
        Some(s) if s == u64::from(WIRE_SCHEMA) => {}
        Some(other) => return Err(ProtocolError::Schema(other)),
        None => {
            return Err(ProtocolError::Malformed(
                "missing `schema` field".to_string(),
            ))
        }
    }
    // The body ignores the extra `schema` key (the message enums aren't `deny_unknown_fields`).
    serde_json::from_value::<T>(value).map_err(|e| ProtocolError::Malformed(e.to_string()))
}

/// Read one `\n`-terminated line into `out` (the newline excluded), bounded at `cap` bytes:
/// [`ProtocolError::TooLarge`] the moment the line would exceed it, so a lying or never-terminating
/// peer can't grow host memory without bound. Returns `Ok(true)` if it stopped at EOF (the line may
/// be unterminated), `Ok(false)` if it stopped on a newline. Reads through the `BufRead`'s own buffer
/// (`fill_buf`/`consume`), so it is byte-precise without being a syscall per byte.
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
                    return Err(ProtocolError::TooLarge);
                }
                out.extend_from_slice(&available[..i]);
                reader.consume(i + 1); // consume through the newline, which we drop
                return Ok(false);
            }
            None => {
                let used = available.len();
                if out.len() + used > cap {
                    return Err(ProtocolError::TooLarge);
                }
                out.extend_from_slice(available);
                reader.consume(used);
            }
        }
    }
}

/// Write one message `body` as a single schema-stamped `\n`-terminated JSON line and flush it. The
/// daemon writes a [`Response`]; a client writes a [`Request`].
///
/// # Errors
/// [`ProtocolError::Io`] on a write failure (serialization of these fixed types is infallible).
pub fn write_message<T: Serialize>(w: &mut impl Write, body: &T) -> Result<(), ProtocolError> {
    let envelope = Envelope {
        schema: WIRE_SCHEMA,
        body,
    };
    // These types always serialize (no maps with non-string keys, no failing custom impls), so a
    // serialize error is a bug, not a runtime state, fold it into `Io` rather than a new variant.
    let mut line = serde_json::to_string(&envelope)
        .map_err(|e| ProtocolError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
    line.push('\n');
    w.write_all(line.as_bytes()).map_err(ProtocolError::Io)?;
    w.flush().map_err(ProtocolError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a request through [`write_message`] and decode it back through [`read_message`], the
    /// exact round trip the daemon and a client make across the socket.
    fn roundtrip_request(req: &Request) -> Request {
        let mut wire = Vec::new();
        write_message(&mut wire, req).expect("encode");
        read_message(&mut wire.as_slice())
            .expect("decode ok")
            .expect("a message, not EOF")
    }

    #[test]
    fn requests_round_trip_through_the_versioned_line_codec() {
        for req in [
            Request::Open {
                vcpus: Some(2),
                mem_mib: Some(512),
                wall_secs: Some(60),
                output_cap: None,
            },
            Request::Open {
                vcpus: None,
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
            },
            Request::Exec {
                argv: vec!["echo".into(), "hi".into()],
                stdin: Some("piped\n".into()),
            },
            Request::Put {
                path: "input.txt".into(),
                content: "hello\n".into(),
            },
            Request::Get {
                path: "out.txt".into(),
            },
            Request::Snapshot,
            Request::Trace,
            Request::TraceSummary,
            Request::Close,
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
            },
            Response::Snapshotted {
                dir: "/var/lib/agentd/snap-1".into(),
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
            },
        ] {
            let mut wire = Vec::new();
            write_message(&mut wire, &resp).expect("encode");
            let back: Response = read_message(&mut wire.as_slice())
                .expect("decode")
                .expect("a message");
            assert_eq!(back, resp);
        }
    }

    #[test]
    fn every_message_carries_the_schema() {
        // The stamp is present and legible on both directions of the wire.
        let mut req_wire = Vec::new();
        write_message(&mut req_wire, &Request::Close).expect("encode");
        assert_eq!(req_wire, b"{\"schema\":1,\"op\":\"close\"}\n");

        let mut resp_wire = Vec::new();
        write_message(&mut resp_wire, &Response::Closed).expect("encode");
        assert_eq!(resp_wire, b"{\"schema\":1,\"reply\":\"closed\"}\n");
    }

    #[test]
    fn a_wrong_schema_is_a_typed_error_before_the_body_is_trusted() {
        // A future/foreign schema is rejected as `Schema`, even when the body is an op we do know...
        assert!(matches!(
            read_message::<Request>(&mut b"{\"schema\":2,\"op\":\"close\"}\n".as_slice()),
            Err(ProtocolError::Schema(2))
        ));
        // ...and even when the body is a shape this version has never seen.
        assert!(matches!(
            read_message::<Request>(&mut b"{\"schema\":99,\"op\":\"teleport\"}\n".as_slice()),
            Err(ProtocolError::Schema(99))
        ));
        // A message with no schema at all is malformed, not silently accepted.
        assert!(matches!(
            read_message::<Request>(&mut b"{\"op\":\"close\"}\n".as_slice()),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn omitted_open_fields_default_to_none() {
        // A minimal `open` (no knobs) decodes, so a client can take every default.
        let req: Request = read_message(&mut b"{\"schema\":1,\"op\":\"open\"}\n".as_slice())
            .expect("decode")
            .expect("a message");
        assert_eq!(
            req,
            Request::Open {
                vcpus: None,
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
            }
        );
    }

    #[test]
    fn blank_lines_are_skipped_and_eof_is_none() {
        // Leading blank lines are tolerated; a stream with only whitespace is a clean EOF.
        let req: Request = read_message(&mut b"\n\n{\"schema\":1,\"op\":\"close\"}\n".as_slice())
            .expect("decode")
            .expect("a message past the blanks");
        assert_eq!(req, Request::Close);
        assert!(read_message::<Request>(&mut b"\n  \n".as_slice())
            .expect("decode")
            .is_none());
        assert!(read_message::<Request>(&mut b"".as_slice())
            .expect("decode")
            .is_none());
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
                    read_message::<Request>(&mut bad.as_bytes()),
                    Err(ProtocolError::Malformed(_))
                ),
                "{bad:?} should be a typed Malformed error"
            );
        }
    }

    #[test]
    fn an_overlong_line_is_rejected_before_allocating_unboundedly() {
        // A line that never terminates (no newline, past the cap) is a typed TooLarge, not an
        // unbounded read that grows host memory.
        let flood = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            read_message::<Request>(&mut flood.as_slice()),
            Err(ProtocolError::TooLarge)
        ));
    }
}
