//! Dependency-light fuzz-style property tests for the wire message reader, the in-gate half of this
//! crate's fuzzing (the deep, nightly `cargo fuzz` half lives in `fuzz/`).
//!
//! **Why here.** The daemon (`bsx serve`) reads these bytes off its unix socket from *any* client:
//! this is the outermost untrusted-input boundary the engine exposes, unlike the channel decoder,
//! which only sees a guest already contained inside a VM. A hostile or buggy peer must be
//! a typed [`ProtocolError`], never a host panic, hang, or leak. These tests assert exactly that: for
//! **any** input, the reader returns a value or a typed error, never panics, never loops unboundedly,
//! and never buffers past [`MAX_REQUEST_BYTES`](crate::MAX_REQUEST_BYTES).
//!
//! **No `proptest`/`arbitrary`.** This crate is a deliberately-thin leaf (serde only); rather than
//! pull a fuzzing framework into its tree, the generator is `bsx_test_support::Rng`, a workspace
//! leaf with an empty `[dependencies]`. Fixed seeds mean a failure reproduces exactly and the gate
//! never flakes. Valid messages are built with the crate's own `write_message`, so the generator
//! can't drift from the wire format.

use std::io::Cursor;

use bsx_test_support::Rng;
use serde_json::json;

use super::*;

/// A small valid-UTF-8 alphabet, including a JSON metacharacter, a quote, and a multibyte char, so
/// generated strings exercise serde's escaping without being invalid by construction.
const ALPHABET: &[char] = &['a', ' ', '\n', '"', '\\', '{', '}', '0', '/', 'é', '🦀'];

fn rand_string(rng: &mut Rng) -> String {
    let n = rng.below(10);
    (0..n)
        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
        .collect()
}

fn rand_request(rng: &mut Rng) -> Request {
    match rng.below(9) {
        0 => Request::Open(OpenParams {
            vcpus: Some(rng.byte()),
            mem_mib: Some(rng.next_u64() as u32),
            wall_secs: Some(rng.next_u64()),
            output_cap: if rng.below(2) == 0 {
                Some(rng.next_u64())
            } else {
                None
            },
            net: Some(rng.below(2) == 0),
            allow: if rng.below(2) == 0 {
                Some((0..rng.below(4)).map(|_| rand_string(rng)).collect())
            } else {
                None
            },
        }),
        1 => Request::Exec(ExecParams {
            argv: (0..rng.below(6)).map(|_| rand_string(rng)).collect(),
            stdin: if rng.below(2) == 0 {
                Some(rand_string(rng))
            } else {
                None
            },
            // `Some(vec![])` and `None` are distinct values that must both survive the round trip,
            // so generate the empty list as well as the absent field.
            env: if rng.below(2) == 0 {
                Some(
                    (0..rng.below(4))
                        .map(|_| (rand_string(rng), rand_string(rng)))
                        .collect(),
                )
            } else {
                None
            },
        }),
        2 => Request::Put(PutParams {
            path: rand_string(rng),
            content: rand_string(rng),
        }),
        3 => Request::Get(GetParams {
            path: rand_string(rng),
        }),
        4 => Request::Snapshot,
        5 => Request::Trace,
        6 => Request::TraceSummary,
        7 => Request::Cancel,
        _ => Request::Close,
    }
}

/// A random [`FaultKind`], including the untagged `Unknown` arm.
///
/// `Unknown`'s payload is prefixed so it can never spell a known variant's wire name. That is a
/// round-trip requirement, not neatness: `Unknown` is untagged, so `Unknown("guest")` serializes to
/// `"guest"` and decodes back as `Guest`, and `request_and_response_round_trip` asserts equality.
/// Today's `ALPHABET` cannot spell `guest` anyway, but that is an accident of the alphabet, and
/// widening it later must not resurrect a confusing intermittent failure.
fn rand_fault_kind(rng: &mut Rng) -> FaultKind {
    match rng.below(6) {
        0 => FaultKind::Infra,
        1 => FaultKind::Transport,
        2 => FaultKind::Guest,
        3 => FaultKind::Protocol,
        4 => FaultKind::Refused,
        _ => FaultKind::Unknown(format!("x-{}", rand_string(rng))),
    }
}

fn rand_response(rng: &mut Rng) -> Response {
    match rng.below(11) {
        0 => Response::opened(rng.next_u64(), rng.below(2) == 0),
        1 => Response::result(
            rng.next_u64() as i32,
            rand_string(rng),
            rand_string(rng),
            rng.next_u64(),
        ),
        2 => Response::got(
            rand_string(rng),
            rand_string(rng),
            rng.below(2) == 0,
            rng.below(2) == 0,
        ),
        3 => Response::trace(json!({"schema": 2, "n": rng.byte()})),
        4 => Response::snapshotted(rand_string(rng)),
        5 => Response::Closed,
        6 => Response::error(rand_string(rng), rng.below(2) == 0, rand_fault_kind(rng)),
        7 => Response::at_capacity(rng.next_u64()),
        8 => Response::Cancelled,
        9 => Response::trace_summary(json!({"schema": 1, "n": rng.byte()})),
        _ => Response::put(rand_string(rng)),
    }
}

/// Encode through the direction's own writer, so a generated message is bounded by exactly the cap
/// the matching reader will apply to it. Writing everything under the larger cap would let a request
/// between the two bounds encode and then fail its own round trip.
fn encode_request(req: &Request) -> Vec<u8> {
    let mut buf = Vec::new();
    write_request(&mut buf, req).expect("a generated request serializes under the request cap");
    buf
}

fn encode_response(resp: &Response) -> Vec<u8> {
    let mut buf = Vec::new();
    write_response(&mut buf, resp).expect("a generated response serializes under the response cap");
    buf
}

/// How many inputs each property explores. Parsing is cheap, so this stays in the milliseconds.
const ITERS: usize = 20_000;

/// The reader must return a `Result` for arbitrary bytes, never panic, never hang. Newlines are
/// injected so the framing (blank lines, multiple lines per buffer) is stressed, not just one blob.
#[test]
fn reader_never_panics_on_arbitrary_bytes() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..ITERS {
        let mut data = rng.bytes_upto(96);
        // Sprinkle newlines so the line splitter, not just the first-line decode, is exercised.
        for b in data.iter_mut() {
            if rng.below(8) == 0 {
                *b = b'\n';
            }
        }
        // Drained the way the daemon reads, so a recovered error is followed by the *next* message
        // rather than ending the run: stopping at the first error would leave the resync path, and
        // anything else only reachable past a refusal, unexplored.
        crate::drain_like_the_daemon(&mut Cursor::new(&data[..]), read_request);
        crate::drain_like_the_daemon(&mut Cursor::new(&data[..]), read_response);
    }
}

/// Encode then decode is the identity for every well-formed message: the writer and reader can't
/// silently disagree on the schema envelope or the tag.
#[test]
fn request_and_response_round_trip() {
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..4_000 {
        let req = rand_request(&mut rng);
        let buf = encode_request(&req);
        let mut cur = Cursor::new(&buf);
        assert_eq!(read_request(&mut cur).unwrap(), Some(req));

        let resp = rand_response(&mut rng);
        let buf = encode_response(&resp);
        let mut cur = Cursor::new(&buf);
        assert_eq!(read_response(&mut cur).unwrap(), Some(resp));
    }
}

/// Every truncation of a valid message line decodes to a typed error (or `None`) and never panics:
/// the "peer closed mid-message" path any client can force at will.
#[test]
fn truncations_of_valid_messages_never_panic() {
    let mut rng = Rng::new(0x0F0F_0F0F_1234_9999);
    for _ in 0..4_000 {
        let buf = encode_request(&rand_request(&mut rng));
        let cut = rng.below(buf.len());
        let mut cur = Cursor::new(&buf[..cut]);
        let _ = read_request(&mut cur);

        let buf = encode_response(&rand_response(&mut rng));
        let cut = rng.below(buf.len());
        let mut cur = Cursor::new(&buf[..cut]);
        let _ = read_response(&mut cur);
    }
}

/// A line past the cap is a typed `TooLarge` (an exactly-at-cap line is still legal), never an
/// unbounded buffer, the DoS a client can attempt by never sending a newline. `read_line_capped`
/// must refuse before `out` exceeds the cap.
#[test]
fn an_overlong_line_is_bounded_not_buffered() {
    // One byte past the cap with no newline: the reader must stop at the cap, not read it all in.
    let flood = vec![b'x'; MAX_REQUEST_BYTES + 1];
    let mut cur = Cursor::new(&flood);
    let mut out = Vec::new();
    let err = read_line_capped(&mut cur, MAX_REQUEST_BYTES, &mut out).unwrap_err();
    assert!(matches!(err, ProtocolError::TooLarge { .. }));
    assert!(
        out.len() <= MAX_REQUEST_BYTES,
        "buffered {} bytes, past the {MAX_REQUEST_BYTES} cap",
        out.len()
    );
}
