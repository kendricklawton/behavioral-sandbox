//! Dependency-light fuzz-style property tests for the wire message reader, the in-gate half of this
//! crate's fuzzing (the deep, nightly `cargo fuzz` half lives in `fuzz/`; see
//! `docs/contributing-fuzzing.md`).
//!
//! **Why here.** The daemon (`agent serve`) reads these bytes off its unix socket from *any* client:
//! this is the outermost untrusted-input boundary the engine exposes, unlike the channel decoder,
//! which only sees a guest already contained inside a VM. Guardrail 5 says a hostile or buggy peer is
//! a typed [`ProtocolError`], never a host panic, hang, or leak. These tests assert exactly that: for
//! **any** input, the reader returns a value or a typed error, never panics, never loops unboundedly,
//! and never buffers past [`MAX_MESSAGE_BYTES`](crate::MAX_MESSAGE_BYTES).
//!
//! **No `proptest`/`arbitrary`.** This crate is a deliberately-thin leaf (serde only); rather than
//! pull a fuzzing framework into its tree, the generator is a tiny deterministic PRNG. Fixed seeds
//! mean a failure reproduces exactly and the gate never flakes. Valid messages are built with the
//! crate's own `write_message`, so the generator can't drift from the wire format.

use std::io::Cursor;

use serde_json::json;

use super::*;

/// A `xorshift64*` PRNG: deterministic, seedable, zero-dependency. Not cryptographic; it only sprays
/// varied bytes at the reader reproducibly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    fn bytes_upto(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max);
        self.bytes(len)
    }
}

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
    match rng.below(8) {
        0 => Request::Open {
            vcpus: Some(rng.byte()),
            mem_mib: Some(rng.next_u64() as u32),
            wall_secs: Some(rng.next_u64()),
            output_cap: None,
        },
        1 => Request::Exec {
            argv: (0..rng.below(6)).map(|_| rand_string(rng)).collect(),
            stdin: if rng.below(2) == 0 {
                Some(rand_string(rng))
            } else {
                None
            },
        },
        2 => Request::Put {
            path: rand_string(rng),
            content: rand_string(rng),
        },
        3 => Request::Get {
            path: rand_string(rng),
        },
        4 => Request::Snapshot,
        5 => Request::Trace,
        6 => Request::TraceSummary,
        _ => Request::Close,
    }
}

fn rand_response(rng: &mut Rng) -> Response {
    match rng.below(8) {
        0 => Response::Opened {
            boot_ms: rng.next_u64(),
            pooled: rng.below(2) == 0,
        },
        1 => Response::Result {
            exit_code: rng.next_u64() as i32,
            stdout: rand_string(rng),
            stderr: rand_string(rng),
            exec_wall_ms: rng.next_u64(),
        },
        2 => Response::Got {
            path: rand_string(rng),
            content: rand_string(rng),
            present: rng.below(2) == 0,
        },
        3 => Response::Trace {
            record: json!({"schema": 2, "n": rng.byte()}),
        },
        4 => Response::Snapshotted {
            dir: rand_string(rng),
        },
        5 => Response::Closed,
        6 => Response::Error {
            message: rand_string(rng),
            fatal: rng.below(2) == 0,
        },
        _ => Response::Put {
            path: rand_string(rng),
        },
    }
}

fn encode<T: serde::Serialize>(msg: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    write_message(&mut buf, msg).expect("a generated message serializes under the size cap");
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
        let mut cur = Cursor::new(&data);
        // Bounded drain: read until EOF or the first error, never looping unboundedly on garbage.
        while let Ok(Some(_)) = read_message::<Request>(&mut cur) {}
        let mut cur = Cursor::new(&data);
        while let Ok(Some(_)) = read_message::<Response>(&mut cur) {}
    }
}

/// Encode then decode is the identity for every well-formed message: the writer and reader can't
/// silently disagree on the schema envelope or the tag.
#[test]
fn request_and_response_round_trip() {
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..4_000 {
        let req = rand_request(&mut rng);
        let buf = encode(&req);
        let mut cur = Cursor::new(&buf);
        assert_eq!(read_message::<Request>(&mut cur).unwrap(), Some(req));

        let resp = rand_response(&mut rng);
        let buf = encode(&resp);
        let mut cur = Cursor::new(&buf);
        assert_eq!(read_message::<Response>(&mut cur).unwrap(), Some(resp));
    }
}

/// Every truncation of a valid message line decodes to a typed error (or `None`) and never panics:
/// the "peer closed mid-message" path any client can force at will.
#[test]
fn truncations_of_valid_messages_never_panic() {
    let mut rng = Rng::new(0x0F0F_0F0F_1234_9999);
    for _ in 0..4_000 {
        let buf = encode(&rand_request(&mut rng));
        let cut = rng.below(buf.len());
        let mut cur = Cursor::new(&buf[..cut]);
        let _ = read_message::<Request>(&mut cur);

        let buf = encode(&rand_response(&mut rng));
        let cut = rng.below(buf.len());
        let mut cur = Cursor::new(&buf[..cut]);
        let _ = read_message::<Response>(&mut cur);
    }
}

/// A line at or past the cap is a typed `TooLarge`, never an unbounded buffer, the DoS a client can
/// attempt by never sending a newline. `read_line_capped` must refuse before `out` exceeds the cap.
#[test]
fn an_overlong_line_is_bounded_not_buffered() {
    // One byte past the cap with no newline: the reader must stop at the cap, not read it all in.
    let flood = vec![b'x'; MAX_MESSAGE_BYTES + 1];
    let mut cur = Cursor::new(&flood);
    let mut out = Vec::new();
    let err = read_line_capped(&mut cur, MAX_MESSAGE_BYTES, &mut out).unwrap_err();
    assert!(matches!(err, ProtocolError::TooLarge));
    assert!(
        out.len() <= MAX_MESSAGE_BYTES,
        "buffered {} bytes, past the {MAX_MESSAGE_BYTES} cap",
        out.len()
    );
}
