//! Dependency-free fuzz-style property tests for the wire decoders, the in-gate half of the
//! channel's fuzzing (the deep, nightly `cargo fuzz` half lives in `fuzz/`; see
//! `docs/contributing-fuzzing.md`).
//!
//! **Why here.** The guest is untrusted, and a hostile guest fully controls the in-guest agent, so
//! the *host* decodes attacker-chosen bytes every time it reads a [`Response`](crate::Response).
//! Guardrail 5 says a broken channel is a typed error, never a host panic, hang, or leak. These
//! tests assert exactly that: for **any** input, the decoders return a value or a typed
//! [`ChannelError`], never panic, never loop unboundedly, and never allocate past
//! [`MAX_PAYLOAD`](crate::MAX_PAYLOAD).
//!
//! **Dependency-free on purpose.** `agent-channel` is dependency-free by design and the supply-chain
//! gate keeps a tight license allowlist, so rather than pull in `proptest`/`arbitrary` (and their
//! trees) as dev-dependencies, the generator is a tiny deterministic PRNG. Fixed seeds mean a
//! failure reproduces exactly and the gate never flakes.

use super::*;

/// A `xorshift64*` PRNG: deterministic, seedable, zero-dependency. Not cryptographic, it only has
/// to spray varied bytes at the decoders reproducibly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point for xorshift, so force it non-zero.
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

    /// A value in `0..n` (0 when `n == 0`, so callers never divide by zero).
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

    /// A byte vector of a random length in `0..max`, the two draws are sequenced so neither borrows
    /// `self` inside the other's call.
    fn bytes_upto(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max);
        self.bytes(len)
    }
}

/// Valid-UTF-8 alphabet with multibyte, control, and NUL chars, so generated strings exercise the
/// `String::from_utf8` and length-prefix paths without ever being invalid by construction.
const ALPHABET: &[char] = &[
    'a', 'z', ' ', '\n', '\t', '0', '/', '.', '-', 'é', '🦀', '\u{0}',
];

fn rand_string(rng: &mut Rng) -> String {
    let n = rng.below(12);
    (0..n)
        .map(|_| ALPHABET[rng.below(ALPHABET.len())])
        .collect()
}

/// How many inputs each property explores. Parsing is cheap, so this stays in the milliseconds while
/// covering far more shapes than the hand-written unit tests.
const ITERS: usize = 20_000;

/// Every host-visible decoder must return a `Result` for arbitrary bytes, never panic, never hang.
/// Short inputs are deliberate: they stress the fixed-size header and mid-field EOF edges.
#[test]
fn decoders_never_panic_on_arbitrary_bytes() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..ITERS {
        let data = rng.bytes_upto(64);
        let _ = read_response(&mut data.as_slice());
        let _ = read_request(&mut data.as_slice());
        let _ = read_handshake(&mut data.as_slice());
        // Any accepted frame's payload is bounded, so a lying length header can't drive a huge alloc.
        if let Ok((_tag, payload)) = read_frame(&mut data.as_slice()) {
            assert!(payload.len() <= MAX_PAYLOAD);
        }
    }
}

/// Wrap a body in a well-formed frame header (`tag · len · body`) so the fuzzer gets *past* the
/// header and into the body parsers (`Body::u32`/`blob`/`string`, the count loops) instead of
/// bouncing off the length check.
fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + body.len());
    v.push(tag);
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(body);
    v
}

/// Well-framed frames with random bodies reach the message-body parsers. This is where a lying
/// inner count (a huge `argc`/`envc`) or a blob length past the body would bite: the decoders must
/// run the bounded body dry and error, never pre-size from the count or loop forever.
#[test]
fn decoders_never_panic_on_well_framed_random_bodies() {
    let mut rng = Rng::new(0xD1B5_4A32_D192_ED03);
    let tags = [
        TAG_EXEC,
        TAG_PUTFILE,
        TAG_STDOUT,
        TAG_STDERR,
        TAG_FILE,
        TAG_EXIT,
        TAG_TIMEDOUT,
        TAG_ERROR,
        0,
        255,
    ];
    for _ in 0..ITERS {
        let tag = tags[rng.below(tags.len())];
        let body = rng.bytes_upto(256);
        let frame = framed(tag, &body);
        let _ = read_request(&mut frame.as_slice());
        let _ = read_response(&mut frame.as_slice());
    }
}

fn rand_request(rng: &mut Rng) -> Request {
    // Only the two sendable variants, `Unknown` is decode-only (`write_request` rejects it).
    if rng.below(2) == 0 {
        Request::PutFile {
            path: rand_string(rng),
            data: rng.bytes_upto(64),
        }
    } else {
        let argv = (0..rng.below(8)).map(|_| rand_string(rng)).collect();
        let env = (0..rng.below(4))
            .map(|_| (rand_string(rng), rand_string(rng)))
            .collect();
        let artifacts = (0..rng.below(4)).map(|_| rand_string(rng)).collect();
        Request::Exec {
            argv,
            stdin: rng.bytes_upto(64),
            env,
            artifacts,
            timeout_ms: rng.next_u64() as u32,
        }
    }
}

fn rand_response(rng: &mut Rng) -> Response {
    match rng.below(6) {
        0 => Response::Stdout(rng.bytes_upto(64)),
        1 => Response::Stderr(rng.bytes_upto(64)),
        2 => Response::File {
            path: rand_string(rng),
            data: rng.bytes_upto(64),
        },
        3 => Response::Exit {
            code: rng.next_u64() as i32,
        },
        4 => Response::TimedOut {
            elapsed_ms: rng.next_u64() as u32,
        },
        _ => Response::Error(rand_string(rng)),
    }
}

/// Encode then decode is the identity for every well-formed message, the encoder and decoder can't
/// silently disagree on the framing.
#[test]
fn request_and_response_encode_decode_round_trip() {
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..4_000 {
        let req = rand_request(&mut rng);
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();
        assert_eq!(read_request(&mut buf.as_slice()).unwrap(), req);

        let resp = rand_response(&mut rng);
        let mut buf = Vec::new();
        write_response(&mut buf, &resp).unwrap();
        let decoded = read_response(&mut buf.as_slice()).unwrap();
        match resp {
            // `Response::Error` decodes through `sanitize_error_msg` (control chars escaped, length
            // capped) since it reaches the operator's terminal unquoted, so the round-trip identity
            // is the *sanitized* message, not the raw one.
            Response::Error(s) => assert_eq!(decoded, Response::Error(sanitize_error_msg(&s))),
            other => assert_eq!(decoded, other),
        }
    }
}

/// Every truncation of a valid frame decodes to a typed error (or, for a zero-length body, a value)
/// and never panics, the "peer closed mid-frame" path a hostile guest can force at will.
#[test]
fn truncations_of_valid_frames_never_panic() {
    let mut rng = Rng::new(0x0F0F_0F0F_1234_9999);
    for _ in 0..4_000 {
        let mut buf = Vec::new();
        write_request(&mut buf, &rand_request(&mut rng)).unwrap();
        let cut = rng.below(buf.len());
        let _ = read_request(&mut &buf[..cut]);

        let mut buf = Vec::new();
        write_response(&mut buf, &rand_response(&mut rng)).unwrap();
        let cut = rng.below(buf.len());
        let _ = read_response(&mut &buf[..cut]);
    }
}
