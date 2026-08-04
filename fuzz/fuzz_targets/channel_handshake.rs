#![no_main]
//! The handshake decoder, the first bytes off a fresh connection, before any framed message. The
//! host validates a guest-chosen magic + version here, so like the other decoders it must return a
//! value or a typed error for any input, never panic. Low surface (a fixed 6-byte read), fuzzed for
//! parity so every exposed `ekvm_channel::fuzz::decode_*` entry point has a deep target.
//!
//! Two shapes per input. Raw bytes match the 4-byte magic with probability 2^-32, so on their own
//! they only ever exercise the bad-magic and short-read rejects; the magic-prefixed shape is what
//! makes the version check and the accept path reachable by mutation at all.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Wrong or truncated magic: the reject paths.
    ekvm_channel::fuzz::decode_handshake(data);
    // Correct magic, fuzzed version bytes: the version check and the accept path.
    ekvm_channel::fuzz::decode_handshake_after_magic(data);
});
