#![no_main]
//! The handshake decoder, the first bytes off a fresh connection, before any framed message. The
//! host validates a guest-chosen magic + version here, so like the other decoders it must return a
//! value or a typed error for any input, never panic. Low surface (a fixed 6-byte read), fuzzed for
//! parity so every exposed `agent_channel::fuzz::decode_*` entry point has a deep target.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    agent_channel::fuzz::decode_handshake(data);
});
