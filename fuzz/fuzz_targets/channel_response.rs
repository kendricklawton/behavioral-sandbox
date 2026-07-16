#![no_main]
//! The host reading a `Response` from the untrusted guest agent — the highest-value target: a
//! hostile guest chooses these bytes and the host parses them. The decoder must return a value or a
//! typed error for any input, never panic, hang, or over-allocate.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    agent_channel::fuzz::decode_response(data);
});
