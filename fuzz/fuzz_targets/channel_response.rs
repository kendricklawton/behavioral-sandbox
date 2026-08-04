#![no_main]
//! The host reading a `Response` from the untrusted guest agent, the highest-value target: a
//! hostile guest chooses these bytes and the host parses them. The decoder must return a value or a
//! typed error for any input, never panic, hang, or over-allocate.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Raw bytes: the frame gate's reject branches.
    ekvm_channel::fuzz::decode_response(data);
    // A frame whose len header matches its payload: mutation reaches the per-tag Body parsing,
    // which a raw mutation almost never does (an insert or delete falsifies the len header).
    ekvm_channel::fuzz::decode_response_wellformed(data);
});
