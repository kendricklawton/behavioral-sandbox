#![no_main]
//! The guest agent reading a `Request` from the host. The host is trusted, so this is defense in
//! depth, but the guest-side parser must be just as unpanicky on any bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Raw bytes: the frame gate's reject branches.
    ekvm_channel::fuzz::decode_request(data);
    // A frame whose len header matches its payload: mutation reaches the per-tag Body parsing
    // (nested counts, strings, blobs), which a raw mutation almost never does, since any insert
    // or delete falsifies the len header and dies at the gate.
    ekvm_channel::fuzz::decode_request_wellformed(data);
});
