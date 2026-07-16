#![no_main]
//! The guest agent reading a `Request` from the host. The host is trusted, so this is defense in
//! depth, but the guest-side parser must be just as unpanicky on any bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    agent_channel::fuzz::decode_request(data);
});
