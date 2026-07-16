#![no_main]
//! The raw frame codec (`tag · len · payload`) both directions share — the length-bound check that
//! keeps a lying header from driving a huge allocation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    agent_channel::fuzz::decode_frame(data);
});
