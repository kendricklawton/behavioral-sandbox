#![no_main]
//! The raw frame codec (`tag · len · payload`) both directions share, the length-bound check that
//! keeps a lying header from driving a huge allocation.
//!
//! Two shapes per input, because the raw one cannot reach the whole decoder on its own: a `len`
//! taken straight from fuzz bytes is a random `u32`, so it fails the `MAX_PAYLOAD` bound for all
//! but ~0.02% of inputs and the payload read for all but ~0.0001%. The well-formed shape supplies
//! a matching header so mutation reaches the payload path instead of bouncing off two rejects.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A lying or truncated header: the bounds check and the short-read path.
    bsx_channel::fuzz::decode_frame(data);
    // A header that agrees with its payload: everything past the bounds check.
    bsx_channel::fuzz::decode_frame_wellformed(data);
});
