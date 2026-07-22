//! Fuzz the daemon's untrusted-client wire: `read_message` over the newline-JSON protocol. `agent
//! serve` decodes exactly these bytes off its unix socket from *any* client, the outermost
//! untrusted-input boundary the engine exposes (unlike the channel decoder, which only sees a guest
//! already contained inside a VM). Hostile bytes here must always land in a value or a typed
//! `ProtocolError`, never a panic, hang, or unbounded buffer (guardrail 5).

#![no_main]

use agent_protocol::fuzz::{read_requests, read_responses};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The daemon reads `Request`s (the high-value path); a client reads `Response`s. Drive both:
    // each drains the buffer message-by-message, exercising the line splitter, the schema gate, and
    // the bounded line reader on whatever framing the input implies.
    read_requests(data);
    read_responses(data);
});
