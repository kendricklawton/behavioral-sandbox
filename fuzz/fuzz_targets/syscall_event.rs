//! Fuzz the shared eBPF-boundary parsers: `SyscallEvent::from_bytes` (the ring-buffer record) and
//! `parse_ipv4_5tuple` (an Ethernet frame off the tap). The record is kernel-written, so it is
//! defense in depth, but `parse_ipv4_5tuple` reads a **guest-crafted** frame: attacker bytes. Either
//! must be a value-or-`None`, and the string-building accessors must clamp on an attacker-influenced
//! `detail_len`, never panic or read past the buffer (guardrail 5).

#![no_main]

use kee_probes_common::{parse_ipv4_5tuple, SyscallEvent};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(ev) = SyscallEvent::from_bytes(data) {
        // The formatting helpers build owned strings from the parsed (attacker-shaped) bytes.
        let _ = ev.detail();
        let _ = ev.describe();
        let _ = ev.comm_lossy();
    }
    let _ = parse_ipv4_5tuple(data);
});
