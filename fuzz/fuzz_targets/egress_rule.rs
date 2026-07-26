//! Fuzz the network egress rule parser: `parse_allow` (which wraps `Ipv4Cidr::new`).
//! `--allow IP[/CIDR][:PORT][/PROTO]` parses user/CLI inputs, so hostile strings here must
//! always return Ok/Err, never panic or overflow.

#![no_main]

use ekvm::policy::parse_allow;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_allow(s);
    }
});
