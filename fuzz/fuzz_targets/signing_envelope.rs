//! Fuzz the signed-record envelope surface: `verify`, `verify_chain` (input split on newlines),
//! and `TrustedKey::from_hex`. The envelope is attacker-relayed by design (a verifier checks a
//! record without trusting the host that delivered it, decision 034), so hostile bytes here must
//! always land in `Ok`/`Err`, never a panic.

#![no_main]

use std::sync::OnceLock;

use kee_probes_loader::{verify, verify_chain, HostKey, TrustedKey};
use libfuzzer_sys::fuzz_target;

/// A fixed trusted set (the unit tests' deterministic key) so per-iteration cost stays low and a
/// mutation of a genuinely signed corpus entry can reach the signature-check paths.
fn trusted() -> &'static [TrustedKey] {
    static TRUSTED: OnceLock<Vec<TrustedKey>> = OnceLock::new();
    TRUSTED.get_or_init(|| vec![HostKey::from_seed([7u8; 32]).verifying_key()])
}

fuzz_target!(|data: &[u8]| {
    // The envelope is a text surface; non-UTF-8 never reaches the parser.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = verify(s, trusted());
    let lines: Vec<&str> = s.lines().collect();
    let _ = verify_chain(&lines, trusted());
    let _ = TrustedKey::from_hex(s);
});
