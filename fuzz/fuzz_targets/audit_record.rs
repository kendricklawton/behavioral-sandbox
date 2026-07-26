//! Fuzz the canonical-record leg of the signing envelope: `HostKey::sign_canonical` /
//! `sign_canonical_chained` → `verify` / `verify_chain` must round-trip **any** record text
//! byte-for-byte (the record rides inside the envelope as a JSON-escaped string, so an escaping
//! bug would corrupt or forge the audit trail), and `record_hash` must never panic. Complements
//! `signing_envelope`, which fuzzes hostile *envelope* input; this fuzzes arbitrary *record*
//! content through the real construct-then-parse cycle.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use probes_loader::{record_hash, verify, verify_chain, HostKey, TrustedKey};

/// One deterministic key (the unit tests' seed) so per-iteration cost is one sign + one verify,
/// not a keygen.
fn key() -> &'static HostKey {
    static KEY: OnceLock<HostKey> = OnceLock::new();
    KEY.get_or_init(|| HostKey::from_seed([7u8; 32]))
}

fn trusted() -> &'static [TrustedKey] {
    static TRUSTED: OnceLock<Vec<TrustedKey>> = OnceLock::new();
    TRUSTED.get_or_init(|| vec![key().verifying_key()])
}

fuzz_target!(|data: &[u8]| {
    // The canonical record is a text surface; non-UTF-8 never reaches the signer.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // Stay far enough under MAX_ENVELOPE_BYTES that even worst-case JSON escaping (6 bytes per
    // input byte) cannot trip the size refusal; oversize refusal is signing_envelope's territory.
    if s.len() > 1024 * 1024 {
        return;
    }

    let hash = record_hash(s);

    let envelope = key().sign_canonical(s);
    match verify(&envelope, trusted()) {
        Ok(record) => assert_eq!(record, s, "sign→verify must round-trip the record verbatim"),
        Err(e) => panic!("a freshly signed record must verify: {e}"),
    }

    let chained = key().sign_canonical_chained(s, Some(&hash));
    match verify_chain(&[&envelope, &chained], trusted()) {
        Ok(records) => assert_eq!(records, [s, s], "chain must round-trip both records"),
        Err(e) => panic!("a freshly signed chain must verify: {e}"),
    }
});
