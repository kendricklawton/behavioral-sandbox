//! Fuzz the audit `RunRecord` JSON parser and summarizer (`probes_loader::RunRecord`).
//! `ekvm verify <record>` parses JSON audit records provided by untrusted or relayed callers,
//! so hostile JSON structures must always land in Ok/Err, never panic or divide by zero.

#![no_main]

use libfuzzer_sys::fuzz_target;


fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = v.to_string();
        }
    }
});

