//! `bsx verify` on a **chain file**: one envelope per line, the shape a daemon client saves its
//! `trace` replies in (each reply commits to the previous one's hash). Host-safe: signing and
//! verification are pure key operations, no VM, no KVM, so this runs in the everyday gate.
// A test binary: `panic!`/`expect` is the idiomatic assertion, which the workspace's
// `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use bsx_probes_loader::{HostKey, record_hash};

/// A scratch dir for the chain file, removed on drop; also the spawn cwd and the spawned process's
/// `$HOME`, so neither a `.bsx.toml` higher up the tree nor the developer's own user config can leak
/// configuration (a `trusted_keys` entry above all) into the run.
struct ChainDir(PathBuf);

impl ChainDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bsx-chain-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
        Self(dir)
    }
}

impl Drop for ChainDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Three chained envelopes from a fixed-seed key, exactly as a daemon session signs its `trace`
/// replies: the first unchained, each next committing to its predecessor's hash.
fn chain_of_three(key: &HostKey) -> [String; 3] {
    let records = [
        r#"{"schema":1,"n":1}"#,
        r#"{"schema":1,"n":2}"#,
        r#"{"schema":1,"n":3}"#,
    ];
    let e0 = key.sign_canonical_chained(records[0], None);
    let e1 = key.sign_canonical_chained(records[1], Some(&record_hash(records[0])));
    let e2 = key.sign_canonical_chained(records[2], Some(&record_hash(records[1])));
    [e0, e1, e2]
}

/// Run `bsx verify <file> --key <hex>` from `dir`, returning `(exit_code, stdout, stderr)`.
fn verify_in(dir: &ChainDir, file: &Path, key_hex: &str) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bsx"))
        .arg("verify")
        .arg(file)
        .args(["--key", key_hex])
        .current_dir(&dir.0)
        .env("HOME", &dir.0)
        .output()
        .unwrap_or_else(|e| panic!("spawn bsx verify: {e}"));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_chain_file_verifies_and_a_reordered_or_tampered_one_fails() {
    let key = HostKey::from_seed([7u8; 32]);
    let hex = key.key_id();
    let dir = ChainDir::new("roundtrip");
    let [e0, e1, e2] = chain_of_three(&key);

    // The intact sequence, one envelope per line, verifies as a chain.
    let good = dir.0.join("session.jsonl");
    std::fs::write(&good, format!("{e0}\n{e1}\n{e2}\n")).unwrap_or_else(|e| panic!("write: {e}"));
    let (code, stdout, stderr) = verify_in(&dir, &good, &hex);
    assert_eq!(code, Some(0), "an intact chain verifies: {stderr}");
    assert!(
        stdout.contains("3 records") && stdout.contains("chain"),
        "the ok line says what was proven (a chain of 3, not one record): {stdout}"
    );

    // Reordered: the same three valid envelopes out of order must fail, which is the whole point
    // of the chain (each record alone still carries a valid signature).
    let reordered = dir.0.join("reordered.jsonl");
    std::fs::write(&reordered, format!("{e0}\n{e2}\n{e1}\n"))
        .unwrap_or_else(|e| panic!("write: {e}"));
    let (code, _, stderr) = verify_in(&dir, &reordered, &hex);
    assert_eq!(code, Some(1), "a reordered chain must fail");
    assert!(
        stderr.contains("FAILED") && stderr.contains("chain"),
        "the failure names the chain break: {stderr}"
    );

    // Tampered: one flipped character inside the middle record's content. The record rides in the
    // envelope as an embedded JSON string, so its quotes are escaped there (`\"n\":2`), and the
    // pattern must match that escaped form; the assert guards against a no-op "tamper" that would
    // let this case pass by verifying an untouched chain.
    let tampered_line = e1.replace("\\\"n\\\":2", "\\\"n\\\":9");
    assert_ne!(tampered_line, e1, "the tamper must actually change bytes");
    let tampered = dir.0.join("tampered.jsonl");
    std::fs::write(&tampered, format!("{e0}\n{tampered_line}\n{e2}\n"))
        .unwrap_or_else(|e| panic!("write: {e}"));
    let (code, _, stderr) = verify_in(&dir, &tampered, &hex);
    assert_eq!(code, Some(1), "a tampered record must fail");
    assert!(stderr.contains("FAILED"), "{stderr}");

    // A dropped record: e1 missing, so e2's prev no longer matches its predecessor.
    let dropped = dir.0.join("dropped.jsonl");
    std::fs::write(&dropped, format!("{e0}\n{e2}\n")).unwrap_or_else(|e| panic!("write: {e}"));
    let (code, _, stderr) = verify_in(&dir, &dropped, &hex);
    assert_eq!(
        code,
        Some(1),
        "a chain with a dropped record must fail: {stderr}"
    );
}

#[test]
fn a_single_envelope_file_still_verifies_as_before() {
    // One line stays single-record verification, byte for byte the same code path a `--record`
    // file takes.
    let key = HostKey::from_seed([7u8; 32]);
    let dir = ChainDir::new("single");
    let one = dir.0.join("run.json");
    std::fs::write(&one, key.sign_canonical(r#"{"schema":1,"n":1}"#) + "\n")
        .unwrap_or_else(|e| panic!("write: {e}"));
    let (code, stdout, stderr) = verify_in(&dir, &one, &key.key_id());
    assert_eq!(code, Some(0), "a single envelope verifies: {stderr}");
    assert!(stdout.contains("verified"), "{stdout}");
}
