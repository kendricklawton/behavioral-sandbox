//! `bsx verify <record>`: check a signed audit record's `ed25519` signature.
//!
//! Re-reads the canonical record bytes from the envelope and verifies them against a **trusted**
//! public key: the host's own by default, or one (or more) `--key <hex>` supplied out of band, so a
//! supervisor can verify a record **without trusting the host that relayed it**. Exit non-zero on any
//! mismatch (a tampered record, an untrusted signer, or a malformed envelope).
//!
//! The file's shape picks the check. One line is a single envelope; several lines are a **session chain**,
//! one envelope per line in order, where each commits to the previous one's hash. [`verify_chain`]
//! therefore also rejects a reordered, inserted, or dropped record, which per-envelope signatures cannot
//! see: every record in a reordered chain still carries a valid signature.

use std::io::Read as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use bsx_record::{HostKey, MAX_ENVELOPE_BYTES, TrustedKey, verify, verify_chain};

use crate::CliError;
use crate::config;

/// `bsx verify` arguments.
#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// The signed record file to check (as written by `bsx run --record`).
    #[arg(value_name = "RECORD")]
    record: PathBuf,
    /// A trusted public key as 64 hex chars (a record's `key_id`), repeatable. Default: the host's
    /// own signing key (its public half), for records this host produced.
    #[arg(long = "key", value_name = "HEX")]
    keys: Vec<String>,
}

/// Verify the record file, printing the outcome and returning a non-zero exit on any failure.
pub fn run(args: VerifyArgs, sources: &config::Sources) -> Result<ExitCode, CliError> {
    let content = read_bounded(&args.record)?;
    let trusted = trusted_keys(&args, sources)?;

    // One non-empty line is a single envelope; several are a session chain in file order. The
    // per-envelope size bound stays enforced inside the record crate either way
    // (`VerifyError::TooLarge`); `read_bounded` bounds the whole file.
    let envelopes: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let outcome: Result<String, String> = match envelopes.as_slice() {
        [] => Err("empty file; not a signed record".to_string()),
        [one] => verify(one, &trusted)
            .map(|_record| "verified".to_string())
            .map_err(|e| e.to_string()),
        chain => verify_chain(chain, &trusted)
            .map(|records| format!("verified: {} records, unbroken chain", records.len()))
            .map_err(|e| e.to_string()),
    };
    match outcome {
        Ok(what) => {
            let _ = writeln!(std::io::stdout(), "ok: {} {what}", args.record.display());
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            // A rejected record is a real, expected outcome (the demo flips a byte), so report it
            // plainly on stderr and exit non-zero, not as an operational `Err`.
            let _ = writeln!(std::io::stderr(), "FAILED: {}: {e}", args.record.display());
            Ok(ExitCode::from(1))
        }
    }
}

/// The most bytes this reads from a record **file**, as distinct from [`MAX_ENVELOPE_BYTES`], which
/// bounds **one** envelope: a session chain is one envelope per line, so a long session legitimately
/// exceeds the per-envelope bound while every envelope in it stays inside it. A memory bound on the
/// verifying host, not a claim about chain length, since [`verify_chain`] checks the sequence as a
/// unit and so the whole file is read at once.
const MAX_RECORD_FILE_BYTES: usize = 16 * MAX_ENVELOPE_BYTES;

/// Conflating the two bounds is the defect this constant exists to keep fixed: a chain is one
/// envelope per line, so the file bound must exceed the envelope bound. A compile error rather than a
/// test, since nothing here is worth deferring to run time.
const _: () = assert!(MAX_RECORD_FILE_BYTES > MAX_ENVELOPE_BYTES);

/// Read the record file, stopping at [`MAX_RECORD_FILE_BYTES`] rather than swallowing an arbitrarily
/// large file. The **per-envelope** bound stays where it belongs, inside `verify`.
fn read_bounded(path: &std::path::Path) -> Result<String, CliError> {
    read_bounded_to(path, MAX_RECORD_FILE_BYTES)
}

/// [`read_bounded`] against an explicit limit, so the boundary is testable without a file the size of
/// the real one. Length is checked on bytes, before UTF-8 conversion, so an over-bound file reads as
/// "too large" rather than a misleading encoding error.
fn read_bounded_to(path: &std::path::Path, limit: usize) -> Result<String, CliError> {
    let file = std::fs::File::open(path)
        .map_err(|e| CliError::Cli(format!("read {}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CliError::Cli(format!("read {}: {e}", path.display())))?;
    if bytes.len() > limit {
        return Err(CliError::Cli(format!(
            "{}: larger than the {limit}-byte bound on a record file (a single record, or a session \
             chain of one record per line)",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| {
        CliError::Cli(format!(
            "{}: not UTF-8; not a signed record",
            path.display()
        ))
    })
}

/// The trusted key **set**: the union of explicit `--key` values, the configured trusted keys
/// (`BSX_TRUSTED_KEYS` / `.bsx.toml`), and the host's own current signing key. A set rather than one
/// key is what lets a record signed *before* a rotation still verify. Everything reduces to `key_id`
/// hex, so the sources dedup cleanly.
fn trusted_keys(args: &VerifyArgs, sources: &config::Sources) -> Result<Vec<TrustedKey>, CliError> {
    let mut hexes: Vec<String> = args.keys.clone();
    hexes.extend(config::trusted_key_hexes(sources));
    // The host's own current key (its public half), if the file is present. A present-but-unreadable
    // key doesn't block an explicit `--key`/configured trust, so warn and skip rather than fail.
    let key_path = config::signing_key_path(sources);
    if key_path.exists() {
        match HostKey::open(&key_path) {
            Ok(hk) => hexes.push(hk.key_id()),
            Err(e) => tracing::warn!(
                path = %key_path.display(),
                error = %e,
                "signing key present but unreadable; not adding it to the trusted set"
            ),
        }
    }
    hexes.sort();
    hexes.dedup();
    if hexes.is_empty() {
        return Err(CliError::Cli(format!(
            "no trusted key: pass --key <hex>, set BSX_TRUSTED_KEYS, or provide a signing key at {}",
            key_path.display()
        )));
    }
    hexes
        .iter()
        .map(|h| {
            TrustedKey::from_hex(h).map_err(|e| CliError::Cli(format!("trusted key {h}: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_bound_admits_its_limit_and_names_a_record_file_past_it() {
        let scratch = bsx_test_support::ScratchDir::created("verify-bound");
        let path = scratch.path().join("record.jsonl");

        std::fs::write(&path, "x".repeat(8)).expect("write a file at the limit");
        assert_eq!(
            read_bounded_to(&path, 8)
                .expect("exactly the limit is admitted, not refused")
                .len(),
            8
        );

        std::fs::write(&path, "x".repeat(9)).expect("write a file past the limit");
        let msg = read_bounded_to(&path, 8)
            .expect_err("one byte past the limit is refused")
            .to_string();
        assert!(
            msg.contains("record file"),
            "the refusal names what was too big, not `not a signed record`: {msg}"
        );
    }
}
