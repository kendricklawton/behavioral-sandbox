//! `agent verify <record>`: check a signed audit record's `ed25519` signature (decision 034).
//!
//! Re-reads the canonical record bytes from the envelope and verifies them against a **trusted**
//! public key: the host's own by default, or one (or more) `--key <hex>` supplied out of band, so a
//! supervisor can verify a record **without trusting the host that relayed it**. Exit non-zero on any
//! mismatch (a tampered record, an untrusted signer, or a malformed envelope), the demo P19.3 asks for.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use agent_probes_loader::{verify, HostKey, TrustedKey};

use crate::config;
use crate::CliError;

/// `agent verify` arguments.
#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// The signed record file to check (as written by `agent run --record`).
    #[arg(value_name = "RECORD")]
    record: PathBuf,
    /// A trusted public key as 64 hex chars (a record's `key_id`), repeatable. Default: the host's
    /// own signing key (its public half), for records this host produced.
    #[arg(long = "key", value_name = "HEX")]
    keys: Vec<String>,
}

/// Verify the record file, printing the outcome and returning a non-zero exit on any failure.
pub fn run(args: VerifyArgs, file: Option<&config::AgentToml>) -> Result<ExitCode, CliError> {
    let envelope = std::fs::read_to_string(&args.record)
        .map_err(|e| CliError::Cli(format!("read {}: {e}", args.record.display())))?;

    let trusted = trusted_keys(&args, file)?;
    match verify(envelope.trim(), &trusted) {
        Ok(_record) => {
            let _ = writeln!(std::io::stdout(), "ok: {} verified", args.record.display());
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

/// The trusted key **set**: the union of explicit `--key` values, the configured trusted keys
/// (`AGENT_TRUSTED_KEYS` / `.agent.toml`, for rotation), and the host's own current signing key.
/// Trusting a set is what lets a record signed *before* a key rotation still verify (decision 034):
/// keep the old public key in the set and it stays valid. Everything reduces to `key_id` hex, so the
/// sources dedup cleanly.
fn trusted_keys(
    args: &VerifyArgs,
    file: Option<&config::AgentToml>,
) -> Result<Vec<TrustedKey>, CliError> {
    let mut hexes: Vec<String> = args.keys.clone();
    hexes.extend(config::trusted_key_hexes(file));
    // The host's own current key (its public half), if the file is present. A present-but-unreadable
    // key doesn't block an explicit `--key`/configured trust, so warn and skip rather than fail.
    let key_path = config::signing_key_path(file);
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
            "no trusted key: pass --key <hex>, set AGENT_TRUSTED_KEYS, or provide a signing key at {}",
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
