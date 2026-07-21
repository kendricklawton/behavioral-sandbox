//! Record integrity: an `ed25519` **detached** signature over the canonical audit-record bytes, so a
//! consumer can detect **post-hoc alteration** of a stored or transmitted record without trusting the
//! host, operator, or transport that relayed it (decision 034). The signing key is **host-side**: the
//! guest never sees it, exactly like the eBPF probes it complements.
//!
//! **What is signed.** The exact bytes of [`RunRecord::to_json`](crate::RunRecord) (the deterministic
//! JSON of decision 024). Because those bytes are byte-stable, a verifier reconstructs the signed
//! message exactly, so a single flipped byte fails the check.
//!
//! **The envelope.** Signing wraps the record in a schema-2 delivery surface:
//! `{"schema":2,"key_id":"<hex>","signature":"<hex>","record":"<canonical record JSON>"}`. The record
//! rides as an **embedded string**, not a nested object, on purpose: a string value survives a
//! `serde` round-trip byte-for-byte (the wire `trace` reply re-serializes the envelope), where a
//! re-parsed nested object would not, and the signed bytes must not change in flight. `schema` here is
//! the *delivery* surface (v1 was the bare record; v2 is this envelope); the record keeps its own
//! `schema` inside the string ([`AUDIT_SCHEMA_VERSION`](crate::AUDIT_SCHEMA_VERSION)).
//!
//! **The session hash-chain.** A record can also commit to the previous one: a chained envelope adds
//! a `prev` field (the [`record_hash`] of the prior record) and signs `prev + "\n" + canonical`, so a
//! *sequence* is tamper-evident as a whole, [`verify_chain`] rejects a reordered, inserted, or
//! deleted record, not just a single-record edit. Off for a one-shot run (no `prev`, identical to the
//! single-record envelope); on for a session, which threads the chain across its records. (Truncating
//! the *tail* of a chain is undetectable without an external anchor, the append-only limitation.)
//!
//! **The boundary (decision 034).** The trust root is the host signing key. This detects alteration
//! *after* the producing host; it does **not** protect against a fully-compromised host, which can
//! sign a consistent lie. Key custody and rotation are the hoster's; this module only signs with a
//! given key and verifies against a trusted set, keyed by `key_id`.

use std::fmt;
use std::fmt::Write as _;
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::path::PathBuf;

use ed25519_dalek::Signature;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use sha2::Digest as _;
use sha2::Sha256;

use crate::RunRecord;

/// The version of the **signed delivery surface**: the `schema` field of the signature envelope. v1
/// was the bare record; v2 wraps it in `{schema, key_id, signature, record}`. A consumer reads this to
/// know it is holding a signed envelope; the record inside carries its own
/// [`AUDIT_SCHEMA_VERSION`](crate::AUDIT_SCHEMA_VERSION).
pub const SIGNED_RECORD_SCHEMA_VERSION: u32 = 2;

/// A host signing key (an `ed25519` keypair). Held host-side; the guest never sees it. Sign a record
/// to produce the envelope; hand [`verifying_key`](Self::verifying_key) to [`verify`] as a trusted key.
pub struct HostKey {
    signing: SigningKey,
}

impl fmt::Debug for HostKey {
    /// Never print the secret; the `key_id` (public) identifies the key in logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl HostKey {
    /// Build a key from a 32-byte `ed25519` seed (the secret scalar's seed).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Load the host key from `path`, or **generate and persist** one there on first use (seed from
    /// `/dev/urandom`, written `0600`, parent dirs created). The generate-on-first-run path is why a
    /// hoster needs no key ceremony to get a signed record; custody of the file is theirs.
    ///
    /// # Errors
    /// [`KeyError`] if the file exists but is unreadable or malformed, or if generation/persist fails.
    pub fn load_or_generate(path: &Path) -> Result<Self, KeyError> {
        if path.exists() {
            Self::load(path)
        } else {
            let key = Self::from_seed(random_seed()?);
            key.persist(path)?;
            Ok(key)
        }
    }

    /// Load an **existing** host key from `path`, without generating one (unlike
    /// [`load_or_generate`](Self::load_or_generate)). For verification, which trusts a key that must
    /// already exist rather than minting a fresh, useless one.
    ///
    /// # Errors
    /// [`KeyError`] if the file is missing, unreadable, or malformed.
    pub fn open(path: &Path) -> Result<Self, KeyError> {
        Self::load(path)
    }

    /// Load a key from a hex-seed file.
    fn load(path: &Path) -> Result<Self, KeyError> {
        let text = std::fs::read_to_string(path).map_err(KeyError::Io)?;
        let mut seed = [0u8; 32];
        hex_decode(text.trim(), &mut seed).map_err(|()| {
            KeyError::Malformed("signing-key file is not a 32-byte hex seed".into())
        })?;
        Ok(Self::from_seed(seed))
    }

    /// Persist the secret seed as hex, `0600`, creating parent dirs. Only called on first-run
    /// generation, so it never widens an existing file's permissions.
    fn persist(&self, path: &Path) -> Result<(), KeyError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(KeyError::Io)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(KeyError::Io)?;
        let mut hex = hex_encode(&self.signing.to_bytes());
        hex.push('\n');
        f.write_all(hex.as_bytes()).map_err(KeyError::Io)
    }

    /// The public verifying key: hand this to [`verify`] as a trusted key.
    #[must_use]
    pub fn verifying_key(&self) -> TrustedKey {
        TrustedKey(self.signing.verifying_key())
    }

    /// The key's identifier: the hex of its public key. Records name it so a verifier can select the
    /// right trusted key, and so a rotated key (a new `key_id`) doesn't invalidate older records.
    #[must_use]
    pub fn key_id(&self) -> String {
        self.verifying_key().key_id()
    }

    /// Sign a finalized record (unchained): canonicalize it ([`RunRecord::to_json`]) and wrap it in
    /// the signature envelope. The returned string is the schema-2 delivery surface.
    #[must_use]
    pub fn sign_record(&self, record: &RunRecord) -> String {
        self.sign_canonical_chained(&record.to_json(), None)
    }

    /// Sign a record as the next link in a session chain: it commits to `prev` (the [`record_hash`] of
    /// the previous record in the session) so reordering, inserting, or deleting a record in the
    /// sequence is detectable ([`verify_chain`]). `prev` is `None` for the first record in a session
    /// (an unchained anchor, byte-identical to [`sign_record`](Self::sign_record)).
    #[must_use]
    pub fn sign_record_chained(&self, record: &RunRecord, prev: Option<&str>) -> String {
        self.sign_canonical_chained(&record.to_json(), prev)
    }

    /// Sign already-canonical record bytes (unchained), returning the envelope. The signed message is
    /// `canonical` verbatim; verification re-reads it from the envelope's `record` string.
    #[must_use]
    pub fn sign_canonical(&self, canonical: &str) -> String {
        self.sign_canonical_chained(canonical, None)
    }

    /// Sign already-canonical record bytes, optionally chained to `prev`. With `prev`, the signed
    /// message is `prev + "\n" + canonical` and the envelope carries a `prev` field; without it, the
    /// message is `canonical` and no `prev` appears (so unchained envelopes stay byte-identical).
    #[must_use]
    pub fn sign_canonical_chained(&self, canonical: &str, prev: Option<&str>) -> String {
        let signature: Signature = match prev {
            Some(p) => self.signing.sign(link_message(p, canonical).as_bytes()),
            None => self.signing.sign(canonical.as_bytes()),
        };
        let sig_hex = hex_encode(&signature.to_bytes());
        let mut out = String::with_capacity(canonical.len() + 320);
        out.push_str("{\"schema\":");
        let _ = write!(out, "{SIGNED_RECORD_SCHEMA_VERSION}");
        out.push_str(",\"key_id\":\"");
        out.push_str(&self.key_id());
        out.push_str("\",\"signature\":\"");
        out.push_str(&sig_hex);
        out.push('"');
        if let Some(p) = prev {
            // `prev` is 64 hex chars (no JSON metacharacters), so it needs no escaping.
            out.push_str(",\"prev\":\"");
            out.push_str(p);
            out.push('"');
        }
        out.push_str(",\"record\":\"");
        push_json_string(&mut out, canonical);
        out.push_str("\"}");
        out
    }
}

/// The chain hash of a record's canonical bytes: SHA-256, hex. A chained record's `prev` field is the
/// chain hash of the previous record, so a sequence's order and membership are committed.
#[must_use]
pub fn record_hash(canonical: &str) -> String {
    hex_encode(&Sha256::digest(canonical.as_bytes()))
}

/// The signed message for a chained record: `prev + "\n" + canonical`. `prev` is 64 hex chars and
/// `canonical` is compact JSON with no leading newline, so the single `\n` is an unambiguous frame.
fn link_message(prev: &str, canonical: &str) -> String {
    let mut m = String::with_capacity(prev.len() + 1 + canonical.len());
    m.push_str(prev);
    m.push('\n');
    m.push_str(canonical);
    m
}

/// A trusted **public** key to verify a record against: the host's own (from
/// [`HostKey::verifying_key`]) or one supplied out of band ([`TrustedKey::from_hex`]). Opaque, so the
/// crypto library type stays out of the public API.
#[derive(Debug, Clone)]
pub struct TrustedKey(VerifyingKey);

impl TrustedKey {
    /// Parse a trusted public key from its `key_id` form (64 hex chars = 32 bytes).
    ///
    /// # Errors
    /// [`KeyError::Malformed`] if the hex is the wrong length or not a valid `ed25519` public key.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let mut bytes = [0u8; 32];
        hex_decode(hex.trim(), &mut bytes)
            .map_err(|()| KeyError::Malformed("public key is not 32-byte hex".into()))?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|e| KeyError::Malformed(format!("not a valid ed25519 public key: {e}")))
    }

    /// This key's identifier: the hex of its 32 public-key bytes (what a record's `key_id` names).
    #[must_use]
    pub fn key_id(&self) -> String {
        hex_encode(&self.0.to_bytes())
    }
}

/// The default host-key path when neither a flag, `AGENT_SIGNING_KEY`, nor a config file sets one:
/// `$XDG_DATA_HOME/agent/record-signing.ed25519` (falling back to `$HOME/.local/share`, then
/// `/var/lib`). A signing key is host **state**, so it lives under a data dir, not a config dir.
#[must_use]
pub fn default_key_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
        .unwrap_or_else(|| PathBuf::from("/var/lib"));
    base.join("agent").join("record-signing.ed25519")
}

/// Verify a signed record envelope against a set of **trusted** verifying keys, returning the exact
/// canonical record bytes on success. Fails closed: an unknown `key_id`, a malformed envelope, or a
/// signature that doesn't check is an [`Err`], never a silent pass.
///
/// The record's `key_id` must name a key in `trusted`; a record re-signed with an attacker's key
/// therefore fails with [`VerifyError::UntrustedKey`] rather than verifying against its own embedded
/// key. Uses `verify_strict` (rejects the known `ed25519` malleability corner).
///
/// # Errors
/// [`VerifyError`] on a malformed envelope, an untrusted `key_id`, or a bad signature.
pub fn verify(envelope: &str, trusted: &[TrustedKey]) -> Result<String, VerifyError> {
    verify_entry(envelope, trusted).map(|(record, _prev)| record)
}

/// Verify one envelope and return `(canonical record, prev)`, where `prev` is the chain link if the
/// record was signed chained (`None` if unchained). The signed message is `prev + "\n" + record` when
/// chained, else `record`, so the `prev` link is covered by the signature and can't be rewritten.
fn verify_entry(
    envelope: &str,
    trusted: &[TrustedKey],
) -> Result<(String, Option<String>), VerifyError> {
    let v: serde_json::Value =
        serde_json::from_str(envelope).map_err(|e| VerifyError::Malformed(e.to_string()))?;
    let field = |name: &str| -> Result<String, VerifyError> {
        v.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| VerifyError::Malformed(format!("missing string field `{name}`")))
    };
    let record = field("record")?;
    let key_id = field("key_id")?;
    let sig_hex = field("signature")?;
    // `prev` is optional: present only on a chained record.
    let prev = v
        .get("prev")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let mut sig_bytes = [0u8; 64];
    hex_decode(&sig_hex, &mut sig_bytes)
        .map_err(|()| VerifyError::Malformed("signature is not 64-byte hex".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let key = trusted
        .iter()
        .find(|k| k.key_id() == key_id)
        .ok_or_else(|| VerifyError::UntrustedKey(key_id.clone()))?;
    let message = match &prev {
        Some(p) => link_message(p, &record),
        None => record.clone(),
    };
    key.0
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| VerifyError::BadSignature)?;
    Ok((record, prev))
}

/// Verify a **sequence** of signed record envelopes as a hash chain (decision 034), returning the
/// canonical records in order. Each entry's signature must check (against `trusted`) **and** its
/// `prev` must equal the [`record_hash`] of the previous entry's record (the first entry must be
/// unchained). A reordered, inserted, or middle-deleted record breaks a link and is rejected.
///
/// Note: truncating the **tail** of the chain is not detectable here without an external anchor (the
/// append-only limitation); it detects any edit *within* the delivered sequence.
///
/// # Errors
/// [`ChainError::Entry`] if an envelope fails to verify; [`ChainError::BrokenLink`] if a `prev` link
/// doesn't match the previous record's hash.
pub fn verify_chain(envelopes: &[&str], trusted: &[TrustedKey]) -> Result<Vec<String>, ChainError> {
    let mut records = Vec::with_capacity(envelopes.len());
    let mut expected_prev: Option<String> = None;
    for (index, envelope) in envelopes.iter().enumerate() {
        let (record, prev) = verify_entry(envelope, trusted)
            .map_err(|source| ChainError::Entry { index, source })?;
        if prev.as_deref() != expected_prev.as_deref() {
            return Err(ChainError::BrokenLink { index });
        }
        expected_prev = Some(record_hash(&record));
        records.push(record);
    }
    Ok(records)
}

/// Read 32 random bytes from `/dev/urandom` (the OS CSPRNG on the Linux-only engine), so key
/// generation needs no `rand` dependency.
fn random_seed() -> Result<[u8; 32], KeyError> {
    let mut seed = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").map_err(KeyError::Io)?;
    f.read_exact(&mut seed).map_err(KeyError::Io)?;
    Ok(seed)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode hex into a fixed-size buffer; `Err(())` if the length is wrong or a digit is not hex.
fn hex_decode(s: &str, out: &mut [u8]) -> Result<(), ()> {
    let b = s.as_bytes();
    if b.len() != out.len() * 2 {
        return Err(());
    }
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (hexval(b[2 * i])? << 4) | hexval(b[2 * i + 1])?;
    }
    Ok(())
}

fn hexval(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

/// Escape `s` as the contents of a JSON string (no surrounding quotes). The record is embedded this
/// way so its bytes survive verbatim; the inverse is any JSON parser's string unescape.
fn push_json_string(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// A signing-key load/generate failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum KeyError {
    /// Reading, creating, or writing the key file failed.
    Io(std::io::Error),
    /// The key file exists but isn't a 32-byte hex seed.
    Malformed(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "signing key I/O: {e}"),
            Self::Malformed(m) => write!(f, "signing key malformed: {m}"),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Malformed(_) => None,
        }
    }
}

/// Why a signed record failed verification. Fail-closed: every variant is a rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The envelope isn't well-formed (not JSON, or missing `record`/`key_id`/`signature`).
    Malformed(String),
    /// The record's `key_id` names no key in the trusted set (the given id).
    UntrustedKey(String),
    /// The signature did not verify against the trusted key: the record was altered, or signed by a
    /// different key than its `key_id` claims.
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "not a signed record envelope: {m}"),
            Self::UntrustedKey(id) => write!(f, "record signed by an untrusted key (key_id {id})"),
            Self::BadSignature => {
                write!(
                    f,
                    "signature does not verify: the record was altered or mis-signed"
                )
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Why a record **chain** failed verification ([`verify_chain`]). Fail-closed: every variant rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainError {
    /// Envelope at `index` failed to verify on its own.
    Entry {
        /// The zero-based position in the sequence.
        index: usize,
        /// The per-record failure.
        source: VerifyError,
    },
    /// The `prev` link at `index` doesn't match the previous record's hash: a reordered, inserted, or
    /// deleted record.
    BrokenLink {
        /// The zero-based position whose link is broken.
        index: usize,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry { index, source } => write!(f, "record {index} in the chain: {source}"),
            Self::BrokenLink { index } => write!(
                f,
                "record {index} breaks the hash chain: a run was reordered, inserted, or deleted"
            ),
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Entry { source, .. } => Some(source),
            Self::BrokenLink { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed seed so signatures are deterministic in tests (ed25519 signing is deterministic).
    fn test_key() -> HostKey {
        HostKey::from_seed([7u8; 32])
    }

    #[test]
    fn sign_then_verify_round_trips_and_returns_the_canonical_bytes() {
        let key = test_key();
        let canonical = r#"{"schema":1,"timing":{"boot_ns":1}}"#;
        let envelope = key.sign_canonical(canonical);
        let recovered = verify(&envelope, &[key.verifying_key()]).expect("verifies");
        assert_eq!(
            recovered, canonical,
            "verify returns the exact signed bytes"
        );
    }

    #[test]
    fn a_flipped_byte_in_the_record_is_rejected() {
        let key = test_key();
        let envelope = key.sign_canonical(r#"{"schema":1,"timing":{"boot_ns":1}}"#);
        // Flip a digit inside the embedded record string.
        let tampered = envelope.replacen("boot_ns\\\":1", "boot_ns\\\":9", 1);
        assert_ne!(
            tampered, envelope,
            "the replacement actually changed a byte"
        );
        assert_eq!(
            verify(&tampered, &[key.verifying_key()]),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn a_record_signed_by_an_untrusted_key_is_rejected() {
        let signer = test_key();
        let other = HostKey::from_seed([9u8; 32]);
        let envelope = signer.sign_canonical(r#"{"schema":1}"#);
        // Only `other` is trusted; the record names `signer`'s key_id, which isn't in the set.
        assert_eq!(
            verify(&envelope, &[other.verifying_key()]),
            Err(VerifyError::UntrustedKey(signer.key_id()))
        );
    }

    #[test]
    fn a_rotated_key_set_still_verifies_records_from_the_old_key() {
        // Key rotation (decision 034): sign with the "old" key A, rotate to "new" key B. A verifier
        // that trusts the *set* {A, B} accepts records from either; a record from an untrusted C does
        // not, even though the set is non-empty.
        let old = HostKey::from_seed([1u8; 32]);
        let new = HostKey::from_seed([2u8; 32]);
        let outsider = HostKey::from_seed([3u8; 32]);
        let trusted = [old.verifying_key(), new.verifying_key()];

        let old_record = old.sign_canonical(r#"{"schema":1,"n":1}"#);
        let new_record = new.sign_canonical(r#"{"schema":1,"n":2}"#);
        assert!(
            verify(&old_record, &trusted).is_ok(),
            "old key still trusted"
        );
        assert!(verify(&new_record, &trusted).is_ok(), "new key trusted");

        let outsider_record = outsider.sign_canonical(r#"{"schema":1,"n":3}"#);
        assert_eq!(
            verify(&outsider_record, &trusted),
            Err(VerifyError::UntrustedKey(outsider.key_id())),
            "a key outside the set is rejected"
        );
    }

    #[test]
    fn a_record_chain_verifies_and_detects_reorder_insert_and_delete() {
        let key = test_key();
        let trusted = [key.verifying_key()];
        // Build a 3-record chain: the first is unchained (the anchor), each next commits to the
        // previous record's hash.
        let r = [
            "{\"schema\":1,\"n\":0}",
            "{\"schema\":1,\"n\":1}",
            "{\"schema\":1,\"n\":2}",
        ];
        let e0 = key.sign_canonical(r[0]);
        let e1 = key.sign_canonical_chained(r[1], Some(&record_hash(r[0])));
        let e2 = key.sign_canonical_chained(r[2], Some(&record_hash(r[1])));

        let good = [e0.as_str(), e1.as_str(), e2.as_str()];
        assert_eq!(
            verify_chain(&good, &trusted).expect("a valid chain verifies"),
            vec![r[0].to_string(), r[1].to_string(), r[2].to_string()]
        );

        // Reorder: the links no longer line up.
        assert!(matches!(
            verify_chain(&[e0.as_str(), e2.as_str(), e1.as_str()], &trusted),
            Err(ChainError::BrokenLink { .. })
        ));
        // Delete the middle record: record 1 (was e2) references the deleted record's hash.
        assert_eq!(
            verify_chain(&[e0.as_str(), e2.as_str()], &trusted),
            Err(ChainError::BrokenLink { index: 1 })
        );
        // Insert a foreign (but validly signed) record breaks the following link.
        let inserted =
            key.sign_canonical_chained("{\"schema\":1,\"n\":9}", Some(&record_hash(r[0])));
        assert!(matches!(
            verify_chain(
                &[e0.as_str(), inserted.as_str(), e1.as_str(), e2.as_str()],
                &trusted
            ),
            Err(ChainError::BrokenLink { .. })
        ));
        // A tampered entry fails as an Entry error (its signature no longer checks).
        let tampered = e1.replacen("\\\"n\\\":1", "\\\"n\\\":8", 1);
        assert!(matches!(
            verify_chain(&[e0.as_str(), tampered.as_str()], &trusted),
            Err(ChainError::Entry { index: 1, .. })
        ));
    }

    #[test]
    fn record_hash_is_sha256_hex_and_deterministic() {
        let h = record_hash("{\"schema\":1}");
        assert_eq!(h.len(), 64, "SHA-256 as hex");
        assert_eq!(h, record_hash("{\"schema\":1}"), "stable");
        assert_ne!(h, record_hash("{\"schema\":2}"), "content-sensitive");
    }

    #[test]
    fn a_non_envelope_is_malformed_not_a_panic() {
        let key = test_key();
        assert!(matches!(
            verify("not json", &[key.verifying_key()]),
            Err(VerifyError::Malformed(_))
        ));
        assert!(matches!(
            verify(r#"{"schema":2}"#, &[key.verifying_key()]),
            Err(VerifyError::Malformed(_))
        ));
    }

    #[test]
    fn the_envelope_is_valid_json_with_the_expected_shape() {
        let key = test_key();
        let envelope = key.sign_canonical(r#"{"a":"has \"quotes\" and \\ slashes"}"#);
        let v: serde_json::Value = serde_json::from_str(&envelope).expect("valid json");
        assert_eq!(v["schema"], SIGNED_RECORD_SCHEMA_VERSION);
        assert_eq!(v["key_id"], key.key_id());
        assert_eq!(
            v["record"], r#"{"a":"has \"quotes\" and \\ slashes"}"#,
            "the embedded record round-trips through JSON string escaping"
        );
        // And it still verifies (escaping is the inverse of the parser's unescape).
        verify(&envelope, &[key.verifying_key()]).expect("verifies after escaping");
    }

    #[test]
    fn key_id_is_the_public_key_hex_and_is_stable() {
        let key = test_key();
        assert_eq!(key.key_id(), key.verifying_key().key_id());
        assert_eq!(key.key_id().len(), 64, "32 public-key bytes as hex");
        assert_eq!(HostKey::from_seed([7u8; 32]).key_id(), key.key_id());
        // A trusted key parsed back from its key_id hex matches.
        let parsed = TrustedKey::from_hex(&key.key_id()).expect("valid hex key");
        assert_eq!(parsed.key_id(), key.key_id());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff, 0x10];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "000fa5ff10");
        let mut out = [0u8; 5];
        hex_decode(&hex, &mut out).expect("decodes");
        assert_eq!(out, bytes);
        assert!(hex_decode("zz", &mut [0u8; 1]).is_err(), "non-hex rejected");
        assert!(
            hex_decode("00", &mut [0u8; 2]).is_err(),
            "wrong length rejected"
        );
    }

    #[test]
    fn load_or_generate_persists_then_reloads_the_same_key() {
        let dir = std::env::temp_dir().join(format!("agent-key-{}", std::process::id()));
        let path = dir.join("record-signing.ed25519");
        let _ = std::fs::remove_dir_all(&dir);
        let first = HostKey::load_or_generate(&path).expect("generates");
        let second = HostKey::load_or_generate(&path).expect("reloads");
        assert_eq!(
            first.key_id(),
            second.key_id(),
            "second load reuses the file"
        );
        // Persisted 0600.
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&path).expect("stat"));
        assert_eq!(
            mode & 0o777,
            0o600,
            "secret key is not world/group readable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
