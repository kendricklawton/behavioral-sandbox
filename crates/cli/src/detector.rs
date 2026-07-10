//! [`DetectorName`] — a validated detector identifier.
//!
//! A detector name comes from config (flags / env / TOML) and becomes part of an artifact
//! filename, so it must be a bare token that cannot escape the artifact directory. Parsing a
//! `&str` into a `DetectorName` is the **single** place that rule lives — *parse, don't
//! validate*: every consumer (path resolution today; `pull` / `serve` later) then receives a name
//! that is already known safe, carried in the type rather than re-checked at each use.

use std::fmt;
use std::str::FromStr;

/// A detector identifier constrained to a non-empty `[A-Za-z0-9_-]+`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorName(String);

impl DetectorName {
    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DetectorName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        anyhow::ensure!(
            valid,
            "invalid detector name '{s}': use letters, digits, '_', or '-'"
        );
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for DetectorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_names_that_escape_the_artifact_dir() {
        for bad in [
            "../evil",
            "a/b",
            "..",
            ".",
            "mock.wasm",
            "",
            "a b",
            "x/../y",
        ] {
            assert!(
                bad.parse::<DetectorName>().is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn accepts_bare_identifiers() {
        assert_eq!("mock".parse::<DetectorName>().unwrap().as_str(), "mock");
        assert!("secrets-v2".parse::<DetectorName>().is_ok());
        assert!("pii_us".parse::<DetectorName>().is_ok());
    }
}
