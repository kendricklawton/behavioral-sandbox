//! Layered configuration: **flags > env (`AGENT_*`) > file (TOML) > defaults**.
//!
//! Resolution is a pure fold over partial layers ([`resolve`]), so precedence is unit-testable
//! without touching the process environment. `agent` holds **no secrets** — there is no API key
//! anywhere in config, by design (see `.rules`); the TOML schema even rejects unknown keys, so a
//! stray `api_key = …` is an error, not a silent read.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// The fully-resolved configuration the CLI runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Which detector `agent check` runs.
    pub detector: String,
    /// Log filter directive for stderr tracing (e.g. `warn`, `debug`, `agent=debug`).
    pub log: String,
    /// Where built/pulled detector artifacts resolve from (Phase 3+); `None` ⇒ the default.
    pub artifact_dir: Option<PathBuf>,
}

impl Config {
    /// The built-in defaults — the lowest-precedence layer.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            detector: "mock".to_string(),
            log: "warn".to_string(),
            artifact_dir: None,
        }
    }
}

/// A partial configuration — any field may be unset. One per layer (file, env, flags); a missing
/// field falls through to the next lower-precedence layer.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partial {
    /// Override the detector.
    pub detector: Option<String>,
    /// Override the log filter.
    pub log: Option<String>,
    /// Override the artifact directory.
    pub artifact_dir: Option<PathBuf>,
}

impl Partial {
    /// Overlay `higher` onto `self`: any field set in `higher` wins.
    #[must_use]
    fn overlay(self, higher: Partial) -> Partial {
        Partial {
            detector: higher.detector.or(self.detector),
            log: higher.log.or(self.log),
            artifact_dir: higher.artifact_dir.or(self.artifact_dir),
        }
    }

    /// Read the `AGENT_*` environment layer from the process environment.
    #[must_use]
    pub fn from_env() -> Partial {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// [`from_env`](Self::from_env) with an injectable getter, so precedence tests never touch
    /// the real (global, racy) process environment.
    #[must_use]
    fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Partial {
        Partial {
            detector: get("AGENT_DETECTOR"),
            log: get("AGENT_LOG"),
            artifact_dir: get("AGENT_ARTIFACT_DIR").map(PathBuf::from),
        }
    }

    /// Parse the TOML file layer.
    ///
    /// # Errors
    /// If the file can't be read, or isn't valid TOML for the config schema (unknown keys and
    /// type mismatches are rejected).
    pub fn from_toml_file(path: &Path) -> anyhow::Result<Partial> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config file {}", path.display()))
    }
}

/// Fold the layers into a final [`Config`]. Precedence is **flags > env > file > defaults**.
#[must_use]
pub fn resolve(file: Partial, env: Partial, flags: Partial) -> Config {
    let merged = Partial::default().overlay(file).overlay(env).overlay(flags);
    let defaults = Config::defaults();
    Config {
        detector: merged.detector.unwrap_or(defaults.detector),
        log: merged.log.unwrap_or(defaults.log),
        artifact_dir: merged.artifact_dir.or(defaults.artifact_dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partial(detector: Option<&str>, log: Option<&str>) -> Partial {
        Partial {
            detector: detector.map(String::from),
            log: log.map(String::from),
            artifact_dir: None,
        }
    }

    #[test]
    fn all_empty_yields_defaults() {
        let c = resolve(Partial::default(), Partial::default(), Partial::default());
        assert_eq!(c, Config::defaults());
        assert_eq!(c.detector, "mock");
        assert_eq!(c.log, "warn");
        assert_eq!(c.artifact_dir, None);
    }

    #[test]
    fn precedence_is_flags_over_env_over_file_over_defaults() {
        // detector: set in file+env+flags → flags win
        // log:      set in file+env       → env wins over file
        // artifact: set only in file      → file survives over the default (None)
        let file = Partial {
            detector: Some("file-det".into()),
            log: Some("file-log".into()),
            artifact_dir: Some(PathBuf::from("/from/file")),
        };
        let env = partial(Some("env-det"), Some("env-log"));
        let flags = partial(Some("flag-det"), None);

        let c = resolve(file, env, flags);
        assert_eq!(c.detector, "flag-det");
        assert_eq!(c.log, "env-log");
        assert_eq!(c.artifact_dir, Some(PathBuf::from("/from/file")));
    }

    #[test]
    fn env_layer_reads_agent_vars() {
        let env = Partial::from_env_with(|k| match k {
            "AGENT_DETECTOR" => Some("pii".into()),
            "AGENT_LOG" => Some("debug".into()),
            _ => None,
        });
        assert_eq!(env.detector.as_deref(), Some("pii"));
        assert_eq!(env.log.as_deref(), Some("debug"));
        assert_eq!(env.artifact_dir, None);
    }

    #[test]
    fn toml_parses_valid_and_rejects_unknown_keys() {
        let ok: Partial = toml::from_str("detector = \"secrets\"\nlog = \"info\"").unwrap();
        assert_eq!(ok.detector.as_deref(), Some("secrets"));
        assert_eq!(ok.log.as_deref(), Some("info"));
        // A stray secret-shaped key is a hard error — config never carries secrets.
        assert!(toml::from_str::<Partial>("api_key = \"nope\"").is_err());
    }
}
