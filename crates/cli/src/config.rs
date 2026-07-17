//! The `.agent.toml` **file layer** of the config precedence `flags > env (AGENT_*) > file >
//! defaults`.
//!
//! The env layer already lives in [`agent_vmm::BootConfig::from_env`], and the flags layer is the
//! CLI's own arguments; this module inserts a file between env and defaults. **One vocabulary:** the
//! file's keys mirror the `AGENT_*` env names 1:1 (minus the prefix, lowercased), so a value is
//! spelled the same whether it comes from a flag, the environment, or the file. Discovery is the
//! **nearest `.agent.toml` walking up from the cwd** (like `.gitignore`/`.editorconfig`), so a
//! project pins its engine config beside its code.
//!
//! **Typos are a typed error, never a silent no-op:** the file is parsed with
//! `deny_unknown_fields`, so a misspelled key (`kernal = …`) fails loudly rather than being ignored.
//!
//! The layering itself is done by composing a lookup for [`BootConfig::from_env_with`](agent_vmm::BootConfig::from_env_with): return the
//! real env var if set, else the file's value — which resolves `env > file > defaults` for the
//! artifact/scratch keys with zero duplication of the engine's env-key logic or defaults. The `log`
//! key has no `BootConfig` field (it drives `tracing`), so the CLI reads it from here directly.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use agent_vmm::VmmError;
use serde::Deserialize;

/// The file name discovered up from the cwd.
const FILE_NAME: &str = ".agent.toml";

/// A parsed `.agent.toml`. Every field is optional (an absent key falls through to the env/default
/// layer); every key mirrors an `AGENT_*` env name. Unknown keys are rejected so a typo can't
/// silently no-op.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentToml {
    /// Mirrors `AGENT_FIRECRACKER`.
    firecracker: Option<PathBuf>,
    /// Mirrors `AGENT_KERNEL`.
    kernel: Option<PathBuf>,
    /// Mirrors `AGENT_ROOTFS`.
    rootfs: Option<PathBuf>,
    /// Mirrors `AGENT_MARKER`.
    marker: Option<String>,
    /// Mirrors `AGENT_SCRATCH_DIR`.
    scratch_dir: Option<PathBuf>,
    /// Mirrors `AGENT_LOG` (the stderr `tracing` filter). No `BootConfig` field; the CLI reads it.
    log: Option<String>,
}

impl AgentToml {
    /// Discover and parse the nearest `.agent.toml` walking up from `start`, or `None` if none
    /// exists between `start` and the filesystem root.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if a file is found but can't be read or has an unknown/mistyped key or bad
    /// TOML — a config the operator wrote but got wrong must fail loudly, not be skipped.
    pub fn discover(start: &Path) -> Result<Option<Self>, VmmError> {
        let mut dir = Some(start);
        while let Some(d) = dir {
            let candidate = d.join(FILE_NAME);
            if candidate.is_file() {
                return Self::parse_file(&candidate).map(Some);
            }
            dir = d.parent();
        }
        Ok(None)
    }

    /// Read + parse one `.agent.toml`, naming the file in any error.
    fn parse_file(path: &Path) -> Result<Self, VmmError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| VmmError::Vmm(format!("read {}: {e}", path.display())))?;
        Self::parse(&text).map_err(|e| VmmError::Vmm(format!("{}: {e}", path.display())))
    }

    /// Parse TOML text into an [`AgentToml`], surfacing an unknown-key/type error as a plain string
    /// (the pure core the file reader and the unit tests share).
    fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.message().to_string())
    }

    /// The file's value for an `AGENT_*` env key, as an [`OsString`], or `None` if the key is unset
    /// in the file — the shape [`from_env_with`](agent_vmm::BootConfig::from_env_with) consumes, so
    /// the file slots in *under* the environment in one composed lookup.
    #[must_use]
    pub fn env_value(&self, key: &str) -> Option<OsString> {
        match key {
            "AGENT_FIRECRACKER" => self.firecracker.clone().map(PathBuf::into_os_string),
            "AGENT_KERNEL" => self.kernel.clone().map(PathBuf::into_os_string),
            "AGENT_ROOTFS" => self.rootfs.clone().map(PathBuf::into_os_string),
            "AGENT_MARKER" => self.marker.as_ref().map(OsString::from),
            "AGENT_SCRATCH_DIR" => self.scratch_dir.clone().map(PathBuf::into_os_string),
            _ => None,
        }
    }

    /// The file's `log` filter, if set (no `BootConfig` field; the CLI folds it into its own
    /// flag > env > file > default resolution for `tracing`).
    #[must_use]
    pub fn log(&self) -> Option<&str> {
        self.log.as_deref()
    }
}

/// Resolve the stderr log filter with the full precedence `flag > env (AGENT_LOG) > file > default`.
/// The `BootConfig` layers can't carry `log` (it has no field), so this mirrors that precedence for
/// the one config value that drives `tracing` instead of the engine.
#[must_use]
pub fn resolve_log(flag: Option<&str>, file: Option<&AgentToml>) -> Option<String> {
    flag.map(str::to_string)
        .or_else(|| std::env::var("AGENT_LOG").ok())
        .or_else(|| file.and_then(AgentToml::log).map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_is_a_typed_error_not_a_silent_no_op() {
        // A typo (`kernal`) must fail loudly, per the deny-unknown-fields contract.
        let err = AgentToml::parse("kernal = \"/x/vmlinux\"\n").expect_err("typo must error");
        assert!(
            err.contains("kernal") || err.contains("unknown"),
            "names the bad key: {err}"
        );
    }

    #[test]
    fn known_keys_parse_into_env_values() {
        let toml = AgentToml::parse(
            "kernel = \"/k/vmlinux\"\nrootfs = \"/r/root.ext4\"\nmarker = \"UP\"\nlog = \"debug\"\n",
        )
        .expect("valid toml parses");
        assert_eq!(
            toml.env_value("AGENT_KERNEL"),
            Some(OsString::from("/k/vmlinux"))
        );
        assert_eq!(
            toml.env_value("AGENT_ROOTFS"),
            Some(OsString::from("/r/root.ext4"))
        );
        assert_eq!(toml.env_value("AGENT_MARKER"), Some(OsString::from("UP")));
        assert_eq!(
            toml.env_value("AGENT_FIRECRACKER"),
            None,
            "unset key falls through"
        );
        assert_eq!(toml.log(), Some("debug"));
    }

    #[test]
    fn env_beats_file_beats_default_via_the_composed_lookup() {
        // The layering `BootConfig::from_env_with` sees: env wins over file, file over default. Model
        // that composition here without a real process env or a real BootConfig.
        let file = AgentToml::parse("kernel = \"/file/vmlinux\"\nrootfs = \"/file/root\"\n")
            .expect("valid");
        // A fake environment that only sets the kernel.
        let env = |key: &str| -> Option<OsString> {
            match key {
                "AGENT_KERNEL" => Some(OsString::from("/env/vmlinux")),
                _ => None,
            }
        };
        // The composed lookup: env first, then file.
        let composed = |key: &str| env(key).or_else(|| file.env_value(key));
        // kernel: env wins over the file.
        assert_eq!(
            composed("AGENT_KERNEL"),
            Some(OsString::from("/env/vmlinux"))
        );
        // rootfs: only the file has it → file wins over the default.
        assert_eq!(composed("AGENT_ROOTFS"), Some(OsString::from("/file/root")));
        // marker: neither sets it → None, so the BootConfig default stands.
        assert_eq!(composed("AGENT_MARKER"), None);
    }

    #[test]
    fn discover_walks_up_from_the_cwd_and_finds_the_nearest() {
        // A three-level temp tree with a file at the top; discovery from the leaf finds it.
        let base = std::env::temp_dir().join(format!("agent-cfg-{}", std::process::id()));
        let leaf = base.join("a/b");
        std::fs::create_dir_all(&leaf).expect("mkdirs");
        std::fs::write(base.join(".agent.toml"), "marker = \"FROMFILE\"\n").expect("write");
        // A nearer file shadows the farther one.
        std::fs::write(base.join("a/.agent.toml"), "marker = \"NEARER\"\n").expect("write nearer");
        let found = AgentToml::discover(&leaf)
            .expect("discover ok")
            .expect("a file exists");
        assert_eq!(found.log(), None);
        assert_eq!(
            found.env_value("AGENT_MARKER"),
            Some(OsString::from("NEARER"))
        );
        // None above the tree.
        let empty = std::env::temp_dir().join(format!("agent-cfg-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).expect("mkdir empty");
        assert_eq!(AgentToml::discover(&empty).expect("ok"), None);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
