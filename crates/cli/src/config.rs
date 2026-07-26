//! The `.ekvm.toml` **file layer** of the config precedence `flags > env (EKVM_*) > file >
//! defaults`.
//!
//! The env layer already lives in [`vmm::BootConfig::from_env`], and the flags layer is the
//! CLI's own arguments; this module inserts a file between env and defaults. **One vocabulary:** the
//! file's keys mirror the `EKVM_*` env names 1:1 (minus the prefix, lowercased), so a value is
//! spelled the same whether it comes from a flag, the environment, or the file. Discovery is the
//! **nearest `.ekvm.toml` walking up from the cwd** (like `.gitignore`/`.editorconfig`), so a
//! project pins its engine config beside its code.
//!
//! **Typos are a typed error, never a silent no-op:** the file is parsed with
//! `deny_unknown_fields`, so a misspelled key (`kernal = …`) fails loudly rather than being ignored.
//!
//! The layering itself is done by composing a lookup for [`BootConfig::from_env_with`](vmm::BootConfig::from_env_with): return the
//! real env var if set, else the file's value, which resolves `env > file > defaults` for the
//! artifact/scratch keys with zero duplication of the engine's env-key logic or defaults. The `log`
//! key has no `BootConfig` field (it drives `tracing`), so the CLI reads it from here directly.

use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroU8};
use std::path::{Path, PathBuf};

use probes_loader::{Ipv4Cidr, Ipv6Cidr};
use serde::Deserialize;
use vmm::VmmError;

use crate::policy::Policy;

/// The file name discovered up from the cwd.
const FILE_NAME: &str = ".ekvm.toml";

/// A parsed `.ekvm.toml`. Every field is optional (an absent key falls through to the env/default
/// layer); every key mirrors an `EKVM_*` env name. Unknown keys are rejected so a typo can't
/// silently no-op.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentToml {
    /// Mirrors `EKVM_FIRECRACKER`.
    firecracker: Option<PathBuf>,
    /// Mirrors `EKVM_KERNEL`.
    kernel: Option<PathBuf>,
    /// Mirrors `EKVM_ROOTFS`.
    rootfs: Option<PathBuf>,
    /// Mirrors `EKVM_MARKER`.
    marker: Option<String>,
    /// Mirrors `EKVM_SCRATCH_DIR`.
    scratch_dir: Option<PathBuf>,
    /// Mirrors `EKVM_REQUIRE_LIMITS` (fail closed when cgroup caps can't be applied).
    require_limits: Option<bool>,
    /// Mirrors `EKVM_LOG` (the stderr `tracing` filter). No `BootConfig` field; the CLI reads it.
    log: Option<String>,
    /// Mirrors `EKVM_SIGNING_KEY` (the host record-signing key path). No `BootConfig`
    /// field; the CLI reads it to sign `--record`.
    signing_key: Option<PathBuf>,
    /// Mirrors `EKVM_TRUSTED_KEYS`: public keys (`key_id` hex) `ekvm verify` trusts *in addition*
    /// to the current signing key, so rotating the host key doesn't invalidate already-signed records.
    /// No `BootConfig` field.
    trusted_keys: Option<Vec<String>>,

    // Operator policy. These do **not** mirror `EKVM_*` env keys: they are the
    // host's posture, not a per-invocation knob, and the ceilings exist precisely to bound what a
    // caller may ask for, so routing them through the flags > env > file precedence would let the
    // caller they bound edit them. See `crate::policy` for where this binds and where it is only a
    // guardrail.
    /// House default vCPUs when a caller does not ask.
    vcpus: Option<NonZeroU8>,
    /// House default guest memory, MiB.
    mem_mib: Option<NonZeroU32>,
    /// House default wall-clock budget, seconds.
    wall_secs: Option<u64>,
    /// House default captured-output cap, bytes.
    output_cap: Option<usize>,
    /// Ceiling on vCPUs; a caller asking for more is refused.
    max_vcpus: Option<NonZeroU8>,
    /// Ceiling on guest memory, MiB.
    max_mem_mib: Option<NonZeroU32>,
    /// Ceiling on the wall-clock budget, seconds.
    max_wall_secs: Option<u64>,
    /// Ceiling on the captured-output cap, bytes.
    max_output_cap: Option<usize>,
    /// Withdraw the `--unjailed` opt-out on this host.
    require_jail: Option<bool>,
    /// Whether a caller may attach a guest NIC at all; unset permits it.
    allow_net: Option<bool>,
    /// Refuse a run without an audit record on this host.
    require_record: Option<bool>,
    /// Directory where audit records are saved by default.
    records_dir: Option<PathBuf>,
    /// Operator ceiling on allowed IPv4 egress CIDRs.
    max_egress_v4: Option<Vec<CidrV4>>,
    /// Operator ceiling on allowed IPv6 egress CIDRs.
    max_egress_v6: Option<Vec<CidrV6>>,
}

/// A `max_egress_v4` entry, validated at deserialize time: a typo'd ceiling entry must be a loud
/// parse error, because dropping it would *widen* the ceiling (an empty ceiling means
/// "no restriction" in [`Policy::check_egress`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
struct CidrV4(Ipv4Cidr);

impl TryFrom<String> for CidrV4 {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_v4_cidr(&s).map(CidrV4)
    }
}

/// The v6 twin of [`CidrV4`], for `max_egress_v6` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
struct CidrV6(Ipv6Cidr);

impl TryFrom<String> for CidrV6 {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_v6_cidr(&s).map(CidrV6)
    }
}

impl AgentToml {
    /// Discover and parse the nearest `.ekvm.toml` walking up from `start`, or `None` if none
    /// exists between `start` and the filesystem root.
    /// # Errors
    /// [`VmmError::Vmm`] if a file is found but can't be read or has an unknown/mistyped key or bad
    /// TOML, a config the operator wrote but got wrong must fail loudly, not be skipped.
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

    /// Read + parse one `.ekvm.toml`, naming the file in any error.
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

    /// The file's value for an `EKVM_*` env key, as an [`OsString`], or `None` if the key is unset
    /// in the file, the shape [`from_env_with`](vmm::BootConfig::from_env_with) consumes, so
    /// the file slots in *under* the environment in one composed lookup.
    #[must_use]
    pub fn env_value(&self, key: &str) -> Option<OsString> {
        match key {
            "EKVM_FIRECRACKER" => self
                .firecracker
                .as_ref()
                .map(|p| p.as_os_str().to_os_string()),
            "EKVM_KERNEL" => self.kernel.as_ref().map(|p| p.as_os_str().to_os_string()),
            "EKVM_ROOTFS" => self.rootfs.as_ref().map(|p| p.as_os_str().to_os_string()),
            "EKVM_MARKER" => self.marker.as_ref().map(OsString::from),
            "EKVM_SCRATCH_DIR" => self
                .scratch_dir
                .as_ref()
                .map(|p| p.as_os_str().to_os_string()),

            // A bool rendered as the canonical token `from_env_with`'s `parse_env_bool` accepts, so
            // the file slots under the env in the same composed lookup as the string keys.
            "EKVM_REQUIRE_LIMITS" => self
                .require_limits
                .map(|b| OsString::from(if b { "true" } else { "false" })),
            _ => None,
        }
    }

    /// The file's `log` filter, if set (no `BootConfig` field; the CLI folds it into its own
    /// flag > env > file > default resolution for `tracing`).
    #[must_use]
    pub fn log(&self) -> Option<&str> {
        self.log.as_deref()
    }

    /// The file's `signing_key` path, if set (no `BootConfig` field; folded into
    /// [`signing_key_path`]'s precedence).
    #[must_use]
    pub fn signing_key(&self) -> Option<&Path> {
        self.signing_key.as_deref()
    }

    /// The file's `trusted_keys` list (public-key hex), or an empty slice.
    #[must_use]
    pub fn trusted_keys(&self) -> &[String] {
        self.trusted_keys.as_deref().unwrap_or(&[])
    }

    /// The operator policy this file declares. An absent file, or one that sets none
    /// of these keys, yields the default policy, which changes nothing.
    #[must_use]
    pub fn policy(&self) -> Policy {
        // Already validated at deserialize time (`CidrV4`/`CidrV6`), so this projection cannot
        // drop an entry.
        let max_egress_v4 = self
            .max_egress_v4
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|c| c.0)
            .collect();
        let max_egress_v6 = self
            .max_egress_v6
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|c| c.0)
            .collect();

        Policy {
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            wall_secs: self.wall_secs,
            output_cap: self.output_cap,
            max_vcpus: self.max_vcpus,
            max_mem_mib: self.max_mem_mib,
            max_wall_secs: self.max_wall_secs,
            max_output_cap: self.max_output_cap,
            require_jail: self.require_jail.unwrap_or(false),
            allow_net: self.allow_net,
            require_record: self.require_record.unwrap_or(false),
            records_dir: self.records_dir.clone(),
            max_egress_v4,
            max_egress_v6,
        }
    }
}

fn parse_v4_cidr(s: &str) -> Result<Ipv4Cidr, String> {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            let addr: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("invalid IPv4 address {ip:?} in max_egress_v4 entry {s:?}"))?;
            let prefix: u8 = prefix.parse().map_err(|_| {
                format!("invalid CIDR prefix {prefix:?} in max_egress_v4 entry {s:?}")
            })?;
            Ipv4Cidr::new(addr, prefix).map_err(|e| format!("max_egress_v4 entry {s:?}: {e}"))
        }
        None => {
            let addr: Ipv4Addr = s
                .parse()
                .map_err(|_| format!("invalid IPv4 address in max_egress_v4 entry {s:?}"))?;
            Ok(Ipv4Cidr::host(addr))
        }
    }
}

fn parse_v6_cidr(s: &str) -> Result<Ipv6Cidr, String> {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            let addr: Ipv6Addr = ip
                .parse()
                .map_err(|_| format!("invalid IPv6 address {ip:?} in max_egress_v6 entry {s:?}"))?;
            let prefix: u8 = prefix.parse().map_err(|_| {
                format!("invalid CIDR prefix {prefix:?} in max_egress_v6 entry {s:?}")
            })?;
            Ipv6Cidr::new(addr, prefix).map_err(|e| format!("max_egress_v6 entry {s:?}: {e}"))
        }
        None => {
            let addr: Ipv6Addr = s
                .parse()
                .map_err(|_| format!("invalid IPv6 address in max_egress_v6 entry {s:?}"))?;
            Ok(Ipv6Cidr::host(addr))
        }
    }
}

/// The operator policy for this process: the nearest `.ekvm.toml`'s, or the permissive default when
/// there is no file. One call site so the CLI and the daemon can't drift on how policy is sourced.
#[must_use]
pub fn policy_of(file: Option<&AgentToml>) -> Policy {
    file.map(AgentToml::policy).unwrap_or_default()
}

/// Resolve the host record-signing key path with `env (EKVM_SIGNING_KEY) > file > default`
/// Like `log`, this has no `BootConfig` field, so its precedence is mirrored here.
/// The default is [`probes_loader::default_key_path`] (a data-dir path, generated on first use).
#[must_use]
pub fn signing_key_path(file: Option<&AgentToml>) -> PathBuf {
    std::env::var_os("EKVM_SIGNING_KEY")
        .map(PathBuf::from)
        .or_else(|| file.and_then(AgentToml::signing_key).map(Path::to_path_buf))
        .unwrap_or_else(probes_loader::default_key_path)
}

/// The configured set of extra trusted public keys (`key_id` hex) for `ekvm verify`, the **union**
/// of `EKVM_TRUSTED_KEYS` (comma-separated) and the file's `trusted_keys` list. A set, not an
/// override: every configured key stays trusted so a record signed before a key rotation still
/// verifies. Parsing/validation is the caller's (`TrustedKey::from_hex`).
#[must_use]
pub fn trusted_key_hexes(file: Option<&AgentToml>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(v) = std::env::var_os("EKVM_TRUSTED_KEYS") {
        out.extend(
            v.to_string_lossy()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    if let Some(f) = file {
        out.extend(f.trusted_keys().iter().cloned());
    }
    out
}

/// Resolve the stderr log filter with the full precedence `flag > env (EKVM_LOG) > file > default`.
/// The `BootConfig` layers can't carry `log` (it has no field), so this mirrors that precedence for
/// the one config value that drives `tracing` instead of the engine.
#[must_use]
pub fn resolve_log(flag: Option<&str>, file: Option<&AgentToml>) -> Option<String> {
    flag.map(str::to_string)
        .or_else(|| std::env::var("EKVM_LOG").ok())
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
            toml.env_value("EKVM_KERNEL"),
            Some(OsString::from("/k/vmlinux"))
        );
        assert_eq!(
            toml.env_value("EKVM_ROOTFS"),
            Some(OsString::from("/r/root.ext4"))
        );
        assert_eq!(toml.env_value("EKVM_MARKER"), Some(OsString::from("UP")));
        assert_eq!(
            toml.env_value("EKVM_FIRECRACKER"),
            None,
            "unset key falls through"
        );
        assert_eq!(toml.log(), Some("debug"));
    }

    #[test]
    fn require_limits_bool_renders_the_env_token_from_env_parses() {
        // The file bool slots under the env in one composed lookup: `env_value` renders the canonical
        // token, and `BootConfig::from_env_with` parses it back onto the posture (env > file > default).
        let on = AgentToml::parse("require_limits = true\n").expect("valid toml parses");
        assert_eq!(
            on.env_value("EKVM_REQUIRE_LIMITS"),
            Some(OsString::from("true"))
        );
        assert!(vmm::BootConfig::from_env_with(|k| on.env_value(k)).require_limits);

        let off = AgentToml::parse("require_limits = false\n").expect("valid toml parses");
        assert_eq!(
            off.env_value("EKVM_REQUIRE_LIMITS"),
            Some(OsString::from("false"))
        );
        assert!(!vmm::BootConfig::from_env_with(|k| off.env_value(k)).require_limits);

        // Unset in the file falls through to the default.
        let bare = AgentToml::parse("marker = \"UP\"\n").expect("valid toml parses");
        assert_eq!(bare.env_value("EKVM_REQUIRE_LIMITS"), None);
    }

    #[test]
    fn signing_key_parses_from_the_file_layer() {
        let toml =
            AgentToml::parse("signing_key = \"/keys/host.ed25519\"\n").expect("valid toml parses");
        assert_eq!(
            toml.signing_key(),
            Some(Path::new("/keys/host.ed25519")),
            "the file layer carries the record-signing key path"
        );
        assert_eq!(
            AgentToml::default().signing_key(),
            None,
            "unset falls through"
        );
    }

    #[test]
    fn trusted_keys_parse_as_a_list_from_the_file_layer() {
        let toml =
            AgentToml::parse("trusted_keys = [\"aa\", \"bb\"]\n").expect("valid toml parses");
        assert_eq!(toml.trusted_keys(), ["aa".to_string(), "bb".to_string()]);
        assert!(
            AgentToml::default().trusted_keys().is_empty(),
            "unset is an empty set, not an error"
        );
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
                "EKVM_KERNEL" => Some(OsString::from("/env/vmlinux")),
                _ => None,
            }
        };
        // The composed lookup: env first, then file.
        let composed = |key: &str| env(key).or_else(|| file.env_value(key));
        // kernel: env wins over the file.
        assert_eq!(
            composed("EKVM_KERNEL"),
            Some(OsString::from("/env/vmlinux"))
        );
        // rootfs: only the file has it → file wins over the default.
        assert_eq!(composed("EKVM_ROOTFS"), Some(OsString::from("/file/root")));
        // marker: neither sets it → None, so the BootConfig default stands.
        assert_eq!(composed("EKVM_MARKER"), None);
    }

    #[test]
    fn malformed_egress_ceiling_is_a_typed_error_not_a_dropped_entry() {
        // A dropped ceiling entry *widens* the ceiling (empty means unrestricted in
        // `Policy::check_egress`), so a typo must refuse the whole file, loudly, at parse time.
        let err = AgentToml::parse("max_egress_v4 = [\"10.0.0.0-8\"]\n")
            .expect_err("a malformed CIDR entry must fail the parse");
        assert!(
            err.contains("10.0.0.0-8") && err.contains("max_egress_v4"),
            "error names the entry and the key: {err}"
        );

        let err = AgentToml::parse("max_egress_v4 = [\"10.0.0.0/33\"]\n")
            .expect_err("an out-of-range prefix must fail the parse");
        assert!(err.contains("10.0.0.0/33"), "error names the entry: {err}");

        let err = AgentToml::parse("max_egress_v6 = [\"fd00::/129\"]\n")
            .expect_err("an out-of-range v6 prefix must fail the parse");
        assert!(err.contains("fd00::/129"), "error names the entry: {err}");
    }

    #[test]
    fn egress_ceilings_parse_into_the_policy_unabridged() {
        let toml = AgentToml::parse(
            "max_egress_v4 = [\"10.0.0.0/8\", \"192.0.2.7\"]\nmax_egress_v6 = [\"fd00::/8\"]\n",
        )
        .expect("valid ceilings parse");
        let policy = toml.policy();
        assert_eq!(
            policy.max_egress_v4,
            vec![
                probes_loader::Ipv4Cidr::new("10.0.0.0".parse().unwrap(), 8).unwrap(),
                probes_loader::Ipv4Cidr::host("192.0.2.7".parse().unwrap()),
            ],
            "every entry reaches the policy: a bare host reads as /32"
        );
        assert_eq!(
            policy.max_egress_v6,
            vec![probes_loader::Ipv6Cidr::new("fd00::".parse().unwrap(), 8).unwrap()]
        );
        // Absent keys stay "no restriction": the permissive default, explicitly chosen.
        let bare = AgentToml::parse("marker = \"UP\"\n").expect("valid");
        assert!(bare.policy().max_egress_v4.is_empty());
        assert!(bare.policy().max_egress_v6.is_empty());
    }

    #[test]
    fn discover_walks_up_from_the_cwd_and_finds_the_nearest() {
        // A three-level temp tree with a file at the top; discovery from the leaf finds it.
        let base = std::env::temp_dir().join(format!("ekvm-cfg-{}", std::process::id()));
        let leaf = base.join("a/b");
        std::fs::create_dir_all(&leaf).expect("mkdirs");
        std::fs::write(base.join(".ekvm.toml"), "marker = \"FROMFILE\"\n").expect("write");
        // A nearer file shadows the farther one.
        std::fs::write(base.join("a/.ekvm.toml"), "marker = \"NEARER\"\n").expect("write nearer");
        let found = AgentToml::discover(&leaf)
            .expect("discover ok")
            .expect("a file exists");
        assert_eq!(found.log(), None);
        assert_eq!(
            found.env_value("EKVM_MARKER"),
            Some(OsString::from("NEARER"))
        );
        // None above the tree.
        let empty = std::env::temp_dir().join(format!("ekvm-cfg-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).expect("mkdir empty");
        assert_eq!(AgentToml::discover(&empty).expect("ok"), None);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
