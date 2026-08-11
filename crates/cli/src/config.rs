//! The `.bsx.toml` **file layer** of the config precedence
//! `flags > env (BSX_*) > project file > user file > defaults`.
//!
//! The env layer lives in [`bsx_engine::BootConfig::from_env`] and the flags layer is the CLI's own
//! arguments, so this module inserts two files between env and defaults.
//!
//! - **Two files, two trust levels.** The **user file** is `$HOME/.bsx.toml` and carries every key.
//!   The **project file** is the nearest `.bsx.toml` walking up from the cwd, like `.gitignore`, and
//!   carries only the keys that cannot weaken this host's posture. A file found above the working
//!   directory can arrive with the code it configures, so the keys that name a host binary, a guest
//!   image, a key path, a write root, or a jail id are read from the user file, the environment, or a
//!   flag. [`project_from`] is the enforcer: it destructures every field of [`UserConfig`] with no
//!   rest pattern, so a new key does not compile until it is classified.
//! - **Two vocabularies.** The *artifact and scratch* keys mirror their `BSX_*` env names (minus the
//!   prefix, lowercased), so a value is spelled the same wherever it comes from. The **operator-policy**
//!   keys deliberately do not: they are the host's posture, and routing them through the precedence
//!   above would let the caller they bound edit them (see [`UserConfig`]).
//! - **A misplaced or mistyped key is a typed error**, never a silent no-op: the file is parsed with
//!   `deny_unknown_fields`, and a project file naming a user-only key is refused rather than dropped.
//! - **The layering** composes a lookup for
//!   [`BootConfig::from_env_with`](bsx_engine::BootConfig::from_env_with), returning the real env var if
//!   set and a file's value otherwise, so the engine's env-key logic and defaults are not duplicated.
//!   The `log` key has no `BootConfig` field, so the CLI reads it from here directly.

use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};

use bsx_engine::{MAX_VCPUS, vcpus_supported};
use bsx_probes_loader::{Ipv4Cidr, Ipv6Cidr};
use serde::Deserialize;

use crate::policy::Policy;

/// The file name, both under `$HOME` and when discovered up from the cwd.
const FILE_NAME: &str = ".bsx.toml";

/// A parsed `.bsx.toml`. Every field is optional (an absent key falls through to the env/default
/// layer); every key mirrors an `BSX_*` env name. Unknown keys are rejected so a typo can't
/// silently no-op.
///
/// Named for where it may be read from in full: `$HOME/.bsx.toml`. A file found above the working
/// directory is parsed into this type too, then narrowed by [`project_from`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// Mirrors `BSX_FIRECRACKER`.
    firecracker: Option<PathBuf>,
    /// Mirrors `BSX_KERNEL`.
    kernel: Option<PathBuf>,
    /// Mirrors `BSX_ROOTFS`.
    rootfs: Option<PathBuf>,
    /// Mirrors `BSX_MARKER`.
    marker: Option<String>,
    /// Mirrors `BSX_SCRATCH_DIR`.
    scratch_dir: Option<PathBuf>,
    /// Mirrors `BSX_REQUIRE_LIMITS` (fail closed when cgroup caps can't be applied).
    require_limits: Option<bool>,
    /// Mirrors `BSX_GATEWAY`: the default route this host hands its guests. A host fact, so it
    /// belongs in the file rather than on every command line; `--gateway` overrides it.
    gateway: Option<Ipv4Addr>,
    /// Mirrors `BSX_RESOLVER`: the resolver this host's guests are told to use. Read only when a
    /// gateway resolved, since a resolver the guest cannot route to is inert.
    resolver: Option<Ipv4Addr>,
    /// Mirrors `BSX_LOG` (the stderr `tracing` filter). No `BootConfig` field; the CLI reads it.
    log: Option<String>,
    /// Mirrors `BSX_SIGNING_KEY` (the host record-signing key path). No `BootConfig`
    /// field; the CLI reads it to sign `--record`.
    signing_key: Option<PathBuf>,
    /// Mirrors `BSX_TRUSTED_KEYS`: public keys (`key_id` hex) `bsx verify` trusts *in addition*
    /// to the current signing key, so rotating the host key doesn't invalidate already-signed records.
    /// No `BootConfig` field.
    trusted_keys: Option<Vec<String>>,

    // Operator policy. The ceilings and postures here do **not** mirror `BSX_*` env keys: they are
    // the host's posture, not a per-invocation knob, and they exist precisely to bound what a caller
    // may ask for, so routing them through the flags > env > file precedence would let the caller
    // they bound edit them. The two jail ids are the exception, and carry `BSX_JAIL_UID` /
    // `BSX_JAIL_GID`: an operator sets them per host, so they layer like the artifact keys and are
    // read from the user file alone. See `crate::policy` for where this binds and where it is only a
    // guardrail.
    /// House default vCPUs when a caller does not ask.
    #[serde(default, deserialize_with = "vcpus_field")]
    vcpus: Option<NonZeroU8>,
    /// House default guest memory, MiB.
    mem_mib: Option<NonZeroU32>,
    /// House default wall-clock budget, seconds.
    wall_secs: Option<u64>,
    /// House default captured-output cap, bytes.
    output_cap: Option<usize>,
    /// Ceiling on vCPUs; a caller asking for more is refused.
    #[serde(default, deserialize_with = "max_vcpus_field")]
    max_vcpus: Option<NonZeroU8>,
    /// Ceiling on guest memory, MiB.
    max_mem_mib: Option<NonZeroU32>,
    /// Ceiling on the wall-clock budget, seconds.
    max_wall_secs: Option<u64>,
    /// Ceiling on the captured-output cap, bytes.
    max_output_cap: Option<usize>,
    /// Withdraw the `--unjailed` opt-out on this host.
    require_jail: Option<bool>,
    /// The uid the jailer drops the VMM to. An operator fact, not a caller's: on a host running
    /// more than one sandbox, a caller who chose its own could name a neighbour's.
    jail_uid: Option<u32>,
    /// The gid the jailer drops the VMM to. See [`jail_uid`](Self::jail_uid).
    jail_gid: Option<u32>,
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

/// A vCPU count from the file, validated at deserialize time against what the VMM can actually boot.
/// `NonZeroU8` already refuses `0`; [`vcpus_supported`] is the rest of the rule (1 or an even number
/// up to [`MAX_VCPUS`]), which the `--vcpus` flag has always applied through `crate::parse_vcpus`.
///
/// `key` is passed in because `parse` keeps only the bare message from a TOML error, dropping the
/// span that would otherwise point at the line; without it a file setting both keys would not say
/// which one it meant.
fn bootable_vcpus<'de, D>(key: &str, deserializer: D) -> Result<Option<NonZeroU8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let parsed = Option::<NonZeroU8>::deserialize(deserializer)?;
    if let Some(v) = parsed
        && !vcpus_supported(v.get())
    {
        return Err(serde::de::Error::custom(format!(
            "{key} must be 1 or an even number in 1..={MAX_VCPUS}, got {v}"
        )));
    }
    Ok(parsed)
}

/// [`bootable_vcpus`] for the `vcpus` key.
fn vcpus_field<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<NonZeroU8>, D::Error> {
    bootable_vcpus("vcpus", d)
}

/// [`bootable_vcpus`] for the `max_vcpus` key. The ceiling takes the same check, not for symmetry:
/// [`Policy::resolve`] clamps a house default *down to* the ceiling, so an odd `max_vcpus` turns a
/// legal `vcpus` into an illegal boot count, and the refusal then names a number nobody wrote.
fn max_vcpus_field<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<NonZeroU8>, D::Error> {
    bootable_vcpus("max_vcpus", d)
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
        parse_v4_cidr(&s, "max_egress_v4").map(CidrV4)
    }
}

/// The v6 twin of [`CidrV4`], for `max_egress_v6` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
struct CidrV6(Ipv6Cidr);

impl TryFrom<String> for CidrV6 {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_v6_cidr(&s, "max_egress_v6").map(CidrV6)
    }
}

impl UserConfig {
    /// The nearest `.bsx.toml` walking up from `start`, or `None` if none exists between `start`
    /// and the filesystem root.
    fn nearest(start: &Path) -> Option<PathBuf> {
        let mut dir = Some(start);
        while let Some(d) = dir {
            let candidate = d.join(FILE_NAME);
            if candidate.is_file() {
                return Some(candidate);
            }
            dir = d.parent();
        }
        None
    }

    /// Read + parse one `.bsx.toml`, naming the file in any error.
    fn parse_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        Self::parse(&text).map_err(|message| ConfigError::Parse {
            path: path.to_path_buf(),
            message,
        })
    }

    /// Read + parse an already-opened `.bsx.toml`, so the file parsed is the one that was judged.
    fn parse_open(mut file: std::fs::File, path: &Path) -> Result<Self, ConfigError> {
        use std::io::Read as _;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|e| ConfigError::Read {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        Self::parse(&text).map_err(|message| ConfigError::Parse {
            path: path.to_path_buf(),
            message,
        })
    }

    /// Parse TOML text into a [`UserConfig`], surfacing an unknown-key/type error as a plain string
    /// (the pure core the file reader and the unit tests share).
    fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.message().to_string())
    }

    /// The file's value for an `BSX_*` env key, as an [`OsString`], or `None` if the key is unset
    /// in the file, the shape [`from_env_with`](bsx_engine::BootConfig::from_env_with) consumes, so
    /// the file slots in *under* the environment in one composed lookup.
    #[must_use]
    pub fn env_value(&self, key: &str) -> Option<OsString> {
        match key {
            "BSX_FIRECRACKER" => self
                .firecracker
                .as_ref()
                .map(|p| p.as_os_str().to_os_string()),
            "BSX_KERNEL" => self.kernel.as_ref().map(|p| p.as_os_str().to_os_string()),
            "BSX_ROOTFS" => self.rootfs.as_ref().map(|p| p.as_os_str().to_os_string()),
            "BSX_MARKER" => self.marker.as_ref().map(OsString::from),
            "BSX_SCRATCH_DIR" => self
                .scratch_dir
                .as_ref()
                .map(|p| p.as_os_str().to_os_string()),

            // A bool rendered as the canonical token `from_env_with`'s `parse_env_bool` accepts, so
            // the file slots under the env in the same composed lookup as the string keys.
            "BSX_REQUIRE_LIMITS" => self
                .require_limits
                .map(|b| OsString::from(if b { "true" } else { "false" })),
            // Rendered as decimal text, so the file goes through `from_env_with`'s own id parse
            // (which is what refuses zero) rather than a second validation path that could drift.
            "BSX_JAIL_UID" => self.jail_uid.map(|u| OsString::from(u.to_string())),
            "BSX_JAIL_GID" => self.jail_gid.map(|g| OsString::from(g.to_string())),
            // Rendered back to the dotted-quad text `from_env_with` parses, so the file slots under
            // the env in the same composed lookup rather than needing a second path into the config.
            "BSX_GATEWAY" => self.gateway.map(|a| OsString::from(a.to_string())),
            "BSX_RESOLVER" => self.resolver.map(|a| OsString::from(a.to_string())),
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
            max_egress_v4: cidrs_v4(self.max_egress_v4.as_deref()),
            max_egress_v6: cidrs_v6(self.max_egress_v6.as_deref()),
        }
    }
}

/// Already validated at deserialize time (`CidrV4`), so this projection cannot drop an entry.
fn cidrs_v4(list: Option<&[CidrV4]>) -> Vec<Ipv4Cidr> {
    list.unwrap_or(&[]).iter().map(|c| c.0).collect()
}

/// The v6 twin of [`cidrs_v4`].
fn cidrs_v6(list: Option<&[CidrV6]>) -> Vec<Ipv6Cidr> {
    list.unwrap_or(&[]).iter().map(|c| c.0).collect()
}

/// What a `.bsx.toml` found above the working directory may set: house defaults a caller could pass
/// on the command line anyway, and ceilings and postures that only ever refuse more than they
/// permit. It carries no path, key, or identity field, so no lookup over it can return one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProjectConfig {
    marker: Option<String>,
    log: Option<String>,
    require_limits: bool,
    policy: Policy,
}

impl ProjectConfig {
    /// The file's `marker`, if set.
    #[must_use]
    pub fn marker(&self) -> Option<&str> {
        self.marker.as_deref()
    }

    /// The file's `log` filter, if set.
    #[must_use]
    pub fn log(&self) -> Option<&str> {
        self.log.as_deref()
    }

    /// Whether the file asks for `require_limits`. There is no "asks it off": see [`project_from`].
    #[must_use]
    pub fn require_limits(&self) -> bool {
        self.require_limits
    }

    /// The operator policy this file declares.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

/// The `BSX_*` variable a user-only key mirrors, or `None` for the keys that have none.
fn env_mirror(key: &str) -> Option<&'static str> {
    match key {
        "firecracker" => Some("BSX_FIRECRACKER"),
        "kernel" => Some("BSX_KERNEL"),
        "rootfs" => Some("BSX_ROOTFS"),
        "scratch_dir" => Some("BSX_SCRATCH_DIR"),
        "signing_key" => Some("BSX_SIGNING_KEY"),
        "trusted_keys" => Some("BSX_TRUSTED_KEYS"),
        "gateway" => Some("BSX_GATEWAY"),
        "resolver" => Some("BSX_RESOLVER"),
        "jail_uid" => Some("BSX_JAIL_UID"),
        "jail_gid" => Some("BSX_JAIL_GID"),
        _ => None,
    }
}

/// Narrow a parsed file to what a project-local one may carry, or name every user-only key it set.
///
/// **This function is the enforcer for the two trust levels.** It destructures every field of
/// [`UserConfig`] with no rest pattern, so a new key does not compile here until someone classifies
/// it, and a binding that is neither returned nor refused trips the workspace's denied
/// `unused_variables`.
///
/// # Errors
/// The names of the user-only keys the file set, in declaration order.
pub fn project_from(cfg: UserConfig) -> Result<ProjectConfig, Vec<&'static str>> {
    let UserConfig {
        // User-only. Each names a binary this host executes, an image it boots, a key it signs or
        // verifies with, a directory it writes into, or the identity a VMM drops to.
        firecracker,
        kernel,
        rootfs,
        scratch_dir,
        signing_key,
        trusted_keys,
        records_dir,
        gateway,
        resolver,
        jail_uid,
        jail_gid,
        // Project-honored.
        marker,
        log,
        require_limits,
        vcpus,
        mem_mib,
        wall_secs,
        output_cap,
        max_vcpus,
        max_mem_mib,
        max_wall_secs,
        max_output_cap,
        require_jail,
        allow_net,
        require_record,
        max_egress_v4,
        max_egress_v6,
    } = cfg;

    let refused: Vec<&'static str> = [
        ("firecracker", firecracker.is_some()),
        ("kernel", kernel.is_some()),
        ("rootfs", rootfs.is_some()),
        ("scratch_dir", scratch_dir.is_some()),
        ("signing_key", signing_key.is_some()),
        ("trusted_keys", trusted_keys.is_some()),
        ("records_dir", records_dir.is_some()),
        ("gateway", gateway.is_some()),
        ("resolver", resolver.is_some()),
        ("jail_uid", jail_uid.is_some()),
        ("jail_gid", jail_gid.is_some()),
    ]
    .into_iter()
    .filter_map(|(name, set)| set.then_some(name))
    .collect();
    if !refused.is_empty() {
        return Err(refused);
    }

    Ok(ProjectConfig {
        marker,
        log,
        // Only the strengthening direction travels, so a project `false` contributes nothing and
        // cannot displace a user file's `true` in the composed lookup.
        require_limits: require_limits.unwrap_or(false),
        policy: Policy {
            vcpus,
            mem_mib,
            wall_secs,
            output_cap,
            max_vcpus,
            max_mem_mib,
            max_wall_secs,
            max_output_cap,
            require_jail: require_jail.unwrap_or(false),
            allow_net,
            require_record: require_record.unwrap_or(false),
            // `records_dir` is user-only and was refused above.
            records_dir: None,
            max_egress_v4: cidrs_v4(max_egress_v4.as_deref()),
            max_egress_v6: cidrs_v6(max_egress_v6.as_deref()),
        },
    })
}

/// Parse one IPv4 egress-ceiling entry, `IP` or `IP/PREFIX`. `context` is what the operator wrote it
/// in (a config key, or `--max-egress`), so the same parser serves both without either message
/// naming the other's spelling.
pub(crate) fn parse_v4_cidr(s: &str, context: &str) -> Result<Ipv4Cidr, String> {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            let addr: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("invalid IPv4 address {ip:?} in {context} entry {s:?}"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("invalid CIDR prefix {prefix:?} in {context} entry {s:?}"))?;
            Ipv4Cidr::new(addr, prefix).map_err(|e| format!("{context} entry {s:?}: {e}"))
        }
        None => {
            let addr: Ipv4Addr = s
                .parse()
                .map_err(|_| format!("invalid IPv4 address in {context} entry {s:?}"))?;
            Ok(Ipv4Cidr::host(addr))
        }
    }
}

/// The v6 twin of [`parse_v4_cidr`].
pub(crate) fn parse_v6_cidr(s: &str, context: &str) -> Result<Ipv6Cidr, String> {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            let addr: Ipv6Addr = ip
                .parse()
                .map_err(|_| format!("invalid IPv6 address {ip:?} in {context} entry {s:?}"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("invalid CIDR prefix {prefix:?} in {context} entry {s:?}"))?;
            Ipv6Cidr::new(addr, prefix).map_err(|e| format!("{context} entry {s:?}: {e}"))
        }
        None => {
            let addr: Ipv6Addr = s
                .parse()
                .map_err(|_| format!("invalid IPv6 address in {context} entry {s:?}"))?;
            Ok(Ipv6Cidr::host(addr))
        }
    }
}

/// A `.bsx.toml` the CLI could not use. Every variant names the file, so a message can send the
/// reader to the line they wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file exists but could not be read.
    Read { path: PathBuf, message: String },
    /// The file is not valid TOML, or names a key that does not exist.
    Parse { path: PathBuf, message: String },
    /// The user file is there, but another local user could have authored or replaced it.
    Untrusted(String),
    /// A project-local file set keys that are read from the user file, the environment, or a flag.
    UserOnlyKeys {
        path: PathBuf,
        user_path: Option<PathBuf>,
        keys: Vec<&'static str>,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read { path, message } => write!(f, "read {}: {message}", path.display()),
            ConfigError::Parse { path, message } => write!(f, "{}: {message}", path.display()),
            // Already names the file and the fix; re-prefixing would print the path twice.
            ConfigError::Untrusted(message) => write!(f, "{message}"),
            ConfigError::UserOnlyKeys {
                path,
                user_path,
                keys,
            } => {
                let names: Vec<String> = keys.iter().map(|k| format!("`{k}`")).collect();
                let names = names.join(", ");
                let (verb, pronoun) = if keys.len() == 1 {
                    ("is", "it")
                } else {
                    ("are", "them")
                };
                // Name the `BSX_*` route only when every refused key has one: `records_dir` has no
                // mirror, so a blanket "the matching variable" would send the reader to nothing.
                let envs = keys
                    .iter()
                    .map(|k| env_mirror(k))
                    .collect::<Option<Vec<_>>>()
                    .map(|v| v.join(" / "));
                let (source, fix) = match (user_path, &envs) {
                    (Some(p), Some(e)) => (
                        format!("{} or {e}", p.display()),
                        format!("set {pronoun} in {}", p.display()),
                    ),
                    (Some(p), None) => (
                        p.display().to_string(),
                        format!("set {pronoun} in {}", p.display()),
                    ),
                    (None, Some(e)) => (
                        format!("{e}, since $HOME does not resolve here"),
                        format!("set {e}"),
                    ),
                    (None, None) => (
                        "$HOME/.bsx.toml, which does not resolve here".to_string(),
                        "set $HOME so the user config resolves".to_string(),
                    ),
                };
                write!(
                    f,
                    "{}: {names} {verb} read from {source}, not from a file found above the working \
                     directory, because such a file can arrive with the code it configures. Remove \
                     {pronoun} from this file, or {fix}.",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The two config files this process reads: the user's own, and the project-local one.
///
/// Threading one of these instead of a bare parsed file is what keeps the trust levels apart at the
/// call sites: the accessors that reach a host binary, a key, or a jail id read [`Self::user`]
/// alone, and no lookup can reach a path through the project layer because [`ProjectConfig`] has no
/// path field to reach.
#[derive(Debug, Default, Clone)]
pub struct Sources {
    user: Option<UserConfig>,
    user_path: Option<PathBuf>,
    project: Option<ProjectConfig>,
    project_path: Option<PathBuf>,
}

impl Sources {
    /// Read `$HOME/.bsx.toml` and the nearest `.bsx.toml` above `cwd`.
    ///
    /// # Errors
    /// [`ConfigError`] if either file cannot be read or parsed, or if the project-local one sets a
    /// user-only key. A config the operator wrote but got wrong must fail loudly, not be skipped.
    pub fn discover(cwd: &Path) -> Result<Self, ConfigError> {
        Self::discover_with(cwd, std::env::var_os("HOME").map(PathBuf::from))
    }

    /// The pure core of [`discover`](Self::discover), taking `$HOME` rather than reading it, so
    /// every precedence case is unit-testable without mutating the process environment (`set_var`
    /// is `unsafe` in edition 2024 and races the parallel test runner).
    ///
    /// # Errors
    /// As [`discover`](Self::discover).
    pub(crate) fn discover_with(cwd: &Path, home: Option<PathBuf>) -> Result<Self, ConfigError> {
        // A relative `$HOME` names a different directory depending on where the process started, so
        // it does not identify the user's own file. Same filter `bsx_record`'s data dir applies.
        let user_path = home.filter(|h| h.is_absolute()).map(|h| h.join(FILE_NAME));
        // The user file is the one that still carries the keys reaching host execution and host
        // trust, so it is opened through the ownership and mode gate rather than by path. The
        // project file is not: it can set only knobs and postures, and gating it would refuse every
        // `0o664` file a developer on `umask 002` creates, for nothing.
        let user = match user_path.as_deref() {
            Some(p) => match crate::trust::open_trusted(p).map_err(ConfigError::Untrusted)? {
                Some(file) => Some(UserConfig::parse_open(file, p)?),
                None => None,
            },
            None => None,
        };

        // Walking up from a cwd under `$HOME` lands on the user's own file. Classifying it as a
        // project file would refuse the user their own keys, so identity is resolved first.
        let project_path = UserConfig::nearest(cwd).filter(|n| !same_file(n, user_path.as_deref()));
        let project = match project_path.as_deref() {
            Some(p) => {
                let parsed = UserConfig::parse_file(p)?;
                Some(
                    project_from(parsed).map_err(|keys| ConfigError::UserOnlyKeys {
                        path: p.to_path_buf(),
                        user_path: user_path.clone(),
                        keys,
                    })?,
                )
            }
            None => None,
        };

        Ok(Self {
            user,
            user_path,
            project,
            project_path,
        })
    }

    /// The composed `env > project > user` lookup
    /// [`BootConfig::from_env_with`](bsx_engine::BootConfig::from_env_with) consumes.
    pub fn boot_lookup(&self) -> impl Fn(&str) -> Option<OsString> + '_ {
        move |key| {
            std::env::var_os(key)
                .or_else(|| self.project_env(key))
                .or_else(|| self.user.as_ref().and_then(|u| u.env_value(key)))
        }
    }

    /// The project layer's contribution to the composed lookup. Two arms, and a third that returned
    /// a path could not be written: [`ProjectConfig`] holds no such field.
    fn project_env(&self, key: &str) -> Option<OsString> {
        let p = self.project.as_ref()?;
        match key {
            "BSX_MARKER" => p.marker().map(OsString::from),
            "BSX_REQUIRE_LIMITS" => p.require_limits().then(|| OsString::from("true")),
            _ => None,
        }
    }

    /// Where the user file was looked for, whether or not one is there.
    #[must_use]
    pub fn user_path(&self) -> Option<&Path> {
        self.user_path.as_deref()
    }

    /// The project-local file that was read, if one was.
    #[must_use]
    pub fn project_path(&self) -> Option<&Path> {
        self.project_path.as_deref()
    }
}

/// Whether `path` and `other` name the same file, resolving links so a `$HOME` that is itself a
/// symlink still recognises its own config.
fn same_file(path: &Path, other: Option<&Path>) -> bool {
    let Some(other) = other else { return false };
    match (path.canonicalize(), other.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => path == other,
    }
}

/// The operator policy for this process: the user file's, tightened by the project file's.
/// `run` and `shell` both source policy through here, so the two CLI paths agree.
///
/// The daemon deliberately does **not**: `serve` builds its [`Policy`] from its own flags, because a
/// daemon must not read a security control out of whatever directory it happened to be started in.
/// That divergence is the design, not drift, so this function is the CLI's single source and not the
/// process's.
#[must_use]
pub fn policy_of(sources: &Sources) -> Policy {
    let user = sources
        .user
        .as_ref()
        .map(UserConfig::policy)
        .unwrap_or_default();
    match sources.project.as_ref() {
        Some(p) => user.tightened_by(p.policy()),
        None => user,
    }
}

/// Resolve the host record-signing key path with `env (BSX_SIGNING_KEY) > file > default`
/// Like `log`, this has no `BootConfig` field, so its precedence is mirrored here.
/// The default is [`bsx_probes_loader::default_key_path`] (a data-dir path, generated on first use).
#[must_use]
pub fn signing_key_path(sources: &Sources) -> PathBuf {
    std::env::var_os("BSX_SIGNING_KEY")
        .map(PathBuf::from)
        .or_else(|| {
            sources
                .user
                .as_ref()
                .and_then(UserConfig::signing_key)
                .map(Path::to_path_buf)
        })
        .unwrap_or_else(bsx_probes_loader::default_key_path)
}

/// The configured set of extra trusted public keys (`key_id` hex) for `bsx verify`, the **union**
/// of `BSX_TRUSTED_KEYS` (comma-separated) and the file's `trusted_keys` list. A set, not an
/// override: every configured key stays trusted so a record signed before a key rotation still
/// verifies. Parsing/validation is the caller's (`TrustedKey::from_hex`).
#[must_use]
pub fn trusted_key_hexes(sources: &Sources) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(v) = std::env::var_os("BSX_TRUSTED_KEYS") {
        out.extend(
            v.to_string_lossy()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    // The user file only: this set is additive, so a file that could add to it could make a record
    // it signed verify against this host.
    if let Some(f) = sources.user.as_ref() {
        out.extend(f.trusted_keys().iter().cloned());
    }
    out
}

/// Resolve the stderr log filter with the full precedence `flag > env (BSX_LOG) > file > default`.
/// The `BootConfig` layers can't carry `log` (it has no field), so this mirrors that precedence for
/// the one config value that drives `tracing` instead of the engine.
#[must_use]
pub fn resolve_log(flag: Option<&str>, sources: &Sources) -> Option<String> {
    flag.map(str::to_string)
        .or_else(|| std::env::var("BSX_LOG").ok())
        .or_else(|| {
            sources
                .project
                .as_ref()
                .and_then(ProjectConfig::log)
                .map(str::to_string)
        })
        .or_else(|| {
            sources
                .user
                .as_ref()
                .and_then(UserConfig::log)
                .map(str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use bsx_test_support::ScratchDir;

    use super::*;

    #[test]
    fn unknown_key_is_a_typed_error_not_a_silent_no_op() {
        // A typo (`kernal`) must fail loudly, per the deny-unknown-fields contract.
        let err = UserConfig::parse("kernal = \"/x/vmlinux\"\n").expect_err("typo must error");
        assert!(
            err.contains("kernal") || err.contains("unknown"),
            "names the bad key: {err}"
        );
    }

    #[test]
    fn known_keys_parse_into_env_values() {
        let toml = UserConfig::parse(
            "kernel = \"/k/vmlinux\"\nrootfs = \"/r/root.ext4\"\nmarker = \"UP\"\nlog = \"debug\"\n",
        )
        .expect("valid toml parses");
        assert_eq!(
            toml.env_value("BSX_KERNEL"),
            Some(OsString::from("/k/vmlinux"))
        );
        assert_eq!(
            toml.env_value("BSX_ROOTFS"),
            Some(OsString::from("/r/root.ext4"))
        );
        assert_eq!(toml.env_value("BSX_MARKER"), Some(OsString::from("UP")));
        assert_eq!(
            toml.env_value("BSX_FIRECRACKER"),
            None,
            "unset key falls through"
        );
        assert_eq!(toml.log(), Some("debug"));
    }

    #[test]
    fn jail_ids_render_env_tokens_the_engine_parses_back_onto_the_jail() {
        // The file ids slot under the env in one composed lookup, like every other key: `env_value`
        // renders decimal text and `from_env_with` parses it back, so the file never gets a second
        // validation path that could accept an id the env layer refuses.
        let set =
            UserConfig::parse("jail_uid = 20001\njail_gid = 20002\n").expect("valid toml parses");
        assert_eq!(set.env_value("BSX_JAIL_UID"), Some(OsString::from("20001")));
        assert_eq!(set.env_value("BSX_JAIL_GID"), Some(OsString::from("20002")));
        let jail = bsx_engine::BootConfig::from_env_with(|k| set.env_value(k))
            .jail
            .expect("an id in the file materialises the jail it names");
        assert_eq!((jail.uid, jail.gid), (20001, 20002));

        // Unset leaves the jail alone: the CLI's own `unwrap_or_default()` supplies the pinned ids,
        // and an unjailed boot drops the whole `Jail` regardless.
        let bare = UserConfig::parse("marker = \"UP\"\n").expect("valid toml parses");
        assert!(bare.env_value("BSX_JAIL_UID").is_none());
        assert!(
            bsx_engine::BootConfig::from_env_with(|k| bare.env_value(k))
                .jail
                .is_none()
        );
    }

    #[test]
    fn require_limits_bool_renders_the_env_token_from_env_parses() {
        // The file bool slots under the env in one composed lookup: `env_value` renders the canonical
        // token, and `BootConfig::from_env_with` parses it back onto the posture (env > file > default).
        let on = UserConfig::parse("require_limits = true\n").expect("valid toml parses");
        assert_eq!(
            on.env_value("BSX_REQUIRE_LIMITS"),
            Some(OsString::from("true"))
        );
        assert!(bsx_engine::BootConfig::from_env_with(|k| on.env_value(k)).require_limits);

        let off = UserConfig::parse("require_limits = false\n").expect("valid toml parses");
        assert_eq!(
            off.env_value("BSX_REQUIRE_LIMITS"),
            Some(OsString::from("false"))
        );
        assert!(!bsx_engine::BootConfig::from_env_with(|k| off.env_value(k)).require_limits);

        // Unset in the file falls through to the default.
        let bare = UserConfig::parse("marker = \"UP\"\n").expect("valid toml parses");
        assert_eq!(bare.env_value("BSX_REQUIRE_LIMITS"), None);
    }

    #[test]
    fn signing_key_parses_from_the_file_layer() {
        let toml =
            UserConfig::parse("signing_key = \"/keys/host.ed25519\"\n").expect("valid toml parses");
        assert_eq!(
            toml.signing_key(),
            Some(Path::new("/keys/host.ed25519")),
            "the file layer carries the record-signing key path"
        );
        assert_eq!(
            UserConfig::default().signing_key(),
            None,
            "unset falls through"
        );
    }

    #[test]
    fn trusted_keys_parse_as_a_list_from_the_file_layer() {
        let toml =
            UserConfig::parse("trusted_keys = [\"aa\", \"bb\"]\n").expect("valid toml parses");
        assert_eq!(toml.trusted_keys(), ["aa".to_string(), "bb".to_string()]);
        assert!(
            UserConfig::default().trusted_keys().is_empty(),
            "unset is an empty set, not an error"
        );
    }

    #[test]
    fn env_beats_file_beats_default_via_the_composed_lookup() {
        // The layering `BootConfig::from_env_with` sees: env wins over file, file over default. Model
        // that composition here without a real process env or a real BootConfig.
        let file = UserConfig::parse("kernel = \"/file/vmlinux\"\nrootfs = \"/file/root\"\n")
            .expect("valid");
        // A fake environment that only sets the kernel.
        let env = |key: &str| -> Option<OsString> {
            match key {
                "BSX_KERNEL" => Some(OsString::from("/env/vmlinux")),
                _ => None,
            }
        };
        // The composed lookup: env first, then file.
        let composed = |key: &str| env(key).or_else(|| file.env_value(key));
        // kernel: env wins over the file.
        assert_eq!(composed("BSX_KERNEL"), Some(OsString::from("/env/vmlinux")));
        // rootfs: only the file has it → file wins over the default.
        assert_eq!(composed("BSX_ROOTFS"), Some(OsString::from("/file/root")));
        // marker: neither sets it → None, so the BootConfig default stands.
        assert_eq!(composed("BSX_MARKER"), None);
    }

    #[test]
    fn malformed_egress_ceiling_is_a_typed_error_not_a_dropped_entry() {
        // A dropped ceiling entry *widens* the ceiling (empty means unrestricted in
        // `Policy::check_egress`), so a typo must refuse the whole file, loudly, at parse time.
        let err = UserConfig::parse("max_egress_v4 = [\"10.0.0.0-8\"]\n")
            .expect_err("a malformed CIDR entry must fail the parse");
        assert!(
            err.contains("10.0.0.0-8") && err.contains("max_egress_v4"),
            "error names the entry and the key: {err}"
        );

        let err = UserConfig::parse("max_egress_v4 = [\"10.0.0.0/33\"]\n")
            .expect_err("an out-of-range prefix must fail the parse");
        assert!(err.contains("10.0.0.0/33"), "error names the entry: {err}");

        let err = UserConfig::parse("max_egress_v6 = [\"fd00::/129\"]\n")
            .expect_err("an out-of-range v6 prefix must fail the parse");
        assert!(err.contains("fd00::/129"), "error names the entry: {err}");
    }

    #[test]
    fn egress_ceilings_parse_into_the_policy_unabridged() {
        let toml = UserConfig::parse(
            "max_egress_v4 = [\"10.0.0.0/8\", \"192.0.2.7\"]\nmax_egress_v6 = [\"fd00::/8\"]\n",
        )
        .expect("valid ceilings parse");
        let policy = toml.policy();
        assert_eq!(
            policy.max_egress_v4,
            vec![
                bsx_probes_loader::Ipv4Cidr::new("10.0.0.0".parse().unwrap(), 8).unwrap(),
                bsx_probes_loader::Ipv4Cidr::host("192.0.2.7".parse().unwrap()),
            ],
            "every entry reaches the policy: a bare host reads as /32"
        );
        assert_eq!(
            policy.max_egress_v6,
            vec![bsx_probes_loader::Ipv6Cidr::new("fd00::".parse().unwrap(), 8).unwrap()]
        );
        // Absent keys stay "no restriction": the permissive default, explicitly chosen.
        let bare = UserConfig::parse("marker = \"UP\"\n").expect("valid");
        assert!(bare.policy().max_egress_v4.is_empty());
        assert!(bare.policy().max_egress_v6.is_empty());
    }

    /// A three-level tree under a reclaimed scratch dir, with `.bsx.toml` bodies written at the
    /// levels `at` names. Returns the scratch dir (kept alive by the caller) and the leaf.
    fn tree(tag: &str, at: &[(&str, &str)]) -> (ScratchDir, PathBuf) {
        let dir = ScratchDir::created(tag);
        let leaf = dir.path().join("a/b");
        std::fs::create_dir_all(&leaf).expect("mkdirs");
        for (rel, body) in at {
            let p = dir.path().join(rel).join(FILE_NAME);
            std::fs::write(&p, body).expect("write a .bsx.toml into the tree");
        }
        (dir, leaf)
    }

    #[test]
    fn nearest_project_file_shadows_a_farther_one() {
        let (dir, leaf) = tree(
            "cfg-nearest",
            &[
                ("", "marker = \"FARTHER\"\n"),
                ("a", "marker = \"NEARER\"\n"),
            ],
        );
        let sources = Sources::discover_with(&leaf, None).expect("discover ok");
        assert_eq!(
            sources.project.as_ref().and_then(ProjectConfig::marker),
            Some("NEARER"),
            "the nearer file shadows the farther one"
        );
        assert_eq!(
            sources.project_path(),
            Some(dir.path().join("a").join(FILE_NAME).as_path())
        );

        // None above a tree that has no file at all.
        let empty = ScratchDir::created("cfg-empty");
        let bare = Sources::discover_with(empty.path(), None).expect("ok");
        assert!(bare.project_path().is_none() && bare.user_path().is_none());
    }

    #[test]
    fn the_user_file_supplies_artifact_paths_when_a_project_file_shadows_it() {
        // What the split exists for: a project file setting one knob must not shadow the user's whole
        // file and take the artifact paths with it.
        let home = ScratchDir::created("cfg-home");
        std::fs::write(
            home.path().join(FILE_NAME),
            "kernel = \"/user/vmlinux\"\nvcpus = 8\n",
        )
        .expect("write user file");
        let (_dir, leaf) = tree("cfg-shadow", &[("a", "vcpus = 2\n")]);

        let sources =
            Sources::discover_with(&leaf, Some(home.path().to_path_buf())).expect("discover ok");
        let lookup = sources.boot_lookup();
        assert_eq!(
            lookup("BSX_KERNEL"),
            Some(OsString::from("/user/vmlinux")),
            "the user file still supplies the kernel path"
        );
        assert_eq!(
            policy_of(&sources).vcpus.map(NonZeroU8::get),
            Some(2),
            "and the nearer file still wins for a house default"
        );
    }

    #[test]
    fn a_project_file_that_sets_a_user_only_key_is_refused_naming_the_key_and_where_it_may_live() {
        let home = ScratchDir::created("cfg-refuse-home");
        std::fs::write(home.path().join(FILE_NAME), "vcpus = 1\n").expect("write user file");
        let (_dir, leaf) = tree("cfg-refuse", &[("a", "kernel = \"/evil/vmlinux\"\n")]);

        let err = Sources::discover_with(&leaf, Some(home.path().to_path_buf()))
            .expect_err("a project file may not name `kernel`");
        let msg = err.to_string();
        assert!(msg.contains("`kernel`"), "names the key: {msg}");
        assert!(msg.contains("BSX_KERNEL"), "names the env route: {msg}");
        assert!(
            msg.contains(&home.path().join(FILE_NAME).display().to_string()),
            "names where it may live: {msg}"
        );
    }

    #[test]
    fn project_config_drops_every_user_only_key() {
        let all = "firecracker = \"/f\"\nkernel = \"/k\"\nrootfs = \"/r\"\n\
                   scratch_dir = \"/s\"\nsigning_key = \"/sk\"\ntrusted_keys = [\"aa\"]\n\
                   records_dir = \"/rd\"\ngateway = \"10.0.0.1\"\nresolver = \"10.0.0.2\"\n\
                   jail_uid = 20001\njail_gid = 20002\nvcpus = 2\n";
        let keys = project_from(UserConfig::parse(all).expect("valid toml"))
            .expect_err("every user-only key must be refused");
        assert_eq!(
            keys,
            vec![
                "firecracker",
                "kernel",
                "rootfs",
                "scratch_dir",
                "signing_key",
                "trusted_keys",
                "records_dir",
                "gateway",
                "resolver",
                "jail_uid",
                "jail_gid",
            ],
            "all eleven are named, in declaration order"
        );
    }

    #[test]
    fn a_project_file_at_the_user_path_is_read_once_as_the_user_file() {
        // Working inside `$HOME` is the ordinary case: the walk up lands on the user's own file,
        // which must keep its full authority rather than be narrowed as a project file.
        let home = ScratchDir::created("cfg-identity");
        std::fs::write(home.path().join(FILE_NAME), "kernel = \"/user/vmlinux\"\n")
            .expect("write user file");
        let sources = Sources::discover_with(home.path(), Some(home.path().to_path_buf()))
            .expect("the user's own file is not a project file");
        assert!(
            sources.project_path().is_none(),
            "not classified as a project file"
        );
        assert_eq!(
            sources.boot_lookup()("BSX_KERNEL"),
            Some(OsString::from("/user/vmlinux"))
        );
    }

    #[test]
    fn no_home_means_no_user_config_and_a_project_file_still_supplies_the_house_defaults() {
        // 4, not 3: an odd count above 1 is not a value this file may carry, and the number here is
        // incidental to what the test is about.
        let (_dir, leaf) = tree("cfg-nohome", &[("a", "vcpus = 4\n")]);
        let sources = Sources::discover_with(&leaf, None).expect("discover ok");
        assert!(sources.user_path().is_none());
        assert_eq!(policy_of(&sources).vcpus.map(NonZeroU8::get), Some(4));
    }

    #[test]
    fn a_vcpu_count_the_vmm_cannot_boot_is_refused_by_the_file_that_named_it() {
        // The file keys apply the rule `--vcpus` applies, not just `NonZeroU8`'s rejection of `0`: an
        // odd count above 1 must be refused here, naming the file and the key that set it, rather than
        // at `Vm::boot`, which can name only Firecracker's rule.
        for bad in ["vcpus = 7\n", "vcpus = 33\n", "max_vcpus = 3\n"] {
            let (_dir, leaf) = tree("cfg-vcpus-bad", &[("a", bad)]);
            let msg = Sources::discover_with(&leaf, None)
                .expect_err(&format!("{bad:?} names a count no VM can boot"))
                .to_string();
            let key = bad.split_whitespace().next().expect("the key");
            assert!(
                msg.contains(key) && msg.contains("1 or an even number"),
                "the refusal names the key and states the rule: {msg}"
            );
        }

        // Why the *ceiling* takes the same check: `resolve` clamps a house default down to the
        // ceiling, so `vcpus = 8` under `max_vcpus = 7` would otherwise resolve to 7 and be refused at
        // boot for a number the operator never wrote.
        let (_dir, leaf) = tree("cfg-vcpus-clamp", &[("a", "vcpus = 8\nmax_vcpus = 7\n")]);
        assert!(
            Sources::discover_with(&leaf, None).is_err(),
            "an odd ceiling silently turns a legal default into an illegal boot count"
        );

        // What the rule admits is untouched: 1, and the even numbers up to the cap.
        for good in [
            "vcpus = 1\n",
            "vcpus = 2\n",
            "vcpus = 32\n",
            "max_vcpus = 8\n",
        ] {
            let (_dir, leaf) = tree("cfg-vcpus-ok", &[("a", good)]);
            assert!(
                Sources::discover_with(&leaf, None).is_ok(),
                "{good:?} is a count the VMM boots"
            );
        }
    }

    #[test]
    fn a_project_require_limits_can_tighten_the_posture_and_cannot_relax_it() {
        let home = ScratchDir::created("cfg-rl-home");
        std::fs::write(home.path().join(FILE_NAME), "require_limits = true\n").expect("write");

        // A project file saying `false` contributes nothing, so the user's `true` still stands.
        let (_off, leaf_off) = tree("cfg-rl-off", &[("a", "require_limits = false\n")]);
        let relaxed = Sources::discover_with(&leaf_off, Some(home.path().to_path_buf()))
            .expect("discover ok");
        assert_eq!(
            relaxed.boot_lookup()("BSX_REQUIRE_LIMITS"),
            Some(OsString::from("true")),
            "a project file cannot relax the user's posture"
        );

        // And it can strengthen one the user never set.
        let (_on, leaf_on) = tree("cfg-rl-on", &[("a", "require_limits = true\n")]);
        let tightened = Sources::discover_with(&leaf_on, None).expect("discover ok");
        assert_eq!(
            tightened.boot_lookup()("BSX_REQUIRE_LIMITS"),
            Some(OsString::from("true"))
        );
    }
}
