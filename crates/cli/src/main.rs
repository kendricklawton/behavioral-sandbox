//! The `bsx` CLI, drive the sandbox lifecycle: boot a microVM, run one command in it (`run`),
//! or hold it open as an interactive stateful session (`shell`), with the run's host-observed
//! **audit surface** on flags (`--trace`/`--record`/`--record-summary`/`--watch`, see [`audit`]).
//!
//! `tracing` logs to **stderr** and **stdout** is reserved for a run's result, so `bsx run … 2>/dev/null`
//! stays pipe-clean; the `--watch` live view draws on stderr for the same reason. The log filter resolves
//! flags > env (`BSX_LOG`) > file > default. Both subcommands run **jailed by default** with `--unjailed`
//! as the explicit opt-out, and both point at the env-layered artifacts.
#![forbid(unsafe_code)]

mod audit;
mod config;
mod deadline;
mod doctor;
mod metrics;
mod policy;
mod serve;
mod session;
mod trace;
mod trust;
mod verify;
mod watch;

use std::io::{IsTerminal, Read, Write};
use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::policy::{AllowRule, Policy, Requested, parse_allow};
use bsx_engine::{
    Artifact, BootConfig, ErrorKind, Limits, MAX_PAYLOAD, Sandbox, VmmError, sweep_orphans,
};
use bsx_engine::{MAX_VCPUS, vcpus_supported};
use bsx_probes_loader::{EgressPolicy, MAX_POLICY_RULES, Timing};
use clap::{Parser, Subcommand};

/// Exit code for an operational failure (a boot/exec/channel error, as opposed to the guest
/// command's own exit code): conventional "2", named so the intent is legible at the
/// `ExitCode::from` site, the same convention (and name) as the guest agent's.
const EXIT_OPERATIONAL: u8 = 2;

/// The version of the `--json` **run-result** contract (exit code, streams, artifacts, metrics,
/// limits), versioned independently of the audit record's `AUDIT_SCHEMA_VERSION`: additive within a
/// version, a rename or removal bumps it (docs/cli.md).
const RUN_RESULT_SCHEMA: u32 = 1;

/// A CLI-layer failure, kept distinct from the engine's [`VmmError`] so the library's typed error (and
/// its `kind()` buckets, pinned by embedders) is never minted for a fault that is the CLI's own: a bad
/// flag combination, a refused artifact path, a local file write. `Engine` passes the driver's error
/// through untouched; both print as `bsx: <reason>` and exit 2, so the split is for honesty rather
/// than for different handling.
#[derive(Debug)]
enum CliError {
    /// A CLI-layer fault (usage or local I/O), phrased for the operator.
    Cli(String),
    /// The engine's typed error, passed through.
    Engine(VmmError),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cli(m) => f.write_str(m),
            Self::Engine(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cli(_) => None,
            // Transparent wrapper: `Display` already prints `e`'s own message, so the chain must
            // continue from `e`'s cause, or a chain-walking reporter prints the message twice.
            Self::Engine(e) => e.source(),
        }
    }
}

#[cfg(test)]
mod cli_error_tests {
    use super::*;

    #[test]
    fn engine_wrapper_is_transparent_not_a_duplicate_chain() {
        let err = CliError::from(VmmError::Vmm("boot failed".into()));
        // Display carries the engine message once ...
        assert_eq!(err.to_string(), "vmm error: boot failed");
        // ... so `source()` must not surface the same message again.
        let dup = std::error::Error::source(&err).is_some_and(|s| s.to_string() == err.to_string());
        assert!(!dup, "source() repeats what Display already printed");
    }
}

impl From<VmmError> for CliError {
    fn from(e: VmmError) -> Self {
        Self::Engine(e)
    }
}

impl From<config::ConfigError> for CliError {
    fn from(e: config::ConfigError) -> Self {
        Self::Cli(e.to_string())
    }
}

impl From<policy::PolicyError> for CliError {
    /// A policy refusal is a caller-facing CLI error: the message already names the knob, the
    /// ceiling, and the fix.
    fn from(e: policy::PolicyError) -> Self {
        Self::Cli(e.to_string())
    }
}

#[derive(Parser)]
#[command(
    name = "bsx",
    // The crate version, which release tags mirror (`RELEASES.md`): `bsx --version` exists so an
    // installed binary can be told from a stale one, which is a different question from "which
    // release is this".
    version,
    about = "Run untrusted code in a Firecracker microVM, with a host-observed audit trail.",
    // A first-run reader needs a command to type, not a feature list: `doctor` explains the host,
    // then the two run forms differ only by whether this host can jail.
    after_help = "\
Getting started:
  bsx doctor                          check what this host can do
  sudo -E bsx run -- echo hello       run a command in a sandbox (jailed, the default)
  bsx run --unjailed -- echo hello    same, without the jailer (needs no root)
  bsx run --trace -- <cmd>            run it and print the audit trail

Config layers, highest first: flags, BSX_* env, .bsx.toml, defaults."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Log filter for stderr (overrides `BSX_LOG`), e.g. `info`, `debug`.
    #[arg(long, global = true, value_name = "FILTER")]
    log: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    // Each variant's doc comment is user-facing help, so the first line is a one-line summary (what
    // `bsx --help` lists) and the detail follows after a blank line (what `bsx <cmd> --help`
    // shows). Rationale about the *code* belongs in `//` comments, which clap never renders.
    /// Run one command in a microVM.
    ///
    /// Boots a sandbox, runs the command inside it, and tears it down. Jailed by default,
    /// with `--unjailed` as the explicit opt-out. The run's host-observed audit surface rides on
    /// `--trace`, `--record`, `--record-summary`, and `--watch`.
    // Boxed because `run` carries far more flags than the other subcommands: behind an indirection
    // the whole `Cmd` enum isn't sized to it (the `clippy::large_enum_variant` this would trip).
    #[command(after_help = "\
Examples:
  bsx run -- echo hello
  bsx run --vcpus 2 --mem 512 --wall 60 -- ./build.sh
  bsx run --put main.rs --get a.out -- rustc main.rs -o a.out
  bsx run --net --allow 1.1.1.1:443/tcp --trace -- curl https://1.1.1.1
  bsx run --record run.json -- ./untrusted && bsx verify run.json

Everything after `--` is the guest command, so its own flags are never parsed here.")]
    Run(Box<RunArgs>),
    /// Open an interactive session in a microVM.
    ///
    /// One command per line. State persists on the session's filesystem until you exit; shell
    /// process state (a `cd`, a variable) does not, because each line is its own exec.
    ///
    /// The operator policy (`.bsx.toml` ceilings, `require_jail`, `require_record`) binds
    /// exactly as it does for `run`.
    Shell(ShellArgs),
    /// Check whether this host can run the engine.
    ///
    /// Reports KVM, the jailer, host tools, the guest artifacts, and eBPF capabilities, saying what
    /// will work, degrade, or refuse before the first sandbox, and names a first command that works
    /// on this host. Exits non-zero when a hard prerequisite is missing, so `bsx doctor && bsx
    /// run …` gates correctly.
    Doctor(doctor::DoctorArgs),
    /// Verify a signed audit record.
    ///
    /// Checks a `--record` file's `ed25519` signature against a trusted key (the host's own, or
    /// `--key <hex>`), so alteration after the producing host is caught. Exits non-zero
    /// if the record was altered or signed by an untrusted key.
    Verify(verify::VerifyArgs),
    /// Run the driver daemon.
    ///
    /// Exposes the sandbox lifecycle over a unix socket (the versioned newline-JSON wire API), so a
    /// local client drives microVMs without linking the engine. Access control is the socket
    /// directory's permissions (no auth, a recorded non-goal).
    ///
    /// Every flag here is the operator's: the wire carries no identity, so no client names any of
    /// them, and a ceiling refuses an `open` that exceeds it rather than quietly clamping it.
    Serve(Box<serve::ServeArgs>),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Boot only, run no command (the boot-only demo).
    #[arg(long)]
    demo_boot: bool,
    /// Run the VMM without the jailer.
    /// The default is confined (jailed, which needs real root and the `jailer` binary);
    /// this is the explicit opt-out for hosts that can't jail. The guest stays behind KVM either way.
    #[arg(long, help_heading = "Isolation")]
    unjailed: bool,
    /// Refuse the boot if the cgroup caps can't be applied.
    /// Instead of the default warn-and-boot-uncapped. Needs the jailer (so not with
    /// `--unjailed`) and delegated cgroup v2 controllers; also settable via `BSX_REQUIRE_LIMITS`
    /// or `.bsx.toml`.
    #[arg(long, help_heading = "Isolation")]
    require_limits: bool,
    /// The uid the jailer drops the VMM to [default: 10000].
    /// An operator setting, not a caller's: sandboxes sharing an id can signal each other's VMMs.
    /// Also settable via `BSX_JAIL_UID` or `.bsx.toml`.
    #[arg(long, value_name = "UID", value_parser = parse_jail_id, help_heading = "Isolation")]
    jail_uid: Option<u32>,
    /// The gid the jailer drops the VMM to [default: 10000]. See `--jail-uid`.
    #[arg(long, value_name = "GID", value_parser = parse_jail_id, help_heading = "Isolation")]
    jail_gid: Option<u32>,
    /// Guest vCPUs, 1 or an even number up to 32 [default: 1].
    /// Zero or over-cap is a typed CLI error, never a silent clamp (Firecracker caps a microVM
    /// at 32).
    #[arg(long, value_name = "N", value_parser = parse_vcpus, help_heading = "Guest resources")]
    vcpus: Option<NonZeroU8>,
    /// Guest memory in MiB [default: 256].
    /// At least 1; zero is a typed CLI error.
    #[arg(long, value_name = "MIB", value_parser = parse_mem_mib, help_heading = "Guest resources")]
    mem: Option<NonZeroU32>,
    /// Wall-clock budget in seconds [default: 30].
    /// The boot deadline and the command's runtime budget alike; the guest kills the command past
    /// it. Zero is rejected at parse (there is no "no limit"), never silently rounded up.
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..), help_heading = "Guest resources")]
    wall: Option<u64>,
    /// Cap on captured stdout+stderr+artifacts, in bytes [default: 16 MiB].
    /// At least 1; zero is a typed CLI error, since a run that may capture nothing is not a run.
    #[arg(long, value_name = "BYTES", value_parser = parse_output_cap, help_heading = "Guest resources")]
    output_cap: Option<usize>,
    /// Boot with a NIC (a per-VM tap the host-side probes observe).
    /// Deny-by-default is unchanged: with no egress allowance the guest reaches nothing beyond the
    /// host end of its /30. What crosses the tap lands in the audit record's network section.
    #[arg(long, conflicts_with = "demo_boot", help_heading = "Network")]
    net: bool,
    /// Allow one egress destination past the deny-by-default tap (repeatable).
    /// Given as `IP[/CIDR][:PORT][/PROTO]`, e.g. `1.1.1.1`, `10.0.0.0/8`, `1.1.1.1:443/tcp`.
    /// Requires `--net`; the allowances build the run's egress policy, armed before the tap goes
    /// live. A host that can't enforce (missing eBPF caps) is a typed refusal, never a silent
    /// unenforced run.
    #[arg(long, value_name = "IP[:PORT]", value_parser = parse_allow, requires = "net", help_heading = "Network")]
    allow: Vec<AllowRule>,
    /// Give the guest a default route via this address (the host end of its /30).
    ///
    /// Must be on the guest's own link, which the shipped /30 narrows to one usable value; anything
    /// else is refused, because the guest could not ARP it and would come up sealed.
    /// Names a path rather than creating one: the engine builds no uplink, so on a host whose per-VM
    /// netns nothing has furnished the guest still reaches nothing. What it changes is that the
    /// attempt now crosses the tap, so `--allow` can bound it and the record can show it. Normally
    /// the host end of the guest's /30. Requires `--net`; see design decision 9.
    #[arg(long, value_name = "IP", requires = "net", help_heading = "Network")]
    gateway: Option<std::net::Ipv4Addr>,
    /// Tell the guest to resolve names at this address.
    ///
    /// Reaching it needs an allowance like any other destination, and the engine runs no resolver.
    /// Requires `--gateway`, since a resolver the guest cannot route to is inert.
    #[arg(
        long,
        value_name = "IP",
        requires = "gateway",
        help_heading = "Network"
    )]
    resolver: Option<std::net::Ipv4Addr>,
    /// Set an environment variable on the guest command (repeatable).
    /// Values are treated as secrets: the engine never logs them.
    #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env_pair, help_heading = "Files and environment")]
    env: Vec<(String, String)>,
    /// Inject a host file into the run's working directory (repeatable).
    /// The guest-side name is the basename.
    #[arg(long, value_name = "FILE", help_heading = "Files and environment")]
    put: Vec<PathBuf>,
    /// Fetch a file back from the run's working directory (repeatable).
    /// Written under the current directory at the same relative path.
    #[arg(long, value_name = "PATH", help_heading = "Files and environment")]
    get: Vec<String>,
    /// Emit the structured run result as JSON on stdout.
    /// One object carrying the exit code, lossy stdout/stderr, the artifact list, metrics, and the
    /// effective limits, instead of relaying the raw streams.
    #[arg(long, help_heading = "Result and audit trail")]
    json: bool,
    /// Print the run's audit trail on stdout afterwards.
    /// Attaches the host-side probes and renders the trail human-readably. Fail-open: a host without
    /// eBPF caps still runs, with the gaps explained. Machine consumers use `--record` (so this
    /// conflicts with `--json`).
    #[arg(long, conflicts_with_all = ["json", "demo_boot"], help_heading = "Result and audit trail")]
    trace: bool,
    /// Write the run's deterministic audit record to a file.
    /// Attaches the host-side probes and writes one line of JSON, the machine surface, for later
    /// inspection or `bsx verify`.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "demo_boot",
        help_heading = "Result and audit trail"
    )]
    record: Option<PathBuf>,
    /// Write a model-legible summary of the run to a file.
    /// One line of JSON: a compact projection of the audit record shaped for an agent's
    /// observe-then-act loop (what it reached, what egress was denied, its resource envelope, and
    /// any coverage gap).
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "demo_boot",
        help_heading = "Result and audit trail"
    )]
    record_summary: Option<PathBuf>,
    /// Watch the run live in a full-screen view on stderr.
    /// Shows network flows and denials, resources, the VMM's host syscalls, and a timeline while the
    /// command runs. Needs stderr on a terminal. `q` closes the view (the run continues); after the
    /// command finishes, the view stays up until closed.
    #[arg(
        long,
        conflicts_with = "demo_boot",
        help_heading = "Result and audit trail"
    )]
    watch: bool,
    /// The command to run in the guest, after `--`.
    #[arg(trailing_var_arg = true)]
    argv: Vec<String>,
}

#[derive(clap::Args)]
struct ShellArgs {
    /// Run the VMM without the jailer (see `run --unjailed`).
    #[arg(long)]
    unjailed: bool,
    /// Refuse the boot if the cpu/memory cgroup caps can't be applied (see `run --require-limits`).
    #[arg(long)]
    require_limits: bool,
    /// The uid the jailer drops the VMM to (see `run --jail-uid`).
    #[arg(long, value_name = "UID", value_parser = parse_jail_id)]
    jail_uid: Option<u32>,
    /// The gid the jailer drops the VMM to (see `run --jail-uid`).
    #[arg(long, value_name = "GID", value_parser = parse_jail_id)]
    jail_gid: Option<u32>,
    /// Guest vCPUs (default 1). 1 or an even number up to 32 (see `run --vcpus`).
    #[arg(long, value_name = "N", value_parser = parse_vcpus)]
    vcpus: Option<NonZeroU8>,
    /// Guest memory in MiB (default 256). A whole number of at least 1 (see `run --mem`).
    #[arg(long, value_name = "MIB", value_parser = parse_mem_mib)]
    mem: Option<NonZeroU32>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // The daemon owns its own logging (info default, optional JSON) and reads no `.bsx.toml`
    // (its config is flags + environment), so `serve` dispatches *before* the CLI's project-file
    // discovery and tracing init below, which are the run/shell/doctor conveniences. It still
    // receives the shared global `--log` filter.
    if let Cmd::Serve(args) = cli.cmd {
        return serve::serve(*args, cli.log);
    }
    // The `.bsx.toml` layers are discovered once: the user's own file, and the nearest one above
    // the cwd. A mistyped key, or a project-local file reaching for a user-only one, is a loud
    // failure here, before any boot (a config the operator got wrong must not silently no-op).
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let sources = match config::Sources::discover(&cwd) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "bsx: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    // Log filter resolves flags > env > project file > user file > default.
    let filter = config::resolve_log(cli.log.as_deref(), &sources);
    if let Err(e) = init_tracing(filter.as_deref().unwrap_or("warn"), false) {
        let _ = writeln!(std::io::stderr(), "bsx: {e}");
        return ExitCode::from(EXIT_OPERATIONAL);
    }
    match run(cli.cmd, &sources) {
        Ok(code) => code,
        Err(e) => {
            // `eprintln!` panics on a closed stderr; a diagnostics write error is not our failure.
            let _ = writeln!(std::io::stderr(), "bsx: {e}");
            // An infra-bucket failure means the host couldn't stand the microVM up, so point at the
            // tool that explains the host. Keyed on the `kind()` bucket rather than on variants, so
            // the hint can't drift as `VmmError` (which is `#[non_exhaustive]`) grows.
            if matches!(&e, CliError::Engine(err) if err.kind() == ErrorKind::Infra) {
                let _ = writeln!(
                    std::io::stderr(),
                    "bsx: the host may not be ready, run `bsx doctor`"
                );
            }
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn run(cmd: Cmd, sources: &config::Sources) -> Result<ExitCode, CliError> {
    match cmd {
        Cmd::Run(args) => {
            sweep_vm_residue(&base_config(sources).scratch_dir, None);
            run_command(*args, sources)
        }
        Cmd::Shell(args) => {
            sweep_vm_residue(&base_config(sources).scratch_dir, None);
            shell(args, sources)
        }
        Cmd::Doctor(args) => Ok(doctor::report(&base_config(sources), &args, sources)),
        Cmd::Verify(args) => verify::run(args, sources),
        // `serve` is dispatched in `main` before this point (it skips the project-file/tracing
        // setup `run` runs under), so this arm is never reached; a typed error rather than a
        // panic keeps the no-panic discipline even for the impossible case.
        Cmd::Serve(_) => Err(CliError::Cli(
            "internal: serve is dispatched in main() before run()".into(),
        )),
    }
}

/// Reclaim the per-VM residue (scratch dirs + network namespaces) a **crashed** prior `bsx` left: a
/// `Ctrl-C`/SIGKILL skips `Drop`, so the lifetime sentinel reaps the VM process but the scratch dir
/// and netns are out of its scope. Run once at startup by every path that boots a VM, the CLI's
/// subcommands and the daemon alike, which is why it takes `metrics` (`None` off the daemon) rather
/// than living beside either caller. Best-effort and conservative: [`sweep_orphans`] only reclaims
/// this euid's dead-pid dirs, so it never touches a concurrent run's live sandbox.
fn sweep_vm_residue(scratch: &std::path::Path, metrics: Option<&metrics::Metrics>) {
    match sweep_orphans(scratch) {
        Ok(r) => {
            if let Some(m) = metrics {
                m.record_sweep(&r);
            }
            if r.dirs_reclaimed + r.netns_reclaimed > 0 {
                tracing::info!(
                    dirs = r.dirs_reclaimed,
                    netns = r.netns_reclaimed,
                    "reclaimed crashed-run VM residue at startup"
                );
            }
        }
        // The scratch base is `/tmp` unless an operator named one, so an unreadable base is a real
        // condition (a wrong `BSX_SCRATCH_DIR`, or permissions) and leaves residue unreclaimed.
        Err(e) => {
            tracing::warn!(error = %e, "startup orphan sweep failed; residue is left in place")
        }
    }
}

/// The env+file-layered base config, `env > project file > user file > defaults`, over which each
/// subcommand applies its flags. Composes a single lookup that prefers the real environment, then
/// each `.bsx.toml` layer, then (inside [`BootConfig::from_env_with`]) the pinned default, so the
/// lower layers stay one vocabulary keyed by the `BSX_*` names.
fn base_config(sources: &config::Sources) -> BootConfig {
    BootConfig::from_env_with(sources.boot_lookup())
}

/// Fold the shared hardening posture into `config`, the flag layer over what env/file already set:
/// `--require-limits` only *strengthens* (an env/file `true` survives an absent flag, never forced
/// `false`), and `--jail-uid`/`--jail-gid` overlay the folded ids. Shared by `run`, `shell`, and
/// `serve` so the three cannot drift on which layer wins. An unjailed boot drops the whole `Jail`
/// later, so setting ids for one is inert rather than wrong, and the require_limits/unjailed
/// contradiction is owned by the engine (`LimitsUnavailable`, before any VMM); `serve` alone
/// pre-checks it, because a daemon must fail at startup rather than refuse every session.
fn apply_posture(
    config: &mut BootConfig,
    require_limits: bool,
    jail_uid: Option<u32>,
    jail_gid: Option<u32>,
) {
    if require_limits {
        config.require_limits = true;
    }
    if let Some(uid) = jail_uid {
        config.jail.get_or_insert_default().uid = uid;
    }
    if let Some(gid) = jail_gid {
        config.jail.get_or_insert_default().gid = gid;
    }
}

/// `bsx run`: open (jailed by default), attach the probes when asked (fail-open), run one exec with
/// the flag-supplied inputs, write the requested artifacts, finalize the audit record while the
/// sandbox is still alive, close, then report. The record has three faces: the `--trace` human trail,
/// the `--record` full JSON, and the `--record-summary` model-legible projection.
fn run_command(args: RunArgs, sources: &config::Sources) -> Result<ExitCode, CliError> {
    // The run's root span: boot, exec, and the audit-record events all nest under it, so one run's
    // telemetry is greppable as a unit. `vmm_pid` is recorded once the sandbox is up, the id that
    // ties these log lines to the audit record and the host's own process table.
    let span = tracing::info_span!("run", vmm_pid = tracing::field::Empty);
    let _span = span.enter();
    // Resolve the caller's knobs against the operator's policy. For the CLI this is a
    // guardrail rather than a boundary (a local caller owns the config file, and `docs/security.md`
    // trusts them), but it keeps a host's defaults and ceilings consistent across both entry points.
    let host_policy = config::policy_of(sources);
    let limits = host_policy.resolve(&Requested {
        vcpus: args.vcpus,
        mem_mib: args.mem,
        wall_secs: args.wall,
        output_cap: args.output_cap,
    })?;
    host_policy.check_jail(policy::IsolationMode::from_unjailed(args.unjailed))?;
    host_policy.check_net(args.net)?;
    // The effective signed-record destination: an explicit `--record` wins; otherwise the
    // operator's `records_dir` records every run there by default (which is also how a
    // `require_record` host is satisfied without callers remembering a flag).
    let record_path: Option<PathBuf> = args
        .record
        .clone()
        .or_else(|| host_policy.records_dir.as_deref().map(default_record_path));
    // `--record-summary` does not count: the summary is an unsigned *projection* of the record
    // (its own flag doc), so a summary-only run leaves nothing verifiable, exactly what
    // `require_record` exists to refuse ("refuses any run that would leave no audit record",
    // docs/cli-config.md). `require_record_refuses_a_run_that_would_leave_no_audit_record` pins it.
    host_policy.check_record(record_path.is_some())?;

    // Refuse `--watch` without a terminal *before* paying a boot: the live view draws on stderr.
    if args.watch && !std::io::stderr().is_terminal() {
        return Err(CliError::Cli(
            "--watch draws on stderr and needs it to be a terminal; use --trace or --record when \
             piping"
                .to_string(),
        ));
    }
    // Build the egress policy from `--allow` (clap already required `--net`). Enforcement needs the
    // eBPF probes, so refuse up front on a host that plainly can't load them, before paying a boot,
    // and never degrading to an unenforced run (the tap-attach cap check `attach` does catches the
    // residual CAP_NET_ADMIN case that this cheap pre-flight can't).
    let egress = if args.allow.is_empty() {
        None
    } else {
        let policy = build_egress(&args.allow)?;
        if let Err(e) = bsx_probes_loader::check_support() {
            return Err(CliError::Cli(format!(
                "--allow requested egress enforcement, but this host can't load the eBPF probes: {e}"
            )));
        }
        Some(policy)
    };
    if let Some(ref pol) = egress {
        host_policy.check_egress(pol)?;
    }

    // Read the local `--put` files *before* the (jailed-by-default) boot: a bad path is a cheap stat
    // failure, so validate it up front rather than paying a full boot + teardown only to fail on it.
    let files_in = read_put_files(&args.put)?;

    // Resolve the signing key **before** booting: the signing path rejects a group- or world-readable key
    // file, and learning that after the guest ran would throw the record away with the work already done.
    // Last of the pre-flight checks, because it is the only one that *creates* something, which a run a
    // cheaper check rejects should not do. Loading is idempotent.
    if record_path.is_some() {
        let key_path = config::signing_key_path(sources);
        bsx_probes_loader::HostKey::load_or_generate(&key_path).map_err(|e| {
            CliError::Cli(format!(
                "signing key {} is unusable, so this run could not be recorded: {e}",
                key_path.display()
            ))
        })?;
    }
    let mut config = base_config(sources).with_limits(limits);
    config.enable_network = args.net;
    // Flags win over the `BSX_GATEWAY`/`BSX_RESOLVER` + file layers `base_config` already resolved,
    // so a run can override the host's uplink without editing its config.
    if let Some(gateway) = args.gateway {
        let mut egress = bsx_engine::GuestEgress::via(gateway);
        if let Some(resolver) = args.resolver {
            egress = egress.with_resolver(resolver);
        }
        config.egress = Some(egress);
    }
    apply_posture(
        &mut config,
        args.require_limits,
        args.jail_uid,
        args.jail_gid,
    );
    // Captured before `config` moves into the boot: the record needs it, and an allowance means
    // something different with a route behind it than without.
    let gateway = config.egress.map(|e| e.gateway());
    let mut sandbox = open(config, policy::IsolationMode::from_unjailed(args.unjailed))?;
    span.record("vmm_pid", sandbox.vmm_pid());
    if args.demo_boot {
        // The run result goes to stdout (stderr is reserved for logs). Not `println!`,
        // it panics on a closed pipe (`bsx run … | head -0`).
        let _ = writeln!(
            std::io::stdout(),
            "booted microVM to userspace in {} ms",
            sandbox.boot_latency().as_millis()
        );
        return sandbox
            .shutdown()
            .map(|()| ExitCode::SUCCESS)
            .map_err(CliError::from);
    }

    // The audit surface, when a flag asked for it (a plain `bsx run` pays nothing): load the shared
    // probes and bind them to this sandbox by the plain values it exposes, the launch sequence the
    // `bsx-probes-loader` documents, composed here in the caller. `--allow` enforces (arming the tap before
    // it goes live) and pulls in the bundle even without an observation flag; observation is fail-open,
    // enforcement is a typed refusal (`attach`).
    let observing = args.trace
        || record_path.is_some()
        || args.record_summary.is_some()
        || args.watch
        || egress.is_some();
    let probes = if observing {
        let params = audit::attach_params(&sandbox, egress.as_ref(), gateway);
        Some(audit::Observability::load().attach(sandbox.name(), params)?)
    } else {
        None
    };

    let boot_latency = sandbox.boot_latency();
    let vmm_pid = sandbox.vmm_pid();
    let stdin = piped_stdin()?;
    let (sandbox, result) = if args.watch {
        // Exec on a worker thread that owns the sandbox; the main thread runs the live view off
        // non-destructive probe snapshots until the worker flags completion.
        let done = Arc::new(AtomicBool::new(false));
        let worker_done = Arc::clone(&done);
        let (argv, env, get) = (args.argv.clone(), args.env.clone(), args.get.clone());
        let worker = std::thread::spawn(move || {
            // Drop-based, not a plain store after the call: a panicking exec must still flag
            // completion on unwind, or the view shows "running" forever and only `q` closes it
            // (the panic itself still surfaces through `worker.join()` below).
            struct DoneOnExit(Arc<AtomicBool>);
            impl Drop for DoneOnExit {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _done = DoneOnExit(worker_done);
            let result = sandbox.exec_with_files(&argv, &stdin, &files_in, &env, &get);
            (sandbox, result)
        });
        if let Some(p) = probes.as_ref() {
            let meta = watch::WatchMeta {
                vmm_pid,
                boot: boot_latency,
                command: args.argv.join(" "),
            };
            // A broken live view must not fail a working run: log it and let the exec finish
            // headless. (The terminal is restored by the view's own guard either way.)
            if let Err(e) = watch::live(p, &meta, &done) {
                tracing::warn!(error = %e, "live view failed; run continues headless");
            }
        }
        if !done.load(Ordering::Acquire) {
            let _ = writeln!(
                std::io::stderr(),
                "bsx: live view closed; waiting for the command to finish"
            );
        }
        let (sandbox, result) = worker
            .join()
            .map_err(|_| VmmError::Vmm("exec worker thread panicked".to_string()))?;
        (sandbox, result?)
    } else {
        let result =
            sandbox.exec_with_files(&args.argv, &stdin, &files_in, &args.env, &args.get)?;
        (sandbox, result)
    };
    // Finalize the audit record **while the sandbox is still alive** (the attached bundle reads the
    // live cgroup + maps) and **before** the fallible artifact write below: an artifact-write error
    // must not lose the record for exactly the misbehaving-guest run whose audit you want.
    let record = probes.map(|p| p.collect(Timing::new(boot_latency, result.metrics.wall)));
    write_artifacts(&result.files, &args.get)?;
    // Teardown is best-effort: a shutdown error must not mask the run's real result (its exit code,
    // streams, and the record just collected). Log and continue, as `shell`'s teardown already does.
    if let Err(e) = sandbox.shutdown() {
        tracing::warn!(error = %e, "sandbox shutdown reported an error after the run");
    }

    if args.json {
        // The structured run result, one JSON object on stdout, the machine-readable form of the
        // pipe-clean convention (stderr already carries the logs). Byte streams are lossy UTF-8
        // here; exact bytes ride the artifact files, which are on disk by now.
        let structured = serde_json::json!({
            // Versions the run-result contract (distinct from the audit record's own `schema`).
            // Additive changes keep this integer; a rename/removal bumps it, see docs/cli.md.
            "schema": RUN_RESULT_SCHEMA,
            "exit_code": result.exit_code,
            "stdout": String::from_utf8_lossy(&result.stdout),
            "stderr": String::from_utf8_lossy(&result.stderr),
            "artifacts": result
                .files
                .iter()
                .map(|a| serde_json::json!({ "path": a.path, "bytes": a.data.len() }))
                .collect::<Vec<_>>(),
            "metrics": {
                "boot_ms": session::ms(boot_latency),
                "exec_wall_ms": session::ms(result.metrics.wall),
            },
            // The effective limits this run actually booted with, the flag values folded onto the
            // defaults, echoed back so a `--json` caller sees what it got, not just what it asked.
            "limits": {
                "vcpus": limits.vcpus.get(),
                "mem_mib": limits.mem_mib.get(),
                "wall_ms": u64::try_from(limits.wall.as_millis()).unwrap_or(u64::MAX),
                "output_cap_bytes": limits.output_cap,
            },
        });
        // The structured result is the machine surface a `--json` caller consumes, so a failed write
        // (a full disk) is a real failure, not to be swallowed like the guest-output relay below (the
        // `--record` file writes are treated the same). A downstream-closed pipe is still not our
        // fault, so BrokenPipe is the one exception.
        if let Err(e) = writeln!(std::io::stdout(), "{structured}")
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(VmmError::Artifact(format!("write --json result to stdout: {e}")).into());
        }
    } else {
        // Relay the guest's output on our own stdout/stderr, the whole point of `exec`. Ignore
        // write errors (a closed pipe is not our failure); the guest exit code is what we return.
        let _ = std::io::stdout().write_all(&result.stdout);
        let _ = std::io::stderr().write_all(&result.stderr);
    }
    if let Some(record) = record {
        if args.trace {
            // The human-readable audit trail, after the guest's own output: a requested run
            // result, so it belongs on stdout like the rest (never mixed with `--json`, clap
            // makes the two conflict; machine consumers take `--record`).
            let _ = writeln!(std::io::stdout(), "\n{}", trace::render(&record).trim_end());
        }
        if let Some(path) = &record_path {
            // The machine surface, one line, byte-stable: the deterministic record wrapped in an
            // `ed25519` signature envelope, so a consumer detects post-hoc alteration
            // off-host. The signing key is host-side (the guest never sees it), loaded/generated at
            // the config-resolved path.
            let source = if args.record.is_some() {
                "--record"
            } else {
                // A defaulted destination is operator config, so materialize the directory; an
                // explicit `--record` path's parent stays the caller's responsibility.
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| {
                        VmmError::Artifact(format!("records_dir {}: {e}", dir.display()))
                    })?;
                }
                "records_dir"
            };
            let key_path = config::signing_key_path(sources);
            let key = bsx_probes_loader::HostKey::load_or_generate(&key_path).map_err(|e| {
                VmmError::Vmm(format!("load signing key {}: {e}", key_path.display()))
            })?;
            std::fs::write(path, key.sign_record(&record) + "\n")
                .map_err(|e| VmmError::Artifact(format!("{source} {}: {e}", path.display())))?;
            tracing::info!(path = %path.display(), key_id = %key.key_id(), "wrote signed audit record");
        }
        if let Some(path) = &args.record_summary {
            // The model-legible projection, a compact, byte-stable view of the same record.
            std::fs::write(path, record.to_summary_json() + "\n").map_err(|e| {
                VmmError::Artifact(format!("--record-summary {}: {e}", path.display()))
            })?;
            tracing::info!(path = %path.display(), "wrote record summary");
        }
    }
    Ok(ExitCode::from(u8::try_from(result.exit_code).unwrap_or(1)))
}

/// `bsx shell`: one sandbox held open, one `sh -c` exec per input line, a stateful session
/// (every exec shares the guest's session working directory, so files persist across lines;
/// process state like `cd` and shell variables does not). The prompt and diagnostics go to stderr,
/// command output to stdout, so a piped script of lines stays clean.
fn shell(args: ShellArgs, sources: &config::Sources) -> Result<ExitCode, CliError> {
    let limits = shell_policy(&args, &config::policy_of(sources))?;
    let mut config = base_config(sources).with_limits(limits);
    apply_posture(
        &mut config,
        args.require_limits,
        args.jail_uid,
        args.jail_gid,
    );
    let mut sandbox = open(config, policy::IsolationMode::from_unjailed(args.unjailed))?;
    let mut err_out = std::io::stderr();
    let _ = writeln!(
        err_out,
        "bsx shell: microVM up in {} ms; one command per line, files persist across lines, \
         `exit` (or EOF) to quit",
        sandbox.boot_latency().as_millis()
    );
    let stdin = std::io::stdin();
    loop {
        let _ = write!(err_out, "bsx> ");
        let _ = err_out.flush();
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                let _ = writeln!(err_out, "bsx: read stdin: {e}");
                break;
            }
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "exit" || line == "quit" {
            break;
        }
        match sandbox.exec(&["sh".into(), "-c".into(), line.to_string()], &[]) {
            Ok(result) => {
                let _ = std::io::stdout().write_all(&result.stdout);
                let _ = std::io::stdout().flush();
                let _ = err_out.write_all(&result.stderr);
                if result.exit_code != 0 {
                    let _ = writeln!(err_out, "[exit {}]", result.exit_code);
                }
            }
            // A guest fault (a timeout, a flooded cap, an unrunnable command) belongs to that one
            // line; the session survives it. Infra/transport means the VM itself is gone, end the
            // session with the typed error.
            Err(e) if e.kind() == ErrorKind::Guest => {
                let _ = writeln!(err_out, "bsx: {e}");
            }
            Err(e) => {
                let _ = writeln!(err_out, "bsx: session lost: {e}");
                let _ = sandbox.shutdown();
                return Err(e.into());
            }
        }
    }
    sandbox
        .shutdown()
        .map(|()| ExitCode::SUCCESS)
        .map_err(CliError::from)
}

/// Open the sandbox jailed by default, unjailed on the explicit flag, the CLI face of the
/// library's differently-named constructors.
fn open(config: BootConfig, isolation: policy::IsolationMode) -> Result<Sandbox, VmmError> {
    if isolation.is_unjailed() {
        Sandbox::open_unjailed(config)
    } else {
        Sandbox::open(config)
    }
}

/// Fold the `--allow` rules into a deny-by-default [`EgressPolicy`]. Refuses more than the kernel
/// policy map holds ([`MAX_POLICY_RULES`]) with a typed error naming the cap, rather than letting the
/// overflow surface as a cryptic attach-time failure.
fn build_egress(allows: &[AllowRule]) -> Result<EgressPolicy, CliError> {
    if allows.len() > MAX_POLICY_RULES {
        return Err(CliError::Cli(format!(
            "too many --allow rules: {} given, but the kernel egress policy holds at most \
             {MAX_POLICY_RULES}",
            allows.len()
        )));
    }
    let mut policy = EgressPolicy::deny_all();
    for a in allows {
        policy = policy.allow(a.cidr, a.port, a.proto);
    }
    Ok(policy)
}

/// The defaulted signed-record destination under the operator's `records_dir`:
/// `run-<epoch-secs>-<pid>.json`, unique per run (one record write per process) and
/// time-sortable by name, with no timestamp dependency.
fn default_record_path(dir: &Path) -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    dir.join(format!("run-{secs}-{}.json", std::process::id()))
}

/// Resolve `bsx shell`'s limits and posture against the operator policy: the same boundary
/// `run_command` enforces, so switching subcommand cannot bypass a ceiling, `require_jail`, or
/// `require_record`. Operator *defaults* apply too: an unset `--vcpus`/`--mem` takes the host's
/// default profile, not the bare engine default. Shell has no `--net`, so the net/egress checks
/// have nothing to check.
fn shell_policy(args: &ShellArgs, host_policy: &Policy) -> Result<Limits, CliError> {
    let limits = host_policy.resolve(&Requested {
        vcpus: args.vcpus,
        mem_mib: args.mem,
        wall_secs: None,
        output_cap: None,
    })?;
    host_policy.check_jail(policy::IsolationMode::from_unjailed(args.unjailed))?;
    // A shell session writes no audit record, so a record-requiring host refuses it outright
    // rather than hosting an unauditable execution path.
    host_policy
        .check_record(false)
        .map_err(|e| CliError::Cli(format!("{e} (an interactive shell writes no audit record)")))?;
    Ok(limits)
}

/// Parse `--jail-uid`/`--jail-gid`. Zero is refused by name rather than accepted and quietly
/// undoing the drop: `setuid(0)` leaves the VMM as root, which is the one id the jail exists to
/// leave. A typed CLI error here, where the env layer can only warn and fall back.
fn parse_jail_id(s: &str) -> Result<u32, String> {
    match s.parse::<u32>() {
        Ok(0) => Err(
            "0 is root, which is the id the jailer exists to drop; pick a non-zero \
                      uid/gid that owns nothing else on this host"
                .to_string(),
        ),
        Ok(id) => Ok(id),
        Err(_) => Err(format!("expected a uid/gid, got {s:?}")),
    }
}

/// Parse `--vcpus` into the [`Limits::vcpus`] [`NonZeroU8`]. Parsing straight into the non-zero type
/// rejects `0` (and any non-number / u8 overflow); [`vcpus_supported`] rejects the rest of what the
/// pinned VMM won't boot, an over-32 count or an odd one above 1. Either way it is a **typed CLI
/// error, never a silent clamp**: the value is refused at parse, not narrowed behind the caller's
/// back or surfaced as a late boot error.
fn parse_vcpus(s: &str) -> Result<NonZeroU8, String> {
    let vcpus: NonZeroU8 = s
        .parse()
        .map_err(|_| format!("expected a whole number of vCPUs in 1..={MAX_VCPUS}, got {s:?}"))?;
    if !vcpus_supported(vcpus.get()) {
        return Err(policy::unsupported_vcpus("vCPUs", vcpus));
    }
    Ok(vcpus)
}

/// Parse `--mem`: guest memory in whole MiB into the [`Limits::mem_mib`] [`NonZeroU32`]. Parsing
/// straight into the non-zero type rejects `0` (and any non-number / overflow) as a typed CLI error,
/// never a silent clamp.
fn parse_mem_mib(s: &str) -> Result<NonZeroU32, String> {
    s.parse()
        .map_err(|_| format!("expected guest memory in whole MiB (at least 1), got {s:?}"))
}

/// Parse `--output-cap`: the captured-output budget in whole bytes. `0` is refused for the reason
/// every sibling knob refuses it: there is no "no limit" spelling here, so a zero read as one would
/// be the opposite of what it says, and read literally it is a run that can capture nothing.
fn parse_output_cap(s: &str) -> Result<usize, String> {
    match s.parse() {
        Ok(0) | Err(_) => Err(format!(
            "expected a captured-output cap in whole bytes (at least 1), got {s:?}"
        )),
        Ok(n) => Ok(n),
    }
}

/// A `KEY=VALUE` pair for `--env`. Values are secrets by presumption, so the error names only the
/// malformed *key side* shape, never echoes a value.
fn parse_env_pair(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
        _ => Err("expected KEY=VALUE with a non-empty KEY".to_string()),
    }
}

/// Read each `--put` host file into an injected `(guest-name, bytes)` pair; the guest name is the
/// file's basename (the working dir is flat unless the command makes it otherwise).
fn read_put_files(puts: &[PathBuf]) -> Result<Vec<(String, Vec<u8>)>, VmmError> {
    puts.iter()
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .filter(|n| !n.is_empty())
                .ok_or_else(|| {
                    VmmError::Artifact(format!("--put {}: no file name", path.display()))
                })?;
            let data = std::fs::read(path)
                .map_err(|e| VmmError::Artifact(format!("--put {}: {e}", path.display())))?;
            Ok((name, data))
        })
        .collect()
}

/// Write the guest's returned artifacts under the current directory, refusing anything the run
/// didn't explicitly ask for. Deny-by-default: the operator's `--get` set is
/// the *only* allowance, so a returned path that wasn't requested (a planted `.git/config`,
/// `Makefile`) is refused, never written. The exec API already guarantees each path is relative and
/// non-climbing (`run_exec`); here we additionally resolve every component without following a
/// symlink, so a pre-existing symlinked directory in the cwd (`out -> /etc`) can't turn a
/// `Normal`-component path into an escape the string check alone is blind to.
fn write_artifacts(files: &[Artifact], requested: &[String]) -> Result<(), CliError> {
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::Cli(format!("resolve current directory: {e}")))?;
    write_artifacts_in(&cwd, files, requested)
}

/// The core of [`write_artifacts`], resolving destinations under an explicit `base` so it is
/// testable without mutating the process-global cwd.
fn write_artifacts_in(
    base: &Path,
    files: &[Artifact],
    requested: &[String],
) -> Result<(), CliError> {
    for Artifact { path, data, .. } in files {
        // Deny-by-default: the guest doesn't get to choose what lands on the host, only a name the
        // operator requested with `--get` is eligible. An honest guest only ever returns requested
        // paths (it echoes the request's artifact list), so a mismatch is a misbehaving guest.
        if !requested.iter().any(|r| r == path) {
            return Err(CliError::Cli(format!(
                "refusing artifact {path:?}: not requested with --get"
            )));
        }
        // Backstop the public API's own check, and require the path to actually name a file.
        let rel = Path::new(path);
        let named = rel.file_name().is_some()
            && rel
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if !named {
            return Err(CliError::Cli(format!(
                "refusing to write artifact {path:?} outside the current directory"
            )));
        }
        let dest = confined_dest(base, rel)?;
        std::fs::write(&dest, data)
            .map_err(|e| CliError::Cli(format!("write artifact {path:?}: {e}")))?;
        tracing::info!(path = %path, bytes = data.len(), "wrote artifact");
    }
    Ok(())
}

/// Resolve `rel` (already checked relative and non-climbing) against `base` into an absolute
/// destination, creating intermediate directories but **refusing to follow a symlink** at any
/// component. `symlink_metadata` is `lstat` (no traversal), so a pre-existing symlinked directory,
/// or a symlinked final name, is rejected rather than written through, closing the
/// `out -> /etc` escape that a string-only check misses.
fn confined_dest(base: &Path, rel: &Path) -> Result<PathBuf, CliError> {
    let names: Vec<_> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None, // `CurDir` contributes nothing; the caller excluded every other kind.
        })
        .collect();
    let mut cur = base.to_path_buf();
    for (i, name) in names.iter().enumerate() {
        cur.push(name);
        let last = i + 1 == names.len();
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(CliError::Cli(format!(
                    "refusing to write artifact through the symlink {cur:?}"
                )));
            }
            // The final component may already be a regular file (a legitimate overwrite), but not a
            // directory we'd clobber; an intermediate component must be a real directory to descend.
            Ok(m) if last && m.is_dir() => {
                return Err(CliError::Cli(format!(
                    "refusing to write artifact over the directory {cur:?}"
                )));
            }
            Ok(m) if !last && !m.is_dir() => {
                return Err(CliError::Cli(format!(
                    "artifact path component {cur:?} is not a directory"
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Create missing intermediate dirs; the final missing component the write creates.
                if !last {
                    std::fs::create_dir(&cur)
                        .map_err(|e| CliError::Cli(format!("create artifact dir {cur:?}: {e}")))?;
                }
            }
            Err(e) => return Err(CliError::Cli(format!("stat artifact path {cur:?}: {e}"))),
        }
    }
    Ok(cur)
}

/// The bytes piped into our stdin, or empty when stdin is the terminal (an interactive `bsx run`
/// shouldn't block waiting for EOF). The read is **bounded at one frame + 1 byte**: the exec request
/// is a single frame, so anything past the channel's cap is rejected as a typed `PayloadTooLarge`
/// regardless, reading it all first would let `cat 10GB.bin | bsx run …` balloon host RAM before
/// the same error. The `+ 1` still overshoots the cap by a byte so the oversize case is caught rather
/// than silently truncated to exactly the cap. Bulk data belongs on the block-device path anyway.
fn piped_stdin() -> Result<Vec<u8>, CliError> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Ok(Vec::new());
    }
    let mut buf = Vec::new();
    // A failed read is a hard error, never a shrug: proceeding with whatever arrived would run
    // the guest on silently truncated input and sign a record that calls it complete. The one
    // exception is a *closed* fd 0 (`bsx run … 0<&-`), which is not a truncated read but no
    // stdin at all, the same thing a terminal means here.
    /// `EBADF`. Named because `io::ErrorKind` has no stable variant for it (it arrives as
    /// `Uncategorized`), so the raw errno is the only way to tell "fd 0 is closed" from a real
    /// read failure.
    const EBADF: i32 = 9;
    if let Err(e) = stdin
        .lock()
        .take(MAX_PAYLOAD as u64 + 1)
        .read_to_end(&mut buf)
    {
        if e.raw_os_error() != Some(EBADF) {
            return Err(CliError::Cli(format!("read piped stdin: {e}")));
        }
        buf.clear();
    }
    Ok(buf)
}

/// Installs the stderr subscriber for an **already-resolved** `filter`, optionally as one JSON object
/// per line. The CLI and the daemon share this; each resolves its own precedence and default first,
/// because they read different layers (`bsx serve` dispatches before project-file discovery).
///
/// A filter `tracing` cannot parse is a **typed refusal**, the same loudness the file layer gives a
/// mistyped key. What this cannot police is `EnvFilter`'s own grammar, where a bare unknown ident parses as
/// a *target* name, so only what the parser itself rejects is refused. `try_init` absorbs a double-init.
///
/// # Errors
/// A message naming the unparseable filter and the two spellings that would work.
pub(crate) fn init_tracing(filter: &str, json: bool) -> Result<(), String> {
    let env_filter = tracing_subscriber::EnvFilter::try_new(filter).map_err(|e| {
        format!(
            "invalid log filter {filter:?}: {e} (a level like warn|info|debug, or a tracing \
             directive like \"bsx=debug\")"
        )
    })?;
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .with_target(false);
    let _ = if json {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AllowRule, Artifact, Cli, MAX_VCPUS, Policy, ShellArgs, apply_posture, build_egress,
        parse_allow, parse_env_pair, parse_jail_id, parse_mem_mib, parse_output_cap, parse_vcpus,
        shell_policy, sweep_vm_residue, write_artifacts_in,
    };
    use bsx_probes_loader::{Ipv4Cidr, MAX_POLICY_RULES, Protocol};
    use bsx_test_support::ScratchDir;
    use clap::CommandFactory;

    /// The CLI and the daemon reclaim crashed-run residue through the same sweep, and the only
    /// thing that differs is whether a metrics registry is there to charge: `None` off the daemon.
    /// A registry that stops being charged is a gauge that reads zero on a host that is leaking.
    #[test]
    fn the_daemon_sweep_charges_its_registry_and_the_cli_sweep_needs_none() {
        let scratch = ScratchDir::created("sweep-seam");
        // `bsx-<pid>-<seq>`, the per-VM workdir shape, owned by us with a pid that cannot be live.
        let dead = |seq: u32| scratch.path().join(format!("bsx-{}-{seq}", u32::MAX - 1));
        std::fs::create_dir(dead(0)).expect("stage a dead run's dir");

        let metrics = crate::metrics::Metrics::default();
        sweep_vm_residue(scratch.path(), Some(&metrics));
        assert!(!dead(0).exists(), "a dead run's dir must be reclaimed");
        let rendered = metrics.render(&crate::metrics::CapacitySample::default());
        assert!(
            rendered.contains("bsx_sweep_reclaimed_total{resource=\"dirs\"} 1"),
            "the daemon's counter must see what the sweep reclaimed:\n{rendered}"
        );

        // The same call with no registry: the CLI's path, which must reclaim just the same.
        std::fs::create_dir(dead(1)).expect("stage another");
        sweep_vm_residue(scratch.path(), None);
        assert!(!dead(1).exists(), "no registry must not mean no sweep");
    }

    /// The `--vcpus` refusal is the shared rule, named for the flag. Anchored to the helper rather
    /// than to a copy of the sentence, so the wire's and the config file's refusals cannot drift
    /// away from this one.
    #[test]
    fn the_flag_refuses_an_unbootable_count_with_the_shared_rule() {
        assert_eq!(
            parse_vcpus("3").expect_err("an odd count above 1 cannot boot"),
            crate::policy::unsupported_vcpus("vCPUs", 3)
        );
        assert!(parse_vcpus("2").is_ok() && parse_vcpus("1").is_ok());
    }

    /// A `///` on a clap field **is** the user interface, so it has to survive being rendered at a
    /// real terminal width. Clap wraps nothing unless the `wrap_help` feature is on, and it was not:
    /// `bsx run -h` printed 19 lines past 80 columns, running off the edge of any normal terminal.
    /// Rendering every subcommand narrow is what catches that, because the overflow is invisible at
    /// the width a developer happens to be using.
    #[test]
    fn help_wraps_to_the_terminal_instead_of_running_off_it() {
        // Not narrower than 80: clap cannot wrap below its own option column, so a 60
        // would fail on `serve`'s long flag names for a reason no terminal ever presents.
        for width in [80usize, 100, 120] {
            let mut root = Cli::command();
            // Every subcommand, not just the root: the long help lives on `run`'s and `serve`'s
            // flags, which the root's own `--help` never renders.
            let names: Vec<String> = root
                .get_subcommands()
                .map(|c| c.get_name().to_owned())
                .collect();
            for name in std::iter::once(String::new()).chain(names) {
                let cmd = if name.is_empty() {
                    &mut root
                } else {
                    root.find_subcommand_mut(&name).expect("subcommand")
                };
                let text = cmd.clone().term_width(width).render_long_help().to_string();
                let worst = text.lines().map(str::len).max().unwrap_or(0);
                assert!(
                    worst <= width,
                    "`bsx {name} --help` renders {worst} columns at a {width}-column terminal"
                );
            }
        }
    }
    use std::net::Ipv4Addr;
    use std::num::{NonZeroU8, NonZeroU32};

    fn artifact(path: &str, data: &[u8]) -> Vec<Artifact> {
        vec![Artifact::new(path, data.to_vec())]
    }

    #[test]
    fn env_pairs_parse_and_reject_malformed() {
        assert_eq!(
            parse_env_pair("KEY=value"),
            Ok(("KEY".to_string(), "value".to_string()))
        );
        // The value may itself contain `=` (tokens often do); only the first splits.
        assert_eq!(
            parse_env_pair("KEY=a=b"),
            Ok(("KEY".to_string(), "a=b".to_string()))
        );
        assert_eq!(
            parse_env_pair("EMPTY="),
            Ok(("EMPTY".to_string(), String::new()))
        );
        assert!(parse_env_pair("novalue").is_err());
        assert!(parse_env_pair("=orphan").is_err());
    }

    #[test]
    fn vcpus_parse_only_counts_the_vmm_would_boot() {
        assert_eq!(parse_vcpus("1"), Ok(NonZeroU8::MIN));
        assert_eq!(parse_vcpus("32"), NonZeroU8::new(32).ok_or(String::new()));
        assert_eq!(parse_vcpus("2"), NonZeroU8::new(2).ok_or(String::new()));
        // Zero, over-cap, u8 overflow, and non-numbers are each a typed error, never a clamp.
        assert!(
            parse_vcpus("0").is_err(),
            "zero is unbootable, not a small budget"
        );
        assert!(parse_vcpus("33").is_err(), "over the vCPU cap");
        assert!(parse_vcpus("300").is_err(), "u8 overflow");
        assert!(parse_vcpus("").is_err());
        assert!(parse_vcpus("two").is_err());
        // The parity half of Firecracker's domain: an odd count above 1 is refused here rather than
        // reaching `PUT /machine-config` and failing after a VMM has been spawned. 1 is the
        // deliberate exception, and it is the default.
        for odd in ["3", "5", "31"] {
            assert!(
                parse_vcpus(odd).is_err(),
                "{odd} is odd and above 1, which Firecracker refuses"
            );
        }
        // The refusal names the cap so it is actionable.
        assert!(
            parse_vcpus("64")
                .unwrap_err()
                .contains(&MAX_VCPUS.to_string())
        );
    }

    #[test]
    fn a_jail_id_flag_refuses_root_and_wins_over_the_env_and_file_layer() {
        assert_eq!(parse_jail_id("20001"), Ok(20001));
        // Root is the id the jail exists to leave, so a flag naming it is a typed refusal here
        // rather than a boot that jails into a chroot and drops nothing.
        let err = parse_jail_id("0").expect_err("0 is root");
        assert!(err.contains("root"), "the refusal must say why: {err}");
        assert!(parse_jail_id("-1").is_err());
        assert!(parse_jail_id("nobody").is_err());
        assert!(parse_jail_id("").is_err());

        // The flag is the top layer: it overwrites whatever env or file already put on the jail,
        // and it only touches the field it names.
        let mut config = bsx_engine::BootConfig::from_env_with(|k| match k {
            "BSX_JAIL_UID" => Some("30001".into()),
            "BSX_JAIL_GID" => Some("30002".into()),
            _ => None,
        });
        apply_posture(&mut config, false, Some(20001), None);
        let jail = config.jail.expect("the jail survives the flag layer");
        assert_eq!(jail.uid, 20001, "the flag wins over the env");
        assert_eq!(jail.gid, 30002, "an absent flag leaves the env value alone");

        // With nothing anywhere, the jail stays unset and the CLI's own default supplies the ids.
        let mut bare = bsx_engine::BootConfig::from_env_with(|_| None);
        apply_posture(&mut bare, false, None, None);
        assert!(bare.jail.is_none());
    }

    #[test]
    fn mem_mib_parses_any_nonzero_u32() {
        assert_eq!(
            parse_mem_mib("256"),
            NonZeroU32::new(256).ok_or(String::new())
        );
        assert_eq!(
            parse_mem_mib("1"),
            NonZeroU32::new(1).ok_or(String::new()),
            "1 MiB is the floor, not zero"
        );
        assert!(parse_mem_mib("0").is_err(), "zero memory is unbootable");
        assert!(parse_mem_mib("").is_err());
        assert!(parse_mem_mib("lots").is_err());
    }

    #[test]
    fn output_cap_parses_like_its_sibling_knobs_and_refuses_zero() {
        assert_eq!(parse_output_cap("1"), Ok(1), "one byte is the floor");
        assert_eq!(parse_output_cap("16777216"), Ok(16 << 20));
        assert!(
            parse_output_cap("0").is_err(),
            "there is no `no limit` spelling here, so a zero read as one would invert the flag"
        );
        assert!(parse_output_cap("").is_err());
        assert!(parse_output_cap("-1").is_err());
        assert!(parse_output_cap("plenty").is_err());
    }

    #[test]
    fn allow_parses_every_field_combination() {
        let host = |a: [u8; 4]| Ipv4Cidr::host(Ipv4Addr::from(a));
        // Bare host: /32, any port, any proto.
        assert_eq!(
            parse_allow("1.1.1.1"),
            Ok(AllowRule {
                cidr: host([1, 1, 1, 1]),
                port: None,
                proto: None
            })
        );
        // CIDR only.
        assert_eq!(
            parse_allow("10.0.0.0/8"),
            Ok(AllowRule {
                cidr: Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).expect("valid /8"),
                port: None,
                proto: None
            })
        );
        // Host + port + proto, and the full CIDR+port+proto form.
        assert_eq!(
            parse_allow("1.1.1.1:443/tcp"),
            Ok(AllowRule {
                cidr: host([1, 1, 1, 1]),
                port: Some(443),
                proto: Some(Protocol::Tcp)
            })
        );
        assert_eq!(
            parse_allow("10.0.0.0/8:53/udp"),
            Ok(AllowRule {
                cidr: Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).expect("valid /8"),
                port: Some(53),
                proto: Some(Protocol::Udp)
            })
        );
        // Proto without a port (the `/proto` suffix is stripped before the `:port` split).
        assert_eq!(
            parse_allow("8.8.8.8/udp").map(|r| r.proto),
            Ok(Some(Protocol::Udp))
        );
    }

    #[test]
    fn allow_rejects_malformed_fields_with_a_typed_error() {
        // Each bad field is a typed error naming the offending token, never a dropped allowance.
        assert!(parse_allow("999.1.1.1").is_err(), "bad octet");
        assert!(parse_allow("1.1.1.1/33").is_err(), "CIDR prefix over 32");
        assert!(parse_allow("1.1.1.1:70000").is_err(), "port over u16");
        assert!(parse_allow("1.1.1.1:").is_err(), "empty port");
        assert!(parse_allow("").is_err(), "empty");
        // The prefix error names the offending token.
        assert!(parse_allow("1.1.1.1/33").unwrap_err().contains("33"));
    }

    #[test]
    fn an_unparseable_log_filter_names_the_filter_and_both_spellings_that_work() {
        // The CLI and the daemon share this refusal, so the advice cannot differ between them.
        // `an_invalid_log_filter_is_a_loud_refusal_not_a_silent_warn` drives both entry points but
        // asserts only that the filter is named; the hint is what an operator acts on, so pin it
        // where it is now written once. The error path installs no global subscriber, so this is
        // safe to call from a test.
        let err = super::init_tracing("bsx=notalevel", false).expect_err("unparseable directive");
        assert!(err.contains("bsx=notalevel"), "names the filter: {err}");
        assert!(
            err.contains("warn|info|debug"),
            "offers a bare level: {err}"
        );
        assert!(
            err.contains("\"bsx=debug\""),
            "offers the directive form: {err}"
        );
    }

    #[test]
    fn an_allow_refusal_quotes_the_whole_rule_not_the_address_slice() {
        // `--allow` shares the config file's CIDR parser, which is handed only the address slice.
        // The locus travels separately for this reason: quoting the slice would send the reader
        // looking for `"1.1.1.1/33"` in a line where they wrote the port and protocol too.
        for rule in ["1.1.1.1/33:443/tcp", "999.1.1.1:80", "1.1.1.1/x:80/udp"] {
            let err = parse_allow(rule).expect_err("malformed");
            assert!(
                err.contains(&format!("--allow {rule:?}")),
                "the refusal quotes the whole rule: {err}"
            );
        }
    }

    #[test]
    fn build_egress_denies_by_default_and_caps_the_rule_count() {
        // No rules is still a policy, deny-everything.
        assert!(build_egress(&[]).expect("empty is valid").is_deny_all());
        // Each allow becomes one rule.
        let one = parse_allow("1.1.1.1:443/tcp").expect("valid");
        assert_eq!(build_egress(&[one]).expect("one rule").rules().len(), 1);
        // Over the kernel-map cap is a typed refusal (not a cryptic attach-time overflow).
        let many = vec![one; MAX_POLICY_RULES + 1];
        let err = build_egress(&many).expect_err("over the cap must refuse");
        assert!(format!("{err}").contains(&MAX_POLICY_RULES.to_string()));
    }

    fn shell_args(vcpus: Option<u8>, mem: Option<u32>, unjailed: bool) -> ShellArgs {
        ShellArgs {
            unjailed,
            require_limits: false,
            jail_uid: None,
            jail_gid: None,
            vcpus: vcpus.and_then(NonZeroU8::new),
            mem: mem.and_then(NonZeroU32::new),
        }
    }

    #[test]
    fn default_record_path_lands_under_records_dir_with_a_unique_name() {
        let dir = std::path::Path::new("/var/log/bsx");
        let path = super::default_record_path(dir);
        assert!(path.starts_with(dir), "joins under the operator's dir");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("run-") && name.ends_with(".json"),
            "{name}"
        );
        assert!(
            name.contains(&std::process::id().to_string()),
            "pid makes the name unique per process: {name}"
        );
    }

    #[test]
    fn shell_enforces_the_same_operator_policy_as_run() {
        // The bypass this closes: `require_jail`/ceilings must bind `shell` exactly as they bind
        // `run`; switching subcommand is not an opt-out.
        let policy = Policy {
            max_mem_mib: NonZeroU32::new(512),
            require_jail: true,
            ..Policy::default()
        };
        let err = shell_policy(&shell_args(None, Some(65536), false), &policy)
            .expect_err("an over-ceiling ask is refused");
        assert!(
            format!("{err}").contains("512"),
            "refusal names the ceiling: {err}"
        );
        let err = shell_policy(&shell_args(None, None, true), &policy)
            .expect_err("--unjailed is refused where the operator withdrew it");
        assert!(
            format!("{err}").contains("jail"),
            "refusal names the jail: {err}"
        );

        // A record-requiring host refuses the unauditable interactive path outright.
        let recording = Policy {
            require_record: true,
            ..Policy::default()
        };
        let err = shell_policy(&shell_args(None, None, false), &recording)
            .expect_err("require_record refuses a shell");
        assert!(format!("{err}").contains("audit record"), "{err}");
    }

    #[test]
    fn shell_takes_operator_defaults_and_flag_overrides() {
        let policy = Policy {
            vcpus: NonZeroU8::new(2),
            mem_mib: NonZeroU32::new(1024),
            ..Policy::default()
        };
        let defaults = shell_policy(&shell_args(None, None, false), &policy).expect("resolves");
        assert_eq!(defaults.vcpus.get(), 2, "unset flag takes the host default");
        assert_eq!(defaults.mem_mib.get(), 1024);
        let asked = shell_policy(&shell_args(Some(4), Some(2048), false), &policy)
            .expect("an in-ceiling ask resolves");
        assert_eq!(asked.vcpus.get(), 4, "a set flag wins over the default");
        assert_eq!(asked.mem_mib.get(), 2048);
    }

    #[test]
    fn artifact_writes_refuse_escaping_paths() {
        // Absolute and climbing paths are refused (backstopping the public API); the error names the path
        // (allowed) and carries none of the data. Requested here so the escape check, not the
        // deny-by-default check, is what fires.
        let base = ScratchDir::created("escape");
        for bad in ["/etc/owned", "../escape.txt", "a/../../b"] {
            let err = write_artifacts_in(base.path(), &artifact(bad, b"data"), &[bad.to_string()])
                .expect_err("escaping artifact path must be refused");
            let msg = format!("{err}");
            assert!(msg.contains(bad), "error should name the path: {msg}");
            assert!(
                !msg.contains("data"),
                "error must not carry the data: {msg}"
            );
        }
    }

    #[test]
    fn unrequested_artifacts_are_refused() {
        // Deny-by-default: a guest returning a file the operator never asked for is refused, even
        // though the name itself is a harmless relative path.
        let base = ScratchDir::created("unrequested");
        let err = write_artifacts_in(base.path(), &artifact("Makefile", b"pwn"), &[])
            .expect_err("an unrequested artifact must be refused");
        assert!(format!("{err}").contains("Makefile"));
        // Nothing was written.
        assert!(!base.path().join("Makefile").exists());
    }

    #[test]
    fn symlinked_component_cannot_escape_the_base() {
        // A pre-existing symlinked directory in the cwd must not let a `Normal`-component path be
        // written through it, the string check can't see the on-disk symlink, `confined_dest` can.
        let base = ScratchDir::created("symlink");
        let outside = ScratchDir::created("symlink-outside");
        // `out -> <outside>`, then a requested `out/x.txt` would land in `outside` if followed.
        std::os::unix::fs::symlink(outside.path(), base.path().join("out")).expect("symlink");
        let err = write_artifacts_in(
            base.path(),
            &artifact("out/x.txt", b"data"),
            &["out/x.txt".to_string()],
        )
        .expect_err("a symlinked path component must be refused");
        assert!(format!("{err}").contains("symlink"));
        // The escape target stayed empty.
        assert!(!outside.path().join("x.txt").exists());
    }

    #[test]
    fn requested_nested_artifact_is_written() {
        // The happy path: a requested nested name is written under the base, with the intermediate
        // directory created.
        let base = ScratchDir::created("write");
        write_artifacts_in(
            base.path(),
            &artifact("sub/out.txt", b"HELLO\n"),
            &["sub/out.txt".to_string()],
        )
        .expect("a requested artifact writes");
        let written = std::fs::read(base.path().join("sub").join("out.txt")).expect("read back");
        assert_eq!(written, b"HELLO\n");
    }
}
