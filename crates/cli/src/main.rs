//! The `ekvm` CLI, drive the sandbox lifecycle: boot a microVM, run one command in it (`run`),
//! or hold it open as an interactive stateful session (`shell`), with the run's host-observed
//! **audit surface** on flags (`--trace`/`--record`/`--record-summary`/`--watch`, see [`audit`]).
//!
//! `tracing` logs to **stderr**; **stdout** is reserved for a run's result (the guest's raw output,
//! or the `--json` structured result / audit log), so `ekvm run … 2>/dev/null` stays
//! pipe-clean (the `--watch` live view also draws on stderr, same reason). Log filter resolves
//! flags > env (`EKVM_LOG`) > default. Both subcommands run
//! **jailed by default** with `--unjailed` as the explicit opt-out, and both point
//! at the env-layered artifacts (`EKVM_ROOTFS`/`EKVM_KERNEL`/`EKVM_MARKER`, exec needs the
//! guest rootfs from `cargo xtask build-rootfs`).
#![forbid(unsafe_code)]

use ekvm::audit;
use ekvm::config;
mod doctor;
mod metrics;
mod serve;
mod session;
mod trace;
mod verify;
mod watch;

use std::io::{IsTerminal, Read, Write};
use std::num::{NonZeroU32, NonZeroU8};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ekvm::policy::{parse_allow, AllowRule, Policy, Requested};
use ekvm::{vcpus_supported, MAX_VCPUS};
use probes_loader::{EgressPolicy, Timing, MAX_POLICY_RULES};
use vmm::{sweep_orphans, Artifact, BootConfig, ErrorKind, Limits, Sandbox, VmmError, MAX_PAYLOAD};

/// Exit code for an operational failure (a boot/exec/channel error, as opposed to the guest
/// command's own exit code): conventional "2", named so the intent is legible at the
/// `ExitCode::from` site, the same convention (and name) as the guest agent's.
const EXIT_OPERATIONAL: u8 = 2;

/// The version of the `--json` **run-result** contract (exit code, streams, artifacts, metrics,
/// limits). Distinct from the audit record's `probes_loader::AUDIT_SCHEMA_VERSION`: two
/// surfaces, two independent versions. Same policy, additive within a version, a rename/removal
/// bumps it (docs/cli.md).
const RUN_RESULT_SCHEMA: u32 = 1;

/// A CLI-layer failure, kept distinct from the engine's [`VmmError`] so the library's typed error
/// (and its `kind()` buckets, pinned by embedders) is never minted for faults that are the CLI's
/// own: a bad flag combination, a refused artifact path, a local file write. `Engine` passes the
/// driver's error through untouched (`?` converts via `From`); both print as `ekvm: <reason>` and
/// exit 2, the taxonomy is for honesty, not for different handling.
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

#[derive(Parser)]
#[command(
    name = "ekvm",
    // The crate version, which is the in-development working number until the first tag
    // (`RELEASES.md`): `ekvm --version` exists so an installed binary can be told from a stale one,
    // which is a different question from "which release is this".
    version,
    about = "Run untrusted code in a Firecracker microVM, with a host-observed audit trail.",
    // A first-run reader needs a command to type, not a feature list: `doctor` explains the host,
    // then the two run forms differ only by whether this host can jail.
    after_help = "\
Getting started:
  ekvm doctor                          check what this host can do
  sudo -E ekvm run -- echo hello       run a command in a sandbox (jailed, the default)
  ekvm run --unjailed -- echo hello    same, without the jailer (needs no root)
  ekvm run --trace -- <cmd>            run it and print the audit trail

Config layers, highest first: flags, EKVM_* env, .ekvm.toml, defaults."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Log filter for stderr (overrides `EKVM_LOG`), e.g. `info`, `debug`.
    #[arg(long, global = true, value_name = "FILTER")]
    log: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    // Each variant's doc comment is user-facing help, so the first line is a one-line summary (what
    // `ekvm --help` lists) and the detail follows after a blank line (what `ekvm <cmd> --help`
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
  ekvm run -- echo hello
  ekvm run --vcpus 2 --mem 512 --wall 60 -- ./build.sh
  ekvm run --put main.rs --get a.out -- rustc main.rs -o a.out
  ekvm run --net --allow 1.1.1.1:443/tcp --trace -- curl https://1.1.1.1
  ekvm run --record run.json -- ./untrusted && ekvm verify run.json

Everything after `--` is the guest command, so its own flags are never parsed here.")]
    Run(Box<RunArgs>),
    /// Open an interactive session in a microVM.
    ///
    /// One command per line. State persists on the session's filesystem until you exit; shell
    /// process state (a `cd`, a variable) does not, because each line is its own exec.
    ///
    /// The operator policy (`.ekvm.toml` ceilings, `require_jail`, `require_record`) binds
    /// exactly as it does for `run`.
    Shell(ShellArgs),
    /// Check whether this host can run the engine.
    ///
    /// Reports KVM, the jailer, host tools, the guest artifacts, and eBPF capabilities, saying what
    /// will work, degrade, or refuse before the first sandbox, and names a first command that works
    /// on this host. Exits non-zero when a hard prerequisite is missing, so `ekvm doctor && ekvm
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
    /// Exposes the sandbox lifecycle over a unix socket (the versioned newline-JSON wire API), so a local client drives microVMs without linking the engine. Access control is
    /// the socket directory's permissions (no auth, a recorded non-goal).
    Serve(Box<serve::ServeArgs>),
}

#[derive(clap::Args)]
struct RunArgs {
    // Every flag's doc comment is user-facing: the first line is the one-line summary `-h` lists,
    // and the detail follows a blank line, where only `--help` shows it. Keeping the summary to one
    // line is what makes `-h` a usable table rather than a wall of paragraphs.
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
    /// `--unjailed`) and delegated cgroup v2 controllers; also settable via `EKVM_REQUIRE_LIMITS`
    /// or `.ekvm.toml`.
    #[arg(long, help_heading = "Isolation")]
    require_limits: bool,
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
    #[arg(long, value_name = "BYTES", help_heading = "Guest resources")]
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
    /// inspection or `ekvm verify`.
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
    /// Guest vCPUs (default 1). 1 or an even number up to 32 (see `run --vcpus`).
    #[arg(long, value_name = "N", value_parser = parse_vcpus)]
    vcpus: Option<NonZeroU8>,
    /// Guest memory in MiB (default 256). A whole number of at least 1 (see `run --mem`).
    #[arg(long, value_name = "MIB", value_parser = parse_mem_mib)]
    mem: Option<NonZeroU32>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // The daemon owns its own logging (info default, optional JSON) and reads no `.ekvm.toml`
    // (its config is flags + environment), so `serve` dispatches *before* the CLI's project-file
    // discovery and tracing init below, which are the run/shell/doctor conveniences. It still
    // receives the shared global `--log` filter.
    if let Cmd::Serve(args) = cli.cmd {
        return serve::serve(*args, cli.log);
    }
    // The `.ekvm.toml` file layer is discovered once, from the cwd, a mistyped key is a loud
    // failure here, before any boot (config typos must not silently no-op).
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let file = match config::EkvmToml::discover(&cwd) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "ekvm: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    // Log filter resolves flags > env > file > default.
    init_tracing(config::resolve_log(cli.log.as_deref(), file.as_ref()).as_deref());
    match run(cli.cmd, file.as_ref()) {
        Ok(code) => code,
        Err(e) => {
            // `eprintln!` panics on a closed stderr; a diagnostics write error is not our failure.
            let _ = writeln!(std::io::stderr(), "ekvm: {e}");
            // An infra-bucket failure means the host couldn't stand the microVM up, so point at the
            // tool that explains the host. Keyed on the `kind()` bucket rather than on variants, so
            // the hint can't drift as `VmmError` (which is `#[non_exhaustive]`) grows.
            if matches!(&e, CliError::Engine(err) if err.kind() == ErrorKind::Infra) {
                let _ = writeln!(
                    std::io::stderr(),
                    "ekvm: the host may not be ready, run `ekvm doctor`"
                );
            }
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn run(cmd: Cmd, file: Option<&config::EkvmToml>) -> Result<ExitCode, CliError> {
    match cmd {
        Cmd::Run(args) => {
            sweep_vm_residue(file);
            run_command(*args, file)
        }
        Cmd::Shell(args) => {
            sweep_vm_residue(file);
            shell(args, file)
        }
        Cmd::Doctor(args) => Ok(doctor::report(&base_config(file), &args)),
        Cmd::Verify(args) => verify::run(args, file),
        // `serve` is dispatched in `main` before this point (it skips the project-file/tracing
        // setup `run` runs under), so this arm is never reached; a typed error rather than a
        // panic keeps the no-panic discipline even for the impossible case.
        Cmd::Serve(_) => Err(CliError::Cli(
            "internal: serve is dispatched in main() before run()".into(),
        )),
    }
}

/// Reclaim the per-VM residue (scratch dirs + network namespaces) a **crashed** prior `ekvm`
/// run left: a `Ctrl-C`/SIGKILL of a boot subcommand skips `Drop`, so the lifetime sentinel reaps
/// the VM process but the scratch dir and netns are out of its scope. Run once before a
/// boot subcommand as the boot-time GC the engine owes its host. Best-effort and
/// conservative: [`sweep_orphans`] only reclaims this euid's dead-pid dirs, so it never touches a
/// concurrent run's live sandbox.
fn sweep_vm_residue(file: Option<&config::EkvmToml>) {
    match sweep_orphans(&base_config(file).scratch_dir) {
        Ok(r) if r.dirs_reclaimed + r.netns_reclaimed > 0 => tracing::info!(
            dirs = r.dirs_reclaimed,
            netns = r.netns_reclaimed,
            "reclaimed crashed-run VM residue at startup"
        ),
        Ok(_) => {}
        Err(e) => tracing::debug!(error = %e, "startup orphan sweep skipped"),
    }
}

/// The env+file-layered base config, `env > file > defaults`, over which each subcommand applies
/// its flags. Composes a single lookup that prefers the real environment, then the `.ekvm.toml`
/// value, then (inside [`BootConfig::from_env_with`]) the pinned default, so the three lower layers
/// stay one vocabulary keyed by the `EKVM_*` names.
fn base_config(file: Option<&config::EkvmToml>) -> BootConfig {
    BootConfig::from_env_with(|key| {
        std::env::var_os(key).or_else(|| file.and_then(|f| f.env_value(key)))
    })
}

/// `ekvm run`: open (jailed by default) → attach the probes when asked (`--trace`/`--record`/
/// `--record-summary`/`--watch`, fail-open) → one exec with the flag-supplied inputs (live-viewed
/// under `--watch`) → write the requested artifacts → finalize the audit record while the sandbox is
/// alive → close → report (raw relay or the `--json` structured result, then the `--trace` human trail
/// / `--record` full JSON / `--record-summary` model-legible projection, the three faces of one record).
fn run_command(args: RunArgs, file: Option<&config::EkvmToml>) -> Result<ExitCode, CliError> {
    // The run's root span: boot, exec, and the audit-record events all nest under it, so one run's
    // telemetry is greppable as a unit. `vmm_pid` is recorded once the sandbox is up, the id that
    // ties these log lines to the audit record and the host's own process table.
    let span = tracing::info_span!("run", vmm_pid = tracing::field::Empty);
    let _span = span.enter();
    // Resolve the caller's knobs against the operator's policy. For the CLI this is a
    // guardrail rather than a boundary (a local caller owns the config file, and `docs/security.md`
    // trusts them), but it keeps a host's defaults and ceilings consistent across both entry points.
    let host_policy = config::policy_of(file);
    let limits = host_policy
        .resolve(&Requested {
            vcpus: args.vcpus,
            mem_mib: args.mem,
            wall_secs: args.wall,
            output_cap: args.output_cap,
        })
        .map_err(|e| CliError::Cli(e.to_string()))?;
    host_policy
        .check_jail(args.unjailed)
        .map_err(|e| CliError::Cli(e.to_string()))?;
    host_policy
        .check_net(args.net)
        .map_err(|e| CliError::Cli(e.to_string()))?;
    // The effective signed-record destination: an explicit `--record` wins; otherwise the
    // operator's `records_dir` records every run there by default (which is also how a
    // `require_record` host is satisfied without callers remembering a flag).
    let record_path: Option<PathBuf> = args
        .record
        .clone()
        .or_else(|| host_policy.records_dir.as_deref().map(default_record_path));
    host_policy
        .check_record(record_path.is_some() || args.record_summary.is_some())
        .map_err(|e| CliError::Cli(e.to_string()))?;

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
        if let Err(e) = probes_loader::check_support() {
            return Err(CliError::Cli(format!(
                "--allow requested egress enforcement, but this host can't load the eBPF probes: {e}"
            )));
        }
        Some(policy)
    };
    if let Some(ref pol) = egress {
        host_policy
            .check_egress(pol)
            .map_err(|e| CliError::Cli(e.to_string()))?;
    }

    // Read the local `--put` files *before* the (jailed-by-default) boot: a bad path is a cheap stat
    // failure, so validate it up front rather than paying a full boot + teardown only to fail on it.
    let files_in = read_put_files(&args.put)?;

    // If this run will sign a record, resolve the key **now**, before booting. The signing path
    // rejects a group/world-readable key file (its secrecy is what the "host-signed" claim rests
    // on), and finding that out after the guest has already run would throw the record away with
    // the work already done. Last of the pre-flight checks, because it is the only one that
    // *creates* something (a first-run key), which a run rejected by a cheaper check above should
    // not do. Loading is idempotent: the write path reloads the same key.
    if record_path.is_some() {
        let key_path = config::signing_key_path(file);
        probes_loader::HostKey::load_or_generate(&key_path).map_err(|e| {
            CliError::Cli(format!(
                "signing key {} is unusable, so this run could not be recorded: {e}",
                key_path.display()
            ))
        })?;
    }
    let mut config = base_config(file).with_limits(limits);
    config.enable_network = args.net;
    // Flag layer over env/file (both folded by `base_config`): the flag only strengthens the
    // posture, so an env/file `true` survives an absent flag.
    if args.require_limits {
        config.require_limits = true;
    }
    // Captured before `config` moves into the boot: the record needs it, and an allowance means
    // something different with a route behind it than without.
    let gateway = config.egress.map(|e| e.gateway());
    let sandbox = open(config, args.unjailed)?;
    span.record("vmm_pid", sandbox.vmm_pid());
    if args.demo_boot {
        // The run result goes to stdout (stderr is reserved for logs). Not `println!`,
        // it panics on a closed pipe (`ekvm run … | head -0`).
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

    // The audit surface, when a flag asked for it (a plain `ekvm run` pays nothing): load the shared
    // probes and bind them to this sandbox by the plain values it exposes, the launch sequence the
    // probes-loader documents, composed here in the caller. `--allow` enforces (arming the tap before
    // it goes live) and pulls in the bundle even without an observation flag; observation is fail-open,
    // enforcement is a typed refusal (`attach`).
    let observing = args.trace
        || record_path.is_some()
        || args.record_summary.is_some()
        || args.watch
        || egress.is_some();
    let probes = if observing {
        Some(audit::Observability::load().attach(
            sandbox.name(),
            sandbox.vmm_pid(),
            sandbox.netns(),
            sandbox.tap_name(),
            egress.as_ref(),
            gateway,
        )?)
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
                "ekvm: live view closed; waiting for the command to finish"
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
    let record = probes.map(|p| {
        p.collect(Timing {
            boot: boot_latency,
            exec_wall: result.metrics.wall,
        })
    });
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
                "boot_ms": boot_latency.as_millis() as u64,
                "exec_wall_ms": result.metrics.wall.as_millis() as u64,
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
        if let Err(e) = writeln!(std::io::stdout(), "{structured}") {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(
                    VmmError::Artifact(format!("write --json result to stdout: {e}")).into(),
                );
            }
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
            let key_path = config::signing_key_path(file);
            let key = probes_loader::HostKey::load_or_generate(&key_path).map_err(|e| {
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

/// `ekvm shell`: one sandbox held open, one `sh -c` exec per input line, a stateful session
/// (every exec shares the guest's session working directory, so files persist across lines;
/// process state like `cd` and shell variables does not). The prompt and diagnostics go to stderr,
/// command output to stdout, so a piped script of lines stays clean.
fn shell(args: ShellArgs, file: Option<&config::EkvmToml>) -> Result<ExitCode, CliError> {
    let limits = shell_policy(&args, &config::policy_of(file))?;
    let mut config = base_config(file).with_limits(limits);
    if args.require_limits {
        config.require_limits = true;
    }
    let sandbox = open(config, args.unjailed)?;
    let mut err_out = std::io::stderr();
    let _ = writeln!(
        err_out,
        "ekvm shell: microVM up in {} ms; one command per line, files persist across lines, \
         `exit` (or EOF) to quit",
        sandbox.boot_latency().as_millis()
    );
    let stdin = std::io::stdin();
    loop {
        let _ = write!(err_out, "ekvm> ");
        let _ = err_out.flush();
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                let _ = writeln!(err_out, "ekvm: read stdin: {e}");
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
                let _ = writeln!(err_out, "ekvm: {e}");
            }
            Err(e) => {
                let _ = writeln!(err_out, "ekvm: session lost: {e}");
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
fn open(config: BootConfig, unjailed: bool) -> Result<Sandbox, VmmError> {
    if unjailed {
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

/// Resolve `ekvm shell`'s limits and posture against the operator policy: the same boundary
/// `run_command` enforces, so switching subcommand cannot bypass a ceiling, `require_jail`, or
/// `require_record`. Operator *defaults* apply too: an unset `--vcpus`/`--mem` takes the host's
/// default profile, not the bare engine default. Shell has no `--net`, so the net/egress checks
/// have nothing to check.
fn shell_policy(args: &ShellArgs, host_policy: &Policy) -> Result<Limits, CliError> {
    let limits = host_policy
        .resolve(&Requested {
            vcpus: args.vcpus,
            mem_mib: args.mem,
            wall_secs: None,
            output_cap: None,
        })
        .map_err(|e| CliError::Cli(e.to_string()))?;
    host_policy
        .check_jail(args.unjailed)
        .map_err(|e| CliError::Cli(e.to_string()))?;
    // A shell session writes no audit record, so a record-requiring host refuses it outright
    // rather than hosting an unauditable execution path.
    host_policy
        .check_record(false)
        .map_err(|e| CliError::Cli(format!("{e} (an interactive shell writes no audit record)")))?;
    Ok(limits)
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
        return Err(format!(
            "vCPUs must be 1 or an even number in 1..={MAX_VCPUS}, got {vcpus}"
        ));
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

/// The bytes piped into our stdin, or empty when stdin is the terminal (an interactive `ekvm run`
/// shouldn't block waiting for EOF). The read is **bounded at one frame + 1 byte**: the exec request
/// is a single frame, so anything past the channel's cap is rejected as a typed `PayloadTooLarge`
/// regardless, reading it all first would let `cat 10GB.bin | ekvm run …` balloon host RAM before
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
    // exception is a *closed* fd 0 (`ekvm run … 0<&-`), which is not a truncated read but no
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

/// Initialize stderr logging from the filter [`config::resolve_log`] already resolved
/// (`flag > EKVM_LOG > file`), falling back to `warn` when nothing set it. Does not re-read the
/// environment: the precedence is single-sourced in `resolve_log`, this only applies the result.
/// An invalid filter falls back to `warn` rather than failing the run.
fn init_tracing(filter: Option<&str>) {
    let filter = filter.unwrap_or("warn");
    let env_filter = tracing_subscriber::EnvFilter::try_new(filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::{
        build_egress, parse_allow, parse_env_pair, parse_mem_mib, parse_vcpus, shell_policy,
        write_artifacts_in, AllowRule, Artifact, Policy, ShellArgs, MAX_VCPUS,
    };
    use probes_loader::{Ipv4Cidr, Protocol, MAX_POLICY_RULES};
    use std::net::Ipv4Addr;
    use std::num::{NonZeroU32, NonZeroU8};
    use test_support::ScratchDir;

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
        assert!(parse_vcpus("64")
            .unwrap_err()
            .contains(&MAX_VCPUS.to_string()));
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
            vcpus: vcpus.and_then(NonZeroU8::new),
            mem: mem.and_then(NonZeroU32::new),
        }
    }

    #[test]
    fn default_record_path_lands_under_records_dir_with_a_unique_name() {
        let dir = std::path::Path::new("/var/log/ekvm");
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
