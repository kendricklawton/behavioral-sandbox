//! The `agent` CLI, drive the sandbox lifecycle: boot a microVM, run one command in it (`run`),
//! or hold it open as an interactive stateful session (`shell`), with the run's host-observed
//! **audit surface** on flags (`--trace`/`--record`/`--record-summary`/`--watch`, see [`audit`]).
//!
//! `tracing` logs to **stderr**; **stdout** is reserved for a run's result (the guest's raw output,
//! or the `--json` structured result / audit log), so `agent run … 2>/dev/null` stays
//! pipe-clean (the `--watch` live view also draws on stderr, same reason). Log filter resolves
//! flags > env (`AGENT_LOG`) > default. Both subcommands run
//! **jailed by default** (decision 015) with `--unjailed` as the explicit opt-out, and both point
//! at the env-layered artifacts (`AGENT_ROOTFS`/`AGENT_KERNEL`/`AGENT_MARKER`, exec needs the
//! agent rootfs from `cargo xtask build-rootfs`).
#![forbid(unsafe_code)]

use agent_cli::audit;
mod config;
mod doctor;
mod trace;
mod watch;

use std::io::{IsTerminal, Read, Write};
use std::net::Ipv4Addr;
use std::num::{NonZeroU32, NonZeroU8};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_probes_loader::{EgressPolicy, Ipv4Cidr, Protocol, Timing, MAX_POLICY_RULES};
use agent_vmm::{BootConfig, ErrorKind, Limits, Sandbox, VmmError, MAX_PAYLOAD};
use clap::{Parser, Subcommand};

/// Exit code for an operational failure (a boot/exec/channel error, as opposed to the guest
/// command's own exit code): conventional "2", named so the intent is legible at the
/// `ExitCode::from` site, the same convention (and name) as the guest agent's.
const EXIT_OPERATIONAL: u8 = 2;

/// The version of the `--json` **run-result** contract (exit code, streams, artifacts, metrics,
/// limits). Distinct from the audit record's `agent_probes_loader::AUDIT_SCHEMA_VERSION`: two
/// surfaces, two independent versions. Same policy, additive within a version, a rename/removal
/// bumps it (docs/cli.md).
const RUN_RESULT_SCHEMA: u32 = 1;

#[derive(Parser)]
#[command(
    name = "agent",
    about = "a self-hostable Firecracker + aya code-execution sandbox"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Log filter for stderr (overrides `AGENT_LOG`), e.g. `info`, `debug`.
    #[arg(long, global = true, value_name = "FILTER")]
    log: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Boot a microVM and run one command inside it. Boxed: `run` carries far more flags than the
    /// other subcommands, so keeping it behind an indirection stops the whole `Cmd` enum from being
    /// sized to it (the `clippy::large_enum_variant` this would otherwise trip).
    Run(Box<RunArgs>),
    /// Open an interactive session in a microVM: one command per line, state persists on the
    /// session's filesystem until you exit (shell process state like `cd`/variables does not,
    /// each line is its own exec).
    Shell(ShellArgs),
    /// Check this host's readiness to run the engine, KVM, the jailer, tools, artifacts, eBPF
    /// capabilities, and print what will work, degrade, or refuse before the first sandbox.
    Doctor,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Just boot a microVM and read its console, no command (the boot-only demo).
    #[arg(long)]
    demo_boot: bool,
    /// Run the VMM without the jailer. The default is confined (jailed, which needs real root and
    /// the `jailer` binary, decision 015); this is the explicit opt-out for hosts that can't jail.
    #[arg(long)]
    unjailed: bool,
    /// Set an environment variable on the guest command (repeatable). Values are treated as
    /// secrets: the engine never logs them.
    #[arg(long = "env", value_name = "KEY=VALUE", value_parser = parse_env_pair)]
    env: Vec<(String, String)>,
    /// Inject a host file into the run's working directory (repeatable; guest name = basename).
    #[arg(long, value_name = "FILE")]
    put: Vec<PathBuf>,
    /// Fetch a file from the run's working directory afterwards (repeatable; written under the
    /// current directory at the same relative path).
    #[arg(long, value_name = "PATH")]
    get: Vec<String>,
    /// Wall-clock budget in seconds (default 30, minimum 1): the boot deadline and the command's
    /// runtime budget alike, the guest kills the command past it. Zero is rejected at parse
    /// (there is no "no limit"), never silently rounded up.
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
    wall: Option<u64>,
    /// Cap, in bytes, on captured stdout+stderr+artifacts (default 16 MiB).
    #[arg(long, value_name = "BYTES")]
    output_cap: Option<usize>,
    /// Guest vCPUs (default 1). A whole number in 1..=32; zero or over-cap is a typed CLI error,
    /// never a silent clamp (Firecracker v1.9 caps a microVM at 32, decision 001).
    #[arg(long, value_name = "N", value_parser = parse_vcpus)]
    vcpus: Option<NonZeroU8>,
    /// Guest memory in MiB (default 256). A whole number of at least 1; zero is a typed CLI error.
    #[arg(long, value_name = "MIB", value_parser = parse_mem_mib)]
    mem: Option<NonZeroU32>,
    /// Emit the structured run result as one JSON object on stdout (exit code, lossy
    /// stdout/stderr, artifact list, metrics, and the effective limits) instead of relaying the
    /// raw streams.
    #[arg(long)]
    json: bool,
    /// Boot with a NIC (a per-VM tap the host-side probes observe). Deny-by-default is unchanged:
    /// with no egress allowance the guest reaches nothing beyond the host end of its /30. What
    /// crosses the tap lands in the audit record's network section.
    #[arg(long, conflicts_with = "demo_boot")]
    net: bool,
    /// Allow one egress destination past the deny-by-default tap (repeatable), as
    /// `IP[/CIDR][:PORT][/PROTO]`, e.g. `1.1.1.1`, `10.0.0.0/8`, `1.1.1.1:443/tcp`. Requires
    /// `--net`; the allowances build the run's egress policy, armed before the tap goes live. A
    /// host that can't enforce (missing eBPF caps) is a typed refusal, never a silent unenforced
    /// run.
    #[arg(long, value_name = "IP[/CIDR][:PORT][/PROTO]", value_parser = parse_allow, requires = "net")]
    allow: Vec<AllowRule>,
    /// Attach the host-side probes and print the run's audit trail (human-readable) on stdout
    /// after the run. Fail-open: a host without eBPF caps still runs, with the gaps explained.
    /// Machine consumers use `--record` (so this conflicts with `--json`).
    #[arg(long, conflicts_with_all = ["json", "demo_boot"])]
    trace: bool,
    /// Attach the host-side probes and write the run's deterministic audit record (one line of
    /// JSON, the machine surface) to this file for later inspection.
    #[arg(long, value_name = "FILE", conflicts_with = "demo_boot")]
    record: Option<PathBuf>,
    /// Attach the host-side probes and write the run's **model-legible summary** (one line of JSON, a
    /// compact projection of the audit record shaped for an agent's observe→act loop: what it reached,
    /// what egress was denied, its resource envelope, and any coverage gap) to this file.
    #[arg(long, value_name = "FILE", conflicts_with = "demo_boot")]
    record_summary: Option<PathBuf>,
    /// Watch the run live: a full-screen view on stderr (network flows and denials, resources,
    /// the VMM's host syscalls, a timeline) while the command runs. Needs stderr on a terminal.
    /// `q` closes the view (the run continues); after the command finishes, the view stays up
    /// until closed.
    #[arg(long, conflicts_with = "demo_boot")]
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
    /// Guest vCPUs (default 1). A whole number in 1..=32 (see `run --vcpus`).
    #[arg(long, value_name = "N", value_parser = parse_vcpus)]
    vcpus: Option<NonZeroU8>,
    /// Guest memory in MiB (default 256). A whole number of at least 1 (see `run --mem`).
    #[arg(long, value_name = "MIB", value_parser = parse_mem_mib)]
    mem: Option<NonZeroU32>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // The `.agent.toml` file layer is discovered once, from the cwd, a mistyped key is a loud
    // failure here, before any boot (config typos must not silently no-op).
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let file = match config::AgentToml::discover(&cwd) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "agent: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    // Log filter resolves flags > env > file > default.
    init_tracing(config::resolve_log(cli.log.as_deref(), file.as_ref()).as_deref());
    match run(cli.cmd, file.as_ref()) {
        Ok(code) => code,
        Err(e) => {
            // `eprintln!` panics on a closed stderr; a diagnostics write error is not our failure.
            let _ = writeln!(std::io::stderr(), "agent: {e}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn run(cmd: Cmd, file: Option<&config::AgentToml>) -> Result<ExitCode, VmmError> {
    match cmd {
        Cmd::Run(args) => run_command(*args, file),
        Cmd::Shell(args) => shell(args, file),
        Cmd::Doctor => Ok(doctor::report(&base_config(file))),
    }
}

/// The env+file-layered base config, `env > file > defaults`, over which each subcommand applies
/// its flags. Composes a single lookup that prefers the real environment, then the `.agent.toml`
/// value, then (inside [`BootConfig::from_env_with`]) the pinned default, so the three lower layers
/// stay one vocabulary keyed by the `AGENT_*` names.
fn base_config(file: Option<&config::AgentToml>) -> BootConfig {
    BootConfig::from_env_with(|key| {
        std::env::var_os(key).or_else(|| file.and_then(|f| f.env_value(key)))
    })
}

/// `agent run`: open (jailed by default) → attach the probes when asked (`--trace`/`--record`/
/// `--record-summary`/`--watch`, fail-open) → one exec with the flag-supplied inputs (live-viewed
/// under `--watch`) → write the requested artifacts → finalize the audit record while the sandbox is
/// alive → close → report (raw relay or the `--json` structured result, then the `--trace` human trail
/// / `--record` full JSON / `--record-summary` model-legible projection, the three faces of one record).
fn run_command(args: RunArgs, file: Option<&config::AgentToml>) -> Result<ExitCode, VmmError> {
    let mut limits = limits_with(args.vcpus, args.mem);
    if let Some(secs) = args.wall {
        limits.wall = Duration::from_secs(secs); // clap enforced >= 1 at parse
    }
    if let Some(bytes) = args.output_cap {
        limits.output_cap = bytes;
    }
    // Refuse `--watch` without a terminal *before* paying a boot: the live view draws on stderr.
    if args.watch && !std::io::stderr().is_terminal() {
        return Err(VmmError::Vmm(
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
        if let Err(e) = agent_probes_loader::check_support() {
            return Err(VmmError::Vmm(format!(
                "--allow requested egress enforcement, but this host can't load the eBPF probes: {e}"
            )));
        }
        Some(policy)
    };
    // Read the local `--put` files *before* the (jailed-by-default) boot: a bad path is a cheap stat
    // failure, so validate it up front rather than paying a full boot + teardown only to fail on it.
    let files_in = read_put_files(&args.put)?;
    let mut config = base_config(file).with_limits(limits);
    config.enable_network = args.net;
    let sandbox = open(config, args.unjailed)?;
    if args.demo_boot {
        // The run result goes to stdout (stderr is reserved for logs). Not `println!`,
        // it panics on a closed pipe (`agent run … | head -0`), and a no-panic host path
        // includes the shell pipeline case.
        let _ = writeln!(
            std::io::stdout(),
            "booted microVM to userspace in {} ms",
            sandbox.boot_latency().as_millis()
        );
        return sandbox.shutdown().map(|()| ExitCode::SUCCESS);
    }

    // The audit surface, when a flag asked for it (a plain `agent run` pays nothing): load the shared
    // probes and bind them to this sandbox by the plain values it exposes, the launch sequence the
    // probes-loader documents, composed here in the caller. `--allow` enforces (arming the tap before
    // it goes live) and pulls in the bundle even without an observation flag; observation is fail-open,
    // enforcement is a typed refusal (`attach`).
    let observing = args.trace
        || args.record.is_some()
        || args.record_summary.is_some()
        || args.watch
        || egress.is_some();
    let probes = if observing {
        Some(audit::Observability::load().attach(
            sandbox.vmm_pid(),
            sandbox.netns(),
            sandbox.tap_name(),
            egress.as_ref(),
        )?)
    } else {
        None
    };

    let boot_latency = sandbox.boot_latency();
    let vmm_pid = sandbox.vmm_pid();
    let stdin = piped_stdin();
    let (sandbox, result) = if args.watch {
        // Exec on a worker thread that owns the sandbox; the main thread runs the live view off
        // non-destructive probe snapshots until the worker flags completion.
        let done = Arc::new(AtomicBool::new(false));
        let worker_done = Arc::clone(&done);
        let (argv, env, get) = (args.argv.clone(), args.env.clone(), args.get.clone());
        let worker = std::thread::spawn(move || {
            let result = sandbox.exec_with_files(&argv, &stdin, &files_in, &env, &get);
            worker_done.store(true, Ordering::Release);
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
                "agent: live view closed; waiting for the command to finish"
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
    write_artifacts(&result.files, &args.get)?;
    // Finalize the audit record **while the sandbox is still alive** (the attached bundle reads the
    // live cgroup + maps), then close.
    let record = probes.map(|p| {
        p.collect(Timing {
            boot: boot_latency,
            exec_wall: result.metrics.wall,
        })
    });
    sandbox.shutdown()?;

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
                .map(|(path, data)| serde_json::json!({ "path": path, "bytes": data.len() }))
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
        let _ = writeln!(std::io::stdout(), "{structured}");
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
        if let Some(path) = &args.record {
            // The deterministic JSON record, the machine surface, one line, byte-stable.
            std::fs::write(path, record.to_json() + "\n")
                .map_err(|e| VmmError::Artifact(format!("--record {}: {e}", path.display())))?;
            tracing::info!(path = %path.display(), "wrote audit record");
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

/// `agent shell`: one sandbox held open, one `sh -c` exec per input line, a stateful session
/// (every exec shares the guest's session working directory, so files persist across lines;
/// process state like `cd` and shell variables does not). The prompt and diagnostics go to stderr,
/// command output to stdout, so a piped script of lines stays clean.
fn shell(args: ShellArgs, file: Option<&config::AgentToml>) -> Result<ExitCode, VmmError> {
    let sandbox = open(
        base_config(file).with_limits(limits_with(args.vcpus, args.mem)),
        args.unjailed,
    )?;
    let mut err_out = std::io::stderr();
    let _ = writeln!(
        err_out,
        "agent shell: microVM up in {} ms; one command per line, files persist across lines, \
         `exit` (or EOF) to quit",
        sandbox.boot_latency().as_millis()
    );
    let stdin = std::io::stdin();
    loop {
        let _ = write!(err_out, "agent> ");
        let _ = err_out.flush();
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                let _ = writeln!(err_out, "agent: read stdin: {e}");
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
                let _ = writeln!(err_out, "agent: {e}");
            }
            Err(e) => {
                let _ = writeln!(err_out, "agent: session lost: {e}");
                let _ = sandbox.shutdown();
                return Err(e);
            }
        }
    }
    sandbox.shutdown().map(|()| ExitCode::SUCCESS)
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

/// One parsed `--allow` allowance: a validated destination CIDR with optional port/protocol, the
/// CLI face of one [`EgressPolicy`] rule. `Clone` for clap's repeatable collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllowRule {
    cidr: Ipv4Cidr,
    port: Option<u16>,
    proto: Option<Protocol>,
}

/// Parse one `--allow` value, `IP[/CIDR][:PORT][/PROTO]`, into an [`AllowRule`]. Parsed
/// right-to-left so the grammar is unambiguous: an optional `/tcp`|`/udp` **protocol** suffix comes
/// off first (the only non-numeric `/`, so a numeric CIDR prefix can never be mistaken for it), then
/// an optional `:port`, then the address with an optional `/prefix`. Every malformed field is a
/// typed CLI error naming the offending token, never a silently dropped allowance.
fn parse_allow(s: &str) -> Result<AllowRule, String> {
    // Trailing protocol: `/tcp` or `/udp` (case-insensitive), else none.
    let (head, proto) = match s.rsplit_once('/') {
        Some((rest, tail)) if tail.eq_ignore_ascii_case("tcp") => (rest, Some(Protocol::Tcp)),
        Some((rest, tail)) if tail.eq_ignore_ascii_case("udp") => (rest, Some(Protocol::Udp)),
        _ => (s, None),
    };
    // Optional `:port`.
    let (addr_cidr, port) = match head.rsplit_once(':') {
        Some((addr, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("invalid port {p:?} in --allow {s:?}"))?;
            (addr, Some(port))
        }
        None => (head, None),
    };
    // The address, with an optional `/prefix` CIDR (absent = a single-host `/32`).
    let cidr = match addr_cidr.split_once('/') {
        Some((ip, prefix)) => {
            let ip: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("invalid IPv4 address {ip:?} in --allow {s:?}"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("invalid CIDR prefix {prefix:?} in --allow {s:?}"))?;
            Ipv4Cidr::new(ip, prefix).map_err(|e| format!("--allow {s:?}: {e}"))?
        }
        None => Ipv4Cidr::host(
            addr_cidr
                .parse()
                .map_err(|_| format!("invalid IPv4 address {addr_cidr:?} in --allow {s:?}"))?,
        ),
    };
    Ok(AllowRule { cidr, port, proto })
}

/// Fold the `--allow` rules into a deny-by-default [`EgressPolicy`]. Refuses more than the kernel
/// policy map holds ([`MAX_POLICY_RULES`]) with a typed error naming the cap, rather than letting the
/// overflow surface as a cryptic attach-time failure.
fn build_egress(allows: &[AllowRule]) -> Result<EgressPolicy, VmmError> {
    if allows.len() > MAX_POLICY_RULES {
        return Err(VmmError::Vmm(format!(
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

/// Firecracker v1.9 caps a microVM at 32 vCPUs (decision 001), so refuse anything above it at the
/// CLI edge rather than surfacing a late Firecracker API error mid-boot.
const MAX_VCPUS: u8 = 32;

/// Fold the `--vcpus`/`--mem` overrides onto the default [`Limits`], the two resource knobs both
/// `run` and `shell` project. An unset flag keeps the (deliberately conservative) default; a set one
/// carries the already-validated [`NonZeroU8`]/[`NonZeroU32`] the parsers produced. `run` layers its
/// own `--wall`/`--output-cap` on top of the result.
fn limits_with(vcpus: Option<NonZeroU8>, mem_mib: Option<NonZeroU32>) -> Limits {
    let mut limits = Limits::default();
    if let Some(vcpus) = vcpus {
        limits.vcpus = vcpus;
    }
    if let Some(mem_mib) = mem_mib {
        limits.mem_mib = mem_mib;
    }
    limits
}

/// Parse `--vcpus`: a whole number in `1..=32` into the [`Limits::vcpus`] [`NonZeroU8`]. Parsing
/// straight into the non-zero type rejects `0` (and any non-number / u8 overflow); the explicit cap
/// check rejects an over-32 value. Either way it is a **typed CLI error, never a silent clamp**, the
/// value is refused at parse, not narrowed behind the caller's back or surfaced as a late boot error.
fn parse_vcpus(s: &str) -> Result<NonZeroU8, String> {
    let vcpus: NonZeroU8 = s
        .parse()
        .map_err(|_| format!("expected a whole number of vCPUs in 1..={MAX_VCPUS}, got {s:?}"))?;
    if vcpus.get() > MAX_VCPUS {
        return Err(format!("vCPUs must be in 1..={MAX_VCPUS}, got {vcpus}"));
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
/// didn't explicitly ask for. Deny-by-default (`.rules` guardrail 3): the operator's `--get` set is
/// the *only* allowance, so a returned path that wasn't requested (a planted `.git/config`,
/// `Makefile`) is refused, never written. The exec API already guarantees each path is relative and
/// non-climbing (`run_exec`); here we additionally resolve every component without following a
/// symlink, so a pre-existing symlinked directory in the cwd (`out -> /etc`) can't turn a
/// `Normal`-component path into an escape the string check alone is blind to.
fn write_artifacts(files: &[(String, Vec<u8>)], requested: &[String]) -> Result<(), VmmError> {
    let cwd = std::env::current_dir()
        .map_err(|e| VmmError::Vmm(format!("resolve current directory: {e}")))?;
    write_artifacts_in(&cwd, files, requested)
}

/// The core of [`write_artifacts`], resolving destinations under an explicit `base` so it is
/// testable without mutating the process-global cwd.
fn write_artifacts_in(
    base: &Path,
    files: &[(String, Vec<u8>)],
    requested: &[String],
) -> Result<(), VmmError> {
    for (path, data) in files {
        // Deny-by-default: the guest doesn't get to choose what lands on the host, only a name the
        // operator requested with `--get` is eligible. An honest guest only ever returns requested
        // paths (it echoes the request's artifact list), so a mismatch is a misbehaving guest.
        if !requested.iter().any(|r| r == path) {
            return Err(VmmError::Vmm(format!(
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
            return Err(VmmError::Vmm(format!(
                "refusing to write artifact {path:?} outside the current directory"
            )));
        }
        let dest = confined_dest(base, rel)?;
        std::fs::write(&dest, data)
            .map_err(|e| VmmError::Vmm(format!("write artifact {path:?}: {e}")))?;
        tracing::info!(path = %path, bytes = data.len(), "wrote artifact");
    }
    Ok(())
}

/// Resolve `rel` (already checked relative and non-climbing) against `base` into an absolute
/// destination, creating intermediate directories but **refusing to follow a symlink** at any
/// component. `symlink_metadata` is `lstat` (no traversal), so a pre-existing symlinked directory,
/// or a symlinked final name, is rejected rather than written through, closing the
/// `out -> /etc` escape that a string-only check misses.
fn confined_dest(base: &Path, rel: &Path) -> Result<PathBuf, VmmError> {
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
                return Err(VmmError::Vmm(format!(
                    "refusing to write artifact through the symlink {cur:?}"
                )));
            }
            // The final component may already be a regular file (a legitimate overwrite), but not a
            // directory we'd clobber; an intermediate component must be a real directory to descend.
            Ok(m) if last && m.is_dir() => {
                return Err(VmmError::Vmm(format!(
                    "refusing to write artifact over the directory {cur:?}"
                )));
            }
            Ok(m) if !last && !m.is_dir() => {
                return Err(VmmError::Vmm(format!(
                    "artifact path component {cur:?} is not a directory"
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Create missing intermediate dirs; the final missing component the write creates.
                if !last {
                    std::fs::create_dir(&cur)
                        .map_err(|e| VmmError::Vmm(format!("create artifact dir {cur:?}: {e}")))?;
                }
            }
            Err(e) => return Err(VmmError::Vmm(format!("stat artifact path {cur:?}: {e}"))),
        }
    }
    Ok(cur)
}

/// The bytes piped into our stdin, or empty when stdin is the terminal (an interactive `agent run`
/// shouldn't block waiting for EOF). The read is **bounded at one frame + 1 byte**: the exec request
/// is a single frame, so anything past the channel's cap is rejected as a typed `PayloadTooLarge`
/// regardless, reading it all first would let `cat 10GB.bin | agent run …` balloon host RAM before
/// the same error. The `+ 1` still overshoots the cap by a byte so the oversize case is caught rather
/// than silently truncated to exactly the cap. Bulk data belongs on the block-device path anyway.
fn piped_stdin() -> Vec<u8> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let _ = stdin
        .lock()
        .take(MAX_PAYLOAD as u64 + 1)
        .read_to_end(&mut buf);
    buf
}

/// Initialize stderr logging, resolving the filter from the flag, then `AGENT_LOG`, then `warn`.
/// An invalid filter falls back to `warn` rather than failing the run.
fn init_tracing(flag: Option<&str>) {
    let filter = flag
        .map(str::to_string)
        .or_else(|| std::env::var("AGENT_LOG").ok())
        .unwrap_or_else(|| "warn".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_new(&filter)
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
        build_egress, limits_with, parse_allow, parse_env_pair, parse_mem_mib, parse_vcpus,
        write_artifacts_in, AllowRule, MAX_VCPUS,
    };
    use agent_probes_loader::{Ipv4Cidr, Protocol, MAX_POLICY_RULES};
    use std::net::Ipv4Addr;
    use std::num::{NonZeroU32, NonZeroU8};
    use std::path::{Path, PathBuf};

    /// A scratch dir removed on drop, so a panicking assertion can't leak it. Unique per (pid, tag,
    /// counter) so parallel tests don't collide, the artifact tests write real files.
    struct TestDir(PathBuf);
    impl TestDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "agent-cli-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn artifact(path: &str, data: &[u8]) -> Vec<(String, Vec<u8>)> {
        vec![(path.to_string(), data.to_vec())]
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
    fn vcpus_parse_within_the_one_to_thirty_two_domain() {
        assert_eq!(parse_vcpus("1"), Ok(NonZeroU8::MIN));
        assert_eq!(parse_vcpus("32"), NonZeroU8::new(32).ok_or(String::new()));
        // Zero, over-cap, u8 overflow, and non-numbers are each a typed error, never a clamp.
        assert!(
            parse_vcpus("0").is_err(),
            "zero is unbootable, not a small budget"
        );
        assert!(parse_vcpus("33").is_err(), "over the v1.9 cap");
        assert!(parse_vcpus("300").is_err(), "u8 overflow");
        assert!(parse_vcpus("").is_err());
        assert!(parse_vcpus("two").is_err());
        // The over-cap message names the cap so the refusal is actionable.
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

    #[test]
    fn limits_fold_overrides_onto_conservative_defaults() {
        // An unset flag keeps the default; a set one wins. The other knobs are untouched by this
        // helper (run layers wall/output-cap separately).
        let d = agent_vmm::Limits::default();
        let none = limits_with(None, None);
        assert_eq!(none.vcpus, d.vcpus);
        assert_eq!(none.mem_mib, d.mem_mib);
        let both = limits_with(NonZeroU8::new(4), NonZeroU32::new(1024));
        assert_eq!(both.vcpus.get(), 4);
        assert_eq!(both.mem_mib.get(), 1024);
        assert_eq!(both.wall, d.wall, "wall is not this helper's to touch");
        assert_eq!(both.output_cap, d.output_cap);
    }

    #[test]
    fn artifact_writes_refuse_escaping_paths() {
        // Absolute and climbing paths are refused (backstopping the public API); the error names the path
        // (allowed) and carries none of the data. Requested here so the escape check, not the
        // deny-by-default check, is what fires.
        let base = TestDir::new("escape");
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
        let base = TestDir::new("unrequested");
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
        let base = TestDir::new("symlink");
        let outside = TestDir::new("symlink-outside");
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
        let base = TestDir::new("write");
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
