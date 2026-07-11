//! The `agent` CLI — drive the sandbox: boot a microVM, run a command in it, open a shell.
//!
//! `tracing` logs to **stderr**; **stdout** is reserved for a run's result / flight recorder, so
//! `agent run … 2>/dev/null` stays pipe-clean. Log filter resolves flags > env (`AGENT_LOG`) >
//! default. **Skeleton** — the subcommands are wired to the driver, whose behavior lands in
//! ROADMAP Phase 1+ (until then they report a typed "not implemented yet" and exit `2`).
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use agent_vmm::{Limits, Sandbox, VmmError};
use clap::{Parser, Subcommand};

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
    /// Boot a microVM and run a command inside it.
    Run(RunArgs),
    /// Open an interactive shell in a microVM.
    Shell,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Just boot a microVM and read its console — no command (the Phase 1 demo).
    #[arg(long)]
    demo_boot: bool,
    /// The command to run in the guest, after `--`.
    #[arg(trailing_var_arg = true)]
    argv: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.log.as_deref());
    match run(cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            // `eprintln!` panics on a closed stderr; a diagnostics write error is not our failure.
            let _ = writeln!(std::io::stderr(), "agent: {e}");
            ExitCode::from(2) // operational error
        }
    }
}

fn run(cmd: Cmd) -> Result<ExitCode, VmmError> {
    match cmd {
        Cmd::Run(args) => {
            // Phase 1 boots the microVM; Phase 2 execs the argv and streams its output.
            let sandbox = Sandbox::boot(Limits::default())?;
            if args.demo_boot {
                // The run result goes to stdout (stderr is reserved for logs). Not `println!` —
                // it panics on a closed pipe (`agent run … | head -0`), and a no-panic host path
                // includes the shell pipeline case.
                let _ = writeln!(
                    std::io::stdout(),
                    "booted microVM to userspace in {} ms",
                    sandbox.boot_latency().as_millis()
                );
                return sandbox.shutdown().map(|()| ExitCode::SUCCESS);
            }
            // No stdin piped from the CLI yet (that lands with file/streaming I/O).
            let result = sandbox.exec(&args.argv, &[])?;
            sandbox.shutdown()?;
            // Relay the guest's output on our own stdout/stderr — the whole point of `exec`. Ignore
            // write errors (a closed pipe is not our failure); the guest exit code is what we return.
            let _ = std::io::stdout().write_all(&result.stdout);
            let _ = std::io::stderr().write_all(&result.stderr);
            Ok(ExitCode::from(u8::try_from(result.exit_code).unwrap_or(1)))
        }
        Cmd::Shell => Err(VmmError::Unimplemented("agent shell (ROADMAP Phase 7)")),
    }
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
