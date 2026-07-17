//! The `agent` CLI — drive the sandbox lifecycle: boot a microVM, run one command in it (`run`),
//! or hold it open as an interactive stateful session (`shell`), with the run's host-observed
//! **audit surface** on flags (`--trace`/`--record`/`--watch` — see [`audit`]).
//!
//! `tracing` logs to **stderr**; **stdout** is reserved for a run's result (the guest's raw output,
//! or the `--json` structured result / audit log), so `agent run … 2>/dev/null` stays
//! pipe-clean (the `--watch` live view also draws on stderr, same reason). Log filter resolves
//! flags > env (`AGENT_LOG`) > default. Both subcommands run
//! **jailed by default** (decision 015) with `--unjailed` as the explicit opt-out, and both point
//! at the env-layered artifacts (`AGENT_ROOTFS`/`AGENT_KERNEL`/`AGENT_MARKER` — exec needs the
//! agent rootfs from `cargo xtask build-rootfs`).
#![forbid(unsafe_code)]

mod audit;
mod trace;
mod watch;

use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_probes_loader::Timing;
use agent_vmm::{BootConfig, ErrorKind, Limits, Sandbox, VmmError, MAX_PAYLOAD};
use clap::{Parser, Subcommand};

/// Exit code for an operational failure (a boot/exec/channel error, as opposed to the guest
/// command's own exit code): conventional "2", named so the intent is legible at the
/// `ExitCode::from` site — the same convention (and name) as the guest agent's.
const EXIT_OPERATIONAL: u8 = 2;

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
    /// Boot a microVM and run one command inside it.
    Run(RunArgs),
    /// Open an interactive session in a microVM: one command per line, state persists on the
    /// session's filesystem until you exit (shell process state like `cd`/variables does not —
    /// each line is its own exec).
    Shell(ShellArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Just boot a microVM and read its console — no command (the boot-only demo).
    #[arg(long)]
    demo_boot: bool,
    /// Run the VMM without the jailer. The default is confined (jailed, which needs real root and
    /// the `jailer` binary — decision 015); this is the explicit opt-out for hosts that can't jail.
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
    /// runtime budget alike — the guest kills the command past it. Zero is rejected at parse
    /// (there is no "no limit"), never silently rounded up.
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
    wall: Option<u64>,
    /// Cap, in bytes, on captured stdout+stderr+artifacts (default 16 MiB).
    #[arg(long, value_name = "BYTES")]
    output_cap: Option<usize>,
    /// Emit the structured run result as one JSON object on stdout (exit code, lossy
    /// stdout/stderr, artifact list, metrics) instead of relaying the raw streams.
    #[arg(long)]
    json: bool,
    /// Boot with a NIC (a per-VM tap the host-side probes observe). Deny-by-default is unchanged:
    /// with no egress allowance the guest reaches nothing beyond the host end of its /30. What
    /// crosses the tap lands in the audit record's network section.
    #[arg(long, conflicts_with = "demo_boot")]
    net: bool,
    /// Attach the host-side probes and print the run's audit trail (human-readable) on stdout
    /// after the run. Fail-open: a host without eBPF caps still runs, with the gaps explained.
    /// Machine consumers use `--record` (so this conflicts with `--json`).
    #[arg(long, conflicts_with_all = ["json", "demo_boot"])]
    trace: bool,
    /// Attach the host-side probes and write the run's deterministic audit record (one line of
    /// JSON, the machine surface) to this file for later inspection.
    #[arg(long, value_name = "FILE", conflicts_with = "demo_boot")]
    record: Option<PathBuf>,
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.log.as_deref());
    match run(cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            // `eprintln!` panics on a closed stderr; a diagnostics write error is not our failure.
            let _ = writeln!(std::io::stderr(), "agent: {e}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn run(cmd: Cmd) -> Result<ExitCode, VmmError> {
    match cmd {
        Cmd::Run(args) => run_command(args),
        Cmd::Shell(args) => shell(args),
    }
}

/// `agent run`: open (jailed by default) → attach the probes when asked (`--trace`/`--record`/
/// `--watch`, fail-open) → one exec with the flag-supplied inputs (live-viewed under `--watch`) →
/// write the requested artifacts → finalize the audit record while the sandbox is alive → close →
/// report (raw relay or the `--json` structured result, then the `--trace` trail / `--record` file).
fn run_command(args: RunArgs) -> Result<ExitCode, VmmError> {
    let mut limits = Limits::default();
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
    // Read the local `--put` files *before* the (jailed-by-default) boot: a bad path is a cheap stat
    // failure, so validate it up front rather than paying a full boot + teardown only to fail on it.
    let files_in = read_put_files(&args.put)?;
    let mut config = BootConfig::from_env().with_limits(limits);
    config.enable_network = args.net;
    let sandbox = open(config, args.unjailed)?;
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

    // The audit surface, only when a flag asked for it (a plain `agent run` pays nothing): load the
    // shared probes and bind them to this sandbox by the plain values it exposes — the launch
    // sequence the probes-loader documents, composed here in the caller. Fail-open throughout.
    let observing = args.trace || args.record.is_some() || args.watch;
    let probes = observing.then(|| {
        audit::Observability::load().attach(sandbox.vmm_pid(), sandbox.netns(), sandbox.tap_name())
    });

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
        // The structured run result, one JSON object on stdout — the machine-readable form of the
        // pipe-clean convention (stderr already carries the logs). Byte streams are lossy UTF-8
        // here; exact bytes ride the artifact files, which are on disk by now.
        let structured = serde_json::json!({
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
        });
        let _ = writeln!(std::io::stdout(), "{structured}");
    } else {
        // Relay the guest's output on our own stdout/stderr — the whole point of `exec`. Ignore
        // write errors (a closed pipe is not our failure); the guest exit code is what we return.
        let _ = std::io::stdout().write_all(&result.stdout);
        let _ = std::io::stderr().write_all(&result.stderr);
    }
    if let Some(record) = record {
        if args.trace {
            // The human-readable audit trail, after the guest's own output: a requested run
            // result, so it belongs on stdout like the rest (never mixed with `--json` — clap
            // makes the two conflict; machine consumers take `--record`).
            let _ = writeln!(std::io::stdout(), "\n{}", trace::render(&record).trim_end());
        }
        if let Some(path) = &args.record {
            // The deterministic JSON record — the machine surface, one line, byte-stable.
            std::fs::write(path, record.to_json() + "\n")
                .map_err(|e| VmmError::Artifact(format!("--record {}: {e}", path.display())))?;
            tracing::info!(path = %path.display(), "wrote audit record");
        }
    }
    Ok(ExitCode::from(u8::try_from(result.exit_code).unwrap_or(1)))
}

/// `agent shell`: one sandbox held open, one `sh -c` exec per input line — a stateful session
/// (every exec shares the guest's session working directory, so files persist across lines;
/// process state like `cd` and shell variables does not). The prompt and diagnostics go to stderr,
/// command output to stdout, so a piped script of lines stays clean.
fn shell(args: ShellArgs) -> Result<ExitCode, VmmError> {
    let sandbox = open(
        BootConfig::from_env().with_limits(Limits::default()),
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
            // line; the session survives it. Infra/transport means the VM itself is gone — end the
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

/// Open the sandbox jailed by default, unjailed on the explicit flag — the CLI face of the
/// library's differently-named constructors.
fn open(config: BootConfig, unjailed: bool) -> Result<Sandbox, VmmError> {
    if unjailed {
        Sandbox::open_unjailed(config)
    } else {
        Sandbox::open(config)
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
        // Deny-by-default: the guest doesn't get to choose what lands on the host — only a name the
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
/// component. `symlink_metadata` is `lstat` (no traversal), so a pre-existing symlinked directory —
/// or a symlinked final name — is rejected rather than written through, closing the
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
/// regardless — reading it all first would let `cat 10GB.bin | agent run …` balloon host RAM before
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
    use super::{parse_env_pair, write_artifacts_in};
    use std::path::{Path, PathBuf};

    /// A scratch dir removed on drop, so a panicking assertion can't leak it. Unique per (pid, tag,
    /// counter) so parallel tests don't collide — the artifact tests write real files.
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
        // written through it — the string check can't see the on-disk symlink, `confined_dest` can.
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
