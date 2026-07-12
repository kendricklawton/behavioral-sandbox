//! The `agent-guest` binary: listen for connections and [`serve`](agent_guest::serve) one command
//! each.
//!
//! **Two transports.** In a real guest the agent listens on **vsock** (`vsock:<port>`) — the in-VM
//! channel the host reaches through Firecracker's vsock socket. For host-side development and tests
//! it can also listen on a **unix socket** (`unix:<path>`), which makes the whole exec path runnable
//! with no VM. `serve` is transport-agnostic (any `Read`+`Write`); only the listener differs.
//!
//! `tracing` goes to stderr. The agent writes exactly one line to **stdout** — the readiness
//! sentinel ([`GUEST_READY_MARKER`](agent_channel::GUEST_READY_MARKER)) emitted once its vsock
//! listener is bound — because the guest's stdout is the serial console the host scans to learn the
//! agent is up. One connection = one command, so the loop just accepts, serves, logs, and continues.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use vsock::{VsockListener, VMADDR_CID_ANY};

/// Read/write deadline on each served connection. Liveness is the transport's job: with a deadline
/// set, a dead-or-stalled host surfaces as a typed timeout in `serve` instead of hanging the agent.
/// Generous, because a real host reads continuously — anything this slow is a broken peer.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> ExitCode {
    init_tracing();

    let spec = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("AGENT_GUEST_LISTEN").ok());
    let Some(spec) = spec else {
        eprintln!("usage: agent-guest <vsock:<port>|unix:<path>>   (or set AGENT_GUEST_LISTEN)");
        return ExitCode::from(2);
    };

    match run(&spec) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::from(2)
        }
    }
}

/// Where to listen: the in-VM `vsock:<port>` or a host-dev `unix:<path>`.
#[derive(Debug, PartialEq, Eq)]
enum Listen<'a> {
    Vsock(u32),
    Unix(&'a str),
}

/// Bind the listener named by `spec` and serve connections until killed.
fn run(spec: &str) -> Result<(), String> {
    match parse_listen(spec)? {
        Listen::Vsock(port) => run_vsock(port),
        Listen::Unix(path) => run_unix(path),
    }
}

/// Serve connections from a bound `AF_VSOCK` listener — the in-VM transport. Announces readiness on
/// the console *after* the bind, so the host never dials before we're accepting.
fn run_vsock(port: u32) -> Result<(), String> {
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)
        .map_err(|e| format!("bind vsock port {port}: {e}"))?;
    tracing::info!(transport = "vsock", port, "guest agent listening");
    announce_ready(port);

    for conn in listener.incoming() {
        match conn {
            // Refuse a connection we can't bound — the no-hang guarantee depends on the deadline
            // (see `agent_guest::serve`). `VsockStream`'s setters return `nix::Error`.
            Ok(stream) => match stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
            {
                Ok(()) => serve_one(stream),
                Err(e) => tracing::warn!("skipping connection: cannot set deadlines: {e}"),
            },
            Err(e) => tracing::warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Serve connections from a unix socket — the host-side dev/test transport (no VM).
fn run_unix(path: &str) -> Result<(), String> {
    // A stale socket file (from a previous run) would make `bind` fail with EADDRINUSE; the path is
    // ours, so clear it first — the same "own your scratch path" discipline as the VMM driver.
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {path}: {e}"))?;
    tracing::info!(transport = "unix", %path, "guest agent listening");

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => match set_unix_deadlines(&stream) {
                Ok(()) => serve_one(stream),
                Err(e) => tracing::warn!("skipping connection: cannot set deadlines: {e}"),
            },
            Err(e) => tracing::warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Serve one connection, logging (not propagating) a failure so one bad peer never ends the loop.
/// `serve` emits its own `exec` span with the command + exit; only failures need a line here.
fn serve_one<S: std::io::Read + std::io::Write + Send>(stream: S) {
    if let Err(e) = agent_guest::serve(stream) {
        tracing::warn!("connection failed: {e}");
    }
}

/// Print the readiness sentinel to stdout (the serial console) and flush, so the host's console scan
/// fires exactly once the vsock listener is accepting. See [`agent_channel::GUEST_READY_MARKER`].
/// `writeln!` (not `println!`) so a closed console is ignored, never a panic.
fn announce_ready(port: u32) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{} vsock:{port}", agent_channel::GUEST_READY_MARKER);
    let _ = out.flush();
}

/// Set the read/write deadline on a freshly accepted unix connection.
fn set_unix_deadlines(stream: &UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

/// Parse a `vsock:<port>` or `unix:<path>` listen spec (or a clear error). Pure, so it's unit-
/// testable without binding anything.
fn parse_listen(spec: &str) -> Result<Listen<'_>, String> {
    match spec.split_once(':') {
        Some(("vsock", port)) => port
            .parse::<u32>()
            .map(Listen::Vsock)
            .map_err(|_| format!("invalid vsock port {port:?} (want vsock:<port>)")),
        Some(("unix", path)) if !path.is_empty() => Ok(Listen::Unix(path)),
        Some(("unix", _)) => Err("empty unix socket path (want unix:<path>)".to_string()),
        _ => Err(format!(
            "unrecognized listen address {spec:?} (want vsock:<port> or unix:<path>)"
        )),
    }
}

/// stderr logging, filter from `AGENT_LOG` else `info`. `info` (not the CLI's `warn`) is deliberate:
/// the agent's per-command `exec` span is the guest's operational trace, captured off the serial
/// console. `try_init` + an explicit fallback so a bad filter or a double-init never panics the run.
fn init_tracing() {
    let filter = std::env::var("AGENT_LOG").unwrap_or_else(|_| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_new(&filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::{parse_listen, Listen};

    #[test]
    fn parses_vsock_port() {
        assert_eq!(parse_listen("vsock:1024"), Ok(Listen::Vsock(1024)));
        assert!(parse_listen("vsock:notaport").is_err());
        assert!(parse_listen("vsock:").is_err()); // empty → parse error
    }

    #[test]
    fn parses_unix_path() {
        assert_eq!(
            parse_listen("unix:/tmp/a.sock"),
            Ok(Listen::Unix("/tmp/a.sock"))
        );
        // A path may itself contain a colon; only the first `:` is the scheme separator.
        assert_eq!(parse_listen("unix:/tmp/a:b"), Ok(Listen::Unix("/tmp/a:b")));
    }

    #[test]
    fn rejects_empty_unix_and_garbage() {
        assert!(parse_listen("unix:").is_err());
        assert!(parse_listen("/tmp/a.sock").is_err()); // no scheme
        assert!(parse_listen("tcp:1.2.3.4:9").is_err());
    }
}
