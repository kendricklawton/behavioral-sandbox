//! The `agent-guest` binary: listen for connections and [`serve`](agent_guest::serve) one command
//! each.
//!
//! **Transport today: a unix socket.** In a real guest the agent will listen on **vsock** — but the
//! host-side vsock wiring and the VMM device config land together in P2.3, so this build listens on
//! a unix socket, which makes the whole exec path runnable and testable on the host with no VM. The
//! listen address is `unix:<path>` (via argv or `AGENT_GUEST_LISTEN`); `vsock:<port>` is reserved
//! for P2.3 and rejected clearly until then.
//!
//! `tracing` goes to stderr; the agent writes nothing to stdout (the guest's stdout is the serial
//! console). One connection = one command, so the loop just accepts, serves, logs, and continues.
#![forbid(unsafe_code)]

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

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
        eprintln!("usage: agent-guest unix:<path>   (or set AGENT_GUEST_LISTEN)");
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

/// Bind the listener named by `spec` and serve connections until killed.
fn run(spec: &str) -> Result<(), String> {
    let path = parse_listen(spec)?;

    // A stale socket file (from a previous run) would make `bind` fail with EADDRINUSE; the path is
    // ours, so clear it first — the same "own your scratch path" discipline as the VMM driver.
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {path}: {e}"))?;
    tracing::info!(transport = "unix", %path, "guest agent listening");

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // Refuse to serve a connection we can't bound — the no-hang guarantee depends on
                // the deadline (see `agent_guest::serve`).
                if let Err(e) = set_deadlines(&stream) {
                    tracing::warn!("skipping connection: cannot set deadlines: {e}");
                    continue;
                }
                // `serve` emits its own `exec` span with the command + exit; only failures need a
                // line here.
                if let Err(e) = agent_guest::serve(stream) {
                    tracing::warn!("connection failed: {e}");
                }
            }
            Err(e) => tracing::warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Parse a `unix:<path>` listen spec into its socket path (or a clear error). Pure, so it's unit-
/// testable without binding anything.
fn parse_listen(spec: &str) -> Result<&str, String> {
    match spec.split_once(':') {
        Some(("unix", path)) if !path.is_empty() => Ok(path),
        Some(("unix", _)) => Err("empty unix socket path (want unix:<path>)".to_string()),
        Some(("vsock", _)) => {
            Err("vsock transport lands in P2.3; use unix:<path> for now".to_string())
        }
        _ => Err(format!(
            "unrecognized listen address {spec:?} (want unix:<path>)"
        )),
    }
}

/// Set the read/write deadline on a freshly accepted connection.
fn set_deadlines(stream: &UnixStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
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
    use super::parse_listen;

    #[test]
    fn parses_unix_path() {
        assert_eq!(parse_listen("unix:/tmp/a.sock"), Ok("/tmp/a.sock"));
        // A path may itself contain a colon; only the first `:` is the scheme separator.
        assert_eq!(parse_listen("unix:/tmp/a:b"), Ok("/tmp/a:b"));
    }

    #[test]
    fn rejects_empty_path_vsock_and_garbage() {
        assert!(parse_listen("unix:").is_err());
        assert!(parse_listen("vsock:5").is_err());
        assert!(parse_listen("/tmp/a.sock").is_err()); // no scheme
        assert!(parse_listen("tcp:1.2.3.4:9").is_err());
    }
}
