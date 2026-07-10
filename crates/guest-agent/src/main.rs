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

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("AGENT_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

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
    let path = match spec.split_once(':') {
        Some(("unix", path)) => path,
        Some(("vsock", _)) => {
            return Err("vsock transport lands in P2.3; use unix:<path> for now".to_string());
        }
        _ => {
            return Err(format!(
                "unrecognized listen address {spec:?} (want unix:<path>)"
            ))
        }
    };

    // A stale socket file (from a previous run) would make `bind` fail with EADDRINUSE; the path is
    // ours, so clear it first — the same "own your scratch path" discipline as the VMM driver.
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {path}: {e}"))?;
    tracing::info!(transport = "unix", %path, "guest agent listening");

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => match agent_guest::serve(stream) {
                Ok(code) => tracing::info!(exit_code = code, "command finished"),
                Err(e) => tracing::warn!("connection failed: {e}"),
            },
            Err(e) => tracing::warn!("accept failed: {e}"),
        }
    }
    Ok(())
}
