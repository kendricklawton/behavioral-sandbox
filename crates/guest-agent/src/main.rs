//! The `guest-agent` binary: listens for connections and serves one command each.
//!
//! - **Two transports.** In a real guest the agent listens on **vsock** (`vsock:<port>`), the channel
//!   the host reaches through Firecracker's vsock socket. For host-side development it also listens on
//!   a **unix socket** (`unix:<path>`), which makes the whole exec path runnable with no VM. Only the
//!   listener differs, since `serve` takes any `Read`+`Write`.
//! - **Streams.** `tracing` goes to stderr. Exactly one line goes to **stdout**, the readiness
//!   sentinel ([`GUEST_READY_MARKER`](bsx_channel::GUEST_READY_MARKER)) emitted once the vsock
//!   listener is bound, because the guest's stdout is the serial console the host scans.
//! - **One session per process.** Every connection serves from the same working directory
//!   ([`session_dir`]), so repeated execs against one VM compose into a **stateful session**.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use vsock::{VMADDR_CID_ANY, VsockListener};

use bsx_guest_agent::serve_session;

/// Read/write deadline on each served connection: with one set, a dead-or-stalled host surfaces as
/// a typed timeout in `serve` instead of hanging the agent. Generous, because a real host reads
/// continuously and anything this slow is a broken peer.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Exit code for an operational failure (bad usage, a bind/serve error): conventional "2", named so
/// the intent is legible at the `ExitCode::from` sites.
const EXIT_OPERATIONAL: u8 = 2;

/// The listen-spec scheme tokens, shared by the parser and the readiness announcement so the
/// `vsock:<port>` the host scans for is one definition. The vsock one comes from [`bsx_channel`]
/// because the rootfs build writes it into the guest's init line too; `unix:` is host-side dev
/// transport only, so it stays local.
use bsx_channel::VSOCK_SCHEME;
const UNIX_SCHEME: &str = "unix";

fn main() -> ExitCode {
    init_tracing();

    let spec = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("BSX_GUEST_LISTEN").ok());
    let Some(spec) = spec else {
        eprintln!("usage: guest-agent <vsock:<port>|unix:<path>>   (or set BSX_GUEST_LISTEN)");
        return ExitCode::from(EXIT_OPERATIONAL);
    };

    match run(&spec) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// Where to listen: the in-VM `vsock:<port>` or a host-dev `unix:<path>`.
#[derive(Debug, PartialEq, Eq)]
enum Listen<'a> {
    Vsock(u32),
    Unix(&'a str),
}

/// Binds the listener named by `spec` and serves connections until killed.
fn run(spec: &str) -> Result<(), String> {
    match parse_listen(spec)? {
        Listen::Vsock(port) => run_vsock(port),
        Listen::Unix(path) => run_unix(path),
    }
}

/// Serves connections from a bound `AF_VSOCK` listener, the in-VM transport. Announces readiness on the
/// console *after* the bind, so the host never dials before we're accepting.
fn run_vsock(port: u32) -> Result<(), String> {
    // Serving vsock is the one state that proves this process is inside a guest, so this is
    // where the guest-only setup belongs: without it, every session directory this agent writes
    // under `/tmp` goes through the rw root virtiofs into the shared image tree on the host and
    // survives the VM (found as a pile of `bsx-session-*` dirs in the built image). A tmpfs over
    // `/tmp` keeps session scratch in guest RAM, bounded by the VM's own memory cap. Best-effort:
    // a guest that refuses the mount still serves, it just scribbles, which `build-rootfs
    // --verify` reports as drift.
    if let Err(e) = rustix::mount::mount(
        "tmpfs",
        "/tmp",
        "tmpfs",
        rustix::mount::MountFlags::empty(),
        None::<&std::ffi::CStr>,
    ) {
        tracing::warn!("cannot mount a tmpfs over /tmp ({e}); session scratch will hit the root");
    }
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)
        .map_err(|e| format!("bind vsock port {port}: {e}"))?;
    tracing::info!(transport = "vsock", port, "guest agent listening");
    announce_ready(port);

    serve_incoming(listener.incoming(), |s| {
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))
    });
    Ok(())
}

/// Serves connections from a unix socket, the host-side dev and test transport.
fn run_unix(path: &str) -> Result<(), String> {
    // A stale socket file makes `bind` fail with EADDRINUSE, and the path is ours to own.
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {path}: {e}"))?;
    tracing::info!(transport = "unix", %path, "guest agent listening");

    serve_incoming(listener.incoming(), |s| {
        s.set_read_timeout(Some(IO_TIMEOUT))?;
        s.set_write_timeout(Some(IO_TIMEOUT))
    });
    Ok(())
}

/// The one accept loop for both transports: serves each accepted connection, refusing any whose
/// read/write deadline cannot be set, because `serve`'s no-hang property rests on that deadline.
/// The deadline setter comes from the caller, since the two stream types share no trait.
fn serve_incoming<S, E>(
    incoming: impl Iterator<Item = Result<S, E>>,
    set_deadlines: impl Fn(&S) -> std::io::Result<()>,
) where
    S: bsx_guest_agent::SplitStream + 'static,
    E: std::fmt::Display,
{
    for conn in incoming {
        match conn {
            Ok(stream) => match set_deadlines(&stream) {
                Ok(()) => serve_one(stream),
                Err(e) => tracing::warn!("skipping connection: cannot set deadlines: {e}"),
            },
            Err(e) => tracing::warn!("accept failed: {e}"),
        }
    }
}

/// The one working directory every connection this process serves runs in, which is what makes a
/// sequence of execs against one agent a **stateful session**. One agent process per VM, so the VM
/// *is* the session.
///
/// The pid in the name is for the host-side `unix:` dev transport, where several agent processes may
/// share one `/tmp`. A snapshot clone keeps its pid, so the path is stable across restore.
fn session_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("bsx-session-{}", std::process::id()))
}

/// Serves one connection, logging rather than propagating a failure so one bad peer never ends the
/// loop. `serve_session` emits its own `exec` span, so only failures need a line here.
fn serve_one<S: bsx_guest_agent::SplitStream + 'static>(stream: S) {
    // One thread per connection, so a wedged session cannot take the listener down: the whole-tree
    // reap needs cgroup v2, so on an off-spec guest a command that double-forks a daemon holds the
    // output pipes open and its `pump` never sees EOF. Served inline, that one stuck exec would
    // block `accept`. The session dir stays shared, since it is the session's state.
    let spawned = std::thread::Builder::new()
        .name("bsx-session".to_string())
        .spawn(move || {
            match serve_session(stream, &session_dir()) {
                Ok(_) => {}
                // A peer that hands back nothing after the handshake is a readiness probe, not a
                // failure: reporting it as one would put a warning on the console of every
                // healthy `bsx up`.
                Err(e) if e.is_disconnect() => tracing::debug!("connection closed: {e}"),
                Err(e) => tracing::warn!("connection failed: {e}"),
            }
        });
    if let Err(e) = spawned {
        // The spawn took the stream with it, so this connection closes and the host surfaces its
        // typed dial error rather than the accept loop blocking.
        tracing::warn!("cannot spawn a session thread ({e}); dropping the connection");
    }
}

/// Prints the readiness sentinel to stdout (the serial console) and flushes, so the host's console
/// scan fires once the vsock listener is accepting. `writeln!` rather than `println!`, which panics
/// on a closed console.
fn announce_ready(port: u32) {
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "{} {VSOCK_SCHEME}:{port}",
        bsx_channel::GUEST_READY_MARKER
    );
    let _ = out.flush();
}

/// Parses a `vsock:<port>` or `unix:<path>` listen spec. Pure, so it is unit-testable without binding
/// anything.
fn parse_listen(spec: &str) -> Result<Listen<'_>, String> {
    match spec.split_once(':') {
        Some((VSOCK_SCHEME, port)) => port
            .parse::<u32>()
            .map(Listen::Vsock)
            .map_err(|_| format!("invalid vsock port {port:?} (want {VSOCK_SCHEME}:<port>)")),
        Some((UNIX_SCHEME, path)) if !path.is_empty() => Ok(Listen::Unix(path)),
        Some((UNIX_SCHEME, _)) => Err("empty unix socket path (want unix:<path>)".to_string()),
        _ => Err(format!(
            "unrecognized listen address {spec:?} (want {VSOCK_SCHEME}:<port> or {UNIX_SCHEME}:<path>)"
        )),
    }
}

/// stderr logging, filter from `BSX_LOG` else `info`. `info` rather than the CLI's `warn`, because
/// the agent's per-command `exec` span is the guest's operational trace, captured off the serial
/// console. `try_init` plus a fallback, so a bad filter or a double-init never panics the run.
fn init_tracing() {
    let filter = std::env::var("BSX_LOG").unwrap_or_else(|_| "info".to_string());
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
    use super::{Listen, parse_listen};

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
        // Only the first `:` is the scheme separator, so a path may contain one.
        assert_eq!(parse_listen("unix:/tmp/a:b"), Ok(Listen::Unix("/tmp/a:b")));
    }

    #[test]
    fn rejects_empty_unix_and_garbage() {
        assert!(parse_listen("unix:").is_err());
        assert!(parse_listen("/tmp/a.sock").is_err()); // no scheme
        assert!(parse_listen("tcp:1.2.3.4:9").is_err());
    }
}
