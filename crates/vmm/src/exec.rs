//! The host side of the guest-agent exec channel: dial Firecracker's vsock Unix socket, speak its
//! `CONNECT <port>` handshake, and drive one bounded exec (output cap, guest budget, host wall
//! deadline) over the `agent-channel` protocol. Every bound exists so a hostile guest is a typed
//! error, never a host hang or leak.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use agent_channel::{ClientConnection, Request, Response};

use crate::{RunResult, VmmError};

/// Deadline for the vsock connect + `CONNECT` handshake, and the read/write timeout the exec
/// connection carries — so a dead-or-stalled guest is a typed timeout, never a host hang
/// (decision 002: liveness is the transport's job).
pub(crate) const VSOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for a [`RunningVm::probe_agent`] health check. Much shorter than [`VSOCK_TIMEOUT`]: an
/// idle, healthy agent accepts immediately, and the pool's take-path shouldn't stall long on a dead
/// clone before discarding it and serving the next.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Cap on the stdout+stderr+artifacts the host buffers for one `exec`. Each frame is already
/// `≤ MAX_PAYLOAD`, but a guest can send *unboundedly many* frames (`yes`), so the aggregate is
/// capped too — a hostile guest never grows host memory without bound. (A command's *runtime* is a
/// separate axis, bounded by the exec wall-timeout below.) A fixed default for now — it joins the
/// hoster-tunable per-run resource policy (cpu/mem/wall/output) once that shape is decided.
pub(crate) const MAX_EXEC_OUTPUT: usize = 16 << 20; // 16 MiB

/// Per-frame overhead charged toward the output cap, so a flood of empty (or all-`path`, no-`data`)
/// frames can't spin the collect loop or grow the artifact list without advancing the cap.
const FRAME_FLOOR: usize = 64;

/// Default wall-clock budget for one command, sent to the guest agent, which kills the command past
/// it. A fixed default for now — it joins the hoster-tunable per-run resource policy later. (The
/// guest clamps a host-sent budget to its own 1 h ceiling. When the budget becomes a policy knob,
/// both the socket idle timeout *and* the host deadline must be derived from the *requested* value —
/// `budget + EXEC_KILL_SLACK` — not from this const, or a long quiet command is cut off early.)
pub(crate) const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// Slack past a command's own budget before the *host* gives up on the exec connection: the margin
/// for the guest agent to notice its deadline, SIGKILL the command, and get its `TimedOut` frame
/// back. The host's total patience is `budget + EXEC_KILL_SLACK`, used both as the exec socket's
/// per-read idle timeout (so a legitimately long-but-quiet command isn't cut off by the transport)
/// and as the wall-clock deadline on the collect loop (so a silent-or-hostile guest that never
/// self-reports can't park `exec` forever — decision 002: liveness is the transport's job, not the
/// guest's). Ordered so the guest's cooperative `TimedOut` (fired at `budget`) always beats the host
/// deadline for a legitimate timeout; the host fires only when the guest fails to report.
pub(crate) const EXEC_KILL_SLACK: Duration = Duration::from_secs(5);

/// Dial Firecracker's vsock socket, speak the `CONNECT <port>` handshake, and complete the channel
/// handshake — the whole host side of reaching the guest agent. Factored out of
/// [`RunningVm::connect_agent`] so it can be tested against a fake vsock socket without a VM.
pub(crate) fn connect_agent_at(
    uds: &Path,
    port: u32,
    timeout: Duration,
) -> Result<ClientConnection<UnixStream>, VmmError> {
    let stream = vsock_connect(uds, port, timeout)?;
    ClientConnection::connect(stream)
        .map_err(|e| VmmError::Vmm(format!("channel handshake over vsock: {e}")))
}

/// Drive one exec over an established [`ClientConnection`]: send the request, then aggregate the
/// response stream into a [`RunResult`]. Bounded on two axes so a flooding *or* dribbling guest can't
/// hurt the host: `max_output` caps buffered bytes, and `wall` is the host's own wall-clock deadline
/// on the collect loop (`timeout` is the guest's command budget; `wall` = `timeout` + kill slack).
/// A guest that keeps the per-read idle timer alive by dribbling tiny frames — never sending its
/// terminal `Exit`/`TimedOut` — trips `wall` and yields [`VmmError::ExecUnresponsive`], rather than
/// parking the caller indefinitely. Factored out of [`RunningVm::exec`] so it can be tested without a VM.
/// The host-enforced bounds on one exec, bundled so they travel together (and to keep `run_exec`
/// under the argument-count limit). Seeds the hoster-tunable per-run resource policy the timeout
/// constants above anticipate.
pub(crate) struct ExecBounds {
    /// The guest's command wall-clock budget, sent to the agent as `timeout_ms`; the agent kills the
    /// command past it and reports `TimedOut`.
    pub(crate) timeout: Duration,
    /// The *host's* own deadline on the collect loop — `timeout` + kill slack — so a guest that never
    /// reports the command's end can't park `exec` forever. Trips [`VmmError::ExecUnresponsive`].
    pub(crate) wall: Duration,
    /// Aggregate cap on buffered stdout+stderr+artifacts, so a flooding guest can't grow host memory.
    pub(crate) max_output: usize,
}

pub(crate) fn run_exec<S: Read + Write>(
    conn: &mut ClientConnection<S>,
    argv: &[String],
    stdin: &[u8],
    files_in: &[(String, Vec<u8>)],
    artifacts: &[String],
    bounds: ExecBounds,
) -> Result<RunResult, VmmError> {
    // Host-side trace of the exec (the guest's own `exec` span goes to the serial console, not the
    // operator's stderr), keyed by argv so `agent run` failures are diagnosable host-side.
    let span = tracing::info_span!("exec", argv = ?argv);
    let _span = span.enter();
    let started = Instant::now();
    // The host's own deadline, independent of the socket's per-read idle timeout. A `Duration::MAX`
    // "no limit" must stay a *bounded* wait, not an `Instant + Duration` overflow panic — clamp to a
    // day (mirrors the boot deadline).
    let deadline = started
        .checked_add(bounds.wall)
        .unwrap_or_else(|| started + Duration::from_secs(86_400));

    // Inject input files first, then the terminal exec request.
    // `?` on channel calls yields `VmmError::Channel(..)`, preserving the `ChannelError` source.
    for (path, data) in files_in {
        conn.send_request(&Request::PutFile {
            path: path.clone(),
            data: data.clone(),
        })?;
    }
    conn.send_request(&Request::Exec {
        argv: argv.to_vec(),
        stdin: stdin.to_vec(),
        artifacts: artifacts.to_vec(),
        timeout_ms: u32::try_from(bounds.timeout.as_millis()).unwrap_or(u32::MAX),
    })?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    // Bound stdout + stderr + artifact *names and bytes* together. `FRAME_FLOOR` is charged per
    // frame so a flood of empty frames (or `File` frames whose budget is spent on `path`, not
    // `data`) can't spin the loop or grow `files` without advancing the cap.
    let mut captured = 0usize;
    loop {
        // The host's own wall-clock deadline, checked *before* each blocking read. The socket's
        // per-read idle timeout is reset by every frame, so a guest that dribbles tiny well-formed
        // frames — never sending its terminal `Exit`/`TimedOut` — would otherwise keep this loop
        // alive indefinitely under the output cap. `wall` outlasts the guest's own `TimedOut`, so a
        // legitimate timeout still arrives as `ExecTimeout`; this only fires for a non-reporting
        // guest. Worst case the loop is parked in `recv_response` when the deadline passes, so the
        // real bound is `deadline + one idle period` — bounded, not a hang.
        if Instant::now() >= deadline {
            return Err(VmmError::ExecUnresponsive { limit: bounds.wall });
        }
        match conn.recv_response()? {
            Response::Stdout(b) => {
                captured += b.len() + FRAME_FLOOR;
                stdout.extend_from_slice(&b);
            }
            Response::Stderr(b) => {
                captured += b.len() + FRAME_FLOOR;
                stderr.extend_from_slice(&b);
            }
            Response::File { path, data } => {
                captured += path.len() + data.len() + FRAME_FLOOR;
                files.push((path, data));
            }
            Response::Exit { code } => {
                tracing::info!(
                    exit_code = code,
                    stdout_bytes = stdout.len(),
                    stderr_bytes = stderr.len(),
                    artifacts = files.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "guest command finished"
                );
                return Ok(RunResult {
                    exit_code: code,
                    stdout,
                    stderr,
                    files,
                });
            }
            // The guest killed the command at its wall-clock deadline. Distinct typed error, and
            // logged host-side (the guest's own log goes to the serial console, not the operator).
            // NOTE: the partial stdout/stderr streamed before the kill is discarded here; carrying
            // it on the error (or a `timed_out` RunResult) is a future enhancement.
            Response::TimedOut { elapsed_ms } => {
                tracing::warn!(
                    limit_ms = bounds.timeout.as_millis() as u64,
                    elapsed_ms,
                    "guest command timed out"
                );
                return Err(VmmError::ExecTimeout {
                    limit: bounds.timeout,
                });
            }
            // A guest-side fault on a healthy channel — distinct from a transport failure.
            Response::Error(msg) => return Err(VmmError::GuestExec(msg)),
            _ => {
                return Err(VmmError::Vmm(
                    "unexpected response frame from guest agent".into(),
                ))
            }
        }
        if captured > bounds.max_output {
            return Err(VmmError::OutputCap {
                limit: bounds.max_output,
            });
        }
    }
}

/// Connect to `uds` and perform Firecracker's host-initiated vsock handshake: send
/// `CONNECT <port>\n`, expect `OK <host_port>\n`. Returns the stream positioned right after the
/// ack, with read/write deadlines set.
fn vsock_connect(uds: &Path, port: u32, timeout: Duration) -> Result<UnixStream, VmmError> {
    // `connect` is the one step without a deadline (std has no `UnixStream::connect_timeout`), but
    // the peer is Firecracker's own vsock socket — created pre-`InstanceStart` and accepting
    // promptly — so it returns or refuses at once; every step after this is deadline-bounded.
    // ECONNREFUSED means the socket file exists but nothing accepts: a dead VMM's stale socket (a
    // pooled clone that crashed) — the retryable/discard signal, not broken infra.
    let mut stream = UnixStream::connect(uds).map_err(|e| {
        let detail = format!("connect vsock socket {}: {e}", uds.display());
        if e.kind() == std::io::ErrorKind::ConnectionRefused {
            VmmError::GuestUnavailable(detail)
        } else {
            VmmError::Vmm(detail)
        }
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| VmmError::Vmm(format!("set vsock timeouts: {e}")))?;

    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .map_err(|e| VmmError::Vmm(format!("vsock CONNECT {port}: {e}")))?;
    read_connect_ack(&mut stream, port)?;
    Ok(stream)
}

/// Read Firecracker's `OK <port>\n` ack **one byte at a time**: the guest agent sends its channel
/// handshake immediately after the connection is established, so a buffered read here would swallow
/// those bytes and desync the protocol.
fn read_connect_ack(stream: &mut UnixStream, port: u32) -> Result<(), VmmError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                // Firecracker closes the connection with no ack when nothing is listening on the
                // guest port — the canonical "agent not up yet / not anymore" signal, typed so a
                // retry/pool caller can branch on it (P2.7's deferred variant, landed with the pool).
                return Err(VmmError::GuestUnavailable(format!(
                    "vsock CONNECT {port}: peer closed before ack (is the guest agent listening?)"
                )));
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > 64 {
                    return Err(VmmError::Vmm(format!(
                        "vsock CONNECT {port}: ack line too long"
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(VmmError::Timeout(format!(
                    "vsock CONNECT {port}: no ack before deadline"
                )))
            }
            Err(e) => return Err(VmmError::Vmm(format!("vsock CONNECT {port}: {e}"))),
        }
    }
    let ack = String::from_utf8_lossy(&line);
    if ack.starts_with("OK ") {
        Ok(())
    } else {
        // A well-formed non-OK ack is Firecracker refusing the port — same "nothing listening"
        // semantics as the peer-close above, so the same retryable variant.
        Err(VmmError::GuestUnavailable(format!(
            "vsock CONNECT {port} refused: {ack:?} (is the guest agent listening?)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TestDir;
    use crate::vm::VSOCK_UDS;
    use agent_channel::AGENT_VSOCK_PORT;
    use std::path::PathBuf;

    /// Stand up a fake Firecracker vsock socket: accept, answer the `CONNECT <port>` handshake, then
    /// hand the same stream to the *real* guest agent. Lets us exercise the entire host exec path
    /// (vsock connect + `CONNECT` ack + channel handshake + exec round trip) with no VM.
    fn fake_vsock_agent(tag: &str) -> (TestDir, PathBuf, std::thread::JoinHandle<()>) {
        use std::os::unix::net::UnixListener;
        let dir = TestDir::new(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Read `CONNECT <port>\n` one byte at a time — mustn't over-read the client handshake.
            let mut b = [0u8; 1];
            loop {
                stream.read_exact(&mut b).expect("read CONNECT");
                if b[0] == b'\n' {
                    break;
                }
            }
            stream.write_all(b"OK 10000\n").expect("write ack");
            let _ = agent_guest::serve(stream);
        });
        (dir, uds, handle)
    }

    #[test]
    fn exec_over_fake_vsock_runs_a_command() {
        // P2.8 happy path: `exec("echo hi")` → `hi`, exit 0 — through the *real* agent (only the
        // Firecracker vsock UDS is faked).
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-echo");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["echo".into(), "hi".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("exec");
        assert_eq!(result.stdout, b"hi\n");
        assert!(result.stderr.is_empty());
        assert_eq!(result.exit_code, 0);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_over_fake_vsock_feeds_stdin() {
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-stdin");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["cat".into()],
            b"from the host\n",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("exec");
        assert_eq!(result.stdout, b"from the host\n");
        assert_eq!(result.exit_code, 0);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_injects_files_and_returns_artifacts() {
        // Put a file in, run a command that reads it and writes an output file, pull the artifact
        // back. Exercises PutFile + working-dir cwd + artifact return end to end against the agent.
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-files");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &[
                "sh".into(),
                "-c".into(),
                "mkdir -p out && tr a-z A-Z < in.txt > out/up.txt".into(),
            ],
            b"",
            &[("in.txt".into(), b"hello\n".to_vec())],
            &["out/up.txt".into(), "missing.txt".into()],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("exec");
        assert_eq!(result.exit_code, 0);
        // The one artifact that exists comes back; the missing one is simply omitted.
        assert_eq!(
            result.files,
            vec![("out/up.txt".to_string(), b"HELLO\n".to_vec())]
        );
        server.join().expect("server thread");
    }

    #[test]
    fn exec_crashing_command_is_a_typed_error() {
        // P2.8: a command the guest can't run ("crashing" in the agent-fault sense) comes back as a
        // terminal `Error` frame → the typed `VmmError::GuestExec`, end to end through the real
        // agent (which reports the spawn failure), not via a hand-crafted `Error` response.
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-crash");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["definitely-not-a-real-binary-zzz".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::GuestExec(_)), "got {err:?}");
        server.join().expect("server thread");
    }

    #[test]
    fn exec_signal_death_is_a_faithful_result_not_an_error() {
        // The load-bearing taxonomy semantic: a command that *runs and crashes* (here SIGKILL via
        // `kill -9 $$`) is NOT a `VmmError` — the agent maps signal death to `128+sig` and the host
        // returns a faithful `RunResult{exit_code: 137}`. This pins the *host*-side mapping in
        // `run_exec`; the guest-agent-layer version lives in crates/guest-agent/tests/exec.rs.
        let (_dir, uds, server) = fake_vsock_agent("agent-vsock-signal");
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["sh".into(), "-c".into(), "kill -9 $$".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("signal death is a result, not an error");
        assert_eq!(result.exit_code, 137, "128 + SIGKILL(9)");
        server.join().expect("server thread");
    }

    /// A fake vsock peer that answers `CONNECT`, does the channel handshake, then hands the
    /// [`ServerConnection`](agent_channel::ServerConnection) to `handler` — so a test can craft the
    /// exact response stream (unlike `fake_vsock_agent`, which runs the real agent).
    fn fake_vsock_server<F>(
        tag: &str,
        handler: F,
    ) -> (TestDir, PathBuf, std::thread::JoinHandle<()>)
    where
        F: FnOnce(agent_channel::ServerConnection<std::os::unix::net::UnixStream>) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let dir = TestDir::new(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut b = [0u8; 1];
            loop {
                stream.read_exact(&mut b).expect("read CONNECT");
                if b[0] == b'\n' {
                    break;
                }
            }
            stream.write_all(b"OK 10000\n").expect("write ack");
            let conn = agent_channel::ServerConnection::accept(stream).expect("server handshake");
            handler(conn);
        });
        (dir, uds, handle)
    }

    #[test]
    fn exec_surfaces_a_guest_error_as_typed_error() {
        // The agent reports a spawn failure with a terminal `Error` frame → `VmmError::GuestExec`,
        // distinct from a transport fault.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-err", |mut conn| {
            let _ = conn.recv_request();
            let _ = conn.send_response(&Response::Error("no such binary".into()));
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["nope".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::GuestExec(_)), "got {err:?}");
        server.join().expect("server thread");
    }

    #[test]
    fn exec_channel_drop_mid_exec_is_a_typed_channel_error() {
        // The channel/transport bucket end to end: a guest that accepts the request then drops the
        // connection makes `recv_response` hit EOF → `ChannelError::Io(UnexpectedEof)` →
        // `VmmError::Channel`. Every *other* channel-ish fault is at connect time (→ `Vmm`), so this
        // is the only test that exercises the steady-state `Channel` arm and the `From<ChannelError>`
        // conversion at the vmm layer.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-drop", |mut conn| {
            let _ = conn.recv_request();
            drop(conn); // no response frames — the host's next read sees a clean EOF
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["echo".into(), "hi".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::Channel(ref e) if e.is_disconnect()),
            "got {err:?}"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn exec_output_cap_is_enforced() {
        // A guest that floods stdout must trip the cap as a typed error, not grow host memory.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-flood", |mut conn| {
            let _ = conn.recv_request();
            // Keep sending until the host drops the connection (cap exceeded → our writes error).
            while conn
                .send_response(&Response::Stdout(vec![b'x'; 500]))
                .is_ok()
            {}
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["flood".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: 1000,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::OutputCap { limit: 1000 }),
            "got {err:?}"
        );
        // Close the connection so the flooding server's next write errors and its loop ends.
        drop(conn);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_maps_guest_timeout_to_typed_timeout() {
        // The agent's terminal `TimedOut` (command killed at its deadline) becomes the distinct
        // VmmError::ExecTimeout — not conflated with a channel/transport timeout.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-timeout", |mut conn| {
            let _ = conn.recv_request();
            let _ = conn.send_response(&Response::TimedOut { elapsed_ms: 1000 });
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["sleep".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(1),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::ExecTimeout { .. }), "got {err:?}");
        server.join().expect("server thread");
    }

    #[test]
    fn output_cap_counts_file_path_bytes_not_just_data() {
        // Regression: a guest flooding File frames whose budget is spent on `path` (empty `data`)
        // must still trip the cap — path bytes and a per-frame floor count toward it.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-pathflood", |mut conn| {
            let _ = conn.recv_request();
            let big_path = "p".repeat(4096);
            while conn
                .send_response(&Response::File {
                    path: big_path.clone(),
                    data: Vec::new(),
                })
                .is_ok()
            {}
        });
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["flood".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: 10_000,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VmmError::OutputCap { .. }), "got {err:?}");
        drop(conn);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_dribbling_guest_trips_the_host_wall_deadline() {
        // A guest that keeps the per-read idle timer alive with tiny well-formed frames but never
        // sends its terminal Exit/TimedOut would, without a host wall deadline, park exec forever
        // under the output cap. The host's own `wall` must give up with `ExecUnresponsive`, fast.
        let (_dir, uds, server) = fake_vsock_server("agent-vsock-dribble", |mut conn| {
            let _ = conn.recv_request();
            // Dribble every 50 ms — well under the 200 ms idle timeout, so the idle timer never
            // fires; only the host's wall deadline can end this.
            while conn.send_response(&Response::Stdout(vec![b'x'; 8])).is_ok() {
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        // Idle (200 ms) > dribble interval (50 ms), so the socket idle timeout can't fire; wall
        // (150 ms) is the thing under test. All sub-second so the suite stays fast.
        let mut conn =
            connect_agent_at(&uds, AGENT_VSOCK_PORT, Duration::from_millis(200)).expect("connect");
        let started = std::time::Instant::now();
        let err = run_exec(
            &mut conn,
            &["dribble".into()],
            b"",
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_millis(100), // guest budget (the fake server ignores it)
                wall: Duration::from_millis(150),    // host wall deadline — under test
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::ExecUnresponsive { .. }),
            "got {err:?}"
        );
        // Loose upper bound only (never a tight lower bound): it must fail fast, not hang the suite.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should fail fast, took {:?}",
            started.elapsed()
        );
        drop(conn);
        server.join().expect("server thread");
    }

    /// A fake `CONNECT` target: answer nothing but the ack `handler` chooses, so the connect-ack
    /// paths can be tested without the channel layer.
    fn fake_connect_target<F>(
        tag: &str,
        handler: F,
    ) -> (TestDir, PathBuf, std::thread::JoinHandle<()>)
    where
        F: FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let dir = TestDir::new(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut b = [0u8; 1];
            loop {
                if stream.read_exact(&mut b).is_err() || b[0] == b'\n' {
                    break;
                }
            }
            handler(stream);
        });
        (dir, uds, handle)
    }

    #[test]
    fn connect_ack_refused_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-refuse", |mut s| {
            let _ = s.write_all(b"NOPE\n");
        });
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        // "Nothing listening on the guest port" is the retryable GuestUnavailable, not broken infra.
        assert!(
            matches!(err, VmmError::GuestUnavailable(ref m) if m.contains("refused")),
            "got {err:?}"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_peer_close_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-close", drop);
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        // The canonical agent-not-up signal: typed retryable, so a pool can discard-and-retry.
        assert!(
            matches!(err, VmmError::GuestUnavailable(ref m) if m.contains("closed")),
            "got {err:?}"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_too_long_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-long", |mut s| {
            let _ = s.write_all(&[b'x'; 100]); // 100 bytes, no newline
            std::thread::sleep(Duration::from_millis(200)); // keep the stream open past the read
        });
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(m) if m.contains("too long")),
            "wrong error"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_timeout_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("agent-ack-timeout", |s| {
            std::thread::sleep(Duration::from_millis(300)); // never send; outlive the client deadline
            drop(s);
        });
        let err = vsock_connect(&uds, AGENT_VSOCK_PORT, Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, VmmError::Timeout(_)), "got {err:?}");
        server.join().expect("server");
    }
}
