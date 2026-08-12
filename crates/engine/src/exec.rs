//! The host side of the guest-agent exec channel: dial Firecracker's vsock Unix socket, speak its
//! `CONNECT <port>` handshake, and drive one bounded exec (output cap, guest budget, host wall
//! deadline) over the `bsx-channel` protocol. Every bound exists so a hostile guest is a typed
//! error, never a host hang or leak.

use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use bsx_channel::{ChannelError, ClientConnection, Response};

use crate::deadline::DeadlineStream;
use crate::{Artifact, ExecMetrics, RunResult, VmmError};

/// Deadline for the vsock connect + `CONNECT` handshake, and the read/write timeout the exec
/// connection carries, so a dead-or-stalled guest is a typed timeout, never a host hang
/// (liveness is the transport's job).
pub(crate) const VSOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for a [`RunningVm::probe_agent`] health check. Much shorter than [`VSOCK_TIMEOUT`]: an
/// idle, healthy agent accepts immediately, and the pool's take-path shouldn't stall long on a dead
/// clone before discarding it and serving the next.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Default cap on the stdout+stderr+artifacts the host buffers for one `exec`, the
/// [`Limits::output_cap`](crate::Limits::output_cap) default, so a guest sending unboundedly many
/// `≤ MAX_PAYLOAD` frames cannot grow host memory without bound. Per-sandbox: it rides `Limits` →
/// `BootConfig` → `RunningVm`.
pub(crate) const MAX_EXEC_OUTPUT: usize = 16 << 20; // 16 MiB

/// Per-frame overhead charged toward the output cap, so a flood of empty (or all-`path`, no-`data`)
/// frames can't spin the collect loop or grow the artifact list without advancing the cap.
const FRAME_FLOOR: usize = 64;

/// Default wall-clock budget for one command, the [`Limits::wall`](crate::Limits::wall) default, sent
/// to the guest agent, which kills the command past it. The socket idle timeout and the host give-up
/// deadline both derive from the *configured* value (`budget + EXEC_KILL_SLACK`), never from this
/// const, so a raised budget cannot leave a long quiet command cut off by the transport.
pub(crate) const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// Slack past a command's own budget before the *host* gives up: the margin for the guest agent to
/// notice its deadline, SIGKILL the command, and get its `TimedOut` frame back. `budget +
/// EXEC_KILL_SLACK` is both the socket's per-read idle timeout and the collect loop's wall deadline,
/// so a silent-or-hostile guest cannot park `exec` forever. The ordering is what matters: the guest's
/// cooperative `TimedOut` fires at `budget`, so the host deadline fires only when the guest does not.
pub(crate) const EXEC_KILL_SLACK: Duration = Duration::from_secs(5);

/// Cap on the **dial-retry window** in [`connect_agent_at`], short enough that a genuinely dead agent
/// fails in ≤2s rather than burning the caller's full exec wall, long enough to absorb the
/// establishment-time peer closes, which are observed at millisecond scale.
const DIAL_RETRY_CAP: Duration = Duration::from_secs(2);

/// Dial Firecracker's vsock socket, speak the `CONNECT <port>` handshake, and complete the channel
/// handshake, the whole host side of reaching the guest agent. Factored out of
/// [`RunningVm::connect_agent`] so it can be tested against a fake vsock socket without a VM.
///
/// A peer close during establishment (EPIPE writing `CONNECT`, EOF before the ack, EOF in the channel
/// handshake) is retried within `min(timeout, DIAL_RETRY_CAP)`, so one request-scale race does not kill
/// a session; exhaustion returns the last [`VmmError::GuestUnavailable`]. This is symptom-level
/// hardening: the trigger is not pinned down, and the guest kernel queues pending vsock dials, so it is
/// *not* simply the agent being between accepts. Per-attempt deadlines and the returned stream's
/// timeouts stay the caller's full `timeout`, so the worst case is ~`timeout + DIAL_RETRY_CAP`.
pub(crate) fn connect_agent_at(
    uds: &Path,
    port: u32,
    timeout: Duration,
) -> Result<ClientConnection<UnixStream>, VmmError> {
    with_dial_retry(timeout, || connect_agent_once(uds, port, timeout))
}

/// [`connect_agent_at`] returning a connection whose reads and writes are bounded by **one absolute
/// deadline**, `timeout` from the moment the channel handshake starts, rather than by a per-syscall
/// timeout the peer re-arms with every byte.
///
/// This is the exec path's constructor, and the difference is the threat: the plain form's
/// `SO_RCVTIMEO` is reset by each byte that arrives, so a guest dribbling one byte per interval holds
/// the host inside a single `read_exact` for `frame_bytes × timeout`. The deadline is armed after the
/// dial rather than before, so a retried dial does not spend the exec's budget.
pub(crate) fn connect_agent_bounded(
    uds: &Path,
    port: u32,
    timeout: Duration,
) -> Result<ClientConnection<DeadlineStream<UnixStream>>, VmmError> {
    with_dial_retry(timeout, || {
        let stream = vsock_connect(uds, port, timeout)?;
        let bounded = DeadlineStream::new(stream, Instant::now() + timeout, "guest exec");
        ClientConnection::connect(bounded).map_err(handshake_err)
    })
}

/// The dial-retry loop both constructors share, so the window and its reasoning live once.
fn with_dial_retry<T>(
    timeout: Duration,
    mut attempt: impl FnMut() -> Result<T, VmmError>,
) -> Result<T, VmmError> {
    let retry_deadline = Instant::now() + timeout.min(DIAL_RETRY_CAP);
    let mut backoff = crate::spawn::PollBackoff::new();
    loop {
        match attempt() {
            Ok(conn) => return Ok(conn),
            Err(e @ VmmError::GuestUnavailable(_)) if Instant::now() < retry_deadline => {
                tracing::debug!(error = %e, "vsock dial failed transiently; retrying");
                backoff.sleep();
            }
            Err(e) => return Err(e),
        }
    }
}

/// One dial attempt, no retry: the body [`connect_agent_at`] loops over, and what
/// [`RunningVm::probe_agent`] uses directly, so a pool health check discards a dead clone on its
/// instant ECONNREFUSED rather than spending a retry window on a corpse.
pub(crate) fn connect_agent_once(
    uds: &Path,
    port: u32,
    timeout: Duration,
) -> Result<ClientConnection<UnixStream>, VmmError> {
    let stream = vsock_connect(uds, port, timeout)?;
    ClientConnection::connect(stream).map_err(handshake_err)
}

/// Classify a channel-handshake failure. A peer close mid-handshake is the same transient "not
/// serving right now" condition as a close during CONNECT, typed retryable; anything else (bad magic,
/// a mismatched agent) is a permanent fault, and retrying it would only mislabel it as
/// unavailability.
fn handshake_err(e: bsx_channel::ChannelError) -> VmmError {
    let detail = format!("channel handshake over vsock: {e}");
    if channel_err_is_disconnect(&e) {
        VmmError::GuestUnavailable(format!("{detail} (is the guest agent listening?)"))
    } else {
        VmmError::Vmm(detail)
    }
}

/// Whether an io error kind is a peer disconnect (EPIPE / ECONNRESET / EOF), the shared predicate
/// behind [`send_was_disconnect`] and the establishment-phase retryable classification.
fn is_disconnect(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// [`is_disconnect`] over a [`ChannelError`]: `Io` with a disconnect kind. `Protocol` and every
/// other (current or future, the enum is `#[non_exhaustive]`) variant reads as **not** a
/// disconnect, so unknown failures default to permanent rather than silently retried.
fn channel_err_is_disconnect(e: &ChannelError) -> bool {
    matches!(e, ChannelError::Io(io) if is_disconnect(io.kind()))
}

/// Drive one exec over an established [`ClientConnection`]: send the request, then aggregate the
/// response stream into a [`RunResult`]. Bounded on two axes so a flooding *or* dribbling guest can't
/// hurt the host: `max_output` caps buffered bytes, and `wall` is the host's own wall-clock deadline
/// on the collect loop (`timeout` is the guest's command budget; `wall` = `timeout` + kill slack).
/// A guest that keeps the per-read idle timer alive by dribbling tiny frames, never sending its
/// terminal `Exit`/`TimedOut`, trips `wall` and yields [`VmmError::ExecUnresponsive`], rather than
/// parking the caller indefinitely. Factored out of [`RunningVm::exec`] so it can be tested without a VM.
/// The host-enforced bounds on one exec, bundled so they travel together (and to keep `run_exec`
/// under the argument-count limit). Seeds the hoster-tunable per-run resource policy the timeout
/// constants above anticipate.
pub(crate) struct ExecBounds {
    /// The guest's command wall-clock budget, sent to the agent as `timeout_ms`; the agent kills the
    /// command past it and reports `TimedOut`.
    pub(crate) timeout: Duration,
    /// The *host's* own deadline on the collect loop, `timeout` + kill slack, so a guest that never
    /// reports the command's end can't park `exec` forever. Trips [`VmmError::ExecUnresponsive`].
    pub(crate) wall: Duration,
    /// Aggregate cap on buffered stdout+stderr+artifacts, so a flooding guest can't grow host memory.
    pub(crate) max_output: usize,
}

/// Encode a command budget as the wire `timeout_ms`, **floored at 1 ms**. The host never means
/// "unlimited" (every exec carries a real budget), which is why this returns [`NonZeroU32`] and the
/// caller wraps it in `Some`: the channel spells "use the agent's ceiling" as `None`, so a budget
/// encoded here cannot become one. The floor is what keeps a sub-millisecond budget (e.g.
/// `Duration::from_micros(500)`) meaning "very short" rather than truncating away to nothing.
/// Saturates rather than wraps for absurd budgets.
fn wire_timeout_ms(timeout: Duration) -> NonZeroU32 {
    NonZeroU32::new(u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX))
        .unwrap_or(NonZeroU32::MIN)
}

/// Whether a send failure is the guest *disconnecting* mid-write (EPIPE / ECONNRESET / EOF), the only
/// case where a typed refusal it queued before closing is still readable past the close, so worth a
/// recovery `recv_response`. A `PayloadTooLarge`/`Protocol` error wrote nothing to the socket, and a
/// local write timeout leaves the guest healthy and awaiting a request: for those, reading back would
/// just park for the full socket read timeout, so the caller surfaces the send error directly.
fn send_was_disconnect(err: &VmmError) -> bool {
    matches!(err, VmmError::Channel(e) if channel_err_is_disconnect(e))
}

pub(crate) fn run_exec<S: Read + Write>(
    conn: &mut ClientConnection<S>,
    argv: &[&str],
    stdin: &[u8],
    files_in: &[(&str, &[u8])],
    env: &[(&str, &str)],
    artifacts: &[&str],
    bounds: ExecBounds,
) -> Result<RunResult, VmmError> {
    // Host-side trace of the exec (the guest's own `exec` span goes to the serial console, not the
    // operator's stderr), keyed by argv so `bsx run` failures are diagnosable host-side. The env
    // *count* only, never a value, and not even the key list, per the secret-hygiene contract.
    let span = tracing::info_span!("exec", argv = ?argv, env_vars = env.len());
    let _span = span.enter();
    let started = Instant::now();

    // The host's own deadline, independent of the socket's per-read idle timeout. A `Duration::MAX`
    // "no limit" must stay a *bounded* wait, not an `Instant + Duration` overflow panic, clamp to a
    // day (mirrors the boot deadline).
    let deadline = started
        .checked_add(bounds.wall)
        .unwrap_or_else(|| started + Duration::from_secs(86_400));

    // Inject input files first, then the terminal exec request. The injected bytes are secrets by
    // presumption (the secret-hygiene contract on `RunningVm::exec_with_files`): the borrowed-send
    // path serializes straight from the caller's slices into a single exact-sized wire buffer that
    // the channel wipes after each send, so the engine keeps no extra copy of a file
    // body or env value to strand, and nothing on this path logs one.
    let sent = (|| -> Result<(), VmmError> {
        for (path, data) in files_in {
            conn.send_put_file(path.as_ref(), data)?;
        }
        // `Some`, always: the engine sends a real budget, never the agent's ceiling.
        conn.send_exec(
            argv,
            stdin,
            env,
            artifacts,
            Some(wire_timeout_ms(bounds.timeout)),
        )?;
        Ok(())
    })();

    if let Err(send_err) = sent {
        // The guest may have rejected an earlier request and closed *while the host was still
        // writing* (a peer disconnect: EPIPE / ECONNRESET / EOF): its typed refusal is already in
        // the socket buffer, readable past the close, so prefer that reason over the transport
        // symptom. Only a disconnect leaves a refusal to read: a `PayloadTooLarge`/`Protocol` send
        // error wrote nothing, and a local write timeout leaves the guest healthy and awaiting a
        // request, so draining either would just park `recv_response` for the full read timeout.
        if send_was_disconnect(&send_err)
            && let Ok(Response::Error(msg)) = conn.recv_response()
        {
            return Err(VmmError::GuestExec(msg));
        }
        return Err(send_err);
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut files: Vec<Artifact> = Vec::new();
    // Bound stdout + stderr + artifact *names and bytes* together. `FRAME_FLOOR` is charged per
    // frame so a flood of empty frames (or `File` frames whose budget is spent on `path`, not
    // `data`) can't spin the loop or grow `files` without advancing the cap.
    //
    // The charge is checked **before** buffering: a frame that would push past the cap is rejected
    // without being copied in, so `max_output` is a hard bound on what the host buffers, not a
    // soft one that a final `MAX_PAYLOAD`-sized frame could overshoot by ~1 MiB.
    fn charge(captured: &mut usize, add: usize, max: usize) -> Result<(), VmmError> {
        let next = captured.saturating_add(add);
        if next > max {
            return Err(VmmError::OutputCap { limit: max });
        }
        *captured = next;
        Ok(())
    }
    let mut captured = 0usize;
    loop {
        // The host's own wall-clock deadline, checked *before* each blocking read: a guest that
        // dribbles tiny well-formed frames, never sending its terminal `Exit`/`TimedOut`, would
        // otherwise keep this loop alive indefinitely under the output cap. `wall` outlasts the
        // guest's own `TimedOut`, so a legitimate timeout still arrives as `ExecTimeout`; this only
        // fires for a non-reporting guest.
        //
        // This check bounds the loop *between* frames only. Bounding the read *within* one frame is
        // `DeadlineStream`'s job (the connection comes from `connect_agent_bounded`), because a
        // per-syscall socket timeout is re-armed by every byte and so bounds one `read`, not one
        // `read_exact` of a whole frame. With both, the worst case is the deadline plus one syscall.
        if Instant::now() >= deadline {
            return Err(VmmError::ExecUnresponsive { limit: bounds.wall });
        }
        match conn.recv_response()? {
            Response::Stdout(b) => {
                charge(&mut captured, b.len() + FRAME_FLOOR, bounds.max_output)?;
                stdout.extend_from_slice(&b);
            }
            Response::Stderr(b) => {
                charge(&mut captured, b.len() + FRAME_FLOOR, bounds.max_output)?;
                stderr.extend_from_slice(&b);
            }
            Response::File { path, data } => {
                // The guest names these paths; `artifact_path_is_safe` owns the containment story.
                if !artifact_path_is_safe(&path) {
                    return Err(VmmError::GuestProtocol(format!(
                        "guest returned artifact path {path:?} that is absolute or escapes the \
                         working tree"
                    )));
                }
                charge(
                    &mut captured,
                    path.len() + data.len() + FRAME_FLOOR,
                    bounds.max_output,
                )?;
                files.push(Artifact::new(path, data));
            }
            Response::Exit { code } => {
                tracing::info!(
                    exit_code = code,
                    stdout_bytes = stdout.len(),
                    stderr_bytes = stderr.len(),
                    artifacts = files.len(),
                    elapsed_ms = crate::ms(started.elapsed()),
                    "guest command finished"
                );
                return Ok(RunResult {
                    exit_code: code,
                    stdout,
                    stderr,
                    files,
                    metrics: ExecMetrics {
                        wall: started.elapsed(),
                    },
                });
            }
            // The guest killed the command at its wall-clock deadline. Distinct typed error, and
            // logged host-side (the guest's own log goes to the serial console, not the operator).
            // NOTE: the partial stdout/stderr streamed before the kill is discarded here; carrying
            // it on the error (or a `timed_out` RunResult) is a future enhancement.
            Response::TimedOut { elapsed_ms } => {
                tracing::warn!(
                    limit_ms = crate::ms(bounds.timeout),
                    elapsed_ms,
                    "guest command timed out"
                );
                return Err(VmmError::ExecTimeout {
                    limit: bounds.timeout,
                });
            }
            // A guest-side fault on a healthy channel, distinct from a transport failure.
            Response::Error(msg) => return Err(VmmError::GuestExec(msg)),
            // A well-framed frame the exec loop never expects here (a stray `PutFile` echo, a
            // second handshake): the channel is intact but the guest is off-script. A protocol
            // violation, same bucket as a bad artifact path, the guest's fault, not the host's.
            _ => {
                return Err(VmmError::GuestProtocol(
                    "unexpected response frame from guest agent".into(),
                ));
            }
        }
    }
}

/// Whether a guest-returned artifact path is safe to hand an embedder: a non-empty **relative** path
/// whose every component is a plain name or `.`, no absolute root, no `..` climb. The guest names
/// these paths and the guest agent is not the trust boundary, so this predicate is what keeps a
/// path that would write outside a caller's working tree out of `RunResult.files`. The CLI's
/// `write_artifacts` relies on it rather than repeating it, so every embedder is covered once.
fn artifact_path_is_safe(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Connect to `uds` and perform Firecracker's host-initiated vsock handshake: send
/// `CONNECT <port>\n`, expect `OK <host_port>\n`. Returns the stream positioned right after the
/// ack, with read/write deadlines set.
fn vsock_connect(uds: &Path, port: u32, timeout: Duration) -> Result<UnixStream, VmmError> {
    // `connect_with_timeout` bounds the connection step with a deadline.
    // ECONNREFUSED means the socket file exists but nothing accepts: a dead VMM's stale socket (a
    // pooled clone that crashed), the retryable/discard signal, not broken infra.
    let mut stream = crate::firecracker::connect_with_timeout(uds, timeout).map_err(|e| {
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

    writeln!(stream, "CONNECT {port}").map_err(|e| {
        let detail = format!("vsock CONNECT {port}: {e}");
        // EPIPE/ECONNRESET here is the write-side face of the same peer-close the ack read sees
        // as EOF: which one lands is a timing coin-flip, so both must classify retryable, or the
        // dial-retry seam only heals half the race.
        if is_disconnect(e.kind()) {
            VmmError::GuestUnavailable(format!("{detail} (is the guest agent listening?)"))
        } else {
            VmmError::Vmm(detail)
        }
    })?;
    read_connect_ack(&mut stream, port)?;
    Ok(stream)
}

/// Read Firecracker's `OK <port>\n` ack **one byte at a time**: the guest agent sends its channel
/// handshake immediately after the connection is established, so a buffered read here would swallow
/// those bytes and desync the protocol.
fn read_connect_ack(stream: &mut UnixStream, port: u32) -> Result<(), VmmError> {
    let mut line = [0u8; 64];
    let mut len = 0usize;
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                // Firecracker closes the connection with no ack when nothing is listening on the
                // guest port, the canonical "agent not up yet / not anymore" signal, typed so a
                // retry/pool caller can branch on it.
                return Err(VmmError::GuestUnavailable(format!(
                    "vsock CONNECT {port}: peer closed before ack (is the guest agent listening?)"
                )));
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if len >= line.len() {
                    return Err(VmmError::Vmm(format!(
                        "vsock CONNECT {port}: ack line too long"
                    )));
                }
                line[len] = byte[0];
                len += 1;
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
                )));
            }
            Err(e) if is_disconnect(e.kind()) => {
                // A reset mid-ack: the same peer-close as the EOF arm above, same retryable type.
                return Err(VmmError::GuestUnavailable(format!(
                    "vsock CONNECT {port}: {e} (is the guest agent listening?)"
                )));
            }
            Err(e) => return Err(VmmError::Vmm(format!("vsock CONNECT {port}: {e}"))),
        }
    }
    let ack = String::from_utf8_lossy(&line[..len]);
    if ack.starts_with("OK ") {
        Ok(())
    } else {
        // A well-formed non-OK ack is Firecracker refusing the port, same "nothing listening"
        // semantics as the peer-close above, so the same retryable variant.
        Err(VmmError::GuestUnavailable(format!(
            "vsock CONNECT {port} refused: {ack:?} (is the guest agent listening?)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::VSOCK_UDS;
    use bsx_channel::VSOCK_PORT;
    use bsx_guest_agent::serve_session;
    use bsx_test_support::{LogSink, ScratchDir};
    use std::path::PathBuf;

    /// Consume one `CONNECT <port>\n` request line, a byte at a time: the client's channel handshake
    /// follows on the same stream, so a buffered read would swallow it. Returns the read error
    /// rather than panicking, for the peers whose subject is closing mid-line.
    fn read_connect_line(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<()> {
        let mut b = [0u8; 1];
        loop {
            stream.read_exact(&mut b)?;
            if b[0] == b'\n' {
                return Ok(());
            }
        }
    }

    /// Answer one `CONNECT` handshake as Firecracker does: consume the request line, then write the
    /// `OK <host_port>` ack every fake peer here answers with.
    fn answer_connect(stream: &mut std::os::unix::net::UnixStream) {
        read_connect_line(stream).expect("read CONNECT");
        stream.write_all(b"OK 10000\n").expect("write ack");
    }

    /// Stand up a fake Firecracker vsock socket: accept, answer the `CONNECT <port>` handshake, then
    /// hand the same stream to the *real* guest agent. Lets us exercise the entire host exec path
    /// (vsock connect + `CONNECT` ack + channel handshake + exec round trip) with no VM.
    fn fake_vsock_agent(tag: &str) -> (ScratchDir, PathBuf, std::thread::JoinHandle<()>) {
        use std::os::unix::net::UnixListener;
        let dir = ScratchDir::created(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            answer_connect(&mut stream);
            let _ = serve_session(stream, &std::env::temp_dir().join("bsx-session-test"));
        });
        (dir, uds, handle)
    }

    /// Where a flaky fake peer closes each of its first `drops` connections, modeling the faces of
    /// a peer close during establishment the dial retry must absorb.
    enum DropPhase {
        /// Close the instant the connection is accepted (the host sees EPIPE on the CONNECT write
        /// or EOF before the ack, timing's choice).
        BeforeAck,
        /// Answer `OK`, then close before the channel handshake.
        AfterAck,
    }

    /// A [`fake_vsock_agent`] that drops its first `drops` connections at `phase`, then serves the
    /// real agent on the next one: the regression harness for the establishment retry.
    fn flaky_vsock_agent(
        tag: &str,
        drops: usize,
        phase: DropPhase,
    ) -> (ScratchDir, PathBuf, std::thread::JoinHandle<()>) {
        use std::os::unix::net::UnixListener;
        let dir = ScratchDir::created(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            for _ in 0..drops {
                let (mut stream, _) = listener.accept().expect("accept doomed dial");
                if matches!(phase, DropPhase::AfterAck) {
                    answer_connect(&mut stream);
                }
                drop(stream); // the peer-close under test
            }
            let (mut stream, _) = listener.accept().expect("accept the surviving dial");
            answer_connect(&mut stream);
            let _ = serve_session(stream, &std::env::temp_dir().join("bsx-session-test"));
        });
        (dir, uds, handle)
    }

    #[test]
    fn connect_retries_through_dropped_dials() {
        // A peer close before the ack must not kill the caller (in the daemon: the session): the
        // dial retries within its window and the request proceeds on the surviving connection.
        let (_dir, uds, server) =
            flaky_vsock_agent("bsx-vsock-flaky-preack", 2, DropPhase::BeforeAck);
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5))
            .expect("retry through two dropped dials");
        let result = run_exec(
            &mut conn,
            &["echo", "survived"],
            b"",
            &[],
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect("exec after the retried dial");
        assert_eq!(result.stdout, b"survived\n");
        server.join().expect("server thread");
    }

    #[test]
    fn connect_retries_through_a_handshake_close() {
        // The other face: the ack arrives but the peer closes before the channel handshake. Same
        // transient condition, same retry.
        let (_dir, uds, server) =
            flaky_vsock_agent("bsx-vsock-flaky-postack", 2, DropPhase::AfterAck);
        let conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5));
        assert!(
            conn.is_ok(),
            "a post-ack close is retryable, not fatal: {:?}",
            conn.err()
        );
        drop(conn);
        server.join().expect("server thread");
    }

    #[test]
    fn a_dead_peer_is_a_bounded_guest_unavailable() {
        // A peer that never serves: the retry window must expire with the typed retryable error,
        // within the documented bound (~timeout + retry cap), never hang.
        use std::os::unix::net::UnixListener;
        let dir = ScratchDir::created("bsx-vsock-dead");
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let dead = std::thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => drop(stream),
                    Err(_) => return,
                }
            }
        });
        let window = Duration::from_millis(300);
        let started = Instant::now();
        let err = connect_agent_at(&uds, VSOCK_PORT, window)
            .map(|_| ())
            .expect_err("an always-closing peer must fail");
        let elapsed = started.elapsed();
        assert!(
            matches!(err, VmmError::GuestUnavailable(_)),
            "exhaustion surfaces the retryable variant: {err}"
        );
        assert!(
            elapsed < window * 4,
            "the retry window is bounded (allowing the documented per-attempt looseness): {elapsed:?}"
        );
        drop(dead); // detached: the listener thread dies with the process
    }

    #[test]
    fn a_single_shot_probe_fails_fast_on_a_dead_socket() {
        // The pool's health check must discard a corpse in microseconds, not spend the dial-retry
        // window on it: `connect_agent_once` (what `probe_agent` uses) never retries.
        let dir = ScratchDir::created("bsx-vsock-stale");
        let uds = dir.path().join(VSOCK_UDS);
        // A socket file nothing listens on: the SIGKILLed-clone shape (instant ECONNREFUSED).
        {
            use std::os::unix::net::UnixListener;
            let _bound_then_dropped = UnixListener::bind(&uds).expect("bind then drop");
        }
        let started = Instant::now();
        let err = connect_agent_once(&uds, VSOCK_PORT, PROBE_TIMEOUT)
            .map(|_| ())
            .expect_err("a dead socket must refuse");
        assert!(
            matches!(err, VmmError::GuestUnavailable(_)),
            "a stale socket is the discard signal: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "no retry window is spent on a corpse: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn exec_over_fake_vsock_runs_a_command() {
        // Happy path: `exec("echo hi")` → `hi`, exit 0, through the *real* agent (only the
        // Firecracker vsock UDS is faked).
        let (_dir, uds, server) = fake_vsock_agent("bsx-vsock-echo");
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["echo", "hi"],
            b"",
            &[],
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
        // The structured result's metrics leg: a real exec took nonzero host-observed time.
        assert!(result.metrics.wall > Duration::ZERO);
        server.join().expect("server thread");
    }

    #[test]
    fn exec_over_fake_vsock_feeds_stdin() {
        let (_dir, uds, server) = fake_vsock_agent("bsx-vsock-stdin");
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["cat"],
            b"from the host\n",
            &[],
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
        let (_dir, uds, server) = fake_vsock_agent("bsx-vsock-files");
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &[
                "sh",
                "-c",
                "mkdir -p out && tr a-z A-Z < in.txt > out/up.txt",
            ],
            b"",
            &[("in.txt", &b"hello\n"[..])],
            &[],
            &["out/up.txt", "missing.txt"],
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
            vec![Artifact::new("out/up.txt", b"HELLO\n".to_vec())]
        );
        server.join().expect("server thread");
    }

    #[test]
    fn wire_timeout_never_encodes_a_real_budget_as_unlimited() {
        // A sub-millisecond budget must not truncate away to nothing; the floor keeps a real
        // budget a real limit. (`NonZeroU32` is what stops it reaching the wire's ceiling
        // sentinel at all, so this now pins the floor's *value*, not its existence.)
        let nz = |n: u32| NonZeroU32::new(n).expect("a nonzero budget");
        assert_eq!(wire_timeout_ms(Duration::from_micros(500)), NonZeroU32::MIN);
        assert_eq!(wire_timeout_ms(Duration::ZERO), NonZeroU32::MIN);
        // Whole-millisecond budgets pass through unchanged.
        assert_eq!(wire_timeout_ms(Duration::from_millis(1)), nz(1));
        assert_eq!(wire_timeout_ms(Duration::from_millis(1500)), nz(1500));
        assert_eq!(wire_timeout_ms(Duration::from_secs(3600)), nz(3_600_000));
        // An absurd budget saturates rather than wrapping back toward (or to) zero.
        assert_eq!(wire_timeout_ms(Duration::from_secs(u64::MAX)), nz(u32::MAX));
    }

    #[test]
    fn only_a_peer_disconnect_triggers_the_send_failure_drain() {
        use std::io::{Error, ErrorKind};
        // A disconnect mid-write: the guest closed after queuing a refusal, so read it back.
        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::UnexpectedEof,
        ] {
            let err = VmmError::Channel(ChannelError::Io(Error::from(kind)));
            assert!(send_was_disconnect(&err), "{kind:?} should drain");
        }
        // Wrote-nothing / guest-still-healthy failures must NOT drain (they would block on a read
        // for the full socket timeout): an oversized frame, a protocol misuse, and a write timeout.
        let too_large = VmmError::Channel(ChannelError::PayloadTooLarge {
            tag: 0,
            len: 1 << 21,
        });
        let protocol = VmmError::Channel(ChannelError::Protocol("bad".into()));
        let write_timeout = VmmError::Channel(ChannelError::Io(Error::from(ErrorKind::WouldBlock)));
        assert!(!send_was_disconnect(&too_large));
        assert!(!send_was_disconnect(&protocol));
        assert!(!send_was_disconnect(&write_timeout));
    }

    #[test]
    fn artifact_path_is_safe_rejects_escaping_and_absolute_paths() {
        // The public API's containment predicate: only relative, non-climbing paths survive.
        for ok in ["a.txt", "out/up.txt", "./out/up.txt", "a/b/c"] {
            assert!(artifact_path_is_safe(ok), "{ok:?} should be accepted");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../escape.txt",
            "../../etc/cron.d/x",
            "out/../../etc/passwd",
            "a/../../b",
        ] {
            assert!(!artifact_path_is_safe(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn run_exec_rejects_a_guest_returned_escaping_artifact_path() {
        // A *hostile* guest (not the real agent, which validates its own writes): the fake server
        // speaks the channel protocol directly and returns a `File` whose path climbs out of the
        // working tree. The public API must reject it as a `GuestProtocol` fault (bucket `Guest`) rather
        // than pass the escaping path up in `RunResult.files` for an embedder to write to disk.
        use bsx_channel::ServerConnection;
        let (client, server) = UnixStream::pair().expect("socketpair");
        let hostile = std::thread::spawn(move || {
            let mut srv = ServerConnection::accept(server).expect("accept");
            let _req = srv.recv_request().expect("recv exec");
            // Off-script: hand back an absolute-escaping artifact the caller never confined.
            let _ = srv.send_response(&Response::File {
                path: "../../etc/cron.d/pwn".into(),
                data: b"* * * * * root sh".to_vec(),
            });
        });
        let mut conn = ClientConnection::connect(client).expect("connect");
        let err = run_exec(
            &mut conn,
            &["true"],
            b"",
            &[],
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_secs(5),
                wall: Duration::from_secs(30),
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect_err("an escaping artifact path must be a typed error");
        assert!(
            matches!(err, VmmError::GuestProtocol(_)),
            "want GuestProtocol, got {err:?}"
        );
        assert_eq!(err.kind(), crate::ErrorKind::Guest);
        hostile.join().expect("hostile server thread");
    }

    #[test]
    fn injected_secrets_reach_no_observable_surface() {
        // The secret-hygiene leak test (host half): drive a succeeding exec whose
        // env value and injected file hold a sentinel, and a failing injection whose *data* holds
        // it, while capturing, at TRACE, every log line the driver and the in-process real agent
        // emit. The sentinel may appear only in the RunResult (the caller's own data); never in a
        // log line, never in an error's Display/Debug (which may name the *path*). The console
        // surface needs a real VM; that half lives in the integration suite (tests/sandbox.rs).
        use std::os::unix::net::UnixListener;
        const SENTINEL: &str = "S3KR1T-canary-77f2c9e1";
        let bounds = || ExecBounds {
            timeout: Duration::from_secs(5),
            wall: Duration::from_secs(30),
            max_output: MAX_EXEC_OUTPUT,
        };

        let sink = LogSink::default();
        let dir = ScratchDir::created("bsx-vsock-leak");
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let agent_sink = sink.clone();
        let server = std::thread::spawn(move || {
            tracing::subscriber::with_default(agent_sink.subscriber(), || {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().expect("accept");
                    answer_connect(&mut stream);
                    let _ = serve_session(stream, &std::env::temp_dir().join("bsx-session-test"));
                }
            });
        });

        let (result, err) = tracing::subscriber::with_default(sink.subscriber(), || {
            // Happy path: the env value and the file content must reach the command in-guest.
            let mut conn =
                connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
            let result = run_exec(
                &mut conn,
                &[
                    "sh",
                    "-c",
                    "printf '%s ' \"$LEAK_TEST_SECRET\"; cat leak.txt",
                ],
                b"",
                &[("leak.txt", SENTINEL.as_bytes())],
                &[("LEAK_TEST_SECRET", SENTINEL)],
                &[],
                bounds(),
            )
            .expect("exec");
            // Failure path: an escaping path is rejected; the error may name the path, not the data.
            let mut conn =
                connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
            let err = run_exec(
                &mut conn,
                &["true"],
                b"",
                &[("../escape.txt", SENTINEL.as_bytes())],
                &[],
                &[],
                bounds(),
            )
            .unwrap_err();
            (result, err)
        });
        server.join().expect("server thread");

        // The run received both inputs, RunResult is the caller's data, the one allowed surface.
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert_eq!(stdout, format!("{SENTINEL} {SENTINEL}"));
        // The failure is typed, names the path, and carries none of the data.
        assert!(matches!(err, VmmError::GuestExec(_)), "got {err:?}");
        let (display, debug) = (format!("{err}"), format!("{err:?}"));
        assert!(
            !display.contains(SENTINEL) && !debug.contains(SENTINEL),
            "sentinel leaked into the error: {debug}"
        );
        assert!(
            display.contains("escape.txt"),
            "the error should still name the offending path: {display}"
        );
        // Every captured log line, both sides, at TRACE: non-empty (the capture worked, the two
        // exec spans are in there) and sentinel-free.
        let logs = sink.contents();
        assert!(
            logs.contains("exec"),
            "expected captured spans, got {logs:?}"
        );
        assert!(
            !logs.contains(SENTINEL),
            "sentinel leaked into logs: {logs}"
        );
    }

    #[test]
    fn exec_crashing_command_is_a_typed_error() {
        // A command the guest can't run ("crashing" in the agent-fault sense) comes back as a
        // terminal `Error` frame → the typed `VmmError::GuestExec`, end to end through the real
        // agent (which reports the spawn failure), not via a hand-crafted `Error` response.
        let (_dir, uds, server) = fake_vsock_agent("bsx-vsock-crash");
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["definitely-not-a-real-binary-zzz"],
            b"",
            &[],
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
        // `kill -9 $$`) is NOT a `VmmError`, the agent maps signal death to `128+sig` and the host
        // returns a faithful `RunResult{exit_code: 137}`. This pins the *host*-side mapping in
        // `run_exec`; the guest-agent-layer version lives in crates/guest-agent/tests/exec.rs.
        let (_dir, uds, server) = fake_vsock_agent("bsx-vsock-signal");
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let result = run_exec(
            &mut conn,
            &["sh", "-c", "kill -9 $$"],
            b"",
            &[],
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
    /// [`ServerConnection`](bsx_channel::ServerConnection) to `handler`, so a test can craft the
    /// exact response stream (unlike `fake_vsock_agent`, which runs the real agent).
    fn fake_vsock_server<F>(
        tag: &str,
        handler: F,
    ) -> (ScratchDir, PathBuf, std::thread::JoinHandle<()>)
    where
        F: FnOnce(bsx_channel::ServerConnection<std::os::unix::net::UnixStream>) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let dir = ScratchDir::created(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            answer_connect(&mut stream);
            let conn = bsx_channel::ServerConnection::accept(stream).expect("server handshake");
            handler(conn);
        });
        (dir, uds, handle)
    }

    /// [`fake_vsock_server`] handing back the **raw** stream after both handshakes, so a test can
    /// write bytes the channel encoder would never produce: a frame header followed by a payload
    /// dribbled a byte at a time.
    fn fake_vsock_server_raw<F>(
        tag: &str,
        handler: F,
    ) -> (ScratchDir, PathBuf, std::thread::JoinHandle<()>)
    where
        F: FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let dir = ScratchDir::created(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind fake vsock");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            answer_connect(&mut stream);
            // The channel handshake by hand (its encoders are private to `bsx-channel`): magic, then
            // the version, then the peer's own six bytes.
            let mut hello = [0u8; 6];
            hello[..4].copy_from_slice(b"AGCH");
            hello[4..].copy_from_slice(&bsx_channel::PROTOCOL_VERSION.to_le_bytes());
            stream.write_all(&hello).expect("write handshake");
            stream.flush().expect("flush handshake");
            let mut peer = [0u8; 6];
            stream.read_exact(&mut peer).expect("read handshake");
            handler(stream);
        });
        (dir, uds, handle)
    }

    #[test]
    fn a_guest_dribbling_one_frames_bytes_cannot_outlast_the_wall() {
        // The in-frame twin of `exec_dribbling_guest_trips_the_host_wall_deadline`: that one dribbles
        // whole frames, which the loop's between-frames deadline check catches. This one dribbles the
        // bytes *inside* a single frame, where the loop never gets control, so only an absolute bound
        // on the reads themselves can end it. A per-syscall `SO_RCVTIMEO` cannot: the kernel re-arms
        // it on every byte that arrives, so the frame is bounded by `payload_len × timeout`.
        const PAYLOAD: usize = 200;
        const PER_BYTE: Duration = Duration::from_millis(20);
        let (_dir, uds, server) = fake_vsock_server_raw("bsx-vsock-inframe", |mut s| {
            // A well-formed `Stdout` header promising PAYLOAD bytes, then one byte at a time. Each
            // arrival is far inside the socket timeout, so the idle timer never fires.
            let mut header = [0u8; 5];
            header[0] = 2; // Tag::Stdout
            header[1..].copy_from_slice(&(PAYLOAD as u32).to_le_bytes());
            if s.write_all(&header).is_err() {
                return;
            }
            for _ in 0..PAYLOAD {
                if s.write_all(b"x").is_err() || s.flush().is_err() {
                    return;
                }
                std::thread::sleep(PER_BYTE);
            }
        });

        // Dribbling the whole payload takes PAYLOAD * PER_BYTE = 4 s. The wall is 300 ms, and it is
        // the socket timeout too, so an unbounded read would sit here for the full 4 s and *succeed*.
        let wall = Duration::from_millis(300);
        let mut conn = connect_agent_bounded(&uds, VSOCK_PORT, wall).expect("connect");
        let started = std::time::Instant::now();
        let err = run_exec(
            &mut conn,
            &["dribble-in-frame"],
            b"",
            &[],
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_millis(200),
                wall,
                max_output: MAX_EXEC_OUTPUT,
            },
        )
        .expect_err("a frame that outruns the wall must not be waited out");
        let held = started.elapsed();

        let unbounded = PER_BYTE * PAYLOAD as u32; // ~4 s
        assert!(
            held < unbounded / 2,
            "the read must end near the {wall:?} wall, not near the {unbounded:?} the dribble \
             would take; held {held:?} ({err:?})"
        );
        drop(conn);
        let _ = server.join();
    }

    #[test]
    fn exec_surfaces_a_guest_error_as_typed_error() {
        // The agent reports a spawn failure with a terminal `Error` frame → `VmmError::GuestExec`,
        // distinct from a transport fault.
        let (_dir, uds, server) = fake_vsock_server("bsx-vsock-err", |mut conn| {
            let _ = conn.recv_request();
            let _ = conn.send_response(&Response::Error("no such binary".into()));
        });
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["nope"],
            b"",
            &[],
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
        let (_dir, uds, server) = fake_vsock_server("bsx-vsock-drop", |mut conn| {
            let _ = conn.recv_request();
            drop(conn); // no response frames, the host's next read sees a clean EOF
        });
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["echo", "hi"],
            b"",
            &[],
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
        let (_dir, uds, server) = fake_vsock_server("bsx-vsock-flood", |mut conn| {
            let _ = conn.recv_request();
            // Keep sending until the host drops the connection (cap exceeded → our writes error).
            while conn
                .send_response(&Response::Stdout(vec![b'x'; 500]))
                .is_ok()
            {}
        });
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["flood"],
            b"",
            &[],
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
        // VmmError::ExecTimeout, not conflated with a channel/transport timeout.
        let (_dir, uds, server) = fake_vsock_server("bsx-vsock-timeout", |mut conn| {
            let _ = conn.recv_request();
            let _ = conn.send_response(&Response::TimedOut { elapsed_ms: 1000 });
        });
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["sleep"],
            b"",
            &[],
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
        // must still trip the cap, path bytes and a per-frame floor count toward it.
        let (_dir, uds, server) = fake_vsock_server("bsx-vsock-pathflood", |mut conn| {
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
        let mut conn = connect_agent_at(&uds, VSOCK_PORT, Duration::from_secs(5)).expect("connect");
        let err = run_exec(
            &mut conn,
            &["flood"],
            b"",
            &[],
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
        let (_dir, uds, server) = fake_vsock_server("bsx-vsock-dribble", |mut conn| {
            let _ = conn.recv_request();
            // Dribble every 50 ms, well under the 200 ms idle timeout, so the idle timer never
            // fires; only the host's wall deadline can end this.
            while conn.send_response(&Response::Stdout(vec![b'x'; 8])).is_ok() {
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        // Idle (200 ms) > dribble interval (50 ms), so the socket idle timeout can't fire; wall
        // (150 ms) is the thing under test. All sub-second so the suite stays fast.
        let mut conn =
            connect_agent_at(&uds, VSOCK_PORT, Duration::from_millis(200)).expect("connect");
        let started = std::time::Instant::now();
        let err = run_exec(
            &mut conn,
            &["dribble"],
            b"",
            &[],
            &[],
            &[],
            ExecBounds {
                timeout: Duration::from_millis(100), // guest budget (the fake server ignores it)
                wall: Duration::from_millis(150),    // host wall deadline, under test
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
    ) -> (ScratchDir, PathBuf, std::thread::JoinHandle<()>)
    where
        F: FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let dir = ScratchDir::created(tag);
        let uds = dir.path().join(VSOCK_UDS);
        let listener = UnixListener::bind(&uds).expect("bind");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_connect_line(&mut stream); // closing mid-line is a subject here
            handler(stream);
        });
        (dir, uds, handle)
    }

    #[test]
    fn connect_ack_refused_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("bsx-ack-refuse", |mut s| {
            let _ = s.write_all(b"NOPE\n");
        });
        let err = vsock_connect(&uds, VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        // "Nothing listening on the guest port" is the retryable GuestUnavailable, not broken infra.
        assert!(
            matches!(err, VmmError::GuestUnavailable(ref m) if m.contains("refused")),
            "got {err:?}"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_peer_close_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("bsx-ack-close", drop);
        let err = vsock_connect(&uds, VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        // The canonical agent-not-up signal: typed retryable, so a pool can discard-and-retry.
        assert!(
            matches!(err, VmmError::GuestUnavailable(ref m) if m.contains("closed")),
            "got {err:?}"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_too_long_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("bsx-ack-long", |mut s| {
            let _ = s.write_all(&[b'x'; 100]); // 100 bytes, no newline
            std::thread::sleep(Duration::from_millis(200)); // keep the stream open past the read
        });
        let err = vsock_connect(&uds, VSOCK_PORT, Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(m) if m.contains("too long")),
            "wrong error"
        );
        server.join().expect("server");
    }

    #[test]
    fn connect_ack_timeout_is_typed_error() {
        let (_d, uds, server) = fake_connect_target("bsx-ack-timeout", |s| {
            std::thread::sleep(Duration::from_millis(300)); // never send; outlive the client deadline
            drop(s);
        });
        let err = vsock_connect(&uds, VSOCK_PORT, Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, VmmError::Timeout(_)), "got {err:?}");
        server.join().expect("server");
    }
}
