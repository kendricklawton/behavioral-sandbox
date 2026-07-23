//! One client connection = one sandbox **session**. Mirrors `agent shell`'s lifecycle over the wire:
//! the first message opens the sandbox (jailed by default, the daemon's launch posture, never the
//! client's to weaken), then each verb acts on it, sharing one working directory (the VM *is* the
//! session, ADR 016), until `close` (or a hung-up connection) tears it down.
//!
//! The session runs on an owned [`RunningVm`], not a [`Sandbox`](agent_vmm::Sandbox), so a warm clone
//! popped from the pool and a cold boot serve through the exact same code, the only difference the
//! client sees is the `pooled` flag and the boot latency.
//!
//! **The verbs** (the versioned wire API, ADR 030): `open` boots; `exec` runs a command; `put`/`get`
//! write/read a working-directory file (a no-op exec that only injects/returns it, since injection is
//! the engine's only file seam); `snapshot` writes a bundle (a typed refusal for a jailed session);
//! `trace` returns the host-observed audit record (`RunRecord`) so far; `close` ends it.
//!
//! No-panic host path (guardrail 5): a hostile or buggy client, bad JSON, a wrong first message, a
//! wrong wire schema, a command that can't spawn, a mid-session hang-up, is a typed
//! [`Response::Error`] or a dropped connection, never a daemon panic. The exec-fault taxonomy follows
//! the CLI's shell: a **guest** fault (a bad command, a timeout, a flooded cap) is per-request and the
//! session survives it, while an **infra/transport** fault means the VM itself is gone, so the session
//! ends and its VM drops (tearing the microVM down). Losing the whole daemon process can't leak a VM
//! either, the lifetime sentinel (ADR 011) owns that.

use std::io::{BufReader, Read};
use std::num::{NonZeroU32, NonZeroU8};
use std::os::unix::net::UnixStream;
use std::sync::TryLockError;
use std::time::{Duration, Instant};

use agent_cli::audit::RunProbes;
use agent_cli::policy::{Policy, Requested};
use agent_cli::MAX_VCPUS;
use agent_probes_loader::Timing;
use agent_protocol::{read_message, write_message, ProtocolError, Request, Response};
use agent_vmm::{BootConfig, ErrorKind, Limits, RunningVm, Vm, VmmError, DEFAULT_GUEST_CID};

use crate::metrics::{Metrics, Verb};
use crate::serve::Server;

/// The no-op command `put`/`get` run: the engine injects files and returns artifacts only *around an
/// exec*, so a bare file write/read rides a command that does nothing but carry them. `true` exits 0
/// and is resolved from the guest's `PATH` (the same bare-name resolution `exec` already relies on).
const NOOP_ARGV: &str = "true";

/// Serve one connection to completion: open the session's sandbox, act on it, tear down. Never
/// returns an error, every failure is reported to the client (best-effort) and logged, so one bad
/// connection can't take the daemon down.
pub fn serve(stream: UnixStream, server: &Server) {
    // A second handle for writing, so the read side can sit in a `BufReader` while we still reply.
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "cannot split the connection; dropping it");
            return;
        }
    };
    // The idle timeout (if configured) bounds **both** directions, each with the right shape for its
    // threat. The read half needs an *absolute per-message deadline* ([`DeadlineStream`]), not a bare
    // `set_read_timeout`: `SO_RCVTIMEO` is re-armed by the OS on every byte, so a client dripping one
    // byte per interval inside a 4 MiB line would reset a per-read timeout forever, pinning a session
    // thread + a `--max-sessions` slot (the same slowloris the metrics endpoint's `read_request_head`
    // closes). The write half stays a plain socket timeout: an `exec` reply can be megabytes against a
    // ~200 KiB socket buffer, so a client that opens a session and then never reads would otherwise
    // park the session thread in `write_all` forever. Best-effort on the sockopts: a platform that
    // refuses them just runs without them.
    let mut reader = BufReader::new(DeadlineStream::new(stream, server.idle_timeout));
    if let Some(idle) = server.idle_timeout {
        let _ = writer.set_write_timeout(Some(idle));
    }

    // The first message must be `open` (carrying the session's resource envelope). Anything else,
    // EOF, a stray verb, a malformed/wrong-schema line, ends the connection before any VM is booted.
    let open = match read_message::<Request>(&mut reader) {
        Ok(Some(req)) => req,
        Ok(None) => return, // client hung up before opening; nothing to tear down
        Err(e) => {
            if !matches!(e, ProtocolError::Io(_)) {
                server.metrics.protocol_error();
            }
            let _ = write_response(&mut writer, &fatal(format!("before open: {e}")));
            return;
        }
    };
    let (limits, bare) = match open_limits(&open, &server.policy) {
        Ok(parsed) => parsed,
        Err(message) => {
            server.metrics.open_failed();
            let _ = write_response(&mut writer, &fatal(message));
            return;
        }
    };

    // Boot the session's VM: a warm clone from the pool when this is a bare-default `open`, else a
    // cold boot with the requested envelope. A boot failure is fatal to the session (there is no
    // sandbox), reported and then done.
    let (vm, pooled) = match boot_session_vm(server, limits, bare) {
        Ok(booted) => booted,
        Err(e) => {
            server.metrics.open_failed();
            let _ = write_response(&mut writer, &fatal(format!("open sandbox: {e}")));
            return;
        }
    };
    let boot = vm.boot_latency();
    let boot_ms = ms(boot);

    // Attach the host-side probes so `trace` has something to report. Observe-only (no egress policy
    // over the wire yet), so this is pure fail-open: a host without the eBPF caps yields a
    // coverage-gapped record, never a refused session. `egress = None` means `attach` cannot return
    // the enforcement refusal, but stay defensive and treat any error as "no probes".
    let probes = match server
        .observ
        .attach(vm.vmm_pid(), vm.netns(), vm.tap_name(), None)
    {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(error = %e, "probe attach failed; `trace` will report an empty record");
            None
        }
    };

    server.metrics.session_opened(pooled, boot);
    tracing::info!(vmm_pid = vm.vmm_pid(), boot_ms, pooled, "session opened");
    if !send(&mut writer, &Response::Opened { boot_ms, pooled }) {
        end_session(server, vm, probes, pooled); // client gone before we could serve
        return;
    }

    // The command loop: one request per line until `close`, EOF, or a session-ending fault.
    let mut total_exec_wall = Duration::ZERO;
    // The session's record hash-chain (decision 034): each `trace` reply commits to the previous
    // one's hash, so a client can `verify_chain` the sequence and detect a reordered/dropped record.
    // `None` until the first `trace`; the first record is the unchained anchor.
    let mut record_chain: Option<String> = None;
    loop {
        // Each message gets a fresh full budget: the clock starts here, not at `open`, so a long
        // boot or a long-running previous command never eats into the next request's deadline.
        reader.get_mut().rearm();
        match read_message::<Request>(&mut reader) {
            Ok(None) => break, // clean EOF, teardown below
            Ok(Some(Request::Close)) => {
                let _ = send(&mut writer, &Response::Closed);
                break;
            }
            Ok(Some(Request::Open { .. })) => {
                if !send(
                    &mut writer,
                    &nonfatal("session already open (open is the first message only)"),
                ) {
                    break;
                }
            }
            Ok(Some(Request::Exec { argv, stdin })) => {
                server.metrics.request(Verb::Exec);
                let t0 = Instant::now();
                let result = vm.exec(&argv, stdin.as_deref().unwrap_or("").as_bytes());
                if !serve_run(
                    &mut writer,
                    &server.metrics,
                    result,
                    t0.elapsed(),
                    &mut total_exec_wall,
                    true, // a real guest command
                    |r| Response::Result {
                        exit_code: r.exit_code,
                        stdout: lossy(&r.stdout),
                        stderr: lossy(&r.stderr),
                        exec_wall_ms: ms(r.metrics.wall),
                    },
                ) {
                    break;
                }
            }
            Ok(Some(Request::Put { path, content })) => {
                server.metrics.request(Verb::Put);
                let t0 = Instant::now();
                let result = vm.exec_with_files(
                    &[NOOP_ARGV.to_string()],
                    b"",
                    &[(path.clone(), content.into_bytes())],
                    &[],
                    &[],
                );
                if !serve_run(
                    &mut writer,
                    &server.metrics,
                    result,
                    t0.elapsed(),
                    &mut total_exec_wall,
                    false, // put rides a no-op `true`, not a guest command
                    |_| Response::Put { path: path.clone() },
                ) {
                    break;
                }
            }
            Ok(Some(Request::Get { path })) => {
                server.metrics.request(Verb::Get);
                let t0 = Instant::now();
                let result = vm.exec_with_files(
                    &[NOOP_ARGV.to_string()],
                    b"",
                    &[],
                    &[],
                    std::slice::from_ref(&path),
                );
                if !serve_run(
                    &mut writer,
                    &server.metrics,
                    result,
                    t0.elapsed(),
                    &mut total_exec_wall,
                    false, // get rides a no-op `true`, not a guest command
                    |r| {
                        let found = r.files.iter().find(|a| a.path == path);
                        Response::Got {
                            path: path.clone(),
                            content: found.map(|a| lossy(&a.data)).unwrap_or_default(),
                            present: found.is_some(),
                        }
                    },
                ) {
                    break;
                }
            }
            Ok(Some(Request::Snapshot)) => {
                server.metrics.request(Verb::Snapshot);
                // Always non-fatal: a jailed refusal never touches the VM, and a genuine mid-snapshot
                // failure surfaces on the next exec (the fault taxonomy handles it there).
                let resp = match do_snapshot(server, &vm) {
                    Ok(dir) => Response::Snapshotted { dir },
                    Err(e) => {
                        server.metrics.request_failed(true);
                        nonfatal(format!("snapshot: {e}"))
                    }
                };
                if !send(&mut writer, &resp) {
                    break;
                }
            }
            Ok(Some(Request::Trace)) => {
                server.metrics.request(Verb::Trace);
                let timing = Timing {
                    boot,
                    exec_wall: total_exec_wall,
                };
                // Sign the finalized record with the host key (decision 034) and carry the envelope:
                // the record rides inside it as a string, so its signed bytes survive the wire's
                // serde round-trip and a client can verify without trusting this daemon's transport.
                // Chained to the previous `trace` in this session, so the sequence is tamper-evident
                // as a whole, not just per record.
                let resp = match probes.as_ref() {
                    Some(p) => {
                        let canonical = p.live_record(timing).to_json();
                        let envelope = server
                            .signing_key
                            .sign_canonical_chained(&canonical, record_chain.as_deref());
                        record_chain = Some(agent_probes_loader::record_hash(&canonical));
                        Response::Trace {
                            record: record_to_value(&envelope),
                        }
                    }
                    None => {
                        server.metrics.request_failed(true);
                        nonfatal("audit probes are not attached for this session")
                    }
                };
                if !send(&mut writer, &resp) {
                    break;
                }
            }
            Ok(Some(Request::TraceSummary)) => {
                server.metrics.request(Verb::TraceSummary);
                let timing = Timing {
                    boot,
                    exec_wall: total_exec_wall,
                };
                // The same live, non-destructive record snapshot as `trace`, projected to the
                // model-legible summary the CLI's `--record-summary` writes.
                let resp = match probes.as_ref() {
                    Some(p) => Response::TraceSummary {
                        summary: record_to_value(&p.live_record(timing).to_summary_json()),
                    },
                    None => {
                        server.metrics.request_failed(true);
                        nonfatal("audit probes are not attached for this session")
                    }
                };
                if !send(&mut writer, &resp) {
                    break;
                }
            }
            // A malformed/oversize line is the client's fault and per-request; the session survives.
            // A wrong wire schema means the peer speaks another protocol, end the session. A
            // transport I/O error means the connection itself is broken, stop.
            Err(ProtocolError::Io(e)) => {
                // An idle-timeout read surfaces here as `WouldBlock`/`TimedOut` (the armed
                // `SO_RCVTIMEO`); name it so an operator can tell an idle drop from a real transport
                // break. Either way the connection is done, tear the session down.
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) {
                    tracing::info!("session idle past --idle-timeout; ending session");
                } else {
                    tracing::warn!(error = %e, "connection read failed; ending session");
                }
                break;
            }
            Err(e @ ProtocolError::Schema(_)) => {
                server.metrics.protocol_error();
                let _ = send(&mut writer, &fatal(e.to_string()));
                break;
            }
            Err(e) => {
                server.metrics.protocol_error();
                if !send(&mut writer, &nonfatal(e.to_string())) {
                    break;
                }
            }
        }
    }
    tracing::info!("session closed");
    end_session(server, vm, probes, pooled);
}

/// Reply to a verb that ran a guest command (`exec`/`put`/`get`): on success accumulate the exec
/// wall and send `to_response(result)`; on failure send a typed error. Returns `false` when the loop
/// should stop, the connection broke, or the fault is session-ending (an **infra/transport** fault
/// means the VM is gone; a **guest** fault the session survives).
fn serve_run(
    w: &mut UnixStream,
    metrics: &Metrics,
    result: Result<agent_vmm::RunResult, VmmError>,
    wall: Duration,
    total_exec_wall: &mut Duration,
    is_command: bool,
    to_response: impl FnOnce(&agent_vmm::RunResult) -> Response,
) -> bool {
    // Only a real `exec` counts as a guest command. `put`/`get` ride a no-op `true` purely to carry a
    // file, so folding their wall into the `guest_command` histogram or the trace `exec_wall` would
    // dilute the user-command latency signal with file-transfer overhead (16-G); `requests_total{verb}`
    // already counts put/get separately. For a real command, accumulate the **host-measured** wall on
    // both success and failure: a timed-out or capped exec still consumed time (up to the whole
    // budget), so `exec_wall` must count it, not silently drop it by only summing successful runs.
    if is_command {
        *total_exec_wall += wall;
    }
    match result {
        Ok(run) => {
            if is_command {
                metrics.guest_command(run.metrics.wall);
            }
            send(w, &to_response(&run))
        }
        Err(e) => {
            let session_survives = e.kind() == ErrorKind::Guest;
            metrics.request_failed(session_survives);
            // Logged host-side too: the error reply reaches only the one client, and an operator
            // (or CI log) diagnosing a failed request needs the cause without owning that client.
            tracing::warn!(error = %e, fatal = !session_survives, "request failed");
            let sent = send(w, &error(e.to_string(), !session_survives));
            sent && session_survives
        }
    }
}

/// Boot the session's VM. A **bare** `open` (every knob defaulted) is served from the pre-warmed pool
/// when the daemon has one, the fast path, since the pool's clones carry the default profile. Any
/// custom resource knob (or no pool) is a cold boot with the requested envelope.
///
/// The lock is taken **non-blocking** (`try_lock`) and held only to pop **ready stock** (an O(1)
/// pop), never across a `Vm::restore` (16-A). Two ways it declines and cold-boots instead of blocking:
/// an empty (or poisoned) pool, and a *contended* one, `end_session` holds this same lock across its
/// `refill`'s inline restores, so a blocking `lock()` here would serialize every bare `open` behind
/// that whole refill window. Falling through to a lock-free cold boot keeps opens independent of
/// refills; the trade is a `pooled: false` on the transient dry/busy window instead of a stall.
fn boot_session_vm(
    server: &Server,
    limits: Limits,
    bare: bool,
) -> Result<(RunningVm, bool), VmmError> {
    if bare {
        if let Some(pool) = &server.pool {
            match pool.try_lock() {
                Ok(mut p) => {
                    // Pop only when there is ready stock, `Pool::take` would otherwise restore
                    // inline under this lock (the 16-A serialization). No stock ⇒ fall through to a
                    // lock-free cold boot below.
                    if p.ready() > 0 {
                        match p.take() {
                            Ok(vm) => return Ok((vm, true)),
                            Err(e) => tracing::warn!(
                                error = %e,
                                "pool take failed; cold-booting this session"
                            ),
                        }
                    }
                }
                // Contended (a refill holds the lock): don't wait it out, cold-boot instead.
                Err(std::sync::TryLockError::WouldBlock) => {
                    tracing::debug!("pool busy (refilling?); cold-booting this session")
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    tracing::warn!("pool lock poisoned; cold-booting this session")
                }
            }
        }
    }
    let config = server.base.clone().with_limits(limits);
    Ok((cold_boot(config, server.jailed)?, false))
}

/// Cold-boot a `RunningVm` with the daemon's confinement posture, replicating what
/// [`Sandbox::open`](agent_vmm::Sandbox::open) does before booting, force the vsock exec channel on,
/// and set (or clear) the jail, so a cold session and a pooled one are the same shape of VM.
fn cold_boot(mut config: BootConfig, jailed: bool) -> Result<RunningVm, VmmError> {
    config.jail = if jailed {
        Some(config.jail.unwrap_or_default())
    } else {
        None
    };
    if config.guest_cid.is_none() {
        config.guest_cid = Some(DEFAULT_GUEST_CID);
    }
    Vm::boot(config)
}

/// Snapshot the session's VM into a fresh daemon-side bundle directory, returning its host path. A
/// jailed session is a typed refusal inside `snapshot` (its disk is in the chroot).
fn do_snapshot(server: &Server, vm: &RunningVm) -> Result<String, VmmError> {
    let dir = server.next_snapshot_dir();
    // Don't pre-create the bundle dir: `Vm::snapshot` refuses a restored/jailed/device-bearing VM
    // *before* writing anything, and creates the dir itself only on its success path. Pre-creating it
    // would orphan an empty `snap-N` on every refusal, and the default daemon posture is jailed (where
    // snapshot is always a refusal), so a client looping `snapshot` would leak dirs unbounded.
    // The returned `Snapshot` is just metadata pointing at the on-disk bundle; the client gets the
    // directory (the bundle stays on the daemon host, ADR 030 keeps bulk bytes off this line).
    let _snapshot = vm.snapshot(&dir)?;
    Ok(dir.to_string_lossy().into_owned())
}

/// Tear the session down: detach the probes, shut the VM, and top the pool back up (off the hot path,
/// between sessions, the moment the [`Pool`](agent_vmm::Pool) doc reserves for restore cost).
///
/// The refill is **best-effort and non-blocking** (16-A): `try_lock`, and skip if the pool is
/// contended. A close never waits on the pool lock, so a burst of closes can't queue up behind one
/// another's restore. Stock recovers on the next uncontended close (the holder refills all the way to
/// target), and any bare `open` that meanwhile finds the pool dry cold-boots, correct, just not
/// pooled.
fn end_session(server: &Server, vm: RunningVm, probes: Option<RunProbes>, _pooled: bool) {
    server.metrics.session_closed();
    drop(probes); // detach from the shared tracer/meter (its own `Drop`)
    if let Err(e) = vm.shutdown() {
        tracing::debug!(error = %e, "session VM shutdown reported an error");
    }
    if let Some(pool) = &server.pool {
        match pool.try_lock() {
            Ok(mut p) => match p.refill() {
                Ok(n) if n > 0 => tracing::debug!(restored = n, "pool refilled after session"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "pool refill failed"),
            },
            Err(TryLockError::WouldBlock) => {
                tracing::debug!("pool busy; skipping refill on this close")
            }
            Err(TryLockError::Poisoned(_)) => tracing::warn!("pool lock poisoned; not refilling"),
        }
    }
}

/// Fold an [`Request::Open`]'s optional knobs onto the [`Limits`] the operator's `policy` allows,
/// validating each as a typed message (never a panic): vCPUs in `1..=32`, memory and wall nonzero.
/// Also reports whether the `open` was **bare** (every knob defaulted), which decides pool
/// eligibility. A non-`Open` first message is the caller's error too.
///
/// This is the daemon's policy boundary, not a convenience: a client arrives over a socket and
/// controls neither this process's environment nor its `.agent.toml`, so bounding the request here
/// is what makes an operator ceiling real (decision 041). Asking past a ceiling is refused, never
/// quietly clamped.
fn open_limits(req: &Request, policy: &Policy) -> Result<(Limits, bool), String> {
    let Request::Open {
        vcpus,
        mem_mib,
        wall_secs,
        output_cap,
    } = req
    else {
        return Err("first message must be `open`".to_string());
    };
    let bare = vcpus.is_none() && mem_mib.is_none() && wall_secs.is_none() && output_cap.is_none();

    // Shape errors first (a 0 or an over-32 vCPU count is malformed regardless of policy), so the
    // caller gets the specific complaint rather than a ceiling message about a nonsense value.
    let mut requested = Requested::default();
    if let Some(v) = vcpus {
        if *v == 0 || *v > MAX_VCPUS {
            return Err(format!("vcpus must be in 1..={MAX_VCPUS}, got {v}"));
        }
        requested.vcpus = NonZeroU8::new(*v);
    }
    if let Some(m) = mem_mib {
        requested.mem_mib =
            Some(NonZeroU32::new(*m).ok_or_else(|| "mem_mib must be at least 1".to_string())?);
    }
    if let Some(s) = wall_secs {
        if *s == 0 {
            return Err("wall_secs must be at least 1".to_string());
        }
        requested.wall_secs = Some(*s);
    }
    requested.output_cap = *output_cap;

    let limits = policy.resolve(&requested).map_err(|e| e.to_string())?;
    Ok((limits, bare))
}

/// Parse the record's own JSON string into a value for the [`Response::Trace`] envelope. The record's
/// `to_json` is always well-formed; the fallback only guards the impossible so no path can panic.
fn record_to_value(json: &str) -> serde_json::Value {
    serde_json::from_str(json)
        .unwrap_or_else(|_| serde_json::json!({ "error": "record serialization failed" }))
}

/// Send a response, returning `false` (so the caller stops) if the write failed, a broken pipe is a
/// gone client, not a daemon fault.
fn send(w: &mut UnixStream, resp: &Response) -> bool {
    match write_response(w, resp) {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!(error = %e, "reply failed; the client is gone");
            false
        }
    }
}

/// Write one schema-stamped response line (the shared codec).
fn write_response(w: &mut UnixStream, resp: &Response) -> Result<(), ProtocolError> {
    write_message(w, resp)
}

/// UTF-8-lossy rendering of captured bytes, matching `agent run --json`.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A session-ending error response.
fn fatal(message: String) -> Response {
    error(message, true)
}

/// A per-request error response the session survives.
fn nonfatal(message: impl Into<String>) -> Response {
    error(message.into(), false)
}

/// Build a typed error response.
fn error(message: String, fatal: bool) -> Response {
    Response::Error { message, fatal }
}

/// The session's read half, bounded by one **absolute deadline per message** instead of a bare
/// socket timeout. `SO_RCVTIMEO` is re-armed by the OS on every byte, so a per-read timeout alone
/// lets a slow-drip client (one byte just inside the interval) stretch a single 4 MiB line
/// indefinitely while holding a session thread and a `--max-sessions` slot; with this wrapper the
/// whole message must complete within one idle budget of its first-awaited byte, the same
/// discipline as the metrics endpoint's `read_request_head` and the VMM's `DeadlineReader`. A
/// `None` budget (idle timeout disabled) reads plain, today's opt-out.
struct DeadlineStream {
    stream: UnixStream,
    /// The per-message budget; [`rearm`](Self::rearm) restarts the clock for the next message.
    budget: Option<Duration>,
    /// When the in-flight message must be complete.
    deadline: Option<Instant>,
}

impl DeadlineStream {
    fn new(stream: UnixStream, budget: Option<Duration>) -> Self {
        let mut s = Self {
            stream,
            budget,
            deadline: None,
        };
        s.rearm();
        s
    }

    /// Start the next message's budget clock (a no-op when the idle timeout is disabled).
    fn rearm(&mut self) {
        self.deadline = self.budget.map(|b| Instant::now() + b);
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(deadline) = self.deadline {
            // Shrink the socket timeout to the time left, so the sum of all reads honors one wall
            // clock; a spent budget is the timeout itself. The sockopt stays best-effort (a refusing
            // platform still gets the spent-budget check on every read return).
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "session message exceeded the idle deadline",
                ));
            }
            let _ = self.stream.set_read_timeout(Some(remaining));
        }
        self.stream.read(buf)
    }
}

/// A [`Duration`] as whole milliseconds, saturating (a run never realistically overflows `u64` ms).
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_limits_folds_validates_and_flags_bare() {
        // A full open folds each knob and is not bare; the defaults stand where omitted.
        let (limits, bare) = open_limits(
            &Request::Open {
                vcpus: Some(4),
                mem_mib: Some(1024),
                wall_secs: Some(60),
                output_cap: Some(4096),
            },
            &Policy::default(),
        )
        .expect("valid open");
        assert!(!bare, "a knobbed open is not pool-eligible");
        assert_eq!(limits.vcpus.get(), 4);
        assert_eq!(limits.mem_mib.get(), 1024);
        assert_eq!(limits.wall, Duration::from_secs(60));
        assert_eq!(limits.output_cap, 4096);

        let d = Limits::default();
        let (base, bare) = open_limits(
            &Request::Open {
                vcpus: None,
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
            },
            &Policy::default(),
        )
        .expect("bare open");
        assert!(bare, "a fully-defaulted open is pool-eligible");
        assert_eq!(base.vcpus, d.vcpus);
        assert_eq!(base.mem_mib, d.mem_mib);
        assert_eq!(base.wall, d.wall);
        assert_eq!(base.output_cap, d.output_cap);
    }

    #[test]
    fn an_operator_ceiling_refuses_a_greedy_client_open() {
        // The daemon's policy boundary: a client controls neither the daemon's flags nor its
        // environment, so this is the point where an operator ceiling becomes real. Asking past it
        // must be refused, not served a quietly smaller VM (decision 026/041).
        let policy = Policy {
            max_vcpus: NonZeroU8::new(2),
            max_mem_mib: NonZeroU32::new(512),
            ..Policy::default()
        };
        let err = open_limits(
            &Request::Open {
                vcpus: Some(16),
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
            },
            &policy,
        )
        .expect_err("16 vCPUs is past the operator's ceiling");
        assert!(
            err.contains("vcpus") && err.contains('2'),
            "the refusal names the knob and the bound: {err}"
        );

        // Under the ceiling still works, and the pool-eligibility signal is unaffected by policy.
        let (limits, bare) = open_limits(
            &Request::Open {
                vcpus: Some(2),
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
            },
            &policy,
        )
        .expect("at the ceiling is allowed");
        assert_eq!(limits.vcpus.get(), 2);
        assert!(!bare);
    }

    #[test]
    fn an_operator_default_fills_in_a_bare_client_open() {
        // A silent client gets the house profile, and stays pool-eligible: `bare` tracks what the
        // *client* asked for, not what policy resolved to.
        let policy = Policy {
            mem_mib: NonZeroU32::new(768),
            ..Policy::default()
        };
        let (limits, bare) = open_limits(
            &Request::Open {
                vcpus: None,
                mem_mib: None,
                wall_secs: None,
                output_cap: None,
            },
            &policy,
        )
        .expect("bare open under policy");
        assert_eq!(limits.mem_mib.get(), 768, "the house default applied");
        assert!(bare, "policy does not make a bare open non-bare");
    }

    #[test]
    fn a_single_knob_makes_the_open_non_bare() {
        // Even one custom knob means the pool's default-profile clone can't serve it, cold boot.
        let (_, bare) = open_limits(
            &Request::Open {
                vcpus: None,
                mem_mib: Some(512),
                wall_secs: None,
                output_cap: None,
            },
            &Policy::default(),
        )
        .expect("valid open");
        assert!(!bare);
    }

    #[test]
    fn open_limits_rejects_illegal_values_as_typed_messages() {
        for (req, needle) in [
            (
                Request::Open {
                    vcpus: Some(0),
                    mem_mib: None,
                    wall_secs: None,
                    output_cap: None,
                },
                "vcpus",
            ),
            (
                Request::Open {
                    vcpus: Some(33),
                    mem_mib: None,
                    wall_secs: None,
                    output_cap: None,
                },
                "vcpus",
            ),
            (
                Request::Open {
                    vcpus: None,
                    mem_mib: Some(0),
                    wall_secs: None,
                    output_cap: None,
                },
                "mem_mib",
            ),
            (
                Request::Open {
                    vcpus: None,
                    mem_mib: None,
                    wall_secs: Some(0),
                    output_cap: None,
                },
                "wall_secs",
            ),
        ] {
            let err =
                open_limits(&req, &Policy::default()).expect_err("illegal value must be rejected");
            assert!(err.contains(needle), "error should name {needle}: {err}");
        }
    }

    #[test]
    fn a_non_open_first_message_is_rejected() {
        let err =
            open_limits(&Request::Close, &Policy::default()).expect_err("close is not an open");
        assert!(err.contains("open"), "{err}");
    }

    #[test]
    fn record_to_value_parses_json_and_never_panics() {
        assert_eq!(record_to_value("{\"schema\":1}")["schema"], 1);
        // A malformed string can't happen from `to_json`, but the fallback must still be an object.
        assert!(record_to_value("not json").get("error").is_some());
    }

    #[test]
    fn a_slow_drip_message_is_bounded_by_the_absolute_deadline() {
        // The property `serve` relies on for the read half: a client dripping one byte per interval
        // (each drip inside what a bare `SO_RCVTIMEO` would allow, so a per-read timeout would reset
        // forever) is ended when the *message* deadline lapses. Prove it at the socket level, no VM:
        // the drip happens before any `open` completes.
        let (client, server_end) = UnixStream::pair().expect("socketpair");
        let budget = Duration::from_millis(200);
        let mut reader = BufReader::new(DeadlineStream::new(server_end, Some(budget)));

        let dripper = std::thread::spawn(move || {
            use std::io::Write;
            // 20 bytes, 50ms apart: each gap is well inside the 200ms budget, so only an absolute
            // deadline (not a per-read timeout) can end this read early. Finite, so a regression
            // fails on timing/EOF instead of hanging the test.
            for _ in 0..20 {
                if (&client).write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        let started = Instant::now();
        let result = read_message::<Request>(&mut reader);
        let elapsed = started.elapsed();
        dripper.join().expect("dripper");

        assert!(
            matches!(result, Err(ProtocolError::Io(_))),
            "a dripped never-completing message must be a bounded typed error, got {result:?}"
        );
        // Under the fix the error lands at ~200ms; under a per-read-timeout regression the reader
        // instead drains all 20 drips (~1s) to EOF, failing the `Err` assert above AND this bound.
        // 800ms leaves scheduling slack for a loaded CI box without losing the discrimination.
        assert!(
            elapsed < Duration::from_millis(800),
            "the deadline must bound the whole message (~200ms), not reset per byte: {elapsed:?}"
        );
    }

    #[test]
    fn the_deadline_is_per_message_so_legit_traffic_is_never_cut() {
        // The other half of the contract: `rearm` gives every message a fresh budget, so a client
        // that idles between requests (within the budget) and then sends promptly is unaffected.
        let (client, server_end) = UnixStream::pair().expect("socketpair");
        let mut reader = BufReader::new(DeadlineStream::new(
            server_end,
            Some(Duration::from_millis(200)),
        ));

        let sender = std::thread::spawn(move || {
            let mut client = client;
            write_message(&mut client, &Request::Trace).expect("first message");
            // Idle 150ms: inside the first budget's leftover only if the deadline were cumulative;
            // well inside a *fresh* 200ms budget after rearm.
            std::thread::sleep(Duration::from_millis(150));
            write_message(&mut client, &Request::Close).expect("second message");
        });

        let first = read_message::<Request>(&mut reader).expect("first parses");
        assert_eq!(first, Some(Request::Trace));
        reader.get_mut().rearm();
        let second = read_message::<Request>(&mut reader).expect("second parses after rearm");
        assert_eq!(second, Some(Request::Close));
        sender.join().expect("sender");
    }

    #[test]
    fn an_armed_write_timeout_unblocks_a_stalled_reply_instead_of_hanging() {
        // The property `serve` relies on: with the write timeout armed, a reply to a client that has
        // stopped reading fails in bounded time (`send` returns false → the session ends → the VM
        // drops → the slot frees) rather than parking the session thread in `write_all` forever. Prove
        // it at the socket level, no VM: fill the buffers of a peer that never reads and assert the
        // write gives up at its timeout.
        use std::io::Write;
        let (writer, _reader) = UnixStream::pair().expect("socketpair");
        writer
            .set_write_timeout(Some(Duration::from_millis(100)))
            .expect("arm write timeout");
        // `_reader` is held (never read) so the kernel send+recv buffers fill and the write stalls.
        let chunk = vec![0u8; 1024 * 1024];
        let started = Instant::now();
        let mut err = None;
        for _ in 0..64 {
            // Up to 64 MiB, far past any default unix-socket buffer, so a non-draining peer forces
            // the stall regardless of the host's autotuned buffer size.
            if let Err(e) = (&writer).write_all(&chunk) {
                err = Some(e);
                break;
            }
        }
        let err = err.expect("a non-draining peer must make the write time out, not block forever");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "expected a timeout-family error, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the write must give up at its timeout, not hang"
        );
    }
}
