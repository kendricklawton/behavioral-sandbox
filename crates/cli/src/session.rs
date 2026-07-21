//! One client connection = one sandbox **session**. Mirrors `agent shell`'s lifecycle over the wire:
//! the first message opens the sandbox (jailed by default, the daemon's launch posture, never the
//! client's to weaken), then each verb acts on it, sharing one working directory (the VM *is* the
//! session, ADR 019), until `close` (or a hung-up connection) tears it down.
//!
//! The session runs on an owned [`RunningVm`], not a [`Sandbox`](agent_vmm::Sandbox), so a warm clone
//! popped from the pool and a cold boot serve through the exact same code, the only difference the
//! client sees is the `pooled` flag and the boot latency.
//!
//! **The verbs** (the versioned wire API, ADR 034): `open` boots; `exec` runs a command; `put`/`get`
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
//! either, the lifetime sentinel (ADR 014) owns that.

use std::io::BufReader;
use std::num::{NonZeroU32, NonZeroU8};
use std::os::unix::net::UnixStream;
use std::sync::TryLockError;
use std::time::{Duration, Instant};

use agent_cli::audit::RunProbes;
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
    let mut reader = BufReader::new(stream);

    // Arm the idle timeout (if configured) on **both** directions: a read that blocks this long with
    // no client bytes, or a write that blocks this long because the client stopped draining, fails
    // (`WouldBlock`/`TimedOut`), which the loop treats as a broken connection and ends the session,
    // so a wedged client can't pin a VM + a `--max-sessions` slot indefinitely. The write half is not
    // optional: an `exec` reply can be up to a per-message cap (megabytes) against a ~200 KiB socket
    // buffer, so a client that opens a session and then never reads would otherwise park the session
    // thread in `write_all` forever, past the read timeout it never reaches. Covers the wait for
    // `open` too. Best-effort: a platform that refuses the sockopt just runs without it.
    if let Some(idle) = server.idle_timeout {
        let _ = reader.get_ref().set_read_timeout(Some(idle));
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
    let (limits, bare) = match open_limits(&open) {
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
    loop {
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
                let resp = match probes.as_ref() {
                    Some(p) => Response::Trace {
                        record: record_to_value(&p.live_record(timing).to_json()),
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
    // directory (the bundle stays on the daemon host, ADR 034 keeps bulk bytes off this line).
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

/// Fold an [`Request::Open`]'s optional knobs onto the conservative [`Limits`] default, validating
/// each as a typed message (never a panic): vCPUs in `1..=32`, memory and wall nonzero. Also reports
/// whether the `open` was **bare** (every knob defaulted), which decides pool eligibility. A non-`Open`
/// first message is the caller's error too.
fn open_limits(req: &Request) -> Result<(Limits, bool), String> {
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
    let mut limits = Limits::default();
    if let Some(v) = vcpus {
        if *v == 0 || *v > MAX_VCPUS {
            return Err(format!("vcpus must be in 1..={MAX_VCPUS}, got {v}"));
        }
        limits.vcpus = NonZeroU8::new(*v).unwrap_or(NonZeroU8::MIN);
    }
    if let Some(m) = mem_mib {
        limits.mem_mib =
            NonZeroU32::new(*m).ok_or_else(|| "mem_mib must be at least 1".to_string())?;
    }
    if let Some(s) = wall_secs {
        if *s == 0 {
            return Err("wall_secs must be at least 1".to_string());
        }
        limits.wall = Duration::from_secs(*s);
    }
    if let Some(c) = output_cap {
        limits.output_cap = *c;
    }
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
        let (limits, bare) = open_limits(&Request::Open {
            vcpus: Some(4),
            mem_mib: Some(1024),
            wall_secs: Some(60),
            output_cap: Some(4096),
        })
        .expect("valid open");
        assert!(!bare, "a knobbed open is not pool-eligible");
        assert_eq!(limits.vcpus.get(), 4);
        assert_eq!(limits.mem_mib.get(), 1024);
        assert_eq!(limits.wall, Duration::from_secs(60));
        assert_eq!(limits.output_cap, 4096);

        let d = Limits::default();
        let (base, bare) = open_limits(&Request::Open {
            vcpus: None,
            mem_mib: None,
            wall_secs: None,
            output_cap: None,
        })
        .expect("bare open");
        assert!(bare, "a fully-defaulted open is pool-eligible");
        assert_eq!(base.vcpus, d.vcpus);
        assert_eq!(base.mem_mib, d.mem_mib);
        assert_eq!(base.wall, d.wall);
        assert_eq!(base.output_cap, d.output_cap);
    }

    #[test]
    fn a_single_knob_makes_the_open_non_bare() {
        // Even one custom knob means the pool's default-profile clone can't serve it, cold boot.
        let (_, bare) = open_limits(&Request::Open {
            vcpus: None,
            mem_mib: Some(512),
            wall_secs: None,
            output_cap: None,
        })
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
            let err = open_limits(&req).expect_err("illegal value must be rejected");
            assert!(err.contains(needle), "error should name {needle}: {err}");
        }
    }

    #[test]
    fn a_non_open_first_message_is_rejected() {
        let err = open_limits(&Request::Close).expect_err("close is not an open");
        assert!(err.contains("open"), "{err}");
    }

    #[test]
    fn record_to_value_parses_json_and_never_panics() {
        assert_eq!(record_to_value("{\"schema\":1}")["schema"], 1);
        // A malformed string can't happen from `to_json`, but the fallback must still be an object.
        assert!(record_to_value("not json").get("error").is_some());
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
