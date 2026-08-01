//! One client connection = one sandbox **session**. Mirrors `ekvm shell`'s lifecycle over the wire:
//! the first message opens the sandbox (jailed by default, the daemon's launch posture, never the
//! client's to weaken), then each verb acts on it, sharing one working directory (the VM *is* the
//! session), until `close` (or a hung-up connection) tears it down.
//!
//! The session runs on an owned [`RunningVm`], not a [`Sandbox`](vmm::Sandbox), so a warm clone
//! popped from the pool and a cold boot serve through the exact same code, the only difference the
//! client sees is the `pooled` flag and the boot latency.
//!
//! **The verbs** (the versioned wire API): `open` boots; `exec` runs a command; `put`/`get`
//! write/read a working-directory file (a no-op exec that only injects/returns it, since injection is
//! the engine's only file seam); `snapshot` writes a bundle (a typed refusal for a jailed session);
//! `trace` returns the host-observed audit record (`RunRecord`) so far; `close` ends it.
//!
//! Untrusted input: a hostile or buggy client, bad JSON, a wrong first message, a
//! wrong wire schema, a command that can't spawn, a mid-session hang-up, is a typed
//! [`Response::Error`] or a dropped connection, never a daemon panic. The exec-fault taxonomy follows
//! the CLI's shell: a **guest** fault (a bad command, a timeout, a flooded cap) is per-request and the
//! session survives it, while an **infra/transport** fault means the VM itself is gone, so the session
//! ends and its VM drops (tearing the microVM down). Losing the whole daemon process can't leak a VM
//! either, the lifetime sentinel owns that.

use std::io::{BufReader, Read};
use std::num::{NonZeroU32, NonZeroU8};
use std::os::unix::net::UnixStream;
use std::sync::TryLockError;
use std::time::{Duration, Instant};

use ekvm::audit::RunProbes;
use ekvm::policy::{parse_allow, Policy, Requested};
use ekvm::{vcpus_supported, MAX_VCPUS};
use probes_loader::{EgressPolicy, Timing, MAX_POLICY_RULES};
use protocol::{read_message, write_message, FaultKind, ProtocolError, Request, Response};
use vmm::{BootConfig, ErrorKind, Limits, RunningVm, Vm, VmmError, DEFAULT_GUEST_CID};

use crate::metrics::{Metrics, Verb};
use crate::serve::{
    pool_clone_limits, release_pool_clones, reserve_pool_clones, ResourceReservation, Server,
    AT_CAPACITY_RETRY_MS,
};

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
            let _ = write_response(
                &mut writer,
                &fatal(format!("before open: {e}"), FaultKind::Protocol),
            );
            return;
        }
    };
    let (limits, bare) = match open_limits(&open, &server.policy) {
        Ok(parsed) => parsed,
        Err(message) => {
            server.metrics.open_failed();
            let _ = write_response(&mut writer, &fatal(message, FaultKind::Protocol));
            return;
        }
    };
    let net = match open_network(&open, &server.policy) {
        Ok(resolved) => resolved,
        Err(message) => {
            server.metrics.open_failed();
            let _ = write_response(&mut writer, &fatal(message, FaultKind::Protocol));
            return;
        }
    };

    // Resource-aware admission: the count ticket (acquired at accept) bounds *how many*
    // sessions; this reservation bounds *how much* they commit, so a memory-heterogeneous fleet can't
    // overcommit the host into OOM while still under `--max-sessions`. Charged before boot from the
    // resolved `Limits`, held for the session, released on teardown by `Drop`. A refusal is the
    // distinct `at_capacity` reply a dispatcher fails over on, not a boot failure.
    let _reservation = match ResourceReservation::try_acquire(
        server,
        u64::from(limits.mem_mib.get()),
        u64::from(limits.vcpus.get()),
    ) {
        Some(reservation) => reservation,
        None => {
            server.metrics.open_refused(true);
            tracing::warn!(
                mem_mib = limits.mem_mib.get(),
                vcpus = limits.vcpus.get(),
                "refusing an open: at an aggregate resource ceiling"
            );
            let _ = write_response(
                &mut writer,
                &Response::AtCapacity {
                    retry_after_ms: AT_CAPACITY_RETRY_MS,
                },
            );
            return;
        }
    };

    // Boot the session's VM: a warm clone from the pool when this is a bare-default `open`, else a
    // cold boot with the requested envelope. A boot failure is fatal to the session (there is no
    // sandbox), reported and then done.
    let (vm, pooled) = match boot_session_vm(server, limits, bare, net.nic) {
        Ok(booted) => booted,
        Err(e) => {
            server.metrics.open_failed();
            let _ = write_response(
                &mut writer,
                &fatal(format!("open sandbox: {e}"), wire_kind(e.kind())),
            );
            return;
        }
    };
    let boot = vm.boot_latency();
    let boot_ms = ms(boot);

    // Attach the host-side probes so `trace` has something to report. Observation is fail-open (a
    // host without the eBPF caps yields a coverage-gapped record, never a refused session), but
    // **enforcement is not**: when the session asked for an egress policy, an attach that could not
    // police the tap is a fatal refusal below, never a session running unenforced.
    //
    // The gateway comes from the daemon's own `BootConfig`, not from the wire: whether a route out
    // exists is the operator's posture, like the jail.
    let gateway = server.base.egress.map(|e| e.gateway());
    let enforcing = net.egress.is_some();
    let probes = match server.observ.attach(
        vm.name(),
        vm.vmm_pid(),
        vm.netns(),
        vm.tap_name(),
        net.egress.as_ref(),
        gateway,
    ) {
        Ok(p) => Some(p),
        Err(e) => {
            // Enforcement does not fail open. If the session asked for an egress policy and the tap
            // could not be policed, ending the session is the only honest answer: the alternative is
            // a running sandbox whose caller believes its allow-list is in force.
            if enforcing {
                server.metrics.open_failed();
                let _ = write_response(
                    &mut writer,
                    &fatal(
                        format!("open sandbox: egress enforcement could not be armed: {e}"),
                        wire_kind(e.kind()),
                    ),
                );
                end_session(server, vm, None, pooled);
                return;
            }
            tracing::warn!(error = %e, "probe attach failed; `trace` will report an empty record");
            None
        }
    };

    server
        .metrics
        .session_opened(pooled, boot, vm.sentinel_degraded());
    tracing::info!(vmm_pid = vm.vmm_pid(), boot_ms, pooled, "session opened");
    if !send(&mut writer, &Response::Opened { boot_ms, pooled }) {
        end_session(server, vm, probes, pooled); // client gone before we could serve
        return;
    }

    // The command loop: one request per line until `close`, EOF, or a session-ending fault.
    let mut total_exec_wall = Duration::ZERO;
    // The session's record hash-chain: each `trace` reply commits to the previous
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
                    &nonfatal(
                        "session already open (open is the first message only)",
                        FaultKind::Protocol,
                    ),
                ) {
                    break;
                }
            }
            Ok(Some(Request::Exec { argv, stdin, env })) => {
                server.metrics.request(Verb::Exec);
                let t0 = Instant::now();
                let (result, interrupted) = exec_watching_for_cancel(
                    &vm,
                    &argv,
                    stdin.as_deref().unwrap_or(""),
                    env.as_deref().unwrap_or(&[]),
                    &writer,
                );
                if interrupted {
                    // The sandbox is gone, so the exec's own error is noise; acknowledge only if
                    // the client actually sent `cancel` (an outright hang-up gets no reply, there
                    // is nobody to read it).
                    server.metrics.request_failed(false);
                    if matches!(
                        read_message::<Request>(&mut reader),
                        Ok(Some(Request::Cancel))
                    ) {
                        let _ = write_response(&mut writer, &Response::Cancelled);
                    }
                    break;
                }
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
            Ok(Some(Request::Cancel)) => {
                // Legal only while a request is in flight, and that case is handled inside
                // `exec_watching_for_cancel`. Reaching the top of the loop means nothing is
                // outstanding, so there is nothing to cancel: the client's state machine is wrong,
                // but the session is fine.
                if !send(
                    &mut writer,
                    &nonfatal(
                        "nothing in flight to cancel (cancel is legal only while a request is outstanding)",
                        FaultKind::Protocol,
                    ),
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
                        nonfatal(format!("snapshot: {e}"), wire_kind(e.kind()))
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
                // Sign the finalized record with the host key. and carry the envelope:
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
                        record_chain = Some(probes_loader::record_hash(&canonical));
                        Response::Trace {
                            record: record_to_value(&envelope),
                        }
                    }
                    None => {
                        server.metrics.request_failed(true);
                        nonfatal(
                            "audit probes are not attached for this session",
                            FaultKind::Refused,
                        )
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
                        nonfatal(
                            "audit probes are not attached for this session",
                            FaultKind::Refused,
                        )
                    }
                };
                if !send(&mut writer, &resp) {
                    break;
                }
            }
            // `Request` is `#[non_exhaustive]`, so this arm exists and the compiler can no longer
            // tell us a verb went unhandled: the check that used to be a build error is now this
            // runtime reply. Unreachable from the wire (an unknown `op` fails at decode), so getting
            // here means `protocol` grew a verb the daemon never wired up. Loud on purpose.
            Ok(Some(other)) => {
                server.metrics.protocol_error();
                tracing::error!(request = ?other, "unhandled wire verb; the daemon is behind its own protocol crate");
                if !send(
                    &mut writer,
                    &nonfatal(
                        "this daemon does not implement that verb",
                        FaultKind::Protocol,
                    ),
                ) {
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
                let _ = send(&mut writer, &fatal(e.to_string(), FaultKind::Protocol));
                break;
            }
            Err(e) => {
                server.metrics.protocol_error();
                if !send(&mut writer, &nonfatal(e.to_string(), FaultKind::Protocol)) {
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
    result: Result<vmm::RunResult, VmmError>,
    wall: Duration,
    total_exec_wall: &mut Duration,
    is_command: bool,
    to_response: impl FnOnce(&vmm::RunResult) -> Response,
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
            let sent = send(
                w,
                &error(e.to_string(), !session_survives, wire_kind(e.kind())),
            );
            sent && session_survives
        }
    }
}

/// Boot the session's VM. A **bare** `open` (every knob defaulted) is served from the pre-warmed pool
/// when the daemon has one, the fast path, since the pool's clones carry the default profile. Any
/// custom resource knob (or no pool) is a cold boot with the requested envelope.
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
    nic: bool,
) -> Result<(RunningVm, bool), VmmError> {
    // Pool-eligible only when the resolved limits equal the clones' actual profile, not merely
    // when the request was bare: with operator defaults set, a bare open resolves to a different
    // profile than the pooled clones hold, and handing one out would both under-serve the session
    // and desynchronize the committed-resource accounting from the real footprint.
    if bare && limits == pool_clone_limits() {
        if let Some(pool) = &server.pool {
            match pool.try_lock() {
                Ok(mut p) => {
                    // Pop only when there is ready stock, `Pool::take` would otherwise restore
                    // inline under this lock (the 16-A serialization). No stock ⇒ fall through to a
                    // lock-free cold boot below.
                    if p.ready() > 0 {
                        match p.take() {
                            Ok(vm) => {
                                // The clone's charge hands off to the session's own reservation
                                // (already acquired), so the committed gauges keep matching the
                                // RAM actually resident; the brief overlap between the two
                                // charges is conservative, never an undercount.
                                release_pool_clones(server, 1, &pool_clone_limits());
                                return Ok((vm, true));
                            }
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
    let mut config = server.base.clone().with_limits(limits);
    config.enable_network = nic;
    Ok((cold_boot(config, server.jailed)?, false))
}

/// Cold-boot a `RunningVm` with the daemon's confinement posture, replicating what
/// [`Sandbox::open`](vmm::Sandbox::open) does before booting, force the vsock exec channel on,
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
    // directory (the bundle stays on the daemon host, keeping bulk bytes off this line).
    let _snapshot = vm.snapshot(&dir)?;
    Ok(dir.to_string_lossy().into_owned())
}

/// Tear the session down: detach the probes, shut the VM, and top the pool back up (off the hot path,
/// between sessions, the moment the [`Pool`](vmm::Pool) doc reserves for restore cost).
/// The refill is **best-effort and non-blocking** (16-A): `try_lock`, and skip if the pool is
/// contended. A close never waits on the pool lock, so a burst of closes can't queue up behind one
/// another's restore. Stock recovers on the next uncontended close (the holder refills all the way to
/// target), and any bare `open` that meanwhile finds the pool dry cold-boots, correct, just not
/// pooled.
fn end_session(server: &Server, vm: RunningVm, probes: Option<RunProbes>, _pooled: bool) {
    server.metrics.session_closed(vm.sentinel_degraded());
    drop(probes); // detach from the shared tracer/meter (its own `Drop`)
    if let Err(e) = vm.shutdown() {
        tracing::debug!(error = %e, "session VM shutdown reported an error");
    }
    if let Some(pool) = &server.pool {
        match pool.try_lock() {
            Ok(mut p) => {
                // Reserve-then-restore, one clone at a time: each restored clone is paid for
                // against the committed ceilings *before* it exists, so a refill can never push
                // the daemon past a ceiling that live sessions' reservations are holding. No
                // headroom means no refill this close; stock recovers on a later one.
                let clone = pool_clone_limits();
                let mut restored = 0usize;
                loop {
                    if reserve_pool_clones(server, 1, &clone) == 0 {
                        tracing::debug!(
                            restored,
                            "no committed-resource headroom for a pool refill; deferring"
                        );
                        break;
                    }
                    match p.refill_up_to(1) {
                        Ok(1) => restored += 1,
                        Ok(_) => {
                            // Already at target: the speculative reservation buys nothing.
                            release_pool_clones(server, 1, &clone);
                            break;
                        }
                        Err(e) => {
                            release_pool_clones(server, 1, &clone);
                            tracing::warn!(error = %e, "pool refill failed");
                            break;
                        }
                    }
                }
                if restored > 0 {
                    tracing::debug!(restored, "pool refilled after session");
                }
            }
            Err(TryLockError::WouldBlock) => {
                tracing::debug!("pool busy; skipping refill on this close")
            }
            Err(TryLockError::Poisoned(_)) => tracing::warn!("pool lock poisoned; not refilling"),
        }
    }
}

/// What an `open` asked for on the network axis, resolved against the operator's policy: whether the
/// session gets a NIC, and the egress policy to arm on its tap.
///
/// The daemon's own posture is untouched by this. A client can ask for a NIC and bound what crosses
/// it; whether a route out exists is the daemon's launch-time `BootConfig`, the same way the jail is,
/// so no wire message can route a session out of its sandbox (design decision 9).
#[derive(Debug, Default)]
struct SessionNet {
    /// Whether to boot with a tap.
    nic: bool,
    /// The egress policy to arm. `Some` whenever [`nic`](Self::nic) is set, deny-all at minimum, so
    /// a wire client can never obtain an unpoliced tap; `None` only when there is no NIC to police.
    egress: Option<EgressPolicy>,
}

/// Resolve an [`Request::Open`]'s network request against the operator's `policy`. Refuses rather
/// than clamping, like [`open_limits`]: a session that asked for egress it cannot have is an error,
/// never a quietly narrowed run.
fn open_network(req: &Request, policy: &Policy) -> Result<SessionNet, String> {
    let Request::Open { net, allow, .. } = req else {
        return Err("first message must be `open`".to_string());
    };
    let nic = net.unwrap_or(false);
    let allows = allow.as_deref().unwrap_or(&[]);
    if !allows.is_empty() && !nic {
        return Err("allow requires net: an egress policy needs a tap to be armed on".to_string());
    }
    // The operator's withdrawal of guest networking, checked before anything is parsed.
    policy.check_net(nic).map_err(|e| e.to_string())?;
    if !nic {
        return Ok(SessionNet::default());
    }
    // **A NIC over the wire is always policed**, deny-all at minimum. The CLI treats a bare `--net`
    // as observe-only, which is safe there because the caller is local and owns the config file; a
    // wire client is neither. Left observe-only, a client could ask for a NIC with no allowances and
    // get an unpoliced tap, which on a host that configured a gateway and furnished an uplink is
    // unrestricted egress, and `max_egress_v4` would never be consulted because it is only checked
    // against rules that were asked for. Deny-all costs the same attach and keeps design rule 3.
    if allows.is_empty() {
        return Ok(SessionNet {
            nic: true,
            egress: Some(EgressPolicy::deny_all()),
        });
    }
    if allows.len() > MAX_POLICY_RULES {
        return Err(format!(
            "too many allow rules: {} given, but the kernel egress policy holds at most              {MAX_POLICY_RULES}",
            allows.len()
        ));
    }
    let mut egress = EgressPolicy::deny_all();
    for spec in allows {
        let rule = parse_allow(spec)?;
        egress = egress.allow(rule.cidr, rule.port, rule.proto);
    }
    // Containment against the operator's ceilings (`max_egress_v4`/`max_egress_v6`), the check that
    // makes a ceiling real for a caller who controls neither this process's environment nor its
    // config file.
    policy.check_egress(&egress).map_err(|e| e.to_string())?;
    Ok(SessionNet {
        nic: true,
        egress: Some(egress),
    })
}

/// Fold an [`Request::Open`]'s optional knobs onto the [`Limits`] the operator's `policy` allows,
/// validating each as a typed message (never a panic): a vCPU count the VMM accepts (1 or an even
/// number up to 32), memory and wall nonzero.
/// Also reports whether the `open` was **bare** (every knob defaulted), which decides pool
/// eligibility. A non-`Open` first message is the caller's error too.
/// This is the daemon's policy boundary, not a convenience: a client arrives over a socket and
/// controls neither this process's environment nor its `.ekvm.toml`, so bounding the request here
/// is what makes an operator ceiling real. Asking past a ceiling is refused, never
/// quietly clamped.
fn open_limits(req: &Request, policy: &Policy) -> Result<(Limits, bool), String> {
    let Request::Open {
        vcpus,
        mem_mib,
        wall_secs,
        output_cap,
        net,
        allow,
    } = req
    else {
        return Err("first message must be `open`".to_string());
    };
    // `net`/`allow` count toward bareness even though they are not resource knobs: a pooled clone
    // restores a snapshot whose NIC presence is baked in, so a session that asked for a NIC cannot
    // be served from a pool built without one.
    let bare = vcpus.is_none()
        && mem_mib.is_none()
        && wall_secs.is_none()
        && output_cap.is_none()
        && net.is_none_or(|n| !n)
        && allow.is_none();

    // Shape errors first (a vCPU count the VMM would refuse is malformed regardless of policy), so
    // the caller gets the specific complaint rather than a ceiling message about a nonsense value.
    let mut requested = Requested::default();
    if let Some(v) = vcpus {
        if !vcpus_supported(*v) {
            return Err(format!(
                "vcpus must be 1 or an even number in 1..={MAX_VCPUS}, got {v}"
            ));
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
    // Narrow the wire's fixed-width `u64` to this host's `usize`. Saturating, not wrapping: on a
    // 32-bit daemon an absurd cap becomes "as much as this host can address", which the policy layer
    // then clamps to the operator's ceiling anyway. Lossless on 64-bit.
    requested.output_cap = output_cap.map(|c| usize::try_from(c).unwrap_or(usize::MAX));

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

/// UTF-8-lossy rendering of captured bytes, matching `ekvm run --json`.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// How long each readability check waits before re-testing whether the exec finished. The `peek`
/// itself blocks for this, so the watch costs one syscall per tick, never a spin; it only bounds how
/// stale a cancel can be, so it trades a few milliseconds of latency against wakeups on an idle
/// session.
const CANCEL_POLL: Duration = Duration::from_millis(50);

/// Run one guest command while watching the socket, returning `(result, interrupted)`.
///
/// `interrupted` means the client became readable mid-exec: either a [`Request::Cancel`] or an
/// outright hang-up. Both mean the same thing (nothing else is legal while a request is in flight),
/// so both kill the sandbox, which is what unblocks the exec: the guest dies, the vsock peer closes,
/// and `exec` returns a typed error instead of running out its wall budget with a client that is no
/// longer listening.
///
/// **Thread discipline.** The worker is scoped, so it is *always* joined: `thread::scope` cannot
/// return until it finishes. That is safe here only because `exec` is bounded on both sides, by the
/// session's wall budget and, once the kill lands, by the dead guest. A scoped thread wrapping an
/// unbounded call would be a host hang, which is why the `peek` (not a second blocking read) does
/// the watching: a reader parked on a silent client would have no such bound.
fn exec_watching_for_cancel(
    vm: &RunningVm,
    argv: &[String],
    stdin: &str,
    env: &[(String, String)],
    socket: &UnixStream,
) -> (Result<vmm::RunResult, VmmError>, bool) {
    let kill = vm.kill_handle();
    std::thread::scope(|scope| {
        // `exec_with_files` rather than `exec`: same call, but it carries the session's env. No
        // files or artifacts here, those ride the `put`/`get` verbs on their own.
        let worker = scope.spawn(|| vm.exec_with_files(argv, stdin.as_bytes(), &[], env, &[]));
        let mut interrupted = false;
        while !worker.is_finished() {
            if client_spoke(socket) {
                interrupted = true;
                // Best-effort: a kill that cannot land leaves the exec to its own wall budget,
                // which is the pre-cancel behavior, never a hang.
                if let Err(e) = kill.kill() {
                    tracing::warn!(error = %e, "cancel could not reach the sandbox");
                }
                // Nothing left to watch: the join below blocks (zero CPU) until the exec
                // returns, bounded by its wall budget. Staying in this loop would busy-spin,
                // since `client_spoke`'s 50ms block was the only thing pacing it.
                break;
            }
        }
        // Joins the worker: already-returned on the loop's natural exit, or blocking out the
        // killed exec's remaining wall budget after a cancel.
        (
            worker
                .join()
                .unwrap_or_else(|_| Err(VmmError::Vmm("exec worker panicked".to_string()))),
            interrupted,
        )
    })
}

/// Whether the client sent anything (or hung up), waiting up to [`CANCEL_POLL`].
///
/// `peek` is deliberate: it does **not** consume, so the pending line is still there for the reply
/// path to parse, and the session's framing cannot desync on a partially-arrived message.
fn client_spoke(socket: &UnixStream) -> bool {
    use std::os::fd::AsRawFd as _;

    let restore = socket.read_timeout().ok().flatten();
    let _ = socket.set_read_timeout(Some(CANCEL_POLL));
    let spoke = match nix::sys::socket::recv(
        socket.as_raw_fd(),
        &mut [0u8; 1],
        nix::sys::socket::MsgFlags::MSG_PEEK,
    ) {
        Ok(0) => true, // hung up
        Ok(_) => true, // said something, illegal while a request is in flight
        Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => false,
        Err(_) => true, // a broken socket is not a client we can still answer
    };
    let _ = socket.set_read_timeout(restore);
    spoke
}

/// A session-ending error response.
fn fatal(message: String, kind: FaultKind) -> Response {
    error(message, true, kind)
}

/// A per-request error response the session survives.
fn nonfatal(message: impl Into<String>, kind: FaultKind) -> Response {
    error(message.into(), false, kind)
}

/// Build a typed error response.
fn error(message: String, fatal: bool, kind: FaultKind) -> Response {
    Response::Error {
        message,
        fatal,
        kind,
    }
}

/// The engine's pinned error taxonomy, as the wire's. Kept a total, wildcard-free match so a new
/// `ErrorKind` variant fails the build here instead of silently becoming the wrong wire kind;
/// `a_vmm_error_kind_maps_onto_the_wire_kind` pins it.
fn wire_kind(kind: ErrorKind) -> FaultKind {
    match kind {
        ErrorKind::Infra => FaultKind::Infra,
        ErrorKind::Transport => FaultKind::Transport,
        ErrorKind::Guest => FaultKind::Guest,
    }
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
                net: None,
                allow: None,
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
                net: None,
                allow: None,
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
        // must be refused, not served a quietly smaller VM.
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
                net: None,
                allow: None,
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
                net: None,
                allow: None,
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
                net: None,
                allow: None,
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
                net: None,
                allow: None,
            },
            &Policy::default(),
        )
        .expect("valid open");
        assert!(!bare);
    }

    /// An `open` asking for a NIC and the given allowances.
    fn open_net(net: Option<bool>, allow: &[&str]) -> Request {
        Request::Open {
            vcpus: None,
            mem_mib: None,
            wall_secs: None,
            output_cap: None,
            net,
            allow: Some(allow.iter().map(|s| (*s).to_string()).collect()),
        }
    }

    #[test]
    fn open_network_resolves_the_wire_request_against_the_operators_ceilings() {
        let open = |policy: &Policy, req: &Request| open_network(req, policy);

        // The shipped default: no NIC asked for, none given.
        let sealed = open(&Policy::default(), &open_net(None, &[])).expect("no NIC is valid");
        assert!(!sealed.nic);
        assert!(sealed.egress.is_none());

        // A NIC with no allowance is deny-all, **not** observe-only. This is the one place the
        // daemon is deliberately stricter than the CLI: a local caller owns the config file, a wire
        // client does not, so handing one an unpoliced tap would be unrestricted egress on any host
        // that furnished an uplink, with `max_egress_v4` never consulted.
        let observed = open(&Policy::default(), &open_net(Some(true), &[])).expect("a bare NIC");
        assert!(observed.nic);
        let bare_policy = observed
            .egress
            .expect("a NIC over the wire is always policed");
        assert!(
            bare_policy.is_deny_all(),
            "no allowances must mean deny-all, never accept-all"
        );

        // A NIC plus allowances builds a deny-by-default policy carrying exactly those rules.
        let policed = open(
            &Policy::default(),
            &open_net(Some(true), &["1.1.1.1:443/tcp", "10.0.0.0/8"]),
        )
        .expect("a policed NIC");
        assert!(policed.nic);
        assert_eq!(policed.egress.expect("a policy was built").rules().len(), 2);
    }

    #[test]
    fn open_network_refuses_rather_than_narrowing() {
        // Allowances without a NIC: nothing to arm them on. Caught before any parsing, so the
        // message names the contradiction rather than complaining about a rule.
        let err = open_network(&open_net(None, &["1.1.1.1"]), &Policy::default())
            .expect_err("allow without net must refuse");
        assert!(err.contains("requires net"), "{err}");

        // A host that has withdrawn guest networking refuses the NIC outright.
        let no_net = Policy {
            allow_net: Some(false),
            ..Policy::default()
        };
        let err = open_network(&open_net(Some(true), &[]), &no_net)
            .expect_err("a withdrawn NIC must refuse");
        assert!(!err.is_empty(), "the refusal carries a reason");

        // A malformed rule is a typed message, not a panic and not a silently dropped rule.
        let err = open_network(&open_net(Some(true), &["not-an-ip"]), &Policy::default())
            .expect_err("a malformed rule must refuse");
        assert!(!err.is_empty(), "the refusal carries a reason");

        // Past the kernel map's fixed rule count, refused here with the cap named rather than
        // failing cryptically at attach time.
        let many: Vec<&str> =
            std::iter::repeat_n("1.1.1.1:443/tcp", MAX_POLICY_RULES + 1).collect();
        let err = open_network(&open_net(Some(true), &many), &Policy::default())
            .expect_err("over the cap must refuse");
        assert!(err.contains(&MAX_POLICY_RULES.to_string()), "{err}");
    }

    #[test]
    fn a_networked_open_is_never_served_from_the_pool() {
        // Pooled clones restore a snapshot whose NIC presence is baked in, so a session that asked
        // for one cannot be served from a pool built without one. `bare` is what gates that.
        let (_, bare) = open_limits(&open_net(Some(true), &[]), &Policy::default()).expect("valid");
        assert!(!bare, "a NIC request must not be pool-eligible");

        // Explicitly declining a NIC stays bare: it is the same VM the pool already holds.
        let (_, bare) =
            open_limits(&open_net(Some(false), &[]), &Policy::default()).expect("valid");
        assert!(
            !bare,
            "an explicit allow list (even empty) is a stated request, not a bare open"
        );
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
                    net: None,
                    allow: None,
                },
                "vcpus",
            ),
            (
                Request::Open {
                    vcpus: Some(33),
                    mem_mib: None,
                    wall_secs: None,
                    output_cap: None,
                    net: None,
                    allow: None,
                },
                "vcpus",
            ),
            (
                Request::Open {
                    vcpus: None,
                    mem_mib: Some(0),
                    wall_secs: None,
                    output_cap: None,
                    net: None,
                    allow: None,
                },
                "mem_mib",
            ),
            (
                Request::Open {
                    vcpus: None,
                    mem_mib: None,
                    wall_secs: Some(0),
                    output_cap: None,
                    net: None,
                    allow: None,
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

    #[test]
    fn a_vmm_error_kind_maps_onto_the_wire_kind() {
        // The daemon computes the engine's pinned bucket and must hand it to the client intact:
        // before this, `kind()` was computed only to derive `fatal` and then discarded, leaving an
        // SDK to string-match `message`. A drift here is a silently wrong SDK branch, not a
        // compile error, so pin all three.
        assert_eq!(wire_kind(ErrorKind::Infra), FaultKind::Infra);
        assert_eq!(wire_kind(ErrorKind::Transport), FaultKind::Transport);
        assert_eq!(wire_kind(ErrorKind::Guest), FaultKind::Guest);
    }

    #[test]
    fn fatal_and_kind_answer_different_questions() {
        // `fatal` says "is this session over", `kind` says "whose fault is it". A guest fault is
        // non-fatal (send another command); an infra fault ends the session but is not the
        // caller's to fix. Collapsing the two is exactly the bug this field fixes.
        let guest = nonfatal("no such binary", FaultKind::Guest);
        assert!(
            matches!(
                &guest,
                Response::Error {
                    fatal: false,
                    kind: FaultKind::Guest,
                    ..
                }
            ),
            "a guest fault leaves the session usable, got {guest:?}"
        );

        let infra = fatal("open sandbox: no kvm".to_string(), FaultKind::Infra);
        assert!(
            matches!(
                &infra,
                Response::Error {
                    fatal: true,
                    kind: FaultKind::Infra,
                    ..
                }
            ),
            "a failed boot ends the session but is the host's fault, got {infra:?}"
        );
    }
}
