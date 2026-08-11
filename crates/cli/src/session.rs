//! One client connection = one sandbox **session**. Mirrors `bsx shell`'s lifecycle over the wire:
//! the first message opens the sandbox (jailed by default, the daemon's launch posture, never the
//! client's to weaken), then each verb acts on it, sharing one working directory (the VM *is* the
//! session), until `close` (or a hung-up connection) tears it down.
//!
//! The session runs on an owned [`RunningVm`], not a [`Sandbox`](bsx_engine::Sandbox), so a warm clone
//! popped from the pool and a cold boot serve through the exact same code, the only difference the
//! client sees is the `pooled` flag and the boot latency.
//!
//! **The verbs.** `open` boots, `exec` runs a command, `put`/`get` write and read a working-directory
//! file through a no-op exec (injection is the engine's only file seam), `snapshot` writes a bundle and is
//! a typed refusal for a jailed session, `trace` returns the host-observed record so far, and `close`
//! ends it.
//!
//! **Untrusted input.** Bad JSON, a wrong first message, a wrong wire schema, a command that can't spawn,
//! or a mid-session hang-up is a typed [`Response::Error`] or a dropped connection, never a daemon panic.
//! The exec-fault taxonomy follows the CLI's shell: a **guest** fault is per-request and the session
//! survives it, while an **infra or transport** fault means the VM is gone, so the session ends and its VM
//! drops. Losing the whole daemon process can't leak a VM either, since the lifetime sentinel owns that.

use std::io::BufReader;
use std::num::{NonZeroU8, NonZeroU32};
use std::os::unix::net::UnixStream;
use std::sync::TryLockError;
use std::time::{Duration, Instant};

use crate::audit::RunProbes;
use crate::deadline::DeadlineStream;
use crate::policy::{Policy, Requested, parse_allow};
use bsx_engine::{BootConfig, DEFAULT_GUEST_CID, ErrorKind, Limits, RunningVm, Vm, VmmError};
use bsx_engine::{MAX_VCPUS, vcpus_supported};
use bsx_probes_loader::{EgressPolicy, MAX_POLICY_RULES, Timing};
use bsx_protocol::{
    ExecParams, FaultKind, GetParams, OpenParams, ProtocolError, PutParams, Request, Response,
    read_request, write_response,
};

use crate::metrics::{Metrics, Verb};
use crate::serve::{
    AT_CAPACITY_RETRY_MS, ResourceReservation, Server, pool_clone_limits, release_pool_clones,
    reserve_pool_clones,
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
    // The idle timeout bounds **both** directions, each with the shape its threat needs. The read half
    // needs an *absolute per-message deadline*, not a bare `set_read_timeout`: `SO_RCVTIMEO` is re-armed
    // on every byte, so a client dripping one byte per interval would reset a per-read timeout forever and
    // pin a session thread plus a `--max-sessions` slot. The write half stays a plain socket timeout,
    // since an `exec` reply can be megabytes against a small socket buffer and a client that never reads
    // would park the thread in `write_all`. Best-effort on the sockopts.
    let mut reader = BufReader::new(DeadlineStream::new(
        stream,
        server.idle_timeout,
        IDLE_DEADLINE_MSG,
    ));
    if let Some(idle) = server.idle_timeout {
        let _ = writer.set_write_timeout(Some(idle));
    }

    // The first message must be `open` (carrying the session's resource envelope). Anything else,
    // EOF, a stray verb, a malformed/wrong-schema line, ends the connection before any VM is booted.
    let open = match read_request(&mut reader) {
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
        Err(refusal) => {
            server.metrics.open_failed();
            let _ = write_response(&mut writer, &refusal.into_fatal());
            return;
        }
    };
    let net = match open_network(&open, &server.policy) {
        Ok(resolved) => resolved,
        Err(refusal) => {
            server.metrics.open_failed();
            let _ = write_response(&mut writer, &refusal.into_fatal());
            return;
        }
    };

    // The count ticket (acquired at accept) bounds *how many* sessions; this reservation bounds *how
    // much* they commit, so a memory-heterogeneous fleet cannot overcommit the host into OOM while
    // still under `--max-sessions`. Charged before boot, released on teardown by `Drop`.
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
            let _ = write_response(&mut writer, &Response::at_capacity(AT_CAPACITY_RETRY_MS));
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

    // Observation is fail-open, so a host without the eBPF caps yields a coverage-gapped record rather
    // than a refused session, but **enforcement is not**: a session that asked for an egress policy and
    // could not police the tap is a fatal refusal below. The gateway comes from the daemon's own
    // `BootConfig` rather than the wire, since whether a route out exists is the operator's posture.
    let gateway = server.base.egress.map(|e| e.gateway());
    let enforcing = net.egress.is_some();
    let mut attach_params = bsx_probes_loader::AttachParams::new(vm.vmm_pid());
    attach_params.nic = match (vm.netns(), vm.tap_name()) {
        (Some(netns), Some(tap)) => Some(bsx_probes_loader::Nic { netns, tap }),
        _ => None,
    };
    attach_params.egress = net.egress.as_ref();
    attach_params.gateway = gateway;
    let probes = match server.observ.attach(vm.name(), attach_params) {
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
                // Shut the VM down directly rather than through `end_session`, which decrements the
                // active-session gauge this path never incremented (`session_opened` is below).
                // Nothing else of `end_session`'s work applies: a session that reached enforcement
                // asked for a NIC, and a NIC request is never pool-eligible, so no clone was taken
                // and there is nothing to refill.
                if let Err(e) = vm.shutdown() {
                    tracing::debug!(error = %e, "shutdown after a failed enforcement attach");
                }
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
    if !send(&mut writer, &Response::opened(boot_ms, pooled)) {
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
        match read_request(&mut reader) {
            Ok(None) => break, // clean EOF, teardown below
            Ok(Some(Request::Close)) => {
                let _ = send(&mut writer, &Response::Closed);
                break;
            }
            Ok(Some(Request::Open(OpenParams { .. }))) => {
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
            Ok(Some(Request::Exec(ExecParams {
                argv, stdin, env, ..
            }))) => {
                server.metrics.request(Verb::Exec);
                let t0 = Instant::now();
                let (result, interrupted) = exec_watching_for_cancel(
                    &vm,
                    &argv,
                    stdin.as_deref().unwrap_or(""),
                    env.as_deref().unwrap_or(&[]),
                    &writer,
                    &reader,
                );
                if interrupted {
                    // The sandbox is gone, so the exec's own error is noise. Acknowledge only a real
                    // `cancel`, since a hang-up has nobody to read the reply. This read awaits a *new*
                    // message, so it gets a fresh deadline: the in-flight one was armed when the exec
                    // request arrived, and an exec longer than the idle budget has already spent it, which
                    // would turn the ack into a reset with the cancel line unread
                    // (`a_cancel_after_the_idle_deadline_still_gets_its_ack` pins this).
                    server.metrics.request_failed(false);
                    reader.get_mut().rearm();
                    if matches!(read_request(&mut reader), Ok(Some(Request::Cancel))) {
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
                    |r| {
                        Response::result(
                            r.exit_code,
                            lossy(&r.stdout),
                            lossy(&r.stderr),
                            ms(r.metrics.wall),
                        )
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
            Ok(Some(Request::Put(PutParams { path, content, .. }))) => {
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
                    |_| Response::put(path.clone()),
                ) {
                    break;
                }
            }
            Ok(Some(Request::Get(GetParams { path, .. }))) => {
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
                        Response::got(
                            path.clone(),
                            found.map(|a| lossy(&a.data)).unwrap_or_default(),
                            found.is_some(),
                            // Flagged, never silent: replacement characters in `content` are not
                            // the file's bytes, and only the daemon (which saw the bytes) knows.
                            found.is_some_and(|a| std::str::from_utf8(&a.data).is_err()),
                        )
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
                    Ok(dir) => Response::snapshotted(dir),
                    Err(e) => {
                        server.metrics.request_failed(true);
                        nonfatal(e.message(), e.kind())
                    }
                };
                if !send(&mut writer, &resp) {
                    break;
                }
            }
            Ok(Some(Request::Trace)) => {
                server.metrics.request(Verb::Trace);
                let timing = Timing::new(boot, total_exec_wall);
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
                        record_chain = Some(bsx_probes_loader::record_hash(&canonical));
                        Response::trace(record_to_value(&envelope))
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
                let timing = Timing::new(boot, total_exec_wall);
                // The same live, non-destructive record snapshot as `trace`, projected to the
                // model-legible summary the CLI's `--record-summary` writes.
                let resp = match probes.as_ref() {
                    Some(p) => Response::trace_summary(record_to_value(
                        &p.live_record(timing).to_summary_json(),
                    )),
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
            // `Request` is `#[non_exhaustive]`, so this arm exists and the compiler cannot tell
            // us a verb went unhandled; that check is this runtime reply instead of a build error.
            // Unreachable from the wire (an unknown `op` fails at decode), so getting
            // here means `bsx-protocol` grew a verb the daemon never wired up. Loud on purpose.
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
    result: Result<bsx_engine::RunResult, VmmError>,
    wall: Duration,
    total_exec_wall: &mut Duration,
    is_command: bool,
    to_response: impl FnOnce(&bsx_engine::RunResult) -> Response,
) -> bool {
    // Only a real `exec` counts as a guest command. `put`/`get` ride a no-op `true` purely to carry a
    // file, so folding their wall into the `guest_command` histogram or the trace `exec_wall` would
    // dilute the user-command latency signal with file-transfer overhead; `requests_total{verb}`
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

/// Boot the session's VM: a **bare** `open` (every knob defaulted) is served from the pre-warmed pool
/// when the daemon has one, and any custom resource knob (or no pool) is a cold boot with the
/// requested envelope.
///
/// The pool lock is **non-blocking** (`try_lock`) and held only for an O(1) pop of ready stock, never
/// across a `Vm::restore`. It declines on an empty, poisoned, *or contended* pool, because
/// `end_session` holds this same lock across its refill's inline restores, so a blocking `lock()`
/// would serialize every bare `open` behind that window. The trade is a `pooled: false` on the
/// transient dry/busy window instead of a stall.
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
    if bare
        && limits == pool_clone_limits()
        && let Some(pool) = &server.pool
    {
        match pool.try_lock() {
            Ok(mut p) => {
                // Pop only when there is ready stock, `Pool::take` would otherwise restore
                // inline under this lock, the exact hold-across-restore this function's doc
                // rules out. No stock ⇒ fall through to a lock-free cold boot below.
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
    let mut config = server.base.clone().with_limits(limits);
    config.enable_network = nic;
    Ok((cold_boot(config, server.isolation)?, false))
}

/// Cold-boot a `RunningVm` with the daemon's confinement posture, replicating what
/// [`Sandbox::open`](bsx_engine::Sandbox::open) does before booting, force the vsock exec channel on,
/// and set (or clear) the jail, so a cold session and a pooled one are the same shape of VM.
fn cold_boot(
    mut config: BootConfig,
    isolation: crate::policy::IsolationMode,
) -> Result<RunningVm, VmmError> {
    config.jail = if isolation.is_jailed() {
        Some(config.jail.unwrap_or_default())
    } else {
        None
    };
    if config.guest_cid.is_none() {
        config.guest_cid = Some(DEFAULT_GUEST_CID);
    }
    Vm::boot(config)
}

/// Why a `snapshot` produced no bundle. Split by fault: a disk ceiling is the operator's posture and
/// a client can retry against it once a bundle is removed, an engine refusal (a jailed session) never
/// will be, and an unreadable bundle directory is the daemon's own problem.
enum SnapshotRefusal {
    /// The daemon already holds `--max-snapshots` bundles.
    AtCeiling { held: usize },
    /// The bundle directory could not be read, so the headroom is unknown.
    Unverifiable(std::io::Error),
    /// `Vm::snapshot` refused or failed.
    Engine(VmmError),
}

impl SnapshotRefusal {
    /// The wire message, prefixed like every other `snapshot` failure.
    fn message(&self) -> String {
        match self {
            Self::AtCeiling { held } => format!(
                "snapshot: this host already holds {held} snapshot bundle(s) (operator policy: \
                 `--max-snapshots` on bsx serve); a bundle outlives its session, so remove one you \
                 have consumed to make room"
            ),
            Self::Unverifiable(e) => {
                format!("snapshot: cannot read the bundle directory to check headroom: {e}")
            }
            Self::Engine(e) => format!("snapshot: {e}"),
        }
    }

    fn kind(&self) -> FaultKind {
        match self {
            Self::AtCeiling { .. } => FaultKind::Refused,
            Self::Unverifiable(_) => FaultKind::Infra,
            Self::Engine(e) => wire_kind(e.kind()),
        }
    }
}

/// Whether another bundle fits under the ceiling. `0` is the unlimited opt-out, so it never refuses.
fn snapshot_fits(held: usize, max: usize) -> bool {
    max == 0 || held < max
}

/// Snapshot the session's VM into a fresh daemon-side bundle directory, returning its host path. A
/// jailed session is a typed refusal inside `snapshot` (its disk is in the chroot).
///
/// The ceiling is checked **before** the VM is paused: a bundle is guest RAM plus a copy of the root
/// disk and nothing on the wire reclaims one, so an unbounded `snapshot` loop is what fills the
/// scratch filesystem.
fn do_snapshot(server: &Server, vm: &RunningVm) -> Result<String, SnapshotRefusal> {
    let held = server
        .snapshot_bundles()
        .map_err(SnapshotRefusal::Unverifiable)?;
    if !snapshot_fits(held, server.max_snapshots) {
        return Err(SnapshotRefusal::AtCeiling { held });
    }
    let dir = server.next_snapshot_dir();
    // Don't pre-create the bundle dir: `Vm::snapshot` refuses a restored/jailed/device-bearing VM
    // *before* writing anything, and creates the dir itself only on its success path. Pre-creating it
    // would orphan an empty `snap-N` on every refusal, and the default daemon posture is jailed (where
    // snapshot is always a refusal), so a client looping `snapshot` would leak dirs unbounded.
    // The returned `Snapshot` is just metadata pointing at the on-disk bundle; the client gets the
    // directory (the bundle stays on the daemon host, keeping bulk bytes off this line).
    let _snapshot = vm.snapshot(&dir).map_err(SnapshotRefusal::Engine)?;
    Ok(dir.to_string_lossy().into_owned())
}

/// Tear the session down: detach the probes, shut the VM, and top the pool back up (off the hot path,
/// between sessions, the moment the [`Pool`](bsx_engine::Pool) doc reserves for restore cost).
///
/// The refill is **best-effort and non-blocking** (`try_lock`, skip if contended), so a burst of closes
/// cannot queue behind one another's restore. Stock recovers on the next uncontended close, and a bare
/// `open` that meanwhile finds the pool dry cold-boots: correct, just not pooled.
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

/// Why an `open` was refused before any VM existed, split the way the wire's fault table splits
/// (docs/daemon-protocol.md): [`Malformed`](Self::Malformed) is the client's own message (a value
/// the VMM could never boot, a contradiction like allowances without a NIC), which goes out as
/// [`FaultKind::Protocol`]; [`Policy`](Self::Policy) is a well-formed ask the operator's posture
/// declines, which goes out as [`FaultKind::Refused`], so a client branching on the table repairs
/// the right thing (its own message vs its ask).
/// `an_operator_ceiling_refusal_is_kind_refused_on_the_wire` pins the split.
#[derive(Debug, PartialEq, Eq)]
enum OpenRefusal {
    /// The client's message is wrong in itself: fix the client.
    Malformed(String),
    /// The message is fine; this host's operator declines the ask: don't retry as-is.
    Policy(String),
}

impl OpenRefusal {
    /// The human-readable reason, whichever bucket carries it. Test-only: the serving path moves
    /// the message out through [`into_fatal`](Self::into_fatal) instead of borrowing it.
    #[cfg(test)]
    fn message(&self) -> &str {
        match self {
            Self::Malformed(m) | Self::Policy(m) => m,
        }
    }

    /// The session-ending error response, carrying the bucket's wire kind.
    fn into_fatal(self) -> Response {
        let kind = match &self {
            Self::Malformed(_) => FaultKind::Protocol,
            Self::Policy(_) => FaultKind::Refused,
        };
        match self {
            Self::Malformed(m) | Self::Policy(m) => fatal(m, kind),
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
fn open_network(req: &Request, policy: &Policy) -> Result<SessionNet, OpenRefusal> {
    let Request::Open(OpenParams { net, allow, .. }) = req else {
        return Err(OpenRefusal::Malformed(
            "first message must be `open`".to_string(),
        ));
    };
    let nic = net.unwrap_or(false);
    let allows = allow.as_deref().unwrap_or(&[]);
    if !allows.is_empty() && !nic {
        return Err(OpenRefusal::Malformed(
            "allow requires net: an egress policy needs a tap to be armed on".to_string(),
        ));
    }
    // The operator's withdrawal of guest networking, checked before anything is parsed.
    policy
        .check_net(nic)
        .map_err(|e| OpenRefusal::Policy(e.daemon_message()))?;
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
        return Err(OpenRefusal::Malformed(format!(
            "too many allow rules: {} given, but the kernel egress policy holds at most \
             {MAX_POLICY_RULES}",
            allows.len()
        )));
    }
    let mut egress = EgressPolicy::deny_all();
    for spec in allows {
        let rule = parse_allow(spec).map_err(OpenRefusal::Malformed)?;
        egress = egress.allow(rule.cidr, rule.port, rule.proto);
    }
    // Containment against the operator's ceilings (`max_egress_v4`/`max_egress_v6`), the check that
    // makes a ceiling real for a caller who controls neither this process's environment nor its
    // config file.
    policy
        .check_egress(&egress)
        .map_err(|e| OpenRefusal::Policy(e.daemon_message()))?;
    Ok(SessionNet {
        nic: true,
        egress: Some(egress),
    })
}

/// Fold an [`Request::Open`]'s optional knobs onto the [`Limits`] the operator's `policy` allows,
/// validating each as a typed message (never a panic): a vCPU count the VMM accepts (1 or an even
/// number up to 32), memory and wall nonzero. Also reports whether the `open` was **bare** (every knob
/// defaulted), which decides pool eligibility; a non-`Open` first message is the caller's error too.
///
/// The daemon's policy boundary: a client controls neither this process's environment nor its
/// `.bsx.toml`, so bounding the request here is what makes an operator ceiling real. Asking past a
/// ceiling is refused, never quietly clamped.
fn open_limits(req: &Request, policy: &Policy) -> Result<(Limits, bool), OpenRefusal> {
    let Request::Open(OpenParams {
        vcpus,
        mem_mib,
        wall_secs,
        output_cap,
        net,
        allow,
        ..
    }) = req
    else {
        return Err(OpenRefusal::Malformed(
            "first message must be `open`".to_string(),
        ));
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
            return Err(OpenRefusal::Malformed(format!(
                "vcpus must be 1 or an even number in 1..={MAX_VCPUS}, got {v}"
            )));
        }
        requested.vcpus = NonZeroU8::new(*v);
    }
    if let Some(m) = mem_mib {
        requested.mem_mib = Some(
            NonZeroU32::new(*m)
                .ok_or_else(|| OpenRefusal::Malformed("mem_mib must be at least 1".to_string()))?,
        );
    }
    if let Some(s) = wall_secs {
        if *s == 0 {
            return Err(OpenRefusal::Malformed(
                "wall_secs must be at least 1".to_string(),
            ));
        }
        requested.wall_secs = Some(*s);
    }
    // Narrow the wire's fixed-width `u64` to this host's `usize`. Saturating, not wrapping: on a
    // 32-bit daemon an absurd cap becomes "as much as this host can address", which the policy layer
    // then clamps to the operator's ceiling anyway. Lossless on 64-bit.
    requested.output_cap = output_cap.map(|c| usize::try_from(c).unwrap_or(usize::MAX));

    let limits = policy
        .resolve(&requested)
        .map_err(|e| OpenRefusal::Policy(e.daemon_message()))?;
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
        // Not a gone client: the daemon's own reply outgrew what one line carries, which a run can
        // reach under an `output_cap` larger than the wire's (output dense in C0 controls escapes
        // to six bytes each, invalid UTF-8 to three). The session is intact, so answer the typed
        // flooded-output error the taxonomy already carries rather than dropping the connection and
        // leaving the client to infer why.
        Err(ProtocolError::TooLarge { limit }) => {
            let (what, kind) = oversize_reply(resp);
            tracing::warn!(
                limit,
                what,
                "reply exceeds the wire cap; answering a flooded reply"
            );
            let flooded = nonfatal(
                format!("{what} exceeds the {limit}-byte reply cap and cannot be carried"),
                kind,
            );
            match write_response(w, &flooded) {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!(error = %e, "reply failed; the client is gone");
                    false
                }
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "reply failed; the client is gone");
            false
        }
    }
}

/// What did not fit, and whose fault that is, for a reply the wire cannot carry. Named per variant
/// because `send` serves every reply: a `get` of a binary file expands 3x through [`lossy`] and
/// trips the same bound as a flooding `exec`, and telling that caller its *run's output* was too big
/// would point at the wrong thing. The record replies are host-built, so they are [`FaultKind::Infra`]
/// rather than the guest's doing.
/// `a_flooded_reply_names_what_did_not_fit` pins the pairing.
fn oversize_reply(resp: &Response) -> (&'static str, FaultKind) {
    match resp {
        Response::Result { .. } => ("the run's output", FaultKind::Guest),
        Response::Got { .. } => ("the file read back", FaultKind::Guest),
        Response::Trace { .. } | Response::TraceSummary { .. } => {
            ("the session's audit record", FaultKind::Infra)
        }
        _ => ("the reply", FaultKind::Infra),
    }
}

/// UTF-8-lossy rendering of captured bytes, matching `bsx run --json`.
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
/// **Thread discipline.** The worker is scoped, so `thread::scope` cannot return until it finishes,
/// which is safe only because `exec` is bounded on both sides: by the session's wall budget and, once
/// the kill lands, by the dead guest. A scoped thread wrapping an unbounded call would be a host hang,
/// which is why a `peek` rather than a second blocking read does the watching.
///
/// The `reader` is taken whole rather than as a "has it buffered" flag, so no caller can answer that
/// question wrongly: the peek sees only the *kernel* receive queue, and a client that wrote its
/// `cancel` in the same call as its `exec` has already had that line pulled into the `BufReader`,
/// leaving the peek blind to it. Nothing reads the reader again until this returns.
fn exec_watching_for_cancel(
    vm: &RunningVm,
    argv: &[String],
    stdin: &str,
    env: &[(String, String)],
    socket: &UnixStream,
    reader: &BufReader<DeadlineStream<UnixStream>>,
) -> (Result<bsx_engine::RunResult, VmmError>, bool) {
    let kill = vm.kill_handle();
    std::thread::scope(|scope| {
        // `exec_with_files` rather than `exec`: same call, but it carries the session's env. No
        // files or artifacts here, those ride the `put`/`get` verbs on their own.
        let worker = scope.spawn(|| vm.exec_with_files(argv, stdin.as_bytes(), &[], env, &[]));
        let mut interrupted = false;
        while !worker.is_finished() {
            if client_spoke(socket, !reader.buffer().is_empty()) {
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
///
/// `buffered` short-circuits it, because the peek only ever sees what is still in the kernel. Bytes
/// the session's `BufReader` has already pulled into userspace are just as much the client speaking,
/// and a `cancel` that arrived coalesced with its `exec` is exactly that case: the queue is empty, so
/// the peek alone would return `false` for the whole run and the kill would never land.
fn client_spoke(socket: &UnixStream, buffered: bool) -> bool {
    use std::os::fd::AsRawFd as _;

    if buffered {
        return true;
    }
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
    Response::error(message, fatal, kind)
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

/// What a blown per-message idle deadline reads as, on the shared [`DeadlineStream`].
const IDLE_DEADLINE_MSG: &str = "session message exceeded the idle deadline";

/// A [`Duration`] as whole milliseconds, saturating (a run never realistically overflows `u64` ms).
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsx_protocol::{MAX_RESPONSE_BYTES, write_request};

    #[test]
    fn the_wire_can_carry_the_default_output_cap() {
        // The enforcer for `MAX_RESPONSE_BYTES`, which lives here because `bsx-protocol` is
        // engine-free and cannot read `Limits::default()` itself. A `result` carrying the default
        // cap's worth of ordinary text must encode: bounding a reply below what the engine will
        // capture is what makes a legitimate run's own output undeliverable.
        let cap = Limits::default().output_cap;
        let encodes = |stdout: String| {
            let mut wire = Vec::new();
            write_response(&mut wire, &Response::result(0, stdout, String::new(), 5))
        };

        // 1x, ordinary text.
        let encoded = encodes("x".repeat(cap));
        assert!(
            encoded.is_ok(),
            "a result at the default output_cap ({cap} bytes) must fit the wire: {encoded:?}"
        );

        // 2x, the escape of a quote (a JSON file, a log of quoted strings). Twice the cap is *not*
        // enough on its own: the envelope pushes this the last 84 bytes over, which is why the bound
        // carries a MiB of slack rather than being exactly double.
        let encoded = encodes("\"".repeat(cap));
        assert!(
            encoded.is_ok(),
            "quote-dense output at the cap escapes to 2x and must still fit: {encoded:?}"
        );

        // What the number does *not* cover, stated as a test so the limit is measured rather than
        // assumed: a C0 control byte is valid UTF-8 and JSON-escapes to six bytes, so a cap's worth
        // of them exceeds the reply bound and is reported (`send` answers a flooded-output error)
        // rather than carried.
        assert!(
            matches!(
                encodes("\u{1}".repeat(cap)),
                Err(ProtocolError::TooLarge {
                    limit: MAX_RESPONSE_BYTES
                })
            ),
            "control-dense output at the cap expands past the reply bound by design"
        );
    }

    #[test]
    fn a_flooded_reply_names_what_did_not_fit() {
        // `send` serves every reply, so one hard-coded "the run's output" is wrong for three of
        // them. A `get` of a binary file reaches this bound through the 3x lossy expansion, and the
        // record replies reach it without the guest doing anything at all.
        for (resp, want, kind) in [
            (
                Response::result(0, String::new(), String::new(), 0),
                "the run's output",
                FaultKind::Guest,
            ),
            (
                Response::got("f".into(), String::new(), true, false),
                "the file read back",
                FaultKind::Guest,
            ),
            (
                Response::trace(serde_json::json!({})),
                "the session's audit record",
                FaultKind::Infra,
            ),
            (
                Response::trace_summary(serde_json::json!({})),
                "the session's audit record",
                FaultKind::Infra,
            ),
            (Response::opened(1, false), "the reply", FaultKind::Infra),
        ] {
            assert_eq!(oversize_reply(&resp), (want, kind), "{resp:?}");
        }
    }

    /// An `open` with the given knobs set on an otherwise-default request: the foreign-crate way
    /// to build the `#[non_exhaustive]` params struct, and the shape every future knob keeps.
    fn open_req(set: impl FnOnce(&mut OpenParams)) -> Request {
        let mut p = OpenParams::default();
        set(&mut p);
        Request::Open(p)
    }

    #[test]
    fn open_limits_folds_validates_and_flags_bare() {
        // A full open folds each knob and is not bare; the defaults stand where omitted.
        let (limits, bare) = open_limits(
            &open_req(|p| {
                p.vcpus = Some(4);
                p.mem_mib = Some(1024);
                p.wall_secs = Some(60);
                p.output_cap = Some(4096);
            }),
            &Policy::default(),
        )
        .expect("valid open");
        assert!(!bare, "a knobbed open is not pool-eligible");
        assert_eq!(limits.vcpus.get(), 4);
        assert_eq!(limits.mem_mib.get(), 1024);
        assert_eq!(limits.wall, Duration::from_secs(60));
        assert_eq!(limits.output_cap, 4096);

        let d = Limits::default();
        let (base, bare) = open_limits(&open_req(|_| {}), &Policy::default()).expect("bare open");
        assert!(bare, "a fully-defaulted open is pool-eligible");
        assert_eq!(base.vcpus, d.vcpus);
        assert_eq!(base.mem_mib, d.mem_mib);
        assert_eq!(base.wall, d.wall);
        assert_eq!(base.output_cap, d.output_cap);
    }

    #[test]
    fn the_widest_cap_the_wire_can_carry_meets_the_operator_ceiling() {
        // `output_cap` is a `u64` on the wire, so the widest ask reaches the policy layer as
        // `usize::MAX` on a 64-bit host: the ceiling has to refuse at that end, not merely at
        // values a client might plausibly type.
        let policy = Policy {
            max_output_cap: Some(Limits::default().output_cap),
            ..Policy::default()
        };
        let refusal = open_limits(&open_req(|p| p.output_cap = Some(u64::MAX)), &policy)
            .expect_err("a cap past the operator ceiling is refused, not clamped");
        assert!(
            matches!(&refusal, OpenRefusal::Policy(m) if m.contains("--max-output-cap")),
            "a ceiling is a policy refusal naming the flag that set it: {refusal:?}"
        );

        // Without the ceiling the same ask resolves, which is what makes the flag the only thing
        // standing between that number and `charge`'s `captured + add > max` never being true.
        let (limits, _) = open_limits(
            &open_req(|p| p.output_cap = Some(u64::MAX)),
            &Policy::default(),
        )
        .expect("no ceiling, no refusal");
        assert_eq!(limits.output_cap, usize::MAX);
    }

    #[test]
    fn the_snapshot_ceiling_refuses_at_the_bound_and_zero_is_unlimited() {
        // A bundle is guest RAM plus a copy of the root disk and nothing on the wire reclaims one,
        // so this ceiling is what stands between a `snapshot` loop and a full scratch filesystem.
        assert!(snapshot_fits(0, 4), "an empty daemon has room");
        assert!(snapshot_fits(3, 4), "one below the ceiling still fits");
        assert!(
            !snapshot_fits(4, 4),
            "at the ceiling is refused, not the one past it"
        );
        assert!(!snapshot_fits(9, 4), "and so is anything beyond it");
        assert!(
            snapshot_fits(usize::MAX, 0),
            "`0` is the unlimited opt-out, as it is for --max-sessions and --idle-timeout"
        );
    }

    #[test]
    fn a_snapshot_refusal_names_its_fault_and_the_flag_that_set_it() {
        let at_ceiling = SnapshotRefusal::AtCeiling { held: 16 };
        assert_eq!(
            at_ceiling.kind(),
            FaultKind::Refused,
            "an operator posture the client can retry against, not a broken daemon"
        );
        let msg = at_ceiling.message();
        assert!(msg.contains("--max-snapshots"), "{msg}");
        assert!(
            msg.contains("16"),
            "the message says how many are held: {msg}"
        );

        // The daemon's own failure to read its bundle directory is infra, and it refuses rather
        // than assuming headroom it could not verify.
        assert_eq!(
            SnapshotRefusal::Unverifiable(std::io::Error::other("boom")).kind(),
            FaultKind::Infra
        );
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
            &open_req(|p| {
                p.vcpus = Some(16);
            }),
            &policy,
        )
        .expect_err("16 vCPUs is past the operator's ceiling");
        assert!(
            err.message().contains("vcpus") && err.message().contains('2'),
            "the refusal names the knob and the bound: {}",
            err.message()
        );
        assert!(
            matches!(err, OpenRefusal::Policy(_)),
            "a ceiling is the operator declining (wire kind `refused`), not a malformed message"
        );

        // Under the ceiling still works, and the pool-eligibility signal is unaffected by policy.
        let (limits, bare) = open_limits(
            &open_req(|p| {
                p.vcpus = Some(2);
            }),
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
        let (limits, bare) =
            open_limits(&open_req(|_| {}), &policy).expect("bare open under policy");
        assert_eq!(limits.mem_mib.get(), 768, "the house default applied");
        assert!(bare, "policy does not make a bare open non-bare");
    }

    #[test]
    fn a_single_knob_makes_the_open_non_bare() {
        // Even one custom knob means the pool's default-profile clone can't serve it, cold boot.
        let (_, bare) = open_limits(
            &open_req(|p| {
                p.mem_mib = Some(512);
            }),
            &Policy::default(),
        )
        .expect("valid open");
        assert!(!bare);
    }

    /// An `open` asking for a NIC and the given allowances.
    fn open_net(net: Option<bool>, allow: &[&str]) -> Request {
        open_req(|p| {
            p.net = net;
            p.allow = Some(allow.iter().map(|s| (*s).to_string()).collect());
        })
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
        // message names the contradiction rather than complaining about a rule. The client's own
        // contradiction, so the `Malformed` bucket (wire kind `protocol`).
        let err = open_network(&open_net(None, &["1.1.1.1"]), &Policy::default())
            .expect_err("allow without net must refuse");
        assert!(err.message().contains("requires net"), "{}", err.message());
        assert!(matches!(err, OpenRefusal::Malformed(_)));

        // A host that has withdrawn guest networking refuses the NIC outright: the operator
        // declining a well-formed ask, so the `Policy` bucket (wire kind `refused`).
        let no_net = Policy {
            allow_net: Some(false),
            ..Policy::default()
        };
        let err = open_network(&open_net(Some(true), &[]), &no_net)
            .expect_err("a withdrawn NIC must refuse");
        assert!(!err.message().is_empty(), "the refusal carries a reason");
        assert!(matches!(err, OpenRefusal::Policy(_)));

        // A malformed rule is a typed message, not a panic and not a silently dropped rule.
        let err = open_network(&open_net(Some(true), &["not-an-ip"]), &Policy::default())
            .expect_err("a malformed rule must refuse");
        assert!(!err.message().is_empty(), "the refusal carries a reason");
        assert!(matches!(err, OpenRefusal::Malformed(_)));

        // Past the kernel map's fixed rule count, refused here with the cap named rather than
        // failing cryptically at attach time. An engine limit the client can fix by sending fewer
        // rules, not an operator posture: `Malformed`.
        let many: Vec<&str> =
            std::iter::repeat_n("1.1.1.1:443/tcp", MAX_POLICY_RULES + 1).collect();
        let err = open_network(&open_net(Some(true), &many), &Policy::default())
            .expect_err("over the cap must refuse");
        assert!(
            err.message().contains(&MAX_POLICY_RULES.to_string()),
            "{}",
            err.message()
        );
        assert!(matches!(err, OpenRefusal::Malformed(_)));

        // An egress rule outside the operator's ceiling: well-formed, declined, `Policy`.
        let ceiling = Policy {
            max_egress_v4: vec![
                bsx_probes_loader::Ipv4Cidr::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 8)
                    .expect("valid /8"),
            ],
            ..Policy::default()
        };
        let err = open_network(&open_net(Some(true), &["192.168.1.1"]), &ceiling)
            .expect_err("outside the egress ceiling must refuse");
        assert!(matches!(err, OpenRefusal::Policy(_)));
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
                open_req(|p| {
                    p.vcpus = Some(0);
                }),
                "vcpus",
            ),
            (
                open_req(|p| {
                    p.vcpus = Some(33);
                }),
                "vcpus",
            ),
            (
                open_req(|p| {
                    p.mem_mib = Some(0);
                }),
                "mem_mib",
            ),
            (
                open_req(|p| {
                    p.wall_secs = Some(0);
                }),
                "wall_secs",
            ),
        ] {
            let err =
                open_limits(&req, &Policy::default()).expect_err("illegal value must be rejected");
            assert!(
                err.message().contains(needle),
                "error should name {needle}: {}",
                err.message()
            );
            // A value the VMM could never boot is the client's own message, never a policy call.
            assert!(matches!(err, OpenRefusal::Malformed(_)));
        }
    }

    #[test]
    fn a_non_open_first_message_is_rejected() {
        let err =
            open_limits(&Request::Close, &Policy::default()).expect_err("close is not an open");
        assert!(err.message().contains("open"), "{}", err.message());
        assert!(matches!(err, OpenRefusal::Malformed(_)));
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
        let mut reader = BufReader::new(DeadlineStream::new(
            server_end,
            Some(budget),
            IDLE_DEADLINE_MSG,
        ));

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
        let result = read_request(&mut reader);
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
    fn a_cancel_coalesced_with_its_exec_is_still_noticed() {
        use std::io::Write as _;

        // A pipelining client writes `exec` and `cancel` in one `write_all`, which is legal. Reading
        // the exec pulls *both* lines into the `BufReader`, so the cancel is sitting in userspace
        // and the kernel receive queue is empty.
        let (client, server_end) = UnixStream::pair().expect("socketpair");
        let peer = server_end
            .try_clone()
            .expect("the second handle `serve` peeks on");
        let mut reader = BufReader::new(DeadlineStream::new(server_end, None, IDLE_DEADLINE_MSG));

        let mut both = Vec::new();
        write_request(
            &mut both,
            &Request::Exec(ExecParams::new(vec!["sleep".into(), "infinity".into()])),
        )
        .expect("encode the exec");
        write_request(&mut both, &Request::Cancel).expect("encode the cancel");
        (&client)
            .write_all(&both)
            .expect("one write, both messages");

        assert!(
            matches!(read_request(&mut reader), Ok(Some(Request::Exec(_)))),
            "the exec arrives first"
        );
        assert!(
            !reader.buffer().is_empty(),
            "the cancel is buffered in userspace, which is what sets this case up"
        );
        // The defect, asserted rather than described: with only the peek to go on, the watcher sees
        // an idle socket for the whole exec and the kill never lands.
        assert!(
            !client_spoke(&peer, false),
            "precondition: the peek cannot see a line the reader already took"
        );
        assert!(
            client_spoke(&peer, !reader.buffer().is_empty()),
            "asking the reader too is what makes a pipelined cancel land"
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
            IDLE_DEADLINE_MSG,
        ));

        let sender = std::thread::spawn(move || {
            let mut client = client;
            write_request(&mut client, &Request::Trace).expect("first message");
            // Idle 150ms: inside the first budget's leftover only if the deadline were cumulative;
            // well inside a *fresh* 200ms budget after rearm.
            std::thread::sleep(Duration::from_millis(150));
            write_request(&mut client, &Request::Close).expect("second message");
        });

        let first = read_request(&mut reader).expect("first parses");
        assert_eq!(first, Some(Request::Trace));
        reader.get_mut().rearm();
        let second = read_request(&mut reader).expect("second parses after rearm");
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
        // discarding it after deriving `fatal` would leave a client string-matching `message`.
        // A drift here is a silently wrong client branch, not a
        // compile error, so pin all three.
        assert_eq!(wire_kind(ErrorKind::Infra), FaultKind::Infra);
        assert_eq!(wire_kind(ErrorKind::Transport), FaultKind::Transport);
        assert_eq!(wire_kind(ErrorKind::Guest), FaultKind::Guest);
    }

    #[test]
    fn fatal_and_kind_answer_different_questions() {
        // `fatal` says "is this session over", `kind` says "whose fault is it". A guest fault is
        // non-fatal (send another command); an infra fault ends the session but is not the
        // caller's to fix. Collapsing the two loses that distinction.
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
