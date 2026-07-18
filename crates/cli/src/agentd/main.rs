//! `agentd`, the long-lived driver **daemon**: it exposes the sandbox lifecycle and the full
//! [wire API](agentd_protocol) (`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`close`) over a **unix
//! socket**, so a local client drives microVMs without linking the `agent-vmm` library itself. This
//! is the engine's programmatic interface: a thin host of the same public API the CLI and embedders
//! use, **still engine, not platform**, no tenancy, no auth, no billing, no scheduler (those are the
//! hoster's, above this).
//!
//! **Shape.** One connection is one sandbox **session** (the VM *is* the session, decision 019),
//! served on its own thread, synchronous, no async runtime, matching the driver's posture. The wire
//! is the versioned newline-JSON contract in the shared [`agentd_protocol`] crate (decision 034);
//! the confinement posture (jailed by default) is the daemon's launch choice, never a client's.
//! `tracing` goes to **stderr** (operational logs); the socket carries only the protocol.
//!
//! **Fast `open`.** With `--prewarm N` the daemon keeps a [`Pool`] of pre-warmed
//! clones and serves a bare-default `open` from it in milliseconds; a custom resource profile (or no
//! pool) cold-boots. Building the pool needs KVM (and root, for jailed clones); it is **fail-open**,
//! a host that can't build it logs one warning and every session cold-boots.
//!
//! **Observable by the hoster.** Logs are structured `tracing` lines on stderr (human text by
//! default, JSON with `--log-json` for a log shipper), and `--metrics ADDR` serves a Prometheus
//! text-exposition endpoint ([`metrics`]) the hoster scrapes, sessions, verbs, faults, boot and
//! exec latency histograms, pool stock. The daemon exposes its numbers; dashboards and alerting are
//! the hoster's (engine, not platform).
//!
//! **Access control is the hoster's.** The daemon does no authentication (a recorded non-goal): who
//! may connect is governed by the filesystem permissions on the socket and its directory, which the
//! deploying hoster sets. Place the socket where only trusted local clients can reach it. The same
//! goes for the metrics endpoint: it serves plain HTTP with no auth, so bind it to loopback (or a
//! private scrape network), never a public interface.
//!
//! **Bounded concurrency.** Every session is a full microVM (guest RAM, a tap, a cgroup), so the
//! daemon bounds its own core resource: at the `--max-sessions` ceiling a new connection gets a
//! typed "at capacity" refusal *before* any VM is booted, instead of walking the host into
//! OOM/KVM/fd exhaustion. The ceiling is the hoster's knob (`0` = unlimited); admission control is
//! engine self-protection, not tenancy (still no auth, no scheduling, no queueing).
//!
//! **Teardown is crash-safe, shutdown is prompt.** A live session's VM drops when its connection
//! ends, tearing the microVM down; and losing the whole daemon process (SIGKILL, OOM) can't leak a
//! VM either, the lifetime sentinel (decision 014) reaps it, and the next start clears a stale
//! socket file. A supervisor's SIGTERM/SIGINT is handled: the daemon logs, unlinks its socket, and
//! exits cleanly (in-flight sessions end crash-consistently, their VMs reaped by the sentinel); a
//! graceful *drain* of in-flight sessions remains a later ops concern.
#![forbid(unsafe_code)]

mod metrics;
mod session;

use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agent_cli::audit::Observability;
use agent_vmm::{BootConfig, Limits, Pool, Sandbox, VmmError, DEFAULT_GUEST_CID};
use clap::Parser;

use crate::metrics::Metrics;

/// Exit code for an operational failure (a bad socket path, a bind failure): conventional "2", the
/// same convention the `agent` CLI and the guest agent use.
const EXIT_OPERATIONAL: u8 = 2;

/// `agentd`, drive the sandbox lifecycle over a unix socket.
#[derive(Parser)]
#[command(
    name = "agentd",
    about = "the agent driver daemon: run sandboxes over a unix socket"
)]
struct Cli {
    /// The unix socket to listen on. Its directory's permissions are the access control (the daemon
    /// does no auth, a recorded non-goal), so place it where only trusted local clients can reach.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,
    /// Keep a pre-warmed pool of this many clones for fast `open`. A bare-default `open` pops a
    /// warm clone in milliseconds; a custom profile cold-boots. Fail-open: if the pool can't be
    /// built (no KVM, no root for jailed clones), every session cold-boots. Omit (or `0`) to disable.
    #[arg(long, value_name = "N")]
    prewarm: Option<usize>,
    /// Run every session's VMM without the jailer. The default is confined (jailed, decision 015,
    /// needs real root + the `jailer` binary); this is the daemon-wide opt-out for hosts that can't
    /// jail. A **client never chooses this**, the confinement posture is the hoster's, set here.
    #[arg(long)]
    unjailed: bool,
    /// Serve a Prometheus metrics endpoint at this address (e.g. `127.0.0.1:9920`) for the hoster to
    /// scrape (`GET /metrics`). Plain HTTP, no auth, bind loopback or a private scrape network. Off
    /// when omitted.
    #[arg(long, value_name = "ADDR")]
    metrics: Option<SocketAddr>,
    /// Emit stderr logs as JSON lines (for a log shipper) instead of human-readable text. Also
    /// enabled by `AGENT_LOG_FORMAT=json`.
    #[arg(long)]
    log_json: bool,
    /// Log filter for stderr (overrides `AGENT_LOG`), e.g. `info`, `debug`.
    #[arg(long, value_name = "FILTER")]
    log: Option<String>,
    /// The ceiling on concurrent sessions. Every session is a full microVM (guest RAM, a tap, a
    /// cgroup), so the daemon bounds its own core resource: at the ceiling a new connection is
    /// refused with a typed "at capacity" error *before* any VM boots, rather than exhausting the
    /// host. Size it to the host (sessions × guest memory must fit in RAM); `0` means unlimited.
    #[arg(long, value_name = "N", default_value_t = 16)]
    max_sessions: usize,
    /// Drop a session after this many seconds with **no request** from the client, so a wedged or
    /// forgotten connection can't pin a microVM and a `--max-sessions` slot forever (the idle half of
    /// the same capacity guarantee the ceiling gives). Applies to the wait for the first `open` too.
    /// A client streaming requests keeps resetting it; `0` disables the timeout. Default 300 (5 min).
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    idle_timeout: u64,
}

/// The daemon's shared context, handed by `Arc` to every session thread: the env-layered base config
/// each session boots from, the launch-time confinement posture, the process-wide host-side probes
/// (loaded once, one `sched_switch` meter, one tracer, the bounded-overhead shared model), the
/// optional pre-warmed pool, and a monotonic source of snapshot-bundle directories.
struct Server {
    /// The env-layered base config; a session's `open` folds its resource knobs on top.
    base: BootConfig,
    /// `true` unless launched `--unjailed`, the confinement posture no client can weaken.
    jailed: bool,
    /// The shared host-side probes, loaded once, attached per session (fail-open) for `trace`.
    observ: Observability,
    /// The pre-warmed pool for fast `open`, or `None` (cold boots) when `--prewarm` was off or the
    /// pool could not be built. Behind a `Mutex`: `take`/`refill` need `&mut`, and sessions run on
    /// many threads.
    pool: Option<Mutex<Pool>>,
    /// Where `snapshot` bundle directories are created (per-daemon, so concurrent daemons don't
    /// collide), each named by the monotonic [`snapshot_seq`](Self::snapshot_seq).
    snapshot_base: PathBuf,
    /// The next snapshot-bundle sequence number, so concurrent `snapshot`s land in distinct dirs.
    snapshot_seq: AtomicU64,
    /// The metric registry the session threads bump; `Arc` so the metrics endpoint thread renders it
    /// independently of the `Server` borrow.
    metrics: Arc<Metrics>,
    /// The `--max-sessions` ceiling (`0` = unlimited), enforced by [`SessionTicket::acquire`].
    max_sessions: usize,
    /// The per-session idle timeout (`None` = disabled), from `--idle-timeout`: a read that waits this
    /// long with no client bytes ends the session, freeing its VM and `--max-sessions` slot.
    idle_timeout: Option<std::time::Duration>,
    /// Live sessions right now, the counter the admission check compares against the ceiling.
    /// Incremented by a successful [`SessionTicket::acquire`], decremented by the ticket's `Drop`.
    active_sessions: AtomicUsize,
}

impl Server {
    /// A fresh, unique directory for the next `snapshot` bundle. Monotonic across threads, so two
    /// concurrent sessions snapshotting at once can't target the same directory.
    fn next_snapshot_dir(&self) -> PathBuf {
        let n = self.snapshot_seq.fetch_add(1, Ordering::Relaxed);
        self.snapshot_base.join(format!("snap-{n}"))
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let log_json = cli.log_json
        || std::env::var("AGENT_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    init_tracing(cli.log.as_deref(), log_json);

    // The env-layered base config every session boots from (`with_limits` folds each `open`'s knobs
    // on top). The daemon has no `.agent.toml` cwd discovery, that's a CLI-in-a-project convenience;
    // a daemon's config is its own flags + environment. Computed up front so the signal handler and
    // the startup sweep both know where this daemon's guest-memory-sized bundle dirs live.
    let base = BootConfig::from_env();
    let jailed = !cli.unjailed;

    let listener = match bind(&cli.socket) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    // A supervisor's stop signal gets a prompt, clean exit: log, unlink the socket (so a restart
    // never depends on the stale-path heuristic), remove this daemon's bundle dirs (else a
    // `--prewarm` restart leaks a guest-RAM-sized bundle each time), and exit 0. In-flight sessions
    // end crash-consistently; their VMs are reaped by the lifetime sentinel (decision 014).
    install_signal_handler(
        cli.socket.clone(),
        vec![
            prewarm_dir(&base.scratch_dir),
            snapshots_dir(&base.scratch_dir),
        ],
    );
    // Reclaim bundle dirs a *crashed* prior daemon (SIGKILL/OOM, no handler) leaked, before this one
    // adds its own. Best-effort, this-user, dead-pid only.
    sweep_stale_agentd_bundles(&base.scratch_dir);
    // Bind the metrics endpoint *before* any session can be served, so a scrape target asked for
    // explicitly either works or the daemon refuses to start, an operational surface the hoster
    // requested must not silently be absent (the same posture as `--allow`'s enforcement refusal).
    let metrics_listener = match cli.metrics.map(TcpListener::bind).transpose() {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "cannot bind the metrics endpoint; refusing to start");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    // The endpoint is plain HTTP with no auth (the doc says bind loopback or a private scrape
    // network); a public bind may be a deliberate private-network choice, so warn, don't refuse,
    // a fat-fingered `0.0.0.0` must at least be visible in the startup log.
    if let Some(addr) = cli.metrics {
        if !addr.ip().is_loopback() {
            tracing::warn!(
                %addr,
                "metrics endpoint bound to a non-loopback address; it serves plain HTTP with no \
                 auth, make sure this is a private scrape network"
            );
        }
    }
    // Snapshot bundles are guest-memory-sized, so they live under the engine's own scratch knob
    // (`AGENT_SCRATCH_DIR`, `BootConfig::scratch_dir`), not a hardcoded `$TMPDIR`: on a host where
    // `/tmp` is a size-limited tmpfs the operator points scratch at real disk once and every
    // large artifact (boot scratch, prewarm, snapshots) follows.
    let snapshot_base = snapshots_dir(&base.scratch_dir);
    let pool = build_optional_pool(cli.prewarm, &base, jailed);
    let server = Arc::new(Server {
        base,
        jailed,
        observ: Observability::load(),
        pool,
        snapshot_base,
        snapshot_seq: AtomicU64::new(0),
        metrics: Arc::new(Metrics::default()),
        max_sessions: cli.max_sessions,
        idle_timeout: (cli.idle_timeout > 0)
            .then(|| std::time::Duration::from_secs(cli.idle_timeout)),
        active_sessions: AtomicUsize::new(0),
    });
    if let Some(metrics_listener) = metrics_listener {
        spawn_metrics(metrics_listener, &server);
    }
    tracing::info!(
        socket = %cli.socket.display(),
        jailed,
        prewarmed = server.pool.is_some(),
        metrics = cli.metrics.as_ref().map(tracing::field::display),
        "agentd listening"
    );

    // Accept forever, one thread per connection. A daemon runs until its supervisor stops it; the
    // sentinel guarantees no VM leak on process death, so there is no accept-loop exit to manage.
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => spawn_session(stream, Arc::clone(&server)),
            // A transient accept error must not end the daemon, log and keep serving.
            Err(e) => tracing::warn!(error = %e, "accept failed"),
        }
    }
    ExitCode::SUCCESS
}

/// Serve the metrics endpoint on its own thread, sampling the pool's live stock per scrape. The
/// thread runs for the daemon's whole life (the endpoint has no drain to manage, crash-only, like
/// the sessions).
fn spawn_metrics(listener: TcpListener, server: &Arc<Server>) {
    let registry = Arc::clone(&server.metrics);
    let sampled = Arc::clone(server);
    let spawned = std::thread::Builder::new()
        .name("agentd-metrics".into())
        .spawn(move || {
            metrics::serve(listener, registry, move || {
                // `try_lock`, never a blocking acquire (16-C): the scrape must not stall behind a
                // session's pool refill/restore. On contention (or poison) the sample is omitted for
                // this scrape, `agentd_pool_ready` is momentarily absent, the same absent-not-zero
                // shape the endpoint already uses for a daemon with no pool, rather than the
                // visibility surface freezing under the load it exists to report on.
                sampled
                    .pool
                    .as_ref()
                    .and_then(|p| p.try_lock().ok())
                    .map(|pool| u64::try_from(pool.ready()).unwrap_or(u64::MAX))
            })
        });
    if let Err(e) = spawned {
        // The listener was bound (the hoster's ask is satisfiable); a spawn failure here is the
        // same transient-resource class as a session-thread failure, log loudly, keep serving.
        tracing::error!(error = %e, "cannot spawn the metrics thread; endpoint will not answer");
    }
}

/// Serve one accepted connection on its own thread, behind the `--max-sessions` admission check:
/// at the ceiling the client gets a typed "at capacity" refusal *before* any VM resource is
/// committed (the whole point of the cap; thread-spawn EAGAIN would fire only after the boot was
/// already under way). A thread-spawn failure (EAGAIN under load) drops just that connection,
/// never the daemon.
fn spawn_session(stream: UnixStream, server: Arc<Server>) {
    let Some(ticket) = SessionTicket::acquire(&server) else {
        refuse_at_capacity(stream, &server);
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("agentd-session".into())
        .spawn(move || {
            // The ticket lives exactly as long as the session: its `Drop` releases the slot
            // however `serve` ends (clean close, client hang-up, or a panic unwinding).
            let _ticket = ticket;
            session::serve(stream, &server);
        });
    if let Err(e) = spawned {
        // The ticket was moved into the failed closure and dropped with it: the slot is free.
        tracing::warn!(error = %e, "cannot spawn a session thread; dropping the connection");
    }
}

/// One admitted session's slot in the `--max-sessions` budget, released on `Drop` (RAII, so a
/// session can't leak its slot on any exit path).
struct SessionTicket(Arc<Server>);

impl SessionTicket {
    /// Take a slot if the daemon is under its ceiling (`None` at capacity). Lock-free CAS loop so
    /// two racing accepts can never over-admit past the ceiling; `max_sessions == 0` is unlimited.
    fn acquire(server: &Arc<Server>) -> Option<Self> {
        if server.max_sessions == 0 {
            server.active_sessions.fetch_add(1, Ordering::Relaxed);
            return Some(Self(Arc::clone(server)));
        }
        let mut current = server.active_sessions.load(Ordering::Relaxed);
        loop {
            if current >= server.max_sessions {
                return None;
            }
            match server.active_sessions.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self(Arc::clone(server))),
                Err(now) => current = now,
            }
        }
    }
}

impl Drop for SessionTicket {
    fn drop(&mut self) {
        self.0.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Refuse a connection that arrived past the `--max-sessions` ceiling: one typed fatal
/// [`agentd_protocol::Response::Error`] (the client's `open` reads it as the reply), then the
/// connection drops. The write is timeout-bounded so a stalled client can't park the accept loop,
/// and best-effort, the refusal itself must never take the daemon down.
fn refuse_at_capacity(stream: UnixStream, server: &Server) {
    tracing::warn!(
        max_sessions = server.max_sessions,
        "refusing a connection: at the session ceiling"
    );
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
    let mut stream = stream;
    let refusal = agentd_protocol::Response::Error {
        message: format!(
            "at capacity: {} session(s) live, the daemon's --max-sessions ceiling; retry later \
             or raise the ceiling",
            server.max_sessions
        ),
        fatal: true,
    };
    let _ = agentd_protocol::write_message(&mut stream, &refusal);
}

/// This daemon's prewarm snapshot bundle dir (guest-memory-sized), under the engine's scratch knob.
fn prewarm_dir(scratch: &Path) -> PathBuf {
    scratch.join(format!("agentd-prewarm-{}", std::process::id()))
}

/// This daemon's session-snapshot bundle dir (holds each session's `snap-N`), under the scratch knob.
fn snapshots_dir(scratch: &Path) -> PathBuf {
    scratch.join(format!("agentd-snapshots-{}", std::process::id()))
}

/// The effective uid this process runs as, so the startup sweep only reclaims bundle dirs *it* owns
/// (from a prior crashed daemon of the same user), never another user's on a shared scratch base.
fn own_euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let uid = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    uid.split_whitespace().nth(1)?.parse().ok()
}

/// Reclaim this-user `agentd-prewarm-<pid>` / `agentd-snapshots-<pid>` bundle dirs left by **dead**
/// prior daemons: their guest-memory-sized files are pure leak once the daemon that owned them is
/// gone (SIGKILL/OOM skips the signal-handler cleanup). Best-effort, per-entry: a dir we can't stat
/// or remove is logged and skipped. Skips our own pid and any live pid (a concurrently-running
/// daemon of the same user). A dead daemon's pid is genuinely absent from `/proc` (it's not our
/// unreaped child, so no zombie fools this), so existence is a sound liveness check here.
fn sweep_stale_agentd_bundles(scratch: &Path) {
    use std::os::unix::fs::MetadataExt as _;
    let Some(me) = own_euid() else {
        return; // without our euid we can't prove ownership; skip rather than risk a wrong delete
    };
    let Ok(entries) = std::fs::read_dir(scratch) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(pid) = name
            .strip_prefix("agentd-prewarm-")
            .or_else(|| name.strip_prefix("agentd-snapshots-"))
        else {
            continue; // not a bundle dir this daemon mints
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() {
            continue; // never our own live dirs
        }
        if entry.metadata().map(|m| m.uid()).ok() != Some(me) {
            continue; // another user's residue (their daemon's sweep, not ours)
        }
        if Path::new(&format!("/proc/{pid}")).exists() {
            continue; // a live daemon still owns it
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => tracing::info!(
                dir = %entry.path().display(),
                "swept a stale agentd bundle dir from a dead daemon"
            ),
            Err(e) => tracing::warn!(
                dir = %entry.path().display(),
                error = %e,
                "could not sweep a stale agentd bundle dir"
            ),
        }
    }
}

/// Install the SIGTERM/SIGINT handler: log, unlink the socket, remove this daemon's own bundle dirs
/// (`cleanup_dirs`, guest-memory-sized), then exit 0 (a clean stop for a supervisor). Best-effort, a
/// host where the handler can't be installed keeps the crash-only behavior (the sentinel still reaps
/// VMs; the next start clears the stale socket and the startup sweep reclaims the leaked bundle dirs).
fn install_signal_handler(socket: PathBuf, cleanup_dirs: Vec<PathBuf>) {
    let spawned = std::thread::Builder::new()
        .name("agentd-signals".into())
        .spawn(move || {
            let mut signals = match signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGTERM,
                signal_hook::consts::SIGINT,
            ]) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "cannot install the signal handler; shutdown stays crash-only");
                    return;
                }
            };
            if let Some(signal) = signals.forever().next() {
                tracing::info!(signal, "shutting down: removing the socket and bundle dirs, exiting");
                // In-flight sessions end crash-consistently (their VMs reaped by the sentinel);
                // the unlink is what a plain process kill would leave behind, and the bundle dirs
                // are guest-memory-sized files a plain kill would leak.
                let _ = std::fs::remove_file(&socket);
                for dir in &cleanup_dirs {
                    let _ = std::fs::remove_dir_all(dir);
                }
                std::process::exit(0);
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "cannot spawn the signal thread; shutdown stays crash-only");
    }
}

/// Build the pre-warmed pool when `--prewarm N` (N > 0) asked for one, degrading any failure to
/// `None` (every session then cold-boots), a warning, never a refusal to start, since a pool is a
/// latency optimization, not a correctness requirement.
fn build_optional_pool(
    prewarm: Option<usize>,
    base: &BootConfig,
    jailed: bool,
) -> Option<Mutex<Pool>> {
    let target = prewarm?;
    if target == 0 {
        return None;
    }
    match build_pool(base, jailed, target) {
        Ok(pool) => {
            tracing::info!(target, "pre-warmed pool ready");
            Some(Mutex::new(pool))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                target,
                "could not build the pre-warmed pool; sessions will cold-boot"
            );
            None
        }
    }
}

/// Prewarm the pool: boot an **unjailed** source with the default profile (a jailed disk can't be
/// snapshotted, it lives in the chroot), snapshot it, then restore `target` clones under the
/// daemon's confinement posture. The clones carry the default profile, which is why only a
/// bare-default `open` is pool-eligible (`session::boot_session_vm`).
fn build_pool(base: &BootConfig, jailed: bool, target: usize) -> Result<Pool, VmmError> {
    // Snapshot into a per-daemon dir under the engine's scratch knob (`AGENT_SCRATCH_DIR`), the same
    // routing as the session bundles: guest-memory-sized files belong where the operator pointed
    // scratch, never a hardcoded `$TMPDIR`. On a **successful** build the pool's clones reference this
    // bundle, so it must live until shutdown (the signal handler / startup sweep reclaim it); on any
    // **failure** below, nothing references it, so remove it rather than leak a guest-RAM-sized bundle.
    let snap_dir = prewarm_dir(&base.scratch_dir);
    std::fs::create_dir_all(&snap_dir)
        .map_err(|e| VmmError::Vmm(format!("create prewarm dir {}: {e}", snap_dir.display())))?;
    let built = build_pool_from(base, jailed, target, &snap_dir);
    if built.is_err() {
        let _ = std::fs::remove_dir_all(&snap_dir);
    }
    built
}

/// The snapshot + restore steps of [`build_pool`], split out so the caller can reclaim `snap_dir` on
/// any error without a cleanup branch per `?`.
fn build_pool_from(
    base: &BootConfig,
    jailed: bool,
    target: usize,
    snap_dir: &Path,
) -> Result<Pool, VmmError> {
    // 1. An unjailed prewarm source running only the default profile (no untrusted code, the source
    //    is the daemon's own, its clones are where sessions run).
    let source_config = base.clone().with_limits(Limits::default());
    let source = Sandbox::open_unjailed(source_config)?;

    // 2. Snapshot it into the per-daemon bundle dir the caller prepared.
    let snapshot = source.snapshot(snap_dir)?;
    // The source has served its purpose (its state is captured); tear it down before the pool fills.
    // Best-effort (16-D): the snapshot is the artifact that matters and it is already on disk, so a
    // teardown error must not discard a working pool. `Drop` reclaims the source either way.
    if let Err(e) = source.shutdown() {
        tracing::warn!(error = %e, "prewarm source teardown reported an error; snapshot already captured");
    }

    // 3. Restore `target` clones under the daemon's confinement posture (jailed by default). The
    //    clones inherit the snapshot's vsock, so sessions exec over it exactly like a cold boot.
    let mut pool_config = base.clone().with_limits(Limits::default());
    pool_config.jail = if jailed {
        Some(pool_config.jail.unwrap_or_default())
    } else {
        None
    };
    if pool_config.guest_cid.is_none() {
        pool_config.guest_cid = Some(DEFAULT_GUEST_CID);
    }
    Pool::new(snapshot, pool_config, target)
}

/// Bind the listener at `socket`, clearing a **stale** socket file first but refusing to clobber a
/// **live** daemon. If the path exists, a successful connect means another `agentd` is already
/// listening (a typed refusal); a refused connect means the file is leftover from a dead daemon, so
/// remove it and bind. The parent directory must already exist (the hoster's to create, with the
/// permissions that gate access).
fn bind(socket: &Path) -> Result<UnixListener, String> {
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            return Err(format!(
                "another agentd is already listening on {}",
                socket.display()
            ));
        }
        // Nothing answered: a stale socket from a dead daemon. Reclaim it (own-your-scratch-path,
        // the same discipline as the guest agent's unix listener and the driver's scratch dirs).
        std::fs::remove_file(socket)
            .map_err(|e| format!("remove stale socket {}: {e}", socket.display()))?;
        tracing::warn!(socket = %socket.display(), "removed a stale socket from a dead daemon");
    }
    // Bind at a temp path in the **same directory**, narrow its mode, then atomically rename it into
    // place, so the socket never exists at its canonical (client-known) path with the ambient umask's
    // mode. Binding directly and chmod-ing after leaves a window where a permissive umask lets another
    // local user connect before the 0660 narrowing lands; the temp path is not the path clients dial,
    // so no such window exists. Defense-in-depth on the file's own mode: the parent directory's
    // permissions are the designed access control (the module doc), and a hoster wanting wider access
    // grants it on the directory (or re-chmods) as a deliberate choice, not an inherited umask accident.
    let listener = {
        use std::os::unix::fs::PermissionsExt as _;
        let mut tmp = socket.to_path_buf().into_os_string();
        tmp.push(format!(".{}.tmp", std::process::id()));
        let tmp = std::path::PathBuf::from(tmp);
        let _ = std::fs::remove_file(&tmp); // clear a leftover temp from a prior crashed start
        let listener = UnixListener::bind(&tmp).map_err(|e| {
            format!(
                "bind {}: {e} (does its parent directory exist and is it writable?)",
                tmp.display()
            )
        })?;
        // Fatal on failure: refuse to serve on a wide-open socket rather than warn and continue.
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o660)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!(
                "chmod the socket {} to 0660 failed: {e}; refusing to serve wide-open",
                tmp.display()
            ));
        }
        std::fs::rename(&tmp, socket).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!(
                "move socket into place ({} -> {}): {e}",
                tmp.display(),
                socket.display()
            )
        })?;
        listener
    };
    Ok(listener)
}

/// stderr logging, filter from `--log` else `AGENT_LOG` else `info`. `info` (not the CLI's `warn`):
/// a daemon's per-session boot/close lines are its operational trace. `json` switches the *encoding*
/// of the same structured events, one JSON object per line, fields intact, for a log shipper, the
/// events themselves are identical either way. `try_init` + a fallback so a bad filter or a
/// double-init can never panic the daemon.
fn init_tracing(flag: Option<&str>, json: bool) {
    let filter = flag
        .map(str::to_string)
        .or_else(|| std::env::var("AGENT_LOG").ok())
        .unwrap_or_else(|| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_new(&filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .with_target(false);
    let _ = if json {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
}
