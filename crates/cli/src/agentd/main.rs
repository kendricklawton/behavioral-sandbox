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
//! **Teardown is crash-only.** A live session's VM drops when its connection ends, tearing the microVM
//! down; and losing the whole daemon process (SIGKILL, OOM, a supervisor's SIGTERM) can't leak a VM
//! either, the lifetime sentinel (decision 014) reaps it, and the next start clears a stale socket
//! file. A graceful drain of in-flight sessions on shutdown is a later ops concern.
#![forbid(unsafe_code)]

mod metrics;
mod session;

use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
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

    let listener = match bind(&cli.socket) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
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
    // The env-layered base config every session boots from (`with_limits` folds each `open`'s knobs
    // on top). The daemon has no `.agent.toml` cwd discovery, that's a CLI-in-a-project convenience;
    // a daemon's config is its own flags + environment.
    let base = BootConfig::from_env();
    let jailed = !cli.unjailed;
    let pool = build_optional_pool(cli.prewarm, &base, jailed);
    let server = Arc::new(Server {
        base,
        jailed,
        observ: Observability::load(),
        pool,
        snapshot_base: std::env::temp_dir()
            .join(format!("agentd-snapshots-{}", std::process::id())),
        snapshot_seq: AtomicU64::new(0),
        metrics: Arc::new(Metrics::default()),
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

/// Serve one accepted connection on its own thread. A thread-spawn failure (EAGAIN under load) drops
/// just that connection, never the daemon.
fn spawn_session(stream: UnixStream, server: Arc<Server>) {
    let spawned = std::thread::Builder::new()
        .name("agentd-session".into())
        .spawn(move || session::serve(stream, &server));
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "cannot spawn a session thread; dropping the connection");
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
    // 1. An unjailed prewarm source running only the default profile (no untrusted code, the source
    //    is the daemon's own, its clones are where sessions run).
    let source_config = base.clone().with_limits(Limits::default());
    let source = Sandbox::open_unjailed(source_config)?;

    // 2. Snapshot it into a per-daemon scratch dir.
    let snap_dir = std::env::temp_dir().join(format!("agentd-prewarm-{}", std::process::id()));
    std::fs::create_dir_all(&snap_dir)
        .map_err(|e| VmmError::Vmm(format!("create prewarm dir {}: {e}", snap_dir.display())))?;
    let snapshot = source.snapshot(&snap_dir)?;
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
    UnixListener::bind(socket).map_err(|e| {
        format!(
            "bind {}: {e} (does its parent directory exist and is it writable?)",
            socket.display()
        )
    })
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
