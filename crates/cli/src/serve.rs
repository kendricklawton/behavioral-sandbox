//! `bsx serve`, the long-lived driver **daemon**: exposes the sandbox lifecycle and the full
//! [wire API](bsx_protocol) over a **unix socket**, so a local client drives microVMs without linking
//! `bsx-engine`.
//!
//! No tenancy, no auth, no billing, no scheduler; those are the hoster's, above this.
//!
//! - **Shape.** One connection is one sandbox **session**, on its own thread, synchronous, no async
//!   runtime. The wire is the versioned newline-JSON contract in [`bsx_protocol`], and the
//!   confinement posture is the daemon's launch choice, never a client's. `tracing` goes to stderr;
//!   the socket carries only the protocol.
//! - **Fast `open`.** `--prewarm N` keeps a [`Pool`] of clones and serves a bare-default `open` from
//!   it; a custom resource profile cold-boots. **Fail-open**: a host that cannot build the pool logs
//!   one warning and every session cold-boots.
//! - **Observable by the hoster.** `tracing` on stderr (JSON with `--log-json`) and a Prometheus
//!   endpoint at `--metrics ADDR` ([`crate::metrics`]). Dashboards and alerting are the hoster's.
//! - **Access control is the hoster's.** No authentication, a recorded non-goal: who may connect is
//!   the filesystem permissions on the socket and its directory. The metrics endpoint is plain HTTP
//!   with no auth, so bind it to loopback or a private scrape network.
//! - **Bounded concurrency.** Every session is a full microVM, so at the `--max-sessions` ceiling (or
//!   an aggregate `--max-committed-*` one) a new connection gets the distinct `at_capacity` reply
//!   *before* any VM boots. Admission control is engine self-protection, not tenancy.
//! - **Teardown is crash-safe, shutdown is prompt.** A session's VM drops with its connection, and a
//!   lost daemon process cannot leak one either: the lifetime sentinel reaps it and the next start
//!   clears a stale socket file. SIGTERM/SIGINT unlinks the socket and exits 0, in-flight sessions
//!   ending crash-consistently. A graceful *drain* is not implemented.

use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use std::num::{NonZeroU8, NonZeroU32};

use crate::audit::Observability;
use crate::policy::Policy;
use bsx_engine::{BootConfig, DEFAULT_GUEST_CID, Limits, Pool, Sandbox, VmmError};

use crate::metrics::Metrics;

use crate::EXIT_OPERATIONAL;

/// How long an accept loop pauses after a **resource-exhaustion** accept error, so a condition that
/// fails instantly and persistently ([`accept_error_is_exhaustion`]) cannot spin a core.
pub(crate) const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether an `accept` error is the kind that keeps failing immediately (out of file descriptors,
/// process- or system-wide, or out of memory), which is what makes an unpaced retry harmful.
/// Everything else, notably `ECONNABORTED` from a peer that hung up mid-handshake, is routine:
/// pausing on those would hand any local peer a throttle.
pub(crate) fn accept_error_is_exhaustion(e: &std::io::Error) -> bool {
    /// `EMFILE` (per-process fd limit), `ENFILE` (system-wide), and `ENOBUFS` (which `accept(2)`
    /// documents alongside `ENOMEM` as "not enough free memory"), none of which `io::ErrorKind`
    /// has a stable variant for; `ENOMEM` itself arrives as `OutOfMemory`.
    const EMFILE: i32 = 24;
    const ENFILE: i32 = 23;
    const ENOBUFS: i32 = 105;
    matches!(e.raw_os_error(), Some(EMFILE | ENFILE | ENOBUFS))
        || e.kind() == std::io::ErrorKind::OutOfMemory
}

/// The default `--max-wall-secs`, finite because the wall a client asks for becomes the *host's* own
/// give-up deadline: an unbounded ask holds a session slot and its VM for as long as the client
/// named. One hour is the ceiling the in-guest agent already clamps a command to.
const DEFAULT_MAX_WALL_SECS: u64 = 3600;

/// The default `--max-snapshots`, finite because a bundle **outlives its session** by design: the
/// wire hands back a host path and carries no verb that consumes it. Sixteen matches the default
/// `--max-sessions`, the smallest ceiling that serves a workload where every session snapshots once.
const DEFAULT_MAX_SNAPSHOTS: usize = 16;

/// The default `--max-output-cap`, finite because the cap a client asks for bounds a **host-side**
/// buffer: at `usize::MAX` the collect loop's per-frame charge never refuses. Anchored to
/// [`Limits::output_cap`], so it refuses only asks above the engine's own shipped default.
fn default_max_output_cap() -> usize {
    Limits::default().output_cap
}

/// `bsx serve`, drive the sandbox lifecycle over a unix socket (the daemon). The `--log` filter is
/// the shared global flag on the `bsx` CLI, so it is not repeated here. Every flag is the
/// operator's, and every ceiling refuses rather than clamps: `crate::Commands::Serve`'s own help
/// states that once, so no flag below repeats it.
#[derive(clap::Args)]
pub struct ServeArgs {
    /// The unix socket to listen on. Its directory's permissions are the access control (the daemon
    /// does no auth, a recorded non-goal), so place it where only trusted local clients can reach.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,
    /// Keep a pre-warmed pool of this many clones for fast `open`. A bare-default `open` pops a
    /// warm clone in milliseconds; a custom profile cold-boots. Fail-open: if the pool can't be
    /// built (no KVM, no root for jailed clones), every session cold-boots. Omit (or `0`) to disable.
    #[arg(long, value_name = "N")]
    prewarm: Option<usize>,
    /// Run every session's VMM without the jailer. The default is confined (jailed, needs real root
    /// + the `jailer` binary); this is the daemon-wide opt-out for hosts that cannot jail.
    #[arg(long)]
    unjailed: bool,
    /// Refuse to boot a session's VMM when the cpu/memory cgroup caps can't be applied, instead of
    /// the default warn-and-boot-uncapped. Needs the jailer (so not with `--unjailed`) and delegated
    /// cgroup v2 controllers. Also settable via `BSX_REQUIRE_LIMITS`.
    #[arg(long)]
    require_limits: bool,
    /// The uid the jailer drops each session's VMM to (default 10000). Every session on this daemon
    /// shares it, and so does a second daemon left at the default, so two daemons meant to separate
    /// tenants need different ids. Also settable via `BSX_JAIL_UID`.
    #[arg(long, value_name = "UID", value_parser = crate::parse_jail_id)]
    jail_uid: Option<u32>,
    /// The gid the jailer drops each session's VMM to (default 10000). See `--jail-uid`.
    #[arg(long, value_name = "GID", value_parser = crate::parse_jail_id)]
    jail_gid: Option<u32>,
    /// Serve a Prometheus metrics endpoint at this address (e.g. `127.0.0.1:9920`) for the hoster to
    /// scrape (`GET /metrics`). Plain HTTP, no auth, bind loopback or a private scrape network. Off
    /// when omitted.
    #[arg(long, value_name = "ADDR")]
    metrics: Option<SocketAddr>,
    /// Emit stderr logs as JSON lines (for a log shipper) instead of human-readable text. Also
    /// enabled by `BSX_LOG_FORMAT=json`.
    #[arg(long)]
    log_json: bool,
    /// The ceiling on concurrent sessions. Every session is a full microVM (guest RAM, a tap, a
    /// cgroup), so at the ceiling a new connection gets the distinct `at_capacity` reply *before* any
    /// VM boots. Size it to the host (sessions × guest memory must fit in RAM); for a
    /// memory-heterogeneous fleet add `--max-committed-mem-mib`/`--max-committed-vcpus`.
    /// `0` = unlimited.
    #[arg(long, value_name = "N", default_value_t = 16)]
    max_sessions: usize,
    /// Drop a session after this many seconds with **no progress** on the connection, in either
    /// direction, so a wedged or forgotten connection can't pin a microVM and a `--max-sessions`
    /// slot forever. It is one absolute deadline per message, not a socket timeout, so a client that
    /// drips a request in or drains a reply out just fast enough to keep each syscall progressing is
    /// dropped like one that went silent. Applies to the wait for the first `open` too; a client
    /// streaming requests keeps resetting it. `0` disables it. Default 300 (5 min).
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    idle_timeout: u64,
    /// Ceiling on the vCPUs a session's `open` may ask for. Takes the same 1-or-even rule as
    /// `run --vcpus`, since a ceiling no VM could boot at means the even number below it.
    #[arg(long, value_name = "N", value_parser = crate::parse_vcpus)]
    max_vcpus: Option<NonZeroU8>,
    /// Ceiling on the guest memory (MiB) a session's `open` may ask for.
    #[arg(long, value_name = "MIB")]
    max_mem_mib: Option<NonZeroU32>,
    /// Ceiling on the wall-clock budget (seconds) a session's `open` may ask for. This is what
    /// bounds one exec's hold on a slot: `--idle-timeout` does not arm while a command runs (a long
    /// quiet command is a working session, not a wedged one), so the wall is the only thing that
    /// ends an exec whose guest stops reporting. Default 3600 (1 h), the in-guest agent's own
    /// command ceiling; `0` = unlimited.
    #[arg(long, value_name = "SECONDS", default_value_t = DEFAULT_MAX_WALL_SECS)]
    max_wall_secs: u64,
    /// Ceiling on the captured-output cap (bytes) a session's `open` may ask for. It bounds the
    /// *daemon's* memory, not the guest's: the host buffers one exec's whole stdout, stderr and
    /// artifacts before it can reply, so this, not `--max-committed-mem-mib` (guest RAM), is what
    /// stops a session that streams output from growing this process. Defaults to the engine's own
    /// `output_cap`; `0` = unlimited.
    #[arg(long, value_name = "BYTES", default_value_t = default_max_output_cap())]
    max_output_cap: usize,
    /// Aggregate ceiling on the **summed guest memory** (MiB) across all live sessions *and*
    /// pre-warmed pool clones, whose RAM is real before any session exists. The resource counterpart
    /// to `--max-sessions`: an `open` that would push committed memory past this is refused with
    /// `at_capacity` before booting, and a `--prewarm` that alone exceeds it refuses to start.
    /// Distinct from `--max-mem-mib`, which bounds one request. `0` (the default) is unlimited.
    #[arg(long, value_name = "MIB", default_value_t = 0)]
    max_committed_mem_mib: u64,
    /// Aggregate ceiling on the **summed vCPUs** committed across all live sessions and pre-warmed
    /// pool clones. Set it to your CPU oversubscription budget (e.g. physical cores × a ratio).
    /// `0` (the default) is unlimited.
    #[arg(long, value_name = "N", default_value_t = 0)]
    max_committed_vcpus: u64,
    /// Ceiling on the snapshot bundles this daemon holds on disk at once. Each bundle is roughly the
    /// session's guest RAM plus a copy of its root disk, and bundles **persist after the session
    /// closes** (the reply is a host path, and no wire verb consumes it), so this, not
    /// `--max-committed-mem-mib`, is what bounds the scratch filesystem. Counted from disk on each
    /// request, so removing a bundle you have consumed frees budget. Reachable only on an
    /// `--unjailed` daemon, since snapshotting a jailed session is a typed refusal.
    /// Default 16, one per default session slot; `0` = unlimited.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_SNAPSHOTS)]
    max_snapshots: usize,
    /// Ceiling on the egress destinations a session's `open` may name (repeatable; `IP` or
    /// `IP/PREFIX`, either address family). An `open` whose `allow` rules reach outside every entry
    /// is refused, naming the CIDR it asked for. Unset is no CIDR ceiling, not an open tap: the tap
    /// still denies by default, so the operator loses only the say over what a client may ask for.
    #[arg(long, value_name = "CIDR", value_parser = parse_max_egress)]
    max_egress: Vec<MaxEgress>,
}

/// One `--max-egress` entry. One flag rather than a `-v4`/`-v6` pair: which of [`Policy`]'s two
/// lists it lands in follows from the address it names.
#[derive(Debug, Clone, Copy)]
enum MaxEgress {
    V4(bsx_probes_loader::Ipv4Cidr),
    V6(bsx_probes_loader::Ipv6Cidr),
}

/// Parse one `--max-egress` entry through the config file's CIDR parsers, so the two spellings of
/// this ceiling cannot drift. The family comes from the address rather than from a parse-and-fall-
/// back, so a typo'd IPv4 address is reported as a bad IPv4 address, not as a bad IPv6 one.
fn parse_max_egress(s: &str) -> Result<MaxEgress, String> {
    let addr = s.split_once('/').map_or(s, |(a, _)| a);
    if addr.contains(':') {
        crate::config::parse_v6_cidr(s, &format!("--max-egress entry {s:?}")).map(MaxEgress::V6)
    } else {
        crate::config::parse_v4_cidr(s, &format!("--max-egress entry {s:?}")).map(MaxEgress::V4)
    }
}

/// The per-`open` ceilings, from the daemon's own flags rather than a discovered `.bsx.toml`: a
/// daemon must not read a security control out of whatever directory it was started in. Jail and
/// networking are already daemon-wide, so only the ceilings travel to the session boundary. On a
/// ceiling with a finite default, `0` is the unlimited opt-out.
fn operator_policy(args: &ServeArgs) -> Policy {
    // Wildcard-free, so a third address family cannot be dropped on the floor by this split.
    let mut max_egress_v4 = Vec::new();
    let mut max_egress_v6 = Vec::new();
    for entry in &args.max_egress {
        match entry {
            MaxEgress::V4(c) => max_egress_v4.push(*c),
            MaxEgress::V6(c) => max_egress_v6.push(*c),
        }
    }
    Policy {
        max_vcpus: args.max_vcpus,
        max_mem_mib: args.max_mem_mib,
        max_wall_secs: (args.max_wall_secs > 0).then_some(args.max_wall_secs),
        max_output_cap: (args.max_output_cap > 0).then_some(args.max_output_cap),
        max_egress_v4,
        max_egress_v6,
        ..Policy::default()
    }
}

/// The daemon's shared context, handed by `Arc` to every session thread: the base config each
/// session boots from, the launch-time confinement posture, the process-wide host-side probes
/// (loaded once), the optional pre-warmed pool, and the admission counters.
// `pub(crate)` because `session` is a crate-root sibling of `serve` (both flat under `src/`), so it
// reaches this through crate visibility, not the ancestor visibility a submodule would have.
pub(crate) struct Server {
    /// The env-layered base config; a session's `open` folds its resource knobs on top.
    pub(crate) base: BootConfig,
    /// The confinement posture no client can weaken.
    pub(crate) isolation: crate::policy::IsolationMode,
    /// The operator's per-run policy, from the daemon's own flags at startup ([`operator_policy`]).
    /// The enforcing copy: a client controls neither those flags nor this process's environment.
    pub(crate) policy: Policy,
    /// The shared host-side probes, loaded once, attached per session (fail-open) for `trace`.
    pub(crate) observ: Observability,
    /// The host record-signing key the `trace` reply signs its finalized record with. Host-side;
    /// the guest never sees it.
    pub(crate) signing_key: bsx_probes_loader::HostKey,
    /// The pre-warmed pool for fast `open`, or `None` (cold boots) when `--prewarm` was off or the
    /// pool could not be built. Behind a `Mutex`: `take`/`refill` need `&mut`, and sessions run on
    /// many threads.
    pub(crate) pool: Option<Mutex<Pool>>,
    /// Where `snapshot` bundle directories are created (per-daemon, so concurrent daemons don't
    /// collide), each named by the monotonic [`snapshot_seq`](Self::snapshot_seq).
    snapshot_base: PathBuf,
    /// The next snapshot-bundle sequence number, so concurrent `snapshot`s land in distinct dirs.
    snapshot_seq: AtomicU64,
    /// The metric registry the session threads bump; `Arc` so the metrics endpoint thread renders it
    /// independently of the `Server` borrow.
    pub(crate) metrics: Arc<Metrics>,
    /// The `--max-sessions` ceiling (`0` = unlimited), enforced by [`SessionTicket::acquire`].
    pub(crate) max_sessions: usize,
    /// The per-session idle timeout (`None` = disabled), from `--idle-timeout`: a read that waits this
    /// long with no client bytes ends the session, freeing its VM and `--max-sessions` slot.
    pub(crate) idle_timeout: Option<std::time::Duration>,
    /// Live sessions right now, incremented by a successful [`SessionTicket::acquire`] and
    /// decremented by the ticket's `Drop`.
    pub(crate) active_sessions: AtomicUsize,
    /// Summed guest memory (MiB) committed across live sessions, charged by a [`ResourceReservation`]
    /// once an `open`'s `Limits` are known and released on its `Drop`.
    pub(crate) committed_mem_mib: AtomicU64,
    /// Summed vCPUs committed across live sessions; charged and released like
    /// [`committed_mem_mib`](Self::committed_mem_mib).
    pub(crate) committed_vcpus: AtomicU64,
    /// Aggregate ceiling on [`committed_mem_mib`](Self::committed_mem_mib) (`0` = unlimited), from
    /// `--max-committed-mem-mib`.
    pub(crate) max_committed_mem_mib: u64,
    /// Aggregate ceiling on [`committed_vcpus`](Self::committed_vcpus) (`0` = unlimited), from
    /// `--max-committed-vcpus`.
    pub(crate) max_committed_vcpus: u64,
    /// Ceiling on the snapshot bundles held on disk at once (`0` = unlimited), from
    /// `--max-snapshots`, checked against [`snapshot_bundles`](Self::snapshot_bundles).
    pub(crate) max_snapshots: usize,
}

impl Server {
    /// A fresh, unique directory for the next `snapshot` bundle. Monotonic across threads, so two
    /// concurrent sessions snapshotting at once can't target the same directory.
    pub(crate) fn next_snapshot_dir(&self) -> PathBuf {
        let n = self.snapshot_seq.fetch_add(1, Ordering::Relaxed);
        self.snapshot_base.join(format!("snap-{n}"))
    }

    /// How many snapshot bundles this daemon holds, counted from the filesystem rather than tallied:
    /// bundles outlive their sessions, so removing a consumed one gives the budget back, which a
    /// monotonic counter would not.
    ///
    /// # Errors
    /// The base directory not existing yet is zero bundles, not an error. Any other read failure is
    /// returned, so a daemon that cannot verify its headroom refuses rather than assuming it has any.
    pub(crate) fn snapshot_bundles(&self) -> std::io::Result<usize> {
        match std::fs::read_dir(&self.snapshot_base) {
            // Counts unreadable entries too: for a ceiling, over-counting is the safe direction.
            Ok(entries) => Ok(entries.count()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e),
        }
    }
}

/// Run the daemon (`bsx serve`): the `--log` filter comes from the CLI's shared global flag, the
/// rest from [`ServeArgs`]. Its own [`log_filter`] resolution and its own config (flags +
/// environment, no `.bsx.toml`), so the CLI dispatches this **before** its project-file/tracing
/// setup ([`crate::main`]); the subscriber is [`crate::init_tracing`], shared with the CLI.
pub fn serve(args: ServeArgs, log: Option<String>) -> ExitCode {
    let log_json = args.log_json
        || std::env::var("BSX_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    if let Err(e) = crate::init_tracing(&log_filter(log.as_deref()), log_json) {
        // tracing is not up (that is the failure), so the refusal goes to stderr directly.
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "bsx: {e}");
        return ExitCode::from(EXIT_OPERATIONAL);
    }

    // The env-layered base config every session boots from (`with_limits` folds each `open`'s knobs
    // on top). Computed up front so the signal handler and the startup sweep both know where this
    // daemon's guest-memory-sized bundle dirs live.
    let mut base = BootConfig::from_env();
    crate::apply_posture(&mut base, args.require_limits, args.jail_uid, args.jail_gid);
    let isolation = crate::policy::IsolationMode::from_unjailed(args.unjailed);

    // `require_limits` caps the *jailed* VMM's cgroup, so an unjailed daemon could only accept
    // connections and refuse every session with `LimitsUnavailable`. Refuse at startup instead of
    // running a daemon that looks healthy and serves nothing.
    if base.require_limits && isolation.is_unjailed() {
        tracing::error!(
            "require_limits needs the jailer, but this daemon is --unjailed; an unjailed VMM has no \
             cgroup to cap. Drop --unjailed (and BSX_REQUIRE_LIMITS) or don't require limits."
        );
        return ExitCode::from(EXIT_OPERATIONAL);
    }

    let listener = match bind(&args.socket) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    // The bundle dirs are named here rather than inside the handler so a restart cannot leak the
    // guest-RAM-sized bundle a `--prewarm` daemon staged.
    install_signal_handler(
        args.socket.clone(),
        vec![
            prewarm_dir(&base.scratch_dir),
            snapshots_dir(&base.scratch_dir),
        ],
    );
    // Reclaim what a *crashed* prior daemon (SIGKILL/OOM, no handler) leaked, before this one adds
    // its own.
    sweep_stale_agent_bundles(&base.scratch_dir);
    // Bound *before* any session is served: a scrape target the hoster asked for explicitly either
    // works or the daemon refuses to start, never silently absent (as `--allow` refuses).
    let metrics_listener = match args.metrics.map(TcpListener::bind).transpose() {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "cannot bind the metrics endpoint; refusing to start");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    // A public bind may be a deliberate private-network choice, so warn rather than refuse; a
    // fat-fingered `0.0.0.0` on a no-auth endpoint must at least be visible in the startup log.
    if let Some(addr) = args.metrics
        && !addr.ip().is_loopback()
    {
        tracing::warn!(
            %addr,
            "metrics endpoint bound to a non-loopback address; it serves plain HTTP with no \
             auth, make sure this is a private scrape network"
        );
    }
    // Guest-memory-sized, so under the engine's own scratch knob (`BSX_SCRATCH_DIR`) rather than a
    // hardcoded `$TMPDIR`: the operator points scratch at real disk once and every large artifact
    // follows it.
    let snapshot_base = snapshots_dir(&base.scratch_dir);
    // Fail-closed like the metrics bind: refuse to start rather than serve records that claim to be
    // verifiable and are not signed. No `.bsx.toml` layer, so the path is `BSX_SIGNING_KEY` or the
    // default.
    let signing_key = match bsx_probes_loader::HostKey::load_or_generate(
        &crate::config::signing_key_path(&crate::config::Sources::default()),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "cannot establish the record-signing key; refusing to start");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let pool = build_optional_pool(args.prewarm, &base, isolation);
    // The pool's clones hold real guest RAM before any session exists, so they charge the committed
    // ceilings from the start; a `--prewarm` the ceiling cannot hold is refused below, loudly.
    let clone = pool_clone_limits();
    // Through the poison, as `jail.rs` does: a poisoned lock still guards a real pool, and reading
    // `0` would leave its RAM uncharged for the daemon's whole life.
    let pool_ready = pool.as_ref().map_or(0, |p| {
        p.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ready()
    });
    let pool_mem = pool_ready as u64 * u64::from(clone.mem_mib.get());
    let pool_vcpus = pool_ready as u64 * u64::from(clone.vcpus.get());
    if (args.max_committed_mem_mib != 0 && pool_mem > args.max_committed_mem_mib)
        || (args.max_committed_vcpus != 0 && pool_vcpus > args.max_committed_vcpus)
    {
        tracing::error!(
            prewarm = pool_ready,
            pool_mem_mib = pool_mem,
            pool_vcpus,
            max_committed_mem_mib = args.max_committed_mem_mib,
            max_committed_vcpus = args.max_committed_vcpus,
            "the pre-warmed pool alone exceeds a committed-resource ceiling; lower --prewarm or \
             raise the ceiling"
        );
        return ExitCode::from(EXIT_OPERATIONAL);
    }
    let policy = operator_policy(&args);
    let server = Arc::new(Server {
        base,
        isolation,
        policy,
        observ: Observability::load(),
        signing_key,
        pool,
        snapshot_base,
        snapshot_seq: AtomicU64::new(0),
        metrics: Arc::new(Metrics::default()),
        max_sessions: args.max_sessions,
        idle_timeout: (args.idle_timeout > 0)
            .then(|| std::time::Duration::from_secs(args.idle_timeout)),
        active_sessions: AtomicUsize::new(0),
        committed_mem_mib: AtomicU64::new(pool_mem),
        committed_vcpus: AtomicU64::new(pool_vcpus),
        max_committed_mem_mib: args.max_committed_mem_mib,
        max_committed_vcpus: args.max_committed_vcpus,
        max_snapshots: args.max_snapshots,
    });

    // The per-VM residue (scratch dirs, netns) a crashed *driver* left, reclaimed before sessions.
    // The complement of `sweep_stale_agent_bundles`, which takes only this daemon's bundle dirs.
    crate::sweep_vm_residue(&server.base.scratch_dir, Some(&server.metrics));

    if let Some(metrics_listener) = metrics_listener {
        spawn_metrics(metrics_listener, &server);
    }
    tracing::info!(
        socket = %args.socket.display(),
        jailed = isolation.is_jailed(),
        prewarmed = server.pool.is_some(),
        metrics = args.metrics.as_ref().map(tracing::field::display),
        "bsx listening"
    );

    // Accept forever, one thread per connection: a daemon runs until its supervisor stops it, and
    // the sentinel covers VM reclaim on process death, so there is no loop exit to manage.
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => spawn_session(stream, Arc::clone(&server)),
            // An accept error must not end the daemon. Only exhaustion is paced: it persists and
            // fails instantly, while sleeping on a routine error would let any local peer throttle
            // the daemon by dialing and dropping in a loop.
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                if accept_error_is_exhaustion(&e) {
                    std::thread::sleep(ACCEPT_BACKOFF);
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// Serve the metrics endpoint on its own thread, sampling the pool's live stock per scrape. Runs for
/// the daemon's whole life: crash-only, like the sessions.
fn spawn_metrics(listener: TcpListener, server: &Arc<Server>) {
    let registry = Arc::clone(&server.metrics);
    let sampled = Arc::clone(server);
    let spawned = std::thread::Builder::new()
        .name("bsx-metrics".into())
        .spawn(move || {
            crate::metrics::serve(listener, registry, move || {
                // `try_lock`, never a blocking acquire: a scrape must not stall behind a session's
                // pool refill. On contention or poison `bsx_pool_ready` is absent for that scrape,
                // the same absent-rather-than-zero shape a daemon with no pool gives, instead of the
                // visibility surface freezing under the load it exists to report on.
                crate::metrics::CapacitySample {
                    pool_ready: sampled
                        .pool
                        .as_ref()
                        .and_then(|p| p.try_lock().ok())
                        .map(|pool| u64::try_from(pool.ready()).unwrap_or(u64::MAX)),
                    committed_mem_mib: sampled.committed_mem_mib.load(Ordering::Relaxed),
                    committed_vcpus: sampled.committed_vcpus.load(Ordering::Relaxed),
                    max_committed_mem_mib: sampled.max_committed_mem_mib,
                    max_committed_vcpus: sampled.max_committed_vcpus,
                }
            })
        });
    if let Err(e) = spawned {
        // The listener is bound, so the hoster's ask was satisfiable; a spawn failure is the same
        // transient-resource class as a session thread's. Log loudly, keep serving.
        tracing::error!(error = %e, "cannot spawn the metrics thread; endpoint will not answer");
    }
}

/// Serve one accepted connection on its own thread, behind the `--max-sessions` admission check, so
/// a refusal lands *before* any VM resource is committed. A thread-spawn failure (EAGAIN under load)
/// drops that connection, never the daemon.
fn spawn_session(stream: UnixStream, server: Arc<Server>) {
    let Some(ticket) = SessionTicket::acquire(&server) else {
        refuse_at_capacity(stream, &server);
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("bsx-session".into())
        .spawn(move || {
            // The ticket's `Drop` releases the slot however `serve` ends: clean close, client
            // hang-up, or an unwinding panic.
            let _ticket = ticket;
            crate::session::serve(stream, &server);
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

/// A committed-resource reservation (guest memory + vCPUs) held for a session's lifetime, the
/// aggregate counterpart to [`SessionTicket`]'s count: a memory-heterogeneous fleet can sit under
/// the session-count ceiling and still be past the host's real capacity. Acquired once an `open`'s
/// resources are known (after `open_limits`), released on `Drop`.
pub(crate) struct ResourceReservation<'a> {
    server: &'a Server,
    mem_mib: u64,
    vcpus: u64,
}

impl<'a> ResourceReservation<'a> {
    /// Reserve `mem_mib` + `vcpus` against the daemon's aggregate ceilings, or `None` if either would
    /// be exceeded (a `0` ceiling is unlimited). Both dimensions commit together: a refused vCPU leg
    /// rolls the memory charge back, so a partial reservation never lingers.
    pub(crate) fn try_acquire(server: &'a Server, mem_mib: u64, vcpus: u64) -> Option<Self> {
        if !charge(
            &server.committed_mem_mib,
            server.max_committed_mem_mib,
            mem_mib,
        ) {
            return None;
        }
        if !charge(&server.committed_vcpus, server.max_committed_vcpus, vcpus) {
            server
                .committed_mem_mib
                .fetch_sub(mem_mib, Ordering::Relaxed);
            return None;
        }
        Some(Self {
            server,
            mem_mib,
            vcpus,
        })
    }
}

impl Drop for ResourceReservation<'_> {
    fn drop(&mut self) {
        self.server
            .committed_mem_mib
            .fetch_sub(self.mem_mib, Ordering::Relaxed);
        self.server
            .committed_vcpus
            .fetch_sub(self.vcpus, Ordering::Relaxed);
    }
}

/// Add `amount` to `current` while keeping it `<= ceiling`, via a lock-free CAS loop so racing
/// admissions can't over-commit past the ceiling (a `0` ceiling is unlimited). Returns whether the
/// charge was applied.
fn charge(current: &AtomicU64, ceiling: u64, amount: u64) -> bool {
    if ceiling == 0 {
        current.fetch_add(amount, Ordering::Relaxed);
        return true;
    }
    let mut now = current.load(Ordering::Relaxed);
    loop {
        if now.saturating_add(amount) > ceiling {
            return false;
        }
        match current.compare_exchange_weak(now, now + amount, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return true,
            Err(actual) => now = actual,
        }
    }
}

/// The resource profile every pre-warmed clone holds, single-sourced so the pool builder, the
/// admission charges, and the take-handoff release cannot disagree about a clone's footprint.
pub(crate) fn pool_clone_limits() -> Limits {
    Limits::default()
}

/// Reserve headroom for up to `want` pool clones (per clone, the roll-back shape of
/// [`ResourceReservation::try_acquire`]), returning how many were paid for. The refill restores at
/// most that many, so topping the pool up cannot push past a ceiling live sessions are holding.
pub(crate) fn reserve_pool_clones(server: &Server, want: usize, clone: &Limits) -> usize {
    let mem = u64::from(clone.mem_mib.get());
    let vcpus = u64::from(clone.vcpus.get());
    let mut reserved = 0;
    while reserved < want {
        if !charge(&server.committed_mem_mib, server.max_committed_mem_mib, mem) {
            break;
        }
        if !charge(&server.committed_vcpus, server.max_committed_vcpus, vcpus) {
            server.committed_mem_mib.fetch_sub(mem, Ordering::Relaxed);
            break;
        }
        reserved += 1;
    }
    reserved
}

/// Release `n` clones' worth of committed resources: the exact inverse of
/// [`reserve_pool_clones`], also used when a pooled clone hands off to a session (whose own
/// reservation covers the VM from then on).
pub(crate) fn release_pool_clones(server: &Server, n: usize, clone: &Limits) {
    if n == 0 {
        return;
    }
    let n = n as u64;
    server
        .committed_mem_mib
        .fetch_sub(n * u64::from(clone.mem_mib.get()), Ordering::Relaxed);
    server
        .committed_vcpus
        .fetch_sub(n * u64::from(clone.vcpus.get()), Ordering::Relaxed);
}

/// Backoff hint sent with an [`bsx_protocol::Response::AtCapacity`] refusal. A hint, not a promise:
/// the daemon cannot know when a slot frees.
pub(crate) const AT_CAPACITY_RETRY_MS: u64 = 1000;

/// Refuse a connection past the `--max-sessions` ceiling with one typed
/// [`bsx_protocol::Response::AtCapacity`], then drop it. The write is timeout-bounded so a stalled
/// client cannot park the accept loop, and best-effort: a refusal must never take the daemon down.
fn refuse_at_capacity(stream: UnixStream, server: &Server) {
    server.metrics.open_refused(false);
    tracing::warn!(
        max_sessions = server.max_sessions,
        "refusing a connection: at the session ceiling"
    );
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
    let mut stream = stream;
    let refusal = bsx_protocol::Response::at_capacity(AT_CAPACITY_RETRY_MS);
    let _ = bsx_protocol::write_response(&mut stream, &refusal);
}

/// Every bundle-dir name prefix a daemon mints, each completed by its pid. The one source for both
/// halves of the round trip: [`bundle_dir`] writes these names and [`sweep_stale_agent_bundles`]
/// reclaims exactly what matches them, so a dir shape absent here is a dir nothing sweeps.
const BUNDLE_PREFIXES: [&str; 2] = ["bsx-prewarm-", "bsx-snapshots-"];

/// A bundle dir named `<prefix><pid>` under the engine's scratch knob. `pid` is a parameter so a
/// test can mint another daemon's name; every caller here passes this process's.
fn bundle_dir(scratch: &Path, prefix: &str, pid: u32) -> PathBuf {
    scratch.join(format!("{prefix}{pid}"))
}

/// This daemon's prewarm snapshot bundle dir (guest-memory-sized), under the engine's scratch knob.
fn prewarm_dir(scratch: &Path) -> PathBuf {
    bundle_dir(scratch, BUNDLE_PREFIXES[0], std::process::id())
}

/// This daemon's session-snapshot bundle dir (holds each session's `snap-N`), under the scratch knob.
fn snapshots_dir(scratch: &Path) -> PathBuf {
    bundle_dir(scratch, BUNDLE_PREFIXES[1], std::process::id())
}

/// Reclaims this-user [`BUNDLE_PREFIXES`] dirs left by **dead** prior daemons, whose
/// guest-memory-sized files are pure leak once their owner is gone. Skips this pid and any live
/// one: a dead daemon is not this process's unreaped child, so absence from `/proc` is a sound
/// liveness check.
fn sweep_stale_agent_bundles(scratch: &Path) {
    use std::os::unix::fs::MetadataExt as _;
    let Some(me) = crate::trust::own_euid() else {
        return; // without our euid we can't prove ownership; skip rather than risk a wrong delete
    };
    let Ok(entries) = std::fs::read_dir(scratch) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(pid) = BUNDLE_PREFIXES.iter().find_map(|p| name.strip_prefix(p)) else {
            continue; // not a bundle dir a daemon mints
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
                "swept a stale bsx bundle dir from a dead daemon"
            ),
            Err(e) => tracing::warn!(
                dir = %entry.path().display(),
                error = %e,
                "could not sweep a stale bsx bundle dir"
            ),
        }
    }
}

/// Remove `socket` only while it is still the same inode this daemon published there.
///
/// A path is not an identity: another daemon can publish its own socket at this path while this one
/// runs (the bind's stale-socket reclaim and rename are not one atomic step), and unlinking by path
/// would take out that **live** daemon's socket, leaving it on an inode no client can dial.
///
/// An inode number alone would be too weak, since the kernel recycles one as soon as its last
/// reference goes. It is an identity here because this daemon's own listener is still bound when the
/// signal thread runs, and a bound `AF_UNIX` socket holds a reference to its path: the number cannot
/// land under a successor while this daemon is still here to mistake it for its own.
fn unlink_own_socket(socket: &Path, published: Option<(u64, u64)>) {
    use std::os::unix::fs::MetadataExt as _;

    let Some(published) = published else {
        return; // never published one; there is nothing here that is ours to remove
    };
    let Ok(now) = std::fs::symlink_metadata(socket) else {
        return; // already gone
    };
    if (now.dev(), now.ino()) == published {
        let _ = std::fs::remove_file(socket);
    } else {
        tracing::warn!(
            socket = %socket.display(),
            "another daemon owns this socket path now; leaving it in place"
        );
    }
}

/// Install the SIGTERM/SIGINT handler: unlink this daemon's own socket, remove its own bundle dirs
/// (`cleanup_dirs`, guest-memory-sized), then exit 0. Best-effort: a host where the handler cannot
/// be installed keeps the crash-only path, where the next start clears the stale socket and the
/// startup sweep reclaims the bundle dirs.
fn install_signal_handler(socket: PathBuf, cleanup_dirs: Vec<PathBuf>) {
    use std::os::unix::fs::MetadataExt as _;

    // Taken before the wait, so it identifies the socket this daemon published rather than whatever
    // holds the path at shutdown.
    let published = std::fs::symlink_metadata(&socket)
        .ok()
        .map(|m| (m.dev(), m.ino()));
    let spawned = std::thread::Builder::new()
        .name("bsx-signals".into())
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
                // In-flight sessions end crash-consistently, their VMs reaped by the sentinel;
                // what follows is only what a plain kill would leave behind.
                unlink_own_socket(&socket, published);
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

/// Build the pre-warmed pool when `--prewarm N` (N > 0) asked for one. Any failure degrades to
/// `None` and a warning, never a refusal to start: a pool is latency, not correctness.
fn build_optional_pool(
    prewarm: Option<usize>,
    base: &BootConfig,
    isolation: crate::policy::IsolationMode,
) -> Option<Mutex<Pool>> {
    let target = prewarm?;
    if target == 0 {
        return None;
    }
    match build_pool(base, isolation, target) {
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
/// bare-default `open` is pool-eligible (`crate::session::boot_session_vm`).
fn build_pool(
    base: &BootConfig,
    isolation: crate::policy::IsolationMode,
    target: usize,
) -> Result<Pool, VmmError> {
    // A successful build leaves the pool's clones referencing this bundle, so it lives until
    // shutdown; on any failure below nothing references it, so it must not survive as a
    // guest-RAM-sized leak. [`StagedPath`], so the reclaim covers a *panic* here too, not just `Err`.
    let snap_dir = StagedPath::new(prewarm_dir(&base.scratch_dir));
    std::fs::create_dir_all(snap_dir.path()).map_err(|e| {
        VmmError::Vmm(format!(
            "create prewarm dir {}: {e}",
            snap_dir.path().display()
        ))
    })?;
    let built = build_pool_from(base, isolation, target, snap_dir.path());
    if built.is_ok() {
        snap_dir.published();
    }
    built
}

/// The snapshot + restore steps of [`build_pool`], split out so the caller can reclaim `snap_dir` on
/// any error without a cleanup branch per `?`.
fn build_pool_from(
    base: &BootConfig,
    isolation: crate::policy::IsolationMode,
    target: usize,
    snap_dir: &Path,
) -> Result<Pool, VmmError> {
    // 1. An unjailed prewarm source running only the default profile: no untrusted code runs here,
    //    it runs in the clones. `require_limits` is cleared because the source *must* be unjailed to
    //    be snapshotted and an unjailed boot cannot be capped; enforcement lands on the clones.
    let mut source_config = base.clone().with_limits(pool_clone_limits());
    source_config.require_limits = false;
    let mut source = Sandbox::open_unjailed(source_config)?;

    // 2. Snapshot it into the per-daemon bundle dir the caller prepared.
    let snapshot = source.snapshot(snap_dir)?;
    // Best-effort: the snapshot is already on disk, so a teardown error must not discard a working
    // pool. `Drop` reclaims the source either way.
    if let Err(e) = source.shutdown() {
        tracing::warn!(error = %e, "prewarm source teardown reported an error; snapshot already captured");
    }

    // 3. Restore `target` clones under the daemon's confinement posture (jailed by default). They
    //    inherit the snapshot's vsock, so a session execs over it exactly like a cold boot.
    let mut pool_config = base.clone().with_limits(pool_clone_limits());
    pool_config.jail = if isolation.is_jailed() {
        Some(pool_config.jail.unwrap_or_default())
    } else {
        None
    };
    if pool_config.guest_cid.is_none() {
        pool_config.guest_cid = Some(DEFAULT_GUEST_CID);
    }
    Pool::new(snapshot, pool_config, target)
}

/// Whether a daemon is listening at `socket`, without waiting on one that is.
///
/// The connect is **non-blocking**: a blocking one waits on a full `AF_UNIX` backlog, so a
/// live-but-wedged daemon would hang a new daemon's startup rather than be reported. Non-blocking,
/// that case is `EAGAIN`, still a listener and so still a refusal.
fn someone_is_listening(socket: &Path) -> bool {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr};

    let Ok(addr) = UnixAddr::new(socket) else {
        return false; // too long for `sun_path`; nothing could be listening there
    };
    let Ok(fd) = nix::sys::socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    ) else {
        return false;
    };
    match nix::sys::socket::connect(std::os::fd::AsRawFd::as_raw_fd(&fd), &addr) {
        Ok(()) => true,
        // The backlog is full: a daemon is there and behind, which is the case this exists to catch.
        Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINPROGRESS) => true,
        Err(_) => false,
    }
}

/// Bind the listener at `socket`, clearing a **stale** socket file first but refusing to clobber a
/// **live** daemon ([`someone_is_listening`] decides which). The parent directory must already
/// exist: it is the hoster's to create, with the permissions that gate access.
fn bind(socket: &Path) -> Result<UnixListener, String> {
    if socket.exists() {
        // Only a socket is reclaimable: this daemon often runs as root, so the remove below would
        // take out whatever a mistyped `--socket` named.
        let is_socket = std::fs::symlink_metadata(socket)
            .map(|m| {
                use std::os::unix::fs::FileTypeExt as _;
                m.file_type().is_socket()
            })
            .map_err(|e| format!("stat {}: {e}", socket.display()))?;
        if !is_socket {
            return Err(format!(
                "{} exists and is not a socket; refusing to remove it (mistyped --socket?)",
                socket.display()
            ));
        }
        if someone_is_listening(socket) {
            return Err(format!(
                "another bsx daemon is already listening on {}",
                socket.display()
            ));
        }
        // Nothing answered: a stale socket from a dead daemon, so reclaim it.
        std::fs::remove_file(socket)
            .map_err(|e| format!("remove stale socket {}: {e}", socket.display()))?;
        tracing::warn!(socket = %socket.display(), "removed a stale socket from a dead daemon");
    }
    // Bind at a temp path in the **same directory**, narrow the mode, then rename into place, so the
    // socket never exists at its client-known path with the ambient umask's mode. Binding directly
    // and chmod-ing after leaves a window a permissive umask opens to another local user, and no
    // client dials the temp path. Defence in depth: the parent directory is the access control.
    let listener = {
        use std::os::unix::fs::PermissionsExt as _;
        let mut tmp = socket.as_os_str().to_os_string();

        tmp.push(format!(".{}.tmp", std::process::id()));
        // Unlinked on every exit from here until the rename disarms the guard, so a failed start
        // leaves no `.tmp` orphan beside the canonical path.
        let tmp = StagedPath::new(std::path::PathBuf::from(tmp));
        let _ = std::fs::remove_file(tmp.path()); // clear a leftover temp from a prior crashed start
        let listener = UnixListener::bind(tmp.path()).map_err(|e| {
            format!(
                "bind {}: {e} (does its parent directory exist and is it writable?)",
                tmp.path().display()
            )
        })?;
        // Fatal on failure: refuse to serve on a wide-open socket rather than warn and continue.
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o660)).map_err(
            |e| {
                format!(
                    "chmod the socket {} to 0660 failed: {e}; refusing to serve wide-open",
                    tmp.path().display()
                )
            },
        )?;
        std::fs::rename(tmp.path(), socket).map_err(|e| {
            format!(
                "move socket into place ({} -> {}): {e}",
                tmp.path().display(),
                socket.display()
            )
        })?;
        tmp.published(); // the canonical path owns the inode now; nothing to unlink
        listener
    };
    Ok(listener)
}

/// An RAII guard for a staged-then-published path (the daemon's temp socket, a pool's snapshot
/// bundle dir): `Drop` removes it, file or directory, on an error return *or* an unwinding panic,
/// until [`published`](Self::published) disarms it. A `SIGKILL` in that window still leaks, which
/// the next start's stale-path reclaim covers.
struct StagedPath {
    path: PathBuf,
    armed: bool,
}

impl StagedPath {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Disarm: the path was renamed into place (or handed off), so nothing is removed on drop.
    fn published(mut self) {
        self.armed = false;
    }
}

impl Drop for StagedPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// The daemon's log filter: `--log`, else `BSX_LOG`, else `info` (not the CLI's `warn`, since a
/// daemon's per-session boot/close lines are its operational trace). Resolved here rather than in
/// [`crate::init_tracing`] because `serve` dispatches before project-file discovery, so it reads a
/// different set of layers than the CLI does.
fn log_filter(flag: Option<&str>) -> String {
    log_filter_with(flag, std::env::var("BSX_LOG").ok())
}

/// The pure core of [`log_filter`], taking `BSX_LOG` rather than reading it, so the precedence is
/// unit-testable without `set_var` (`unsafe` in edition 2024, and it races the parallel runner).
fn log_filter_with(flag: Option<&str>, env: Option<String>) -> String {
    flag.map(str::to_string)
        .or(env)
        .unwrap_or_else(|| "info".to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn the_daemon_log_filter_prefers_the_flag_then_the_env_then_info() {
        assert_eq!(
            log_filter_with(Some("debug"), Some("trace".into())),
            "debug"
        );
        assert_eq!(log_filter_with(None, Some("trace".into())), "trace");
        // `info`, not the CLI's `warn`: a daemon's per-session boot/close lines are its operational
        // trace, and `serve` dispatches before project-file discovery so no file layer can set it.
        assert_eq!(log_filter_with(None, None), "info");
    }

    /// Parse a `bsx serve` command line into its args, so a test sees the same defaults clap applies
    /// to the real invocation rather than a hand-built struct that could drift from them.
    fn serve_args(extra: &[&str]) -> ServeArgs {
        #[derive(clap::Parser)]
        struct Harness {
            #[command(flatten)]
            args: ServeArgs,
        }
        let mut argv = vec!["bsx", "--socket", "/tmp/bsx-test.sock"];
        argv.extend_from_slice(extra);
        <Harness as clap::Parser>::parse_from(argv).args
    }

    #[test]
    fn the_default_wall_ceiling_bounds_what_one_exec_can_hold() {
        use crate::policy::Requested;

        // `--idle-timeout` does not arm while a command runs, so without this ceiling one `open`
        // plus one stalled exec holds a slot and its VM for as long as the client asked for.
        let policy = operator_policy(&serve_args(&[]));
        assert_eq!(policy.max_wall_secs, Some(DEFAULT_MAX_WALL_SECS));

        let greedy = Requested {
            wall_secs: Some(u64::MAX),
            ..Requested::default()
        };
        let err = policy
            .resolve(&greedy)
            .expect_err("a wall past the ceiling must be refused, not clamped");
        let message = err.daemon_message();
        assert!(
            message.contains("--max-wall-secs"),
            "the refusal must name the flag that set the ceiling: {message}"
        );

        // A default is not a decision taken from the hoster: the opt-out still restores the
        // unbounded wall, for a fleet whose sessions are meant to run long.
        let unlimited = operator_policy(&serve_args(&["--max-wall-secs", "0"]));
        assert_eq!(unlimited.max_wall_secs, None);
        assert!(
            unlimited.resolve(&greedy).is_ok(),
            "`0` must mean unlimited, as it does for --idle-timeout and --max-sessions"
        );
    }

    #[test]
    fn the_default_output_ceiling_bounds_the_daemons_own_heap() {
        use crate::policy::Requested;

        // The exec collect loop charges every frame against this ask, and the buffer is this
        // process's heap, not the guest's RAM: unbounded is a charge that never refuses.
        let policy = operator_policy(&serve_args(&[]));
        assert_eq!(policy.max_output_cap, Some(Limits::default().output_cap));

        let greedy = Requested {
            output_cap: Some(usize::MAX),
            ..Requested::default()
        };
        let err = policy
            .resolve(&greedy)
            .expect_err("a cap past the ceiling must be refused, not clamped");
        let message = err.daemon_message();
        assert!(
            message.contains("--max-output-cap"),
            "the refusal must name the flag that set the ceiling: {message}"
        );

        // A default is not a decision taken from the hoster: the opt-out restores the unbounded
        // cap for a fleet whose sessions are meant to capture whatever they produce.
        let unlimited = operator_policy(&serve_args(&["--max-output-cap", "0"]));
        assert_eq!(unlimited.max_output_cap, None);
        assert_eq!(
            unlimited
                .resolve(&greedy)
                .expect("`0` must mean unlimited, as it does for --max-wall-secs")
                .output_cap,
            usize::MAX
        );
    }

    #[test]
    fn snapshot_bundles_are_counted_from_disk_so_a_removed_one_frees_budget() {
        // A tally would only ever grow, so a daemon whose bundles the operator has consumed and
        // removed would keep refusing with an empty disk. The count is the disk.
        let scratch = bsx_test_support::ScratchDir::new("snapshot-count");
        let base = scratch.path().join("bundles");
        let mut server = build_test_server(1, 0, 0);
        Arc::get_mut(&mut server)
            .expect("sole owner before the server is shared")
            .snapshot_base = base.clone();

        assert_eq!(
            server.snapshot_bundles().expect("a missing base is zero"),
            0,
            "nothing has snapshotted yet, which is not an error"
        );
        std::fs::create_dir_all(base.join("snap-0")).expect("stage a bundle");
        std::fs::create_dir_all(base.join("snap-1")).expect("stage a bundle");
        assert_eq!(server.snapshot_bundles().expect("readable"), 2);
        std::fs::remove_dir_all(base.join("snap-0")).expect("consume a bundle");
        assert_eq!(
            server.snapshot_bundles().expect("readable"),
            1,
            "removing a consumed bundle must give the budget back"
        );
    }

    #[test]
    fn the_egress_ceiling_reaches_the_policy_a_session_is_resolved_against() {
        use bsx_probes_loader::EgressPolicy;

        // `session::open_network` calls `check_egress`, so what needs pinning is not the check but
        // that the flag reaches the lists it reads: an empty list is a dead ceiling.
        let policy = operator_policy(&serve_args(&["--max-egress", "10.0.0.0/8"]));
        assert_eq!(
            policy.max_egress_v4.len(),
            1,
            "the v4 entry lands in the v4 list"
        );
        assert!(policy.max_egress_v6.is_empty(), "and not in the v6 one");

        let inside = EgressPolicy::default().allow(
            crate::config::parse_v4_cidr("10.1.2.0/24", "test").expect("valid"),
            None,
            None,
        );
        assert!(
            policy.check_egress(&inside).is_ok(),
            "a request inside the ceiling is served"
        );

        let outside = EgressPolicy::default().allow(
            crate::config::parse_v4_cidr("9.9.9.9", "test").expect("valid"),
            None,
            None,
        );
        let msg = policy
            .check_egress(&outside)
            .expect_err("a request outside the ceiling is refused")
            .daemon_message();
        assert!(msg.contains("9.9.9.9"), "the refusal names the ask: {msg}");

        // Unset stays unset: no CIDR ceiling, which is not the same as an open tap.
        let none = operator_policy(&serve_args(&[]));
        assert!(none.max_egress_v4.is_empty() && none.max_egress_v6.is_empty());
        assert!(none.check_egress(&outside).is_ok());
    }

    #[test]
    fn a_max_egress_entry_is_read_in_the_family_its_address_names() {
        let both = operator_policy(&serve_args(&[
            "--max-egress",
            "10.0.0.0/8",
            "--max-egress",
            "fd00::/8",
        ]));
        assert_eq!(both.max_egress_v4.len(), 1);
        assert_eq!(both.max_egress_v6.len(), 1);

        // A typo'd v4 address must report as a bad v4 address, not as a bad v6 one, which is what a
        // try-v4-then-v6 parser would have said.
        let msg = parse_max_egress("10.0.0.999/8").expect_err("not an address");
        assert!(
            msg.contains("IPv4") && msg.contains("--max-egress"),
            "{msg}"
        );
        let msg6 = parse_max_egress("fd00::zz/8").expect_err("not an address");
        assert!(msg6.contains("IPv6"), "{msg6}");
    }

    #[test]
    fn the_default_bounds_snapshot_disk_and_zero_opts_out() {
        let args = serve_args(&[]);
        assert_eq!(args.max_snapshots, DEFAULT_MAX_SNAPSHOTS);
        assert_eq!(serve_args(&["--max-snapshots", "0"]).max_snapshots, 0);
    }

    #[test]
    fn the_liveness_probe_answers_promptly_with_a_full_backlog() {
        // A listener that never accepts fills its backlog, and a *blocking* connect waits on that
        // indefinitely, so a wedged-but-alive daemon would hang a new daemon's startup. The answer
        // must be "yes, live", and prompt, which is why the clock is asserted on.
        //
        // Built by hand with a backlog of **1**: `UnixListener::bind` uses 128, and queueing past
        // that many connections to reproduce the hang is not worth the fds.
        use std::os::fd::AsRawFd as _;
        let scratch = bsx_test_support::ScratchDir::created("bind-wedged");
        let path = scratch.path().join("wedged.sock");
        let addr = nix::sys::socket::UnixAddr::new(&path).expect("addr");
        let listener = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            nix::sys::socket::SockFlag::empty(),
            None,
        )
        .expect("socket");
        nix::sys::socket::bind(listener.as_raw_fd(), &addr).expect("bind");
        nix::sys::socket::listen(
            &listener,
            nix::sys::socket::Backlog::new(1).expect("backlog"),
        )
        .expect("listen");

        // Fill the one-deep queue and then some, with *non-blocking* connects: a blocking one past
        // the backlog would hang the test setup itself, which is the very hazard under test.
        let _fill: Vec<_> = (0..4)
            .filter_map(|_| {
                let fd = nix::sys::socket::socket(
                    nix::sys::socket::AddressFamily::Unix,
                    nix::sys::socket::SockType::Stream,
                    nix::sys::socket::SockFlag::SOCK_NONBLOCK,
                    None,
                )
                .ok()?;
                let _ = nix::sys::socket::connect(fd.as_raw_fd(), &addr);
                Some(fd)
            })
            .collect();

        // Through `bind`, not the probe alone: the defect was reachable only via the caller, and a
        // test of the helper by itself would pass with the blocking connect restored at the call site.
        let started = Instant::now();
        let refused = bind(&path).expect_err("a live daemon must not be clobbered");
        let elapsed = started.elapsed();

        assert!(
            refused.contains("already listening"),
            "a listener that is behind is still a listener: {refused}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the probe must not wait on the backlog: {elapsed:?}"
        );
        assert!(path.exists(), "and the live daemon's socket is left alone");
    }

    #[test]
    fn the_liveness_probe_says_no_for_a_dead_daemons_leftover_socket() {
        let scratch = bsx_test_support::ScratchDir::created("bind-stale");
        let path = scratch.path().join("stale.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        drop(listener); // the daemon died; the socket file outlives it
        assert!(
            !someone_is_listening(&path),
            "nothing is listening, so the file is reclaimable"
        );
        assert!(!someone_is_listening(&scratch.path().join("absent.sock")));
    }

    /// The names a daemon mints and the names its successor's sweep reclaims are one round trip, so
    /// this stages every shape through the minting function and lets the sweep find them. A prefix
    /// that only one half knows is a guest-RAM-sized dir that leaks in silence.
    #[test]
    fn every_bundle_dir_a_daemon_mints_is_one_the_sweep_reclaims() {
        let scratch = bsx_test_support::ScratchDir::created("bundle-sweep");
        // A pid past `pid_max`, so the sweep's liveness check cannot keep these dirs.
        let dead = u32::MAX - 1;
        let mints: [fn(&Path) -> PathBuf; 2] = [prewarm_dir, snapshots_dir];

        // Each dead daemon's dir is named by re-minting what the minting function itself writes,
        // with a dead pid in place of ours. Staging from `BUNDLE_PREFIXES` instead would only prove
        // the sweep reads its own list, which is not where the drift lives.
        let mut staged = Vec::new();
        for mint in mints {
            let ours = mint(scratch.path());
            let name = ours
                .file_name()
                .and_then(|n| n.to_str())
                .expect("a minted bundle dir has a UTF-8 name");
            let prefix = name
                .strip_suffix(&std::process::id().to_string())
                .expect("a minted bundle dir ends in this daemon's pid");
            let dir = scratch.path().join(format!("{prefix}{dead}"));
            std::fs::create_dir(&dir).expect("stage a dead daemon's bundle dir");
            std::fs::write(dir.join("payload"), b"guest ram").expect("stage its contents");
            staged.push(dir);
        }

        // This daemon's own dirs: the sweep runs at *our* startup, so reclaiming them would take
        // out the bundle the pool being built right now references.
        let mine = mints.map(|mint| mint(scratch.path()));
        for dir in &mine {
            std::fs::create_dir(dir).expect("stage our own bundle dir");
        }
        // A per-VM workdir is `sweep_vm_residue`'s to judge, never this one's.
        let bystander = scratch.path().join("bsx-1234-0");
        std::fs::create_dir(&bystander).expect("stage a per-VM workdir");

        sweep_stale_agent_bundles(scratch.path());

        for dir in &staged {
            assert!(
                !dir.exists(),
                "a dead daemon's {} must be reclaimed",
                dir.display()
            );
        }
        for dir in &mine {
            assert!(
                dir.exists(),
                "this daemon's own {} must survive its own sweep",
                dir.display()
            );
        }
        assert!(bystander.exists(), "a per-VM workdir is the other sweep's");
    }

    #[test]
    fn a_mistyped_socket_path_is_refused_not_deleted() {
        // The daemon reclaims a stale socket by removing it and often runs as root, so a `--socket`
        // naming a real file would be a deletion. What matters here is the survival, not the error.
        let dir = bsx_test_support::ScratchDir::created("bind");
        let victim = dir.path().join("precious.toml");
        std::fs::write(&victim, b"do not delete me").expect("write the victim");

        let err = bind(&victim).expect_err("a non-socket path must be refused");
        assert!(err.contains("not a socket"), "got {err}");
        assert_eq!(
            std::fs::read(&victim).expect("the file must still be there"),
            b"do not delete me",
            "refusing must never remove the file it refused"
        );
    }

    #[test]
    fn only_exhaustion_accept_errors_are_paced() {
        // Both halves: nothing else in the tree names these errnos, so a bare list drifts silently,
        // and a predicate that crept wider would hand any local peer a throttle.
        for errno in [
            24,  /* EMFILE */
            23,  /* ENFILE */
            105, /* ENOBUFS */
        ] {
            assert!(
                accept_error_is_exhaustion(&std::io::Error::from_raw_os_error(errno)),
                "errno {errno} is resource exhaustion and must be paced"
            );
        }
        assert!(accept_error_is_exhaustion(&std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "ENOMEM"
        )));
        for e in [
            std::io::Error::from_raw_os_error(103), // ECONNABORTED, the peer hung up mid-handshake
            std::io::Error::from_raw_os_error(4),   // EINTR
            std::io::Error::from_raw_os_error(11),  // EAGAIN
        ] {
            assert!(
                !accept_error_is_exhaustion(&e),
                "{e} is transient: pacing it would let a peer throttle the daemon"
            );
        }
    }

    /// A minimal daemon state for admission tests: no pool, no VM, degraded probes. Holding a
    /// [`SessionTicket`] or a [`ResourceReservation`] never touches a sandbox, so the caps are
    /// provable host-safe.
    fn test_server(max_sessions: usize) -> Arc<Server> {
        build_test_server(max_sessions, 0, 0)
    }

    /// [`test_server`] with the aggregate resource ceilings set (unlimited session count, so only the
    /// resource dimension gates), for the [`ResourceReservation`] tests.
    fn build_test_server(
        max_sessions: usize,
        max_committed_mem_mib: u64,
        max_committed_vcpus: u64,
    ) -> Arc<Server> {
        Arc::new(Server {
            base: bsx_engine::BootConfig::default(),
            isolation: crate::policy::IsolationMode::Unjailed,
            policy: Policy::default(),
            observ: Observability::load(),
            signing_key: bsx_probes_loader::HostKey::from_seed([7u8; 32]),
            pool: None,
            snapshot_base: std::env::temp_dir(),
            snapshot_seq: AtomicU64::new(0),
            metrics: Arc::new(Metrics::default()),
            max_sessions,
            idle_timeout: None,
            active_sessions: AtomicUsize::new(0),
            committed_mem_mib: AtomicU64::new(0),
            committed_vcpus: AtomicU64::new(0),
            max_committed_mem_mib,
            max_committed_vcpus,
            max_snapshots: DEFAULT_MAX_SNAPSHOTS,
        })
    }

    #[test]
    fn the_ceiling_admits_exactly_max_sessions_and_a_freed_slot_readmits() {
        // A slot frees only when its ticket drops. An idle connection holds one without booting a
        // VM, so the whole admission contract is provable host-safe.
        let server = test_server(2);
        let first = SessionTicket::acquire(&server).expect("first admitted");
        let _second = SessionTicket::acquire(&server).expect("second admitted");
        assert!(
            SessionTicket::acquire(&server).is_none(),
            "the third connection must be refused at a ceiling of 2"
        );
        drop(first);
        let _readmitted =
            SessionTicket::acquire(&server).expect("a freed slot must readmit the next connection");
        assert!(
            SessionTicket::acquire(&server).is_none(),
            "the ceiling must hold again after the readmission"
        );
    }

    #[test]
    fn the_aggregate_memory_ceiling_admits_until_full_and_a_freed_reservation_readmits() {
        // Admission on summed memory rather than session count: under a 1024 MiB ceiling two
        // 512 MiB sessions fit, a third of any size is refused, and freeing one readmits.
        let server = build_test_server(0, 1024, 0);
        let first =
            ResourceReservation::try_acquire(&server, 512, 1).expect("first 512 MiB admitted");
        let _second =
            ResourceReservation::try_acquire(&server, 512, 1).expect("second 512 MiB admitted");
        assert!(
            ResourceReservation::try_acquire(&server, 1, 1).is_none(),
            "a third session must be refused once committed memory is at the ceiling"
        );
        drop(first);
        let _readmitted = ResourceReservation::try_acquire(&server, 512, 1)
            .expect("freeing 512 MiB must readmit a 512 MiB session");
        assert_eq!(server.committed_mem_mib.load(Ordering::Relaxed), 1024);
    }

    #[test]
    fn a_vcpu_charge_over_its_ceiling_rolls_back_the_memory_charge() {
        // Both dimensions commit together: if the vCPU charge exceeds its ceiling after the memory
        // charge succeeded, the memory charge is rolled back, so a refused session leaves no residue.
        let server = build_test_server(0, 4096, 2);
        assert!(
            ResourceReservation::try_acquire(&server, 512, 4).is_none(),
            "4 vCPUs must be refused under a 2-vCPU aggregate ceiling"
        );
        assert_eq!(
            server.committed_mem_mib.load(Ordering::Relaxed),
            0,
            "the memory charge must be rolled back when the vCPU charge is refused"
        );
    }

    #[test]
    fn pool_clone_reservations_respect_the_ceiling_and_release_symmetrically() {
        // The pool's clones charge the same committed atomics as sessions, so a refill can only
        // restore what the ceiling affords, and releasing is the exact inverse.
        let clone = pool_clone_limits();
        let clone_mem = u64::from(clone.mem_mib.get());
        // Room for exactly 2 clones (and no third).
        let server = build_test_server(0, clone_mem * 2, 0);
        assert_eq!(
            reserve_pool_clones(&server, 5, &clone),
            2,
            "a want of 5 is capped at what the memory ceiling affords"
        );
        assert_eq!(
            server.committed_mem_mib.load(Ordering::Relaxed),
            clone_mem * 2
        );
        release_pool_clones(&server, 2, &clone);
        assert_eq!(
            server.committed_mem_mib.load(Ordering::Relaxed),
            0,
            "release is symmetric"
        );
        assert_eq!(server.committed_vcpus.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_pool_clone_vcpu_refusal_rolls_back_its_memory_charge() {
        let clone = pool_clone_limits();
        // Memory affords plenty; vCPUs afford exactly one clone.
        let server = build_test_server(0, 0, u64::from(clone.vcpus.get()));
        assert_eq!(reserve_pool_clones(&server, 3, &clone), 1);
        release_pool_clones(&server, 1, &clone);
        assert_eq!(
            server.committed_mem_mib.load(Ordering::Relaxed),
            0,
            "the refused clone's memory leg must not linger"
        );
    }

    #[test]
    fn a_pooled_take_hands_its_charge_to_the_session_reservation() {
        // Startup charges the pool; an open reserves its own footprint; the take releases one
        // clone. Net committed equals one session's worth, exactly the RAM actually resident.
        let clone = pool_clone_limits();
        let clone_mem = u64::from(clone.mem_mib.get());
        let clone_vcpus = u64::from(clone.vcpus.get());
        let server = build_test_server(0, 0, 0);
        // Two prewarmed clones charged at startup (what serve() initializes the atomics to).
        server
            .committed_mem_mib
            .store(clone_mem * 2, Ordering::Relaxed);
        server
            .committed_vcpus
            .store(clone_vcpus * 2, Ordering::Relaxed);
        let _session = ResourceReservation::try_acquire(&server, clone_mem, clone_vcpus)
            .expect("admits with no ceiling");
        release_pool_clones(&server, 1, &clone);
        assert_eq!(
            server.committed_mem_mib.load(Ordering::Relaxed),
            clone_mem * 2,
            "one remaining clone + one live session = two clone-footprints committed"
        );
        assert_eq!(
            server.committed_vcpus.load(Ordering::Relaxed),
            clone_vcpus * 2
        );
    }

    #[test]
    fn a_zero_ceiling_is_unlimited() {
        // The default (`0`) means the aggregate gate is off: any reservation succeeds and only the
        // count ticket applies.
        let server = build_test_server(0, 0, 0);
        let _r = ResourceReservation::try_acquire(&server, 1_000_000, 999)
            .expect("a 0 ceiling admits any size");
    }

    #[test]
    fn zero_max_sessions_means_unlimited() {
        let server = test_server(0);
        let tickets: Vec<_> = (0..64)
            .map(|_| SessionTicket::acquire(&server).expect("unlimited admits every connection"))
            .collect();
        assert_eq!(server.active_sessions.load(Ordering::Relaxed), 64);
        drop(tickets);
        assert_eq!(
            server.active_sessions.load(Ordering::Relaxed),
            0,
            "every dropped ticket must free its slot"
        );
    }

    #[test]
    #[allow(clippy::panic)] // the deliberate panic *is* the unwind this test exercises
    fn a_staged_path_is_removed_even_when_the_scope_unwinds() {
        // A panic between staging a path and publishing it must not strand it. Both the file and
        // dir flavours, plus the disarm: a published path must survive the guard's drop.
        let scratch = bsx_test_support::ScratchDir::created("staged");
        let base = scratch.path();

        let file = base.join("sock.tmp");
        std::fs::write(&file, b"x").expect("stage file");
        let dir = base.join("bundle");
        std::fs::create_dir(&dir).expect("stage dir");
        let (file_p, dir_p) = (file.clone(), dir.clone());
        let caught = std::panic::catch_unwind(move || {
            let _file_guard = StagedPath::new(file_p);
            let _dir_guard = StagedPath::new(dir_p);
            panic!("boom mid-stage");
        });
        assert!(caught.is_err(), "the panic propagated");
        assert!(!file.exists(), "the staged file must be unlinked on unwind");
        assert!(!dir.exists(), "the staged dir must be removed on unwind");

        let kept = base.join("published");
        std::fs::write(&kept, b"x").expect("stage");
        StagedPath::new(kept.clone()).published();
        assert!(kept.exists(), "a published path must survive the guard");
    }

    #[test]
    fn a_refused_connection_gets_the_typed_at_capacity_reply_in_bounded_time() {
        // The refused client's experience: a distinct typed `AtCapacity` reply, delivered within the
        // refusal's 1s write bound, with no VM resource committed to it.
        let server = test_server(1);
        let (client, daemon_end) = UnixStream::pair().expect("socketpair");
        let started = Instant::now();
        refuse_at_capacity(daemon_end, &server);
        let mut reader = std::io::BufReader::new(client);
        let reply = bsx_protocol::read_response(&mut reader)
            .expect("the refusal parses")
            .expect("the refusal is a message, not EOF");
        assert!(
            matches!(&reply, bsx_protocol::Response::AtCapacity { retry_after_ms, .. } if *retry_after_ms > 0),
            "expected the typed at-capacity refusal, got {reply:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the refusal must be bounded by its write timeout"
        );
    }
}
