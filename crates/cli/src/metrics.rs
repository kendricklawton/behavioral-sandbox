//! The daemon's metrics: a small atomic registry ([`Metrics`]) the session threads increment, and a
//! **Prometheus text-exposition endpoint** ([`serve`]) the *hoster* scrapes: the daemon exposes its
//! own numbers; dashboards, alerting, and retention are the hoster's, above the engine.
//!
//! - **Hand-rolled on purpose.** The exposition format is a few lines of stable text and the daemon is
//!   synchronous, so the endpoint is a plain `TcpListener` plus a bounded HTTP/1.1 responder on one
//!   thread rather than a framework import for one GET route. Scrapes are served sequentially, each under
//!   a read and write timeout so a stalled peer can't wedge the endpoint.
//! - **Prometheus conventions.** Base units in **seconds**, `_total` suffixes on counters,
//!   `# HELP`/`# TYPE` for every family, cumulative histogram buckets with an explicit `+Inf` plus
//!   `_sum`/`_count`, a `bsx_build_info` gauge carrying the version as a label, and deliberately **low
//!   label cardinality**: fixed sets, nothing per-session or per-client.
//! - **The scraper is untrusted input.** The request head is read through a hard byte cap and a socket
//!   timeout, so a hostile or broken peer is a dropped connection rather than a panic, hang, or
//!   unbounded allocation.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bsx_engine::SweepReport;

use crate::deadline::DeadlineStream;

/// Upper bound on one scrape request's head (request line + headers). A scrape is a bare `GET`; far
/// past this is not a scraper.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Per-connection socket budget: a scraper answers in milliseconds; a peer slower than this is
/// stalled and gets dropped so the (sequential) endpoint can serve the next scrape.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(5);

/// The histogram bucket upper bounds, in **seconds** (the Prometheus defaults): wide enough to split
/// a warm-pool `open` (~ms) from a cold boot (~100ms+) and a quick exec from a long one. Paired with
/// their exact label text so rendering never depends on float formatting.
const BUCKET_BOUNDS: [(f64, &str); 11] = [
    (0.005, "0.005"),
    (0.01, "0.01"),
    (0.025, "0.025"),
    (0.05, "0.05"),
    (0.1, "0.1"),
    (0.25, "0.25"),
    (0.5, "0.5"),
    (1.0, "1"),
    (2.5, "2.5"),
    (5.0, "5"),
    (10.0, "10"),
];

/// The wire verbs a session serves after `open`, as low-cardinality counter labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Exec,
    Put,
    Get,
    Snapshot,
    Trace,
    TraceSummary,
}

impl Verb {
    /// Every verb, in the fixed order the counter array and the rendering share.
    const ALL: [Verb; 6] = [
        Verb::Exec,
        Verb::Put,
        Verb::Get,
        Verb::Snapshot,
        Verb::Trace,
        Verb::TraceSummary,
    ];

    /// The `verb` label value.
    fn name(self) -> &'static str {
        match self {
            Verb::Exec => "exec",
            Verb::Put => "put",
            Verb::Get => "get",
            Verb::Snapshot => "snapshot",
            Verb::Trace => "trace",
            Verb::TraceSummary => "trace_summary",
        }
    }

    /// This verb's slot in the counter array.
    fn index(self) -> usize {
        match self {
            Verb::Exec => 0,
            Verb::Put => 1,
            Verb::Get => 2,
            Verb::Snapshot => 3,
            Verb::Trace => 4,
            Verb::TraceSummary => 5,
        }
    }
}

/// A fixed-bucket histogram of durations, all-atomic so many session threads observe concurrently
/// without a lock. Buckets store **per-bucket** counts; the cumulative `le` form Prometheus expects
/// is computed at render time. The sum is kept in integer microseconds (an `f64` can't be atomic)
/// and rendered as seconds.
#[derive(Debug, Default)]
struct Histogram {
    /// One slot per [`BUCKET_BOUNDS`] entry: observations at or under that bound (and over the one
    /// before it). Observations past the last bound land only in `count` (the `+Inf` bucket).
    buckets: [AtomicU64; BUCKET_BOUNDS.len()],
    /// Total observed time, microseconds.
    sum_micros: AtomicU64,
    /// Total observations (the `+Inf` cumulative bucket).
    count: AtomicU64,
}

impl Histogram {
    /// Record one observation.
    fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        // Bump `count` (the `+Inf` cumulative) *before* the per-bucket slot: `render` sums the buckets
        // first and reads `count` last, so a concurrent scrape momentarily *under*-counts one bucket, which
        // is valid, rather than over-counting it into the non-monotonic histogram the exposition spec
        // forbids. The loads stay `Relaxed`, since this is a best-effort nudge rather than
        // synchronization.
        self.count.fetch_add(1, Ordering::Relaxed);
        if let Some(i) = BUCKET_BOUNDS.iter().position(|(bound, _)| secs <= *bound) {
            self.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        self.sum_micros.fetch_add(
            u64::try_from(d.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Append the family's samples: cumulative `_bucket{le=…}` lines, `+Inf`, `_sum` (seconds),
    /// `_count`.
    fn render(&self, out: &mut String, name: &str) {
        let mut cumulative = 0u64;
        for (i, (_, label)) in BUCKET_BOUNDS.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            sample(out, name, &format!("_bucket{{le=\"{label}\"}}"), cumulative);
        }
        // `+Inf` and `_count` must be >= every finite bucket cumulative. `Relaxed` promises no
        // cross-thread order, so a scrape can see a slot increment without the matching `count` one:
        // clamping up to `cumulative` keeps the exposition monotonic. Steady state is a no-op, and the
        // raised value keeps `+Inf` and `_count` equal, as the spec also requires.
        let count = self.count.load(Ordering::Relaxed).max(cumulative);
        sample(out, name, "_bucket{le=\"+Inf\"}", count);
        let sum_secs = self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
        sample(out, name, "_sum", format!("{sum_secs:.6}"));
        sample(out, name, "_count", count);
    }
}

/// The daemon's metric registry: plain atomics the session threads bump (no lock on any hot path)
/// and [`render`](Self::render) reads. Counters only go up; the one gauge (`sessions_active`) is
/// inc/dec-paired on the session open/close seam.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Sessions opened from the warm pool / by a cold boot (the `pooled` label pair).
    opened_pooled: AtomicU64,
    opened_cold: AtomicU64,
    /// `open`s that failed to produce a sandbox (boot/restore failure, invalid limits).
    open_failures: AtomicU64,
    /// Connections/opens refused with `at_capacity`, by which ceiling refused them: the session
    /// count (`--max-sessions`) vs an aggregate resource ceiling (`--max-committed-*`). Without
    /// this, a saturated daemon scrapes as healthy while bouncing every caller.
    refused_sessions: AtomicU64,
    refused_resources: AtomicU64,
    /// Sessions currently open (gauge).
    active: AtomicU64,
    /// Active sessions whose VM-lifetime sentinel could not be armed (gauge).
    sentinel_degraded: AtomicU64,
    /// Orphaned per-VM scratch dirs and network namespaces reclaimed by sweeps (counters).
    sweep_dirs_reclaimed: AtomicU64,
    sweep_netns_reclaimed: AtomicU64,
    /// Requests served, one slot per [`Verb`].
    requests: [AtomicU64; Verb::ALL.len()],
    /// Requests answered with an error, split by the fault taxonomy: `guest` (per-request, the
    /// session survives) vs `infra` (session-ending, the VM is gone).
    errors_guest: AtomicU64,
    errors_infra: AtomicU64,
    /// Lines that failed to decode (malformed, oversize, wrong schema).
    protocol_errors: AtomicU64,
    /// Boot-to-serving latency of session sandboxes (a warm pop or a cold boot).
    boot_seconds: Histogram,
    /// Host-observed wall time of guest commands (`exec`/`put`/`get`).
    guest_command_seconds: Histogram,
}

impl Metrics {
    /// A session's sandbox came up (pooled or cold) and the session is now live.
    pub fn session_opened(&self, pooled: bool, boot: Duration, sentinel_degraded: bool) {
        if pooled {
            self.opened_pooled.fetch_add(1, Ordering::Relaxed);
        } else {
            self.opened_cold.fetch_add(1, Ordering::Relaxed);
        }
        if sentinel_degraded {
            self.sentinel_degraded.fetch_add(1, Ordering::Relaxed);
        }
        self.active.fetch_add(1, Ordering::Relaxed);
        self.boot_seconds.observe(boot);
    }

    /// An `open` that never produced a sandbox.
    pub fn open_failed(&self) {
        self.open_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A connection or `open` refused with `at_capacity`: `resource_ceiling` distinguishes an
    /// aggregate committed-resource refusal from the session-count ceiling.
    pub fn open_refused(&self, resource_ceiling: bool) {
        if resource_ceiling {
            self.refused_resources.fetch_add(1, Ordering::Relaxed);
        } else {
            self.refused_sessions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A live session ended (any path: `close`, EOF, a fatal fault). Paired with
    /// [`session_opened`](Self::session_opened) at the one teardown seam, so the gauge can't drift.
    pub fn session_closed(&self, sentinel_degraded: bool) {
        if sentinel_degraded {
            let _ =
                self.sentinel_degraded
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
        }
        // Saturating: an unpaired decrement is a bug, but a wrapped gauge lying "18 quintillion
        // active" to the scraper would be worse than clamping at zero.
        let _ = self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    /// Record an orphan sweep report: increment counters for reclaimed dirs and netns.
    pub fn record_sweep(&self, report: &SweepReport) {
        if report.dirs_reclaimed > 0 {
            self.sweep_dirs_reclaimed
                .fetch_add(report.dirs_reclaimed as u64, Ordering::Relaxed);
        }
        if report.netns_reclaimed > 0 {
            self.sweep_netns_reclaimed
                .fetch_add(report.netns_reclaimed as u64, Ordering::Relaxed);
        }
    }

    /// One request of `verb` was served (counted whether it succeeds or errors).
    pub fn request(&self, verb: Verb) {
        self.requests[verb.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// A request was answered with an error; `guest_fault` follows the session fault taxonomy.
    pub fn request_failed(&self, guest_fault: bool) {
        if guest_fault {
            self.errors_guest.fetch_add(1, Ordering::Relaxed);
        } else {
            self.errors_infra.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A line that failed to decode (malformed JSON, over the cap, wrong wire schema).
    pub fn protocol_error(&self) {
        self.protocol_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// A guest command finished; record its host-observed wall time.
    pub fn guest_command(&self, wall: Duration) {
        self.guest_command_seconds.observe(wall);
    }

    /// Render the whole registry in the Prometheus text exposition format (version 0.0.4). `cap` is a
    /// fresh per-scrape snapshot of live capacity (warm-pool stock, committed resources, and the
    /// aggregate ceilings): `pool_ready` is `None` when the daemon runs without a pool (the family is
    /// then absent, not zero, so "no pool" and "empty pool" stay distinguishable to an alert), and the
    /// committed/capacity gauges let a fleet dispatcher route on real headroom.
    pub fn render(&self, cap: &CapacitySample) -> String {
        let mut out = String::with_capacity(2048);

        family(
            &mut out,
            "bsx_build_info",
            "Build metadata; the value is always 1.",
            "gauge",
        );
        sample(
            &mut out,
            "bsx_build_info",
            concat!("{version=\"", env!("CARGO_PKG_VERSION"), "\"}"),
            1,
        );

        family(
            &mut out,
            "bsx_sessions_opened_total",
            "Sessions opened, by whether the warm pool served the boot.",
            "counter",
        );
        sample(
            &mut out,
            "bsx_sessions_opened_total",
            "{pooled=\"true\"}",
            self.opened_pooled.load(Ordering::Relaxed),
        );
        sample(
            &mut out,
            "bsx_sessions_opened_total",
            "{pooled=\"false\"}",
            self.opened_cold.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_session_open_failures_total",
            "Session opens that failed to produce a sandbox.",
            "counter",
        );
        sample(
            &mut out,
            "bsx_session_open_failures_total",
            "",
            self.open_failures.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_open_refusals_total",
            "Connections/opens refused with at_capacity, by which ceiling refused them.",
            "counter",
        );
        sample(
            &mut out,
            "bsx_open_refusals_total",
            "{reason=\"sessions\"}",
            self.refused_sessions.load(Ordering::Relaxed),
        );
        sample(
            &mut out,
            "bsx_open_refusals_total",
            "{reason=\"resources\"}",
            self.refused_resources.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_sessions_active",
            "Sessions currently open (one live microVM each).",
            "gauge",
        );
        sample(
            &mut out,
            "bsx_sessions_active",
            "",
            self.active.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_sentinel_degraded",
            "Active sessions whose VM-lifetime sentinel could not be armed (fallback to Drop-only cleanup).",
            "gauge",
        );
        sample(
            &mut out,
            "bsx_sentinel_degraded",
            "",
            self.sentinel_degraded.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_sweep_reclaimed_total",
            "Orphaned VM resources reclaimed by orphan sweeps, by resource type.",
            "counter",
        );
        sample(
            &mut out,
            "bsx_sweep_reclaimed_total",
            "{resource=\"dirs\"}",
            self.sweep_dirs_reclaimed.load(Ordering::Relaxed),
        );
        sample(
            &mut out,
            "bsx_sweep_reclaimed_total",
            "{resource=\"netns\"}",
            self.sweep_netns_reclaimed.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_requests_total",
            "Requests served after open, by wire verb.",
            "counter",
        );
        for verb in Verb::ALL {
            sample(
                &mut out,
                "bsx_requests_total",
                &format!("{{verb=\"{}\"}}", verb.name()),
                self.requests[verb.index()].load(Ordering::Relaxed),
            );
        }

        family(
            &mut out,
            "bsx_request_errors_total",
            "Requests answered with an error, by fault kind (guest faults are per-request; infra \
             faults end the session).",
            "counter",
        );
        sample(
            &mut out,
            "bsx_request_errors_total",
            "{kind=\"guest\"}",
            self.errors_guest.load(Ordering::Relaxed),
        );
        sample(
            &mut out,
            "bsx_request_errors_total",
            "{kind=\"infra\"}",
            self.errors_infra.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_protocol_errors_total",
            "Wire lines that failed to decode (malformed, oversize, wrong schema).",
            "counter",
        );
        sample(
            &mut out,
            "bsx_protocol_errors_total",
            "",
            self.protocol_errors.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "bsx_boot_seconds",
            "Boot-to-serving latency of session sandboxes (warm pops and cold boots alike; split \
             them via bsx_sessions_opened_total's pooled label).",
            "histogram",
        );
        self.boot_seconds.render(&mut out, "bsx_boot_seconds");

        family(
            &mut out,
            "bsx_guest_command_seconds",
            "Host-observed wall time of guest commands (exec, and the no-op runs carrying put/get).",
            "histogram",
        );
        self.guest_command_seconds
            .render(&mut out, "bsx_guest_command_seconds");

        if let Some(ready) = cap.pool_ready {
            family(
                &mut out,
                "bsx_pool_ready",
                "Warm clones currently ready in the pre-warmed pool (absent when no pool).",
                "gauge",
            );
            sample(&mut out, "bsx_pool_ready", "", ready);
        }

        // Resource-aware admission headroom: committed vs the aggregate ceiling, so a
        // fleet dispatcher routes on real memory/vCPU headroom, not just session count. A `0` ceiling
        // means unlimited, rendered as `0` (an operator reads it as "count-only admission").
        family(
            &mut out,
            "bsx_committed_mem_mib",
            "Guest memory (MiB) committed across live sessions.",
            "gauge",
        );
        sample(&mut out, "bsx_committed_mem_mib", "", cap.committed_mem_mib);
        family(
            &mut out,
            "bsx_committed_vcpus",
            "vCPUs committed across live sessions.",
            "gauge",
        );
        sample(&mut out, "bsx_committed_vcpus", "", cap.committed_vcpus);
        family(
            &mut out,
            "bsx_capacity_mem_mib",
            "Aggregate committed-memory ceiling (--max-committed-mem-mib; 0 = unlimited).",
            "gauge",
        );
        sample(
            &mut out,
            "bsx_capacity_mem_mib",
            "",
            cap.max_committed_mem_mib,
        );
        family(
            &mut out,
            "bsx_capacity_vcpus",
            "Aggregate committed-vCPU ceiling (--max-committed-vcpus; 0 = unlimited).",
            "gauge",
        );
        sample(&mut out, "bsx_capacity_vcpus", "", cap.max_committed_vcpus);

        out
    }
}

/// A per-scrape snapshot of the daemon's live capacity, gathered fresh each scrape (like the pool
/// stock already is) so the gauges are current: warm-pool stock, committed guest memory/vCPUs, and
/// the aggregate ceilings they run against.
#[derive(Default, Clone, Copy)]
pub struct CapacitySample {
    /// Warm clones ready in the pool, or `None` for a daemon with no pool (keeps "no pool" and
    /// "empty pool" distinguishable).
    pub pool_ready: Option<u64>,
    /// Guest memory (MiB) committed across live sessions.
    pub committed_mem_mib: u64,
    /// vCPUs committed across live sessions.
    pub committed_vcpus: u64,
    /// The aggregate committed-memory ceiling (`0` = unlimited).
    pub max_committed_mem_mib: u64,
    /// The aggregate committed-vCPU ceiling (`0` = unlimited).
    pub max_committed_vcpus: u64,
}

impl CapacitySample {
    /// A pool-only sample (committed gauges zero, ceilings unlimited), for tests and callers that
    /// track no committed resources.
    #[cfg(test)]
    fn pool(pool_ready: Option<u64>) -> Self {
        Self {
            pool_ready,
            ..Self::default()
        }
    }
}

/// Append a family's `# HELP` and `# TYPE` lines.
fn family(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push_str("\n# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

/// Append one sample line: `name<suffix-or-labels> value`.
fn sample(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
    out.push_str(name);
    out.push_str(labels);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Serve the metrics endpoint forever: accept, answer one bounded `GET /metrics`, close. Sequential
/// by design (see the module doc); `sample` is called per scrape so the capacity gauges are live.
/// Never returns except by the process ending; every per-connection failure is logged and skipped.
pub fn serve(listener: TcpListener, metrics: Arc<Metrics>, sample: impl Fn() -> CapacitySample) {
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                // Paced only on resource exhaustion, which fails instantly and persistently; a
                // transient error must not become a throttle any peer can pull (see the daemon's
                // accept loop, whose predicate this shares).
                tracing::warn!(error = %e, "metrics accept failed");
                if crate::serve::accept_error_is_exhaustion(&e) {
                    std::thread::sleep(crate::serve::ACCEPT_BACKOFF);
                }
                continue;
            }
        };
        if let Err(e) = answer_scrape(stream, &metrics, &sample) {
            tracing::debug!(error = %e, "metrics scrape failed");
        }
    }
}

/// Answer one connection: read the request head (bounded, under a timeout), then respond with the
/// exposition text for `GET /metrics` and a 404 for anything else.
fn answer_scrape(
    mut stream: TcpStream,
    metrics: &Metrics,
    sample: &impl Fn() -> CapacitySample,
) -> std::io::Result<()> {
    stream.set_write_timeout(Some(SCRAPE_TIMEOUT))?;
    // Bound the *whole* request head by one absolute deadline, not each read: a slow-drip peer
    // (one byte just inside a bare `SO_RCVTIMEO`) would otherwise hold this single-threaded
    // endpoint until the byte cap. `DeadlineStream` (inside `read_request_head`) is that bound.
    let head = read_request_head(&stream, SCRAPE_TIMEOUT)?;
    let (status, content_type, body) = if is_get_metrics(&head) {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            metrics.render(&sample()),
        )
    } else {
        (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        )
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

/// Read the request head, through the end of the headers (`\r\n\r\n`), capped at
/// [`MAX_REQUEST_BYTES`] and by one absolute `budget` across all reads (the shared
/// [`DeadlineStream`]). A peer that never finishes its head inside the cap or the deadline is an
/// error, so it can't grow memory or hold the endpoint.
fn read_request_head(stream: &TcpStream, budget: Duration) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    let mut bounded = DeadlineStream::new(
        stream,
        Some(budget),
        "scrape request head exceeded the deadline",
    );
    loop {
        let n = bounded.read(&mut chunk)?;
        if n == 0 {
            return Ok(head); // peer closed after (or mid-) request; judge what we have
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head exceeds the scrape cap",
            ));
        }
    }
}

/// Whether the request line is `GET /metrics` (any HTTP/1.x version, an optional query ignored).
fn is_get_metrics(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let Some(line) = text.lines().next() else {
        return false;
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    method == "GET" && (target == "/metrics" || target.starts_with("/metrics?"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    #[test]
    fn histograms_render_cumulative_buckets_in_seconds() {
        let m = Metrics::default();
        // 3 ms, 30 ms, and 7 s: one lands in le=0.005, one in le=0.05, one only under +Inf.
        m.session_opened(false, Duration::from_millis(3), false);
        m.session_opened(false, Duration::from_millis(30), false);
        m.session_opened(true, Duration::from_secs(7), false);
        let text = m.render(&CapacitySample::pool(None));

        // Cumulative: the 3ms one is in every bucket from 0.005 up; the 30ms joins at 0.05; the
        // 7s one appears only at le="10" and +Inf.
        assert!(
            text.contains("bsx_boot_seconds_bucket{le=\"0.005\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("bsx_boot_seconds_bucket{le=\"0.025\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("bsx_boot_seconds_bucket{le=\"0.05\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("bsx_boot_seconds_bucket{le=\"5\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("bsx_boot_seconds_bucket{le=\"10\"} 3"),
            "{text}"
        );
        assert!(
            text.contains("bsx_boot_seconds_bucket{le=\"+Inf\"} 3"),
            "{text}"
        );
        assert!(text.contains("bsx_boot_seconds_count 3"), "{text}");
        // Sum in seconds: 0.003 + 0.030 + 7 = 7.033.
        assert!(text.contains("bsx_boot_seconds_sum 7.033000"), "{text}");
        // The pooled/cold split rode along.
        assert!(
            text.contains("bsx_sessions_opened_total{pooled=\"true\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("bsx_sessions_opened_total{pooled=\"false\"} 2"),
            "{text}"
        );
    }

    #[test]
    fn every_family_carries_help_and_type_and_the_gauge_pairs() {
        let m = Metrics::default();
        m.session_opened(false, Duration::from_millis(100), false);
        m.session_opened(false, Duration::from_millis(100), true);
        m.session_closed(true);
        m.open_failed();
        m.open_refused(false);
        m.open_refused(true);
        m.open_refused(true);
        m.request(Verb::Exec);
        m.request(Verb::Trace);
        m.guest_command(Duration::from_millis(7));
        m.request_failed(true);
        m.request_failed(false);
        m.protocol_error();

        let text = m.render(&CapacitySample::pool(Some(2)));
        for name in [
            "bsx_build_info",
            "bsx_sessions_opened_total",
            "bsx_session_open_failures_total",
            "bsx_open_refusals_total",
            "bsx_sessions_active",
            "bsx_requests_total",
            "bsx_request_errors_total",
            "bsx_protocol_errors_total",
            "bsx_boot_seconds",
            "bsx_guest_command_seconds",
            "bsx_pool_ready",
        ] {
            assert!(
                text.contains(&format!("# HELP {name} ")),
                "missing HELP for {name}"
            );
            assert!(
                text.contains(&format!("# TYPE {name} ")),
                "missing TYPE for {name}"
            );
        }
        assert!(
            text.contains("bsx_sessions_active 1"),
            "opened twice, closed once: {text}"
        );
        assert!(text.contains("bsx_session_open_failures_total 1"), "{text}");
        assert!(
            text.contains("bsx_open_refusals_total{reason=\"sessions\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("bsx_open_refusals_total{reason=\"resources\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("bsx_requests_total{verb=\"exec\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("bsx_requests_total{verb=\"trace\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("bsx_requests_total{verb=\"put\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("bsx_request_errors_total{kind=\"guest\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("bsx_request_errors_total{kind=\"infra\"} 1"),
            "{text}"
        );
        assert!(text.contains("bsx_protocol_errors_total 1"), "{text}");
        assert!(text.contains("bsx_pool_ready 2"), "{text}");
        assert!(text.contains(concat!("{version=\"", env!("CARGO_PKG_VERSION"), "\"} 1")));
    }

    #[test]
    fn without_a_pool_the_pool_family_is_absent_not_zero() {
        // "No pool" and "empty pool" must stay distinguishable to an alert.
        let none = Metrics::default().render(&CapacitySample::pool(None));
        assert!(!none.contains("bsx_pool_ready"), "{none}");
        let empty = Metrics::default().render(&CapacitySample::pool(Some(0)));
        assert!(empty.contains("bsx_pool_ready 0"), "{empty}");
    }

    #[test]
    fn the_committed_resource_gauges_reflect_the_capacity_sample() {
        // The admission headroom a dispatcher routes on: committed vs the aggregate
        // ceiling, both dimensions, always present (unlike the pool family).
        let text = Metrics::default().render(&CapacitySample {
            pool_ready: None,
            committed_mem_mib: 768,
            committed_vcpus: 3,
            max_committed_mem_mib: 2048,
            max_committed_vcpus: 8,
        });
        assert!(text.contains("bsx_committed_mem_mib 768"), "{text}");
        assert!(text.contains("bsx_committed_vcpus 3"), "{text}");
        assert!(text.contains("bsx_capacity_mem_mib 2048"), "{text}");
        assert!(text.contains("bsx_capacity_vcpus 8"), "{text}");
    }

    #[test]
    fn the_gauge_clamps_at_zero_instead_of_wrapping() {
        // An unpaired decrement is a bug, but the scraped value must never wrap to u64::MAX.
        let m = Metrics::default();
        m.session_closed(false);
        assert!(
            m.render(&CapacitySample::pool(None))
                .contains("bsx_sessions_active 0")
        );
    }

    #[test]
    fn a_bucket_visible_before_its_count_still_renders_monotonic() {
        // The weak-ordering transient the render-side clamp guards: a scrape sees a per-bucket increment
        // but not the matching `count` one, since the two `Relaxed` writes carry no cross-thread order.
        // Modelled directly as a bucket at 1 with `count` still 0.
        let h = Histogram::default();
        h.buckets[0].store(1, Ordering::Relaxed);
        let mut out = String::new();
        h.render(&mut out, "x");
        assert!(out.contains("x_bucket{le=\"0.005\"} 1"), "{out}");
        assert!(
            out.contains("x_bucket{le=\"+Inf\"} 1"),
            "+Inf clamps up: {out}"
        );
        assert!(out.contains("x_count 1"), "count matches +Inf: {out}");
    }

    #[test]
    #[allow(clippy::panic)] // a disappearing sample is a test failure, reported via panic
    fn counters_and_histograms_never_decrease_across_any_op_sequence() {
        // "Counters only go up" as an asserted property rather than an argument: a deterministic random op
        // sequence, with every sample checked against its previous render after each op. The one gauge is
        // exempt by design, being inc/dec paired, and its own tests cover it.
        fn samples(render: &str) -> std::collections::HashMap<String, f64> {
            render
                .lines()
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .filter_map(|l| {
                    let (name, value) = l.rsplit_once(' ')?;
                    let is_monotone = ["_total", "_count", "_sum"]
                        .iter()
                        .any(|s| name.split('{').next().unwrap_or(name).ends_with(s))
                        || name.contains("_bucket{");
                    if is_monotone {
                        Some((name.to_string(), value.parse().ok()?))
                    } else {
                        None
                    }
                })
                .collect()
        }

        let m = Metrics::default();
        // The shared generator, seeded exactly as the local one was: `Rng::new` forces the seed
        // odd and this one already is, so the sequence is the same walk as before.
        let mut rng = bsx_test_support::Rng::new(0x9E37_79B9_7F4A_7C15);
        let mut next = || rng.next_u64();
        let mut prev = samples(&m.render(&CapacitySample::pool(None)));
        let mut compared = 0usize;
        for _ in 0..500 {
            match next() % 8 {
                0 => m.session_opened(
                    next() % 2 == 0,
                    Duration::from_millis(next() % 3_000),
                    next() % 2 == 0,
                ),
                1 => m.open_failed(),
                2 => m.session_closed(next() % 2 == 0),
                3 => m.request(match next() % 4 {
                    0 => Verb::Exec,
                    1 => Verb::Put,
                    2 => Verb::Get,
                    _ => Verb::Trace,
                }),
                4 => m.request_failed(next() % 2 == 0),
                5 => m.protocol_error(),
                6 => m.guest_command(Duration::from_millis(next() % 10_000)),
                _ => {} // a render-only step: sampling must not perturb anything either
            }
            let now = samples(&m.render(&CapacitySample::pool(Some(next() % 4))));
            for (name, value) in &prev {
                let current = now
                    .get(name)
                    .copied()
                    .unwrap_or_else(|| panic!("sample {name} disappeared between renders"));
                assert!(current >= *value, "{name} decreased: {value} -> {current}");
                compared += 1;
            }
            prev = now;
        }
        // Anti-vacuous floor: the walk must actually have compared a meaningful sample set.
        assert!(
            compared > 1_000,
            "only {compared} comparisons; the parser went vacuous"
        );
    }

    #[test]
    fn the_request_line_parser_only_accepts_get_metrics() {
        assert!(is_get_metrics(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(is_get_metrics(b"GET /metrics?ts=1 HTTP/1.0\r\n\r\n"));
        assert!(!is_get_metrics(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!is_get_metrics(b"POST /metrics HTTP/1.1\r\n\r\n"));
        assert!(!is_get_metrics(b"GET /metricsX HTTP/1.1\r\n\r\n"));
        assert!(!is_get_metrics(b""));
        assert!(!is_get_metrics(&[0xFF, 0xFE]));
    }

    /// The endpoint end to end, host-safe: bind an ephemeral loopback port, serve on a thread, and
    /// scrape it exactly as Prometheus would.
    #[test]
    fn the_endpoint_serves_the_exposition_text_over_http() {
        let metrics = Arc::new(Metrics::default());
        metrics.session_opened(true, Duration::from_millis(4), false);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let served = Arc::clone(&metrics);
        std::thread::spawn(move || serve(listener, served, || CapacitySample::pool(Some(1))));

        let scrape = |request: &str| -> String {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            stream.write_all(request.as_bytes()).expect("send");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read");
            response
        };

        let ok = scrape("GET /metrics HTTP/1.1\r\nHost: t\r\nAccept: */*\r\n\r\n");
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.contains("text/plain; version=0.0.4"), "{ok}");
        assert!(
            ok.contains("bsx_sessions_opened_total{pooled=\"true\"} 1"),
            "{ok}"
        );
        assert!(ok.contains("bsx_pool_ready 1"), "{ok}");

        let missing = scrape("GET /other HTTP/1.1\r\nHost: t\r\n\r\n");
        assert!(
            missing.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{missing}"
        );
    }

    #[test]
    fn a_slow_drip_head_is_bounded_by_the_absolute_deadline() {
        // A peer that dribbles bytes without ever finishing the head must not hold the endpoint:
        // the read loop is bounded by one wall-clock deadline, not a per-read timeout the drip
        // keeps resetting. The server-side end of a real connection, fed one byte then left idle,
        // must return a TimedOut error well before any byte cap, within ~the deadline.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client.write_all(b"G").expect("drip one byte"); // a partial head, never completed
        let start = std::time::Instant::now();
        let err = read_request_head(&server, Duration::from_millis(200))
            .expect_err("must time out, not hang");
        // Bounded either way: the shrunk socket timeout fires (`WouldBlock`) or the deadline guard
        // trips (`TimedOut`); both mean the endpoint was released, not held.
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "a drip must end in a timeout, got {:?}",
            err.kind()
        );
        // The real proof: it returned near the 200ms deadline, far under the 5s per-read
        // `SCRAPE_TIMEOUT`, which a one-byte-per-4.9s drip would otherwise reset indefinitely.
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "returned near the deadline, not after a full per-read timeout: {:?}",
            start.elapsed()
        );
        drop(client);
    }
}
