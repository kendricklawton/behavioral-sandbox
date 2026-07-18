//! The daemon's metrics: a small atomic registry ([`Metrics`]) the session threads increment, and a
//! **Prometheus text-exposition endpoint** ([`serve`]) the *hoster* scrapes — the operational face of
//! "engine, not platform" (the daemon exposes its own numbers; dashboards, alerting, and retention
//! are the hoster's, above the engine).
//!
//! **Hand-rolled on purpose.** The exposition format is a few lines of stable text, and the daemon is
//! synchronous with no async runtime (decision 034's posture), so the endpoint is a plain
//! `TcpListener` + a bounded HTTP/1.1 responder on one thread — the same discipline as the driver's
//! hand-rolled Firecracker HTTP client, not a `tokio`/framework import for one GET route. Scrapes are
//! served sequentially (a scraper polls every few seconds; there is no fan-in to manage), each under
//! a read/write timeout so a stalled peer can't wedge the endpoint.
//!
//! **Prometheus conventions, followed.** Base units (**seconds**, never milliseconds), `_total`
//! suffixes on counters, `# HELP`/`# TYPE` for every family, cumulative histogram buckets with an
//! explicit `+Inf` plus `_sum`/`_count`, an `agentd_build_info` gauge carrying the version as a
//! label, and deliberately **low label cardinality** (fixed `pooled`/`verb`/`kind` sets — nothing
//! per-session or per-client, which would grow without bound).
//!
//! Guardrail 5 applies to the scraper too: the request head is read through a hard byte cap and a
//! socket timeout, so a hostile or broken peer is a dropped connection, never a panic, hang, or
//! unbounded allocation.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
}

impl Verb {
    /// Every verb, in the fixed order the counter array and the rendering share.
    const ALL: [Verb; 5] = [
        Verb::Exec,
        Verb::Put,
        Verb::Get,
        Verb::Snapshot,
        Verb::Trace,
    ];

    /// The `verb` label value.
    fn name(self) -> &'static str {
        match self {
            Verb::Exec => "exec",
            Verb::Put => "put",
            Verb::Get => "get",
            Verb::Snapshot => "snapshot",
            Verb::Trace => "trace",
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
        if let Some(i) = BUCKET_BOUNDS.iter().position(|(bound, _)| secs <= *bound) {
            self.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        self.sum_micros.fetch_add(
            u64::try_from(d.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Append the family's samples: cumulative `_bucket{le=…}` lines, `+Inf`, `_sum` (seconds),
    /// `_count`.
    fn render(&self, out: &mut String, name: &str) {
        let mut cumulative = 0u64;
        for (i, (_, label)) in BUCKET_BOUNDS.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            sample(out, name, &format!("_bucket{{le=\"{label}\"}}"), cumulative);
        }
        let count = self.count.load(Ordering::Relaxed);
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
    /// Sessions currently open (gauge).
    active: AtomicU64,
    /// Requests served, one slot per [`Verb`].
    requests: [AtomicU64; Verb::ALL.len()],
    /// Requests answered with an error, split by the fault taxonomy: `guest` (per-request, the
    /// session survives) vs `infra` (session-ending — the VM is gone).
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
    pub fn session_opened(&self, pooled: bool, boot: Duration) {
        if pooled {
            self.opened_pooled.fetch_add(1, Ordering::Relaxed);
        } else {
            self.opened_cold.fetch_add(1, Ordering::Relaxed);
        }
        self.active.fetch_add(1, Ordering::Relaxed);
        self.boot_seconds.observe(boot);
    }

    /// An `open` that never produced a sandbox.
    pub fn open_failed(&self) {
        self.open_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A live session ended (any path: `close`, EOF, a fatal fault). Paired with
    /// [`session_opened`](Self::session_opened) at the one teardown seam, so the gauge can't drift.
    pub fn session_closed(&self) {
        // Saturating: an unpaired decrement is a bug, but a wrapped gauge lying "18 quintillion
        // active" to the scraper would be worse than clamping at zero.
        let _ = self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
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

    /// Render the whole registry in the Prometheus text exposition format (version 0.0.4).
    /// `pool_ready` is the warm pool's current stock, or `None` when the daemon runs without a pool
    /// (the family is then absent — absent, not zero, so "no pool" and "empty pool" stay
    /// distinguishable to an alert).
    pub fn render(&self, pool_ready: Option<u64>) -> String {
        let mut out = String::with_capacity(2048);

        family(
            &mut out,
            "agentd_build_info",
            "Build metadata; the value is always 1.",
            "gauge",
        );
        sample(
            &mut out,
            "agentd_build_info",
            concat!("{version=\"", env!("CARGO_PKG_VERSION"), "\"}"),
            1,
        );

        family(
            &mut out,
            "agentd_sessions_opened_total",
            "Sessions opened, by whether the warm pool served the boot.",
            "counter",
        );
        sample(
            &mut out,
            "agentd_sessions_opened_total",
            "{pooled=\"true\"}",
            self.opened_pooled.load(Ordering::Relaxed),
        );
        sample(
            &mut out,
            "agentd_sessions_opened_total",
            "{pooled=\"false\"}",
            self.opened_cold.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "agentd_session_open_failures_total",
            "Session opens that failed to produce a sandbox.",
            "counter",
        );
        sample(
            &mut out,
            "agentd_session_open_failures_total",
            "",
            self.open_failures.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "agentd_sessions_active",
            "Sessions currently open (one live microVM each).",
            "gauge",
        );
        sample(
            &mut out,
            "agentd_sessions_active",
            "",
            self.active.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "agentd_requests_total",
            "Requests served after open, by wire verb.",
            "counter",
        );
        for verb in Verb::ALL {
            sample(
                &mut out,
                "agentd_requests_total",
                &format!("{{verb=\"{}\"}}", verb.name()),
                self.requests[verb.index()].load(Ordering::Relaxed),
            );
        }

        family(
            &mut out,
            "agentd_request_errors_total",
            "Requests answered with an error, by fault kind (guest faults are per-request; infra \
             faults end the session).",
            "counter",
        );
        sample(
            &mut out,
            "agentd_request_errors_total",
            "{kind=\"guest\"}",
            self.errors_guest.load(Ordering::Relaxed),
        );
        sample(
            &mut out,
            "agentd_request_errors_total",
            "{kind=\"infra\"}",
            self.errors_infra.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "agentd_protocol_errors_total",
            "Wire lines that failed to decode (malformed, oversize, wrong schema).",
            "counter",
        );
        sample(
            &mut out,
            "agentd_protocol_errors_total",
            "",
            self.protocol_errors.load(Ordering::Relaxed),
        );

        family(
            &mut out,
            "agentd_boot_seconds",
            "Boot-to-serving latency of session sandboxes (warm pops and cold boots alike; split \
             them via agentd_sessions_opened_total's pooled label).",
            "histogram",
        );
        self.boot_seconds.render(&mut out, "agentd_boot_seconds");

        family(
            &mut out,
            "agentd_guest_command_seconds",
            "Host-observed wall time of guest commands (exec, and the no-op runs carrying put/get).",
            "histogram",
        );
        self.guest_command_seconds
            .render(&mut out, "agentd_guest_command_seconds");

        if let Some(ready) = pool_ready {
            family(
                &mut out,
                "agentd_pool_ready",
                "Warm clones currently ready in the pre-warmed pool (absent when no pool).",
                "gauge",
            );
            sample(&mut out, "agentd_pool_ready", "", ready);
        }

        out
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
/// by design (see the module doc); `pool_ready` is sampled per scrape so the gauge is live. Never
/// returns except by the process ending; every per-connection failure is logged and skipped.
pub fn serve(listener: TcpListener, metrics: Arc<Metrics>, pool_ready: impl Fn() -> Option<u64>) {
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "metrics accept failed");
                continue;
            }
        };
        if let Err(e) = answer_scrape(stream, &metrics, &pool_ready) {
            tracing::debug!(error = %e, "metrics scrape failed");
        }
    }
}

/// Answer one connection: read the request head (bounded, under a timeout), then respond with the
/// exposition text for `GET /metrics` and a 404 for anything else.
fn answer_scrape(
    mut stream: TcpStream,
    metrics: &Metrics,
    pool_ready: &impl Fn() -> Option<u64>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(SCRAPE_TIMEOUT))?;
    stream.set_write_timeout(Some(SCRAPE_TIMEOUT))?;
    let head = read_request_head(&mut stream)?;
    let (status, content_type, body) = if is_get_metrics(&head) {
        (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            metrics.render(pool_ready()),
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

/// Read the request head — through the end of the headers (`\r\n\r\n`) — capped at
/// [`MAX_REQUEST_BYTES`]. A peer that never finishes its head inside the cap (or the socket
/// timeout) is an error, so it can't grow memory or hold the endpoint (guardrail 5).
fn read_request_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk)?;
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
        m.session_opened(false, Duration::from_millis(3));
        m.session_opened(false, Duration::from_millis(30));
        m.session_opened(true, Duration::from_secs(7));
        let text = m.render(None);

        // Cumulative: the 3ms one is in every bucket from 0.005 up; the 30ms joins at 0.05; the
        // 7s one appears only at le="10" and +Inf.
        assert!(
            text.contains("agentd_boot_seconds_bucket{le=\"0.005\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("agentd_boot_seconds_bucket{le=\"0.025\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("agentd_boot_seconds_bucket{le=\"0.05\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("agentd_boot_seconds_bucket{le=\"5\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("agentd_boot_seconds_bucket{le=\"10\"} 3"),
            "{text}"
        );
        assert!(
            text.contains("agentd_boot_seconds_bucket{le=\"+Inf\"} 3"),
            "{text}"
        );
        assert!(text.contains("agentd_boot_seconds_count 3"), "{text}");
        // Sum in seconds: 0.003 + 0.030 + 7 = 7.033.
        assert!(text.contains("agentd_boot_seconds_sum 7.033000"), "{text}");
        // The pooled/cold split rode along.
        assert!(
            text.contains("agentd_sessions_opened_total{pooled=\"true\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("agentd_sessions_opened_total{pooled=\"false\"} 2"),
            "{text}"
        );
    }

    #[test]
    fn every_family_carries_help_and_type_and_the_gauge_pairs() {
        let m = Metrics::default();
        m.session_opened(false, Duration::from_millis(100));
        m.session_opened(false, Duration::from_millis(100));
        m.session_closed();
        m.open_failed();
        m.request(Verb::Exec);
        m.request(Verb::Trace);
        m.guest_command(Duration::from_millis(7));
        m.request_failed(true);
        m.request_failed(false);
        m.protocol_error();

        let text = m.render(Some(2));
        for name in [
            "agentd_build_info",
            "agentd_sessions_opened_total",
            "agentd_session_open_failures_total",
            "agentd_sessions_active",
            "agentd_requests_total",
            "agentd_request_errors_total",
            "agentd_protocol_errors_total",
            "agentd_boot_seconds",
            "agentd_guest_command_seconds",
            "agentd_pool_ready",
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
            text.contains("agentd_sessions_active 1"),
            "opened twice, closed once: {text}"
        );
        assert!(
            text.contains("agentd_session_open_failures_total 1"),
            "{text}"
        );
        assert!(
            text.contains("agentd_requests_total{verb=\"exec\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("agentd_requests_total{verb=\"trace\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("agentd_requests_total{verb=\"put\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("agentd_request_errors_total{kind=\"guest\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("agentd_request_errors_total{kind=\"infra\"} 1"),
            "{text}"
        );
        assert!(text.contains("agentd_protocol_errors_total 1"), "{text}");
        assert!(text.contains("agentd_pool_ready 2"), "{text}");
        assert!(text.contains(concat!("{version=\"", env!("CARGO_PKG_VERSION"), "\"} 1")));
    }

    #[test]
    fn without_a_pool_the_pool_family_is_absent_not_zero() {
        // "No pool" and "empty pool" must stay distinguishable to an alert.
        let none = Metrics::default().render(None);
        assert!(!none.contains("agentd_pool_ready"), "{none}");
        let empty = Metrics::default().render(Some(0));
        assert!(empty.contains("agentd_pool_ready 0"), "{empty}");
    }

    #[test]
    fn the_gauge_clamps_at_zero_instead_of_wrapping() {
        // An unpaired decrement is a bug, but the scraped value must never wrap to u64::MAX.
        let m = Metrics::default();
        m.session_closed();
        assert!(m.render(None).contains("agentd_sessions_active 0"));
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
        metrics.session_opened(true, Duration::from_millis(4));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let served = Arc::clone(&metrics);
        std::thread::spawn(move || serve(listener, served, || Some(1)));

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
            ok.contains("agentd_sessions_opened_total{pooled=\"true\"} 1"),
            "{ok}"
        );
        assert!(ok.contains("agentd_pool_ready 1"), "{ok}");

        let missing = scrape("GET /other HTTP/1.1\r\nHost: t\r\n\r\n");
        assert!(
            missing.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{missing}"
        );
    }
}
