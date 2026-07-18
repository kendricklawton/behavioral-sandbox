//! Phase 16 demo, as tests: drive the real `agentd` daemon over its unix socket through the full
//! **versioned wire API**, `open` → (`exec` | `put` | `get` | `snapshot` | `trace` |
//! `trace_summary`)\* → `close`.
//! Three angles:
//!
//! 1. [`agentd_serves_the_full_wire_api_over_a_unix_socket`] drives it with **hand-built JSON lines**
//!    (parsed with `serde_json::Value`, no access to the daemon's Rust types), the proof the wire is
//!    hand-debuggable and every message carries its `schema`.
//! 2. [`the_reference_client_drives_a_full_session`] drives the same daemon through the **reference
//!    client** ([`agentd_client::Client`]), the P16.4 proof a caller needs only the wire contract
//!    (the client links no `agent-vmm`).
//! 3. [`a_prewarmed_open_is_served_from_the_pool`] launches `agentd --prewarm 1` and asserts a bare
//!    `open` comes back `pooled: true`, the P16.3 fast path.
//!
//! `#[ignore]`d: each spawns the daemon, which boots real microVMs (needs `/dev/kvm` + the agent
//! rootfs). Run via `cargo xtask ci-privileged` or `cargo test -p agent-cli -- --ignored`. Unjailed
//! on purpose, the proof is the wire API, not the jailer (that has its own suite), and unjailed
//! doesn't need root.
// A test binary: `panic!`/`expect` is the idiomatic assertion, which the workspace's `clippy::panic`
// deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agentd_client::{Client, OpenOptions};

/// The workspace root, from this crate's manifest dir, so the artifact paths are cwd-independent.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Why this host can't run the demo (a skip reason), or `None` when it can.
fn skip_reason() -> Option<String> {
    if !std::path::Path::new("/dev/kvm").exists() {
        return Some("/dev/kvm not present".into());
    }
    if !workspace_root()
        .join("artifacts/rootfs-agent.ext4")
        .is_file()
    {
        return Some("agent rootfs not built (run `cargo xtask build-rootfs`)".into());
    }
    None
}

/// A spawned `agentd` that is SIGKILLed on drop, so a panicking assertion can't leak the daemon (its
/// session VMs are then reaped by the lifetime sentinel; the socket file it leaves is cleared on the
/// next bind).
struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A free loopback port for the daemon's metrics endpoint: bind an ephemeral listener, note its
/// port, release it. (A small bind race with another process is possible but fine for a test.)
fn free_loopback_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("probe a port: {e}"));
    listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local addr: {e}"))
        .port()
}

/// `GET /metrics` from the daemon's endpoint, returning the exposition body.
fn scrape_metrics(port: u16) -> String {
    use std::io::Read as _;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("connect to the metrics endpoint: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap_or_else(|e| panic!("set read timeout: {e}"));
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: t\r\n\r\n")
        .unwrap_or_else(|e| panic!("send the scrape: {e}"));
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .unwrap_or_else(|e| panic!("read the scrape: {e}"));
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    response
}

/// Launch `agentd` on a private socket, pointed at the workspace's agent rootfs. `prewarm` becomes
/// `--prewarm N` when set (the pool path); `metrics_port` becomes `--metrics 127.0.0.1:PORT`.
/// Returns once the socket is connectable.
fn launch_daemon(prewarm: Option<usize>, metrics_port: Option<u16>) -> (Daemon, PathBuf) {
    let root = workspace_root();
    let dir = std::env::temp_dir().join(format!("agentd-e2e-{}-{:?}", std::process::id(), prewarm));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("create the daemon's socket dir: {e}");
    }
    let socket = dir.join("agentd.sock");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentd"));
    cmd.arg("--unjailed").arg("--socket").arg(&socket);
    if let Some(n) = prewarm {
        cmd.arg("--prewarm").arg(n.to_string());
    }
    if let Some(port) = metrics_port {
        cmd.arg("--metrics").arg(format!("127.0.0.1:{port}"));
    }
    cmd.env("AGENT_ROOTFS", root.join("artifacts/rootfs-agent.ext4"))
        // The agent rootfs signals readiness with its own marker, not a getty `login:`.
        .env("AGENT_MARKER", agent_vmm::GUEST_READY_MARKER)
        .env("AGENT_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cmd.env("AGENT_KERNEL", root.join("artifacts/vmlinux"));
    }
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn agentd: {e}"));
    let daemon = Daemon { child, dir };

    // Wait for the daemon to bind and start accepting. A prewarmed daemon boots a source + clones
    // first, so allow it longer.
    let budget = if prewarm.is_some() { 40 } else { 10 };
    let deadline = Instant::now() + Duration::from_secs(budget);
    while Instant::now() < deadline {
        if UnixStream::connect(&socket).is_ok() {
            return (daemon, socket);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("agentd never began accepting on {}", socket.display());
}

/// A tiny **raw-JSON** client over the daemon's newline protocol: send a request line, read one
/// response object. Every line the daemon accepts must carry the `schema`, so [`send`](Self::send)
/// takes only the body and stamps it, mirroring what a hand-typed `socat` session sends.
struct RawClient {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl RawClient {
    fn connect(socket: &PathBuf) -> Self {
        let stream =
            UnixStream::connect(socket).unwrap_or_else(|e| panic!("connect to agentd: {e}"));
        if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(45))) {
            panic!("set read timeout: {e}");
        }
        let writer = stream
            .try_clone()
            .unwrap_or_else(|e| panic!("clone the connection: {e}"));
        Self {
            writer,
            reader: BufReader::new(stream),
        }
    }

    /// Send one request `body` (the JSON without its schema), stamped with `"schema":1`. The body
    /// keeps its own closing brace (only its leading `{` is dropped to splice `schema` in first), so
    /// the template must not add one.
    fn send(&mut self, body: &str) {
        let line = format!("{{\"schema\":1,{}\n", body.trim_start_matches('{'));
        if let Err(e) = self.writer.write_all(line.as_bytes()) {
            panic!("send a request line: {e}");
        }
        if let Err(e) = self.writer.flush() {
            panic!("flush: {e}");
        }
    }

    fn recv(&mut self) -> serde_json::Value {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .unwrap_or_else(|e| panic!("read a response line: {e}"));
        assert!(n > 0, "the daemon closed the connection unexpectedly");
        serde_json::from_str(line.trim())
            .unwrap_or_else(|e| panic!("a response is one JSON object ({e}): {line:?}"))
    }
}

#[test]
#[ignore = "spawns agentd; needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn agentd_serves_the_full_wire_api_over_a_unix_socket() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping agentd_serves_the_full_wire_api_over_a_unix_socket: {why}");
        return;
    }
    let metrics_port = free_loopback_port();
    let (_daemon, socket) = launch_daemon(None, Some(metrics_port));
    let mut client = RawClient::connect(&socket);

    // Open: the sandbox boots, the daemon reports its latency, and (no pool) `pooled` is false.
    client.send("{\"op\":\"open\"}");
    let opened = client.recv();
    assert_eq!(
        opened["reply"], "opened",
        "first reply is `opened`: {opened}"
    );
    assert!(
        opened["boot_ms"].as_u64().is_some(),
        "opened carries a boot latency: {opened}"
    );
    assert_eq!(
        opened["pooled"], false,
        "no --prewarm, so a cold boot: {opened}"
    );

    // Exec: stdout comes back, exit 0. The response carries its own schema too.
    client.send("{\"op\":\"exec\",\"argv\":[\"echo\",\"hi\"]}");
    let echoed = client.recv();
    assert_eq!(
        echoed["schema"], 1,
        "every reply is schema-stamped: {echoed}"
    );
    assert_eq!(echoed["reply"], "result", "{echoed}");
    assert_eq!(echoed["exit_code"], 0, "{echoed}");
    assert_eq!(echoed["stdout"], "hi\n", "{echoed}");

    // Stdin rides the request and reaches the command.
    client.send("{\"op\":\"exec\",\"argv\":[\"cat\"],\"stdin\":\"piped\\n\"}");
    assert_eq!(client.recv()["stdout"], "piped\n", "stdin fed the command");

    // put/get: a file written by `put` reads back by `get`, proving the working directory persists.
    client.send("{\"op\":\"put\",\"path\":\"note.txt\",\"content\":\"from put\\n\"}");
    assert_eq!(client.recv()["reply"], "put", "put is acknowledged");
    client.send("{\"op\":\"get\",\"path\":\"note.txt\"}");
    let got = client.recv();
    assert_eq!(got["reply"], "got", "{got}");
    assert_eq!(got["present"], true, "the put file exists: {got}");
    assert_eq!(
        got["content"], "from put\n",
        "get returns what put wrote: {got}"
    );
    // A missing file is `present:false`, not an error.
    client.send("{\"op\":\"get\",\"path\":\"nope.txt\"}");
    assert_eq!(
        client.recv()["present"],
        false,
        "a missing get is present:false"
    );

    // put is visible to a following exec too (same working directory).
    client.send("{\"op\":\"exec\",\"argv\":[\"cat\",\"note.txt\"]}");
    assert_eq!(
        client.recv()["stdout"],
        "from put\n",
        "put lands in the working dir"
    );

    // snapshot (unjailed session): a bundle directory comes back, and the session survives it.
    client.send("{\"op\":\"snapshot\"}");
    let snap = client.recv();
    assert_eq!(
        snap["reply"], "snapshotted",
        "unjailed snapshot succeeds: {snap}"
    );
    assert!(
        snap["dir"].as_str().is_some_and(|d| !d.is_empty()),
        "snapshot returns a bundle dir: {snap}"
    );
    client.send("{\"op\":\"exec\",\"argv\":[\"echo\",\"post-snap\"]}");
    assert_eq!(
        client.recv()["stdout"],
        "post-snap\n",
        "the session survives a snapshot"
    );

    // trace: the host-observed audit record, carrying its own (audit) schema.
    client.send("{\"op\":\"trace\"}");
    let traced = client.recv();
    assert_eq!(traced["reply"], "trace", "{traced}");
    assert!(
        traced["record"]["schema"].as_u64().is_some(),
        "the record carries its audit schema: {traced}"
    );

    // trace_summary: the model-legible projection over the wire, its own summary schema, and the
    // agent-loop shape (a `reached` list, a resource envelope), a smaller line than the full record.
    client.send("{\"op\":\"trace_summary\"}");
    let summarized = client.recv();
    assert_eq!(summarized["reply"], "trace_summary", "{summarized}");
    assert!(
        summarized["summary"]["schema"].as_u64().is_some(),
        "the summary carries its own schema: {summarized}"
    );
    assert!(
        summarized["summary"]["resources"]["cpu_ns"]
            .as_u64()
            .is_some(),
        "the summary carries the resource envelope over the wire: {summarized}"
    );

    // A guest fault (an unrunnable command) is a non-fatal error the session survives.
    client.send("{\"op\":\"exec\",\"argv\":[\"definitely-not-a-real-binary-zzz\"]}");
    let faulted = client.recv();
    assert_eq!(
        faulted["reply"], "error",
        "a guest fault is an error: {faulted}"
    );
    assert_eq!(
        faulted["fatal"], false,
        "a guest fault is non-fatal: {faulted}"
    );
    client.send("{\"op\":\"exec\",\"argv\":[\"echo\",\"alive\"]}");
    assert_eq!(
        client.recv()["stdout"],
        "alive\n",
        "the session survives a guest fault"
    );

    // A wrong wire schema is a fatal, session-ending error (the peer speaks another protocol).
    if let Err(e) = client
        .writer
        .write_all(b"{\"schema\":999,\"op\":\"exec\",\"argv\":[]}\n")
    {
        panic!("send a wrong-schema line: {e}");
    }
    let rejected = client.recv();
    assert_eq!(rejected["reply"], "error", "{rejected}");
    assert_eq!(
        rejected["fatal"], true,
        "a schema mismatch ends the session: {rejected}"
    );

    // A fresh connection opens a brand-new, independent session, the put file is gone.
    let mut second = RawClient::connect(&socket);
    second.send("{\"op\":\"open\"}");
    assert_eq!(second.recv()["reply"], "opened");
    second.send("{\"op\":\"get\",\"path\":\"note.txt\"}");
    assert_eq!(
        second.recv()["present"],
        false,
        "a new session is a new sandbox; the prior session's file is gone"
    );
    second.send("{\"op\":\"close\"}");
    assert_eq!(second.recv()["reply"], "closed");

    // The hoster's metrics endpoint saw all of it: two cold sessions (none active now), the verbs,
    // the guest fault, the wrong-schema protocol error, and boot observations in seconds. The
    // `closed` reply lands before the daemon's teardown finishes, so poll until the active gauge
    // settles at zero rather than racing it.
    let deadline = Instant::now() + Duration::from_secs(15);
    let scraped = loop {
        let body = scrape_metrics(metrics_port);
        if body.contains("agentd_sessions_active 0") || Instant::now() >= deadline {
            break body;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        scraped.contains("agentd_sessions_opened_total{pooled=\"false\"} 2"),
        "{scraped}"
    );
    assert!(scraped.contains("agentd_sessions_active 0"), "{scraped}");
    assert!(
        scraped.contains("agentd_requests_total{verb=\"put\"} 1"),
        "{scraped}"
    );
    assert!(
        scraped.contains("agentd_requests_total{verb=\"snapshot\"} 1"),
        "{scraped}"
    );
    assert!(
        scraped.contains("agentd_request_errors_total{kind=\"guest\"} 1"),
        "{scraped}"
    );
    assert!(
        scraped.contains("agentd_protocol_errors_total 1"),
        "{scraped}"
    );
    assert!(scraped.contains("agentd_boot_seconds_count 2"), "{scraped}");
}

#[test]
#[ignore = "spawns agentd; needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn the_reference_client_drives_a_full_session() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping the_reference_client_drives_a_full_session: {why}");
        return;
    }
    let (_daemon, socket) = launch_daemon(None, None);

    // The whole session over the reference client, the exact surface a non-Rust SDK reimplements.
    let mut client = Client::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    if let Err(e) = client.set_read_timeout(Some(Duration::from_secs(45))) {
        panic!("set read timeout: {e}");
    }

    let opened = client
        .open(OpenOptions::default())
        .unwrap_or_else(|e| panic!("open: {e}"));
    assert!(!opened.pooled, "no --prewarm, so a cold boot");

    let echo = vec!["echo".to_string(), "hello".to_string()];
    let run = client
        .exec(&echo, "")
        .unwrap_or_else(|e| panic!("exec: {e}"));
    assert_eq!(run.exit_code, 0, "echo exits 0");
    assert_eq!(run.stdout, "hello\n", "exec returns stdout");

    client
        .put("data.txt", "payload\n")
        .unwrap_or_else(|e| panic!("put: {e}"));
    let back = client
        .get("data.txt")
        .unwrap_or_else(|e| panic!("get: {e}"));
    assert_eq!(
        back.as_deref(),
        Some("payload\n"),
        "get returns what put wrote"
    );
    assert_eq!(
        client
            .get("absent.txt")
            .unwrap_or_else(|e| panic!("get: {e}")),
        None,
        "a missing file is None, not an error"
    );

    let record = client.trace().unwrap_or_else(|e| panic!("trace: {e}"));
    assert!(
        record["schema"].as_u64().is_some(),
        "the trace record carries its audit schema: {record}"
    );

    // The reference client exposes the projection too, the model-legible face over the wire.
    let summary = client
        .trace_summary()
        .unwrap_or_else(|e| panic!("trace_summary: {e}"));
    assert!(
        summary["schema"].as_u64().is_some(),
        "the summary carries its own schema: {summary}"
    );

    let dir = client
        .snapshot()
        .unwrap_or_else(|e| panic!("snapshot: {e}"));
    assert!(!dir.is_empty(), "snapshot returns a bundle dir");

    client.close().unwrap_or_else(|e| panic!("close: {e}"));
}

#[test]
#[ignore = "spawns agentd --prewarm; needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn a_prewarmed_open_is_served_from_the_pool() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_prewarmed_open_is_served_from_the_pool: {why}");
        return;
    }
    let (_daemon, socket) = launch_daemon(Some(1), None);

    let mut client = Client::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    if let Err(e) = client.set_read_timeout(Some(Duration::from_secs(45))) {
        panic!("set read timeout: {e}");
    }
    // A bare-default open must come from the warm pool: `pooled: true`, and it still execs.
    let opened = client
        .open(OpenOptions::default())
        .unwrap_or_else(|e| panic!("open: {e}"));
    assert!(
        opened.pooled,
        "a bare open under --prewarm is served from the pool"
    );
    let run = client
        .exec(&["echo".to_string(), "warm".to_string()], "")
        .unwrap_or_else(|e| panic!("exec: {e}"));
    assert_eq!(run.stdout, "warm\n", "a pooled session execs normally");
    client.close().unwrap_or_else(|e| panic!("close: {e}"));
}
