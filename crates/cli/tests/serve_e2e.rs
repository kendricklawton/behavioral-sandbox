//! The `bsx serve` daemon end to end, as tests (the wire API, docs/daemon.md): drive the
//! real daemon over its unix socket through the full
//! **versioned wire API**, `open` → (`exec` | `put` | `get` | `snapshot` | `trace` |
//! `trace_summary`)\* → `close`.
//! Three angles:
//!
//! 1. [`agent_serves_the_full_wire_api_over_a_unix_socket`] drives it with **hand-built JSON lines**
//!    (parsed with `serde_json::Value`, no access to the daemon's Rust types), the proof the wire is
//!    hand-debuggable and every message carries its `schema`.
//! 2. [`the_reference_client_drives_a_full_session`] drives the same daemon through the **reference
//!    client** ([`bsx_client::Client`]), the proof a caller needs only the wire contract
//!    (the client links no `bsx`).
//! 3. [`a_prewarmed_open_is_served_from_the_pool`] launches `agent --prewarm 1` and asserts a bare
//!    `open` comes back `pooled: true`, the pre-warmed-pool fast path (docs/daemon.md).
//!
//! `#[ignore]`d: each spawns the daemon, which boots real microVMs (needs `/dev/kvm` + the guest-agent
//! rootfs). Run via `cargo xtask ci-privileged` or `cargo test -p bsx -- --ignored`. Unjailed
//! on purpose, the proof is the wire API, not the jailer (that has its own suite), and unjailed
//! doesn't need root, except [`a_jailed_daemon_serves_prewarmed_opens`], which exists precisely
//! because the jailed daemon composes pieces no other suite drives together (it self-skips
//! without root).
// A test binary: `panic!`/`expect` is the idiomatic assertion, which the workspace's `clippy::panic`
// deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bsx_client::{Client, OpenParams};

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
        .join("artifacts/rootfs-guest.ext4")
        .is_file()
    {
        return Some("guest rootfs not built (run `cargo xtask build-rootfs`)".into());
    }
    None
}

/// A spawned `bsx serve` that is SIGKILLed on drop, so a panicking assertion can't leak the daemon (its
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

/// Launch `bsx serve` on a private socket, pointed at the workspace's guest rootfs. `prewarm` becomes
/// `--prewarm N` when set (the pool path); `metrics_port` becomes `--metrics 127.0.0.1:PORT`.
/// Returns once the socket is connectable.
fn launch_daemon(prewarm: Option<usize>, metrics_port: Option<u16>) -> (Daemon, PathBuf) {
    launch_daemon_opts(prewarm, metrics_port, false, &[])
}

fn launch_daemon_opts(
    prewarm: Option<usize>,
    metrics_port: Option<u16>,
    jailed: bool,
    extra_args: &[&str],
) -> (Daemon, PathBuf) {
    let root = workspace_root();
    // A per-call sequence number, because the process id alone cannot distinguish two tests in
    // this one binary: two launches with the same knobs (`agent_serves…` and `cancel_reclaims…`
    // both pass `(None, None)`) would otherwise share a dir, and each `remove_dir_all` below then
    // deletes the *other* test's live socket, a flake that only fires when the scheduler overlaps
    // them.
    static LAUNCH_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = LAUNCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("bsx-e2e-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("create the daemon's socket dir: {e}");
    }
    let socket = dir.join("bsx.sock");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bsx"));
    cmd.arg("serve");
    if !jailed {
        cmd.arg("--unjailed");
    }
    cmd.arg("--socket").arg(&socket);
    if let Some(n) = prewarm {
        cmd.arg("--prewarm").arg(n.to_string());
    }
    if let Some(port) = metrics_port {
        cmd.arg("--metrics").arg(format!("127.0.0.1:{port}"));
    }
    cmd.args(extra_args);
    cmd.env("BSX_ROOTFS", root.join("artifacts/rootfs-guest.ext4"))
        // The guest rootfs signals readiness with its own marker, not a getty `login:`.
        .env("BSX_MARKER", bsx_engine::GUEST_READY_MARKER)
        // Keep the daemon's generated record-signing key inside the test's socket dir.
        .env("BSX_SIGNING_KEY", dir.join("signing.key"))
        .env("BSX_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if std::env::var_os("BSX_KERNEL").is_none() {
        cmd.env("BSX_KERNEL", root.join("artifacts/vmlinux"));
    }
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn bsx: {e}"));
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
    panic!("bsx never began accepting on {}", socket.display());
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
        let stream = UnixStream::connect(socket).unwrap_or_else(|e| panic!("connect to bsx: {e}"));
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
#[ignore = "spawns bsx; needs /dev/kvm + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn agent_serves_the_full_wire_api_over_a_unix_socket() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping agent_serves_the_full_wire_api_over_a_unix_socket: {why}");
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
    let piped = client.recv();
    assert_eq!(piped["stdout"], "piped\n", "stdin fed the command: {piped}");

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
    let missing = client.recv();
    assert_eq!(
        missing["present"], false,
        "a missing get is present:false: {missing}"
    );

    // put is visible to a following exec too (same working directory).
    client.send("{\"op\":\"exec\",\"argv\":[\"cat\",\"note.txt\"]}");
    let noted = client.recv();
    assert_eq!(
        noted["stdout"], "from put\n",
        "put lands in the working dir: {noted}"
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
    // The daemon runs on this host, so the returned bundle dir must really exist (a fabricated
    // path would satisfy the non-empty check alone).
    let snap_dir = snap["dir"].as_str().expect("dir string");
    assert!(
        std::fs::metadata(snap_dir).is_ok_and(|m| m.is_dir()),
        "the returned bundle dir exists: {snap_dir}"
    );
    client.send("{\"op\":\"exec\",\"argv\":[\"echo\",\"post-snap\"]}");
    let post_snap = client.recv();
    assert_eq!(
        post_snap["stdout"], "post-snap\n",
        "the session survives a snapshot: {post_snap}"
    );

    // trace: the host-observed audit record, a signed envelope. The wire `record`
    // field carries the schema-2 envelope; the record itself rides inside as a string.
    client.send("{\"op\":\"trace\"}");
    let traced = client.recv();
    assert_eq!(traced["reply"], "trace", "{traced}");
    assert_eq!(
        traced["record"]["schema"], 2,
        "the signed envelope: {traced}"
    );
    assert!(
        traced["record"]["signature"]
            .as_str()
            .is_some_and(|s| s.len() == 128),
        "the record is signed: {traced}"
    );
    // The signature must actually *verify*, not merely exist (128 hex chars of garbage would pass
    // the shape check). Envelope-level field order doesn't matter to `verify`; the signed bytes are
    // the embedded record string, which survives the reply's serde round-trip.
    let envelope = serde_json::to_string(&traced["record"]).expect("re-serialize envelope");
    let signer = bsx_probes_loader::TrustedKey::from_hex(
        traced["record"]["key_id"].as_str().expect("key_id string"),
    )
    .expect("key_id parses as an ed25519 public key");
    bsx_probes_loader::verify(&envelope, &[signer])
        .expect("the daemon's signed record verifies against the key it names");
    let inner: serde_json::Value =
        serde_json::from_str(traced["record"]["record"].as_str().expect("record string"))
            .expect("inner record parses");
    assert!(
        inner["schema"].as_u64().is_some(),
        "the embedded record carries its audit schema: {inner}"
    );
    // The first trace is the unchained anchor (no `prev`).
    assert!(
        traced["record"].get("prev").is_none(),
        "the first trace is unchained: {traced}"
    );

    // A second trace chains to the first: its `prev` is the SHA-256 of the first
    // record, so the sequence is tamper-evident as a whole, not just per record.
    let first_record = traced["record"]["record"]
        .as_str()
        .expect("first record string")
        .to_string();
    client.send("{\"op\":\"trace\"}");
    let traced2 = client.recv();
    assert_eq!(
        traced2["record"]["prev"].as_str(),
        Some(bsx_probes_loader::record_hash(&first_record).as_str()),
        "the second trace commits to the first record's hash: {traced2}"
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
        if body.contains("bsx_sessions_active 0") || Instant::now() >= deadline {
            break body;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        scraped.contains("bsx_sessions_opened_total{pooled=\"false\"} 2"),
        "{scraped}"
    );
    assert!(scraped.contains("bsx_sessions_active 0"), "{scraped}");
    assert!(
        scraped.contains("bsx_requests_total{verb=\"put\"} 1"),
        "{scraped}"
    );
    assert!(
        scraped.contains("bsx_requests_total{verb=\"snapshot\"} 1"),
        "{scraped}"
    );
    assert!(
        scraped.contains("bsx_request_errors_total{kind=\"guest\"} 1"),
        "{scraped}"
    );
    assert!(scraped.contains("bsx_protocol_errors_total 1"), "{scraped}");
    assert!(scraped.contains("bsx_boot_seconds_count 2"), "{scraped}");
}

#[test]
#[ignore = "spawns bsx; needs /dev/kvm + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn a_run_whose_output_outgrows_a_request_line_still_reaches_the_client() {
    if let Some(why) = skip_reason() {
        eprintln!(
            "skipping a_run_whose_output_outgrows_a_request_line_still_reaches_the_client: {why}"
        );
        return;
    }
    let (_daemon, socket) = launch_daemon(None, None);
    let mut client = Client::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    if let Err(e) = client.set_read_timeout(Some(Duration::from_secs(60))) {
        panic!("set read timeout: {e}");
    }
    client
        .open(OpenParams::default())
        .unwrap_or_else(|e| panic!("open: {e}"));

    // Six MiB, past `MAX_REQUEST_BYTES` and well inside the default `output_cap`. A reply bounded by
    // the request cap could not carry this, and the client saw the session close with no reply and
    // no diagnostic. The assertion is that a run's own output comes back.
    const OUT: usize = 6 * 1024 * 1024;
    let flood = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("head -c {OUT} /dev/zero | tr '\\0' 'x'"),
    ];
    let run = client.exec(&flood, "").unwrap_or_else(|e| {
        panic!("a {OUT}-byte run must return its output, not a dead session: {e}")
    });
    assert_eq!(run.exit_code, 0, "the command itself succeeds");
    assert_eq!(
        run.stdout.len(),
        OUT,
        "every byte the engine captured must reach the client"
    );

    // And the session is still usable, so nothing about the large reply retired the VM.
    let run = client
        .exec(&["echo".to_string(), "still-here".to_string()], "")
        .unwrap_or_else(|e| panic!("the session must survive a large reply: {e}"));
    assert_eq!(run.stdout, "still-here\n");
    client.close().unwrap_or_else(|e| panic!("close: {e}"));
}

#[test]
#[ignore = "spawns bsx; needs /dev/kvm + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn the_reference_client_drives_a_full_session() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping the_reference_client_drives_a_full_session: {why}");
        return;
    }
    let (_daemon, socket) = launch_daemon(None, None);

    // The whole session over the reference client, the exact surface a non-Rust client reimplements.
    let mut client = Client::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    if let Err(e) = client.set_read_timeout(Some(Duration::from_secs(45))) {
        panic!("set read timeout: {e}");
    }

    let opened = client
        .open(OpenParams::default())
        .unwrap_or_else(|e| panic!("open: {e}"));
    assert!(!opened.pooled, "no --prewarm, so a cold boot");

    let echo = vec!["echo".to_string(), "hello".to_string()];
    let run = client
        .exec(&echo, "")
        .unwrap_or_else(|e| panic!("exec: {e}"));
    assert_eq!(run.exit_code, 0, "echo exits 0");
    assert_eq!(run.stdout, "hello\n", "exec returns stdout");

    // `env` over the wire: the CLI could always set variables (`bsx run --env`), but no wire client
    // could, so a client had no way to pass configuration to a command. Prove both halves of the
    // contract, since the second is the one that matters.
    let print_var = vec![
        "sh".to_string(),
        "-c".to_string(),
        "printf %s \"$WIRE_TOKEN\"".to_string(),
    ];
    let run = client
        .exec_with_env(
            &print_var,
            "",
            &[(
                "WIRE_TOKEN".to_string(),
                "carried-over-the-wire".to_string(),
            )],
        )
        .unwrap_or_else(|e| panic!("exec_with_env: {e}"));
    assert_eq!(run.exit_code, 0, "the command runs");
    assert_eq!(
        run.stdout, "carried-over-the-wire",
        "the variable must reach the spawned command"
    );

    // The scoping promise: env is set on the **spawned command only**, so it must not survive into
    // the next exec on the same session. If it leaked, one caller's credentials would be visible to
    // every later command in that session, which is the whole reason the agent uses `Command::env`
    // rather than setting its own environment.
    let run = client
        .exec(&print_var, "")
        .unwrap_or_else(|e| panic!("exec: {e}"));
    assert_eq!(
        run.stdout, "",
        "a later exec must not inherit the previous exec's environment"
    );

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
    assert_eq!(
        record["schema"], 2,
        "the signed envelope over the wire: {record}"
    );
    assert!(
        record["record"].as_str().is_some(),
        "the envelope carries the record as a string: {record}"
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
#[ignore = "spawns bsx --prewarm; needs /dev/kvm + the guest rootfs (run via `cargo xtask ci-privileged`)"]
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
        .open(OpenParams::default())
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

#[test]
#[ignore = "needs /dev/kvm + real root + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn a_jailed_daemon_serves_prewarmed_opens() {
    // The composition the rest of this (deliberately unjailed) suite never drives: `serve
    // --prewarm` under the jailer. The daemon's pool source is a Sandbox, so its bundle carries a
    // private disk, and every jailed clone stages that disk into its chroot; a staging regression
    // there once killed every jailed pool build while the unjailed suite and the `bsx`-level
    // shared-base pool test both stayed green. This is the missing gate.
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_jailed_daemon_serves_prewarmed_opens: {why}");
        return;
    }
    if !bsx_test_support::have_real_root() {
        eprintln!(
            "skipping a_jailed_daemon_serves_prewarmed_opens: needs real root (the jailer mknods \
             device nodes)"
        );
        return;
    }
    let (_daemon, socket) = launch_daemon_opts(Some(1), None, true, &[]);

    let mut client = Client::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    if let Err(e) = client.set_read_timeout(Some(Duration::from_secs(45))) {
        panic!("set read timeout: {e}");
    }
    let opened = client
        .open(OpenParams::default())
        .unwrap_or_else(|e| panic!("open: {e}"));
    assert!(
        opened.pooled,
        "a bare open on a jailed --prewarm daemon must come from the pool; `pooled: false` means \
         the jailed pool build failed and the daemon silently fell back to cold boots"
    );
    let run = client
        .exec(&["echo".to_string(), "confined-warm".to_string()], "")
        .unwrap_or_else(|e| panic!("exec: {e}"));
    assert_eq!(
        run.stdout, "confined-warm\n",
        "the jailed pooled session execs"
    );
    client.close().unwrap_or_else(|e| panic!("close: {e}"));
}

#[test]
#[ignore = "needs /dev/kvm + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn cancel_reclaims_a_session_wedged_in_a_long_exec() {
    // The one verb legal while a request is in flight. Without it a client blocked in a long `exec`
    // has no way to reach the daemon: hanging up works, but the session thread stays inside
    // `exec` until the wall budget lapses, holding its `--max-sessions` slot and the guest's RAM.
    // Here the exec would run 60s; the cancel must end it in a small fraction of that.
    if let Some(why) = skip_reason() {
        eprintln!("skipping cancel_reclaims_a_session_wedged_in_a_long_exec: {why}");
        return;
    }
    let (_daemon, socket) = launch_daemon(None, None);

    let mut stream = UnixStream::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    // A second handle so the cancel can be written while the first is blocked awaiting the reply,
    // which is exactly the shape a real client needs (the blocked call owns the connection).
    let mut canceller = stream
        .try_clone()
        .unwrap_or_else(|e| panic!("clone the connection: {e}"));

    // A generous session budget so the *exec*, not the wall clock, is what cancel interrupts.
    writeln!(stream, r#"{{"schema":1,"op":"open","wall_secs":120}}"#)
        .unwrap_or_else(|e| panic!("send open: {e}"));
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .unwrap_or_else(|e| panic!("clone for reading: {e}")),
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("read the open reply: {e}"));
    assert!(
        line.contains(r#""reply":"opened""#),
        "expected an opened reply, got {line}"
    );

    writeln!(
        stream,
        r#"{{"schema":1,"op":"exec","argv":["sleep","60"]}}"#
    )
    .unwrap_or_else(|e| panic!("send exec: {e}"));

    // Let the exec actually reach the guest, so this cancels a *running* command rather than
    // racing the daemon before it dispatches.
    std::thread::sleep(Duration::from_secs(2));
    let started = Instant::now();
    writeln!(canceller, r#"{{"schema":1,"op":"cancel"}}"#)
        .unwrap_or_else(|e| panic!("send cancel: {e}"));

    line.clear();
    reader
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("read the cancel reply: {e}"));
    let elapsed = started.elapsed();
    assert!(
        line.contains(r#""reply":"cancelled""#),
        "expected a cancelled reply, got {line}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "cancel should end a 60s exec promptly, took {elapsed:?}"
    );
}

#[test]
#[ignore = "needs /dev/kvm + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn a_cancel_after_the_idle_deadline_still_gets_its_ack() {
    // The sibling of `cancel_reclaims_a_session_wedged_in_a_long_exec`, at the corner where the
    // exec outlives `--idle-timeout`. The per-message deadline was armed when the *exec request*
    // arrived, so by the time a long exec is interrupted it has lapsed; the post-interrupt read
    // that looks for the client's `cancel` must run on a fresh budget, or the ack is replaced by
    // a silent connection drop exactly for the long execs cancel exists to interrupt. (The VM is
    // killed either way; what this pins is the client-visible `cancelled` reply.)
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_cancel_after_the_idle_deadline_still_gets_its_ack: {why}");
        return;
    }
    let (_daemon, socket) = launch_daemon_opts(None, None, false, &["--idle-timeout", "2"]);

    let mut stream = UnixStream::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    let mut canceller = stream
        .try_clone()
        .unwrap_or_else(|e| panic!("clone the connection: {e}"));

    // A wall budget far past the idle timeout, so the exec is what outlives the deadline.
    writeln!(stream, r#"{{"schema":1,"op":"open","wall_secs":120}}"#)
        .unwrap_or_else(|e| panic!("send open: {e}"));
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .unwrap_or_else(|e| panic!("clone for reading: {e}")),
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("read the open reply: {e}"));
    assert!(
        line.contains(r#""reply":"opened""#),
        "expected an opened reply, got {line}"
    );

    writeln!(
        stream,
        r#"{{"schema":1,"op":"exec","argv":["sleep","60"]}}"#
    )
    .unwrap_or_else(|e| panic!("send exec: {e}"));

    // Sit out the 2s idle budget (armed at the exec request) plus slack, so the deadline has
    // provably lapsed before the cancel goes out.
    std::thread::sleep(Duration::from_secs(4));
    writeln!(canceller, r#"{{"schema":1,"op":"cancel"}}"#)
        .unwrap_or_else(|e| panic!("send cancel: {e}"));

    line.clear();
    reader
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("read the cancel reply: {e}"));
    assert!(
        line.contains(r#""reply":"cancelled""#),
        "a cancel sent after the idle deadline lapsed must still be acknowledged, got {line:?} \
         (an empty line is the connection dropping without the ack)"
    );
}

/// Open the daemon at `socket` with `open_body` (the raw JSON after the schema stamp) and return
/// the one reply line.
fn open_reply(socket: &PathBuf, open_body: &str) -> String {
    let mut stream = UnixStream::connect(socket).unwrap_or_else(|e| panic!("connect: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap_or_else(|e| panic!("set read timeout: {e}"));
    writeln!(stream, r#"{{"schema":1,{open_body}}}"#).unwrap_or_else(|e| panic!("send open: {e}"));
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("read the open reply: {e}"));
    line
}

// NOT `#[ignore]`d, alone in this file: a refused `open` is answered before any VM exists, so this
// runs on a host with no KVM and no rootfs, which puts the wire's fault taxonomy in the everyday
// host-safe gate.
#[test]
fn an_operator_ceiling_refusal_is_kind_refused_on_the_wire() {
    // The book's fault table (docs/daemon-protocol.md): `refused` is "understood and declined: an
    // operator-chosen posture"; `protocol` is "the client's own message". An ask past an operator
    // ceiling is a well-formed request this host declines, so it must arrive as `refused`: a client
    // branching on the table would otherwise read a policy refusal as its own malformed message.
    let (_daemon, socket) = launch_daemon_opts(None, None, false, &["--max-vcpus", "2"]);

    let line = open_reply(&socket, r#""op":"open","vcpus":16"#);
    assert!(
        line.contains(r#""reply":"error""#) && line.contains(r#""fatal":true"#),
        "an over-ceiling open is a fatal error reply, got {line}"
    );
    assert!(
        line.contains(r#""kind":"refused""#),
        "an operator ceiling is the daemon declining, not a malformed message: {line}"
    );
    // The refusal points at the knob the operator actually set. This daemon's policy is its own
    // flags (it deliberately reads no `.bsx.toml`), so naming that file would send the client's
    // operator to a file that does not govern this daemon.
    assert!(
        !line.contains(".bsx.toml"),
        "a daemon refusal must not point at a file the daemon never reads: {line}"
    );
    assert!(
        line.contains("--max-vcpus"),
        "the refusal names the serve flag that set the ceiling: {line}"
    );

    // The discrimination: a value the VMM could never boot is the *client's* error and stays
    // `protocol`, so the split is real and not a blanket rename.
    let line = open_reply(&socket, r#""op":"open","vcpus":0"#);
    assert!(
        line.contains(r#""kind":"protocol""#),
        "a malformed value stays the client's fault: {line}"
    );
}

#[test]
#[ignore = "needs /dev/kvm + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn a_binary_get_is_flagged_lossy_and_a_text_get_is_not() {
    // The wire is text (`content` is lossy UTF-8), so fetching a file whose bytes are not valid
    // UTF-8 substitutes replacement characters. The `lossy` flag is what keeps that substitution
    // from being silent: without it a client has no way to know its bytes are not the file's.
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_binary_get_is_flagged_lossy_and_a_text_get_is_not: {why}");
        return;
    }
    let (_daemon, socket) = launch_daemon(None, None);

    let mut stream = UnixStream::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(45)))
        .unwrap_or_else(|e| panic!("set read timeout: {e}"));
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .unwrap_or_else(|e| panic!("clone for reading: {e}")),
    );
    let mut line = String::new();
    let mut roundtrip = |req: &str| -> String {
        writeln!(stream, "{req}").unwrap_or_else(|e| panic!("send: {e}"));
        line.clear();
        reader
            .read_line(&mut line)
            .unwrap_or_else(|e| panic!("read reply: {e}"));
        line.clone()
    };

    let opened = roundtrip(r#"{"schema":1,"op":"open"}"#);
    assert!(opened.contains(r#""reply":"opened""#), "{opened}");

    // One file of raw non-UTF-8 bytes, one of plain text, written inside the guest.
    let wrote = roundtrip(
        r#"{"schema":1,"op":"exec","argv":["sh","-c","printf '\\377\\376\\375' > bin.dat && printf 'hello' > text.txt"]}"#,
    );
    assert!(wrote.contains(r#""exit_code":0"#), "{wrote}");

    let got = roundtrip(r#"{"schema":1,"op":"get","path":"bin.dat"}"#);
    assert!(got.contains(r#""present":true"#), "{got}");
    assert!(
        got.contains(r#""lossy":true"#),
        "non-UTF-8 bytes must be flagged, not silently substituted: {got}"
    );

    let got = roundtrip(r#"{"schema":1,"op":"get","path":"text.txt"}"#);
    assert!(got.contains(r#""content":"hello""#), "{got}");
    assert!(
        got.contains(r#""lossy":false"#),
        "clean UTF-8 is not lossy: {got}"
    );
}
