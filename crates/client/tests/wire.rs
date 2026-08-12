//! The reference client against a **fake daemon**: a `UnixListener` thread answering with canned
//! lines from the pinned wire corpus (`crates/protocol/tests/fixtures/wire-messages.jsonl`), so the
//! client is tested against the same artifact the SDK ports are pointed at, with no KVM, no engine,
//! and no privileges.
//!
//! - **The daemon is the untestable half, not the client.** Everything here runs in the everyday
//!   `cargo xtask ci` gate. The live daemon's side of these exchanges is driven by the `#[ignore]`d
//!   KVM suites in `crates/cli/tests`, and the corpus itself is pinned to the daemon's encoder by
//!   the protocol crate's own tests.
//! - **The request bytes are asserted, not just accepted.** Each test joins the daemon thread and
//!   compares every request line it read against the corpus, so the client's encoding is held to
//!   the published contract byte for byte.

// `panic!` as an assertion helper, the same opt-out the daemon's integration tests take.
#![allow(clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

use bsx_client::{Client, ClientError, FaultKind, OpenParams, ProtocolError};

const CORPUS: &str = include_str!("../../protocol/tests/fixtures/wire-messages.jsonl");

/// One pinned wire line from the corpus, by direction and name, without its terminator.
fn fixture(dir: &str, name: &str) -> String {
    CORPUS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .unwrap_or_else(|e| panic!("corpus line is not JSON: {e}"))
        })
        .find(|v| v["dir"] == dir && v["name"] == name)
        .and_then(|v| v["line"].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("the corpus holds no {dir} fixture named {name}"))
}

/// What the fake daemon does with one incoming request line.
enum Answer {
    /// Read a request, answer with this wire line.
    Reply(String),
    /// Read a request, wait, then answer: the late reply a fired client timeout leaves owed.
    After(Duration, String),
    /// Read a request, then hang up without answering.
    HangUp,
}

/// A one-connection fake daemon: binds a fresh socket, accepts once, follows the script, then
/// closes (which the client sees as EOF). Yields every request line it read, terminators stripped,
/// for the byte-pinning assertions.
fn daemon(test: &str, script: Vec<Answer>) -> (PathBuf, JoinHandle<Vec<String>>) {
    let path = std::env::temp_dir().join(format!("bsx-client-{}-{test}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).unwrap_or_else(|e| panic!("bind the fake daemon's socket: {e}"));
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener
            .accept()
            .unwrap_or_else(|e| panic!("accept the client: {e}"));
        let mut reader = BufReader::new(
            stream
                .try_clone()
                .unwrap_or_else(|e| panic!("clone the read half: {e}")),
        );
        let mut writer = stream;
        let mut requests = Vec::new();
        for answer in script {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .unwrap_or_else(|e| panic!("read a request line: {e}"));
            requests.push(line.trim_end_matches('\n').to_string());
            let reply = match answer {
                Answer::Reply(reply) => reply,
                Answer::After(delay, reply) => {
                    std::thread::sleep(delay);
                    reply
                }
                Answer::HangUp => break,
            };
            writer
                .write_all(reply.as_bytes())
                .unwrap_or_else(|e| panic!("write the reply: {e}"));
            writer
                .write_all(b"\n")
                .unwrap_or_else(|e| panic!("terminate the reply: {e}"));
        }
        requests
    });
    (path, handle)
}

fn connect(path: &PathBuf) -> Client {
    Client::connect(path).unwrap_or_else(|e| panic!("connect to the fake daemon: {e}"))
}

/// The params of the `open_all_knobs` corpus line, spelled field by field because `OpenParams` is
/// `#[non_exhaustive]` (no struct literal or update syntax outside its crate).
#[allow(clippy::field_reassign_with_default)]
fn open_all_knobs() -> OpenParams {
    let mut p = OpenParams::default();
    p.vcpus = Some(2);
    p.mem_mib = Some(512);
    p.wall_secs = Some(60);
    p.output_cap = Some(16_777_216);
    p.net = Some(true);
    p.allow = Some(vec!["1.1.1.1:443/tcp".to_string()]);
    p
}

#[test]
fn every_verb_round_trips_and_speaks_the_pinned_bytes() {
    let script = vec![
        Answer::Reply(fixture("response", "opened")),
        Answer::Reply(fixture("response", "opened")),
        Answer::Reply(fixture("response", "result")),
        Answer::Reply(fixture("response", "put")),
        Answer::Reply(fixture("response", "got")),
        Answer::Reply(fixture("response", "snapshotted")),
        Answer::Reply(fixture("response", "trace")),
        Answer::Reply(fixture("response", "trace_summary")),
        Answer::Reply(fixture("response", "cancelled")),
        Answer::Reply(fixture("response", "closed")),
    ];
    let (path, daemon) = daemon("every-verb", script);
    let mut c = connect(&path);

    let opened = c.open(open_all_knobs()).expect("open with every knob");
    assert_eq!((opened.boot_ms, opened.pooled), (120, true));
    c.open(OpenParams::default())
        .expect("open with the defaults");

    let argv = ["echo".to_string(), "hi".to_string()];
    let outcome = c
        .exec_with_env(&argv, "in\n", &[("K".to_string(), "V".to_string())])
        .expect("exec with stdin and env");
    assert_eq!(outcome.exit_code, 3);
    assert_eq!(
        (outcome.stdout.as_str(), outcome.stderr.as_str()),
        ("out", "err")
    );
    assert_eq!(outcome.exec_wall_ms, 5);

    c.put("in.txt", "data\n").expect("put");
    let got = c
        .get("out.txt")
        .expect("get")
        .expect("the fixture is present");
    assert_eq!((got.content.as_str(), got.lossy), ("data", true));

    assert_eq!(c.snapshot().expect("snapshot"), "/var/lib/bsx/snap-1");
    assert_eq!(c.trace().expect("trace")["schema"], 1);
    assert_eq!(c.trace_summary().expect("trace_summary")["schema"], 1);
    c.cancel().expect("cancel");
    c.close().expect("close");
    drop(c);

    let requests = daemon.join().expect("the fake daemon's thread");
    let pinned = [
        "open_all_knobs",
        "open_defaults",
        "exec_full",
        "put",
        "get",
        "snapshot",
        "trace",
        "trace_summary",
        "cancel",
        "close",
    ]
    .map(|name| fixture("request", name));
    assert_eq!(
        requests, pinned,
        "the client encodes each request exactly as the corpus pins it"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_error_reply_is_typed_with_the_wire_fault_kind() {
    let script = vec![
        Answer::Reply(fixture("response", "error")),
        Answer::Reply(fixture("response", "at_capacity")),
        Answer::Reply(fixture("response", "closed")),
    ];
    let (path, daemon) = daemon("error-replies", script);
    let mut c = connect(&path);

    let argv = ["true".to_string()];
    let err = c
        .exec(&argv, "")
        .expect_err("the error fixture is an error reply");
    match err {
        ClientError::Remote {
            message,
            fatal,
            kind,
        } => {
            assert_eq!((message.as_str(), fatal), ("boom", true));
            assert_eq!(kind, FaultKind::Guest);
        }
        other => panic!("an error reply must be Remote, got {other}"),
    }

    let err = c
        .exec(&argv, "")
        .expect_err("the at_capacity fixture is backpressure");
    assert!(
        matches!(
            err,
            ClientError::AtCapacity {
                retry_after_ms: 1000
            }
        ),
        "backpressure is its own variant, got {err}"
    );

    // Both are real replies: the pairing is intact, so the session must still be usable.
    c.close()
        .expect("an error reply must not poison the session");

    drop(c);
    daemon.join().expect("the fake daemon's thread");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_hang_up_without_a_reply_is_closed_not_a_decode_error() {
    let (path, daemon) = daemon("hang-up", vec![Answer::HangUp]);
    let mut c = connect(&path);

    let argv = ["true".to_string()];
    let err = c.exec(&argv, "").expect_err("the daemon hung up");
    assert!(
        matches!(err, ClientError::Closed),
        "EOF while a reply is owed is Closed, got {err}"
    );
    let err = c.exec(&argv, "").expect_err("the session is over");
    assert!(
        matches!(err, ClientError::Desynced { .. }),
        "a dead session refuses by name instead of erring on the write, got {err}"
    );

    daemon.join().expect("the fake daemon's thread");
    let _ = std::fs::remove_file(&path);
}

/// The finding's exact transcript: a timeout fires, the daemon's late reply is still coming, and
/// the next call would read it as its own well-typed `Ok`. The poison turns that silent
/// misattribution into a typed refusal.
#[test]
fn a_fired_timeout_poisons_the_session_instead_of_desyncing_it() {
    let script = vec![Answer::After(
        Duration::from_millis(400),
        fixture("response", "result"),
    )];
    let (path, daemon) = daemon("late-reply", script);
    let mut c = connect(&path);
    c.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("arm the read timeout");

    let argv = ["first".to_string()];
    let err = c.exec(&argv, "").expect_err("the reply is late");
    assert!(
        matches!(err, ClientError::Protocol(_)),
        "the fired timeout surfaces as an io error, got {err}"
    );

    // Without the poison this second call reads the late reply for "first" and returns it as its
    // own Ok, with nothing in the value to tell the two apart.
    let argv = ["second".to_string()];
    let err = c.exec(&argv, "").expect_err("a reply is owed");
    assert!(
        matches!(err, ClientError::Desynced { .. }),
        "the session owes a reply and must refuse, got {err}"
    );

    // Joined before the drop: the daemon's late write still has a peer, which is the scenario.
    daemon.join().expect("the fake daemon's thread");
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// A well-formed reply of the wrong shape is proof the pairing is already off, so it poisons too.
#[test]
fn a_mismatched_reply_poisons_the_session() {
    let script = vec![Answer::Reply(fixture("response", "closed"))];
    let (path, daemon) = daemon("mismatched-reply", script);
    let mut c = connect(&path);

    let argv = ["true".to_string()];
    let err = c
        .exec(&argv, "")
        .expect_err("closed is not an exec's reply");
    assert!(
        matches!(err, ClientError::Unexpected(_)),
        "the mismatched shape is carried whole, got {err}"
    );
    let err = c.exec(&argv, "").expect_err("the pairing is off");
    assert!(
        matches!(err, ClientError::Desynced { .. }),
        "a mismatched reply must poison, got {err}"
    );

    drop(c);
    daemon.join().expect("the fake daemon's thread");
    let _ = std::fs::remove_file(&path);
}

/// A write that fails partway can leave a torn frame on the wire, so it poisons like a lost reply.
#[test]
fn a_failed_write_poisons_the_session() {
    let (path, daemon) = daemon("dead-peer", vec![]);
    let mut c = connect(&path);
    // Joined first: the daemon is gone and its socket closed, so the big write must fail.
    daemon.join().expect("the fake daemon's thread");

    let big = "x".repeat(2 * 1024 * 1024);
    let err = c.put("in.txt", &big).expect_err("the peer is closed");
    assert!(
        matches!(err, ClientError::Protocol(ProtocolError::Io(_))),
        "the failed write surfaces as an io error, got {err}"
    );

    let argv = ["true".to_string()];
    let err = c.exec(&argv, "").expect_err("the frame may be torn");
    assert!(
        matches!(err, ClientError::Desynced { .. }),
        "a failed write must poison, got {err}"
    );
    let _ = std::fs::remove_file(&path);
}

/// An over-cap request is refused before any byte moves, so it must not cost the session.
#[test]
fn an_over_cap_request_leaves_the_session_usable() {
    let script = vec![Answer::Reply(fixture("response", "closed"))];
    let (path, daemon) = daemon("over-cap", script);
    let mut c = connect(&path);

    let big = "x".repeat(5 * 1024 * 1024);
    let err = c.put("in.txt", &big).expect_err("over the request cap");
    assert!(
        matches!(err, ClientError::Protocol(ProtocolError::TooLarge { .. })),
        "an over-cap request is a typed refusal, got {err}"
    );

    c.close().expect("no byte moved, so the session is intact");
    drop(c);
    daemon.join().expect("the fake daemon's thread");
    let _ = std::fs::remove_file(&path);
}

/// The daemon is the only party that saw the file's bytes; its lossy flag must reach the caller,
/// and a missing file is `None`, not an error.
#[test]
fn get_surfaces_the_lossy_flag_and_maps_absent_to_none() {
    let absent =
        r#"{"schema":1,"reply":"got","path":"x","content":"","present":false,"lossy":false}"#;
    let script = vec![
        Answer::Reply(fixture("response", "got")),
        Answer::Reply(absent.to_string()),
    ];
    let (path, daemon) = daemon("lossy-get", script);
    let mut c = connect(&path);

    let got = c.get("out.txt").expect("get").expect("present");
    assert!(
        got.lossy,
        "the daemon flagged a lossy rendering and the client must carry it"
    );
    assert_eq!(got.content, "data");

    assert!(
        c.get("x").expect("get").is_none(),
        "a missing file is None, not an error"
    );

    drop(c);
    daemon.join().expect("the fake daemon's thread");
    let _ = std::fs::remove_file(&path);
}
