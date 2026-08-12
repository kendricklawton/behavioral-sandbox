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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use bsx_client::{Client, ClientError, FaultKind, OpenParams, ProtocolError};

const CORPUS: &str = include_str!("../../protocol/tests/fixtures/wire-messages.jsonl");

/// One pinned wire line from the corpus, by direction and name, without its terminator. Exactly
/// one match, because protocol's `corpus()` refuses a duplicated line loudly and this reader must
/// not paper over the same fault by taking the first.
fn fixture(dir: &str, name: &str) -> String {
    let matches: Vec<_> = CORPUS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .unwrap_or_else(|e| panic!("corpus line is not JSON: {e}"))
        })
        .filter(|v| v["dir"] == dir && v["name"] == name)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "the corpus holds {} {dir} fixtures named {name}, want exactly one",
        matches.len()
    );
    matches[0]["line"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| panic!("the {dir} fixture {name} carries no line"))
}

/// What the fake daemon does with one incoming request line.
enum Answer {
    /// Read a request, answer with this wire line.
    Reply(String),
    /// Read a request, wait, then answer: the late reply a fired client timeout leaves owed.
    After(Duration, String),
    /// Read a request and answer nothing, leaving the caller blocked awaiting its reply.
    Swallow,
    /// Read a request, then answer one byte at a time: the slow drip a bare socket timeout never
    /// bounds. Ends early once the client gives up and hangs up.
    Drip(Duration, String),
    /// Read nothing and answer nothing, holding the connection open: the never-draining peer a
    /// bounded send must time out against.
    Hold(Duration),
    /// Read a request, then hang up without answering.
    HangUp,
}

/// A one-connection fake daemon: binds a fresh socket, accepts once, follows the script, then
/// closes (which the client sees as EOF). Yields every request line it read, terminators stripped,
/// for the byte-pinning assertions.
fn daemon(test: &str, script: Vec<Answer>) -> (SocketPath, JoinHandle<Vec<String>>) {
    let path = SocketPath::reserve(test);
    let listener = UnixListener::bind(path.as_path())
        .unwrap_or_else(|e| panic!("bind the fake daemon's socket: {e}"));
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
            if let Answer::Hold(delay) = answer {
                std::thread::sleep(delay);
                break;
            }
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
                Answer::Drip(interval, reply) => {
                    let mut gone = false;
                    for b in reply.as_bytes().iter().chain(b"\n") {
                        std::thread::sleep(interval);
                        if writer.write_all(std::slice::from_ref(b)).is_err() {
                            gone = true;
                            break;
                        }
                    }
                    if gone {
                        break;
                    }
                    continue;
                }
                Answer::Swallow => continue,
                // Intercepted before the read at the top of the loop; kept for exhaustiveness.
                Answer::Hold(_) => break,
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

fn connect(path: &SocketPath) -> Client {
    Client::connect(path.as_path()).unwrap_or_else(|e| panic!("connect to the fake daemon: {e}"))
}

/// The fake daemon's socket path, unlinked when this is dropped.
///
/// Every test used to repeat the unlink as its own last line, after the assertions, so a failing
/// one left the socket in `/tmp`. `bsx-client` carries no `[dev-dependencies]` by decision (the
/// point of the reference client is that a caller needs nothing but the wire contract), so this is
/// a local guard rather than the `test-support` edge.
struct SocketPath(PathBuf);

impl SocketPath {
    /// Reserves a path unique to this process **and** this call, so two runs of the suite cannot
    /// collide on one pid-named socket.
    fn reserve(test: &str) -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "bsx-client-{}-{}-{test}.sock",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path)
    }

    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
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
        "close",
    ]
    .map(|name| fixture("request", name));
    assert_eq!(
        requests, pinned,
        "the client encodes each request exactly as the corpus pins it"
    );
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
}

/// The one verb legal while a request is in flight, through the shape built for it: the call
/// blocks on one thread, the [`Canceller`] speaks from another, and the blocked call comes back
/// typed. This is the wire exchange `cancel` exists for, and its request bytes are pinned here.
#[test]
fn a_canceller_reaches_a_session_blocked_in_a_call() {
    let script = vec![
        Answer::Swallow,
        Answer::Reply(fixture("response", "cancelled")),
    ];
    let (path, daemon) = daemon("cancel-in-flight", script);
    let mut c = connect(&path);
    let mut canceller = c.canceller();

    std::thread::scope(|scope| {
        let blocked = scope.spawn(|| {
            let argv = ["echo".to_string(), "hi".to_string()];
            c.exec_with_env(&argv, "in\n", &[("K".to_string(), "V".to_string())])
        });
        // Late enough that the exec line is on the wire first; the daemon reads in order either
        // way, but the byte pin below asserts the order this test means to stage.
        std::thread::sleep(Duration::from_millis(200));
        canceller.cancel().expect("write the cancel");

        let err = blocked
            .join()
            .expect("the blocked thread")
            .expect_err("the exec was cancelled");
        assert!(
            matches!(err, ClientError::Cancelled),
            "the interrupted call returns the typed cancel, got {err}"
        );
    });

    let err = c
        .exec(&["true".to_string()], "")
        .expect_err("the session is over");
    assert!(
        matches!(err, ClientError::Desynced { .. }),
        "a cancelled session refuses whatever comes next, got {err}"
    );

    let requests = daemon.join().expect("the fake daemon's thread");
    let pinned = ["exec_full", "cancel"].map(|name| fixture("request", name));
    assert_eq!(
        requests, pinned,
        "the canceller speaks the pinned cancel bytes"
    );
    drop(c);
}

/// The race the cancel contract covers: the exec's result reaches the wire before the cancel line
/// does, so the call returns `Ok` and the daemon is already tearing down. Cancelling is what ends
/// the session, not the ack's arrival, so the next call must refuse without touching the wire.
#[test]
fn a_cancel_that_loses_the_race_still_ends_the_session() {
    let script = vec![
        Answer::Reply(fixture("response", "result")),
        Answer::Swallow,
    ];
    let (path, daemon) = daemon("cancel-race", script);
    let mut c = connect(&path);
    let mut canceller = c.canceller();

    let argv = ["true".to_string()];
    let outcome = c.exec(&argv, "").expect("the result won the race");
    assert_eq!(outcome.exit_code, 3);

    canceller
        .cancel()
        .expect("the cancel is written either way");
    let err = c.exec(&argv, "").expect_err("the session was cancelled");
    assert!(
        matches!(err, ClientError::Desynced { .. }),
        "a cancelled session refuses even when the cancel lost the race, got {err}"
    );

    daemon.join().expect("the fake daemon's thread");
    drop(c);
}

/// The finding's measurement restaged: a ~90-byte reply dripped at 60 ms/byte ran 5.2 s past a
/// 100 ms "bound", because `SO_RCVTIMEO` re-arms on every byte. The absolute budget makes the
/// documented bound real.
#[test]
fn a_dripped_reply_is_bounded_by_the_absolute_budget() {
    let script = vec![Answer::Drip(
        Duration::from_millis(60),
        fixture("response", "result"),
    )];
    let (path, daemon) = daemon("drip-reply", script);
    let mut c = connect(&path);
    c.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set the budget");

    let argv = ["true".to_string()];
    let started = std::time::Instant::now();
    let err = c
        .exec(&argv, "")
        .expect_err("the drip must not stretch the call");
    let elapsed = started.elapsed();
    assert!(
        matches!(&err, ClientError::Protocol(ProtocolError::Io(e))
            if e.kind() == std::io::ErrorKind::TimedOut),
        "a lapsed budget is TimedOut, got {err}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the call must end near its 100 ms budget, took {elapsed:?}"
    );

    drop(c);
    daemon.join().expect("the fake daemon's thread");
}

/// Disabling the budget must clear the sockopt the last bounded call armed (one file description,
/// shared by every clone), or a later unbounded call inherits it and times out spuriously.
#[test]
fn disabling_the_budget_clears_the_armed_timeout() {
    let script = vec![
        Answer::Reply(fixture("response", "opened")),
        Answer::After(Duration::from_millis(600), fixture("response", "result")),
    ];
    let (path, daemon) = daemon("budget-off", script);
    let mut c = connect(&path);

    c.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set the budget");
    c.open(OpenParams::default())
        .expect("a quick reply inside the budget");

    c.set_read_timeout(None).expect("disable the budget");
    let argv = ["true".to_string()];
    c.exec(&argv, "")
        .expect("an unbounded call outwaits a reply slower than the old budget");

    drop(c);
    daemon.join().expect("the fake daemon's thread");
}

/// The write twin: a daemon that never drains cannot hold a bounded send past its budget. The
/// chunked write is what makes the deadline check reachable at all; unchunked, a multi-MiB
/// request is one syscall whose in-kernel waits each reset the sockopt.
#[test]
fn a_never_draining_daemon_cannot_hold_a_bounded_send() {
    let script = vec![Answer::Hold(Duration::from_secs(1))];
    let (path, daemon) = daemon("held-send", script);
    let mut c = connect(&path);
    c.set_write_timeout(Some(Duration::from_millis(300)))
        .expect("set the budget");

    let big = "x".repeat(2 * 1024 * 1024);
    let started = std::time::Instant::now();
    let err = c.put("in.txt", &big).expect_err("nobody drains the socket");
    let elapsed = started.elapsed();
    assert!(
        matches!(&err, ClientError::Protocol(ProtocolError::Io(e))
            if e.kind() == std::io::ErrorKind::TimedOut),
        "a lapsed write budget is TimedOut, got {err}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the send must end near its 300 ms budget, took {elapsed:?}"
    );

    drop(c);
    daemon.join().expect("the fake daemon's thread");
}

/// A poisoned session says **which** death it died, and the two cancel paths say the same thing.
///
/// Every poison test asserted only that the session was `Desynced`, never what it reported, so a
/// cause wired to the wrong arm read as healthy to the whole suite. This string is what a caller
/// reads back from every later call, and the only thing that tells a hang-up from a cancel from a
/// broken pairing.
///
/// The two cancels are here because a cancel is poisoned from two places: `Canceller::cancel`
/// before the line is written, and the read path when the daemon reports one this client never
/// asked for. They must agree, or a caller learns a different fact depending on who noticed first.
///
/// Asserted by the distinguishing word rather than verbatim, so rewording the prose does not fail
/// the test while pointing an arm at the wrong cause still does.
#[test]
fn a_poisoned_session_names_the_death_it_died() {
    fn cause_of(err: ClientError) -> String {
        match err {
            ClientError::Desynced { cause } => cause.to_string(),
            other => panic!("expected a poisoned session, got {other}"),
        }
    }
    let argv = ["true".to_string()];

    // The peer hung up.
    let (path, thread) = daemon("cause-hangup", vec![Answer::HangUp]);
    let mut c = connect(&path);
    let _ = c.exec(&argv, "").expect_err("the daemon hung up");
    let closed = cause_of(c.exec(&argv, "").expect_err("the session is over"));
    thread.join().expect("the fake daemon's thread");

    // A well-formed reply that answers a different request.
    let (path, thread) = daemon(
        "cause-mispaired",
        vec![Answer::Reply(fixture("response", "closed"))],
    );
    let mut c = connect(&path);
    let _ = c
        .exec(&argv, "")
        .expect_err("closed is not an exec's reply");
    let mispaired = cause_of(c.exec(&argv, "").expect_err("the pairing is off"));
    drop(c);
    thread.join().expect("the fake daemon's thread");

    // The **daemon** reports a cancel this client never asked for: the read path poisons.
    let (path, thread) = daemon(
        "cause-daemon-cancel",
        vec![Answer::Reply(fixture("response", "cancelled"))],
    );
    let mut c = connect(&path);
    let err = c
        .exec(&argv, "")
        .expect_err("the daemon cancelled the session");
    assert!(
        matches!(err, ClientError::Cancelled),
        "a `cancelled` reply is its own typed error, got {err}"
    );
    let by_daemon = cause_of(c.exec(&argv, "").expect_err("the session is over"));
    drop(c);
    thread.join().expect("the fake daemon's thread");

    // **This** client cancels: the canceller poisons before the line is written.
    let script = vec![
        Answer::Reply(fixture("response", "result")),
        Answer::Swallow,
    ];
    let (path, thread) = daemon("cause-self-cancel", script);
    let mut c = connect(&path);
    let mut canceller = c.canceller();
    c.exec(&argv, "").expect("the result won the race");
    canceller.cancel().expect("the cancel is written");
    let by_caller = cause_of(c.exec(&argv, "").expect_err("the session was cancelled"));
    thread.join().expect("the fake daemon's thread");
    drop(c);

    assert!(
        closed.contains("closed"),
        "a hang-up must say the daemon closed the connection, got {closed:?}"
    );
    assert!(
        mispaired.contains("different request"),
        "a mismatched reply must say the pairing is off, got {mispaired:?}"
    );
    assert_eq!(
        by_daemon, by_caller,
        "whoever noticed the cancel, the caller must learn the same thing"
    );
    assert!(
        by_caller.contains("cancelled"),
        "and it must say so, got {by_caller:?}"
    );
    let distinct: std::collections::BTreeSet<&String> = [&closed, &mispaired, &by_caller].into();
    assert_eq!(
        distinct.len(),
        3,
        "three different deaths must not report one cause: {closed:?} {mispaired:?} {by_caller:?}"
    );
}
