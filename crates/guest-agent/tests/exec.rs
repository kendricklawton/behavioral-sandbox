//! Integration tests for the guest agent, driving [`agent_guest::serve`] through the **public**
//! channel API ([`ClientConnection`]) over a unix socketpair, the same protocol the host will speak
//! over vsock, but with no VM.
// This is a test binary; the `run` helper isn't a `#[test]` fn, so the workspace's
// no-unwrap/expect lints don't auto-exempt it. Panicking on setup failure is correct in a test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use agent_channel::{ClientConnection, Request, Response};

/// Play the host side against `serve`: connect (handshake), send one exec request, then read
/// responses until a terminal frame. Returns collected stdout, stderr, and the final code or error.
fn run(argv: &[&str]) -> (Vec<u8>, Vec<u8>, Result<i32, String>) {
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
    let agent = std::thread::spawn(move || agent_guest::serve(guest));

    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::Exec {
            argv,
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("send request");

    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = loop {
        match client.recv_response().expect("read response") {
            Response::Stdout(b) => out.extend_from_slice(&b),
            Response::Stderr(b) => err.extend_from_slice(&b),
            Response::Exit { code } => break Ok(code),
            Response::Error(msg) => break Err(msg),
            other => panic!("unexpected response frame: {other:?}"),
        }
    };
    let _ = agent.join();
    (out, err, result)
}

#[test]
fn echo_reports_stdout_and_exit_zero() {
    let (out, err, result) = run(&["echo", "hi"]);
    assert_eq!(out, b"hi\n");
    assert!(err.is_empty());
    assert_eq!(result, Ok(0));
}

#[test]
fn captures_stderr_and_nonzero_exit() {
    let (out, err, result) = run(&["sh", "-c", "echo out; echo err 1>&2; exit 3"]);
    assert_eq!(out, b"out\n");
    assert_eq!(err, b"err\n");
    assert_eq!(result, Ok(3));
}

#[test]
fn missing_binary_reports_error_not_exit() {
    let (_, _, result) = run(&["definitely-not-a-real-binary-zzz"]);
    assert!(
        result.is_err(),
        "a spawn failure is a terminal Error frame, not an Exit"
    );
}

#[test]
fn empty_command_is_rejected() {
    let (_, _, result) = run(&[]);
    assert!(result.is_err());
}

#[test]
fn large_output_streams_without_deadlock() {
    // ~600 KiB of output, far past a pipe buffer: proves the two pumps drain concurrently so the
    // child never blocks. A single-threaded read-then-forward would hang here.
    let (out, _, result) = run(&["sh", "-c", "seq 1 100000"]);
    assert_eq!(result, Ok(0));
    assert!(out.len() > 500_000, "got {} bytes", out.len());
    assert!(out.starts_with(b"1\n"));
    assert!(out.ends_with(b"100000\n"));
}

#[test]
fn signal_death_maps_to_128_plus_signal() {
    // SIGKILL is 9 → 137 (the shell convention).
    let (_, _, result) = run(&["sh", "-c", "kill -9 $$"]);
    assert_eq!(result, Ok(137));
}

#[test]
fn stdin_is_fed_to_the_command() {
    // `cat` echoes its stdin to stdout: proves the request's stdin buffer reaches the child and is
    // closed (EOF), so `cat` exits.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || agent_guest::serve(guest));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::Exec {
            argv: vec!["cat".into()],
            stdin: b"piped input\n".to_vec(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("send request");

    let mut out = Vec::new();
    let code = loop {
        match client.recv_response().expect("read response") {
            Response::Stdout(b) => out.extend_from_slice(&b),
            Response::Exit { code } => break code,
            other => panic!("unexpected response frame: {other:?}"),
        }
    };
    assert_eq!(out, b"piped input\n");
    assert_eq!(code, 0);
    let _ = agent.join();
}

#[test]
fn env_reaches_the_command_but_never_the_agents_own_process() {
    // The two halves of the env contract in one run: the injected variable is visible to the
    // spawned command, and it is set via `Command::env` only, `serve` runs in *this* process here,
    // so if the agent ever `set_var`'d it, the assertion on our own environment would catch it.
    let key = "AGENT_TEST_ENV_SCOPE";
    assert!(
        std::env::var_os(key).is_none(),
        "test precondition: {key} must not be set"
    );
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || agent_guest::serve(guest));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::Exec {
            argv: vec!["sh".into(), "-c".into(), format!("printf '%s' \"${key}\"")],
            stdin: Vec::new(),
            env: vec![(key.to_string(), "from-the-host".into())],
            artifacts: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("send request");

    let mut out = Vec::new();
    let code = loop {
        match client.recv_response().expect("read response") {
            Response::Stdout(b) => out.extend_from_slice(&b),
            Response::Exit { code } => break code,
            other => panic!("unexpected response frame: {other:?}"),
        }
    };
    assert_eq!(code, 0);
    assert_eq!(
        out, b"from-the-host",
        "the command must see the injected env"
    );
    let _ = agent.join();
    assert!(
        std::env::var_os(key).is_none(),
        "the agent process's own environment must stay untouched"
    );
}

#[test]
fn injected_file_is_read_by_the_command_and_artifact_returned() {
    // Put a file in, `cat` it (proving cwd = the working dir), and pull an artifact back.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || agent_guest::serve(guest));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::PutFile {
            path: "note.txt".into(),
            data: b"contents\n".to_vec(),
        })
        .expect("put file");
    client
        .send_request(&Request::Exec {
            argv: vec![
                "sh".into(),
                "-c".into(),
                "cat note.txt; cp note.txt copy.txt".into(),
            ],
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: vec!["copy.txt".into()],
            timeout_ms: 30_000,
        })
        .expect("exec");

    let (mut out, mut files) = (Vec::new(), Vec::new());
    let code = loop {
        match client.recv_response().expect("recv") {
            Response::Stdout(b) => out.extend_from_slice(&b),
            Response::File { path, data } => files.push((path, data)),
            Response::Exit { code } => break code,
            other => panic!("unexpected frame: {other:?}"),
        }
    };
    assert_eq!(code, 0);
    assert_eq!(out, b"contents\n");
    assert_eq!(
        files,
        vec![("copy.txt".to_string(), b"contents\n".to_vec())]
    );
    let _ = agent.join();
}

#[test]
fn session_state_persists_across_connections() {
    // The stateful-session contract at the agent layer: two connections served with the same
    // session dir see one working directory, a file injected before the first exec, and a file
    // that exec writes, are both still there for the second. (One-shot `serve` keeps its
    // fresh-and-removed semantics; this is the `serve_session` path the in-VM binary runs.)
    let dir = std::env::temp_dir().join(format!("agent-session-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // Exec 1: read the injected file, append to it, and write a new one.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let session = dir.clone();
    let agent = std::thread::spawn(move || agent_guest::serve_session(guest, &session));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::PutFile {
            path: "seed.txt".into(),
            data: b"one\n".to_vec(),
        })
        .expect("put file");
    client
        .send_request(&Request::Exec {
            argv: vec!["sh".into(), "-c".into(), "echo two >> seed.txt".into()],
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("exec 1");
    loop {
        match client.recv_response().expect("recv") {
            Response::Exit { code } => break assert_eq!(code, 0),
            Response::Stdout(_) | Response::Stderr(_) => {}
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    agent.join().expect("agent 1").expect("serve 1");

    // Exec 2, a fresh connection on the same session dir: the accumulated file is still there.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let session = dir.clone();
    let agent = std::thread::spawn(move || agent_guest::serve_session(guest, &session));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::Exec {
            argv: vec!["cat".into(), "seed.txt".into()],
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("exec 2");
    let mut out = Vec::new();
    loop {
        match client.recv_response().expect("recv") {
            Response::Stdout(b) => out.extend_from_slice(&b),
            Response::Exit { code } => break assert_eq!(code, 0),
            Response::Stderr(_) => {}
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    assert_eq!(
        out, b"one\ntwo\n",
        "state written by exec 1 must be visible to exec 2"
    );
    agent.join().expect("agent 2").expect("serve 2");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hung_command_is_killed_at_its_deadline() {
    // A command that would run far longer than its timeout must be killed and reported as TimedOut,
    // not hang the agent. A short timeout keeps the test fast.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || agent_guest::serve(guest));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::Exec {
            argv: vec!["sleep".into(), "30".into()],
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: 300,
        })
        .expect("send request");

    let started = std::time::Instant::now();
    match client.recv_response().expect("recv") {
        Response::TimedOut { .. } => {}
        other => panic!("expected TimedOut, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the agent must kill the command promptly, not wait it out"
    );
    // The agent's own return signals the SIGKILL convention.
    assert!(matches!(agent.join().expect("agent thread"), Ok(137)));
}

#[test]
fn command_under_its_deadline_is_not_falsely_killed() {
    // A command that finishes well within its budget must exit normally, never TimedOut.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || agent_guest::serve(guest));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::Exec {
            argv: vec!["sh".into(), "-c".into(), "sleep 0.1; echo done".into()],
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: 5_000,
        })
        .expect("send request");

    let mut out = Vec::new();
    let code = loop {
        match client.recv_response().expect("recv") {
            Response::Stdout(b) => out.extend_from_slice(&b),
            Response::Exit { code } => break code,
            other => panic!("unexpected frame (false timeout?): {other:?}"),
        }
    };
    assert_eq!(code, 0);
    assert_eq!(out, b"done\n");
    let _ = agent.join();
}

#[test]
fn put_file_rejects_path_traversal() {
    // A path that climbs out of the working dir must be rejected with a terminal Error, not written.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || agent_guest::serve(guest));
    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::PutFile {
            path: "../escape.txt".into(),
            data: b"nope".to_vec(),
        })
        .expect("put file");
    match client.recv_response().expect("recv") {
        Response::Error(_) => {}
        other => panic!("expected a rejection, got {other:?}"),
    }
    let result = agent.join().expect("agent thread");
    assert!(result.is_err(), "a traversing path must fail the request");
}

#[test]
fn bad_handshake_is_rejected_not_hung() {
    // A peer that opens the connection and sends garbage (≥6 bytes, wrong magic) must make `serve`
    // fail promptly, not block. No deadline needed: read_exact gets its 6 bytes and the magic fails.
    let (mut host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || agent_guest::serve(guest));
    host.write_all(b"XXXXXX not a handshake")
        .expect("write garbage");
    let result = agent.join().expect("agent thread");
    assert!(result.is_err(), "a bad handshake must be a typed error");
}

#[test]
fn stalled_host_does_not_wedge_the_guest() {
    // The regression test for the bug this pass fixes: a host that handshakes and requests, then
    // STOPS reading, against a command that floods output. With a write deadline on the guest
    // stream, `serve` must return an Err in bounded time (the pump's forward times out → drain-and-
    // discard → child exits) rather than hang forever.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    guest
        .set_write_timeout(Some(Duration::from_millis(200)))
        .expect("set write timeout");

    let (tx, rx) = std::sync::mpsc::channel();
    let agent = std::thread::spawn(move || {
        let r = agent_guest::serve(guest);
        let _ = tx.send(());
        r
    });

    let mut client = ClientConnection::connect(host).expect("client handshake");
    client
        .send_request(&Request::Exec {
            argv: vec!["sh".into(), "-c".into(), "seq 1 200000".into()],
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: 30_000,
        })
        .expect("send request");
    // Deliberately never read a response, the guest's send buffer fills and its forward blocks.

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(()) => {
            let result = agent.join().expect("agent thread");
            assert!(
                result.is_err(),
                "a stalled host must surface as a channel error, not success"
            );
        }
        Err(_) => panic!("serve wedged: a stalled host hung the guest agent"),
    }
    drop(client);
}
