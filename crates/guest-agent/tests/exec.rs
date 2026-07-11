//! Integration tests for the guest agent, driving [`agent_guest::serve`] through the **public**
//! channel API ([`ClientConnection`]) over a unix socketpair — the same protocol the host will speak
//! over vsock, but with no VM.
// This is a test binary; the `run` helper isn't a `#[test]` fn, so the workspace's
// no-unwrap/expect lints don't auto-exempt it. Panicking on setup failure is correct in a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

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
        })
        .expect("send request");
    // Deliberately never read a response — the guest's send buffer fills and its forward blocks.

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
