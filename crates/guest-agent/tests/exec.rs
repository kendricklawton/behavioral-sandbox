//! Integration tests for the guest agent, driving [`agent_guest::serve`] through its **public**
//! API over a unix socketpair — the same protocol the host will speak over vsock, but with no VM.
// This is a test binary; the shared `run` helper isn't a `#[test]` fn, so the workspace's
// no-unwrap/expect lints don't auto-exempt it. Panicking on setup failure is correct in a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::net::UnixStream;

use agent_channel::{Request, Response};

/// Play the host side against `serve`: handshake, one exec request, then read responses until a
/// terminal frame. Returns collected stdout, stderr, and the final exit code or error message.
fn run(argv: &[&str]) -> (Vec<u8>, Vec<u8>, Result<i32, String>) {
    let (mut host, guest) = UnixStream::pair().expect("socketpair");
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
    let agent = std::thread::spawn(move || agent_guest::serve(guest));

    agent_channel::write_handshake(&mut host).expect("host handshake write");
    agent_channel::read_handshake(&mut host).expect("host handshake read");
    agent_channel::write_request(&mut host, &Request::Exec { argv }).expect("send request");

    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = loop {
        match agent_channel::read_response(&mut host).expect("read response") {
            Response::Stdout(b) => out.extend_from_slice(&b),
            Response::Stderr(b) => err.extend_from_slice(&b),
            Response::Exit(code) => break Ok(code),
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
