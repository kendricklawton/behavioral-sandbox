//! The interactive path, end to end over a socketpair: a real pty, a real `sh`, no VM.
//!
//! What a guest does with a `Request::ExecPty` is exactly what these do on the host: the pty
//! machinery is the kernel's on both sides, so the gate covers the whole session shape and only
//! the vsock transport and the VM around it wait for `/dev/kvm`.

#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::os::unix::net::UnixStream;

use bsx_channel::{ClientConnection, Request, Response};
use bsx_guest_agent::serve;

/// Runs one pty session and returns everything the terminal printed plus the exit code.
/// `after_first_output` is sent once the first output frame arrives, which is what makes a
/// resize-then-ack script deterministic instead of timing-dependent.
fn pty_session(
    argv: &[&str],
    cols: u16,
    rows: u16,
    after_first_output: &[Request],
) -> (String, i32) {
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || serve(guest));

    let mut conn = ClientConnection::connect(host.try_clone().expect("clone")).expect("handshake");
    let mut sender = ClientConnection::resume(host);
    conn.send_request(&Request::ExecPty {
        argv: argv.iter().map(|a| a.to_string()).collect(),
        env: vec![("TERM".into(), "dumb".into())],
        cols,
        rows,
    })
    .expect("send the session request");

    let mut out = Vec::new();
    let mut sent_follow_ups = false;
    let code = loop {
        match conn.recv_response().expect("a response") {
            Response::Stdout(bytes) => {
                out.extend_from_slice(&bytes);
                if !sent_follow_ups {
                    sent_follow_ups = true;
                    for req in after_first_output {
                        sender.send_request(req).expect("send a follow-up");
                    }
                }
            }
            Response::Exit { code } => break code,
            other => panic!("unexpected response: {other:?}"),
        }
    };
    drop(conn);
    drop(sender);
    let _ = agent.join().expect("agent thread");
    (String::from_utf8_lossy(&out).into_owned(), code)
}

/// The command runs on a real terminal: `tty` names a pts, and the size it sees is the size the
/// request carried, not a pipe and not 0x0.
#[test]
fn the_command_runs_on_a_pty_of_the_requested_size() {
    let (out, code) = pty_session(&["sh", "-c", "tty; stty size"], 80, 24, &[]);
    assert!(out.contains("/dev/pts/"), "not a pty: {out:?}");
    assert!(out.contains("24 80"), "wrong size: {out:?}");
    assert_eq!(code, 0);
}

/// A `Resize` reaches the running command. The script prints its size, waits for one byte of
/// input, and prints again; the resize is sent before the byte, so the frames' order on the wire
/// is the order of effects and nothing here races.
#[test]
fn a_resize_reaches_the_running_command() {
    let (out, _) = pty_session(
        &["sh", "-c", "stty size; head -c1 >/dev/null; stty size"],
        80,
        24,
        &[
            Request::Resize {
                cols: 100,
                rows: 50,
            },
            // With a newline: the pty starts in canonical mode, where a lone byte sits in the
            // line buffer forever and `head -c1` never returns.
            Request::Stdin(b"x\n".to_vec()),
        ],
    );
    assert!(out.contains("24 80"), "initial size missing: {out:?}");
    assert!(out.contains("50 100"), "the resize never landed: {out:?}");
}

/// Keystrokes reach the command's stdin through the pty, echo and all, and the exit code comes
/// back as the session's answer.
#[test]
fn stdin_bytes_reach_the_command_and_the_exit_code_returns() {
    // `echo ready` first: the harness sends its follow-ups on the first output frame, and a
    // script that waits for input before printing anything would wait forever.
    let (out, code) = pty_session(
        &["sh", "-c", "echo ready; read line; echo got:$line; exit 3"],
        80,
        24,
        &[Request::Stdin(b"hello\n".to_vec())],
    );
    assert!(out.contains("got:hello"), "{out:?}");
    assert_eq!(code, 3);
}

/// The session's terminal is a *controlling* terminal, which is what job control and `^C` need:
/// `sh` can open `/dev/tty`, which resolves only through a ctty.
#[test]
fn the_pty_is_the_commands_controlling_terminal() {
    let (out, code) = pty_session(&["sh", "-c", "echo ok > /dev/tty"], 80, 24, &[]);
    assert!(out.contains("ok"), "/dev/tty did not resolve: {out:?}");
    assert_eq!(code, 0);
}

/// An empty command is refused with a message, not a hung session.
#[test]
fn an_empty_pty_command_is_refused() {
    let (host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || serve(guest));
    let mut conn = ClientConnection::connect(host).expect("handshake");
    conn.send_request(&Request::ExecPty {
        argv: vec![],
        env: vec![],
        cols: 80,
        rows: 24,
    })
    .expect("send");
    let resp = conn.recv_response().expect("a refusal");
    assert!(
        matches!(&resp, Response::Error(msg) if msg.contains("empty")),
        "{resp:?}"
    );
    assert!(agent.join().expect("agent thread").is_err());
}
