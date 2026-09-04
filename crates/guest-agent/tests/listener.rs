//! The agent **binary** serving its own listener, rather than [`bsx_guest_agent::serve`] driven
//! over a socketpair in this process (roadmap 0.6, 0.7).
//!
//! What the other suites cannot show: that the process a guest image runs binds a socket, accepts,
//! and serves the same frames, and that a **second** connection reaches the session the first
//! left. The transport here is `unix:<path>`, which is the shape `krun_add_vsock_port2` maps a
//! guest port onto, so this is the whole exec path with no VM; the in-VM half of the same claim is
//! `a_channel_frame_crosses_the_vsock_mapping_to_the_guest_and_back` in the CLI's suite.
// The agent, and so this suite, is Linux-only; the crate under test compiles to nothing
// elsewhere. `cargo xtask ci` prints the skip, because an empty test binary passes.
#![cfg(target_os = "linux")]
// This is a test binary; the helpers aren't `#[test]` fns, so the workspace's no-unwrap/expect
// lints don't auto-exempt them. Panicking on setup failure is correct in a test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

mod common;

use common::{Agent, Exec, Outcome};

/// Long enough that a loaded machine still binds in time; a failure here is a listener that never
/// came up, not a slow one.
const BIND_GRACE: Duration = Duration::from_secs(10);

/// The agent binary, listening on a socket of its own, reaped on drop.
struct Listening {
    child: Child,
    socket: PathBuf,
    _dir: bsx_test_support::ScratchDir,
}

impl Listening {
    /// Spawns `guest-agent unix:<path>` and hands back the socket to dial.
    fn start(tag: &str) -> Self {
        let dir = bsx_test_support::ScratchDir::created(tag);
        let socket = dir.path().join("agent.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_guest-agent"))
            .arg(format!("unix:{}", socket.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the agent binary");
        Self {
            child,
            socket,
            _dir: dir,
        }
    }

    fn dial(&self) -> Agent {
        Agent::connect(&self.socket, BIND_GRACE)
    }

    fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One `bsx-channel` exchange crosses a real unix socket into the agent **process** and back: the
/// handshake, an `Exec` frame out, the command's stdout and its exit code in.
#[test]
fn the_agent_binary_serves_a_frame_over_its_own_socket() {
    let agent = Listening::start("agent-listener");
    let mut client = agent.dial();
    let run = client.exec(Exec::new(&["echo", "over-the-socket"])).drain();
    assert_eq!(run.stdout, b"over-the-socket\n");
    assert!(run.stderr.is_empty());
    assert_eq!(run.outcome, Outcome::Exit(0));
    assert!(
        agent.socket().exists(),
        "the listener's socket is the thing the host dials"
    );
}

/// A **second** connection reaches the session the first left (roadmap 0.6): the agent serves
/// every connection from one working directory, so a file one exec writes is there for the next.
/// This is what makes a long-lived sandbox worth more than a fresh boot per command.
#[test]
fn a_second_connection_reaches_the_session_the_first_left() {
    let agent = Listening::start("agent-session");
    let run = agent
        .dial()
        .exec(Exec::new(&["sh", "-c", "echo kept > state"]))
        .drain();
    assert_eq!(run.outcome, Outcome::Exit(0), "{run:?}");

    // A new connection, and therefore a new `serve` call in the agent: what it shares with the
    // first is the session directory, not the connection.
    let run = agent.dial().exec(Exec::new(&["cat", "state"])).drain();
    assert_eq!(run.stdout, b"kept\n");
    assert_eq!(run.outcome, Outcome::Exit(0));
}

/// Connections are served one after another, not one and then silence: the accept loop comes back
/// for the next caller however the last one ended, including a command that failed.
#[test]
fn the_accept_loop_survives_a_failed_command_and_a_hangup() {
    let agent = Listening::start("agent-accept");
    let run = agent
        .dial()
        .exec(Exec::new(&["sh", "-c", "exit 7"]))
        .drain();
    assert_eq!(run.outcome, Outcome::Exit(7));

    // Hung up mid-session: connected, handshaken, and dropped without a request.
    drop(agent.dial());

    let run = agent
        .dial()
        .exec(Exec::new(&["echo", "still-serving"]))
        .drain();
    assert_eq!(run.stdout, b"still-serving\n");
    assert_eq!(run.outcome, Outcome::Exit(0));
}
