//! The host side of an agent connection, shared by the agent's test binaries.
//!
//! Each test used to spell the whole scaffold itself: a socketpair, `serve` on a thread, the
//! handshake, an `Exec` literal with all five fields, and a response loop.
//!
//! - **One drain, one answer about which frames are legal.** The hand-written loops disagreed: some
//!   panicked on a `Stderr` chunk, some ignored it, some read an `Error` as a terminal frame and
//!   some as a bug. [`Agent::drain`] accepts every frame the protocol defines and reports the
//!   terminal one as an [`Outcome`], so a test says what it means in an assertion rather than in
//!   which match arm panics.
//! - **`test-support` cannot hold this.** It dev-depends the other way round, so this lives in the
//!   test binaries' own `common` module.

// A test helper: panicking on setup failure is the assertion, and the workspace's
// no-unwrap/expect lints do not auto-exempt a non-`#[test]` fn.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::num::NonZeroU32;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread::JoinHandle;

use bsx_channel::{ClientConnection, Request, Response};
use bsx_guest_agent::AgentError;

/// The deadline every test that is not *about* the deadline sends: long enough that a slow machine
/// never trips it, so a `TimedOut` in those tests is a real finding.
const TEST_TIMEOUT_MS: u32 = 30_000;

/// How one exec ended, named by the terminal frame that ended it.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The command ran to completion with this status.
    Exit(i32),
    /// The agent refused or failed the request, carrying its message.
    Error(String),
    /// The agent killed the command at its deadline.
    TimedOut { elapsed_ms: u32 },
}

/// What one exec produced: both streams, any artifacts returned, and how it ended.
#[derive(Debug)]
pub struct Run {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub files: Vec<(String, Vec<u8>)>,
    pub outcome: Outcome,
}

/// An `Exec` request under construction, so a test names only the fields it cares about.
pub struct Exec {
    argv: Vec<String>,
    stdin: Vec<u8>,
    env: Vec<(String, String)>,
    artifacts: Vec<String>,
    timeout_ms: u32,
}

impl Exec {
    /// A command with no stdin, no injected env, no artifacts, and [`TEST_TIMEOUT_MS`].
    pub fn new(argv: &[&str]) -> Self {
        Self {
            argv: argv.iter().map(|a| (*a).to_string()).collect(),
            stdin: Vec::new(),
            env: Vec::new(),
            artifacts: Vec::new(),
            timeout_ms: TEST_TIMEOUT_MS,
        }
    }

    pub fn stdin(mut self, bytes: &[u8]) -> Self {
        self.stdin = bytes.to_vec();
        self
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    pub fn artifact(mut self, path: &str) -> Self {
        self.artifacts.push(path.to_string());
        self
    }

    pub fn timeout_ms(mut self, ms: u32) -> Self {
        self.timeout_ms = ms;
        self
    }

    fn request(self) -> Request {
        Request::Exec {
            argv: self.argv,
            stdin: self.stdin,
            env: self.env,
            artifacts: self.artifacts,
            timeout_ms: NonZeroU32::new(self.timeout_ms),
        }
    }
}

/// A live agent: `serve` on its own thread over a socketpair, with the host-side client already
/// handshaken.
pub struct Agent {
    client: ClientConnection<UnixStream>,
    thread: JoinHandle<Result<i32, AgentError>>,
}

impl Agent {
    /// An agent on a fresh per-run working dir ([`bsx_guest_agent::serve`]).
    pub fn start() -> Self {
        Self::spawn(bsx_guest_agent::serve)
    }

    /// An agent on the caller's stable session dir ([`bsx_guest_agent::serve_session`]), the
    /// state-across-connections path.
    pub fn start_in(dir: &Path) -> Self {
        let dir = dir.to_path_buf();
        Self::spawn(move |guest| bsx_guest_agent::serve_session(guest, &dir))
    }

    /// An agent running `serve` on its own thread, for a caller that must wrap the call (a test
    /// installing a tracing subscriber, say). [`start`](Self::start) and
    /// [`start_in`](Self::start_in) are the plain ones.
    pub fn spawn(
        serve: impl FnOnce(UnixStream) -> Result<i32, AgentError> + Send + 'static,
    ) -> Self {
        let (host, guest) = UnixStream::pair().expect("socketpair");
        let thread = std::thread::spawn(move || serve(guest));
        let client = ClientConnection::connect(host).expect("client handshake");
        Self { client, thread }
    }

    /// Stages a file in the run's working directory.
    pub fn put_file(&mut self, path: &str, data: &[u8]) -> &mut Self {
        self.client
            .send_request(&Request::PutFile {
                path: path.to_string(),
                data: data.to_vec(),
            })
            .expect("send put_file");
        self
    }

    /// Sends an exec request. The responses arrive through [`drain`](Self::drain).
    pub fn exec(&mut self, exec: Exec) -> &mut Self {
        self.client
            .send_request(&exec.request())
            .expect("send exec");
        self
    }

    /// Reads responses until a terminal frame, collecting both streams and any artifacts.
    ///
    /// Every frame the protocol defines today is legal here; which of them a given test will accept
    /// is the test's own assertion on the returned [`Outcome`], not this loop's business.
    /// `Response` is `#[non_exhaustive]`, so the wildcard is required from outside the crate: it
    /// panics by name, in one place, rather than being skipped in each of thirteen loops.
    pub fn drain(&mut self) -> Run {
        let (mut stdout, mut stderr, mut files) = (Vec::new(), Vec::new(), Vec::new());
        let outcome = loop {
            match self.client.recv_response().expect("read response") {
                Response::Stdout(b) => stdout.extend_from_slice(&b),
                Response::Stderr(b) => stderr.extend_from_slice(&b),
                Response::File { path, data } => files.push((path, data)),
                Response::Exit { code } => break Outcome::Exit(code),
                Response::Error(msg) => break Outcome::Error(msg),
                Response::TimedOut { elapsed_ms } => break Outcome::TimedOut { elapsed_ms },
                other => panic!("a response frame this harness has not learned: {other:?}"),
            }
        };
        Run {
            stdout,
            stderr,
            files,
            outcome,
        }
    }

    /// Sends `exec`, drains it, and hangs up. The whole exchange for a test that runs one command.
    pub fn run(exec: Exec) -> Run {
        let mut agent = Self::start();
        agent.exec(exec);
        let run = agent.drain();
        agent.finish();
        run
    }

    /// Hangs up and waits for the agent thread, discarding its result. For a test whose subject is
    /// the responses rather than what `serve` returned.
    pub fn finish(self) {
        let _ = self.thread.join();
    }

    /// Hangs up and returns what `serve` itself returned: the agent's own verdict on the session.
    pub fn join(self) -> Result<i32, AgentError> {
        self.thread.join().expect("the agent thread must not panic")
    }
}
