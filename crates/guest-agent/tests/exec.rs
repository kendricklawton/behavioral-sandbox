//! Integration tests for the guest agent, driving [`bsx_guest_agent::serve`] through the **public**
//! channel API ([`ClientConnection`]) over a unix socketpair, the same protocol the host will speak
//! over vsock, but with no VM.
// This is a test binary; the helpers aren't `#[test]` fns, so the workspace's no-unwrap/expect
// lints don't auto-exempt them. Panicking on setup failure is correct in a test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use bsx_channel::{ClientConnection, Request};

mod common;

use common::{Agent, Exec, Outcome};

#[test]
fn echo_reports_stdout_and_exit_zero() {
    let run = Agent::run(Exec::new(&["echo", "hi"]));
    assert_eq!(run.stdout, b"hi\n");
    assert!(run.stderr.is_empty());
    assert_eq!(run.outcome, Outcome::Exit(0));
}

#[test]
fn captures_stderr_and_nonzero_exit() {
    let run = Agent::run(Exec::new(&["sh", "-c", "echo out; echo err 1>&2; exit 3"]));
    assert_eq!(run.stdout, b"out\n");
    assert_eq!(run.stderr, b"err\n");
    assert_eq!(run.outcome, Outcome::Exit(3));
}

#[test]
fn missing_binary_reports_error_not_exit() {
    let run = Agent::run(Exec::new(&["definitely-not-a-real-binary-zzz"]));
    assert!(
        matches!(run.outcome, Outcome::Error(_)),
        "a spawn failure is a terminal Error frame, not an Exit: {:?}",
        run.outcome
    );
}

#[test]
fn empty_command_is_rejected() {
    let run = Agent::run(Exec::new(&[]));
    assert!(
        matches!(run.outcome, Outcome::Error(_)),
        "got {:?}",
        run.outcome
    );
}

#[test]
fn large_output_streams_without_deadlock() {
    // Far past a pipe buffer, so the two pumps must drain concurrently: a single-threaded
    // read-then-forward hangs here.
    let run = Agent::run(Exec::new(&["sh", "-c", "seq 1 100000"]));
    assert_eq!(run.outcome, Outcome::Exit(0));
    assert!(run.stdout.len() > 500_000, "got {} bytes", run.stdout.len());
    assert!(run.stdout.starts_with(b"1\n"));
    assert!(run.stdout.ends_with(b"100000\n"));
}

#[test]
fn signal_death_maps_to_128_plus_signal() {
    // SIGKILL is 9 → 137 (the shell convention).
    let run = Agent::run(Exec::new(&["sh", "-c", "kill -9 $$"]));
    assert_eq!(run.outcome, Outcome::Exit(137));
}

#[test]
fn stdin_is_fed_to_the_command() {
    // `cat` only exits once its stdin is closed, so this pins both the delivery and the EOF.
    let run = Agent::run(Exec::new(&["cat"]).stdin(b"piped input\n"));
    assert_eq!(run.stdout, b"piped input\n");
    assert_eq!(run.outcome, Outcome::Exit(0));
}

#[test]
fn env_reaches_the_command_but_never_the_agents_own_process() {
    // Both halves: the variable reaches the command, and `serve` did not touch this process's env.
    let key = "BSX_TEST_ENV_SCOPE";
    assert!(
        std::env::var_os(key).is_none(),
        "test precondition: {key} must not be set"
    );
    let run = Agent::run(
        Exec::new(&["sh", "-c", &format!("printf '%s' \"${key}\"")]).env(key, "from-the-host"),
    );
    assert_eq!(run.outcome, Outcome::Exit(0));
    assert_eq!(
        run.stdout, b"from-the-host",
        "the command must see the injected env"
    );
    assert!(
        std::env::var_os(key).is_none(),
        "the agent process's own environment must stay untouched"
    );
}

/// A bare program reachable only through the **injected** `PATH` runs: the up-front check has to
/// read the same `PATH` the spawn will.
#[test]
fn a_program_on_the_injected_path_runs_rather_than_being_refused() {
    let scratch = bsx_test_support::ScratchDir::created("agent-injected-path");
    let bin = scratch.path().join("bin");
    std::fs::create_dir_all(&bin).expect("bin dir");
    let tool = bin.join("bsx-probe-tool");
    std::fs::write(&tool, "#!/bin/sh\nprintf 'ran-from-injected-PATH'\n").expect("write the tool");
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let inherited = std::env::var("PATH").unwrap_or_default();
    let injected = format!("{}:{inherited}", bin.display());
    let run = Agent::run(Exec::new(&["bsx-probe-tool"]).env("PATH", &injected));
    assert_eq!(
        run.outcome,
        Outcome::Exit(0),
        "the command must run, not be refused up front"
    );
    assert_eq!(run.stdout, b"ran-from-injected-PATH");
}

#[test]
fn injected_file_is_read_by_the_command_and_artifact_returned() {
    // Put a file in, `cat` it (proving cwd = the working dir), and pull an artifact back.
    let mut agent = Agent::start();
    agent
        .put_file("note.txt", b"contents\n")
        .exec(Exec::new(&["sh", "-c", "cat note.txt; cp note.txt copy.txt"]).artifact("copy.txt"));
    let run = agent.drain();
    agent.finish();

    assert_eq!(run.outcome, Outcome::Exit(0));
    assert_eq!(run.stdout, b"contents\n");
    assert_eq!(
        run.files,
        vec![("copy.txt".to_string(), b"contents\n".to_vec())]
    );
}

#[test]
fn session_state_persists_across_connections() {
    // Two connections on one session dir share a working directory, across both an injected file
    // and one the first exec wrote.
    let scratch = bsx_test_support::ScratchDir::new("agent-session");

    // Exec 1: read the injected file, append to it, and write a new one.
    let mut agent = Agent::start_in(scratch.path());
    agent
        .put_file("seed.txt", b"one\n")
        .exec(Exec::new(&["sh", "-c", "echo two >> seed.txt"]));
    assert_eq!(agent.drain().outcome, Outcome::Exit(0));
    agent.join().expect("serve 1");

    // Exec 2, a fresh connection on the same session dir: the accumulated file is still there.
    let mut agent = Agent::start_in(scratch.path());
    agent.exec(Exec::new(&["cat", "seed.txt"]));
    let run = agent.drain();
    agent.join().expect("serve 2");

    assert_eq!(run.outcome, Outcome::Exit(0));
    assert_eq!(
        run.stdout, b"one\ntwo\n",
        "state written by exec 1 must be visible to exec 2"
    );
}

#[test]
fn a_relative_program_built_in_the_session_runs_by_its_path() {
    // A `/`-bearing relative program resolves against the run's dir, not the agent's cwd.
    let scratch = bsx_test_support::ScratchDir::new("agent-relprog");

    // One exec per connection against the shared session dir: build the executable, then run it.
    let run_argv = |argv: &[&str]| {
        let mut agent = Agent::start_in(scratch.path());
        agent.exec(Exec::new(argv));
        let run = agent.drain();
        agent.finish();
        run
    };

    // Build the executable via a shell line (argv[0] = "sh" is PATH-resolved), then invoke it by path.
    let built = run_argv(&[
        "sh",
        "-c",
        "printf '#!/bin/sh\\necho ran-in-workdir\\n' > tool && chmod +x tool",
    ]);
    assert_eq!(built.outcome, Outcome::Exit(0), "building ./tool");

    let run = run_argv(&["./tool"]);
    assert_eq!(
        run.outcome,
        Outcome::Exit(0),
        "a session-built ./tool must run, not be rejected"
    );
    assert_eq!(run.stdout, b"ran-in-workdir\n");
}

#[test]
fn hung_command_is_killed_at_its_deadline() {
    // A command that would run far longer than its timeout must be killed and reported as TimedOut,
    // not hang the agent. A short timeout keeps the test fast.
    let mut agent = Agent::start();
    agent.exec(Exec::new(&["sleep", "30"]).timeout_ms(300));

    let started = std::time::Instant::now();
    let run = agent.drain();
    assert!(
        matches!(run.outcome, Outcome::TimedOut { .. }),
        "expected TimedOut, got {:?}",
        run.outcome
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the agent must kill the command promptly, not wait it out"
    );
    // The agent's own return signals the SIGKILL convention.
    assert!(matches!(agent.join(), Ok(137)));
}

#[test]
fn command_under_its_deadline_is_not_falsely_killed() {
    // A command that finishes well within its budget must exit normally, never TimedOut.
    let run = Agent::run(Exec::new(&["sh", "-c", "sleep 0.1; echo done"]).timeout_ms(5_000));
    assert_eq!(
        run.outcome,
        Outcome::Exit(0),
        "a command inside its budget must not be killed"
    );
    assert_eq!(run.stdout, b"done\n");
}

#[test]
fn put_file_rejects_path_traversal() {
    // A path that climbs out of the working dir must be rejected with a terminal Error, not written.
    let mut agent = Agent::start();
    agent.put_file("../escape.txt", b"nope");
    let run = agent.drain();
    assert!(
        matches!(run.outcome, Outcome::Error(_)),
        "expected a rejection, got {:?}",
        run.outcome
    );
    assert!(
        agent.join().is_err(),
        "a traversing path must fail the request"
    );
    // Rejected must mean *not written*, since a reject-after-write bug would pass the error asserts
    // alone.
    assert!(
        !std::path::Path::new("../escape.txt").exists(),
        "the traversing path must be rejected before any write"
    );
}

/// Every stream the command wrote reaches the caller, and only the artifacts it asked for.
#[test]
fn a_run_carries_both_streams_and_only_the_requested_artifacts() {
    let run = Agent::run(Exec::new(&[
        "sh",
        "-c",
        "echo o; echo e 1>&2; printf 'c' > unasked.txt; exit 7",
    ]));
    assert_eq!(run.stdout, b"o\n");
    assert_eq!(run.stderr, b"e\n", "stderr is collected, never discarded");
    assert_eq!(run.outcome, Outcome::Exit(7));
    assert!(
        run.files.is_empty(),
        "the artifact list is a request, not a description of the working dir: {:?}",
        run.files
    );
}

#[test]
fn bad_handshake_is_rejected_not_hung() {
    // A wrong magic fails promptly: `read_exact` gets its 6 bytes and the check fails.
    let (mut host, guest) = UnixStream::pair().expect("socketpair");
    let agent = std::thread::spawn(move || bsx_guest_agent::serve(guest));
    host.write_all(b"XXXXXX not a handshake")
        .expect("write garbage");
    let result = agent.join().expect("agent thread");
    assert!(result.is_err(), "a bad handshake must be a typed error");
}

#[test]
fn stalled_host_does_not_wedge_the_guest() {
    // A host that stops reading against a flooding command: the write deadline bounds `serve`.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    guest
        .set_write_timeout(Some(Duration::from_millis(200)))
        .expect("set write timeout");

    let (tx, rx) = std::sync::mpsc::channel();
    let agent = std::thread::spawn(move || {
        let r = bsx_guest_agent::serve(guest);
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
            timeout_ms: NonZeroU32::new(30_000),
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

#[test]
fn a_host_that_stalls_mid_frame_is_a_bounded_typed_error() {
    // The read-side twin: deadlines are the transport owner's job, and the crate arms none.
    let (host, guest) = UnixStream::pair().expect("socketpair");
    guest
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");
    // A raw clone of the host end, so the partial frame can be written outside the typed client.
    let raw = host.try_clone().expect("clone host end");

    let (tx, rx) = std::sync::mpsc::channel();
    let agent = std::thread::spawn(move || {
        let r = bsx_guest_agent::serve(guest);
        let _ = tx.send(());
        r
    });

    let client = ClientConnection::connect(host).expect("client handshake");
    (&raw)
        .write_all(&[0x01, 0x00])
        .expect("write a partial frame header");
    // ...then silence: the agent's next read must trip the armed deadline, not block forever.

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(()) => {
            let result = agent.join().expect("agent thread");
            assert!(
                result.is_err(),
                "a mid-frame stall must be a typed error, not success"
            );
        }
        Err(_) => panic!("serve wedged: a mid-frame host stall hung the guest agent"),
    }
    drop(client);
}
