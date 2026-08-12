//! That the agent **reports** losing its per-exec cgroup, in its own test binary.
//!
//! Separate from `exec.rs` because the report is latched once per agent *process*: sharing a binary
//! with the other tests would make the assertion depend on which of them ran an exec first.
// A test binary: panicking on setup failure is the idiomatic assertion here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsx_test_support::LogSink;

mod common;

use common::{Agent, Exec};

/// Whether this host lets the agent make a per-exec cgroup, answered by doing it rather than by
/// guessing from a uid: the privileged gate runs as real root with a writable cgroup v2 mount, an
/// ordinary dev box does not, and the agent must be right on both.
fn can_make_a_cgroup() -> bool {
    let probe = std::path::Path::new("/sys/fs/cgroup")
        .join(format!("bsx-cgroup-probe-{}", std::process::id()));
    match std::fs::create_dir(&probe) {
        Ok(()) => {
            let _ = std::fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Runs `n` trivial execs, one per agent, all logging into one sink.
///
/// `serve` is one connection one command, so `n` execs means `n` agents. They share this test
/// binary's process, which is the scope the report is latched over.
fn log_of_execs(n: usize) -> String {
    let sink = LogSink::default();
    for _ in 0..n {
        let agent_sink = sink.clone();
        let mut agent = Agent::spawn(move |guest| {
            tracing::subscriber::with_default(agent_sink.subscriber(), || {
                bsx_guest_agent::serve(guest)
            })
        });
        agent.exec(Exec::new(&["true"]));
        let _ = agent.drain();
        agent.finish();
    }
    sink.contents()
}

/// Losing the per-exec cgroup is reported, and reported once.
///
/// What is lost is whole-tree reaping: a command that double-forks a daemon holding the output pipes
/// keeps them open, so the pumps never see EOF and the session thread parks until that daemon exits.
/// The engine reports the same degradation of its own lifetime cgroup (`lifetime.rs`'s `adopt`).
#[test]
fn a_lost_per_exec_cgroup_is_reported_once() {
    // Two execs, so one run of the test covers both halves: that it is said at all, and that it is
    // not said twice. The latch is process-global, so this is the binary's only chance to see it.
    let log = log_of_execs(2);
    let said = log.matches("no per-exec cgroup").count();

    if can_make_a_cgroup() {
        assert_eq!(
            said, 0,
            "this host makes the cgroup, so nothing is lost to report; got:\n{log}"
        );
        return;
    }
    assert!(
        log.contains("whole-tree reaping is off"),
        "the fallback must name what it costs, not just that it happened; got:\n{log}"
    );
    assert_eq!(
        said, 1,
        "once per agent process, not once per exec, or a long session on a cgroup-less guest \
         buries every command's own output under repeats of it; got:\n{log}"
    );
}
