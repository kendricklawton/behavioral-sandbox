//! Integration tests for the [`Sandbox`] public API: the lifecycle `open → exec (files + env) →
//! outputs → snapshot → close`, the jailed-by-default polarity (ADR 012), and the VM half of
//! the secret-hygiene leak check (the host-log/error half runs without a VM in `src/exec.rs`).
//!
//! `#[ignore]`d because they need `/dev/kvm` and the agent rootfs. Run via
//! `cargo xtask ci-privileged`; the jailed-default test additionally needs real root and self-skips
//! without it.
#![allow(clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use agent_vmm::{Limits, Sandbox, Vm, VmmError, DEFAULT_JAIL_UID};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::{agent_rootfs_config, have_jailer_privileges, TmpDir};

/// The uid the process behind `pid` runs as (the real uid from `/proc/<pid>/status`), as text.
fn vmm_uid(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
        })
}

#[test]
#[ignore = "needs /dev/kvm + real root + the jailer (run via `cargo xtask ci-privileged` as root)"]
fn sandbox_opens_jailed_by_default() {
    // The ADR 012 polarity flip, proven at the public API: the config sets *no* jail, and `open`
    // confines anyway, the VMM runs as the dropped uid and still serves an exec. The unjailed
    // path below is only reachable by writing `open_unjailed`.
    if !have_jailer_privileges() {
        eprintln!("skipping sandbox_opens_jailed_by_default: needs real root (euid 0)");
        return;
    }
    let cfg = agent_rootfs_config();
    assert!(
        cfg.jail.is_none(),
        "precondition: the config asks for no jail"
    );
    let sandbox = Sandbox::open(cfg).expect("the sandbox should open jailed");
    assert_eq!(
        vmm_uid(sandbox.vmm_pid()).as_deref(),
        Some(DEFAULT_JAIL_UID.to_string().as_str()),
        "the VMM must run as the dropped jail uid without being asked to"
    );
    let out = sandbox
        .exec(&["echo".into(), "confined".into()], b"")
        .expect("exec inside the jailed-by-default sandbox");
    assert_eq!(out.stdout, b"confined\n");
    sandbox.shutdown().expect("shutdown");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn lifecycle_runs_inputs_and_collects_outputs() {
    // The embedder's whole loop without ever touching `RunningVm`: open (with a bulk output dir),
    // one exec carrying every input the public API takes, stdin, an injected file, env, an artifact
    // request, and a bulk write to `/output`, then collect the outputs on close.
    // (`open_unjailed`: the explicit dev-host opt-out; the jailed default is proven root-gated
    // above, and the two differ only in confinement, not in this surface.)
    let out_dir = TmpDir::new("sandbox-outputs");
    let mut cfg = agent_rootfs_config();
    cfg.output_dir = Some(out_dir.path().to_path_buf());
    let sandbox = Sandbox::open_unjailed(cfg).expect("open");

    let result = sandbox
        .exec_with_files(
            &[
                "sh".into(),
                "-c".into(),
                // stdin → stdout; file + env → an artifact; env → a bulk output file.
                "cat; printf '%s=%s' \"$RUN_MODE\" \"$(cat in.txt)\" > art.txt; \
                 printf '%s' \"$RUN_MODE\" > /output/mode.txt"
                    .into(),
            ],
            b"from stdin\n",
            &[("in.txt".into(), b"from a file".to_vec())],
            &[("RUN_MODE".into(), "api-test".into())],
            &["art.txt".into()],
        )
        .expect("exec with the full input set");
    assert_eq!(result.exit_code, 0, "console:\n{}", sandbox.console());
    assert_eq!(result.stdout, b"from stdin\n");
    assert_eq!(
        result.files,
        vec![agent_vmm::Artifact::new(
            "art.txt",
            b"api-test=from a file".to_vec()
        )],
        "the artifact must hold the env value and the injected file, combined in-guest"
    );

    let captured = sandbox.collect_outputs().expect("collect bulk outputs");
    assert_eq!(captured, vec!["mode.txt".to_string()]);
    let bulk = std::fs::read(out_dir.path().join("mode.txt")).expect("read captured output");
    assert_eq!(bulk, b"api-test");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn kill_handle_stays_inert_during_output_readback() {
    // `collect_outputs` reaps the VMM, then runs a multi-second `e2fsck`/`debugfs` readback before
    // the sandbox drops into teardown. `power_off_and_wait` marks teardown down *before* that reap,
    // so a `KillHandle` fired across the readback finds `torn_down` already set and no-ops, it can
    // never signal the reaped (recyclable) pid (the degraded-host `kill -9 <pid>` fallback). Fire it
    // hard from another thread for the whole call and assert the outputs still come back clean and
    // every `kill()` is a no-op `Ok` (never the "could not reach VMM pid" error). On a cgroup host
    // the handle takes the cgroup path; the ordering it guards is the same either way.
    let out_dir = TmpDir::new("readback-killhandle");
    let mut cfg = agent_rootfs_config();
    cfg.output_dir = Some(out_dir.path().to_path_buf());
    let sandbox = Sandbox::open_unjailed(cfg).expect("open");
    sandbox
        .exec(
            &["sh".into(), "-c".into(), "printf ok > /output/f.txt".into()],
            b"",
        )
        .expect("write a bulk output");

    let handle = sandbox.kill_handle();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        while !stop_worker.load(Ordering::Relaxed) {
            handle
                .kill()
                .expect("a fired kill handle is always Ok (cgroup write or a torn-down no-op)");
        }
    });

    let captured = sandbox
        .collect_outputs()
        .expect("collect outputs under a concurrently-fired kill handle");
    stop.store(true, Ordering::Relaxed);
    worker.join().expect("kill-handle worker thread");

    assert_eq!(captured, vec!["f.txt".to_string()]);
    let bulk = std::fs::read(out_dir.path().join("f.txt")).expect("read captured output");
    assert_eq!(bulk, b"ok");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn session_state_persists_across_execs() {
    // Stateful sessions against a real guest: the VM is the session. Every exec serves
    // from the agent's one persistent working directory, so a file injected before exec 1 and a
    // file exec 1 writes are both visible to exec 2, and the guest filesystem beyond the workdir
    // (here /root, on the boot's tmpfs overlay) accumulates too. State's lifetime is the VM's:
    // teardown discards the overlay, so nothing outlives the session.
    let sandbox = Sandbox::open_unjailed(agent_rootfs_config()).expect("open");

    let first = sandbox
        .exec_with_files(
            &[
                "sh".into(),
                "-c".into(),
                "cat seed.txt > grown.txt && echo second >> grown.txt && echo root > /root/state"
                    .into(),
            ],
            b"",
            &[("seed.txt".into(), b"first\n".to_vec())],
            &[],
            &[],
        )
        .expect("exec 1");
    assert_eq!(first.exit_code, 0, "console:\n{}", sandbox.console());

    // A later exec, a fresh vsock connection: the injected file, the written file, and the
    // out-of-workdir state are all still there.
    let second = sandbox
        .exec(
            &[
                "sh".into(),
                "-c".into(),
                "cat seed.txt grown.txt /root/state".into(),
            ],
            b"",
        )
        .expect("exec 2");
    assert_eq!(second.exit_code, 0);
    assert_eq!(
        second.stdout, b"first\nfirst\nsecond\nroot\n",
        "state from exec 1 must be visible to exec 2"
    );
    sandbox.shutdown().expect("shutdown");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn exec_budgets_are_per_sandbox_knobs() {
    // The two budgets as knobs, driven end to end through Limits → BootConfig → every exec:
    // a 2 s wall makes a long sleep the cooperative ExecTimeout (the guest killed it, the
    // unchanged semantics), and a 4 KiB output cap makes a flood the typed OutputCap. Same
    // sandbox, both knobs, plus a within-budget exec proving the knobs don't false-positive.
    let mut limits = Limits::default();
    limits.wall = Duration::from_secs(2);
    limits.output_cap = 4096;
    let mut cfg = agent_rootfs_config().with_limits(limits);
    // One `wall` covers boot and exec at the public API (ADR 010); this test wants a tight *exec*
    // budget without gambling on a 2 s boot, so it uses the driver-level split beneath the public API.
    cfg.boot_timeout = Duration::from_secs(30);
    let sandbox = Sandbox::open_unjailed(cfg).expect("open");

    let ok = sandbox
        .exec(&["echo".into(), "within budget".into()], b"")
        .expect("a modest exec passes both knobs");
    assert_eq!(ok.stdout, b"within budget\n");

    let started = Instant::now();
    let err = sandbox
        .exec(&["sleep".into(), "30".into()], b"")
        .expect_err("a 30 s sleep must trip the 2 s exec wall");
    assert!(
        matches!(err, VmmError::ExecTimeout { limit } if limit == Duration::from_secs(2)),
        "got {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the guest must kill at the budget, not wait the sleep out (took {:?})",
        started.elapsed()
    );

    let err = sandbox
        .exec(&["seq".into(), "1".into(), "100000".into()], b"")
        .expect_err("a flood must trip the 4 KiB output cap");
    assert!(
        matches!(err, VmmError::OutputCap { limit: 4096 }),
        "got {err:?}"
    );
    sandbox.shutdown().expect("shutdown");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn many_sandboxes_run_concurrently_without_interference() {
    // Concurrency: several sandboxes boot and exec *at the same time*, from threads, so
    // the boots genuinely overlap, and each result is exactly its own: no cross-talk on the vsock
    // channels, no scratch-dir or netns collisions, no wedge. (Concurrent *clones* are proven in
    // tests/snapshot.rs; this is concurrent independent sandboxes, the embedder's fan-out shape.)
    let workers: Vec<_> = (0..3)
        .map(|i| {
            std::thread::spawn(move || {
                let sandbox = Sandbox::open_unjailed(agent_rootfs_config()).expect("open");
                let out = sandbox
                    .exec(
                        &[
                            "sh".into(),
                            "-c".into(),
                            format!("echo {i} > mine.txt; printf 'sandbox-%s' \"$(cat mine.txt)\""),
                        ],
                        b"",
                    )
                    .expect("exec in a concurrent sandbox");
                assert_eq!(out.exit_code, 0, "console:\n{}", sandbox.console());
                // `$(…)` strips the trailing newline and the bare `printf` adds none back.
                assert_eq!(
                    String::from_utf8_lossy(&out.stdout),
                    format!("sandbox-{i}"),
                    "each sandbox must see exactly its own state"
                );
                sandbox.shutdown().expect("shutdown");
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("concurrent sandbox thread");
    }
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn two_concurrent_stateful_sessions_stay_isolated() {
    // Two stateful sessions at once: session identity is VM identity (ADR 016), so
    // isolation between them is KVM, not agent bookkeeping. Both sandboxes are live together and
    // their execs interleave A1 → B1 → A2 → B2 on the *same* relative filename; each session then
    // reads back exactly its own accumulated state, and a file that exists only in B is absent
    // in A.
    let a = Sandbox::open_unjailed(agent_rootfs_config()).expect("open session A");
    let b = Sandbox::open_unjailed(agent_rootfs_config()).expect("open session B");

    let sh = |cmd: &str| vec!["sh".into(), "-c".into(), cmd.to_string()];
    assert_eq!(
        a.exec(&sh("echo A1 > state.txt"), b"")
            .expect("A1")
            .exit_code,
        0
    );
    assert_eq!(
        b.exec(&sh("echo B1 > state.txt; echo only-b > only_b.txt"), b"")
            .expect("B1")
            .exit_code,
        0
    );
    assert_eq!(
        a.exec(&sh("echo A2 >> state.txt"), b"")
            .expect("A2")
            .exit_code,
        0
    );
    assert_eq!(
        b.exec(&sh("echo B2 >> state.txt"), b"")
            .expect("B2")
            .exit_code,
        0
    );

    let a_state = a.exec(&sh("cat state.txt"), b"").expect("read A");
    assert_eq!(
        a_state.stdout, b"A1\nA2\n",
        "session A must hold exactly its own interleaved writes"
    );
    let b_state = b.exec(&sh("cat state.txt"), b"").expect("read B");
    assert_eq!(
        b_state.stdout, b"B1\nB2\n",
        "session B must hold exactly its own interleaved writes"
    );
    // Negative half: B's private file never appears in A.
    let leak = a
        .exec(&sh("cat only_b.txt"), b"")
        .expect("probe A for B's file");
    assert_ne!(
        leak.exit_code,
        0,
        "a file written in session B must not exist in session A; got {:?}",
        String::from_utf8_lossy(&leak.stdout)
    );
    a.shutdown().expect("shutdown A");
    b.shutdown().expect("shutdown B");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn snapshot_yields_a_restorable_bundle() {
    // `Sandbox::snapshot` closes the lifecycle: a prewarmed (unjailed, overlay) sandbox snapshots, and
    // the bundle restores to an exec-ready clone. (Jailed clones from such a bundle are the jailed-restore path's
    // proof in tests/snapshot.rs; snapshotting a *jailed* sandbox stays a typed refusal.)
    let bundle = TmpDir::new("sandbox-bundle");
    let sandbox = Sandbox::open_unjailed(agent_rootfs_config()).expect("open");
    let prewarmed = ["python3", "-c", "import json"].map(String::from);
    assert_eq!(
        sandbox.exec(&prewarmed, b"").expect("warm-up").exit_code,
        0,
        "warm-up should succeed"
    );
    let snapshot = sandbox
        .snapshot(bundle.path())
        .expect("snapshot the sandbox");
    sandbox.shutdown().expect("close the source");

    let clone = Vm::restore(&snapshot, &agent_rootfs_config()).expect("restore from the bundle");
    let out = clone
        .exec(&["python3".into(), "-c".into(), "print(6 * 7)".into()], b"")
        .expect("exec in the restored clone");
    assert_eq!(out.stdout, b"42\n");
    clone.shutdown().expect("shutdown the clone");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn injected_secrets_never_reach_the_console_or_host_logs() {
    // The VM half of the leak gate: a sentinel rides in as an env value and as an injected
    // file against a *real* guest, and is then grepped out of every observable engine surface,
    // the serial console (where the guest agent's own log lands), the host's log stream (captured
    // at TRACE around the calls), and a failing injection's error rendering. The run's own
    // RunResult is the one surface allowed to carry it.
    const SENTINEL: &str = "S3KR1T-vm-canary-41ab88";

    let sandbox = Sandbox::open_unjailed(agent_rootfs_config()).expect("open");

    // Capture the host-side tracing this thread emits during the execs.
    use std::sync::{Arc, Mutex, PoisonError};
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Sink::default();
    let writer_sink = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer_sink.clone())
        .finish();

    let (received, err) = tracing::subscriber::with_default(subscriber, || {
        let received = sandbox
            .exec_with_files(
                &[
                    "sh".into(),
                    "-c".into(),
                    "printf '%s %s' \"$LEAK_SECRET\" \"$(cat leak.txt)\"".into(),
                ],
                b"",
                &[("leak.txt".into(), SENTINEL.as_bytes().to_vec())],
                &[("LEAK_SECRET".into(), SENTINEL.into())],
                &[],
            )
            .expect("exec with the sentinel inputs");
        // Env is per-exec: a later command must not see it (the agent's own process, which spawned
        // it, was never polluted, in a real guest, not just the unit harness).
        let after = sandbox
            .exec(
                &[
                    "sh".into(),
                    "-c".into(),
                    "printf '%s' \"$LEAK_SECRET\"".into(),
                ],
                b"",
            )
            .expect("env-free exec");
        assert!(
            after.stdout.is_empty(),
            "a later exec must not inherit an earlier exec's env"
        );
        // A failing injection whose *data* holds the sentinel: the error names the path only.
        let err = sandbox
            .exec_with_files(
                &["true".into()],
                b"",
                &[("../escape.txt".into(), SENTINEL.as_bytes().to_vec())],
                &[],
                &[],
            )
            .expect_err("an escaping path must be refused");
        (received, err)
    });

    // The guest received both inputs, RunResult is the caller's data, the allowed surface.
    assert_eq!(
        String::from_utf8_lossy(&received.stdout),
        format!("{SENTINEL} {SENTINEL}")
    );
    assert!(matches!(err, VmmError::GuestExec(_)), "got {err:?}");
    let (display, debug) = (format!("{err}"), format!("{err:?}"));
    assert!(
        !display.contains(SENTINEL) && !debug.contains(SENTINEL),
        "sentinel leaked into the error: {debug}"
    );

    // Positive control before the negative grep: the agent's completion log line reaches the
    // console (its stderr is the serial console), so the console genuinely is the surface an
    // env-logging agent would leak on. It arrives through the console reader asynchronously.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sandbox.console().contains("command finished") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let console = sandbox.console();
    assert!(
        console.contains("command finished"),
        "expected the agent's exec log on the console; console:\n{console}"
    );
    assert!(
        !console.contains(SENTINEL),
        "sentinel leaked into the serial console:\n{console}"
    );
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap_or_else(PoisonError::into_inner))
        .into_owned();
    assert!(
        logs.contains("exec"),
        "expected captured host spans, got {logs:?}"
    );
    assert!(
        !logs.contains(SENTINEL),
        "sentinel leaked into host logs: {logs}"
    );
    sandbox.shutdown().expect("shutdown");
}
