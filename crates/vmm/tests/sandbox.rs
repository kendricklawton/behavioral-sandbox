//! Integration tests for the [`Sandbox`] seam (P7.1): the lifecycle `open → exec (files + env) →
//! outputs → snapshot → close`, the jailed-by-default polarity (decision 015), and the VM half of
//! the secret-hygiene leak check (the host-log/error half runs without a VM in `src/exec.rs`).
//!
//! `#[ignore]`d because they need `/dev/kvm` and the agent rootfs. Run via
//! `cargo xtask ci-privileged`; the jailed-default test additionally needs real root and self-skips
//! without it.
#![allow(clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use agent_vmm::{Limits, Sandbox, Vm, VmmError, DEFAULT_JAIL_UID};

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
    // The decision-015 polarity flip, proven at the seam: the config sets *no* jail, and `open`
    // confines anyway — the VMM runs as the dropped uid and still serves an exec. The unjailed
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
fn lifecycle_runs_inputs_at_the_seam_and_collects_outputs() {
    // The embedder's whole loop without ever touching `RunningVm`: open (with a bulk output dir),
    // one exec carrying every input the seam takes — stdin, an injected file, env, an artifact
    // request — and a bulk write to `/output`, then collect the outputs on close.
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
            &[("RUN_MODE".into(), "seam-test".into())],
            &["art.txt".into()],
        )
        .expect("exec with the full input set");
    assert_eq!(result.exit_code, 0, "console:\n{}", sandbox.console());
    assert_eq!(result.stdout, b"from stdin\n");
    assert_eq!(
        result.files,
        vec![("art.txt".to_string(), b"seam-test=from a file".to_vec())],
        "the artifact must hold the env value and the injected file, combined in-guest"
    );

    let captured = sandbox.collect_outputs().expect("collect bulk outputs");
    assert_eq!(captured, vec!["mode.txt".to_string()]);
    let bulk = std::fs::read(out_dir.path().join("mode.txt")).expect("read captured output");
    assert_eq!(bulk, b"seam-test");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn session_state_persists_across_execs() {
    // Stateful sessions (P7.2) against a real guest: the VM is the session. Every exec serves
    // from the agent's one persistent working directory, so a file injected before exec 1 and a
    // file exec 1 writes are both visible to exec 2 — and the guest filesystem beyond the workdir
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
    // The two budgets as knobs (P7.3), driven end to end through Limits → BootConfig → every exec:
    // a 2 s wall makes a long sleep the cooperative ExecTimeout (the guest killed it — the
    // unchanged semantics), and a 4 KiB output cap makes a flood the typed OutputCap. Same
    // sandbox, both knobs, plus a within-budget exec proving the knobs don't false-positive.
    let mut limits = Limits::default();
    limits.wall = Duration::from_secs(2);
    limits.output_cap = 4096;
    let mut cfg = agent_rootfs_config().with_limits(limits);
    // One `wall` covers boot and exec at the seam (decision 013); this test wants a tight *exec*
    // budget without gambling on a 2 s boot, so it uses the driver-level split beneath the seam.
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
fn snapshot_at_the_seam_yields_a_restorable_bundle() {
    // `Sandbox::snapshot` closes the lifecycle: a warm (unjailed, overlay) sandbox snapshots, and
    // the bundle restores to an exec-ready clone. (Jailed clones from such a bundle are P7.0e's
    // proof in tests/snapshot.rs; snapshotting a *jailed* sandbox stays a typed refusal.)
    let bundle = TmpDir::new("sandbox-bundle");
    let sandbox = Sandbox::open_unjailed(agent_rootfs_config()).expect("open");
    let warm = ["python3", "-c", "import json"].map(String::from);
    assert_eq!(
        sandbox.exec(&warm, b"").expect("warm-up").exit_code,
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
    // The VM half of the P7.1 leak gate: a sentinel rides in as an env value and as an injected
    // file against a *real* guest, and is then grepped out of every observable engine surface —
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
        // it, was never polluted — in a real guest, not just the unit harness).
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

    // The guest received both inputs — RunResult is the caller's data, the allowed surface.
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
