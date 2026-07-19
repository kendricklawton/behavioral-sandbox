//! CLI/daemon parity golden (the wire API, ADR 034): the **CLI** (`agent run --json`) and the
//! **daemon wire API** (`agentd`, driven
//! through the reference [`agentd_client::Client`]) render the *same* command **identically**, same
//! exit code, same stdout, same stderr. The two faces are thin hosts of one `agent-vmm` lifecycle, so
//! a run must never depend on which door it came through; this pins that invariant against drift (a
//! stream captured differently, an exit code mapped differently, a default limit that diverged).
//!
//! It compares only what is a *run result* on both faces: a command that **runs** and returns a
//! [`RunResult`](agent_vmm), exit code (zero or not), stdout, stderr. A guest fault that never
//! produces a result (an unspawnable binary) is deliberately *out* of scope: the CLI renders it as an
//! operational error (exit 2, a stderr diagnostic), the daemon as a non-fatal `error` reply, two
//! faithful renderings of a non-result, not a golden mismatch.
//!
//! `#[ignore]`d: boots real microVMs (needs `/dev/kvm` + the agent rootfs). Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-cli -- --ignored`. Both faces run
//! **unjailed**, the golden is the run-result rendering, not the jailer (that has its own suite),
//! and unjailed needs no root.
// A test binary: `panic!`/`expect` is the idiomatic assertion, which the workspace's `clippy::panic`
// deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agentd_client::{Client, OpenOptions};

/// The workspace root, from this crate's manifest dir, so the artifact paths are cwd-independent.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Why this host can't run the demo (a skip reason), or `None` when it can.
fn skip_reason() -> Option<String> {
    if !std::path::Path::new("/dev/kvm").exists() {
        return Some("/dev/kvm not present".into());
    }
    if !workspace_root()
        .join("artifacts/rootfs-agent.ext4")
        .is_file()
    {
        return Some("agent rootfs not built (run `cargo xtask build-rootfs`)".into());
    }
    None
}

/// A run result reduced to the three fields both faces render, the golden comparison surface.
#[derive(Debug, PartialEq, Eq)]
struct RunOutcome {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// The command cases exercised through both faces: a plain success, a non-zero exit that still
/// *runs* (a faithful result on both, not an error), and a stdin passthrough. Each is
/// `(argv, stdin, expected)`.
fn cases() -> Vec<(Vec<String>, String, RunOutcome)> {
    let argv = |parts: &[&str]| parts.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    vec![
        (
            argv(&["echo", "hello"]),
            String::new(),
            RunOutcome {
                exit_code: 0,
                stdout: "hello\n".into(),
                stderr: String::new(),
            },
        ),
        (
            // Runs, writes both streams, exits non-zero: a result, not an error, on both faces.
            argv(&["sh", "-c", "echo out; echo err 1>&2; exit 7"]),
            String::new(),
            RunOutcome {
                exit_code: 7,
                stdout: "out\n".into(),
                stderr: "err\n".into(),
            },
        ),
        (
            argv(&["cat"]),
            "piped payload\n".into(),
            RunOutcome {
                exit_code: 0,
                stdout: "piped payload\n".into(),
                stderr: String::new(),
            },
        ),
    ]
}

/// A spawned `agentd` that is SIGKILLed on drop, so a panicking assertion can't leak the daemon (its
/// session VM is then reaped by the lifetime sentinel; the socket file is cleared on the next bind).
struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The env the two faces share: the same rootfs, kernel, and readiness marker, so any difference in
/// the result is the *rendering*, not the inputs.
fn shared_env(cmd: &mut Command, root: &std::path::Path) {
    cmd.env("AGENT_ROOTFS", root.join("artifacts/rootfs-agent.ext4"))
        // The agent rootfs signals readiness with its own marker, not a getty `login:`.
        .env("AGENT_MARKER", agent_vmm::GUEST_READY_MARKER)
        .env("AGENT_LOG", "warn");
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cmd.env("AGENT_KERNEL", root.join("artifacts/vmlinux"));
    }
}

/// Launch `agentd --unjailed` on a private socket, returning once the socket is connectable.
fn launch_daemon() -> (Daemon, PathBuf) {
    let root = workspace_root();
    let dir = std::env::temp_dir().join(format!("agentd-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("create the daemon's socket dir: {e}");
    }
    let socket = dir.join("agentd.sock");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentd"));
    cmd.arg("--unjailed").arg("--socket").arg(&socket);
    shared_env(&mut cmd, &root);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn agentd: {e}"));
    let daemon = Daemon { child, dir };

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if UnixStream::connect(&socket).is_ok() {
            return (daemon, socket);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("agentd never began accepting on {}", socket.display());
}

/// Run one command through the **CLI** face: `agent run --unjailed --json -- <argv>`, feeding
/// `stdin`, and read the structured result off stdout (stderr carries only logs, so stdout is the one
/// JSON object).
fn run_via_cli(argv: &[String], stdin: &str) -> RunOutcome {
    let root = workspace_root();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent"));
    cmd.arg("run").arg("--unjailed").arg("--json").arg("--");
    cmd.args(argv);
    shared_env(&mut cmd, &root);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("spawn agent run: {e}"));
    child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("agent run has no stdin handle"))
        .write_all(stdin.as_bytes())
        .unwrap_or_else(|e| panic!("feed stdin to agent run: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait for agent run: {e}"));

    let body = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(body.trim())
        .unwrap_or_else(|e| panic!("agent --json result is one JSON object ({e}): {body:?}"));
    RunOutcome {
        exit_code: json["exit_code"]
            .as_i64()
            .unwrap_or_else(|| panic!("exit_code is an integer: {json}")) as i32,
        stdout: json["stdout"]
            .as_str()
            .unwrap_or_else(|| panic!("stdout is a string: {json}"))
            .to_string(),
        stderr: json["stderr"]
            .as_str()
            .unwrap_or_else(|| panic!("stderr is a string: {json}"))
            .to_string(),
    }
}

/// Run one command through the **daemon** face: an `exec` on an already-open session driven by the
/// reference client.
fn run_via_daemon(client: &mut Client, argv: &[String], stdin: &str) -> RunOutcome {
    let run = client
        .exec(argv, stdin)
        .unwrap_or_else(|e| panic!("daemon exec {argv:?}: {e}"));
    RunOutcome {
        exit_code: run.exit_code,
        stdout: run.stdout,
        stderr: run.stderr,
    }
}

#[test]
#[ignore = "spawns agentd + agent; needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn the_cli_and_the_daemon_render_a_run_identically() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping the_cli_and_the_daemon_render_a_run_identically: {why}");
        return;
    }

    // One daemon session drives every case (the commands are stateless; a fresh CLI process boots per
    // case, since that is how the CLI is used). Both open with the default profile, so both boot the
    // same conservative `Limits::default()`, no divergence hides in a differing knob.
    let (_daemon, socket) = launch_daemon();
    let mut client = Client::connect(&socket).unwrap_or_else(|e| panic!("connect: {e}"));
    if let Err(e) = client.set_read_timeout(Some(Duration::from_secs(45))) {
        panic!("set read timeout: {e}");
    }
    client
        .open(OpenOptions::default())
        .unwrap_or_else(|e| panic!("open: {e}"));

    for (argv, stdin, expected) in cases() {
        let via_cli = run_via_cli(&argv, &stdin);
        let via_daemon = run_via_daemon(&mut client, &argv, &stdin);

        // The two faces agree with each other...
        assert_eq!(
            via_cli, via_daemon,
            "CLI and daemon must render {argv:?} identically"
        );
        // ...and both agree with the expected result (so a shared bug can't pass by matching itself).
        assert_eq!(
            via_cli, expected,
            "the rendered result for {argv:?} must be the expected one"
        );
    }

    client.close().unwrap_or_else(|e| panic!("close: {e}"));
}
