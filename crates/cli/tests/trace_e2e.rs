//! End-to-end test of the CLI's audit face: `agent run --net --trace --record` on a real
//! sandbox yields the guest's output, a human-readable audit trail, and a parseable, deterministic
//! JSON record — the flag plumbing over the engine's convergence (whose *substance* — flows showing
//! up exactly, every axis bound — is proven by the loader's own `audit_record` e2e).
//!
//! `#[ignore]`d: it boots a real microVM (needs `/dev/kvm` + the agent rootfs) and attaches the
//! host-side probes (needs `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN` + kernel BTF + the built
//! object). Run via `cargo xtask ci-privileged`. Drives the **built `agent` binary** (Cargo's
//! `CARGO_BIN_EXE_agent`), so what's tested is exactly what an operator runs.

// A test binary: `expect` in non-`#[test]` helpers is the idiomatic assertion, which the
// workspace's deny doesn't auto-exempt outside `#[test]` fns (same note as the vmm suites).
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use agent_probes_loader::{check_support, object_path};

/// The workspace root, from this crate's manifest dir, so the artifact paths are cwd-independent.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Why this host can't run the test (a skip reason), or `None` when it can.
fn skip_reason() -> Option<String> {
    if let Err(e) = check_support() {
        return Some(e.to_string());
    }
    if !object_path().is_file() {
        return Some(format!(
            "BPF object {} not built (run `cargo xtask build-probes`)",
            object_path().display()
        ));
    }
    if !Path::new("/dev/kvm").exists() {
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

/// A scratch dir removed on drop, so a failing assertion can't leak it.
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("agent-trace-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        Self(dir)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn run_with_trace_and_record_yields_trail_and_json() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping run_with_trace_and_record_yields_trail_and_json: {why}");
        return;
    }
    let root = workspace_root();
    let scratch = TestDir::new();
    let record_path = scratch.0.join("record.json");

    // A workload that touches a file in-guest and prints — interesting enough to leave a footprint
    // on every axis the CLI surfaces. Unjailed on purpose: the proof here is the audit face, and
    // the unjailed path doesn't depend on the /dev/kvm jail-uid ACL.
    let out = Command::new(env!("CARGO_BIN_EXE_agent"))
        .current_dir(&root)
        .env("AGENT_ROOTFS", root.join("artifacts/rootfs-agent.ext4"))
        .env("AGENT_MARKER", "AGENT-GUEST-READY")
        .args(["run", "--unjailed", "--net", "--trace", "--record"])
        .arg(&record_path)
        .args([
            "--",
            "python3",
            "-c",
            "open('/etc/hostname').read(); print('p14-audit-demo')",
        ])
        .output()
        .expect("run the agent binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "agent run failed ({}): stderr: {stderr}",
        out.status
    );

    // The guest's own output is relayed first, then the human trail — both on stdout.
    assert!(stdout.contains("p14-audit-demo"), "guest output: {stdout}");
    assert!(
        stdout.contains("audit trail (host-observed"),
        "the --trace trail follows the run: {stdout}"
    );
    assert!(
        stdout.contains("guest sent"),
        "a --net run renders the network axis: {stdout}"
    );
    assert!(
        stdout.contains("the VMM's host footprint"),
        "the syscall axis is labeled honestly: {stdout}"
    );

    // The exported record is one line of parseable JSON with the pinned top-level shape, and a
    // capable host binds every axis (no coverage gap).
    let json = std::fs::read_to_string(&record_path).expect("read the --record file");
    assert_eq!(json.lines().count(), 1, "one line of JSON: {json}");
    let record: serde_json::Value = serde_json::from_str(&json).expect("record parses");
    assert!(record["timing"]["boot_ns"]
        .as_u64()
        .is_some_and(|ns| ns > 0));
    assert!(
        record["network"].is_object(),
        "a --net run has a network section"
    );
    assert!(record["host_syscalls"]["total"].is_u64());
    assert_eq!(
        record["coverage"].as_array().map(Vec::len),
        Some(0),
        "every axis binds on a capable host: {json}"
    );
}
