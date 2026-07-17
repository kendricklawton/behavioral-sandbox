//! End-to-end test of the CLI's audit face: `agent run --net --trace --record` on a real
//! sandbox yields the guest's output, a human-readable audit trail, and a parseable, deterministic
//! JSON record — the flag plumbing over the engine's convergence (whose *substance* — flows showing
//! up exactly, every axis bound — is proven by the loader's own `audit_record` e2e).
//!
//! `#[ignore]`d: it boots a real microVM (needs `/dev/kvm` + the agent rootfs) and attaches the
//! host-side probes (needs `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN` + kernel BTF + the built
//! object). Run via `cargo xtask ci-privileged`. Drives the **built `agent` binary** (Cargo's
//! `CARGO_BIN_EXE_agent`), so what's tested is exactly what an operator runs.

// A test binary: `expect`/`panic!` in non-`#[test]` helpers are the idiomatic assertions, which the
// workspace's deny doesn't auto-exempt outside `#[test]` fns (same note as the vmm suites).
#![allow(clippy::expect_used, clippy::panic)]

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

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn allow_enforces_egress_and_the_record_shows_the_allowed_flow_and_the_denial() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping allow_enforces_egress_and_the_record_shows_the_allowed_flow_and_the_denial: {why}");
        return;
    }
    let root = workspace_root();
    let scratch = TestDir::new();
    let record_path = scratch.0.join("record.json");

    // The host end of every VM's fixed point-to-point /30 is `10.200.0.1` (the guest is `.2`), so the
    // gateway address is known from outside — no per-run allocation to discover. Allow it on **one**
    // UDP port and deny another: the guest can route to `10.200.0.1` (its connected /30), so both
    // datagrams reach the tap, where the policy passes 9999 (a flow) and drops 8888 (a denial).
    let workload = "\
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(5):
    s.sendto(b'ok', ('10.200.0.1', 9999))
for _ in range(5):
    try:
        s.sendto(b'no', ('10.200.0.1', 8888))
    except OSError:
        pass
print('p14-9b-egress')
";
    let out = Command::new(env!("CARGO_BIN_EXE_agent"))
        .current_dir(&root)
        .env("AGENT_ROOTFS", root.join("artifacts/rootfs-agent.ext4"))
        .env("AGENT_MARKER", "AGENT-GUEST-READY")
        .args([
            "run",
            "--unjailed",
            "--net",
            "--allow",
            "10.200.0.1:9999/udp",
            "--record",
        ])
        .arg(&record_path)
        .args(["--", "python3", "-c", workload])
        .output()
        .expect("run the agent binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "agent run --allow failed ({}): stderr: {stderr}",
        out.status
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("p14-9b-egress"),
        "the guest workload ran"
    );

    let json = std::fs::read_to_string(&record_path).expect("read the --record file");
    let record: serde_json::Value = serde_json::from_str(&json).expect("record parses");
    // Enforcement armed — no coverage gap (the --allow refusal path did not fire on a capable host).
    assert_eq!(
        record["coverage"].as_array().map(Vec::len),
        Some(0),
        "enforcement should arm cleanly on a capable host: {json}"
    );
    let network = &record["network"];
    // The allowed endpoint passed the tap → a flow to 10.200.0.1:9999/udp.
    let flows = network["flows"].as_array().expect("flows array");
    assert!(
        flows
            .iter()
            .any(|f| f["dst"] == "10.200.0.1" && f["dst_port"] == 9999 && f["proto"] == "udp"),
        "the allowed flow to 10.200.0.1:9999 should be recorded: {json}"
    );
    // The denied endpoint was dropped at the tap → a denial to 10.200.0.1:8888/udp.
    let denials = network["denials"].as_array().expect("denials array");
    let denial = denials
        .iter()
        .find(|d| d["dst"] == "10.200.0.1" && d["dst_port"] == 8888 && d["proto"] == "udp")
        .unwrap_or_else(|| panic!("the blocked port 8888 should be a denial: {json}"));
    assert!(
        denial["packets"].as_u64().is_some_and(|n| n >= 1),
        "the denial counts the dropped packet(s): {denial}"
    );
}

/// The absolute artifact paths, so every spawned `agent` finds the kernel/rootfs regardless of the
/// working directory (`--get` writes relative to the cwd, so the run itself uses a scratch cwd).
fn artifact_env() -> [(String, std::path::PathBuf); 2] {
    let root = workspace_root();
    [
        ("AGENT_KERNEL".to_string(), root.join("artifacts/vmlinux")),
        (
            "AGENT_ROOTFS".to_string(),
            root.join("artifacts/rootfs-agent.ext4"),
        ),
    ]
}

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn doctor_passes_then_one_run_drives_every_projection_at_once() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping doctor_passes_then_one_run_drives_every_projection_at_once: {why}");
        return;
    }
    let scratch = TestDir::new();
    let env = artifact_env();

    // 1) `agent doctor` on a capable host reports ready (exit 0): the gate an operator runs first.
    let doc = Command::new(env!("CARGO_BIN_EXE_agent"))
        .envs(env.iter().cloned())
        .arg("doctor")
        .output()
        .expect("run agent doctor");
    assert!(
        doc.status.success(),
        "agent doctor should report ready on the privileged host: {}",
        String::from_utf8_lossy(&doc.stdout)
    );
    assert!(String::from_utf8_lossy(&doc.stdout).contains("Ready"));

    // 2) One `agent run` exercising **every** projection at once: limits (--vcpus/--mem), the network
    //    + egress policy (--net/--allow), file injection + retrieval (--put/--get), piped stdin, and
    //    the structured result (--json). The workload folds stdin + the injected file into a returned
    //    artifact and sends UDP to the allowed endpoint.
    let injected = scratch.0.join("injected.txt");
    std::fs::write(&injected, b"INJECTED").expect("write the --put file");
    let workload = "\
import sys, socket
data = sys.stdin.read()
put = open('injected.txt').read()
open('result.txt', 'w').write(data + '|' + put)
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('10.200.0.1', 9999))
print('p14-9f-complete')
";
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent"))
        .current_dir(&scratch.0) // --get writes result.txt here
        .envs(env.iter().cloned())
        .args([
            "run",
            "--unjailed",
            "--vcpus",
            "2",
            "--mem",
            "512",
            "--net",
            "--allow",
            "10.200.0.1:9999/udp",
            "--json",
        ])
        .arg("--put")
        .arg(&injected)
        .args(["--get", "result.txt", "--", "python3", "-c", workload])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn agent run");
    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(b"STDIN")
        .expect("feed stdin");
    let out = child.wait_with_output().expect("await agent run");
    assert!(
        out.status.success(),
        "the everything-run failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    // The structured result: schema-versioned, the effective limits echoed back (limits projection),
    // and the guest's stdout captured (stdin projection reached the command).
    let result: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--json result parses");
    assert_eq!(result["schema"], 1, "the run result is schema-versioned");
    assert_eq!(result["limits"]["vcpus"], 2, "the --vcpus projection took");
    assert_eq!(
        result["limits"]["mem_mib"], 512,
        "the --mem projection took"
    );
    assert!(
        result["stdout"]
            .as_str()
            .is_some_and(|s| s.contains("p14-9f-complete")),
        "the guest ran: {result}"
    );

    // The retrieved artifact (--get) landed under the cwd and folds stdin + the injected file — so
    // --put, --get, and stdin all round-tripped through the one run.
    let got =
        std::fs::read_to_string(scratch.0.join("result.txt")).expect("--get wrote result.txt");
    assert_eq!(
        got, "STDIN|INJECTED",
        "stdin + --put round-tripped via --get"
    );
}
