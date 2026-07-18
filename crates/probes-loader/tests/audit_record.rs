//! End-to-end test: a workload that touches the network + a file yields a per-run audit record
//! that shows exactly what the host could observe of it.
//!
//! `#[ignore]`d: it boots a real microVM (needs `/dev/kvm` + the agent rootfs) and attaches all three
//! host-side probes (needs `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN` + kernel BTF + the built object). Run
//! via `cargo xtask ci-privileged`. Uses `agent-vmm` as a **dev-dependency only**, so the loader library
//! stays independent of the driver: the two tracks bridge by plain values (a VMM pid, a netns, a tap).
//!
//! This is the convergence proof, the microVM and the eBPF observability as **one system**. It drives
//! the exact launch sequence a caller (the CLI/daemon, later) will: load the shared tracer + meter once,
//! boot the sandbox, `attach` the bundle to it by plain values, run the guest workload, then `collect`
//! the fused [`RunRecord`] while the sandbox is still alive and serialize it to deterministic JSON.
//!
//! **What the host can and can't see, by design.** The guest's outbound packets cross the tap on the
//! host, so the **network** touch shows up *exactly* in the record's flows, the strong cross-boundary
//! signal. The guest's **file** read happens in-guest and does *not* trap to the host's
//! syscall tracepoints (a microVM services its own syscalls): that is the isolation
//! working, not a gap. The record's host-syscall axis is the **VMM's** host footprint, and the test
//! asserts that axis *bound* to this sandbox (no coverage gap) rather than asserting in-guest activity it
//! is architecturally blind to. Network exactness + every axis bound + a serializable record is the
//! audit trail the exit gate calls for.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_probes_loader::{
    check_support, object_path, AxisGap, SandboxProbes, SharedMeter, SharedTracer, Timing,
};
use agent_vmm::{BootConfig, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};

/// IP protocol number for UDP (the loader re-exports the flow types but not this constant).
const IPPROTO_UDP: u8 = 17;

/// The workspace root, from this crate's manifest dir, so the artifact paths are cwd-independent.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Why this host can't run the test (a skip reason), or `None` when it can, so it prints *why* it
/// skipped, like the other probe tests.
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

/// A networked agent-rootfs boot config pointed at the workspace artifacts (absolute paths, so it's
/// cwd-independent). Read-only shared base + tmpfs overlay, vsock exec on, and a NIC.
fn networked_agent_config() -> BootConfig {
    let root = workspace_root();
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    cfg.rootfs = root.join("artifacts/rootfs-agent.ext4");
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.read_only_root = true;
    cfg.enable_network = true;
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn a_networked_file_touching_run_yields_a_faithful_audit_record() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_networked_file_touching_run_yields_a_faithful_audit_record: {why}");
        return;
    }

    // Load the two host-wide probes **once** (the shared model). A real host loads these at
    // startup and hands them to every sandbox; here one sandbox exercises the same path.
    let tracer = SharedTracer::load().expect("load the shared syscall tracer");
    let meter = SharedMeter::load().expect("load the shared CPU meter");

    // Boot a networked sandbox. Unjailed on purpose: the proof is the fused record and the tap flows,
    // not the jailer, and the unjailed path doesn't depend on the /dev/kvm jail-uid ACL.
    let vm = Vm::boot(networked_agent_config()).expect("a networked agent microVM should boot");
    let host_ip = vm.host_ip().expect("a networked VM exposes its host end");

    // Attach the bundle to *this* sandbox by the plain values the driver exposes, the exact
    // arm-free, single post-boot `attach` a caller will use. Observe-only (no egress policy).
    let probes = SandboxProbes::attach(
        vm.vmm_pid(),
        vm.netns(),
        vm.tap_name(),
        None,
        &tracer,
        &meter,
    );
    // Every axis we asked for must have bound, a networked sandbox on a capable host has no reason to
    // gap the network or host-syscall axis. (Absence here is the fail-open honesty working.)
    assert!(
        probes.coverage().is_empty(),
        "all axes should bind on a capable host; gaps: {:?}",
        probes.coverage()
    );

    // The workload: read a file *in-guest* (touches files) and send UDP to the host end (touches the
    // network). Python is in the agent rootfs, so this is deterministic where a busybox applet's
    // raw-socket permissions might not be. No listener is needed, the datagrams still cross the tap.
    let workload = format!(
        "import socket, time\n\
         open('/etc/hostname').read()\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         for _ in range(5):\n    s.sendto(b'agent-p13', ('{host_ip}', 9999)); time.sleep(0.02)\n"
    );
    let out = vm
        .exec(&["python3".into(), "-c".into(), workload], b"")
        .expect("run the guest workload");
    assert_eq!(
        out.exit_code,
        0,
        "guest workload exited {}: {}",
        out.exit_code,
        String::from_utf8_lossy(&out.stderr)
    );
    std::thread::sleep(Duration::from_millis(100)); // let the last datagrams settle onto the tap

    // Finalize the record while the sandbox is still alive: reads all three probes, detaches
    // this run's cgroup from the shared tracer + meter, and returns the fused record.
    let record = probes.collect(Timing {
        boot: vm.boot_latency(),
        exec_wall: out.metrics.wall,
    });

    // --- The network touch shows up *exactly* --------------------------------------------------------
    let network = record
        .network
        .as_ref()
        .expect("a networked sandbox has a network section");
    let host_u32 = u32::from(host_ip);
    let flow = network
        .flows
        .iter()
        .find(|f| {
            f.key.dst_addr == host_u32 && f.key.dst_port == 9999 && f.key.proto == IPPROTO_UDP
        })
        .unwrap_or_else(|| {
            panic!(
                "no UDP flow to {host_ip}:9999 in the record: {:?}",
                network.flows
            )
        });
    assert!(
        flow.counts.ingress_packets >= 1,
        "the guest's UDP packets must be counted on the tap ingress; got {:?}",
        flow.counts
    );
    assert!(
        network.totals.ingress_packets >= 1,
        "the per-VM rollup must include the guest's traffic; got {:?}",
        network.totals
    );

    // --- Every axis bound, and the record is honest about coverage -----------------------------------
    // No axis gap survived to the record (the network + host-syscall + CPU axes all attached). The
    // guest's in-guest file read is *not* a host syscall, its absence from `host_syscalls`
    // is the isolation working, so we assert the axis *bound*, not that guest file ops appear.
    assert!(
        !record
            .coverage
            .iter()
            .any(|g| matches!(g, AxisGap::HostSyscalls(_))),
        "the host-syscall axis should have bound to this sandbox; coverage: {:?}",
        record.coverage
    );
    assert!(
        record.timing.boot > Duration::ZERO,
        "the record carries the host-measured boot latency"
    );

    // --- The record serializes to deterministic JSON, showing the flow -------------------------------
    // (Byte-stability across shuffled inputs is pinned by the host-safe unit tests,
    // `json_is_byte_stable_across_input_order`, so it isn't re-proven here.)
    let json = record.to_json();
    assert!(
        json.contains(&format!("\"dst\":\"{host_ip}\"")) && json.contains("\"proto\":\"udp\""),
        "the JSON audit surface should show the guest's flow: {json}"
    );

    vm.shutdown().expect("shut the sandbox down");
}
