//! End-to-end test: a workload that touches the network + a file yields a per-run audit record
//! that shows exactly what the host could observe of it.
//!
//! `#[ignore]`d: it boots a real microVM and attaches all three host-side probes, so it needs `/dev/kvm`,
//! the guest rootfs, `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN`, kernel BTF, and the built object. Run via
//! `cargo xtask ci-privileged`. Uses `bsx` as a **dev-dependency only**, so the loader library stays
//! independent of the driver and the two tracks bridge by plain values.
//!
//! The convergence proof, the microVM and the eBPF observability as **one system**. It drives the launch
//! sequence a caller drives: load the shared tracer and meter once, boot the sandbox, `attach` the bundle
//! by plain values, run the guest workload, then `collect` the fused [`RunRecord`] while the sandbox is
//! still alive and serialize it to deterministic JSON.
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

use std::time::Duration;

use bsx_engine::{BootConfig, Vm};
use bsx_probes_common::IPPROTO_UDP;
use bsx_probes_loader::{
    AttachParams, AxisGap, EgressPolicy, Nic, Protocol, RecordSubject, SandboxProbes, SharedMeter,
    SharedTracer, Timing,
};

mod common;

use common::{networked_agent_config, probe_and_vm_skip_reason};

/// The [`networked_agent_config`] boot without its NIC, for the no-NIC attach path, where the
/// record's network section must be absent rather than gapped.
fn nicless_agent_config() -> BootConfig {
    let mut cfg = networked_agent_config();
    cfg.enable_network = false;
    cfg
}

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON + BTF + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn a_nicless_run_omits_the_network_section_without_a_gap() {
    if let Some(why) = probe_and_vm_skip_reason() {
        eprintln!("skipping a_nicless_run_omits_the_network_section_without_a_gap: {why}");
        return;
    }

    let tracer = SharedTracer::load().expect("load the shared syscall tracer");
    let meter = SharedMeter::load().expect("load the shared CPU meter");

    let mut vm = Vm::boot(nicless_agent_config()).expect("a NIC-less agent microVM should boot");

    // The sealed posture: a bare `new`, no `Nic`. "No NIC" and "the network axis failed" are
    // different records, and this pins the first: section absent, coverage clean.
    let probes = SandboxProbes::attach(AttachParams::new(vm.vmm_pid()), &tracer, &meter);
    assert!(
        probes.coverage().is_empty(),
        "a NIC-less attach on a capable host gaps nothing: {:?}",
        probes.coverage()
    );

    let out = vm
        .exec(&["/bin/echo".into(), "quiet".into()], b"")
        .expect("exec in the NIC-less sandbox");
    assert_eq!(
        out.exit_code,
        0,
        "guest workload exited {}: {}",
        out.exit_code,
        String::from_utf8_lossy(&out.stderr)
    );

    let record = probes.collect(
        RecordSubject::new(vm.name().to_string(), 0),
        Timing::new(vm.boot_latency(), out.metrics.wall),
    );

    assert!(
        record.network.is_none(),
        "no NIC means the network section is absent, not empty or gapped"
    );
    assert!(
        record.coverage.is_empty(),
        "absence of a NIC is not a coverage gap, and the other axes bound: {:?}",
        record.coverage
    );

    vm.shutdown().expect("shut the sandbox down");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn a_networked_file_touching_run_yields_a_faithful_audit_record() {
    if let Some(why) = probe_and_vm_skip_reason() {
        eprintln!("skipping a_networked_file_touching_run_yields_a_faithful_audit_record: {why}");
        return;
    }

    // Load the two host-wide probes **once** (the shared model). A real host loads these at
    // startup and hands them to every sandbox; here one sandbox exercises the same path.
    let tracer = SharedTracer::load().expect("load the shared syscall tracer");
    let meter = SharedMeter::load().expect("load the shared CPU meter");

    // Boot a networked sandbox. Unjailed on purpose: the proof is the fused record and the tap flows,
    // not the jailer, and the unjailed path doesn't depend on the /dev/kvm jail-uid ACL.
    let mut vm = Vm::boot(networked_agent_config()).expect("a networked agent microVM should boot");
    let host_ip = vm.ipv4().expect("a networked VM exposes its host end").host;

    // Attach the bundle to *this* sandbox by the plain values the driver exposes, the exact
    // arm-free, single post-boot `attach` a caller will use. Observe-only (no egress policy).
    let mut params = AttachParams::new(vm.vmm_pid());
    params.nic = Some(Nic {
        netns: vm.netns().expect("a networked boot names its netns"),
        tap: vm.tap_name().expect("a networked boot names its tap"),
    });
    let probes = SandboxProbes::attach(params, &tracer, &meter);
    // Every axis we asked for must have bound, a networked sandbox on a capable host has no reason to
    // gap the network or host-syscall axis. (Absence here is the fail-open honesty working.)
    assert!(
        probes.coverage().is_empty(),
        "all axes should bind on a capable host; gaps: {:?}",
        probes.coverage()
    );

    // The workload: read a file *in-guest* (touches files) and send UDP to the host end (touches the
    // network). Python is in the guest rootfs, so this is deterministic where a busybox applet's
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
    let record = probes.collect(
        RecordSubject::new(vm.name().to_string(), 0),
        Timing::new(vm.boot_latency(), out.metrics.wall),
    );

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

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn an_ipv6_run_shows_its_flows_and_a_v6_denial_in_the_record() {
    // The dual-stack twin of the test above, and the load-time proof that the kernel
    // **verifier accepts** the v6 datapath (a compiled-and-linked object still has to load). Boots a
    // networked sandbox, attaches with a v6 egress policy allowing only the host end on udp/9999, then
    // sends UDP to two v6 ports on the on-link host: :9999 (allowed) and :8888 (denied). Both reach the
    // tap (the host end is the on-link neighbour, so ND resolves), so `flows6` records both and
    // `denials6` records the blocked port, the v6 audit trail folded into the record.
    if let Some(why) = probe_and_vm_skip_reason() {
        eprintln!("skipping an_ipv6_run_shows_its_flows_and_a_v6_denial_in_the_record: {why}");
        return;
    }

    let tracer = SharedTracer::load().expect("load the shared syscall tracer");
    let meter = SharedMeter::load().expect("load the shared CPU meter");
    let mut vm = Vm::boot(networked_agent_config()).expect("a networked agent microVM should boot");
    let host_ip6 = vm
        .ipv6()
        .expect("a networked VM exposes its v6 host end")
        .host;

    // Enforce a v6 policy: only host_ip6:9999/udp is allowed (ICMPv6 to the on-link host is spared
    // in-kernel, so the guest can still resolve the host end). Attaching with `Some(policy)` arms enforcement
    // before the tap goes live, the same no-un-enforced-window path the v4 tests use.
    let policy = EgressPolicy::deny_all().allow_host6(host_ip6, Some(9999), Some(Protocol::Udp));
    let mut params = AttachParams::new(vm.vmm_pid());
    params.nic = Some(Nic {
        netns: vm.netns().expect("a networked boot names its netns"),
        tap: vm.tap_name().expect("a networked boot names its tap"),
    });
    params.egress = Some(&policy);
    let probes = SandboxProbes::attach(params, &tracer, &meter);
    assert!(
        probes.coverage().is_empty(),
        "all axes should bind on a capable host (this also proves the v6 datapath loaded + verified); \
         gaps: {:?}",
        probes.coverage()
    );

    // Send UDP over v6 to the allowed port and a denied one, both to the on-link host end.
    let workload = format!(
        "import socket, time\n\
         s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)\n\
         for _ in range(5):\n    s.sendto(b'agent-v6', ('{host_ip6}', 9999)); time.sleep(0.02)\n\
         for _ in range(5):\n    \
             try:\n        s.sendto(b'agent-v6', ('{host_ip6}', 8888))\n    \
             except OSError:\n        pass\n    time.sleep(0.02)\n"
    );
    let out = vm
        .exec(&["python3".into(), "-c".into(), workload], b"")
        .expect("run the guest v6 workload");
    assert_eq!(
        out.exit_code,
        0,
        "guest v6 workload exited {}: {}",
        out.exit_code,
        String::from_utf8_lossy(&out.stderr)
    );
    std::thread::sleep(Duration::from_millis(100)); // let the last datagrams settle onto the tap

    let record = probes.collect(
        RecordSubject::new(vm.name().to_string(), 0),
        Timing::new(vm.boot_latency(), out.metrics.wall),
    );

    let network = record
        .network
        .as_ref()
        .expect("a networked sandbox has a network section");
    let octets = host_ip6.octets();
    // The allowed v6 flow is recorded on the tap (a flow is counted before the egress verdict, so the
    // denied port appears among flows6 too, only the *verdict* differs).
    assert!(
        network.flows6.iter().any(|f| f.key.dst_addr == octets
            && f.key.dst_port == 9999
            && f.key.proto == IPPROTO_UDP),
        "no allowed v6 UDP flow to [{host_ip6}]:9999 in the record: {:?}",
        network.flows6
    );
    // The blocked port is in the v6 denial trail.
    assert!(
        network
            .denials6
            .iter()
            .any(|d| d.dst_addr == octets && d.dst_port == 8888),
        "the blocked v6 endpoint [{host_ip6}]:8888 should be in denials6: {:?}",
        network.denials6
    );
    // And the allow-listed port must never be denied: the flow assert above counts pre-verdict and
    // UDP gives the sender no failure signal, so without this a deny-all v6 matcher passes too
    // (the v4 twin of this pin lives in net_enforce.rs).
    assert!(
        !network
            .denials6
            .iter()
            .any(|d| d.dst_addr == octets && d.dst_port == 9999),
        "the allowed v6 endpoint [{host_ip6}]:9999 must not appear in denials6: {:?}",
        network.denials6
    );

    // The deterministic JSON surface shows the v6 flow.
    let json = record.to_json();
    assert!(
        json.contains(&format!("\"dst\":\"{host_ip6}\"")),
        "the JSON audit surface should show the guest's v6 flow: {json}"
    );

    vm.shutdown().expect("shut the sandbox down");
}
