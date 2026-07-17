//! The consolidated **trust-story** suite: one hostile guest run, contained on every axis, and the
//! containment **shown in the host-observed audit record** — plus the proof that the guest can
//! neither see nor disable the probes doing the observing.
//!
//! `#[ignore]`d: each boots a real microVM (needs `/dev/kvm` + the agent rootfs) and attaches all
//! three host-side probes (needs `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN` + kernel BTF + the built
//! object). Run via `cargo xtask ci-privileged`. Uses `agent-vmm` as a **dev-dependency only**, so
//! the loader library stays independent of the driver: the two tracks bridge by plain values.
//!
//! These fuse constituents that already pass individually — deny-by-default egress with an
//! allow-listed exception (`net_enforce.rs`), a fork storm that creates no host threads (hardware
//! isolation), and the faithful record (`audit_record.rs`) — into **one hostile guest**, and add the
//! part those pieces don't: the record is the evidence. Full VM/jail escape and the cgroup
//! cpu/mem/pid caps are proven under real root by the `agent-vmm` confinement suite (a mem-hog /
//! fork-bomb bounded by `memory.max`/`cpu.max`); this suite runs on the probe-capability path and
//! consolidates the *observed and recorded* dimensions of containment.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_probes_loader::{
    check_support, object_path, AxisGap, EgressPolicy, Protocol, SandboxProbes, SharedMeter,
    SharedTracer, Timing,
};
use agent_test_support::{have_real_root, process_threads, LimitCgroup};
use agent_vmm::{BootConfig, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};

/// IP protocol number for UDP, for the raw flow/denial-key comparisons the loader doesn't re-export
/// a const for.
const IPPROTO_UDP: u8 = Protocol::Udp as u8;
/// The one endpoint the hostile guest is permitted to reach on its host end — the allow-listed
/// exception. Every other destination is denied by the deny-by-default policy.
const ALLOWED_PORT: u16 = 9999;
/// A port the guest is **not** allowed to reach — the exfiltration attempt that must be dropped at
/// the tap and land in the record's denial trail.
const BLOCKED_PORT: u16 = 8888;

/// The workspace root, from this crate's manifest dir, so the artifact paths are cwd-independent.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Why this host can't run the suite (a skip reason), or `None` when it can — so it prints *why* it
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
/// cwd-independent). Read-only shared base + tmpfs overlay, vsock exec on, and a NIC. Unjailed on
/// purpose: the proof is the fused record + the tap enforcement, not the jailer, and the unjailed
/// path doesn't depend on the `/dev/kvm` jail-uid ACL.
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
fn a_hostile_guest_is_contained_and_the_record_shows_it() {
    // P15.1 — the consolidated adversarial suite as one hostile guest: it tries to **exfiltrate**
    // (reach a blocked endpoint) and to **DoS** the host (a fork storm), and every attempt is both
    // *contained* and *recorded*. Exfiltration is denied at the tap and the drop lands in the audit
    // record; the storm creates zero host threads (hardware isolation) and the VM stays responsive;
    // the record's coverage stays clean throughout, so the observation itself survived the attack.
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_hostile_guest_is_contained_and_the_record_shows_it: {why}");
        return;
    }

    // Load the two host-wide probes once (the shared model a real host uses at startup).
    let tracer = SharedTracer::load().expect("load the shared syscall tracer");
    let meter = SharedMeter::load().expect("load the shared CPU meter");

    let vm = Vm::boot(networked_agent_config()).expect("a networked agent microVM should boot");
    let host_ip = vm.host_ip().expect("a networked VM exposes its host end");
    let host_u32 = u32::from(host_ip);

    // Attach the full bundle to this sandbox **enforcing** a deny-by-default egress policy whose
    // single exception is host_ip:ALLOWED_PORT/udp. `attach` arms the policy before the tc programs
    // go live, so there is no un-enforced window for the guest's first packet.
    let egress =
        EgressPolicy::deny_all().allow_host(host_ip, Some(ALLOWED_PORT), Some(Protocol::Udp));
    let probes = SandboxProbes::attach(
        vm.vmm_pid(),
        vm.netns(),
        vm.tap_name(),
        Some(&egress),
        &tracer,
        &meter,
    );
    assert!(
        probes.coverage().is_empty(),
        "all axes should bind on a capable host; gaps: {:?}",
        probes.coverage()
    );

    // Attack 1 — exfiltrate. The guest sends UDP to its host end on both the one allowed port and a
    // blocked one. No listener is needed (the verdict is at the tap, before delivery); Python is in
    // the agent rootfs, so this is deterministic. The `for` body is 4-space-indented via a leading
    // `\x20` so Rust's `\`-continuation can't strip Python's indentation.
    let exfil = format!(
        "import socket, time\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         for _ in range(5):\n\
        \x20   s.sendto(b'allowed', ('{host_ip}', {ALLOWED_PORT}))\n\
        \x20   s.sendto(b'exfil', ('{host_ip}', {BLOCKED_PORT}))\n\
        \x20   time.sleep(0.02)\n\
         print('exfil-done')\n"
    );
    let out = vm
        .exec(&["python3".into(), "-c".into(), exfil], b"")
        .expect("run the guest exfiltration attempt");
    assert_eq!(
        out.exit_code,
        0,
        "the guest run must survive its own attack (contained, not crashed): {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Attack 2 — DoS via a fork storm. 50 spinning shells for 2 s: a bounded storm (not the
    // unbounded `:(){ :|:& };:`, which would starve the in-guest agent — a guest-availability
    // problem, while the host-facing claim is what this asserts). Hardware isolation means those 50
    // guest processes never become host threads.
    let threads_before = process_threads(vm.vmm_pid());
    let storm = [
        "sh",
        "-c",
        "i=0; while [ \"$i\" -lt 50 ]; do i=$((i+1)); while :; do :; done & done; sleep 2; echo storm-live",
    ]
    .map(String::from);
    let storm_out = vm.exec(&storm, b"").expect("run the guest fork storm");
    assert_eq!(storm_out.exit_code, 0, "the storm command should exit 0");
    assert!(
        storm_out.stdout.ends_with(b"storm-live\n"),
        "the storm should have run its course"
    );
    let threads_after = process_threads(vm.vmm_pid());
    assert_eq!(
        threads_after, threads_before,
        "guest forks must not create host threads (hardware isolation): {threads_before} -> {threads_after}"
    );

    std::thread::sleep(Duration::from_millis(100)); // let the last datagrams settle onto the tap

    // Finalize the fused record while the sandbox is still alive.
    let record = probes.collect(Timing {
        boot: vm.boot_latency(),
        exec_wall: out.metrics.wall,
    });
    let network = record
        .network
        .as_ref()
        .expect("a networked sandbox has a network section");

    // Exfiltration contained + recorded: the blocked endpoint is in the denial trail, dropped.
    let denial = network
        .denials
        .iter()
        .find(|d| d.dst_addr == host_u32 && d.dst_port == BLOCKED_PORT && d.proto == IPPROTO_UDP)
        .unwrap_or_else(|| {
            panic!(
                "the blocked exfil to {host_ip}:{BLOCKED_PORT} must be recorded as a denial: {:?}",
                network.denials
            )
        });
    assert!(
        denial.count >= 1,
        "the denial must carry a nonzero dropped-packet count, got {}",
        denial.count
    );

    // The allow-listed exception is recorded too: the permitted flow crossed the tap and was counted
    // (deny-by-default with one hole, both halves visible in the one record).
    let allowed = network.flows.iter().find(|f| {
        f.key.dst_addr == host_u32 && f.key.dst_port == ALLOWED_PORT && f.key.proto == IPPROTO_UDP
    });
    assert!(
        allowed.is_some_and(|f| f.counts.ingress_packets >= 1),
        "the allow-listed flow to {host_ip}:{ALLOWED_PORT} must be recorded: {:?}",
        network.flows
    );

    // The observation itself survived the attack: no axis gapped, and the VMM's host-syscall axis
    // stayed bound to this sandbox (its absence would mean a poisoned probe, not containment).
    assert!(
        record.coverage.is_empty(),
        "the record's coverage must stay clean through the attack; gaps: {:?}",
        record.coverage
    );
    assert!(
        !record
            .coverage
            .iter()
            .any(|g| matches!(g, AxisGap::HostSyscalls(_))),
        "the host-syscall axis should stay bound; coverage: {:?}",
        record.coverage
    );

    // The audit surface (the serialized record downstream consumers read) shows the denial.
    let json = record.to_json();
    assert!(
        json.contains(&format!("\"dst\":\"{host_ip}\"")) && json.contains("\"denials\":[{"),
        "the JSON audit surface should carry the recorded denial: {json}"
    );

    // The VM survived its own worst behaviour: still exec-responsive after the attack.
    let alive = vm
        .exec(&["echo".into(), "alive".into()], b"")
        .expect("post-attack exec should run");
    assert_eq!(alive.stdout, b"alive\n", "the contained VM stays usable");

    vm.shutdown().expect("shut the sandbox down");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn a_guest_cannot_see_or_disable_the_host_side_probes() {
    // P15.2 — the guest can neither see nor disable the host-side observation. It runs its **own**
    // kernel inside the microVM; the eBPF probes live in the **host** kernel, and the tap monitor
    // sits on the **host** end of the VM's tap, outside the guest. There is no in-guest syscall,
    // file, or device that reaches any of it. The proof is behavioural: a guest that spends its run
    // looking for the observability and then generating traffic is still fully recorded — because it
    // never had a handle on the probe to begin with.
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_guest_cannot_see_or_disable_the_host_side_probes: {why}");
        return;
    }

    let tracer = SharedTracer::load().expect("load the shared syscall tracer");
    let meter = SharedMeter::load().expect("load the shared CPU meter");

    let vm = Vm::boot(networked_agent_config()).expect("a networked agent microVM should boot");
    let host_ip = vm.host_ip().expect("a networked VM exposes its host end");
    let host_u32 = u32::from(host_ip);

    // Observe-only (no egress policy): the point is visibility of the probe, not enforcement.
    let probes = SandboxProbes::attach(
        vm.vmm_pid(),
        vm.netns(),
        vm.tap_name(),
        None,
        &tracer,
        &meter,
    );
    assert!(
        probes.coverage().is_empty(),
        "all axes should bind on a capable host; gaps: {:?}",
        probes.coverage()
    );

    // The guest looks for the host's eBPF (its own bpffs, if mounted at all, holds only what the
    // guest pinned — nothing; host BPF is in the host kernel, unreachable), reports what it found,
    // then sends identifiable traffic. The host tap must record that traffic regardless — proving
    // the guest could not blind it.
    let probe_hunt = format!(
        "import os, socket, time\n\
         try:\n\
        \x20   entries = os.listdir('/sys/fs/bpf')\n\
         except OSError:\n\
        \x20   entries = []\n\
         print('BPF_ENTRIES=%d' % len(entries))\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         for _ in range(10):\n\
        \x20   s.sendto(b'p15-2', ('{host_ip}', {ALLOWED_PORT}))\n\
        \x20   time.sleep(0.02)\n\
         print('SENT')\n"
    );
    let out = vm
        .exec(&["python3".into(), "-c".into(), probe_hunt], b"")
        .expect("run the guest probe-hunt workload");
    assert_eq!(
        out.exit_code,
        0,
        "the probe-hunt workload should complete: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The guest saw no host eBPF object: from inside the VM there is nothing to see.
    assert!(
        stdout.contains("BPF_ENTRIES=0"),
        "the guest must find no host BPF objects in its view: {stdout}"
    );

    std::thread::sleep(Duration::from_millis(100));

    let record = probes.collect(Timing {
        boot: vm.boot_latency(),
        exec_wall: out.metrics.wall,
    });

    // The host kept recording through the guest's probing: the guest's own packets are in the
    // record. It could not disable what it could not reach.
    let network = record
        .network
        .as_ref()
        .expect("a networked sandbox has a network section");
    let flow = network.flows.iter().find(|f| {
        f.key.dst_addr == host_u32 && f.key.dst_port == ALLOWED_PORT && f.key.proto == IPPROTO_UDP
    });
    assert!(
        flow.is_some_and(|f| f.counts.ingress_packets >= 1),
        "the host must still record the guest's flow after its probe-hunt: {:?}",
        network.flows
    );
    // No axis was knocked out — the observation survived intact, not silently thinned.
    assert!(
        record.coverage.is_empty(),
        "the guest must not have induced any coverage gap; gaps: {:?}",
        record.coverage
    );

    vm.shutdown().expect("shut the sandbox down");
}

#[test]
#[ignore = "needs /dev/kvm + real root + delegated cgroups + CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged` as root)"]
fn all_exhaustion_vectors_are_bounded_by_the_cgroup_and_egress_policy() {
    // P15.3 — one hostile guest attacks on every exhaustion axis at once, and the engine's two
    // enforcement mechanisms bound all of them: the **cgroup** caps compute + memory (a memory hog
    // stays under `memory.max` without the host OOM-killing the VMM; a fork storm burns no more than
    // its CPU quota and creates zero host threads), and the **egress policy** caps the network (a
    // packet flood to a blocked endpoint is dropped at the tap, at volume, and recorded). This is the
    // multi-tenant-safety centerpiece: a guest that does its worst on all fronts stays in its lane.
    if let Some(why) = skip_reason() {
        eprintln!(
            "skipping all_exhaustion_vectors_are_bounded_by_the_cgroup_and_egress_policy: {why}"
        );
        return;
    }
    if !have_real_root() {
        eprintln!("skipping all_exhaustion_vectors_are_bounded_by_the_cgroup_and_egress_policy: needs real root for the cgroup caps");
        return;
    }

    let tracer = SharedTracer::load().expect("load the shared syscall tracer");
    let meter = SharedMeter::load().expect("load the shared CPU meter");

    let cfg = networked_agent_config();
    let (vcpus, mem_mib) = (u32::from(cfg.vcpus.get()), cfg.mem_mib.get());
    let Some(cg) = LimitCgroup::create(vcpus, mem_mib, "hostile") else {
        eprintln!("skipping all_exhaustion_vectors_are_bounded_by_the_cgroup_and_egress_policy: cgroup v2 not writable/delegated");
        return;
    };
    let vm = Vm::boot(cfg).expect("a networked agent microVM should boot");
    let host_ip = vm.host_ip().expect("a networked VM exposes its host end");
    let host_u32 = u32::from(host_ip);

    // Cap first, then attach: the VMM enters the limited cgroup before the probes resolve its cgroup
    // id, so the meter/tracer target the same cgroup the caps bind (and the tap monitor, keyed on
    // netns+tap, is unaffected either way).
    cg.enter(vm.vmm_pid());
    let egress =
        EgressPolicy::deny_all().allow_host(host_ip, Some(ALLOWED_PORT), Some(Protocol::Udp));
    let probes = SandboxProbes::attach(
        vm.vmm_pid(),
        vm.netns(),
        vm.tap_name(),
        Some(&egress),
        &tracer,
        &meter,
    );
    assert!(
        probes.coverage().is_empty(),
        "all axes should bind on a capable host; gaps: {:?}",
        probes.coverage()
    );

    // Vector 1 — memory exhaustion. Touch pages (bytearray zero-fills), so every chunk is real guest
    // RAM the VMM must back with host memory, charged to the limited cgroup. The hog ends in the
    // guest's MemoryError or its own OOM killer — inside the hardware boundary — never the VMM's
    // death. One literal with explicit `\n`s + single-space block indents (a `\`-continuation would
    // strip Python's indentation).
    let hog = [
        "python3",
        "-c",
        "bufs = []\ntry:\n while True: bufs.append(bytearray(16 * 1024 * 1024))\nexcept MemoryError: pass\nprint('hog-done')",
    ]
    .map(String::from);
    let hog_out = vm
        .exec(&hog, b"")
        .expect("the mem-hog exec must complete (guest OOM, not VMM death)");
    assert_eq!(
        hog_out.exit_code, 0,
        "the mem-hog run stays contained, exit 0"
    );
    let peak: u64 = cg
        .read("memory.peak")
        .trim()
        .parse()
        .expect("parse memory.peak (kernel >= 5.19)");
    let max: u64 = cg
        .read("memory.max")
        .trim()
        .parse()
        .expect("parse memory.max");
    assert!(
        peak > 64 * 1024 * 1024,
        "the hog should have pushed real memory through the cgroup (peak {peak})"
    );
    assert!(
        peak <= max,
        "memory.peak {peak} must never pass memory.max {max}"
    );
    assert_eq!(
        cg.stat("memory.events", "oom_kill"),
        0,
        "the host cap must bound the VMM without OOM-killing it"
    );

    // Vector 2 — a fork storm. Hardware isolation means the guest's processes never become host
    // threads, and cpu.max means the whole VM can't burn more than its quota.
    let threads_before = process_threads(vm.vmm_pid());
    let usage_before = cg.stat("cpu.stat", "usage_usec");
    let storm_started = std::time::Instant::now();
    let storm = [
        "sh",
        "-c",
        "i=0; while [ \"$i\" -lt 50 ]; do i=$((i+1)); while :; do :; done & done; sleep 2; echo storm-live",
    ]
    .map(String::from);
    let storm_out = vm
        .exec(&storm, b"")
        .expect("the fork storm exec must complete");
    let storm_wall = storm_started.elapsed();
    assert_eq!(storm_out.exit_code, 0, "the storm command should exit 0");
    assert_eq!(
        process_threads(vm.vmm_pid()),
        threads_before,
        "guest forks must not create host threads (hardware isolation)"
    );
    let cpu_used = cg.stat("cpu.stat", "usage_usec") - usage_before;
    let cpu_cap = storm_wall.as_micros() as u64 * u64::from(vcpus) + 2_000_000;
    assert!(
        cpu_used <= cpu_cap,
        "host CPU burned ({cpu_used} usec) must stay within the cgroup quota ({cpu_cap} usec)"
    );

    // Vector 3 — a network flood. Blast packets at a blocked endpoint (and the one allowed one). The
    // egress policy drops the flood at the tap, at volume, and the drops are recorded.
    let flood = format!(
        "import socket\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         for _ in range(200):\n\
        \x20   s.sendto(b'flood', ('{host_ip}', {BLOCKED_PORT}))\n\
        \x20   s.sendto(b'ok', ('{host_ip}', {ALLOWED_PORT}))\n\
         print('flood-done')\n"
    );
    let flood_out = vm
        .exec(&["python3".into(), "-c".into(), flood], b"")
        .expect("run the guest network flood");
    assert_eq!(
        flood_out.exit_code, 0,
        "the flood run stays contained, exit 0"
    );

    std::thread::sleep(Duration::from_millis(100));
    let record = probes.collect(Timing {
        boot: vm.boot_latency(),
        exec_wall: hog_out.metrics.wall,
    });
    let network = record
        .network
        .as_ref()
        .expect("a networked sandbox has a network section");

    // The flood was bounded by the egress policy: many packets to the blocked endpoint, all dropped
    // and counted (a high denial count, not a trickle — enforcement held under volume).
    let denial = network
        .denials
        .iter()
        .find(|d| d.dst_addr == host_u32 && d.dst_port == BLOCKED_PORT && d.proto == IPPROTO_UDP)
        .unwrap_or_else(|| {
            panic!(
                "the flood to {host_ip}:{BLOCKED_PORT} must be recorded as denied: {:?}",
                network.denials
            )
        });
    assert!(
        denial.count >= 50,
        "the flood should have driven a high denial count, got {} (enforcement must hold under load)",
        denial.count
    );
    // The allow-listed endpoint still worked through the flood: enforcement is a scalpel, not a
    // sledgehammer that drops everything under pressure.
    assert!(
        network.flows.iter().any(|f| {
            f.key.dst_addr == host_u32
                && f.key.dst_port == ALLOWED_PORT
                && f.key.proto == IPPROTO_UDP
        }),
        "the allow-listed flow must survive the flood: {:?}",
        network.flows
    );

    // The VM survived every vector: still exec-responsive.
    let alive = vm
        .exec(&["echo".into(), "alive".into()], b"")
        .expect("post-exhaustion exec should run");
    assert_eq!(alive.stdout, b"alive\n", "the contained VM stays usable");

    vm.shutdown().expect("shut the sandbox down");
}
