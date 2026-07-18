//! End-to-end test: a guest reaches an allow-listed endpoint and is blocked from everything else.
//!
//! `#[ignore]`d: it boots a real microVM (needs `/dev/kvm` + the agent rootfs) and attaches an enforcing
//! `tc` program inside the VM's netns (needs `CAP_BPF`+`CAP_NET_ADMIN` + BTF + the built object). Run via
//! `cargo xtask ci-privileged`. Uses `agent-vmm` as a **dev-dependency only**, so the loader library
//! stays independent of the driver: the two tracks bridge by plain values (a netns name and a tap name).
//!
//! The proof is at the enforcement point (the tap): the guest sends UDP to two ports of its host end, one
//! allow-listed and one not. The blocked port shows up in the `DENIALS` audit trail (dropped); the
//! allowed port does not (accepted). Deny-by-default with a single-endpoint allow-list, the guest can
//! reach exactly what the policy admits and nothing more.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_probes_loader::{check_support, object_path, EgressPolicy, Protocol, TapMonitor};
use agent_vmm::{BootConfig, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};

/// IP protocol number for UDP, for the raw flow-key comparisons the loader doesn't re-export a const for.
const IPPROTO_UDP: u8 = Protocol::Udp as u8;
/// The one port the guest is allowed to reach on its host end; every other port is denied.
const ALLOWED_PORT: u16 = 9999;
/// A port the guest is *not* allowed to reach, the "blocked from everything else" half.
const BLOCKED_PORT: u16 = 8888;

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
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn a_guest_reaches_the_allow_listed_endpoint_and_is_blocked_from_the_rest() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping a_guest_reaches_the_allow_listed_endpoint_and_is_blocked_from_the_rest: {why}");
        return;
    }

    // Boot a networked sandbox. Unjailed on purpose: the proof is about the tap enforcement, not
    // the jailer, and the unjailed path doesn't depend on the /dev/kvm jail-uid ACL.
    let vm = Vm::boot(networked_agent_config()).expect("a networked agent microVM should boot");
    let netns = vm
        .netns()
        .expect("a networked VM exposes its netns")
        .to_string();
    let tap = vm
        .tap_name()
        .expect("a networked VM exposes its tap")
        .to_string();
    let host_ip = vm.host_ip().expect("a networked VM exposes its host end");

    // Launch enforcement with a single-endpoint allow-list, only host_ip:ALLOWED_PORT/udp.
    // `enforce_in_netns` arms the policy before the tc programs go live, so there is no un-enforced window.
    let policy =
        EgressPolicy::deny_all().allow_host(host_ip, Some(ALLOWED_PORT), Some(Protocol::Udp));
    let monitor = TapMonitor::enforce_in_netns(&netns, &tap, &policy)
        .expect("attach + enforce the egress policy in the VM netns");

    // The guest sends UDP to both ports of its host end: the allowed one and the blocked one. No listener
    // is needed (the enforcement verdict is at the tap, before delivery), and Python is in the agent rootfs.
    let sender = format!(
        "import socket, time\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         for _ in range(5):\n\
        \x20   s.sendto(b'allowed', ('{host_ip}', {ALLOWED_PORT}))\n\
        \x20   s.sendto(b'blocked', ('{host_ip}', {BLOCKED_PORT}))\n\
        \x20   time.sleep(0.02)\n"
    );
    let out = vm
        .exec(&["python3".into(), "-c".into(), sender], b"")
        .expect("run the guest UDP sender");
    assert_eq!(
        out.exit_code,
        0,
        "guest sender exited {}: {}",
        out.exit_code,
        String::from_utf8_lossy(&out.stderr)
    );
    std::thread::sleep(Duration::from_millis(100));

    let host_u32 = u32::from(host_ip);
    let denials = monitor.denials().expect("read the denials map");

    // "Blocked from everything else": the disallowed port is in the audit trail, dropped at the tap.
    let blocked = denials.iter().find(|(k, _)| {
        k.dst_addr == host_u32 && k.dst_port == BLOCKED_PORT && k.proto == IPPROTO_UDP
    });
    match blocked {
        Some((_, count)) => assert!(
            *count >= 1,
            "the blocked port must have a nonzero denial count, got {count}"
        ),
        None => panic!(
            "the blocked UDP flow to {host_ip}:{BLOCKED_PORT} is missing from denials: {denials:?}"
        ),
    }

    // "Reaches the allow-listed endpoint": the allowed port was accepted, so it is NOT in the denials.
    assert!(
        !denials
            .iter()
            .any(|(k, _)| k.dst_addr == host_u32 && k.dst_port == ALLOWED_PORT),
        "the allow-listed port {ALLOWED_PORT} must never be denied, but it appears in {denials:?}"
    );

    // Both were seen on the tap (counting runs before the verdict), so the allowed one really was sent and
    // let through rather than never generated, the flow counters corroborate the enforcement.
    let flows = monitor.flows().expect("read the flow map");
    assert!(
        flows.iter().any(|(k, c)| k.dst_addr == host_u32
            && k.dst_port == ALLOWED_PORT
            && c.ingress_packets >= 1),
        "the allowed flow to {host_ip}:{ALLOWED_PORT} should show in the flow counters: {flows:?}"
    );

    drop(monitor);
    vm.shutdown().expect("shut the sandbox down");
}
