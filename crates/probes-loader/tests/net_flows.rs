//! End-to-end test: traffic from a guest shows up in the per-VM flow counters.
//!
//! `#[ignore]`d: it boots a real microVM (needs `/dev/kvm` + the agent rootfs) and attaches a `tc`
//! program inside the VM's netns (needs `CAP_BPF`+`CAP_NET_ADMIN` + BTF + the built object). Run via
//! `cargo xtask ci-privileged`. Uses `agent-vmm` as a **dev-dependency only**, so the loader library
//! stays independent of the driver: the two tracks bridge by plain values (a netns name and a tap name).
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_probes_loader::{check_support, object_path, TapMonitor};
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
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_NET_ADMIN + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn guest_traffic_shows_up_in_the_per_vm_counters() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping guest_traffic_shows_up_in_the_per_vm_counters: {why}");
        return;
    }

    // Boot a networked sandbox. Unjailed on purpose: the proof is about the tap counters, not the
    // jailer, and the unjailed path doesn't depend on the /dev/kvm jail-uid ACL.
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

    // Bind the monitor to *this* sandbox's tap, inside its own netns.
    let monitor =
        TapMonitor::attach_in_netns(&netns, &tap).expect("attach the tap monitor in the VM netns");

    // Drive traffic *from the guest*: a few UDP datagrams at the host end of the /30. No listener is
    // needed (the packets still cross the tap on the way out), and Python is in the agent rootfs, so
    // this is deterministic where a busybox `ping` applet's raw-socket permissions might not be.
    let sender = format!(
        "import socket, time\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         for _ in range(5):\n    s.sendto(b'agent-p10', ('{host_ip}', 9999)); time.sleep(0.02)\n"
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

    // The guest's packets show up in the per-flow counters, on the flow to the host end.
    let flows = monitor.flows().expect("read the flow map");
    let host_u32 = u32::from(host_ip);
    let (key, counts) = match flows
        .iter()
        .find(|(k, _)| k.dst_addr == host_u32 && k.dst_port == 9999 && k.proto == IPPROTO_UDP)
    {
        Some(flow) => flow,
        None => panic!("no UDP flow to {host_ip}:9999 among the captured flows: {flows:?}"),
    };
    assert!(
        counts.ingress_packets >= 1,
        "the guest's UDP packets must be counted on the tap's ingress; got {counts:?} for `{key}`"
    );

    // The per-VM rollup reflects it too.
    let totals = monitor.totals().expect("read the per-VM totals");
    assert!(
        totals.ingress_packets >= 1,
        "the per-VM ingress total must include the guest's traffic; got {totals:?}"
    );

    // Close cleanly. Dropping the monitor frees its userspace handles; the VM shutdown tears the
    // netns down, which reclaims the tc filter (ADR 023), leaving no dangling host state.
    drop(monitor);
    vm.shutdown().expect("shut the sandbox down");
}
