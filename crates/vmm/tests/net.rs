//! Privileged integration tests for guest networking: the deny-by-default tap, host↔guest
//! addressing/reachability, per-VM isolation, and allowed-vs-blocked endpoints.
//!
//! `#[ignore]`d because they need `/dev/kvm` + `CAP_NET_ADMIN` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use agent_vmm::Vm;

use common::{agent_rootfs_config, have_net_admin};

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn attaches_a_tap_and_the_guest_sees_a_deny_by_default_nic() {
    // P4.1: with `enable_network`, the driver creates a host tap and attaches it as virtio-net, so
    // the guest gets an `eth0` carrying the driver's locally-administered MAC. This test pins the NIC
    // + MAC and the deny-by-default invariant (no default route); guest addressing itself is P4.2's
    // `addresses_the_guest_and_routes_host_to_guest`. Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");

    // The driver exposes the tap name as the eBPF-binding handle (P4.6): it must be a real,
    // `fc`-prefixed host interface the Phase-8 loader can resolve and attach `tc`/XDP to.
    let tap = vm
        .tap_name()
        .expect("a networked VM should expose its tap name");
    assert!(
        tap.starts_with("fc"),
        "tap name should be fc-prefixed; got {tap:?}"
    );
    let present = std::process::Command::new("ip")
        .args(["link", "show", "dev", tap])
        .output()
        .expect("run ip link show");
    assert!(
        present.status.success(),
        "the exposed tap name {tap} should be a live host interface"
    );

    // The NIC is present with our LAA MAC (first octet 0x02 = locally administered + unicast); the
    // guest kernel exposes it at `/sys/class/net/eth0/address` regardless of link state.
    let mac = vm
        .exec(&["cat".into(), "/sys/class/net/eth0/address".into()], b"")
        .expect("read the guest NIC address");
    assert_eq!(
        mac.exit_code,
        0,
        "eth0 should exist; console:\n{}",
        vm.console()
    );
    assert!(
        String::from_utf8_lossy(&mac.stdout)
            .trim()
            .starts_with("02:"),
        "guest eth0 should carry the driver's locally-administered MAC; got {:?}",
        String::from_utf8_lossy(&mac.stdout)
    );

    // Deny-by-default: the guest has no default route (P4.2 adds a connected /30, never a route to
    // the world) — `ip route` lists no `default`.
    let routes = vm
        .exec(&["ip".into(), "route".into()], b"")
        .expect("list guest routes");
    assert!(
        !String::from_utf8_lossy(&routes.stdout).contains("default"),
        "deny-by-default: guest must have no default route; got {:?}",
        String::from_utf8_lossy(&routes.stdout)
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn addresses_the_guest_and_routes_host_to_guest() {
    // P4.2: static addressing over the tap. The kernel configures `eth0` with the guest's /30 IP via
    // the `ip=` boot param, giving a connected route to the host end and NO default route — so
    // host<->guest works but the guest reaches nothing else (deny-by-default). Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");
    let host_ip = vm.host_ip().expect("host ip when networked").to_string();
    let guest_ip = vm.guest_ip().expect("guest ip when networked").to_string();

    // The guest kernel configured eth0 with its assigned address.
    let addr = vm
        .exec(
            &[
                "ip".into(),
                "-4".into(),
                "addr".into(),
                "show".into(),
                "eth0".into(),
            ],
            b"",
        )
        .expect("show guest eth0");
    assert!(
        String::from_utf8_lossy(&addr.stdout).contains(&guest_ip),
        "guest eth0 should carry {guest_ip}; got:\n{}\nconsole:\n{}",
        String::from_utf8_lossy(&addr.stdout),
        vm.console()
    );

    // Host<->guest reachability: the guest can reach the host end of the point-to-point /30.
    let ping = vm
        .exec(
            &[
                "ping".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                "1".into(),
                host_ip.clone(),
            ],
            b"",
        )
        .expect("ping the host tap IP");
    assert_eq!(
        ping.exit_code,
        0,
        "guest should reach the host tap IP {host_ip}; console:\n{}",
        vm.console()
    );

    // Deny-by-default: an off-subnet address is unreachable (a fast ENETUNREACH, no route — not a
    // timeout), proving there's no default route or masquerade opening the guest to the world.
    let off = vm
        .exec(
            &[
                "ping".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                "1".into(),
                "192.0.2.1".into(), // RFC 5737 TEST-NET-1, provably off the /30
            ],
            b"",
        )
        .expect("ping an off-subnet address");
    assert_ne!(
        off.exit_code, 0,
        "deny-by-default: the guest must not reach an off-subnet address"
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn two_vms_cannot_reach_each_others_tap() {
    // P4.4: per-VM isolation. Two concurrently-booted networked VMs get distinct /30s — the driver
    // makes each host-address assignment the /30's atomic reservation, so a folded-index collision
    // retries instead of sharing a subnet — and with no default route a guest can only address its
    // own connected /30. So VM-A cannot even reach VM-B's tap. Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg_a = agent_rootfs_config();
    cfg_a.enable_network = true;
    let vm_a = Vm::boot(cfg_a).expect("VM A with a NIC should boot to readiness");
    let mut cfg_b = agent_rootfs_config();
    cfg_b.enable_network = true;
    let vm_b = Vm::boot(cfg_b).expect("VM B with a NIC should boot to readiness");

    let a_host = vm_a.host_ip().expect("A host ip when networked");
    let a_guest = vm_a.guest_ip().expect("A guest ip when networked");
    let b_host = vm_b.host_ip().expect("B host ip when networked");
    let b_guest = vm_b.guest_ip().expect("B guest ip when networked");

    // The allocator handed the two VMs disjoint /30s: no shared subnet to bridge them.
    assert_ne!(
        a_host, b_host,
        "the two VMs must get distinct host /30 ends"
    );
    assert_ne!(
        a_guest, b_guest,
        "the two VMs must get distinct guest addresses"
    );

    // From A, B's addresses are off A's only (connected) route: a fast ENETUNREACH, not a timeout —
    // the same deny-by-default lever that blocks the world also isolates one VM from another.
    for target in [b_host.to_string(), b_guest.to_string()] {
        let out = vm_a
            .exec(
                &[
                    "ping".into(),
                    "-c".into(),
                    "1".into(),
                    "-W".into(),
                    "1".into(),
                    target.clone(),
                ],
                b"",
            )
            .expect("ping VM B from VM A");
        assert_ne!(
            out.exit_code,
            0,
            "VM A must not reach VM B's address {target}; console:\n{}",
            vm_a.console()
        );
    }

    vm_a.shutdown().expect("shutdown A should succeed");
    vm_b.shutdown().expect("shutdown B should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn guest_reaches_an_allowed_host_endpoint_but_not_a_blocked_one() {
    // P4.7: prove the allow/deny posture at the transport layer, not just ICMP. Per decision 008,
    // "allowed" in Phase 4 is host-local (world-egress allow-listing is eBPF-enforced in P8): the
    // guest completes a real TCP connection to a listener bound on the host tap IP, and cannot reach
    // an off-subnet endpoint (no route, fast failure). Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");
    let host_ip = vm.host_ip().expect("host ip when networked");

    // A genuine host-side endpoint on the tap's host address. `bind` already starts listening, and the
    // kernel queues the connection in the backlog, so the guest's connect completes even before the
    // acceptor thread runs — no bind/connect race. Port 0 picks a free ephemeral port.
    let listener =
        std::net::TcpListener::bind((host_ip, 0)).expect("bind a host endpoint on the tap IP");
    let port = listener.local_addr().expect("listener local addr").port();
    let acceptor = std::thread::spawn(move || {
        // One accepted connection is enough to prove reachability; drop it and finish.
        let _ = listener.accept();
    });

    // Allowed: the guest's TCP connect to the host endpoint succeeds (python3 exits 0; an unreachable
    // peer would raise and exit non-zero). python3 is in the agent rootfs (see execs_python_*).
    let allowed = vm
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!(
                    "import socket; s=socket.socket(); s.settimeout(3); s.connect(('{host_ip}',{port}))"
                ),
            ],
            b"",
        )
        .expect("guest connects to the allowed host endpoint");
    assert_eq!(
        allowed.exit_code,
        0,
        "guest should reach the allowed host endpoint {host_ip}:{port}; console:\n{}",
        vm.console()
    );

    // Blocked: an off-subnet endpoint has no route, so connect fails (raises, exits non-zero). RFC 5737
    // TEST-NET-1 is provably off the /30. The same port keeps the two probes symmetric.
    let blocked = vm
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!(
                    "import socket; s=socket.socket(); s.settimeout(3); s.connect(('192.0.2.1',{port}))"
                ),
            ],
            b"",
        )
        .expect("guest attempts a blocked endpoint");
    assert_ne!(
        blocked.exit_code, 0,
        "deny-by-default: the guest must not reach an off-subnet endpoint"
    );

    vm.shutdown().expect("shutdown should succeed");
    let _ = acceptor.join();
}
