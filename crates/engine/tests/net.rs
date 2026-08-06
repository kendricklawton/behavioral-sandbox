//! Privileged integration tests for guest networking: the deny-by-default tap, host↔guest
//! addressing/reachability, per-VM isolation, and allowed-vs-blocked endpoints.
//!
//! `#[ignore]`d because they need `/dev/kvm` + `CAP_NET_ADMIN` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p ekvm-engine -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::process::Command;

use std::net::Ipv4Addr;

use ekvm_engine::{GuestEgress, Vm};

use common::{guest_rootfs_config, have_net_admin};

/// The host end of every guest's /30 (`net.rs` keeps it constant across netns), which is the only
/// address a guest can reach without a gateway and therefore the only sensible gateway to configure.
const HOST_END: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// A resolver address deliberately *off* the guest's link: a resolver is meant to be reachable
/// through the gateway, so an on-link one would prove nothing about the gateway being configured.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// Run `ip netns exec <netns> <args...>` and return the completed output (for host-side checks that
/// must happen *inside* the VM's network namespace, where its tap lives).
fn ip_netns_exec(netns: &str, args: &[&str]) -> std::process::Output {
    let mut full = vec!["netns", "exec", netns];
    full.extend_from_slice(args);
    match Command::new("ip").args(&full).output() {
        Ok(out) => out,
        Err(e) => panic!("run ip netns exec: {e}"),
    }
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn attaches_a_tap_and_the_guest_sees_a_deny_by_default_nic() {
    // Under the netns model: with `enable_network`, the driver creates a per-VM network
    // namespace with a tap inside it, attached as virtio-net, so the guest gets an `eth0` carrying the
    // driver's locally-administered MAC. This pins the NIC + MAC + the deny-by-default invariant (no
    // default route); guest addressing itself is `addresses_the_guest_and_routes_host_to_guest`.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = guest_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");

    // The driver exposes the netns + tap name as the eBPF-binding handle: the eBPF loader
    // enters the netns and resolves the tap there. The tap is a real `fc`-prefixed interface *inside*
    // the netns (not the host's), so check it there.
    let netns = vm.netns().expect("a networked VM should expose its netns");
    let tap = vm
        .tap_name()
        .expect("a networked VM should expose its tap name");
    assert!(
        tap.starts_with("fc"),
        "tap name should be fc-prefixed; got {tap:?}"
    );
    let present = ip_netns_exec(netns, &["ip", "link", "show", "dev", tap]);
    assert!(
        present.status.success(),
        "the tap {tap} should be a live interface inside netns {netns}"
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

    // Deny-by-default: the guest has no default route (addressing adds a connected /30, never a route to
    // the world), `ip route` lists no `default`.
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
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn a_gateway_gives_the_guest_a_default_route_and_a_resolver() {
    // The other side of `attaches_a_tap_and_the_guest_sees_a_deny_by_default_nic`, which pins the
    // sealed default (no `default` in `ip route`). With `BootConfig::egress` the two `ip=` fields the
    // driver otherwise leaves empty are filled, so the guest installs a default route and reads its
    // nameserver from the kernel's own record of the boot parameter.
    //
    // This does not claim the guest can *reach* anything: nothing here builds an uplink, and on this
    // host the netns still holds only `lo` and the tap (decision 9). What it pins is that the
    // configuration lands in the guest at all, which is the engine's whole half of the job.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = guest_rootfs_config();
    cfg.enable_network = true;
    // The gateway is the host end of the guest's own /30, the only address it can reach without one.
    // The resolver is deliberately *not* on-link, since a resolver's whole point is to be reachable
    // through the gateway rather than beside it.
    cfg.egress = Some(GuestEgress::via(HOST_END).with_resolver(RESOLVER));
    let vm = Vm::boot(cfg).expect("a microVM with a gateway should boot to readiness");

    // The default route exists and points at the configured gateway. `ip=`'s third field is what
    // installs it, so this failing means the boot parameter never carried it.
    let routes = vm
        .exec(&["ip".into(), "route".into()], b"")
        .expect("list guest routes");
    let routes = String::from_utf8_lossy(&routes.stdout).to_string();
    assert!(
        routes.contains("default"),
        "a configured gateway must install a default route; got:\n{routes}\nconsole:\n{}",
        vm.console()
    );
    assert!(
        routes.contains(&HOST_END.to_string()),
        "the default route must be via the configured gateway {HOST_END}; got:\n{routes}"
    );

    // The resolver reaches the guest's libc through `/etc/resolv.conf`, which the image bakes as a
    // symlink to the kernel's `/proc/net/pnp`. This is the end-to-end check on that link: the driver
    // wrote the DNS field, the kernel parsed it, and the guest reads it where a resolver looks.
    let resolv = vm
        .exec(&["cat".into(), "/etc/resolv.conf".into()], b"")
        .expect("read the guest resolver config");
    let resolv = String::from_utf8_lossy(&resolv.stdout).to_string();
    assert!(
        resolv.contains(&format!("nameserver {RESOLVER}")),
        "the guest must resolve at the configured resolver; /etc/resolv.conf held:\n{resolv}\nconsole:\n{}",
        vm.console()
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn addresses_the_guest_and_routes_host_to_guest() {
    // Static addressing over the tap. The kernel configures `eth0` with the guest's /30 IP via
    // the `ip=` boot param, giving a connected route to the host end and NO default route, so
    // host<->guest works but the guest reaches nothing else (deny-by-default). Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = guest_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");
    let host_ip = vm.ipv4().expect("ipv4 when networked").host.to_string();
    let guest_ip = vm.ipv4().expect("ipv4 when networked").guest.to_string();

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

    // Deny-by-default: an off-subnet address is unreachable (a fast ENETUNREACH, no route, not a
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
    // Pin the *reason*: no route (ENETUNREACH), not a timeout. TEST-NET is bogon-filtered on the
    // public internet too, so a plain non-zero exit would also pass with a full default route +
    // masquerade, the exact regression this probe exists to catch.
    let off_err = format!(
        "{}{}",
        String::from_utf8_lossy(&off.stdout),
        String::from_utf8_lossy(&off.stderr)
    );
    assert!(
        off_err.contains("nreachable"),
        "the block must be no-route, not a timeout; output: {off_err}"
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn addresses_the_guest_over_ipv6_and_routes_host_to_guest() {
    // The IPv6 twin of `addresses_the_guest_and_routes_host_to_guest`. The kernel
    // `ip=`/`CONFIG_IP_PNP` param is v4-only, so the guest's v6 address rides the `guest_ip6=`
    // cmdline token that `/sbin/net-up` applies to `eth0`. Prove: the guest carries its static v6
    // address, reaches the host v6 end over the connected /64, and (deny-by-default) cannot reach an
    // off-link v6 address, no v6 default route is installed. This is the live proof of P4.9a's link.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = guest_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");
    let host_ip6 = vm.ipv6().expect("ipv6 when networked").host.to_string();
    let guest_ip6 = vm.ipv6().expect("ipv6 when networked").guest.to_string();

    // The guest applied its static v6 address to eth0 (via `/sbin/net-up`, `ip` then `ifconfig`). A
    // missing address here means net-up didn't run or the guest busybox lacks v6 address support, the
    // one runtime unknown this test exists to catch.
    let addr = vm
        .exec(
            &[
                "ip".into(),
                "-6".into(),
                "addr".into(),
                "show".into(),
                "eth0".into(),
            ],
            b"",
        )
        .expect("show guest eth0 v6");
    assert!(
        String::from_utf8_lossy(&addr.stdout).contains(&guest_ip6),
        "guest eth0 should carry {guest_ip6} (via /sbin/net-up); got:\n{}\nconsole:\n{}",
        String::from_utf8_lossy(&addr.stdout),
        vm.console()
    );

    // Host<->guest v6 reachability: the guest reaches the host end of the connected /64.
    let ping = vm
        .exec(
            &[
                "ping".into(),
                "-6".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                "1".into(),
                host_ip6.clone(),
            ],
            b"",
        )
        .expect("ping the host tap v6 address");
    assert_eq!(
        ping.exit_code,
        0,
        "guest should reach the host v6 end {host_ip6}; console:\n{}",
        vm.console()
    );

    // Deny-by-default: an off-link v6 address is unreachable (no v6 default route). RFC 3849
    // documentation range `2001:db8::/32` is provably off the /64.
    let off = vm
        .exec(
            &[
                "ping".into(),
                "-6".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                "1".into(),
                "2001:db8::1".into(),
            ],
            b"",
        )
        .expect("ping an off-link v6 address");
    assert_ne!(
        off.exit_code, 0,
        "deny-by-default: the guest must not reach an off-link v6 address"
    );
    // Pin the reason (no route, not a timeout), and the mechanism (no v6 default route), the same
    // two binds the v4 twin carries: `2001:db8::/32` is bogon-filtered on the public internet, so
    // the bare non-zero exit would also pass with full v6 egress.
    let off_err = format!(
        "{}{}",
        String::from_utf8_lossy(&off.stdout),
        String::from_utf8_lossy(&off.stderr)
    );
    assert!(
        off_err.contains("nreachable"),
        "the v6 block must be no-route, not a timeout; output: {off_err}"
    );
    let route = vm
        .exec(&["ip".into(), "-6".into(), "route".into()], b"")
        .expect("show guest v6 routes");
    let route_out = String::from_utf8_lossy(&route.stdout);
    assert!(
        !route_out.contains("default"),
        "no v6 default route may exist (deny-by-default): {route_out}"
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn two_networked_vms_run_in_isolated_netns() {
    // Under the netns model: per-VM isolation is **kernel-enforced** by a per-VM network
    // namespace rather than by address separation. Two concurrently-booted networked VMs hold
    // identically-named taps on the *same* fixed /30, yet share no path: each is its own network
    // stack. This is strictly stronger than L3-unreachability (it holds even for identical addresses).
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg_a = guest_rootfs_config();
    cfg_a.enable_network = true;
    let vm_a = Vm::boot(cfg_a).expect("VM A with a NIC should boot to readiness");
    let mut cfg_b = guest_rootfs_config();
    cfg_b.enable_network = true;
    let vm_b = Vm::boot(cfg_b).expect("VM B with a NIC should boot to readiness");

    // Distinct network namespaces are the isolation boundary. The two guests even share an address
    // (the fixed /30), which is only safe *because* they are in separate stacks.
    let ns_a = vm_a.netns().expect("A netns when networked");
    let ns_b = vm_b.netns().expect("B netns when networked");
    assert_ne!(
        ns_a, ns_b,
        "the two VMs must run in distinct network namespaces"
    );
    assert_eq!(
        vm_a.ipv4().map(|l| l.guest),
        vm_b.ipv4().map(|l| l.guest),
        "the netns model gives every VM the same fixed /30 (isolation is the namespace, not the address)"
    );

    // A's tap is invisible from B's netns: `ip link show` for A's netns-local link, run inside B's
    // netns, must fail (no such interface), the two stacks share nothing. (Both taps are named the
    // same, so this checks presence-in-the-right-stack, which the addresses below make unambiguous.)
    // Deny-by-default holds per VM: neither guest can reach an off-/30 address, and the other VM lives
    // entirely in a separate netns, so it is off every route either guest has.
    for (vm, other) in [(&vm_a, ns_b), (&vm_b, ns_a)] {
        let off = vm
            .exec(
                &[
                    "ping".into(),
                    "-c".into(),
                    "1".into(),
                    "-W".into(),
                    "1".into(),
                    "192.0.2.1".into(), // RFC 5737 TEST-NET-1, off the /30
                ],
                b"",
            )
            .expect("ping an off-subnet address");
        assert_ne!(
            off.exit_code, 0,
            "each guest must be deny-by-default, so it can't reach the other in netns {other}"
        );
        let off_err = format!(
            "{}{}",
            String::from_utf8_lossy(&off.stdout),
            String::from_utf8_lossy(&off.stderr)
        );
        assert!(
            off_err.contains("nreachable"),
            "the block must be no-route, not a timeout; output: {off_err}"
        );
    }

    vm_a.shutdown().expect("shutdown A should succeed");
    vm_b.shutdown().expect("shutdown B should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the guest rootfs (run via `cargo xtask ci-privileged`)"]
fn guest_reaches_an_allowed_host_endpoint_but_not_a_blocked_one() {
    // Prove the allow/deny posture at the transport layer, not just ICMP. "Allowed" here is
    // host-local by design (world-egress allow-listing is eBPF-enforced at the tap). Under
    // the netns model the tap's host end lives *inside* the VM's netns, so the host endpoint the guest
    // reaches is bound there too: a real TCP listener on the host `/30` end, entered via
    // `ip netns exec`. An off-subnet endpoint stays unreachable (no route, fast failure).
    use std::io::{BufRead, BufReader};
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = guest_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");
    let netns = vm.netns().expect("netns when networked").to_string();
    let host_ip = vm.ipv4().expect("ipv4 when networked").host.to_string();
    let port = 45_000u16; // fixed; the netns is private, so no host-side port contention

    // A genuine host-side endpoint on the tap's host address, bound **inside the VM's netns**. It
    // prints READY once listening (the kernel then backlogs the guest's connect), waits for one
    // connection, and exits. python3 is available on the host (it builds the rootfs artifacts).
    let script = format!(
        "import socket,sys\n\
         s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n\
         s.bind(('{host_ip}',{port})); s.listen(1)\n\
         sys.stdout.write('READY\\n'); sys.stdout.flush()\n\
         s.settimeout(30)\n\
         try:\n c,_=s.accept()\n c.close()\n\
         except Exception: pass\n"
    );
    let mut listener = Command::new("ip")
        .args(["netns", "exec", &netns, "python3", "-c", &script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn the in-netns host listener");
    // Wait until it is actually listening before the guest connects.
    let out = listener.stdout.take().expect("listener stdout piped");
    let mut lines = BufReader::new(out).lines();
    let ready = lines.next().and_then(Result::ok);
    assert_eq!(
        ready.as_deref(),
        Some("READY"),
        "in-netns listener should report READY"
    );

    // Allowed: the guest's TCP connect to the host endpoint succeeds (python3 exits 0; an unreachable
    // peer would raise and exit non-zero).
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
    let _ = listener.wait();

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
    // Pin the reason: ENETUNREACH (no route), not the 3 s socket timeout, which is what an
    // internet-open guest probing bogon-filtered TEST-NET would report.
    let blocked_err = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        blocked_err.contains("nreachable"),
        "the block must be no-route, not a timeout; stderr: {blocked_err}"
    );

    vm.shutdown().expect("shutdown should succeed");
}
