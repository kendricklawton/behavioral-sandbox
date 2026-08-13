//! Differential tests: the in-kernel classifier against the host twins it was mirrored from.
//!
//! `crates/probes`'s `parse` reads a frame through `ctx.load` (a verifier-bounded
//! `bpf_skb_load_bytes` per field) while [`parse_ipv4_5tuple`] reads the same offsets through a
//! slice. The byte positions are single-sourced `const`s, so the two cannot disagree on where a
//! field lives; the surrounding logic (the ethertype check, the fragment gate, the protocol test)
//! is mirrored by hand. These tests are the enforcer for that mirror: the same frame goes to both
//! halves and they must agree.
//!
//! The kernel half runs via `BPF_PROG_TEST_RUN`, which hands a loaded program a synthetic packet
//! and returns its verdict. That needs the program **loaded**, not attached, so unlike every other
//! test in this directory it needs no VM, no tap, and no netns: `CAP_BPF` + `CAP_PERFMON` + BTF and
//! the built object are the whole requirement. `#[ignore]`d because those still mean real root.
#![allow(clippy::panic)]

use std::net::{Ipv4Addr, Ipv6Addr};

use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::tc::SchedClassifier;
use aya::programs::{TestRun, TestRunOptions};
use aya::{Ebpf, EbpfLoader};
use bsx_probes_common::{
    ETH_HLEN, ETH_P_ARP, ETH_P_IP, ETH_P_IPV6, FLOW_COUNTS_SIZE, FLOW_KEY_SIZE, FLOW_KEY6_SIZE,
    FlowKey, FlowKey6, GUEST_LINK6, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, IPV6_DST_OFFSET,
    IPV6_HLEN, IPV6_NEXT_HEADER_OFFSET, IPV6_SRC_OFFSET, MAX_POLICY_RULES, POLICY_RULE_SIZE,
    POLICY_RULE6_SIZE, PolicyRule, PolicyRule6, egress_allowed, egress_allowed6, icmp6_dst_on_link,
    parse_ipv4_5tuple, parse_ipv6_5tuple,
};
use bsx_probes_loader::{EgressPolicy, Protocol, object_path};

mod common;

use bsx_probes_loader::skip_reason as probe_skip_reason;

/// `TC_ACT_OK`: the classifier accepted the frame.
const TC_ACT_OK: u32 = 0;
/// `TC_ACT_SHOT`: the classifier dropped it.
const TC_ACT_SHOT: u32 = 2;

/// Load the object and load (not attach) one classifier by name, ready for `test_run`.
fn load_classifier(name: &str) -> Ebpf {
    let mut ebpf = EbpfLoader::new()
        .load_file(object_path())
        .unwrap_or_else(|e| panic!("load the eBPF object: {e}"));
    let prog: &mut SchedClassifier = ebpf
        .program_mut(name)
        .unwrap_or_else(|| panic!("program `{name}` not in the object"))
        .try_into()
        .unwrap_or_else(|e| panic!("`{name}` is not a classifier: {e}"));
    prog.load()
        .unwrap_or_else(|e| panic!("load `{name}` into the kernel: {e}"));
    ebpf
}

/// Run one frame through a loaded classifier and return its verdict.
///
/// `what` names the corpus case, and the failure carries it with the frame's length and the
/// `errno`: `BPF_PROG_TEST_RUN` refusing the *call* is a different failure from the classifier
/// returning the wrong verdict, and these tests run only under the privileged gate, so a message
/// that names neither the frame nor the cause costs a whole root run to narrow.
fn verdict(ebpf: &mut Ebpf, name: &str, what: &str, frame: &[u8]) -> u32 {
    // The kernel copies the (possibly modified) packet back, so the buffer must be able to hold it;
    // a short one is `-ENOSPC` rather than a wrong answer. These programs never write to the packet,
    // so generous slack costs nothing.
    let mut out = vec![0u8; frame.len() + 256];
    let prog: &SchedClassifier = ebpf
        .program(name)
        .unwrap_or_else(|| panic!("program `{name}` missing"))
        .try_into()
        .unwrap_or_else(|e| panic!("`{name}` is not a classifier: {e}"));
    prog.test_run(TestRunOptions {
        data_in: Some(frame),
        data_out: Some(&mut out),
        repeat: 1,
        ..Default::default()
    })
    .unwrap_or_else(|e| {
        panic!(
            "test_run `{name}` on {what:?} ({} byte frame): {}",
            frame.len(),
            with_causes(&e)
        )
    })
    .return_value
}

/// An error rendered with its source chain. aya reports a refused syscall as `` `bpf_prog_test_run`
/// failed `` and carries the `errno` as the source, so `{e}` alone names the call and never the
/// reason it was refused.
fn with_causes(e: &dyn std::error::Error) -> String {
    let mut rendered = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        rendered.push_str(": ");
        rendered.push_str(&cause.to_string());
        source = cause.source();
    }
    rendered
}

/// Whether `BPF_PROG_TEST_RUN` can carry this frame to a classifier at all. The kernel builds a
/// real skb from `data_in` and rejects a frame whose IPv4/IPv6 ethertype promises a fixed L3
/// header the bytes cannot hold (`EINVAL`, before the program runs), so such a frame exists in a
/// corpus for the host twin alone and the kernel loops skip it.
/// `the_kernel_inexpressible_entries_are_exactly_the_known_ones` holds the skip to the entries
/// that need it.
fn test_run_can_express(frame: &[u8]) -> bool {
    // 20 is sizeof(struct iphdr), the fixed v4 header the kernel's bound checks (ihl options
    // extend a real header past it, but the refusal is on the fixed part).
    match ethertype(frame) {
        Some(ETH_P_IP) => frame.len() >= ETH_HLEN + 20,
        Some(ETH_P_IPV6) => frame.len() >= ETH_HLEN + IPV6_HLEN,
        _ => true,
    }
}

/// Every `FlowKey` currently in the `FLOWS` map, decoded with the same shared `from_bytes` the
/// loader uses, so this reads the map exactly as production does.
fn flow_keys(ebpf: &Ebpf) -> Vec<FlowKey> {
    let map = ebpf
        .map("FLOWS")
        .unwrap_or_else(|| panic!("map `FLOWS` not found"));
    let flows: AyaHashMap<_, [u8; FLOW_KEY_SIZE], [u8; FLOW_COUNTS_SIZE]> =
        AyaHashMap::try_from(map).unwrap_or_else(|e| panic!("open `FLOWS` as a hash map: {e}"));
    flows
        .keys()
        .map(|k| {
            let raw = k.unwrap_or_else(|e| panic!("iterate `FLOWS`: {e}"));
            FlowKey::from_bytes(&raw)
                .unwrap_or_else(|| panic!("decode a `FLOWS` key: {} bytes", raw.len()))
        })
        .collect()
}

/// Write `rules` into `POLICY` and arm `ENFORCE`, the same shape `TapMonitor::enforce` writes.
fn arm(ebpf: &mut Ebpf, rules: &[PolicyRule]) {
    {
        let map = ebpf
            .map_mut("POLICY")
            .unwrap_or_else(|| panic!("map `POLICY` not found"));
        let mut policy: Array<_, [u8; POLICY_RULE_SIZE]> =
            Array::try_from(map).unwrap_or_else(|e| panic!("open `POLICY` as an array: {e}"));
        for i in 0..MAX_POLICY_RULES {
            let bytes = rules
                .get(i)
                .map_or([0u8; POLICY_RULE_SIZE], PolicyRule::to_bytes);
            policy
                .set(i as u32, bytes, 0)
                .unwrap_or_else(|e| panic!("write `POLICY`[{i}]: {e}"));
        }
    }
    let map = ebpf
        .map_mut("ENFORCE")
        .unwrap_or_else(|| panic!("map `ENFORCE` not found"));
    let mut enforce: Array<_, u32> =
        Array::try_from(map).unwrap_or_else(|e| panic!("open `ENFORCE` as an array: {e}"));
    enforce
        .set(0, 1, 0)
        .unwrap_or_else(|e| panic!("arm `ENFORCE`: {e}"));
}

/// An Ethernet + IPv4 frame with an L4 header, padded to a realistic minimum length. Checksums are
/// left zero: the classifier never validates them, and a wrong one must not change its answer.
fn ipv4_frame(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    proto: u8,
    frag_off: u16,
) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst MAC
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src MAC
    f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
    f[ETH_HLEN] = 0x45; // IPv4, ihl = 5 words (20 bytes)
    f[ETH_HLEN + 2..ETH_HLEN + 4].copy_from_slice(&46u16.to_be_bytes()); // total length
    f[ETH_HLEN + 6..ETH_HLEN + 8].copy_from_slice(&frag_off.to_be_bytes());
    f[ETH_HLEN + 8] = 64; // ttl
    f[ETH_HLEN + 9] = proto;
    f[ETH_HLEN + 12..ETH_HLEN + 16].copy_from_slice(&src.octets());
    f[ETH_HLEN + 16..ETH_HLEN + 20].copy_from_slice(&dst.octets());
    let l4 = ETH_HLEN + 20;
    f[l4..l4 + 2].copy_from_slice(&sport.to_be_bytes());
    f[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
    f
}

/// An ARP frame: the one non-IP ethertype the ingress verdict spares, so the guest can resolve its
/// on-link host end and send IP at all.
fn arp_frame() -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    f
}

/// The corpus both v4 differential tests run. **IPv4, ARP and junk only, deliberately:** a v6 frame
/// takes the kernel's `parse6`/`egress_verdict6` path (its own policy map, plus the on-link ICMPv6
/// spare), which [`parse_ipv4_5tuple`] and [`egress_allowed`] cannot model, so including one would
/// make the oracle agree for the wrong reason. [`corpus6`] is its v6 counterpart, split for the
/// same reason in reverse.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let guest = Ipv4Addr::new(10, 200, 0, 2);
    let host = Ipv4Addr::new(10, 200, 0, 1);
    let world = Ipv4Addr::new(9, 9, 9, 9);
    vec![
        (
            "udp to the allowed host endpoint",
            ipv4_frame(guest, host, 40000, 9999, IPPROTO_UDP, 0),
        ),
        (
            "udp to a denied port on the allowed host",
            ipv4_frame(guest, host, 40000, 8888, IPPROTO_UDP, 0),
        ),
        (
            "tcp to a denied destination",
            ipv4_frame(guest, world, 40000, 443, IPPROTO_TCP, 0),
        ),
        (
            "icmp (no ports at the port offsets)",
            ipv4_frame(guest, host, 0, 0, 1, 0),
        ),
        (
            "a non-first fragment, whose port offsets are payload",
            ipv4_frame(guest, host, 40000, 9999, IPPROTO_UDP, 0x0025),
        ),
        ("arp", arp_frame()),
        ("a frame that is only an ethernet header", vec![0u8; 14]),
    ]
}

#[test]
#[ignore = "loads an eBPF program; needs real root + BTF (run via `cargo xtask ci-privileged`)"]
fn the_kernels_frame_parse_agrees_with_the_host_twin() {
    if let Some(why) = probe_skip_reason() {
        eprintln!("skipping the_kernels_frame_parse_agrees_with_the_host_twin: {why}");
        return;
    }
    // `tap_egress` counts every frame and always passes, so it isolates the parser from the policy.
    let mut ebpf = load_classifier("tap_egress");
    let mut seen: Vec<FlowKey> = Vec::new();

    for (what, frame) in corpus() {
        let before = flow_keys(&ebpf);
        assert_eq!(
            verdict(&mut ebpf, "tap_egress", what, &frame),
            TC_ACT_OK,
            "{what}"
        );
        let after = flow_keys(&ebpf);

        // The key the kernel's `parse` produced for this frame, if it produced one: whatever is in
        // `FLOWS` that wasn't there before.
        let fresh: Vec<FlowKey> = after.into_iter().filter(|k| !before.contains(k)).collect();
        let host = parse_ipv4_5tuple(&frame);

        match host {
            Some(expected) if !seen.contains(&expected) => {
                assert_eq!(
                    fresh,
                    vec![expected],
                    "{what}: the kernel's parse must produce exactly what the host twin does"
                );
                seen.push(expected);
            }
            // The host twin keys it, but an earlier frame already created that row: no new key.
            Some(_) => assert!(fresh.is_empty(), "{what}: an existing flow must not re-key"),
            None => assert!(
                fresh.is_empty(),
                "{what}: the host twin keys nothing, so the kernel must not either, got {fresh:?}"
            ),
        }
    }
}

#[test]
#[ignore = "loads an eBPF program; needs real root + BTF (run via `cargo xtask ci-privileged`)"]
fn the_kernels_egress_verdict_agrees_with_the_host_twin() {
    if let Some(why) = probe_skip_reason() {
        eprintln!("skipping the_kernels_egress_verdict_agrees_with_the_host_twin: {why}");
        return;
    }
    let policy = EgressPolicy::deny_all().allow_host(
        Ipv4Addr::new(10, 200, 0, 1),
        Some(9999),
        Some(Protocol::Udp),
    );
    let rules = policy.rules().to_vec();
    let mut ebpf = load_classifier("tap_ingress");
    arm(&mut ebpf, &rules);

    for (what, frame) in corpus() {
        // The host twin of `egress_verdict`, built from the two host oracles: a keyed frame is the
        // policy's answer, an unkeyable one is ARP-spared or deny-by-default.
        let expected = match parse_ipv4_5tuple(&frame) {
            Some(k) if egress_allowed(&rules, k.dst_addr, k.dst_port, k.proto) => TC_ACT_OK,
            Some(_) => TC_ACT_SHOT,
            None if ethertype(&frame) == Some(ETH_P_ARP) => TC_ACT_OK,
            None => TC_ACT_SHOT,
        };
        assert_eq!(
            verdict(&mut ebpf, "tap_ingress", what, &frame),
            expected,
            "{what}: the kernel's verdict must be the host twin's"
        );
    }
}

#[test]
#[ignore = "loads an eBPF program; needs real root + BTF (run via `cargo xtask ci-privileged`)"]
fn observe_only_passes_every_frame_enforcement_would_drop() {
    if let Some(why) = probe_skip_reason() {
        eprintln!("skipping observe_only_passes_every_frame_enforcement_would_drop: {why}");
        return;
    }
    // The false-positive control for the test above: same corpus, same empty-by-default policy, but
    // `ENFORCE` left at its load-time 0. Without this, a classifier that passed everything
    // unconditionally would still satisfy the observe-only half of the contract silently.
    let mut ebpf = load_classifier("tap_ingress");
    for (what, frame) in corpus() {
        assert_eq!(
            verdict(&mut ebpf, "tap_ingress", what, &frame),
            TC_ACT_OK,
            "{what}: observe-only must accept every frame"
        );
    }
}

/// The frame's ethertype, or `None` if it is too short to carry one.
fn ethertype(frame: &[u8]) -> Option<u16> {
    let b = frame.get(12..14)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

// ---------------------------------------------------------------------------
// The IPv6 half.
//
// `parse6`/`egress_verdict6` are mirrored from `parse_ipv6_5tuple`/`egress_allowed6` exactly as the
// v4 pair is, and until now nothing held them together: the host halves had unit tests and no
// caller, so a drift in either direction was invisible. The v6 corpus is kept separate from the v4
// one because the two take different kernel paths (their own policy map, plus the on-link ICMPv6
// spare), so a shared corpus would make each oracle agree for the wrong reason.

/// Every `FlowKey6` currently in `FLOWS6`, decoded with the shared `from_bytes` the loader uses.
fn flow_keys6(ebpf: &Ebpf) -> Vec<FlowKey6> {
    let map = ebpf
        .map("FLOWS6")
        .unwrap_or_else(|| panic!("map `FLOWS6` not found"));
    let flows: AyaHashMap<_, [u8; FLOW_KEY6_SIZE], [u8; FLOW_COUNTS_SIZE]> =
        AyaHashMap::try_from(map).unwrap_or_else(|e| panic!("open `FLOWS6` as a hash map: {e}"));
    flows
        .keys()
        .map(|k| {
            let raw = k.unwrap_or_else(|e| panic!("iterate `FLOWS6`: {e}"));
            FlowKey6::from_bytes(&raw)
                .unwrap_or_else(|| panic!("decode a `FLOWS6` key: {} bytes", raw.len()))
        })
        .collect()
}

/// Write `rules` into `POLICY6` and arm `ENFORCE`, the v6 twin of [`arm`].
fn arm6(ebpf: &mut Ebpf, rules: &[PolicyRule6]) {
    {
        let map = ebpf
            .map_mut("POLICY6")
            .unwrap_or_else(|| panic!("map `POLICY6` not found"));
        let mut policy: Array<_, [u8; POLICY_RULE6_SIZE]> =
            Array::try_from(map).unwrap_or_else(|e| panic!("open `POLICY6` as an array: {e}"));
        for i in 0..MAX_POLICY_RULES {
            let bytes = rules
                .get(i)
                .map_or([0u8; POLICY_RULE6_SIZE], PolicyRule6::to_bytes);
            policy
                .set(i as u32, bytes, 0)
                .unwrap_or_else(|e| panic!("write `POLICY6`[{i}]: {e}"));
        }
    }
    let map = ebpf
        .map_mut("ENFORCE")
        .unwrap_or_else(|| panic!("map `ENFORCE` not found"));
    let mut enforce: Array<_, u32> =
        Array::try_from(map).unwrap_or_else(|e| panic!("open `ENFORCE` as an array: {e}"));
    enforce
        .set(0, 1, 0)
        .unwrap_or_else(|e| panic!("arm `ENFORCE`: {e}"));
}

/// An Ethernet + IPv6 frame with a 4-byte L4 header. `next_header` doubles as the protocol, which is
/// what both halves key on; an extension-header value therefore yields ports of zero on both sides.
fn ipv6_frame(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, next_header: u8) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst MAC
    f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src MAC
    f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    f[ETH_HLEN] = 0x60; // version 6, traffic class 0
    f[ETH_HLEN + 4..ETH_HLEN + 6].copy_from_slice(&4u16.to_be_bytes()); // payload length
    f[ETH_HLEN + IPV6_NEXT_HEADER_OFFSET] = next_header;
    f[ETH_HLEN + 7] = 64; // hop limit
    f[ETH_HLEN + IPV6_SRC_OFFSET..ETH_HLEN + IPV6_DST_OFFSET].copy_from_slice(&src.octets());
    f[ETH_HLEN + IPV6_DST_OFFSET..ETH_HLEN + IPV6_HLEN].copy_from_slice(&dst.octets());
    let l4 = ETH_HLEN + IPV6_HLEN;
    f[l4..l4 + 2].copy_from_slice(&sport.to_be_bytes());
    f[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
    f
}

/// The guest's own `/64`, from the single-sourced [`GUEST_LINK6`] rather than a literal, so a change
/// to the link moves this corpus with it.
fn on_guest_link(last: u16) -> Ipv6Addr {
    let (net, _) = GUEST_LINK6;
    let mut o = net;
    o[14..16].copy_from_slice(&last.to_be_bytes());
    Ipv6Addr::from(o)
}

/// The v6 corpus. **IPv6, ARP and junk only**, for the reason [`corpus`] states in reverse: a v4
/// frame takes the kernel's `parse`/`egress_verdict` path, which the v6 oracles cannot model.
fn corpus6() -> Vec<(&'static str, Vec<u8>)> {
    let guest = on_guest_link(2);
    let host = on_guest_link(1);
    let world = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let link_mcast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    vec![
        (
            "udp to the allowed host endpoint",
            ipv6_frame(guest, host, 40000, 9999, IPPROTO_UDP),
        ),
        (
            "udp to a denied port on the allowed host",
            ipv6_frame(guest, host, 40000, 8888, IPPROTO_UDP),
        ),
        (
            "tcp to a denied global destination",
            ipv6_frame(guest, world, 40000, 443, IPPROTO_TCP),
        ),
        (
            "icmpv6 to a link-local destination (neighbor discovery)",
            ipv6_frame(guest, link_local, 0, 0, IPPROTO_ICMPV6),
        ),
        (
            "icmpv6 to link-scoped multicast (MLD)",
            ipv6_frame(guest, link_mcast, 0, 0, IPPROTO_ICMPV6),
        ),
        (
            "icmpv6 on the guest's own link",
            ipv6_frame(guest, host, 0, 0, IPPROTO_ICMPV6),
        ),
        // The one that matters most: a routable ICMPv6 Echo must fall through to POLICY6 rather than
        // ride the on-link spare, or the spare is an unpoliced egress channel.
        (
            "icmpv6 to a global destination, which the spare must not cover",
            ipv6_frame(guest, world, 0, 0, IPPROTO_ICMPV6),
        ),
        (
            "an extension header, whose port offsets are not ports",
            ipv6_frame(guest, host, 40000, 9999, 0),
        ),
        ("arp", arp_frame()),
        ("a frame that is only an ethernet header", vec![0u8; 14]),
        // Shorter than the fixed IPv6 header its ethertype promises. `bpf_prog_test_run_skb`
        // refuses to build such an skb, so this entry reaches the host twin only and the kernel
        // loops skip it ([`test_run_can_express`]).
        (
            "a v6 frame truncated inside its own header",
            ipv6_frame(guest, host, 40000, 9999, IPPROTO_UDP)[..ETH_HLEN + 30].to_vec(),
        ),
        // Cut at the end of the fixed header instead: the ports the parse needs are missing, but
        // the header the kernel demands is whole, so unlike its sibling above this one runs
        // in-kernel and keeps a truncation case in the differential proper.
        (
            "a v6 frame truncated at its L4 ports",
            ipv6_frame(guest, host, 40000, 9999, IPPROTO_UDP)[..ETH_HLEN + IPV6_HLEN].to_vec(),
        ),
    ]
}

#[test]
#[ignore = "loads an eBPF program; needs real root + BTF (run via `cargo xtask ci-privileged`)"]
fn the_kernels_v6_frame_parse_agrees_with_the_host_twin() {
    if let Some(why) = probe_skip_reason() {
        eprintln!("skipping the_kernels_v6_frame_parse_agrees_with_the_host_twin: {why}");
        return;
    }
    let mut ebpf = load_classifier("tap_egress");
    let mut seen: Vec<FlowKey6> = Vec::new();

    for (what, frame) in corpus6() {
        if !test_run_can_express(&frame) {
            continue; // host-twin-only; see `test_run_can_express`
        }
        let before = flow_keys6(&ebpf);
        assert_eq!(
            verdict(&mut ebpf, "tap_egress", what, &frame),
            TC_ACT_OK,
            "{what}"
        );
        let after = flow_keys6(&ebpf);
        let fresh: Vec<FlowKey6> = after.into_iter().filter(|k| !before.contains(k)).collect();

        match parse_ipv6_5tuple(&frame) {
            Some(expected) if !seen.contains(&expected) => {
                assert_eq!(
                    fresh,
                    vec![expected],
                    "{what}: the kernel's `parse6` must produce exactly what the host twin does"
                );
                seen.push(expected);
            }
            Some(_) => assert!(fresh.is_empty(), "{what}: an existing flow must not re-key"),
            None => assert!(
                fresh.is_empty(),
                "{what}: the host twin keys nothing, so the kernel must not either, got {fresh:?}"
            ),
        }
    }
}

#[test]
#[ignore = "loads an eBPF program; needs real root + BTF (run via `cargo xtask ci-privileged`)"]
fn the_kernels_v6_egress_verdict_agrees_with_the_host_twin() {
    if let Some(why) = probe_skip_reason() {
        eprintln!("skipping the_kernels_v6_egress_verdict_agrees_with_the_host_twin: {why}");
        return;
    }
    let policy =
        EgressPolicy::deny_all().allow_host6(on_guest_link(1), Some(9999), Some(Protocol::Udp));
    let rules = policy.rules6().to_vec();
    let mut ebpf = load_classifier("tap_ingress");
    arm6(&mut ebpf, &rules);

    for (what, frame) in corpus6() {
        if !test_run_can_express(&frame) {
            continue; // host-twin-only; see `test_run_can_express`
        }
        // The host twin of `egress_verdict6`: the on-link ICMPv6 spare is consulted first, exactly
        // as the kernel consults it, then the policy, then deny-by-default.
        let expected = match parse_ipv6_5tuple(&frame) {
            Some(k) if k.proto == IPPROTO_ICMPV6 && icmp6_dst_on_link(k.dst_addr) => TC_ACT_OK,
            Some(k) if egress_allowed6(&rules, k.dst_addr, k.dst_port, k.proto) => TC_ACT_OK,
            Some(_) => TC_ACT_SHOT,
            None if ethertype(&frame) == Some(ETH_P_ARP) => TC_ACT_OK,
            None => TC_ACT_SHOT,
        };
        assert_eq!(
            verdict(&mut ebpf, "tap_ingress", what, &frame),
            expected,
            "{what}: the kernel's v6 verdict must be the host twin's"
        );
    }
}

/// Host-safe, so it runs in the everyday gate: the corpus is what the differentials above believe
/// it is. Without this a mis-built frame would make both `#[ignore]`d tests agree on a case neither
/// intended, and the mistake would only surface as a confusing privileged failure.
#[test]
fn the_v6_corpus_is_the_shape_the_differentials_assume() {
    let host = on_guest_link(1);
    let world = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let keyed: Vec<(&str, Option<FlowKey6>)> = corpus6()
        .into_iter()
        .map(|(what, f)| (what, parse_ipv6_5tuple(&f)))
        .collect();

    let key = |what: &str| -> FlowKey6 {
        keyed
            .iter()
            .find(|(w, _)| *w == what)
            .unwrap_or_else(|| panic!("no corpus entry {what:?}"))
            .1
            .unwrap_or_else(|| panic!("{what} must parse"))
    };

    let udp = key("udp to the allowed host endpoint");
    assert_eq!((udp.dst_port, udp.proto), (9999, IPPROTO_UDP));
    assert_eq!(udp.dst_addr, host.octets());
    assert_eq!(key("tcp to a denied global destination").proto, IPPROTO_TCP);

    // The three spared scopes and the one that must not be spared.
    for what in [
        "icmpv6 to a link-local destination (neighbor discovery)",
        "icmpv6 to link-scoped multicast (MLD)",
        "icmpv6 on the guest's own link",
    ] {
        let k = key(what);
        assert_eq!(k.proto, IPPROTO_ICMPV6, "{what}");
        assert!(icmp6_dst_on_link(k.dst_addr), "{what} must be on-link");
    }
    let routable = key("icmpv6 to a global destination, which the spare must not cover");
    assert_eq!(routable.proto, IPPROTO_ICMPV6);
    assert_eq!(routable.dst_addr, world.octets());
    assert!(
        !icmp6_dst_on_link(routable.dst_addr),
        "a global destination must fall through to POLICY6, or the spare is an egress channel"
    );

    // An extension header is not a protocol with ports: both halves must read zeros there.
    let ext = key("an extension header, whose port offsets are not ports");
    assert_eq!((ext.proto, ext.src_port, ext.dst_port), (0, 0, 0));

    // The four that must key nothing at all.
    for what in [
        "arp",
        "a frame that is only an ethernet header",
        "a v6 frame truncated inside its own header",
        "a v6 frame truncated at its L4 ports",
    ] {
        assert!(
            keyed.iter().any(|(w, k)| *w == what && k.is_none()),
            "{what} must not parse as a v6 flow"
        );
    }
}

/// Host-safe: exactly which corpus entries `BPF_PROG_TEST_RUN` cannot express. The kernel loops
/// skip by [`test_run_can_express`], so this is what keeps that skip from quietly widening into
/// a differential that runs less than it appears to; the empty v4 list is what fails first if a
/// truncated v4 case is ever added without teaching the v4 loops to skip it.
#[test]
fn the_kernel_inexpressible_entries_are_exactly_the_known_ones() {
    let inexpressible = |entries: Vec<(&'static str, Vec<u8>)>| -> Vec<&'static str> {
        entries
            .into_iter()
            .filter(|(_, f)| !test_run_can_express(f))
            .map(|(what, _)| what)
            .collect()
    };
    assert_eq!(
        inexpressible(corpus()),
        Vec::<&str>::new(),
        "the v4 kernel loops run every entry, so none may be inexpressible"
    );
    assert_eq!(
        inexpressible(corpus6()),
        vec!["a v6 frame truncated inside its own header"],
        "the v6 kernel loops skip exactly one entry, the L3-truncated host-twin-only case"
    );
}
