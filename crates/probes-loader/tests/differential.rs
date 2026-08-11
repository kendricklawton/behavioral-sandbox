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

use std::net::Ipv4Addr;

use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::tc::SchedClassifier;
use aya::programs::{TestRun, TestRunOptions};
use aya::{Ebpf, EbpfLoader};
use bsx_probes_common::{
    ETH_HLEN, ETH_P_ARP, ETH_P_IP, FLOW_COUNTS_SIZE, FLOW_KEY_SIZE, FlowKey, IPPROTO_TCP,
    IPPROTO_UDP, MAX_POLICY_RULES, POLICY_RULE_SIZE, PolicyRule, egress_allowed, parse_ipv4_5tuple,
};
use bsx_probes_loader::{EgressPolicy, Protocol, object_path};

mod common;

use common::probe_skip_reason;

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
fn verdict(ebpf: &mut Ebpf, name: &str, frame: &[u8]) -> u32 {
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
    .unwrap_or_else(|e| panic!("test_run `{name}`: {e}"))
    .return_value
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

/// The corpus both differential tests run. **IPv4, ARP and junk only, deliberately:** a v6 frame
/// takes the kernel's `parse6`/`egress_verdict6` path (its own policy map, plus the on-link ICMPv6
/// spare), which [`parse_ipv4_5tuple`] and [`egress_allowed`] cannot model, so including one would
/// make the oracle agree for the wrong reason. The v6 twin of this file is its own work.
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
            verdict(&mut ebpf, "tap_egress", &frame),
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
            verdict(&mut ebpf, "tap_ingress", &frame),
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
            verdict(&mut ebpf, "tap_ingress", &frame),
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
