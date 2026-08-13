//! Privileged integration test for the tap flow monitor (attach a tc program to a tap).
//!
//! `#[ignore]`d like the other probe tests: loading + attaching `tc` BPF needs `CAP_BPF` +
//! `CAP_NET_ADMIN` (or root), a BTF kernel, and the built object (`cargo xtask build-probes`). Run via
//! `cargo xtask ci-privileged`. This proves the **attach** path and that the flow map reads
//! back; the header **parsing** is covered host-safe by `bsx-probes-common`'s unit tests, and
//! the live "guest traffic shows up in the counters" proof is `net_flows.rs` (it needs a booted VM driving its
//! tap, which no `#[ignore]`d unit test can stand up on its own).
#![allow(clippy::panic)]

use std::net::Ipv4Addr;
use std::process::Command;

use bsx_probes_loader::{EgressPolicy, ProbeError, Protocol, TapMonitor};

mod common;

use bsx_probes_loader::skip_reason as probe_skip_reason;

#[test]
#[ignore = "needs CAP_BPF+CAP_NET_ADMIN/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn attaches_to_a_tap_and_reads_the_flow_map() {
    // Attach the two clsact classifiers to a real ethernet device (a tap, exactly what a VM
    // uses) and read the per-flow map back. Freshly attached on an idle tap it is empty, the point
    // here is that the qdisc-add + ingress/egress attach + map-open path works end to end.
    if let Some(why) = probe_skip_reason() {
        eprintln!("skipping attaches_to_a_tap_and_reads_the_flow_map: {why}");
        return;
    }

    // A persistent tap is an ethernet device with the same shape as a VM's `fc0`. The name stays well
    // inside the 15-byte `IFNAMSIZ` limit (`p10t` + pid).
    let dev = format!("p10t{}", std::process::id());
    let created = Command::new("ip")
        .args(["tuntap", "add", "dev", &dev, "mode", "tap"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !created {
        eprintln!(
            "skipping attaches_to_a_tap_and_reads_the_flow_map: could not create a tap (need \
             CAP_NET_ADMIN)"
        );
        return;
    }
    let _ = Command::new("ip")
        .args(["link", "set", &dev, "up"])
        .status();

    let result: Result<(), ProbeError> = (|| {
        let monitor = TapMonitor::attach(&dev)?;
        let flows = monitor.flows()?;
        assert!(
            flows.is_empty(),
            "a just-attached monitor on an idle tap has no flows yet, saw {flows:?}"
        );
        Ok(())
    })();

    // Always delete the tap (cascading its clsact qdisc + the filters away), whether or not the attach
    // assertions passed, no leaked host interface.
    let _ = Command::new("ip").args(["link", "del", &dev]).status();
    result.expect("attach the classifiers and read the flow map");
}

#[test]
#[ignore = "needs CAP_BPF+CAP_NET_ADMIN/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn a_replaced_policy_leaves_no_revoked_rule_behind() {
    // The runtime re-policy surface, read back from the maps the classifier consults. The stake is
    // that a *revoked* allowance is gone: `apply_policy` zeroes every slot before writing the new
    // grants, so a shrinking policy cannot leave the old rule live in a higher slot.
    if let Some(why) = probe_skip_reason() {
        eprintln!("skipping a_replaced_policy_leaves_no_revoked_rule_behind: {why}");
        return;
    }

    let dev = format!("p10r{}", std::process::id());
    let created = Command::new("ip")
        .args(["tuntap", "add", "dev", &dev, "mode", "tap"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !created {
        eprintln!(
            "skipping a_replaced_policy_leaves_no_revoked_rule_behind: could not create a tap \
             (need CAP_NET_ADMIN)"
        );
        return;
    }
    let _ = Command::new("ip")
        .args(["link", "set", &dev, "up"])
        .status();

    let revoked = Ipv4Addr::new(203, 0, 113, 7);
    let kept = Ipv4Addr::new(198, 51, 100, 9);
    let result: Result<(), ProbeError> = (|| {
        let mut monitor = TapMonitor::attach(&dev)?;
        // Two allowances, then one: the second write must not leave the first's second rule behind.
        monitor.set_egress_policy(
            &EgressPolicy::deny_all()
                .allow_host(revoked, Some(443), Some(Protocol::Tcp))
                .allow_host(kept, Some(443), Some(Protocol::Tcp)),
        )?;
        let before = monitor.posture(None)?;
        assert_eq!(
            before.allowed.len(),
            2,
            "both allowances must reach the map the classifier reads, saw {before:?}"
        );

        monitor.set_egress_policy(&EgressPolicy::deny_all().allow_host(
            kept,
            Some(443),
            Some(Protocol::Tcp),
        ))?;
        let after = monitor.posture(None)?;
        assert!(
            after.enforcing,
            "a replacement must leave the tap enforcing, never observe-only: {after:?}"
        );
        let live: Vec<u32> = after.allowed.iter().map(|r| r.addr).collect();
        assert!(
            !live.contains(&revoked.to_bits()),
            "the revoked endpoint is still in a POLICY slot, so the classifier would still admit \
             it: {after:?}"
        );
        assert_eq!(
            live,
            vec![kept.to_bits()],
            "the replacement policy is exactly what the kernel holds: {after:?}"
        );
        Ok(())
    })();

    let _ = Command::new("ip").args(["link", "del", &dev]).status();
    result.expect("re-policy an attached tap and read the posture back");
}
