//! Privileged integration test for the tap flow monitor (attach a tc program to a tap).
//!
//! `#[ignore]`d like the other probe tests: loading + attaching `tc` BPF needs `CAP_BPF` +
//! `CAP_NET_ADMIN` (or root), a BTF kernel, and the built object (`cargo xtask build-probes`). Run via
//! `cargo xtask ci-privileged`. This proves the **attach** path and that the flow map reads
//! back; the header **parsing** is covered host-safe by `agent-probes-common`'s unit tests, and
//! the live "guest traffic shows up in the counters" proof is `net_flows.rs` (it needs a booted VM driving its
//! tap, which no `#[ignore]`d unit test can stand up on its own).
#![allow(clippy::panic)]

use std::process::Command;

use agent_probes_loader::{check_support, object_path, ProbeError, TapMonitor};

/// Why this host can't load the probe (a skip reason), or `None` when it can, so the test prints
/// *why* it skipped. Same gate the tracer/counter tests use.
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
    None
}

#[test]
#[ignore = "needs CAP_BPF+CAP_NET_ADMIN/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn attaches_to_a_tap_and_reads_the_flow_map() {
    // Attach the two clsact classifiers to a real ethernet device (a tap, exactly what a VM
    // uses) and read the per-flow map back. Freshly attached on an idle tap it is empty, the point
    // here is that the qdisc-add + ingress/egress attach + map-open path works end to end.
    if let Some(why) = skip_reason() {
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
