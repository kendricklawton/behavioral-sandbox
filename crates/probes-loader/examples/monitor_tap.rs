//! Demo: attach the tap flow monitor to an interface, wait, and print the per-flow
//! byte/packet counters. This is the network half of the observability story, the guest's *own*
//! traffic, counted at its tap on the host (unlike the syscall trace, which sees only the host's
//! footprint).
//!
//! Needs `CAP_BPF`+`CAP_NET_ADMIN` (or root), a BTF kernel, and the built object
//! (`cargo xtask build-probes`). Point it at an interface that carries traffic, a VM's `fc0` inside
//! its netns, or any ethernet device in the current netns:
//!
//! ```console
//! cargo xtask build-probes
//! cargo build -p agent-probes-loader --example monitor_tap
//! sudo target/debug/examples/monitor_tap <interface>
//! ```
//!
//! Returning the typed `ProbeError` from `main` keeps this within the no-panic host discipline.

use std::thread::sleep;
use std::time::Duration;

use agent_probes_loader::{ProbeError, TapMonitor};

fn main() -> Result<(), ProbeError> {
    let Some(interface) = std::env::args().nth(1) else {
        eprintln!("usage: monitor_tap <interface>   (e.g. a VM's tap device)");
        return Ok(());
    };

    let monitor = TapMonitor::attach(&interface)?;
    println!("watching flows on {interface} for 5s...");
    sleep(Duration::from_secs(5));

    let flows = monitor.flows()?;
    if flows.is_empty() {
        println!("no IPv4 flows seen (idle interface, or traffic was not IPv4-over-ethernet)");
    }
    for (key, counts) in &flows {
        // `key` renders as `src:port -> dst:port proto`; "in" is the tap's ingress (guest -> world).
        println!(
            "  {key}  |  in {} pkt / {} B   out {} pkt / {} B",
            counts.ingress_packets,
            counts.ingress_bytes,
            counts.egress_packets,
            counts.egress_bytes
        );
    }
    Ok(())
}
