//! **Reference integration: embedding the engine end to end.**
//!
//! The smallest complete host application that runs untrusted code the way an embedder should:
//! configure a sandbox, load the host-side observers, boot it (hardware-isolated, jailed), run the
//! code, then read back **both** what the code produced and the host-observed audit record, and
//! close. This is the launch sequence the driver (`agent-vmm`) and the loader (`agent-probes-loader`)
//! document, composed **by the caller**. The model/agent, if any, is always the caller here, never
//! in the host path (ADR 035).
//!
//! The two halves bridge only by the plain values `Sandbox` exposes (`vmm_pid`, `netns`, `tap_name`,
//! `boot_latency`), so the driver never gains a dependency on the eBPF loader (ADRs 024/026);
//! that is why this reference lives in the loader crate, which dev-depends on the driver, not the
//! other way round.
//!
//! Requirements to *run* it (it compiles anywhere): a KVM host, real root + the `jailer` binary (the
//! confined default; swap to `Sandbox::open_unjailed` on a dev box without root), the built guest
//! artifacts, and, for the audit record, `CAP_BPF`+`CAP_PERFMON` and the eBPF object.
//!
//! ```console
//! cargo xtask self-host                     # guest kernel + rootfs + eBPF object, one command
//! cargo build -p agent-probes-loader --example reference_integration
//! sudo ./target/debug/examples/reference_integration -- python3 -c 'print(2 ** 100)'
//! ```
//!
//! Returning a boxed error from `main` keeps this within the no-panic host discipline (no
//! `unwrap`/`expect`): every failure prints its typed cause and exits nonzero.

use std::error::Error;
use std::time::Duration;

use agent_probes_loader::{SandboxProbes, SharedMeter, SharedTracer, Timing};
use agent_vmm::{BootConfig, Limits, Sandbox};

fn main() -> Result<(), Box<dyn Error>> {
    // The untrusted workload: the tokens after a `--`, or a small default.
    let argv = workload_from_args();
    println!("# workload: {}", argv.join(" "));

    // 1. Load the host-side observers ONCE. A long-lived host (the daemon) shares these across many
    //    sandboxes; a single run uses them once. Needs CAP_BPF+CAP_PERFMON and the eBPF object.
    let tracer = SharedTracer::load()?;
    let meter = SharedMeter::load()?;

    // 2. Configure the run. `from_env` layers flags/env/`.agent.toml`/defaults for the artifact
    //    paths; `Limits` is the per-run resource budget (ADR 013). Conservative defaults, with
    //    the whole-run wall-clock budget raised for this demo; `vcpus`/`mem_mib` are `NonZero` knobs
    //    on the same struct.
    let mut limits = Limits::default();
    limits.wall = Duration::from_secs(20);
    let config = BootConfig::from_env().with_limits(limits);

    // 3. Boot: hardware isolation (KVM) under the jailer, the confined default (ADR 015).
    //    `open_unjailed` is the greppable dev opt-out for a host without root.
    let sandbox = Sandbox::open(config)?;
    println!(
        "# sandbox up: vmm pid {}, booted in {} ms",
        sandbox.vmm_pid(),
        sandbox.boot_latency().as_millis()
    );

    // 4. Attach the observers to THIS sandbox by the plain values it exposes. `None` egress =
    //    deny-by-default networking, observe-only; `Some(&policy)` would enforce a per-VM allow-list
    //    at the tap (ADR 025). Each axis that can't attach degrades to a recorded coverage gap.
    let probes = SandboxProbes::attach(
        sandbox.vmm_pid(),
        sandbox.netns(),
        sandbox.tap_name(),
        None,
        &tracer,
        &meter,
    );

    // 5. Run the untrusted code. Synchronous; a `RunResult`, never a panic/hang/leak, whatever the
    //    guest does. A non-zero command exit is a normal result, not an error.
    let run = sandbox.exec(&argv, b"")?;

    // 6. Finalize the host-observed record **while the sandbox is still alive** (it reads the live
    //    cgroup + maps), then close. Timing enters as plain `Duration`s, so the record never depends
    //    on the driver type.
    let record = probes.collect(Timing {
        boot: sandbox.boot_latency(),
        exec_wall: run.metrics.wall,
    });
    sandbox.shutdown()?;

    // 7. Report both faces: what the code produced, and what the host observed from outside it.
    println!("\n## what the code produced");
    println!("exit: {}", run.exit_code);
    print!("{}", String::from_utf8_lossy(&run.stdout));
    if !run.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&run.stderr));
    }
    println!("\n## what the host observed (audit record)");
    println!("{}", record.to_json());
    Ok(())
}

/// The workload argv: the tokens after a `--`, or a default compute so a bare run still does something.
fn workload_from_args() -> Vec<String> {
    let after: Vec<String> = std::env::args().skip_while(|a| a != "--").skip(1).collect();
    if after.is_empty() {
        ["python3", "-c", "print(2 ** 100)"]
            .iter()
            .map(|&s| s.to_string())
            .collect()
    } else {
        after
    }
}
