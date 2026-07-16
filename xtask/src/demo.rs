//! The Phase 9 exit-gate demo (`trace-sandbox`): a **live syscall trace of a running sandbox**.
//!
//! Binds the two tracks an embedder binds — boot a real microVM sandbox (the Firecracker driver,
//! `agent-vmm`) and watch its host footprint with the eBPF syscall tracer (`agent-probes-loader`),
//! attributed to the sandbox's cgroup. It is deliberately the *VMM's host footprint* (the
//! jailer/Firecracker `execve`, the drive/tap/socket `openat`s), not the guest's own syscalls: a
//! microVM services those in-guest and they never trap to the host (the hardware-isolation
//! consequence Phase 9 opens with).
//!
//! Needs `/dev/kvm`, the agent rootfs, `CAP_BPF`+`CAP_PERFMON`, and the built probe object — a
//! privileged, user-run demo like `bench-boot`, never part of the host-safe gate.

use std::path::Path;
use std::time::{Duration, Instant};

use agent_probes_loader::{cgroup_id_of_pid, SyscallTracer, TapMonitor};
use agent_vmm::{BootConfig, Sandbox, DEFAULT_GUEST_CID, GUEST_READY_MARKER};
use anyhow::{bail, Context, Result};

use crate::{agent_rootfs_path, kernel_path};

/// The effective uid from `/proc/self/status` (`Uid:`'s second field), or `None` if unreadable — so
/// the demo confines when it can (root → jailed) and still runs on a dev host (unjailed) when it
/// can't, no `libc`/`unsafe`.
fn effective_uid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|u| u.parse().ok())
}

/// Boot a sandbox and stream its cgroup-attributed host syscall footprint — the Phase 9 exit-gate
/// demo. `seconds` is the length of the live tail after the boot+exec window is printed.
pub(crate) fn trace_sandbox(seconds: u64) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("trace-sandbox needs /dev/kvm (run on a KVM-capable host)");
    }
    if let Err(e) = agent_probes_loader::check_support() {
        bail!("trace-sandbox needs eBPF support: {e}");
    }
    let object = agent_probes_loader::object_path();
    if !object.is_file() {
        bail!(
            "trace-sandbox needs the built probe object ({}) — run `cargo xtask build-probes`",
            object.display()
        );
    }
    let kernel = kernel_path();
    let rootfs = agent_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("agent rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {} — run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    // Attach the tracer BEFORE boot, watching the whole host: the jailer creates the sandbox's cgroup
    // *during* boot, so we can't filter on its id up front. Capture host-wide, learn the id once the
    // VMM is up, and keep only that sandbox's events — each event already carries its cgroup id, so the
    // attribution is exact after the fact.
    let mut tracer = SyscallTracer::load().context("load + attach the syscall tracer")?;
    tracer.watch_all().context("watch the whole host")?;
    tracer
        .drain(|_| {})
        .context("clear the pre-boot baseline")?;

    // Boot a sandbox on the agent rootfs. Jailed when we're root (the confinement is the point);
    // otherwise the explicit unjailed opt-out, so the demo still runs on a dev host without root. A
    // plain read-write copy (`read_only_root = false`) boots either way, with no overlay dependency.
    let mut cfg = BootConfig::from_env();
    cfg.kernel = kernel.clone();
    cfg.rootfs = rootfs.clone();
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.read_only_root = false;
    cfg.boot_timeout = Duration::from_secs(30);
    let sandbox = if effective_uid() == Some(0) {
        Sandbox::open(cfg).context("boot the sandbox (jailed)")?
    } else {
        println!(
            "# not root: booting unjailed (Sandbox::open_unjailed) — the host trace is the same"
        );
        Sandbox::open_unjailed(cfg).context("boot the sandbox (unjailed)")?
    };

    let vmm_pid = sandbox.vmm_pid();
    let cgroup = cgroup_id_of_pid(vmm_pid).context("resolve the sandbox's cgroup id")?;
    println!(
        "# sandbox up: VMM pid {vmm_pid}, cgroup id {cgroup}, booted in {} ms",
        sandbox.boot_latency().as_millis()
    );

    // Run one command in the guest so the trace is of a sandbox that actually ran code, not just one
    // that booted. (The guest's own `echo` syscalls stay in-guest; what we capture is the host side.)
    let out = sandbox
        .exec(&["echo".into(), "traced".into()], b"")
        .context("exec in the sandbox")?;
    println!(
        "# guest ran `echo traced` -> {:?} (exit {})",
        String::from_utf8_lossy(&out.stdout).trim(),
        out.exit_code
    );

    // Drain the boot+exec window, keeping only this sandbox's host footprint.
    let mut events = Vec::new();
    tracer
        .drain(|ev| {
            if ev.cgroup_id == cgroup {
                events.push(ev);
            }
        })
        .context("drain the boot+exec trace")?;
    println!(
        "\n# {} host syscalls attributed to sandbox cgroup {cgroup}:",
        events.len()
    );
    for ev in &events {
        println!("  {}", ev.describe());
    }

    // A short live tail, scoped in-kernel to the sandbox's cgroup, so the demo also exercises the
    // streaming consumer (P9.3) against the running sandbox.
    if seconds > 0 {
        println!("\n# streaming this sandbox's host footprint for {seconds}s...");
        tracer
            .watch_cgroup(cgroup)
            .context("scope the live stream to the sandbox")?;
        tracer.drain(|_| {}).context("clear before the live tail")?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let n = tracer
            .stream(
                Duration::from_millis(2),
                || Instant::now() < deadline,
                |ev| println!("  {}", ev.describe()),
            )
            .context("stream the live trace")?;
        println!("# {n} more during the live tail");
    }

    sandbox.shutdown().context("shut the sandbox down")?;
    println!(
        "\n# sandbox shut down. This was the VMM's HOST footprint (jailer/Firecracker execve,"
    );
    println!(
        "# drive/tap/socket openats), attributed by cgroup id. The guest's own syscalls never"
    );
    println!(
        "# trapped here: they stayed in-guest, behind the KVM boundary (Phase 9's opening note)."
    );
    Ok(())
}

/// The Phase 10 exit-gate demo (`watch-sandbox`): **live per-microVM network visibility**. Boot a real
/// networked sandbox and watch the guest's own traffic on its tap, per flow and as a per-VM rollup,
/// scoped to the sandbox's own netns (decision 017). Unlike the syscall trace, this is the guest's
/// *own* packets: they cross the tap on the host, so the host sees every one.
///
/// Needs `/dev/kvm`, the agent rootfs, `CAP_BPF`+`CAP_NET_ADMIN`, and the built probe object — a
/// privileged, user-run demo like `trace-sandbox`. `rounds` is how many guest-traffic bursts to send
/// (watching the counters climb each one).
pub(crate) fn watch_sandbox(rounds: u64) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("watch-sandbox needs /dev/kvm (run on a KVM-capable host)");
    }
    if let Err(e) = agent_probes_loader::check_support() {
        bail!("watch-sandbox needs eBPF support: {e}");
    }
    let object = agent_probes_loader::object_path();
    if !object.is_file() {
        bail!(
            "watch-sandbox needs the built probe object ({}) — run `cargo xtask build-probes`",
            object.display()
        );
    }
    let kernel = kernel_path();
    let rootfs = agent_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("agent rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {} — run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    // Boot a networked sandbox: jailed when we're root (the confinement is the point), else the
    // explicit unjailed opt-out so the demo still runs on a dev host.
    let mut cfg = BootConfig::from_env();
    cfg.kernel = kernel.clone();
    cfg.rootfs = rootfs.clone();
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.read_only_root = true;
    cfg.enable_network = true;
    cfg.boot_timeout = Duration::from_secs(30);
    let sandbox = if effective_uid() == Some(0) {
        Sandbox::open(cfg).context("boot the sandbox (jailed)")?
    } else {
        println!("# not root: booting unjailed (Sandbox::open_unjailed)");
        Sandbox::open_unjailed(cfg).context("boot the sandbox (unjailed)")?
    };

    let netns = sandbox
        .netns()
        .context("the sandbox has no netns (networking should be on)")?
        .to_string();
    let tap = sandbox
        .tap_name()
        .context("the sandbox has no tap (networking should be on)")?
        .to_string();
    println!(
        "# sandbox up: booted in {} ms, watching tap {tap} in netns {netns}",
        sandbox.boot_latency().as_millis()
    );

    // Bind the monitor to *this* sandbox's tap, inside its own netns (P10.4).
    let monitor =
        TapMonitor::attach_in_netns(&netns, &tap).context("attach the tap monitor in the netns")?;

    // The guest can reach only the host end of its point-to-point /30 (deny-by-default); under the
    // netns model that end is the fixed 10.200.0.1 (decision 017). Have the guest fire UDP at it each
    // round and watch the per-VM counters climb: live network visibility.
    let sender = "import socket, time\n\
                  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
                  for _ in range(10):\n    s.sendto(b'agent-p10-watch', ('10.200.0.1', 9999)); time.sleep(0.02)\n";
    let rounds = rounds.max(1);
    for round in 1..=rounds {
        let out = sandbox
            .exec(&["python3".into(), "-c".into(), sender.into()], b"")
            .context("run the guest traffic generator")?;
        if out.exit_code != 0 {
            bail!(
                "guest traffic generator exited {}: {}",
                out.exit_code,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let t = monitor.totals().context("read the per-VM totals")?;
        println!(
            "# round {round}/{rounds}: guest sent {} pkt / {} B, received {} pkt / {} B",
            t.ingress_packets, t.ingress_bytes, t.egress_packets, t.egress_bytes
        );
    }

    // The per-flow breakdown: which conversations the guest actually had.
    let flows = monitor.flows().context("read the flow map")?;
    println!(
        "\n# {} flow(s) attributed to this sandbox's tap:",
        flows.len()
    );
    for (key, counts) in &flows {
        println!(
            "  {key}  |  in {} pkt / {} B   out {} pkt / {} B",
            counts.ingress_packets,
            counts.ingress_bytes,
            counts.egress_packets,
            counts.egress_bytes
        );
    }

    drop(monitor);
    sandbox.shutdown().context("shut the sandbox down")?;
    println!(
        "\n# sandbox shut down; its netns teardown reclaimed the tap and the tc filter (decision 023)."
    );
    println!(
        "# This was the guest's OWN traffic, observed at its tap from the host and scoped by netns."
    );
    Ok(())
}
