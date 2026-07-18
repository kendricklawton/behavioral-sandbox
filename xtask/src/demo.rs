//! The syscall-trace demo (`trace-sandbox`): a **live syscall trace of a running sandbox**.
//!
//! Binds the two tracks an embedder binds, boot a real microVM sandbox (the Firecracker driver,
//! `agent-vmm`) and watch its host footprint with the eBPF syscall tracer (`agent-probes-loader`),
//! attributed to the sandbox's cgroup. It is deliberately the *VMM's host footprint* (the
//! jailer/Firecracker `execve`, the drive/tap/socket `openat`s), not the guest's own syscalls: a
//! microVM services those in-guest and they never trap to the host (the hardware-isolation
//! consequence stated up front).
//!
//! Needs `/dev/kvm`, the agent rootfs, `CAP_BPF`+`CAP_PERFMON`, and the built probe object, a
//! privileged, user-run demo like `bench-boot`, never part of the host-safe gate.

use std::time::{Duration, Instant};

use agent_probes_loader::{
    cgroup_id_of_pid, EgressPolicy, Protocol, ResourceMeter, SyscallTracer, TapMonitor,
};
use agent_vmm::{BootConfig, Sandbox, DEFAULT_GUEST_CID, GUEST_READY_MARKER};
use anyhow::{bail, Context, Result};

use crate::{agent_rootfs_path, kernel_path};

/// The effective uid from `/proc/self/status` (`Uid:`'s second field), or `None` if unreadable, so
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

/// Boot a sandbox and stream its cgroup-attributed host syscall footprint, the syscall-trace exit-gate
/// demo. `seconds` is the length of the live tail after the boot+exec window is printed.
pub(crate) fn trace_sandbox(seconds: u64) -> Result<()> {
    crate::require_kvm("trace-sandbox")?;
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
    // VMM is up, and keep only that sandbox's events, each event already carries its cgroup id, so the
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
    // streaming consumer against the running sandbox.
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
        "# trapped here: they stayed in-guest, behind the KVM boundary (the hardware-isolation note)."
    );
    Ok(())
}

/// The network-observability exit-gate demo (`watch-sandbox`): **live per-microVM network visibility**. Boot a real
/// networked sandbox and watch the guest's own traffic on its tap, per flow and as a per-VM rollup,
/// scoped to the sandbox's own netns (decision 017). Unlike the syscall trace, this is the guest's
/// *own* packets: they cross the tap on the host, so the host sees every one.
///
/// Needs `/dev/kvm`, the agent rootfs, `CAP_BPF`+`CAP_NET_ADMIN`, and the built probe object, a
/// privileged, user-run demo like `trace-sandbox`. `rounds` is how many guest-traffic bursts to send
/// (watching the counters climb each one).
pub(crate) fn watch_sandbox(rounds: u64) -> Result<()> {
    crate::require_kvm("watch-sandbox")?;
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

    // Bind the monitor to *this* sandbox's tap, inside its own netns.
    let monitor =
        TapMonitor::attach_in_netns(&netns, &tap).context("attach the tap monitor in the netns")?;

    // The guest can reach only the host end of its point-to-point /30 (deny-by-default); under the
    // netns model that end is the fixed 10.200.0.1 (decision 017). Have the guest fire UDP at it each
    // round and watch the per-VM counters climb: live network visibility.
    let sender = "import socket, time\n\
                  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
                  for _ in range(10):\n    s.sendto(b'agent-p10-watch', ('10.200.0.1', 9999)); time.sleep(0.02)\n";
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

/// The egress-enforcement exit-gate demo (`enforce-sandbox`): **kernel-enforced per-sandbox egress**. Boot a real
/// networked sandbox, arm a deny-by-default egress policy that allows exactly one endpoint, have the guest
/// send to that endpoint and to a blocked one, and show the allow-listed traffic passing while everything
/// else is dropped at the tap and recorded in the denials audit trail.
///
/// Needs `/dev/kvm`, the agent rootfs, `CAP_BPF`+`CAP_NET_ADMIN`, and the built probe object, a
/// privileged, user-run demo like `watch-sandbox`.
pub(crate) fn enforce_sandbox() -> Result<()> {
    crate::require_kvm("enforce-sandbox")?;
    if let Err(e) = agent_probes_loader::check_support() {
        bail!("enforce-sandbox needs eBPF support: {e}");
    }
    let object = agent_probes_loader::object_path();
    if !object.is_file() {
        bail!(
            "enforce-sandbox needs the built probe object ({}) — run `cargo xtask build-probes`",
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

    // Boot a networked sandbox: jailed when we're root (the confinement is the point), else the explicit
    // unjailed opt-out so the demo still runs on a dev host.
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

    // Deny-by-default egress with a single allowed endpoint: the netns host end on UDP 9999 (decision
    // 017). Everything else the guest sends is dropped at the tap and logged.
    const ALLOWED_PORT: u16 = 9999;
    const BLOCKED_PORT: u16 = 8888;
    let host_end = std::net::Ipv4Addr::new(10, 200, 0, 1);
    let policy =
        EgressPolicy::deny_all().allow_host(host_end, Some(ALLOWED_PORT), Some(Protocol::Udp));
    println!(
        "# sandbox up: booted in {} ms; enforcing egress on tap {tap} in netns {netns}",
        sandbox.boot_latency().as_millis()
    );
    println!("# policy: allow only {host_end}:{ALLOWED_PORT}/udp (deny-by-default for all else)");

    // `enforce_in_netns` arms the policy *before* the tc programs go live: no un-enforced window.
    let monitor = TapMonitor::enforce_in_netns(&netns, &tap, &policy)
        .context("attach + enforce the egress policy in the netns")?;

    // The guest sends to the allowed port and a blocked port; watch the allowed pass and the blocked drop.
    let sender = format!(
        "import socket, time\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         for _ in range(10):\n\
        \x20   s.sendto(b'allowed', ('{host_end}', {ALLOWED_PORT}))\n\
        \x20   s.sendto(b'blocked', ('{host_end}', {BLOCKED_PORT}))\n\
        \x20   time.sleep(0.02)\n"
    );
    let out = sandbox
        .exec(&["python3".into(), "-c".into(), sender], b"")
        .context("run the guest traffic generator")?;
    if out.exit_code != 0 {
        bail!(
            "guest traffic generator exited {}: {}",
            out.exit_code,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The denials audit trail: which endpoints the policy blocked.
    let denials = monitor.denials().context("read the denials map")?;
    println!("\n# denied (blocked at the tap, recorded for the audit log):");
    if denials.is_empty() {
        println!("  (none)");
    }
    for (key, count) in &denials {
        println!("  {key}  |  {count} packet(s) dropped");
    }

    // The flow counters show the allowed endpoint was seen and let through (both are counted before the
    // verdict, so a blocked flow appears here too, but only the blocked one appears under denials).
    let flows = monitor.flows().context("read the flow map")?;
    println!(
        "\n# flows seen on the tap (allowed traffic passes; blocked is counted then dropped):"
    );
    for (key, counts) in &flows {
        let verdict = if denials.iter().any(|(k, _)| k == key) {
            "DENIED"
        } else {
            "allowed"
        };
        println!(
            "  [{verdict}] {key}  |  in {} pkt / {} B",
            counts.ingress_packets, counts.ingress_bytes
        );
    }

    drop(monitor);
    sandbox.shutdown().context("shut the sandbox down")?;
    println!(
        "\n# sandbox shut down. The guest reached only its allow-listed endpoint; every other packet"
    );
    println!(
        "# was dropped at the tap by the host-side eBPF and recorded — kernel-enforced per-sandbox egress."
    );
    Ok(())
}

/// The resource-metering exit-gate demo (`meter-sandbox`): **per-sandbox resource metrics from eBPF**. Boot a
/// real sandbox, meter its cgroup with the `sched_switch` accounting probe, and show an idle guest
/// charging near-zero host CPU while a CPU-heavy guest charges most of a core, the engine *measures*,
/// the hoster *bills*. Prints the full `ResourceSummary` (CPU from eBPF, memory/IO from the kernel's
/// cgroup v2 counters) for the busy run.
///
/// Needs `/dev/kvm`, the agent rootfs, `CAP_BPF`+`CAP_PERFMON`, and the built probe object, a
/// privileged, user-run demo like `trace-sandbox`.
pub(crate) fn meter_sandbox() -> Result<()> {
    crate::require_kvm("meter-sandbox")?;
    if let Err(e) = agent_probes_loader::check_support() {
        bail!("meter-sandbox needs eBPF support: {e}");
    }
    let object = agent_probes_loader::object_path();
    if !object.is_file() {
        bail!(
            "meter-sandbox needs the built probe object ({}) — run `cargo xtask build-probes`",
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

    // Boot a sandbox on the agent rootfs (jailed as root, else the unjailed opt-out so a dev host still
    // runs it). Its VMM runs in a per-VM lifetime cgroup, the cgroup the meter attributes to.
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
            "# not root: booting unjailed (Sandbox::open_unjailed) — the accounting is the same"
        );
        Sandbox::open_unjailed(cfg).context("boot the sandbox (unjailed)")?
    };

    let vmm_pid = sandbox.vmm_pid();
    let cgroup = cgroup_id_of_pid(vmm_pid).context("resolve the sandbox's cgroup id")?;
    println!(
        "# sandbox up: VMM pid {vmm_pid}, cgroup id {cgroup}, booted in {} ms",
        sandbox.boot_latency().as_millis()
    );

    // Attach the meter and target this sandbox's cgroup (the bridge: VMM pid -> cgroup id). One
    // shared program on the global sched_switch would meter many sandboxes; here we register just one.
    let mut meter = ResourceMeter::load().context("load + attach the resource meter")?;
    meter
        .add_target(cgroup)
        .context("meter the sandbox cgroup")?;
    let window = Duration::from_millis(1500);
    let secs = window.as_secs_f64();
    // Charges post at **switch-out** (when `sched_switch` fires): a pegged vCPU's whole slice lands only
    // once the guest idles and the vCPU thread blocks, so give that chain a moment before each read.
    let settle = Duration::from_millis(300);

    // Idle: the guest sleeps, the VMM parks its vCPU, near-zero host CPU charged to the cgroup. Python
    // for both phases (same interpreter, only the workload differs), not busybox `sleep`, whose float
    // support is a build option.
    meter.reset(cgroup).context("zero the idle baseline")?;
    let idle = sandbox
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!("import time; time.sleep({secs})"),
            ],
            b"",
        )
        .context("run the idle guest command")?;
    if idle.exit_code != 0 {
        bail!("idle command exited {}", idle.exit_code);
    }
    std::thread::sleep(settle);
    let idle_cpu = meter.cpu_time(cgroup).context("read idle CPU")?;
    println!("# idle guest (time.sleep({secs})): charged {idle_cpu:?} of host CPU to the sandbox");

    // Busy: a Python loop pegs a vCPU flat out for the same wall time, the VMM's vCPU thread runs hot.
    meter.reset(cgroup).context("zero the busy baseline")?;
    let busy_src = format!(
        "import time\nend = time.monotonic() + {secs}\nwhile time.monotonic() < end:\n    pass\n"
    );
    let busy = sandbox
        .exec(&["python3".into(), "-c".into(), busy_src], b"")
        .context("run the CPU-heavy guest command")?;
    if busy.exit_code != 0 {
        bail!("busy command exited {}", busy.exit_code);
    }
    std::thread::sleep(settle);

    // The full per-run summary: CPU from the eBPF meter, memory/IO from the kernel's cgroup v2 counters.
    let summary = meter
        .summary_for_pid(vmm_pid)
        .context("assemble the resource summary")?;
    println!(
        "# busy guest (spin {secs}s): charged {:?} of host CPU to the sandbox",
        summary.cpu_time
    );
    println!("#");
    println!("# per-run ResourceSummary for this sandbox:");
    println!("#   cpu_time (eBPF sched_switch) : {:?}", summary.cpu_time);
    let cg = summary.cgroup;
    println!(
        "#   cpu.stat usage_usec (x-check): {}",
        cg.cpu_usage_usec
            .map_or("n/a".into(), |u| format!("{u} us"))
    );
    println!(
        "#   memory.current / peak        : {} / {}",
        cg.memory_current.map_or("n/a".into(), fmt_bytes),
        cg.memory_peak.map_or("n/a".into(), fmt_bytes)
    );
    println!(
        "#   io rbytes / wbytes           : {} / {}",
        cg.io_rbytes.map_or("n/a".into(), fmt_bytes),
        cg.io_wbytes.map_or("n/a".into(), fmt_bytes)
    );
    println!("#");
    if summary.cpu_time > idle_cpu {
        println!(
            "# the CPU-heavy run charged {}x the idle run — measured from the host scheduler,",
            (summary.cpu_time.as_millis().max(1) / idle_cpu.as_millis().max(1)).max(1)
        );
        println!(
            "# attributed to exactly this sandbox's cgroup. The engine measures; the hoster bills."
        );
    }

    drop(meter);
    sandbox.shutdown().context("shut the sandbox down")?;
    Ok(())
}

/// A byte count as a short human string (`B`/`KiB`/`MiB`/`GiB`), for the demo's summary lines only.
fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
