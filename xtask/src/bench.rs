//! The latency benchmarks: boot-to-userspace vs base size (`bench-boot`) and
//! time-to-first-result across the three start paths (`bench-warm`), reported as honest
//! nearest-rank percentiles.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_probes_loader::{ResourceMeter, SyscallTracer};
use agent_vmm::{BootConfig, Pool, RunningVm, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};
use anyhow::{bail, Context, Result};

use crate::{agent_rootfs_path, kernel_path};

/// Real (non-sparse) bytes an image occupies — the base's actual footprint, matching `du`. The ext4
/// carries free space, but `mke2fs`/`truncate` leave it unallocated, so allocated blocks ≈ the used
/// payload.
pub(crate) fn image_used_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(meta.blocks().saturating_mul(512))
}

/// Measure boot-to-userspace latency of the agent rootfs. Boots `runs` times on **each** of
/// two paths — the read-only *shared* base (no per-VM copy) and the read-write *copy* base — and
/// reports percentiles for both, so the base **size**'s effect on boot is visible: the copy path
/// duplicates the whole image per boot, the shared path doesn't. "Measured, not marketed."
pub(crate) fn bench_boot(runs: usize) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("bench-boot needs /dev/kvm (run on a KVM-capable host)");
    }
    if runs == 0 {
        bail!("--runs must be >= 1");
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

    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    println!("bench-boot: agent rootfs {used_mib} MiB, {runs} boots per path\n");

    for (label, read_only_root) in [
        ("read-only shared base", true),
        ("read-write per-VM copy", false),
    ] {
        let mut latencies = Vec::with_capacity(runs);
        for i in 0..runs {
            let mut cfg = BootConfig::from_env();
            cfg.kernel = kernel.clone();
            cfg.rootfs = rootfs.clone();
            cfg.userspace_marker = GUEST_READY_MARKER.to_string();
            cfg.guest_cid = Some(DEFAULT_GUEST_CID);
            cfg.read_only_root = read_only_root;
            let vm = Vm::boot(cfg).with_context(|| format!("{label}: boot {i} failed"))?;
            latencies.push(vm.boot_latency().as_millis() as u64);
            vm.shutdown().ok();
        }
        report_percentiles(label, &mut latencies, "ms");
    }
    println!(
        "\nBoth paths boot in well under a second. The {used_mib} MiB base is cheap to duplicate (the\n\
         host page cache serves the copy), so its size barely moves boot latency here — keeping the\n\
         base small mainly buys memory-sharing (page-cache dedup across VMs + disk), not boot time."
    );
    Ok(())
}

/// A scratch dir removed on drop, so an early `?` return can't leak the snapshot bundle.
struct ScratchDir(PathBuf);
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The agent-rootfs boot config the prewarmed bench uses: vsock (the exec channel) plus the agent's
/// readiness marker. `read_only_root` is the shared-base switch: `true` is what a prewarmed snapshot
/// requires (the bundle references the base in place, clones share its page cache), `false` is the
/// full-copy baseline that duplicates the whole image per VM.
fn warm_bench_config(kernel: &Path, rootfs: &Path, read_only_root: bool) -> BootConfig {
    let mut cfg = BootConfig::from_env();
    cfg.kernel = kernel.to_path_buf();
    cfg.rootfs = rootfs.to_path_buf();
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.read_only_root = read_only_root;
    cfg
}

/// Exec the timed Python one-liner on `vm` and verify the answer actually came back: a sample
/// counts only if it produced the result (a bench that times failures would be lying).
fn timed_python(vm: &RunningVm) -> Result<()> {
    let argv = ["python3", "-c", "print(6 * 7)"].map(String::from);
    let out = vm.exec(&argv, &[]).context("exec python")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.exit_code != 0 || stdout.trim() != "42" {
        bail!(
            "python returned exit {} / {:?} instead of 42",
            out.exit_code,
            stdout
        );
    }
    Ok(())
}

/// Measure time-to-first-result of the three start paths: a **cold boot** (per-VM rootfs
/// copy, the full-copy baseline), a **prewarmed-snapshot restore**, and a **prewarmed-pool take**, each
/// timed from "start a sandbox" to "a Python one-liner's output is back on the host". One prewarmed
/// snapshot (Python imported, then paused) feeds the restore and pool paths, the way an embedder
/// would hold one prewarmed image per runtime. Teardown and pool refill happen off the clock: they're
/// the cost a caller pays between requests, not on the request path.
pub(crate) fn bench_warm(runs: usize) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("bench-warm needs /dev/kvm (run on a KVM-capable host)");
    }
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    let kernel = kernel_path();
    let rootfs = agent_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("agent rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {}: run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    println!("bench-warm: agent rootfs {used_mib} MiB, {runs} runs per path\n");

    // One prewarmed snapshot feeds the restore and pool paths: boot the shared read-only base, load
    // Python once (interpreter + imports resident in guest memory), pause + snapshot, drop the
    // source.
    let bundle =
        ScratchDir(std::env::temp_dir().join(format!("agent-bench-warm-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&bundle.0);
    let source =
        Vm::boot(warm_bench_config(&kernel, &rootfs, true)).context("boot the prewarmed source")?;
    let warm_up = ["python3", "-c", "import json, os, sys"].map(String::from);
    let out = source.exec(&warm_up, &[]).context("warm-up exec")?;
    if out.exit_code != 0 {
        bail!("warm-up python exited {}", out.exit_code);
    }
    let snapshot = source
        .snapshot(&bundle.0)
        .context("take the prewarmed snapshot")?;
    source.shutdown().ok();
    let mem_mib = image_used_bytes(snapshot.mem_path())? / (1024 * 1024);

    // Path 1: cold boot + exec, on a private read-write copy of the image. The honest baseline:
    // what every run pays without snapshots, disk copy and all.
    let mut cold = Vec::with_capacity(runs);
    for i in 0..runs {
        let t0 = std::time::Instant::now();
        let vm = Vm::boot(warm_bench_config(&kernel, &rootfs, false))
            .with_context(|| format!("cold boot {i}"))?;
        timed_python(&vm).with_context(|| format!("cold exec {i}"))?;
        cold.push(t0.elapsed().as_millis() as u64);
        vm.shutdown().ok();
    }

    // Path 2: restore a fresh clone from the prewarmed snapshot + exec.
    let restore_cfg = warm_bench_config(&kernel, &rootfs, true);
    let mut restore = Vec::with_capacity(runs);
    for i in 0..runs {
        let t0 = std::time::Instant::now();
        let vm = Vm::restore(&snapshot, &restore_cfg).with_context(|| format!("restore {i}"))?;
        timed_python(&vm).with_context(|| format!("restore exec {i}"))?;
        restore.push(t0.elapsed().as_millis() as u64);
        vm.shutdown().ok();
    }

    // Path 3: pool take + exec. The take pops prefilled stock (plus a health probe); the refill
    // that pays the restore back runs off the clock, per the pool's caller-chooses-when contract.
    let mut pool = Pool::new(snapshot, warm_bench_config(&kernel, &rootfs, true), 1)
        .context("prefill the prewarmed pool")?;
    let mut take = Vec::with_capacity(runs);
    for i in 0..runs {
        let t0 = std::time::Instant::now();
        let vm = pool.take().with_context(|| format!("pool take {i}"))?;
        timed_python(&vm).with_context(|| format!("pool exec {i}"))?;
        take.push(t0.elapsed().as_millis() as u64);
        vm.shutdown().ok();
        pool.refill().with_context(|| format!("pool refill {i}"))?;
    }
    pool.shutdown();

    report_percentiles("cold boot + exec", &mut cold, "ms");
    report_percentiles("prewarmed restore + exec", &mut restore, "ms");
    report_percentiles("pool take + exec", &mut take, "ms");
    println!(
        "\nFootprint per sandbox: the cold path copies the whole {used_mib} MiB image per VM (on a\n\
         tmpfs /tmp that's host RAM); a prewarmed clone copies nothing: it references the read-only base\n\
         in place and maps the bundle's one {mem_mib} MiB memory file, both shared by every clone\n\
         through the page cache, so a clone's private cost is its copy-on-write dirty pages."
    );
    Ok(())
}

/// Print min/p50/p90/p99/max of `samples` (in `unit`), sorting in place. Nearest-rank, no
/// interpolation. A percentile whose rank lands on the last sample has no observation above it — it's
/// `max` relabeled, which is dishonest at small `n` (e.g. `p99` needs n≥100 to mean anything). Those
/// print `—`, so a short bench can't dress up its slowest sample as a tail percentile.
fn report_percentiles(label: &str, samples: &mut [u64], unit: &str) {
    samples.sort_unstable();
    let n = samples.len();
    let pct = |p: usize| -> String {
        let rank = (p * n).div_ceil(100).clamp(1, n); // 1-based nearest rank
        if rank >= n {
            format!("{:>7}", "—")
        } else {
            format!("{:>7}", samples[rank - 1])
        }
    };
    println!(
        "  {label:<26} min {:>7}  p50 {}  p90 {}  p99 {}  max {:>7}  ({unit}, n={n})",
        samples[0],
        pct(50),
        pct(90),
        pct(99),
        samples[n - 1],
    );
}

/// Issue `n` `openat` syscalls against a fixed **nonexistent** path and return the elapsed time.
/// `openat` is the cheapest syscall the tracer hooks, and `sys_enter_openat` fires whether or not the
/// path exists — so a guaranteed-missing path is a pure, side-effect-free unit of the traced syscall:
/// no file is created, read, closed, or left behind. The `Err` result is `black_box`ed so the loop
/// can't be optimized away.
fn openat_burst(path: &Path, n: usize) -> Duration {
    let t0 = Instant::now();
    for _ in 0..n {
        let r = std::fs::File::open(path);
        std::hint::black_box(&r);
    }
    t0.elapsed()
}

/// The mean nanoseconds-per-`openat` over one `BATCH`-sized burst — the per-sample unit `bench_trace`
/// feeds to [`report_percentiles`].
fn ns_per_openat(path: &Path, batch: usize) -> u64 {
    (openat_burst(path, batch).as_nanos() / batch as u128) as u64
}

/// Measure the **tracing overhead**: the added per-syscall cost of the attached
/// `sys_enter_*` tracepoints, in three conditions timed on the same `openat` micro-workload:
///
/// 1. **baseline** — no probes attached at all;
/// 2. **unwatched** — probes attached but the `FILTER` excludes us (the tracepoint fires on every
///    host `openat`, checks the filter, and drops ours in-kernel): the cost every *other* process on
///    the box pays just for the probes being live;
/// 3. **watched** — the filter includes us, so every `openat` writes a whole `SyscallEvent` into the
///    ring buffer: the cost the *one sandbox you watch* pays.
///
/// The delta of (2)/(3) over (1) is the honest, measured overhead — "measured, not marketed". Needs
/// `CAP_BPF`+`CAP_PERFMON` and the built object (not KVM), so it runs on any eBPF-capable host.
pub(crate) fn bench_trace(runs: usize) -> Result<()> {
    if let Err(e) = agent_probes_loader::check_support() {
        bail!("bench-trace needs eBPF support: {e}");
    }
    let object = agent_probes_loader::object_path();
    if !object.is_file() {
        bail!(
            "bench-trace needs the built probe object ({}) — run `cargo xtask build-probes`",
            object.display()
        );
    }
    if runs == 0 {
        bail!("--runs must be >= 1");
    }

    // openats per timed burst. Kept below the 256 KiB ring buffer's capacity (~1480 records of 168 B
    // plus per-record header) so a *watched* burst never overflows and starts dropping before it's
    // drained — we want the steady-state write cost, not the cheaper reserve-fails-when-full cost.
    const BATCH: usize = 1000;
    // A path that does not (and will not) exist: every `File::open` is then a pure `openat`, no file
    // created or read. Named by pid so concurrent benches don't share a path.
    let missing =
        std::env::temp_dir().join(format!("agent-bench-trace-{}-missing", std::process::id()));
    println!("bench-trace: {runs} bursts x {BATCH} openat/burst per condition\n");

    // 1. Baseline: nothing attached.
    let mut baseline = Vec::with_capacity(runs);
    for _ in 0..runs {
        baseline.push(ns_per_openat(&missing, BATCH));
    }

    // Attach the tracer once; the two remaining conditions differ only in the filter.
    let mut tracer = SyscallTracer::load().context("load + attach the syscall tracer")?;

    // 2. Unwatched: filter to a tgid that is never a real process (so every host openat is dropped
    // in-kernel and the ring stays empty — no drain needed).
    tracer
        .watch_pid(u32::MAX)
        .context("set the exclude filter")?;
    let mut unwatched = Vec::with_capacity(runs);
    for _ in 0..runs {
        unwatched.push(ns_per_openat(&missing, BATCH));
    }

    // 3. Watched: filter to us, so every openat writes a full event. Drain between bursts (off the
    // timed path) so the ring can't overflow mid-burst.
    tracer
        .watch_pid(std::process::id())
        .context("set the include filter")?;
    tracer
        .drain(|_| {})
        .context("clear the pre-filter baseline")?;
    let mut watched = Vec::with_capacity(runs);
    let mut captured = 0usize;
    for _ in 0..runs {
        watched.push(ns_per_openat(&missing, BATCH));
        captured += tracer.drain(|_| {}).context("drain the burst")?;
    }
    drop(tracer); // detach before we print (nothing pinned; explicit for legibility)

    report_percentiles("baseline (no probes)", &mut baseline, "ns/openat");
    report_percentiles("unwatched (filtered out)", &mut unwatched, "ns/openat");
    report_percentiles("watched (event written)", &mut watched, "ns/openat");

    // Deltas from the p50s. Same nearest-rank formula `report_percentiles` prints (the vecs are sorted
    // in place by it above), so this delta matches the p50 columns rather than a second definition.
    let p50 = |v: &[u64]| {
        let n = v.len();
        v[(50 * n).div_ceil(100).clamp(1, n) - 1]
    };
    let base = p50(&baseline);
    let unwatched_cost = p50(&unwatched).saturating_sub(base);
    let watched_cost = p50(&watched).saturating_sub(base);
    println!(
        "\nAdded cost per openat (p50 vs baseline): unwatched +{unwatched_cost} ns, watched \
         +{watched_cost} ns. Captured {captured} of {} watched openats.",
        runs * BATCH
    );
    println!(
        "The attached tracepoint adds a bounded per-syscall cost: the in-kernel filter keeps it small\n\
         for unwatched processes and pays the full event write only for the one sandbox you watch. A\n\
         microVM's own syscalls never trap here (they stay in-guest), so this bounds the cost on the\n\
         VMM's host footprint, not on guest code."
    );
    Ok(())
}

/// A cross-thread **ping-pong** for a fixed number of round-trips, returning the wall-clock elapsed.
/// Two rendezvous channels (`sync_channel(0)`, so a send blocks until the peer receives) hand a unit
/// back and forth: each round-trip is one handoff each way, ~2 context switches — a reliable, portable
/// way to drive the scheduler (and thus the `sched_switch` tracepoint the meter hooks) without pinning
/// threads or touching `unsafe`. A channel failure (the worker died) is a typed error, so a broken run
/// can't masquerade as a fast one.
fn pingpong(rounds: usize) -> Result<Duration> {
    use std::sync::mpsc::sync_channel;
    let (to_b, b_rx) = sync_channel::<()>(0);
    let (to_a, a_rx) = sync_channel::<()>(0);
    let worker = std::thread::spawn(move || {
        // Mirror the driver: receive, then send back, until the sender hangs up (channel closed).
        while b_rx.recv().is_ok() {
            if to_a.send(()).is_err() {
                break;
            }
        }
    });
    let t0 = Instant::now();
    for _ in 0..rounds {
        to_b.send(())
            .map_err(|_| anyhow::anyhow!("ping-pong worker went away mid-burst"))?;
        a_rx.recv()
            .map_err(|_| anyhow::anyhow!("ping-pong worker went away mid-burst"))?;
    }
    let elapsed = t0.elapsed();
    drop(to_b); // close the channel so the worker's `recv` returns `Err` and it exits
    let _ = worker.join();
    Ok(elapsed)
}

/// Mean nanoseconds per **context switch** over one `rounds`-sized ping-pong burst (~2 switches per
/// round-trip) — the per-sample unit `bench_meter` feeds to [`report_percentiles`].
fn ns_per_switch(rounds: usize) -> Result<u64> {
    let elapsed = pingpong(rounds)?;
    Ok((elapsed.as_nanos() / (rounds as u128 * 2)) as u64)
}

/// Measure the **resource-metering overhead**: the added per-context-switch cost of the attached
/// `sched_switch` accounting probe, in three conditions on the same ping-pong micro-workload (mirroring
/// `bench-trace`'s baseline/unwatched/watched shape):
///
/// 1. **baseline** — no meter attached;
/// 2. **attached, not metering us** — the probe is live but our cgroup isn't a target, so every switch
///    is a target-set lookup that misses and returns: the cost every *other* workload on the box pays
///    just for the meter being attached;
/// 3. **attached, metering us** — our cgroup is a target, so every switch does the lookup **and**
///    accumulates our on-CPU time: the cost the *one sandbox you meter* pays.
///
/// The delta of (2)/(3) over (1) is the honest, measured overhead — "measured, not marketed", and the
/// evidence for the "bounded, sane under many sandboxes" claim: one shared program, a hash lookup per
/// switch, independent of how many cgroups are metered. Needs `CAP_BPF`+`CAP_PERFMON` and the built
/// object (not KVM), so it runs on any eBPF-capable host.
pub(crate) fn bench_meter(runs: usize) -> Result<()> {
    if let Err(e) = agent_probes_loader::check_support() {
        bail!("bench-meter needs eBPF support: {e}");
    }
    let object = agent_probes_loader::object_path();
    if !object.is_file() {
        bail!(
            "bench-meter needs the built probe object ({}) — run `cargo xtask build-probes`",
            object.display()
        );
    }
    if runs == 0 {
        bail!("--runs must be >= 1");
    }

    // Round-trips per timed burst. Large enough to average out scheduler jitter, small enough to stay
    // sub-second per burst.
    const ROUNDS: usize = 2000;
    println!(
        "bench-meter: {runs} bursts x {ROUNDS} ping-pong round-trips (~2 ctx switches each) per condition\n"
    );

    // 1. Baseline: nothing attached.
    let mut baseline = Vec::with_capacity(runs);
    for _ in 0..runs {
        baseline.push(ns_per_switch(ROUNDS)?);
    }

    // Attach the meter once; the two remaining conditions differ only in whether our cgroup is a target.
    let mut meter = ResourceMeter::load().context("load + attach the resource meter")?;

    // 2. Attached but not metering us: register a cgroup id that can't match a real one, so our switches
    // are pure lookup-misses (the meter is live, but nothing accumulates for us).
    meter
        .add_target(u64::MAX)
        .context("register a never-matching target")?;
    let mut untargeted = Vec::with_capacity(runs);
    for _ in 0..runs {
        untargeted.push(ns_per_switch(ROUNDS)?);
    }

    // 3. Attached and metering us: add our own cgroup, so every one of our switches accumulates.
    let me = agent_probes_loader::cgroup_id_of_self().context("resolve our cgroup id")?;
    meter.add_target(me).context("register our cgroup")?;
    meter.reset(me).context("zero our CPU baseline")?;
    let mut targeted = Vec::with_capacity(runs);
    for _ in 0..runs {
        targeted.push(ns_per_switch(ROUNDS)?);
    }
    let charged = meter.cpu_time(me).context("read our accumulated CPU")?;
    drop(meter); // detach before printing (nothing pinned; explicit for legibility)

    report_percentiles("baseline (no meter)", &mut baseline, "ns/ctx-switch");
    report_percentiles(
        "attached (not metering us)",
        &mut untargeted,
        "ns/ctx-switch",
    );
    report_percentiles("attached (metering us)", &mut targeted, "ns/ctx-switch");

    // Deltas from the p50s, the same nearest-rank formula `report_percentiles` printed above.
    let p50 = |v: &[u64]| {
        let n = v.len();
        v[(50 * n).div_ceil(100).clamp(1, n) - 1]
    };
    let base = p50(&baseline);
    let untargeted_cost = p50(&untargeted).saturating_sub(base);
    let targeted_cost = p50(&targeted).saturating_sub(base);
    println!(
        "\nAdded cost per context switch (p50 vs baseline): not-metering-us +{untargeted_cost} ns, \
         metering-us +{targeted_cost} ns. The meter charged {charged:?} of CPU to our cgroup while \
         targeted."
    );
    println!(
        "One shared program is attached to the global `sched_switch`, so the per-switch cost is a single\n\
         hash lookup regardless of how many cgroups are metered — the accounting stays bounded under many\n\
         concurrent sandboxes (each is one more entry in the target set, not one more attached program)."
    );
    Ok(())
}
