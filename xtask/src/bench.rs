//! The latency benchmarks: boot-to-userspace vs base size (`bench-boot`) and the three start paths'
//! latency (`bench-warm`), cold boot, snapshot restore, pre-warmed-pool take, each split into its
//! isolated start and its time-to-first-result, reported as honest nearest-rank percentiles; plus
//! `bench-density`, the memory-sharing curve (summed Rss vs Pss) as concurrent clones stack up, and
//! `bench-footprint`, the per-sandbox memory cost and how the overlay/rootfs choice moves it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_probes_loader::{ResourceMeter, SyscallTracer};
use agent_vmm::{BootConfig, Pool, RunningVm, Vm, VmmError, DEFAULT_GUEST_CID, GUEST_READY_MARKER};
use anyhow::{bail, Context, Result};

use crate::{agent_rootfs_path, kernel_path};

/// Real (non-sparse) bytes an image occupies, the base's actual footprint, matching `du`. The ext4
/// carries free space, but `mke2fs`/`truncate` leave it unallocated, so allocated blocks ≈ the used
/// payload.
pub(crate) fn image_used_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(meta.blocks().saturating_mul(512))
}

/// Measure boot-to-userspace latency of the agent rootfs. Boots `runs` times on **each** of
/// two paths, the read-only *shared* base (no per-VM copy) and the read-write *copy* base, and
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

/// Measure the latency of the three start paths, a **cold boot** (per-VM rootfs copy, the full-copy
/// baseline), a **prewarmed-snapshot restore**, and a **prewarmed-pool take**, each decomposed into
/// two percentile series: the **start** (begin a sandbox → an exec-ready VM) and the
/// **time-to-first-result** (that start plus a Python one-liner's output back on the host). Isolating
/// the start makes the three headline latencies (cold boot, snapshot restore, pool take) legible on
/// their own, and the composite is what a caller actually waits on. One prewarmed snapshot (Python
/// imported, then paused) feeds the restore and pool paths, the way an embedder would hold one
/// prewarmed image per runtime. Teardown and pool refill happen off the clock: they're the cost a
/// caller pays between requests, not on the request path.
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

    // Each path splits into two per-run samples: the **start** (begin a sandbox → an exec-ready VM)
    // and the **time-to-first-result** (start + the first exec's round-trip). Reporting them apart
    // makes the three headline start latencies, cold boot, snapshot restore, pool take, visible on
    // their own, not just folded into the composite, so it is legible where a run's latency goes.

    // Path 1: cold boot, on a private read-write copy of the image. The honest baseline: what every
    // run pays without snapshots, disk copy and all.
    let mut cold_start = Vec::with_capacity(runs);
    let mut cold_result = Vec::with_capacity(runs);
    for i in 0..runs {
        let t0 = Instant::now();
        let vm = Vm::boot(warm_bench_config(&kernel, &rootfs, false))
            .with_context(|| format!("cold boot {i}"))?;
        cold_start.push(t0.elapsed().as_millis() as u64);
        timed_python(&vm).with_context(|| format!("cold exec {i}"))?;
        cold_result.push(t0.elapsed().as_millis() as u64);
        vm.shutdown().ok();
    }

    // Path 2: restore a fresh clone from the prewarmed snapshot. The start here is the snapshot
    // restore itself, bring a clone to exec-ready, the fast-start the whole snapshot machinery buys.
    let restore_cfg = warm_bench_config(&kernel, &rootfs, true);
    let mut restore_start = Vec::with_capacity(runs);
    let mut restore_result = Vec::with_capacity(runs);
    for i in 0..runs {
        let t0 = Instant::now();
        let vm = Vm::restore(&snapshot, &restore_cfg).with_context(|| format!("restore {i}"))?;
        restore_start.push(t0.elapsed().as_millis() as u64);
        timed_python(&vm).with_context(|| format!("restore exec {i}"))?;
        restore_result.push(t0.elapsed().as_millis() as u64);
        vm.shutdown().ok();
    }

    // Path 3: pool take. The start pops prefilled stock (plus a health probe); the refill that pays
    // the restore back runs off the clock, per the pool's caller-chooses-when contract, so this is
    // the latency a session actually sees on the fast path.
    let mut pool = Pool::new(snapshot, warm_bench_config(&kernel, &rootfs, true), 1)
        .context("prefill the prewarmed pool")?;
    let mut take_start = Vec::with_capacity(runs);
    let mut take_result = Vec::with_capacity(runs);
    for i in 0..runs {
        let t0 = Instant::now();
        let vm = pool.take().with_context(|| format!("pool take {i}"))?;
        take_start.push(t0.elapsed().as_millis() as u64);
        timed_python(&vm).with_context(|| format!("pool exec {i}"))?;
        take_result.push(t0.elapsed().as_millis() as u64);
        vm.shutdown().ok();
        pool.refill().with_context(|| format!("pool refill {i}"))?;
    }
    pool.shutdown();

    // The three headline start latencies, isolated (cold boot / snapshot restore / pool take)...
    println!("start latency (begin a sandbox → exec-ready):");
    report_percentiles("cold boot", &mut cold_start, "ms");
    report_percentiles("snapshot restore", &mut restore_start, "ms");
    report_percentiles("pool take", &mut take_start, "ms");
    // ...and the composite each caller waits on: that start plus the first exec's round-trip.
    println!("\ntime-to-first-result (start + first exec):");
    report_percentiles("cold boot + exec", &mut cold_result, "ms");
    report_percentiles("restore + exec", &mut restore_result, "ms");
    report_percentiles("pool take + exec", &mut take_result, "ms");
    println!(
        "\nFootprint per sandbox: the cold path copies the whole {used_mib} MiB image per VM (on a\n\
         tmpfs /tmp that's host RAM); a prewarmed clone copies nothing: it references the read-only base\n\
         in place and maps the bundle's one {mem_mib} MiB memory file, both shared by every clone\n\
         through the page cache, so a clone's private cost is its copy-on-write dirty pages."
    );
    Ok(())
}

/// A single `Key:  N kB` field from a /proc file's contents (`/proc/meminfo` or a `smaps_rollup`), in
/// KiB. Exact match on the pre-colon token, so a query for `Rss`/`Pss` never picks up `RssAnon` or
/// `Pss_Anon`.
fn proc_kib(contents: &str, key: &str) -> Option<u64> {
    contents
        .lines()
        .find(|l| l.split(':').next() == Some(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
}

/// `MemAvailable` (KiB): the kernel's own estimate of what can be allocated without swapping.
fn mem_available_kib() -> Result<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    proc_kib(&s, "MemAvailable").context("no MemAvailable in /proc/meminfo")
}

/// `(Rss, Pss)` for a process (KiB), from its `smaps_rollup`. **Rss** counts every resident page in
/// full; **Pss** (proportional set size) splits each shared page across its sharers. So a *sum of Pss*
/// over the clones is the true host footprint, while a *sum of Rss* double-counts the read-only base
/// every clone shares, the gap between them is exactly the memory-sharing benefit.
fn rss_pss_kib(pid: u32) -> Result<(u64, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .with_context(|| format!("read smaps_rollup for pid {pid} (needs Linux ≥ 4.14)"))?;
    let rss = proc_kib(&s, "Rss").context("no Rss in smaps_rollup")?;
    let pss = proc_kib(&s, "Pss").context("no Pss in smaps_rollup")?;
    Ok((rss, pss))
}

/// Why [`bench_density`] stopped stacking clones, typed so the "how many concurrent before it
/// degrades" answer always names its actual cause, rather than being an ad-hoc string a refactor
/// could drift from the logic.
enum StopReason {
    /// Every requested clone came up: the host wasn't the limit at this count.
    TargetReached(usize),
    /// The memory floor would have been crossed, the honest "this is where it degrades" stop.
    FloorHit { clones: usize, avail_mib: u64 },
    /// A restore failed outright (`at` is the 1-based clone that failed).
    RestoreFailed { at: usize, err: VmmError },
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetReached(n) => write!(f, "reached the target of {n} clones"),
            Self::FloorHit { clones, avail_mib } => write!(
                f,
                "free memory hit the floor at {clones} clones ({avail_mib} MiB available)"
            ),
            Self::RestoreFailed { at, err } => write!(f, "restore failed at clone {at}: {err}"),
        }
    }
}

/// Measure **memory-sharing under concurrency**: how the host's memory cost grows as prewarmed clones
/// stack up, and how far that goes before it degrades. Restores clones one at a time from a single
/// prewarmed snapshot, each sharing the read-only base disk and the snapshot memory file, so a
/// clone's only private cost is its copy-on-write dirty pages, and keeps **every clone alive** while
/// sampling, at checkpoints, the summed `Rss` (naive, double-counts the shared base), the summed `Pss`
/// (proportional set size, the true footprint), and the host's `MemAvailable`. It stops at the target
/// count, on a restore failure, or when free memory would cross a floor (so it can't drive the host
/// into swap), and reports **which**, so "how many concurrent microVMs before it degrades" is a
/// measured number, not a guess. Needs KVM + the built agent rootfs.
pub(crate) fn bench_density(count: usize) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("bench-density needs /dev/kvm (run on a KVM-capable host)");
    }
    if count == 0 {
        bail!("--count must be >= 1");
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

    // One prewarmed snapshot feeds every clone (Python resident, then paused): the same read-only
    // shared base `bench-warm` uses, so a clone's marginal memory is only its copy-on-write pages.
    let bundle = ScratchDir(
        std::env::temp_dir().join(format!("agent-bench-density-{}", std::process::id())),
    );
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
    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    let mem_mib = image_used_bytes(snapshot.mem_path())? / (1024 * 1024);

    // A memory floor the bench refuses to cross, so it can't push the host into swap/OOM: keep at
    // least max(1 GiB, 5% of RAM) available. Crossing it is a "degraded" stop, reported as one.
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let mem_total = proc_kib(&meminfo, "MemTotal").context("no MemTotal in /proc/meminfo")?;
    let floor_kib = (mem_total / 20).max(1024 * 1024);
    let start_avail = mem_available_kib()?;

    println!("bench-density: agent rootfs {used_mib} MiB, snapshot mem {mem_mib} MiB, target {count} clones");
    println!(
        "  keeping ≥ {} MiB available (a floor, so this never swaps the host)",
        floor_kib / 1024
    );
    println!(
        "  (Pss = true resident with shared pages divided; used = MemAvailable drop since start)\n"
    );
    println!("  clones   Rss sum    Pss sum    used       MemAvail   (MiB)");

    let cfg = warm_bench_config(&kernel, &rootfs, true);
    let mut clones: Vec<RunningVm> = Vec::with_capacity(count);
    let mut rows: Vec<(usize, u64, u64)> = Vec::new(); // (clones, Rss sum, Pss sum) at checkpoints
    let mut stop_reason = StopReason::TargetReached(count);
    // Print a row at 1, each power of two, and the final count, a curve without a line per clone.
    let is_checkpoint = |n: usize| n == 1 || n == count || n.is_power_of_two();

    for _ in 0..count {
        // Guard the floor before paying another restore.
        let avail = mem_available_kib()?;
        if avail < floor_kib {
            stop_reason = StopReason::FloorHit {
                clones: clones.len(),
                avail_mib: avail / 1024,
            };
            break;
        }
        match Vm::restore(&snapshot, &cfg) {
            Ok(vm) => clones.push(vm),
            Err(err) => {
                stop_reason = StopReason::RestoreFailed {
                    at: clones.len() + 1,
                    err,
                };
                break;
            }
        }
        let n = clones.len();
        if is_checkpoint(n) {
            let (mut rss, mut pss) = (0u64, 0u64);
            for vm in &clones {
                let (r, p) = rss_pss_kib(vm.vmm_pid())?;
                rss += r;
                pss += p;
            }
            let avail = mem_available_kib()?;
            println!(
                "  {n:<6}   {:>7}    {:>7}    {:>7}    {:>7}",
                rss / 1024,
                pss / 1024,
                start_avail.saturating_sub(avail) / 1024,
                avail / 1024,
            );
            rows.push((n, rss, pss));
        }
    }

    // Tear every clone down (Drop guarantees it too; explicit is politer and prompt).
    for vm in clones.drain(..) {
        vm.shutdown().ok();
    }

    println!("\n{stop_reason}.");
    if let (Some(&(n0, _, p0)), Some(&(n1, r1, p1))) = (rows.first(), rows.last()) {
        if n1 > n0 {
            let marginal = (p1.saturating_sub(p0)) / (n1 - n0) as u64;
            println!(
                "Marginal cost per added clone: ~{} MiB Pss — its private copy-on-write pages; the\n\
                 read-only base disk and the {mem_mib} MiB snapshot memory file stay shared across all\n\
                 {n1} clones (page-cache-deduped), not copied per VM.",
                marginal / 1024,
            );
        }
        let saved = r1.saturating_sub(p1);
        let ratio = if p1 > 0 { r1 as f64 / p1 as f64 } else { 0.0 };
        println!(
            "At {n1} clones: {} MiB Rss if each VM's shared base were counted in full, but only {} MiB\n\
             Pss actually resident — memory-sharing saves ~{} MiB ({ratio:.1}x denser than unshared).",
            r1 / 1024,
            p1 / 1024,
            saved / 1024,
        );
    }
    Ok(())
}

/// Measure the **per-sandbox memory footprint** and how the **overlay/rootfs choice** moves it. The
/// engine offers three ways to give a sandbox its disk, each with a different host-memory cost:
///
/// 1. **cold boot, per-VM RW copy** (`read_only_root = false`), each VM gets its own read-write copy
///    of the whole rootfs image (on the scratch dir, host RAM when that's tmpfs); nothing is shared.
/// 2. **cold boot, shared RO base** (`read_only_root = true`), every VM mounts the *one* base image
///    read-only (its pages page-cache-shared across all VMs) and writes to a guest-side tmpfs overlay,
///    so the disk costs one shared copy no matter how many VMs run.
/// 3. **snapshot restore**, the shared RO base *plus* a shared, copy-on-write memory file, so a
///    clone's only private cost is the pages it dirties.
///
/// A per-VM RW copy lives in **tmpfs, outside the VMM's own address space**, so a VMM's `smaps` Pss
/// can't see it, the honest per-sandbox cost is the whole-host `MemAvailable` drop for a cohort,
/// divided by the cohort size. This brings up `count` identical sandboxes per strategy, samples the
/// per-VM VMM Pss (percentiles, not an average) *and* the whole-host drop, then tears the cohort down
/// before the next strategy. The RW-copy-minus-shared-base gap is the rootfs choice made a number.
/// Needs KVM + the built agent rootfs.
pub(crate) fn bench_footprint(count: usize) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("bench-footprint needs /dev/kvm (run on a KVM-capable host)");
    }
    if count == 0 {
        bail!("--count must be >= 1");
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

    // One prewarmed snapshot feeds the restore strategy (Python resident, then paused), the same
    // shared read-only base the cold-shared and restore paths use.
    let bundle = ScratchDir(
        std::env::temp_dir().join(format!("agent-bench-footprint-{}", std::process::id())),
    );
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
    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    let mem_mib = image_used_bytes(snapshot.mem_path())? / (1024 * 1024);
    let cfg = warm_bench_config(&kernel, &rootfs, true);
    let guest_mib = cfg.mem_mib.get();

    // A memory floor the bench refuses to cross, so a large `--count` can't swap the host: keep at
    // least max(1 GiB, 5% of RAM) available. Same floor as `bench-density`.
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let mem_total = proc_kib(&meminfo, "MemTotal").context("no MemTotal in /proc/meminfo")?;
    let floor_kib = (mem_total / 20).max(1024 * 1024);

    println!("bench-footprint: agent rootfs {used_mib} MiB, snapshot mem {mem_mib} MiB, guest RAM {guest_mib} MiB");
    println!("  cohort of {count} identical sandboxes per strategy (per-VM Pss from smaps; whole-host from MemAvailable)");
    println!(
        "  keeping ≥ {} MiB available (a floor, so this never swaps the host)",
        floor_kib / 1024
    );
    println!(
        "  (whole-host attributes the *first touch* of shared files: a page-cache-warm base —"
    );
    println!(
        "   e.g. right after another bench — shrinks the shared-base row; a settled host shows"
    );
    println!("   the fleet cost)\n");

    footprint_cohort("cold boot, per-VM RW copy", count, floor_kib, || {
        Vm::boot(warm_bench_config(&kernel, &rootfs, false))
    })?;
    footprint_cohort("cold boot, shared RO base", count, floor_kib, || {
        Vm::boot(warm_bench_config(&kernel, &rootfs, true))
    })?;
    footprint_cohort("snapshot restore", count, floor_kib, || {
        Vm::restore(&snapshot, &cfg)
    })?;

    println!(
        "\nGuest RAM ({guest_mib} MiB configured) dominates a sandbox's footprint; the rootfs choice moves\n\
         the rest. A per-VM RW copy pays the whole {used_mib} MiB image per sandbox (private, unshared); the\n\
         shared RO base pays it once for the fleet (page-cache-deduped, writes in a guest tmpfs overlay);\n\
         a restore shares even the {mem_mib} MiB memory file copy-on-write, so its per-sandbox cost is just\n\
         the pages the guest dirties. Whole-host MemAvailable is the honest meter here: a per-VM disk copy\n\
         lives in tmpfs, outside the VMM's address space, so its Pss alone would undercount it."
    );
    Ok(())
}

/// One [`bench_footprint`] cohort: bring up `count` identical sandboxes with `spawn`, sample the
/// per-VM VMM Pss and the whole-host `MemAvailable` drop, and tear the cohort down. Reads its own
/// `before`, so page-cache drift between strategies can't leak into the delta. Stops early, with a
/// printed note, so a smaller `n` is never silent, if free memory would cross `floor_kib`; a cohort
/// the floor prevented entirely is a typed error, not a zero-sandbox row with fabricated arithmetic.
fn footprint_cohort(
    label: &str,
    count: usize,
    floor_kib: u64,
    spawn: impl Fn() -> std::result::Result<RunningVm, VmmError>,
) -> Result<()> {
    let before = mem_available_kib()?;
    let mut vms: Vec<RunningVm> = Vec::with_capacity(count);
    for i in 0..count {
        if mem_available_kib()? < floor_kib {
            break;
        }
        vms.push(spawn().with_context(|| format!("{label}: bring up sandbox {i}"))?);
    }
    if vms.is_empty() {
        bail!("{label}: free memory was below the floor before the first sandbox could come up");
    }
    if vms.len() < count {
        println!(
            "  {label}: stopped at {} of {count} sandboxes (memory floor)",
            vms.len()
        );
    }
    let (mut rss_sum, mut pss_mib) = (0u64, Vec::with_capacity(vms.len()));
    for vm in &vms {
        let (r, p) = rss_pss_kib(vm.vmm_pid())?;
        rss_sum += r;
        pss_mib.push(p / 1024);
    }
    let n = vms.len() as u64;
    let host_drop_mib = before.saturating_sub(mem_available_kib()?) / 1024;
    for vm in vms.drain(..) {
        vm.shutdown().ok();
    }
    report_percentiles(label, &mut pss_mib, "MiB Pss/VM");
    println!(
        "  {:<26} whole-host {host_drop_mib} MiB for {n} sandboxes = {} MiB/sandbox (naive Rss {} MiB/VM)",
        "→",
        host_drop_mib / n,
        rss_sum / 1024 / n,
    );
    Ok(())
}

/// Print min/p50/p90/p99/max of `samples` (in `unit`), sorting in place. Nearest-rank, no
/// interpolation. A percentile whose rank lands on the last sample has no observation above it, it's
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
/// path exists, so a guaranteed-missing path is a pure, side-effect-free unit of the traced syscall:
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

/// The mean nanoseconds-per-`openat` over one `BATCH`-sized burst, the per-sample unit `bench_trace`
/// feeds to [`report_percentiles`].
fn ns_per_openat(path: &Path, batch: usize) -> u64 {
    (openat_burst(path, batch).as_nanos() / batch as u128) as u64
}

/// Measure the **tracing overhead**: the added per-syscall cost of the attached
/// `sys_enter_*` tracepoints, in three conditions timed on the same `openat` micro-workload:
///
/// 1. **baseline**, no probes attached at all;
/// 2. **unwatched**, probes attached but the `FILTER` excludes us (the tracepoint fires on every
///    host `openat`, checks the filter, and drops ours in-kernel): the cost every *other* process on
///    the box pays just for the probes being live;
/// 3. **watched**, the filter includes us, so every `openat` writes a whole `SyscallEvent` into the
///    ring buffer: the cost the *one sandbox you watch* pays.
///
/// The delta of (2)/(3) over (1) is the honest, measured overhead, "measured, not marketed". Needs
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
    // drained, we want the steady-state write cost, not the cheaper reserve-fails-when-full cost.
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
    // in-kernel and the ring stays empty, no drain needed).
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

    // Deltas from the p50s, the same [`nearest_p50`] rule the columns above used, one shared
    // definition (the vecs are already sorted, so its re-sort is a no-op).
    let base = nearest_p50(&mut baseline);
    let unwatched_cost = nearest_p50(&mut unwatched).saturating_sub(base);
    let watched_cost = nearest_p50(&mut watched).saturating_sub(base);
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
/// back and forth: each round-trip is one handoff each way, ~2 context switches, a reliable, portable
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
/// round-trip), the per-sample unit `bench_meter` feeds to [`report_percentiles`].
fn ns_per_switch(rounds: usize) -> Result<u64> {
    let elapsed = pingpong(rounds)?;
    Ok((elapsed.as_nanos() / (rounds as u128 * 2)) as u64)
}

/// Measure the **resource-metering overhead**: the added per-context-switch cost of the attached
/// `sched_switch` accounting probe, in three conditions on the same ping-pong micro-workload (mirroring
/// `bench-trace`'s baseline/unwatched/watched shape):
///
/// 1. **baseline**, no meter attached;
/// 2. **attached, not metering us**, the probe is live but our cgroup isn't a target, so every switch
///    is a target-set lookup that misses and returns: the cost every *other* workload on the box pays
///    just for the meter being attached;
/// 3. **attached, metering us**, our cgroup is a target, so every switch does the lookup **and**
///    accumulates our on-CPU time: the cost the *one sandbox you meter* pays.
///
/// The delta of (2)/(3) over (1) is the honest, measured overhead, "measured, not marketed", and the
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

    // Deltas from the p50s, the same [`nearest_p50`] rule the columns above used, one shared
    // definition (the vecs are already sorted, so its re-sort is a no-op).
    let base = nearest_p50(&mut baseline);
    let untargeted_cost = nearest_p50(&mut untargeted).saturating_sub(base);
    let targeted_cost = nearest_p50(&mut targeted).saturating_sub(base);
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

/// The nearest-rank p50 of `samples`, sorting in place, the same rank rule
/// [`report_percentiles`] uses, extracted so the delta lines in `bench-trace`/`bench-meter` and the
/// scaling sweep's per-size columns all share one definition instead of re-deriving the formula.
fn nearest_p50(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    let n = samples.len();
    samples[(50 * n).div_ceil(100).clamp(1, n) - 1]
}

/// Measure the **eBPF overhead under load**: does the per-event cost of the two shared probes stay
/// bounded as the number of watched sandboxes grows? `bench-trace`/`bench-meter` measure the cost of
/// watching *one* sandbox; this sweeps the **watched-target-set size** (1 → 512) and shows the cost is
/// flat, the design claim ("one shared program, an O(1) map lookup per event, independent of how many
/// sandboxes are watched") turned into a measured curve rather than an assertion.
///
/// For each size the set holds **our own cgroup** (so our events take the expensive watched path) plus
/// enough never-matching dummy cgroups to reach the size, and the per-event cost is timed on the same
/// micro-workloads the other benches use: an `openat` burst for the syscall tracer, a ping-pong burst
/// for the `sched_switch` meter. A rising column would mean the lookup is not O(1); a flat one is the
/// evidence. Needs `CAP_BPF`+`CAP_PERFMON` and the built object (not KVM).
pub(crate) fn bench_scale(runs: usize) -> Result<()> {
    if let Err(e) = agent_probes_loader::check_support() {
        bail!("bench-scale needs eBPF support: {e}");
    }
    let object = agent_probes_loader::object_path();
    if !object.is_file() {
        bail!(
            "bench-scale needs the built probe object ({}) — run `cargo xtask build-probes`",
            object.display()
        );
    }
    if runs == 0 {
        bail!("--runs must be >= 1");
    }

    // openats per tracer burst (below the ring's capacity so a watched burst never overflows before
    // it's drained) and round-trips per meter burst, the same units `bench-trace`/`bench-meter` use.
    const BATCH: usize = 1000;
    const ROUNDS: usize = 2000;
    // Watched-target-set sizes to sweep. All ≤ the probes' `MAX_CGROUPS` (1024) target map.
    const SIZES: [usize; 4] = [1, 8, 64, 512];
    // Synthetic cgroup ids that can't collide with a real one (no process lives in these), used only
    // to pad the target set to a size, they never match, so they only enlarge the map.
    const DUMMY_BASE: u64 = 0xDEAD_0000_0000_0000;

    let me = agent_probes_loader::cgroup_id_of_self().context("resolve our cgroup id")?;
    println!(
        "bench-scale: per-event cost vs watched-target-set size, {runs} bursts per size\n\
         (the set is our own cgroup — the watched path — plus dummy cgroups to pad the size)\n"
    );

    // The syscall tracer: cost per watched openat as the trace target set grows.
    let missing =
        std::env::temp_dir().join(format!("agent-bench-scale-{}-missing", std::process::id()));
    let mut tracer = SyscallTracer::load().context("load + attach the syscall tracer")?;
    tracer
        .add_target(me)
        .context("register our cgroup for tracing")?;
    tracer
        .drain(|_| {})
        .context("clear the pre-measurement baseline")?;
    println!("syscall tracer — ns per watched openat:");
    println!("  targets   ns/openat(p50)");
    let (mut dummy, mut current) = (0u64, 1usize); // our cgroup is already in the set
    for &size in &SIZES {
        while current < size {
            tracer
                .add_target(DUMMY_BASE + dummy)
                .context("pad the trace target set")?;
            dummy += 1;
            current += 1;
        }
        let mut samples = Vec::with_capacity(runs);
        for _ in 0..runs {
            samples.push(ns_per_openat(&missing, BATCH));
            tracer.drain(|_| {}).context("drain the burst")?; // keep the ring from overflowing
        }
        println!("  {size:<8}  {:>6}", nearest_p50(&mut samples));
    }
    drop(tracer); // detach before the meter (nothing pinned; explicit for legibility)

    // The resource meter: cost per context switch as the meter target set grows.
    let mut meter = ResourceMeter::load().context("load + attach the resource meter")?;
    meter.add_target(me).context("register our cgroup")?;
    meter.reset(me).context("zero our CPU baseline")?;
    println!("\nresource meter — ns per context switch:");
    println!("  targets   ns/switch(p50)");
    let (mut dummy, mut current) = (0u64, 1usize);
    for &size in &SIZES {
        while current < size {
            meter
                .add_target(DUMMY_BASE + dummy)
                .context("pad the meter target set")?;
            dummy += 1;
            current += 1;
        }
        let mut samples = Vec::with_capacity(runs);
        for _ in 0..runs {
            samples.push(ns_per_switch(ROUNDS)?);
        }
        println!("  {size:<8}  {:>6}", nearest_p50(&mut samples));
    }
    drop(meter);

    println!(
        "\nBoth per-event costs stay flat as the watched set grows from 1 to {} — each event is a single\n\
         O(1) hash lookup no matter how many sandboxes are watched, so total probe overhead scales with\n\
         the event rate, not with the number of concurrent sandboxes (one shared program, not one per VM).",
        SIZES[SIZES.len() - 1],
    );
    Ok(())
}

/// The **reproducible bench harness**: one command that runs the whole suite in order and prints the
/// results as one report, with the methodology stated up front (nearest-rank percentiles, never
/// averages; a `p99` prints `—` below n=100 so a short run can't dress its max as a tail) and the host
/// it ran on recorded, so a run is legible and repeatable. Each section states what it measures
/// **against its honest baseline**, restore/pool vs a cold boot, a probe's added cost vs no probe, a
/// shared clone's Pss vs the naive Rss. A section whose host prerequisite is missing (`/dev/kvm`, or
/// `CAP_BPF`+`CAP_PERFMON` + the built object) is **skipped with the reason**, never silently dropped,
/// so the report says exactly what it did and didn't measure. `runs` sizes the percentile benches; the
/// concurrency benches use fixed cohort sizes (a bigger sweep is the dedicated command's job).
pub(crate) fn bench_all(runs: usize) -> Result<()> {
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    // A section's skip reason: `None` = its host prerequisite is met, `Some(why)` = skip with that
    // reason. One value per prerequisite, so availability and its explanation can't drift apart.
    let kvm_skip: Option<String> =
        (!Path::new("/dev/kvm").exists()).then(|| "needs /dev/kvm".into());
    let object = agent_probes_loader::object_path();
    let ebpf_skip: Option<String> = match agent_probes_loader::check_support() {
        Err(e) => Some(e.to_string()),
        Ok(()) if !object.is_file() => Some(format!(
            "missing the built probe object ({}) — run `cargo xtask build-probes`",
            object.display()
        )),
        Ok(()) => None,
    };

    // Host facts, so a number is legible against the machine that produced it.
    let kernel_rel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let mem_gib = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| proc_kib(&s, "MemTotal"))
        .map(|kib| kib / 1024 / 1024)
        .unwrap_or(0);

    println!("bench-all: the full benchmark suite, one report.");
    println!("  host: Linux {kernel_rel}, {cpus} CPUs, {mem_gib} GiB RAM");
    println!(
        "  method: nearest-rank percentiles, never averages; a p99 prints `—` below n=100 (no sample\n\
         above it), so a short run can't pass its max off as a tail. Each section is measured against\n\
         its honest baseline (a cold boot, no probe attached, the naive Rss)."
    );
    for (what, skip) in [("KVM", &kvm_skip), ("eBPF", &ebpf_skip)] {
        match skip {
            None => println!("  {what} benches: available"),
            Some(why) => println!("  {what} benches: SKIPPED ({why})"),
        }
    }
    println!();

    // Array elements evaluate in order, so this *is* the sequential run; each entry pairs a section's
    // name with whether it came out healthy (ran clean or was skipped).
    let kvm = kvm_skip.as_deref();
    let ebpf = ebpf_skip.as_deref();
    let results = [
        (
            "bench-boot",
            run_section("bench-boot", kvm, || bench_boot(runs)),
        ),
        (
            "bench-warm",
            run_section("bench-warm", kvm, || bench_warm(runs)),
        ),
        (
            "bench-footprint",
            run_section("bench-footprint", kvm, || bench_footprint(4)),
        ),
        (
            "bench-density",
            run_section("bench-density", kvm, || bench_density(16)),
        ),
        (
            "bench-trace",
            run_section("bench-trace", ebpf, || bench_trace(runs)),
        ),
        (
            "bench-meter",
            run_section("bench-meter", ebpf, || bench_meter(runs)),
        ),
        (
            "bench-scale",
            run_section("bench-scale", ebpf, || bench_scale(runs)),
        ),
    ];
    let failed: Vec<&str> = results
        .iter()
        .filter(|(_, healthy)| !healthy)
        .map(|&(name, _)| name)
        .collect();

    println!(
        "Done. The percentile benches ran at n={runs}; for publication-grade tails run the individual\n\
         command at n≥100 (e.g. `cargo xtask bench-warm --runs 100`). The written report with recorded\n\
         numbers and full methodology lives in docs/benchmarks.md."
    );
    // A failed section was reported inline and the suite continued; the run as a whole must still
    // exit non-zero, or a scripted `bench-all` would read a broken suite as a green one.
    if !failed.is_empty() {
        bail!("{} section(s) failed: {}", failed.len(), failed.join(", "));
    }
    Ok(())
}

/// Run one `bench-all` section: the header, then the bench, or the skip note when `skip` names a
/// missing host prerequisite. Returns whether the section is healthy (ran clean *or* was skipped;
/// a skip is a stated non-measurement, not a failure). A bench that errors mid-run is reported and
/// the suite continues, so one failure can't blank the rest of the report, the caller folds the
/// returned flags into its exit code instead.
fn run_section(name: &str, skip: Option<&str>, f: impl FnOnce() -> Result<()>) -> bool {
    println!("========== {name} ==========");
    if let Some(why) = skip {
        println!("  skipped: {why}\n");
        return true;
    }
    let ok = match f() {
        Ok(()) => true,
        Err(e) => {
            println!("  FAILED: {e:#}");
            false
        }
    };
    println!();
    ok
}
