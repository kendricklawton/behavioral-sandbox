//! The latency benchmarks: boot-to-userspace vs base size (`bench-boot`) and the three start paths'
//! latency (`bench-warm`), cold boot, snapshot restore, pre-warmed-pool take, each split into its
//! isolated start and its time-to-first-result, reported as honest nearest-rank percentiles; plus
//! `bench-density`, the memory-sharing curve (summed Rss vs Pss) as concurrent clones stack up, and
//! `bench-footprint`, the per-sandbox memory cost and how the overlay/rootfs choice moves it.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use bsx_engine::{
    BootConfig, DEFAULT_GUEST_CID, GUEST_READY_MARKER, Pool, RunningVm, Snapshot, Vm, VmmError,
};

use crate::{guest_rootfs_path, kernel_path};

/// The driver's own mountinfo parser, compiled in rather than restated: the banner names the mount
/// holding the scratch dir by the same selection rule the boot path uses, so the two cannot
/// disagree about which filesystem a run staged onto.
// The module's own rustdoc links point at items beside it in `bsx-engine`, where they resolve; a
// binary crate's doc graph does not carry them, so the links read as broken only here.
#[allow(dead_code, rustdoc::broken_intra_doc_links)]
#[path = "../../crates/engine/src/mountinfo.rs"]
mod mountinfo;

/// Real (non-sparse) bytes an image occupies, the base's actual footprint, matching `du`. The ext4
/// carries free space, but `mke2fs`/`truncate` leave it unallocated, so allocated blocks ≈ the used
/// payload.
pub(crate) fn image_used_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(meta.blocks().saturating_mul(512))
}

/// A one-line progress ticker on stderr, drawn only when stderr is a TTY: the report on stdout
/// stays pipe-clean, and a CI log gets no carriage-return spam. Ticks are placed between timed
/// samples, never inside one, so the draw cost cannot land in a measurement.
struct Progress {
    label: String,
    total: usize,
    tty: bool,
}

impl Progress {
    fn new(label: &str, total: usize) -> Self {
        use std::io::IsTerminal;
        Self {
            label: label.to_string(),
            total,
            tty: std::io::stderr().is_terminal(),
        }
    }

    /// Redraw the line: `done` of `total` complete, `note` carrying the freshest sample.
    fn tick(&self, done: usize, note: &str) {
        if !self.tty {
            return;
        }
        use std::io::Write;
        const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
        let spin = SPINNER[done % SPINNER.len()];
        let mut err = std::io::stderr();
        let _ = write!(
            err,
            "\r  {spin} {} {done}/{} {note}\x1b[K",
            self.label, self.total
        );
        let _ = err.flush();
    }

    /// Clear the line, so the next stdout print starts on a clean row.
    fn clear(&self) {
        if !self.tty {
            return;
        }
        use std::io::Write;
        let mut err = std::io::stderr();
        let _ = write!(err, "\r\x1b[K");
        let _ = err.flush();
    }
}

/// Measure boot-to-userspace latency of the guest rootfs. Boots `runs` times on **each** of
/// two paths, the read-only *shared* base (no per-VM copy) and the read-write *copy* base, and
/// reports each as three percentile rows: the wall (`Vm::boot` end to end), the guest boot
/// (InstanceStart → the userspace marker), and host staging (their per-boot difference). The two
/// paths make the base **size**'s effect visible (the copy path duplicates the whole image per
/// boot); the split makes the guest kernel's share a measurement rather than an inference.
pub(crate) fn bench_boot(runs: usize) -> Result<()> {
    crate::require_kvm("bench-boot")?;
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    let kernel = kernel_path();
    let rootfs = guest_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("guest rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {} — run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    println!("bench-boot: guest rootfs {used_mib} MiB, {runs} boots per path\n");

    let mut wall_p50s = Vec::with_capacity(2);
    let mut split_p50s = Vec::with_capacity(2);
    for (label, read_only_root) in [
        ("read-only shared base", true),
        ("read-write per-VM copy", false),
    ] {
        let mut walls = Vec::with_capacity(runs);
        let mut guests = Vec::with_capacity(runs);
        let progress = Progress::new(label, runs);
        for i in 0..runs {
            let mut cfg = BootConfig::from_env();
            cfg.kernel = kernel.clone();
            cfg.rootfs = rootfs.clone();
            cfg.userspace_marker = GUEST_READY_MARKER.to_string();
            cfg.guest_cid = Some(DEFAULT_GUEST_CID);
            cfg.read_only_root = read_only_root;
            // Two clocks per boot: the wall covers the whole `Vm::boot`, host-side staging (workdir,
            // rootfs copy, device setup) included, and `boot_latency()` covers InstanceStart → the
            // userspace marker. Reporting both splits the wall into a host share and a guest share:
            // the copy the two paths differ on shows in the wall, a guest-kernel change shows in the
            // guest. (bench-warm keeps the wall alone: its subject is what a caller waits on.)
            let t0 = Instant::now();
            let vm = Vm::boot(cfg).with_context(|| format!("{label}: boot {i} failed"))?;
            let wall = t0.elapsed().as_millis() as u64;
            let guest = vm.boot_latency().as_millis() as u64;
            walls.push(wall);
            guests.push(guest);
            vm.shutdown().ok();
            progress.tick(i + 1, &format!("(last {wall} ms)"));
        }
        progress.clear();
        // Before the reports below sort the series in place: the pairwise subtraction needs the
        // boot-order pairing, not two independently sorted columns.
        let mut staging = setup_series(&walls, &guests);
        println!("{label}:");
        report_percentiles("wall (Vm::boot)", &mut walls, "ms");
        report_percentiles("guest boot", &mut guests, "ms");
        report_percentiles("host staging", &mut staging, "ms");
        println!();
        wall_p50s.push(nearest_p50(&mut walls));
        split_p50s.push((nearest_p50(&mut guests), nearest_p50(&mut staging)));
    }
    // Derive the takeaways from the measured series instead of asserting them: the read-write
    // path's excess over the shared base *is* the per-VM copy's contribution to boot latency, and
    // the shared-base split is the number a guest-kernel change moves.
    let (shared_p50, copy_p50) = (wall_p50s[0], wall_p50s[1]);
    let copy_delta = copy_p50.saturating_sub(shared_p50);
    let (shared_guest, shared_staging) = split_p50s[0];
    println!(
        "Shared-base p50 {shared_p50} ms vs per-VM-copy p50 {copy_p50} ms: duplicating the \
         {used_mib} MiB\nbase adds ~{copy_delta} ms to boot here (the host page cache serves the \
         copy). Keeping the base\nsmall buys that boot delta plus memory-sharing (page-cache dedup \
         across VMs + disk).\nThe shared-base p50 splits into ~{shared_guest} ms guest boot and \
         ~{shared_staging} ms host staging, so a\nguest-kernel change is judged on the guest share, \
         not the wall."
    );
    Ok(())
}

/// The per-boot host-staging series, `wall − guest` pairwise: each boot's own difference, so
/// percentiles of the result describe the staging cost of a real boot. Not a difference of
/// percentiles, which nearest-rank does not preserve: the boot with the slowest wall need not be
/// the boot with the slowest guest, and rank-wise subtraction of the two sorted series would
/// reintroduce exactly that error at every rank.
fn setup_series(wall: &[u64], guest: &[u64]) -> Vec<u64> {
    wall.iter()
        .zip(guest)
        .map(|(w, g)| w.saturating_sub(*g))
        .collect()
}

/// A scratch dir removed on drop, so an early `?` return can't leak the snapshot bundle.
struct ScratchDir(PathBuf);
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The agent-rootfs boot config the prewarmed bench uses: vsock (the exec channel) plus the agent's
/// readiness marker. `read_only_root` is the shared-base switch: `true` is the pool shape the CLI
/// and CLI boot (the bundle references the base in place, clones share its page cache), `false`
/// is the full-copy baseline that duplicates the whole image per VM.
fn warm_bench_config(kernel: &Path, rootfs: &Path, read_only_root: bool) -> BootConfig {
    let mut cfg = BootConfig::from_env();
    cfg.kernel = kernel.to_path_buf();
    cfg.rootfs = rootfs.to_path_buf();
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.read_only_root = read_only_root;
    cfg
}

/// Build one prewarmed Python snapshot: boot the shared read-only base, load Python once (its
/// interpreter and imports left resident in guest memory), pause, snapshot into a fresh scratch
/// bundle, drop the source. Returns the snapshot and its bundle guard, which the caller must keep
/// alive (the snapshot maps files under the bundle). `tag` names the scratch dir. The three memory
/// benches share this identical preamble.
fn prewarm_python_snapshot(
    kernel: &Path,
    rootfs: &Path,
    tag: &str,
) -> Result<(Snapshot, ScratchDir)> {
    let bundle =
        ScratchDir(std::env::temp_dir().join(format!("bsx-bench-{tag}-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&bundle.0);
    let mut source =
        Vm::boot(warm_bench_config(kernel, rootfs, true)).context("boot the prewarmed source")?;
    let warm_up = ["python3", "-c", "import json, os, sys"].map(String::from);
    let out = source.exec(&warm_up, &[]).context("warm-up exec")?;
    if out.exit_code != 0 {
        bail!("warm-up python exited {}", out.exit_code);
    }
    let snapshot = source
        .snapshot(&bundle.0)
        .context("take the prewarmed snapshot")?;
    source.shutdown().ok();
    Ok((snapshot, bundle))
}

/// Exec the timed Python one-liner on `vm` and verify the answer actually came back: a sample
/// counts only if it produced the result (a bench that times failures would be lying).
fn timed_python(vm: &mut RunningVm) -> Result<()> {
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
    crate::require_kvm("bench-warm")?;
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    let kernel = kernel_path();
    let rootfs = guest_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("guest rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {}: run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    println!("bench-warm: guest rootfs {used_mib} MiB, {runs} runs per path\n");

    // One prewarmed snapshot feeds the restore and pool paths.
    let prep = Progress::new("building the prewarmed python snapshot", 1);
    prep.tick(0, "");
    let (snapshot, _bundle) = prewarm_python_snapshot(&kernel, &rootfs, "warm")?;
    prep.clear();
    let mem_mib = image_used_bytes(snapshot.mem_path())? / (1024 * 1024);

    // Each path splits into two per-run samples: the **start** (begin a sandbox → an exec-ready VM)
    // and the **time-to-first-result** (start + the first exec's round-trip). Reporting them apart
    // makes the three headline start latencies, cold boot, snapshot restore, pool take, visible on
    // their own, not just folded into the composite, so it is legible where a run's latency goes.

    // Path 1: cold boot, on a private read-write copy of the image. The honest baseline: what every
    // run pays without snapshots, disk copy and all.
    let mut cold_start = Vec::with_capacity(runs);
    let mut cold_result = Vec::with_capacity(runs);
    let progress = Progress::new("cold boot", runs);
    for i in 0..runs {
        let t0 = Instant::now();
        let mut vm = Vm::boot(warm_bench_config(&kernel, &rootfs, false))
            .with_context(|| format!("cold boot {i}"))?;
        cold_start.push(t0.elapsed().as_millis() as u64);
        timed_python(&mut vm).with_context(|| format!("cold exec {i}"))?;
        let ms = t0.elapsed().as_millis() as u64;
        cold_result.push(ms);
        vm.shutdown().ok();
        progress.tick(i + 1, &format!("(last {ms} ms to first result)"));
    }
    progress.clear();

    // Path 2: restore a fresh clone from the prewarmed snapshot. The start here is the snapshot
    // restore itself, bring a clone to exec-ready, the fast-start the whole snapshot machinery buys.
    let restore_cfg = warm_bench_config(&kernel, &rootfs, true);
    let mut restore_start = Vec::with_capacity(runs);
    let mut restore_result = Vec::with_capacity(runs);
    let progress = Progress::new("snapshot restore", runs);
    for i in 0..runs {
        let t0 = Instant::now();
        let mut vm =
            Vm::restore(&snapshot, &restore_cfg).with_context(|| format!("restore {i}"))?;
        restore_start.push(t0.elapsed().as_millis() as u64);
        timed_python(&mut vm).with_context(|| format!("restore exec {i}"))?;
        let ms = t0.elapsed().as_millis() as u64;
        restore_result.push(ms);
        vm.shutdown().ok();
        progress.tick(i + 1, &format!("(last {ms} ms to first result)"));
    }
    progress.clear();

    // Path 3: pool take. The start pops prefilled stock (plus a health probe); the refill that pays
    // the restore back runs off the clock, per the pool's caller-chooses-when contract, so this is
    // the latency a session actually sees on the fast path.
    let mut pool = Pool::new(snapshot, warm_bench_config(&kernel, &rootfs, true), 1)
        .context("prefill the prewarmed pool")?;
    let mut take_start = Vec::with_capacity(runs);
    let mut take_result = Vec::with_capacity(runs);
    let progress = Progress::new("pool take", runs);
    for i in 0..runs {
        let t0 = Instant::now();
        let mut vm = pool.take().with_context(|| format!("pool take {i}"))?;
        take_start.push(t0.elapsed().as_millis() as u64);
        timed_python(&mut vm).with_context(|| format!("pool exec {i}"))?;
        let ms = t0.elapsed().as_millis() as u64;
        take_result.push(ms);
        vm.shutdown().ok();
        pool.refill().with_context(|| format!("pool refill {i}"))?;
        progress.tick(i + 1, &format!("(last {ms} ms to first result)"));
    }
    progress.clear();
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
/// measured number, not a guess. Needs KVM + the built guest rootfs.
pub(crate) fn bench_density(count: usize) -> Result<()> {
    crate::require_kvm("bench-density")?;
    if count == 0 {
        bail!("--count must be >= 1");
    }
    let kernel = kernel_path();
    let rootfs = guest_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("guest rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {}: run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    // One prewarmed snapshot feeds every clone (the same read-only shared base `bench-warm` uses, so
    // a clone's marginal memory is only its copy-on-write pages).
    let (snapshot, _bundle) = prewarm_python_snapshot(&kernel, &rootfs, "density")?;
    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    let mem_mib = image_used_bytes(snapshot.mem_path())? / (1024 * 1024);

    // A memory floor the bench refuses to cross, so it can't push the host into swap/OOM: keep at
    // least max(1 GiB, 5% of RAM) available. Crossing it is a "degraded" stop, reported as one.
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let mem_total = proc_kib(&meminfo, "MemTotal").context("no MemTotal in /proc/meminfo")?;
    let floor_kib = (mem_total / 20).max(1024 * 1024);
    let start_avail = mem_available_kib()?;

    println!(
        "bench-density: guest rootfs {used_mib} MiB, snapshot mem {mem_mib} MiB, target {count} clones"
    );
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

    let progress = Progress::new("restoring clones", count);
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
        progress.tick(n, "");
        if is_checkpoint(n) {
            // The checkpoint row prints to stdout; clear the ticker so the row starts clean.
            progress.clear();
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
                // Signed: MemAvailable can rise (cache reclaim, other processes freeing) as the
                // cohort grows, so clamping the drop to 0 would fabricate a "free" row.
                (start_avail as i64 - avail as i64) / 1024,
                avail / 1024,
            );
            rows.push((n, rss, pss));
        }
    }
    progress.clear();

    // Tear every clone down (Drop guarantees it too; explicit is politer and prompt).
    for vm in clones.drain(..) {
        vm.shutdown().ok();
    }

    println!("\n{stop_reason}.");
    if let (Some(&(n0, _, p0)), Some(&(n1, r1, p1))) = (rows.first(), rows.last()) {
        if n1 > n0 {
            // Report in KiB: the per-clone copy-on-write cost is the small number this bench exists
            // to surface, and flooring it to MiB would print the interesting regime as "~0 MiB".
            let marginal = p1.saturating_sub(p0) / (n1 - n0) as u64;
            println!(
                "Marginal cost per added clone: ~{marginal} KiB Pss — its private copy-on-write pages;\n\
                 the read-only base disk and the {mem_mib} MiB snapshot memory file stay shared across\n\
                 all {n1} clones (page-cache-deduped), not copied per VM.",
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
/// 1. **cold boot, per-VM RW copy** (`read_only_root = false`), each VM gets its own read-write copy
///    of the whole rootfs image (on the scratch dir, host RAM when that's tmpfs); nothing is shared.
/// 2. **cold boot, shared RO base** (`read_only_root = true`), every VM mounts the *one* base image
///    read-only (its pages page-cache-shared across all VMs) and writes to a guest-side tmpfs overlay,
///    so the disk costs one shared copy no matter how many VMs run.
/// 3. **snapshot restore**, the shared RO base *plus* a shared, copy-on-write memory file, so a
///    clone's only private cost is the pages it dirties.
///
/// A per-VM RW copy lives in **tmpfs, outside the VMM's own address space**, so a VMM's `smaps` Pss cannot
/// see it and the honest per-sandbox cost is the whole-host `MemAvailable` drop for a cohort divided by its
/// size. This brings up `count` identical sandboxes per strategy, samples both the per-VM Pss as
/// percentiles and the whole-host drop, then tears the cohort down before the next strategy. Needs KVM and
/// the built guest rootfs.
pub(crate) fn bench_footprint(count: usize) -> Result<()> {
    crate::require_kvm("bench-footprint")?;
    if count == 0 {
        bail!("--count must be >= 1");
    }
    let kernel = kernel_path();
    let rootfs = guest_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("guest rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {}: run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    // One prewarmed snapshot feeds the restore strategy, the same shared read-only base the
    // cold-shared and restore paths use.
    let (snapshot, _bundle) = prewarm_python_snapshot(&kernel, &rootfs, "footprint")?;
    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    let mem_mib = image_used_bytes(snapshot.mem_path())? / (1024 * 1024);
    let cfg = warm_bench_config(&kernel, &rootfs, true);
    let guest_mib = cfg.mem_mib.get();

    // A memory floor the bench refuses to cross, so a large `--count` can't swap the host: keep at
    // least max(1 GiB, 5% of RAM) available. Same floor as `bench-density`.
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let mem_total = proc_kib(&meminfo, "MemTotal").context("no MemTotal in /proc/meminfo")?;
    let floor_kib = (mem_total / 20).max(1024 * 1024);

    println!(
        "bench-footprint: guest rootfs {used_mib} MiB, snapshot mem {mem_mib} MiB, guest RAM {guest_mib} MiB"
    );
    println!(
        "  cohort of {count} identical sandboxes per strategy (per-VM Pss from smaps; whole-host from MemAvailable)"
    );
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
    let progress = Progress::new(label, count);
    for i in 0..count {
        if mem_available_kib()? < floor_kib {
            break;
        }
        vms.push(spawn().with_context(|| format!("{label}: bring up sandbox {i}"))?);
        progress.tick(vms.len(), "");
    }
    progress.clear();
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
    let n = vms.len() as i64;
    // Signed host-wide delta: MemAvailable can *rise* (cache reclaim, another process freeing) while
    // the cohort is up, so a saturating_sub would clamp real noise to a fabricated "0 MiB/sandbox".
    // Report per-sandbox in KiB so a sub-MiB per-VM cost doesn't floor to "0 MiB" either.
    let host_drop_kib = before as i64 - mem_available_kib()? as i64;
    for vm in vms.drain(..) {
        vm.shutdown().ok();
    }
    report_percentiles(label, &mut pss_mib, "MiB Pss/VM");
    println!(
        "  {:<26} whole-host {} MiB for {n} sandboxes = {} KiB/sandbox (naive Rss {} KiB/VM)",
        "→",
        host_drop_kib / 1024,
        host_drop_kib / n,
        rss_sum as i64 / n,
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
    if n == 0 {
        // Safe on its own: `clamp(1, 0)` and `samples[0]` would panic. Callers guard n >= 1 today,
        // but the primitive shouldn't depend on that.
        println!("  {label:<26} (no samples; {unit})");
        return;
    }
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

/// The nearest-rank p50 of `samples`, sorting in place, sharing the rank *formula*
/// [`report_percentiles`] uses so the delta lines in `bench-trace`/`bench-meter` and the scaling
/// sweep's per-size columns don't re-derive it. Unlike the column, this always returns a concrete
/// value (a delta needs a number): it does not apply the "rank lands on the last sample → `—`"
/// display cutoff, so at `n == 1` this yields the single sample while the p50 column prints `—`.
fn nearest_p50(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    let n = samples.len();
    if n == 0 {
        return 0; // no samples: `clamp(1, 0)` would panic; a delta against 0 is the honest default.
    }
    samples[(50 * n).div_ceil(100).clamp(1, n) - 1]
}

/// Above this 1-minute load average, `bench-scale` says its absolute numbers came off a shared host.
/// A single-threaded bench contributes ~1.0 on its own, so the threshold sits above that: it flags
/// *competing* work, not the measurement itself.
const BUSY_HOST_LOADAVG: f64 = 2.0;

/// The host's 1-minute load average, or `0.0` if `/proc/loadavg` can't be read or parsed (a missing
/// reading must not fail a benchmark; it just means the note below can't be offered).
fn loadavg_1m() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
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
/// The scratch dir every KVM section stages into, and the mount holding it, for the banner: a
/// rootfs copy onto a `tmpfs` scratch is charged to host RAM rather than to a disk, so boot and
/// footprint numbers move with a mount the report must therefore name. The covering-mount rule is
/// the driver's own ([`mountinfo::covering`]), compiled in rather than restated, so the banner and
/// the boot path agree on which mount holds a path.
fn scratch_line() -> String {
    let dir = BootConfig::from_env().scratch_dir;
    let Some(text) = mountinfo::self_text() else {
        return format!("{} (mount table unreadable)", dir.display());
    };
    match mountinfo::covering(&text, &dir) {
        Some(m) => format!(
            "{} on {} ({}, {})",
            dir.display(),
            m.point.display(),
            m.fstype,
            m.options
        ),
        None => format!("{} (no covering mount)", dir.display()),
    }
}

pub(crate) fn bench_all(runs: usize) -> Result<()> {
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    // A section's skip reason: `None` = its host prerequisite is met, `Some(why)` = skip with that
    // reason. One value per prerequisite, so availability and its explanation can't drift apart.
    let kvm_skip: Option<String> = if !Path::new("/dev/kvm").exists() {
        Some("needs /dev/kvm".into())
    } else {
        // The KVM sections boot a real microVM, so they also need the pinned kernel + guest rootfs.
        // A missing build input is a *stated skip* (the suite's promise: skip what it can't run),
        // not four FAILED sections that exit the suite non-zero.
        [("kernel", kernel_path()), ("guest rootfs", guest_rootfs_path())]
            .into_iter()
            .find(|(_, p)| !p.is_file())
            .map(|(what, p)| {
                format!(
                    "missing {what} at {} (run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`)",
                    p.display()
                )
            })
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

    let load = loadavg_1m();
    println!("bench-all: the full benchmark suite, one report.");
    println!("  host: Linux {kernel_rel}, {cpus} CPUs, {mem_gib} GiB RAM, load average {load:.2}");
    println!("  scratch: {}", scratch_line());
    // Up front, not in the footer: this suite runs for many minutes, and a reader of the published
    // table has no way to tell a quiet host from a busy one after the fact. The absolute numbers are
    // the ones at risk; the back-to-back comparisons (restore vs cold boot, Pss vs Rss, probe on vs
    // off) mostly cancel a uniform tax, which is why this warns rather than refuses.
    if load > BUSY_HOST_LOADAVG {
        println!(
            "  WARNING: the host is already busy (load {load:.2}). Every absolute number below will\n\
             be inflated by whatever else is running, so this run is not publishable: stop other work\n\
             (an editor, a browser, a container runtime) and re-run before quoting these figures."
        );
    }
    println!(
        "  method: nearest-rank percentiles, never averages; a p99 prints `—` below n=100 (no sample\n\
         above it), so a short run can't pass its max off as a tail. Each section is measured against\n\
         its honest baseline (a cold boot, no probe attached, the naive Rss)."
    );
    for (what, skip) in [("KVM", &kvm_skip)] {
        match skip {
            None => println!("  {what} benches: available"),
            Some(why) => println!("  {what} benches: SKIPPED ({why})"),
        }
    }
    println!();

    // Array elements evaluate in order, so this *is* the sequential run; each entry pairs a section's
    // name with whether it came out healthy (ran clean or was skipped).
    let kvm = kvm_skip.as_deref();
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

#[cfg(test)]
mod tests {

    /// The banner must name a real mount, not fall through to one of its own error strings: a line
    /// reading "(no covering mount)" is the report failing to record the thing this exists to record.
    #[test]
    fn the_scratch_line_names_a_covering_mount() {
        let line = super::scratch_line();
        assert!(
            !line.contains("no covering mount") && !line.contains("unreadable"),
            "the scratch dir must resolve to a mount: {line}"
        );
        assert!(line.contains(" on "), "names the mount point: {line}");
        eprintln!("scratch banner: {line}");
    }

    use super::*;

    #[test]
    fn host_staging_is_split_per_boot_not_per_percentile() {
        // Boots where the slowest wall is not the slowest guest, so the pairing matters.
        let wall = [10, 20, 30];
        let guest = [9, 5, 10];
        let mut staging = setup_series(&wall, &guest);
        assert_eq!(staging, vec![1, 15, 20]);
        // The median staging cost is the median per-boot difference, not the difference of the
        // two medians (p50(wall) 20 − p50(guest) 9 = 11), which sorting each series before
        // subtracting would produce.
        assert_eq!(nearest_p50(&mut staging), 15);
    }
}
