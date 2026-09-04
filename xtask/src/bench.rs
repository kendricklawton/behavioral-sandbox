//! The libkrun benchmarks: what a sandbox costs to start, and what it costs to keep.
//!
//! - **Nearest-rank percentiles, never averages.** A `p99` whose rank lands on the last sample is
//!   `max` relabelled, so it prints `—` instead. A short run cannot dress its slowest sample up as
//!   a tail.
//! - **Every number carries its host and its date**, printed by the run rather than remembered by
//!   whoever pasted it somewhere.
//! - **libkrun has no snapshot surface**, so every boot is a cold boot. There is no warm path to
//!   compare against and no amortisation to hide behind: the number here is the number a user waits
//!   for, every time.
//!
//! **What cannot be measured yet.** Nothing in the tree can tell "the guest reached userspace" from
//! "the VM booted into nothing", because that needs an in-guest signal and the agent is phase 3's.
//! So the boot bench times what the *host* can see, split at the one boundary it can observe: the
//! vCPU thread appearing. The guest's own share is inside the second number, not separated from it,
//! and this file says so rather than implying a precision it does not have.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::{guest_rootfs_path, workspace_root};

/// Above this 1-minute load average a run says its absolute numbers came off a busy host. A
/// single-threaded bench contributes ~1.0 on its own, so the threshold sits above that: it flags
/// *competing* work, not the measurement itself.
const BUSY_HOST_LOADAVG: f64 = 2.0;

/// How long a VM is given to reach a running vCPU before the bench calls it a failed boot.
const BOOT_GRACE: Duration = Duration::from_secs(10);

/// The guest a footprint cohort runs: alive and idle, so what is sampled is the cost of *existing*
/// rather than the cost of doing something.
const IDLE_GUEST: &str = "sleep 3600";

/// `cargo xtask bench-boot [--runs N]`: what one sandbox costs to start.
///
/// - **to vCPU**: spawn to a running `fc_vcpu` thread. Polled, so it is a floor.
/// - **to exit**: spawn to the process ending, for a `/bin/true` workload.
///
/// Their difference is not reported: subtracting two differently-noisy series would overstate it.
pub(crate) fn bench_boot(runs: usize) -> Result<()> {
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    let ctx = BenchContext::resolve()?;
    ctx.print_header("bench-boot");
    println!(
        "  {runs} cold boots. libkrun has no snapshot surface, so every boot is a cold boot and\n\
         \x20 there is no warm path to compare against.\n"
    );

    let mut to_vcpu = Vec::with_capacity(runs);
    let mut to_exit = Vec::with_capacity(runs);
    let progress = Progress::new("cold boot", runs);
    for i in 0..runs {
        let started = Instant::now();
        let mut child = ctx.spawn_guest(&format!("bench-boot-{i}"), "true")?;
        let pid = child.id();

        // Seen, not merely waited for: the wait also ends when the process dies.
        let mut saw_vcpu = false;
        let ended = wait_until(BOOT_GRACE, || {
            if vm_is_running(pid) {
                saw_vcpu = true;
                return true;
            }
            !pid_is_live(pid)
        });
        if !ended {
            let _ = child.kill();
            let _ = child.wait();
            bail!("boot {i}: no vCPU thread within {BOOT_GRACE:?}");
        }
        if !saw_vcpu {
            let status = child.wait().context("reap the early-exiting helper")?;
            bail!(
                "boot {i}: the helper ended ({status}) before a vCPU was observed; run \
                 `bsx __vmm` by hand to see why"
            );
        }
        to_vcpu.push(started.elapsed().as_millis() as u64);

        let status = child.wait().context("wait for the guest to exit")?;
        to_exit.push(started.elapsed().as_millis() as u64);
        if !status.success() {
            bail!("boot {i}: the guest exited {status}, so this sample is not a clean boot");
        }
        progress.tick(i + 1, "");
    }
    progress.clear();

    report_percentiles("to vCPU running", &mut to_vcpu, "ms");
    report_percentiles("to guest exit", &mut to_exit, "ms");
    println!(
        "\n\"to vCPU\" is polled at {POLL_MS} ms, so it is a floor carrying that interval as noise.\n\
         \"to exit\" is the whole of a sandbox that runs `/bin/true`: spawn, libkrun setup, guest\n\
         boot, the workload, and teardown. Nothing here separates the guest's share, because the\n\
         host cannot see when userspace was reached until the agent exists (phase 3)."
    );
    Ok(())
}

/// `cargo xtask bench-footprint [--count N] [--settle-secs S]`: what a sandbox costs to keep.
///
/// - **Pss per VMM**, which splits shared pages, so summing it is the true resident cost.
/// - **The whole-host `MemAvailable` drop**, which catches what a VMM's `smaps` cannot see.
///
/// Rss sits beside Pss because the gap between them is the sharing.
pub(crate) fn bench_footprint(count: usize, settle: Duration) -> Result<()> {
    if count == 0 {
        bail!("--count must be >= 1");
    }
    let ctx = BenchContext::resolve()?;
    ctx.print_header("bench-footprint");

    // A floor the bench refuses to cross, so a large `--count` cannot drive the host into swap:
    // keep at least max(1 GiB, 5% of RAM) available.
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let mem_total = proc_kib(&meminfo, "MemTotal").context("no MemTotal in /proc/meminfo")?;
    let floor_kib = (mem_total / 20).max(1024 * 1024);
    println!(
        "  cohort of {count} idle VMs, kept alive together, {} MiB guest RAM each",
        ctx.mem_mib
    );
    println!(
        "  keeping >= {} MiB available, so this never swaps the host",
        floor_kib / 1024
    );
    println!(
        "  settling {} s after the last vCPU before sampling\n",
        settle.as_secs()
    );

    let before = mem_available_kib()?;
    let mut cohort: Vec<Child> = Vec::with_capacity(count);
    let progress = Progress::new("bringing up", count);
    for i in 0..count {
        if mem_available_kib()? < floor_kib {
            break;
        }
        let mut child = ctx.spawn_guest(&format!("bench-fp-{i}"), IDLE_GUEST)?;
        let pid = child.id();
        let mut saw_vcpu = false;
        let ended = wait_until(BOOT_GRACE, || {
            if vm_is_running(pid) {
                saw_vcpu = true;
                return true;
            }
            !pid_is_live(pid)
        });
        if !ended || !saw_vcpu {
            let _ = child.kill();
            let _ = child.wait();
            teardown(&mut cohort);
            bail!(
                "VM {i}: never reached a running vCPU (an idle guest has no reason to exit; run \
                 `bsx __vmm` by hand to see why)"
            );
        }
        cohort.push(child);
        progress.tick(cohort.len(), "");
    }
    progress.clear();

    if cohort.is_empty() {
        bail!("free memory was below the floor before the first VM came up");
    }
    if cohort.len() < count {
        println!(
            "  stopped at {} of {count} VMs (memory floor)",
            cohort.len()
        );
    }

    // A running vCPU is not a booted guest: the youngest VM is seconds behind the oldest, and
    // sampling now reads a half-booted one as its idle cost.
    std::thread::sleep(settle);

    let (mut rss_mib, mut pss_mib) = (Vec::new(), Vec::new());
    for child in &cohort {
        let (r, p) = rss_pss_kib(child.id())?;
        rss_mib.push(r / 1024);
        pss_mib.push(p / 1024);
    }
    // Signed: `MemAvailable` can rise while a cohort is up (cache reclaim, another process
    // freeing), and a saturating subtraction would clamp real noise to a fabricated zero.
    let host_drop_kib = before as i64 - mem_available_kib()? as i64;
    let n = cohort.len() as i64;
    teardown(&mut cohort);

    report_percentiles("Pss per VMM", &mut pss_mib, "MiB");
    report_percentiles("Rss per VMM", &mut rss_mib, "MiB");
    println!(
        "  {:<26} whole-host {} MiB across {n} VMs = {} KiB/VM",
        "->",
        host_drop_kib / 1024,
        host_drop_kib / n
    );
    println!(
        "\nPss splits each shared page across its sharers, so summing it is the true resident cost;\n\
         Rss counts every page in full, and the gap between the two is what the VMs share. The\n\
         whole-host figure catches what a VMM's own smaps cannot see, and is the one to trust when\n\
         they disagree."
    );
    Ok(())
}

/// The guest drawer `bench-frames` stages, from the CLI's own fixture, so the bench and the
/// end-to-end tests draw through one program.
const FLIPPER: &str = include_str!("../../crates/cli/tests/drm_flip.py");

/// `cargo xtask bench-frames --display WxH[@HZ] --frames N [--app]`: one run per path (`dirty`,
/// unpaced; `flip`, paced by the refresh rate), reporting frame intervals as the helper saw them
/// against the guest's own timing, then the process boundary and, with `--app`, the window.
pub(crate) fn bench_frames(display: &str, frames: usize, app: bool) -> Result<()> {
    if frames == 0 {
        bail!("--frames must be >= 1");
    }
    let ctx = BenchContext::resolve()?;
    ctx.print_header("bench-frames");
    println!(
        "  display {display}, {frames} frames per path. Throughput into the host process, headless:\n\
         \x20 no window and no panel, so nothing here is presentation. `dirty` is unpaced (what the\n\
         \x20 flush, the readback and the backend sustain together); `flip` waits for a vblank per\n\
         \x20 frame (what a compositor pacing to the refresh rate gets).\n"
    );
    let stage = ctx.runtime.join("frames");
    std::fs::create_dir_all(&stage)?;
    std::fs::write(stage.join("flip.py"), FLIPPER)?;
    for path in ["dirty", "flip"] {
        let log = stage.join(format!("{path}.tsv"));
        let out = Command::new(&ctx.bsx)
            .arg("run")
            .arg("--root")
            .arg(&ctx.guest_root)
            .args(["--display", display])
            .arg("--frame-log")
            .arg(&log)
            .arg("--mount")
            .arg(format!("/mnt={}", stage.display()))
            .args(["--", "python3", "/mnt/flip.py", path, &frames.to_string()])
            .env("XDG_RUNTIME_DIR", &ctx.runtime)
            .env("BSX_RUNS_DIR", ctx.runtime.join("runs"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run the {path} guest"))?;
        if !out.status.success() {
            bail!(
                "the {path} guest failed ({}):\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = |prefix: &str| {
            stdout
                .lines()
                .find(|l| l.starts_with(prefix))
                .unwrap_or("(the guest reported nothing)")
                .to_string()
        };
        let arrivals = read_frame_log(&log)?;
        println!("path {path}:");
        println!("  guest:    {}", line("FLIP setup"));
        println!("            {}", line("FLIP done"));
        report_arrivals(&arrivals, frames);
    }
    println!(
        "\n\"presented\" counts frame ids the backend handed out; \"seen\" counts the frames the\n\
         display thread got to deliver. A gap between them is frames superseded before the thread\n\
         ran, which the latest-frame design allows and a real window would also not have shown."
    );
    bench_boundary(&ctx, display, frames, &stage)?;
    if app {
        bench_app(&ctx, display, frames, &stage)?;
    }
    Ok(())
}

/// The process boundary (4.9): a second process leases the display over the control socket, maps
/// the memfd, and logs each present record as it reads it; the helper's own frame log names the
/// same frames on the same clock, and the difference per frame is what the boundary cost.
fn bench_boundary(ctx: &BenchContext, display: &str, frames: usize, stage: &Path) -> Result<()> {
    let helper_log = stage.join("boundary-helper.tsv");
    let client_log = stage.join("boundary-client.tsv");
    let mut reader = Command::new(&ctx.bsx);
    reader
        .args(["__frames", "bench-frames-boundary"])
        .arg("--log")
        .arg(&client_log);
    let read = run_through_reader(
        ctx,
        "bench-frames-boundary",
        display,
        frames,
        stage,
        &helper_log,
        reader,
    )?;
    if !read.status.success() {
        bail!(
            "the reader failed: {}",
            String::from_utf8_lossy(&read.stderr)
        );
    }
    let helper = read_frame_log(&helper_log)?;
    let client = read_frame_log(&client_log)?;
    println!("path flip, through the boundary (a second process mapping the memfd):");
    println!(
        "  helper saw {} frames, the client read {}",
        helper.len(),
        client.len()
    );
    let mut offsets = offsets_us(&client, &helper);
    report_signed("client minus helper", &mut offsets, "us");
    println!(
        "  the same frame ids on the same clock: when the second process had each frame relative\n\
         to the helper's own display thread. Negative is earlier: the record is written from\n\
         libkrun's thread under the lock, before the helper's thread has woken. This is the\n\
         boundary's whole cost; the frames themselves were never copied."
    );
    Ok(())
}

/// The application (4.10): `bsx-app` leases the display into a window, logging each present as
/// it reads it and each frame it uploads to the GPU. What reaches the screen is bounded by the
/// panel, so "uploaded" against "presented" is the number, and the upload's lag behind the helper
/// is the cost of the window.
fn bench_app(ctx: &BenchContext, display: &str, frames: usize, stage: &Path) -> Result<()> {
    let app = ctx.bsx.with_file_name("bsx-app");
    if !app.is_file() {
        bail!(
            "no release app at {} — run `cargo build --release -p bsx-app`",
            app.display()
        );
    }
    let (wayland, x11) = (
        std::env::var_os("WAYLAND_DISPLAY"),
        std::env::var_os("DISPLAY"),
    );
    if wayland.is_none() && x11.is_none() {
        println!("path flip, through bsx-app: SKIPPED (no WAYLAND_DISPLAY or DISPLAY: no window)");
        return Ok(());
    }
    let helper_log = stage.join("app-helper.tsv");
    let read_log = stage.join("app-read.tsv");
    let drawn_log = stage.join("app-drawn.tsv");
    let mut reader = Command::new(&app);
    reader
        .arg("bench-frames-app")
        .arg("--log")
        .arg(&read_log)
        .arg("--drawn-log")
        .arg(&drawn_log)
        // The notebook stays open when a lease ends; the measurement wants the exit.
        .arg("--exit-with-lease");
    // The app finds the sandbox under the bench's private runtime dir, so the compositor's socket,
    // which lives under the real one, is named by its absolute path.
    if let (Some(real), Some(socket)) = (std::env::var_os("XDG_RUNTIME_DIR"), wayland)
        && !Path::new(&socket).is_absolute()
    {
        reader.env("WAYLAND_DISPLAY", Path::new(&real).join(socket));
    }
    let ran = run_through_reader(
        ctx,
        "bench-frames-app",
        display,
        frames,
        stage,
        &helper_log,
        reader,
    )?;
    let stderr = String::from_utf8_lossy(&ran.stderr);
    if !ran.status.success() {
        bail!("bsx-app failed: {stderr}");
    }
    let helper = read_frame_log(&helper_log)?;
    let read = read_frame_log(&read_log)?;
    let drawn = read_frame_log(&drawn_log)?;
    println!("path flip, through bsx-app (iced, wgpu):");
    for line in stderr.lines().filter(|l| l.starts_with("bsx-app:")) {
        println!("  {}", line.trim_start_matches("bsx-app:").trim());
    }
    println!(
        "  helper saw {} frames, the app read {} and uploaded {}",
        helper.len(),
        read.len(),
        drawn.len()
    );
    if let Some((&(_, first), &(_, last))) = drawn.first().zip(drawn.last()) {
        let span = last.saturating_sub(first).max(1) as f64 / 1e9;
        println!(
            "  uploads: {:.1}/s over {span:.2} s (the panel's refresh rate is the ceiling)",
            drawn.len().saturating_sub(1) as f64 / span
        );
    }
    let mut read_offsets = offsets_us(&read, &helper);
    report_signed("read minus helper", &mut read_offsets, "us");
    let mut drawn_offsets = offsets_us(&drawn, &helper);
    report_signed("uploaded minus helper", &mut drawn_offsets, "us");
    let mut took: Vec<u64> = read_third_column(&drawn_log)?
        .into_iter()
        .map(|ns| ns / 1000)
        .collect();
    report_percentiles("write_texture", &mut took, "us");
    println!(
        "  \"uploaded\" is the frame's bytes queued to the GPU from the mapped slot, at the redraw\n\
         the compositor granted; the frames the app read but never uploaded were superseded before\n\
         a redraw came, which the panel's rate makes inevitable above it. \"write_texture\" is the\n\
         upload call by itself, from the mapped slot into wgpu's staging; the rest of the gap to\n\
         the helper is the wait for the redraw and iced's own frame."
    );
    Ok(())
}

/// `bsx up` with a frame log at `helper_log`, `reader` (which takes the sandbox `name`) on it,
/// the flipper through `bsx exec`, then `bsx stop`; the reader's output once it has exited, which
/// it does when the lease ends.
fn run_through_reader(
    ctx: &BenchContext,
    name: &str,
    display: &str,
    frames: usize,
    stage: &Path,
    helper_log: &Path,
    mut reader: Command,
) -> Result<std::process::Output> {
    let up = Command::new(&ctx.bsx)
        .arg("up")
        .arg("--root")
        .arg(&ctx.guest_root)
        .args(["--name", name, "--display", display])
        .arg("--frame-log")
        .arg(helper_log)
        .arg("--mount")
        .arg(format!("/mnt={}", stage.display()))
        .env("XDG_RUNTIME_DIR", &ctx.runtime)
        .env("BSX_RUNS_DIR", ctx.runtime.join("runs"))
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run bsx up for {name}"))?;
    if !up.status.success() {
        bail!("bsx up failed: {}", String::from_utf8_lossy(&up.stderr));
    }
    let stop = || {
        let _ = Command::new(&ctx.bsx)
            .args(["stop", name])
            .env("XDG_RUNTIME_DIR", &ctx.runtime)
            .env("BSX_RUNS_DIR", ctx.runtime.join("runs"))
            .output();
    };
    // No frame count: the reader ends with the lease, and a late lease misses the first frames.
    let reader = reader
        .env("XDG_RUNTIME_DIR", &ctx.runtime)
        .env("BSX_RUNS_DIR", ctx.runtime.join("runs"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run the reader for {name}"))?;
    let drew = Command::new(&ctx.bsx)
        .args([
            "exec",
            name,
            "--",
            "python3",
            "/mnt/flip.py",
            "flip",
            &frames.to_string(),
        ])
        .env("XDG_RUNTIME_DIR", &ctx.runtime)
        .env("BSX_RUNS_DIR", ctx.runtime.join("runs"))
        .stdin(Stdio::null())
        .output()
        .context("run the flipper through exec")?;
    stop();
    let read = reader.wait_with_output().context("wait for the reader")?;
    if !drew.status.success() {
        bail!(
            "the flipper failed: {}",
            String::from_utf8_lossy(&drew.stderr)
        );
    }
    Ok(read)
}

/// For each frame in `later` that `earlier` also names, `later` minus `earlier` in microseconds.
fn offsets_us(later: &[(u64, u64)], earlier: &[(u64, u64)]) -> Vec<i64> {
    later
        .iter()
        .filter_map(|(id, at)| {
            let (_, seen) = earlier.iter().find(|(h, _)| h == id)?;
            Some((i128::from(*at) - i128::from(*seen)) as i64 / 1000)
        })
        .collect()
}

/// [`report_percentiles`] for values that may be negative.
fn report_signed(label: &str, samples: &mut [i64], unit: &str) {
    samples.sort_unstable();
    let n = samples.len();
    if n == 0 {
        println!("  {label:<26} (no samples; {unit})");
        return;
    }
    let pct = |p: usize| -> String {
        let rank = (p * n).div_ceil(100).clamp(1, n);
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
        samples[n - 1]
    );
}

/// The `frame_id<TAB>nanoseconds` lines of a frame log, in file order; a third column, where a
/// log has one, is read by [`read_third_column`].
fn read_frame_log(path: &Path) -> Result<Vec<(u64, u64)>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read the frame log {}", path.display()))?;
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut cols = line.split('\t');
        let (Some(id), Some(ns)) = (cols.next(), cols.next()) else {
            bail!("frame log line without a tab: {line:?}");
        };
        rows.push((id.parse()?, ns.parse()?));
    }
    Ok(rows)
}

/// The third column of a frame log, where a line has one: the app's `--drawn-log` puts the
/// `write_texture` duration there, in nanoseconds.
fn read_third_column(path: &Path) -> Result<Vec<u64>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read the frame log {}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|line| line.split('\t').nth(2))
        .filter_map(|v| v.parse().ok())
        .collect())
}

/// Frames seen against frames presented, the arrival rate, and the arrival intervals as
/// percentiles in microseconds.
fn report_arrivals(arrivals: &[(u64, u64)], asked: usize) {
    let Some((&(first_id, first_ns), &(last_id, last_ns))) = arrivals.first().zip(arrivals.last())
    else {
        println!("  (no frames arrived)");
        return;
    };
    let seen = arrivals.len();
    let presented = last_id.saturating_sub(first_id).saturating_add(1);
    let span_ns = last_ns.saturating_sub(first_ns).max(1);
    let seen_fps = (seen.saturating_sub(1)) as f64 * 1e9 / span_ns as f64;
    let presented_fps = (presented.saturating_sub(1)) as f64 * 1e9 / span_ns as f64;
    println!(
        "  host:     presented {presented} (asked {asked}), seen {seen}, over {:.2} s: \
         {presented_fps:.1} presented/s, {seen_fps:.1} seen/s",
        span_ns as f64 / 1e9
    );
    let mut intervals: Vec<u64> = arrivals
        .windows(2)
        .map(|w| w[1].1.saturating_sub(w[0].1) / 1000)
        .collect();
    report_percentiles("arrival interval", &mut intervals, "us");
}

/// Kills and reaps a cohort. Both results are discarded: a VM that already died is no failure,
/// and a panic in cleanup would leave the rest running.
fn teardown(cohort: &mut Vec<Child>) {
    for mut child in cohort.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// How often a boot is polled for its vCPU thread. Named because it is the noise floor of the
/// "to vCPU" series, not an arbitrary sleep.
const POLL_MS: u64 = 2;

/// What every bench needs before it can measure anything: the binary under test, a guest tree, and
/// a private runtime directory so a bench's own VMs are the only ones it sees.
struct BenchContext {
    bsx: PathBuf,
    guest_root: PathBuf,
    runtime: PathBuf,
    mem_mib: u32,
}

impl BenchContext {
    /// Resolves the inputs, refusing with the command that produces each missing one.
    fn resolve() -> Result<Self> {
        // Opened, not tested: outside the `kvm` group the device exists and every boot dies.
        if let Some(why) = bsx_test_support::kvm_unusable() {
            bail!("{why}: these benchmarks boot real VMs");
        }
        // The **release** binary, deliberately: a debug build measures the wrong thing, and the old
        // suite's withdrawn numbers included a run whose profile was never recorded.
        let bsx = workspace_root().join("target/release/bsx");
        if !bsx.is_file() {
            bail!(
                "no release binary at {} — run `cargo build --release -p bsx` (a debug build \
                 measures the wrong thing)",
                bsx.display()
            );
        }
        let guest_root = guest_rootfs_path();
        if !guest_root.is_dir() {
            bail!(
                "no guest tree at {} — run `cargo xtask build-rootfs`",
                guest_root.display()
            );
        }
        let runtime = std::env::temp_dir().join(format!("bsx-bench-{}", std::process::id()));
        std::fs::create_dir_all(&runtime)
            .with_context(|| format!("create {}", runtime.display()))?;
        Ok(Self {
            bsx,
            guest_root,
            runtime,
            mem_mib: 512,
        })
    }

    /// Spawns one VM running `script` under `/bin/sh -c`, with its output discarded so a guest's
    /// writes never land in the measurement.
    fn spawn_guest(&self, name: &str, script: &str) -> Result<Child> {
        Command::new(&self.bsx)
            .args(["__vmm", "--name", name])
            .arg("--root")
            .arg(&self.guest_root)
            .args(["--mem", &self.mem_mib.to_string()])
            .args(["--exec", "/bin/sh", "--arg", "-c", "--arg", script])
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn {name}"))
    }

    /// Prints the host, the date and the conditions, so a number pasted elsewhere carries them.
    fn print_header(&self, what: &str) {
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        let cpus = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
        let mem_gib = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| proc_kib(&s, "MemTotal"))
            .map_or(0, |kib| kib / 1024 / 1024);
        let load = loadavg_1m();

        println!("{what}: libkrun {}", libkrun_version());
        println!("  host:   Linux {kernel}, {cpus} CPUs, {mem_gib} GiB RAM, load {load:.2}");
        println!("  date:   {}", today());
        println!("  guest:  {}", self.guest_root.display());
        println!(
            "  method: nearest-rank percentiles, never averages. A p99 prints `—` below n=100,"
        );
        println!("          because at that size its rank lands on the last sample and it would");
        println!("          just be `max` under another name.");
        if load > BUSY_HOST_LOADAVG {
            println!(
                "  WARNING: the host is already busy (load {load:.2}). Every absolute number below\n\
                 \x20          is inflated by whatever else is running: stop other work and re-run\n\
                 \x20          before quoting these."
            );
        }
    }
}

impl Drop for BenchContext {
    fn drop(&mut self) {
        // The runtime dir holds this run's control sockets, which outlive their helpers by design.
        let _ = std::fs::remove_dir_all(&self.runtime);
    }
}

/// The installed libkrun's version, so a number records which library produced it. `pkg-config`
/// rather than a constant, because the point is what is on *this* host.
fn libkrun_version() -> String {
    Command::new("pkg-config")
        .args(["--modversion", "libkrun"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "version unknown".into())
}

/// Today, as `YYYY-MM-DD` in UTC, from `date`. Shelled rather than computed: a bench that carried
/// its own civil-calendar arithmetic would be a second thing to get wrong, and `date` is already a
/// dependency of every other host tool here.
fn today() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "date unknown".into())
}

/// Whether `pid` has a running vCPU thread, the boundary between a started helper and a VM
/// executing guest code. Matched by libkrun's `fc_vcpu 0` name, since a thread count moves.
fn vm_is_running(pid: u32) -> bool {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    tasks.filter_map(Result::ok).any(|t| {
        std::fs::read_to_string(t.path().join("comm"))
            .is_ok_and(|c| c.trim().starts_with("fc_vcpu"))
    })
}

/// Whether `pid` is a live, non-zombie process.
fn pid_is_live(pid: u32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    !status
        .lines()
        .any(|l| l.starts_with("State:") && l.contains('Z'))
}

/// Polls `cond` every [`POLL_MS`] until it holds or `limit` runs out.
fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(POLL_MS));
    }
    cond()
}

/// A single `Key:  N kB` field from a /proc file's contents, in KiB. Exact match on the pre-colon
/// token, so a query for `Rss`/`Pss` never picks up `RssAnon` or `Pss_Anon`.
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
/// full; **Pss** splits each shared page across its sharers, so a sum of Pss over a cohort is the
/// true host footprint while a sum of Rss double-counts everything they share.
fn rss_pss_kib(pid: u32) -> Result<(u64, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .with_context(|| format!("read smaps_rollup for pid {pid} (needs Linux >= 4.14)"))?;
    let rss = proc_kib(&s, "Rss").context("no Rss in smaps_rollup")?;
    let pss = proc_kib(&s, "Pss").context("no Pss in smaps_rollup")?;
    Ok((rss, pss))
}

/// The host's 1-minute load average, or `0.0` when `/proc/loadavg` cannot be read.
fn loadavg_1m() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(0.0)
}

/// Prints min/p50/p90/p99/max of `samples`, sorting in place. Nearest-rank, no interpolation.
///
/// A percentile whose rank lands on the last sample is `max` relabelled, so it prints `—`.
fn report_percentiles(label: &str, samples: &mut [u64], unit: &str) {
    samples.sort_unstable();
    let n = samples.len();
    if n == 0 {
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

/// A one-line progress ticker on stderr, drawn only when stderr is a TTY: the report on stdout stays
/// pipe-clean and a CI log gets no carriage-return spam. Ticks land between samples, never inside
/// one, so the draw cost cannot enter a measurement.
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

    fn tick(&self, done: usize, note: &str) {
        use std::io::Write;
        if !self.tty {
            return;
        }
        let mut err = std::io::stderr();
        let _ = write!(err, "\r  {} {}/{} {note}   ", self.label, done, self.total);
        let _ = err.flush();
    }

    fn clear(&self) {
        use std::io::Write;
        if !self.tty {
            return;
        }
        let mut err = std::io::stderr();
        let _ = write!(err, "\r{:60}\r", "");
        let _ = err.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rank formula is the whole of the honesty claim, so it is pinned by example. At n=4 the
    /// p99 rank lands on the last sample, which makes it `max` under another name.
    #[test]
    fn a_percentile_with_no_sample_above_it_prints_as_absent() {
        // Nothing is asserted about stdout here; what is pinned is the rank arithmetic the printer
        // uses, which is where the dishonesty would live.
        let rank = |p: usize, n: usize| (p * n).div_ceil(100).clamp(1, n);
        assert_eq!(rank(99, 4), 4, "at n=4 the p99 rank is the last sample");
        assert_eq!(rank(99, 100), 99, "at n=100 there is one sample above p99");
        assert_eq!(rank(50, 4), 2);
        assert_eq!(rank(50, 1), 1, "a single sample is its own median");
    }

    /// `/proc` fields are matched on the whole pre-colon token, or `Rss` would read `RssAnon` and
    /// report a number that is wrong rather than missing.
    #[test]
    fn a_proc_field_matches_its_whole_key() {
        let smaps = "Rss:  1024 kB\nRssAnon:  512 kB\nPss:  700 kB\nPss_Anon:  100 kB\n";
        assert_eq!(proc_kib(smaps, "Rss"), Some(1024));
        assert_eq!(proc_kib(smaps, "Pss"), Some(700));
        assert_eq!(proc_kib(smaps, "RssAnon"), Some(512));
        assert_eq!(proc_kib(smaps, "Absent"), None);
    }

    /// The vCPU predicate has to discriminate, or every boot measurement is the poll interval. This
    /// process has no vCPU thread, which is the negative case the benches depend on.
    #[test]
    fn the_vcpu_predicate_says_no_for_a_process_that_is_not_a_vm() {
        assert!(
            !vm_is_running(std::process::id()),
            "the test runner is not a VM, and a predicate that says otherwise measures nothing"
        );
        assert!(pid_is_live(std::process::id()), "but it is alive");
        assert!(
            !vm_is_running(u32::MAX),
            "and a pid that cannot exist is not running"
        );
    }
}
