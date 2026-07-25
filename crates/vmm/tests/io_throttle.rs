//! Privileged proof that the per-drive virtio-blk bandwidth limiter (`RateLimiter::default_guest_io`)
//! actually throttles a sustained-thrashing guest, and leaves a cold boot unthrottled (P19.9c).
//!
//! The limiter is a 256 MiB/s steady cap with a 1 GiB one-time burst on every drive. Two facts shape
//! the test. A *single* write can never show the cap: the only guest-writable virtio-blk device is
//! `/output` (256 MiB, `OUTPUT_IMAGE_MIB`), which is the steady bucket's size, so one write fits it.
//! The threat the cap targets is *sustained* thrashing, so the proof is a **continuous rewrite loop**:
//! once its cumulative virtio traffic clears the 1 GiB burst, the stream pins to the 256 MiB/s cap.
//! It is self-calibrating (a short in-burst write measures this host's raw `/output` speed in the same
//! VM, so the throttle assertion needs no absolute disk model) and skips honestly on a disk too slow
//! to distinguish the cap, rather than asserting something the hardware can't show.
//!
//! `#[ignore]`d: needs `/dev/kvm` + real root + the fetched artifacts. Run via `cargo xtask ci-privileged`.
// A test binary: `panic!`/`.expect()` are the idiomatic assertion here, which the workspace's
// `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::time::Duration;

use vmm::{RunningVm, Vm};

use common::{have_jailer_privileges, jailed_overlay_config, TmpDir};

/// Run one write stream to `/output` (`iters` rewrites of a `count_mib`-MiB file, continuous so the
/// steady bucket can't refill between them) and return the host-observed rate in MiB/s. A rewrite
/// (`conv=notrunc`) keeps the file at `count_mib` MiB, so it never outgrows the 256 MiB image; the
/// `-o sync` mount forces every write through virtio, so the rate is the limiter's, not a cache's.
fn write_rate(vm: &RunningVm, label: &str, iters: u32, count_mib: u32) -> f64 {
    let script = format!(
        "for i in $(seq {iters}); do \
           dd if=/dev/zero of=/output/thrash bs=1M count={count_mib} conv=notrunc 2>/dev/null \
           || exit 1; \
         done"
    );
    let res = vm
        .exec(&["sh".into(), "-c".into(), script], b"")
        .unwrap_or_else(|e| panic!("{label} write exec failed: {e}"));
    assert_eq!(
        res.exit_code,
        0,
        "{label} write returned nonzero (out of space?); console:\n{}",
        vm.console()
    );
    let mib = f64::from(iters) * f64::from(count_mib);
    let rate = mib / res.metrics.wall.as_secs_f64();
    eprintln!(
        "io-throttle {label}: {mib:.0} MiB in {:.2}s = {rate:.0} MiB/s",
        res.metrics.wall.as_secs_f64()
    );
    rate
}

#[test]
#[ignore = "needs /dev/kvm + real root + artifacts (run via `cargo xtask ci-privileged` as root)"]
fn default_guest_io_throttles_sustained_writes_and_leaves_boot_unthrottled() {
    if !have_jailer_privileges() {
        eprintln!(
            "skipping default_guest_io_throttles_sustained_writes_and_leaves_boot_unthrottled: \
             needs real root"
        );
        return;
    }

    let output = TmpDir::new("p199c-out");
    let mut cfg = jailed_overlay_config();
    cfg.output_dir = Some(output.path().to_path_buf());
    // Sustained rewrites past the 1 GiB burst take seconds at the 256 MiB/s cap; give each exec room
    // so the throttle, not the per-exec wall, bounds the run.
    cfg.exec_wall = Duration::from_secs(180);
    let vm =
        Vm::boot(cfg).expect("jailed microVM with a writable /output should boot to readiness");

    // Boot latency unchanged: a cold boot's rootfs reads (tens of MiB) sit far inside the 1 GiB
    // one-time burst, so the limiter cannot touch them. A healthy boot of this guest is a couple of
    // seconds; a regression that throttled boot reads would blow past this ceiling.
    let boot = vm.boot_latency();
    assert!(
        boot < Duration::from_secs(15),
        "cold boot took {boot:?}, far above the healthy band: the limiter must not touch boot \
         reads (they fit the burst); console:\n{}",
        vm.console()
    );

    // Baseline: a short burst-covered stream (600 MiB < the 1 GiB burst) measures this host's raw,
    // unthrottled /output speed in the same VM, so it calibrates the throttle assertion below.
    let baseline = write_rate(&vm, "baseline", 3, 200);

    // A disk that can't clear ~500 MiB/s can't distinguish the 256 MiB/s cap from raw throughput, so
    // the proof simply can't be made on it. Skip honestly (never a flaky failure) rather than assert
    // what the hardware can't show.
    if baseline < 500.0 {
        eprintln!(
            "skipping the throttle assertion: /output baseline {baseline:.0} MiB/s is too slow to \
             distinguish the 256 MiB/s cap on this host's disk"
        );
        return;
    }

    // Drain the rest of the one-time burst: cumulative 600 + 800 = 1400 MiB clears the 1 GiB burst,
    // so the measured stream that follows is pure steady state.
    let _ = write_rate(&vm, "exhaust-burst", 4, 200);

    // The proof: a long continuous rewrite once the burst is gone must pin to the 256 MiB/s steady
    // cap, well under both this host's raw disk (baseline) and a generous ceiling around the cap.
    let throttled = write_rate(&vm, "throttled", 16, 200);

    assert!(
        throttled < 330.0,
        "sustained post-burst writes ran at {throttled:.0} MiB/s, not throttled to the ~256 MiB/s \
         cap (baseline was {baseline:.0} MiB/s); console:\n{}",
        vm.console()
    );
    assert!(
        throttled < baseline * 0.7,
        "sustained writes ({throttled:.0} MiB/s) were not clearly slower than the unthrottled \
         baseline ({baseline:.0} MiB/s), so the cap did not visibly engage"
    );
    assert!(
        throttled > 100.0,
        "sustained write rate {throttled:.0} MiB/s is implausibly low for a 256 MiB/s cap: likely \
         a broken measurement, not the limiter engaging"
    );
}
