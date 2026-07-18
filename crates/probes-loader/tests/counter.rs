//! Privileged integration tests for the eBPF `execve` counter (attach+read, lifetime,
//! counter-moves).
//!
//! `#[ignore]`d: loading eBPF needs `CAP_BPF`+`CAP_PERFMON` (or root), a BTF-capable kernel, and the
//! built object (`cargo xtask build-probes`). Run them via `cargo xtask ci-privileged` (as root), or
//! grant the two caps to the test binary and run it unprivileged:
//! `cargo test -p agent-probes-loader --test counter --no-run` then
//! `sudo setcap cap_bpf,cap_perfmon+ep <binary>` then `<binary> --ignored`. Each self-skips
//! when its prerequisites are absent, so an unprivileged run reports a clean skip, not a failure.
#![allow(clippy::panic)]

use std::process::Command;

use agent_probes_loader::{check_support, object_path, ExecveCounter};

/// Whether this host can actually load the probe, as a skip reason (`Some`) when it can't, so each
/// test prints *why* it skipped. Capability-aware: `check_support` passes under
/// `CAP_BPF`+`CAP_PERFMON`, not just full root, and names the missing BTF/caps legibly; the
/// built object is the remaining prerequisite.
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
#[ignore = "needs /dev/kvm-class privilege (CAP_BPF/root) + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn execve_counter_counts_host_execve_events() {
    // Load + attach the tracepoint, read its per-CPU map, and prove the counter tracks the
    // host's `execve`s, spawn N processes and assert the total rose by at least N.
    if let Some(why) = skip_reason() {
        eprintln!("skipping execve_counter_counts_host_execve_events: {why}");
        return;
    }
    let counter = ExecveCounter::load().expect("load + attach the execve counter");
    let before = counter.count().expect("read the baseline count");

    const SPAWNS: u64 = 10;
    for _ in 0..SPAWNS {
        // Each spawn is one `execve` of `/bin/true`, exactly what the tracepoint counts.
        let _ = Command::new("true").status().expect("spawn `true`");
    }

    let after = counter.count().expect("read the count after the spawns");
    assert!(
        after >= before + SPAWNS,
        "the execve count must rise by at least the {SPAWNS} spawns (before {before}, after {after})"
    );

    // The per-PID hash map recorded the execing processes too (lookup-or-init worked).
    let by_pid = counter.counts_by_pid().expect("read the per-pid counts");
    assert!(
        !by_pid.is_empty(),
        "the per-pid map must record the execing processes"
    );
    let by_pid_total: u64 = by_pid.iter().map(|(_, c)| c).sum();
    assert!(
        by_pid_total >= SPAWNS,
        "per-pid counts should cover at least the {SPAWNS} spawns (got {by_pid_total})"
    );
}

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn counter_drops_without_pinned_residue() {
    // The loader owns the program/map/link; dropping it must leave no residue, nothing pinned
    // into `/sys/fs/bpf`, and no dangling attachment. The real no-dangling-attachment proof is that
    // the `count_execve` program is *gone from the kernel* after the drop: a leaked link would pin its
    // program alive (kept enumerable by `loaded_programs`), so the resident count returning to baseline
    // catches a leaked program *or* a leaked link. (The pin check alone can't: nothing here ever pins,
    // and a fresh load would succeed even with a leak, since a tracepoint takes many attachments.)
    if let Some(why) = skip_reason() {
        eprintln!("skipping counter_drops_without_pinned_residue: {why}");
        return;
    }
    let pins_before = bpf_pins();
    let resident_before = resident_count_execve();
    {
        let counter = ExecveCounter::load().expect("first load");
        counter.count().expect("read the counter while loaded");
        // While loaded, exactly one more `count_execve` is resident, the strong check's precondition.
        if let (Some(before), Some(now)) = (resident_before, resident_count_execve()) {
            assert_eq!(
                now,
                before + 1,
                "one `count_execve` must be resident while loaded (before {before}, now {now})"
            );
        }
        // `counter` drops here: aya detaches the program (dropping the link) and frees the map.
    }
    let pins_after = bpf_pins();
    assert_eq!(
        pins_before, pins_after,
        "loading and dropping the counter must not pin anything into /sys/fs/bpf (before {pins_before:?}, after {pins_after:?})"
    );

    // The no-dangling-attachment proof: the program (and any link that would pin it alive) is gone,
    // so the resident count is back to baseline. Degrades cleanly where the kernel won't let us
    // enumerate program info (older kernel / narrower privilege): the pin check still ran.
    match (resident_before, resident_count_execve()) {
        (Some(before), Some(after)) => assert_eq!(
            after, before,
            "the `count_execve` program must be freed on drop, not left resident (before {before}, after {after})"
        ),
        _ => eprintln!(
            "note: could not enumerate loaded BPF programs here — the no-dangling-attachment check \
             was skipped; only the no-pin check ran"
        ),
    }

    // And a clean drop leaves nothing blocking a fresh load.
    let reloaded = ExecveCounter::load().expect("a second load after drop must succeed");
    assert!(
        reloaded.count().is_ok(),
        "the re-loaded counter must be readable"
    );
}

/// How many loaded BPF programs are named `count_execve`, or `None` if the kernel won't let us
/// enumerate program info here (older kernel, or narrower privilege than the load itself needs).
/// Iterating loaded programs by name is what proves *our* program left the kernel on drop: a leaked
/// program stays here, and a leaked link keeps its program resident too, so this returning to baseline
/// is the actual no-dangling-attachment check the pin diff can't make.
fn resident_count_execve() -> Option<usize> {
    let mut n = 0usize;
    for info in aya::programs::loaded_programs() {
        // A read error (unprivileged/unsupported enumeration, or a program that vanished mid-scan)
        // means we can't make this a hard assertion here, signal "unknown" rather than false-fail.
        if info.ok()?.name_as_str() == Some("count_execve") {
            n += 1;
        }
    }
    Some(n)
}

/// The sorted top-level entries under `/sys/fs/bpf` (the bpffs pin root). Empty when the fs isn't
/// mounted, then "no residue" holds vacuously. Used to prove [`ExecveCounter`] pins nothing.
fn bpf_pins() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/fs/bpf") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
