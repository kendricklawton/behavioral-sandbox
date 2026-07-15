//! Privileged integration tests for the eBPF `execve` counter (P8.3 attach+read, P8.4 lifetime).
//!
//! `#[ignore]`d: loading eBPF needs `CAP_BPF`/root, a BTF-capable kernel, and the built object
//! (`cargo xtask build-probes`), so these run under `cargo xtask ci-privileged` (as root), not the
//! everyday host gate. Each self-skips when its prerequisites are absent, so an unprivileged
//! `cargo test -- --ignored` reports a clean skip rather than a spurious failure.
#![allow(clippy::panic)]

use std::process::Command;

use agent_probes_loader::{ebpf_supported, object_path, ExecveCounter};

/// This process's effective uid (from `/proc/self/status`; the second `Uid:` field), like the
/// vmm suite's privilege check. Loading eBPF here needs root (or `CAP_BPF`, which the privileged
/// gate runs with); the everyday, unprivileged run self-skips on this.
fn euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Whether this host can actually load the probe: root, a BTF kernel, and the object built. Returns
/// a skip reason (`Some`) when it can't, so each test prints *why* it skipped.
fn skip_reason() -> Option<String> {
    if euid() != Some(0) {
        return Some("needs root (CAP_BPF) to load eBPF".into());
    }
    if !ebpf_supported() {
        return Some("kernel BTF (/sys/kernel/btf/vmlinux) not present".into());
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
    // P8.3: load + attach the tracepoint, read its per-CPU map, and prove the counter tracks the
    // host's `execve`s — spawn N processes and assert the total rose by at least N.
    if let Some(why) = skip_reason() {
        eprintln!("skipping execve_counter_counts_host_execve_events: {why}");
        return;
    }
    let counter = ExecveCounter::load().expect("load + attach the execve counter");
    let before = counter.count().expect("read the baseline count");

    const SPAWNS: u64 = 10;
    for _ in 0..SPAWNS {
        // Each spawn is one `execve` of `/bin/true` — exactly what the tracepoint counts.
        let _ = Command::new("true").status().expect("spawn `true`");
    }

    let after = counter.count().expect("read the count after the spawns");
    assert!(
        after >= before + SPAWNS,
        "the execve count must rise by at least the {SPAWNS} spawns (before {before}, after {after})"
    );
}

#[test]
#[ignore = "needs CAP_BPF/root + BTF + the built object (run via `cargo xtask ci-privileged`)"]
fn counter_drops_without_pinned_residue() {
    // P8.4: the loader owns the program/map/link; dropping it must leave no pinned residue in
    // `/sys/fs/bpf`, and a second load after the drop must still succeed (nothing dangling).
    if let Some(why) = skip_reason() {
        eprintln!("skipping counter_drops_without_pinned_residue: {why}");
        return;
    }
    let before = bpf_pins();
    {
        let counter = ExecveCounter::load().expect("first load");
        counter.count().expect("read the counter while loaded");
        // `counter` drops here: aya detaches the program and frees the map, pinning nothing.
    }
    let after = bpf_pins();
    assert_eq!(
        before, after,
        "loading and dropping the counter must not pin anything into /sys/fs/bpf (before {before:?}, after {after:?})"
    );

    // A clean drop leaves no dangling attachment blocking a fresh load.
    let reloaded = ExecveCounter::load().expect("a second load after drop must succeed");
    assert!(
        reloaded.count().is_ok(),
        "the re-loaded counter must be readable"
    );
}

/// The sorted top-level entries under `/sys/fs/bpf` (the bpffs pin root). Empty when the fs isn't
/// mounted — then "no residue" holds vacuously. Used to prove [`ExecveCounter`] pins nothing.
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
