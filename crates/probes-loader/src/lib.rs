//! `agent-probes-loader` — the userspace side of the eBPF story: load and attach the probes from
//! `crates/probes` to a *specific* sandbox (its cgroup, its tap device), read their maps, and
//! stream events into the flight recorder.
//!
//! **Skeleton only** — the aya loader lands in ROADMAP Phase 8+ (syscall tracing), Phase 10 (tap
//! observability), and Phase 11 (egress enforcement).
#![forbid(unsafe_code)]

/// Whether the host can load eBPF at all — a cheap pre-flight the CLI/`setup` can call before it
/// tries to attach anything. Real capability detection arrives with the aya loader (Phase 8).
#[must_use]
pub fn ebpf_supported() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}
