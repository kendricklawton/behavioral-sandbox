//! Placeholder for the eBPF programs.
//!
//! This crate is **excluded** from the workspace and is not built by the host gate. ROADMAP
//! Phase 8 replaces this file with the real `#![no_std]`, `#![no_main]` aya-ebpf programs
//! (syscall tracepoints, tc/XDP on the microVM's tap, cgroup accounting), built for
//! `bpfel-unknown-none` via `bpf-linker`.
fn main() {}
