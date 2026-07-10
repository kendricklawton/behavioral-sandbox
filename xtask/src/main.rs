//! `cargo xtask <cmd>` — dev orchestration for the agent sandbox engine.
//!
//! - **`ci`** — the host-safe gate (fmt · clippy `-D warnings` · build · test · docs · `deny`).
//!   Runs everywhere, needs no KVM or root, and mirrors `.github/workflows/ci.yml`.
//! - **`ci-privileged`** — the KVM/eBPF integration tests (the `#[ignore]`d ones). Needs
//!   `/dev/kvm` and elevated caps, so it's never part of the everyday loop.
//! - **`setup`** — checks the host can do KVM + eBPF and reports what's missing.
//!
//! The eBPF crate (`crates/probes`) builds for `bpfel-unknown-none` and is excluded from the host
//! workspace; its object build folds into `ci` at ROADMAP Phase 8.
#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "dev orchestration for the agent sandbox engine"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host-safe gate: fmt · clippy `-D warnings` · build · test · docs · cargo-deny.
    Ci,
    /// Privileged integration tests (KVM + eBPF) — the `#[ignore]`d tests. Needs `/dev/kvm` + caps.
    CiPrivileged,
    /// Check the host can do KVM + eBPF; report what's missing.
    Setup,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::CiPrivileged => ci_privileged(),
        Cmd::Setup => setup(),
    }
}

/// The host-safe gate. `--locked` everywhere so a stale `Cargo.lock` fails here, not at release.
fn ci() -> Result<()> {
    cargo(&["fmt", "--all", "--check"])?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ])?;
    cargo(&["build", "--workspace", "--locked"])?;
    cargo(&["test", "--workspace", "--locked"])?;
    cargo_env(
        &["doc", "--no-deps", "--workspace", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    cargo(&["deny", "check"])?;
    println!("\n✓ all checks passed");
    Ok(())
}

/// Booting a microVM and loading/attaching eBPF need `/dev/kvm` + elevated caps, so those tests are
/// `#[ignore]`d and run only here, on a machine that has them.
fn ci_privileged() -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("/dev/kvm not present — privileged tests need KVM (run on a KVM-capable host)");
    }
    cargo(&["test", "--workspace", "--locked", "--", "--ignored"])?;
    println!("\n✓ privileged integration passed");
    Ok(())
}

/// Print a checklist of the host prerequisites; read-only, never fails the build.
fn setup() -> Result<()> {
    println!("agent — host capability check\n");
    check("/dev/kvm present", Path::new("/dev/kvm").exists());
    check("/dev/kvm writable (kvm group or root)", kvm_writable());
    check(
        "kernel BTF (/sys/kernel/btf/vmlinux)",
        Path::new("/sys/kernel/btf/vmlinux").exists(),
    );
    check("firecracker in PATH", in_path("firecracker"));
    check("jailer in PATH", in_path("jailer"));
    check("bpf-linker installed", in_path("bpf-linker"));
    println!("\nMissing items are covered in CONTRIBUTING.md → Prerequisites.");
    Ok(())
}

fn check(label: &str, ok: bool) {
    println!("  [{}] {label}", if ok { "✓" } else { " " });
}

fn kvm_writable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

fn in_path(bin: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(bin).is_file())
}

fn cargo(args: &[&str]) -> Result<()> {
    cargo_env(args, &[])
}

fn cargo_env(args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    println!("$ cargo {}", args.join(" "));
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running cargo {}", args.join(" ")))?;
    if !status.success() {
        bail!("cargo {} failed", args.join(" "));
    }
    Ok(())
}
