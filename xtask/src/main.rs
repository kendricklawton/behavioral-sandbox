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

use std::path::{Path, PathBuf};
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
    /// Download + sha256-verify the pinned guest kernel and rootfs into `artifacts/` (needs `curl`).
    FetchArtifacts,
    /// Build the guest agent as a static musl binary (baked into the rootfs at Phase 3).
    BuildGuestAgent,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::CiPrivileged => ci_privileged(),
        Cmd::Setup => setup(),
        Cmd::FetchArtifacts => fetch_artifacts(),
        Cmd::BuildGuestAgent => build_guest_agent(),
    }
}

/// The musl target the guest agent is built for: a fully static binary that runs in the guest with
/// no dynamic loader or libc to bake into the rootfs.
const GUEST_TARGET: &str = "x86_64-unknown-linux-musl";

/// Build the guest agent as a static binary for the guest. Kept out of the `ci` gate (it needs the
/// musl target installed and produces an artifact the host doesn't run); Phase 3 bakes the result
/// into the rootfs.
fn build_guest_agent() -> Result<()> {
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context("running rustup (is it installed?)")?;
    if !String::from_utf8_lossy(&installed.stdout)
        .lines()
        .any(|t| t == GUEST_TARGET)
    {
        bail!("missing target {GUEST_TARGET} — run `rustup target add {GUEST_TARGET}` first");
    }
    cargo(&[
        "build",
        "--release",
        "--locked",
        "-p",
        "agent-guest",
        "--bin",
        "agent-guest",
        "--target",
        GUEST_TARGET,
    ])?;
    let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("target")
        .join(GUEST_TARGET)
        .join("release/agent-guest");
    verify_static(&bin)?;
    println!("\n✓ guest agent built (static): {}", bin.display());
    println!("  (Phase 3 bakes it into the rootfs)");
    Ok(())
}

/// Verify the built binary is actually statically linked — "measured, not marketed." A sys-crate or
/// `build.rs` can silently reintroduce a `NEEDED` dynamic dependency, and a dynamically-linked
/// binary baked into a scratch rootfs would fail at boot with a confusing loader error. Checks for a
/// dynamic-library dependency via `readelf -d`; on a static binary there are no `(NEEDED)` entries.
fn verify_static(bin: &Path) -> Result<()> {
    let out = Command::new("readelf").arg("-d").arg(bin).output();
    match out {
        Ok(o) if o.status.success() => {
            let dynamic = String::from_utf8_lossy(&o.stdout);
            let needed: Vec<_> = dynamic.lines().filter(|l| l.contains("(NEEDED)")).collect();
            if needed.is_empty() {
                Ok(())
            } else {
                bail!(
                    "guest agent is NOT statically linked — it needs {} shared object(s):\n{}",
                    needed.len(),
                    needed.join("\n")
                );
            }
        }
        // No `readelf` (binutils) on this host: don't fake a guarantee we couldn't check.
        _ => {
            println!(
                "  ! could not run `readelf` to verify staticness — install binutils to check"
            );
            Ok(())
        }
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
    // Mirror CI's global `RUSTFLAGS=-D warnings` so the local gate and the runner agree on
    // rustc lints too, not just clippy's.
    cargo_env(
        &["build", "--workspace", "--locked"],
        &[("RUSTFLAGS", "-D warnings")],
    )?;
    cargo_env(
        &["test", "--workspace", "--locked"],
        &[("RUSTFLAGS", "-D warnings")],
    )?;
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
    // The boot tests need the pinned kernel + rootfs; fail with the fix rather than a cryptic
    // boot error. `fetch-artifacts` (not this gate) does the network download; here we verify
    // the hashes too — the sha256 is the contract, and a hand-placed or corrupted artifact
    // should fail this gate, not the boot inside it.
    for a in artifacts()? {
        if !a.dest.is_file() {
            bail!(
                "missing artifact {} — run `cargo xtask fetch-artifacts` first",
                a.dest.display()
            );
        }
        let got = sha256_of(&a.dest)?;
        if got != a.sha256 {
            bail!(
                "artifact {} does not match its pin (expected {}, got {}) — re-run \
                 `cargo xtask fetch-artifacts`",
                a.dest.display(),
                a.sha256,
                got
            );
        }
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
    let dir = artifacts_dir();
    check(
        "guest kernel + rootfs (cargo xtask fetch-artifacts)",
        dir.join("vmlinux").is_file() && dir.join("rootfs.ext4").is_file(),
    );
    println!("\nMissing items are covered in CONTRIBUTING.md → Prerequisites.");
    Ok(())
}

/// A pinned boot artifact: a stable URL, its expected sha256 (the real contract — the URL is
/// replaceable), and where it lands under `artifacts/`.
struct Artifact {
    url: String,
    sha256: &'static str,
    dest: PathBuf,
}

/// The kernel + rootfs pinned for the host architecture. Matched to Firecracker v1.9's CI
/// artifacts (uncompressed `vmlinux` + a minimal Ubuntu ext4). Only x86_64 is pinned so far.
fn artifacts() -> Result<Vec<Artifact>> {
    let dir = artifacts_dir();
    let base = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.9";
    match std::env::consts::ARCH {
        "x86_64" => Ok(vec![
            Artifact {
                url: format!("{base}/x86_64/vmlinux-6.1.102"),
                sha256: "3b6e45c66d1b66d4fb0a1528107abbe890972f94e902bafe85fdf5108288c575",
                dest: dir.join("vmlinux"),
            },
            Artifact {
                url: format!("{base}/x86_64/ubuntu-22.04.ext4"),
                sha256: "b930af6ed56c5347c200eddfa4ae4701eed6f7d7fb30a6b9b8d2d30bfc2a2ed7",
                dest: dir.join("rootfs.ext4"),
            },
        ]),
        other => bail!(
            "no pinned artifacts for arch {other} yet (x86_64 only) — set AGENT_KERNEL/AGENT_ROOTFS \
             to your own uncompressed vmlinux + ext4 rootfs"
        ),
    }
}

/// `artifacts/` under the workspace root (not the cwd), so `fetch-artifacts` works from anywhere.
fn artifacts_dir() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."));
    root.join("artifacts")
}

/// Download each artifact (skipping any already present with the right hash) and sha256-verify it.
fn fetch_artifacts() -> Result<()> {
    let items = artifacts()?;
    let dir = artifacts_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    for a in &items {
        let name = a
            .dest
            .file_name()
            .map_or_else(|| a.dest.clone(), PathBuf::from);
        if a.dest.is_file() && sha256_of(&a.dest)? == a.sha256 {
            println!("✓ {} already present (sha256 ok)", name.display());
            continue;
        }
        println!("↓ {} <- {}", name.display(), a.url);
        // Download to a `.part` and rename into place only after the hash verifies, so an
        // interrupted or failed download can never leave a plausible-looking file at the final
        // path (`ci-privileged` gates on presence alone).
        let part = a.dest.with_extension("part");
        if let Err(e) = curl_download(&a.url, &part) {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        let got = sha256_of(&part)?;
        if got != a.sha256 {
            let _ = std::fs::remove_file(&part);
            bail!(
                "sha256 mismatch for {}: expected {}, got {} (removed)",
                name.display(),
                a.sha256,
                got
            );
        }
        std::fs::rename(&part, &a.dest)
            .with_context(|| format!("move {} into place", part.display()))?;
        println!("✓ {} verified", name.display());
    }
    println!("\n✓ artifacts ready in {}", dir.display());
    Ok(())
}

/// `curl -fSL` a URL to `dest` (fail on HTTP error, follow redirects).
fn curl_download(url: &str, dest: &Path) -> Result<()> {
    let status = Command::new("curl")
        .args(["-fSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .context("running curl (is it installed?)")?;
    if !status.success() {
        bail!("curl failed for {url}");
    }
    Ok(())
}

/// The sha256 of a file, via the `sha256sum` CLI (no hashing crate on the dev-tooling path).
fn sha256_of(path: &Path) -> Result<String> {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .context("running sha256sum (is it installed?)")?;
    if !out.status.success() {
        bail!("sha256sum failed for {}", path.display());
    }
    let text = String::from_utf8(out.stdout).context("sha256sum output not UTF-8")?;
    let hash = text
        .split_whitespace()
        .next()
        .context("empty sha256sum output")?;
    Ok(hash.to_string())
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
