//! `cargo xtask <cmd>` — dev orchestration for the agent sandbox engine.
//!
//! - **`ci`** — the host-safe gate (fmt · clippy `-D warnings` · build · test · docs · `deny`).
//!   Runs everywhere, needs no KVM or root, and mirrors `.github/workflows/ci.yml`.
//! - **`ci-privileged`** — the KVM/eBPF integration tests (the `#[ignore]`d ones). Needs
//!   `/dev/kvm` and elevated caps, so it's never part of the everyday loop. Builds the guest
//!   agent + the agent rootfs first, so the in-VM exec test has something to boot.
//! - **`setup`** — checks the host can do KVM + eBPF and reports what's missing.
//! - **`build-rootfs`** — assemble the reproducible guest rootfs (Alpine base + baked-in agent).
//! - **`bench-boot`** — measure boot-to-userspace latency (percentiles) vs. the base size. Needs KVM.
//! - **`bench-warm`** — time-to-first-result percentiles: cold boot vs warm-snapshot restore vs
//!   warm-pool take. Needs KVM + the built agent rootfs.
//!
//! Split by concern: `guest_bins` (the static musl in-guest builds), `rootfs` (the reproducible
//! image), `bench` (the latency benchmarks), `artifacts` (the pinned kernel/rootfs fetch); the
//! gates and the shared plumbing (paths, `cargo`/tool runners) live here.
//!
//! The eBPF crate (`crates/probes`) builds for `bpfel-unknown-none` and is excluded from the host
//! workspace; its object build folds into `ci` at ROADMAP Phase 8.
#![forbid(unsafe_code)]

mod artifacts;
mod bench;
mod guest_bins;
mod rootfs;

use std::ffi::OsStr;
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
    /// Build the guest agent as a static musl binary (baked into the rootfs by `build-rootfs`).
    BuildGuestAgent,
    /// Build the P3.9 static native-ELF fixture (`examples/writefile`) for the guest target — the
    /// runtime-agnostic test injects and runs it to prove the engine executes any static Linux binary.
    BuildGuestExample,
    /// Assemble the guest rootfs: a minimal Alpine base + the guest runtimes (python3) + the static
    /// agent + a vsock init, as an ext4 image at `artifacts/rootfs-agent.ext4` (needs `curl`,
    /// `tar`, `mke2fs`, `truncate`). Reproducible: two builds are byte-identical.
    BuildRootfs {
        /// Build a second time and assert the image is byte-identical, and fail if the resolved
        /// package closure has drifted from the committed lockfile. The reproducibility gate.
        #[arg(long)]
        verify: bool,
        /// Re-record the resolved package closure into the committed lockfile — the "re-pin" step
        /// after Alpine's branch repo bumps a package out from under the floating install.
        #[arg(long)]
        update_lock: bool,
    },
    /// Measure boot-to-userspace latency (percentiles) of the agent rootfs, on both the read-only
    /// shared base and the read-write per-VM copy, so the base **size**'s effect on boot is visible
    /// (P3.7). Needs `/dev/kvm` + the built agent rootfs.
    BenchBoot {
        /// How many boots to time per path (more → tighter tail percentiles). Default 100 — the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure time-to-first-result (percentiles) of the three start paths: a cold boot (per-VM
    /// rootfs copy, the Phase-1-style baseline), a warm-snapshot restore, and a warm-pool take,
    /// each timed from "start a sandbox" to "a Python one-liner's output is back on the host"
    /// (P5.7). Needs `/dev/kvm` + the built agent rootfs.
    BenchWarm {
        /// How many runs to time per path (more → tighter tail percentiles). Default 100, the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::CiPrivileged => ci_privileged(),
        Cmd::Setup => setup(),
        Cmd::FetchArtifacts => artifacts::fetch_artifacts(),
        Cmd::BuildGuestAgent => guest_bins::build_guest_agent().map(|_| ()),
        Cmd::BuildGuestExample => guest_bins::build_guest_example().map(|_| ()),
        Cmd::BuildRootfs {
            verify,
            update_lock,
        } => rootfs::build_rootfs(verify, update_lock),
        Cmd::BenchBoot { runs } => bench::bench_boot(runs),
        Cmd::BenchWarm { runs } => bench::bench_warm(runs),
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
    // This gate builds and verifies the static guest agent (below), and that verification is the
    // *only* thing standing between a silently-reintroduced dynamic dependency and a confusing
    // in-guest loader failure. `verify_static` soft-skips when `readelf` is absent (so ad-hoc
    // `build-rootfs` still works), so require it *here* — a missing binutils must fail the gate
    // loudly, not quietly disarm the check.
    if !in_path("readelf") {
        bail!(
            "readelf (binutils) not found — the privileged gate verifies the guest agent is \
               statically linked and won't run that check blind; install binutils"
        );
    }
    // The boot tests need the pinned kernel + rootfs; fail with the fix rather than a cryptic
    // boot error. `fetch-artifacts` (not this gate) does the network download; here we verify
    // the hashes too — the sha256 is the contract, and a hand-placed or corrupted artifact
    // should fail this gate, not the boot inside it.
    for a in artifacts::artifacts()? {
        if !a.dest.is_file() {
            bail!(
                "missing artifact {} — run `cargo xtask fetch-artifacts` first",
                a.dest.display()
            );
        }
        let got = artifacts::sha256_of(&a.dest)?;
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
    // The in-VM exec test boots a rootfs with the agent baked in — build it here (not from inside a
    // `#[test]`, which mustn't shell out to a musl `cargo build`). Idempotent: the Alpine base is
    // cached by sha256, so this is a rebuild of the agent + the image, not a re-download. `--verify`
    // makes this the reproducibility gate: it builds twice, asserts byte-identical, and fails on
    // package-closure drift from the lockfile.
    rootfs::build_rootfs(true, false)?;
    // The runtime-agnostic test (P3.9) injects a static native binary; build it here (musl), like the
    // agent — the same "don't shell a musl `cargo build` from a `#[test]`" rule. It is a *fixture*,
    // not part of the image, so it's built separately, not baked into the rootfs.
    guest_bins::build_guest_example()?;
    // Serial (`--test-threads=1`): these tests each boot a real microVM and some assert on
    // host-global state (no leaked scratch dirs / taps / VMM processes, concurrent warm clones). Run
    // in parallel they contend for KVM and, worse, one test's live scratch dir trips another's
    // leak check. Real-VM integration is I/O-bound on boot anyway, so serial costs little.
    cargo(&[
        "test",
        "--workspace",
        "--locked",
        "--",
        "--ignored",
        "--test-threads=1",
    ])?;
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
    check(
        "firecracker is the pinned v1.9 (API schema, decision 001)",
        firecracker_version() == Some((1, 9)),
    );
    check("jailer in PATH", in_path("jailer"));
    check(
        "cgroup v2 cpu+memory delegated (jailer resource limits)",
        cgroup_controllers_delegated(),
    );
    check(
        "kernel >= 5.14 (cgroup.kill — crash-safe VM teardown)",
        kernel_at_least(5, 14),
    );
    check("bpf-linker installed", in_path("bpf-linker"));
    check("mke2fs (rootfs + input block device)", in_path("mke2fs"));
    check(
        "e2fsck + debugfs (output readback)",
        in_path("e2fsck") && in_path("debugfs"),
    );
    check(
        "readelf (binutils — static-link verification)",
        in_path("readelf"),
    );
    check("ip (iproute2 — per-VM tap device)", in_path("ip"));
    check(
        "guest kernel + rootfs (cargo xtask fetch-artifacts)",
        kernel_path().is_file() && boot_rootfs_path().is_file(),
    );

    // The degradation matrix (P6.9b): what each missing capability above costs, in one place, so
    // a mismatched host explains itself *before* the first boot discovers it. The split is decision
    // 013's: resource caps and leak-proofing fail open (they're DoS mitigation), the isolation
    // boundary never does.
    println!("\nDegradation matrix — what a missing item above means at runtime:");
    println!("  fails open (loud warning, still runs):");
    println!(
        "    cgroup v2 not delegated      -> jailed VMs run WITHOUT cpu/memory caps (decision 013)"
    );
    println!("    cgroup v2 not writable       -> Drop-only teardown; a SIGKILLed driver can leak its VM (decision 014)");
    println!("    kernel < 5.14 (no cgroup.kill) -> the lifetime sentinel cannot kill the VM tree (decision 014)");
    println!("    firecracker not v1.9         -> boots continue with a warning; API bodies may not match (decision 001)");
    println!("  hard errors (typed, never a silent half-measure):");
    println!("    /dev/kvm missing/unwritable  -> every boot fails: NoKvm (isolation is hardware)");
    println!("    jail cannot be built         -> jailed boot fails; never a half-confined VM (decision 013)");
    println!("    host tool missing (ip, mke2fs, e2fsck/debugfs, firecracker) -> typed Artifact/Vmm error");
    println!("\nMissing items are covered in CONTRIBUTING.md → Prerequisites.");
    Ok(())
}

/// The `(major, minor)` of `firecracker --version` on PATH (first line `Firecracker v1.9.1`), or
/// `None` when it's missing or unparseable. The same parse the driver runs once per process to
/// warn on an unpinned binary; here it feeds the setup checklist.
fn firecracker_version() -> Option<(u64, u64)> {
    let out = Command::new("firecracker").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let rest = text.split("Firecracker v").nth(1)?;
    let mut parts = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Whether the running kernel is at least `major.minor`, from `/proc/sys/kernel/osrelease`.
fn kernel_at_least(major: u64, minor: u64) -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|s| {
            let mut it = s
                .split(|c: char| !c.is_ascii_digit())
                .filter(|t| !t.is_empty());
            Some((
                it.next()?.parse::<u64>().ok()?,
                it.next()?.parse::<u64>().ok()?,
            ))
        })
        .is_some_and(|v| v >= (major, minor))
}

/// The workspace root (not the cwd), so the commands work from anywhere.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
}

/// `artifacts/` under the workspace root.
fn artifacts_dir() -> PathBuf {
    workspace_root().join("artifacts")
}

/// The artifact filenames under [`artifacts_dir`], defined once so the many readers/writers
/// (`build-rootfs`, `bench-boot`, `setup`, `fetch-artifacts`) can't drift apart: the pinned guest
/// kernel, the Phase-1 boot rootfs (fetched), and the agent rootfs (`build-rootfs` output).
fn kernel_path() -> PathBuf {
    artifacts_dir().join("vmlinux")
}
fn boot_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs.ext4")
}
fn agent_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs-agent.ext4")
}

/// Run an external build tool, echoing the command; fail with context if it's missing or errors.
fn run_tool(program: &str, args: &[&OsStr]) -> Result<()> {
    run_tool_env(program, args, &[])
}

/// [`run_tool`] with extra environment scoped to **this child only** (not `std::env::set_var`, which
/// is process-global and would leak into every later tool). Used to hand `mke2fs` its
/// `SOURCE_DATE_EPOCH` without affecting `tar`/`apk`/`truncate`.
fn run_tool_env(program: &str, args: &[&OsStr], env: &[(&str, &str)]) -> Result<()> {
    let shown: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
    println!("$ {program} {}", shown.join(" "));
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running {program} (is it installed?)"))?;
    if !status.success() {
        bail!("{program} failed");
    }
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

/// Whether the cgroup v2 `cpu`+`memory` controllers are delegated to the cgroup root, so the jailer
/// can set a jailed VM's CPU/memory limits (P6.2). A systemd host enables these by default; where they
/// aren't, jailed boots still run but without limits. Informational only.
fn cgroup_controllers_delegated() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .map(|s| {
            let toks: Vec<&str> = s.split_whitespace().collect();
            toks.contains(&"cpu") && toks.contains(&"memory")
        })
        .unwrap_or(false)
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
