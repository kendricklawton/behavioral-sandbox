//! `cargo xtask <cmd>` — dev orchestration for the agent sandbox engine.
//!
//! - **`ci`** — the host-safe gate (fmt · clippy `-D warnings` · build · test · docs · `deny`).
//!   Runs everywhere, needs no KVM or root, and mirrors `.github/workflows/ci.yml`.
//! - **`ci-privileged`** — the KVM/eBPF integration tests (the `#[ignore]`d ones). Needs
//!   `/dev/kvm` and elevated caps, so it's never part of the everyday loop. Builds the guest
//!   agent + the agent rootfs first, so the in-VM exec test has something to boot.
//! - **`setup`** — checks the host can do KVM + eBPF and reports what's missing.
//! - **`build-rootfs`** — assemble the reproducible guest rootfs (Alpine base + baked-in agent).
//!
//! The eBPF crate (`crates/probes`) builds for `bpfel-unknown-none` and is excluded from the host
//! workspace; its object build folds into `ci` at ROADMAP Phase 8.
#![forbid(unsafe_code)]

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
    /// Assemble the guest rootfs: a minimal Alpine base + the guest runtimes (python3) + the static
    /// agent + a vsock init, as an ext4 image at `artifacts/rootfs-agent.ext4` (needs `curl`,
    /// `tar`, `mke2fs`, `truncate`).
    BuildRootfs,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::CiPrivileged => ci_privileged(),
        Cmd::Setup => setup(),
        Cmd::FetchArtifacts => fetch_artifacts(),
        Cmd::BuildGuestAgent => build_guest_agent().map(|_| ()),
        Cmd::BuildRootfs => build_rootfs(),
    }
}

/// The musl target the guest agent is built for: a fully static binary that runs in the guest with
/// no dynamic loader or libc to bake into the rootfs.
const GUEST_TARGET: &str = "x86_64-unknown-linux-musl";

/// Build the guest agent as a static binary for the guest and return its path. Kept out of the `ci`
/// gate (it needs the musl target installed and produces an artifact the host doesn't run);
/// `build-rootfs` bakes the result into the image.
fn build_guest_agent() -> Result<PathBuf> {
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
    let bin = guest_agent_bin();
    verify_static(&bin)?;
    println!("\n✓ guest agent built (static): {}", bin.display());
    Ok(bin)
}

/// Where `build_guest_agent` leaves the static binary.
fn guest_agent_bin() -> PathBuf {
    workspace_root()
        .join("target")
        .join(GUEST_TARGET)
        .join("release/agent-guest")
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

// ---- rootfs build (ROADMAP P3.1) -------------------------------------------------------------

/// A fixed rootfs UUID so repeated builds don't churn it (Firecracker roots by device, not UUID).
/// True byte-for-byte reproducibility is P3.6; P3.1's bar is pinned inputs + one scripted command.
const ROOTFS_UUID: &str = "5b3a9c1e-0000-4000-8000-000000000001";

/// Image size. Generous headroom over the ~15 MB payload so a later `apk.static --root` (P3.2's
/// Python, P3.9's Node) has room without a re-size. Per-run growth is P3.3's overlay, not this.
const ROOTFS_SIZE_MIB: u32 = 128;

/// The init the image ships, replacing Alpine's OpenRC `inittab`. busybox is PID 1 (it reaps
/// orphans and a crashed child is respawned, neither of which the `forbid(unsafe_code)` agent should
/// own). `sysinit` mounts the pseudo-filesystems a fresh ext4 lacks — a rootless `mke2fs -d` seeds
/// no device nodes, so `devtmpfs` is what provides `/dev/ttyS0` + the vsock device (the guest kernel
/// must auto-mount it, `CONFIG_DEVTMPFS_MOUNT`, for PID 1's own console). The agent then respawns on
/// the contract vsock port (`agent_channel::AGENT_VSOCK_PORT` — the same constant the host dials,
/// so the two sides can't drift), attached to `ttyS0` so its readiness line reaches the serial
/// console the host scans.
fn rootfs_inittab() -> String {
    format!(
        "\
# Minimal init for the agent sandbox rootfs (replaces Alpine's OpenRC inittab).
::sysinit:/bin/mount -t devtmpfs dev /dev
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sys /sys
ttyS0::respawn:/usr/local/bin/agent-guest vsock:{port}
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
",
        port = agent_channel::AGENT_VSOCK_PORT
    )
}

/// The Alpine branch the guest userland comes from: the minirootfs base and the package repo the
/// runtime packages install from. One pin, used by both, so base and packages can't skew branches.
const ALPINE_BRANCH: &str = "v3.24";

/// The language runtimes baked into the guest image (P3.2's reference runtime; P3.9 broadens it).
/// Installed by `apk.static` from the pinned branch. Versions float *within* that stable branch —
/// Alpine branch repos carry only the latest revision per package, so an exact `pkg=ver-rN` pin
/// would break the build on every upstream patch bump; the exact-version lockfile is P3.6's
/// reproducibility work.
const GUEST_PACKAGES: &[&str] = &["python3"];

/// The pinned Alpine minirootfs — a real musl+busybox userland (so init and a shell just work, and
/// `apk` adds the [`GUEST_PACKAGES`] runtimes). A *build input*, deliberately separate from
/// [`artifacts`] (the boot kernel+rootfs the `ci-privileged` hash-guard requires present).
fn alpine_artifact() -> Result<Artifact> {
    let dir = artifacts_dir();
    match std::env::consts::ARCH {
        "x86_64" => Ok(Artifact {
            url: format!(
                "https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/releases/x86_64/\
                 alpine-minirootfs-3.24.1-x86_64.tar.gz"
            ),
            sha256: "41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081",
            dest: dir.join("alpine-minirootfs.tar.gz"),
        }),
        other => bail!("no pinned Alpine minirootfs for arch {other} yet (x86_64 only)"),
    }
}

/// The pinned static `apk` (from Alpine's `apk-tools-static` package — itself a tarball): the
/// installer that puts [`GUEST_PACKAGES`] into the staging dir **rootless**, on any host distro.
fn apk_tools_artifact() -> Result<Artifact> {
    let dir = artifacts_dir();
    match std::env::consts::ARCH {
        "x86_64" => Ok(Artifact {
            url: format!(
                "https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main/x86_64/\
                 apk-tools-static-3.0.6-r0.apk"
            ),
            sha256: "a62f54609910d1eb23d8ebcf69dd7954280fe76047452bb88410122cbca14a6e",
            dest: dir.join("apk-tools-static.apk"),
        }),
        other => bail!("no pinned apk-tools-static for arch {other} yet (x86_64 only)"),
    }
}

/// Assemble `artifacts/rootfs-agent.ext4`: extract the pinned Alpine base, bake the static agent in,
/// install the vsock init, and build the ext4 from the staging dir with `mke2fs -d` (rootless — no
/// loopback mount, no `sudo`). A distinct output path, so the pinned Ubuntu `rootfs.ext4` (and the
/// `ci-privileged` hash-guard + the Phase-1 `login:` boot test) are untouched.
fn build_rootfs() -> Result<()> {
    let agent = build_guest_agent()?;

    let base = alpine_artifact()?;
    fetch_one(&base)?;

    let dir = artifacts_dir();
    let staging = dir.join("rootfs-staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .with_context(|| format!("clean staging {}", staging.display()))?;
    }
    std::fs::create_dir_all(&staging)?;

    // Extract the Alpine base (preserves symlinks + mode bits).
    run_tool(
        "tar",
        &[
            OsStr::new("xzf"),
            base.dest.as_os_str(),
            OsStr::new("-C"),
            staging.as_os_str(),
        ],
    )?;

    // Install the guest runtimes (P3.2: python3) into the staging root with the pinned static apk —
    // rootless, on any host distro. Packages are signature-verified against the keys the minirootfs
    // itself ships (`/etc/apk/keys`). `--no-scripts` because pre/post-install scripts need a chroot
    // (root); the runtime packages are file payloads, and the in-VM exec test proves they run.
    install_guest_packages(&staging)?;

    // Bake the static agent in at /usr/local/bin/agent-guest.
    let bindir = staging.join("usr/local/bin");
    std::fs::create_dir_all(&bindir)?;
    let agent_dest = bindir.join("agent-guest");
    std::fs::copy(&agent, &agent_dest)
        .with_context(|| format!("copy agent into {}", agent_dest.display()))?;
    set_mode_0755(&agent_dest)?;

    // Replace Alpine's OpenRC inittab with our minimal vsock init.
    std::fs::write(staging.join("etc/inittab"), rootfs_inittab()).context("write /etc/inittab")?;

    // Build the ext4 from the staging dir — rootless, via `mke2fs -d`.
    let out = dir.join("rootfs-agent.ext4");
    let _ = std::fs::remove_file(&out);
    run_tool(
        "truncate",
        &[
            OsStr::new("-s"),
            OsStr::new(&format!("{ROOTFS_SIZE_MIB}M")),
            out.as_os_str(),
        ],
    )?;
    run_tool(
        "mke2fs",
        &[
            OsStr::new("-F"),
            OsStr::new("-q"),
            OsStr::new("-t"),
            OsStr::new("ext4"),
            OsStr::new("-b"),
            OsStr::new("4096"),
            OsStr::new("-m"),
            OsStr::new("0"),
            OsStr::new("-U"),
            OsStr::new(ROOTFS_UUID),
            OsStr::new("-d"),
            staging.as_os_str(),
            out.as_os_str(),
        ],
    )?;

    // The image is the product — don't leave the extracted staging tree behind.
    std::fs::remove_dir_all(&staging)
        .with_context(|| format!("clean up staging {}", staging.display()))?;

    println!("\n✓ rootfs built (agent baked in): {}", out.display());
    // The full runnable hint, printed from the contract constants so it can't drift from the code.
    println!(
        "  exec inside a microVM with:\n  AGENT_ROOTFS={} AGENT_MARKER={} cargo run -p agent-cli -- run -- echo hi",
        out.display(),
        agent_channel::GUEST_READY_MARKER
    );
    Ok(())
}

/// Install [`GUEST_PACKAGES`] into the staging root with the pinned `apk.static` — no chroot, no
/// root, no host `apk`. The `.apk` is a tarball; its `sbin/apk.static` is extracted to a scratch
/// dir that's removed after the install (the packages land in `staging`, the tool is ephemeral).
fn install_guest_packages(staging: &Path) -> Result<()> {
    if GUEST_PACKAGES.is_empty() {
        return Ok(());
    }
    let tools = apk_tools_artifact()?;
    fetch_one(&tools)?;

    let tooldir = artifacts_dir().join("apk-tools");
    if tooldir.exists() {
        std::fs::remove_dir_all(&tooldir)?;
    }
    std::fs::create_dir_all(&tooldir)?;
    run_tool(
        "tar",
        &[
            OsStr::new("xzf"),
            tools.dest.as_os_str(),
            OsStr::new("-C"),
            tooldir.as_os_str(),
        ],
    )?;

    let apk = tooldir.join("sbin/apk.static");
    let repo = format!("https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main");
    // The host's arch, not a literal: Alpine's arch names match Rust's for the arches we'll pin
    // (x86_64/aarch64), and the pinned-artifact fns above already bail on anything unpinned — so
    // this stays correct by itself when a second arch lands, instead of silently installing
    // x86_64 packages into an aarch64 image.
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("--root"),
        staging.as_os_str(),
        OsStr::new("--arch"),
        OsStr::new(std::env::consts::ARCH),
        OsStr::new("--repository"),
        OsStr::new(&repo),
        OsStr::new("--no-scripts"),
        OsStr::new("--no-cache"),
        OsStr::new("add"),
    ];
    args.extend(GUEST_PACKAGES.iter().map(OsStr::new));
    let apk_str = apk.to_string_lossy().into_owned();
    let result = run_tool(&apk_str, &args);

    // The tool is scratch either way — clean it before propagating any install failure.
    let _ = std::fs::remove_dir_all(&tooldir);
    result
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
    // The in-VM exec test boots a rootfs with the agent baked in — build it here (not from inside a
    // `#[test]`, which mustn't shell out to a musl `cargo build`). Idempotent: the Alpine base is
    // cached by sha256, so this is a rebuild of the agent + the image, not a re-download.
    build_rootfs()?;
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
    check("mke2fs (rootfs build)", in_path("mke2fs"));
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

/// Download each pinned kernel/rootfs artifact (skipping any already present with the right hash).
fn fetch_artifacts() -> Result<()> {
    let items = artifacts()?;
    for a in &items {
        fetch_one(a)?;
    }
    println!("\n✓ artifacts ready in {}", artifacts_dir().display());
    Ok(())
}

/// Fetch one artifact into place if it isn't already present with the right hash. Downloads to a
/// `.part` and renames only after the hash verifies, so an interrupted download can never leave a
/// plausible-looking file at the final path (`ci-privileged` gates on presence alone).
fn fetch_one(a: &Artifact) -> Result<()> {
    let name = a
        .dest
        .file_name()
        .map_or_else(|| a.dest.clone(), PathBuf::from);
    if a.dest.is_file() && sha256_of(&a.dest)? == a.sha256 {
        println!("✓ {} already present (sha256 ok)", name.display());
        return Ok(());
    }
    if let Some(parent) = a.dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    println!("↓ {} <- {}", name.display(), a.url);
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

/// Run an external build tool, echoing the command; fail with context if it's missing or errors.
fn run_tool(program: &str, args: &[&OsStr]) -> Result<()> {
    let shown: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
    println!("$ {program} {}", shown.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("running {program} (is it installed?)"))?;
    if !status.success() {
        bail!("{program} failed");
    }
    Ok(())
}

/// `chmod 0755` — the agent must be executable inside the image even if the copy didn't preserve it.
fn set_mode_0755(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod +x {}", path.display()))
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
