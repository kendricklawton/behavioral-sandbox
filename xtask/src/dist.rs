//! `cargo xtask dist`: assemble the shippable release package (decision 035), the release binary
//! plus the xtask-built guest kernel, rootfs, and eBPF object, staged into one directory,
//! checksummed, and tarred. The artifacts are built here at package time, never carried in the
//! source tree; the sha256 manifest is the integrity contract, the same discipline as the pinned
//! boot artifacts. `install.sh` (repo root, also packed into the tarball) consumes the result.
//!
//! Every step reuses the tested building blocks the individual `xtask` commands use, so this is
//! orchestration, not a second build path. Vendor-aware like `self-host`: with `AGENT_VENDOR_DIR`
//! set the whole assembly runs offline.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::artifacts::sha256_of;
use crate::{agent_rootfs_path, build_probes, cargo, kernel_path, workspace_root};

/// The packaged eBPF object's name inside `share/agent/` (the loader finds it via
/// `AGENT_PROBES_OBJECT`, which `install.sh` and the container image point here).
const PROBES_NAME: &str = "probes";

/// `cargo xtask dist [--version V]`: build binary + artifacts, stage, checksum, tar.
pub(crate) fn dist(version: Option<String>) -> Result<()> {
    // The supported platform is x86_64 (decision 032); a package assembled elsewhere would carry
    // artifacts that were never privileged-tested, so refuse rather than ship an untested claim.
    if std::env::consts::ARCH != "x86_64" {
        bail!(
            "dist packages only x86_64 (decision 032): this host is {}",
            std::env::consts::ARCH
        );
    }
    let version = match version {
        Some(v) => v,
        None => default_version(),
    };
    let name = format!("agent-{version}-x86_64-linux");
    println!("dist: assembling {name}\n");

    println!("== 1/5  obtain the pinned guest kernel ==");
    let kernel = kernel_path();
    let pinned = crate::artifacts::artifacts()?
        .into_iter()
        .find(|a| a.dest == kernel)
        .context("no pinned guest kernel for this architecture")?;
    crate::artifacts::fetch_one(&pinned)?;

    println!("\n== 2/5  build the guest rootfs (agent baked in) ==");
    crate::rootfs::build_rootfs(false, false)?;

    println!("\n== 3/5  build the eBPF probe object ==");
    build_probes()?;
    let object = workspace_root().join("crates/probes/target/bpfel-unknown-none/release/probes");
    if !object.is_file() {
        // `build_probes` soft-skips without the eBPF toolchain so the everyday gate stays
        // host-safe; a *package* without the observability half is not the product, so hard-fail.
        bail!(
            "eBPF object not built ({}) — a dist ships the audit half; install bpf-linker + the \
             nightly toolchain (see docs/contributing-building.md)",
            object.display()
        );
    }

    println!("\n== 4/5  build the release binary ==");
    cargo(&["build", "--release", "--locked", "-p", "agent-cli"])?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from);
    let agent = target.join("release/agent");
    if !agent.is_file() {
        bail!("built binary {} not found", agent.display());
    }

    println!("\n== 5/5  stage + checksum + tar ==");
    let dist_dir = workspace_root().join("dist");
    let stage = dist_dir.join(&name);
    if stage.exists() {
        std::fs::remove_dir_all(&stage)
            .with_context(|| format!("clear stale stage {}", stage.display()))?;
    }
    let share = stage.join("share/agent");
    std::fs::create_dir_all(stage.join("bin")).context("create stage bin/")?;
    std::fs::create_dir_all(&share).context("create stage share/agent/")?;

    copy_mode(&agent, &stage.join("bin/agent"), 0o755)?;
    copy_mode(&kernel, &share.join("vmlinux"), 0o644)?;
    copy_mode(
        &agent_rootfs_path(),
        &share.join("rootfs-agent.ext4"),
        0o644,
    )?;
    copy_mode(&object, &share.join(PROBES_NAME), 0o644)?;
    copy_mode(
        &workspace_root().join("install.sh"),
        &stage.join("install.sh"),
        0o755,
    )?;
    copy_mode(
        &workspace_root().join("LICENSE"),
        &stage.join("LICENSE"),
        0o644,
    )?;
    write_manifest(&stage)?;

    let tarball = dist_dir.join(format!("{name}.tar.gz"));
    tar_stage(&dist_dir, &name, &tarball)?;
    let tar_sha = sha256_of(&tarball)?;
    let sums = dist_dir.join("SHA256SUMS");
    std::fs::write(&sums, format!("{tar_sha}  {name}.tar.gz\n"))
        .with_context(|| format!("write {}", sums.display()))?;

    println!("\n✓ dist assembled:");
    println!("    {}", tarball.display());
    println!("    {}  (sha256 {tar_sha})", sums.display());
    println!(
        "  install it (any host):   sh {}/install.sh",
        stage.display()
    );
    println!(
        "  or from the tarball:     AGENT_DIST_TARBALL={} sh install.sh",
        tarball.display()
    );
    println!(
        "  container image:         docker build -f Containerfile --build-arg DIST=dist/{name} -t agent:{version} ."
    );
    Ok(())
}

/// The default package version: the nearest checkpoint tag (`git describe --tags`, the `v0.0.x`
/// pre-release line RELEASES.md defines, `v` stripped), falling back to `0.0.0-dev.<rev>` in a
/// tagless clone. Release CI passes `--version` from the pushed tag instead.
fn default_version() -> String {
    let describe = git_stdout(&["describe", "--tags", "--always", "--dirty=.dirty"]);
    match describe {
        Some(d) if d.starts_with('v') => d[1..].to_string(),
        Some(rev) => format!("0.0.0-dev.{rev}"),
        None => "0.0.0-dev.unknown".to_string(),
    }
}

/// One trimmed line of `git <args>` output, or `None` if git fails (not a repo, no git).
fn git_stdout(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(workspace_root())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Copy `src` to `dest` with an explicit mode (a copy may not preserve the bits we need).
fn copy_mode(src: &Path, dest: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::copy(src, dest)
        .with_context(|| format!("copy {} -> {}", src.display(), dest.display()))?;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(dest, perms)
        .with_context(|| format!("chmod {mode:o} {}", dest.display()))?;
    println!("  staged {}", dest.display());
    Ok(())
}

/// Write `MANIFEST.sha256` inside the stage: one `sha256sum -c`-checkable line per staged file
/// (relative paths), so `install.sh` verifies the extracted contents, not just the tarball.
fn write_manifest(stage: &Path) -> Result<()> {
    let mut lines = Vec::new();
    let mut files = Vec::new();
    collect_files(stage, stage, &mut files)?;
    files.sort();
    for rel in files {
        let hash = sha256_of(&stage.join(&rel))?;
        lines.push(format!("{hash}  {}", rel.display()));
    }
    let manifest = stage.join("MANIFEST.sha256");
    std::fs::write(&manifest, lines.join("\n") + "\n")
        .with_context(|| format!("write {}", manifest.display()))?;
    println!("  staged {}", manifest.display());
    Ok(())
}

/// Collect every file under `dir` as a path relative to `root`.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(root, &path, out)?;
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.to_path_buf());
        }
    }
    Ok(())
}

/// Tar the staged directory deterministically (sorted names, numeric zero owners; `--mtime` pinned
/// when `SOURCE_DATE_EPOCH` is set, the same reproducibility seam the rootfs build honors).
fn tar_stage(dist_dir: &Path, name: &str, tarball: &Path) -> Result<()> {
    let mut cmd = Command::new("tar");
    cmd.arg("--sort=name")
        .arg("--owner=0")
        .arg("--group=0")
        .arg("--numeric-owner");
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        cmd.arg(format!("--mtime=@{epoch}"));
    }
    cmd.arg("-C")
        .arg(dist_dir)
        .arg("-czf")
        .arg(tarball)
        .arg(name);
    let status = cmd.status().context("running tar (is it installed?)")?;
    if !status.success() {
        bail!("tar failed for {}", tarball.display());
    }
    println!("  packed {}", tarball.display());
    Ok(())
}
