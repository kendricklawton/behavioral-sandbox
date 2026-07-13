//! The pinned boot artifacts: download, sha256-verify, and cache the guest kernel + rootfs
//! under `artifacts/`. The sha256 is the contract; the URL is replaceable.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{artifacts_dir, boot_rootfs_path, kernel_path};

/// A pinned boot artifact: a stable URL, its expected sha256 (the real contract — the URL is
/// replaceable), and where it lands under `artifacts/`.
pub(crate) struct Artifact {
    pub(crate) url: String,
    pub(crate) sha256: &'static str,
    pub(crate) dest: PathBuf,
}

/// The kernel + rootfs pinned for the host architecture. Matched to Firecracker v1.9's CI
/// artifacts (uncompressed `vmlinux` + a minimal Ubuntu ext4). Only x86_64 is pinned so far.
pub(crate) fn artifacts() -> Result<Vec<Artifact>> {
    let base = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.9";
    match std::env::consts::ARCH {
        "x86_64" => Ok(vec![
            Artifact {
                url: format!("{base}/x86_64/vmlinux-6.1.102"),
                sha256: "3b6e45c66d1b66d4fb0a1528107abbe890972f94e902bafe85fdf5108288c575",
                dest: kernel_path(),
            },
            Artifact {
                url: format!("{base}/x86_64/ubuntu-22.04.ext4"),
                sha256: "b930af6ed56c5347c200eddfa4ae4701eed6f7d7fb30a6b9b8d2d30bfc2a2ed7",
                dest: boot_rootfs_path(),
            },
        ]),
        other => bail!(
            "no pinned artifacts for arch {other} yet (x86_64 only) — set AGENT_KERNEL/AGENT_ROOTFS \
             to your own uncompressed vmlinux + ext4 rootfs"
        ),
    }
}

/// Download each pinned kernel/rootfs artifact (skipping any already present with the right hash).
pub(crate) fn fetch_artifacts() -> Result<()> {
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
pub(crate) fn fetch_one(a: &Artifact) -> Result<()> {
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
pub(crate) fn sha256_of(path: &Path) -> Result<String> {
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
