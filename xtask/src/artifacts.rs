//! Obtaining a pinned upstream input: download or restore from the vendor mirror, sha256-verify,
//! and cache under `artifacts/`. The sha256 is the contract; the URL is replaceable.
//!
//! The machinery `rootfs.rs` uses for the Alpine base and the static `apk`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::vendor_dir;

/// A pinned boot artifact: a stable URL, its expected sha256 (the real contract, the URL is
/// replaceable), and where it lands under `artifacts/`.
pub(crate) struct Artifact {
    pub(crate) url: String,
    pub(crate) sha256: &'static str,
    pub(crate) dest: PathBuf,
}

/// Obtain one artifact into place. **Vendor-aware:** if `BSX_VENDOR_DIR` is set, the artifact is
/// restored from the local vendor mirror (a sha-verified copy, no network); otherwise it is
/// downloaded from its pinned upstream URL. Either way the sha256 is the contract, so a corrupt or
/// substituted file fails here. Every build path (`build-rootfs`)
/// goes through here, so setting `BSX_VENDOR_DIR` takes all of them offline at once.
pub(crate) fn fetch_one(a: &Artifact) -> Result<()> {
    match vendor_dir() {
        Some(v) => restore_from_vendor(a, &v),
        None => download_one(a),
    }
}

/// The final path component of an artifact's `dest`, as a display string, the name it carries both
/// under `artifacts/` and in the vendor mirror.
fn artifact_name(a: &Artifact) -> String {
    a.dest.file_name().map_or_else(
        || a.dest.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Restore one artifact from the local vendor mirror `<vendor>/<name>`, a sha-verified copy, no
/// network, so an offline host builds from the vendored inputs. A missing vendored file is a clear
/// error naming `cargo xtask vendor`, never a silent fallback to the network (which would defeat the
/// point of pinning the host offline).
fn restore_from_vendor(a: &Artifact, vendor: &Path) -> Result<()> {
    let name = artifact_name(a);
    if a.dest.is_file() && sha256_of(&a.dest)? == a.sha256 {
        println!("✓ {name} already present (sha256 ok)");
        return Ok(());
    }
    let src = vendor.join(&name);
    if !src.is_file() {
        bail!(
            "vendored input {name} not found in {} — run `cargo xtask vendor` to populate the \
             mirror (or unset BSX_VENDOR_DIR to fetch from upstream)",
            vendor.display()
        );
    }
    let got = sha256_of(&src)?;
    if got != a.sha256 {
        bail!(
            "vendored {name} sha256 mismatch: expected {}, got {got}",
            a.sha256
        );
    }
    if let Some(parent) = a.dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::copy(&src, &a.dest).with_context(|| format!("copy vendored {name} into place"))?;
    println!("✓ {name} restored from vendor (sha256 ok)");
    Ok(())
}

/// Download one artifact into place if it isn't already present with the right hash. Downloads to a
/// `.part` and renames only after the hash verifies, so an interrupted download can never leave a
/// plausible-looking file at the final path. This is the raw upstream fetch; `cargo xtask vendor`
/// calls it directly (bypassing the vendor mirror) to populate that mirror in the first place.
pub(crate) fn download_one(a: &Artifact) -> Result<()> {
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
    // Per-pid temp name so two concurrent `xtask` fetches into the same dir can't interleave writes
    // to one `.part` (each verifies its own, then renames onto the shared final path atomically).
    let part = a
        .dest
        .with_extension(format!("part.{}", std::process::id()));
    if let Err(e) = curl_download(&a.url, &part) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    // Clean up the `.part` on *any* verify failure, including a `sha256sum` that can't run, so a
    // failed check never leaves a temp file behind.
    let got = match sha256_of(&part) {
        Ok(got) => got,
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
    };
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
    crate::run_tool(
        "curl",
        &[
            std::ffi::OsStr::new("-fSL"),
            std::ffi::OsStr::new("-o"),
            dest.as_os_str(),
            std::ffi::OsStr::new(url),
        ],
    )
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
