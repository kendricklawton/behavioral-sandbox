//! `cargo xtask vendor`, snapshot every sha-pinned upstream input into a **local mirror**, so a
//! fresh host builds the engine without the Firecracker S3 bucket or the Alpine CDN staying alive.
//!
//! This is the durable hardening [decision 007](../../docs/contributing-architecture.md) deferred:
//! the boot kernel + rootfs (Firecracker CI), the Alpine minirootfs, the static `apk` tool, **and**
//! the resolved `.apk` package closure are all fetched once, sha-verified, and written under the
//! vendor dir alongside a [`MANIFEST_NAME`] recording each file's hash. Afterwards, setting
//! `AGENT_VENDOR_DIR` to that dir takes every build path offline: [`fetch_one`](crate::artifacts)
//! restores the binary artifacts from the mirror, and the rootfs build installs the packages from the
//! vendored apk cache (`--no-network`) instead of the CDN.
//!
//! The mirror is **not** committed (it's gitignored, like `artifacts/`, the guardrail against
//! carrying built/downloaded images in the tree). A self-hoster produces it once and can then rebuild
//! offline forever; the manifest makes the vendored set auditable and offline-re-verifiable.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::artifacts::{artifacts, download_one, sha256_of, Artifact};
use crate::rootfs::{alpine_artifact, apk_tools_artifact, populate_apk_cache, APK_CACHE_SUBDIR};
use crate::workspace_root;

/// The manifest file the vendor snapshot writes: one `sha256  relpath` line per vendored file, so the
/// mirror is auditable and can be re-verified offline (`verify`) without re-contacting upstream.
pub(crate) const MANIFEST_NAME: &str = "vendor-manifest.txt";

/// The default vendor directory (`vendor/` under the workspace root) when `--dir` is omitted.
pub(crate) fn default_vendor_dir() -> PathBuf {
    workspace_root().join("vendor")
}

/// `cargo xtask vendor [--dir DIR]`: download every sha-pinned upstream input into `DIR`, populate
/// the apk cache with the resolved package closure, and write the sha manifest. Always fetches from
/// **upstream** (it is what fills the mirror), regardless of any `AGENT_VENDOR_DIR` already set.
pub(crate) fn vendor(dir: Option<PathBuf>) -> Result<()> {
    let dir = dir.unwrap_or_else(default_vendor_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create vendor dir {}", dir.display()))?;
    println!(
        "vendoring sha-pinned upstream inputs into {}\n",
        dir.display()
    );

    // The four single-file inputs: the boot kernel + rootfs (Firecracker CI) and the Alpine base +
    // static apk tool. Retargeted to land in the vendor dir, downloaded raw (bypassing the mirror).
    let mut inputs = artifacts()?;
    inputs.push(alpine_artifact()?);
    inputs.push(apk_tools_artifact()?);
    let alpine_tar = dir.join(artifact_name(&alpine_artifact()?));
    let apk_tools_tar = dir.join(artifact_name(&apk_tools_artifact()?));
    for a in inputs {
        download_one(&retarget(a, &dir))?;
    }

    // The `.apk` closure + index, an online `apk add` into a throwaway root, caching every package.
    // This is the piece decision 007 called out as "fetched-not-pinned"; the manifest below pins it.
    println!("\n↓ resolving + caching the guest package closure ...");
    populate_apk_cache(&dir.join(APK_CACHE_SUBDIR), &alpine_tar, &apk_tools_tar)?;

    // Record every vendored file's hash, so the set is auditable and re-verifiable offline.
    let entries = hash_tree(&dir)?;
    let count = entries.len();
    std::fs::write(dir.join(MANIFEST_NAME), render_manifest(&entries))
        .with_context(|| format!("write {}", dir.join(MANIFEST_NAME).display()))?;

    println!(
        "\n✓ vendored {count} files + manifest in {}\n  build offline with: AGENT_VENDOR_DIR={} \
         cargo xtask self-host",
        dir.display(),
        dir.display()
    );
    Ok(())
}

/// Re-verify a vendored mirror against its manifest, every listed file must still hash to its
/// recorded sha256. Offline (no upstream contact), so a self-hoster can prove the mirror is intact
/// before an offline build, and a bit-rotted or tampered file fails loudly here.
pub(crate) fn verify(dir: &Path) -> Result<()> {
    let manifest = dir.join(MANIFEST_NAME);
    let text = std::fs::read_to_string(&manifest).with_context(|| {
        format!(
            "read {} — run `cargo xtask vendor` to build the mirror first",
            manifest.display()
        )
    })?;
    let recorded = parse_manifest(&text);
    if recorded.is_empty() {
        bail!("vendor manifest {} is empty", manifest.display());
    }
    for (sha, rel) in &recorded {
        let path = dir.join(rel);
        if !path.is_file() {
            bail!("vendored file {} listed in the manifest is missing", rel);
        }
        let got = sha256_of(&path)?;
        if &got != sha {
            bail!("vendored {rel} sha256 mismatch: manifest {sha}, got {got}");
        }
    }
    println!(
        "✓ vendor mirror {} verified ({} files match the manifest)",
        dir.display(),
        recorded.len()
    );
    Ok(())
}

/// The final path component of an artifact's `dest`, as a `String`, the name it carries in the
/// vendor mirror.
fn artifact_name(a: &Artifact) -> String {
    a.dest
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
}

/// Point an artifact's `dest` at `<dir>/<name>` (its filename under the vendor mirror) while keeping
/// its URL + pinned sha, so `download_one` writes it into the mirror rather than `artifacts/`.
fn retarget(a: Artifact, dir: &Path) -> Artifact {
    let name = artifact_name(&a);
    Artifact {
        url: a.url,
        sha256: a.sha256,
        dest: dir.join(name),
    }
}

/// Every file under `root` (recursively), as sorted `(sha256, relative_path)` pairs, the manifest
/// body. The manifest file itself is skipped (it can't record its own hash).
fn hash_tree(root: &Path) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    walk_files(root, &mut files)?;
    let mut entries = Vec::with_capacity(files.len());
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        if rel == MANIFEST_NAME {
            continue;
        }
        entries.push((sha256_of(&path)?, rel));
    }
    entries.sort();
    Ok(entries)
}

/// Collect every regular file under `root` (recursing into subdirectories) into `out`.
fn walk_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let path = entry.path();
        if ty.is_dir() {
            walk_files(&path, out)?;
        } else if ty.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Render the manifest body: a header comment plus one `sha256  relpath` line per entry.
fn render_manifest(entries: &[(String, String)]) -> String {
    let mut out = String::from(
        "# agent vendored upstream inputs — `sha256  path` (path relative to this dir).\n\
         # Regenerate with `cargo xtask vendor`; re-verify offline with `cargo xtask vendor --verify`.\n\
         # This mirror is not committed (gitignored); the hashes below are the audit trail.\n",
    );
    for (sha, rel) in entries {
        out.push_str(sha);
        out.push_str("  ");
        out.push_str(rel);
        out.push('\n');
    }
    out
}

/// Parse a manifest back into `(sha256, relpath)` pairs, skipping comments and blank lines, the
/// inverse of [`render_manifest`].
fn parse_manifest(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (sha, rel) = l.split_once("  ")?;
            Some((sha.to_string(), rel.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips() {
        let entries = vec![
            ("aaaa".to_string(), "vmlinux".to_string()),
            (
                "bbbb".to_string(),
                "apk-cache/python3-3.12.1-r0.apk".to_string(),
            ),
        ];
        let rendered = render_manifest(&entries);
        assert_eq!(parse_manifest(&rendered), entries);
    }

    #[test]
    fn parse_skips_comments_and_blanks_and_keeps_pathed_names() {
        let text = "# a header\n\
                    \n\
                    dead  rootfs.ext4\n\
                    beef  apk-cache/APKINDEX.tar.gz\n";
        assert_eq!(
            parse_manifest(text),
            vec![
                ("dead".to_string(), "rootfs.ext4".to_string()),
                ("beef".to_string(), "apk-cache/APKINDEX.tar.gz".to_string()),
            ]
        );
    }

    #[test]
    fn a_two_space_separator_tolerates_spaces_in_neither_field() {
        // The `  ` split is exact: a single-space line (a malformed entry) is dropped, not
        // mis-parsed into a wrong (sha, path).
        assert!(parse_manifest("dead rootfs.ext4\n").is_empty());
    }
}
