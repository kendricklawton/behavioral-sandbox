//! `cargo xtask dist`: assemble the shippable release package: the release binary
//! plus the xtask-built guest kernel, rootfs, and eBPF object, staged into one directory,
//! checksummed, and tarred. The artifacts are built here at package time, never carried in the
//! source tree; the sha256 manifest is the integrity contract, the same discipline as the pinned
//! boot artifacts. `install.sh` (repo root, also packed into the tarball) consumes the result.
//!
//! Every step reuses the tested building blocks the individual `xtask` commands use, so this is
//! orchestration, not a second build path. Vendor-aware like `self-host`: with `EKVM_VENDOR_DIR`
//! set the whole assembly runs offline.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::artifacts::sha256_of;
use crate::{build_probes, cargo, guest_rootfs_path, kernel_path, workspace_root};

/// The packaged eBPF object's name inside `share/ekvm/` (the loader finds it via
/// `EKVM_PROBES_OBJECT`, which `install.sh` and the container image point here).
const PROBES_NAME: &str = "probes";

/// `cargo xtask dist [--version V]`: build binary + artifacts, stage, checksum, tar.
pub(crate) fn dist(version: Option<String>) -> Result<()> {
    // The supported platform is x86_64; a package assembled elsewhere would carry
    // artifacts that were never privileged-tested, so refuse rather than ship an untested claim.
    if std::env::consts::ARCH != "x86_64" {
        bail!(
            "dist packages only x86_64: this host is {}",
            std::env::consts::ARCH
        );
    }
    let version = match version {
        Some(v) => v,
        None => default_version(),
    };
    let name = format!("ekvm-{version}-x86_64-linux");
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
             nightly toolchain (see docs/contributing.md)",
            object.display()
        );
    }

    println!("\n== 4/5  build the release binary ==");
    cargo(&["build", "--release", "--locked", "-p", "ekvm"])?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from);
    let bin = target.join("release/ekvm");
    if !bin.is_file() {
        bail!("built binary {} not found", bin.display());
    }

    println!("\n== 5/5  stage + checksum + tar ==");
    let dist_dir = workspace_root().join("dist");
    let stage = dist_dir.join(&name);
    if stage.exists() {
        std::fs::remove_dir_all(&stage)
            .with_context(|| format!("clear stale stage {}", stage.display()))?;
    }
    let share = stage.join("share/ekvm");
    std::fs::create_dir_all(stage.join("bin")).context("create stage bin/")?;
    std::fs::create_dir_all(&share).context("create stage share/ekvm/")?;

    copy_mode(&bin, &stage.join("bin/ekvm"), 0o755)?;
    copy_mode(&kernel, &share.join("vmlinux"), 0o644)?;
    copy_mode(
        &guest_rootfs_path(),
        &share.join("rootfs-guest.ext4"),
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
    let sums_text = format!("{tar_sha}  {name}.tar.gz\n");
    std::fs::write(&sums, &sums_text).with_context(|| format!("write {}", sums.display()))?;

    let key_id = sign_release_manifest(&dist_dir)?;

    println!("\n✓ dist assembled:");
    println!("    {}", tarball.display());
    println!("    {}  (sha256 {tar_sha})", sums.display());
    match &key_id {
        Some(id) => println!(
            "    {}.sig  (detached ed25519, key_id {id})",
            sums.display()
        ),
        None => println!("    (UNSIGNED: no EKVM_RELEASE_SIGNING_KEY; do not publish)"),
    }
    println!(
        "  install it (any host):   sh {}/install.sh",
        stage.display()
    );
    println!(
        "  or from the tarball:     EKVM_DIST_TARBALL={} sh install.sh",
        tarball.display()
    );
    println!(
        "  container image:         docker build -f Containerfile --build-arg DIST=dist/{name} -t ekvm:{version} ."
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

/// The pinned release **public** key: `release-key.pem` at the repo root, byte-identical to the
/// PEM `install.sh` embeds (a dist test enforces the two never drift).
pub(crate) fn release_pubkey_path() -> PathBuf {
    workspace_root().join("release-key.pem")
}

/// Sign `dist/SHA256SUMS` with the operator's release key (`EKVM_RELEASE_SIGNING_KEY`, a key-file
/// path; distinct from `EKVM_SIGNING_KEY`, the *audit-record* key), writing `dist/SHA256SUMS.sig`:
/// a raw detached `ed25519` signature over the manifest's exact bytes, so a stock
/// `openssl pkeyutl -verify -rawin` checks it with no ekvm binary in the loop. Fail-closed by
/// construction: no key means an *unsigned* dist with a loud warning (release CI separately
/// refuses to publish one), never a generated throwaway key, and never key material under
/// `dist/`; a key that doesn't match the pinned `release-key.pem` is refused.
fn sign_release_manifest(dist_dir: &Path) -> Result<Option<String>> {
    let stale = dist_dir.join("release-signing.ed25519");
    if stale.exists() {
        bail!(
            "{} is a private key minted by the old signing scheme: remove it (and rotate the \
             key if it was ever published) before assembling a dist",
            stale.display()
        );
    }

    let Some(key_path) = std::env::var_os("EKVM_RELEASE_SIGNING_KEY") else {
        println!("  ! dist is UNSIGNED (set EKVM_RELEASE_SIGNING_KEY=<key file> to sign)");
        println!("  ! do not publish an unsigned dist; release CI refuses one");
        return Ok(None);
    };
    let key_path = PathBuf::from(key_path);
    let key = probes_loader::HostKey::open(&key_path)
        .with_context(|| format!("load release signing key from {}", key_path.display()))?;

    // The signing key must be the pinned release identity, not merely *a* key: a dist signed by
    // anything else fails every installer's pin.
    let pin_path = release_pubkey_path();
    let pin_pem = std::fs::read_to_string(&pin_path)
        .with_context(|| format!("read the pinned release public key {}", pin_path.display()))?;
    let pin = probes_loader::TrustedKey::from_spki_pem(&pin_pem)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", pin_path.display()))?;
    if pin.key_id() != key.key_id() {
        bail!(
            "signing key {} does not match the pinned release-key.pem ({}): wrong secret, or \
             the pin was not rotated",
            key.key_id(),
            pin.key_id()
        );
    }

    sign_manifest_bytes(dist_dir, &key)?;
    Ok(Some(key.key_id()))
}

/// The env-free signing core (what the tests call directly): a raw detached signature over the
/// manifest's exact bytes, nothing re-serialized in between, so the bytes `sha256sum -c` reads
/// are the bytes the signature covers.
fn sign_manifest_bytes(dist_dir: &Path, key: &probes_loader::HostKey) -> Result<()> {
    let sums_path = dist_dir.join("SHA256SUMS");
    let content =
        std::fs::read(&sums_path).with_context(|| format!("read {}", sums_path.display()))?;
    let sig_path = dist_dir.join("SHA256SUMS.sig");
    std::fs::write(&sig_path, key.sign_detached(&content))
        .with_context(|| format!("write {}", sig_path.display()))?;
    Ok(())
}

/// `cargo xtask release-key --path <file>`: mint (or show) the release signing key and print the
/// pin-and-secret ceremony. The private key lives wherever the operator points, never inside the
/// workspace's `dist/`.
pub(crate) fn release_key(path: &Path) -> Result<()> {
    let dist_dir = workspace_root().join("dist");
    if path.starts_with(&dist_dir) {
        bail!(
            "refusing to put the release private key under {} (it would ship with the artifacts)",
            dist_dir.display()
        );
    }
    let key = probes_loader::HostKey::load_or_generate(path)
        .map_err(|e| anyhow::anyhow!("load or generate {}: {e}", path.display()))?;
    let pem = key
        .verifying_key()
        .to_spki_pem()
        .map_err(|e| anyhow::anyhow!("encode public key: {e}"))?;
    println!("release signing key: {}", path.display());
    println!("key_id: {}", key.key_id());
    println!("\npublic key (SPKI PEM):\n{pem}");
    println!("ceremony (each step required before the next tagged release):");
    println!(
        "  1. pin it:      write the PEM above to {} AND into the install.sh heredoc",
        release_pubkey_path().display()
    );
    println!("                  (the dist test asserts the two match)");
    println!(
        "  2. CI secret:   gh secret set EKVM_RELEASE_SIGNING_KEY < {}",
        path.display()
    );
    println!("  3. keep custody: the key file stays outside the repo; rotating = repeat 1-2");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn detached_manifest_signature_round_trips_and_binds_the_exact_bytes() {
        let path = std::env::temp_dir().join(format!("dist_sign_test_{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        let _guard = TempDir(path.clone());

        let sample_manifest =
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  test.tar.gz\n";
        std::fs::write(path.join("SHA256SUMS"), sample_manifest).unwrap();

        let key = probes_loader::HostKey::from_seed([7u8; 32]);
        sign_manifest_bytes(&path, &key).unwrap();

        let sig = std::fs::read(path.join("SHA256SUMS.sig")).unwrap();
        let sig: [u8; 64] = sig
            .as_slice()
            .try_into()
            .expect("a raw detached ed25519 signature is exactly 64 bytes");
        key.verifying_key()
            .verify_detached(sample_manifest.as_bytes(), &sig)
            .expect("the signature covers the manifest's exact bytes");

        // A tampered manifest (what the installer's `sha256sum -c` would read) fails the check.
        let tampered = sample_manifest.replacen('1', "2", 1);
        assert!(key
            .verifying_key()
            .verify_detached(tampered.as_bytes(), &sig)
            .is_err());
    }

    /// The two pins can never drift: the PEM `install.sh` embeds (what installers trust) must be
    /// byte-identical to `release-key.pem` (what `sign_release_manifest` asserts the signing key
    /// against). Extracts the heredoc between the `PIN_EOF` markers.
    #[test]
    fn install_sh_pinned_key_matches_release_key_pem() {
        let repo = workspace_root();
        let install = std::fs::read_to_string(repo.join("install.sh")).unwrap();
        let mut lines = install.lines();
        let mut heredoc = String::new();
        for line in lines.by_ref() {
            if line.trim_end().ends_with("<<'PIN_EOF'") {
                break;
            }
        }
        for line in lines {
            if line.trim() == "PIN_EOF" {
                break;
            }
            heredoc.push_str(line);
            heredoc.push('\n');
        }
        assert!(
            heredoc.contains("BEGIN PUBLIC KEY"),
            "install.sh carries a pinned SPKI PEM heredoc (PIN_EOF markers)"
        );
        let pinned = std::fs::read_to_string(release_pubkey_path()).unwrap();
        assert_eq!(
            heredoc, pinned,
            "install.sh's embedded key must be byte-identical to release-key.pem"
        );
        // And the pin is a real ed25519 SPKI key, not a placeholder.
        probes_loader::TrustedKey::from_spki_pem(&pinned).expect("release-key.pem parses");
    }
}
