//! `cargo xtask dist`: assembles the shippable release package, the release binary plus the xtask-built
//! guest kernel, rootfs, and eBPF object, staged into one directory, checksummed, and tarred.
//!
//! The artifacts are built here at package time rather than carried in the source tree, and the sha256
//! manifest is the integrity contract. `install.sh`, also packed into the tarball, consumes the result.
//! Every step reuses the building blocks the individual `xtask` commands use, so this is orchestration
//! rather than a second build path, and it is vendor-aware, so with `BSX_VENDOR_DIR` set the whole
//! assembly runs offline.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::artifacts::sha256_of;
use crate::{build_probes, cargo_reproducible, guest_rootfs_path, kernel_path, workspace_root};

/// The packaged eBPF object's name inside `share/bsx/` (the loader finds it via
/// `BSX_PROBES_OBJECT`, which `install.sh` and the container image point here).
const PROBES_NAME: &str = "probes";

/// The target the **shipped** binary is built for: static musl, so the package carries no libc
/// dependency at all.
///
/// A glibc build binds to the build host's symbol versions, and glibc is backward but **not forward**
/// compatible, so a binary built on a newer runner fails before `main()` with a loader error that says
/// nothing about this engine. Building on the oldest supported glibc would make the CI runner the
/// compatibility floor; linking musl statically removes the floor instead, the same move `guest-agent`
/// makes. Dev builds stay native, since this is the package's target rather than the workspace's.
const DIST_TARGET: &str = "x86_64-unknown-linux-musl";

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
    version_matches_manifest(&version, env!("CARGO_PKG_VERSION"))?;
    let name = format!("bsx-{version}-x86_64-linux");
    println!("dist: assembling {name}\n");

    println!("== 1/5  obtain the pinned guest kernel ==");
    let kernel = kernel_path();
    let pinned = crate::artifacts::artifacts()?
        .into_iter()
        .find(|a| a.dest == kernel)
        .context("no pinned guest kernel for this architecture")?;
    crate::artifacts::fetch_one(&pinned)?;

    println!("\n== 2/5  build the guest rootfs (agent baked in) ==");
    // `build_rootfs` only *warns* below the floor, so a dev build still works on a stale host. A
    // package is the one place that is wrong: the image would boot fine and hash differently from
    // every other build of the same tree, which is undetectable from the tarball alone and turns a
    // signed artifact into one nobody can reproduce. Same call as the eBPF object below.
    match crate::rootfs::mke2fs_version() {
        Some(v) if v < crate::rootfs::MKE2FS_SOURCE_DATE_EPOCH_MIN => {
            let (ma, mi, pa) = v;
            let (fa, fi, fp) = crate::rootfs::MKE2FS_SOURCE_DATE_EPOCH_MIN;
            bail!(
                "mke2fs {ma}.{mi}.{pa} ignores SOURCE_DATE_EPOCH (honoured from e2fsprogs \
                 {fa}.{fi}.{fp}), so the packaged rootfs would not be byte-reproducible. A dist \
                 ships an image whose hash is recorded; install e2fsprogs >= {fa}.{fi}.{fp}"
            );
        }
        None => bail!(
            "mke2fs not found or its version unparseable; a dist needs it to build the guest rootfs"
        ),
        Some(_) => {}
    }
    crate::rootfs::build_rootfs(false, false)?;

    println!("\n== 3/5  build the eBPF probe object ==");
    build_probes()?;
    let object = workspace_root().join("crates/probes/target/bpfel-unknown-none/release/probes");
    if !object.is_file() {
        // `build_probes` soft-skips without the eBPF toolchain so the everyday gate stays
        // host-safe; a *package* without the observability half is not the product, so hard-fail.
        bail!(
            "eBPF object not built ({}) — a dist ships the audit half; install bpf-linker + the \
             nightly toolchain (see AGENTS.md)",
            object.display()
        );
    }

    println!("\n== 4/5  build the release binary (static, {DIST_TARGET}) ==");
    cargo_reproducible(&[
        "build",
        "--release",
        "--locked",
        "-p",
        "bsx",
        "--target",
        DIST_TARGET,
    ])
    .with_context(|| {
        format!(
            "static build failed. The target has to be installed: `rustup target add {DIST_TARGET}`"
        )
    })?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from);
    let bin = target.join(DIST_TARGET).join("release/bsx");
    if !bin.is_file() {
        bail!("built binary {} not found", bin.display());
    }
    crate::guest_bins::verify_static(&bin, "bsx host binary")?;

    println!("\n== 5/5  stage + checksum + tar ==");
    let dist_dir = workspace_root().join("dist");
    let stage = dist_dir.join(&name);
    if stage.exists() {
        std::fs::remove_dir_all(&stage)
            .with_context(|| format!("clear stale stage {}", stage.display()))?;
    }
    let share = stage.join("share/bsx");
    std::fs::create_dir_all(stage.join("bin")).context("create stage bin/")?;
    std::fs::create_dir_all(&share).context("create stage share/bsx/")?;

    copy_mode(&bin, &stage.join("bin/bsx"), 0o755)?;
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
        None => println!("    (UNSIGNED: no BSX_RELEASE_SIGNING_KEY; do not publish)"),
    }
    println!(
        "  install it (any host):   sh {}/install.sh",
        stage.display()
    );
    println!(
        "  or from the tarball:     BSX_DIST_TARBALL={} sh install.sh",
        tarball.display()
    );
    println!(
        "  container image:         docker build -f Containerfile --build-arg DIST=dist/{name} -t bsx:{version} ."
    );
    Ok(())
}

/// A release version names the tarball but does *not* set what the binary reports: that comes from
/// the workspace `version`, compiled in. `v0.0.1` shipped with the two disagreeing, so
/// `bsx-0.0.1-x86_64-linux.tar.gz` answered `bsx --version` with `0.0.0`. Release CI passes
/// `--version` from the pushed tag, so packaging is where the tag meets the manifest: refuse rather
/// than ship a binary that misreports itself.
///
/// `-dev.<rev>` builds are exempt. They are not a tag and never claim to be.
fn version_matches_manifest(version: &str, pkg: &str) -> Result<()> {
    if !version.contains("-dev.") && version != pkg {
        bail!(
            "version mismatch: packaging {version} but the workspace is {pkg}, so the binary would \
             report {pkg}. Bump `version` in Cargo.toml (and crates/probes, fuzz) to {version}, or \
             tag v{pkg}."
        );
    }
    Ok(())
}

/// The default package version: the nearest checkpoint tag (`git describe --tags`, the `v0.0.x`
/// pre-release line RELEASES.md defines, `v` stripped), falling back to `<pkg>-dev.<rev>` in a
/// tagless clone. Release CI passes `--version` from the pushed tag instead.
///
/// The fallback's number comes from the workspace version rather than a literal, which was `0.0.0`
/// here until the `v0.0.1` tag made it stale: a hardcoded version in the *dev* path goes wrong
/// quietly, since the tagged path never reads it.
fn default_version() -> String {
    let describe = git_stdout(&["describe", "--tags", "--always", "--dirty=.dirty"]);
    let pkg = env!("CARGO_PKG_VERSION");
    match describe {
        Some(d) if d.starts_with('v') => d[1..].to_string(),
        Some(rev) => format!("{pkg}-dev.{rev}"),
        None => format!("{pkg}-dev.unknown"),
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

/// The flags that make the release tarball byte-identical across builds of one tree: a stable entry
/// order, ownership that cannot carry the builder's uid, and an mtime pinned to a constant.
///
/// Split out from [`tar_stage`] so it is assertable without running `tar`, since the property is a
/// claim about these flags rather than about the process.
fn deterministic_tar_flags() -> Vec<String> {
    vec![
        "--sort=name".to_string(),
        "--owner=0".to_string(),
        "--group=0".to_string(),
        "--numeric-owner".to_string(),
        format!("--mtime=@{}", crate::rootfs::ROOTFS_SOURCE_DATE_EPOCH),
    ]
}

/// Tar the staged directory deterministically: sorted names, numeric zero owners, and `--mtime`
/// pinned to the **same fixed epoch the rootfs image uses**, so two builds of one tree agree.
///
/// The epoch comes from the constant, never from the ambient `SOURCE_DATE_EPOCH`: an
/// environment-dependent value cannot give the property this function claims, because a verifier's shell
/// is not the release runner's, and an unset variable falls back to wall clock.
fn tar_stage(dist_dir: &Path, name: &str, tarball: &Path) -> Result<()> {
    let mut cmd = Command::new("tar");
    cmd.args(deterministic_tar_flags());
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

/// Sign `dist/SHA256SUMS` with the operator's release key (`BSX_RELEASE_SIGNING_KEY`, a key-file
/// path; distinct from `BSX_SIGNING_KEY`, the *audit-record* key), writing `dist/SHA256SUMS.sig`:
/// a raw detached `ed25519` signature over the manifest's exact bytes, so a stock
/// `openssl pkeyutl -verify -rawin` checks it with no bsx binary in the loop. Fail-closed by
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

    let Some(key_path) = std::env::var_os("BSX_RELEASE_SIGNING_KEY") else {
        println!("  ! dist is UNSIGNED (set BSX_RELEASE_SIGNING_KEY=<key file> to sign)");
        println!("  ! do not publish an unsigned dist; release CI refuses one");
        return Ok(None);
    };
    let key_path = PathBuf::from(key_path);
    let key = bsx_probes_loader::HostKey::open(&key_path)
        .with_context(|| format!("load release signing key from {}", key_path.display()))?;

    // The signing key must be the pinned release identity, not merely *a* key: a dist signed by
    // anything else fails every installer's pin.
    let pin_path = release_pubkey_path();
    let pin_pem = std::fs::read_to_string(&pin_path)
        .with_context(|| format!("read the pinned release public key {}", pin_path.display()))?;
    let pin = bsx_probes_loader::TrustedKey::from_spki_pem(&pin_pem)
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
fn sign_manifest_bytes(dist_dir: &Path, key: &bsx_probes_loader::HostKey) -> Result<()> {
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
    let key = bsx_probes_loader::HostKey::load_or_generate(path)
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
        "  2. CI secret:   gh secret set BSX_RELEASE_SIGNING_KEY < {}",
        path.display()
    );
    println!("  3. keep custody: the key file stays outside the repo; rotating = repeat 1-2");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BPF_LINKER_VERSION;

    /// The release tarball has to be byte-identical across builds of one tree, so a verifier on a
    /// stranger box reaches the `SHA256SUMS` the release signed. Wall-clock mtimes defeat that, and
    /// they are what `tar` writes unless told otherwise. This pins the flag rather than the
    /// resulting hash: a hash would have to be regenerated on every content change and would stop
    /// testing anything.
    ///
    /// Reading `SOURCE_DATE_EPOCH` from the environment was the original bug. Nothing in `dist` set
    /// it, so the pin silently did not apply, and two builds minutes apart differed.
    #[test]
    fn the_release_tarball_mtime_is_pinned_to_the_rootfs_epoch() {
        let flags = deterministic_tar_flags();
        let expected = format!("--mtime=@{}", crate::rootfs::ROOTFS_SOURCE_DATE_EPOCH);
        assert!(
            flags.contains(&expected),
            "tar must pin --mtime to the fixed rootfs epoch, got {flags:?}"
        );
        // The value has to be a constant, not whatever the caller's shell happens to carry: a
        // verifier's environment is not the release runner's.
        assert!(
            crate::rootfs::ROOTFS_SOURCE_DATE_EPOCH
                .chars()
                .all(|c| c.is_ascii_digit()),
            "the epoch must be a literal timestamp"
        );
    }

    /// Ownership must not depend on who ran the build, the same property `5b34dfd` fixed one layer
    /// down for the rootfs image itself.
    #[test]
    fn the_release_tarball_records_no_builder_identity() {
        let flags = deterministic_tar_flags();
        for expected in ["--owner=0", "--group=0", "--numeric-owner", "--sort=name"] {
            assert!(
                flags.iter().any(|f| f == expected),
                "tar must pass {expected}, got {flags:?}"
            );
        }
    }

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

        let key = bsx_probes_loader::HostKey::from_seed([7u8; 32]);
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
        assert!(
            key.verifying_key()
                .verify_detached(tampered.as_bytes(), &sig)
                .is_err()
        );
    }

    /// The exact shape that shipped `v0.0.1`: the pushed tag said `0.0.1`, the workspace still said
    /// `0.0.0`, and nothing compared them, so the tarball's name and the binary's `--version`
    /// disagreed. A dev build carries the rev and is left alone.
    #[test]
    fn dist_refuses_a_version_the_binary_would_not_report() {
        assert!(version_matches_manifest("0.0.1", "0.0.0").is_err());
        assert!(version_matches_manifest("0.1.0", "0.0.2").is_err());

        assert!(version_matches_manifest("0.0.2", "0.0.2").is_ok());
        assert!(version_matches_manifest("0.0.2-dev.abc1234", "0.0.2").is_ok());
        // The dev path builds its string from the workspace version, but a stale tag in the
        // describe output must not turn into a release-shaped package either.
        assert!(version_matches_manifest("0.0.1-dev.abc1234", "0.0.2").is_ok());
    }

    /// `sh` reading from a pipe executes as it reads, so `curl … | sh` over a connection that drops
    /// mid-transfer runs a *prefix* of the script. Before the `main()` guard, a drop after the
    /// binary install left the kernel, rootfs and probes object missing, exit status 0, and a green
    /// tick as the last line. Deferring every filesystem-touching statement to `main`, invoked on
    /// the last line, makes a truncated stream a no-op: nothing runs until the whole file parses.
    ///
    /// Asserted structurally rather than by truncating at 300 line offsets in the gate: the
    /// regression this guards against is someone adding a statement back at column zero.
    #[test]
    fn installer_body_is_deferred_to_a_main_guard() {
        let install = std::fs::read_to_string(workspace_root().join("install.sh")).unwrap();

        let last = install
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .expect("install.sh is not empty");
        assert_eq!(
            last, "main \"$@\"",
            "the main call must be the last line, or a truncated stream still executes a prefix"
        );

        // Everything at column zero that is not a comment, a blank, `set -eu`, a constant
        // assignment, a function definition or its closing brace, a heredoc body, or the call
        // itself. That set being empty is what makes every proper prefix of this file a no-op.
        let mut stray: Vec<&str> = Vec::new();
        let mut heredoc_end: Option<String> = None;
        for line in install.lines().map(str::trim_end) {
            // Heredoc bodies sit at column zero on purpose (the pinned PEM is compared
            // byte-for-byte against release-key.pem) and are data, not statements.
            if let Some(marker) = &heredoc_end {
                if line == marker {
                    heredoc_end = None;
                }
                continue;
            }
            if let Some((_, rest)) = line.split_once("<<'")
                && let Some(marker) = rest.strip_suffix('\'')
            {
                heredoc_end = Some(marker.to_string());
            }
            if line.starts_with(char::is_whitespace)
                || line.is_empty()
                || line.starts_with('#')
                || line == "set -eu"
                || line == "}"
                || line == "main \"$@\""
                // `name() {` and one-line `name() { … }` definitions.
                || (line.contains("()") && line.contains('{'))
            {
                continue;
            }
            // `NAME="value"` constants.
            let is_constant = line.split_once('=').is_some_and(|(name, _)| {
                name.starts_with(|c: char| c.is_ascii_uppercase())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
            if !is_constant {
                stray.push(line);
            }
        }
        assert!(
            stray.is_empty(),
            "install.sh runs these at top level, so a truncated `curl | sh` would execute them; \
             move them inside main(): {stray:?}"
        );
    }

    /// The same drift guard, for the guest's IPv6 link. `bsx-probes-common` needs the prefix as a
    /// `#![no_std]` constant ([`GUEST_LINK6`]) because the in-kernel ICMPv6 spare decides on-link
    /// versus routable without a map lookup; `crates/engine/src/net.rs` owns the addresses it
    /// actually assigns. The engine does not depend on `probes-common`, and its address constants
    /// are `pub(crate)`, so neither can read the other: the copies are compared here, exactly as the
    /// Firecracker pin's are.
    ///
    /// Drift is a **security** defect, not an inconsistency. If the engine re-addresses the link and
    /// the eBPF constant stays put, the spare stops covering the real host end (NUD breaks, noisily)
    /// or, worse, keeps sparing a prefix the guest can now route off, which is the unpoliced ICMPv6
    /// channel narrowing `fc00::/7` to this one `/64` closed.
    #[test]
    fn the_guest_v6_link_is_the_same_in_the_engine_and_the_probes() {
        let repo = workspace_root();
        let net = std::fs::read_to_string(repo.join("crates/engine/src/net.rs"))
            .expect("crates/engine/src/net.rs");
        let common = std::fs::read_to_string(repo.join("crates/probes-common/src/lib.rs"))
            .expect("crates/probes-common/src/lib.rs");

        // The engine writes its ends as `Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, N)`; take the
        // first two hextets (the /32 the /64 prefix's non-zero bytes live in) plus the prefix length.
        let hextets = |text: &str, name: &str| -> Option<(u16, u16)> {
            let line = text
                .lines()
                .find(|l| l.contains(name) && l.contains("Ipv6Addr::new"))?;
            let args = line.split("Ipv6Addr::new(").nth(1)?.split(')').next()?;
            let mut it = args.split(',').map(str::trim);
            let parse = |t: &str| u16::from_str_radix(t.trim_start_matches("0x"), 16).ok();
            Some((parse(it.next()?)?, parse(it.next()?)?))
        };
        let host = hextets(&net, "HOST_IP6").expect("net.rs must define HOST_IP6");
        let guest = hextets(&net, "GUEST_IP6").expect("net.rs must define GUEST_IP6");
        assert_eq!(host, guest, "the two ends must sit on one prefix");
        let engine_len: u8 = net
            .lines()
            .find(|l| l.contains("HOST_PREFIX6") && l.contains('='))
            .and_then(|l| l.rsplit('=').next())
            .map(|v| v.trim().trim_end_matches(';').trim())
            .and_then(|v| v.parse().ok())
            .expect("net.rs must define HOST_PREFIX6");

        // `GUEST_LINK6` is `([u8; 16], u8)`, so the declaration ends at the tuple's `);` (not at the
        // first `;`, which sits inside the array type). Its first four bytes carry the same two
        // hextets the engine writes, and its trailing decimal is the prefix length.
        let body = common
            .split("pub const GUEST_LINK6")
            .nth(1)
            .and_then(|rest| rest.split(");").next())
            .expect("probes-common must define GUEST_LINK6");
        let bytes: Vec<u16> = body
            .split(|c: char| !c.is_ascii_hexdigit() && c != 'x')
            .filter(|t| t.starts_with("0x"))
            .filter_map(|t| u16::from_str_radix(&t[2..], 16).ok())
            .collect();
        assert!(
            bytes.len() >= 4,
            "GUEST_LINK6 must spell its prefix bytes as 0x.. literals, got {bytes:?}"
        );
        let probes = (
            (bytes[0] << 8) | bytes[1],
            (bytes[2] << 8) | bytes[3],
            body.rsplit(',')
                .find_map(|t| t.trim().parse::<u8>().ok())
                .expect("GUEST_LINK6 must carry a prefix length"),
        );
        assert_eq!(
            (host.0, host.1, engine_len),
            probes,
            "the engine assigns {:x}:{:x}::/{engine_len} but the eBPF ICMPv6 spare covers \
             {:x}:{:x}::/{}: the in-kernel policy and the real link must name one prefix",
            host.0,
            host.1,
            probes.0,
            probes.1,
            probes.2
        );
    }

    /// Same drift guard, for the Firecracker pin. `install.sh` carries its own copy of the pinned
    /// release sha256 (installers run it before this repo is built, so it cannot call into `bsx`),
    /// and `doctor.rs` carries the one the engine checks at runtime. Two copies of a security-
    /// relevant hash drift silently, and nothing but this compares them.
    #[test]
    fn install_sh_firecracker_pin_matches_doctor() {
        let repo = workspace_root();
        let install = std::fs::read_to_string(repo.join("install.sh")).unwrap();
        let doctor = std::fs::read_to_string(repo.join("crates/engine/src/doctor.rs")).unwrap();

        let shas_in = |text: &str, prefix: &str| -> Vec<String> {
            text.lines()
                .filter(|l| l.contains(prefix))
                .filter_map(|l| {
                    l.split('"')
                        .find(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
                })
                .map(str::to_string)
                .collect()
        };

        let installer = shas_in(&install, "FC_PIN");
        assert!(
            !installer.is_empty(),
            "install.sh should carry at least one pinned Firecracker sha256 (FC_PIN*)"
        );
        // Every hash the installer trusts must be one the engine also blesses; the engine may know
        // about more (a newly hashed patch release lands there first).
        let blessed: Vec<String> = doctor
            .lines()
            .filter(|l| l.contains("// v1."))
            .filter_map(|l| {
                l.split('"')
                    .find(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
            })
            .map(str::to_string)
            .collect();
        assert!(
            !blessed.is_empty(),
            "doctor.rs should carry PINNED_FIRECRACKER_SHA256 entries commented with their version"
        );
        for sha in &installer {
            assert!(
                blessed.contains(sha),
                "install.sh pins {sha}, which doctor.rs no longer blesses: the two copies drifted"
            );
        }
    }

    /// Same drift guard, for the release *version* the installer's printed commands download.
    /// The sha test above would catch a drifted binary, but only after an operator installed the
    /// wrong one; this catches the printed instructions themselves going stale when
    /// `PINNED_FC_VERSION` moves.
    #[test]
    fn install_sh_firecracker_version_is_in_the_pinned_series() {
        let repo = workspace_root();
        let install = std::fs::read_to_string(repo.join("install.sh")).unwrap();
        let spawn =
            std::fs::read_to_string(repo.join("crates/engine/src/spawn/fcversion.rs")).unwrap();

        let fc_ver = install
            .lines()
            .find_map(|l| l.strip_prefix("FC_VER=\"v")?.strip_suffix('"'))
            .expect("install.sh single-sources the release as FC_VER=\"vX.Y.Z\"");
        // `pub(crate) const PINNED_FC_VERSION: (u64, u64) = (1, 16);` -> "1, 16" -> "1.16".
        let pinned_series = spawn
            .lines()
            .find(|l| l.contains("PINNED_FC_VERSION: (u64, u64)"))
            .and_then(|l| l.rsplit('(').next())
            .map(|t| {
                t.trim_end_matches(|c: char| !c.is_ascii_digit())
                    .replace(", ", ".")
            })
            .expect("spawn/fcversion.rs declares PINNED_FC_VERSION: (u64, u64)");
        assert!(
            !pinned_series.is_empty() && pinned_series.contains('.'),
            "parsed an empty series out of spawn/fcversion.rs: the declaration's shape moved"
        );
        assert!(
            fc_ver == pinned_series || fc_ver.starts_with(&format!("{pinned_series}.")),
            "install.sh tells operators to install v{fc_ver}, but the engine pins the v{pinned_series} \
             series: the printed install commands drifted"
        );
    }

    /// The privileged workflow gates **every** series the engine claims, not just the pinned one.
    /// A GitHub Actions matrix cannot read `MIN_SUPPORTED_FC_VERSION`/`PINNED_FC_VERSION`, so its
    /// lane list is a fourth copy of the range and drifts like every copy: this compares the set of
    /// series it installs against the set the engine declares, in both directions.
    ///
    /// The asymmetry is what makes it worth a test. A missing lane is silent, and specifically
    /// silent about the end of the range nobody runs by hand: the engine adapts its API requests
    /// across the supported window (`clock_realtime` is withheld below v1.16), so a claim of
    /// "v1.15 through v1.16" gated only at v1.16 can regress on the floor with CI fully green.
    /// A lane for a series the engine no longer claims is the opposite failure, spending a
    /// privileged runner on a VMM upstream has stopped patching.
    #[test]
    fn the_privileged_workflow_gates_every_supported_firecracker_series() {
        let repo = workspace_root();
        let wf = repo.join(".github/workflows/ci-privileged-hosted.yml");
        let text = std::fs::read_to_string(&wf).expect("ci-privileged-hosted.yml");
        let spawn =
            std::fs::read_to_string(repo.join("crates/engine/src/spawn/fcversion.rs")).unwrap();

        // `pub(crate) const NAME: (u64, u64) = (1, 15);` -> (1, 15).
        let constant = |name: &str| -> (u64, u64) {
            let nums = spawn
                .lines()
                .find(|l| l.contains(&format!("{name}: (u64, u64)")))
                .and_then(|l| l.rsplit('(').next())
                .map(|t| {
                    t.split(|c: char| !c.is_ascii_digit())
                        .filter_map(|d| d.parse::<u64>().ok())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            assert!(
                nums.len() >= 2,
                "spawn/fcversion.rs must declare `{name}: (u64, u64) = (major, minor)`; parsed \
                 {nums:?}, so the declaration's shape moved and this guard reads nothing"
            );
            (nums[0], nums[1])
        };
        let (floor, pin) = (
            constant("MIN_SUPPORTED_FC_VERSION"),
            constant("PINNED_FC_VERSION"),
        );

        // The lanes: `- fc: vX.Y.Z` entries in the matrix, reduced to their series. A lane installs
        // a patch release; what the engine reasons about is the series.
        let mut lanes: Vec<(u64, u64)> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.strip_prefix("- fc: v"))
            .map(|v| {
                let mut it = v.split('.').filter_map(|d| d.parse::<u64>().ok());
                (it.next().unwrap_or(0), it.next().unwrap_or(0))
            })
            .collect();
        lanes.sort_unstable();
        lanes.dedup();
        assert!(
            !lanes.is_empty(),
            "no `- fc: vX.Y.Z` lanes found in {}: the matrix shape this test greps for moved, so \
             it is asserting nothing",
            wf.display()
        );

        // Every series from the floor through the pin, which is what the support claim names.
        assert_eq!(
            floor.0, pin.0,
            "the supported range spans a major bump: {floor:?}..={pin:?}"
        );
        let claimed: Vec<(u64, u64)> = (floor.1..=pin.1).map(|minor| (floor.0, minor)).collect();
        assert_eq!(
            lanes, claimed,
            "the privileged workflow gates {lanes:?} but the engine claims {claimed:?} \
             (MIN_SUPPORTED_FC_VERSION..=PINNED_FC_VERSION): every claimed series needs a lane, \
             and a lane for an unclaimed series burns a privileged runner on a VMM the engine \
             does not support"
        );
    }

    /// Same drift guard, for the **third** copy of the Firecracker pin: the container image's
    /// `FC_VERSION` build arg. Unchecked, it can sit below the supported floor and bundle a VMM
    /// upstream no longer patches into the image.
    #[test]
    fn containerfile_firecracker_is_the_pinned_series() {
        let repo = workspace_root();
        let container = std::fs::read_to_string(repo.join("Containerfile")).expect("Containerfile");
        let spawn =
            std::fs::read_to_string(repo.join("crates/engine/src/spawn/fcversion.rs")).unwrap();

        let fc_ver = container
            .lines()
            .find_map(|l| l.strip_prefix("ARG FC_VERSION=v"))
            .expect("Containerfile single-sources its release as ARG FC_VERSION=vX.Y.Z");
        let pinned_series = spawn
            .lines()
            .find(|l| l.contains("PINNED_FC_VERSION: (u64, u64)"))
            .and_then(|l| l.rsplit('(').next())
            .map(|t| {
                t.trim_end_matches(|c: char| !c.is_ascii_digit())
                    .replace(", ", ".")
            })
            .expect("spawn/fcversion.rs declares PINNED_FC_VERSION: (u64, u64)");
        assert!(
            fc_ver == pinned_series || fc_ver.starts_with(&format!("{pinned_series}.")),
            "Containerfile bundles Firecracker v{fc_ver}, but the engine pins the v{pinned_series} \
             series: the image would ship a VMM the engine does not test"
        );

        // The sha is the download's integrity contract; a version bump that forgets it downloads
        // one release and verifies another, which the build then fails on, but say so here first.
        let sha = container
            .lines()
            .find_map(|l| l.strip_prefix("ARG FC_SHA256="))
            .expect("Containerfile pins the tarball as ARG FC_SHA256=<64 hex>");
        assert!(
            sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit()),
            "FC_SHA256 is not a sha256: {sha:?}"
        );
    }

    /// Same drift guard, for the eBPF build toolchain. Unlike `aya` (a Cargo dependency, pinned by
    /// `Cargo.lock`), the nightly compiler and `bpf-linker` are installed **out of band**, so each
    /// needs its own pin, and each pin has copies a workflow file cannot resolve at runtime: a
    /// GitHub Actions step cannot read `rust-toolchain.toml` or a Rust constant, so it restates the
    /// version. This compares every copy against its single source, which is the only thing standing
    /// between them and the drift that let the Firecracker pin sit 21 months stale.
    ///
    /// Both are checked together because they move together: `bpf-linker` links against the pinned
    /// nightly's LLVM, so bumping one alone is how the pair desynchronizes.
    #[test]
    fn ebpf_toolchain_pins_are_single_sourced() {
        let repo = workspace_root();
        // The sources of truth: the toolchain file, and xtask's own constant.
        let toolchain = std::fs::read_to_string(repo.join("crates/probes/rust-toolchain.toml"))
            .expect("crates/probes/rust-toolchain.toml");
        let channel = toolchain
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| l.strip_prefix("channel"))
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_string())
            .expect("crates/probes/rust-toolchain.toml must declare [toolchain] channel");
        // A floating channel is the defect this test exists to prevent, not merely an inconsistency:
        // every copy would "agree" while each machine built with a different compiler.
        assert!(
            channel.starts_with("nightly-") && channel.len() > "nightly-".len(),
            "the probes toolchain must pin an exact dated nightly, got {channel:?}: a floating \
             channel means CI builds with whatever shipped that morning"
        );

        // **Every** workflow, discovered by reading the directory rather than a hardcoded list: a
        // list silently exempts whatever it omits, which reads as coverage and is not. (The first
        // version of this test listed four files and missed both fuzz workflows, each of which
        // installed a floating nightly.) A new workflow is covered the moment it is added.
        let dir = repo.join(".github/workflows");
        let mut checked = 0usize;
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .expect(".github/workflows")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
            .collect();
        entries.sort();
        assert!(
            !entries.is_empty(),
            "no workflows found in {}",
            dir.display()
        );
        for path in &entries {
            let wf = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let text = std::fs::read_to_string(path).expect("read workflow");
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('#') {
                    continue;
                }
                if line.contains("rustup toolchain install") && line.contains("nightly") {
                    assert!(
                        line.contains(&channel),
                        "{wf} installs a nightly that is not the pinned {channel}: {line}"
                    );
                    checked += 1;
                }
                for (tool, version) in [("bpf-linker", BPF_LINKER_VERSION)] {
                    if line.contains(&format!("cargo install {tool}")) {
                        assert!(
                            line.contains(&format!("--version {version}")),
                            "{wf} installs {tool} unpinned; `--locked` locks its dependencies, not \
                             {tool} itself, so add `--version {version}`: {line}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        // A rename of the install step (or a move to a composite action) would otherwise make every
        // assertion above vacuous while the test still passed: no matches, no failures, green.
        assert!(
            checked > 0,
            "no pinned toolchain/tool installs matched in {}: the patterns this test greps for have \
             drifted from what the workflows actually run, so it is asserting nothing",
            dir.display()
        );

        // The build instructions hand out the same commands; a reader who follows them must land on
        // the pinned versions, not on whatever is newest.
        const BUILDING_DOC: &str = "AGENTS.md";
        let contributing = std::fs::read_to_string(repo.join(BUILDING_DOC)).expect(BUILDING_DOC);
        let mut doc_checked = 0usize;
        for line in contributing.lines() {
            for (tool, version) in [("bpf-linker", BPF_LINKER_VERSION)] {
                if line.contains(&format!("cargo install {tool}")) {
                    doc_checked += 1;
                    assert!(
                        line.contains(&format!("--version {version}")),
                        "{BUILDING_DOC} tells contributors to install {tool} unpinned: {line}"
                    );
                }
            }
        }
        // Same non-vacuity guard as the workflow scan above: moving the install command to another
        // page (or rewording it) would otherwise leave this loop matching nothing and passing green,
        // which is how an unpinned `cargo install` gets back into the docs unnoticed.
        assert!(
            doc_checked > 0,
            "no `cargo install` line matched in {BUILDING_DOC}: the setup commands moved, so this \
             test is asserting nothing. Point it at the page that now hands them out."
        );
    }

    /// Workflows name repo files as bare shell text: a parser's target, or an error message telling a
    /// human which file to edit. The prose-drift lint reads `.rs` and `.md` only, and even there it wants
    /// a backticked span, so without this a rename lands green and the weekly job fails days later on a
    /// path that no longer exists.
    ///
    /// Scoped to the `crates/` and `xtask/` prefixes, which are ours. A workflow also fetches a
    /// path out of upstream Firecracker's repo by URL, and `dist/` is build output; neither is a
    /// file this tree can be asked to hold.
    #[test]
    fn workflow_repo_paths_exist() {
        let repo = workspace_root();
        let dir = repo.join(".github/workflows");
        let mut checked = 0usize;
        let mut missing: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect(".github/workflows") {
            let path = entry.expect("workflow dir entry").path();
            // Both spellings: a `.yaml` file GitHub runs but this scan skipped would be a
            // silent hole in exactly the coverage the test claims.
            if !matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            ) {
                continue;
            }
            let wf = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).expect("read workflow");
            for (idx, line) in text.lines().enumerate() {
                for token in line.split(|c: char| c.is_ascii_whitespace() || "\"'`(),".contains(c))
                {
                    if !(token.starts_with("crates/") || token.starts_with("xtask/")) {
                        continue;
                    }
                    // `crates/engine/**` is a path *filter*, not a file: check the dir it roots.
                    // Trailing sentence punctuation is not part of the path either.
                    let target = token
                        .trim_end_matches("/**")
                        .trim_end_matches(['.', ':', ';']);
                    checked += 1;
                    if !repo.join(target).exists() {
                        missing.push(format!("{wf}:{}: {target}", idx + 1));
                    }
                }
            }
        }
        // Without this, a workflow rename (or a move to composite actions) leaves the scan
        // matching nothing and passing green, which is the failure mode this whole test exists
        // to prevent.
        assert!(
            checked > 0,
            "no crates/ or xtask/ path reference matched in {}: the workflows no longer name repo \
             files the way this scan looks for, so it is asserting nothing",
            dir.display()
        );
        assert!(
            missing.is_empty(),
            "workflow(s) reference repo paths that no longer exist:\n  {}",
            missing.join("\n  ")
        );
    }

    /// The sharper half of the question above. A workflow that greps a constant out of a source
    /// file depends on two things: the file existing (checked above) *and* the pattern still
    /// matching inside it. Moving a constant out of a file that itself stays in place satisfies the
    /// path check while the parser matches nothing. Runs each workflow's own `grep -oE` against its
    /// own target and requires a hit, so the parser's contract is a test rather than a surprise.
    #[test]
    fn workflow_source_parsers_still_match() {
        let repo = workspace_root();
        let dir = repo.join(".github/workflows");
        let mut checked = 0usize;
        let mut unreadable: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect(".github/workflows") {
            let path = entry.expect("workflow dir entry").path();
            // Both spellings: a `.yaml` file GitHub runs but this scan skipped would be a
            // silent hole in exactly the coverage the test claims.
            if !matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            ) {
                continue;
            }
            let wf = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).expect("read workflow");
            let lines: Vec<&str> = text.lines().collect();
            for (idx, line) in lines.iter().enumerate() {
                let Some(after) = line.split_once("grep -oE ").map(|(_, r)| r) else {
                    continue;
                };
                // The target follows the pattern, on this line or (line-continued) the next. A
                // grep reading a pipe rather than a file has no such token and is skipped.
                let target = [after, lines.get(idx + 1).copied().unwrap_or("")]
                    .iter()
                    .flat_map(|l| l.split_ascii_whitespace())
                    .find(|t| t.starts_with("crates/") || t.starts_with("xtask/"));
                let Some(target) = target else { continue };
                // Shell single-quoting, so the pattern ends at the next `'`. Silently skipping an
                // unreadable one would be the hole: this grep reads one of our files, so dropping
                // it loses real coverage while the count below still looks healthy.
                let Some(pattern) = after.strip_prefix('\'').and_then(|r| r.split('\'').next())
                else {
                    unreadable.push(format!("{wf}:{}: {target}", idx + 1));
                    continue;
                };
                let out = std::process::Command::new("grep")
                    .arg("-oE")
                    .arg(pattern)
                    .arg(repo.join(target))
                    .output()
                    .expect("run grep");
                assert!(
                    !out.stdout.is_empty(),
                    "{wf}:{} greps /{pattern}/ out of {target} and matches nothing. The workflow \
                     will fail on its next run; point it at wherever that moved.",
                    idx + 1
                );
                checked += 1;
            }
        }
        assert!(
            unreadable.is_empty(),
            "workflow grep(s) read one of our source files with a pattern this scan cannot parse \
             (expected single quotes). Widen the parser rather than losing the check:\n  {}",
            unreadable.join("\n  ")
        );
        assert!(
            checked > 0,
            "no source-file grep matched in {}: the workflows no longer parse constants this way, \
             so this test is asserting nothing",
            dir.display()
        );
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
        bsx_probes_loader::TrustedKey::from_spki_pem(&pinned).expect("release-key.pem parses");
    }

    /// The body of the first `fn <name>` in `src`, from its opening brace to the matching close.
    /// Braces inside string literals would break the count; none of the functions compared here has
    /// one, and a change that introduces one fails loudly rather than silently comparing garbage.
    fn fn_body(src: &str, name: &str) -> String {
        let needle = format!("fn {name}");
        assert!(src.contains(&needle), "`fn {name}` must exist");
        let start = src.find(&needle).expect("asserted present just above");
        let open = src[start..].find('{').expect("a function has a body") + start;
        let mut depth = 0usize;
        let end = src[open..].char_indices().find_map(|(i, c)| match c {
            '{' => {
                depth += 1;
                None
            }
            '}' => {
                depth -= 1;
                (depth == 0).then_some(i)
            }
            _ => None,
        });
        assert!(end.is_some(), "`fn {name}`'s braces must balance");
        src[open..=open + end.expect("asserted balanced just above")].to_string()
    }

    /// `parse_cap_eff` exists twice, byte-identical, and **cannot be shared**: `bsx-test-support` is
    /// zero-dependency by decision and is a dev-dependency of `bsx-probes-loader`, so a dependency
    /// either way round is a cycle. The duplication is therefore deliberate; what is not deliberate
    /// is the two drifting, and nothing but this test would notice.
    ///
    /// The stake is which tests *run*. The loader's copy decides whether a host can load the probes
    /// at all; the helper's copy decides whether the privileged suites skip themselves. A field
    /// index that moves in one and not the other reads a capable host as incapable, and a skipped
    /// test is a pass.
    #[test]
    fn the_cap_eff_parse_is_the_same_in_the_loader_and_the_test_support() {
        let repo = workspace_root();
        let loader = std::fs::read_to_string(repo.join("crates/probes-loader/src/lib.rs"))
            .expect("crates/probes-loader/src/lib.rs");
        let support = std::fs::read_to_string(repo.join("crates/test-support/src/lib.rs"))
            .expect("crates/test-support/src/lib.rs");
        assert_eq!(
            fn_body(&loader, "parse_cap_eff"),
            fn_body(&support, "parse_cap_eff"),
            "the two `parse_cap_eff` copies have drifted; they cannot share a function (the \
             dependency would be a cycle), so they must stay identical by hand"
        );
    }

    /// Every public `exec` on the engine takes `&mut self`, the one thing keeping two of them off a
    /// single sandbox.
    ///
    /// The guest agent serves every connection from one working directory, so two execs in flight
    /// against one VM read and write each other's injected files: a `RunResult::files` can come back
    /// carrying bytes that run never produced, which makes it a wrong **audit** record and not just a
    /// wrong result. `Sandbox` is `Sync` and each exec dials its own vsock connection, so nothing
    /// else stands in the way.
    ///
    /// A revert would not pass silently (`-D warnings` catches the `mut` bindings it strands), but it
    /// would land as fifty `unused_mut`s across the test suite, which reads as tidy-up. This says
    /// what the receiver is for, where it is declared.
    #[test]
    fn every_public_exec_on_the_engine_takes_a_unique_borrow() {
        let repo = workspace_root();
        for (file, ty) in [
            ("crates/engine/src/lib.rs", "Sandbox"),
            ("crates/engine/src/vm.rs", "RunningVm"),
        ] {
            let src = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
            assert!(!src.is_empty(), "{file} must be readable and non-empty");
            for name in ["exec", "exec_with_files"] {
                // The `(` is what keeps `exec` from matching `exec_with_files` first.
                let needle = format!("pub fn {name}(");
                assert!(src.contains(&needle), "{file} must declare `{needle}`");
                let at = src.find(&needle).expect("asserted present just above");
                let receiver: String = src[at + needle.len()..]
                    .chars()
                    .take_while(|c| *c != ',')
                    .collect();
                assert!(
                    receiver.trim().starts_with("&mut self"),
                    "{ty}::{name} must take `&mut self`, got `{}`: a shared receiver lets an \
                     embedder run two execs against one working directory",
                    receiver.trim()
                );
            }
        }
    }

    /// `unescape_octal` exists twice, byte-identical, and **cannot be shared**: the parser it
    /// belongs to (`mountinfo::mounts`) is `pub(crate)`, and `confinement.rs` compiles as a foreign
    /// crate, so reaching it would put a `/proc` parser on `bsx-engine`'s pinned public API for a
    /// test's convenience.
    ///
    /// The kernel writes a mount point's space, tab, newline and backslash as octal escapes, and
    /// `BSX_SCRATCH_DIR` is operator-supplied, so a scratch base with a space in it is legal. A copy
    /// that compares the raw field matches nothing: a crashed run's binds stay attached, the
    /// following `remove_dir_all` fails `EBUSY`, and the leaked mount goes on answering every later
    /// test's mountinfo scan.
    #[test]
    fn the_mountinfo_escape_decode_is_the_same_in_the_engine_and_its_confinement_test() {
        let repo = workspace_root();
        let engine = std::fs::read_to_string(repo.join("crates/engine/src/mountinfo.rs"))
            .expect("crates/engine/src/mountinfo.rs");
        let test = std::fs::read_to_string(repo.join("crates/engine/tests/confinement.rs"))
            .expect("crates/engine/tests/confinement.rs");
        assert_eq!(
            fn_body(&engine, "unescape_octal"),
            fn_body(&test, "unescape_octal"),
            "the two `unescape_octal` copies have drifted; the parser they belong to is \
             `pub(crate)` and the test is a foreign crate, so they must stay identical by hand"
        );
        // The decoder existing is not the property; the cleanup routing its mount points through it
        // is. Reverting that call leaves the function behind and the comparison raw again.
        assert!(
            fn_body(&test, "detach_mounts_under").contains("unescape_octal"),
            "confinement.rs's `detach_mounts_under` must decode a mount point before comparing it"
        );
    }

    /// Every bounded map in the probes counts what a full map turned away.
    ///
    /// The crate's stated discipline is that best-effort loss is *visible*: the loader reads each
    /// drop counter and a nonzero delta becomes an `AxisGap`, so a run's record is thin and says so
    /// rather than looking complete. A discarded `insert` breaks that in the one direction nothing
    /// else catches, since the map is not full from the reader's side and the value is simply
    /// absent: a sandbox that never got a `CPU_NS` slot reports zero CPU, which reads as "used
    /// none" instead of "not measured".
    ///
    /// Every map here is fixed-capacity (sized at load), so this holds for every one of them, and
    /// the next map added inherits it.
    #[test]
    fn every_bounded_map_in_the_probes_counts_what_it_could_not_admit() {
        let repo = workspace_root();
        let src = std::fs::read_to_string(repo.join("crates/probes/src/main.rs"))
            .expect("crates/probes/src/main.rs");
        let lines: Vec<&str> = src.lines().collect();
        let inserts = lines.iter().filter(|l| l.contains(".insert(")).count();
        assert!(
            inserts >= 6,
            "expected an insert per bounded map, found {inserts}"
        );
        for (n, line) in lines.iter().enumerate() {
            if !line.contains(".insert(") {
                continue;
            }
            assert!(
                line.contains(".is_err()"),
                "crates/probes/src/main.rs:{}: a discarded map insert is a silent loss; test it \
                 and count the drop: {}",
                n + 1,
                line.trim()
            );
            assert!(
                lines[n + 1].contains("count_map_drop("),
                "crates/probes/src/main.rs:{}: a failed insert must bump a drop counter the loader \
                 reads, or the loss reaches no record: {}",
                n + 1,
                line.trim()
            );
        }
    }

    /// Every tracepoint argument offset the probes read is on the list the loader checks.
    ///
    /// The offsets are an ABI assumption no relocation carries, so `check_tracepoint_abi` compares
    /// each one against the kernel's own `format` file before attaching. That check walks
    /// `TRACEPOINT_ARGS`, so a `TracepointArg` const that the probe reads but the array leaves out
    /// is verified nowhere, and the failure it would let through is silent: an event recorded with
    /// an empty or unrelated path, no error and no drop counted.
    ///
    /// A numeric literal passed to `record` is the same hole by a shorter route, so this holds the
    /// read sites to the named consts too.
    #[test]
    fn every_tracepoint_arg_is_checked_before_the_attach() {
        let repo = workspace_root();
        let common = std::fs::read_to_string(repo.join("crates/probes-common/src/lib.rs"))
            .expect("crates/probes-common/src/lib.rs");
        let probes = std::fs::read_to_string(repo.join("crates/probes/src/main.rs"))
            .expect("crates/probes/src/main.rs");

        let declared: Vec<&str> = common
            .lines()
            .filter_map(|l| l.strip_prefix("pub const ")?.split(':').next())
            .filter(|name| name.ends_with("_ARG"))
            .collect();
        assert!(
            declared.len() >= 4,
            "expected the four traced arguments to be declared, found {declared:?}"
        );
        let table = const_list(&common, "pub const TRACEPOINT_ARGS");
        for name in &declared {
            assert!(
                table.contains(name),
                "`{name}` is declared but missing from TRACEPOINT_ARGS, so the loader never checks \
                 the offset it reads against the kernel's own layout"
            );
        }

        // The tracers are what actually read an offset, so a literal in one is an unchecked offset.
        // Every argument slot starts at 16, so "no multi-digit literal here" is the grep-able form.
        for tracer in ["trace_execve", "trace_openat", "trace_connect"] {
            let body = fn_body(&probes, tracer);
            assert!(
                body.contains("_ARG.offset"),
                "`{tracer}` must read its offset from a TracepointArg const, so the loader checks \
                 the same number the program reads"
            );
            assert!(
                !body
                    .as_bytes()
                    .windows(2)
                    .any(|w| w[0].is_ascii_digit() && w[1].is_ascii_digit()),
                "`{tracer}` carries a multi-digit literal, which is an argument offset nothing \
                 checks against the kernel's layout"
            );
        }
    }

    /// The array literal a `const` is initialized to, the [`fn_body`] shape for a declaration whose
    /// "body" is a list rather than a block. Anchored on `= [` so the item's own array *type*
    /// (`: [T; N]`) is not mistaken for its value.
    fn const_list(src: &str, decl: &str) -> String {
        let at = src.find(decl);
        assert!(at.is_some(), "`{decl}` must be declared");
        let at = at.expect("asserted declared just above");
        let open = src[at..].find("= [");
        assert!(open.is_some(), "`{decl}` must be initialized to a list");
        let open = at + open.expect("asserted initialized just above") + 2;
        let close = src[open..].find(']');
        assert!(close.is_some(), "`{decl}`'s list must close");
        src[open..=open + close.expect("asserted closed just above")].to_string()
    }

    /// Every resolution of a `/proc/<pid>/cgroup` `0::` line must refuse the **root** cgroup.
    ///
    /// A registered cgroup matches every process whose `bpf_get_current_cgroup_id` equals it, so the
    /// root folds the whole host's syscalls and CPU into one sandbox's signed record. `0::/` is what
    /// a process in the root cgroup reads, and what every process reads inside a container with the
    /// default private cgroup namespace. `crates/probes-loader` shipped without this guard while
    /// `crates/engine` had it, which is the drift this test exists to catch; the two crates have no
    /// dependency edge in either direction, so a shared function is not available.
    #[test]
    fn the_cgroup_resolution_refuses_the_root_cgroup_everywhere() {
        let repo = workspace_root();
        // Each resolver, named with the file it lives in so a failure says where to look.
        let sites = [
            ("crates/engine/src/jail.rs", "read_cgroup_dir"),
            ("crates/probes-loader/src/lib.rs", "cgroup_dir_in"),
            ("crates/engine/tests/common/mod.rs", "cgroup_of"),
        ];
        for (file, func) in sites {
            let src = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
            assert!(!src.is_empty(), "{file} must be readable and non-empty");
            let body = fn_body(&src, func);
            assert!(
                body.contains(r#"rel == "/""#),
                "{file}'s `{func}` must refuse the root cgroup (`rel == \"/\"`), or a sandbox's \
                 record absorbs every process in it"
            );
        }
    }

    /// Every reap of a spawned child on the host path is bounded.
    ///
    /// A child in uninterruptible sleep (a hung scratch filesystem, a stuck KVM ioctl) does not die
    /// on `SIGKILL` and never returns from `wait`, so a bare `child.wait()` is a driver hang, which is
    /// what design rule 5 forbids. `drives::kill_and_reap_briefly` is the bounded form: it gives up
    /// and detaches, taking an unreaped zombie over a parked thread. The hazard cannot be staged in a
    /// test (it needs a filesystem that stops answering), so the shape is pinned instead.
    #[test]
    fn every_child_reap_on_the_host_path_is_bounded() {
        let repo = workspace_root();
        for file in [
            "crates/engine/src/spawn.rs",
            "crates/engine/src/jail.rs",
            "crates/engine/src/vm.rs",
            "crates/engine/src/lifetime.rs",
            "crates/engine/src/drives.rs",
        ] {
            let src = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
            assert!(!src.is_empty(), "{file} must be readable and non-empty");
            // Only the production half: a test may reap its own helper however it likes. Split on
            // the test *module*, not the first `#[cfg(test)]`: several of these files carry
            // test-only `use` lines near the top, and splitting there would leave almost the whole
            // file unscanned.
            let prod = src
                .split("#[cfg(test)]\nmod tests {")
                .next()
                .unwrap_or_default();
            for (n, line) in prod.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                assert!(
                    !code.contains(".wait()"),
                    "{file}:{} reaps with a bare `wait()`; use `kill_and_reap_briefly` so a \
                     D-state child detaches instead of parking the driver: {}",
                    n + 1,
                    line.trim()
                );
            }
        }
    }

    /// Both escapers that stand between a guest-authored string and the operator's terminal cover the
    /// same `Bidi_Control` set.
    ///
    /// `char::is_control` is category `Cc` only, so the bidi controls pass it and a guest `Error`
    /// string, a captured `openat` path, or a boot-failure console tail can reorder the line it lands
    /// in. Three surfaces render guest-authored text to the operator's terminal and each carries its
    /// own copy: `crates/cli` has no dependency edge to `crates/channel`, and while `crates/engine`
    /// does, the predicate is private there and making it public would put a text utility on that
    /// crate's pinned surface. A shared function is not available, so the set is pinned instead.
    #[test]
    fn the_terminal_escapers_agree_on_the_bidi_controls() {
        let repo = workspace_root();
        let sites = [
            ("crates/channel/src/lib.rs", "is_bidi_control"),
            ("crates/cli/src/trace.rs", "is_bidi_control"),
            ("crates/engine/src/console.rs", "is_bidi_control"),
        ];
        // The Unicode `Bidi_Control` property, as the two predicates spell it.
        let required = [
            r"'\u{061C}'",
            r"'\u{200E}'",
            r"'\u{200F}'",
            r"'\u{202A}'..='\u{202E}'",
            r"'\u{2066}'..='\u{2069}'",
        ];
        for (file, func) in sites {
            let src = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
            assert!(!src.is_empty(), "{file} must be readable and non-empty");
            let body = fn_body(&src, func);
            for point in required {
                assert!(
                    body.contains(point),
                    "{file}'s `{func}` must cover {point}: a bidi control it misses reaches the \
                     operator's terminal and reorders the line around it"
                );
            }
        }
    }

    /// Every socket bounded by an absolute deadline refuses a spent budget instead of arming it.
    ///
    /// `SO_RCVTIMEO`/`SO_SNDTIMEO` are re-armed by the kernel on every byte, so a peer dripping just
    /// inside the interval holds the host thread that reads it for as long as it likes. Each adapter
    /// shrinks the sockopt to what is left of one absolute `Instant` instead. The zero case is the
    /// load-bearing one: the kernel reads a zero timeout as "block forever", so a copy that arms a
    /// spent budget is the hang the adapter exists to prevent, which is what design rule 5 forbids.
    ///
    /// The copies cannot share a function. `crates/cli` reaching `bsx-engine`'s adapter would put a
    /// CLI-shaped convenience type on that crate's pinned public API, which `docs/embedding-scope.md`
    /// draws out of scope. So the invariant is pinned instead. A site names the method that arms the
    /// sockopt and, where the budget is computed in a helper rather than inline, that helper too.
    #[test]
    fn every_deadline_bounded_socket_refuses_a_spent_budget() {
        /// One bounded direction of one adapter.
        struct Site {
            file: &'static str,
            /// The impl the method lives in. Slicing here first is what stops `fn read` matching a
            /// `read_response` that comes earlier in the file.
            imp: &'static str,
            method: &'static str,
            /// The sockopt this direction arms.
            sockopt: &'static str,
            /// Where the budget is computed, when that is not the method itself.
            budget: Option<(&'static str, &'static str)>,
        }
        /// The body of the first `fn <method>` after `imp`.
        fn body_after(src: &str, imp: &str, method: &str, file: &str) -> String {
            assert!(src.contains(imp), "{file} must contain `{imp}`");
            let at = src.find(imp).expect("asserted present just above");
            fn_body(&src[at..], method)
        }
        let repo = workspace_root();
        let sites = [
            Site {
                file: "crates/cli/src/deadline.rs",
                imp: "impl<S: Read + SetReadTimeout> Read for",
                method: "read",
                sockopt: "set_read_timeout",
                budget: Some(("impl<S> DeadlineStream<S> {", "remaining")),
            },
            Site {
                file: "crates/cli/src/deadline.rs",
                imp: "impl<S: Write + SetWriteTimeout> Write for",
                method: "write",
                sockopt: "set_write_timeout",
                budget: Some(("impl<S> DeadlineStream<S> {", "remaining")),
            },
            Site {
                file: "crates/engine/src/deadline.rs",
                imp: "impl<S: Borrow<UnixStream>> Read for",
                method: "read",
                sockopt: "set_read_timeout",
                budget: Some(("impl<S> DeadlineStream<S> {", "remaining")),
            },
            Site {
                file: "crates/engine/src/deadline.rs",
                imp: "impl<S: Borrow<UnixStream>> Write for",
                method: "write",
                sockopt: "set_write_timeout",
                budget: Some(("impl<S> DeadlineStream<S> {", "remaining")),
            },
        ];
        for Site {
            file,
            imp,
            method,
            sockopt,
            budget,
        } in sites
        {
            let src = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
            assert!(!src.is_empty(), "{file} must be readable and non-empty");
            let mut body = body_after(&src, imp, method, file);
            if let Some((bimp, bmethod)) = budget {
                body.push_str(&body_after(&src, bimp, bmethod, file));
            }
            for (part, why) in [
                (
                    "saturating_duration_since",
                    "the budget must come from one absolute deadline, not a per-syscall timeout a \
                     dripping peer re-arms",
                ),
                (
                    ".is_zero()",
                    "a spent budget must be recognised before it is armed: a zero sockopt is \
                     \"block forever\"",
                ),
                (
                    "ErrorKind::TimedOut",
                    "a spent budget must read as a typed timeout, not a hang",
                ),
                (
                    sockopt,
                    "the remaining budget must reach the socket, or the bound is computed and \
                     thrown away",
                ),
            ] {
                assert!(
                    body.contains(part),
                    "{file}'s `{method}` (under `{imp}`) must keep `{part}`: {why}"
                );
            }
            // The write half needs one more thing the read half does not. `sendmsg` loops inside the
            // kernel until the caller's whole buffer is sent, re-applying `SO_SNDTIMEO` to each
            // internal wait, so a whole frame in one `write` is a single syscall that a slowly
            // draining peer stretches with no deadline check in between. `recvmsg` returns what is
            // available instead of filling the buffer, so reads need no cap.
            assert!(
                method != "write" || body.contains("WRITE_CHUNK"),
                "{file}'s `write` must cap what one syscall hands the kernel (`WRITE_CHUNK`), or \
                 the deadline is only checked once for the whole buffer"
            );
        }
    }
}
