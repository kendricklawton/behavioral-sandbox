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

/// The target the **shipped** binary is built for: static musl, so the package carries no libc
/// dependency at all.
///
/// A glibc build binds to the build host's symbol versions, and glibc is backward but **not
/// forward** compatible: a binary built on Ubuntu 24.04 (glibc 2.39) will not start on RHEL 9
/// (2.34) or Ubuntu 22.04 (2.35), failing before `main()` with a loader error that says nothing
/// about this engine. Building on the oldest supported glibc would fix it by making the CI runner
/// the compatibility floor; linking musl statically removes the floor instead, which is the same
/// move `guest-agent` already makes for the same reason (nothing to link against at the far end).
///
/// Dev builds stay native: this is the package's target, not the workspace's.
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
             nightly toolchain (see docs/contributing-building.md)",
            object.display()
        );
    }

    println!("\n== 4/5  build the release binary (static, {DIST_TARGET}) ==");
    cargo(&[
        "build",
        "--release",
        "--locked",
        "-p",
        "ekvm",
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
    let bin = target.join(DIST_TARGET).join("release/ekvm");
    if !bin.is_file() {
        bail!("built binary {} not found", bin.display());
    }
    crate::guest_bins::verify_static(&bin, "ekvm host binary")?;

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
    use crate::BPF_LINKER_VERSION;

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

    /// Same drift guard, for the Firecracker pin. `install.sh` carries its own copy of the pinned
    /// release sha256 (installers run it before this repo is built, so it cannot call into `vmm`),
    /// and `doctor.rs` carries the one the engine checks at runtime. Two copies of a security-
    /// relevant hash drift silently: the pair sat on v1.9 for 21 months, about a year past
    /// upstream's support window, and nothing compared them.
    #[test]
    fn install_sh_firecracker_pin_matches_doctor() {
        let repo = workspace_root();
        let install = std::fs::read_to_string(repo.join("install.sh")).unwrap();
        let doctor = std::fs::read_to_string(repo.join("crates/vmm/src/doctor.rs")).unwrap();

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
            std::fs::read_to_string(repo.join("crates/vmm/src/spawn/fcversion.rs")).unwrap();

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

    /// Same drift guard, for the **third** copy of the Firecracker pin: the container image's
    /// `FC_VERSION` build arg. The install.sh/doctor.rs pair drifted for 21 months before their
    /// test existed; this file was missed in that sweep and sat on v1.9.1 (below the supported
    /// floor, so the image bundled a VMM upstream no longer patches) until 2026-07-29.
    #[test]
    fn containerfile_firecracker_is_the_pinned_series() {
        let repo = workspace_root();
        let container = std::fs::read_to_string(repo.join("Containerfile")).expect("Containerfile");
        let spawn =
            std::fs::read_to_string(repo.join("crates/vmm/src/spawn/fcversion.rs")).unwrap();

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

        // The contributor-facing docs hand out the same commands; a reader who follows them must
        // land on the pinned versions, not on whatever is newest.
        const BUILDING_DOC: &str = "docs/contributing-building.md";
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

    /// Workflows name repo files as bare shell text: a parser's target (`grep … crates/…`), an
    /// error message telling a human which file to edit. Nothing checked those paths. The
    /// prose-drift lint reads `.rs` and `.md` only, and even there it wants a backticked span,
    /// so a rename lands green and the weekly job fails days later on a path that no longer
    /// exists: splitting `spawn.rs` into `spawn/fcversion.rs` broke `firecracker-pin.yml`'s floor
    /// parser exactly that way, and only its own non-vacuity guard would have reported it.
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
                    // `crates/vmm/**` is a path *filter*, not a file: check the dir it roots.
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
    /// matching inside it. Only the second one caught the real case. Splitting `spawn.rs` left the
    /// file in place and moved `MIN_SUPPORTED_FC_VERSION` out of it, so a path check stayed green
    /// while the parser matched nothing. Runs each workflow's own `grep -oE` against its own
    /// target and requires a hit, which is the parser's contract stated as a test rather than
    /// discovered on a Wednesday.
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
        probes_loader::TrustedKey::from_spki_pem(&pinned).expect("release-key.pem parses");
    }
}
