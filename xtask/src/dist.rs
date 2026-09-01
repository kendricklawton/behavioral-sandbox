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
use crate::{cargo_reproducible, guest_rootfs_path, kernel_path, workspace_root};

/// The artifacts staged under `share/bsx/`, the names an installed host carries. `install.sh`
/// carries its own copy of this list, because a shell script cannot read this one;
/// `the_installer_installs_exactly_what_dist_stages` holds the two together, since a divergence
/// surfaces only when a *released* tarball is installed.
const SHARE_MEMBERS: [&str; 2] = ["vmlinux", "rootfs-guest.ext4"];

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
    copy_mode(&kernel, &share.join(SHARE_MEMBERS[0]), 0o644)?;
    copy_mode(&guest_rootfs_path(), &share.join(SHARE_MEMBERS[1]), 0o644)?;
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

    println!("\n✓ dist assembled:");
    println!("    {}", tarball.display());
    println!("    {}  (sha256 {tar_sha})", sums.display());
    println!("    (unsigned: artifact signing is not implemented)");
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
/// pre-release line, `v` stripped), falling back to `<pkg>-dev.<rev>` in a
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
    let flags = deterministic_tar_flags();
    let mut args: Vec<&std::ffi::OsStr> = flags.iter().map(std::ffi::OsStr::new).collect();
    args.extend([
        std::ffi::OsStr::new("-C"),
        dist_dir.as_os_str(),
        std::ffi::OsStr::new("-czf"),
        tarball.as_os_str(),
        std::ffi::OsStr::new(name),
    ]);
    crate::run_tool("tar", &args)?;
    println!("  packed {}", tarball.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// `install.sh` installs a hardcoded list of `share/bsx/` members and writes the kernel's
    /// installed path into the starter `~/.bsx.toml`; a shell script cannot read [`SHARE_MEMBERS`],
    /// so the two lists are a copy. Held together here because a divergence is invisible until a
    /// *released* tarball is installed: the loop fails on a missing file, or the config names a
    /// kernel that was never installed.
    #[test]
    fn the_installer_installs_exactly_what_dist_stages() {
        let install = std::fs::read_to_string(workspace_root().join("install.sh")).unwrap();

        let listed: Vec<&str> = install
            .lines()
            .find_map(|l| l.trim().strip_prefix("for f in")?.strip_suffix("; do"))
            .expect("install.sh has a `for f in <members>; do` install loop")
            .split_whitespace()
            .collect();
        assert_eq!(
            listed, SHARE_MEMBERS,
            "install.sh installs a different set of share/bsx/ members than `dist` stages"
        );

        // The starter config points at the installed kernel by name, so a rename that missed this
        // line would install the kernel and then configure a path that holds nothing.
        assert!(
            install.contains(&format!("\"$DATA/{}\"", SHARE_MEMBERS[0])),
            "install.sh's starter .bsx.toml must name $DATA/{} as the kernel",
            SHARE_MEMBERS[0]
        );
    }

    /// Same drift guard, for *where* Firecracker goes. `install.sh` prints an install hint when it
    /// finds no firecracker on PATH, and `docs/cli-install.md` gives the same commands in prose;
    /// the directory is the load-bearing part. A user-local prefix is not on sudoers'
    /// `secure_path`, so a hint that pointed there would put the VMM exactly where the jailed
    /// posture (which runs under sudo) cannot resolve it, and the two copies would drift silently.
    #[test]
    fn install_sh_firecracker_dir_matches_the_install_guide() {
        let install = std::fs::read_to_string(workspace_root().join("install.sh")).unwrap();
        let guide = std::fs::read_to_string(workspace_root().join("docs/cli-install.md")).unwrap();

        let dir = install
            .lines()
            .find_map(|l| l.strip_prefix("FC_INSTALL_DIR=\"")?.strip_suffix('"'))
            .expect("install.sh declares FC_INSTALL_DIR at column zero");

        // Named rather than inferred: the whole point is that this is a *system* dir, not the
        // user-local prefix the `bsx` binary itself goes to.
        assert!(
            dir.starts_with("/usr/") || dir.starts_with("/opt/"),
            "{dir} is not a system dir, so sudo would not resolve the VMM from it"
        );

        for bin in ["firecracker", "jailer"] {
            // The script installs through the constant, so its hint cannot drift from the value
            // this test read; the guide spells the path out, so it is compared literally.
            assert!(
                install.contains(&format!("$FC_INSTALL_DIR/{bin}")),
                "install.sh's hint must place {bin} through $FC_INSTALL_DIR, not a literal path"
            );
            assert!(
                guide.contains(&format!("{dir}/{bin}")),
                "the install guide must install {bin} to {dir}, the dir secure_path covers"
            );
        }
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
        let mut checked = 0usize;
        let mut missing: Vec<String> = Vec::new();
        for (wf, text) in workflow_texts(repo) {
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
            "no crates/ or xtask/ path reference matched in .github/workflows: the workflows no \
             longer name repo files the way this scan looks for, so it is asserting nothing"
        );
        assert!(
            missing.is_empty(),
            "workflow(s) reference repo paths that no longer exist:\n  {}",
            missing.join("\n  ")
        );
    }

    /// Every workflow file with its text, in name order: discovered by reading the directory
    /// rather than a hardcoded list, because a list silently exempts whatever it omits. Both
    /// GitHub spellings, since a `.yaml` file GitHub runs but a scan skipped would be a silent
    /// hole in exactly the coverage the callers claim; an empty directory fails here rather than
    /// leaving every caller's scan vacuously green.
    fn workflow_texts(repo: &Path) -> Vec<(String, String)> {
        let dir = repo.join(".github/workflows");
        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .expect(".github/workflows")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
            .collect();
        paths.sort();
        assert!(!paths.is_empty(), "no workflows found in {}", dir.display());
        paths
            .into_iter()
            .map(|p| {
                let wf = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let text = std::fs::read_to_string(&p).expect("read workflow");
                (wf, text)
            })
            .collect()
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

    /// `WaitBackoff` (the guest agent's child-exit poll) and `PollBackoff` (the engine's
    /// readiness poll) are deliberate twins: the agent is the static musl guest binary and takes
    /// no `bsx` dependency, so the two cannot share a type. Their constants and the
    /// double-toward-the-cap progression must stay equal by hand; a cap widened on one side
    /// re-quantizes the latency the other was tuned against.
    #[test]
    fn the_backoff_twins_share_their_constants_and_progression() {
        let repo = workspace_root();
        let agent = std::fs::read_to_string(repo.join("crates/guest-agent/src/lib.rs"))
            .expect("crates/guest-agent/src/lib.rs");
        let engine = std::fs::read_to_string(repo.join("crates/engine/src/spawn.rs"))
            .expect("crates/engine/src/spawn.rs");
        // Each file declares exactly one backoff, so the bare const names find it.
        for name in ["const INITIAL", "const CAP"] {
            assert_eq!(
                const_value(&agent, name),
                const_value(&engine, name),
                "`{name}` differs between WaitBackoff and PollBackoff"
            );
        }
        for (file, src) in [("WaitBackoff", &agent), ("PollBackoff", &engine)] {
            assert!(
                src.contains("(self.next * 2).min(Self::CAP)"),
                "`{file}` must keep the double-toward-the-cap progression"
            );
        }
    }

    /// The `Uid:` parse exists three times by decision: the CLI's `uids`, the engine's `euid_in`,
    /// and xtask's `effective_uid`, which share no dependency edge. Each must consume the token
    /// with `strip_prefix`, the convention whose violation (a `starts_with` split leaving `Uid:`
    /// as field 0 and shifting every index) is the trap.
    #[test]
    fn the_uid_parses_share_the_field_convention() {
        let repo = workspace_root();
        let ids = std::fs::read_to_string(repo.join("crates/cli/src/ids.rs"))
            .expect("crates/cli/src/ids.rs");
        let sweep = std::fs::read_to_string(repo.join("crates/engine/src/sweep.rs"))
            .expect("crates/engine/src/sweep.rs");
        let xtask_main =
            std::fs::read_to_string(repo.join("xtask/src/main.rs")).expect("xtask/src/main.rs");
        for (name, src) in [
            ("uids", &ids),
            ("euid_in", &sweep),
            ("effective_uid", &xtask_main),
        ] {
            let body = fn_body(src, name);
            assert!(
                body.contains(r#"strip_prefix("Uid:")"#),
                "`{name}` must consume the `Uid:` token with strip_prefix"
            );
            assert!(
                !body.contains("starts_with"),
                "`{name}` must not switch to the starts_with split its doc names as the trap"
            );
        }
        assert!(
            fn_body(&sweep, "euid_in").contains("nth(1)")
                && fn_body(&xtask_main, "effective_uid").contains("nth(1)"),
            "the effective uid is the second field after the consumed token"
        );
    }

    /// The scalar initializer of a `const`, the [`const_list`] shape for a value that is not a
    /// list: the text between its `=` and the closing `;`, trimmed.
    fn const_value(src: &str, decl: &str) -> String {
        let at = src.find(decl);
        assert!(at.is_some(), "`{decl}` must be declared");
        let at = at.expect("asserted declared just above");
        let open = src[at..].find('=');
        assert!(open.is_some(), "`{decl}` must be initialized");
        let open = at + open.expect("asserted initialized just above") + 1;
        let close = src[open..].find(';');
        assert!(close.is_some(), "`{decl}`'s initializer must end");
        src[open..open + close.expect("asserted ended just above")]
            .trim()
            .to_string()
    }

    /// The cgroup-limit derivation exists twice and **cannot be shared**: `bsx-test-support` is
    /// zero-dependency by decision and a dev-dependency of `bsx-engine`, so a dependency either
    /// way round is a cycle. `LimitCgroup` mirrors `jail`'s constants and arithmetic so the
    /// privileged enforcement tests cap a VMM exactly where the jailer would.
    ///
    /// The stake is what those tests measure. If `jail.rs` moves the overhead or reshapes a
    /// formula and the mirror does not, the enforcement suites keep capping at the old numbers
    /// and stay green while measuring a limit production no longer sets.
    #[test]
    fn the_cgroup_limit_derivation_is_the_same_in_the_jail_and_the_test_support() {
        let repo = workspace_root();
        let jail = std::fs::read_to_string(repo.join("crates/engine/src/jail.rs"))
            .expect("crates/engine/src/jail.rs");
        let support = std::fs::read_to_string(repo.join("crates/test-support/src/lib.rs"))
            .expect("crates/test-support/src/lib.rs");
        // The values must match; the declared types deliberately differ (`u32` widened at the
        // jail's use site, `u64` in the helper), so the comparison is initializer text.
        for name in ["const MEMORY_OVERHEAD_MIB", "const CPU_PERIOD_US"] {
            assert_eq!(
                const_value(&jail, name),
                const_value(&support, name),
                "`{name}` differs between the jail and test-support"
            );
        }
        // And the arithmetic that uses them, pinned as the exact expressions (each side spells
        // its own integer widening), so a formula reshaped on one side forces a look at its
        // mirror in the same commit.
        let jail_body = fn_body(&jail, "cgroup_args_for");
        for needle in [
            "u64::from(vcpus.get()) * CPU_PERIOD_US",
            "(u64::from(mem_mib.get()) + u64::from(MEMORY_OVERHEAD_MIB)) * 1024 * 1024",
            "cpu.max={quota} {CPU_PERIOD_US}",
        ] {
            assert!(
                jail_body.contains(needle),
                "`cgroup_args_for` must contain `{needle}`"
            );
        }
        for needle in [
            "u64::from(vcpus) * CPU_PERIOD_US",
            "(u64::from(mem_mib) + MEMORY_OVERHEAD_MIB) * 1024 * 1024",
            "{cpu_quota_us} {CPU_PERIOD_US}",
        ] {
            assert!(
                support.contains(needle),
                "test-support's `LimitCgroup` must contain `{needle}`"
            );
        }
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

    /// `confinement.rs`'s cleanup must route its mount points through the engine's own parser, which
    /// it reaches by compiling `mountinfo.rs` in (`#[path]`) rather than mirroring it: a copy would
    /// be a second `/proc` parser to keep in step, and widening the real one would put it on
    /// `bsx-engine`'s pinned public API for a test's convenience.
    ///
    /// The kernel writes a mount point's space, tab, newline and backslash as octal escapes, and
    /// `BSX_SCRATCH_DIR` is operator-supplied, so a scratch base with a space in it is legal. A
    /// cleanup that compares the raw field matches nothing: a crashed run's binds stay attached, the
    /// following `remove_dir_all` fails `EBUSY`, and the leaked mount goes on answering every later
    /// test's mountinfo scan.
    #[test]
    fn the_confinement_cleanup_decodes_mount_points_with_the_engines_own_parser() {
        let repo = workspace_root();
        let test = std::fs::read_to_string(repo.join("crates/engine/tests/confinement.rs"))
            .expect("crates/engine/tests/confinement.rs");
        assert!(
            test.contains("#[path = \"../src/mountinfo.rs\"]"),
            "confinement.rs must compile in the engine's mountinfo parser rather than mirror it"
        );
        assert!(
            fn_body(&test, "detach_mounts_under").contains("mountinfo::mounts"),
            "confinement.rs's `detach_mounts_under` must decode a mount point before comparing it"
        );
    }

    /// Every readiness poll that owns a VMM fails fast when that VMM dies.
    ///
    /// `await_api_socket`, `await_userspace`, `await_guest_ready` and the snapshot resume wait each
    /// poll a probe under a deadline. One that watches only the clock reports a VMM that died
    /// mid-wait as a timeout at the far end of its wall, instead of naming the exit status at once,
    /// which is how the snapshot resume behaved for its full 10-second window. Staging that needs a
    /// real microVM dying under a pause, so the shape is pinned instead.
    ///
    /// Scoped to the loops holding a child handle. `exec.rs`'s dial retry and `firecracker.rs`'s UDS
    /// dial also back off, but they are short inner retries reached *through* these four, take no
    /// child, and are already covered by the liveness check of whichever of these wraps them.
    #[test]
    fn every_readiness_poll_checks_the_vmm_is_still_alive() {
        let repo = workspace_root();
        let mut checked = 0usize;
        for file in [
            "crates/engine/src/spawn.rs",
            "crates/engine/src/snapshot.rs",
        ] {
            let src = std::fs::read_to_string(repo.join(file)).unwrap_or_default();
            assert!(!src.is_empty(), "{file} must be readable and non-empty");
            let prod = src
                .split("#[cfg(test)]\nmod tests {")
                .next()
                .unwrap_or_default();

            // Segment at each function declaration, so one loop's liveness check cannot satisfy the
            // next one down the file.
            let mut name = String::from("<file scope>");
            let mut body = String::new();
            let mut segments: Vec<(String, String)> = Vec::new();
            for line in prod.lines() {
                let trimmed = line.trim_start();
                let decl = trimmed
                    .strip_prefix("pub(crate) fn ")
                    .or_else(|| trimmed.strip_prefix("pub fn "))
                    .or_else(|| trimmed.strip_prefix("fn "));
                if let Some(rest) = decl {
                    segments.push((std::mem::take(&mut name), std::mem::take(&mut body)));
                    name = rest.split('(').next().unwrap_or(rest).to_string();
                }
                body.push_str(line);
                body.push('\n');
            }
            segments.push((name, body));

            for (name, body) in segments {
                if !body.contains("PollBackoff::new()") {
                    continue;
                }
                checked += 1;
                assert!(
                    body.contains("try_wait") || body.contains("exited()"),
                    "{file}'s `{name}` polls for readiness without checking the VMM is still \
                     alive, so a VMM that dies mid-wait surfaces as a timeout at the end of its \
                     wall rather than by its exit status"
                );
            }
        }
        assert_eq!(
            checked, 4,
            "expected four VMM-owning readiness polls; a new one must check liveness too, or be \
             excluded here with its reason"
        );
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
    /// own copy: the predicate is private in `crates/engine` and making it public would put a text
    /// utility on that crate's pinned surface. A shared function is not available, so the set is
    /// pinned instead.
    #[test]
    fn the_terminal_escapers_agree_on_the_bidi_controls() {
        let repo = workspace_root();
        let sites = [
            ("crates/channel/src/lib.rs", "is_bidi_control"),
            ("crates/engine/src/console.rs", "is_bidi_control"),
        ];
        // The Unicode `Bidi_Control` property, as the predicates spell it.
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
    /// A site names the method that arms the sockopt and, where the budget is computed in a helper
    /// rather than inline, that helper too.
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
