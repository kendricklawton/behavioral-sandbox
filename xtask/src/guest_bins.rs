//! Static musl builds of the in-guest binaries: the guest agent (baked into the rootfs) and the
//! native-ELF test fixture, each verified actually statically linked before use.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::cargo_reproducible;
use crate::rootfs::GuestArch;

/// Whether the guest musl target is installed: the soft form `cargo xtask setup` reports (the hard
/// `ensure_guest_target` is what the build path enforces). A missing or failing `rustup` reads as
/// "not installed", which is the actionable answer for a host-readiness check.
pub(crate) fn guest_target_installed(arch: GuestArch) -> bool {
    Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .is_ok_and(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|t| t == arch.musl_target())
        })
}

/// Build the guest agent as a static binary for the guest and return its path. Kept out of the `ci`
/// gate (it needs the musl target installed and produces an artifact the host doesn't run);
/// `build-rootfs` bakes the result into the image.
pub(crate) fn build_guest_agent(arch: GuestArch) -> Result<PathBuf> {
    build_guest_musl(arch)
}

/// Build the static musl guest agent (`--locked`, the guest musl target) and verify it's actually
/// statically linked before returning its path.
fn build_guest_musl(arch: GuestArch) -> Result<PathBuf> {
    ensure_guest_target(arch)?;
    let target = arch.musl_target();
    let (selector, subpath, label) = (
        &["--bin", "guest-agent"][..],
        "release/guest-agent",
        "guest agent",
    );
    let mut args = vec!["build", "--release", "--locked", "-p", "bsx-guest-agent"];
    args.extend_from_slice(selector);
    args.extend_from_slice(&["--target", target]);
    cargo_reproducible(&args)?;
    let bin = crate::target_dir().join(target).join(subpath);
    verify_static(&bin, label)?;
    println!("\n✓ {label} built (static): {}", bin.display());
    Ok(bin)
}

/// Fail with a clear fix if the guest musl target isn't installed, cargo would otherwise error more
/// obscurely deep in the build.
fn ensure_guest_target(arch: GuestArch) -> Result<()> {
    let target = arch.musl_target();
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context("running rustup (is it installed?)")?;
    if !installed.status.success() {
        // Without this, a non-zero rustup (no default toolchain, corrupt state) yields empty stdout
        // and the check below misreports it as "target not installed", the wrong fix to suggest.
        bail!(
            "`rustup target list --installed` failed (exit {:?}): {}",
            installed.status.code(),
            String::from_utf8_lossy(&installed.stderr).trim()
        );
    }
    if !String::from_utf8_lossy(&installed.stdout)
        .lines()
        .any(|t| t == target)
    {
        bail!("missing target {target} — run `rustup target add {target}` first");
    }
    Ok(())
}

/// Verifies the built binary is statically linked, since a sys-crate can reintroduce a `NEEDED`
/// dependency and a dynamic binary fails at boot with a loader error. Both no `(NEEDED)` and no
/// `INTERP`, so a static-PIE is rejected too.
pub(crate) fn verify_static(bin: &Path, what: &str) -> Result<()> {
    // `readelf -d` (dynamic section): a static binary lists no `(NEEDED)` shared objects.
    let Some(dynamic) = readelf(bin, "-d")? else {
        // No `readelf` (binutils) on this host: don't fake a guarantee we couldn't check. (A
        // `readelf` that is present but fails is an error, not this soft skip.)
        println!("  ! could not run `readelf` to verify staticness — install binutils to check");
        return Ok(());
    };
    let needed: Vec<_> = dynamic.lines().filter(|l| l.contains("(NEEDED)")).collect();
    if !needed.is_empty() {
        bail!(
            "{what} is NOT statically linked — it needs {} shared object(s):\n{}",
            needed.len(),
            needed.join("\n")
        );
    }
    // `readelf -l` (program headers): a fully static binary carries no `INTERP` segment (loader).
    let Some(segments) = readelf(bin, "-l")? else {
        println!("  ! could not run `readelf -l` to verify no interpreter — install binutils");
        return Ok(());
    };
    if segments.lines().any(|l| l.contains("INTERP")) {
        bail!("{what} carries a PT_INTERP program header — it wants a runtime loader, not static");
    }
    Ok(())
}

/// Runs `readelf <flag> <bin>` and returns its stdout. `Ok(None)` is binutils absent, the only
/// soft skip; a `readelf` present but failing is an `Err`, or a tool failure would disarm the
/// static-link check silently.
fn readelf(bin: &Path, flag: &str) -> Result<Option<String>> {
    let out = match Command::new("readelf").arg(flag).arg(bin).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("running readelf {flag}")),
    };
    if !out.status.success() {
        bail!(
            "readelf {flag} {} exited {:?} — cannot verify static linking",
            bin.display(),
            out.status.code()
        );
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}
