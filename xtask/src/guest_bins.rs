//! Static musl builds of the in-guest binaries: the guest agent (baked into the rootfs) and the
//! native-ELF test fixture, each verified actually statically linked before use.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{cargo, workspace_root};

/// The musl target the guest agent is built for: a fully static binary that runs in the guest with
/// no dynamic loader or libc to bake into the rootfs.
const GUEST_TARGET: &str = "x86_64-unknown-linux-musl";

/// Build the guest agent as a static binary for the guest and return its path. Kept out of the `ci`
/// gate (it needs the musl target installed and produces an artifact the host doesn't run);
/// `build-rootfs` bakes the result into the image.
pub(crate) fn build_guest_agent() -> Result<PathBuf> {
    build_guest_musl(GuestBin::Agent)
}

/// Build the static native-ELF fixture (`crates/guest-agent/examples/writefile.rs`) for the
/// guest target and return its path. A statically linked musl binary with no interpreter/libc, which
/// the runtime-agnostic test injects and execs to prove the engine runs *any* Linux binary. Built
/// like the agent (musl, `--locked`) and verified static.
pub(crate) fn build_guest_example() -> Result<PathBuf> {
    build_guest_musl(GuestBin::Example)
}

/// A static musl guest binary `xtask` builds: the agent itself, or the native-ELF fixture.
enum GuestBin {
    Agent,
    Example,
}

impl GuestBin {
    /// The cargo target selector, the built binary's path under `target/<triple>/release/`, and a
    /// human label, the only things that differ between the two builds.
    fn spec(&self) -> (&'static [&'static str], &'static str, &'static str) {
        match self {
            GuestBin::Agent => (
                &["--bin", "agent-guest"],
                "release/agent-guest",
                "guest agent",
            ),
            GuestBin::Example => (
                &["--example", "writefile"],
                "release/examples/writefile",
                "guest example",
            ),
        }
    }
}

/// Build a static musl guest binary (`--locked`, the guest musl target) and verify it's actually
/// statically linked before returning its path. The shared body of [`build_guest_agent`] and
/// [`build_guest_example`], which differ only in [`GuestBin::spec`].
fn build_guest_musl(kind: GuestBin) -> Result<PathBuf> {
    ensure_guest_target()?;
    let (selector, subpath, label) = kind.spec();
    let mut args = vec!["build", "--release", "--locked", "-p", "agent-guest"];
    args.extend_from_slice(selector);
    args.extend_from_slice(&["--target", GUEST_TARGET]);
    cargo(&args)?;
    let bin = workspace_root()
        .join("target")
        .join(GUEST_TARGET)
        .join(subpath);
    verify_static(&bin, label)?;
    println!("\n✓ {label} built (static): {}", bin.display());
    Ok(bin)
}

/// Fail with a clear fix if the guest musl target isn't installed, cargo would otherwise error more
/// obscurely deep in the build.
fn ensure_guest_target() -> Result<()> {
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context("running rustup (is it installed?)")?;
    if !installed.status.success() {
        // Without this, a non-zero rustup (no default toolchain, corrupt state) yields empty stdout
        // and the check below misreports it as "target not installed" — the wrong fix to suggest.
        bail!(
            "`rustup target list --installed` failed (exit {:?}): {}",
            installed.status.code(),
            String::from_utf8_lossy(&installed.stderr).trim()
        );
    }
    if !String::from_utf8_lossy(&installed.stdout)
        .lines()
        .any(|t| t == GUEST_TARGET)
    {
        bail!("missing target {GUEST_TARGET} — run `rustup target add {GUEST_TARGET}` first");
    }
    Ok(())
}

/// Verify the built binary is actually statically linked, "measured, not marketed." A sys-crate or
/// `build.rs` can silently reintroduce a `NEEDED` dynamic dependency, and a dynamically-linked
/// binary baked into a scratch rootfs would fail at boot with a confusing loader error. Two checks,
/// so the guarantee matches the claim: `readelf -d` finds no `(NEEDED)` shared objects, **and**
/// `readelf -l` finds no `INTERP` program header, a fully static binary needs no runtime loader, so
/// a static-PIE (no `NEEDED` but with an interpreter) is also rejected.
fn verify_static(bin: &Path, what: &str) -> Result<()> {
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

/// Run `readelf <flag> <bin>` and return its stdout. `Ok(None)` means `readelf` (binutils) isn't
/// installed, the only outcome the caller may treat as a soft skip. A `readelf` that *is* present
/// but exits non-zero is an `Err`, never a silent `None`: otherwise a tool failure would quietly
/// disarm the static-link check and let a dynamically-linked guest agent pass as "verified static".
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
