//! Ad-hoc code signing for the one binary that reaches a hypervisor.
//!
//! - **macOS refuses an unentitled process.** `hv_vm_create` answers `HV_DENIED` without
//!   `com.apple.security.hypervisor` and `HV_SUCCESS` with it, measured on one binary both ways
//!   (roadmap 6.2). The entitlement is `xtask/hypervisor.entitlements`, committed so that what the
//!   binary is granted is reviewable in the tree.
//! - **A build drops the signature**, because cargo writes a new binary on every relink. So this is
//!   a step *after* a build rather than a setup done once, and re-running it is the normal case.
//! - **Ad-hoc is enough**: `codesign -s -` needs no Apple Developer identity.
//! - **`bsx` alone.** It carries the `__vmm` helper that calls `krun_start_enter`, the only call in
//!   the tree that asks a hypervisor for anything. `bsx-app` maps shared frames and spawns `bsx`.
//! - **Signing is verified, not assumed**: `codesign` can report success having applied nothing, so
//!   the entitlement is read back off the binary and its absence is an error.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{target_dir, workspace_root};

/// The entitlement that decides whether the hypervisor answers, relative to the workspace root.
const ENTITLEMENTS: &str = "xtask/hypervisor.entitlements";

/// The key the signed binary must carry, and what a verification reads back.
const HYPERVISOR_KEY: &str = "com.apple.security.hypervisor";

/// The binary that becomes a VM. `bsx-app` is not here: it never calls into a hypervisor.
const SIGNED_BIN: &str = "bsx";

/// Signs the built `bsx` so it can reach the hypervisor, or explains why there is nothing to do.
pub(crate) fn sign_for_hypervisor(release: bool) -> Result<()> {
    if !cfg!(target_os = "macos") {
        // Said rather than passed over: a step that silently does nothing reads as a step that
        // worked, and on Linux the hypervisor is reached through a device node, not a signature.
        println!("sign: nothing to sign on this host (Hypervisor.framework is macOS's)");
        return Ok(());
    }

    let bin = binary_path(release);
    if !bin.is_file() {
        bail!(
            "no {} at {} — build it first with `cargo build{} -p bsx`",
            SIGNED_BIN,
            bin.display(),
            if release { " --release" } else { "" }
        );
    }

    let entitlements = workspace_root().join(ENTITLEMENTS);
    if !entitlements.is_file() {
        bail!("no entitlement file at {}", entitlements.display());
    }

    codesign(&bin, &entitlements)?;
    if !grants_hypervisor(&bin)? {
        bail!(
            "codesign reported success but {} does not grant {HYPERVISOR_KEY}",
            bin.display()
        );
    }
    println!("sign: {} grants {HYPERVISOR_KEY}", bin.display());
    Ok(())
}

/// Replaces whatever signature the linker left with an ad-hoc one carrying the entitlement.
fn codesign(bin: &Path, entitlements: &Path) -> Result<()> {
    let out = Command::new("codesign")
        .arg("--force")
        // `-` is the ad-hoc identity: no Apple Developer account, and no keychain to unlock.
        .args(["--sign", "-"])
        .arg("--entitlements")
        .arg(entitlements)
        .arg(bin)
        .output()
        .context("running codesign (Xcode command line tools)")?;
    if !out.status.success() {
        bail!(
            "codesign failed for {}: {}",
            bin.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Whether `bin`'s signature actually grants the hypervisor: the key present **and** true.
///
/// The value is what is checked, not the key. A plist carrying the key set `<false/>` signs without
/// complaint and leaves the binary `HV_DENIED`, so a check for the key alone reports a working
/// binary that cannot start a VM.
fn grants_hypervisor(bin: &Path) -> Result<bool> {
    let out = Command::new("codesign")
        // The `:` prefix asks for the entitlements as a raw plist on stdout; the bare `-` form
        // writes an annotated dump to stderr whose layout has moved between releases.
        .args(["-d", "--entitlements", ":-"])
        .arg(bin)
        .output()
        .context("reading back the entitlements codesign applied")?;
    let plist: String = String::from_utf8_lossy(&out.stdout)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    Ok(plist.contains(&format!("<key>{HYPERVISOR_KEY}</key><true/>")))
}

/// Where cargo leaves the binary this signs, under the profile it was built with.
fn binary_path(release: bool) -> std::path::PathBuf {
    target_dir()
        .join(if release { "release" } else { "debug" })
        .join(SIGNED_BIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed entitlement grants exactly one key. A second one would widen what an ad-hoc
    /// signature hands a binary that runs untrusted guests, so it is asserted rather than reviewed.
    #[test]
    fn the_entitlement_grants_the_hypervisor_and_nothing_else() {
        let path = workspace_root().join(ENTITLEMENTS);
        let plist = std::fs::read_to_string(&path).expect("the committed entitlement file");
        let packed: String = plist.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            packed.contains(&format!("<key>{HYPERVISOR_KEY}</key><true/>")),
            "{path:?} must grant {HYPERVISOR_KEY}, and `<false/>` signs just as quietly"
        );
        let keys: Vec<&str> = plist
            .lines()
            .filter_map(|l| l.trim().strip_prefix("<key>"))
            .filter_map(|l| l.strip_suffix("</key>"))
            .collect();
        assert_eq!(
            keys,
            [HYPERVISOR_KEY],
            "one entitlement, or the grant has widened"
        );
    }

    /// The read-back reads the **value**: a binary signed with the key set `<false/>` is not
    /// granted the hypervisor, and reporting it as granted would pass a binary that is `HV_DENIED`.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_false_entitlement_is_not_read_as_a_grant() {
        let dir = bsx_test_support::ScratchDir::created("sign-readback");
        let subject = dir.path().join("subject");
        std::fs::copy(std::env::current_exe().expect("this test binary"), &subject)
            .expect("a binary to sign");

        let refused = dir.path().join("false.entitlements");
        std::fs::write(
            &refused,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
                 <key>{HYPERVISOR_KEY}</key><false/></dict></plist>\n"
            ),
        )
        .expect("the refusing plist");
        codesign(&subject, &refused).expect("codesign accepts a false grant");
        assert!(
            !grants_hypervisor(&subject).expect("read back"),
            "`<false/>` is a key without a grant"
        );

        codesign(&subject, &workspace_root().join(ENTITLEMENTS)).expect("codesign the real grant");
        assert!(
            grants_hypervisor(&subject).expect("read back"),
            "the committed entitlement grants it"
        );
    }

    /// The profile picks the directory the signature is applied to, so `--release` cannot sign a
    /// debug binary and report the release one signed.
    #[test]
    fn the_profile_picks_which_binary_is_signed() {
        assert!(
            binary_path(false).ends_with("debug/bsx"),
            "{:?}",
            binary_path(false)
        );
        assert!(
            binary_path(true).ends_with("release/bsx"),
            "{:?}",
            binary_path(true)
        );
        assert_ne!(binary_path(false), binary_path(true));
    }

    /// `CARGO_TARGET_DIR` moves where cargo writes, so it has to move what is signed with it, or
    /// a host that sets it signs a path nothing was built at.
    #[test]
    fn the_signed_path_follows_cargo_target_dir() {
        let under = target_dir();
        assert!(
            binary_path(false).starts_with(&under),
            "{:?} is not under {:?}",
            binary_path(false),
            under
        );
    }
}
