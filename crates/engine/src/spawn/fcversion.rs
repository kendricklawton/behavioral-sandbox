//! What Firecracker release is on this host, and what the driver may therefore send it.
//!
//! Pure version logic with no VM state: probe once, cache it, and gate any request field newer
//! than the support floor on a `_SINCE` constant so a new field cannot silently raise the floor.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::deadline_after;

/// The **oldest** Firecracker this engine supports, tracking upstream's own release-status table
/// rather than a number of our choosing; `.github/workflows/firecracker-pin.yml` fails weekly if
/// this drifts from it.
///
/// The floor rejects *unpatched* VMMs, not old ones (the argument by which `doctor` enforces a host
/// kernel floor), so it rises only when a series leaves upstream's table, never to chase a newer
/// feature.
pub(crate) const MIN_SUPPORTED_FC_VERSION: (u64, u64) = (1, 15);

/// The **newest** supported Firecracker: the release CI exercises and `doctor` names first. All of
/// `MIN_SUPPORTED..=PINNED` is expected to work, but only this one is tested. **The single source
/// of this pin**, since a second copy is how it and `install.sh`'s sha256 drift.
pub(crate) const PINNED_FC_VERSION: (u64, u64) = (1, 16);

/// First release accepting `clock_realtime` on `PUT /snapshot/load`. Firecracker rejects unknown
/// fields outright, so sending it to anything older fails **every** restore: the field is therefore
/// conditional ([`clock_realtime_arg`]), which keeps the supported floor at
/// [`MIN_SUPPORTED_FC_VERSION`] rather than dragging it up to this for one optional nicety.
pub(crate) const FC_CLOCK_REALTIME_SINCE: (u64, u64) = (1, 16);

/// What probing `firecracker --version` established, cached process-wide.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FcProbe {
    /// The binary could not be run at all (missing, not executable). Silent in the version
    /// warning, because the spawn itself fails with the legible typed error moments later.
    Unavailable,
    /// The binary ran but its version output was unrecognizable.
    Unparseable,
    /// A parsed `(major, minor)`.
    Version((u64, u64)),
}

/// The probed version of the `firecracker` this process drives, resolved at the first boot/restore
/// and cached, because the probe costs a child spawn. One cache for the whole process, so an
/// embedder pointing separate `BootConfig`s at *different* firecracker binaries gets the first
/// one's version for all of them.
static FC_VERSION: std::sync::OnceLock<FcProbe> = std::sync::OnceLock::new();

/// Runs `firecracker --version` under a wall and classifies the result. Bounded because this is
/// the one probe that runs before any boot deadline is consulted, so an `BSX_FIRECRACKER` pointed
/// at a binary that hangs on `--version` would otherwise hang every boot with nothing to report. A
/// wedged probe is [`FcProbe::Unavailable`], the silent case.
pub(crate) fn probe_fc_version(firecracker: &Path) -> FcProbe {
    probe_fc_version_within(firecracker, crate::proc::VERSION_PROBE_TIMEOUT)
}

/// [`probe_fc_version`] with the wall as an argument, so the wedged-binary case can be tested
/// against a short one. A parameter rather than a `#[cfg(test)]` constant, because a compile-time
/// swap would leave the shipped path and the tested path as two different paths.
pub(super) fn probe_fc_version_within(firecracker: &Path, wall: Duration) -> FcProbe {
    // stdout goes to a **file**, not a pipe: `BSX_FIRECRACKER` may point at a wrapper script, and
    // a wrapper that backgrounds anything inheriting stdout keeps a pipe's write end open forever,
    // so reading it after the child is reaped would block inside this `OnceLock`. A file read
    // always terminates. stdin/stderr are nulled so a wrapper cannot consume the driver's stdin or
    // write onto an embedder's stderr. A flooding wrapper writes to disk for up to the wall, so the
    // file is unlinked at creation and its space returns the moment the fd closes.
    let Ok((sink, back)) = crate::proc::scratch_pair("fcver") else {
        return FcProbe::Unavailable;
    };
    let mut cmd = Command::new(firecracker);
    cmd.arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(sink))
        .stderr(std::process::Stdio::null());
    match cmd.spawn() {
        Err(_) => FcProbe::Unavailable,
        Ok(mut child) => {
            let deadline = deadline_after(wall);
            if crate::drives::wait_bounded(
                &mut child,
                deadline,
                "firecracker --version",
                Duration::from_millis(5),
                crate::drives::HELPER_REAP_GRACE,
            )
            .is_err()
            {
                FcProbe::Unavailable
            } else {
                match crate::proc::read_head(back, VERSION_HEAD_CAP) {
                    Ok(head) => match fc_version_of(&head) {
                        Some(v) => FcProbe::Version(v),
                        None => FcProbe::Unparseable,
                    },
                    Err(_) => FcProbe::Unavailable,
                }
            }
        }
    }
}

/// How much of the probe's captured stdout is read back, so a binary that floods stdout is never
/// read into host RAM.
pub(crate) const VERSION_HEAD_CAP: u64 = 4096;

/// A warning rather than a typed error because an embedder may knowingly run a build we have not
/// tested; a *missing* or unrunnable binary stays silent here ([`FcProbe::Unavailable`]).
pub(crate) fn warn_on_unpinned_firecracker(firecracker: &Path) {
    let probed = *FC_VERSION.get_or_init(|| probe_fc_version(firecracker));
    let (min_maj, min_min) = MIN_SUPPORTED_FC_VERSION;
    let (pin_maj, pin_min) = PINNED_FC_VERSION;
    match probed {
        // Inside the supported range: silent. Only `PINNED` is tested, but every release in the
        // range is one upstream patches and this driver builds valid request bodies for.
        FcProbe::Version(v) if (MIN_SUPPORTED_FC_VERSION..=PINNED_FC_VERSION).contains(&v) => {}
        FcProbe::Version((maj, min)) if (maj, min) < MIN_SUPPORTED_FC_VERSION => tracing::warn!(
            found = %format!("v{maj}.{min}"),
            supported = %format!("v{min_maj}.{min_min}..=v{pin_maj}.{pin_min}"),
            "firecracker is older than any release upstream still patches: boots may work, but this \
             engine neither tests nor supports it, and running untrusted code on an unpatched VMM is \
             the hole the isolation boundary exists to close; install a supported release: \
             https://github.com/firecracker-microvm/firecracker/releases"
        ),
        FcProbe::Version((maj, min)) => tracing::warn!(
            found = %format!("v{maj}.{min}"),
            supported = %format!("v{min_maj}.{min_min}..=v{pin_maj}.{pin_min}"),
            "firecracker is newer than the release this engine is tested against: request bodies and \
             snapshot semantics may have moved"
        ),
        FcProbe::Unparseable => tracing::warn!(
            binary = %firecracker.display(),
            "could not parse `firecracker --version`; this engine supports v{min_maj}.{min_min}..=v{pin_maj}.{pin_min}"
        ),
        FcProbe::Unavailable => {}
    }
}

/// The `clock_realtime` value for `PUT /snapshot/load`: `Some(true)` only when the probed binary is
/// new enough to know the field, else `None` so it is omitted from the body entirely.
///
/// Conservative by construction: an unprobed or unparseable version omits the field, and the
/// omitted body is the one every supported release accepts. Guessing wrong in that direction costs
/// a restored clone whose clock did not advance; guessing wrong the other way fails the restore.
pub(crate) fn clock_realtime_arg() -> Option<bool> {
    let FcProbe::Version(probed) = *FC_VERSION.get()? else {
        return None;
    };
    (probed >= FC_CLOCK_REALTIME_SINCE).then_some(true)
}

/// The `(major, minor)` out of `firecracker --version` output (first line `Firecracker v1.16.1`).
/// Its one non-test caller is [`probe_fc_version_within`], so every surface that names a version
/// reaches this parse through that probe.
pub(crate) fn fc_version_of(text: &str) -> Option<(u64, u64)> {
    let rest = text.split("Firecracker v").nth(1)?;
    let mut parts = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}
