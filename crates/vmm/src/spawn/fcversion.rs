//! What Firecracker release is on this host, and what the driver may therefore send it.
//!
//! Pure version logic with no VM state: probe once, cache it, and gate any request field newer
//! than the support floor on a `_SINCE` constant so a new field cannot silently raise the floor.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::deadline_after;

/// The **oldest** Firecracker this engine supports, deliberately tracking upstream's own support
/// window rather than a number of our choosing. Upstream's own release-status table (their release
/// policy doc) is the authority (v1.14 ended the day v1.16 shipped; v1.15 and v1.16 are the current
/// "Supported" rows), and `.github/workflows/firecracker-pin.yml` fails weekly if this drifts from
/// it.
///
/// The floor exists to reject *unpatched* VMMs, not old ones: `doctor` enforces a host kernel floor
/// on the grounds that untrusted code on an unpatched kernel is a threat-model hole, and the same
/// argument says a release upstream still patches must be accepted. So this rises only when a series
/// leaves upstream's table, never to chase a newer feature.
pub(crate) const MIN_SUPPORTED_FC_VERSION: (u64, u64) = (1, 15);

/// The **newest** supported Firecracker: the release CI exercises, `install.sh` hashes, and
/// `doctor` names first. Everything in `MIN_SUPPORTED..=PINNED` is expected to work; only this one
/// is actually tested, which is why the range is documented as "supported" and this one as "tested".
///
/// **The single source of this pin.** `doctor` reports it and `install.sh` mirrors its sha256; a
/// second copy is how the pair sat on v1.9 for 21 months while only one of them was bumped.
pub(crate) const PINNED_FC_VERSION: (u64, u64) = (1, 16);

/// First release accepting `clock_realtime` on `PUT /snapshot/load`. Firecracker rejects unknown
/// fields outright, so sending it to anything older fails **every** restore: the field is therefore
/// conditional ([`clock_realtime_arg`]) rather than unconditional, which is what lets the supported
/// floor sit at [`MIN_SUPPORTED_FC_VERSION`] instead of being dragged up to this by one optional
/// nicety.
pub(crate) const FC_CLOCK_REALTIME_SINCE: (u64, u64) = (1, 16);

/// What probing `firecracker --version` established, cached process-wide.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FcProbe {
    /// The binary could not be run at all (missing, not executable): stays silent in the version
    /// warning, because the spawn itself fails with the legible typed error moments later, and a
    /// "could not parse" warning about a binary that does not exist misleads.
    Unavailable,
    /// The binary ran but its version output was unrecognizable.
    Unparseable,
    /// A parsed `(major, minor)`.
    Version((u64, u64)),
}

/// The probed version of the `firecracker` this process drives, resolved at the first
/// boot/restore and cached: the pin check is process-wide and the probe costs a child spawn.
///
/// One cache for the process, so an embedder pointing separate `BootConfig`s at *different*
/// firecracker binaries gets the first one's version for all of them. Deliberate: the alternative
/// is a probe per boot on the hot path, and a single-binary host is the shape every deployment has.
static FC_VERSION: std::sync::OnceLock<FcProbe> = std::sync::OnceLock::new();

/// Probe (once) and warn, loudly but never fatally, when the binary is outside the supported range.
/// Run `firecracker --version` under a wall and classify the result. Bounded because this is the
/// one probe that runs before any boot deadline is consulted: an `EKVM_FIRECRACKER` pointed at a
/// binary that hangs on `--version` would hang every boot forever with nothing to report. A wedged
/// probe is [`FcProbe::Unavailable`], the silent case, since the spawn that follows produces the
/// legible typed error.
pub(crate) fn probe_fc_version(firecracker: &Path) -> FcProbe {
    // stdout goes to a **file**, not a pipe. `EKVM_FIRECRACKER` may point at a wrapper script, and
    // a wrapper that backgrounds anything inheriting stdout keeps a pipe's write end open forever:
    // reading it after the child is reaped would then block inside this `OnceLock`, hanging every
    // boot, which is the failure the wall above exists to prevent. A file read always terminates.
    // stdin/stderr are nulled (as `Command::output()` nulled stdin) so a wrapper cannot consume the
    // driver's stdin or write onto an embedder's stderr. What a file costs that a pipe didn't: a
    // wrapper flooding stdout writes to disk for up to the wall instead of blocking at 64 KiB, so
    // the file is unlinked at creation and its space returns the moment the fd closes.
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
            let deadline = deadline_after(crate::proc::VERSION_PROBE_TIMEOUT);
            if crate::drives::wait_bounded(
                &mut child,
                deadline,
                "firecracker --version",
                Duration::from_millis(5),
                || None,
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

/// How much of the probe's captured stdout is read back. A version banner is one line; the cap is
/// what keeps a binary that floods stdout from being read into host RAM.
pub(crate) const VERSION_HEAD_CAP: u64 = 4096;

/// A warning rather than a typed error because an embedder may knowingly run a build we have not
/// tested; a *missing* or unrunnable binary stays silent here ([`FcProbe::Unavailable`]).
pub(crate) fn warn_on_unpinned_firecracker(firecracker: &Path) {
    let probed = *FC_VERSION.get_or_init(|| probe_fc_version(firecracker));
    let (min_maj, min_min) = MIN_SUPPORTED_FC_VERSION;
    let (pin_maj, pin_min) = PINNED_FC_VERSION;
    match probed {
        // Inside the supported range: silent. Only the tested version is `PINNED`, but every release
        // in the range is one upstream patches and this driver builds valid request bodies for.
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
/// Conservative by construction: an unprobed or unparseable version omits the field, and the omitted
/// body is the one every supported release accepts. The cost of guessing wrong in that direction is
/// a restored clone whose clock did not advance; guessing wrong the other way fails the restore
/// outright, which is what shipping this unconditionally actually did.
pub(crate) fn clock_realtime_arg() -> Option<bool> {
    let FcProbe::Version(probed) = *FC_VERSION.get()? else {
        return None;
    };
    (probed >= FC_CLOCK_REALTIME_SINCE).then_some(true)
}

/// The `(major, minor)` out of `firecracker --version` output (first line `Firecracker v1.16.1`).
/// Single-sourced here (the driver's own boot-time pin check) so `doctor`'s readiness probe reports
/// the exact same version the driver validates against, the two surfaces can't drift.
pub(crate) fn fc_version_of(text: &str) -> Option<(u64, u64)> {
    let rest = text.split("Firecracker v").nth(1)?;
    let mut parts = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}
