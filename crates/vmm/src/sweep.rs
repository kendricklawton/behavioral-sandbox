//! The orphan sweep — the engine's garbage collector for crashed-driver residue.
//!
//! Teardown is `Drop`-based and the lifetime sentinel (decision 014) owns the VM *process tree*,
//! but a driver that dies without `Drop` (SIGKILL, OOM) still leaves filesystem and network
//! residue: its per-VM scratch dirs and — the part that is **not** inert — its taps. An orphaned
//! `fc*` tap still holds its /30 host address, which is the allocator's atomic reservation
//! (decision 009), so accumulated crashes clog the finite `10.200/16` pool until the allocator's
//! bounded retry exhausts and every networked boot on a healthy host fails. [`sweep_orphans`]
//! reclaims both, the way kubelet's image/container GC reclaims a crashed kubelet's leavings.
//!
//! **Ownership is keyed on the pid embedded in the scratch-dir name** (`agent-<pid>-<n>`), plus a
//! tap-name record the driver writes into the dir at tap creation ([`record_tap`]). The tap *name*
//! is never trusted as an ownership key on its own: a restored clone's tap carries the snapshot's
//! recorded name (decision 011), whose embedded token belongs to the — possibly dead — source
//! driver, so only the dir-plus-record pairing says who owns what.
//!
//! Conservative by construction:
//! - A dir whose embedded pid is **alive** is skipped: a live driver, or a recycled pid we can't
//!   tell from one (the orphan is reclaimed by a later sweep, once the pid frees). The error
//!   direction is always "kept too long", never "reclaimed a live VM's resources".
//! - A tap is deleted only when a **dead** dir records it *and* no live dir records the same name
//!   (a name could be re-minted by a live driver after manual cleanup of the orphan tap).
//! - A dead dir with a **still-running VMM** (only possible where the sentinel degraded: no
//!   writable cgroup v2) is skipped with a warning. The sweep owns fs/net residue; processes are
//!   the sentinel's (decision 014) — it never kills.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::net::{iface_exists, ip_link_del};
use crate::VmmError;

/// The file inside a per-VM scratch dir recording the name of the tap that VM owns, written at tap
/// creation so the sweep can pair network residue with the dir's embedded owner pid.
pub(crate) const TAP_RECORD: &str = "tap";

/// Record `tap` as owned by the VM whose scratch dir is `workdir`. Called right after the tap is
/// created, so the window in which a crash leaves an unrecorded (unsweepable) tap is one write —
/// the same order-of-arming shape as the lifetime sentinel's spawn→enrollment window.
pub(crate) fn record_tap(workdir: &Path, tap: &str) -> Result<(), VmmError> {
    let path = workdir.join(TAP_RECORD);
    std::fs::write(&path, tap)
        .map_err(|e| VmmError::Vmm(format!("record tap {tap} in {}: {e}", path.display())))
}

/// What a [`sweep_orphans`] pass reclaimed and what it deliberately left alone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepReport {
    /// Dead drivers' scratch dirs removed.
    pub dirs_reclaimed: usize,
    /// Orphaned taps deleted (their /30 reservations released back to the allocator).
    pub taps_reclaimed: usize,
    /// Scratch dirs skipped because their owner pid is alive (a live driver, or a recycled pid —
    /// indistinguishable, so both are kept).
    pub live_skipped: usize,
}

/// Reclaim the residue of **dead** drivers under `scratch_dir` (the [`BootConfig::scratch_dir`]
/// base, `/tmp` by default): their per-VM scratch dirs, and the orphaned taps those dirs record —
/// releasing the /30 reservations that would otherwise clog the allocator (decision 009). Never
/// touches a live driver's resources; see the module doc for the ownership rules.
///
/// Safe to run at any time — embedder startup is the natural moment (the analogue of a container
/// runtime's boot-time GC) — and concurrently with live drivers: liveness is checked per dir, and
/// everything a live pid owns is skipped. Per-entry failures are logged and skipped, never fatal,
/// so one undeletable dir can't shadow the rest of the sweep.
///
/// [`BootConfig::scratch_dir`]: crate::BootConfig::scratch_dir
///
/// # Errors
/// [`VmmError::Vmm`] only if `scratch_dir` itself can't be read.
pub fn sweep_orphans(scratch_dir: &Path) -> Result<SweepReport, VmmError> {
    let entries = std::fs::read_dir(scratch_dir)
        .map_err(|e| VmmError::Vmm(format!("read scratch base {}: {e}", scratch_dir.display())))?;

    // Partition the per-VM dirs by owner liveness, and collect every tap name a *live* dir records
    // so a dead dir's record can never delete a name a live driver has since re-minted.
    let mut report = SweepReport::default();
    let mut dead: Vec<(PathBuf, Option<String>)> = Vec::new();
    let mut live_taps: BTreeSet<String> = BTreeSet::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = owner_pid(&name) else {
            continue; // Not a per-VM scratch dir; never touched.
        };
        let path = entry.path();
        if pid_alive(pid) {
            report.live_skipped += 1;
            if let Some(tap) = recorded_tap(&path) {
                live_taps.insert(tap);
            }
        } else {
            let tap = recorded_tap(&path);
            dead.push((path, tap));
        }
    }

    for (dir, tap) in dead {
        // The one way a dead driver leaves a *running* VMM is a degraded sentinel (no writable
        // cgroup v2, decision 014). Deleting files under a live VMM would strand it on unlinked
        // inodes; processes are the sentinel's jurisdiction, so skip loudly instead.
        if let Some(vmm) = vmm_running_in(&dir) {
            tracing::warn!(
                dir = %dir.display(),
                vmm,
                "sweep: dead driver but its VMM is still running (degraded sentinel?); skipping"
            );
            report.live_skipped += 1;
            continue;
        }
        if let Some(tap) = tap {
            if live_taps.contains(&tap) {
                tracing::warn!(%tap, dir = %dir.display(),
                    "sweep: tap recorded by a dead dir is also recorded by a live one; leaving it");
            } else if iface_exists(&tap) {
                ip_link_del(&tap);
                if iface_exists(&tap) {
                    tracing::warn!(%tap, "sweep: failed to delete orphaned tap");
                } else {
                    report.taps_reclaimed += 1;
                    tracing::info!(%tap, "sweep: reclaimed orphaned tap (freed its /30)");
                }
            }
        }
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                report.dirs_reclaimed += 1;
                tracing::info!(dir = %dir.display(), "sweep: reclaimed dead driver's scratch dir");
            }
            // E.g. root-owned chroot content under a non-root sweep (jailed boots need root, so
            // their residue does too). The tap half is already reclaimed; the dir waits for a
            // sufficiently-privileged sweep.
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "sweep: failed to remove dir")
            }
        }
    }
    Ok(report)
}

/// The owner pid embedded in a per-VM scratch-dir name, iff `name` matches the exact
/// `agent-<pid>-<seq>` pattern `create_workdir` mints (both fields numeric). Anything else —
/// including the test suite's `agent-<tag>-<pid>` temp dirs — is not a sweep candidate.
fn owner_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix("agent-")?;
    let (pid, seq) = rest.split_once('-')?;
    if pid.is_empty() || seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

/// Whether `pid` currently exists. Deliberately not comm-checked: the driver is the *embedder's*
/// process, whose name we can't know — so a recycled pid reads as alive and its dir is kept
/// (the conservative direction; a later sweep gets it).
fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// The tap name recorded in `dir`, validated hard before it can ever reach `ip link del`: the
/// `fc<hex>` shape the allocator mints, nothing else. A scratch dir is `0700` and driver-written,
/// but the sweep may run long after with no context — parse, don't trust.
fn recorded_tap(dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(dir.join(TAP_RECORD)).ok()?;
    let name = raw.trim();
    let hex = name.strip_prefix("fc")?;
    // IFNAMSIZ-1 = 15 bytes; the allocator emits `fc` + ≤12 hex digits.
    if name.len() > 15 || hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(name.to_string())
}

/// The pid of a `firecracker`/`jailer` process whose cwd is inside `dir`, if one is running. An
/// unjailed VMM's cwd *is* its scratch dir (`spawn_fc` sets it for the relative vsock path); a
/// jailed VMM's cwd is its chroot root, `<dir>/<exec-name>/<id>/root`. Identity is compared by
/// `(st_dev, st_ino)` through the `/proc/<pid>/cwd` magic link — the link *text* is
/// namespace-relative after a pivot_root (the P6.6 lesson), but `metadata` resolves through it.
/// Processes whose cwd we can't stat (another user's) are ignored; jailed boots need root, so a
/// sweep of jailed residue runs as root and can see them.
fn vmm_running_in(dir: &Path) -> Option<u32> {
    let protected = protected_identities(dir);
    if protected.is_empty() {
        return None;
    }
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if !matches!(comm.trim(), "firecracker" | "jailer") {
            continue;
        }
        if let Ok(cwd) = std::fs::metadata(entry.path().join("cwd")) {
            if protected.contains(&(cwd.dev(), cwd.ino())) {
                return Some(pid);
            }
        }
    }
    None
}

/// The `(st_dev, st_ino)` identities a VMM's cwd could carry for the VM whose scratch dir is
/// `dir`: the dir itself (unjailed), plus any `<dir>/<x>/<y>/root` chroot roots the jailer built.
fn protected_identities(dir: &Path) -> BTreeSet<(u64, u64)> {
    let mut ids = BTreeSet::new();
    if let Ok(m) = std::fs::metadata(dir) {
        ids.insert((m.dev(), m.ino()));
    }
    // The jailer nests its chroot two levels down: `<chroot-base>/<exec-file-name>/<id>/root`.
    for lvl1 in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        for lvl2 in std::fs::read_dir(lvl1.path())
            .into_iter()
            .flatten()
            .flatten()
        {
            if let Ok(m) = std::fs::metadata(lvl2.path().join("root")) {
                ids.insert((m.dev(), m.ino()));
            }
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TestDir;

    /// A pid guaranteed dead: spawn a short-lived child and reap it. Immediate recycling of a
    /// just-freed pid is effectively impossible (the kernel allocates pids cyclically).
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn `true`");
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    #[test]
    fn sweep_reclaims_dead_dirs_and_spares_live_and_foreign_ones() {
        let base = TestDir::new("agent-sweep-base");
        let dead = base.path().join(format!("agent-{}-0", dead_pid()));
        let live = base.path().join(format!("agent-{}-0", std::process::id()));
        let foreign = base.path().join("agent-bundle-1234"); // the test suite's TmpDir shape
        for d in [&dead, &live, &foreign] {
            std::fs::create_dir(d).expect("create test dir");
        }
        // The dead dir records a valid-shaped tap that doesn't exist; deletion is skipped (no
        // iface), but the dir itself must go.
        record_tap(&dead, "fcdead0").expect("record tap");

        let report = sweep_orphans(base.path()).expect("sweep");
        assert!(!dead.exists(), "dead driver's dir must be reclaimed");
        assert!(live.exists(), "live driver's dir must be spared");
        assert!(
            foreign.exists(),
            "non-workdir entries must never be touched"
        );
        assert_eq!(report.dirs_reclaimed, 1);
        assert_eq!(report.live_skipped, 1);
        assert_eq!(report.taps_reclaimed, 0, "no such iface, nothing deleted");
    }

    #[test]
    fn owner_pid_parses_only_the_workdir_pattern() {
        assert_eq!(owner_pid("agent-1234-0"), Some(1234));
        assert_eq!(owner_pid("agent-1234-56"), Some(1234));
        for miss in [
            "agent-1234",        // no sequence
            "agent-bundle-1234", // a TmpDir tag, not a pid
            "agent-1234-x",      // non-numeric sequence
            "agent--0",          // empty pid
            "other-1234-0",      // wrong prefix
            "agent-1234-0-x",    // trailing junk in the seq field
        ] {
            assert_eq!(owner_pid(miss), None, "{miss} must not parse");
        }
    }

    #[test]
    fn recorded_tap_rejects_hostile_or_malformed_names() {
        let dir = TestDir::new("agent-sweep-rec");
        let record = |content: &str| {
            std::fs::write(dir.path().join(TAP_RECORD), content).expect("write record");
            recorded_tap(dir.path())
        };
        assert_eq!(record("fcdeadbeef\n"), Some("fcdeadbeef".into()), "trimmed");
        assert_eq!(record("fc0123456789abc"), Some("fc0123456789abc".into()));
        for bad in [
            "eth0",             // not ours
            "fc",               // no token
            "fczz",             // non-hex
            "fc12/../../x",     // path traversal shape
            "fc0123456789abcd", // 16 bytes: past IFNAMSIZ-1
            "fc12 extra",       // embedded whitespace
            "-fc12",            // could parse as a flag
        ] {
            assert_eq!(record(bad), None, "{bad:?} must be rejected");
        }
        std::fs::remove_file(dir.path().join(TAP_RECORD)).expect("rm record");
        assert_eq!(recorded_tap(dir.path()), None, "missing record is None");
    }

    #[test]
    fn sweep_errors_only_on_an_unreadable_base() {
        let err = sweep_orphans(Path::new("/nonexistent-sweep-base"))
            .expect_err("missing base is a typed error");
        assert!(matches!(err, VmmError::Vmm(_)));
    }
}
