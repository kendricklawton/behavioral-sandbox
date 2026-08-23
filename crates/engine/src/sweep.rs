//! The orphan sweep, the engine's garbage collector for crashed-driver residue.
//!
//! The lifetime sentinel owns the VM *process tree*, but a driver that dies without `Drop` leaves
//! its per-VM scratch dirs and per-VM network namespaces, each holding the VM's tap. **Ownership is
//! keyed on the pid embedded in the scratch-dir name** (`bsx-<pid>-<n>`), and a dir's netns carries
//! that dir's own name (a restored clone's, its own rather than its source's).
//!
//! Conservative by construction:
//! - **Owner uid.** Only dirs owned by the sweeping euid are candidates: the scratch base is
//!   world-writable, and `create_workdir` makes real per-VM dirs `0700` and driver-owned, so
//!   ownership is the authorship proof that stops a decoy dir naming a *victim's* live netns.
//! - **Live pid.** A dir whose embedded pid is alive is skipped, whether a live driver or a
//!   recycled pid. The error direction is always "kept too long", never "reclaimed a live VM".
//! - **Live VMM.** A dead dir with a still-running VMM, only possible where the sentinel degraded,
//!   is skipped with a warning: the sweep owns fs and net residue, processes are the sentinel's.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::VmmError;
use crate::jail::unmount_base;
use crate::net::{netns_del, netns_exists};
use crate::spawn::VM_DIR_PREFIX;

/// What a [`sweep_orphans`] pass reclaimed and what it deliberately left alone. `#[non_exhaustive]`
/// so a later pass can report a new count without breaking a caller reading these.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepReport {
    /// Dead drivers' scratch dirs removed.
    pub dirs_reclaimed: usize,
    /// Orphaned per-VM network namespaces deleted (each cascading its tap away).
    pub netns_reclaimed: usize,
    /// Scratch dirs left alone because something in them was still live: the owner pid (a live
    /// driver, or one whose pid was recycled), or, under a dead owner pid, its VMM process.
    pub live_skipped: usize,
    /// Dead-pid dirs whose removal was deferred because a restore is staging a disk into them right
    /// now, witnessed by a live stager's pid in the dir's `RESTORE_STAGING_MARKER` file.
    pub restore_staging_skipped: usize,
}

/// The marker a restoring driver drops in the staging dir for exactly the copy→`PUT /snapshot/load`
/// window, holding its own pid (`stage_restore_disk` writes it, `unstage_restore_disk` removes it),
/// so the sweep defers a dead dir only while the marker names a live pid.
pub(crate) const RESTORE_STAGING_MARKER: &str = ".restore-staging";

/// Reclaim the residue of **dead** drivers under `scratch_dir` (the [`BootConfig::scratch_dir`]
/// base, `/tmp` by default): their per-VM scratch dirs, and the per-VM network namespaces named
/// after them (each holding an orphaned tap). Safe to run at any time and concurrently with live
/// drivers: liveness is checked per dir, everything a live pid owns is skipped, and a per-entry
/// failure is logged rather than fatal, so one undeletable dir can't shadow the rest of the sweep.
///
/// **The hoster's half.** This reclaims only dirs the calling euid owns, so deploying it is the
/// caller's: nothing schedules it, drivers running as several users each need their own sweep, and
/// a scratch base only the engine user can write leaves no decoy for the ownership check to reject.
///
/// [`BootConfig::scratch_dir`]: crate::BootConfig::scratch_dir
///
/// # Errors
/// [`VmmError::Vmm`] only if `scratch_dir` itself can't be read.
pub fn sweep_orphans(scratch_dir: &Path) -> Result<SweepReport, VmmError> {
    let entries = std::fs::read_dir(scratch_dir)
        .map_err(|e| VmmError::Vmm(format!("read scratch base {}: {e}", scratch_dir.display())))?;
    // Fail closed: without the ownership proof, the candidate set on a world-writable base is an
    // attacker-writable kill list.
    let Some(me) = own_euid() else {
        return Err(VmmError::Vmm(
            "cannot read own euid from /proc/self/status; refusing to sweep without it".into(),
        ));
    };

    let mut report = SweepReport::default();
    let mut dead: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = owner_pid(&name) else {
            continue; // Not a per-VM scratch dir; never touched.
        };
        if entry.metadata().map(|m| m.uid()).ok() != Some(me) {
            continue;
        }
        if pid_alive(pid) {
            report.live_skipped += 1;
        } else {
            dead.push(entry.path());
        }
    }

    for dir in dead {
        // Deleting files under a live VMM would strand it on unlinked inodes.
        if let Some(vmm) = vmm_running_in(&dir) {
            tracing::warn!(
                dir = %dir.display(),
                vmm,
                "sweep: dead driver but its VMM is still running (degraded sentinel?); skipping"
            );
            report.live_skipped += 1;
            continue;
        }
        // Deleting the netns cascades its tap away.
        if let Some(netns) = dir.file_name().and_then(|n| n.to_str())
            && netns_exists(netns)
        {
            netns_del(netns);
            if netns_exists(netns) {
                tracing::warn!(%netns, "sweep: failed to delete orphaned netns");
            } else {
                report.netns_reclaimed += 1;
                tracing::info!(%netns, "sweep: reclaimed orphaned network namespace");
            }
        }
        // A cross-process restore stages the source's disk into this dead-source-pid dir, so
        // `remove_dir_all` mid-copy would flake it. Only the dir removal waits, not the netns.
        if restore_staging_in(&dir) {
            tracing::debug!(
                dir = %dir.display(),
                "sweep: a restore is staging into this dir; deferring its removal"
            );
            report.restore_staging_skipped += 1;
            continue;
        }
        // A crashed driver's jailed read-only boot leaves the shared base **bind-mounted** into its
        // chroot, and `remove_dir_all` would `EBUSY` on that mount point and leak the whole dir.
        detach_mounts_under(&dir);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {
                report.dirs_reclaimed += 1;
                tracing::info!(dir = %dir.display(), "sweep: reclaimed dead driver's scratch dir");
            }
            // E.g. root-owned chroot content under a non-root sweep: the tap half is already
            // reclaimed, and the dir waits for a sufficiently-privileged sweep.
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "sweep: failed to remove dir")
            }
        }
    }
    Ok(report)
}

/// Detach (lazy, best-effort) every mount whose mount point lies under `dir`, deepest first, so a
/// following `remove_dir_all` can't `EBUSY` on a mount a crashed driver left behind. A no-op when
/// `dir` holds no mounts.
fn detach_mounts_under(dir: &Path) {
    let Some(info) = crate::mountinfo::self_text() else {
        return;
    };
    for mp in mounts_under(&info, dir) {
        unmount_base(&mp);
    }
}

/// The mount points under `dir` in `mountinfo`, **deepest first**, since a child mount must be
/// detached before its parent's mount point. Split from the unmounting so both are unit-testable
/// against a fixture rather than a live `/proc`.
fn mounts_under(mountinfo: &str, dir: &Path) -> Vec<PathBuf> {
    let mut points: Vec<PathBuf> = crate::mountinfo::mounts(mountinfo)
        .filter(|m| m.point.starts_with(dir))
        .map(|m| m.point)
        .collect();
    points.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    points
}

/// Whether a live process is staging a restore disk into `dir` right now: its
/// [`RESTORE_STAGING_MARKER`] names a [`pid_alive`] pid. A crashed stager (dead pid) or a dead
/// driver's own boot disk (no marker) defers nothing; a recycled stager pid defers, conservatively.
fn restore_staging_in(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join(RESTORE_STAGING_MARKER)) else {
        return false;
    };
    text.trim().parse::<u32>().is_ok_and(pid_alive)
}

/// The owner pid embedded in a per-VM scratch-dir name, iff `name` matches the exact
/// `bsx-<pid>-<seq>` pattern `create_workdir` mints (both fields numeric). Anything else,
/// including the test suite's `bsx-<tag>-<pid>` temp dirs, is not a sweep candidate.
fn owner_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(VM_DIR_PREFIX)?.strip_prefix('-')?;
    let (pid, seq) = rest.split_once('-')?;
    if pid.is_empty() || seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

/// Whether `pid` currently exists. Deliberately not comm-checked, since the driver is the
/// *embedder's* process, so a recycled pid reads as alive and its dir is kept for a later sweep.
fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// This process's **effective** uid, from `/proc/self/status`, no `unsafe`, no libc.
pub(crate) fn own_euid() -> Option<u32> {
    euid_in(&std::fs::read_to_string("/proc/self/status").ok()?)
}

/// The effective uid in a `/proc/<pid>/status` body. `strip_prefix` consumes the `Uid:` token, so
/// the remaining whitespace fields are `[real, effective, saved, fs]` and the effective one is
/// index 1; a `starts_with` split would leave `Uid:` as field 0 and shift it to 2. Split from the
/// read so that index is pinned against a **setuid-shaped** line, which a live `/proc` cannot do.
fn euid_in(status: &str) -> Option<u32> {
    let uid = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    uid.split_whitespace().nth(1)?.parse().ok()
}

/// The pid of a `firecracker`/`jailer` process whose cwd is inside `dir`, if one is running. An
/// unjailed VMM's cwd *is* its scratch dir (`spawn_fc` sets it for the relative vsock path); a
/// jailed VMM's cwd is its chroot root. Identity is compared by `(st_dev, st_ino)` through the
/// `/proc/<pid>/cwd` magic link, because the link *text* is namespace-relative after a `pivot_root`
/// while `metadata` resolves through it. Processes whose cwd we can't stat (another user's) are
/// ignored; jailed boots need root, so a sweep of jailed residue runs as root and can see them.
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
        if let Ok(cwd) = std::fs::metadata(entry.path().join("cwd"))
            && protected.contains(&(cwd.dev(), cwd.ino()))
        {
            return Some(pid);
        }
    }
    None
}

/// The `(st_dev, st_ino)` identities a VMM's cwd could carry for the VM whose scratch dir is `dir`:
/// the dir itself (unjailed), plus the `<dir>/<exec-file-name>/<id>/root` chroot roots the jailer
/// nests two levels down.
fn protected_identities(dir: &Path) -> BTreeSet<(u64, u64)> {
    let mut ids = BTreeSet::new();
    if let Ok(m) = std::fs::metadata(dir) {
        ids.insert((m.dev(), m.ino()));
    }
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
    use bsx_test_support::ScratchDir;

    #[test]
    fn mounts_under_finds_an_escaped_point_and_orders_children_first() {
        // `BSX_SCRATCH_DIR` is operator-supplied and a path with a space is legal, so the mount
        // point the kernel writes is octal-escaped. Comparing the raw field misses it, the binds a
        // crashed run left stay attached, and the following `remove_dir_all` fails `EBUSY`.
        let mountinfo = "\
21 1 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
40 21 0:30 / /my\\040scratch/bsx-1 rw,relatime - ext4 /dev/sdb rw
41 40 0:31 / /my\\040scratch/bsx-1/root/rootfs.ext4 rw,relatime - ext4 /dev/sdc rw
42 21 0:32 / /my\\040scratch/bsx-2 rw,relatime - ext4 /dev/sdd rw
";
        let found = mounts_under(mountinfo, Path::new("/my scratch/bsx-1"));
        assert_eq!(
            found,
            vec![
                PathBuf::from("/my scratch/bsx-1/root/rootfs.ext4"),
                PathBuf::from("/my scratch/bsx-1"),
            ],
            "both mounts under the dir, the child before the parent it sits on"
        );

        // A sibling run's dir is not swept by this one, and `/` covers everything but is not under
        // it, so neither may appear above.
        assert!(mounts_under(mountinfo, Path::new("/my scratch/bsx-3")).is_empty());
    }

    /// A pid that is certainly dead: spawn a short-lived child and reap it. Immediate recycling of
    /// a just-freed pid is very unlikely (the kernel allocates pids cyclically).
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
        let base = ScratchDir::created("bsx-sweep-base");
        let dead = base.path().join(format!("bsx-{}-0", dead_pid()));
        let live = base.path().join(format!("bsx-{}-0", std::process::id()));
        let foreign = base.path().join("bsx-bundle-1234"); // the test suite's TmpDir shape
        for d in [&dead, &live, &foreign] {
            std::fs::create_dir(d).expect("create test dir");
        }
        // No netns exists for the dead dir here (creating one needs CAP_NET_ADMIN; the privileged
        // `sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir` test exercises that path). So the
        // netns reclaim is a no-op and the dir itself must still go.
        let report = sweep_orphans(base.path()).expect("sweep");
        assert!(!dead.exists(), "dead driver's dir must be reclaimed");
        assert!(live.exists(), "live driver's dir must be spared");
        assert!(
            foreign.exists(),
            "non-workdir entries must never be touched"
        );
        assert_eq!(report.dirs_reclaimed, 1);
        assert_eq!(report.live_skipped, 1);
        assert_eq!(report.netns_reclaimed, 0, "no such netns, nothing deleted");
    }

    #[test]
    fn owner_pid_parses_only_the_workdir_pattern() {
        assert_eq!(owner_pid("bsx-1234-0"), Some(1234));
        assert_eq!(owner_pid("bsx-1234-56"), Some(1234));
        for miss in [
            "bsx-1234",        // no sequence
            "bsx-bundle-1234", // a TmpDir tag, not a pid
            "bsx-1234-x",      // non-numeric sequence
            "bsx--0",          // empty pid
            "other-1234-0",    // wrong prefix
            "bsx-1234-0-x",    // trailing junk in the seq field
        ] {
            assert_eq!(owner_pid(miss), None, "{miss} must not parse");
        }
    }

    #[test]
    fn sweep_errors_only_on_an_unreadable_base() {
        let err = sweep_orphans(Path::new("/nonexistent-sweep-base"))
            .expect_err("missing base is a typed error");
        assert!(matches!(err, VmmError::Vmm(_)));
    }

    #[test]
    fn restore_staging_is_witnessed_only_by_a_live_stagers_marker() {
        let dir = ScratchDir::created("bsx-stage-marker");
        // No marker: nothing staging (a plain orphan, or a dead driver's own boot disk).
        assert!(!restore_staging_in(dir.path()));
        std::fs::write(dir.path().join("rootfs.ext4"), b"disk").expect("write a disk");
        assert!(
            !restore_staging_in(dir.path()),
            "a disk alone (a dead driver's own boot copy) is not a staging witness"
        );
        // A live stager (this process).
        let marker = dir.path().join(RESTORE_STAGING_MARKER);
        std::fs::write(&marker, std::process::id().to_string()).expect("write marker");
        assert!(restore_staging_in(dir.path()));
        // A crashed stager (dead pid) or a garbled marker defers nothing.
        std::fs::write(&marker, dead_pid().to_string()).expect("rewrite marker");
        assert!(!restore_staging_in(dir.path()));
        std::fs::write(&marker, "not-a-pid").expect("rewrite marker");
        assert!(!restore_staging_in(dir.path()));
    }

    #[test]
    fn sweep_defers_a_dead_dir_a_live_restore_is_staging_into() {
        // A cross-process restore stages the source's disk into the source's now-dead-pid dir; the
        // sweep must not `remove_dir_all` it mid-copy. The witness is the stager's live-pid marker.
        let base = ScratchDir::created("bsx-sweep-stage");
        let staging = base.path().join(format!("bsx-{}-0", dead_pid()));
        std::fs::create_dir(&staging).expect("create staging dir");
        std::fs::write(staging.join("rootfs.ext4"), b"disk").expect("stage a disk");
        std::fs::write(
            staging.join(RESTORE_STAGING_MARKER),
            std::process::id().to_string(),
        )
        .expect("write the stager marker");
        let report = sweep_orphans(base.path()).expect("sweep");
        assert!(
            staging.exists(),
            "a dead dir with a live restore staging into it must be spared"
        );
        assert_eq!(report.restore_staging_skipped, 1);
        assert_eq!(report.dirs_reclaimed, 0);
    }

    #[test]
    fn sweep_reclaims_a_dead_drivers_dir_despite_its_own_fresh_boot_disk() {
        // A writable-root boot leaves the driver's own
        // `rootfs.ext4` in its workdir, and a driver that crashes soon after booting must not have
        // its dir mistaken for an in-flight restore stage and left behind.
        let base = ScratchDir::created("bsx-sweep-owndisk");
        let dir = base.path().join(format!("bsx-{}-0", dead_pid()));
        std::fs::create_dir(&dir).expect("create dead driver dir");
        std::fs::write(dir.join("rootfs.ext4"), b"disk").expect("write its boot disk");
        let report = sweep_orphans(base.path()).expect("sweep");
        assert!(!dir.exists(), "the dead driver's dir must be reclaimed");
        assert_eq!(report.dirs_reclaimed, 1);
        assert_eq!(report.restore_staging_skipped, 0);
    }

    #[test]
    fn own_euid_matches_what_our_files_carry() {
        // The candidate filter compares dir ownership against this value, so the two must agree:
        // a dir this process creates (like every real workdir) must pass the filter. (The
        // rejection side, a foreign-uid decoy, needs a second uid, so it can't be unit-tested
        // unprivileged; the filter's equality is the whole mechanism.)
        let dir = ScratchDir::created("bsx-sweep-uid");
        let dir_uid = std::fs::metadata(dir.path()).expect("stat test dir").uid();
        assert_eq!(own_euid(), Some(dir_uid));
    }

    #[test]
    fn the_uid_line_parse_reads_the_effective_field() {
        // **Four distinct values on purpose.** The test above cross-checks this parse against the
        // kernel's own answer, but an ordinary process's four uid fields are all equal, so it cannot
        // tell one index from another. A setuid-shaped `1000 0 0 0` is no better: fields 1 and 2 are
        // both `0`, so it passes on an off-by-one too. Only a line where every field differs can see
        // the index.
        let status = "Name:\tbsx\nUid:\t1000\t1001\t1002\t1003\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(
            euid_in(status),
            Some(1001),
            "field 1 after the label is the effective uid (real 1000, saved 1002, fs 1003)"
        );
        assert_eq!(euid_in("Name:\tbsx\n"), None, "no Uid: line");
        assert_eq!(euid_in("Uid:\t1000\n"), None, "no effective field");
        assert_eq!(euid_in("Uid:\t1000\tnotanumber\n"), None);
    }
}
