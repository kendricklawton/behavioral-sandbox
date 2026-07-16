//! The orphan sweep — the engine's garbage collector for crashed-driver residue.
//!
//! Teardown is `Drop`-based and the lifetime sentinel (decision 014) owns the VM *process tree*,
//! but a driver that dies without `Drop` (SIGKILL, OOM) still leaves filesystem and network
//! residue: its per-VM scratch dirs and its per-VM **network namespaces** (each holding the VM's
//! tap). The netns model retired the finite-`/30`-pool exhaustion an earlier tap-in-the-host-netns
//! design risked — every netns reuses the same fixed `/30`, so there is no shared pool to clog — but
//! an orphaned netns is still residue (a namespace, a tap, a `/run/netns/<name>` handle) worth
//! reclaiming. [`sweep_orphans`] reclaims both dir and netns, the garbage collection a long-running
//! runtime owes its host for the residue a crashed sibling leaves behind.
//!
//! **Ownership is keyed on the pid embedded in the scratch-dir name** (`agent-<pid>-<n>`). The netns
//! is named after the dir it belongs to, so no separate record is needed and no cross-ownership
//! confusion arises (a restored clone's netns is named after *its own* dir, not the snapshot source's).
//!
//! Conservative by construction:
//! - Only dirs **owned by the sweeping euid** are candidates. The scratch base (`/tmp` by
//!   default) is world-writable, so a hostile local user could plant a dead-looking
//!   `agent-<pid>-<n>` dir naming a *victim's* live netns; `create_workdir` makes real per-VM dirs
//!   `0700`, driver-owned, so ownership is the authorship proof. The flip side is deliberate: each
//!   uid sweeps its own residue (root sweeps root's jailed dirs, a user sweeps their user-driver
//!   dirs), never another's.
//! - A dir whose embedded pid is **alive** is skipped: a live driver, or a recycled pid we can't
//!   tell from one (the orphan is reclaimed by a later sweep, once the pid frees). The error
//!   direction is always "kept too long", never "reclaimed a live VM's resources".
//! - A dead dir with a **still-running VMM** (only possible where the sentinel degraded: no
//!   writable cgroup v2) is skipped with a warning. The sweep owns fs/net residue; processes are
//!   the sentinel's (decision 014) — it never kills.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::jail::unmount_base;
use crate::net::{netns_del, netns_exists};
use crate::VmmError;

/// What a [`sweep_orphans`] pass reclaimed and what it deliberately left alone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepReport {
    /// Dead drivers' scratch dirs removed.
    pub dirs_reclaimed: usize,
    /// Orphaned per-VM network namespaces deleted (each cascading its tap away).
    pub netns_reclaimed: usize,
    /// Scratch dirs skipped because their owner pid is alive (a live driver, or a recycled pid —
    /// indistinguishable, so both are kept).
    pub live_skipped: usize,
}

/// Reclaim the residue of **dead** drivers under `scratch_dir` (the [`BootConfig::scratch_dir`]
/// base, `/tmp` by default): their per-VM scratch dirs, and the per-VM network namespaces named after
/// them (each holding an orphaned tap). Never touches a live driver's resources; see the module doc
/// for the ownership rules.
///
/// Safe to run at any time — embedder startup is the natural moment (the analogue of a container
/// runtime's boot-time GC) — and concurrently with live drivers: liveness is checked per dir, and
/// everything a live pid owns is skipped. Per-entry failures are logged and skipped, never fatal,
/// so one undeletable dir can't shadow the rest of the sweep.
///
/// **The hoster's half (decision 016).** The engine guarantees this call can't be weaponized (it
/// only ever reclaims dirs the calling euid owns), but *deploying* it is the caller's:
/// - **Schedule it.** Nothing calls this for you — a self-refilling janitor daemon is platform
///   territory (Phase 16). Run it at startup and periodically.
/// - **One per identity.** It reclaims only what the calling euid owns, so if drivers run as
///   several users, each must run its own sweep; one root sweep does **not** cover a user driver's
///   residue (nor should it — that would be the weaponization the ownership check prevents).
/// - **Harden the base.** Prefer a scratch base only the engine user can write (via
///   [`BootConfig::scratch_dir`]) over the world-writable `/tmp` default, so no other local user
///   can even plant a decoy for the ownership check to reject.
///
/// [`BootConfig::scratch_dir`]: crate::BootConfig::scratch_dir
///
/// # Errors
/// [`VmmError::Vmm`] only if `scratch_dir` itself can't be read.
pub fn sweep_orphans(scratch_dir: &Path) -> Result<SweepReport, VmmError> {
    let entries = std::fs::read_dir(scratch_dir)
        .map_err(|e| VmmError::Vmm(format!("read scratch base {}: {e}", scratch_dir.display())))?;
    // Refusing to sweep at all beats sweeping without the ownership proof (see the module doc):
    // on a world-writable base, an unowned candidate set is an attacker-writable kill list.
    let Some(me) = own_euid() else {
        return Err(VmmError::Vmm(
            "cannot read own euid from /proc/self/status; refusing to sweep without it".into(),
        ));
    };

    // Partition the per-VM dirs by owner liveness. The netns a dir owns is named after the dir, so no
    // separate record or live-name bookkeeping is needed: a dead dir's netns is unambiguously its own.
    let mut report = SweepReport::default();
    let mut dead: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(pid) = owner_pid(&name) else {
            continue; // Not a per-VM scratch dir; never touched.
        };
        // Not ours: another uid's residue (their sweep's job), or a planted decoy on the
        // world-writable base (see the module doc). Either way, not a candidate.
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
        // The netns is named after the scratch dir; a networked VM whose driver died leaves it behind
        // (holding the tap). Delete it (cascading the tap away). No ownership ambiguity: the dir is
        // ours (checked above) and the netns carries its name.
        if let Some(netns) = dir.file_name().and_then(|n| n.to_str()) {
            if netns_exists(netns) {
                netns_del(netns);
                if netns_exists(netns) {
                    tracing::warn!(%netns, "sweep: failed to delete orphaned netns");
                } else {
                    report.netns_reclaimed += 1;
                    tracing::info!(%netns, "sweep: reclaimed orphaned network namespace");
                }
            }
        }
        // A crashed driver's jailed read-only boot leaves the shared base **bind-mounted** into its
        // chroot; `remove_dir_all` would `EBUSY` on that mount point and leak the whole dir. Detach any
        // mount under this dir first (lazy, best-effort), so reclamation is never blocked by a mount
        // its owning driver died before unmounting.
        detach_mounts_under(&dir);
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

/// Detach (lazy, best-effort) every mount whose mount point lies under `dir`, deepest first, so a
/// following `remove_dir_all` can't `EBUSY` on a mount a crashed driver left behind — today that is
/// the read-only base a jailed overlay boot bind-mounts into its chroot. Reads `/proc/self/mountinfo`
/// (mount point is its 5th space-separated field); paths a self-hosted scratch dir carries have no
/// spaces, so the octal-escape edge (`\040`) is not decoded. A no-op when `dir` holds no mounts.
fn detach_mounts_under(dir: &Path) {
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return;
    };
    let mut points: Vec<PathBuf> = info
        .lines()
        .filter_map(|line| {
            let mp = Path::new(line.split(' ').nth(4)?);
            mp.starts_with(dir).then(|| mp.to_path_buf())
        })
        .collect();
    // Deepest first: a child mount must be detached before its parent mount point.
    points.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for mp in points {
        unmount_base(&mp);
    }
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

/// This process's **effective** uid, from `/proc/self/status` (`Uid:` is real/effective/saved/fs;
/// effective is the second field) — no `unsafe`, no libc, the same read the test helpers use.
/// The euid is what names the files this process creates, so it's the identity `create_workdir`'s
/// dirs carry and the one the candidate filter must match.
fn own_euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let uid = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    uid.split_whitespace().nth(1)?.parse().ok()
}

/// The pid of a `firecracker`/`jailer` process whose cwd is inside `dir`, if one is running. An
/// unjailed VMM's cwd *is* its scratch dir (`spawn_fc` sets it for the relative vsock path); a
/// jailed VMM's cwd is its chroot root, `<dir>/<exec-name>/<id>/root`. Identity is compared by
/// `(st_dev, st_ino)` through the `/proc/<pid>/cwd` magic link — the link *text* is
/// namespace-relative after a pivot_root (the P6.6 finding), but `metadata` resolves through it.
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
    fn sweep_errors_only_on_an_unreadable_base() {
        let err = sweep_orphans(Path::new("/nonexistent-sweep-base"))
            .expect_err("missing base is a typed error");
        assert!(matches!(err, VmmError::Vmm(_)));
    }

    #[test]
    fn own_euid_matches_what_our_files_carry() {
        // The candidate filter compares dir ownership against this value, so the two must agree:
        // a dir this process creates (like every real workdir) must pass the filter. (The
        // rejection side — a foreign-uid decoy — needs a second uid, so it can't be unit-tested
        // unprivileged; the filter's equality is the whole mechanism.)
        let dir = TestDir::new("agent-sweep-uid");
        let dir_uid = std::fs::metadata(dir.path()).expect("stat test dir").uid();
        assert_eq!(own_euid(), Some(dir_uid));
    }
}
