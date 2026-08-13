//! The prewarmed [`Pool`]: pre-restored clones of one prewarmed [`Snapshot`], handed out ready to
//! [`exec`](crate::RunningVm::exec), so a run starts in milliseconds instead of a cold boot.
//!
//! **Synchronous by design.** The engine has no async runtime and no background threads on the host
//! path (the console reader is the one exception), and the pool smuggles none in: restores run
//! inline, in [`new`](Pool::new), in [`refill`](Pool::refill) at the *caller's* chosen moment, and
//! in [`take`](Pool::take) only as the pool-ran-dry fallback. A self-refilling,
//! concurrency-managed pool belongs to the daemon, not the library.

use crate::vm::{Snapshot, Vm};
use crate::{BootConfig, FDS_PER_VM, RunningVm, VmmError};

/// Fd slack reserved for everything that is *not* a pooled clone: the process baseline plus the
/// transient fds a boot/exec opens. Part of `target × FDS_PER_VM + POOL_FD_HEADROOM ≤ ulimit -n`.
const POOL_FD_HEADROOM: usize = 64;

/// A pool of pre-restored, exec-ready prewarmed clones of one [`Snapshot`].
///
/// [`take`](Pool::take) health-checks each candidate before handing it out: a clone that died or
/// wedged while pooled (a typed probe failure, most specifically [`VmmError::GuestUnavailable`]) is
/// **discarded and replaced by the next**, never handed to the caller. An empty pool falls back to
/// an inline restore, so `take` fails only when a *fresh* restore fails too. Dropping the pool
/// tears down every clone; [`shutdown`](Pool::shutdown) is the graceful form. Networked snapshots
/// pool without a concurrency limit, since each clone recreates the baked-in tap in its own netns.
///
/// **Sizing:** each pooled clone holds up to [`FDS_PER_VM`](crate::FDS_PER_VM) driver-side fds, so
/// `target × FDS_PER_VM + POOL_FD_HEADROOM` must stay under the process's soft `ulimit -n`.
/// [`new`](Pool::new) warns rather than refuses when a target is over budget: sizing is fairness
/// hygiene, not the isolation boundary, and the soft limit may be raised after this process was
/// probed.
#[derive(Debug)]
#[must_use = "dropping a Pool kills its pooled microVMs"]
pub struct Pool {
    snapshot: Snapshot,
    config: BootConfig,
    /// How many clones [`new`](Pool::new)/[`refill`](Pool::refill) keep ready.
    target: usize,
    /// Ready clones, taken LIFO: the most recently restored clone is the likeliest to still be
    /// healthy, and its guest memory the likeliest to still be page-cache-hot.
    ready: Vec<RunningVm>,
}

impl Pool {
    /// Restore `target` clones from `snapshot` and keep them ready. `config` is what
    /// [`Vm::restore`] takes (the `firecracker` binary and `boot_timeout`). `target` may be `0`,
    /// which makes every [`take`](Pool::take) restore on demand.
    ///
    /// # Errors
    /// Any [`Vm::restore`] failure during the prefill; already-restored clones are torn down by
    /// `Pool`'s drop on the error return, so a failed prefill leaks nothing.
    pub fn new(snapshot: Snapshot, config: BootConfig, target: usize) -> Result<Self, VmmError> {
        // Stated up front rather than discovered as an illegible mid-restore `EMFILE` in whatever
        // syscall lands first.
        if let Some((need, soft)) = nofile_soft_limit().and_then(|s| fd_budget_excess(target, s)) {
            tracing::warn!(
                target,
                fds_per_vm = FDS_PER_VM,
                headroom = POOL_FD_HEADROOM,
                need,
                nofile_soft = soft,
                "pool target exceeds the fd budget: raise `ulimit -n` or shrink the target, \
                 or restores may fail with EMFILE"
            );
        }
        let mut pool = Self {
            snapshot,
            config,
            target,
            ready: Vec::with_capacity(target),
        };
        pool.refill()?;
        Ok(pool)
    }

    /// Hand out a ready, health-checked clone: pops ready stock, discards and tears down any clone
    /// that fails its probe, and falls back to an inline restore when the pool is dry. A snapshot
    /// without the vsock exec channel has nothing to probe, so its clones are handed out directly
    /// rather than discarded on that structural condition. Does **not** refill what it hands out;
    /// the caller pays restore time back through [`refill`](Pool::refill), off the hot path.
    ///
    /// # Errors
    /// Only what a fresh [`Vm::restore`] can return; pooled-clone health failures are consumed by
    /// the discard-and-retry loop, not surfaced.
    pub fn take(&mut self) -> Result<RunningVm, VmmError> {
        while let Some(mut vm) = self.ready.pop() {
            // Without the exec channel `probe_agent` returns the *permanent* `require_vsock` error,
            // which read as "unhealthy" would tear down the whole pool on the first take. The
            // liveness signal left is the VMM process, checked with `try_wait` rather than a
            // `/proc/<pid>` probe: a pooled VMM is nobody's `wait()`, so a dead one is an unreaped
            // zombie whose `/proc` entry still reads as alive.
            if !self.snapshot.has_vsock {
                let pid = vm.vmm_pid();
                if vm.vmm_alive() {
                    return Ok(vm);
                }
                tracing::warn!(
                    vmm_pid = pid,
                    "discarding pooled clone whose VMM process died"
                );
                drop(vm);
                continue;
            }
            match vm.probe_agent() {
                Ok(()) => return Ok(vm),
                Err(e) => {
                    tracing::warn!(
                        vmm_pid = vm.vmm_pid(),
                        error = %e,
                        "discarding unhealthy pooled clone"
                    );
                    drop(vm);
                }
            }
        }
        // Dry, or everything pooled was dead: a fresh clone can still serve this take.
        Vm::restore(&self.snapshot, &self.config)
    }

    /// Top the pool back up to its target, returning how many clones were restored.
    ///
    /// # Errors
    /// The first [`Vm::restore`] failure; clones restored before it stay pooled.
    pub fn refill(&mut self) -> Result<usize, VmmError> {
        self.refill_up_to(usize::MAX)
    }

    /// Like [`refill`](Self::refill), but restore at most `max_new` clones this call, for a caller
    /// accounting pool memory against a host-wide ceiling: the pool stays below target rather than
    /// overshooting that budget, and a later call tops up the rest.
    ///
    /// # Errors
    /// The first [`Vm::restore`] failure; clones restored before it stay pooled.
    pub fn refill_up_to(&mut self, max_new: usize) -> Result<usize, VmmError> {
        let mut restored = 0;
        while self.ready.len() < self.target && restored < max_new {
            self.ready.push(Vm::restore(&self.snapshot, &self.config)?);
            restored += 1;
        }
        Ok(restored)
    }

    /// How many clones are currently pooled (ready stock, before health checks).
    #[must_use]
    pub fn ready(&self) -> usize {
        self.ready.len()
    }

    /// The pooled clones' VMM pids, for out-of-band supervision (see [`RunningVm::vmm_pid`]).
    /// Valid only while the clones stay pooled.
    #[must_use]
    pub fn vmm_pids(&self) -> Vec<u32> {
        self.ready.iter().map(RunningVm::vmm_pid).collect()
    }

    /// Gracefully shut down every pooled clone. Asks **every** guest to power off first, then polls
    /// them all against **one** shared grace window, so a pool of N clones that ignore
    /// `SendCtrlAltDel` pays one `POWER_OFF_TIMEOUT` rather than N. A guest still alive at the
    /// deadline is hard-killed by its `Drop` when `self.ready` drops below.
    pub fn shutdown(mut self) {
        use std::time::Instant;
        for vm in &mut self.ready {
            vm.request_power_off();
        }
        let deadline = Instant::now() + crate::vm::POWER_OFF_TIMEOUT;
        // One clock for the whole set: `vmm_alive` reaps a clone the instant it exits, so only the
        // stubborn ones ride to the deadline.
        while Instant::now() < deadline && self.ready.iter_mut().any(RunningVm::vmm_alive) {
            std::thread::sleep(crate::vm::POWER_OFF_POLL);
        }
        // `self.ready` drops here: each `RunningVm::Drop` kills and reaps whatever is still alive.
    }
}

/// The sizing rule [`Pool::new`] states, as a pure check: `Some((need, soft))` when `target` pooled
/// clones (at [`FDS_PER_VM`] each, plus [`POOL_FD_HEADROOM`]) would oversubscribe the soft fd
/// limit. Pure so the arithmetic is unit-testable without a snapshot to pool.
fn fd_budget_excess(target: usize, soft: u64) -> Option<(usize, u64)> {
    let need = target
        .saturating_mul(FDS_PER_VM)
        .saturating_add(POOL_FD_HEADROOM);
    (need as u64 > soft).then_some((need, soft))
}

/// This process's soft `RLIMIT_NOFILE`, read from `/proc/self/limits` because the host path takes
/// no `libc` and `getrlimit` has no `unsafe`-free std surface. `None` if the file is missing or
/// unparseable, which skips the sizing warning rather than failing a boot.
fn nofile_soft_limit() -> Option<u64> {
    parse_nofile_soft(&std::fs::read_to_string("/proc/self/limits").ok()?)
}

/// The testable core of [`nofile_soft_limit`]: finds the `Max open files  <soft>  <hard>  files`
/// row and parses its **soft** column. A soft limit of `unlimited` is `None`, no bound to warn on.
fn parse_nofile_soft(limits: &str) -> Option<u64> {
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    line.trim_start_matches("Max open files")
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{POOL_FD_HEADROOM, fd_budget_excess, parse_nofile_soft};
    use crate::FDS_PER_VM;

    #[test]
    fn fd_budget_warns_only_past_the_bound() {
        // Comfortably under a dev-box default: no warning.
        assert_eq!(fd_budget_excess(2, 1024), None);
        // A target that oversubscribes a small limit: the warning carries the arithmetic.
        let need = 100 * FDS_PER_VM + POOL_FD_HEADROOM;
        assert_eq!(fd_budget_excess(100, 256), Some((need, 256)));
        // Equality holds the line, since the headroom is already inside `need`.
        let exact = (10 * FDS_PER_VM + POOL_FD_HEADROOM) as u64;
        assert_eq!(fd_budget_excess(10, exact), None);
        assert!(fd_budget_excess(10, exact - 1).is_some());
    }

    #[test]
    fn nofile_soft_parses_the_proc_limits_shape() {
        // The real layout: name column padded with spaces, then soft, hard, unit.
        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max cpu time              unlimited            unlimited            seconds\n\
                      Max open files            1024                 524288               files\n\
                      Max locked memory         8388608              8388608              bytes\n";
        assert_eq!(parse_nofile_soft(limits), Some(1024));
    }

    #[test]
    fn nofile_soft_is_none_for_unlimited_or_absent() {
        // `unlimited` is not a number → no bound to warn against; a missing row likewise.
        let unlimited =
            "Max open files            unlimited            unlimited            files\n";
        assert_eq!(parse_nofile_soft(unlimited), None);
        assert_eq!(parse_nofile_soft("Max cpu time  1  2  seconds\n"), None);
        assert_eq!(parse_nofile_soft(""), None);
    }

    #[test]
    fn this_process_reports_a_soft_limit() {
        // The row is numeric or unlimited on any Linux box; either way the call must not panic.
        if let Some(soft) = super::nofile_soft_limit() {
            assert!(soft > 0);
        }
    }
}
