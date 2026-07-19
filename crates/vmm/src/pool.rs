//! The prewarmed [`Pool`]: pre-restored clones of one prewarmed [`Snapshot`], handed out ready to
//! [`exec`](crate::RunningVm::exec), so a run starts in milliseconds instead of a cold boot.
//!
//! **Synchronous by design.** The engine has no async runtime and no background threads on the host
//! path (the console reader is the one exception), and the pool doesn't smuggle one in: restores
//! happen inline, in [`new`](Pool::new) (the prefill), in [`refill`](Pool::refill) (explicit
//! top-up, at the *caller's* chosen moment), and in [`take`](Pool::take) only as the
//! pool-ran-dry fallback. A prewarmed restore is milliseconds, so even the fallback path keeps the
//! "starts in ms" property; what the pool buys over restore-on-demand is the **µs pop** when stock
//! is ready, and a place to put the health/discard policy. A self-refilling, concurrency-managed
//! pool belongs to the daemon, not the library.

use crate::vm::{Snapshot, Vm};
use crate::{BootConfig, RunningVm, VmmError, FDS_PER_VM};

/// Fd slack reserved for everything that is *not* a pooled clone: the process baseline (stdio,
/// logging, the embedder's own files) plus the transient fds a boot/exec opens and closes. Part of
/// the sizing rule [`Pool::new`] states: `target × FDS_PER_VM + POOL_FD_HEADROOM ≤ ulimit -n`.
const POOL_FD_HEADROOM: usize = 64;

/// A pool of pre-restored, exec-ready prewarmed clones of one [`Snapshot`].
///
/// [`take`](Pool::take) health-checks each candidate before handing it out: a clone that died or
/// wedged while pooled (a typed probe failure, most specifically
/// [`VmmError::GuestUnavailable`]) is **discarded and replaced by the next**, never handed to the
/// caller (the retry semantics that variant exists for). An empty pool falls back to an inline
/// restore, so `take` fails only when a *fresh* restore fails too.
///
/// Dropping the pool tears down every pooled clone (each [`RunningVm`]'s own `Drop`);
/// [`shutdown`](Pool::shutdown) is the graceful form. **Networked snapshots** pool without a
/// concurrency limit: each clone recreates the baked-in tap in its own network namespace
/// (ADR 017). **Confined pool**: set [`jail`](crate::BootConfig::jail) on `config` and
/// every pooled clone restores under the jailer, chroot, dropped uid, seccomp, its own netns,
/// so prewarmed starts and confinement compose (needs real root, like any jailed boot).
///
/// **Sizing:** each pooled clone holds up to [`FDS_PER_VM`](crate::FDS_PER_VM) driver-side fds, so
/// `target × FDS_PER_VM + POOL_FD_HEADROOM` must stay under the process's soft `ulimit -n`, state
/// the bound, don't discover it via `EMFILE` mid-restore. [`new`](Pool::new) enforces the
/// *stating*: an over-budget target logs one `tracing::warn!` naming the numbers and the fix
/// (raise `ulimit -n`, or shrink the target) before the prefill runs. A warning, not a refusal,
/// like the cgroup caps (ADR 013), sizing is fairness hygiene, not the isolation boundary,
/// and the soft limit may be raised by the embedder after this process was probed.
#[derive(Debug)]
#[must_use = "dropping a Pool kills its pooled microVMs"]
pub struct Pool {
    snapshot: Snapshot,
    config: BootConfig,
    /// How many clones [`new`](Pool::new)/[`refill`](Pool::refill) keep ready.
    target: usize,
    /// Ready clones, taken LIFO: the most recently restored (or checked) clone is the most likely
    /// to still be healthy, and its guest memory the most likely to still be page-cache-hot.
    ready: Vec<RunningVm>,
}

impl Pool {
    /// Restore `target` clones from `snapshot` and keep them ready. `config` is what
    /// [`Vm::restore`] takes (the `firecracker` binary and `boot_timeout`). `target` may be `0`:
    /// every [`take`](Pool::take) then restores on demand, which still makes sense as a single
    /// place to hold the snapshot + config + discard policy.
    ///
    /// # Errors
    /// Any [`Vm::restore`] failure during the prefill; already-restored clones are torn down by
    /// `Pool`'s drop on the error return, so a failed prefill leaks nothing.
    pub fn new(snapshot: Snapshot, config: BootConfig, target: usize) -> Result<Self, VmmError> {
        // State the fd bound up front rather than letting the prefill discover it as an
        // illegible mid-restore `EMFILE` in whatever syscall lands first. Warn-only: sizing is
        // fairness hygiene, not the isolation boundary (the ADR-013 fail-open posture).
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

    /// Hand out a ready, health-checked clone. Pops ready stock (microseconds, plus a fast probe);
    /// a pooled clone that fails its probe is discarded (logged, torn down) and the next is tried.
    /// If the pool is dry, falls back to restoring a fresh clone inline: milliseconds for a prewarmed
    /// snapshot, and the caller can't tell the difference except by latency. A snapshot without the
    /// vsock exec channel has nothing to probe, so its clones are handed out directly (no health
    /// check) rather than discarded on the structural no-vsock condition.
    ///
    /// Does **not** refill what it hands out: the caller decides when to pay restore time back via
    /// [`refill`](Pool::refill) (e.g. between requests, not on the hot path).
    ///
    /// # Errors
    /// Only what a fresh [`Vm::restore`] can return; pooled-clone health failures are consumed by
    /// the discard-and-retry loop, not surfaced.
    pub fn take(&mut self) -> Result<RunningVm, VmmError> {
        while let Some(mut vm) = self.ready.pop() {
            // The probe is a vsock health check. A snapshot without the exec channel has nothing to
            // probe, `probe_agent` would return the *permanent* `require_vsock` error, a structural
            // condition, not a dead-clone signal, so hand the popped clone out directly rather than
            // reading that error as "unhealthy" and tearing down the whole pool on the first take.
            // The one cheap liveness signal left is the VMM process itself: a clone whose VMM died
            // while pooled is discarded like a failed probe, not handed out to fail on first use.
            // `try_wait` (not a `/proc/<pid>` probe): the pooled VMM is nobody's `wait()`, so a dead
            // one is an unreaped zombie that keeps its `/proc` entry, which the old probe read as
            // alive; `try_wait` sees the real exit and reaps it.
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
                    // The typed discard signal (GuestUnavailable for a dead clone's channel; any
                    // probe failure means this clone is useless). Dropping it tears it down.
                    tracing::warn!(
                        vmm_pid = vm.vmm_pid(),
                        error = %e,
                        "discarding unhealthy pooled clone"
                    );
                    drop(vm);
                }
            }
        }
        // Dry (or everything pooled was dead): restore inline rather than failing a take that a
        // fresh clone could serve.
        Vm::restore(&self.snapshot, &self.config)
    }

    /// Top the pool back up to its target, returning how many clones were restored.
    ///
    /// # Errors
    /// The first [`Vm::restore`] failure; clones restored before it stay pooled.
    pub fn refill(&mut self) -> Result<usize, VmmError> {
        let mut restored = 0;
        while self.ready.len() < self.target {
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

    /// The pooled clones' VMM pids, for out-of-band supervision (the same rationale as
    /// [`RunningVm::vmm_pid`]: cgroup placement under confinement, host-side observers,
    /// leak assertions in tests). Valid only while the clones stay pooled.
    #[must_use]
    pub fn vmm_pids(&self) -> Vec<u32> {
        self.ready.iter().map(RunningVm::vmm_pid).collect()
    }

    /// Gracefully shut down every pooled clone (ask each guest to power off, then the guaranteed
    /// teardown). Dropping the pool gives the same no-leak guarantee without the polite ask.
    pub fn shutdown(self) {
        for vm in self.ready {
            let _ = vm.shutdown();
        }
    }
}

/// The sizing rule [`Pool::new`] states, as a pure check: `Some((need, soft))` when `target`
/// pooled clones (at [`FDS_PER_VM`] each, plus [`POOL_FD_HEADROOM`]) would oversubscribe the soft
/// fd limit; `None` when the budget holds. Pure so the arithmetic is unit-testable without a
/// snapshot to pool.
fn fd_budget_excess(target: usize, soft: u64) -> Option<(usize, u64)> {
    let need = target
        .saturating_mul(FDS_PER_VM)
        .saturating_add(POOL_FD_HEADROOM);
    (need as u64 > soft).then_some((need, soft))
}

/// This process's soft `RLIMIT_NOFILE`, read from `/proc/self/limits` (the host path takes no
/// `libc`, and `getrlimit` has no `unsafe`-free std surface). `None` if the file is missing or
/// unparseable, the sizing warning is then simply skipped, never a boot failure.
fn nofile_soft_limit() -> Option<u64> {
    parse_nofile_soft(&std::fs::read_to_string("/proc/self/limits").ok()?)
}

/// The testable core of [`nofile_soft_limit`]: find the "Max open files" row and parse its **soft**
/// column. The row's layout is `Max open files  <soft>  <hard>  files`; a soft limit of
/// `unlimited` parses as `None` (no bound to warn against).
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
    use super::{fd_budget_excess, parse_nofile_soft, POOL_FD_HEADROOM};
    use crate::FDS_PER_VM;

    #[test]
    fn fd_budget_warns_only_past_the_bound() {
        // Comfortably under a dev-box default: no warning.
        assert_eq!(fd_budget_excess(2, 1024), None);
        // A target that oversubscribes a small limit: the warning carries the arithmetic.
        let need = 100 * FDS_PER_VM + POOL_FD_HEADROOM;
        assert_eq!(fd_budget_excess(100, 256), Some((need, 256)));
        // Exactly at the bound is still within budget ("stays under with headroom", the headroom
        // is already inside `need`, so equality holds the line).
        let exact = (10 * FDS_PER_VM + POOL_FD_HEADROOM) as u64;
        assert_eq!(fd_budget_excess(10, exact), None);
        assert!(fd_budget_excess(10, exact - 1).is_some());
    }

    #[test]
    fn nofile_soft_parses_the_proc_limits_shape() {
        // The real /proc/self/limits layout: name column padded with spaces, then soft, hard, unit.
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
        // The /proc read itself: on any Linux dev box the row exists and is numeric or unlimited,
        // either way the call must not panic; a numeric result must be nonzero.
        if let Some(soft) = super::nofile_soft_limit() {
            assert!(soft > 0);
        }
    }
}
