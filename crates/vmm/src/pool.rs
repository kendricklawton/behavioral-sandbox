//! The warm [`Pool`]: pre-restored clones of one warm [`Snapshot`], handed out ready to
//! [`exec`](crate::RunningVm::exec), so a run starts in milliseconds instead of a cold boot.
//!
//! **Synchronous by design.** The engine has no async runtime and no background threads on the host
//! path (the console reader is the one exception), and the pool doesn't smuggle one in: restores
//! happen inline, in [`new`](Pool::new) (the prefill), in [`refill`](Pool::refill) (explicit
//! top-up, at the *caller's* chosen moment), and in [`take`](Pool::take) only as the
//! pool-ran-dry fallback. A warm restore is milliseconds, so even the fallback path keeps the
//! "starts in ms" property; what the pool buys over restore-on-demand is the **µs pop** when stock
//! is ready, and a place to put the health/discard policy. A self-refilling, concurrency-managed
//! pool belongs to the daemon (Phase 16), not the library.

use crate::vm::{Snapshot, Vm};
use crate::{BootConfig, RunningVm, VmmError};

/// A pool of pre-restored, exec-ready warm clones of one [`Snapshot`].
///
/// [`take`](Pool::take) health-checks each candidate before handing it out: a clone that died or
/// wedged while pooled (a typed probe failure, most specifically
/// [`VmmError::GuestUnavailable`]) is **discarded and replaced by the next**, never handed to the
/// caller (the retry semantics that variant exists for). An empty pool falls back to an inline
/// restore, so `take` fails only when a *fresh* restore fails too.
///
/// Dropping the pool tears down every pooled clone (each [`RunningVm`]'s own `Drop`);
/// [`shutdown`](Pool::shutdown) is the graceful form. **Networked snapshots:** decision 011 allows
/// only one live networked clone per snapshot on the pinned Firecracker (the tap name is baked in),
/// so a pool over a networked snapshot is limited to `target <= 1`; prefilling deeper fails with the
/// typed taken-name error.
///
/// **Sizing:** each pooled clone holds up to [`FDS_PER_VM`](crate::FDS_PER_VM) driver-side fds, so
/// `target × FDS_PER_VM` must stay under the process's `ulimit -n` with headroom — state the bound,
/// don't discover it via `EMFILE` (P6.9c).
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
    /// If the pool is dry, falls back to restoring a fresh clone inline: milliseconds for a warm
    /// snapshot, and the caller can't tell the difference except by latency.
    ///
    /// Does **not** refill what it hands out: the caller decides when to pay restore time back via
    /// [`refill`](Pool::refill) (e.g. between requests, not on the hot path).
    ///
    /// # Errors
    /// Only what a fresh [`Vm::restore`] can return; pooled-clone health failures are consumed by
    /// the discard-and-retry loop, not surfaced.
    pub fn take(&mut self) -> Result<RunningVm, VmmError> {
        while let Some(vm) = self.ready.pop() {
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
    /// [`RunningVm::vmm_pid`]: cgroup placement in the confinement phase, host-side observers,
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
