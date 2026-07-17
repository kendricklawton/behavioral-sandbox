//! The attach bundle (P13.1): bind the three host-side probes to one sandbox at launch and roll
//! their output into a [`RunRecord`].
//!
//! `agent-vmm` stays independent of this crate (decisions 024/026), so the bundle takes **plain
//! values** the driver already exposes — the VMM pid (→ its cgroup, for the syscall tracer and the CPU
//! meter) and the netns + tap names (for the network monitor) — never a `Sandbox`. The composition is
//! the caller's (the CLI/daemon later), a short launch sequence around `Sandbox::open`.
//!
//! **Two phases, because the ordering demands it.** The syscall tracer must attach *before* boot: the
//! jailer creates the sandbox's cgroup *during* boot, so its id isn't knowable up front — the tracer
//! watches host-wide, then scopes to the cgroup once it exists and filters the buffered boot window
//! post-hoc (the pattern the Phase-9 demo proves). The tap monitor and the meter, by contrast, need the
//! netns/cgroup to already exist, so they bind *after* boot. Hence [`ArmedProbes::arm`] (pre-boot) →
//! [`ArmedProbes::bind`] (post-boot).
//!
//! **The meter is shared, not per-VM.** One `sched_switch` program meters a *set* of cgroups
//! (decision 026); a fresh [`ResourceMeter`] per sandbox would re-instantiate that global program per
//! VM (O(N) per context switch — the exact thing 026 rejects). So the bundle registers its cgroup as a
//! **target** on a caller-owned [`SharedMeter`] and unregisters on drop. The tracer and tap are
//! legitimately per-VM and owned by the bundle.
//!
//! **Fail-open.** Every axis degrades independently to a recorded [`AxisGap`]; a host missing caps, BTF,
//! or the object still runs the sandbox and produces a (thinner, honestly-annotated) record.

use std::sync::{Arc, Mutex};

use crate::record::{AxisGap, NetSection, RunRecord, SyscallFold, SyscallFootprint, Timing};
use crate::{cgroup_id_of_pid, EgressPolicy, ProbeError, ResourceMeter, SyscallTracer, TapMonitor};

/// A process-shared [`ResourceMeter`]: loaded **once** and handed (cloned) to every sandbox's
/// [`bind`](ArmedProbes::bind), which registers its cgroup as a target. The one CPU-metering program
/// for the whole host (decision 026). Cheap, thread-safe clone.
#[derive(Clone)]
pub struct SharedMeter(Arc<Mutex<ResourceMeter>>);

impl SharedMeter {
    /// Load and attach the shared `sched_switch` meter (needs `CAP_BPF`+`CAP_PERFMON` + the object).
    ///
    /// # Errors
    /// [`ProbeError`] if the meter can't be loaded/attached.
    pub fn load() -> Result<Self, ProbeError> {
        Ok(Self(Arc::new(Mutex::new(ResourceMeter::load()?))))
    }

    /// Run `f` against the meter, or `None` if the lock is poisoned (a fail-open loss of the CPU axis,
    /// never a panic on the host path).
    fn with<R>(&self, f: impl FnOnce(&mut ResourceMeter) -> R) -> Option<R> {
        self.0.lock().ok().map(|mut m| f(&mut m))
    }
}

/// Pre-boot half: the syscall tracer attached host-wide with a cleared baseline, waiting for a cgroup
/// to scope to. Create it *before* `Sandbox::open`, then [`bind`](Self::bind) it after.
#[must_use = "arm() only loads the tracer; call bind() after boot to attach the rest"]
pub struct ArmedProbes {
    tracer: Option<SyscallTracer>,
    /// Why the tracer is absent (host can't load it), carried into the record's coverage.
    gap: Option<AxisGap>,
}

impl ArmedProbes {
    /// P13.1, pre-boot. Load the syscall tracer host-wide and drain its baseline. **Fail-open**: a host
    /// without caps/BTF/object yields an `ArmedProbes` with no tracer and a recorded reason, so a run is
    /// never blocked by missing observability.
    pub fn arm() -> Self {
        match Self::load_tracer() {
            Ok(tracer) => Self {
                tracer: Some(tracer),
                gap: None,
            },
            Err(e) => Self {
                tracer: None,
                gap: Some(AxisGap::HostSyscalls(e.to_string())),
            },
        }
    }

    /// The strict form for callers (tests, the future `--trace`) that want a hard error if the tracer
    /// can't load rather than a silent gap.
    ///
    /// # Errors
    /// [`ProbeError`] if the tracer can't be loaded/attached.
    pub fn arm_strict() -> Result<Self, ProbeError> {
        Ok(Self {
            tracer: Some(Self::load_tracer()?),
            gap: None,
        })
    }

    /// Load the tracer, watch host-wide, and drain the pre-existing baseline so only events from here on
    /// count.
    fn load_tracer() -> Result<SyscallTracer, ProbeError> {
        let mut tracer = SyscallTracer::load()?;
        tracer.watch_all()?;
        let _ = tracer.drain(|_| {}); // clear the baseline; a drain error just leaves it uncleared
        Ok(tracer)
    }

    /// P13.1, post-boot. Bind every available probe to this one VM by plain values:
    /// - resolve the VMM's cgroup id, scope the tracer to it (dropping the tracer if it can't be
    ///   attributed), and fold the buffered boot window in;
    /// - if `netns` + `tap` are present, attach a per-VM tap monitor — enforcing `egress` (armed before
    ///   the tc programs go live) when given, else observe-only;
    /// - register the cgroup as a target on the shared `meter`.
    ///
    /// Each sub-attach degrades to a recorded [`AxisGap`]; the returned bundle is always valid.
    pub fn bind(
        self,
        vmm_pid: u32,
        netns: Option<&str>,
        tap: Option<&str>,
        egress: Option<&EgressPolicy>,
        meter: SharedMeter,
    ) -> SandboxProbes {
        let mut gaps: Vec<AxisGap> = Vec::new();
        if let Some(g) = self.gap {
            gaps.push(g);
        }

        // The cgroup id is the tracer + meter axis; resolve it from the pid (the plain-value bridge).
        let cgroup_id = match cgroup_id_of_pid(vmm_pid) {
            Ok(id) => Some(id),
            Err(e) => {
                gaps.push(AxisGap::Cpu(format!("resolve cgroup: {e}")));
                None
            }
        };

        // Scope the tracer to the cgroup and start a fold over the buffered boot window. Without a
        // known cgroup the events can't be attributed, so the tracer is dropped rather than kept host-wide.
        let (tracer, fold) = match (self.tracer, cgroup_id) {
            (Some(mut tracer), Some(cgid)) => match tracer.watch_cgroup(cgid) {
                Ok(()) => {
                    let mut fold = SyscallFold::new(cgid);
                    let _ = tracer.drain(|ev| fold.record(&ev));
                    (Some(tracer), Some(fold))
                }
                Err(e) => {
                    gaps.push(AxisGap::HostSyscalls(format!("scope tracer: {e}")));
                    (None, None)
                }
            },
            (Some(_), None) => {
                gaps.push(AxisGap::HostSyscalls(
                    "cgroup id unknown, cannot attribute host syscalls".to_string(),
                ));
                (None, None)
            }
            (None, _) => (None, None),
        };

        // Attach the per-VM tap monitor. Absent netns/tap = no NIC: the network section is simply
        // absent (not a gap); an attach failure is a gap.
        let tap_mon = match (netns, tap) {
            (Some(ns), Some(iface)) => {
                let attached = match egress {
                    Some(policy) => TapMonitor::enforce_in_netns(ns, iface, policy),
                    None => TapMonitor::attach_in_netns(ns, iface),
                };
                match attached {
                    Ok(m) => Some(m),
                    Err(e) => {
                        gaps.push(AxisGap::Network(format!("attach tap: {e}")));
                        None
                    }
                }
            }
            _ => None,
        };

        // Register the cgroup as a target on the shared meter (the CPU axis).
        let metered = match cgroup_id {
            Some(cgid) => match meter.with(|m| m.add_target(cgid)) {
                Some(Ok(())) => true,
                Some(Err(e)) => {
                    gaps.push(AxisGap::Cpu(format!("meter add_target: {e}")));
                    false
                }
                None => {
                    gaps.push(AxisGap::Cpu("meter lock poisoned".to_string()));
                    false
                }
            },
            None => false,
        };

        SandboxProbes {
            vmm_pid,
            cgroup_id,
            tracer,
            fold,
            tap: tap_mon,
            meter,
            metered,
            gaps,
        }
    }
}

/// Post-boot, live bundle for one VM: the per-VM tracer + tap, a target ticket on the shared meter, and
/// the coverage gaps seen so far. [`collect`](Self::collect) reads the probes into a [`RunRecord`]; drop
/// detaches (RAII) and unregisters the meter target.
#[must_use = "dropping SandboxProbes detaches this run's probes; call collect() first"]
pub struct SandboxProbes {
    vmm_pid: u32,
    cgroup_id: Option<u64>,
    tracer: Option<SyscallTracer>,
    fold: Option<SyscallFold>,
    tap: Option<TapMonitor>,
    meter: SharedMeter,
    metered: bool,
    gaps: Vec<AxisGap>,
}

impl SandboxProbes {
    /// P13.2. Read the three probes and roll up into a [`RunRecord`]. **Must run while the sandbox is
    /// still alive** — the cgroup dir and map fds must be live. `timing` comes from the caller
    /// (`Sandbox::boot_latency` + `RunResult::metrics.wall`), so the record never depends on `agent-vmm`.
    /// Each axis degrades to a recorded gap on a read error.
    pub fn collect(mut self, timing: Timing) -> RunRecord {
        // Host syscalls: drain the remaining window into the fold, then finalize.
        let host_syscalls = match (self.tracer.take(), self.fold.take()) {
            (Some(mut tracer), Some(mut fold)) => {
                let _ = tracer.drain(|ev| fold.record(&ev));
                fold.finish()
            }
            _ => SyscallFootprint::default(),
        };

        // Network + denials from the one per-VM tap monitor.
        let network = match self.tap.as_ref() {
            Some(monitor) => match (monitor.flows(), monitor.totals(), monitor.denials()) {
                (Ok(flows), Ok(totals), Ok(denials)) => {
                    Some(NetSection::from_tap(flows, totals, denials))
                }
                _ => {
                    self.gaps
                        .push(AxisGap::Network("reading tap maps failed".to_string()));
                    None
                }
            },
            None => None,
        };

        // Resources: the shared meter rolls CPU + the cgroup's native memory/IO from the pid. Best-effort
        // — a lost lock or a metering gap yields zero CPU with memory/IO still read where available.
        let resources = self
            .meter
            .with(|m| m.summary_for_pid(self.vmm_pid).ok())
            .flatten()
            .unwrap_or_default();

        RunRecord::from_parts(
            network,
            resources,
            host_syscalls,
            timing,
            std::mem::take(&mut self.gaps),
        )
    }

    /// The gaps recorded so far (which axes are unavailable and why) — useful to a caller before
    /// `collect`, e.g. to warn.
    #[must_use]
    pub fn coverage(&self) -> &[AxisGap] {
        &self.gaps
    }
}

impl Drop for SandboxProbes {
    /// Unregister this run's cgroup from the shared meter so the metered set doesn't accumulate dead
    /// cgroups. The per-VM tracer/tap detach via their own aya `Ebpf` drops (nothing pinned, decision
    /// 020); the tap's in-kernel filter is reclaimed by the sandbox's netns teardown.
    fn drop(&mut self) {
        if self.metered {
            if let Some(cgid) = self.cgroup_id {
                let _ = self.meter.with(|m| m.remove_target(cgid));
            }
        }
    }
}
