//! The CLI's audit face: compose the two tracks the way the engine intends — boot the sandbox
//! (`agent-vmm`), then bind the host-side probes to it by the **plain values** `Sandbox` exposes
//! (`vmm_pid`/`netns`/`tap_name`) and fuse their output into the per-run [`RunRecord`].
//!
//! This is the caller-side launch sequence the loader's decision log promises (decisions 024/028):
//! the driver and the eBPF loader stay independent crates; the CLI is where they meet.
//!
//! **Fail-open, like the loader.** A host that can't load the shared probes (no `CAP_BPF`/
//! `CAP_PERFMON`, no BTF, the object not built) still runs the sandbox; the record it yields is
//! thinner and says exactly why in its coverage section. `--trace` on an unprivileged dev box is a
//! working command with an honest, mostly-gap record — never a refused run.

use agent_probes_loader::{
    AxisGap, LiveSnapshot, ResourceSummary, RunRecord, SandboxProbes, SharedMeter, SharedTracer,
    SyscallFootprint, Timing,
};

/// The host-wide shared probes, loaded **once** per process (one `sched_switch` meter, one set of
/// `sys_enter_*` tracepoints — the bounded-overhead shared model) and handed to every run's
/// [`attach`](Observability::attach). Each probe that fails to load is a recorded [`AxisGap`], not
/// an error: observability degrades, the run never blocks.
pub struct Observability {
    tracer: Option<SharedTracer>,
    meter: Option<SharedMeter>,
    /// Why a shared probe is absent — folded into any record produced without an attached bundle.
    load_gaps: Vec<AxisGap>,
}

impl Observability {
    /// Load the shared tracer + meter, degrading each failure to a recorded gap.
    pub fn load() -> Self {
        let mut load_gaps = Vec::new();
        let tracer = match SharedTracer::load() {
            Ok(t) => Some(t),
            Err(e) => {
                load_gaps.push(AxisGap::HostSyscalls(format!("load shared tracer: {e}")));
                None
            }
        };
        let meter = match SharedMeter::load() {
            Ok(m) => Some(m),
            Err(e) => {
                load_gaps.push(AxisGap::Cpu(format!("load shared meter: {e}")));
                None
            }
        };
        Self {
            tracer,
            meter,
            load_gaps,
        }
    }

    /// Bind the probes to one booted sandbox (post-boot, by plain values). With both shared probes
    /// live this is [`SandboxProbes::attach`] — observe-only (no egress policy; the `--allow`
    /// projection lands with the wider CLI surface, decision 029). Without them nothing attaches
    /// (the bundle needs both), and the returned handle will produce a record whose coverage
    /// explains every unbound axis.
    pub fn attach(&self, vmm_pid: u32, netns: Option<&str>, tap: Option<&str>) -> RunProbes {
        match (&self.tracer, &self.meter) {
            (Some(tracer), Some(meter)) => RunProbes {
                probes: Some(SandboxProbes::attach(
                    vmm_pid, netns, tap, None, tracer, meter,
                )),
                gaps: Vec::new(),
            },
            _ => {
                let mut gaps = self.load_gaps.clone();
                // Name every axis that never bound, not just the probe that failed to load: a
                // half-loaded pair still attaches nothing, and the record must explain all of it.
                if self.tracer.is_some() {
                    gaps.push(AxisGap::HostSyscalls(
                        "shared probes incomplete; tracer not attached".to_string(),
                    ));
                }
                if self.meter.is_some() {
                    gaps.push(AxisGap::Cpu(
                        "shared probes incomplete; meter not attached".to_string(),
                    ));
                }
                if netns.is_some() && tap.is_some() {
                    gaps.push(AxisGap::Network(
                        "shared probes unavailable; tap monitor not attached".to_string(),
                    ));
                }
                RunProbes { probes: None, gaps }
            }
        }
    }
}

/// One run's live probe handle: the attached [`SandboxProbes`] bundle, or — fail-open — nothing but
/// the gaps that explain why. Either way [`collect`](Self::collect) yields a [`RunRecord`].
pub struct RunProbes {
    probes: Option<SandboxProbes>,
    /// The coverage carried into the record when no bundle attached (empty otherwise — an attached
    /// bundle records its own gaps).
    gaps: Vec<AxisGap>,
}

impl RunProbes {
    /// A live, non-destructive reading for the watch view; empty axes when nothing attached.
    pub fn snapshot(&self) -> LiveSnapshot {
        self.probes
            .as_ref()
            .map(SandboxProbes::snapshot)
            .unwrap_or_default()
    }

    /// Finalize the run's record — **while the sandbox is still alive** (the attached bundle reads
    /// the live cgroup + maps). Without a bundle, the record is the honest empty one: no axes, every
    /// absence explained in coverage.
    pub fn collect(self, timing: Timing) -> RunRecord {
        match self.probes {
            Some(probes) => probes.collect(timing),
            None => RunRecord::from_parts(
                None,
                ResourceSummary::default(),
                SyscallFootprint::default(),
                timing,
                self.gaps,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unattached_probes_collect_an_honest_empty_record() {
        // The fail-open path a capability-less host takes: no bundle, gaps carried through.
        let probes = RunProbes {
            probes: None,
            gaps: vec![
                AxisGap::HostSyscalls("load shared tracer: no BTF".into()),
                AxisGap::Cpu("load shared meter: no BTF".into()),
            ],
        };
        assert!(probes.snapshot().network.is_none());
        let timing = Timing {
            boot: Duration::from_millis(100),
            exec_wall: Duration::from_millis(5),
        };
        let record = probes.collect(timing);
        assert!(record.network.is_none());
        assert_eq!(record.host_syscalls.total, 0);
        assert_eq!(record.coverage.len(), 2, "every absence is explained");
        assert_eq!(record.timing, timing, "timing rides through regardless");
    }
}
