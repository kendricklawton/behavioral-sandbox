//! The CLI's audit face: compose the two tracks the way the engine intends, boot the sandbox
//! (`agent-vmm`), then bind the host-side probes to it by the **plain values** `Sandbox` exposes
//! (`vmm_pid`/`netns`/`tap_name`) and fuse their output into the per-run [`RunRecord`].
//!
//! This is the caller-side launch sequence the loader's decision log promises (decisions 024/028):
//! the driver and the eBPF loader stay independent crates; the CLI is where they meet.
//!
//! **Observation fails open; enforcement does not.** A host that can't load the shared probes (no
//! `CAP_BPF`/`CAP_PERFMON`, no BTF, the object not built) still runs the sandbox; the record it
//! yields is thinner and says exactly why in its coverage section. `--trace` on an unprivileged dev
//! box is a working command with an honest, mostly-gap record, never a refused run. An egress
//! *policy* (`--allow`) is the exception: it is a security control, so a run that asked to enforce
//! one and couldn't arm the tap is a typed refusal, never a silent unenforced run.

use agent_probes_loader::{
    AxisGap, EgressPolicy, LiveSnapshot, ResourceSummary, RunRecord, SandboxProbes, SharedMeter,
    SharedTracer, SyscallFootprint, Timing,
};
use agent_vmm::VmmError;

/// The host-wide shared probes, loaded **once** per process (one `sched_switch` meter, one set of
/// `sys_enter_*` tracepoints, the bounded-overhead shared model) and handed to every run's
/// [`attach`](Observability::attach). Each probe that fails to load is a recorded [`AxisGap`], not
/// an error: observability degrades, the run never blocks.
pub struct Observability {
    tracer: Option<SharedTracer>,
    meter: Option<SharedMeter>,
    /// Why a shared probe is absent, folded into any record produced without an attached bundle.
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
    /// live this is [`SandboxProbes::attach`], passing `egress` through: `Some(policy)` arms
    /// enforcement on the tap (armed before it goes live, decision 025), `None` is observe-only.
    ///
    /// **Observation fails open; enforcement does not.** Without the shared probes the bundle
    /// simply doesn't attach and the record's coverage explains every unbound axis (a thinner but
    /// working `--trace`). But `egress` is a *security control*, not an observation: if a policy was
    /// asked for and the tap couldn't be policed (no probes, or the network axis gapped on
    /// caps/BTF/attach), this is a **typed refusal**, never a run with the operator's allow-list
    /// silently unapplied.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] when `egress` is `Some` but enforcement could not be armed.
    pub fn attach(
        &self,
        vmm_pid: u32,
        netns: Option<&str>,
        tap: Option<&str>,
        egress: Option<&EgressPolicy>,
    ) -> Result<RunProbes, VmmError> {
        match (&self.tracer, &self.meter) {
            (Some(tracer), Some(meter)) => {
                let probes = SandboxProbes::attach(vmm_pid, netns, tap, egress, tracer, meter);
                // Enforcement is all-or-nothing: a policed tap that gapped (missing CAP_NET_ADMIN,
                // a tc attach failure) must refuse, not degrade to an unenforced run.
                if egress.is_some() {
                    if let Some(reason) = probes.coverage().iter().find_map(network_gap_reason) {
                        return Err(VmmError::Vmm(format!(
                            "--allow requested egress enforcement, but the tap could not be \
                             policed: {reason}"
                        )));
                    }
                }
                Ok(RunProbes {
                    probes: Some(probes),
                    gaps: Vec::new(),
                })
            }
            _ => {
                if egress.is_some() {
                    return Err(VmmError::Vmm(format!(
                        "--allow requested egress enforcement, but the host-side probes could not \
                         load: {}",
                        self.load_reasons()
                    )));
                }
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
                Ok(RunProbes { probes: None, gaps })
            }
        }
    }

    /// The load-failure reasons joined into one line, for the enforcement-refusal message.
    fn load_reasons(&self) -> String {
        self.load_gaps
            .iter()
            .map(gap_reason)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// The reason string carried by any [`AxisGap`] variant.
fn gap_reason(gap: &AxisGap) -> &str {
    match gap {
        AxisGap::HostSyscalls(r) | AxisGap::Network(r) | AxisGap::Cpu(r) => r,
    }
}

/// The reason string of a [`AxisGap::Network`] gap, else `None`, the enforcement-armed check.
fn network_gap_reason(gap: &AxisGap) -> Option<&str> {
    match gap {
        AxisGap::Network(r) => Some(r),
        _ => None,
    }
}

/// One run's live probe handle: the attached [`SandboxProbes`] bundle, or, fail-open, nothing but
/// the gaps that explain why. Either way [`collect`](Self::collect) yields a [`RunRecord`].
pub struct RunProbes {
    probes: Option<SandboxProbes>,
    /// The coverage carried into the record when no bundle attached (empty otherwise, an attached
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

    /// A **non-destructive** [`RunRecord`] of the run so far, the daemon's `trace` verb, which a
    /// client may ask for repeatedly mid-session. Unlike [`collect`](Self::collect) it neither
    /// consumes the bundle nor detaches the probes, so observation continues after it; each call is a
    /// fresh point-in-time reading built from a live [`snapshot`](SandboxProbes::snapshot) plus the
    /// coverage gaps recorded so far. Without a bundle it is the honest empty record (every absence
    /// explained), exactly like `collect`'s fail-open path.
    pub fn live_record(&self, timing: Timing) -> RunRecord {
        match &self.probes {
            Some(probes) => {
                let snap = probes.snapshot();
                RunRecord::from_parts(
                    snap.network,
                    snap.resources.unwrap_or_default(),
                    snap.host_syscalls.unwrap_or_default(),
                    timing,
                    probes.coverage().to_vec(),
                )
            }
            None => RunRecord::from_parts(
                None,
                ResourceSummary::default(),
                SyscallFootprint::default(),
                timing,
                self.gaps.clone(),
            ),
        }
    }

    /// Finalize the run's record, **while the sandbox is still alive** (the attached bundle reads
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

    #[test]
    fn only_a_network_gap_arms_the_enforcement_refusal() {
        // The enforcement check keys on the *network* axis alone: a syscall/CPU gap is fail-open
        // observation, but a policed tap that gapped must refuse.
        assert_eq!(
            network_gap_reason(&AxisGap::Network("no CAP_NET_ADMIN".into())),
            Some("no CAP_NET_ADMIN")
        );
        assert_eq!(
            network_gap_reason(&AxisGap::Cpu("meter poisoned".into())),
            None
        );
        assert_eq!(
            network_gap_reason(&AxisGap::HostSyscalls("no BTF".into())),
            None
        );
        // `gap_reason` reads the string from any variant (the load-failure message).
        assert_eq!(gap_reason(&AxisGap::Cpu("x".into())), "x");
    }
}
