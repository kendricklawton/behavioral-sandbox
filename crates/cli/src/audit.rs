//! The CLI's audit face: compose the two tracks the way the engine intends, boot the sandbox
//! (`bsx-engine`), then bind the host-side probes to it by the **plain values** `Sandbox` exposes
//! (`vmm_pid`/`netns`/`tap_name`) and fuse their output into the per-run [`RunRecord`].
//!
//! The caller-side launch sequence the loader specifies: the driver and the eBPF loader stay
//! independent crates, and the CLI is where they meet.
//!
//! **Observation fails open; enforcement does not.** A host that can't load the shared probes still runs
//! the sandbox, and the record it yields is thinner and says why in its coverage section, so `--trace` on
//! an unprivileged box is a working command rather than a refused run. An egress *policy* is the
//! exception: it is a security control, so a run that asked to enforce one and couldn't arm the tap is a
//! typed refusal, never a silent unenforced run.

use bsx_engine::VmmError;
use bsx_probes_loader::{
    AttachParams, AxisGap, EgressPolicy, LiveSnapshot, Nic, RecordSubject, ResourceSummary,
    RunRecord, SandboxProbes, SharedMeter, SharedTracer, SyscallFootprint, Timing,
};

/// A booted thing the CLI binds probes to: a [`Sandbox`](bsx_engine::Sandbox) for a one-shot `run`,
/// a [`RunningVm`](bsx_engine::RunningVm) for a daemon session. Both already expose the same three
/// plain values; naming that lets [`attach_params`] assemble either.
pub(crate) trait ProbeSubject {
    /// The VMM's host pid.
    fn vmm_pid(&self) -> u32;
    /// The per-VM network namespace, or `None` when the sandbox has no NIC.
    fn netns(&self) -> Option<&str>;
    /// The tap device inside that namespace, or `None` when the sandbox has no NIC.
    fn tap_name(&self) -> Option<&str>;
}

impl ProbeSubject for bsx_engine::Sandbox {
    fn vmm_pid(&self) -> u32 {
        self.vmm_pid()
    }
    fn netns(&self) -> Option<&str> {
        self.netns()
    }
    fn tap_name(&self) -> Option<&str> {
        self.tap_name()
    }
}

impl ProbeSubject for bsx_engine::RunningVm {
    fn vmm_pid(&self) -> u32 {
        self.vmm_pid()
    }
    fn netns(&self) -> Option<&str> {
        self.netns()
    }
    fn tap_name(&self) -> Option<&str> {
        self.tap_name()
    }
}

/// The per-run [`AttachParams`] for `subject`. Both NIC names come from the engine's single tap
/// field, so they are `Some` together or not at all; pairing them here rather than at each call
/// site is what keeps two same-typed strings off a caller's hands.
pub(crate) fn attach_params<'a>(
    subject: &'a impl ProbeSubject,
    egress: Option<&'a EgressPolicy>,
    gateway: Option<std::net::Ipv4Addr>,
) -> AttachParams<'a> {
    let mut params = AttachParams::new(subject.vmm_pid());
    params.nic = match (subject.netns(), subject.tap_name()) {
        (Some(netns), Some(tap)) => Some(Nic { netns, tap }),
        _ => None,
    };
    params.egress = egress;
    params.gateway = gateway;
    params
}

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
                load_gaps.push(AxisGap::HostSyscalls(
                    format!("load shared tracer: {e}").into(),
                ));
                None
            }
        };
        let meter = match SharedMeter::load() {
            Ok(m) => Some(m),
            Err(e) => {
                load_gaps.push(AxisGap::Cpu(format!("load shared meter: {e}").into()));
                None
            }
        };
        Self {
            tracer,
            meter,
            load_gaps,
        }
    }

    /// Binds the probes to one booted sandbox by the plain values in `params`, passing `params.egress`
    /// through: `Some(policy)` arms enforcement on the tap before it goes live, `None` is observe-only.
    ///
    /// Without the shared probes the bundle does not attach and the record's coverage explains every
    /// unbound axis, but `egress` is a security control rather than an observation, so a policy that
    /// could not be armed is a **typed refusal**, never a silently unapplied allow-list.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] when `params.egress` is `Some` but enforcement could not be armed.
    pub fn attach(
        &self,
        sandbox_id: &str,
        params: AttachParams<'_>,
    ) -> Result<RunProbes, VmmError> {
        // Stamped here, not at collect: attaching the probes *is* the start of observation, so this
        // is when the run began. A host with an unreadable clock yields 0, the same fail-open
        // honesty the coverage gaps carry, rather than refusing the run.
        let subject = RecordSubject::new(sandbox_id.to_string(), unix_nanos_now());
        match (&self.tracer, &self.meter) {
            (Some(tracer), Some(meter)) => {
                let probes = SandboxProbes::attach(params, tracer, meter);
                // Enforcement is all-or-nothing: a policed tap that gapped (missing CAP_NET_ADMIN,
                // a tc attach failure) must refuse, not degrade to an unenforced run.
                if params.egress.is_some()
                    && let Some(reason) = probes.coverage().iter().find_map(network_gap_reason)
                {
                    return Err(VmmError::Vmm(format!(
                        "--allow requested egress enforcement, but the tap could not be \
                             policed: {reason}"
                    )));
                }
                Ok(RunProbes {
                    probes: Some(probes),
                    gaps: Vec::new(),
                    subject,
                })
            }
            _ => {
                if params.egress.is_some() {
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
                        "shared probes incomplete; tracer not attached".into(),
                    ));
                }
                if self.meter.is_some() {
                    gaps.push(AxisGap::Cpu(
                        "shared probes incomplete; meter not attached".into(),
                    ));
                }
                if params.nic.is_some() {
                    gaps.push(AxisGap::Network(
                        "shared probes unavailable; tap monitor not attached".into(),
                    ));
                }

                Ok(RunProbes {
                    probes: None,
                    gaps,
                    subject,
                })
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

/// The reason string carried by any [`AxisGap`] variant. `AxisGap` is `#[non_exhaustive]`, so a
/// new axis (unknown to this build) reads as a generic marker rather than a compile break.
fn gap_reason(gap: &AxisGap) -> &str {
    gap.reason()
}

/// The reason string of a [`AxisGap::Network`] gap, else `None`, the enforcement-armed check.
fn network_gap_reason(gap: &AxisGap) -> Option<&str> {
    match gap {
        AxisGap::Network(_) => Some(gap.reason()),
        _ => None,
    }
}

/// Wall-clock now, nanoseconds since the Unix epoch, or `0` if the host clock is unreadable or
/// before the epoch. Never panics and never refuses a run over a clock: an unstamped record is worse
/// than a run that did not happen only for the auditor, so this degrades like a coverage gap.
fn unix_nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

/// One run's live probe handle: the attached [`SandboxProbes`] bundle, or, fail-open, nothing but
/// the gaps that explain why. Either way [`collect`](Self::collect) yields a [`RunRecord`].
pub struct RunProbes {
    probes: Option<SandboxProbes>,
    /// What this run's record is about: fixed when the probes attached, so every record this handle
    /// yields (live or final) names the same sandbox and the same start.
    subject: RecordSubject,
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

    /// A **non-destructive** [`RunRecord`] of the run so far (the daemon's `trace` verb), which a
    /// client may ask for repeatedly mid-session: unlike [`collect`](Self::collect) it neither
    /// consumes the bundle nor detaches the probes, so each call is a fresh point-in-time reading and
    /// observation continues after it. Without a bundle it is the honest empty record, like `collect`.
    pub fn live_record(&self, timing: Timing) -> RunRecord {
        match &self.probes {
            Some(probes) => {
                let snap = probes.snapshot();
                RunRecord::from_parts(
                    self.subject.clone(),
                    snap.network,
                    snap.resources.unwrap_or_default(),
                    snap.host_syscalls.unwrap_or_default(),
                    timing,
                    probes.coverage().to_vec(),
                )
            }
            None => RunRecord::from_parts(
                self.subject.clone(),
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
            Some(probes) => probes.collect(self.subject, timing),
            None => RunRecord::from_parts(
                self.subject,
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

    /// A stand-in for the two engine handles, so the pairing is testable without booting a VM.
    struct FakeSubject {
        netns: Option<&'static str>,
        tap: Option<&'static str>,
    }

    impl ProbeSubject for FakeSubject {
        fn vmm_pid(&self) -> u32 {
            4242
        }
        fn netns(&self) -> Option<&str> {
            self.netns
        }
        fn tap_name(&self) -> Option<&str> {
            self.tap
        }
    }

    /// `run` and a daemon session assemble these params from the same seam, and the two NIC names
    /// are same-typed strings: crossed, the tap monitor is asked for a device in the wrong
    /// namespace, and the record's whole network section is missing or wrong.
    #[test]
    fn a_nic_is_paired_in_the_order_the_engine_names_it_or_not_at_all() {
        let params = attach_params(
            &FakeSubject {
                netns: Some("ns-of-this-vm"),
                tap: Some("tap-of-this-vm"),
            },
            None,
            None,
        );
        assert_eq!(params.vmm_pid, 4242);
        let nic = params.nic.expect("a sandbox with both names has a NIC");
        assert_eq!(nic.netns, "ns-of-this-vm", "the namespace is the namespace");
        assert_eq!(nic.tap, "tap-of-this-vm", "and the tap is the tap");

        // Both names come from one engine field, so a half-configured NIC is a bug either way:
        // it must read as "no NIC" (an absent network section) rather than as a NIC to bind.
        for half in [
            FakeSubject {
                netns: Some("ns"),
                tap: None,
            },
            FakeSubject {
                netns: None,
                tap: Some("tap"),
            },
            FakeSubject {
                netns: None,
                tap: None,
            },
        ] {
            assert!(
                attach_params(&half, None, None).nic.is_none(),
                "half a NIC is no NIC"
            );
        }

        // The sealed posture is what `AttachParams::new` starts at, and the caller's policy and
        // route travel through untouched.
        let policy = EgressPolicy::default();
        let gw = std::net::Ipv4Addr::new(10, 200, 0, 1);
        let armed = attach_params(
            &FakeSubject {
                netns: None,
                tap: None,
            },
            Some(&policy),
            Some(gw),
        );
        assert!(armed.egress.is_some(), "the policy reaches enforcement");
        assert_eq!(armed.gateway, Some(gw));
    }

    #[test]
    fn unattached_probes_collect_an_honest_empty_record() {
        // The fail-open path a capability-less host takes: no bundle, gaps carried through.
        let probes = RunProbes {
            probes: None,
            subject: RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            gaps: vec![
                AxisGap::HostSyscalls("load shared tracer: no BTF".into()),
                AxisGap::Cpu("load shared meter: no BTF".into()),
            ],
        };
        assert!(probes.snapshot().network.is_none());
        let timing = Timing::new(Duration::from_millis(100), Duration::from_millis(5));
        let record = probes.collect(timing);
        assert!(record.network.is_none());
        assert_eq!(record.host_syscalls.total, 0);
        assert_eq!(record.coverage.len(), 2, "every absence is explained");
        assert_eq!(record.timing, timing, "timing rides through regardless");
    }

    /// `load` is the only place a probe that will not load becomes a recorded absence, and the
    /// correspondence has to hold in both directions: an axis whose probe is missing must carry a
    /// gap, and an axis that loaded must not invent one. Asserted against a real `load` on whatever
    /// host runs it, so a capability-less box exercises the failure half and a privileged one
    /// exercises the success half.
    #[test]
    fn every_probe_that_did_not_load_is_named_by_a_gap() {
        let obs = Observability::load();

        let syscall_gap = obs
            .load_gaps
            .iter()
            .any(|g| matches!(g, AxisGap::HostSyscalls(_)));
        assert_eq!(
            obs.tracer.is_none(),
            syscall_gap,
            "a tracer that did not load is a gap, and one that did is not: \
             tracer={:?} gaps={:?}",
            obs.tracer.is_some(),
            obs.load_gaps
        );

        let cpu_gap = obs.load_gaps.iter().any(|g| matches!(g, AxisGap::Cpu(_)));
        assert_eq!(
            obs.meter.is_none(),
            cpu_gap,
            "same for the meter: meter={:?} gaps={:?}",
            obs.meter.is_some(),
            obs.load_gaps
        );

        // Loading is never itself a failure: a host with no eBPF still runs sandboxes.
        assert!(
            obs.load_gaps.len() <= 2,
            "at most one gap per shared probe: {:?}",
            obs.load_gaps
        );
    }

    /// The fail-open path end to end through the **real** `attach`, rather than a hand-built
    /// `RunProbes`: a host whose shared probes did not load still yields a record, and every axis
    /// that never bound is named in its coverage. The NIC is the one that is easy to lose, since
    /// nothing about an unloaded tracer mentions it.
    #[test]
    fn an_unloadable_probe_set_records_every_axis_it_could_not_bind() {
        let obs = Observability {
            tracer: None,
            meter: None,
            load_gaps: vec![
                AxisGap::HostSyscalls("load shared tracer: no BTF".into()),
                AxisGap::Cpu("load shared meter: no BTF".into()),
            ],
        };
        let mut params = AttachParams::new(4242);
        params.nic = Some(Nic {
            netns: "bsx-test-ns",
            tap: "fc0",
        });

        let probes = obs
            .attach("bsx-4242-0", params)
            .expect("observe-only attach never refuses a run");
        let record = probes.collect(Timing::new(
            Duration::from_millis(100),
            Duration::from_millis(5),
        ));

        assert!(
            record
                .coverage
                .iter()
                .any(|g| matches!(g, AxisGap::HostSyscalls(_))),
            "the syscall axis is named: {:?}",
            record.coverage
        );
        assert!(
            record.coverage.iter().any(|g| matches!(g, AxisGap::Cpu(_))),
            "the cpu axis is named: {:?}",
            record.coverage
        );
        assert!(
            record
                .coverage
                .iter()
                .any(|g| matches!(g, AxisGap::Network(_))),
            "a NIC that never got a tap monitor is a gap, not silence: {:?}",
            record.coverage
        );
        assert!(record.network.is_none(), "nothing was observed to report");
    }

    /// Egress is a security control, not an observation, so the one thing that must **not**
    /// fail open is a policy that could not be armed. A host that cannot load the probes has to
    /// refuse the run rather than proceed with an unenforced allow-list.
    #[test]
    fn a_policy_that_cannot_be_armed_refuses_the_run() {
        let obs = Observability {
            tracer: None,
            meter: None,
            load_gaps: vec![AxisGap::HostSyscalls("load shared tracer: no BTF".into())],
        };
        let policy = EgressPolicy::default();
        let mut params = AttachParams::new(4242);
        params.nic = Some(Nic {
            netns: "bsx-test-ns",
            tap: "fc0",
        });
        params.egress = Some(&policy);

        // `RunProbes` holds live probe handles and so carries no `Debug`; take the error side by
        // hand rather than `expect_err`, which would require one.
        let refusal = obs.attach("bsx-4242-0", params).err();
        assert!(
            refusal.is_some(),
            "an unarmable policy must refuse, never degrade to observe-only"
        );
        let msg = refusal.map(|e| e.to_string()).unwrap_or_default();
        assert!(
            msg.contains("egress enforcement"),
            "the refusal names what it refused: {msg}"
        );
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
