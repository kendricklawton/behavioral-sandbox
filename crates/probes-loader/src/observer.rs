//! The attach bundle: binds the host-side probes to one sandbox, rolls their output into a
//! [`RunRecord`], and detaches on close.
//!
//! - **Plain values, not a `Sandbox`:** [`AttachParams`] carries the VMM pid and the [`Nic`]
//!   names, so `bsx` stays independent of this crate.
//! - **The host-wide probes are shared, not per-VM:** the `sched_switch` meter and the
//!   `sys_enter_*` tracepoints are global, so each is loaded once ([`SharedMeter`],
//!   [`SharedTracer`]) and a sandbox registers its cgroup as a *target*, keeping the per-event
//!   cost one hash lookup. The tap monitor is legitimately per-VM.
//! - **One post-boot attach:** the cgroup exists once the jailer creates it, so
//!   [`SandboxProbes::attach`] runs once after `open` and the tracer observes from registration
//!   onward, the trade the bounded-overhead shared model asks for.
//! - **Fail-open:** every axis degrades independently to a recorded [`AxisGap`], so a host
//!   missing caps, BTF, or the object still runs the sandbox with a thinner, annotated record.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bsx_probes_common::SyscallEvent;

use bsx_record::{
    AxisGap, NetSection, RecordSubject, RunRecord, SyscallFold, SyscallFootprint, Timing,
};

use crate::{EgressPolicy, ProbeError, ResourceMeter, SyscallTracer, TapMonitor, cgroup_id_of_pid};

/// A process-shared [`ResourceMeter`]: loaded **once** and handed to every sandbox's
/// [`attach`](SandboxProbes::attach), which registers its cgroup as a target. The one CPU-metering
/// program for the whole host. Cheap, thread-safe clone.
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

    /// Runs `f` against the meter, or `None` if the lock is poisoned, which is a fail-open loss of the CPU
    /// axis rather than a panic on the host path.
    fn with<R>(&self, f: impl FnOnce(&mut ResourceMeter) -> R) -> Option<R> {
        self.0.lock().ok().map(|mut m| f(&mut m))
    }

    /// The kernel's cumulative count of cgroups a full `CPU_NS` map could not admit, or `None` if
    /// unreadable; `attach` snapshots it and `collect` gaps a nonzero delta, because an unmetered
    /// cgroup reads back zero CPU.
    fn cpu_drops(&self) -> Option<u64> {
        self.with(|m| m.dropped_cgroups().ok()).flatten()
    }
}

/// A process-shared [`SyscallTracer`]: loaded **once**, switched to set mode, and handed to every
/// sandbox's [`attach`](SandboxProbes::attach). Each sandbox registers its cgroup and gets a
/// private [`SyscallFold`]; one drain routes each event to the matching fold, so concurrent
/// sandboxes stay independent. Cheap, thread-safe clone.
#[derive(Clone)]
pub struct SharedTracer(Arc<Mutex<TracerInner>>);

/// The tracer and its per-cgroup accumulators, behind the [`SharedTracer`] lock.
struct TracerInner {
    tracer: SyscallTracer,
    /// One accumulator per registered sandbox, keyed by cgroup id. Draining routes each event here.
    folds: HashMap<u64, SyscallFold>,
}

impl SharedTracer {
    /// Load + attach the three `sys_enter_*` tracepoints once and switch to **set mode** with an empty
    /// target set, so nothing is emitted until a sandbox is registered via
    /// [`attach`](SandboxProbes::attach) (needs `CAP_BPF`+`CAP_PERFMON` + the object).
    ///
    /// # Errors
    /// [`ProbeError`] if the tracer can't be loaded/attached or the mode can't be set.
    pub fn load() -> Result<Self, ProbeError> {
        let mut tracer = SyscallTracer::load()?;
        tracer.use_target_set()?;
        // Between the unfiltered attach inside `load()` and the mode flip above, the whole host's events
        // stream into the ring buffer, so drain and discard them: residue occupies space a full buffer needs
        // for *new* events, and could misattribute onto a later sandbox whose recycled cgroup id collides.
        let _ = tracer.drain(|_| {});
        Ok(Self(Arc::new(Mutex::new(TracerInner {
            tracer,
            folds: HashMap::new(),
        }))))
    }

    /// Drains the shared ring buffer now, routing pending events to every registered sandbox's
    /// fold, and returns how many were delivered. Draining also happens at each `attach` and
    /// `collect`; a long-lived host calls this between them to keep a busy VMM from filling the
    /// buffer (a drop is counted and surfaces as a gap, but polling is what prevents it).
    pub fn poll(&self) -> usize {
        self.with(drain_route).unwrap_or(0)
    }

    /// Registers one sandbox's cgroup: routes pending events, adds the cgroup to the kernel target
    /// set, and opens a **fresh** fold rather than reusing a stale one, because cgroup ids are
    /// inode numbers that recycle and a dead run's fold would misattribute its events.
    ///
    /// # Errors
    /// [`ProbeError::Poisoned`] if the lock is poisoned, or the target write's error (the caller
    /// records a gap either way).
    fn register(&self, cgroup_id: u64) -> Result<(), ProbeError> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| ProbeError::Poisoned("shared tracer lock".to_string()))?;
        drain_route(&mut inner);
        inner.tracer.add_target(cgroup_id)?;
        inner.folds.insert(cgroup_id, SyscallFold::new(cgroup_id));
        Ok(())
    }

    /// Finalizes one sandbox: drains pending events to every fold, then removes and finishes this
    /// cgroup's fold and unregisters it. `None` if the lock is poisoned or the fold is gone, which
    /// the caller records as a gap rather than passing off an empty footprint as a quiet run.
    fn finalize(&self, cgroup_id: u64) -> Option<SyscallFootprint> {
        self.with(|inner| {
            drain_route(inner);
            // Best-effort unregister: this footprint is already drained, and a failure's only
            // effect, extra ring-buffer pressure, surfaces as ring-drop gaps in later records.
            let _ = inner.tracer.remove_target(cgroup_id);
            inner.folds.remove(&cgroup_id).map(SyscallFold::finish)
        })
        .flatten()
    }

    /// A live, non-destructive read of one sandbox's footprint so far: finishes a **clone** of
    /// this cgroup's fold, so the original keeps accumulating. `None` if the lock is poisoned or
    /// the fold is gone.
    fn snapshot_fold(&self, cgroup_id: u64) -> Option<SyscallFootprint> {
        self.with(|inner| {
            drain_route(inner);
            inner.folds.get(&cgroup_id).map(SyscallFold::snapshot)
        })
        .flatten()
    }

    /// Detaches one sandbox without producing a footprint, the abandoned path. Best-effort; a
    /// poisoned lock is a no-op (the fold goes with the process).
    fn detach(&self, cgroup_id: u64) {
        let _ = self.with(|inner| {
            let _ = inner.tracer.remove_target(cgroup_id);
            inner.folds.remove(&cgroup_id);
        });
    }

    /// The kernel's cumulative dropped-event count, or `None` if unreadable; `attach` snapshots it
    /// and `collect` gaps a nonzero delta. Host-global, so approximate, but a footprint that may
    /// undercount says so.
    fn drops(&self) -> Option<u64> {
        self.with(|inner| inner.tracer.dropped_events().ok())
            .flatten()
    }

    /// The reader-side twin of [`drops`](Self::drops): the tracer's undecodable-record counter
    /// ([`SyscallTracer::undecodable_events`]), covering writer/reader drift the way `drops` covers
    /// a full buffer. `None` only if the lock is poisoned.
    fn undecodable(&self) -> Option<u64> {
        self.with(|inner| inner.tracer.undecodable_events())
    }

    fn with<R>(&self, f: impl FnOnce(&mut TracerInner) -> R) -> Option<R> {
        self.0.lock().ok().map(|mut g| f(&mut g))
    }
}

/// Drain the tracer's ring buffer, routing each event to its cgroup's fold; returns how many events
/// were delivered. Events for an unregistered cgroup are dropped (under the set filter none should
/// exist except a just-unregistered sandbox's stragglers). The disjoint-field split lets the drain
/// closure borrow `folds` while `tracer` drains.
fn drain_route(inner: &mut TracerInner) -> usize {
    let TracerInner { tracer, folds } = inner;
    tracer
        .drain(|ev: SyscallEvent| {
            if let Some(fold) = folds.get_mut(&ev.cgroup_id) {
                fold.record(&ev);
            }
        })
        .unwrap_or(0)
}

/// Folds a monotonic loss counter's attach-to-collect window into a gap **reason**: `None` when
/// both endpoints read and nothing was lost, `lost(delta)` when the counter moved, `unreadable`
/// when an endpoint is missing, because unknown loss is still loss. The one delta rule for every
/// loss counter in `collect`, so none drifts into a laxer reading; the caller names the axis.
fn loss_gap(
    before: Option<u64>,
    after: Option<u64>,
    lost: impl FnOnce(u64) -> String,
    unreadable: &'static str,
) -> Option<std::borrow::Cow<'static, str>> {
    match (before, after) {
        (Some(before), Some(after)) if after > before => Some(lost(after - before).into()),
        (Some(_), Some(_)) => None, // both endpoints read, no increase: exact
        _ => Some(unreadable.into()),
    }
}

/// One sandbox's NIC as the driver names it: the netns and the tap device inside it, **both or
/// neither**, so the mixed state a bare pair of `Option<&str>`s admits is unrepresentable.
///
/// Deliberately not `#[non_exhaustive]` (the crate's one exception): named-field literal
/// construction is the anti-swap mechanism for two same-typed strings, and a constructor would
/// reintroduce the positional pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nic<'a> {
    /// The sandbox's network namespace name (the driver's `netns()`).
    pub netns: &'a str,
    /// The tap device name inside that netns (the driver's `tap_name()`, typically `fc0`).
    pub tap: &'a str,
}

/// The per-run inputs to [`SandboxProbes::attach`]: [`new`](Self::new) starts at the sealed
/// posture (no NIC, no policy, no route) and the optional fields are set on the value, so a new
/// knob lands additively (`#[non_exhaustive]`) rather than as a positional-parameter break.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct AttachParams<'a> {
    /// The VMM's host pid, resolved to its cgroup (the tracer + meter axis).
    pub vmm_pid: u32,
    /// The per-VM NIC to bind the tap monitor to; `None` = no NIC, so the record's network
    /// section is simply absent (not a gap).
    pub nic: Option<Nic<'a>>,
    /// `Some(policy)` arms enforcement before the tc programs go live on the tap; `None` is
    /// observe-only.
    pub egress: Option<&'a EgressPolicy>,
    /// The default route the driver configured, carried through to the record. The tap cannot
    /// see it (it is on the guest's command line, not on the wire), and the record needs it
    /// because an allowance means something different with a route than without.
    pub gateway: Option<std::net::Ipv4Addr>,
}

impl<'a> AttachParams<'a> {
    /// Params for one run at the sealed posture: no NIC, no egress policy, no gateway.
    #[must_use]
    pub fn new(vmm_pid: u32) -> Self {
        Self {
            vmm_pid,
            nic: None,
            egress: None,
            gateway: None,
        }
    }
}

/// Live bundle for one VM: a target registration on the shared tracer + meter, the per-VM tap, and the
/// coverage gaps seen so far. [`collect`](Self::collect) finalizes it into a [`RunRecord`] while
/// the sandbox is still alive; dropping without collecting detaches (RAII) and unregisters both shared
/// targets so a dead sandbox leaves no residue.
#[must_use = "dropping SandboxProbes detaches this run's probes; call collect() first to finalize the record"]
pub struct SandboxProbes {
    vmm_pid: u32,
    cgroup_id: Option<u64>,
    tracer: SharedTracer,
    /// Registered on the shared tracer (its cgroup is a trace target with an open fold).
    traced: bool,
    tap: Option<TapMonitor>,
    meter: SharedMeter,
    /// Registered on the shared meter (its cgroup is a metering target).
    metered: bool,
    /// The kernel's cumulative ring-buffer drop count at attach time; `collect` reports a nonzero
    /// delta as a coverage gap (the footprint may undercount). `None` if unreadable at attach.
    drops_at_attach: Option<u64>,
    /// The [`drops_at_attach`](Self::drops_at_attach) twin for the reader-side undecodable-record
    /// counter; a nonzero delta at `collect` is the same class of gap.
    undecodable_at_attach: Option<u64>,
    /// The [`drops_at_attach`](Self::drops_at_attach) twin on the CPU axis: cgroups a full `CPU_NS`
    /// map turned away. `None` if unreadable at attach, or if this sandbox was never metered.
    cpu_drops_at_attach: Option<u64>,
    /// The default route the driver configured, carried through to the record. The tap cannot see
    /// it, so it rides as a plain value rather than being observed.
    gateway: Option<std::net::Ipv4Addr>,
    gaps: Vec<AxisGap>,
    /// Set once [`collect`](Self::collect) has read + detached everything, so `Drop` is a no-op.
    finalized: bool,
}

impl SandboxProbes {
    /// Post-boot: bind every available probe to this one VM by the plain values in `params`:
    /// resolve the VMM's cgroup and register it on the shared tracer and meter, and attach a
    /// per-VM tap monitor when a [`Nic`] is given, enforcing `params.egress` (armed before the tc
    /// programs go live) when set. Each sub-attach degrades to a recorded [`AxisGap`]; the
    /// returned bundle is always valid.
    pub fn attach(
        params: AttachParams<'_>,
        tracer: &SharedTracer,
        meter: &SharedMeter,
    ) -> SandboxProbes {
        let mut gaps: Vec<AxisGap> = Vec::new();

        // The cgroup id is the tracer and meter axis, resolved from the pid.
        let cgroup_id = match cgroup_id_of_pid(params.vmm_pid) {
            Ok(id) => Some(id),
            Err(e) => {
                gaps.push(AxisGap::Cpu(format!("resolve cgroup: {e}").into()));
                None
            }
        };

        // Host syscalls: register the cgroup on the shared tracer (opens its fold).
        let traced = match cgroup_id {
            Some(cgid) => match tracer.register(cgid) {
                Ok(()) => true,
                Err(e) => {
                    gaps.push(AxisGap::HostSyscalls(
                        format!("register tracer: {e}").into(),
                    ));
                    false
                }
            },
            None => {
                gaps.push(AxisGap::HostSyscalls(
                    "cgroup id unknown, cannot attribute host syscalls".into(),
                ));
                false
            }
        };

        // Attach the per-VM tap monitor. No `Nic` = no NIC: the network section is simply absent
        // (not a gap); an attach failure is a gap.
        let tap_mon = params.nic.and_then(|nic| {
            let attached = match params.egress {
                Some(policy) => TapMonitor::enforce_in_netns(nic.netns, nic.tap, policy),
                None => TapMonitor::attach_in_netns(nic.netns, nic.tap),
            };
            match attached {
                Ok(m) => Some(m),
                Err(e) => {
                    gaps.push(AxisGap::Network(format!("attach tap: {e}").into()));
                    None
                }
            }
        });

        // Register the cgroup as a target on the shared meter (the CPU axis).
        let metered = match cgroup_id {
            Some(cgid) => match meter.with(|m| m.add_target(cgid)) {
                Some(Ok(())) => true,
                Some(Err(e)) => {
                    gaps.push(AxisGap::Cpu(format!("meter add_target: {e}").into()));
                    false
                }
                None => {
                    gaps.push(AxisGap::Cpu("meter lock poisoned".into()));
                    false
                }
            },
            None => false,
        };

        SandboxProbes {
            vmm_pid: params.vmm_pid,
            gateway: params.gateway,
            cgroup_id,
            tracer: tracer.clone(),
            traced,
            tap: tap_mon,
            meter: meter.clone(),
            metered,
            drops_at_attach: if traced { tracer.drops() } else { None },
            undecodable_at_attach: if traced { tracer.undecodable() } else { None },
            cpu_drops_at_attach: if metered { meter.cpu_drops() } else { None },
            gaps,
            finalized: false,
        }
    }

    /// **Finalize + detach on close**: read the three probes into a [`RunRecord`] and
    /// unregister this run's cgroup from the shared tracer + meter. **Must run while the sandbox is still
    /// alive**, the cgroup dir and map fds must be live. `timing` comes from the caller
    /// (`Sandbox::boot_latency` + `RunResult::metrics.wall`), so the record never depends on `bsx`.
    /// Each axis degrades to a recorded gap on a read error.
    pub fn collect(mut self, subject: RecordSubject, timing: Timing) -> RunRecord {
        // A lost fold or poisoned lock is a recorded gap, never an empty footprint passed off as a
        // quiet run.
        let had_tracer = matches!((self.traced, self.cgroup_id), (true, Some(_)));
        let host_syscalls = match (self.traced, self.cgroup_id) {
            (true, Some(cgid)) => match self.tracer.finalize(cgid) {
                Some(footprint) => footprint,
                None => {
                    self.gaps.push(AxisGap::HostSyscalls(
                        "shared tracer state unavailable at finalize (lock poisoned or fold lost)"
                            .into(),
                    ));
                    SyscallFootprint::default()
                }
            },
            _ => SyscallFootprint::default(),
        };
        self.traced = false;

        // The ring buffer is host-global: a moved loss counter means the footprint may undercount,
        // and an unreadable endpoint is unknown loss, still a gap.
        if had_tracer {
            self.gaps.extend(
                loss_gap(
                    self.drops_at_attach,
                    self.tracer.drops(),
                    |n| {
                        format!(
                            "ring buffer dropped {n} event(s) during this run's window; the \
                             footprint may undercount"
                        )
                    },
                    "ring-buffer event-loss counter unreadable at finalize; possible undercount",
                )
                .map(AxisGap::HostSyscalls),
            );
            self.gaps.extend(
                loss_gap(
                    self.undecodable_at_attach,
                    self.tracer.undecodable(),
                    |n| {
                        format!(
                            "{n} ring record(s) did not decode as a SyscallEvent (kernel/userspace \
                             event-record drift); the footprint may undercount"
                        )
                    },
                    "undecodable-record counter unreadable at finalize; possible undercount",
                )
                .map(AxisGap::HostSyscalls),
            );
        }

        // Totals are the section's spine (a section without them misreads as "no traffic"), so
        // their failure gaps the whole axis; a failed flow/denial read keeps the rest.
        let network = match self.tap.as_ref() {
            Some(monitor) => match monitor.totals() {
                Err(e) => {
                    self.gaps
                        .push(AxisGap::Network(format!("read tap totals: {e}").into()));

                    None
                }
                Ok(totals) => {
                    let flows = monitor.flows().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap flows: {e}").into()));
                        Vec::new()
                    });
                    let denials = monitor.denials().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap denials: {e}").into()));
                        Vec::new()
                    });
                    // Full-map drop counters: nonzero means this section undercounts and the loss
                    // must ride the record; a failed read of a counter is its own gap.
                    let dropped_flows = monitor.dropped_flows().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap flow drops: {e}").into()));
                        0
                    });
                    let dropped_denials = monitor.dropped_denials().unwrap_or_else(|e| {
                        self.gaps.push(AxisGap::Network(
                            format!("read tap denial drops: {e}").into(),
                        ));
                        0
                    });
                    if dropped_flows > 0 {
                        self.gaps.push(AxisGap::Network(
                            format!(
                                "flow table full: {dropped_flows} new flow(s) dropped; flows and \
                             totals undercount"
                            )
                            .into(),
                        ));
                    }
                    if dropped_denials > 0 {
                        self.gaps.push(AxisGap::Network(
                            format!(
                                "denial table full: {dropped_denials} denied packet(s) missing a \
                             destination row (the packets were still dropped at the tap)"
                            )
                            .into(),
                        ));
                    }
                    // Frames the flow view can't represent mean the section is not the whole tap
                    // traffic, so gap them; a failed read of the counter is itself a gap.
                    match monitor.unparsed_l3() {
                        Ok(n) if n > 0 => self.gaps.push(AxisGap::Network(
                            format!(
                            "{n} unrepresentable frame(s) (VLAN, or a truncated IPv4/IPv6 frame) \
                             crossed the tap; this section is not the complete tap traffic"
                        )
                            .into(),
                        )),
                        Ok(_) => {}
                        Err(e) => self.gaps.push(AxisGap::Network(
                            format!("read tap unparsed-L3 counter: {e}").into(),
                        )),
                    }
                    // The IPv6 half: an unreadable v6 map is its own gap, so v6 traffic is never
                    // silently absent.
                    let flows6 = monitor.flows6().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap v6 flows: {e}").into()));
                        Vec::new()
                    });
                    let denials6 = monitor.denials6().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap v6 denials: {e}").into()));
                        Vec::new()
                    });
                    // The posture is read back from the classifier's own maps; a failed read is a
                    // gap, because "no rules" and "could not tell" must never conflate.
                    let posture = monitor.posture(self.gateway).map_err(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read egress posture: {e}").into()));
                    });
                    let section = NetSection::from_tap(
                        flows,
                        totals,
                        denials,
                        dropped_flows,
                        dropped_denials,
                    )
                    .with_v6(flows6, denials6);
                    Some(match posture {
                        Ok(p) => section.with_posture(p),
                        Err(()) => section,
                    })
                }
            },
            None => None,
        };

        // Read the resources *before* unregistering, while the cgroup dir is still live; a failure
        // is a recorded gap, so zero CPU never means "the read silently failed".
        let resources = match self.meter.with(|m| m.summary_for_pid(self.vmm_pid)) {
            Some(Ok(summary)) => summary,
            Some(Err(e)) => {
                self.gaps
                    .push(AxisGap::Cpu(format!("read resource summary: {e}").into()));
                crate::ResourceSummary::default()
            }
            None => {
                self.gaps.push(AxisGap::Cpu("meter lock poisoned".into()));
                crate::ResourceSummary::default()
            }
        };

        if self.metered {
            // A cgroup a full `CPU_NS` could not admit reads back zero CPU, which must never pass
            // for "this run used none"; the counter is host-global, so any delta stops the number
            // being called exact.
            self.gaps.extend(
                loss_gap(
                    self.cpu_drops_at_attach,
                    self.meter.cpu_drops(),
                    |n| {
                        format!(
                            "the per-cgroup CPU map was full during this run's window ({n} \
                             cgroup(s) dropped); a dropped cgroup accumulates no time and reads \
                             back as zero"
                        )
                    },
                    "per-cgroup CPU-map drop counter unreadable at finalize; the CPU total may be \
                     unmeasured rather than zero",
                )
                .map(AxisGap::Cpu),
            );
            if let Some(cgid) = self.cgroup_id {
                // Unregister and free the `CPU_NS` row (already read above), so a long-lived
                // meter doesn't accumulate dead cgroups against `MAX_CGROUPS`. Best-effort.
                let _ = self.meter.with(|m| {
                    let _ = m.remove_target(cgid);
                    m.clear(cgid)
                });
            }
            self.metered = false;
        }

        self.finalized = true;
        RunRecord::from_parts(
            subject,
            network,
            resources,
            host_syscalls,
            timing,
            std::mem::take(&mut self.gaps),
        )
    }

    /// A **live, non-destructive** read of this sandbox's probes so far, the watcher's poll. A
    /// transiently unreadable axis is `None` (the watcher keeps its last good view); the
    /// authoritative, gap-recording read is [`collect`](Self::collect), which this never disturbs.
    #[must_use]
    pub fn snapshot(&self) -> LiveSnapshot {
        let host_syscalls = match (self.traced, self.cgroup_id) {
            (true, Some(cgid)) => self.tracer.snapshot_fold(cgid),
            _ => None,
        };
        let network = self.tap.as_ref().and_then(|monitor| {
            let totals = monitor.totals().ok()?;
            let flows = monitor.flows().ok()?;
            let denials = monitor.denials().ok()?;
            // Live view: a transiently unreadable drop counter reads as 0 (the authoritative,
            // gap-recording read is `collect`); a real nonzero still marks the view truncated.
            let dropped_flows = monitor.dropped_flows().unwrap_or(0);
            let dropped_denials = monitor.dropped_denials().unwrap_or(0);
            // Live view: v6 reads that transiently fail read as empty (the authoritative read is
            // `collect`); a real v6 flow still shows here.
            let flows6 = monitor.flows6().unwrap_or_default();
            let denials6 = monitor.denials6().unwrap_or_default();
            Some(
                NetSection::from_tap(flows, totals, denials, dropped_flows, dropped_denials)
                    .with_v6(flows6, denials6),
            )
        });
        let resources = self
            .meter
            .with(|m| m.summary_for_pid(self.vmm_pid).ok())
            .flatten();
        LiveSnapshot {
            network,
            resources,
            host_syscalls,
        }
    }

    /// The gaps recorded so far (which axes are unavailable and why), useful to a caller before
    /// `collect`, e.g. to warn.
    #[must_use]
    pub fn coverage(&self) -> &[AxisGap] {
        &self.gaps
    }
}

/// One point-in-time reading of a live sandbox's probes, from [`SandboxProbes::snapshot`], what a
/// live view redraws from between attach and collect. Pure data (no aya), so consumers stay
/// host-safe testable. An unreadable axis is `None`; *why* an axis is missing belongs to the final
/// [`RunRecord`](crate::RunRecord)'s coverage, not here.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LiveSnapshot {
    /// The tap's flows/totals/denials at this instant, already deterministically sorted
    /// ([`NetSection::from_tap`]). `None` without a NIC or on a transient read failure.
    pub network: Option<NetSection>,
    /// The shared meter's CPU + cgroup memory/IO reading at this instant.
    pub resources: Option<crate::ResourceSummary>,
    /// The VMM's host-syscall footprint accrued so far (a finished clone of the live fold).
    pub host_syscalls: Option<SyscallFootprint>,
}

impl Drop for SandboxProbes {
    /// Detach on close: unregister this run's cgroup from the shared tracer + meter so neither set
    /// accumulates dead cgroups. A no-op after [`collect`](Self::collect) (which already detached). The
    /// per-VM tap detaches via its own aya `Ebpf` drop (nothing pinned); its in-kernel
    /// filter is reclaimed by the sandbox's netns teardown.
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        if self.traced
            && let Some(cgid) = self.cgroup_id
        {
            self.tracer.detach(cgid);
        }
        if self.metered
            && let Some(cgid) = self.cgroup_id
        {
            // Drop-path teardown with no final read: unregister and free the `CPU_NS` row so the
            // shared map doesn't accumulate this dead cgroup (mirrors `collect`).
            let _ = self.meter.with(|m| {
                let _ = m.remove_target(cgid);
                m.clear(cgid)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    // Host-safe: the loss-counter delta rule and the params posture, no aya, no kernel.
    use super::{AttachParams, loss_gap};

    #[test]
    fn attach_params_new_is_the_sealed_posture() {
        // A bare `new` must mean the sealed sandbox: no NIC, no allowance, no route. A default
        // that opened anything would arm probes (or claim a route) no caller asked for.
        let params = AttachParams::new(4242);
        assert_eq!(params.vmm_pid, 4242);
        assert!(params.nic.is_none());
        assert!(params.egress.is_none());
        assert!(params.gateway.is_none());
    }

    #[test]
    fn a_counter_increase_between_attach_and_collect_is_a_gap() {
        let gap = loss_gap(Some(2), Some(5), |n| format!("{n} lost"), "unreadable")
            .expect("an increase is loss");
        assert_eq!(gap, "3 lost", "the reason names the window's delta");
    }

    #[test]
    fn equal_endpoints_are_exact_and_gap_nothing() {
        assert!(loss_gap(Some(7), Some(7), |n| format!("{n} lost"), "unreadable").is_none());
        assert!(loss_gap(Some(0), Some(0), |n| format!("{n} lost"), "unreadable").is_none());
    }

    #[test]
    fn an_unreadable_endpoint_is_unknown_loss_which_is_still_a_gap() {
        // Unknown loss is loss: a missing endpoint on either side must gap, never read as exact.
        for (before, after) in [(None, Some(5)), (Some(2), None), (None, None)] {
            let gap = loss_gap(before, after, |n| format!("{n} lost"), "counter unreadable")
                .expect("a missing endpoint is unknown loss");
            assert_eq!(gap, "counter unreadable");
        }
    }
}
