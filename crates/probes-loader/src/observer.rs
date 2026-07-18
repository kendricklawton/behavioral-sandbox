//! The attach bundle: bind the three host-side probes to one sandbox and roll their
//! output into a [`RunRecord`], and detach + finalize on close.
//!
//! `agent-vmm` stays independent of this crate (decisions 024/026/028), so the bundle takes **plain
//! values** the driver already exposes, the VMM pid (→ its cgroup, for the syscall tracer and the CPU
//! meter) and the netns + tap names (for the network monitor), never a `Sandbox`. The composition is
//! the caller's (the CLI/daemon later): a short launch sequence around `Sandbox::open`.
//!
//! **Both host-wide probes are shared, not per-VM.** The `sched_switch` meter (decision 026) and
//! the three `sys_enter_*` tracepoints are *global*: a fresh copy per sandbox would run *N* programs on
//! every context switch / syscall (O(sandboxes), the shape decision 026 rejects). So each is loaded
//! **once** for the host, [`SharedMeter`] and [`SharedTracer`], and every sandbox registers its cgroup
//! as a *target* on both; the per-event cost stays a single hash lookup regardless of how many sandboxes
//! are live, and each shared map only ever holds the registered cgroups. The tap monitor is legitimately
//! per-VM (one tap, one sandbox) and owned by the bundle.
//!
//! **One post-boot attach.** Because both shared probes are already attached host-wide and a sandbox
//! only *registers its cgroup* (which exists once the jailer creates it during boot), there is no
//! per-VM program to stand up before boot: [`SandboxProbes::attach`] runs once, after `open`. The syscall
//! tracer therefore observes the VMM's host footprint from **registration onward**, not the pre-boot
//! window, a deliberate trade for the bounded-overhead shared model (decision 028); the record's core
//! (network + resources + denials) is unaffected.
//!
//! **Fail-open.** Every axis degrades independently to a recorded [`AxisGap`]; a host missing caps, BTF,
//! or the object still runs the sandbox and produces a (thinner, honestly-annotated) record.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use agent_probes_common::SyscallEvent;

use crate::record::{AxisGap, NetSection, RunRecord, SyscallFold, SyscallFootprint, Timing};
use crate::{cgroup_id_of_pid, EgressPolicy, ProbeError, ResourceMeter, SyscallTracer, TapMonitor};

/// A process-shared [`ResourceMeter`]: loaded **once** and handed to every sandbox's
/// [`attach`](SandboxProbes::attach), which registers its cgroup as a target. The one CPU-metering
/// program for the whole host (decision 026). Cheap, thread-safe clone.
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

/// A process-shared [`SyscallTracer`]: loaded **once**, switched to set mode, and handed to every
/// sandbox's [`attach`](SandboxProbes::attach). One shared tracer serves all sandboxes, each registers
/// its cgroup as a target and gets a private [`SyscallFold`]; a single drain routes each event to the
/// matching cgroup's fold, so concurrent sandboxes stay independent (a sandbox reads only its own cgroup's
/// footprint, and unregistering one leaves the others untouched). Cheap, thread-safe clone.
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
        // Clear the load-window baseline: between the (unfiltered) attach inside `load()` and the mode
        // flip above, the whole host's events streamed into the ring buffer. Drain and discard them so
        // the buffer starts empty, residue would occupy space (a full buffer drops *new* events) and
        // could even misattribute onto a later sandbox whose recycled cgroup id collides.
        let _ = tracer.drain(|_| {});
        Ok(Self(Arc::new(Mutex::new(TracerInner {
            tracer,
            folds: HashMap::new(),
        }))))
    }

    /// Drain the shared ring buffer now, routing pending events to every registered sandbox's fold, and
    /// return how many were delivered (0 if the lock is poisoned). The buffer is drained automatically at
    /// each [`attach`](SandboxProbes::attach) and [`collect`](SandboxProbes::collect); a long-lived host
    /// process (the daemon later) calls this periodically between them so a busy VMM can't fill the
    /// buffer, a drop is counted by the kernel and surfaces as a coverage gap, but polling is what
    /// prevents it.
    pub fn poll(&self) -> usize {
        self.with(drain_route).unwrap_or(0)
    }

    /// Register one sandbox's cgroup: route pending events to their current owners, add the cgroup to
    /// the kernel target set, and open a **fresh** fold (replacing, not reusing, any stale fold a
    /// failed teardown left behind, cgroup ids are inode numbers and can recycle, and inheriting a
    /// dead run's fold would misattribute its events onto the new run).
    ///
    /// # Errors
    /// [`ProbeError`] if the lock is poisoned or the target write fails (the caller records a gap).
    fn register(&self, cgroup_id: u64) -> Result<(), ProbeError> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| ProbeError::Map("shared tracer lock poisoned".to_string()))?;
        drain_route(&mut inner);
        inner.tracer.add_target(cgroup_id)?;
        inner.folds.insert(cgroup_id, SyscallFold::new(cgroup_id));
        Ok(())
    }

    /// Finalize one sandbox: drain every pending event (routing all cgroups' events to their folds so no
    /// sandbox loses events to another's collect), then remove + finish this cgroup's fold and unregister
    /// it from the kernel set. `None` if the lock is poisoned or the fold is gone, the caller records
    /// that as a coverage gap rather than passing off an empty footprint as a quiet run.
    fn finalize(&self, cgroup_id: u64) -> Option<SyscallFootprint> {
        self.with(|inner| {
            drain_route(inner);
            // Best-effort unregister: this footprint is already drained, so a failure here can't
            // undercount *this* run. Its only downstream effect, the departed cgroup keeping the
            // host-global ring buffer under pressure, is not silent: those extra drops surface as
            // `AxisGap::HostSyscalls` ring-drop gaps in the *later* sandboxes' records (see `collect`).
            let _ = inner.tracer.remove_target(cgroup_id);
            inner.folds.remove(&cgroup_id).map(SyscallFold::finish)
        })
        .flatten()
    }

    /// A live, non-destructive read of one sandbox's footprint-so-far: drain pending events to every
    /// fold, then finish a **clone** of this cgroup's fold (the original keeps accumulating). `None` if
    /// the lock is poisoned or the fold is gone.
    fn snapshot_fold(&self, cgroup_id: u64) -> Option<SyscallFootprint> {
        self.with(|inner| {
            drain_route(inner);
            inner
                .folds
                .get(&cgroup_id)
                .map(|fold| fold.clone().finish())
        })
        .flatten()
    }

    /// Detach one sandbox without producing a footprint (the abandoned path): unregister its cgroup and
    /// drop its fold. Best-effort; a poisoned lock is a no-op (the fold goes with the process).
    fn detach(&self, cgroup_id: u64) {
        let _ = self.with(|inner| {
            let _ = inner.tracer.remove_target(cgroup_id);
            inner.folds.remove(&cgroup_id);
        });
    }

    /// The kernel's cumulative dropped-event count (a full ring buffer rejects writes), or `None` if it
    /// can't be read. [`attach`](SandboxProbes::attach) snapshots this and [`collect`](SandboxProbes::collect)
    /// reports a nonzero delta as a coverage gap: the drops are host-global (one shared buffer), so the
    /// attribution is approximate, but a footprint that *may* undercount says so instead of looking exact.
    fn drops(&self) -> Option<u64> {
        self.with(|inner| inner.tracer.dropped_events().ok())
            .flatten()
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
    gaps: Vec<AxisGap>,
    /// Set once [`collect`](Self::collect) has read + detached everything, so `Drop` is a no-op.
    finalized: bool,
}

impl SandboxProbes {
    /// Post-boot: bind every available probe to this one VM by plain values:
    /// - resolve the VMM's cgroup id and register it on the shared syscall tracer (its host-syscall
    ///   footprint accrues from here);
    /// - if `netns` + `tap` are present, attach a per-VM tap monitor, enforcing `egress` (armed before
    ///   the tc programs go live) when given, else observe-only;
    /// - register the cgroup as a target on the shared meter.
    ///
    /// Each sub-attach degrades to a recorded [`AxisGap`]; the returned bundle is always valid.
    pub fn attach(
        vmm_pid: u32,
        netns: Option<&str>,
        tap: Option<&str>,
        egress: Option<&EgressPolicy>,
        tracer: &SharedTracer,
        meter: &SharedMeter,
    ) -> SandboxProbes {
        let mut gaps: Vec<AxisGap> = Vec::new();

        // The cgroup id is the tracer + meter axis; resolve it from the pid (the plain-value bridge).
        let cgroup_id = match cgroup_id_of_pid(vmm_pid) {
            Ok(id) => Some(id),
            Err(e) => {
                gaps.push(AxisGap::Cpu(format!("resolve cgroup: {e}")));
                None
            }
        };

        // Host syscalls: register the cgroup on the shared tracer (opens its fold).
        let traced = match cgroup_id {
            Some(cgid) => match tracer.register(cgid) {
                Ok(()) => true,
                Err(e) => {
                    gaps.push(AxisGap::HostSyscalls(format!("register tracer: {e}")));
                    false
                }
            },
            None => {
                gaps.push(AxisGap::HostSyscalls(
                    "cgroup id unknown, cannot attribute host syscalls".to_string(),
                ));
                false
            }
        };

        // Attach the per-VM tap monitor. Absent netns/tap = no NIC: the network section is simply absent
        // (not a gap); an attach failure is a gap.
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
            tracer: tracer.clone(),
            traced,
            tap: tap_mon,
            meter: meter.clone(),
            metered,
            drops_at_attach: if traced { tracer.drops() } else { None },
            gaps,
            finalized: false,
        }
    }

    /// **Finalize + detach on close**: read the three probes into a [`RunRecord`] and
    /// unregister this run's cgroup from the shared tracer + meter. **Must run while the sandbox is still
    /// alive**, the cgroup dir and map fds must be live. `timing` comes from the caller
    /// (`Sandbox::boot_latency` + `RunResult::metrics.wall`), so the record never depends on `agent-vmm`.
    /// Each axis degrades to a recorded gap on a read error.
    pub fn collect(mut self, timing: Timing) -> RunRecord {
        // Host syscalls: drain + finish this cgroup's fold on the shared tracer (also unregisters it).
        // A lost fold or poisoned lock is a *recorded gap*, never an empty footprint passed off as a
        // quiet run.
        let had_tracer = matches!((self.traced, self.cgroup_id), (true, Some(_)));
        let host_syscalls = match (self.traced, self.cgroup_id) {
            (true, Some(cgid)) => match self.tracer.finalize(cgid) {
                Some(footprint) => footprint,
                None => {
                    self.gaps.push(AxisGap::HostSyscalls(
                        "shared tracer state unavailable at finalize (lock poisoned or fold lost)"
                            .to_string(),
                    ));
                    SyscallFootprint::default()
                }
            },
            _ => SyscallFootprint::default(),
        };
        self.traced = false;

        // The shared ring buffer is host-global; if the kernel counted drops during this run's window,
        // the footprint may undercount, say so instead of looking exact. And if the tracer was attached
        // but either endpoint of the delta is *unreadable*, the loss is unknown, still a gap (unknown
        // loss is loss), never silence.
        if had_tracer {
            match (self.drops_at_attach, self.tracer.drops()) {
                (Some(before), Some(after)) if after > before => {
                    self.gaps.push(AxisGap::HostSyscalls(format!(
                        "ring buffer dropped {} event(s) during this run's window; the footprint \
                         may undercount",
                        after - before
                    )));
                }
                (Some(_), Some(_)) => {} // both read, no increase: exact
                _ => self.gaps.push(AxisGap::HostSyscalls(
                    "ring-buffer event-loss counter unreadable at finalize; possible undercount"
                        .to_string(),
                )),
            }
        }

        // Network + denials from the one per-VM tap monitor. Totals are the section's spine (a section
        // without them would misread as "no traffic"), so their failure gaps the whole axis; a failed
        // flow/denial read keeps the rest and records exactly which read was lost.
        let network = match self.tap.as_ref() {
            Some(monitor) => match monitor.totals() {
                Err(e) => {
                    self.gaps
                        .push(AxisGap::Network(format!("read tap totals: {e}")));
                    None
                }
                Ok(totals) => {
                    let flows = monitor.flows().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap flows: {e}")));
                        Vec::new()
                    });
                    let denials = monitor.denials().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap denials: {e}")));
                        Vec::new()
                    });
                    // The kernel's full-map drop counters: nonzero means the flow table / denial
                    // rows saturated and this section undercounts, the loss must ride the record
                    // (a truncated section + a coverage gap), never read as a complete account.
                    // A failed *read* of a counter is its own gap, unknown loss is still loss.
                    let dropped_flows = monitor.dropped_flows().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap flow drops: {e}")));
                        0
                    });
                    let dropped_denials = monitor.dropped_denials().unwrap_or_else(|e| {
                        self.gaps
                            .push(AxisGap::Network(format!("read tap denial drops: {e}")));
                        0
                    });
                    if dropped_flows > 0 {
                        self.gaps.push(AxisGap::Network(format!(
                            "flow table full: {dropped_flows} new flow(s) dropped; flows and \
                             totals undercount"
                        )));
                    }
                    if dropped_denials > 0 {
                        self.gaps.push(AxisGap::Network(format!(
                            "denial table full: {dropped_denials} denied packet(s) missing a \
                             destination row (the packets were still dropped at the tap)"
                        )));
                    }
                    // Non-IPv4 (IPv6/VLAN) frames the flow view can't represent: not a flow, but their
                    // presence means the section is IPv4-only, not the whole picture, so gap it. A
                    // failed read of the counter is itself a gap (unknown coverage is a gap).
                    match monitor.unparsed_l3() {
                        Ok(n) if n > 0 => self.gaps.push(AxisGap::Network(format!(
                            "{n} non-IPv4 (IPv6/VLAN) frame(s) crossed the tap; the flow view covers \
                             IPv4 only, so this section is not the complete tap traffic"
                        ))),
                        Ok(_) => {}
                        Err(e) => self
                            .gaps
                            .push(AxisGap::Network(format!("read tap unparsed-L3 counter: {e}"))),
                    }
                    Some(NetSection::from_tap(
                        flows,
                        totals,
                        denials,
                        dropped_flows,
                        dropped_denials,
                    ))
                }
            },
            None => None,
        };

        // Resources: read the shared meter's CPU + the cgroup's native memory/IO *before* unregistering
        // (the cgroup dir must still be live). Every failure is a recorded gap, a record showing zero
        // CPU must mean "the sandbox used none", never "the read silently failed".
        let resources = match self.meter.with(|m| m.summary_for_pid(self.vmm_pid)) {
            Some(Ok(summary)) => summary,
            Some(Err(e)) => {
                self.gaps
                    .push(AxisGap::Cpu(format!("read resource summary: {e}")));
                crate::ResourceSummary::default()
            }
            None => {
                self.gaps
                    .push(AxisGap::Cpu("meter lock poisoned".to_string()));
                crate::ResourceSummary::default()
            }
        };
        if self.metered {
            if let Some(cgid) = self.cgroup_id {
                // Unregister *and* free the cgroup's `CPU_NS` row (the summary above already read
                // it), so a long-lived shared meter doesn't accumulate dead cgroups against the
                // map's fixed `MAX_CGROUPS` capacity. Both are best-effort teardown.
                let _ = self.meter.with(|m| {
                    let _ = m.remove_target(cgid);
                    m.clear(cgid)
                });
            }
            self.metered = false;
        }

        self.finalized = true;
        RunRecord::from_parts(
            network,
            resources,
            host_syscalls,
            timing,
            std::mem::take(&mut self.gaps),
        )
    }

    /// A **live, non-destructive** read of this sandbox's probes so far, the watcher's poll (a live
    /// view redraws from these mid-run). Each axis is a point-in-time reading: the syscall footprint
    /// accrued so far (a finished *clone*; the underlying fold keeps accumulating), the tap's
    /// flows/totals/denials now, and the meter's resource summary now. A transiently unreadable axis is
    /// `None`, the watcher keeps its last good view; the *authoritative*, gap-recording read is
    /// [`collect`](Self::collect), which this never disturbs.
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
            Some(NetSection::from_tap(
                flows,
                totals,
                denials,
                dropped_flows,
                dropped_denials,
            ))
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
/// live view (the CLI's `--watch` TUI, a daemon's stream) redraws from between attach and collect.
/// Pure data (no aya), so consumers that transform it (timeline diffing, rendering) stay host-safe
/// testable. An axis that couldn't be read *right now* is `None`; honesty about *why* an axis is
/// missing belongs to the final [`RunRecord`](crate::RunRecord)'s coverage, not here.
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
    /// per-VM tap detaches via its own aya `Ebpf` drop (nothing pinned, decision 020); its in-kernel
    /// filter is reclaimed by the sandbox's netns teardown.
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        if self.traced {
            if let Some(cgid) = self.cgroup_id {
                self.tracer.detach(cgid);
            }
        }
        if self.metered {
            if let Some(cgid) = self.cgroup_id {
                // Drop-path teardown with no final read: unregister and free the `CPU_NS` row so the
                // shared map doesn't accumulate this dead cgroup (mirrors `collect`).
                let _ = self.meter.with(|m| {
                    let _ = m.remove_target(cgid);
                    m.clear(cgid)
                });
            }
        }
    }
}
