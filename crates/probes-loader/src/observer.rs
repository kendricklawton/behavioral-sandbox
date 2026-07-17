//! The attach bundle (P13.1/P13.5): bind the three host-side probes to one sandbox and roll their
//! output into a [`RunRecord`], and detach + finalize on close (P13.3).
//!
//! `agent-vmm` stays independent of this crate (decisions 024/026/028), so the bundle takes **plain
//! values** the driver already exposes — the VMM pid (→ its cgroup, for the syscall tracer and the CPU
//! meter) and the netns + tap names (for the network monitor) — never a `Sandbox`. The composition is
//! the caller's (the CLI/daemon later): a short launch sequence around `Sandbox::open`.
//!
//! **Both host-wide probes are shared, not per-VM (P13.5).** The `sched_switch` meter (decision 026) and
//! the three `sys_enter_*` tracepoints are *global*: a fresh copy per sandbox would run *N* programs on
//! every context switch / syscall (O(sandboxes) — the shape decision 026 rejects). So each is loaded
//! **once** for the host — [`SharedMeter`] and [`SharedTracer`] — and every sandbox registers its cgroup
//! as a *target* on both; the per-event cost stays a single hash lookup regardless of how many sandboxes
//! are live, and each shared map only ever holds the registered cgroups. The tap monitor is legitimately
//! per-VM (one tap, one sandbox) and owned by the bundle.
//!
//! **One post-boot attach.** Because both shared probes are already attached host-wide and a sandbox
//! only *registers its cgroup* (which exists once the jailer creates it during boot), there is no
//! per-VM program to stand up before boot: [`SandboxProbes::attach`] runs once, after `open`. The syscall
//! tracer therefore observes the VMM's host footprint from **registration onward**, not the pre-boot
//! window — a deliberate trade for the bounded-overhead shared model (decision 028); the record's core
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

/// A process-shared [`SyscallTracer`] (P13.5): loaded **once**, switched to set mode, and handed to every
/// sandbox's [`attach`](SandboxProbes::attach). One shared tracer serves all sandboxes — each registers
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
    /// target set — so nothing is emitted until a sandbox is registered via
    /// [`attach`](SandboxProbes::attach) (needs `CAP_BPF`+`CAP_PERFMON` + the object).
    ///
    /// # Errors
    /// [`ProbeError`] if the tracer can't be loaded/attached or the mode can't be set.
    pub fn load() -> Result<Self, ProbeError> {
        let mut tracer = SyscallTracer::load()?;
        tracer.use_target_set()?;
        Ok(Self(Arc::new(Mutex::new(TracerInner {
            tracer,
            folds: HashMap::new(),
        }))))
    }

    /// Register one sandbox's cgroup: add it to the kernel target set and open its fold.
    ///
    /// # Errors
    /// [`ProbeError`] if the lock is poisoned or the target write fails (the caller records a gap).
    fn register(&self, cgroup_id: u64) -> Result<(), ProbeError> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| ProbeError::Map("shared tracer lock poisoned".to_string()))?;
        inner.tracer.add_target(cgroup_id)?;
        inner
            .folds
            .entry(cgroup_id)
            .or_insert_with(|| SyscallFold::new(cgroup_id));
        Ok(())
    }

    /// Finalize one sandbox: drain every pending event (routing all cgroups' events to their folds so no
    /// sandbox loses events to another's collect), then remove + finish this cgroup's fold and unregister
    /// it from the kernel set. Default footprint if its fold is gone or the lock is poisoned (fail-open).
    fn finalize(&self, cgroup_id: u64) -> SyscallFootprint {
        self.with(|inner| {
            drain_route(inner);
            let _ = inner.tracer.remove_target(cgroup_id);
            inner
                .folds
                .remove(&cgroup_id)
                .map(SyscallFold::finish)
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    /// Detach one sandbox without producing a footprint (the abandoned path): unregister its cgroup and
    /// drop its fold. Best-effort; a poisoned lock is a no-op (the fold goes with the process).
    fn detach(&self, cgroup_id: u64) {
        let _ = self.with(|inner| {
            let _ = inner.tracer.remove_target(cgroup_id);
            inner.folds.remove(&cgroup_id);
        });
    }

    fn with<R>(&self, f: impl FnOnce(&mut TracerInner) -> R) -> Option<R> {
        self.0.lock().ok().map(|mut g| f(&mut g))
    }
}

/// Drain the tracer's ring buffer, routing each event to its cgroup's fold. Events for an unregistered
/// cgroup (a brief race at registration, or none under the set filter) are dropped. The disjoint-field
/// split lets the drain closure borrow `folds` while `tracer` drains.
fn drain_route(inner: &mut TracerInner) {
    let TracerInner { tracer, folds } = inner;
    let _ = tracer.drain(|ev: SyscallEvent| {
        if let Some(fold) = folds.get_mut(&ev.cgroup_id) {
            fold.record(&ev);
        }
    });
}

/// Live bundle for one VM: a target registration on the shared tracer + meter, the per-VM tap, and the
/// coverage gaps seen so far. [`collect`](Self::collect) finalizes it into a [`RunRecord`] (P13.3) while
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
    gaps: Vec<AxisGap>,
    /// Set once [`collect`](Self::collect) has read + detached everything, so `Drop` is a no-op.
    finalized: bool,
}

impl SandboxProbes {
    /// P13.1/P13.5, post-boot. Bind every available probe to this one VM by plain values:
    /// - resolve the VMM's cgroup id and register it on the shared syscall tracer (its host-syscall
    ///   footprint accrues from here);
    /// - if `netns` + `tap` are present, attach a per-VM tap monitor — enforcing `egress` (armed before
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
            gaps,
            finalized: false,
        }
    }

    /// P13.2/P13.3. **Finalize + detach on close**: read the three probes into a [`RunRecord`] and
    /// unregister this run's cgroup from the shared tracer + meter. **Must run while the sandbox is still
    /// alive** — the cgroup dir and map fds must be live. `timing` comes from the caller
    /// (`Sandbox::boot_latency` + `RunResult::metrics.wall`), so the record never depends on `agent-vmm`.
    /// Each axis degrades to a recorded gap on a read error.
    pub fn collect(mut self, timing: Timing) -> RunRecord {
        // Host syscalls: drain + finish this cgroup's fold on the shared tracer (also unregisters it).
        let host_syscalls = match (self.traced, self.cgroup_id) {
            (true, Some(cgid)) => self.tracer.finalize(cgid),
            _ => SyscallFootprint::default(),
        };
        self.traced = false;

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

        // Resources: read the shared meter's CPU + the cgroup's native memory/IO *before* unregistering
        // (the cgroup dir must still be live). Best-effort — a lost lock yields zero CPU.
        let resources = self
            .meter
            .with(|m| m.summary_for_pid(self.vmm_pid).ok())
            .flatten()
            .unwrap_or_default();
        if self.metered {
            if let Some(cgid) = self.cgroup_id {
                let _ = self.meter.with(|m| m.remove_target(cgid));
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

    /// The gaps recorded so far (which axes are unavailable and why) — useful to a caller before
    /// `collect`, e.g. to warn.
    #[must_use]
    pub fn coverage(&self) -> &[AxisGap] {
        &self.gaps
    }
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
                let _ = self.meter.with(|m| m.remove_target(cgid));
            }
        }
    }
}
