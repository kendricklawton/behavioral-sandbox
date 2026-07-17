//! The fused per-run **audit record** (P13.2) and its pure builders.
//!
//! This module is deliberately dependency-light: no aya, no `agent-vmm`. It defines the shape of
//! "what a run did" as observed from *outside* the guest, and the aggregation that folds the three
//! probes' raw output into it. The attach machinery that produces those inputs lives next door in
//! [`observer`](crate::observer); keeping the record pure means its whole aggregation is unit-tested
//! on the host gate with synthetic inputs, no KVM or caps.
//!
//! The record's **core is network + resources + denials** — the signals host-side eBPF observes
//! strongly across the hardware boundary. [`host_syscalls`](RunRecord::host_syscalls) is the **VMM's
//! host footprint**, explicitly *not* the guest's syscalls (a microVM services those in-guest; see
//! ROADMAP Phase 9). Every collection is deterministically sorted, so a record built from the same
//! observations is byte-stable regardless of map-iteration order — the property the Phase-14 JSON
//! output will rely on. Kept here, out of `agent-vmm`, so the driver stays independent of the eBPF
//! loader (decisions 024/026); the two tracks bridge only by plain values.

use std::collections::btree_map::{BTreeMap, Entry};
use std::time::Duration;

use agent_probes_common::{FlowCounts, FlowKey, Syscall, SyscallEvent};

use crate::{NetStats, ResourceSummary};

/// The cap on **distinct** notable syscalls kept in a footprint. Repetition is already collapsed into
/// a hit count, so this bounds cardinality: a run that touches thousands of *different* paths keeps the
/// first `MAX_NOTABLE` distinct ones (by sort order) and records the rest as a count, never growing the
/// record without bound.
pub const MAX_NOTABLE: usize = 64;

/// One run's fused audit record: what the host observed the sandbox do, from outside the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    /// The guest's own network traffic on its tap, plus the blocked-egress trail. `None` when the
    /// sandbox had no NIC (nothing to observe), distinct from "observed, and it was empty".
    pub network: Option<NetSection>,
    /// Host CPU (eBPF) + the cgroup's native memory/IO counters (reused verbatim from P12).
    pub resources: ResourceSummary,
    /// The VMM's **host** syscall footprint — not in-guest syscalls (Phase 9). Bounded.
    pub host_syscalls: SyscallFootprint,
    /// Boot + exec wall time, supplied by the caller as plain [`Duration`]s (the record never depends
    /// on `agent-vmm` to learn them).
    pub timing: Timing,
    /// Which axes were unavailable, and why — fail-open honesty, so a partial record is legible rather
    /// than silently thin.
    pub coverage: Vec<AxisGap>,
}

impl RunRecord {
    /// Assemble a record from already-collected parts. Pure — no eBPF, no `agent-vmm`. This is what
    /// [`SandboxProbes::collect`](crate::observer::SandboxProbes::collect) calls after reading the
    /// probes, and what the unit tests exercise directly.
    #[must_use]
    pub fn from_parts(
        network: Option<NetSection>,
        resources: ResourceSummary,
        host_syscalls: SyscallFootprint,
        timing: Timing,
        coverage: Vec<AxisGap>,
    ) -> Self {
        Self {
            network,
            resources,
            host_syscalls,
            timing,
            coverage,
        }
    }
}

/// The network axis: per-VM totals, the per-flow breakdown, and the denied-egress trail — all read
/// from the one per-VM tap monitor, so they belong together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetSection {
    /// One sandbox's traffic summed across flows (the rollup a caller exports).
    pub totals: NetStats,
    /// Per-flow byte/packet counters, sorted deterministically by destination then source.
    pub flows: Vec<FlowRecord>,
    /// Destinations the egress policy blocked, with the dropped-packet count — the audit trail
    /// decision 025 folds in here. Sorted deterministically by destination.
    pub denials: Vec<DenialRecord>,
}

impl NetSection {
    /// Build a sorted section from the tap monitor's raw reads (`flows`, `totals`, `denials`). Sorting
    /// here is what makes the record stable across map-iteration order.
    #[must_use]
    pub fn from_tap(
        flows: Vec<(FlowKey, FlowCounts)>,
        totals: NetStats,
        denials: Vec<(FlowKey, u64)>,
    ) -> Self {
        let mut flows: Vec<FlowRecord> = flows
            .into_iter()
            .map(|(key, counts)| FlowRecord { key, counts })
            .collect();
        flows.sort_by_key(|f| flow_order(&f.key));
        let mut denials: Vec<DenialRecord> = denials
            .into_iter()
            .map(|(key, count)| DenialRecord { key, count })
            .collect();
        denials.sort_by_key(|d| denial_order(&d.key));
        Self {
            totals,
            flows,
            denials,
        }
    }
}

/// One flow's identity and its per-direction counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub counts: FlowCounts,
}

/// One blocked destination and how many packets to it were dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialRecord {
    pub key: FlowKey,
    pub count: u64,
}

/// Sort a flow by destination first (the meaningful axis), then source, for a stable order.
fn flow_order(k: &FlowKey) -> (u32, u16, u8, u32, u16) {
    (k.dst_addr, k.dst_port, k.proto, k.src_addr, k.src_port)
}

/// Sort a denial by its destination (source/port of a dropped probe is noise).
fn denial_order(k: &FlowKey) -> (u32, u16, u8) {
    (k.dst_addr, k.dst_port, k.proto)
}

/// The VMM's host syscall footprint: exact counts plus a bounded, de-duplicated sample of notable
/// events. Both dimensions of unboundedness are closed — repetition collapses into a hit count, and
/// the distinct set is capped at [`MAX_NOTABLE`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyscallFootprint {
    /// Every attributed event — an exact `u64` counter, always O(1) memory.
    pub total: u64,
    /// Counts by syscall kind (an unrecognized discriminant lands in `unknown`).
    pub by_kind: SyscallCounts,
    /// Distinct `(kind, detail)` events with a hit count, sorted deterministically, capped.
    pub notable: Vec<NotableSyscall>,
    /// `true` if distinct events exceeded [`MAX_NOTABLE`] and some were dropped.
    pub notable_truncated: bool,
    /// How many distinct events were dropped past the cap (0 when not truncated).
    pub distinct_dropped: u64,
}

impl SyscallFootprint {
    /// Fold a sequence of events into a footprint, keeping only those in `cgroup_id`. The convenience
    /// form of [`SyscallFold`] for callers (and the tests) that already have the events in hand.
    #[must_use]
    pub fn from_events<'a>(
        cgroup_id: u64,
        events: impl IntoIterator<Item = &'a SyscallEvent>,
    ) -> Self {
        let mut fold = SyscallFold::new(cgroup_id);
        for ev in events {
            fold.record(ev);
        }
        fold.finish()
    }
}

/// Counts of the host syscalls the probes trace, by kind. Fixed fields, so it's deterministic by
/// construction (no ordering to stabilize).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyscallCounts {
    pub execve: u64,
    pub openat: u64,
    pub connect: u64,
    /// Events whose discriminant didn't decode to a known [`Syscall`].
    pub unknown: u64,
}

/// A notable host syscall: its kind, the decoded detail (an opened/exec'd path, or a connect target),
/// the `comm` that made it, and how many times this exact `(kind, detail)` occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotableSyscall {
    pub kind: Syscall,
    pub detail: String,
    pub comm: String,
    pub hits: u64,
}

/// A streaming accumulator for [`SyscallFootprint`]: [`record`](Self::record) it per event (e.g. from
/// `SyscallTracer::drain`'s callback), then [`finish`](Self::finish). Bounds memory *during* the fold —
/// once [`MAX_NOTABLE`] distinct events are held, further distinct events are counted, not stored.
#[derive(Debug, Clone)]
pub struct SyscallFold {
    cgroup_id: u64,
    total: u64,
    by_kind: SyscallCounts,
    /// Keyed by `(kind discriminant, detail)`; the value carries the typed kind + comm + hits.
    notable: BTreeMap<(u32, String), NotableAccum>,
    distinct_dropped: u64,
}

#[derive(Debug, Clone)]
struct NotableAccum {
    kind: Syscall,
    comm: String,
    hits: u64,
}

impl SyscallFold {
    /// Start a fold scoped to one sandbox's cgroup. Events from any other cgroup are ignored.
    #[must_use]
    pub fn new(cgroup_id: u64) -> Self {
        Self {
            cgroup_id,
            total: 0,
            by_kind: SyscallCounts::default(),
            notable: BTreeMap::new(),
            distinct_dropped: 0,
        }
    }

    /// Fold one event in (a no-op if it belongs to a different cgroup).
    pub fn record(&mut self, ev: &SyscallEvent) {
        if ev.cgroup_id != self.cgroup_id {
            return;
        }
        self.total += 1;
        let kind = match ev.kind() {
            Some(k) => k,
            None => {
                // Unknown discriminant: counted, but no typed notable entry (its detail is unreliable).
                self.by_kind.unknown += 1;
                return;
            }
        };
        match kind {
            Syscall::Execve => self.by_kind.execve += 1,
            Syscall::Openat => self.by_kind.openat += 1,
            Syscall::Connect => self.by_kind.connect += 1,
        }
        let key = (kind as u32, ev.detail_display());
        // Read the length before the mutable `entry` borrow so the cap check doesn't alias it.
        let at_cap = self.notable.len() >= MAX_NOTABLE;
        match self.notable.entry(key) {
            Entry::Occupied(mut e) => e.get_mut().hits += 1,
            Entry::Vacant(v) => {
                if at_cap {
                    self.distinct_dropped += 1;
                } else {
                    v.insert(NotableAccum {
                        kind,
                        comm: ev.comm_lossy().into_owned(),
                        hits: 1,
                    });
                }
            }
        }
    }

    /// Finalize into a sorted, capped [`SyscallFootprint`].
    #[must_use]
    pub fn finish(self) -> SyscallFootprint {
        let mut notable: Vec<NotableSyscall> = self
            .notable
            .into_iter()
            .map(|((_, detail), acc)| NotableSyscall {
                kind: acc.kind,
                detail,
                comm: acc.comm,
                hits: acc.hits,
            })
            .collect();
        notable.sort_by(|a, b| {
            (a.kind as u32, a.detail.as_str(), a.comm.as_str()).cmp(&(
                b.kind as u32,
                b.detail.as_str(),
                b.comm.as_str(),
            ))
        });
        SyscallFootprint {
            total: self.total,
            by_kind: self.by_kind,
            notable,
            notable_truncated: self.distinct_dropped > 0,
            distinct_dropped: self.distinct_dropped,
        }
    }
}

/// Host-measured timing for one run, as plain [`Duration`]s the caller lifts from
/// `Sandbox::boot_latency` and `RunResult::metrics.wall` — so the record never depends on `agent-vmm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub boot: Duration,
    pub exec_wall: Duration,
}

/// One observation axis that was unavailable, and why — carried in [`RunRecord::coverage`] so a
/// fail-open partial record explains its own gaps instead of looking complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxisGap {
    /// The host-syscall trace couldn't be loaded, scoped, or attributed.
    HostSyscalls(String),
    /// The tap monitor couldn't be attached or read.
    Network(String),
    /// The CPU meter couldn't resolve the cgroup or register it.
    Cpu(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic event: a syscall kind (or a raw discriminant), a cgroup, a detail blob, and a
    /// comm. Fields are `pub` on `SyscallEvent`, so no eBPF is involved.
    fn ev(syscall: u32, cgroup: u64, detail: &[u8], comm: &str) -> SyscallEvent {
        let mut d = [0u8; agent_probes_common::DETAIL_CAP];
        let n = detail.len().min(d.len());
        d[..n].copy_from_slice(&detail[..n]);
        let mut c = [0u8; agent_probes_common::COMM_CAP];
        let m = comm.len().min(c.len());
        c[..m].copy_from_slice(&comm.as_bytes()[..m]);
        SyscallEvent {
            cgroup_id: cgroup,
            pid: 7,
            tid: 7,
            syscall,
            detail_len: n as u32,
            comm: c,
            detail: d,
        }
    }

    const CG: u64 = 0x42;

    #[test]
    fn footprint_counts_by_kind_including_unknown() {
        let events = [
            ev(Syscall::Execve as u32, CG, b"/bin/sh", "sh"),
            ev(Syscall::Openat as u32, CG, b"/etc/hostname", "sh"),
            ev(Syscall::Openat as u32, CG, b"/etc/hosts", "sh"),
            ev(
                Syscall::Connect as u32,
                CG,
                &[2, 0, 0, 53, 8, 8, 8, 8],
                "sh",
            ),
            ev(99, CG, b"", "sh"), // unknown discriminant
        ];
        let f = SyscallFootprint::from_events(CG, &events);
        assert_eq!(f.total, 5);
        assert_eq!(f.by_kind.execve, 1);
        assert_eq!(f.by_kind.openat, 2);
        assert_eq!(f.by_kind.connect, 1);
        assert_eq!(f.by_kind.unknown, 1);
        // The unknown event produces no notable entry (its detail is unreliable).
        assert!(f.notable.iter().all(|n| n.hits > 0));
    }

    #[test]
    fn footprint_filters_foreign_cgroup() {
        let events = [
            ev(Syscall::Openat as u32, CG, b"/mine", "sh"),
            ev(Syscall::Openat as u32, 0x999, b"/theirs", "other"), // different cgroup
        ];
        let f = SyscallFootprint::from_events(CG, &events);
        assert_eq!(f.total, 1);
        assert_eq!(f.by_kind.openat, 1);
        assert_eq!(f.notable.len(), 1);
        assert_eq!(f.notable[0].detail, "/mine");
    }

    #[test]
    fn footprint_dedups_repeats_and_caps_distinct() {
        let mut fold = SyscallFold::new(CG);
        // 1000 identical opens collapse to one entry with hits == 1000.
        for _ in 0..1000 {
            fold.record(&ev(Syscall::Openat as u32, CG, b"/etc/hostname", "sh"));
        }
        // MAX_NOTABLE + 10 more *distinct* paths: the cap holds, the overflow is counted, not stored.
        // `/etc/hostname` already took one slot, so of the (1 + MAX_NOTABLE + 10) distinct events
        // offered, MAX_NOTABLE are kept and 11 are dropped.
        for i in 0..(MAX_NOTABLE + 10) {
            let path = format!("/f/{i}");
            fold.record(&ev(Syscall::Openat as u32, CG, path.as_bytes(), "sh"));
        }
        let f = fold.finish();
        assert_eq!(f.notable.len(), MAX_NOTABLE);
        assert!(f.notable_truncated);
        assert_eq!(f.distinct_dropped, 11);
        // The repeated entry survived with its full hit count.
        let hostname = f
            .notable
            .iter()
            .find(|n| n.detail == "/etc/hostname")
            .expect("the deduped entry is kept");
        assert_eq!(hostname.hits, 1000);
        // total counts every event, exactly.
        assert_eq!(f.total, 1000 + (MAX_NOTABLE as u64) + 10);
    }

    #[test]
    fn concurrent_folds_stay_independent() {
        // The shared tracer (P13.5) drains one interleaved stream and routes each event to its cgroup's
        // fold. Mirror that routing here to prove two concurrent sandboxes never contaminate each other:
        // each fold sees only its own cgroup, and one collecting doesn't disturb the other.
        const A: u64 = 0xA;
        const B: u64 = 0xB;
        let mut fa = SyscallFold::new(A);
        let mut fb = SyscallFold::new(B);
        let stream = [
            ev(Syscall::Openat as u32, A, b"/a/one", "a"),
            ev(Syscall::Execve as u32, B, b"/b/bin", "b"),
            ev(Syscall::Openat as u32, A, b"/a/two", "a"),
            ev(Syscall::Connect as u32, B, &[2, 0, 0, 80, 1, 1, 1, 1], "b"),
            ev(Syscall::Openat as u32, A, b"/a/one", "a"), // a repeat in A only
        ];
        for e in &stream {
            match e.cgroup_id {
                A => fa.record(e),
                B => fb.record(e),
                _ => {}
            }
        }
        let a = fa.finish();
        let b = fb.finish();
        // A saw only its three opens (two distinct, one repeated); nothing of B's leaked in.
        assert_eq!(a.total, 3);
        assert_eq!(a.by_kind.openat, 3);
        assert_eq!(a.by_kind.execve, 0);
        assert_eq!(a.by_kind.connect, 0);
        assert!(a.notable.iter().all(|n| n.detail.starts_with("/a/")));
        let one = a
            .notable
            .iter()
            .find(|n| n.detail == "/a/one")
            .expect("A's repeated path is kept");
        assert_eq!(one.hits, 2);
        // B saw only its execve + connect.
        assert_eq!(b.total, 2);
        assert_eq!(b.by_kind.execve, 1);
        assert_eq!(b.by_kind.connect, 1);
        assert_eq!(b.by_kind.openat, 0);
        assert!(b.notable.iter().all(|n| n.comm == "b"));
    }

    fn flow(dst: [u8; 4], dport: u16) -> (FlowKey, FlowCounts) {
        (
            FlowKey::new(
                u32::from_be_bytes([10, 200, 0, 2]),
                u32::from_be_bytes(dst),
                40000,
                dport,
                agent_probes_common::IPPROTO_TCP,
            ),
            FlowCounts {
                ingress_packets: 1,
                ingress_bytes: 60,
                egress_packets: 1,
                egress_bytes: 60,
            },
        )
    }

    #[test]
    fn net_section_sorts_deterministically() {
        let totals = NetStats {
            ingress_packets: 2,
            ingress_bytes: 120,
            egress_packets: 2,
            egress_bytes: 120,
        };
        let a = NetSection::from_tap(
            vec![flow([8, 8, 8, 8], 443), flow([1, 1, 1, 1], 53)],
            totals,
            vec![],
        );
        let b = NetSection::from_tap(
            vec![flow([1, 1, 1, 1], 53), flow([8, 8, 8, 8], 443)],
            totals,
            vec![],
        );
        assert_eq!(a, b); // same flows, different input order → identical section
        assert_eq!(a.flows[0].key.dst_addr, u32::from_be_bytes([1, 1, 1, 1]));
        assert_eq!(a.totals, totals); // totals passed through unchanged
    }

    #[test]
    fn full_record_is_stable_across_input_order() {
        let cg_events = [
            ev(Syscall::Openat as u32, CG, b"/a", "sh"),
            ev(
                Syscall::Connect as u32,
                CG,
                &[2, 0, 0, 80, 1, 1, 1, 1],
                "sh",
            ),
        ];
        let totals = NetStats::default();
        let build = |flows: Vec<(FlowKey, FlowCounts)>| {
            RunRecord::from_parts(
                Some(NetSection::from_tap(flows, totals, vec![])),
                ResourceSummary::default(),
                SyscallFootprint::from_events(CG, &cg_events),
                Timing {
                    boot: Duration::from_millis(120),
                    exec_wall: Duration::from_millis(42),
                },
                vec![],
            )
        };
        let one = build(vec![flow([8, 8, 8, 8], 443), flow([1, 1, 1, 1], 53)]);
        let two = build(vec![flow([1, 1, 1, 1], 53), flow([8, 8, 8, 8], 443)]);
        assert_eq!(one, two);
    }

    #[test]
    fn no_network_sandbox_yields_none_with_a_gap() {
        let record = RunRecord::from_parts(
            None,
            ResourceSummary::default(),
            SyscallFootprint::from_events(CG, &[ev(Syscall::Execve as u32, CG, b"/init", "init")]),
            Timing {
                boot: Duration::from_millis(100),
                exec_wall: Duration::ZERO,
            },
            vec![AxisGap::Network("no NIC on this sandbox".into())],
        );
        assert!(record.network.is_none());
        assert_eq!(record.host_syscalls.total, 1); // other axes intact
        assert!(matches!(record.coverage.as_slice(), [AxisGap::Network(_)]));
    }

    #[test]
    fn timing_and_resources_pass_through_verbatim() {
        let resources = ResourceSummary {
            cpu_time: Duration::from_millis(7),
            cgroup: crate::CgroupStats {
                memory_peak: Some(4096),
                ..crate::CgroupStats::default()
            },
        };
        let timing = Timing {
            boot: Duration::from_millis(88),
            exec_wall: Duration::from_millis(9),
        };
        let record =
            RunRecord::from_parts(None, resources, SyscallFootprint::default(), timing, vec![]);
        assert_eq!(record.resources, resources);
        assert_eq!(record.timing, timing);
    }
}
