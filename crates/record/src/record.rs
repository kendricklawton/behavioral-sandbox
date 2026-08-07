//! The fused per-run **audit record** and its pure builders.
//!
//! It defines the shape of "what a run did" as observed from *outside* the guest, and the
//! aggregation that folds the three probes' raw output into it. The attach machinery that produces
//! those inputs lives in `ekvm-probes-loader`'s `observer`; keeping the record pure means its whole
//! aggregation is unit-tested on the host gate with synthetic inputs, no KVM or caps.
//!
//! The record's **core is network + resources + denials**, the signals host-side eBPF observes
//! strongly across the hardware boundary. [`host_syscalls`](RunRecord::host_syscalls) is the **VMM's
//! host footprint**, explicitly *not* the guest's syscalls (a microVM services those in-guest).
//! Every collection is deterministically sorted, so a record built from the same
//! observations is byte-stable regardless of map-iteration order, the property the JSON
//! output will rely on.

use std::borrow::Cow;
use std::collections::btree_map::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use ekvm_probes_common::{
    FlowCounts, FlowKey, FlowKey6, PolicyRule, PolicyRule6, Syscall, SyscallEvent,
};

use crate::{NetStats, ResourceSummary};

/// The cap on **distinct** notable syscalls kept in a footprint. Repetition is already collapsed into
/// a hit count, so this bounds cardinality: a run that touches thousands of *different* paths keeps
/// the first `MAX_NOTABLE` distinct ones **by arrival order** (the fold caps as events stream in;
/// sorting happens at `finish`, after membership is settled) and counts the rest, never growing the
/// record without bound.
pub const MAX_NOTABLE: usize = 64;

/// **What** a record is about and **when** it happened: the two questions a signature cannot answer.
///
/// A signature proves a record is authentic. It does not say which sandbox produced it, or when, so
/// an operator holding two records could not tell them apart, and a record that cannot be attributed
/// cannot settle a dispute. Both fields are therefore part of the signed bytes.
///
/// Deliberately **not** a tenant. The engine has no notion of one (that is the hoster's layer, a
/// recorded non-goal); it reports the identity it actually minted, and the hoster maps that to
/// whatever identity its own layer tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordSubject {
    /// The sandbox's name, `RunningVm::name` (`ekvm-<pid>-<seq>`). The same handle as its scratch
    /// dir and its netns, so a record can be correlated with on-disk residue and with the host's
    /// own view. Unique among live VMs; pair it with [`started_unix_ns`](Self::started_unix_ns)
    /// for a durable identity, since pids are reused after a driver exits.
    pub sandbox_id: String,
    /// Wall-clock start of the run, nanoseconds since the Unix epoch. Distinct from
    /// [`Timing`], which says how *long* the run took and never *when*: a record without this
    /// cannot be placed on a timeline or correlated with anything else the host logged. `0` when
    /// the host clock could not be read, the same fail-open honesty as [`RunRecord::coverage`].
    pub started_unix_ns: u64,
}

impl RecordSubject {
    /// Name a record's subject. `started_unix_ns` is wall-clock nanoseconds since the Unix epoch;
    /// pass `0` when the host clock could not be read, which reads as "unstamped" rather than as
    /// the epoch.
    #[must_use]
    pub fn new(sandbox_id: String, started_unix_ns: u64) -> Self {
        Self {
            sandbox_id,
            started_unix_ns,
        }
    }
}

/// One run's fused audit record: what the host observed the sandbox do, from outside the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunRecord {
    /// Which sandbox this describes, and when it ran.
    pub subject: RecordSubject,
    /// The guest's own network traffic on its tap, plus the blocked-egress trail. `None` when the
    /// sandbox had no NIC (nothing to observe), distinct from "observed, and it was empty".
    pub network: Option<NetSection>,
    /// Host CPU (eBPF) + the cgroup's native memory/IO counters (reused verbatim from the resource meter).
    pub resources: ResourceSummary,
    /// The VMM's **host** syscall footprint, not in-guest syscalls. Bounded.
    pub host_syscalls: SyscallFootprint,
    /// Boot + exec wall time, supplied by the caller as plain [`Duration`]s (the record never depends
    /// on `ekvm` to learn them).
    pub timing: Timing,
    /// Which axes were unavailable, and why, fail-open honesty, so a partial record is legible rather
    /// than silently thin.
    pub coverage: Vec<AxisGap>,
}

impl RunRecord {
    /// Assemble a record from already-collected parts. Pure, no eBPF. This is what the loader's
    /// `SandboxProbes::collect` calls after reading the probes, and what the unit tests exercise
    /// directly.
    #[must_use]
    pub fn from_parts(
        subject: RecordSubject,
        network: Option<NetSection>,
        resources: ResourceSummary,
        host_syscalls: SyscallFootprint,
        timing: Timing,
        coverage: Vec<AxisGap>,
    ) -> Self {
        Self {
            subject,
            network,
            resources,
            host_syscalls,
            timing,
            coverage,
        }
    }
}

/// The network axis: per-VM totals, the per-flow breakdown, and the denied-egress trail, all read
/// from the one per-VM tap monitor, so they belong together.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetSection {
    /// One sandbox's traffic summed across flows (the rollup a caller exports).
    pub totals: NetStats,
    /// Per-flow byte/packet counters, sorted deterministically by destination then source.
    pub flows: Vec<FlowRecord>,
    /// The IPv6 per-flow breakdown (dual-stack), sorted the same way. Separate from
    /// [`flows`](Self::flows) so a v4-only consumer is unaffected; [`totals`](Self::totals) sums both.
    pub flows6: Vec<FlowRecord6>,
    /// Destinations the egress policy blocked, with the dropped-packet count, the enforcement
    /// audit trail folded in here. **Aggregated by destination** (one row per blocked endpoint,
    /// summed across guest source ports) and sorted by that destination triple.
    pub denials: Vec<DenialRecord>,
    /// The IPv6 blocked-destination trail, aggregated and sorted like [`denials`](Self::denials).
    pub denials6: Vec<DenialRecord6>,
    /// New flows the kernel could not admit because the flow table was full: their traffic is
    /// **absent** from [`flows`](Self::flows) and undercounted in [`totals`](Self::totals). Nonzero
    /// means the section is [`truncated`](Self::truncated), a guest churning source ports must not
    /// be able to evict its real traffic from its own record *silently*.
    pub dropped_flows: u64,
    /// The [`dropped_flows`](Self::dropped_flows) twin for the denial trail: denied packets whose
    /// destination row a full map could not record (the packets were still dropped at the tap;
    /// only the audit row is missing).
    pub dropped_denials: u64,
    /// The egress policy in force, read back from the kernel, and the route the guest was given.
    /// `None` when the posture was not read, which is what a section built without
    /// [`with_posture`](Self::with_posture) reports.
    ///
    /// Without this a record cannot distinguish an unpoliced run from a policed one: zero flows and
    /// zero denials is the same shape whether every destination was allowed or none was. The denial
    /// trail says what was refused, never what was permitted.
    pub posture: Option<EgressPosture>,
}

/// What the tap was actually enforcing, and whether the guest had a route to test it with.
///
/// Read back from the kernel maps after attach rather than restated from the caller's request, so
/// it reports the rules the classifier will consult. The distinction is the point: a policy that
/// never reached the map reads as absent here instead of as applied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct EgressPosture {
    /// Whether the classifier is armed. `false` is observe-only, in which case every packet passes
    /// no matter what [`allowed`](Self::allowed) holds, which is why this rides alongside the rules
    /// rather than being inferred from a non-empty list.
    pub enforcing: bool,
    /// The live IPv4 rules the kernel holds, in slot order.
    pub allowed: Vec<PolicyRule>,
    /// The live IPv6 rules, in slot order.
    pub allowed6: Vec<PolicyRule6>,
    /// The default route the driver configured for the guest, when it configured one. `None` is the
    /// sealed posture: the guest can address nothing beyond the host end of its link, so an
    /// allowance naming anything further has nothing to act on.
    pub gateway: Option<Ipv4Addr>,
}

impl NetSection {
    /// Build a sorted section from the tap monitor's raw reads (`flows`, `totals`, `denials`). Flows
    /// sort on the full 5-tuple; denials **aggregate by destination**, the kernel keys `DENIALS` by
    /// the dropped packet's whole 5-tuple, so retries from different guest source ports arrive as
    /// separate entries, and summing them per `(dst, port, proto)` is what makes the trail both
    /// meaningful (one row per blocked endpoint) and totally ordered. Total orders on both
    /// collections are what make the record byte-stable across map-iteration order.
    ///
    /// `dropped_flows`/`dropped_denials` are the kernel's full-map drop counters: how many new
    /// flows / denial rows could **not** be recorded. They ride the section (and mark it
    /// [`truncated`](Self::truncated)) so a saturated table reads as truncated, never as complete.
    #[must_use]
    pub fn from_tap(
        flows: Vec<(FlowKey, FlowCounts)>,
        totals: NetStats,
        denials: Vec<(FlowKey, u64)>,
        dropped_flows: u64,
        dropped_denials: u64,
    ) -> Self {
        let mut flows: Vec<FlowRecord> = flows
            .into_iter()
            .map(|(key, counts)| FlowRecord { key, counts })
            .collect();
        flows.sort_by_key(|f| flow_order(&f.key));
        // Aggregate denials by destination triple. A BTreeMap keyed on the triple both sums the
        // per-source entries and yields them already in the total (dst, port, proto) order.
        let mut by_dst: BTreeMap<(u32, u16, u8), u64> = BTreeMap::new();
        for (key, count) in denials {
            let slot = by_dst
                .entry((key.dst_addr, key.dst_port, key.proto))
                .or_insert(0);
            // Saturate like the sibling totals/IO rollups: kernel-supplied counters are adversarial
            // by the crate's bar, so a wraparound (debug panic / release wrap) must not corrupt the
            // audit record.
            *slot = slot.saturating_add(count);
        }
        let denials = by_dst
            .into_iter()
            .map(|((dst_addr, dst_port, proto), count)| DenialRecord {
                dst_addr,
                dst_port,
                proto,
                count,
            })
            .collect();
        Self {
            totals,
            flows,
            flows6: Vec::new(),
            denials,
            denials6: Vec::new(),
            dropped_flows,
            dropped_denials,
            posture: None,
        }
    }

    /// Attach the egress posture read back from the kernel maps. A builder for the reason
    /// [`with_v6`](Self::with_v6) is one: every caller that does not read the posture is untouched
    /// and reports `None`, which says "not read" rather than implying an unpoliced run.
    #[must_use]
    pub fn with_posture(mut self, posture: EgressPosture) -> Self {
        self.posture = Some(posture);
        self
    }

    /// Fold the IPv6 half of the tap reads into a section built by [`from_tap`](Self::from_tap): the v6
    /// flows and denials, sorted/aggregated exactly as the v4 ones, and their byte/packet counts summed
    /// into [`totals`](Self::totals) so the rollup is dual-stack. A builder (not a `from_tap` parameter)
    /// so every v4-only caller and test is untouched; a section with no v6 traffic just carries empty
    /// v6 vectors. The v6 drop counters share the v4 `dropped_flows`/`dropped_denials` (a lost row is a
    /// lost row, whichever family), so [`truncated`](Self::truncated) already covers both.
    ///
    /// **Call once.** The v6 counts fold into [`totals`](Self::totals) while
    /// [`flows6`](Self::flows6) is *replaced*, so a second call leaves the first call's bytes in the
    /// rollup with its flows gone.
    #[must_use]
    pub fn with_v6(
        mut self,
        flows6: Vec<(FlowKey6, FlowCounts)>,
        denials6: Vec<(FlowKey6, u64)>,
    ) -> Self {
        let mut recs: Vec<FlowRecord6> = flows6
            .into_iter()
            .map(|(key, counts)| {
                self.totals.ingress_packets = self
                    .totals
                    .ingress_packets
                    .saturating_add(counts.ingress_packets);
                self.totals.ingress_bytes = self
                    .totals
                    .ingress_bytes
                    .saturating_add(counts.ingress_bytes);
                self.totals.egress_packets = self
                    .totals
                    .egress_packets
                    .saturating_add(counts.egress_packets);
                self.totals.egress_bytes =
                    self.totals.egress_bytes.saturating_add(counts.egress_bytes);
                FlowRecord6 { key, counts }
            })
            .collect();
        recs.sort_by_key(|r| flow_order6(&r.key));
        self.flows6 = recs;
        // Aggregate v6 denials by destination triple, like the v4 path.
        let mut by_dst: BTreeMap<([u8; 16], u16, u8), u64> = BTreeMap::new();
        for (key, count) in denials6 {
            let slot = by_dst
                .entry((key.dst_addr, key.dst_port, key.proto))
                .or_insert(0);
            *slot = slot.saturating_add(count);
        }
        self.denials6 = by_dst
            .into_iter()
            .map(|((dst_addr, dst_port, proto), count)| DenialRecord6 {
                dst_addr,
                dst_port,
                proto,
                count,
            })
            .collect();
        self
    }

    /// Whether the section is **incomplete**: the kernel dropped at least one flow or denial row
    /// because its table was full, so [`flows`](Self::flows)/[`totals`](Self::totals)/
    /// [`denials`](Self::denials) undercount what actually crossed the tap. A truncated section
    /// also carries a coverage gap on the record, this is the per-section flag a consumer checks
    /// before trusting the flow list as exhaustive.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.dropped_flows > 0 || self.dropped_denials > 0
    }
}

/// One flow's identity and its per-direction counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlowRecord {
    /// The flow's 5-tuple, as the kernel keyed it.
    pub key: FlowKey,
    /// Its per-direction byte and packet counters.
    pub counts: FlowCounts,
}

/// One blocked **destination** and how many packets to it were dropped, summed across guest source
/// ports (the source of a dropped probe is noise; the endpoint is the audit signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DenialRecord {
    /// Destination IPv4 address, host byte order (as [`FlowKey::dst_addr`]).
    pub dst_addr: u32,
    /// Destination L4 port.
    pub dst_port: u16,
    /// IP protocol number.
    pub proto: u8,
    /// Dropped packets to this destination, summed across all source 5-tuples.
    pub count: u64,
}

/// Sort a flow by destination first (the meaningful axis), then source, the full 5-tuple, so the
/// order is total and the record byte-stable.
fn flow_order(k: &FlowKey) -> (u32, u16, u8, u32, u16) {
    (k.dst_addr, k.dst_port, k.proto, k.src_addr, k.src_port)
}

/// The IPv6 twin of [`flow_order`]: destination-first total order over the v6 5-tuple (addresses
/// compared as their network-order bytes, which orders them numerically since they're big-endian).
fn flow_order6(k: &FlowKey6) -> ([u8; 16], u16, u8, [u8; 16], u16) {
    (k.dst_addr, k.dst_port, k.proto, k.src_addr, k.src_port)
}

/// One IPv6 flow's identity and its per-direction counters, the v6 twin of [`FlowRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlowRecord6 {
    /// The flow's v6 5-tuple, as the kernel keyed it.
    pub key: FlowKey6,
    /// Its per-direction byte and packet counters.
    pub counts: FlowCounts,
}

/// One blocked IPv6 **destination** and how many packets to it were dropped, the v6 twin of
/// [`DenialRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DenialRecord6 {
    /// Destination IPv6 address, network byte order (as [`FlowKey6::dst_addr`]).
    pub dst_addr: [u8; 16],
    /// Destination L4 port.
    pub dst_port: u16,
    /// IP protocol number.
    pub proto: u8,
    /// Dropped packets to this destination, summed across all source 5-tuples.
    pub count: u64,
}

/// The VMM's host syscall footprint: exact counts plus a bounded, de-duplicated sample of notable
/// events. Both dimensions of unboundedness are closed, repetition collapses into a hit count, and
/// the distinct set is capped at [`MAX_NOTABLE`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SyscallFootprint {
    /// Every attributed event, an exact `u64` counter, always O(1) memory.
    pub total: u64,
    /// Counts by syscall kind (an unrecognized discriminant lands in `unknown`).
    pub by_kind: SyscallCounts,
    /// Distinct `(kind, detail)` events with a hit count, sorted deterministically, capped at
    /// [`MAX_NOTABLE`] (kept by arrival order; see the const doc).
    pub notable: Vec<NotableSyscall>,
    /// `true` if the cap was hit and events overflowed it.
    pub notable_truncated: bool,
    /// **Events** (not distinct keys) that overflowed the notable cap: they arrived after it was full
    /// and matched no stored entry, so every occurrence counts (one new path opened 1000 times past the
    /// cap adds 1000). These are still tallied in [`by_kind`](Self::by_kind), whose per-kind totals sum
    /// to [`total`](Self::total) exactly, always, and absent only from the detailed [`notable`](Self::notable)
    /// sample. So the count is what the sample omits, making the truncation honest rather than silent.
    /// 0 when not truncated.
    pub overflow_events: u64,
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
#[non_exhaustive]
pub struct SyscallCounts {
    /// `execve` events attributed to this sandbox's cgroup.
    pub execve: u64,
    /// `openat` events.
    pub openat: u64,
    /// `connect` events.
    pub connect: u64,
    /// Events whose discriminant didn't decode to a known [`Syscall`].
    pub unknown: u64,
}

/// A notable host syscall: its kind, the decoded detail (an opened/exec'd path, or a connect target),
/// the `comm` that made it, and how many times this exact `(kind, detail)` occurred. When more than
/// one `comm` produced the same `(kind, detail)`, the **lexicographically smallest** is kept, an
/// order-independent choice, so the record stays byte-stable regardless of ring-buffer arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotableSyscall {
    /// Which syscall this entry is about.
    pub kind: Syscall,
    /// The decoded detail: an opened or exec'd path, or a connect target. A prefix rather than the
    /// whole value when [`truncated`](Self::truncated) is set.
    pub detail: String,
    /// The `comm` credited with it, lexicographically smallest when several produced the same
    /// `(kind, detail)`, so the record does not depend on ring-buffer arrival order.
    pub comm: String,
    /// How many times this exact `(kind, detail)` occurred.
    pub hits: u64,
    /// The path outran the probe's capture buffer, so [`detail`](Self::detail) is a **prefix**, not
    /// the path the guest used (see `SyscallEvent::detail_truncated`). Two consequences a reader
    /// has to know about: the row names something that was never opened under that name, and rows
    /// alias, since distinct paths sharing a prefix fold into one entry, making [`hits`](Self::hits)
    /// a count of events rather than of one path's opens.
    pub truncated: bool,
}

/// A streaming accumulator for [`SyscallFootprint`]: [`record`](Self::record) it per event (e.g. from
/// `SyscallTracer::drain`'s callback), then [`finish`](Self::finish). Bounds memory *during* the fold,
/// once [`MAX_NOTABLE`] distinct events are held, further distinct events are counted, not stored.
#[derive(Debug, Clone)]
pub struct SyscallFold {
    cgroup_id: u64,
    total: u64,
    by_kind: SyscallCounts,
    /// Keyed `kind → detail → accumulator` (the same `(kind, detail)` dedup as a flat pair key,
    /// nested so [`record`](Self::record) can probe the inner map with a **borrowed** `&str`: the
    /// common repeat path allocates nothing, the owned `String` is built only on a vacant under-cap
    /// insert). Both `BTreeMap` levels keep the total `(kind, detail)` order, so
    /// [`finish`](Self::finish) flattens already-sorted.
    notable: BTreeMap<Syscall, BTreeMap<String, NotableAccum>>,
    /// Total distinct `(kind, detail)` entries held across the nested map, the [`MAX_NOTABLE`] cap
    /// check (the outer map's `len()` counts kinds, not entries).
    distinct: usize,
    overflow_events: u64,
}

/// The per-`(kind, detail)` accumulator. It carries no `kind`: the map's outer key is that fact,
/// and a copy here would be a second place for it to be wrong.
#[derive(Debug, Clone)]
struct NotableAccum {
    comm: String,
    hits: u64,
    /// Sticky: set by *any* event folded into this entry. A truncated capture and a complete one
    /// can share a key (a path of exactly the cap length renders identically to a longer path's
    /// prefix), and the honest merge of "certain" with "cut" is "cut".
    truncated: bool,
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
            distinct: 0,
            overflow_events: 0,
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
        // Probe with the borrowed render (`Cow`): the common repeat path (`get_mut` by `&str`)
        // allocates nothing per event; the owned `String` key (and the comm) are built only on a
        // vacant, under-cap insert. This fold runs once per streamed ring-buffer event, so a
        // per-repeat allocation would be the record path's one avoidable hot-loop cost.
        let detail = ev.detail_display_cow();
        let inner = self.notable.entry(kind).or_default();
        if let Some(acc) = inner.get_mut(detail.as_ref()) {
            acc.hits += 1;
            acc.truncated |= ev.detail_truncated();
            // Attribute the lexicographically smallest `comm`, not the first to arrive. The same
            // `(kind, detail)` is commonly produced by more than one process (e.g. many binaries
            // `openat` `/etc/ld.so.cache`), so a first-arrival `comm` would make the record depend on
            // ring-buffer stream order, breaking the "same observations -> byte-stable record"
            // property signing relies on. The compare borrows `comm` (no alloc for a valid-UTF-8
            // comm, the common case); the owned copy is taken only on the rare replace.
            let comm = ev.comm_lossy();
            if comm.as_ref() < acc.comm.as_str() {
                acc.comm = comm.into_owned();
            }
        } else if self.distinct >= MAX_NOTABLE {
            self.overflow_events += 1;
        } else {
            inner.insert(
                detail.into_owned(),
                NotableAccum {
                    comm: ev.comm_lossy().into_owned(),
                    hits: 1,
                    truncated: ev.detail_truncated(),
                },
            );
            self.distinct += 1;
        }
    }

    /// Finalize into a sorted, capped [`SyscallFootprint`]. Flattening the nested `BTreeMap`s
    /// yields `(kind, detail)` in total order already (both levels are ordered, and an entry per
    /// `(kind, detail)` is unique, so no further sort key is needed), the same deterministic order
    /// the flat pair key produced.
    #[must_use]
    pub fn finish(self) -> SyscallFootprint {
        let notable: Vec<NotableSyscall> = self
            .notable
            .into_iter()
            .flat_map(|(kind, by_detail)| {
                by_detail
                    .into_iter()
                    .map(move |(detail, acc)| NotableSyscall {
                        kind,
                        detail,
                        comm: acc.comm,
                        hits: acc.hits,
                        truncated: acc.truncated,
                    })
            })
            .collect();
        SyscallFootprint {
            total: self.total,
            by_kind: self.by_kind,
            notable,
            notable_truncated: self.overflow_events > 0,
            overflow_events: self.overflow_events,
        }
    }

    /// Produce a live non-destructive [`SyscallFootprint`] snapshot from references without cloning
    /// the outer or inner `BTreeMap` nodes.
    #[must_use]
    pub fn snapshot(&self) -> SyscallFootprint {
        let notable: Vec<NotableSyscall> = self
            .notable
            .iter()
            .flat_map(|(kind, by_detail)| {
                by_detail.iter().map(move |(detail, acc)| NotableSyscall {
                    kind: *kind,
                    detail: detail.clone(),
                    comm: acc.comm.clone(),
                    hits: acc.hits,
                    truncated: acc.truncated,
                })
            })
            .collect();
        SyscallFootprint {
            total: self.total,
            by_kind: self.by_kind,
            notable,
            notable_truncated: self.overflow_events > 0,
            overflow_events: self.overflow_events,
        }
    }
}

/// Host-measured timing for one run, as plain [`Duration`]s the caller lifts from
/// `Sandbox::boot_latency` and `RunResult::metrics.wall`, so the record never depends on `ekvm`.
///
/// A further measurement lands as a new field plus a `with_*` method, never as a wider
/// [`new`](Self::new): the two-argument constructor is the pair every run has, and
/// [`Default`] (all-zero, "unmeasured", the [`RecordSubject::started_unix_ns`] posture) is the
/// starting point for a caller that has only some of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Timing {
    /// Boot to userspace, as the caller measured it.
    pub boot: Duration,
    /// Host-observed wall time of the run's exec.
    pub exec_wall: Duration,
}

impl Timing {
    /// The boot latency and the exec wall time, the two every run measures.
    #[must_use]
    pub fn new(boot: Duration, exec_wall: Duration) -> Self {
        Self { boot, exec_wall }
    }
}

/// One observation axis that was unavailable, and why, carried in [`RunRecord::coverage`] so a
/// fail-open partial record explains its own gaps instead of looking complete.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AxisGap {
    /// The host-syscall trace couldn't be loaded, scoped, or attributed.
    HostSyscalls(Cow<'static, str>),
    /// The tap monitor couldn't be attached or read.
    Network(Cow<'static, str>),
    /// The CPU meter couldn't resolve the cgroup or register it.
    Cpu(Cow<'static, str>),
}

impl AxisGap {
    /// The reason string carried by this gap.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::HostSyscalls(r) | Self::Network(r) | Self::Cpu(r) => r.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ev;

    const CG: u64 = 0x42;

    #[test]
    fn a_path_cut_at_the_cap_is_marked_not_passed_off_as_whole() {
        // The attack this closes: without the flag a path longer than the probe's buffer records
        // as its own prefix, in exactly the shape of a path that fit, so the record would assert
        // an open that never happened. Simulate what the probe produces for an over-long path (a full buffer,
        // NUL-terminated inside it, so `detail_len` is the cap minus the NUL).
        let long = vec![b'a'; ekvm_probes_common::DETAIL_CAP - 1];
        let mut fold = SyscallFold::new(CG);
        fold.record(&ev(Syscall::Openat as u32, CG, &long, "sh"));
        let short = fold_one(b"/etc/hostname");
        let footprint = fold.finish();

        let cut = footprint.notable.first().expect("one notable entry");
        assert!(
            cut.truncated,
            "a path that filled the capture buffer must be flagged, not shown as complete"
        );
        assert!(
            !short.truncated,
            "a path that fits must not be flagged: over-warning on every row would make the flag \
             meaningless"
        );
        // The renderings are pinned in json.rs and summary.rs, next to their own fixtures.
    }

    /// The single notable entry produced by folding one `openat` of `path`.
    fn fold_one(path: &[u8]) -> NotableSyscall {
        let mut fold = SyscallFold::new(CG);
        fold.record(&ev(Syscall::Openat as u32, CG, path, "sh"));
        fold.finish()
            .notable
            .into_iter()
            .next()
            .expect("one notable entry")
    }

    #[test]
    fn a_truncated_row_stays_truncated_when_a_complete_capture_joins_it() {
        // Distinct paths sharing a prefix fold into one row, so a row can mix a cut capture with an
        // exactly-fitting one. "Certain" merged with "cut" is "cut": the alternative lets one
        // complete capture clear the doubt on a row that also stands for something longer.
        let at_cap = vec![b'a'; ekvm_probes_common::DETAIL_CAP - 1];
        let mut fold = SyscallFold::new(CG);
        fold.record(&ev(Syscall::Openat as u32, CG, &at_cap, "sh"));
        fold.record(&ev(Syscall::Openat as u32, CG, &at_cap, "sh"));
        let entry = fold.finish().notable.into_iter().next().expect("one entry");
        assert!(entry.truncated);
        assert_eq!(entry.hits, 2);
    }

    #[test]
    fn a_connect_is_never_reported_as_a_truncated_path() {
        // `connect` fills `detail_len` from the sockaddr snapshot, not a string read, so the
        // cap-length test must not apply to it at all.
        let sockaddr = [2u8, 0, 0, 80, 127, 0, 0, 1];
        let entry = {
            let mut fold = SyscallFold::new(CG);
            fold.record(&ev(Syscall::Connect as u32, CG, &sockaddr, "curl"));
            fold.finish().notable.into_iter().next().expect("one entry")
        };
        assert!(!entry.truncated);
    }

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
        // The unknown event produces no notable entry (its detail is unreliable): exactly the four
        // known-kind events survive as notables.
        assert_eq!(
            f.notable.len(),
            4,
            "one notable per known-kind event, none for the unknown discriminant: {:?}",
            f.notable
        );
    }

    /// `notable` is ordered by `(kind, detail)`, and the *kind* half is now [`Syscall`]'s own
    /// `Ord` rather than a hand-rolled discriminant key. That ordering sits inside the signed
    /// bytes, so pin it against what actually decides it: the enum's **explicit discriminants**,
    /// which are the wire values the probe writes. Source order is not what is being asserted, and
    /// reordering the arms alone is correctly a no-op; changing a discriminant is what must fail.
    #[test]
    fn notable_kinds_are_ordered_by_the_syscall_discriminants() {
        // Fed in descending discriminant order, so arrival order cannot be what produces the result.
        let events = [
            ev(
                Syscall::Connect as u32,
                CG,
                &[2, 0, 0, 53, 8, 8, 8, 8],
                "sh",
            ),
            ev(Syscall::Openat as u32, CG, b"/etc/hosts", "sh"),
            ev(Syscall::Execve as u32, CG, b"/bin/sh", "sh"),
        ];
        let kinds: Vec<Syscall> = SyscallFootprint::from_events(CG, &events)
            .notable
            .iter()
            .map(|n| n.kind)
            .collect();
        assert_eq!(
            kinds,
            [Syscall::Execve, Syscall::Openat, Syscall::Connect],
            "notable kinds follow ascending Syscall discriminants, not arrival order"
        );
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
        // offered, MAX_NOTABLE are kept and 11 events overflow (each offered exactly once here).
        for i in 0..(MAX_NOTABLE + 10) {
            let path = format!("/f/{i}");
            fold.record(&ev(Syscall::Openat as u32, CG, path.as_bytes(), "sh"));
        }
        let f = fold.finish();
        assert_eq!(f.notable.len(), MAX_NOTABLE);
        assert!(f.notable_truncated);
        assert_eq!(f.overflow_events, 11);
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
    fn notable_comm_is_independent_of_arrival_order() {
        // The same (kind, detail) is commonly produced by more than one process. The recorded `comm`
        // must not depend on which event the ring buffer delivered first, or the signed record would
        // vary by stream order, breaking the "same observations -> byte-stable record" property.
        // Two comms, both orders: the footprints must be byte-identical, and the smaller comm wins.
        let a = SyscallFootprint::from_events(
            CG,
            &[
                ev(Syscall::Openat as u32, CG, b"/etc/ld.so.cache", "zsh"),
                ev(Syscall::Openat as u32, CG, b"/etc/ld.so.cache", "bash"),
            ],
        );
        let b = SyscallFootprint::from_events(
            CG,
            &[
                ev(Syscall::Openat as u32, CG, b"/etc/ld.so.cache", "bash"),
                ev(Syscall::Openat as u32, CG, b"/etc/ld.so.cache", "zsh"),
            ],
        );
        assert_eq!(a, b, "shuffled arrival order yields an identical footprint");
        assert_eq!(a.notable.len(), 1);
        assert_eq!(a.notable[0].hits, 2);
        assert_eq!(
            a.notable[0].comm, "bash",
            "the lexicographically smallest comm is kept, not the first to arrive"
        );
    }

    /// [`SyscallFold::snapshot`] is the live-trace read (the daemon's `trace` verb, the watch
    /// TUI) and [`SyscallFold::finish`] is the record's; they are two renderings of one fold and
    /// must say the same thing. `finish` is pinned by the goldens, so pin `snapshot` to `finish`:
    /// a fold mid-stream, with a repeat, a truncation, an overflow, and an unknown discriminant in
    /// play, must snapshot to exactly the footprint finishing it would produce.
    #[test]
    fn a_snapshot_reads_what_finish_would_write() {
        let mut fold = SyscallFold::new(CG);
        fold.record(&ev(
            Syscall::Connect as u32,
            CG,
            &[2, 0, 0, 80, 1, 1, 1, 1],
            "curl",
        ));
        fold.record(&ev(Syscall::Execve as u32, CG, b"/bin/sh", "sh"));
        fold.record(&ev(Syscall::Openat as u32, CG, b"/etc/hosts", "sh"));
        fold.record(&ev(Syscall::Openat as u32, CG, b"/etc/hosts", "zsh")); // repeat, comm contest
        let long = vec![b'a'; ekvm_probes_common::DETAIL_CAP - 1];
        fold.record(&ev(Syscall::Openat as u32, CG, &long, "sh")); // truncated capture
        fold.record(&ev(999, CG, b"", "sh")); // unknown discriminant
        for i in 0..MAX_NOTABLE + 2 {
            // Push past the cap so the overflow/truncation flags are live in both renderings.
            let path = format!("/spill/{i}");
            fold.record(&ev(Syscall::Openat as u32, CG, path.as_bytes(), "sh"));
        }
        assert_eq!(
            fold.snapshot(),
            fold.clone().finish(),
            "the live snapshot and the final record disagree about the same fold"
        );
    }

    #[test]
    fn overflow_counts_every_event_past_the_cap() {
        let mut fold = SyscallFold::new(CG);
        // Fill the cap exactly with distinct paths.
        for i in 0..MAX_NOTABLE {
            let path = format!("/cap/{i}");
            fold.record(&ev(Syscall::Openat as u32, CG, path.as_bytes(), "sh"));
        }
        // One *new* path, opened 3 times past the cap: every occurrence overflows (the field counts
        // events, not distinct keys, that is its documented meaning).
        for _ in 0..3 {
            fold.record(&ev(Syscall::Openat as u32, CG, b"/late/arrival", "sh"));
        }
        // A repeat of a *stored* path still lands on its entry, not in the overflow.
        fold.record(&ev(Syscall::Openat as u32, CG, b"/cap/0", "sh"));
        // An unknown-discriminant event: tallied in `by_kind.unknown` + `total`, but never notable and
        // never overflow (it has no notable key at all), so `by_kind` stays exact while `notable` doesn't.
        fold.record(&ev(999, CG, b"", "sh"));
        let f = fold.finish();
        assert_eq!(f.notable.len(), MAX_NOTABLE);
        assert!(f.notable_truncated);
        assert_eq!(f.overflow_events, 3);
        assert_eq!(f.total, (MAX_NOTABLE as u64) + 3 + 1 + 1);
        // `by_kind` is always exact and complete, its per-kind totals sum to `total`, cap or not.
        let by_kind = f.by_kind.execve + f.by_kind.openat + f.by_kind.connect + f.by_kind.unknown;
        assert_eq!(by_kind, f.total);
        // `notable`'s hits are the *known* events the sample kept: total minus the overflow it omitted
        // and minus the unknowns it never had a key for.
        let attributed: u64 = f.notable.iter().map(|n| n.hits).sum();
        assert_eq!(attributed, f.total - f.overflow_events - f.by_kind.unknown);
    }

    #[test]
    fn denials_aggregate_by_destination_and_stay_byte_stable() {
        // The kernel keys DENIALS by the full 5-tuple, so retries from different guest source ports
        // arrive as separate entries. The record aggregates them: one row per blocked endpoint,
        // stable across input (map-iteration) order.
        let dst = u32::from_be_bytes([9, 9, 9, 9]);
        let d = |sport: u16, count: u64| {
            (
                FlowKey::new(
                    u32::from_be_bytes([10, 200, 0, 2]),
                    dst,
                    sport,
                    443,
                    ekvm_probes_common::IPPROTO_TCP,
                ),
                count,
            )
        };
        let totals = NetStats::default();
        let a = NetSection::from_tap(vec![], totals, vec![d(40000, 3), d(40001, 4)], 0, 0);
        let b = NetSection::from_tap(vec![], totals, vec![d(40001, 4), d(40000, 3)], 0, 0);
        assert_eq!(a, b); // same observations, shuffled input → identical section
        assert_eq!(a.denials.len(), 1, "one row per blocked endpoint");
        assert_eq!(a.denials[0].dst_addr, dst);
        assert_eq!(a.denials[0].dst_port, 443);
        assert_eq!(a.denials[0].count, 7, "per-source counts are summed");
    }

    #[test]
    fn adversarial_denial_counts_saturate_instead_of_wrapping() {
        // Kernel-supplied counters are adversarial by this crate's bar: two near-max per-source
        // counts summing over `u64::MAX` must clamp at the ceiling, never wrap to a small number
        // that would make a flood read as a trickle in the audit record.
        let dst = u32::from_be_bytes([9, 9, 9, 9]);
        let d = |sport: u16, count: u64| {
            (
                FlowKey::new(
                    u32::from_be_bytes([10, 200, 0, 2]),
                    dst,
                    sport,
                    443,
                    ekvm_probes_common::IPPROTO_TCP,
                ),
                count,
            )
        };
        let section = NetSection::from_tap(
            vec![],
            NetStats::default(),
            vec![d(40000, u64::MAX - 1), d(40001, 5)],
            0,
            0,
        );
        assert_eq!(section.denials.len(), 1);
        assert_eq!(
            section.denials[0].count,
            u64::MAX,
            "an overflowing sum must saturate, not wrap"
        );
    }

    #[test]
    fn with_v6_folds_totals_sorts_flows_and_aggregates_denials() {
        use ekvm_probes_common::IPPROTO_TCP;
        let ula = |n: u8| {
            let mut a = [0u8; 16];
            a[0] = 0xfd;
            a[2] = 0x02;
            a[15] = n;
            a
        };
        let counts = FlowCounts {
            ingress_packets: 1,
            ingress_bytes: 100,
            egress_packets: 2,
            egress_bytes: 200,
        };
        let f = |dst: u8| {
            (
                FlowKey6::new(ula(2), ula(dst), 40000, 443, IPPROTO_TCP),
                counts,
            )
        };
        let dn = |dst: u8, c: u64| (FlowKey6::new(ula(2), ula(dst), 55555, 443, IPPROTO_TCP), c);
        // Two v6 flows + two denials to one endpoint, fed in two different orders.
        let a = NetSection::from_tap(vec![], NetStats::default(), vec![], 0, 0)
            .with_v6(vec![f(9), f(1)], vec![dn(7, 3), dn(7, 4)]);
        let b = NetSection::from_tap(vec![], NetStats::default(), vec![], 0, 0)
            .with_v6(vec![f(1), f(9)], vec![dn(7, 4), dn(7, 3)]);
        assert_eq!(a, b, "shuffled v6 input yields an identical section");
        // Flows sorted by destination (::1 before ::9); totals summed across both v6 flows.
        assert_eq!(a.flows6.len(), 2);
        assert_eq!(a.flows6[0].key.dst_addr, ula(1));
        assert_eq!(
            a.totals.egress_bytes, 400,
            "both v6 flows' bytes fold into totals"
        );
        // Denials aggregated to one per-endpoint row.
        assert_eq!(a.denials6.len(), 1);
        assert_eq!(a.denials6[0].dst_addr, ula(7));
        assert_eq!(a.denials6[0].count, 7, "per-source v6 denials summed");
    }

    #[test]
    fn concurrent_folds_stay_independent() {
        // The shared tracer drains one interleaved stream and routes each event to its cgroup's
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

    /// A flow to `dst:dport` from the fixed guest address, over the shared [`crate::testutil::flow`]
    /// builder rather than a second one: a private copy here is what `testutil` exists to prevent,
    /// and its counters had already drifted from the shared ones.
    fn flow(dst: [u8; 4], dport: u16) -> (FlowKey, FlowCounts) {
        crate::testutil::flow(
            [10, 200, 0, 2],
            40000,
            dst,
            dport,
            ekvm_probes_common::IPPROTO_TCP,
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
            0,
            0,
        );
        let b = NetSection::from_tap(
            vec![flow([1, 1, 1, 1], 53), flow([8, 8, 8, 8], 443)],
            totals,
            vec![],
            0,
            0,
        );
        assert_eq!(a, b); // same flows, different input order → identical section
        assert_eq!(a.flows[0].key.dst_addr, u32::from_be_bytes([1, 1, 1, 1]));
        // A full kernel table marks the section truncated: either counter alone is enough, and the
        // healthy shape (0/0) reads complete. This is the honest-loss contract of the denial
        // trail: a guest churning source ports can fill the table but not silence the loss.
        assert!(!a.truncated());
        assert!(NetSection::from_tap(vec![], totals, vec![], 1, 0).truncated());
        assert!(NetSection::from_tap(vec![], totals, vec![], 0, 1).truncated());
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
                RecordSubject::new("ekvm-4242-0".into(), 1_700_000_000_000_000_000),
                Some(NetSection::from_tap(flows, totals, vec![], 0, 0)),
                ResourceSummary::default(),
                SyscallFootprint::from_events(CG, &cg_events),
                Timing::new(Duration::from_millis(120), Duration::from_millis(42)),
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
            RecordSubject::new("ekvm-4242-0".into(), 1_700_000_000_000_000_000),
            None,
            ResourceSummary::default(),
            SyscallFootprint::from_events(CG, &[ev(Syscall::Execve as u32, CG, b"/init", "init")]),
            Timing::new(Duration::from_millis(100), Duration::ZERO),
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
        let timing = Timing::new(Duration::from_millis(88), Duration::from_millis(9));
        let record = RunRecord::from_parts(
            RecordSubject::new("ekvm-4242-0".into(), 1_700_000_000_000_000_000),
            None,
            resources,
            SyscallFootprint::default(),
            timing,
            vec![],
        );
        assert_eq!(record.resources, resources);
        assert_eq!(record.timing, timing);
    }

    /// `Timing` is caller-constructed and `#[non_exhaustive]`, so a caller outside this crate
    /// reaches it only through these two doors. Pin what each one puts where: `new` is positional,
    /// and swapping its arguments is the silent failure the assertion below exists to catch.
    #[test]
    fn timing_is_reachable_by_constructor_and_default_only() {
        let t = Timing::new(Duration::from_millis(88), Duration::from_millis(9));
        assert_eq!(
            t.boot,
            Duration::from_millis(88),
            "boot is the first argument"
        );
        assert_eq!(
            t.exec_wall,
            Duration::from_millis(9),
            "exec_wall is the second argument"
        );
        // All-zero reads as "unmeasured", the starting point for a caller that has only some of
        // the measurements; a future field joins it without touching this assertion.
        assert_eq!(
            Timing::default(),
            Timing::new(Duration::ZERO, Duration::ZERO)
        );
    }
}
