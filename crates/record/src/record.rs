//! The fused per-run **audit record** and its pure builders.
//!
//! Defines the shape of "what a run did" as observed from *outside* the guest, plus the aggregation
//! that folds the probes' raw output into it. The attach machinery producing those inputs lives in
//! `bsx-probes-loader`, so keeping this half pure is what lets the whole aggregation be unit-tested on
//! the host gate with synthetic inputs, no KVM or caps. Every collection is deterministically sorted,
//! so a record built from the same observations is byte-stable regardless of map-iteration order. The
//! one exception is *which* distinct events [`MAX_NOTABLE`] keeps past its cap (arrival order); every
//! count stays exact and order-independent at any size.

use std::borrow::Cow;
use std::collections::btree_map::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use bsx_probes_common::{
    FlowCounts, FlowKey, FlowKey6, PolicyRule, PolicyRule6, Syscall, SyscallEvent,
};

use crate::{NetStats, ResourceSummary};

/// The cap on **distinct** notable syscalls kept in a footprint. Repetition is already collapsed into a
/// hit count, so this bounds cardinality: a run touching thousands of paths keeps the first `MAX_NOTABLE`
/// by arrival order and counts the rest. Only sample *membership* depends on arrival order once the cap
/// is exceeded; `total`, `by_kind`, and `overflow_events` stay exact whatever the order.
pub const MAX_NOTABLE: usize = 64;

/// **What** a record is about and **when** it happened, both part of the signed bytes: a signature
/// proves authenticity, not attribution, and a record that cannot be attributed cannot settle a dispute.
///
/// Deliberately **not** a tenant, which is the hoster's layer and a recorded non-goal. The engine reports
/// the identity it minted and the hoster maps that onto whatever its own layer tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordSubject {
    /// The sandbox's name (`bsx-<pid>-<seq>`), the same handle as its scratch dir and netns, so a record
    /// correlates with on-disk residue. Unique among live VMs; pair it with
    /// [`started_unix_ns`](Self::started_unix_ns) for a durable identity, since pids are reused.
    pub sandbox_id: String,
    /// Wall-clock start of the run, nanoseconds since the Unix epoch. Distinct from [`Timing`], which
    /// says how *long* a run took and never *when*, so without this a record cannot be placed on a
    /// timeline. `0` when the host clock could not be read.
    pub started_unix_ns: u64,
}

impl RecordSubject {
    /// Names a record's subject. Pass `0` for `started_unix_ns` when the host clock could not be read,
    /// which reads as "unstamped" rather than as the epoch.
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
    /// Host CPU from eBPF, plus the cgroup's native memory and IO counters.
    pub resources: ResourceSummary,
    /// The VMM's **host** syscall footprint, not in-guest syscalls. Bounded.
    pub host_syscalls: SyscallFootprint,
    /// Boot and exec wall time, supplied by the caller as plain [`Duration`]s, so the record never
    /// depends on `bsx` to learn them.
    pub timing: Timing,
    /// Which axes were unavailable, and why, so a partial record is legible rather than silently thin.
    pub coverage: Vec<AxisGap>,
}

impl RunRecord {
    /// Assembles a record from already-collected parts. Pure, no eBPF, so the unit tests exercise it
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

/// The network axis: per-VM totals, the per-flow breakdown, and the denied-egress trail, all read from
/// the one per-VM tap monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetSection {
    /// One sandbox's traffic summed across flows (the rollup a caller exports).
    pub totals: NetStats,
    /// Per-flow byte/packet counters, sorted deterministically by destination then source.
    pub flows: Vec<FlowRecord>,
    /// The IPv6 per-flow breakdown, sorted the same way. Separate from [`flows`](Self::flows) so a
    /// v4-only consumer is unaffected; [`totals`](Self::totals) sums both.
    pub flows6: Vec<FlowRecord6>,
    /// Destinations the egress policy blocked, with the dropped-packet count. **Aggregated by
    /// destination**, one row per blocked endpoint summed across guest source ports.
    pub denials: Vec<DenialRecord>,
    /// The IPv6 blocked-destination trail, aggregated and sorted like [`denials`](Self::denials).
    pub denials6: Vec<DenialRecord6>,
    /// New flows a full flow table could not admit, so their traffic is **absent** from
    /// [`flows`](Self::flows) and undercounted in [`totals`](Self::totals). Nonzero means the section is
    /// [`truncated`](Self::truncated), since a guest churning source ports must not be able to evict its
    /// real traffic from its own record silently.
    pub dropped_flows: u64,
    /// The [`dropped_flows`](Self::dropped_flows) twin for the denial trail. The packets were still
    /// dropped at the tap; only the audit row is missing.
    pub dropped_denials: u64,
    /// The egress policy in force, read back from the kernel, and the route the guest was given. `None`
    /// when not read. Without it a record cannot tell an unpoliced run from a policed one: zero flows and
    /// zero denials is the same shape either way, since the denial trail says what was refused, never what
    /// was permitted.
    pub posture: Option<EgressPosture>,
}

/// What the tap was actually enforcing, and whether the guest had a route to test it with.
///
/// Read back from the kernel maps after attach rather than restated from the caller's request, so a
/// policy that never reached the map reads as absent here instead of as applied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct EgressPosture {
    /// Whether the classifier is armed. `false` is observe-only, where every packet passes no matter
    /// what [`allowed`](Self::allowed) holds, which is why this rides alongside the rules rather than
    /// being inferred from a non-empty list.
    pub enforcing: bool,
    /// The live IPv4 rules the kernel holds, in slot order.
    pub allowed: Vec<PolicyRule>,
    /// The live IPv6 rules, in slot order.
    pub allowed6: Vec<PolicyRule6>,
    /// The default route the driver configured for the guest, if any. `None` is the sealed posture,
    /// where the guest can address nothing beyond the host end of its link, so an allowance naming
    /// anything further has nothing to act on.
    pub gateway: Option<Ipv4Addr>,
}

impl NetSection {
    /// Build a sorted section from the tap monitor's raw reads. Flows sort on the full 5-tuple; denials
    /// **aggregate by destination**, summing the kernel's per-5-tuple `DENIALS` rows per `(dst, port,
    /// proto)` into one row per blocked endpoint. Both collections are totally ordered, so the record is
    /// byte-stable across map-iteration order. `dropped_flows`/`dropped_denials` are the kernel's
    /// full-map drop counters, marking the section [`truncated`](Self::truncated) so a saturated table
    /// never reads as complete.
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
        // A BTreeMap keyed on the destination triple both sums the per-source entries and yields them
        // already in the total order.
        let mut by_dst: BTreeMap<(u32, u16, u8), u64> = BTreeMap::new();
        for (key, count) in denials {
            let slot = by_dst
                .entry((key.dst_addr, key.dst_port, key.proto))
                .or_insert(0);
            // Kernel-supplied counters are adversarial by this crate's bar, so a wraparound must not
            // corrupt the audit record.
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

    /// Attaches the egress posture read back from the kernel maps. A builder, so a caller that does not
    /// read the posture reports `None`, which says "not read" rather than implying an unpoliced run.
    #[must_use]
    pub fn with_posture(mut self, posture: EgressPosture) -> Self {
        self.posture = Some(posture);
        self
    }

    /// Folds the IPv6 half of the tap reads into a [`from_tap`](Self::from_tap) section, sorted and
    /// aggregated as the v4 ones and summed into [`totals`](Self::totals) for a dual-stack rollup. A
    /// builder, so a v4-only caller is untouched.
    ///
    /// **Call once.** The v6 counts fold into [`totals`](Self::totals) while [`flows6`](Self::flows6) is
    /// *replaced*, so a second call leaves the first call's bytes in the rollup with its flows gone.
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
        // Aggregated by destination triple, like the v4 path.
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

    /// Whether the section is **incomplete**, meaning a full kernel table dropped at least one flow or
    /// denial row and the counts undercount what crossed the tap. The per-section flag a consumer checks
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
/// ports, since the endpoint is the audit signal and the source of a dropped probe is noise.
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

/// Sorts a flow by destination first, then source, over the full 5-tuple, so the order is total and the
/// record byte-stable.
fn flow_order(k: &FlowKey) -> (u32, u16, u8, u32, u16) {
    (k.dst_addr, k.dst_port, k.proto, k.src_addr, k.src_port)
}

/// The IPv6 twin of [`flow_order`]. Addresses compare as their network-order bytes, which orders them
/// numerically since they are big-endian.
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
/// events. Repetition collapses into a hit count and the distinct set is capped at [`MAX_NOTABLE`], so
/// neither dimension grows without bound.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SyscallFootprint {
    /// Every attributed event, an exact `u64` counter, always O(1) memory.
    pub total: u64,
    /// Counts by syscall kind (an unrecognized discriminant lands in `unknown`).
    pub by_kind: SyscallCounts,
    /// Distinct `(kind, detail)` events with a hit count, sorted deterministically and capped at
    /// [`MAX_NOTABLE`].
    pub notable: Vec<NotableSyscall>,
    /// `true` if the cap was hit and events overflowed it.
    pub notable_truncated: bool,
    /// **Events**, not distinct keys, that overflowed the notable cap (one new path opened 1000 times past
    /// the cap adds 1000). Still tallied in [`by_kind`](Self::by_kind) and [`total`](Self::total); absent
    /// only from the [`notable`](Self::notable) sample, so this is exactly what the sample omits.
    pub overflow_events: u64,
}

impl SyscallFootprint {
    /// Folds a sequence of events into a footprint, keeping only those in `cgroup_id`. The convenience
    /// form of [`SyscallFold`] for callers that already have the events in hand.
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

/// Counts of the host syscalls the probes trace, by kind. Fixed fields, so it is deterministic by
/// construction with no ordering to stabilize.
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

/// A notable host syscall: its kind, the decoded detail, the `comm` that made it, and how many times this
/// exact `(kind, detail)` occurred. Where several `comm`s produced the same pair the **lexicographically
/// smallest** is kept, so which `comm` a row credits does not depend on ring-buffer arrival order.
/// Which rows exist can, past [`MAX_NOTABLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotableSyscall {
    /// Which syscall this entry is about.
    pub kind: Syscall,
    /// The decoded detail: an opened or exec'd path, or a connect target. A prefix rather than the
    /// whole value when [`truncated`](Self::truncated) is set.
    pub detail: String,
    /// The `comm` credited with it, lexicographically smallest when several produced the same
    /// `(kind, detail)`, so this field does not depend on ring-buffer arrival order.
    pub comm: String,
    /// How many times this exact `(kind, detail)` occurred.
    pub hits: u64,
    /// The path outran the probe's capture buffer, so [`detail`](Self::detail) is a **prefix**, not the
    /// path the guest used: the row names something never opened under that name, and distinct paths
    /// sharing a prefix alias into one entry, making [`hits`](Self::hits) a count of events not of opens.
    pub truncated: bool,
}

/// A streaming accumulator for [`SyscallFootprint`]: [`record`](Self::record) per event, then
/// [`finish`](Self::finish). Bounds memory *during* the fold, since past [`MAX_NOTABLE`] distinct events
/// further ones are counted rather than stored.
#[derive(Debug, Clone)]
pub struct SyscallFold {
    cgroup_id: u64,
    total: u64,
    by_kind: SyscallCounts,
    /// Keyed `kind → detail → accumulator`, nested rather than a flat pair key so
    /// [`record`](Self::record) can probe the inner map with a **borrowed** `&str` and the common repeat
    /// path allocates nothing. Both `BTreeMap` levels keep the total order, so
    /// [`finish`](Self::finish) flattens already-sorted.
    notable: BTreeMap<Syscall, BTreeMap<String, NotableAccum>>,
    /// Total distinct `(kind, detail)` entries across the nested map, for the [`MAX_NOTABLE`] check,
    /// since the outer map's `len()` counts kinds rather than entries.
    distinct: usize,
    overflow_events: u64,
}

/// The per-`(kind, detail)` accumulator. It carries no `kind`, since the map's outer key is that fact and
/// a copy here would be a second place for it to be wrong.
#[derive(Debug, Clone)]
struct NotableAccum {
    comm: String,
    hits: u64,
    /// Sticky, set by *any* event folded into this entry: a truncated capture and a complete one can share
    /// a key, and the honest merge of "certain" with "cut" is "cut".
    truncated: bool,
}

impl SyscallFold {
    /// Starts a fold scoped to one sandbox's cgroup. Events from any other cgroup are ignored.
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

    /// Folds one event in, a no-op if it belongs to a different cgroup.
    pub fn record(&mut self, ev: &SyscallEvent) {
        if ev.cgroup_id != self.cgroup_id {
            return;
        }
        self.total += 1;
        let kind = match ev.kind() {
            Some(k) => k,
            None => {
                // Counted, but no notable entry: an unknown discriminant's detail is unreliable.
                self.by_kind.unknown += 1;
                return;
            }
        };
        match kind {
            Syscall::Execve => self.by_kind.execve += 1,
            Syscall::Openat => self.by_kind.openat += 1,
            Syscall::Connect => self.by_kind.connect += 1,
        }
        // Probe with the borrowed render, so the common repeat path allocates nothing and the owned key
        // is built only on a vacant under-cap insert.
        let detail = ev.detail_display_cow();
        let inner = self.notable.entry(kind).or_default();
        if let Some(acc) = inner.get_mut(detail.as_ref()) {
            acc.hits += 1;
            acc.truncated |= ev.detail_truncated();
            // Smallest `comm`, not first to arrive: several processes commonly produce the same
            // `(kind, detail)`, so first-arrival would make this field vary with stream order. The
            // compare borrows `comm`; the owned copy is taken only on the rare replace.
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

    /// Finalizes into a sorted, capped [`SyscallFootprint`]. Flattening the nested `BTreeMap`s yields
    /// `(kind, detail)` in total order already, so no further sort key is needed.
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

    /// Produces a live non-destructive [`SyscallFootprint`] snapshot from references, without cloning the
    /// `BTreeMap` nodes.
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

/// Host-measured timing for one run, as plain [`Duration`]s the caller lifts from its own measurements,
/// so the record never depends on `bsx`.
///
/// A further measurement lands as a new field plus a `with_*` method, never a wider [`new`](Self::new):
/// the two-argument constructor is the pair every run has, and [`Default`] is all-zero "unmeasured".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Timing {
    /// Boot to userspace, as the caller measured it.
    pub boot: Duration,
    /// Host-observed wall time of the run's exec.
    pub exec_wall: Duration,
}

impl Timing {
    /// The boot latency and the exec wall time, the two measurements every run has.
    #[must_use]
    pub fn new(boot: Duration, exec_wall: Duration) -> Self {
        Self { boot, exec_wall }
    }
}

/// One observation axis that was unavailable, and why, carried in [`RunRecord::coverage`] so a partial
/// record explains its own gaps instead of looking complete.
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

    /// The name of the axis this gap is filed under, which is the spelling that reaches the signed
    /// record.
    #[must_use]
    pub fn axis(&self) -> &'static str {
        match self {
            Self::HostSyscalls(_) => "host_syscalls",
            Self::Network(_) => "network",
            Self::Cpu(_) => "cpu",
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
        // Without the flag, a path longer than the probe's buffer records as its own prefix in exactly the
        // shape of a path that fit, so the record would assert an open that never happened.
        let long = vec![b'a'; bsx_probes_common::DETAIL_CAP - 1];
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
        // Distinct paths sharing a prefix fold into one row, so "certain" merged with "cut" must be
        // "cut": the alternative lets one complete capture clear the doubt on a row that also stands for
        // something longer.
        let at_cap = vec![b'a'; bsx_probes_common::DETAIL_CAP - 1];
        let mut fold = SyscallFold::new(CG);
        fold.record(&ev(Syscall::Openat as u32, CG, &at_cap, "sh"));
        fold.record(&ev(Syscall::Openat as u32, CG, &at_cap, "sh"));
        let entry = fold.finish().notable.into_iter().next().expect("one entry");
        assert!(entry.truncated);
        assert_eq!(entry.hits, 2);
    }

    #[test]
    fn a_connect_is_never_reported_as_a_truncated_path() {
        // `connect` fills `detail_len` from the sockaddr snapshot rather than a string read, so the
        // cap-length test must not apply to it.
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
        // The unknown event produces no notable entry, so exactly the four known kinds survive.
        assert_eq!(
            f.notable.len(),
            4,
            "one notable per known-kind event, none for the unknown discriminant: {:?}",
            f.notable
        );
    }

    /// `notable`'s order sits inside the signed bytes, and its *kind* half is [`Syscall`]'s own `Ord`, so
    /// this pins it against what decides it: the enum's **explicit discriminants**, which are the wire
    /// values the probe writes. Reordering the arms is correctly a no-op; changing a discriminant must
    /// fail.
    #[test]
    fn notable_kinds_are_ordered_by_the_syscall_discriminants() {
        // Fed in descending discriminant order, so arrival order cannot produce the result.
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
        // `/etc/hostname` already took a slot, so of the `1 + MAX_NOTABLE + 10` distinct events offered,
        // `MAX_NOTABLE` are kept and 11 overflow.
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
        // The recorded `comm` must not depend on which event the ring buffer delivered first, or the signed
        // record would vary by stream order. Two comms in both orders must give byte-identical footprints,
        // with the smaller comm winning.
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

    /// [`SyscallFold::snapshot`] is the live-trace read and [`SyscallFold::finish`] the record's, two
    /// renderings of one fold that must say the same thing. `finish` is pinned by the goldens, so this pins
    /// `snapshot` to `finish` with a repeat, a truncation, an overflow, and an unknown discriminant in
    /// play.
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
        let long = vec![b'a'; bsx_probes_common::DETAIL_CAP - 1];
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
        // Every occurrence of a new path past the cap overflows, since the field counts events rather than
        // distinct keys.
        for _ in 0..3 {
            fold.record(&ev(Syscall::Openat as u32, CG, b"/late/arrival", "sh"));
        }
        // A repeat of a *stored* path lands on its entry rather than the overflow.
        fold.record(&ev(Syscall::Openat as u32, CG, b"/cap/0", "sh"));
        // An unknown discriminant is tallied in `by_kind.unknown` and `total` but has no notable key at
        // all, so it is neither notable nor overflow.
        fold.record(&ev(999, CG, b"", "sh"));
        let f = fold.finish();
        assert_eq!(f.notable.len(), MAX_NOTABLE);
        assert!(f.notable_truncated);
        assert_eq!(f.overflow_events, 3);
        assert_eq!(f.total, (MAX_NOTABLE as u64) + 3 + 1 + 1);
        // `by_kind` is always exact and complete, its per-kind totals sum to `total`, cap or not.
        let by_kind = f.by_kind.execve + f.by_kind.openat + f.by_kind.connect + f.by_kind.unknown;
        assert_eq!(by_kind, f.total);
        // `notable`'s hits are the known events the sample kept: total minus the overflow it omitted and the
        // unknowns it never had a key for.
        let attributed: u64 = f.notable.iter().map(|n| n.hits).sum();
        assert_eq!(attributed, f.total - f.overflow_events - f.by_kind.unknown);
    }

    #[test]
    fn denials_aggregate_by_destination_and_stay_byte_stable() {
        // The kernel keys denials by the full 5-tuple, so retries from different source ports arrive
        // separately and the record must aggregate them into one row per endpoint, stable across
        // map-iteration order.
        let dst = u32::from_be_bytes([9, 9, 9, 9]);
        let d = |sport: u16, count: u64| {
            (
                FlowKey::new(
                    u32::from_be_bytes([10, 200, 0, 2]),
                    dst,
                    sport,
                    443,
                    bsx_probes_common::IPPROTO_TCP,
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
        // Kernel-supplied counters are adversarial by this crate's bar, so two near-max counts must clamp
        // at the ceiling rather than wrap to a small number that reads a flood as a trickle.
        let dst = u32::from_be_bytes([9, 9, 9, 9]);
        let d = |sport: u16, count: u64| {
            (
                FlowKey::new(
                    u32::from_be_bytes([10, 200, 0, 2]),
                    dst,
                    sport,
                    443,
                    bsx_probes_common::IPPROTO_TCP,
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
        use bsx_probes_common::IPPROTO_TCP;
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
        // The shared tracer drains one interleaved stream and routes each event to its cgroup's fold, so
        // mirror that routing: each fold must see only its own cgroup.
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
        // A saw only its own three opens, two distinct and one repeated.
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
    /// builder rather than a second one, since a private copy here is what `testutil` exists to prevent.
    fn flow(dst: [u8; 4], dport: u16) -> (FlowKey, FlowCounts) {
        crate::testutil::flow(
            [10, 200, 0, 2],
            40000,
            dst,
            dport,
            bsx_probes_common::IPPROTO_TCP,
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
        // Either drop counter alone marks the section truncated, and the healthy `0/0` shape reads
        // complete, so a guest churning source ports can fill the table but not silence the loss.
        assert!(!a.truncated());
        assert!(NetSection::from_tap(vec![], totals, vec![], 1, 0).truncated());
        assert!(NetSection::from_tap(vec![], totals, vec![], 0, 1).truncated());
        assert_eq!(a.totals, totals); // totals passed through unchanged
    }

    #[test]
    fn full_record_is_stable_across_flow_input_order() {
        // The flow axis only: the syscall events below are passed unpermuted and are far under
        // `MAX_NOTABLE`, so this says nothing about arrival order on that axis. The two tests below
        // cover it.
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
                RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
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
    fn a_whole_footprint_below_the_notable_cap_is_stable_across_arrival_order() {
        // `notable_comm_is_independent_of_arrival_order` pins the tie-break on two events; this is the
        // property the crate header claims, on a full-scale stream: every distinct pair contested by
        // two `comm`s, the whole delivery reversed. Below the cap nothing is dropped, so the fold has
        // to land on the same bytes either way.
        //
        // The cap is where that stops, and the header says so: past `MAX_NOTABLE` the sample keeps
        // whichever distinct pairs arrived first. `footprint_dedups_repeats_and_caps_distinct` covers
        // what the cap guarantees in place of that.
        let mut events = Vec::new();
        for i in 0..(MAX_NOTABLE - 4) {
            let path = format!("/tmp/f-{i:04}");
            events.push(ev(Syscall::Openat as u32, CG, path.as_bytes(), "zsh"));
            events.push(ev(Syscall::Openat as u32, CG, path.as_bytes(), "bash"));
        }
        let forward = SyscallFootprint::from_events(CG, &events);
        events.reverse();
        let backward = SyscallFootprint::from_events(CG, &events);

        assert_eq!(forward, backward, "reversing the stream changed the record");
        assert_eq!(forward.notable.len(), MAX_NOTABLE - 4);
        assert!(!forward.notable_truncated, "this stream is under the cap");
        assert!(
            forward.notable.iter().all(|n| n.comm == "bash"),
            "and every row credits the smaller comm, not whichever arrived first"
        );
    }

    #[test]
    fn no_network_sandbox_yields_none_with_a_gap() {
        let record = RunRecord::from_parts(
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
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
            RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
            None,
            resources,
            SyscallFootprint::default(),
            timing,
            vec![],
        );
        assert_eq!(record.resources, resources);
        assert_eq!(record.timing, timing);
    }

    /// `Timing` is caller-constructed and `#[non_exhaustive]`, so a caller outside this crate reaches it
    /// only through these two doors. `new` is positional, and swapping its arguments is the silent failure
    /// this catches.
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
        // All-zero reads as "unmeasured", the starting point for a caller with only some measurements.
        assert_eq!(
            Timing::default(),
            Timing::new(Duration::ZERO, Duration::ZERO)
        );
    }
}
