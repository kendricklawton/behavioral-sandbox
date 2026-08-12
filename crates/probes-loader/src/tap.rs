//! The per-VM tap monitor: the tc classifiers on the VM's network device, the flow and denial
//! maps they populate, and the netns join needed to attach inside the VM's namespace.

use std::fs::File;
use std::net::Ipv4Addr;
use std::path::Path;

use aya::Ebpf;
use aya::maps::{Array, HashMap as AyaHashMap};
use aya::programs::tc::{NlOptions, SchedClassifierLinkId, TcAttachOptions};
use aya::programs::{LinkOrder, SchedClassifier, TcAttachType, tc};
use bsx_probes_common::{
    FLOW_COUNTS_SIZE, FLOW_KEY_SIZE, FLOW_KEY6_SIZE, FlowCounts, FlowKey, FlowKey6,
    MAX_POLICY_RULES, POLICY_RULE_SIZE, POLICY_RULE6_SIZE, PolicyRule, PolicyRule6,
};

use bsx_record::{EgressPosture, NetStats};

use crate::egress::{EgressPolicy, PolicyError};
use crate::tracer::per_cpu_sum;
use crate::{ProbeError, check_support, load_object};

/// The two `tc` classifier programs [`TapMonitor`] attaches (their `#[classifier] fn` symbols in
/// `crates/probes`), one per clsact hook.
const CLS_INGRESS: &str = "tap_ingress";
const CLS_EGRESS: &str = "tap_egress";
/// The per-flow counter map the classifiers write (`#[map] static FLOWS`), and its IPv6 twin
/// (`#[map] static FLOWS6`), read by [`TapMonitor::flows`]/[`flows6`](TapMonitor::flows6).
const FLOWS_MAP: &str = "FLOWS";
const FLOWS6_MAP: &str = "FLOWS6";
/// The egress allow-list the ingress classifier consults (`#[map] static POLICY`), its IPv6 twin
/// (`#[map] static POLICY6`), and the enforcement toggle (`#[map] static ENFORCE`) that arms them, the
/// maps [`TapMonitor::set_egress_policy`] writes.
const POLICY_MAP: &str = "POLICY";
const POLICY6_MAP: &str = "POLICY6";
const ENFORCE_MAP: &str = "ENFORCE";
/// The per-destination denied-packet counters the enforcement drop path records (`#[map] static
/// DENIALS`), its IPv6 twin (`#[map] static DENIALS6`), read back by
/// [`TapMonitor::denials`]/[`denials6`](TapMonitor::denials6), the audit trail of blocked endpoints.
const DENIALS_MAP: &str = "DENIALS";
const DENIALS6_MAP: &str = "DENIALS6";
/// The per-CPU counter of new flows a full `FLOWS` map dropped (`#[map] static FLOW_DROPS`), read by
/// [`TapMonitor::dropped_flows`] so a saturated flow table is reported, never a silently thinner
/// record (the `EVENT_DROPS` discipline, applied to the network axis).
const FLOW_DROPS_MAP: &str = "FLOW_DROPS";
/// The [`FLOW_DROPS_MAP`] twin for denial rows (`#[map] static DENIAL_DROPS`), read by
/// [`TapMonitor::dropped_denials`].
const DENIAL_DROPS_MAP: &str = "DENIAL_DROPS";
/// The per-CPU counter of frames the tap saw but the flow parser can't represent (IPv6, VLAN,
/// or a truncated/malformed IPv4 frame; `#[map] static UNPARSED_L3`), read by
/// [`TapMonitor::unparsed_l3`] so the network section is gapped rather than silently omitting
/// them.
const UNPARSED_L3_MAP: &str = "UNPARSED_L3";
/// Where `ip netns` bind-mounts a named network namespace's handle (matches the driver's own
/// `netns_path`), so [`TapMonitor::attach_in_netns`] can open a sandbox's netns by name.
const NETNS_DIR: &str = "/run/netns";

/// A loaded, attached network-flow monitor: `tc`/clsact classifiers on a VM's tap that count
/// bytes/packets per IPv4 flow per direction into a map [`flows`](Self::flows) / [`totals`](Self::totals)
/// read. Owns the aya [`Ebpf`] (programs, map, live attachments). Bind it to the *specific* tap the
/// driver named for one sandbox with [`attach_in_netns`](Self::attach_in_netns) (its `fc0` inside its
/// netns), or to an interface in the current netns with [`attach`](Self::attach).
///
/// **Lifetime.** Dropping the monitor frees its userspace handles (the map and program fds). The
/// in-kernel `tc` filter it left on the tap is reclaimed by the sandbox's **netns teardown** (`ip netns
/// del` cascades the tap, its clsact qdisc, and the filters away), so a torn-down
/// sandbox leaves no dangling program even if the loader is gone, and nothing is pinned.
#[must_use = "dropping a TapMonitor frees its userspace handles and stops observing (for an interface \
              in the current netns it also detaches; a netns-attached filter goes with the netns teardown)"]
pub struct TapMonitor {
    ebpf: Ebpf,
}

impl TapMonitor {
    /// Attach both classifiers to `interface` **in the current network namespace**, adding a clsact
    /// qdisc first (which gives the device its `tc` ingress and egress hooks). From here every IPv4
    /// frame crossing that interface is counted against its flow until this is dropped. For an interface in
    /// the caller's own netns; for a sandbox's tap, which lives in the
    /// sandbox's netns, use [`attach_in_netns`](Self::attach_in_netns).
    ///
    /// # Errors
    /// [`ProbeError::Unsupported`] if the host can't load eBPF, [`ProbeError::Object`] if the object can't
    /// be read, [`ProbeError::Load`] if the kernel rejects it, or [`ProbeError::Attach`] if adding the qdisc
    /// or a classifier attach
    /// fails (the clsact qdisc needs `CAP_NET_ADMIN`, and `interface` must exist).
    pub fn attach(interface: &str) -> Result<Self, ProbeError> {
        check_support()?;
        let mut ebpf = load_classifiers()?;
        // The current netns persists, so keep the links and let aya's drop detach them here.
        attach_classifiers(&mut ebpf, interface, false)?;
        Ok(Self { ebpf })
    }

    /// Bind the monitor to the **specific tap the driver named for one sandbox**: that tap lives
    /// inside the sandbox's own network namespace, so this enters that netns by name (via
    /// its `/run/netns/<netns>` handle, attaches both classifiers to `interface` there, and returns the
    /// calling thread to the caller's netns. Hand it a sandbox's netns name and tap name (typically
    /// `"fc0"`) and the trace is scoped to exactly that sandbox's traffic. The map is read afterward from
    /// the caller's netns as usual (map fds are not namespace-scoped).
    ///
    /// # Errors
    /// As [`attach`](Self::attach), plus [`ProbeError::Attach`] if the netns handle can't be opened or
    /// entered (the netns must exist and `setns` needs `CAP_SYS_ADMIN`/root).
    pub fn attach_in_netns(netns: &str, interface: &str) -> Result<Self, ProbeError> {
        check_support()?;
        // Load and verify the programs in the caller's netns, since creating maps and loading programs is
        // not
        // namespace-scoped); only the `tc` attach must run inside the sandbox's netns.
        let mut ebpf = load_classifiers()?;
        let handle = Path::new(NETNS_DIR).join(netns);
        // Netns-attached, so forget the links: aya's drop would otherwise fire a wrong-netns
        // filter-delete, and the
        // sandbox's netns teardown reclaims the in-kernel filter.
        with_netns(&handle, || attach_classifiers(&mut ebpf, interface, true))?;
        Ok(Self { ebpf })
    }

    /// The current per-flow counters as `(FlowKey, FlowCounts)` pairs, read from the `FLOWS` map in
    /// unspecified hash-map order. The map is read as raw key/value byte arrays and decoded
    /// with the shared `FlowKey::from_bytes` / `FlowCounts::from_bytes`, so the loader needs no `unsafe`
    /// map-type binding and the record stays single-sourced with the kernel writer.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn flows(&self) -> Result<Vec<(FlowKey, FlowCounts)>, ProbeError> {
        let mut out = Vec::new();
        self.for_each_flow(|key, counts| out.push((key, counts)))?;
        Ok(out)
    }

    /// Iterate the `FLOWS` map, decoding each raw key/value with the shared `from_bytes` and handing the
    /// pair to `f`. The single map read [`flows`](Self::flows) and [`totals`](Self::totals) share, so
    /// neither has to build a `Vec` the other would too: `flows` collects, `totals` folds in place. A
    /// key or value whose size can't decode is a **hard** [`ProbeError::Map`] (the kernel record drifted
    /// from [`FlowKey`]/[`FlowCounts`]), never a silent skip that would undercount the rollup.
    fn for_each_flow(&self, f: impl FnMut(FlowKey, FlowCounts)) -> Result<(), ProbeError> {
        for_each_flow_in::<FLOW_KEY_SIZE, FlowKey>(&self.ebpf, FLOWS_MAP, f)
    }

    /// The per-VM network **totals**: every [`flows`](Self::flows) entry summed into one
    /// [`NetStats`], the sandbox-level rollup a caller exports. Reads the map once and folds in place
    /// (no intermediate `Vec`), saturating-adding each flow's per-direction counters.
    ///
    /// # Errors
    /// As [`flows`](Self::flows).
    pub fn totals(&self) -> Result<NetStats, ProbeError> {
        let mut stats = NetStats::default();
        self.for_each_flow(|_, c| {
            stats.ingress_packets = stats.ingress_packets.saturating_add(c.ingress_packets);
            stats.ingress_bytes = stats.ingress_bytes.saturating_add(c.ingress_bytes);
            stats.egress_packets = stats.egress_packets.saturating_add(c.egress_packets);
            stats.egress_bytes = stats.egress_bytes.saturating_add(c.egress_bytes);
        })?;
        Ok(stats)
    }

    /// New flows the kernel **dropped** because the `FLOWS` map was full, summed across CPUs: each
    /// count is a packet whose 5-tuple could not be admitted to the flow table, so its traffic is
    /// absent from [`flows`](Self::flows) *and* undercounted by [`totals`](Self::totals). Without
    /// this counter a guest could fill the table with benign flows and evict its real traffic from
    /// its own record silently; a nonzero value marks the network section truncated and becomes a
    /// coverage gap on the run's record. Monotonic since attach (each monitor owns fresh maps).
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the drop-counter map is missing or unreadable.
    pub fn dropped_flows(&self) -> Result<u64, ProbeError> {
        per_cpu_sum(&self.ebpf, FLOW_DROPS_MAP)
    }

    /// The [`dropped_flows`](Self::dropped_flows) twin for the denial trail: denied packets whose
    /// destination row a full `DENIALS` map could not record. The packets were still dropped at the
    /// tap (enforcement never depends on the map); only the audit row is missing, and this makes
    /// that loss visible instead of silent.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the drop-counter map is missing or unreadable.
    pub fn dropped_denials(&self) -> Result<u64, ProbeError> {
        per_cpu_sum(&self.ebpf, DENIAL_DROPS_MAP)
    }

    /// Frames the tap saw that the flow parser can't represent (IPv6, 802.1Q VLAN, or a
    /// truncated/malformed IPv4 frame), so they aren't in [`flows`](Self::flows) or
    /// [`totals`](Self::totals). Nonzero means the guest emitted traffic the flow view can't
    /// otherwise show (ARP is not counted, it is expected on-link, not a flow). The consumer
    /// records a coverage gap rather than an exact-looking record. Neither IPv6 nor VLAN is
    /// configured on a sandbox's tap, so on a healthy guest this stays zero.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the counter map is missing or unreadable.
    pub fn unparsed_l3(&self) -> Result<u64, ProbeError> {
        per_cpu_sum(&self.ebpf, UNPARSED_L3_MAP)
    }

    /// The **denied** guest-sent packets: `(FlowKey, count)` pairs from the `DENIALS` map, one per
    /// destination the egress policy dropped, with how many packets were blocked. Empty until enforcement
    /// drops something. The host-observed audit trail of which endpoints a sandbox was blocked from, read
    /// it after a run, log it, or fold it into the per-run record. Order is unspecified.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the `DENIALS` map is missing or a read fails mid-iteration.
    pub fn denials(&self) -> Result<Vec<(FlowKey, u64)>, ProbeError> {
        denial_counts::<FLOW_KEY_SIZE, FlowKey>(&self.ebpf, DENIALS_MAP)
    }

    /// The IPv6 per-flow counters as `(FlowKey6, FlowCounts)` pairs, read from the `FLOWS6` map, the v6
    /// twin of [`flows`](Self::flows). Order is unspecified (hash-map iteration); the record builder
    /// sorts them.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the map is missing or a read fails mid-iteration.
    pub fn flows6(&self) -> Result<Vec<(FlowKey6, FlowCounts)>, ProbeError> {
        let mut out = Vec::new();
        for_each_flow_in::<FLOW_KEY6_SIZE, FlowKey6>(&self.ebpf, FLOWS6_MAP, |key, counts| {
            out.push((key, counts));
        })?;
        Ok(out)
    }

    /// The **denied** guest-sent IPv6 packets as `(FlowKey6, count)` pairs from the `DENIALS6` map, the
    /// v6 twin of [`denials`](Self::denials). Empty until v6 enforcement drops something.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if the `DENIALS6` map is missing or a read fails mid-iteration.
    pub fn denials6(&self) -> Result<Vec<(FlowKey6, u64)>, ProbeError> {
        denial_counts::<FLOW_KEY6_SIZE, FlowKey6>(&self.ebpf, DENIALS6_MAP)
    }

    /// Replace this **already-attached** monitor's [`EgressPolicy`]: arm `ENFORCE`, then write the
    /// rules into `POLICY`/`POLICY6` with every unused slot zeroed. From here the tap's ingress hook
    /// drops any guest-sent packet whose destination matches no rule, and accepts those that do, per
    /// VM, since each monitor owns its own maps. Idempotent.
    ///
    /// **The replacement is fail-closed**: it arms, zeroes every slot, and only then writes the
    /// grants, so mid-update the tap denies rather than admits and revoking an allowance takes
    /// effect at the first write rather
    /// than lingering until the last. There is **no way back to observe-only** on a live tap: a
    /// monitor that has enforced keeps enforcing, and a caller that wants no enforcement attaches
    /// with [`attach_in_netns`](Self::attach_in_netns) and never arms.
    ///
    /// To arm at launch with no un-enforced window at all, prefer
    /// [`enforce_in_netns`](Self::enforce_in_netns), which policies the maps *before* the tc
    /// programs go live on the tap.
    ///
    /// # Errors
    /// [`ProbeError::Policy`] if the policy exceeds [`MAX_POLICY_RULES`], or [`ProbeError::Map`] if a
    /// policy/enforce map is missing or a write fails.
    pub fn set_egress_policy(&mut self, policy: &EgressPolicy) -> Result<(), ProbeError> {
        apply_policy(&mut self.ebpf, policy)
    }
}

impl TapMonitor {
    /// Attach the monitor to a sandbox's netns tap **and** install `policy`, arming enforcement in one
    /// step, the launch-time entry point. The policy is written and `ENFORCE` set *before* the
    /// tc programs are attached to the tap, so there is **no window** in which the tap is live but
    /// un-policed: the very first guest packet the classifier sees is already under policy. Pass
    /// [`EgressPolicy::deny_all`] for deny-by-default. Otherwise like
    /// [`attach_in_netns`](Self::attach_in_netns) (enters the sandbox's netns via `setns`).
    ///
    /// # Errors
    /// As [`attach_in_netns`](Self::attach_in_netns) and [`set_egress_policy`](Self::set_egress_policy).
    pub fn enforce_in_netns(
        netns: &str,
        interface: &str,
        policy: &EgressPolicy,
    ) -> Result<Self, ProbeError> {
        check_support()?;
        // Load + policy the maps in the caller's netns, *then* attach in the sandbox's: arming before
        // attach is what closes the un-enforced window (an attached-but-unpoliced tap would accept-all).
        let mut ebpf = load_classifiers()?;
        apply_policy(&mut ebpf, policy)?;
        let handle = Path::new(NETNS_DIR).join(netns);
        // Netns-attached: forget the links (see `attach_in_netns`) so the drop can't misfire.
        with_netns(&handle, || attach_classifiers(&mut ebpf, interface, true))?;
        Ok(Self { ebpf })
    }
}

impl TapMonitor {
    /// The egress posture **as the kernel holds it**, read back from `POLICY`, `POLICY6`, and
    /// `ENFORCE` after attach, plus the `gateway` the driver configured (a plain value the caller
    /// supplies, since the tap cannot see the guest's command line).
    ///
    /// Read rather than restated so the record stays a record of observation: it reports the rules
    /// the classifier will actually consult, not the ones a caller believes it requested. That
    /// distinction is the point of the field. A rule the kernel dropped, a map written by something
    /// else, or a policy that never reached the map all show up here as themselves.
    ///
    /// Inactive slots are skipped (an all-zero slot is `active == 0`, the shape the policy writer
    /// leaves in the tail), so the result is the live rules in slot order.
    ///
    /// # Errors
    /// [`ProbeError::Map`] if a map is missing, cannot be opened as an array, or holds a slot whose
    /// bytes do not decode as the shared record (which would mean the kernel struct drifted).
    pub fn posture(&self, gateway: Option<Ipv4Addr>) -> Result<EgressPosture, ProbeError> {
        // `EgressPosture` is `#[non_exhaustive]` (defined in `bsx-record`), so it is built
        // through `Default` + field assignment rather than a struct literal.
        let mut posture = EgressPosture::default();
        posture.enforcing = self.enforcing()?;
        posture.allowed = read_policy(&self.ebpf)?;
        posture.allowed6 = read_policy6(&self.ebpf)?;
        posture.gateway = gateway;
        Ok(posture)
    }

    /// Whether the classifier is armed (`ENFORCE` slot 0). `false` is observe-only: every packet
    /// passes regardless of what `POLICY` holds, which is why the record carries this alongside the
    /// rules rather than letting a reader infer enforcement from a non-empty rule list.
    fn enforcing(&self) -> Result<bool, ProbeError> {
        let enforce: Array<_, u32> = crate::maps::open(&self.ebpf, ENFORCE_MAP, "an array")?;
        let on = enforce
            .get(&0, 0)
            .map_err(|e| ProbeError::Map(format!("read `{ENFORCE_MAP}`: {e}")))?;
        Ok(on != 0)
    }
}

/// Read the live rules out of `POLICY`, the read-side twin of [`write_policy`]. Inactive slots are
/// skipped; a slot whose bytes don't decode is a hard error rather than a silent skip, for the
/// reason [`TapMonitor::flows`] treats an undecodable entry that way: a record that quietly omits a
/// rule would understate the policy in force.
fn read_policy(ebpf: &Ebpf) -> Result<Vec<PolicyRule>, ProbeError> {
    read_rules::<POLICY_RULE_SIZE, PolicyRule>(ebpf, POLICY_MAP)
}

/// The IPv6 twin of [`read_policy`], over `POLICY6`.
fn read_policy6(ebpf: &Ebpf) -> Result<Vec<PolicyRule6>, ProbeError> {
    read_rules::<POLICY_RULE6_SIZE, PolicyRule6>(ebpf, POLICY6_MAP)
}

/// Write `policy` into an [`Ebpf`]'s `POLICY`/`POLICY6` maps and arm `ENFORCE`. Works on a loaded
/// object whether or not its programs are attached yet, so it serves both the post-attach
/// [`TapMonitor::set_egress_policy`] and the pre-attach [`TapMonitor::enforce_in_netns`]
/// (arm-before-attach, no un-enforced window).
///
/// **The order is the fail-closed property**, and it is why this is one function rather than a write
/// and an arm at each call site. Arm, then zero every slot, then write the grants. On an
/// already-attached tap the classifier is reading `POLICY` throughout, so the middle of the update
/// is a posture the guest can hit: here it denies. Writing the new rules straight over the old ones
/// slot by slot would instead leave the rule being *revoked* live in a not-yet-overwritten slot, so
/// a packet to the revoked endpoint is admitted for the length of the rewrite, which is fail-open in
/// exactly the direction a revocation must not be.
///
/// What this does not make atomic is a **single slot**: an array-map value is copied without a lock,
/// so a classifier can read one rule mid-write. The transition is now allow -> zero -> new, so a
/// torn read is of a rule that is arriving rather than one the caller just took away.
fn apply_policy(ebpf: &mut Ebpf, policy: &EgressPolicy) -> Result<(), ProbeError> {
    let rules = policy.rules();
    let rules6 = policy.rules6();
    if rules.len() > MAX_POLICY_RULES {
        return Err(PolicyError::TooManyRules {
            got: rules.len(),
            max: MAX_POLICY_RULES,
        }
        .into());
    }
    if rules6.len() > MAX_POLICY_RULES {
        return Err(PolicyError::TooManyRules {
            got: rules6.len(),
            max: MAX_POLICY_RULES,
        }
        .into());
    }
    set_enforce(ebpf, true)?;
    // Deny everything before granting anything: an empty rule list zeroes every slot, and a zeroed
    // slot is `active == 0`.
    write_policy(ebpf, &[])?;
    write_policy6(ebpf, &[])?;
    write_policy(ebpf, rules)?;
    write_policy6(ebpf, rules6)
}

/// Write every `POLICY` slot: the first `rules.len()` from `rules`, the rest zeroed (an all-zero slot is
/// `active == 0`, i.e. empty, so a shrunk policy can't leave a stale allow-rule behind). Rules go in as
/// raw native bytes via [`PolicyRule::to_bytes`], so the loader needs no `unsafe` `aya::Pod` binding,
/// the write-side twin of [`TapMonitor::flows`] reading raw bytes.
fn write_policy(ebpf: &mut Ebpf, rules: &[PolicyRule]) -> Result<(), ProbeError> {
    write_rules::<POLICY_RULE_SIZE, PolicyRule>(ebpf, POLICY_MAP, rules)
}

/// The IPv6 twin of [`write_policy`]: fill every `POLICY6` slot (the rest zeroed, an all-zero slot is
/// `active == 0`), rules as raw native bytes via [`PolicyRule6::to_bytes`].
fn write_policy6(ebpf: &mut Ebpf, rules: &[PolicyRule6]) -> Result<(), ProbeError> {
    write_rules::<POLICY_RULE6_SIZE, PolicyRule6>(ebpf, POLICY6_MAP, rules)
}

/// Set the `ENFORCE` toggle (slot 0): `true` = deny-by-default egress, `false` = observe-only.
fn set_enforce(ebpf: &mut Ebpf, on: bool) -> Result<(), ProbeError> {
    crate::maps::set_flag(ebpf, ENFORCE_MAP, 0, on)
}

/// A fixed-size record of a tap map, tying a key/rule type to its `N`-byte codec so the v4 and v6
/// halves of each map surface share one generic body ([`read_rules`], [`write_rules`],
/// [`denial_counts`], [`for_each_flow_in`]). Const-generic rather than an associated const,
/// because the byte arrays it sizes (`[u8; N]`) cannot take an associated const on stable Rust.
trait Wire<const N: usize>: Sized {
    /// Decodes `N` bytes, `None` when the length or layout doesn't match the shared record.
    fn decode(bytes: &[u8]) -> Option<Self>;
}

/// The policy-rule half of [`Wire`]: a rule is also written back, and carries an `active` slot flag.
trait WireRule<const N: usize>: Wire<N> {
    /// Encodes the rule as the raw native bytes the kernel reads.
    fn encode(&self) -> [u8; N];
    /// Whether the slot holds a real rule (`active != 0`), rather than the zeroed empty tail.
    fn active(&self) -> bool;
}

impl Wire<FLOW_KEY_SIZE> for FlowKey {
    fn decode(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes)
    }
}

impl Wire<FLOW_KEY6_SIZE> for FlowKey6 {
    fn decode(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes)
    }
}

impl Wire<POLICY_RULE_SIZE> for PolicyRule {
    fn decode(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes)
    }
}

impl WireRule<POLICY_RULE_SIZE> for PolicyRule {
    fn encode(&self) -> [u8; POLICY_RULE_SIZE] {
        self.to_bytes()
    }
    fn active(&self) -> bool {
        self.active != 0
    }
}

impl Wire<POLICY_RULE6_SIZE> for PolicyRule6 {
    fn decode(bytes: &[u8]) -> Option<Self> {
        Self::from_bytes(bytes)
    }
}

impl WireRule<POLICY_RULE6_SIZE> for PolicyRule6 {
    fn encode(&self) -> [u8; POLICY_RULE6_SIZE] {
        self.to_bytes()
    }
    fn active(&self) -> bool {
        self.active != 0
    }
}

/// The shared body of [`read_policy`] and [`read_policy6`]: every slot of a policy array map,
/// keeping the active rules in slot order. A slot whose bytes don't decode is a hard error rather
/// than a silent skip, since a record that quietly omits a rule would understate the policy in
/// force.
fn read_rules<const N: usize, R: WireRule<N>>(
    ebpf: &Ebpf,
    name: &str,
) -> Result<Vec<R>, ProbeError> {
    let policy: Array<_, [u8; N]> = crate::maps::open(ebpf, name, "an array")?;
    let mut out = Vec::new();
    for i in 0..MAX_POLICY_RULES {
        let bytes = policy
            .get(&(i as u32), 0)
            .map_err(|e| ProbeError::Map(format!("read `{name}`[{i}]: {e}")))?;
        let rule = R::decode(&bytes).ok_or_else(|| {
            ProbeError::Map(format!(
                "decode `{name}`[{i}]: {} bytes don't match the shared record",
                bytes.len()
            ))
        })?;
        if rule.active() {
            out.push(rule);
        }
    }
    Ok(out)
}

/// The shared body of [`write_policy`] and [`write_policy6`]: every slot of a policy array map,
/// the first `rules.len()` from `rules`, the rest zeroed (an all-zero slot is `active == 0`, so a
/// shrunk policy can't leave a stale allow-rule behind).
fn write_rules<const N: usize, R: WireRule<N>>(
    ebpf: &mut Ebpf,
    name: &str,
    rules: &[R],
) -> Result<(), ProbeError> {
    let mut policy: Array<_, [u8; N]> = crate::maps::open_mut(ebpf, name, "an array")?;
    for i in 0..MAX_POLICY_RULES {
        let bytes = rules.get(i).map_or([0u8; N], R::encode);
        policy
            .set(i as u32, bytes, 0)
            .map_err(|e| ProbeError::Map(format!("write `{name}`[{i}]: {e}")))?;
    }
    Ok(())
}

/// The shared body of [`TapMonitor::for_each_flow`] and [`TapMonitor::flows6`]: iterate a flow
/// map, decoding each raw key/value, and hand every pair to `f`. A key or value whose size can't
/// decode is a **hard** [`ProbeError::Map`] (the kernel record drifted from the shared structs),
/// never a silent skip that would undercount the rollup.
fn for_each_flow_in<const N: usize, K: Wire<N>>(
    ebpf: &Ebpf,
    name: &str,
    mut f: impl FnMut(K, FlowCounts),
) -> Result<(), ProbeError> {
    let flows: AyaHashMap<_, [u8; N], [u8; FLOW_COUNTS_SIZE]> =
        crate::maps::open(ebpf, name, "a hash map")?;
    for entry in flows.iter() {
        let (k, v) = entry.map_err(|e| ProbeError::Map(format!("iterate `{name}`: {e}")))?;
        let (Some(key), Some(counts)) = (K::decode(&k), FlowCounts::from_bytes(&v)) else {
            return Err(ProbeError::Map(format!(
                "decode a `{name}` entry: {}-byte key / {}-byte value don't match the shared record",
                k.len(),
                v.len()
            )));
        };
        f(key, counts);
    }
    Ok(())
}

/// The shared body of [`TapMonitor::denials`] and [`TapMonitor::denials6`]: a denial map's
/// `(key, blocked-packet count)` pairs. An undecodable key is a hard error, as in
/// [`for_each_flow_in`].
fn denial_counts<const N: usize, K: Wire<N>>(
    ebpf: &Ebpf,
    name: &str,
) -> Result<Vec<(K, u64)>, ProbeError> {
    let denials: AyaHashMap<_, [u8; N], u64> = crate::maps::open(ebpf, name, "a hash map")?;
    let mut out = Vec::new();
    for entry in denials.iter() {
        let (k, count) = entry.map_err(|e| ProbeError::Map(format!("iterate `{name}`: {e}")))?;
        let Some(key) = K::decode(&k) else {
            return Err(ProbeError::Map(format!(
                "decode a `{name}` key: {}-byte key doesn't match the shared record",
                k.len()
            )));
        };
        out.push((key, count));
    }
    Ok(out)
}

/// Read the compiled object and load + verify both `tc` classifier programs (not yet attached to any
/// interface). Namespace-independent: creating the maps and loading the programs is global, so this
/// runs in whatever netns the caller is in.
fn load_classifiers() -> Result<Ebpf, ProbeError> {
    let mut ebpf = load_object()?;
    for program in [CLS_INGRESS, CLS_EGRESS] {
        let cls: &mut SchedClassifier = crate::maps::program_mut(&mut ebpf, program, "classifier")?;
        cls.load()
            .map_err(|e| ProbeError::Load(format!("verify/load `{program}`: {e}")))?;
    }
    Ok(ebpf)
}

/// Which kind of link a classifier attach produced. The two demand **opposite** teardown, so the
/// value the attach reports is the value the teardown reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TcLink {
    /// A TCX `bpf_link`. It owns an fd, and its drop detaches through the link, which is
    /// netns-independent.
    Tcx,
    /// The classic netlink clsact filter. It holds no fd, and its drop issues the filter-delete in
    /// the *dropping thread's* netns.
    Netlink,
}

/// Attach one classifier to `interface`, **asking the kernel for TCX and falling back to the netlink
/// clsact filter**, and report which kind it gave.
///
/// `SchedClassifier::attach` makes this choice from `KernelVersion::at_least(6, 6, 0)` and does not
/// report what it chose, so a caller that must know the kind has to mirror that threshold, and a
/// mirrored threshold is a copy that drifts on an aya bump with no diff that mentions it. Both ways
/// of being wrong are silent: predicting TCX where aya used netlink drops a netlink link in the
/// wrong netns, detaching an unrelated device's filter, and predicting netlink where aya used TCX
/// forgets an fd-owning link, one per classifier per run. Naming the option instead makes the answer
/// a value rather than a prediction, and a kernel that cannot do TCX refuses the request.
///
/// The options are the ones `attach` itself passes, so behaviour on both kernels is unchanged. If
/// the fallback also fails, both errors ride the message, since the TCX attempt failing for a reason
/// other than "this kernel has no TCX" (no `CAP_NET_ADMIN`, the interface gone) is the case where
/// swallowing it would mislead.
fn attach_classifier(
    cls: &mut SchedClassifier,
    program: &str,
    interface: &str,
    attach_type: TcAttachType,
) -> Result<(SchedClassifierLinkId, TcLink), ProbeError> {
    let tcx = cls.attach_with_options(
        interface,
        attach_type,
        TcAttachOptions::TcxOrder(LinkOrder::default()),
    );
    let tcx_err = match tcx {
        Ok(link_id) => return Ok((link_id, TcLink::Tcx)),
        Err(e) => e,
    };
    cls.attach_with_options(
        interface,
        attach_type,
        TcAttachOptions::Netlink(NlOptions::default()),
    )
    .map(|link_id| (link_id, TcLink::Netlink))
    .map_err(|e| {
        ProbeError::Attach(format!(
            "attach `{program}` to {interface} ({attach_type:?}): netlink: {e} (TCX first: \
             {tcx_err})"
        ))
    })
}

/// Attach the already-loaded classifiers to `interface`'s clsact ingress and egress hooks, adding the
/// clsact qdisc first. **Namespace-scoped**: the caller must already be in the netns that owns
/// `interface` (the current netns for [`TapMonitor::attach`], the sandbox's for
/// [`TapMonitor::attach_in_netns`]).
fn attach_classifiers(
    ebpf: &mut Ebpf,
    interface: &str,
    forget_links: bool,
) -> Result<(), ProbeError> {
    // clsact gives a device both a `tc` ingress and egress hook. Idempotent: an already-present
    // clsact is fine; any other failure (no CAP_NET_ADMIN, or the interface is gone) is a typed
    // error. aya models "already there" as its own variant, so this matches on the variant rather
    // than on a raw `EEXIST` errno.
    if let Err(e) = tc::qdisc_add_clsact(interface)
        && !matches!(e, aya::programs::TcError::AlreadyAttached)
    {
        return Err(ProbeError::Attach(format!(
            "add clsact qdisc on {interface}: {e}"
        )));
    }
    for (program, attach_type) in [
        (CLS_INGRESS, TcAttachType::Ingress),
        (CLS_EGRESS, TcAttachType::Egress),
    ] {
        let cls: &mut SchedClassifier = crate::maps::program_mut(ebpf, program, "classifier")?;
        let (link_id, link) = attach_classifier(cls, program, interface, attach_type)?;
        if forget_links && link == TcLink::Netlink {
            // Netns-attached, netlink clsact only: the in-kernel `tc` filter is reclaimed by
            // the sandbox's **netns teardown** (the documented model), so take the link out of the
            // program and forget it. Otherwise aya's `Ebpf` drop would issue the netlink
            // filter-delete in the *dropping thread's* netns, where this ifindex may name an
            // unrelated device, detaching someone else's filter. Forgetting leaks no fd here: the
            // clsact filter is in-kernel bookkeeping the netns teardown clears, not a held fd.
            let link = cls.take_link(link_id).map_err(|e| {
                ProbeError::Attach(format!("take `{program}` link on {interface}: {e}"))
            })?;
            std::mem::forget(link);
        }
        // On the TCX path the link *owns an fd*, and its drop detaches via the bpf_link, which is
        // netns-independent (no wrong-netns hazard). So leave it with the program: dropping the
        // monitor both closes the fd and detaches cleanly. Forgetting it here would leak that fd
        // (one per classifier, per run), walking a long-lived daemon toward EMFILE.
    }
    Ok(())
}

/// Run `f` inside the network namespace at `netns_handle`, on a **short-lived scoped thread** that
/// enters the netns and then dies with it, so a `tc` attach lands in a sandbox's netns without moving
/// the calling thread (or the process) at all. The worker's `setns` affects only *that* thread, and
/// because it simply exits afterward there is **no restore step to fail**: moving the caller's own
/// thread would need a restore `setns` whose failure strands the caller in the sandbox's
/// (about-to-be-torn-down) netns. Here a failure just ends the worker, and the caller's thread was
/// never in the sandbox netns. `f`'s result (and any panic) crosses
/// the join. Uses nix's *safe* `setns`, so the loader stays `#![forbid(unsafe_code)]`.
fn with_netns<T: Send>(
    netns_handle: &Path,
    f: impl FnOnce() -> Result<T, ProbeError> + Send,
) -> Result<T, ProbeError> {
    use nix::sched::{CloneFlags, setns};
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let target = File::open(netns_handle).map_err(|e| {
                    ProbeError::Attach(format!("open netns {}: {e}", netns_handle.display()))
                })?;
                setns(&target, CloneFlags::CLONE_NEWNET).map_err(|e| {
                    ProbeError::Attach(format!("enter netns {}: {e}", netns_handle.display()))
                })?;
                f()
            })
            .join()
            .map_err(|_| ProbeError::Attach("netns worker thread panicked".into()))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wrong `N` on a `Wire` impl fails the wrapper's bound at compile time; a wrong codec or
    /// `active` clause fails here, without a loaded eBPF object.
    #[test]
    fn the_wire_codecs_round_trip_their_records_at_their_pinned_sizes() {
        let rule = PolicyRule {
            active: 1,
            ..PolicyRule::default()
        };
        let got =
            <PolicyRule as Wire<POLICY_RULE_SIZE>>::decode(&rule.encode()).expect("v4 decodes");
        assert_eq!(got, rule);
        assert!(got.active());
        assert!(!PolicyRule::default().active(), "a zeroed slot is inactive");

        let rule6 = PolicyRule6 {
            active: 1,
            ..PolicyRule6::default()
        };
        let got6 =
            <PolicyRule6 as Wire<POLICY_RULE6_SIZE>>::decode(&rule6.encode()).expect("v6 decodes");
        assert_eq!(got6, rule6);

        // A key decodes from its own record size and refuses a shorter slice (the codec's
        // contract; a v4-sized buffer is shorter than a v6 key, so the families can't cross).
        assert!(<FlowKey as Wire<FLOW_KEY_SIZE>>::decode(&[0u8; FLOW_KEY_SIZE]).is_some());
        assert!(<FlowKey as Wire<FLOW_KEY_SIZE>>::decode(&[0u8; FLOW_KEY_SIZE - 1]).is_none());
        assert!(<FlowKey6 as Wire<FLOW_KEY6_SIZE>>::decode(&[0u8; FLOW_KEY6_SIZE]).is_some());
        assert!(<FlowKey6 as Wire<FLOW_KEY6_SIZE>>::decode(&[0u8; FLOW_KEY_SIZE]).is_none());
    }
}
