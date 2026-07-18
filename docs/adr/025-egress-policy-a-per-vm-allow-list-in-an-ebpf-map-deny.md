# 025. Egress policy: a per-VM allow-list in an eBPF map, deny-by-default, enforced at the tap *(2026-07-16)*

**Problem.** Phase 11 turns the tap observation (decision 023) into **enforcement**: which world
endpoints a sandbox may reach. This needs a place the policy *lives*, a *schema* for it, and a rule for
*where it is applied*. The engine must supply the **mechanism** (allow/deny a destination, per VM,
host-enforced and recorded) without absorbing **org policy** (who is allowed what, tenancy, quotas),
that is the hoster's, per guardrail 4. This decision fixes the mechanism so the schema doesn't churn.

**Decision.** Policy is a **per-VM allow-list of destination rules in an eBPF map, consulted by the tap's
ingress classifier, deny-by-default, opt-in per monitor**.
- **Where it lives: two `#[map]`s per loaded object.** `POLICY`, a fixed `MAX_POLICY_RULES` (16) array of
  `PolicyRule`, and `ENFORCE`, a one-slot toggle. Because each `TapMonitor` loads its own object, the
  maps are **naturally per VM**, no shared table, no tenant key. Single-sourced in `crates/probes-common`
  next to the flow record (decision 023), so the kernel writer and host reader can't drift.
- **The schema: a masked-CIDR 5-tuple prefix.** A `PolicyRule` is `{ addr, prefix_len, port, proto,
  active }`, a destination **CIDR** (`0` prefix = any address) with an optional **port** and **protocol**
  (`0` = any). A packet is allowed iff its destination matches **any** active rule (`rule_matches`, shared
  by the kernel scan and the host-tested `egress_allowed`). An explicit `active` byte distinguishes an
  empty slot from a `0.0.0.0/0` allow-all, so a zeroed map is deny-all, never accidental allow-all.
- **The userspace surface is typed, not stringly/magic.** The loader exposes an ergonomic builder
  (`EgressPolicy::deny_all().allow_host(ip, Some(port), Some(Protocol::Udp))` / `.allow(cidr, port,
  proto)`) that lowers to the wire `PolicyRule`s. The types carry the intent the raw record can't:
  `Protocol` is an enum (no magic `6`/`17`), the port and protocol are `Option` (`None` = the wildcard,
  no `0`-sentinel at the API), and a CIDR is a validated `Ipv4Cidr` whose prefix is guaranteed `0..=32`
  by construction (`parse, don't validate`, an out-of-range prefix is a typed `PolicyError`, never a
  silent clamp). `TapMonitor::set_egress_policy` applies it to an attached monitor;
  `TapMonitor::enforce_in_netns` applies it **at launch**, arming the maps *before* the tc programs go
  live so there is no un-enforced window (the first guest packet is already policed). On the kernel side
  the classifier's logic speaks a `Verdict` enum (`Pass`/`Drop`), lowering to the `tc` ABI only at the
  return, so no bare action number leaks into the decision code.
- **Applied at the *ingress* hook (guest → world), not egress.** Egress policy governs what the guest
  *sends*, which on a tap is the ingress hook (decision 023). The egress hook (reply → guest) always
  accepts, so replies to allowed traffic return without connection tracking. **ARP is always allowed**,
  the guest must resolve its on-link gateway (`10.200.0.1`, decision 017) before it can reach anything,
  so dropping ARP would make deny-by-default trivially deny-everything.
- **Deny-by-default, opt-in enforcement.** `ENFORCE` off (the load default) is observe-only, preserving
  Phase 10. `ENFORCE` on with no rules drops everything: a sandbox launched with no explicit allowance
  reaches nothing (P11.4). This is the eBPF, host-observed complement to the **driver's** deny-by-default
  (decision 008 gives the guest no route to the world); the tap layer drops anything unlisted where the
  host can see and record it.
- **Denials are recorded (P11.5).** A dropped IPv4 packet is counted per destination in a `DENIALS` map
  before the drop, read back by `TapMonitor::denials`, the audit trail of blocked endpoints Phase 13
  folds into the per-run record.

**Alternatives considered.**
- **An LPM-trie map (`BPF_MAP_TYPE_LPM_TRIE`) keyed by CIDR.** Rejected: it does longest-prefix address
  matching well but doesn't carry **port/proto** in the key, and a per-sandbox allow-list is a handful of
  rules where a bounded linear scan is simpler, verifier-friendly, and keeps CIDR+port+proto in one
  record. The trie is the upgrade if allow-lists ever grow large.
- **Enforce with the driver's netfilter/routing instead of eBPF.** Rejected: decision 008 already keeps
  the driver rules minimal (no MASQUERADE, host-local only), and putting allow-listing in netfilter would
  split enforcement across two systems and lose the host-eBPF observation (core property 2). One tap hook
  both observes and enforces.
- **Store richer, higher-level policy (names, tenants, quotas) in the engine.** Rejected: that is org
  policy (guardrail 4). The engine's schema is destination CIDR/port/proto; a hoster maps its own policy
  onto that.
- **Enforce on the egress (reply) hook too / stateful conntrack.** Rejected for now: egress policy is
  about what the guest *sends*; stateful return-path filtering is more machinery than the allow-list
  mechanism needs. Accepting replies is the stateless, correct default.

**Consequences and notes.**
- **Per-VM, no shared state**, so enforcement scales with monitors and one sandbox's policy can't affect
  another's, the same per-object isolation as the flow map (decision 023).
- **The mask shift is built to stay `< 32`** (`prefix_len == 0` → zero mask, out-of-range → no match), so
  the kernel scan has no undefined shift and the verifier accepts the bounded loop.
- **Not the pinned public API.** The policy surface is on `probes-loader` (`EgressPolicy`,
  `set_egress_policy`, `enforce_in_netns`, `denials`), not `vmm`'s `Sandbox`, so this is **not** an
  `api:` change. Folding attach-and-enforce into `Sandbox::open` is Phase 13's convergence.
- P11.7 (`net_enforce.rs`, ignored/privileged) proves a guest reaches an allow-listed endpoint and is
  denied every other, and `cargo xtask enforce-sandbox` is the live exit-gate demo.
