# 008. Guest networking is deny-by-default: a tap with no route to the world *(2026-07-12)*

**Decision.** When Phase 4 gives the guest a NIC, the per-VM tap device defaults to **no route to the
outside world**, host-local reachability only (host↔guest over the tap's own subnet), with any egress
to the wider network being an **explicit, recorded** allowance, never the default. The driver installs
**no** `MASQUERADE`/general-forward rule as part of standing a VM up. Every routing/netfilter rule the
driver *does* install is enumerated in code and recorded (feeding the audit log, P4.8), so the
network posture of a running sandbox is auditable from the host. This **resolves the direction of the
queued P4.3 decision** (deny-by-default over NAT-to-world) and makes **P4.3 blocking on P4.1**, the
addressing/tap work lands already denying, not opened-then-restricted.

**Alternatives considered.**
- **Default `MASQUERADE` to give the guest general egress (the "it just works" NAT).** Rejected: it is
  the fastest way to make a P4.7-style "guest reaches an allowed endpoint" test pass, but it opens
  *general* egress and **breaks guardrail #4** (deny-by-default). Worse, the real enforcement
  mechanism, host-side eBPF on the tap (Phase 8), does not exist yet, so a default-open tap would be
  *unenforced* open egress for four phases. Opening later behind an allow-list is a one-way door only
  if we start closed.
- **Wire an allow-list now, in the driver, ahead of eBPF.** Rejected as scope/placement error: policy
  enforcement belongs in host-side eBPF (guardrail #2), not in ad-hoc driver-installed `iptables`
  rules that would then have to be unwound in Phase 8. P4 gives the guest an address and a host-local
  path; P8 is where allow/deny egress policy is *enforced and observed* from the host.

**Why.** Deny-by-default is a core property, and today it holds only *by construction*, the guest
has no NIC at all (no `/network-interfaces` PUT, no `ip=` boot arg). Phase 4 flips that to "a NIC
exists," and the safe flip is closed-by-default: the guest can talk to its host (enough for the P4
addressing/routing demo) but reaches nothing beyond it until an explicit, host-enforced policy says so.
This keeps the security boundary on the host and out of the guest's reach, and keeps the "every
allowance is recorded" invariant true from the first tap.

**Consequences and notes.**
- **The tap is the first per-VM resource that lives *outside* the workdir**, so teardown must delete it
  (and its routes) on every path, a hard requirement carried by P4.1/P4.5, not this decision.
- **P4.7's "reaches an allowed endpoint" is deferred to real enforcement**: until eBPF (P8), "allowed"
  means host-local; world-egress allow-listing is an eBPF-enforced, recorded policy, not a driver NAT
  rule. The bench/demo for P4 proves host↔guest reachability and that the guest reaches *nothing else*.
- **No default masquerade is a standing rule**, not a P4-only stopgap: if a hoster wants NAT egress,
  that is an explicit configured allowance the audit log captures, consistent with guardrail #3
  (the hoster's policy, enabled explicitly), never an engine default.

**As shipped.** The addressing/tap work (P4.1/P4.2) implements this directly: the guest's `eth0` is
configured via the kernel `ip=` param with an **empty gateway field**, so the kernel installs only the
connected /30 route and **no default route**, and the driver installs no masquerade and never enables
`ip_forward`. Net effect: the guest reaches its host end of the /30 and nothing else. Proven by the
`addresses_the_guest_and_routes_host_to_guest` integration test, which asserts the guest carries its
address, reaches the host tap IP, and gets a fast `ENETUNREACH` (not a timeout) for an off-subnet
address. So this decision is realized, not just intended.
