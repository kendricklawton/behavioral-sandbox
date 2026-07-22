# 008. Guest networking is deny-by-default: a tap with no route to the world *(2026-07-12)*

**Context.** Deny-by-default is a core property (guardrail #4): a sandbox with no explicit policy
reaches no network. Today that holds only *by construction*, the guest has no NIC at all (no
`/network-interfaces` PUT, no `ip=` boot arg). Giving the guest a NIC flips that to "a NIC exists,"
and two forces shape how it flips. First, deny-by-default has to survive the flip: a newly-networked
guest must reach nothing beyond its host until an explicit, host-enforced policy says otherwise, or the
security boundary drifts into the guest. Second, the real enforcement mechanism, host-side eBPF on the
tap (guardrail #2), lands later than the addressing work, so any egress opened before it exists is
*unenforced* egress. The pull of the "it just works" default (a standing `MASQUERADE` giving general
egress) is real, but opening later behind an allow-list is a one-way door only if we start closed.

**Decision.** When the guest first gets a NIC, the per-VM tap device defaults to **no route to the
outside world**, host-local reachability only (host↔guest over the tap's own subnet), with any egress
to the wider network being an **explicit, recorded** allowance, never the default. The driver installs
**no** `MASQUERADE`/general-forward rule as part of standing a VM up. Every routing/netfilter rule the
driver *does* install is enumerated in code and recorded (feeding the audit log), so the network posture
of a running sandbox is auditable from the host. This settles the queued networking-policy decision
(deny-by-default over NAT-to-world) in favor of denying, and orders it ahead of the addressing/tap work,
so the tap lands already denying, not opened-then-restricted.

The same posture sets the protocol surface: **the network is IPv4 and IPv6, deny-by-default for
both, and both are implemented.** The invariant is that only what the observers can fully parse may
cross the tap, because a protocol they can't read is an unobserved channel deny-by-default forbids
("every allowance is explicit and recorded"). Each family has its own **parallel** types and maps
(so the v4 datapath is byte-for-byte unchanged): the flow view (`FlowKey`/`FlowKey6`), egress policy
(`PolicyRule`/`PolicyRule6`, byte-wise v6 matching since eBPF has no `u128`), and denial records all
speak both. The guest is dual-stack where the host supports v6: it gets a static v6 ULA link
(`fd00:200::/64`, host `::1` / guest `::2`) via an `agent_guest_ip6=` cmdline token a guest sysinit
applies, the connected /64 route only and **no v6 default route**, so v6 egress is denied by
construction exactly as v4 is. The v6 link is **best-effort**: on a host with IPv6 disabled the
driver brings up no v6 end, emits no token, and reports no v6 link (`RunningVm::ipv6()` is `None`),
so the guest never holds an unreachable v6 address; isolation never rests on the v6 address (it
rests on the absent default route and the eBPF hook), so v4 and isolation are unaffected. ICMPv6
neighbor discovery is always allowed under enforcement (the v6 twin of ARP), so the guest can resolve
its host end. The build order was forced (observers → policy → record learned v6 *before* the guest's
`ipv6.disable=1` lifted), so "observe everything that crosses" held through the change; the record's
non-IPv4 gap machinery stays armed as the failsafe for a VLAN tag or a truncated frame.

**Alternatives considered.**
- **Default `MASQUERADE` to give the guest general egress (the "it just works" NAT).** Rejected: it is
  the fastest way to make a "guest reaches an allowed endpoint" test pass, but it opens *general* egress
  and **breaks guardrail #4** (deny-by-default). Worse, the real enforcement mechanism, host-side eBPF on
  the tap, does not exist yet, so a default-open tap would be *unenforced* open egress until the eBPF
  layer lands. Opening later behind an allow-list is a one-way door only if we start closed.
- **Wire an allow-list now, in the driver, ahead of eBPF.** Rejected as scope/placement error: policy
  enforcement belongs in host-side eBPF (guardrail #2), not in ad-hoc driver-installed `iptables`
  rules that would then have to be unwound once eBPF lands. The addressing work gives the guest an
  address and a host-local path; host-side eBPF is where allow/deny egress policy is *enforced and
  observed* from the host.

**Consequences and notes.**
- **The tap is the first per-VM resource that lives *outside* the workdir**, so teardown must delete it
  (and its routes) on every path, a hard requirement carried by the addressing and teardown work, not
  this decision.
- **"Reaches an allowed endpoint" is deferred to real enforcement**: until eBPF, "allowed" means
  host-local; world-egress allow-listing is an eBPF-enforced, recorded policy, not a driver NAT rule.
  The bench/demo proves host↔guest reachability and that the guest reaches *nothing else*.
- **No default masquerade is a standing rule**, not a stopgap for the addressing work: if a hoster wants
  NAT egress, that is an explicit configured allowance the audit log captures, consistent with guardrail
  #3 (the hoster's policy, enabled explicitly), never an engine default.

**As shipped.** The addressing/tap work implements this directly: the guest's `eth0` is configured via
the kernel `ip=` param with an **empty gateway field**, so the kernel installs only the connected /30
route and **no default route**, and the driver installs no masquerade and never enables `ip_forward`.
Net effect: the guest reaches its host end of the /30 and nothing else. Proven by the
`addresses_the_guest_and_routes_host_to_guest` integration test, which asserts the guest carries its
address, reaches the host tap IP, and gets a fast `ENETUNREACH` (not a timeout) for an off-subnet
address. So this decision is realized, not just intended.

**Addendum (2026-07-22): the ICMPv6 spare is scoped to on-link, not the whole protocol.** The original
"ICMPv6 neighbor discovery is always allowed" (above) shipped as a blanket pass of *every* guest-sent
ICMPv6 frame, to any destination. That is broader than the justification: ARP is its own v4 ethertype,
so sparing it leaves all routable v4 (ICMPv4 included) under deny-by-default policy, but ICMPv6 rides
the IPv6 ethertype and can carry a routable Echo, so a blanket pass let a guest Echo an arbitrary
global-unicast host. Containment then rested *solely* on the netns having no v6 default route, an
external invariant the eBPF valve cannot see or assert, so a routing regression would silently reopen an
egress channel (the traffic was still counted in `FLOWS6`, so never audit-invisible, but not dropped).
The valve now spares ICMPv6 only to the **on-link** scopes neighbor discovery / MLD / NUD actually use,
link-local (`fe80::/10`), link-scoped multicast (`ff02::/16`), and the ULA the host end lives in
(`fc00::/7`), via the host-tested `agent_probes_common::icmp6_dst_on_link`; ICMPv6 to a routable
destination now falls through to `POLICY6` and is denied by default, the same posture v4 gives ICMPv4.
Enforcement no longer leans on the routing invariant alone, and a hoster can still allow a specific
ICMPv6 endpoint by an explicit, recorded `POLICY6` rule. The `fc00::/7` spare (rather than the exact
connected prefix) keeps NUD to the on-link host reachable without plumbing the host address into the
program; a ULA is not globally routable, so this widens nothing off-link.
