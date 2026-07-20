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

The same posture fixes the protocol surface: **the sandbox's network world is IPv4-only.** The flow
view, the egress policy, and the denial records all speak IPv4; a protocol the observers cannot parse
is an unobserved channel, which deny-by-default forbids ("every allowance is explicit and recorded",
and no policy can express an IPv6 allowance). So IPv6 is disabled at both ends of the tap rather than
left to kernel defaults: the guest kernel boots with `ipv6.disable=1` (a hostile guest cannot restart
a stack its kernel never started) and the per-VM netns sets the `disable_ipv6` sysctls before any
interface comes up (silencing the host stack's own link-up chatter, MLD reports and duplicate-address
detection, which surfaced as honest non-IPv4 coverage gaps on hosted CI runners). The record's
non-IPv4 gap machinery stays armed as the failsafe: if a frame crosses anyway, the record says so
rather than claiming completeness. Re-enabling IPv6 is a deliberate future capability with a forced
order: the flow view, policy shape, and record learn IPv6 *first*, then the two disables lift.

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
