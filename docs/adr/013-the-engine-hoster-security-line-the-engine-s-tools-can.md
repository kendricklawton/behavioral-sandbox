# 013. The engine/hoster security line: the engine's tools can't be weaponized; deploying them is the hoster's *(2026-07-14)*

**Context.** The engine's isolation boundary is unconditional, and any privileged tool it ships has to
hold to that same standard. The orphan sweep (decision 011's GC) is the first such tool that **acts on a
shared, world-writable surface**: it runs with `CAP_NET_ADMIN`/root and deletes per-VM network
namespaces (each cascading its tap away; at the time of this decision, host taps directly) plus
directories under the scratch base (`/tmp` by default). On a host where not everyone is trusted, that
surface is adversarial by default. A design that decided what to reclaim by the *name* of a dir or the
*contents* of a plantable record would let any local user plant a dead-looking `agent-<pid>-<n>/`
that names a **victim's live netns** (originally, via the since-retired tap-record file, its live
tap), turning the hoster's janitor into an unprivileged user's
cross-tenant kill switch. So the tension is a standing one, not an accident: the engine must ship a
privileged reclaimer, and it must draw a line for where its responsibility ends and the hoster's begins
when the host is shared. The pull of the alternatives is real (a policy-aware sweep, a self-hardening
base, a single all-uid sweep), and each trades the property away.

**Decision.** Draw the line by *category of guarantee*, and put each obligation on the side that can
actually hold it.
- **The engine guarantees its own privileged tools cannot be weaponized, unconditionally, like the
  isolation boundary.** Concretely for the sweep: it reclaims **only dirs owned by the calling euid**
  (`create_workdir`'s `0700` driver-owned dirs are the unforgeable authorship proof), reclaims only a
  euid-owned, dead-pid dir's netns via `ip netns del` (originally: hard-validated any tap-record
  before it could reach `ip link del`), keys liveness on the recorded **pid** not a resource
  name (names outlive and betray their makers: a restored clone recreates its snapshot's recorded
  tap, so a live resource can carry a dead maker's name), and **refuses to run** if it can't
  establish its own identity. This is an *authorship*
  check, not a *policy* check: the engine knows which residue it authored, and touching nothing else is a
  property of the tool, not a decision about who may run what.
- **The hoster owns deployment, as whom, when, over what, and how a shared resource is divided.** Four
  calls only they can make, so the engine **exposes and documents** them and builds none: (1) *schedule*
  the sweep (a self-refilling janitor daemon is platform work, not the library); (2) run *one sweep
  per identity*, since it reclaims only the calling euid's residue (the direct, correct consequence of
  the anti-weaponization rule, a root sweep covering a user driver's dirs would *be* the hole);
  (3) *harden the scratch base* (point `AGENT_SCRATCH_DIR` at an engine-user-owned dir so no decoy can be
  planted at all); (4) *divide the finite `10.200/16` pool* across tenants (quota/fairness is carving a
  shared resource, the definition of the PaaS layer above the engine). ***(Obligation 4 was retired by
  decision 014: every VM reuses one fixed /30 inside its own netns, so there is no address pool to
  divide.)***

The core properties already said "engine, not platform," but tenancy was framed as *features we don't
build* (auth, billing, scheduling). The sweep is the subtler edge: a tool we **do** build and ship
with privilege must not become the lever that breaks a hoster's isolation *for* them, regardless of how
they arrange tenancy. So the rule isn't "we don't touch multi-tenant concerns", it's "we guarantee our
privileged surface is safe at any privilege on any host; the hoster decides everything about how it's
deployed." That keeps the boundary on the host side (core properties 2/3) without the engine ever needing to
know who the tenants are.

**Alternatives considered.**
- **Make the sweep policy-aware** (a config of who-owns-what, allow/deny lists). Rejected: that is
  tenancy state inside the engine (guardrail 4), and it's strictly weaker than the euid check, which
  needs no configuration and can't be misconfigured into unsafety.
- **Have the engine harden the base itself** (refuse a world-writable scratch dir, or `chmod` it).
  Rejected as the *default*: `/tmp` is the zero-config dev default and the ownership check already makes
  a world-writable base safe (a decoy is rejected on ownership), so a hard refusal would break dev for a
  risk the engine already neutralizes. Surfaced as a hardening *recommendation* in `agent setup` instead.
- **A single privileged sweep that reclaims every uid's residue.** Rejected: it is exactly the
  weaponization the euid check exists to prevent (it would act on dirs it didn't author). The per-identity
  cost is the price of that safety, and it's the hoster's to absorb.

**Consequences.**
- Surfaced where a self-hoster looks: `agent setup` prints a "Hardening, the hoster's responsibility"
  section (the calls above, three since obligation 4 retired), alongside the host-check degradation
  matrix; `sweep_orphans`' rustdoc carries the same for an embedder.
- **This is a seed of the full security-boundary record, not its closure.** That record captures the
  *whole* boundary (what's trusted: CPU/KVM/host kernel; what isn't: the guest) with the adversarial
  suite behind it; this entry records the one facet the sweep forced early, which the threat model
  builds on. The box stays unchecked until that later work lands.
- The engine/hoster split now has a concrete precedent to reuse: any future privileged tool
  (a future `agent gc`, daemon-side reconcilers) inherits the same "authorship not policy, euid-scoped,
  refuse-without-identity" rule.

**Relationship to prior decisions.** The sweep it governs is decision 011's GC, and its pid-keyed
liveness rests on the fact that names outlive their makers (a restored clone recreates its snapshot's
recorded tap, so a live resource can carry a dead maker's name).
