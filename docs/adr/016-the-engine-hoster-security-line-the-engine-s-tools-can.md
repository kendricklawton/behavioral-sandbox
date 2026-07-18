# 016. The engine/hoster security line: the engine's tools can't be weaponized; deploying them is the hoster's *(2026-07-14)*

**Problem.** The orphan sweep (P6.9a, decision 014's GC) is the engine's first **privileged tool that
acts on a shared, world-writable surface**: it runs with `CAP_NET_ADMIN`/root and deletes host
interfaces + directories under the scratch base (`/tmp` by default). A design that decided what to
reclaim by the *name* of a dir or the *contents* of its tap-record file would let any local user plant
a dead-looking `agent-<pid>-<n>/` whose record names a **victim's live tap**, turning the hoster's
janitor into an unprivileged user's cross-tenant kill switch. This forced the general question the
project had only answered implicitly: where does the engine's responsibility end and the hoster's begin
when the host is shared and not everyone on it is trusted?

**Decision.** Draw the line by *category of guarantee*, and put each obligation on the side that can
actually hold it.
- **The engine guarantees its own privileged tools cannot be weaponized, unconditionally, like the
  isolation boundary.** Concretely for the sweep: it reclaims **only dirs owned by the calling euid**
  (`create_workdir`'s `0700` driver-owned dirs are the unforgeable authorship proof), hard-validates any
  tap-record before it can reach `ip link del`, keys liveness on the recorded **pid** not a resource
  name (names outlive and betray their makers, a restored clone's tap carries its dead source's token,
  decision 011), and **refuses to run** if it can't establish its own identity. This is an *authorship*
  check, not a *policy* check: the engine knows which residue it authored, and touching nothing else is a
  property of the tool, not a decision about who may run what.
- **The hoster owns deployment, as whom, when, over what, and how a shared resource is divided.** Four
  calls only they can make, so the engine **exposes and documents** them and builds none: (1) *schedule*
  the sweep (a self-refilling janitor daemon is Phase-16/platform, not the library); (2) run *one sweep
  per identity*, since it reclaims only the calling euid's residue (the direct, correct consequence of
  the anti-weaponization rule, a root sweep covering a user driver's dirs would *be* the hole);
  (3) *harden the scratch base* (point `AGENT_SCRATCH_DIR` at an engine-user-owned dir so no decoy can be
  planted at all); (4) *divide the finite `10.200/16` pool* across tenants (quota/fairness is carving a
  shared resource, the definition of the PaaS layer above the engine).

**Why.** The core properties already said "engine, not platform," but tenancy was framed as *features we don't
build* (auth, billing, scheduling). The sweep showed the subtler edge: a tool we **do** build and ship
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

**Consequences and notes.**
- Surfaced where a self-hoster looks: `agent setup` prints a "Hardening, the hoster's responsibility"
  section (the four calls above), alongside the P6.9b degradation matrix; `sweep_orphans`' rustdoc
  carries the same four for an embedder.
- **This is a seed of P15.6, not its closure.** P15.6 records the *whole* security boundary (what's
  trusted: CPU/KVM/host kernel; what isn't: the guest) with the Phase-15 adversarial suite behind it;
  this entry records the one facet the sweep forced early, which the P15.5 threat model
  builds on. The box stays unchecked until Phase 15.
- The engine/hoster split now has a concrete precedent to reuse: any future privileged tool
  (a future `agent gc`, daemon-side reconcilers) inherits the same "authorship not policy, euid-scoped,
  refuse-without-identity" rule.
