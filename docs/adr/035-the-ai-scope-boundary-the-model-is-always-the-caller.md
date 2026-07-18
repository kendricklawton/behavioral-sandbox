# 035. The AI-scope boundary: the model is always the caller, never an engine component *(2026-07-17)*

**Problem.** Phase 18 makes AI-generated code and autonomous agents a first-class workload, and the pull
the instant you say "AI-native" is to reach for a model *inside* the engine: a model that judges whether
a run is safe, classifies the audit record, or adapts the policy. That pull has to be refused explicitly
and on the record, before the Phase-18 surfaces are built on top of it, or "AI-native" quietly becomes
"has an LLM in it," and the four core properties erode one commit at a time into a slap-on nobody
decided to make.

**Decision.** The model is always the **caller**, never an engine component. For an AI workload the
engine's contribution is exactly what it is for any untrusted workload, hardware containment (a KVM
microVM) plus a host-observed, tamper-resistant audit record, plus, new in Phase 18, a **model-legible
projection** of that record (P18.2). Nothing in the host path runs inference, holds a provider key, or
lets a model decide a security question. The reference agent-containment example (P18.4) drives the
engine with a **deterministic scripted agent**, a fixed stand-in for an LLM's tool loop, so the demo
is CI-reproducible and needs no model, no secrets, and no network to a provider.

**Why a model *in* the engine breaks the invariants.** Each failure lands on a different core property,
which is why the line is drawn at the engine's edge and not somewhere softer:

- **Isolation is hardware (invariant 1).** A model gating what a run may do is a *software* trust
  boundary, and a probabilistic one, the exact thing the CPU-is-the-boundary property exists to rule
  out. The moment a model's output decides containment, the boundary is no longer the KVM line; it's a
  prompt.
- **Engine, not platform (invariant 3).** Inference, prompt management, provider keys, and model-driven
  policy are platform concerns, the caller's or hoster's, alongside tenancy, billing, and scheduling.
  Pulling them into the engine is the same category error as bundling a dashboard.
- **Measured, not marketed (invariant 4).** A model call is unbounded and un-benchmarkable: there is no
  honest p99 for "ask an LLM." An engine that made inference part of a run could no longer
  percentile-report the run, every headline latency would carry an unmeasurable tail.

**Why invariant 2 is untouched, and is the whole point.** Observe-and-enforce-from-the-host is not
strained by this line; it is *served* by it. The model-legible record (P18.2) is a **projection of the
record host-side eBPF already built** (decisions 027/028): the model reads a *face* of the host's
observation, it does not help produce it. Observation and enforcement stay entirely host-side, out of
the guest and out of any model. So the AI-native surface adds a **reader**, never a new **authority**,
which is precisely what lets it exist without touching the security boundary.

**Why a scripted agent for the reference example, not a live model.** Three reasons, each an
invariant-preservation and not a convenience. It keeps the containment claim **exercised, not asserted**
(invariant 4): a deterministic agent lets P18.4's "one allowed tool call, one denied, the record proves
which" run in CI on every push, where a live provider would be flaky, keyed, and non-reproducible. It
keeps a model and its secrets out of the repo and the host path (invariants 1/3). And it isolates
*what's being proven*, the engine's containment of agent-generated behavior, from the variance of a
real model. A live model is the caller's to bring; the engine's job is proven without one.

**What this gives an agent supervisor.** The value the thesis promises for this workload: a
tamper-resistant, host-observed record of exactly what an agent's code *reached* and what was *blocked*,
observed from outside the guest where neither the agent nor its generated code can forge it, the trust
substrate a supervisor needs that a pure-execution sandbox can't offer. The model consumes that record
to decide its next action; the engine guarantees the record is true.

**Relationship to prior decisions.** This is the AI-workload face of decision 016 (the engine/hoster
line) and decision 033 (the whole security boundary): the model sits with the hoster and the caller,
*outside* the trust boundary, exactly where tenancy and scheduling already sit. Any change that puts a
model in the host path, gives the engine a provider key, or lets a model's output gate containment or
policy contradicts this decision by construction, the same test the boundary decisions already apply.
