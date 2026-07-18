# Non-goals

What this engine deliberately is **not**. These are design commitments, not gaps to fill: a PR that
adds one of them is wrong by design, and the boundary is what keeps the engine embeddable and its
security properties legible. Each is recorded as a dated [architecture
decision](./contributing-architecture.md) so it can't quietly erode.

## It is an engine, not a platform

The engine is the boring, embeddable core: a runtime plus a clean driver API you self-host. The
moment it grows opinions about *whose* code runs and *who pays*, it stops being embeddable in
anything with its own opinions. So these belong to whatever *hosts* the engine, never to this repo:

- **No tenancy or auth.** The engine trusts its caller completely; multi-user identity, quotas, and
  authorization are the hoster's layer.
- **No billing or metering policy.** The engine *measures* (host-observed metrics, benchmarked
  percentiles); charging for it is the hoster's.
- **No fleet scheduling.** One engine drives sandboxes on one host. Bin-packing across hosts, queues,
  and autoscaling are the hoster's.
- **No dashboard or public platform API.** The programmatic surface is the Rust library, the
  [`agent` CLI](./cli.md), and the [`agentd` daemon](./daemon.md), a *local* driver over a unix
  socket, no auth, no tenancy (access control is the socket directory's permissions). A daemon that
  grows multi-tenant identity or a public HTTP surface is a *hoster*, not this repo.

This line is a security boundary too: everything the engine ships is inert without host privileges
the hoster grants. See [Where the engine ends](./embedding.md#where-the-engine-ends-the-enginepaas-line)
and decisions 016 / 034.

## The AI model is the caller, never a component

The engine's highest-value workload is AI-generated code and autonomous agents, but the **model
always stays the caller's**, outside the trust boundary. The engine does not embed a model, run
inference, or let a model decide policy, that would put a probabilistic, un-benchmarkable software
component in the host path and break "isolation is hardware" and "measured, not marketed." The
AI-native surface is a *reader* of the host-observed record (the [model-legible
summary](./cli.md)), never a new authority. See decision 035 and [Containing an
agent](./examples-agent-containment.md).

## The security boundary never moves into the guest

Isolation is **hardware**, the KVM microVM, never softened to a shared-kernel shortcut "to make it
simpler." Visibility and policy live in host-side eBPF the guest cannot reach. The in-guest agent
carries exec/IO for convenience; it is **never** the thing that contains the guest. See the
[Threat model](./threat-model.md) and decision 033.

## Deny by default, and no unpatched substrate

A sandbox with no explicit policy reaches no network and holds minimal capability; every allowance
is explicit and recorded. And the supported-platform floor is deliberate, not a limitation to lift:
running untrusted code on an unsupported architecture or an end-of-life kernel is a threat-model
hole the engine refuses rather than shrugs at. See [Supported
platforms](./cli-install.md#supported-platforms) and decision 036.

## Not in this repo

The **language SDKs** (Go/Python/Node/C#) and the **Wasmtime sibling** live in separate repositories,
built on this engine's frozen wire API and audit-log format, thin clients and a sibling, never
vendored here. (The Wasmtime variant is a *sibling, not a backend*, so "isolation is hardware" holds
in this repo without exception.) They pin this crate's git rev, which is why public-API changes carry
an `api:` marker in the commit subject. See [Using the engine API](./embedding.md).
