# 042. Hoster admission: a typed capacity refusal, resource-aware admission, committed-resource telemetry *(2026-07-24)*

**Context.** The daemon. already defends itself against overload: it gates on a session
count (`--max-sessions`) via an atomic ticket and refuses a connection **side-effect-free, before any
boot**. But a fleet hoster (a separate repo, guardrail 4) running many daemons behind a dispatcher
cannot build correct, resource-aware, scale-out admission on what the daemon exposes today, and the
host must defend itself under a zero-trust assumption (even a buggy control plane can flood one node):

- **Admission is a session *count*, not resources.** The wire `open` carries client-supplied
  `vcpus`/`mem_mib`., so a host can sit under the count ceiling while memory-overcommitted
  and then OOM at boot instead of admission-rejecting.
- **The refusal is free text.** It is a `Response::Error { message: "at capacity...", fatal: true }`,
  so a dispatcher can only tell "full, fail over to another host" from "terminal, do not retry" by
  string-matching the message.
- **No side-effect-free capacity read.** A load-aware dispatcher has no cheap way to learn how full a
  host is short of attempting an `open`.

Defending the host is the engine's job; the dispatching, tenancy, and rate-limiting that sit above it
are not (guardrail 4). This decision adds only the former.

**Decision.** Three additive parts, all at the daemon edge, none touching the pinned `vmm` API.

- **A typed capacity refusal.** The over-ceiling refusal becomes a distinct
  `Response::AtCapacity { retry_after_ms }` reply, not a `Response::Error`. Backpressure is a healthy,
  expected condition, not a failure, so a dispatcher branches on a stable reply tag instead of parsing
  an error string. Additive on decision 030's wire (no `WIRE_SCHEMA` bump); `retry_after_ms` is a hint,
  since the daemon cannot know when a slot frees.
- **Resource-aware admission.** Alongside the count ticket, the daemon tracks committed `mem_mib` and
  `vcpus` and admits a session only if it fits an operator aggregate ceiling
  (`--max-committed-mem-mib`, a vCPU-oversubscription bound), charged once the request's `Limits` are
  known (`open_limits`) and released on teardown by an RAII reservation mirroring the count ticket. The
  count ceiling stays as a coarse backstop. This is distinct from decision 041's per-`open` ceilings,
  which bound *one* request; this bounds the summed *live* load.
- **Committed-resource telemetry.** The committed tally, the aggregate capacity, and free fds are
  exported on the existing metrics endpoint (not a new wire verb), so a load-aware dispatcher scrapes
  current load and routes (power-of-two-choices) rather than probe-and-fail.

**Alternatives considered.**
- **A `kind`/`code` field on `Response::Error`.** Rejected: it conflates backpressure with failure,
  widens the error shape callers pin, and forces a dispatcher to destructure an error and risk
  mis-bucketing an unknown kind as terminal.
- **A `status` wire verb for the capacity read.** Rejected: the protocol is session-scoped (the first
  message must be `open`, decision 030), so a query verb either breaks that invariant or special-cases
  session entry; the metrics endpoint already carries the numbers at no wire cost.
- **Resource-aware admission in `vmm`.** Rejected for decision 041's reason: an embedder constructs
  `Limits` directly and *is* the operator, so there is no second party to bound. Admission belongs at
  the daemon edge, which keeps the pinned engine API untouched (non-`api:`).
- **Count-only admission (the status quo).** Rejected: it under-defends a memory-heterogeneous fleet,
  the exact failure mode this decision exists to remove.

**Consequences and notes.**
- **Additive wire, no schema bump.** An old client that receives `reply:"at_capacity"` fails as a
  typed `ProtocolError`, never a panic. It lands **before** the wire
  spec freeze precisely because it changes the shape of an existing observable path (the refusal); doing
  it after would be a break, not an addition.
- **Charging `mem_mib` per VM is a conservative upper bound.** Pooled clones share the read-only base
  file copy-on-write, but guest working RAM is per-VM, so the charge is safe (slightly conservative);
  refine only if COW sharing proves it too tight.
- **Absent flags change nothing.** The aggregate ceilings are optional; unset, the daemon behaves
  exactly as today (the count ticket alone).
- **Still engine, not platform (guardrail 4).** The daemon signals capacity and defends the host; the
  fleet dispatcher, tenancy, and rate-limiting stay in the hoster's repo. Per decision 030's scope
  rule, this adds a reply and gauges, never a tenancy field.

**As shipped.** `Response::AtCapacity` lives in `crates/protocol/src/lib.rs`, produced by
`refuse_at_capacity` (the count path) and the resource gate in `crates/cli/src/session.rs`; the
committed-resource atomics and the `ResourceReservation` guard sit on `Server` in
`crates/cli/src/serve.rs`, with the aggregate ceilings from `ekvm serve` flags; the gauges
render in `crates/cli/src/metrics.rs`; the reference `client` surfaces the refusal as
`ClientError::AtCapacity`.
