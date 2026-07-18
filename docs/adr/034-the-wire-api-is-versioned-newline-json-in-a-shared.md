# 034. The wire API is versioned newline-JSON in a shared `agentd-protocol` crate, not gRPC *(2026-07-17)*

**Decision.** `agentd`'s wire API, the SDK contract Phase 20 freezes, is **newline-delimited JSON
over a unix socket**, and every message (request *and* response) carries a leading `schema` field.
The full verb set is the sandbox lifecycle: `open` → (`exec` | `put` | `get` | `snapshot` | `trace`)\*
→ `close`. It is **not gRPC**.

**Why JSON, not gRPC.** The daemon is synchronous, thread-per-connection, with **no async runtime** on
the host path (the same posture the `Pool` doc restates as an invariant); gRPC would drag `tonic` /
`prost` and a `tokio` stack into that posture for no gain here. The peer is a **local, trusted-ish
client** the hoster runs, not the untrusted guest, so hand-debuggability (`socat`/`nc` by hand) and
"any language with a JSON library and a unix socket can drive it" outweigh a compact wire. The one
adversarial concern that still applies is guardrail 5: every decode is bounded by a message-size cap
and returns a typed error, never a panic/hang/unbounded allocation.

**Why a `schema` field now, when the shape isn't frozen.** Precisely *because* it isn't frozen yet:
stamping `schema: 1` on every message and rejecting a mismatch **up front, before the body is
trusted**, means a client built against a future revision fails loudly instead of being
half-understood. The stamp is the seam Phase 20 freezes against. (It is distinct from the audit
record's own `schema` and the CLI's `--json` run-result `schema`: three surfaces, three independent
versions.)

**Why a shared `agentd-protocol` crate (serde-only, no `agent-vmm`).** The wire is the contract, not
shared Rust internals. Putting the `Request`/`Response`/`Envelope` shapes and the bounded line codec
in their own **engine-free** crate means the daemon and the **reference client** (`agentd-client`)
share one source of truth, while a non-Rust SDK reimplements the same JSON shapes with only a JSON
library, the proof a caller needs nothing of the engine but the wire. The reference client depends on
`agentd-protocol` and a JSON value **only, never `agent-vmm`**; if it ever linked the engine, that
proof would be void.

**Verb semantics (faithful to the engine, no new machinery).** `put`/`get` write/read a
working-directory file by riding the engine's only file seam, a no-op `exec` that injects a file or
returns an artifact, since the engine stages files *around* an exec, never standalone. `snapshot`
calls `Sandbox::snapshot`, so a **jailed** session is a typed refusal (its disk is in the chroot),
exactly as the library behaves; the client gets the bundle's **daemon-host directory**, not its bytes
(bulk bytes stay off this line). `trace` returns the host-observed `RunRecord` built **non-destructively**
from a live probe snapshot, so a client may ask repeatedly mid-session without finalizing observation;
it is fail-open (a capability-less host answers a coverage-gapped record, never an error). The
pre-warmed **pool** (`--prewarm N`) serves only a **bare-default** `open` (the pool's clones carry the
default profile); any custom resource knob cold-boots.

**Scope, unchanged.** Still engine, not platform: no auth (socket-directory permissions are the
hoster's access control), no tenancy, no billing, no scheduler. The daemon shares nothing with the
`agent` CLI bin beyond the crate's small shared library (the `audit` composition both bins reuse); the
pinned `agent-vmm` API (`Sandbox`/`Limits`/`RunResult`/`VmmError`/`channel`) is untouched, the daemon
only *consumes* it.
