# Using the `agent serve` daemon

`agent serve` is the engine's **programmatic interface**: a long-lived daemon that exposes the sandbox
lifecycle over a **unix socket**, so a local client drives microVMs without linking the `agent-vmm`
library. It is a thin host of the same public API the [CLI](./cli.md) and [embedders](./embedding.md)
use, and it stays **engine, not platform**: no tenancy, no auth, no billing, no scheduler (those are
the hoster's, above the engine, and are a recorded non-goal).

> **Status.** The wire API is **versioned** (every message carries a `schema` field) but not yet
> **frozen**: a later milestone freezes and formally specs it as the SDK contract (see the
> [roadmap](https://github.com/k-henry-org/agent/blob/main/ROADMAP.md)). Until then the shape may
> still change, which is why every message is schema-stamped and a mismatch is rejected up front.

## Run it

```console
agent serve --socket /run/agent/agent.sock              # jailed by default (needs root + the jailer)
agent serve --socket ./agent.sock --unjailed            # dev host that can't jail
agent serve --socket ./agent.sock --prewarm 4           # a pre-warmed pool of 4 clones for fast `open`
```

Logs go to **stderr** (`--log` / `AGENT_LOG`, default `info`); the socket carries only the protocol.
The guest kernel/rootfs come from the environment (`AGENT_KERNEL` / `AGENT_ROOTFS` / `AGENT_MARKER`),
the same `AGENT_*` layer the CLI reads, a daemon has no `.agent.toml` cwd discovery.

**Confinement is the daemon's, not the client's.** A connection cannot ask for `--unjailed`; the
jail posture is fixed when the daemon launches, so a caller can never weaken it. The same holds for
`--require-limits` (also `AGENT_REQUIRE_LIMITS`): with it set, a session whose cpu/memory cgroup caps
can't be applied is refused rather than booted uncapped (ADR 010's fail-open is the default), so a
hoster can make the resource envelope load-bearing on a shared host. Both are hoster postures, not
per-session wire fields; the prewarm source clears `require_limits` (it must be unjailed to snapshot,
so it can't be capped) while the jailed clones that run sessions enforce it.

**Access control is the hoster's.** The daemon does no authentication. Who may connect is governed by
the filesystem permissions on the socket and its directory, place the socket where only trusted
local clients can reach it. (The socket file itself is pinned to `0660` at bind, defense-in-depth
against a permissive ambient umask; the directory remains the designed gate.)

**Bounded sessions with `--max-sessions N` (default 16).** Every session is a full microVM (guest
RAM, a tap, a cgroup), so the daemon bounds its own core resource: at the ceiling a new connection
gets a typed, fatal `"at capacity"` error as its `open` reply, *before* any VM boots, instead of a
connect-loop walking the host into memory/KVM/fd exhaustion. Size it to the host (sessions × guest
memory must fit in RAM); `0` means unlimited. This is engine self-protection, not tenancy: no
queueing, no auth, no scheduling.

**Idle sessions drop with `--idle-timeout SECONDS` (default 300).** The idle half of the same
guarantee: a session with no request from its client for this long is dropped, freeing its microVM
and its `--max-sessions` slot, so a wedged or forgotten connection can't pin capacity forever. It
covers the wait for the first `open` too; a client that keeps sending requests keeps resetting it.
`0` disables it.

**Shutdown.** SIGTERM/SIGINT gets a prompt, clean exit: the daemon logs, unlinks its socket, and
exits `0`. In-flight sessions end crash-consistently, their VMs reaped by the lifetime sentinel,
the same guarantee as a hard kill; the unlink just spares the next start the stale-socket check.

**Fast `open` with `--prewarm N`.** The daemon boots one unjailed pre-warmed source, snapshots it,
and keeps a [pre-warmed pool](./embedding.md) of `N` restored clones. A **bare** `open` (no resource
knobs) pops a warm
clone in milliseconds and answers `"pooled": true`; an `open` with a custom profile (or a daemon
without `--prewarm`) cold-boots. Building the pool needs KVM (and root, for jailed clones) and is
**fail-open**: a host that can't build it logs one warning and every session cold-boots.

## The wire protocol (versioned JSON, `schema: 1`)

Newline-delimited JSON: the client sends one request object per line, the daemon answers with
response lines. **Every message carries a leading `schema` field**; a peer that sends a different
number gets a fatal, session-ending error before its body is trusted.

Line-delimited JSON (not the length-prefixed binary framing of the host↔guest channel), and not gRPC,
because the peer is a **local, trusted-ish client**: the daemon is synchronous with no async runtime,
and hand-debuggability (`socat`, `nc`) plus "any language with a JSON library and a unix socket can
drive it" matter more than a compact wire (decision 030). Every decode is bounded and typed, so a
malformed or oversize line is an error the daemon reports or drops, never a panic (guardrail 5).

One connection is one sandbox **session**: the VM *is* the session, so repeated verbs share one
working directory, and closing the connection tears the sandbox down.

The shared wire contract lives in the `agent-protocol` crate (serde-only, no `agent-vmm`), so the
daemon, the [reference client](#the-reference-client), and the future polyglot SDKs all speak exactly
the same shapes.

### Requests

| Request | Meaning |
|---|---|
| `{"schema":1,"op":"open","vcpus":2,"mem_mib":512,"wall_secs":60,"output_cap":16777216}` | Boot the session's sandbox (all knobs optional; omitted keeps the conservative default). **First message.** A knobbed `open` is never served from the pool. |
| `{"schema":1,"op":"exec","argv":["echo","hi"],"stdin":"text\n"}` | Run a command, feeding `stdin` (UTF-8 text). |
| `{"schema":1,"op":"put","path":"in.txt","content":"data\n"}` | Write a UTF-8 file into the working directory, for a later `exec`/`get`. |
| `{"schema":1,"op":"get","path":"out.txt"}` | Read a working-directory file back. A missing file is `present:false`, not an error. |
| `{"schema":1,"op":"snapshot"}` | Snapshot the session VM into a daemon-host bundle. A **jailed** session is a typed refusal, deliberately (not a gap): a jailed VM's disk lives at a chroot-relative path torn down with the VM, so a bundle would record an unrestorable backing. Snapshot an unjailed source and restore jailed clones (decision 009). |
| `{"schema":1,"op":"trace"}` | Return the host-observed audit record (`RunRecord`) so far, as a JSON object. Sampled **live** (repeatable mid-session): its coverage reflects attach time, and an absent axis may be a transient read, not a finalized gap (unlike the CLI's `--record`). |
| `{"schema":1,"op":"trace_summary"}` | Return the **model-legible summary** so far, the compact projection the CLI's `--record-summary` writes (what it reached, what egress was denied, its resource envelope, any coverage gap), sampled live like `trace`. The face an agent reads between turns. |
| `{"schema":1,"op":"close"}` | End the session and tear the sandbox down (a hung-up connection does the same). |

`put`/`get` carry **UTF-8 text**; bulk or binary I/O is the block-device path
(`BootConfig::input_dir`/`output_dir`), not this per-message line.

### Responses

| Response | Meaning |
|---|---|
| `{"schema":1,"reply":"opened","boot_ms":118,"pooled":false}` | The sandbox booted; `pooled` says whether it came from the pre-warmed pool. |
| `{"schema":1,"reply":"result","exit_code":0,"stdout":"hi\n","stderr":"","exec_wall_ms":7}` | A command finished (`stdout`/`stderr` lossy UTF-8, like `agent run --json`; a non-zero `exit_code` is a *result*, not an error). |
| `{"schema":1,"reply":"put","path":"in.txt"}` | A `put` landed. |
| `{"schema":1,"reply":"got","path":"out.txt","content":"data\n","present":true}` | A `get`'s contents (`present:false` + empty `content` when the file is absent). |
| `{"schema":1,"reply":"snapshotted","dir":"/tmp/agent-snapshots-…/snap-0"}` | A snapshot bundle was written to that **daemon-host** directory. |
| `{"schema":1,"reply":"trace","record":{…}}` | The audit record as a **signed envelope** (decision 034): `{schema, key_id, signature, record}`, where `record` is the canonical record JSON carried as a string. Verify it with `agent verify` or the trusted public key. Within a session, successive `trace` replies are **hash-chained** (each carries a `prev` field = the SHA-256 of the previous record), so a client can verify the sequence as a whole and detect a dropped or reordered record. |
| `{"schema":1,"reply":"trace_summary","summary":{…}}` | The record summary as its own JSON object (with its own leading `schema`, the *summary* version). |
| `{"schema":1,"reply":"closed"}` | The session ended cleanly. |
| `{"schema":1,"reply":"error","message":"…","fatal":false}` | The request could not be served. `fatal:true` means the session is gone (reconnect); `fatal:false` is a per-request fault (a command that couldn't spawn, a schema-valid but malformed line) the session survives. A wrong `schema` is `fatal:true`. |

Drive it by hand:

```console
$ printf '%s\n' \
    '{"schema":1,"op":"open"}' \
    '{"schema":1,"op":"exec","argv":["echo","hi"]}' \
    '{"schema":1,"op":"close"}' \
  | socat - UNIX-CONNECT:./agent.sock
{"schema":1,"reply":"opened","boot_ms":118,"pooled":false}
{"schema":1,"reply":"result","exit_code":0,"stdout":"hi\n","stderr":"","exec_wall_ms":7}
{"schema":1,"reply":"closed"}
```

## Observability for the hoster

The daemon exposes its own numbers; dashboards, alerting, and retention are the hoster's, above the
engine (engine, not platform).

### Structured logs

Operational logs are structured `tracing` events on **stderr**, human-readable text by default,
or one JSON object per line with `--log-json` (or `AGENT_LOG_FORMAT=json`) for a log shipper. The
events and their fields (`vmm_pid`, `boot_ms`, `pooled`, …) are identical in both encodings; the flag
changes only the framing. The filter is `--log` / `AGENT_LOG` (default `info`, the per-session
open/close lines are the daemon's operational trace).

```console
agent serve --socket ./agent.sock --log-json --log info 2>> /var/log/agent.jsonl
```

### Metrics (Prometheus)

`--metrics ADDR` serves the Prometheus text-exposition format at `GET /metrics`:

```console
agent serve --socket ./agent.sock --metrics 127.0.0.1:9920
curl -s http://127.0.0.1:9920/metrics
```

The endpoint is **off by default**, and it serves plain HTTP with **no auth** (the same posture as
the unix socket: access control is the hoster's), bind it to loopback or a private scrape network,
never a public interface. If the requested address can't be bound, the daemon **refuses to start**
(an operational surface you asked for must not silently be absent). Durations follow the Prometheus
convention of base units: **seconds**, never milliseconds.

| Metric | Type | Meaning |
|---|---|---|
| `agent_build_info{version=…}` | gauge | Build metadata (value always 1). |
| `agent_sessions_opened_total{pooled=…}` | counter | Sessions opened, pre-warmed pool vs cold boot. |
| `agent_session_open_failures_total` | counter | `open`s that never produced a sandbox. |
| `agent_sessions_active` | gauge | Sessions currently open (one live microVM each). |
| `agent_requests_total{verb=…}` | counter | Requests served after `open`, by wire verb. |
| `agent_request_errors_total{kind=…}` | counter | Errored requests: `guest` (session survives) vs `infra` (session-ending). |
| `agent_protocol_errors_total` | counter | Wire lines that failed to decode (malformed, oversize, wrong schema). |
| `agent_boot_seconds` | histogram | Boot-to-serving latency (warm pops and cold boots alike). |
| `agent_guest_command_seconds` | histogram | Host-observed wall time of guest commands. |
| `agent_pool_ready` | gauge | Warm clones ready in the pool, **absent** (not zero) without a pool. |

A minimal scrape config:

```yaml
scrape_configs:
  - job_name: agent
    static_configs:
      - targets: ["127.0.0.1:9920"]
```

## The reference client

`agent-client` is the **reference Rust client**: a `Client` type that drives the whole session
(`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`trace_summary`/`close`) over the socket. It depends on
`agent-protocol` and a JSON value **only, never `agent-vmm`**, which is the point: it proves a
caller drives the daemon with nothing but the wire contract, the exact surface a non-Rust SDK has.
The polyglot SDKs (Go/Python/Node/C#, planned) are this client's method set hardened per language.

```rust,ignore
use agent_client::{Client, OpenOptions};

let mut client = Client::connect("/run/agent/agent.sock")?;
client.open(OpenOptions::default())?;               // boot the session's sandbox
let run = client.exec(&["echo".into(), "hi".into()], "")?;
assert_eq!(run.stdout, "hi\n");
client.put("input.txt", "payload\n")?;              // stage a file for a later exec
let record = client.trace()?;                       // the host-observed audit record (a JSON value)
client.close()?;                                    // tear the sandbox down
```

## Non-goals: where a PaaS would begin

The daemon is the engine's *programmatic interface*, and it stops exactly where a platform would
start. These are the features a hoster builds **above** `agent`, deliberately absent from the wire
and the daemon, and PRs adding them are wrong by design (engine, not platform):

- **No tenancy or identity.** No message carries a tenant, account, or user. One connection drives
  one sandbox; two callers are two connections to two VMs. *Whose* run is whose is the hoster's
  bookkeeping, above the socket.
- **No authentication or authorization.** The daemon does no auth handshake and trusts whoever can
  reach the socket completely. Who may connect is the filesystem permissions on the socket and its
  directory (place it where only trusted local clients can reach it), an access-control layer the
  hoster owns, not a field on the wire.
- **No billing or quotas.** The daemon *measures* (the [metrics endpoint](#metrics-prometheus),
  host-observed) but never *charges* or *caps by account*. Turning numbers into a bill or a per-tenant
  limit is the hoster's.
- **No fleet scheduling.** One `agent` drives sandboxes on its one host. Bin-packing across hosts,
  queues, and autoscaling are the hoster's scheduler; the daemon has no notion of another host.
- **No public/HTTP platform API.** The surface is a *local* unix socket speaking newline-JSON. A
  daemon that grew a multi-tenant identity model or a public HTTP surface would be a **hoster**, not
  this repo.

The line is a security boundary too: everything the daemon ships is inert without the host
privileges the hoster grants, and the confinement posture is fixed at launch so a client can never
weaken it. This restates, at the wire-API layer, the embedding-side
[Where the engine ends](./embedding.md#where-the-engine-ends-the-enginepaas-line).

## Teardown

Teardown is crash-only, like the rest of the engine. A session's sandbox drops when its connection
ends; and losing the whole daemon process (a supervisor's `SIGTERM`, `SIGKILL`, OOM) can't leak a VM
either, the lifetime sentinel reaps it, and the next start clears a stale socket file. A graceful
drain of in-flight sessions on shutdown is a later operational concern.
