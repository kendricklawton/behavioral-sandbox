# Using the `agentd` daemon

`agentd` is the engine's **programmatic interface**: a long-lived daemon that exposes the sandbox
lifecycle over a **unix socket**, so a local client drives microVMs without linking the `agent-vmm`
library. It is a thin host of the same public API the [CLI](./cli.md) and [embedders](./embedding.md)
use, and it stays **engine, not platform**: no tenancy, no auth, no billing, no scheduler (those are
the hoster's, above the engine, and are a recorded non-goal).

> **Status.** The wire API is **versioned** (every message carries a `schema` field) but not yet
> **frozen**: a later milestone freezes and formally specs it as the SDK contract (see the
> [roadmap](https://github.com/kendricklawton/agent/blob/main/ROADMAP.md)). Until then the shape may
> still change, which is why every message is schema-stamped and a mismatch is rejected up front.

## Run it

```console
agentd --socket /run/agent/agentd.sock              # jailed by default (needs root + the jailer)
agentd --socket ./agentd.sock --unjailed            # dev host that can't jail
agentd --socket ./agentd.sock --prewarm 4           # a pre-warmed pool of 4 clones for fast `open`
```

Logs go to **stderr** (`--log` / `AGENT_LOG`, default `info`); the socket carries only the protocol.
The guest kernel/rootfs come from the environment (`AGENT_KERNEL` / `AGENT_ROOTFS` / `AGENT_MARKER`),
the same `AGENT_*` layer the CLI reads — a daemon has no `.agent.toml` cwd discovery.

**Confinement is the daemon's, not the client's.** A connection cannot ask for `--unjailed`; the
jail posture is fixed when the daemon launches, so a caller can never weaken it.

**Access control is the hoster's.** The daemon does no authentication. Who may connect is governed by
the filesystem permissions on the socket and its directory — place the socket where only trusted
local clients can reach it.

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
drive it" matter more than a compact wire (decision 034). Every decode is bounded and typed, so a
malformed or oversize line is an error the daemon reports or drops, never a panic (guardrail 5).

One connection is one sandbox **session**: the VM *is* the session, so repeated verbs share one
working directory, and closing the connection tears the sandbox down.

The shared wire contract lives in the `agentd-protocol` crate (serde-only, no `agent-vmm`), so the
daemon, the [reference client](#the-reference-client), and the future polyglot SDKs all speak exactly
the same shapes.

### Requests

| Request | Meaning |
|---|---|
| `{"schema":1,"op":"open","vcpus":2,"mem_mib":512,"wall_secs":60,"output_cap":16777216}` | Boot the session's sandbox (all knobs optional; omitted keeps the conservative default). **First message.** A knobbed `open` is never served from the pool. |
| `{"schema":1,"op":"exec","argv":["echo","hi"],"stdin":"text\n"}` | Run a command, feeding `stdin` (UTF-8 text). |
| `{"schema":1,"op":"put","path":"in.txt","content":"data\n"}` | Write a UTF-8 file into the working directory, for a later `exec`/`get`. |
| `{"schema":1,"op":"get","path":"out.txt"}` | Read a working-directory file back. A missing file is `present:false`, not an error. |
| `{"schema":1,"op":"snapshot"}` | Snapshot the session VM into a daemon-host bundle (a typed refusal for a jailed session). |
| `{"schema":1,"op":"trace"}` | Return the host-observed audit record (`RunRecord`) so far, as a JSON object. Sampled **live** (repeatable mid-session): its coverage reflects attach time, and an absent axis may be a transient read, not a finalized gap (unlike the CLI's `--record`). |
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
| `{"schema":1,"reply":"snapshotted","dir":"/tmp/agentd-snapshots-…/snap-0"}` | A snapshot bundle was written to that **daemon-host** directory. |
| `{"schema":1,"reply":"trace","record":{…}}` | The audit record as its own JSON object (with its own `schema` field, the *record* version). |
| `{"schema":1,"reply":"closed"}` | The session ended cleanly. |
| `{"schema":1,"reply":"error","message":"…","fatal":false}` | The request could not be served. `fatal:true` means the session is gone (reconnect); `fatal:false` is a per-request fault (a command that couldn't spawn, a schema-valid but malformed line) the session survives. A wrong `schema` is `fatal:true`. |

Drive it by hand:

```console
$ printf '%s\n' \
    '{"schema":1,"op":"open"}' \
    '{"schema":1,"op":"exec","argv":["echo","hi"]}' \
    '{"schema":1,"op":"close"}' \
  | socat - UNIX-CONNECT:./agentd.sock
{"schema":1,"reply":"opened","boot_ms":118,"pooled":false}
{"schema":1,"reply":"result","exit_code":0,"stdout":"hi\n","stderr":"","exec_wall_ms":7}
{"schema":1,"reply":"closed"}
```

## Observability for the hoster

The daemon exposes its own numbers; dashboards, alerting, and retention are the hoster's, above the
engine (engine, not platform).

### Structured logs

Operational logs are structured `tracing` events on **stderr** — human-readable text by default,
or one JSON object per line with `--log-json` (or `AGENT_LOG_FORMAT=json`) for a log shipper. The
events and their fields (`vmm_pid`, `boot_ms`, `pooled`, …) are identical in both encodings; the flag
changes only the framing. The filter is `--log` / `AGENT_LOG` (default `info` — the per-session
open/close lines are the daemon's operational trace).

```console
agentd --socket ./agentd.sock --log-json --log info 2>> /var/log/agentd.jsonl
```

### Metrics (Prometheus)

`--metrics ADDR` serves the Prometheus text-exposition format at `GET /metrics`:

```console
agentd --socket ./agentd.sock --metrics 127.0.0.1:9920
curl -s http://127.0.0.1:9920/metrics
```

The endpoint is **off by default**, and it serves plain HTTP with **no auth** (the same posture as
the unix socket: access control is the hoster's) — bind it to loopback or a private scrape network,
never a public interface. If the requested address can't be bound, the daemon **refuses to start**
(an operational surface you asked for must not silently be absent). Durations follow the Prometheus
convention of base units: **seconds**, never milliseconds.

| Metric | Type | Meaning |
|---|---|---|
| `agentd_build_info{version=…}` | gauge | Build metadata (value always 1). |
| `agentd_sessions_opened_total{pooled=…}` | counter | Sessions opened, pre-warmed pool vs cold boot. |
| `agentd_session_open_failures_total` | counter | `open`s that never produced a sandbox. |
| `agentd_sessions_active` | gauge | Sessions currently open (one live microVM each). |
| `agentd_requests_total{verb=…}` | counter | Requests served after `open`, by wire verb. |
| `agentd_request_errors_total{kind=…}` | counter | Errored requests: `guest` (session survives) vs `infra` (session-ending). |
| `agentd_protocol_errors_total` | counter | Wire lines that failed to decode (malformed, oversize, wrong schema). |
| `agentd_boot_seconds` | histogram | Boot-to-serving latency (warm pops and cold boots alike). |
| `agentd_guest_command_seconds` | histogram | Host-observed wall time of guest commands. |
| `agentd_pool_ready` | gauge | Warm clones ready in the pool — **absent** (not zero) without a pool. |

A minimal scrape config:

```yaml
scrape_configs:
  - job_name: agentd
    static_configs:
      - targets: ["127.0.0.1:9920"]
```

## The reference client

`agentd-client` is the **reference Rust client**: a `Client` type that drives the whole session
(`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`close`) over the socket. It depends on
`agentd-protocol` and a JSON value **only — never `agent-vmm`** — which is the point: it proves a
caller drives the daemon with nothing but the wire contract, the exact surface a non-Rust SDK has.
The polyglot SDKs (Go/Python/Node/C#, planned) are this client's method set hardened per language.

```rust,ignore
use agentd_client::{Client, OpenOptions};

let mut client = Client::connect("/run/agent/agentd.sock")?;
client.open(OpenOptions::default())?;               // boot the session's sandbox
let run = client.exec(&["echo".into(), "hi".into()], "")?;
assert_eq!(run.stdout, "hi\n");
client.put("input.txt", "payload\n")?;              // stage a file for a later exec
let record = client.trace()?;                       // the host-observed audit record (a JSON value)
client.close()?;                                    // tear the sandbox down
```

## Non-goals: where a PaaS would begin

The daemon is the engine's *programmatic interface*, and it stops exactly where a platform would
start. These are the features a hoster builds **above** `agentd`, deliberately absent from the wire
and the daemon, and PRs adding them are wrong by design (engine, not platform):

- **No tenancy or identity.** No message carries a tenant, account, or user. One connection drives
  one sandbox; two callers are two connections to two VMs. *Whose* run is whose is the hoster's
  bookkeeping, above the socket.
- **No authentication or authorization.** The daemon does no auth handshake and trusts whoever can
  reach the socket completely. Who may connect is the filesystem permissions on the socket and its
  directory (place it where only trusted local clients can reach it) — an access-control layer the
  hoster owns, not a field on the wire.
- **No billing or quotas.** The daemon *measures* (the [metrics endpoint](#metrics-prometheus),
  host-observed) but never *charges* or *caps by account*. Turning numbers into a bill or a per-tenant
  limit is the hoster's.
- **No fleet scheduling.** One `agentd` drives sandboxes on its one host. Bin-packing across hosts,
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
either — the lifetime sentinel reaps it, and the next start clears a stale socket file. A graceful
drain of in-flight sessions on shutdown is a later operational concern.
