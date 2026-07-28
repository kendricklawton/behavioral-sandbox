# Using the `ekvm serve` daemon

`ekvm serve` is the engine's **programmatic interface**: a long-lived daemon that exposes the sandbox
lifecycle over a **unix socket**, so a local client drives microVMs without linking the `vmm`
library. It is a thin host of the same public API the [CLI](./cli.md) and [embedders](./embedding.md)
use, and it stays **engine, not platform**: no tenancy, no auth, no billing, no scheduler (those are
the hoster's, above the engine, and are a recorded non-goal).

> **Status.** The wire API is **versioned**: every message carries a `schema` field, and a
> mismatch is rejected up front. Until the first tagged release the shape may still change; the
> stamp is what makes that survivable for a client.

## Run it

```console
ekvm serve --socket /run/ekvm/ekvm.sock                  # jailed by default (needs root + the jailer)
ekvm serve --socket ./ekvm.sock --unjailed              # dev host that can't jail
ekvm serve --socket ./ekvm.sock --prewarm 4             # a pre-warmed pool of 4 clones for fast `open`
```

Logs go to **stderr** (`--log` / `EKVM_LOG`, default `info`); the socket carries only the protocol.
The guest kernel/rootfs come from the environment (`EKVM_KERNEL` / `EKVM_ROOTFS` / `EKVM_MARKER`),
the same `EKVM_*` layer the CLI reads, a daemon has no `.ekvm.toml` cwd discovery.

**Confinement is the daemon's, not the client's.** A connection cannot ask for `--unjailed`; the
jail posture is fixed when the daemon launches, so a caller can never weaken it. The same holds for
`--require-limits` (also `EKVM_REQUIRE_LIMITS`): with it set, a session whose cpu/memory cgroup caps
can't be applied is refused rather than booted uncapped (fail-open is the default), so a
hoster can make the resource envelope load-bearing on a shared host. Both are hoster postures, not
per-session wire fields; the prewarm source clears `require_limits` (it must be unjailed to snapshot,
so it can't be capped) while the jailed clones that run sessions enforce it.

**Access control is the hoster's.** The daemon does no authentication. Who may connect is governed by
the filesystem permissions on the socket and its directory, place the socket where only trusted
local clients can reach it. (The socket file itself is pinned to `0660` at bind, defense-in-depth
against a permissive ambient umask; the directory remains the designed gate.)

**Bounded sessions with `--max-sessions N` (default 16).** Every session is a full microVM (guest
RAM, a tap, a cgroup), so the daemon bounds its own core resource: at the ceiling a new connection
gets a distinct, session-ending `at_capacity` reply to its `open`, *before* any VM boots, instead of a
connect-loop walking the host into memory/KVM/fd exhaustion. `at_capacity` is its own reply (not an
`error`), so a fleet dispatcher fails over to another host on backpressure without
string-matching. Size it to the host (sessions × guest memory must fit in RAM); `0` means unlimited.
Because a session's `open` may ask for a custom size, `--max-sessions` alone can't bound a
memory-heterogeneous fleet; add `--max-committed-mem-mib` / `--max-committed-vcpus` to bound the
*summed* committed memory / vCPUs across live sessions **and pre-warmed pool clones** (a clone's
RAM is real before any session exists, so the pool charges the ceiling too: a `--prewarm` the
ceiling can't hold refuses to start, a refill only restores what current headroom affords, and a
warm take hands its clone's charge over to the session's own reservation). Sessions past the
ceiling are refused with `at_capacity` before boot.

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
because the peer is a **local, trusted-ish client**: the daemon is synchronous with no async runtime
(a recorded decision with its own re-open conditions, see
[the design notes](./design.md#7-synchronous-engine-no-async-runtime)),
and hand-debuggability (`socat`, `nc`) plus "any language with a JSON library and a unix socket can
drive it" matter more than a compact wire. Every decode is bounded and typed, so a
malformed or oversize line is an error the daemon reports or drops, never a panic.

One connection is one sandbox **session**: the VM *is* the session, so repeated verbs share one
working directory, and closing the connection tears the sandbox down.

The shared wire contract lives in the `protocol` crate (serde-only, no `vmm`), so the
daemon, the [reference client](#the-reference-client), and the future polyglot SDKs all speak exactly
the same shapes.

### Requests

| Request | Meaning |
|---|---|
| `{"schema":1,"op":"open","vcpus":2,"mem_mib":512,"wall_secs":60,"output_cap":16777216}` | Boot the session's sandbox (all knobs optional; omitted keeps the conservative default). **First message.** A knobbed `open` is never served from the pool. |
| `{"schema":1,"op":"exec","argv":["echo","hi"],"stdin":"text\n"}` | Run a command, feeding `stdin` (UTF-8 text). |
| `{"schema":1,"op":"put","path":"in.txt","content":"data\n"}` | Write a UTF-8 file into the working directory, for a later `exec`/`get`. |
| `{"schema":1,"op":"get","path":"out.txt"}` | Read a working-directory file back. A missing file is `present:false`, not an error. |
| `{"schema":1,"op":"snapshot"}` | Snapshot the session VM into a daemon-host bundle. A **jailed** session is a typed refusal, deliberately (not a gap): a jailed VM's disk lives at a chroot-relative path torn down with the VM, so a bundle would record an unrestorable backing. Snapshot an unjailed source and restore jailed clones. |
| `{"schema":1,"op":"trace"}` | Return the host-observed audit record (`RunRecord`) so far, as a JSON object. Sampled **live** (repeatable mid-session): its coverage reflects attach time, and an absent axis may be a transient read, not a finalized gap (unlike the CLI's `--record`). |
| `{"schema":1,"op":"trace_summary"}` | Return the **model-legible summary** so far, the compact projection the CLI's `--record-summary` writes (what it reached, what egress was denied, its resource envelope, any coverage gap), sampled live like `trace`. The face an agent reads between turns. |
| `{"schema":1,"op":"cancel"}` | Abandon an **in-flight** request and end the session, answered `cancelled`. The one verb legal while another request is outstanding: it exists because a client blocked on a long `exec` has no other way to reach the daemon. **It ends the session, it does not abort one command**: the engine cancels a running exec by killing the sandbox, so session state dies with it (snapshot first if it matters). Hanging up has the same end state, but the daemon cannot notice until the in-flight request finishes on its own, so the sandbox holds its `--max-sessions` slot and guest RAM for up to the remaining wall budget; `cancel` reclaims both immediately. |
| `{"schema":1,"op":"close"}` | End the session and tear the sandbox down (a hung-up connection does the same). |

`put`/`get` carry **UTF-8 text**; bulk or binary I/O is the block-device path
(`BootConfig::input_dir`/`output_dir`), not this per-message line.

### Responses

| Response | Meaning |
|---|---|
| `{"schema":1,"reply":"opened","boot_ms":118,"pooled":false}` | The sandbox booted; `pooled` says whether it came from the pre-warmed pool. |
| `{"schema":1,"reply":"result","exit_code":0,"stdout":"hi\n","stderr":"","exec_wall_ms":7}` | A command finished (`stdout`/`stderr` lossy UTF-8, like `ekvm run --json`; a non-zero `exit_code` is a *result*, not an error). |
| `{"schema":1,"reply":"put","path":"in.txt"}` | A `put` landed. |
| `{"schema":1,"reply":"got","path":"out.txt","content":"data\n","present":true}` | A `get`'s contents (`present:false` + empty `content` when the file is absent). |
| `{"schema":1,"reply":"snapshotted","dir":"/tmp/ekvm-snapshots-…/snap-0"}` | A snapshot bundle was written to that **daemon-host** directory. |
| `{"schema":1,"reply":"trace","record":{…}}` | The audit record as a **signed envelope**: `{schema, key_id, signature, record}`, where `record` is the canonical record JSON carried as a string. Verify it with `ekvm verify` or the trusted public key. Within a session, successive `trace` replies are **hash-chained** (each carries a `prev` field = the SHA-256 of the previous record), so a client can verify the sequence as a whole and detect a dropped or reordered record. |
| `{"schema":1,"reply":"trace_summary","summary":{…}}` | The record summary as its own JSON object (with its own leading `schema`, the *summary* version). |
| `{"schema":1,"reply":"cancelled"}` | The in-flight request was abandoned and the sandbox torn down, acknowledging `cancel`. Always the connection's last message; whatever the cancelled request had produced is discarded. |
| `{"schema":1,"reply":"closed"}` | The session ended cleanly. |
| `{"schema":1,"reply":"error","message":"…","fatal":false,"kind":"guest"}` | The request could not be served. `fatal:true` means the session is gone (reconnect); `fatal:false` is a per-request fault (a command that couldn't spawn, a schema-valid but malformed line) the session survives. A wrong `schema` is `fatal:true`. `kind` says **whose fault** it is, so a client branches on a value instead of parsing `message`: see below. |
| `{"schema":1,"reply":"at_capacity","retry_after_ms":1000}` | The daemon is **at capacity** (the `--max-sessions` count or an aggregate resource ceiling is full) and refused the `open` before booting anything. A distinct backpressure signal (not an `error`) a dispatcher fails over on; `retry_after_ms` is a backoff hint. Always session-ending. |

### Error kinds

`fatal` answers "is this session over?"; `kind` answers "whose fault, and what should I do?". They
are independent: a guest fault is non-fatal but retrying the same command changes nothing, while a
failed boot is fatal yet nothing about the caller's request was wrong.

| `kind` | Meaning | What a client should do |
|---|---|---|
| `infra` | The host couldn't stand the sandbox up, or a bounded wait expired. | Retry, or try another host. |
| `transport` | A framing/IO fault on an established exec channel, or a guest silent past its deadline. | Retire the sandbox; don't blame the command. |
| `guest` | The run is at fault: couldn't spawn, outran its budget, flooded output. | Fix the command; an identical retry fails identically. |
| `protocol` | The client's own message: wrong `schema`, undecodable, oversize, or out of order. | Fix the client. |
| `refused` | Understood and declined: an operator-chosen posture (snapshotting a jailed session) or a capability this session lacks (no probes attached). | Don't retry as-is. |

`infra` / `transport` / `guest` are the wire form of the engine's own pinned error taxonomy
(`vmm::ErrorKind`), so a wire client and a Rust embedder classify the same failure the same way.

**Treat an unrecognized `kind` as `infra`.** The set may grow; a value your client predates means
"unclassified", and assuming the host rather than the caller is the conservative read. An absent
`kind` (a daemon older than the field) reads the same way.

### Compatibility rules (what an SDK must do)

The engine's own client is written in Rust with serde, but nothing here depends on that: an SDK in
any language faces these questions independently, so the answers are the protocol's, not the
implementation's. Three rules, in decreasing order of how often you will hit them.

**1. Ignore fields you do not recognize.** Messages may grow fields within a `schema`, so a decoder
must not reject an object because it carries something extra. This is how the wire evolves without a
version bump: a new optional field is invisible to older clients and meaningful to newer ones. An
SDK that rejects unknown fields (a strict struct decoder, a `deny_unknown_fields`-style setting)
will break on a routine daemon upgrade. Note the direction: **omitted** optional fields keep the
documented default, so absence and unfamiliarity are both safe.

**2. Reject a `reply` you do not recognize, loudly.** Unlike fields, an unrecognized *reply kind* is
a hard error and must be surfaced, not skipped. This is deliberate, and it is the opposite of
rule 1: the protocol is strict request/response, so a reply you cannot interpret means you have lost
track of what the daemon is answering. Skipping it would silently desynchronize the session and
misattribute every later reply to the wrong request. Growing the reply set is therefore a
[`schema`](#the-wire-protocol-versioned-json-schema-1) bump, not an additive change, and a bump is
rejected up front by both sides.

**3. Degrade on an unrecognized enumerated *value*.** Where a field carries a value from a named set
rather than free text, the set may grow, and an unfamiliar value must map to a documented
conservative default rather than failing. `kind` is the case that exists today: treat anything you
do not recognize (or an absent `kind`) as `infra`. Values are not replies; they carry no framing, so
degrading loses information rather than synchronization.

The short version: **fields grow, values grow, replies do not.** A `schema` mismatch is always
fatal and always reported before a body is trusted, so a client built against a future revision
fails immediately instead of half-understanding a session.

### Protocol examples

A whole session, driven by hand (an `open` with no fields takes the defaults):

```console
$ printf '%s\n' \
    '{"schema":1,"op":"open"}' \
    '{"schema":1,"op":"exec","argv":["echo","hi"]}' \
    '{"schema":1,"op":"close"}' \
  | socat - UNIX-CONNECT:./ekvm.sock
{"schema":1,"reply":"opened","boot_ms":118,"pooled":false}
{"schema":1,"reply":"result","exit_code":0,"stdout":"hi\n","stderr":"","exec_wall_ms":7}
{"schema":1,"reply":"closed"}
```

#### Inject, run, extract (`put` → `exec` → `get`)

The round trip a caller uses to collect what a run *produced*, not just what it printed:

**Request 1 (`put` the input):**
```json
{"schema":1,"op":"put","path":"app.py","content":"with open('out.txt', 'w') as f:\n    f.write('generated in the guest\\n')\n"}
```
**Response 1:**
```json
{"schema":1,"reply":"put","path":"app.py"}
```

**Request 2 (`exec` it):**
```json
{"schema":1,"op":"exec","argv":["python3","app.py"],"stdin":""}
```
**Response 2:**
```json
{"schema":1,"reply":"result","exit_code":0,"stdout":"","stderr":"","exec_wall_ms":8}
```

**Request 3 (`get` the file the run wrote):**
```json
{"schema":1,"op":"get","path":"out.txt"}
```
**Response 3:**
```json
{"schema":1,"reply":"got","path":"out.txt","content":"generated in the guest\n","present":true}
```

#### Live audit inspection (`trace_summary`)

**Request:**
```json
{"schema":1,"op":"trace_summary"}
```
**Response:**
```json
{
  "schema": 1,
  "reply": "trace_summary",
  "summary": {
    "schema": 1,
    "wall_ms": 142,
    "exit_code": 0,
    "egress_allowed": [],
    "egress_denied": [],
    "resources": {
      "user_cpu_us": 12000,
      "system_cpu_us": 4000,
      "max_rss_bytes": 28432000
    },
    "coverage_gaps": []
  }
}
```

## Observability for the hoster

The daemon exposes its own numbers; dashboards, alerting, and retention are the hoster's, above the
engine.

### Structured logs

Operational logs are structured `tracing` events on **stderr**, human-readable text by default,
or one JSON object per line with `--log-json` (or `EKVM_LOG_FORMAT=json`) for a log shipper. The
events and their fields (`vmm_pid`, `boot_ms`, `pooled`, …) are identical in both encodings; the flag
changes only the framing. The filter is `--log` / `EKVM_LOG` (default `info`, the per-session
open/close lines are the daemon's operational trace).

```console
ekvm serve --socket ./ekvm.sock --log-json --log info 2>> /var/log/ekvm.jsonl
```

### Metrics (Prometheus)

`--metrics ADDR` serves the Prometheus text-exposition format at `GET /metrics`:

```console
ekvm serve --socket ./ekvm.sock --metrics 127.0.0.1:9920
curl -s http://127.0.0.1:9920/metrics
```

The endpoint is **off by default**, and it serves plain HTTP with **no auth** (the same posture as
the unix socket: access control is the hoster's), bind it to loopback or a private scrape network,
never a public interface. If the requested address can't be bound, the daemon **refuses to start**
(an operational surface you asked for must not silently be absent). Durations follow the Prometheus
convention of base units: **seconds**, never milliseconds.

| Metric | Type | Meaning |
|---|---|---|
| `ekvm_build_info{version=…}` | gauge | Build metadata (value always 1). |
| `ekvm_sessions_opened_total{pooled=…}` | counter | Sessions opened, pre-warmed pool vs cold boot. |
| `ekvm_session_open_failures_total` | counter | `open`s that never produced a sandbox. |
| `ekvm_open_refusals_total{reason=…}` | counter | `at_capacity` refusals, by which ceiling refused: `sessions` (`--max-sessions`) vs `resources` (`--max-committed-*`). A flat zero here plus flat opens means saturation, not calm. |
| `ekvm_sessions_active` | gauge | Sessions currently open (one live microVM each). |
| `ekvm_sentinel_degraded` | gauge | Active sessions whose VM-lifetime sentinel could not be armed (fallback to Drop-only cleanup). |
| `ekvm_sweep_reclaimed_total{resource=…}` | counter | Orphaned VM resources reclaimed by sweeps (`resource="dirs"` or `"netns"`). |
| `ekvm_requests_total{verb=…}` | counter | Requests served after `open`, by wire verb. |
| `ekvm_request_errors_total{kind=…}` | counter | Errored requests: `guest` (session survives) vs `infra` (session-ending). |
| `ekvm_protocol_errors_total` | counter | Wire lines that failed to decode (malformed, oversize, wrong schema). |
| `ekvm_boot_seconds` | histogram | Boot-to-serving latency (warm pops and cold boots alike). |
| `ekvm_guest_command_seconds` | histogram | Host-observed wall time of guest commands. |
| `ekvm_pool_ready` | gauge | Warm clones ready in the pool, **absent** (not zero) without a pool. |
| `ekvm_committed_mem_mib` / `_committed_vcpus` | gauge | Guest memory (MiB) / vCPUs committed across live sessions and pre-warmed pool clones: the RAM actually spoken for. |
| `ekvm_capacity_mem_mib` / `_capacity_vcpus` | gauge | The aggregate ceilings (`--max-committed-mem-mib` / `--max-committed-vcpus`; `0` = unlimited). Scrape committed-vs-capacity to route on real headroom. |

A minimal scrape config:

```yaml
scrape_configs:
  - job_name: ekvm
    static_configs:
      - targets: ["127.0.0.1:9920"]
```

## The reference client

`client` is the **reference Rust client**: a `Client` type that drives the whole session
(`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`trace_summary`/`close`) over the socket. It depends on
`protocol` and a JSON value **only, never `vmm`**, which is the point: it proves a
caller drives the daemon with nothing but the wire contract, the exact surface a non-Rust SDK has.
The polyglot SDKs (Go/Python/Node/C#, planned) are this client's method set hardened per language.

```rust,ignore
use client::{Client, OpenOptions};

let mut client = Client::connect("/run/ekvm/ekvm.sock")?;
client.open(OpenOptions::default())?;               // boot the session's sandbox
let run = client.exec(&["echo".into(), "hi".into()], "")?;
assert_eq!(run.stdout, "hi\n");
client.put("input.txt", "payload\n")?;              // stage a file for a later exec
let record = client.trace()?;                       // the host-observed audit record (a JSON value)
client.close()?;                                    // tear the sandbox down
```

## Non-goals: where a PaaS would begin

The canonical engine/PaaS line, tenancy, auth, billing, scheduling, dashboards, is drawn in
[Where the engine ends](./embedding.md#where-the-engine-ends-the-enginepaas-line); the daemon adds
nothing that crosses it. Its wire-level consequences:

- **No message carries a tenant, account, or user.** One connection drives one sandbox; two
  callers are two connections to two VMs. Whose run is whose is the hoster's bookkeeping, above
  the socket.
- **The socket is the whole auth surface.** No handshake: whoever can reach the socket is trusted.
  Access control is the filesystem permissions on the socket and its directory (see
  [Run it](#run-it)).
- **The daemon measures, never charges.** The [metrics endpoint](#metrics-prometheus) exposes
  host-observed numbers; bills, quotas, and per-tenant caps are built above them.
- **One daemon, one host.** Bin-packing, queues, and autoscaling live in the hoster's scheduler;
  the daemon has no notion of another host, and its surface stays a local unix socket, never a
  public HTTP API.

The line is a security boundary too: the confinement posture is fixed at daemon launch, so a
client can never weaken it.

## Teardown

Teardown is crash-only, like the rest of the engine. A session's sandbox drops when its connection
ends; and losing the whole daemon process (a supervisor's `SIGTERM`, `SIGKILL`, OOM) can't leak a VM
either, the lifetime sentinel reaps it, and the next start clears a stale socket file. A graceful
drain of in-flight sessions on shutdown is a later operational concern.
