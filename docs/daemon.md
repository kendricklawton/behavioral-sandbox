# Using the `ekvm serve` daemon

`ekvm serve` is the engine's **programmatic interface**: a long-lived daemon that exposes the sandbox
lifecycle over a **unix socket**, so a local client drives microVMs without linking the `ekvm-engine`
library. It is a thin host of the same public API the [CLI](./cli.md) and [embedders](./embedding.md)
use, and it stays **engine, not platform**: what sits above that line is a recorded non-goal, listed
in [Where the engine ends](./embedding-scope.md).

> **Status.** The wire API is **versioned**: every message carries a `schema` field, and a
> mismatch is rejected up front. Until the first supported release the shape may still change; the
> stamp is what makes that survivable for a client.

## Run it

```console
ekvm serve --socket /run/ekvm/ekvm.sock                  # jailed by default (needs root + the jailer)
ekvm serve --socket ./ekvm.sock --unjailed              # dev host that can't jail
ekvm serve --socket ./ekvm.sock --prewarm 4             # a pre-warmed pool of 4 clones for fast `open`
```

Logs go to **stderr** (`--log` / `EKVM_LOG`, default `info`); the socket carries only the protocol.
The guest kernel/rootfs come from the environment (`EKVM_KERNEL` / `EKVM_ROOTFS` / `EKVM_MARKER`),
the same `EKVM_*` layer the CLI reads, a daemon has no `.ekvm.toml` cwd discovery. That last part
matters for `EKVM_GATEWAY` / `EKVM_RESOLVER`: the environment is the *only* way to give a daemon's
sessions a route, since the file layer the CLI would read is not consulted here.

**Confinement is the daemon's, not the client's.** A connection cannot ask for `--unjailed`; the
jail posture is fixed when the daemon launches, and no field of the wire's `open` carries a jail
knob, so weakening it is not expressible on the wire. The same holds for
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
bound: a session whose connection makes no *progress* for this long is dropped, whether the client
stopped sending requests or stopped draining replies (the flag arms both the read and the write
deadline), freeing its microVM and
its `--max-sessions` slot, so a wedged or forgotten connection does not hold capacity indefinitely. It
covers the wait for the first `open` too; a client that keeps the connection moving keeps resetting it.
`0` disables it.

**Shutdown.** SIGTERM/SIGINT gets a prompt, clean exit: the daemon logs, unlinks its socket, and
exits `0`. In-flight sessions end crash-consistently, their VMs reaped by the lifetime sentinel,
the same path a hard kill takes; the unlink just spares the next start the stale-socket check.

**Fast `open` with `--prewarm N`.** The daemon boots one unjailed pre-warmed source, snapshots it,
and keeps a [pre-warmed pool](./embedding.md) of `N` restored clones. A **bare** `open` (no resource
knobs) pops a warm
clone by restore rather than cold boot and answers `"pooled": true`; an `open` with a custom profile (or a daemon
without `--prewarm`) cold-boots. Building the pool needs KVM (and root, for jailed clones) and is
**fail-open**: a host that can't build it logs one warning and every session cold-boots.

## The reference client

`ekvm-client` is the **reference Rust client**: a `Client` type that drives the whole session
(`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`trace_summary`/`cancel`/`close`) over the socket. It
depends on
`ekvm-protocol` and a JSON value **only, never `ekvm-engine`**, which is the point: it demonstrates that a
caller can drive the daemon with nothing but the wire contract, the exact surface a non-Rust SDK has.
A language SDK is this client's method set hardened per language. Python first, since the caller
driving a sandbox is usually an agent loop, then Go and Node; **none is written**. The wire protocol
is documented so any language can drive it without one.

It pins the same way the engine does (`ekvm-client = { git = "https://github.com/ekvm-rs/ekvm",
rev = "…" }`, directory `crates/client`). Its manifest carries `publish = false`, as every crate
here does, so nothing is published from this repo today. What is worth noting is that the argument
*against* publishing does not apply to this one: the support-window reasoning in [Where the engine
ends](./embedding-scope.md) is computed from Firecracker's, and this crate's whole dependency list
is `ekvm-protocol` and `serde_json`. Whether that line ever gets lifted is a question for the
version sweep, not a promise here.

```rust,ignore
use ekvm_client::{Client, OpenOptions};

let mut client = Client::connect("/run/ekvm/ekvm.sock")?;
client.open(OpenOptions::default())?;               // boot the session's sandbox
let run = client.exec(&["echo".into(), "hi".into()], "")?;
assert_eq!(run.stdout, "hi\n");
client.put("input.txt", "payload\n")?;              // stage a file for a later exec
let record = client.trace()?;                       // the host-observed audit record (a JSON value)
client.close()?;                                    // tear the sandbox down
```

## What a session may ask for, and what it may not

`open` carries the session's resource envelope, whether it wants a NIC (`net`), and the egress
allowances to arm on its tap (`allow`, each `IP[/CIDR][:PORT][/PROTO]`). Both default to the sealed
posture, so a client written before they existed sends bytes that still decode to no NIC at all.

The daemon refuses rather than narrowing, which `open_network_refuses_rather_than_narrowing` pins:
an `allow` without `net` names the contradiction, and a
rule set past the kernel map's fixed count is caught with the cap named. The `.ekvm.toml` operator
policy (`allow_net`, the `max_egress_*` ceilings) is the *CLI's* enforcement surface. The daemon
runs the same checks, but nothing sets those values: it reads no config file and has no flag for
them, so what actually binds a session is the flag ceilings the daemon was launched with plus the
invariants below.

**A NIC over the wire is always policed, deny-all at minimum.** Every networked `open` starts from
`EgressPolicy::deny_all` and adds allowances to it, so there is no path through that produces an
unarmed tap; `open_network_resolves_the_wire_request_against_the_operators_ceilings` opens a bare
NIC and reads the armed policy back. This is the one place the daemon is
deliberately stricter than the CLI. A bare `ekvm run --net` attaches observe-only, and that is safe
there because the caller is local and owns the config file. A wire client is neither, so leaving it
observe-only would mean a session could ask for a NIC with no allowances and get an unpoliced tap:
unrestricted egress on any host that configured a gateway and furnished an uplink.

Two things stay the daemon's:

- **Whether a route out exists.** The gateway is the daemon's launch-time `BootConfig`, like the
  jail, so no wire message can route a session out of its sandbox. A client can ask for a NIC and
  bound what crosses it; it cannot create a path. The division of labour is
  [decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster).
- **That enforcement does not fail open.** A session whose tap could not be policed is ended (the
  attach error is session-fatal, not a logged warning), never
  run with its caller believing an allow-list is in force. Observation still fails open: a host
  without the eBPF caps yields a coverage-gapped record, not a refused session.

A networked `open` is never served from the pre-warmed pool: pool eligibility is the bare default
profile, `net`/`allow` make an `open` non-bare, and a pooled clone restores a snapshot with its NIC
presence baked in, so a networked session cold-boots instead.

## Non-goals: where a PaaS would begin

The canonical engine/PaaS line is drawn in [Where the engine ends](./embedding-scope.md); the daemon
adds nothing that crosses it. Its wire-level consequences:

- **No message carries a tenant, account, or user.** One connection drives one sandbox; two
  callers are two connections to two VMs. Whose run is whose is the hoster's bookkeeping, above
  the socket.
- **The socket is the whole auth surface.** No handshake: whoever can reach the socket is trusted.
  Access control is the filesystem permissions on the socket and its directory (see
  [Run it](#run-it)).
- **The daemon measures, never charges.** The [metrics endpoint](./daemon-observability.md#metrics-prometheus) exposes
  host-observed numbers; bills, quotas, and per-tenant caps are built above them.
- **One daemon, one host.** Bin-packing, queues, and autoscaling live in the hoster's scheduler;
  the daemon has no notion of another host, and its control surface stays a local unix socket, not
  a public HTTP API (the optional `--metrics ADDR` listener is separate and read-only, and a
  non-loopback bind draws a warning).

The line is a security boundary too: the confinement posture is fixed at daemon launch, and the
wire carries no field that could move it.

## Teardown

Teardown is crash-only, like the rest of the engine. A session's sandbox drops when its connection
ends; and when the whole daemon process is lost (a supervisor's `SIGTERM`, `SIGKILL`, OOM) the
lifetime sentinel reaps the VM, which `driver_death_cannot_leak_a_vm` exercises by SIGKILLing a
driver mid-run, and the next start clears a stale socket file. A graceful
drain of in-flight sessions on shutdown is a later operational concern.

## The rest of this chapter

- **[The wire protocol](./daemon-protocol.md)**, the versioned newline-JSON surface an SDK drives:
  requests, responses, error kinds, the compatibility rules, and worked exchanges.
- **[Observability for the hoster](./daemon-observability.md)**, the structured logs and the
  Prometheus metrics a long-lived daemon exposes.
