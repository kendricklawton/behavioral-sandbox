# Using the `bsx serve` daemon

`bsx serve` is the engine's **programmatic interface**: a long-lived daemon that exposes the sandbox
lifecycle over a **unix socket**, so a local client drives microVMs without linking the `bsx-engine`
library. It is a thin host of the same public API the [CLI](./cli.md) and [embedders](./embedding.md)
use, and it stays **engine, not platform**: what sits above that line is a recorded non-goal, listed
in [Where the engine ends](./embedding-scope.md).

> **Status.** The wire API is **versioned**: every message carries a `schema` field, and a
> mismatch is rejected up front. Until the first supported release the shape may still change; the
> stamp is what makes that survivable for a client.

## Run it

```console
bsx serve --socket /run/bsx/bsx.sock                  # jailed by default (needs root + the jailer)
bsx serve --socket ./bsx.sock --unjailed              # dev host that can't jail
bsx serve --socket ./bsx.sock --prewarm 4             # a pre-warmed pool of 4 clones for fast `open`
```

Logs go to **stderr** (`--log` / `BSX_LOG`, default `info`); the socket carries only the protocol.
The guest kernel/rootfs come from the environment (`BSX_KERNEL` / `BSX_ROOTFS` / `BSX_MARKER`),
the same `BSX_*` layer the CLI reads, a daemon has no `.bsx.toml` cwd discovery. That last part
matters for `BSX_GATEWAY` / `BSX_RESOLVER`: the environment is the *only* way to give a daemon's
sessions a route, since the file layer the CLI would read is not consulted here.

**Confinement is the daemon's, not the client's.** A connection cannot ask for `--unjailed`; the
jail posture is fixed when the daemon launches, and no field of the wire's `open` carries a jail
knob, so weakening it is not expressible on the wire. The same holds for
`--require-limits` (also `BSX_REQUIRE_LIMITS`): with it set, a session whose cpu/memory cgroup caps
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

**Size the daemon's own heap alongside the guests'.** Decoding one request costs a multiple of the
line, because the wire is internally tagged JSON and serde buffers a message before it can dispatch
on the tag. Measured 2026-08-10 on an `x86_64` host: up to **40x** a 4 MiB request at the
request-line cap, so roughly **2.5 GiB** across the default 16 sessions, transient and reachable
with nothing but well-formed, legally-sized lines. It is bounded on both axes and no client gets past
it, but it is host memory that neither `--max-committed-mem-mib` (guest RAM) nor `--max-sessions`
(a count) accounts for, so budget it separately or lower the session ceiling.

**Idle sessions drop with `--idle-timeout SECONDS` (default 300).** The idle half of the same
bound: a session whose connection makes no *progress* for this long is dropped, whether the client
stopped sending requests or stopped draining replies (the flag arms both the read and the write
deadline), freeing its microVM and
its `--max-sessions` slot, so a wedged or forgotten connection does not hold capacity indefinitely. It
covers the wait for the first `open` too; a client that keeps the connection moving keeps resetting it.
`0` disables it.

**A running command is bounded by `--max-wall-secs SECONDS` (default 3600), not by the idle
timeout.** A session in the middle of an `exec` sends nothing and reads nothing, so the idle deadline
deliberately does not arm: a long quiet command is a working session, not a wedged one. What ends
that exec is the wall budget, which the client names in its `open` and this flag bounds. The bound
matters because the wall is also the *host's* give-up deadline on a guest that stops reporting its
command's end, so an `open` free to ask for any wall could hold a slot, a microVM, and its committed
memory for as long as it liked. The default is the ceiling the in-guest agent already clamps a
command to, so it refuses only an ask a cooperating guest would never have run out; an `open` past it
is refused rather than quietly clamped, and `0` restores the unbounded wall.

**Snapshot disk is bounded by `--max-snapshots N` (default 16).** A `snapshot` bundle is roughly the
session's guest RAM plus a copy of its root disk, and it **outlives the session**: the reply is a
host path, and no wire verb consumes one, so nothing reclaims a bundle but you. That makes disk the
one committed resource `--max-committed-mem-mib` does not cover, and an unbounded `snapshot` loop
would fill the scratch filesystem. Past the ceiling a `snapshot` is refused (`refused`, and the
session continues); the count is read from disk on each request, so removing a bundle you have
consumed frees budget without restarting the daemon. `0` is unlimited. Only an `--unjailed` daemon
reaches this at all: snapshotting a jailed session is a typed refusal, since its disk lives in the
chroot.

**Egress destinations are bounded by `--max-egress CIDR` (repeatable, unset by default).** A session
that asks for a NIC builds its egress policy from the `allow` rules in its `open`; this bounds which
destinations those rules may name, and an `open` reaching outside every entry is refused naming the
CIDR it asked for. Takes `IP` or `IP/PREFIX` in either address family, and the family follows from
the address. Unset is no CIDR ceiling rather than an open tap: the tap denies by default, so a client
still reaches only what it explicitly asked for, and what the operator gives up is the say over
*what* it may ask for.

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

`bsx-client` is the **reference Rust client**: a `Client` type that drives the whole session
(`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`trace_summary`/`cancel`/`close`) over the socket. It
depends on
`bsx-protocol` and a JSON value **only, never `bsx-engine`**, which is the point: it demonstrates that a
caller can drive the daemon with nothing but the wire contract, the exact surface a non-Rust
client has. The wire protocol is documented so any language can drive it directly.

It pins the same way the engine does (`bsx-client = { git =
"https://github.com/kendricklawton/behavioral-sandbox", rev = "…" }`, directory `crates/client`).
Its manifest carries `publish = false`, as every crate here does, so nothing is published from this
repo today. What is worth noting is that the argument *against* publishing does not apply to this
one: the support-window reasoning in [Where the engine ends](./embedding-scope.md) is computed from
Firecracker's, and this crate's whole dependency list is `bsx-protocol` and `serde_json`. Whether
that line ever gets lifted is a question for the version sweep, not a promise here.

```rust,ignore
use bsx_client::{Client, OpenParams};

let mut client = Client::connect("/run/bsx/bsx.sock")?;
client.open(OpenParams::default())?;                // boot the session's sandbox
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
rule set past the kernel map's fixed count is caught with the cap named. The refusal's `kind` field
says which side must move: a malformed ask is `protocol` (fix the client), a posture the operator
declined is `refused` (don't retry as-is); the [fault table](./daemon-protocol.md#error-kinds)
draws the whole taxonomy. The `.bsx.toml` operator
policy (`allow_net`, the `max_egress_*` ceilings) is the *CLI's* enforcement surface. The daemon
runs the same checks, but nothing sets those values: it reads no config file and has no flag for
them, so what actually binds a session is the flag ceilings the daemon was launched with plus the
invariants below.

**A NIC over the wire is always policed, deny-all at minimum.** Every networked `open` starts from
`EgressPolicy::deny_all` and adds allowances to it, so there is no path through that produces an
unarmed tap; `open_network_resolves_the_wire_request_against_the_operators_ceilings` opens a bare
NIC and reads the armed policy back. This is the one place the daemon is
deliberately stricter than the CLI. A bare `bsx run --net` attaches observe-only, and that is safe
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

- **[The wire protocol](./daemon-protocol.md)**, the versioned newline-JSON surface a client drives:
  requests, responses, error kinds, the compatibility rules, and worked exchanges.
- **[Observability for the hoster](./daemon-observability.md)**, the structured logs and the
  Prometheus metrics a long-lived daemon exposes.
