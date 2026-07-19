# Using the engine API

The sandbox-lifecycle contract, and where the engine ends. This is the embedder's document: what
the `agent-vmm` library promises when you pin it and build on it, stated once, against the real
API. The rustdoc on each item is the reference; this is the contract's shape and the reasoning.
The second half draws the line this project refuses to cross, what the engine deliberately is
**not**, because a runtime that quietly grows platform features stops being embeddable.

Numbers in parentheses (013, 015, …) are dated
[decision records](./adr/README.md); each ADR records the rationale and the alternatives that
lost.

## The lifecycle

```
Sandbox::open(config)            confined by default: KVM + the jailer
    .exec(argv, stdin)           synchronous; RunResult, never a panic/hang/leak
    .exec_with_files(argv, stdin, files, env, artifacts)
    …repeated execs = one stateful session (the VM is the session)
    .snapshot(dir)               a portable pre-warmed bundle (unjailed sources only)
    .collect_outputs()           the bulk /output tree, back on the host
    .shutdown()                  guaranteed reclamation — also on Drop, also on SIGKILL
```

### Open: confined by default

`Sandbox::open(BootConfig)` runs the VMM under **both** walls: the KVM microVM (isolation is
hardware) and Firecracker's jailer (chroot, uid/gid drop, seccomp, its own mount and network
namespaces, a cgroup). An unset `jail` becomes `Jail::default()`; the opt-out for hosts that can't
jail (no real root, no `jailer` binary) is the *differently named constructor*
`Sandbox::open_unjailed`, so an unconfined sandbox is greppable in your source and can never happen
by a forgotten flag (015). Artifacts (kernel, rootfs, `firecracker`) layer from the environment
(`AGENT_KERNEL`, `AGENT_ROOTFS`, …) under explicit `BootConfig` fields.

### Exec: synchronous, bounded, faithful

`exec` connects to the in-guest agent over vsock, runs one command, and returns a `RunResult`:
`exit_code`, `stdout`, `stderr`, requested artifact `files`, and host-measured `metrics` (wall time
the driver observed, the guest can't lie about it). Three properties are load-bearing:

- **A crash inside the sandbox is a result, not an error.** Non-zero exit, even death by signal
  (`128 + signal`), comes back as a faithful `RunResult`. Typed `VmmError`s are reserved for the
  engine's own failure classes.
- **Every bound is host-enforced.** The command's wall budget is sent to the guest (which kills it
  cooperatively → `ExecTimeout`), but the host keeps its own derived deadline (`ExecUnresponsive`)
  and an output cap (`OutputCap`), so a hostile or wedged guest can never park the caller or grow
  host memory. The in-guest agent is exec/IO convenience, never the security boundary.
- **Per-exec inputs ride the call, under a secret-hygiene contract (018).** `stdin`, injected
  `files`, and `env` arrive with the request; env lands on the spawned command only, never the
  agent's process. Injected file contents and env *values* never appear in an engine log line, in
  any `VmmError`'s `Display`/`Debug`, or on the serial console, an error may name a file path or
  an env key, never a value, and the wire copies the engine builds are zero-wiped after send.
  Leak tests pin this; extending them is the review bar for any new log line that touches inputs.
  Bulk data goes on the block-device paths instead: `input_dir` (read-only image built from a host
  dir) and `output_dir` + `collect_outputs()` (a writable image extracted rootlessly after
  teardown).

### Sessions: the VM is the session (019)

Repeated `exec`s against one sandbox compose: the in-guest agent serves every connection from one
persistent working directory, and the boot's overlay makes the wider guest filesystem accumulate
too. Install a package in exec 1, use it in exec 3. Session identity is VM identity, no session
ids, no session protocol: two isolated sessions are two VMs, so isolation between sessions is KVM,
not agent bookkeeping. State's lifetime is the VM's; `shutdown` discards it with the overlay.

### Budgets: quantities on one struct, failing open (013)

`Limits` is the per-sandbox resource policy: `vcpus` (`NonZeroU8`), `mem_mib` (`NonZeroU32`),
`wall` (one wall for the whole run, the boot deadline and each exec's budget), and `output_cap`.
The two quantity fields are typed nonzero because zero is not a small budget but an unbootable
guest, the illegal value can't be constructed. Quantities only, never
capabilities: network egress is a separate deny-by-default concern (008), enforced in a different
layer. The cgroup caps **fail open**, a host without delegated controllers boots uncapped, with a
warning, because caps are fairness/DoS hygiene; the **isolation walls never degrade**: a jail that
can't be built is a hard error, never a silent half-confinement. Defaults are conservative and
load-bearing (1 vCPU, 256 MiB, 30 s, 16 MiB); raising one is a breaking, `api:`-marked change.

### Errors: three buckets you can branch on

Every failure is a typed `VmmError`; `VmmError::kind()` maps it to a pinned, closed `ErrorKind`:

| Bucket | Meaning | Caller's move |
|---|---|---|
| `Infra` | the host couldn't stand the VM up (incl. "agent not up yet/anymore": `GuestUnavailable`) | retry, or fix the host |
| `Transport` | the established exec channel broke mid-run | retire this VM, take another |
| `Guest` | the run's fault: couldn't spawn, outran its budget, flooded output, went silent | surface to the user |

The mapping is a tested contract (the wildcard-free match won't compile past a new variant until
it's deliberately bucketed).

### Lifetime: nothing leaks, even when *you* die

Teardown is layered so no exit path leaks a VMM, a scratch dir, a tap, or a cgroup: `shutdown` is
the polite form, `Drop` is the guarantee, and a cgroup-owned sentinel (014) reaps the VM even if
the embedding *process* is SIGKILL'd or OOM-killed. A `KillHandle` (cheap, cloneable, thread-safe)
force-kills a sandbox whose `exec` some other thread is blocked in, the host-gave-up path.
Residue from crashed embedders is reclaimed by `sweep_orphans` (ownership keyed on liveness, never
on names; only your own euid's residue), so a crash-looping host stays serviceable (016).

### Pre-warmed starts: snapshot an unjailed source, restore jailed clones

`snapshot(dir)` pauses the VM and writes a portable bundle; `Vm::restore` (and the `Pool` built on
it) brings up exec-ready clones in milliseconds, sharing the base disk and memory file read-only
across clones. The confinement story is deliberate (010, 015): a *jailed* VM refuses snapshotting
(its disk lives in the chroot), you snapshot an **unjailed pre-warmed source** that runs only your own
warm-up, and restore **jailed clones** from it, which is where the untrusted code runs. A pooled
clone is a pre-warmed session; entropy is reseeded per clone (VMGenID), and networked clones each
recreate their tap in a private netns (017), so any number coexist.

**Sizing rule** (stated here so you never meet it as `EMFILE`): each live VM holds up to
`FDS_PER_VM` (8) driver-side fds, so keep

```
N_live × FDS_PER_VM + headroom (≈64, process baseline)  ≤  ulimit -n (soft)
```

`Pool::new` checks this and logs one warning naming the numbers when a target oversubscribes the
budget, a warning, not a refusal, per the fail-open posture above. The measured steady state is 2
fds per VM on every start path, pinned by test; the constant is deliberately above it so growth is
a visible bump, never drift.

### A minimal reference integration

For the whole lifecycle in one small file, embedding the engine end to end (load the host-side
observers, `open` a jailed sandbox, attach the probes, `exec`, `collect` the audit record, `close`,
then print both the `RunResult` and the JSON record), see the runnable example
[`crates/probes-loader/examples/reference_integration.rs`](../crates/probes-loader/examples/reference_integration.rs).
It composes the driver and the loader the way a downstream host application would.

### The CLI is the reference embedder

`agent run` is the lifecycle in one command: piped stdin, `--env`, `--put`/`--get`, `--wall`,
`--output-cap`, `--json` (the structured result as one JSON object on stdout, stderr carries the
logs, so pipelines stay clean), `--unjailed` as the loud opt-out. `agent shell` holds one sandbox
open as an interactive stateful session. If you're writing an SDK, start from the daemon's
[reference client](./daemon.md#the-reference-client) (`agentd-client`), it drives the same
lifecycle over the wire API with nothing of the engine linked, which is exactly the surface a
non-Rust SDK has.

## Where the engine ends (the engine/PaaS line)

**This is an engine, not a PaaS.** The engine is the boring, embeddable core:
a runtime plus a clean driver API you self-host. The moment it grows opinions about *whose* code
runs and *who pays*, it stops being embeddable in anything with its own opinions. So, explicit
non-goals, these belong to whatever hosts the engine, and PRs adding them are wrong by design:

- **No tenancy or auth.** The engine trusts its caller completely; multi-user identity, quotas,
  and authorization live in the hoster's layer.
- **No billing or metering policy.** The engine *measures* (host-observed metrics, benchmarked
  percentiles); charging for it is the hoster's.
- **No fleet scheduling.** One engine drives sandboxes on one host. Bin-packing across hosts,
  queues, and autoscaling are the hoster's: the engine runs sandboxes on its host; it doesn't
  schedule a cluster.
- **No dashboard, no platform API.** The programmatic surface is the Rust library, the CLI, and
  the [`agentd` daemon](./daemon.md), a *local* driver daemon over a unix socket, a thin host of
  the same library's public API, with no auth and no tenancy (access control is the socket
  directory's permissions). A daemon that grows multi-tenant identity or a public HTTP surface is
  a *hoster*, not this repo.

The line is a security boundary too (016): everything the engine ships is inert without host
privileges the *hoster* grants, it self-limits (deny-by-default network, dropped-uid jail,
own-euid sweep), and turning its tools into a multi-tenant service safely is the hoster's job.

What the engine *does* owe a long-lived host, and ships: typed errors instead of panics on every
hostile-guest path, GC for crashed embedders' residue (`sweep_orphans`), dependency guards that
fail legibly (`xtask setup`'s degradation matrix, the pinned Firecracker probe), measured budgets
(fd, boot, restore, memory-sharing), and a wire protocol whose version handshake makes skew a typed error
instead of a silent misbehavior.

Downstream of the public API, in separate repos, live the language SDKs (Go/Python/Node/C#) and the
Wasmtime *sibling* (a sibling, not a backend, "isolation is hardware" holds here without
exception). They pin this crate's git rev; that is why public-API changes carry an `api:` marker
in the commit subject, and why `Limits`/`RunResult`/`VmmError`/`Sandbox` and the channel protocol
move deliberately or not at all.
