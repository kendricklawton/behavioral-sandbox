# Using the engine API

The sandbox-lifecycle contract, and where the engine ends. This is the embedder's document: what
the `vmm` library promises when you pin it and build on it, stated once, against the real
API. The rustdoc on each item is the reference; this is the contract's shape and the reasoning.
The second half draws the line this project refuses to cross, what the engine deliberately is
**not**, because a runtime that quietly grows platform features stops being embeddable.

## The lifecycle

```
Sandbox::open(config)            confined by default: KVM + the jailer
    .exec(argv, stdin)           synchronous; RunResult, never a panic/hang/leak
    .exec_with_files(argv, stdin, files, env, artifacts)
    …repeated execs = one stateful session (the VM is the session)
    .snapshot(dir)               a portable pre-warmed bundle (unjailed sources only)
    .collect_outputs()           the bulk /output tree, back on the host
    .shutdown()                  guaranteed reclamation (also on Drop, also on SIGKILL)
```

### Open: confined by default

`Sandbox::open(BootConfig)` runs the VMM under **both** walls: the KVM microVM (isolation is
hardware) and Firecracker's jailer (chroot, uid/gid drop, seccomp, its own mount and network
namespaces, a cgroup). An unset `jail` becomes `Jail::default()`; the opt-out for hosts that can't
jail (no real root, no `jailer` binary) is the *differently named constructor*
`Sandbox::open_unjailed`, so an unconfined sandbox is greppable in your source and can never happen
by a forgotten flag (012). Artifacts (kernel, rootfs, `firecracker`) layer from the environment
(`EKVM_KERNEL`, `EKVM_ROOTFS`, …) under explicit `BootConfig` fields.

### Exec: synchronous, bounded, faithful

`exec` connects to the in-guest agent over vsock, runs one command, and returns a `RunResult`:
`exit_code`, `stdout`, `stderr`, requested artifact `files`, and host-measured `metrics`. Three properties are load-bearing:

- **Guest crash handling:** Non-zero exit code or termination by signal (`128 + signal`) returns a valid `RunResult`. Typed `VmmError` variants indicate engine-level failures.
- **Host-enforced bounds:** Derived wall-clock deadlines (`ExecUnresponsive`) and output limits (`OutputCap`) prevent resource leaks from uncoordinated guests.
- **Per-exec input security:** `stdin`, injected `files`, and `env` are scoped to the spawned process. Secret values are excluded from logs, error messages, and console output. Bulk file transfers use block-device storage (`input_dir` and `output_dir`).

### Sessions: the VM is the session (016)

Repeated `exec` operations within a sandbox share guest working directory and overlay filesystem state. Session state persists for the VM lifetime and is cleared upon `shutdown`.

### Budgets: resource policy (010)

`Limits` specifies per-sandbox resource constraints: `vcpus` (`NonZeroU8`), `mem_mib` (`NonZeroU32`), `wall` (execution deadline), and `output_cap`. Non-zero types ensure valid budget parameters. Network egress is configured separately via policy rules. Cgroup constraints operate on a best-effort basis if host controllers are unassigned, while sandbox isolation remains mandatory.

### Errors: three buckets you can branch on

Every failure is a typed `VmmError`; `VmmError::kind()` maps it to a pinned, closed `ErrorKind`:

| Bucket | Meaning | Caller's move |
|---|---|---|
| `Infra` | the host couldn't stand the VM up (incl. "agent not up yet/anymore": `GuestUnavailable`) | retry, or fix the host |
| `Transport` | the established exec channel broke mid-run, or the guest went silent past its deadline (`ExecUnresponsive`) | retire this VM, take another |
| `Guest` | the run's fault: couldn't spawn, outran its budget, flooded output | surface to the user |

The mapping is a tested contract (the wildcard-free match won't compile past a new variant until
it's deliberately bucketed).

### Lifetime: nothing leaks, even when *you* die

Teardown is layered so no exit path leaks a VMM, a scratch dir, a tap, or a cgroup: `shutdown` is
the polite form, `Drop` is the guarantee, and a cgroup-owned sentinel (011) reaps the VM even if
the embedding *process* is SIGKILL'd or OOM-killed. A `KillHandle` (cheap, cloneable, thread-safe)
force-kills a sandbox whose `exec` some other thread is blocked in, the host-gave-up path.
Residue from crashed embedders is reclaimed by `sweep_orphans` (ownership keyed on liveness, never
on names; only your own euid's residue), so a crash-looping host stays serviceable (013).

### Pre-warmed starts: snapshot an unjailed source, restore jailed clones

`snapshot(dir)` pauses the VM and writes a portable bundle; `Vm::restore` (and the `Pool` built on
it) brings up exec-ready clones in milliseconds, sharing the base disk and memory file read-only
across concurrent sandboxes. (`Vm` is the driver's lower layer: `Vm::boot`/`Vm::restore` yield a
running microVM handle, and a `Sandbox` wraps exactly one of them with the jailed-by-default
posture; the snapshot and pool recipes below work at the `Vm` layer.) Snapshotting is restricted
to *unjailed* sources (their disk lives on a fixed host path); restoring into *jailed* clones is
where the untrusted code runs confined.

---

## Recipes

### One shot: open, run, read the result

```rust,no_run
use vmm::{BootConfig, Sandbox, VmmError};

fn main() -> Result<(), VmmError> {
    // 1. Resolve boot configuration from environment (EKVM_KERNEL, EKVM_ROOTFS, etc.)
    let config = BootConfig::from_env();

    // 2. Open a sandbox (confined by default under the jailer)
    let sandbox = Sandbox::open(config)?;

    // 3. Execute a command in the sandbox
    let result = sandbox.exec(&["python3".into(), "-c".into(), "print('Hello from eKVM!')".into()], b"")?;

    println!("Exit code: {}", result.exit_code);
    println!("Stdout: {}", String::from_utf8_lossy(&result.stdout));
    println!("Host wall-clock latency: {:?}", result.metrics.wall);

    sandbox.shutdown()?;
    Ok(())
}
```

### Budgets and files on the call

```rust,no_run
use std::num::{NonZeroU32, NonZeroU8};
use std::time::Duration;
use vmm::{BootConfig, Limits, Sandbox, VmmError};

fn main() -> Result<(), VmmError> {
    // Define a 2 vCPU, 512 MiB RAM, 60s wall budget limit
    let limits = Limits {
        vcpus: NonZeroU8::new(2).unwrap(),
        mem_mib: NonZeroU32::new(512).unwrap(),
        wall: Duration::from_secs(60),
        output_cap: 16 * 1024 * 1024, // 16 MiB output cap
    };

    // Apply limits onto boot config
    let config = BootConfig::from_env().with_limits(limits);
    let sandbox = Sandbox::open(config)?;

    // Execute with environment variables and input files
    let result = sandbox.exec_with_files(
        &["sh".into(), "-c".into(), "cat input.json && echo $ENV_VAR".into()],
        b"", // stdin
        &[("input.json".into(), b"{\"status\": \"ok\"}".to_vec())], // Injected file
        &[("ENV_VAR".into(), "secret-value".into())],              // Injected env
        &[],                                                       // Artifacts to fetch
    )?;

    println!("Output: {}", String::from_utf8_lossy(&result.stdout));
    sandbox.shutdown()?;
    Ok(())
}
```

### The pre-warmed pool

```rust,no_run
use vmm::{BootConfig, Pool, Snapshot, Vm, VmmError};

fn main() -> Result<(), VmmError> {
    // 1. Boot an unjailed source VM to prepare a pre-warmed snapshot
    let source_cfg = BootConfig::from_env();
    let source_vm = Vm::boot(source_cfg)?;

    let snap_dir = tempfile::tempdir().unwrap();
    let snapshot = source_vm.snapshot(snap_dir.path())?;

    // 2. Initialize a pool of 4 pre-warmed clones (clones will restore jailed)
    let pool_cfg = BootConfig::from_env();
    let mut pool = Pool::new(snapshot, pool_cfg, 4)?;

    // 3. Take a warm clone from the pool (milliseconds; measured in docs/benchmarks.md)
    let warm_vm = pool.take()?;
    let result = warm_vm.exec(&["echo".into(), "warm start".into()], b"")?;
    println!("Execution completed: {}", String::from_utf8_lossy(&result.stdout));

    // 4. Refill pool back to target count
    pool.refill()?;

    pool.shutdown()?;
    Ok(())
}
```

A pooled clone is a pre-warmed session; entropy is reseeded per clone (VMGenID), and networked clones each
recreate their tap in a private netns (014), so any number coexist.

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

`ekvm run` is the lifecycle in one command: piped stdin, `--env`, `--put`/`--get`, `--wall`,
`--output-cap`, `--json` (the structured result as one JSON object on stdout, stderr carries the
logs, so pipelines stay clean), `--unjailed` as the loud opt-out. `ekvm shell` holds one sandbox
open as an interactive stateful session. If you're writing an SDK, start from the daemon's
[reference client](./daemon.md#the-reference-client) (`client`), which exists for exactly that.

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
  the [`ekvm` daemon](./daemon.md), a *local* driver daemon over a unix socket, a thin host of
  the same library's public API, with no auth and no tenancy (access control is the socket
  directory's permissions). A daemon that grows multi-tenant identity or a public HTTP surface is
  a *hoster*, not this repo.

The line is a security boundary too (013): everything the engine ships is inert without host
privileges the *hoster* grants, it self-limits (deny-by-default network, dropped-uid jail,
own-euid sweep), and turning its tools into a multi-tenant service safely is the hoster's job.

What the engine *does* owe a long-lived host, and ships: typed errors instead of panics on every
hostile-guest path, GC for crashed embedders' residue (`sweep_orphans`), dependency guards that
fail legibly (`xtask setup`'s degradation matrix, the pinned Firecracker probe), measured budgets
(fd, boot, restore, memory-sharing), and a wire protocol whose version handshake makes skew a typed error
instead of a silent misbehavior.

Downstream of the public API, in separate repos, live the language SDKs (Go/Python/Node/C#).
They pin this crate's git rev; the pinned surface and its movement rules are the
[Semver section](#semver--api-stability) below.

**The crates are never published to crates.io** (`publish = false` across the workspace), a
decision, not a gap. A crates.io version is immutable and available forever, but this engine's
support window is computed from Firecracker's and deliberately ends: an old published version
would sit on the registry looking usable long after every VMM it can drive stopped receiving
patches. Distribution stays the signed release package for operators and the git-rev pin for
embedders, both of which the support policy in `RELEASES.md` can actually govern.

---

## Semver & API stability

The `vmm` public library API and the `channel` wire protocol are the engine's pinned stability boundary:
- **`Sandbox`**, **`Limits`**, **`RunResult`**
- **`VmmError`**, including variants and the `kind()` -> `ErrorKind` bucket mapping
- The **`channel`** wire framing protocol

### Versioning rules
- **MAJOR**: Breaking changes to the pinned surface (removed/renamed `VmmError` variants, changed `kind()` bucket mappings, breaking channel wire protocol changes, or raising `Limits` defaults).
- **MINOR**: Additive changes (new API methods, new `#[non_exhaustive]` error variants, new optional fields).
- **Commit Tags**: Changes touching this surface are marked with `feat(api):` or `fix(api)!:` in commit subjects for clear auditability.
