# Using the engine API

The sandbox-lifecycle contract, and where the engine ends. This is the embedder's document: what
the `ekvm-engine` library promises when you pin it and build on it, stated once, against the real
API. The rustdoc on each item is the reference; this is the contract's shape and the reasoning.
[Where the engine ends](./embedding-scope.md) draws the line this project refuses to cross, and
[Recipes](./embedding-recipes.md) is the same lifecycle in runnable code.

## Pinning it

The engine is not distributed through crates.io and
[is not meant to be](./embedding-scope.md), so the dependency is a git rev:

```toml
[dependencies]
ekvm-engine = { git = "https://github.com/packsixfour/ekvm", rev = "<40-char sha>" }
```

The package is `ekvm-engine`; its directory is `crates/engine`, and a git dependency resolves by
**package name**, so the path never appears. The bare `ekvm` is the **CLI**, a different crate that
happens to live in the same repository, so depending on it gets you the command-line tool's
internals rather than the engine. Take the rev from a tag or a commit you have read, not from a
branch: a moving `branch = "main"` re-resolves on every `cargo update`, which is the opposite of a
pin. The rev you choose is what the [Semver section](./embedding-scope.md#semver--api-stability)
governs.

**This key has changed twice, so check which era your rev is from.** It was `vmm` until `167dd80`
(2026-08-01), which moved every package under the `ekvm-` prefix and gave the library the bare
`ekvm`; it has been `ekvm-engine` since the commit that handed that bare name to the CLI instead,
later the same day. A rev bump across either is the one change that needs an edit here rather than
only in `Cargo.lock`. Both carry the `api` scope with `!`, so the log alone says where the
boundaries are.

## The lifecycle

```text
Sandbox::open(config)            confined by default: KVM + the jailer
    .exec(argv, stdin)           synchronous; a RunResult or a typed VmmError
    .exec_with_files(argv, stdin, files, env, artifacts)
    …repeated execs = one stateful session (the VM is the session)
    .snapshot(dir)               a portable pre-warmed bundle (unjailed sources only)
    .collect_outputs()           the bulk /output tree, back on the host
    .shutdown()                  releases the VM, scratch dir, tap, cgroup (Drop and the sentinel too)
```

### Open: confined by default

`Sandbox::open(BootConfig)` runs the VMM under **both** walls: the KVM microVM (isolation is
hardware) and Firecracker's jailer (chroot, uid/gid drop, seccomp, its own mount and network
namespaces, a cgroup). An unset `jail` becomes `Jail::default()`; the opt-out for hosts that can't
jail (no real root, no `jailer` binary) is the *differently named constructor*
`Sandbox::open_unjailed`, so an unconfined sandbox is greppable in your source and can never happen
by a forgotten flag ([decision 3](./architecture-decisions.md#3-jailed-execution-by-default)).
Artifacts (kernel, rootfs, `firecracker`) layer from the environment
(`EKVM_KERNEL`, `EKVM_ROOTFS`, …) under explicit `BootConfig` fields.

Networking is off by default. `enable_network` gives the guest a tap whose only reachable address is
the host end of its /30; `egress` additionally hands it a default route and a resolver, which is read
only when `enable_network` is set and ignored otherwise. Neither builds a path: no veth, bridge,
forwarding, or NAT, so on a netns nothing has furnished the reachable set is unchanged and only what
the host can *observe* widens. Attaching an uplink is the embedder's, per
[decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster);
bounding what crosses the tap is the eBPF policy in [`ekvm-probes-loader`](./probes.md).

### Exec: synchronous, bounded, faithful

`exec` connects to the in-guest agent over vsock, runs one command, and returns a `RunResult`:
`exit_code`, `stdout`, `stderr`, requested artifact `files`, and host-measured `metrics`. Three properties are load-bearing:

- **Guest crash handling:** Non-zero exit code or termination by signal (`128 + signal`) returns a valid `RunResult`. Typed `VmmError` variants indicate engine-level failures.
- **Host-enforced bounds:** the wall-clock deadline (`ExecUnresponsive`) and output limit (`OutputCap`) are derived on the host and applied by the host, so an uncoordinated guest does not set them.
- **Per-exec input security:** `stdin`, injected `files`, and `env` are scoped to the spawned process, and the code paths that log or render a run omit secret values. `injected_secrets_never_reach_the_console_or_host_logs` runs a sandbox with a distinctive token and greps the console capture, the captured host logs, and a refused injection's rendered error for it. Bulk file transfers use block-device storage (`input_dir` and `output_dir`).

### Sessions: the VM is the session

Repeated `exec` operations within a sandbox share guest working directory and overlay filesystem
state, per [decision 4](./architecture-decisions.md#4-ephemeral-sandbox-sessions--snapshots).
Session state persists for the VM lifetime and is cleared upon `shutdown`.

### Budgets: resource policy

`Limits` specifies per-sandbox resource constraints: `vcpus` (`NonZeroU8`), `mem_mib` (`NonZeroU32`), `wall` (execution deadline), and `output_cap`. The non-zero types make a zero unrepresentable rather than validated at runtime. Network egress is separate from `Limits`: the route is `BootConfig::egress` (a `GuestEgress`), and the packet-level allow-list lives in `ekvm-probes-loader`'s policy types. Cgroup constraints are best-effort when host controllers are unassigned; the KVM boundary and the jailer are not conditional on them.

### Errors: three buckets you can branch on

Every failure is a typed `VmmError`; `VmmError::kind()` maps it to a pinned, closed `ErrorKind`:

| Bucket | Meaning | Caller's move |
|---|---|---|
| `Infra` | the host couldn't stand the VM up (incl. "agent not up yet/anymore": `GuestUnavailable`) | retry, or fix the host |
| `Transport` | the established exec channel broke mid-run, or the guest went silent past its deadline (`ExecUnresponsive`) | retire this VM, take another |
| `Guest` | the run's fault: couldn't spawn, outran its budget, flooded output | surface to the user |

The mapping is a tested contract (the wildcard-free match won't compile past a new variant until
it's deliberately bucketed).

### Lifetime: the teardown paths, including the ones you don't call

Teardown is layered, so that a VMM, scratch dir, tap, and cgroup have an owner on every exit path:
`shutdown` is the polite form, `Drop` covers an early return or an unwinding panic, and a
cgroup-owned sentinel reaps the VM if the embedding *process* is SIGKILL'd or OOM-killed. A
`KillHandle` (cheap, cloneable, thread-safe) force-kills a sandbox whose `exec` some other thread is
blocked in, the host-gave-up path. Residue from a crashed embedder is reclaimed by `sweep_orphans`,
with ownership keyed on liveness rather than on names, and scoped to your own euid's residue.

`crates/engine/tests/confinement.rs` exercises these paths: `driver_death_cannot_leak_a_vm` SIGKILLs a
driver mid-run and asserts the VMM dies with it, `a_vmm_killed_while_awaiting_userspace_leaks_nothing`
kills a VMM mid-boot and asserts the scratch dir is reclaimed, and
`sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir` covers the residue path. What a passing test
does and does not establish is in [Status](./introduction.md#status).

### Pre-warmed starts: snapshot an unjailed source, restore jailed clones

`snapshot(dir)` pauses the VM and writes a portable bundle; `Vm::restore` (and the `Pool` built on
it) brings up exec-ready clones by restore rather than cold boot. A `read_only_root` source's base
disk is referenced in place by every clone, and a jailed clone bind-mounts the memory file
read-only; a read-write snapshot's unjailed restores are single-flight, run sequentially (the
`Pool` does exactly that). (`Vm` is the driver's lower layer: `Vm::boot`/`Vm::restore` yield a
running microVM handle, and a `Sandbox` wraps exactly one of them with the jailed-by-default
posture; the snapshot and pool [recipes](./embedding-recipes.md) work at the `Vm` layer.) Snapshotting is restricted
to *unjailed* sources (their disk lives on a fixed host path); restoring into *jailed* clones is
where the untrusted code runs confined.

---

## The rest of this chapter

- **[Recipes](./embedding-recipes.md)**, the lifecycle in runnable code: one shot, budgets and
  files, the pre-warmed pool, and a reference integration.
- **[Where the engine ends](./embedding-scope.md)**, the engine/PaaS line, the recorded non-goals,
  and the API surface the project intends to pin at `v0.1.0`.
