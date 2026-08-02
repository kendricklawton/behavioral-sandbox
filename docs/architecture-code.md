# The code

What the crates are for, the types worth knowing before reading code, and the order to read them in.

## Reading the code

For finer detail than this page carries, the code comments are the authority, and they hold the
reasoning this page summarizes. The order things happen in during a run is
[the next page](./architecture-lifecycle.md).

The reading order that works: this page, then `crates/channel/src/lib.rs` (small, self-contained, and
it defines the host/guest contract), then `crates/engine/src/vm.rs` and `spawn.rs`, then the eBPF half.

`spawn.rs` keeps the launch, boot, and abort state machine; its separable parts sit alongside it in
`spawn/restore.rs` (the restore path and its disk staging), `spawn/fcversion.rs` (what release is on
this host and what the driver may therefore send it), and `spawn/workdir.rs` (minting the per-VM dir
and the two path constraints on it).

## The `ekvm-engine` crate

`ekvm-engine` is the engine. It is the crate an embedder depends on, and the only one whose public API
carries the `api` commit scope (`AGENTS.md`).

Its safety posture is the inverse of most VMM projects: **the host path forbids `unsafe` outright**.
Every crate in the workspace carries `#![forbid(unsafe_code)]` except `crates/probes`, so that is a
compiler error rather than a review convention. That one exception is structural: the BPF target
requires raw map dereferences. `every_crate_forbids_unsafe_except_the_bpf_one` holds the rule from
the tree rather than from a list here.

The public surface is deliberately narrow. From `lib.rs`:

```rust,ignore
pub use ekvm_channel::{ClientConnection, Request, Response, GUEST_READY_MARKER, MAX_PAYLOAD};
pub use jail::{Jail, DEFAULT_JAIL_GID, DEFAULT_JAIL_UID, VMM_PIDS_MAX};
pub use lifetime::KillHandle;
pub use net::{GuestEgress, GuestLink};
pub use pool::Pool;
pub use sweep::{sweep_orphans, SweepReport};
pub use vm::{BootConfig, RunningVm, Snapshot, Vm, DEFAULT_GUEST_CID, VSOCK_PORT};
```

Note the first line: `ekvm-channel`'s wire types are re-exported through `ekvm-engine`, so an embedder
reaches them without adding a second dependency, and they are part of the surface
[the stability boundary](./embedding-scope.md#semver--api-stability) names.

Everything else (`console`, `drives`, `exec`, `firecracker`, `jail`'s internals, `paths`, `proc`,
`snapshot`, `spawn`, `sweep`'s internals) is a private module. `doctor` is public because the CLI and
`xtask setup` both render its checks, and it is documented as a diagnostic helper rather than part of
the pinned surface.

## Important concepts

Some types to have in the back of your head before reading further.

* **`Sandbox`** (`lib.rs`) is what an embedder holds. It is a thin wrapper over `RunningVm` whose job
  is to make the right thing the default: `Sandbox::open` **jails unconditionally** (an unset
  `config.jail` becomes `Jail::default()`) and turns the vsock exec channel on, because a `Sandbox`
  exists to run code.

  The opt-out is a *constructor name*, `Sandbox::open_unjailed`, not a boolean flag. That is
  deliberate: a name is greppable, no config field or env var reaches it (`BootConfig` carries no
  unjail knob), and any `jail` set on the config is cleared by it (the name wins). The type is
  `#[must_use = "dropping a Sandbox kills its microVM"]`.

* **`BootConfig`** is the whole boot request: artifact paths, resource knobs, `input_dir`/`output_dir`
  for bulk I/O, networking, the jail. `BootConfig::from_env` applies the
  [layered configuration](./cli-config.md), and the CLI is otherwise a thin translation of flags into
  this struct. If you are adding a boot-time capability, it almost certainly starts here.

* **`RunningVm`** (`vm.rs`) is the booted microVM: the `firecracker` child, its API socket, the scratch
  dir, the captured console, and, importantly, **everything that must be reclaimed**. Its fields are a
  good map of what a VM owns: the active rootfs backing file, the vsock socket, the output device and
  where it extracts to, the per-VM tap (which lives *outside* the workdir, so teardown must delete it
  explicitly), the chroot (whose cgroup is likewise outside), and the lifetime machinery below.

* **`VmLifetime` and `KillHandle`** (`lifetime.rs`) are how a VM dies. `KillHandle` is a cloneable,
  `Send + Sync` handle that force-kills one VM from outside its owning borrow: the host-gave-up path.
  **The kill is the cgroup**, writing `1` to the VM's `cgroup.kill`, which SIGKILLs the whole VMM tree
  with no pid arithmetic, which is why the handle is safe to fire from any thread at any time. On a
  host with no cgroup it falls back to signalling the VMM's pid, which is safe while the VM exists
  (the kernel holds an unreaped child's pid); after teardown the handle no-ops instead of signalling
  a possibly recycled pid, which `kill_handle_writes_cgroup_kill_then_noops_after_teardown` pins.

  Note the distinction the code is careful about: **killing is not tearing down.** Host residue is
  still reclaimed by the owner's `Drop` or `shutdown`, which is unblocked by exactly the death the
  handle causes.

* **`VmmError` and `ErrorKind`** (`lib.rs`) are the typed-error contract. `VmmError` is
  `#[non_exhaustive]` and its `kind()` maps every variant into one of three buckets an embedder can
  branch on: `Infra` (retry or fix the host), `Transport` (retire this VM), `Guest` (surface to the
  user). **The match in `kind()` is deliberately wildcard-free**, so adding a variant fails to compile
  until someone gives it a deliberate bucket. That is the mechanism keeping the contract honest.

* **`SandboxProbes` and `RunRecord`** (`ekvm-probes-loader`) are the observation half: the attach bundle for
  one sandbox, and the record it finalizes. See [the eBPF half](./architecture-ebpf.md).

## The daemon

`ekvm serve` is the same engine behind a versioned newline-JSON protocol on a unix socket. `ekvm-protocol`
holds the wire types, `ekvm-client` is a dependency-light reference client, and `ekvm`'s `serve.rs` and
`session.rs` are the server.

The security-relevant difference from the CLI: a daemon's clients control neither its config file nor
its environment, so it takes its resource ceilings as **explicit flags** rather than from a discovered
`.ekvm.toml`. A daemon must not read a security control out of whatever directory it happened to be
started in.
