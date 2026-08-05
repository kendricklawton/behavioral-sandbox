# Architecture

What the engine is, the rules it holds itself to, and how it is put together. This page carries the
scope and the design rules; the pages under it carry the host integration, the VMM and its jail,
the code, a run from boot to teardown, the eBPF half, and the numbered decisions.

## Scope

### What this is

`eKVM` is a self-hostable, isolated code-execution sandbox engine. Untrusted code runs inside a
**Firecracker** microVM (hardware isolation via Linux KVM). **Host-side eBPF** (`aya`) observes and
enforces what it does from the host side of the KVM boundary: network flows and resource accounting
directly, syscalls only as the VMM's host footprint, since a microVM services guest syscalls in its
own kernel ([the honest limit](./probes.md#the-hardware-isolation-consequence-the-honest-limit)).
The programs are loaded by a host process and attached to host-kernel hooks. The guest
drives four crossings, enumerated in the [threat model](./security-threat-model.md), and none of them names a
BPF program or map.

Every execution yields a host-observed **audit record** of what the host was able to see, and the
paths that persist one sign it with a host key (`ekvm run --record` or an operator's `records_dir`,
and the daemon's `trace` reply). What a signature does and does not establish is stated in
[Record integrity beyond the guest](./security-threat-model.md#record-integrity-beyond-the-guest).

### Design rules

These are the rules the project holds itself to, stated so a change that breaks one is recognisable
as a design error rather than a trade-off. They describe intent and the mechanism serving it, not a
verified outcome.

1. **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. A change that
   moves the boundary into guest-side software is a design error, not an optimisation, and a
   shared-kernel shortcut taken to simplify the engine is the same error.
2. **Observe and enforce from the host.** Visibility and policy belong in host-side eBPF, attached
   to host-kernel hooks. The in-guest agent carries exec and IO framing; a change that makes it
   responsible for containing the guest is a design error.
3. **Deny by default.** A sandbox with no explicit policy is configured with no network route out
   and minimal capability, and each allowance is recorded in the audit log.
4. **Engine, not platform.** A self-hostable runtime and a driver API. Tenancy, auth, billing, fleet
   scheduling, and dashboards belong to whoever hosts the engine, including this project if it ever
   hosts one: the rule places them in a layer *above* the engine rather than ruling out that the
   layer gets built.
5. **No panic, hang, or leak on the host path.** A hostile or crashing guest, a failed probe, or a
   broken channel should surface as a typed error. This is what the code is written against and what
   the confinement suite exercises; it is an aim, not a proven property.
6. **Measure rather than assert.** Boot, snapshot-restore, memory-sharing, and probe overhead are
   reported as nearest-rank percentiles with the host and date they were taken on. Where a number
   cannot be defended, it is withdrawn rather than published; see [Benchmarks](./benchmarks.md).

## Architecture overview

```text
                     CONSUMER ENTRY POINTS & API SURFACES

    [ Rust Embedder ]     [ Polyglot SDK / Daemon Client ]    [ Audit Verifier ]
            |                            |                             |
            v (In-Process)               v (Unix Socket: schema 1)     v (Off-Host)
     `ekvm-engine`                `ekvm-protocol`               `ekvm-record`
  (Sandbox, BootConfig, Vm)   (JSON Request / Response lines)  (ed25519 verify/chain)
            |                            |
            |                            v
            |               `ekvm serve` / `ekvm` CLI
            |            (a thin host of the same `ekvm-engine`)
            |                            |
            +----------------------------+
                                         |
               +-------------------------+-------------------------+
               | (Driver / Lifecycle)                              | (Observation)
               v                                                   v
     Firecracker microVM                                 `ekvm-probes-loader` (aya)
   +-----------------------+                             +------------------------+
   | KVM Hardware Isolation|                             | Attach TC / Tracepoints|
   | In-Guest Agent        |<======(vsock channel)======>| Assemble RunRecord     |
   +-----------------------+   (`ekvm-channel` framing)  +------------------------+
                                                                   ^
                                                                   |
                                                         `ekvm-probes` (eBPF)
                                                         `ekvm-probes-common`
```

## Index of crates

Directories stay short and packages carry the `ekvm-` prefix, so a package is its directory plus that
prefix, with one exception: `crates/cli` builds `ekvm`, the bare name going to the command a user
types. `cargo … -p` takes the **package**, a path takes the **directory**.

| Crate | Directory | Role |
|---|---|---|
| `ekvm-engine` | `crates/engine` | The engine and the embedder-facing API. The Firecracker driver, the jail, networking, snapshots, the pool, and every teardown path. |
| `ekvm-channel` | `crates/channel` | The host/guest wire protocol. Near dependency-free framing (`zeroize`, for the post-send secret wipe, is the one dependency), shared verbatim by driver and agent. |
| `ekvm-guest-agent` | `crates/guest-agent` | The in-guest agent. One command per connection, static musl, baked into the rootfs. Not a security boundary. Its binary keeps the bare name `guest-agent`. |
| `ekvm-probes` | `crates/probes` | The eBPF programs. `no_std`, built for `bpfel-unknown-none`, the one crate allowed `unsafe`. Its object keeps the bare name `probes`. |
| `ekvm-probes-common` | `crates/probes-common` | The `#[repr(C)]` records crossing the eBPF boundary. Zero dependencies, single-sourced. |
| `ekvm-probes-loader` | `crates/probes-loader` | The aya userspace half: attach the probes, read their maps, assemble the record. |
| `ekvm-record` | `crates/record` | The signed audit record: its types, deterministic JSON, summary projection, and ed25519 signing/verification. No aya, so a record verifies off-host. |
| `ekvm-protocol` | `crates/protocol` | The daemon's wire types, versioned. |
| `ekvm-client` | `crates/client` | The Rust reference client for `ekvm serve`. |
| `ekvm` | `crates/cli` | The `ekvm` binary: `run`, `shell`, `doctor`, `verify`, and the `serve` daemon. Package, binary, and command all share the name. |
| `ekvm-test-support` | `crates/test-support` | Test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, the real-root guard. |
| `xtask` | `xtask` | Dev orchestration: the gates, artifact builds, benchmarks, packaging. Never shipped, and never renamed: `cargo xtask` is a `--package xtask` alias. |

## The rest of this section

- **[Host integration](./architecture-host.md)**, where the pieces sit on a host, what the host must
  provide, and how networking and storage are laid out.
- **[The VMM and its jail](./architecture-firecracker.md)**, how the driver talks to Firecracker,
  what the guest ends up holding, and what confines the VMM process itself.
- **[The code](./architecture-code.md)**, what the crates are for, the types worth knowing before
  reading code, and the reading order that works.
- **[A run, start to finish](./architecture-lifecycle.md)**, boot, exec, the four teardown layers,
  and the snapshot pool.
- **[The eBPF half](./architecture-ebpf.md)**, the three probe crates and the three decisions in the
  loader worth understanding before changing it.
- **[Design decisions](./architecture-decisions.md)**, the numbered decisions and the
  reasoning behind each.
