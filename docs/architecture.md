# Architecture and design

What the engine is, the rules it holds itself to, and how it is put together. This page carries the
scope and the design rules; the pages under it carry the host integration, the code, a run from boot
to teardown, the eBPF half, and the numbered decisions with their reasoning.

## Scope

### What this is

`eKVM` is a self-hostable, isolated code-execution sandbox engine. Untrusted code runs inside a
**Firecracker** microVM (hardware isolation via Linux KVM). **Host-side eBPF** (`aya`) observes and
enforces what it does, syscalls, network flows, resource accounting, from the host side of the KVM
boundary: the programs are loaded by a host process and attached to host-kernel hooks. The guest
drives four crossings, enumerated in the [threat model](./security-threat-model.md), and none of them names a
BPF program or map.

Every execution yields a host-observed, host-signed **audit log** of execution events. What a
signature does and does not establish is stated in
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
   scheduling, and dashboards belong to whoever hosts the engine.
5. **No panic, hang, or leak on the host path.** A hostile or crashing guest, a failed probe, or a
   broken channel should surface as a typed error. This is what the code is written against and what
   the confinement suite exercises; it is an aim, not a proven property.
6. **Measure rather than assert.** Boot, snapshot-restore, memory-sharing, and probe overhead are
   reported as nearest-rank percentiles with the host and date they were taken on. Where a number
   cannot be defended, it is withdrawn rather than published; see [Benchmarks](./benchmarks.md).

## Index of crates

| Crate | Role |
|---|---|
| `vmm` | The engine and the embedder-facing API. The Firecracker driver, the jail, networking, snapshots, the pool, and every teardown path. |
| `channel` | The host/guest wire protocol. Dependency-free framing, shared verbatim by driver and agent. |
| `guest-agent` | The in-guest agent. One command per connection, static musl, baked into the rootfs. Not a security boundary. |
| `probes` | The eBPF programs. `no_std`, built for `bpfel-unknown-none`, the one crate allowed `unsafe`. |
| `probes-common` | The `#[repr(C)]` records crossing the eBPF boundary. Zero dependencies, single-sourced. |
| `probes-loader` | The aya userspace half: attach, fold, assemble the record, sign it. |
| `protocol` | The daemon's wire types, versioned. |
| `client` | The Rust reference client for `ekvm serve`. |
| `cli` | The `ekvm` binary: `run`, `shell`, `doctor`, `verify`, and the `serve` daemon. Package name `ekvm`, directory `cli`. |
| `test-support` | Test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, the real-root guard. |
| `xtask` | Dev orchestration: the gates, artifact builds, benchmarks, packaging. Never shipped. |

## The rest of this section

- **[Host integration](./architecture-host.md)**, where the pieces sit on a host, what the host must
  provide, and how networking and storage are laid out.
- **[The code](./architecture-code.md)**, what the crates are for, the types worth knowing before
  reading code, and the reading order that works.
- **[A run, start to finish](./architecture-lifecycle.md)**, boot, exec, the four teardown layers,
  and the snapshot pool.
- **[The eBPF half](./architecture-ebpf.md)**, the three probe crates and the three decisions in the
  loader worth understanding before changing it.
- **[Design decisions](./architecture-decisions.md)**, the eight numbered decisions and the
  reasoning behind each.
