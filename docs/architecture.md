# Architecture

What the engine is, the rules it holds itself to, and how it is put together. This page carries the
scope and the design rules; the pages under it carry the host integration, the VMM and its jail,
the code, a run from boot to teardown, the eBPF half, and the numbered decisions.

## Scope

### What this is

`bsx` is an isolated code-execution sandbox. Untrusted code runs inside a microVM, with the
isolation boundary enforced by the CPU through hardware virtualization. The guest
drives four crossings, enumerated in the [threat model](./security-threat-model.md), and none of them names a
BPF program or map.

Every execution yields a host-observed **audit record** of what the host was able to see, and the

### Design rules

These are the rules the project holds itself to, stated so a change that breaks one is recognisable
as a design error rather than a trade-off. They describe intent and the mechanism serving it, not a
verified outcome.

1. **Isolation is hardware, not software.** Untrusted code runs in a VM under KVM or
   Hypervisor.framework. A change that moves the boundary into guest-side software is a design
   error, not an optimisation, and a shared-kernel shortcut taken to simplify things is the same
   error.
2. **Local-first. Nothing leaves the machine.** No account, no telemetry, no control plane, and no
   licence check that needs a server. A feature that cannot work on a laptop with the network off
   belongs to a different product.
3. **Deny by default.** A sandbox with no explicit configuration shares no host directory and has no
   network. What is shared **is** the policy: no in-kernel enforcer sits behind it, so the set of
   shared directories and the network backend are settled before the VM starts and are visible to
   the person starting it.
4. **An application, not a platform.** The product is a program on one person's machine. The unit is
   the sandbox; there is no tenant, no account, and no fleet. Mechanism that makes one machine's
   sandboxes work belongs here, and anything that must know who is paying is a different product.
   See [Where the engine ends](./embedding-scope.md#where-the-engine-ends-the-enginepaas-line).
5. **No panic, hang, or leak on the host path.** A hostile or crashing guest, or a helper that dies,
   should surface as a typed error. A leak here is a stranded VM holding somebody's laptop RAM, not
   a server you can reboot. This is what the code is written against and what the confinement suite
   exercises; it is an aim, not a proven property.
6. **Measure rather than assert.** Boot, memory, and frame timings are reported as nearest-rank
   percentiles with the host and date they were taken on. Where a number cannot be defended, it is
   withdrawn rather than published; see [Benchmarks](./benchmarks.md). libkrun has no snapshot
   surface, so every boot is a cold boot.

## Architecture overview

```text
                     CONSUMER ENTRY POINTS & API SURFACES

    [ Rust Embedder ]                                     [ Audit Verifier ]
            |                                                     |
            v (In-Process)                                        v (Off-Host)
     `bsx-engine`                                            `bsx` CLI
  (Sandbox, BootConfig, Vm)                          (ed25519 verify/chain)
            |
            v
        `bsx` CLI
  (a thin host of the same `bsx-engine`)
            |
            |
            v  (Driver / Lifecycle)
     Firecracker microVM
   +-----------------------+
   | KVM Hardware Isolation|
   | In-Guest Agent        |  <=== (vsock channel, `bsx-channel` framing)
   +-----------------------+
```

## Index of crates

Directories stay short and packages carry the `bsx-` prefix, so a package is its directory plus that
prefix, with one exception: `crates/cli` builds `bsx`, the bare name going to the command a user
types. `cargo … -p` takes the **package**, a path takes the **directory**.

| Crate | Directory | Role |
|---|---|---|
| `bsx-engine` | `crates/engine` | The engine and the embedder-facing API. The Firecracker driver, the jail, networking, snapshots, the pool, and every teardown path. |
| `bsx-channel` | `crates/channel` | The host/guest wire protocol. Nearly dependency-free framing (`zeroize`, for the post-send secret wipe, is the one dependency), shared verbatim by driver and agent. |
| `bsx-guest-agent` | `crates/guest-agent` | The in-guest agent. One command per connection, static musl, baked into the rootfs. Not a security boundary. Its binary keeps the bare name `guest-agent`. |
| `bsx` | `crates/cli` | The `bsx` binary: `run`, `shell`, `doctor`, `verify`. Package, binary, and command all share the name. |
| `bsx-test-support` | `crates/test-support` | Test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, the real-root guard. |
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
- **[Design decisions](./architecture-decisions.md)**, the numbered decisions and the
  reasoning behind each.
