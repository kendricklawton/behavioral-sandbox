# Architecture

What BSX is, the rules it holds itself to, and what is in the tree today.

## Scope

### What this is

BSX is a local-first desktop sandbox. Untrusted code runs inside a virtual machine, with the
isolation boundary enforced by the CPU through hardware virtualization: KVM on Linux,
Hypervisor.framework on macOS. It is a GUI application with a CLI beside it, both on one machine.

### Where this is, right now

**The tree does not boot anything.** BSX was built on Firecracker with a host-side eBPF observer;
that design was abandoned, and the engine implementing it was deleted rather than carried alongside
its replacement. The replacement runs on [libkrun](https://github.com/containers/libkrun), a library
that makes the calling process the virtual machine monitor, and it is not written yet.

What is in the tree: the host/guest wire framing (`bsx-channel`), the in-guest agent
(`bsx-guest-agent`), the guest image build and the gate (`xtask`), and a `bsx` binary with no verbs.
This page describes the rules the replacement is being built to, not a running system.

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
   An AI model is a caller, never a component: it drives the app from outside.
5. **No panic, hang, or leak on the host path.** A hostile or crashing guest, or a helper that dies,
   should surface as a typed error. A leak here is a stranded VM holding somebody's laptop RAM, not
   a server you can reboot. This is what the code is written against; it is an aim, not a proven
   property, and the suite that exercised it went with the engine it tested.
6. **Measure rather than assert.** Boot, memory, and frame timings are reported as nearest-rank
   percentiles with the host and date they were taken on. Where a number cannot be defended, it is
   withdrawn rather than published. libkrun has no snapshot surface, so every boot is a cold boot.

## Index of crates

Directories stay short and packages carry the `bsx-` prefix, so a package is its directory plus that
prefix, with one exception: `crates/cli` builds `bsx`, the bare name going to the command a user
types. `cargo … -p` takes the **package**, a path takes the **directory**.

| Crate | Directory | Role |
|---|---|---|
| `bsx-supervisor` | `crates/supervisor` | Spawn, track, stop and reap the helper processes that are VMs. One value per live VM; `Drop` tears it down. |
| `bsx-krun` | `crates/krun` | The safe wrapper over libkrun, with the raw declarations private beneath it. The one crate that may use `unsafe`, because the library is C. |
| `bsx-channel` | `crates/channel` | The host/guest wire protocol. Nearly dependency-free framing (`zeroize`, for the post-send secret wipe, is the one dependency), shared verbatim by both ends. |
| `bsx-guest-agent` | `crates/guest-agent` | The in-guest agent. One command per connection, static musl, baked into the guest image. Not a security boundary. Its binary keeps the bare name `guest-agent`. |
| `bsx` | `crates/cli` | The `bsx` binary. No verbs today: the supervisor they call is not written. Package, binary, and command all share the name. |
| `bsx-test-support` | `crates/test-support` | Test fixtures: a self-reclaiming scratch dir, a log sink, and the deterministic generator the in-gate fuzz suites use. |
| `xtask` | `xtask` | Dev orchestration: the gate, the guest image build, the vendor mirror. Never shipped, and never renamed: `cargo xtask` is a `--package xtask` alias. |
