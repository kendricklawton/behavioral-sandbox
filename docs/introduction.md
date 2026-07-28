# Introduction

**ekvm** is a self-hostable engine for running untrusted code in hardware
isolation, with a tamper-evident record of exactly what it did that you can trust without trusting
the code. The code runs inside a **Firecracker** microVM (hardware isolation via KVM);
**host-side eBPF** (**aya**) watches and enforces what it does, syscalls, its network, its
cgroup, from *outside* the guest, where the code can't see or subvert it.

It exists for the usual suspects: a third-party binary, a fork's CI job, a dependency's install
script, an AI-generated snippet, a sample under analysis. The code stays on your own
infrastructure (air-gapped or regulated is fine), and the watching and the policy live in the host
kernel, outside the guest, so the record can't be forged by the code it is recording. The finished record is **host-signed** (`ekvm verify`); the
[threat model](./threat-model.md#record-integrity-beyond-the-guest) states exactly what that does
and does not prove.

The engine can be driven three ways: as the **`ekvm` CLI** (one sandbox per command), as a
**Rust library** embedded in a larger application, or programmatically over a unix socket through
the **`ekvm` daemon** and its versioned wire API.

## How it fits together

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc/XDP) · its cgroup
      → per-run audit record (network flows · notable syscalls · resources · denials)
```

Untrusted code executes within the microVM while the host kernel observes and enforces policy from outside the guest. Four properties every change protects:

- **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. The trust
  boundary is CPU-enforced (KVM).
- **Observe & enforce from the host.** Visibility and policy live in host-side eBPF out of guest reach. In-guest agents exist for exec/IO framing only.
- **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal
  capability; every allowance is explicit and recorded.
- **Empirical benchmarks.** Boot, snapshot-restore, memory-sharing, and eBPF overhead are
  benchmarked using percentiles.

And one scope rule: **engine, not platform.** This is a runtime plus a clean driver API you
self-host. Multi-tenant auth, billing, fleet scheduling, and dashboards belong to whatever *hosts*
the engine, and the model driving an agent is always the *caller*, never an engine component; the
full non-goals list is in [Using the engine API](./embedding.md).

## Reading this book

- **[Design specification](./design.md)**, full architectural design, Firecracker VMM integration, host eBPF containment barriers, and system properties.
- **[Using the eKVM CLI](./cli.md)**, how to run the engine: [install the
  prerequisites](./cli-install.md) and stand it up with one `cargo xtask self-host`, then run
  untrusted code with `ekvm run` and hold interactive sessions with `ekvm shell`. Start here.
- **[Using the engine API](./embedding.md)**, the embedder's contract: the `Sandbox` lifecycle,
  sessions, budgets, typed errors, snapshots and the pre-warmed pool, and where the engine
  deliberately ends.
- **[Using the `ekvm serve` daemon](./daemon.md)**, drive the engine over a unix socket: the versioned
  wire API (`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`trace_summary`/`close`), the pre-warmed pool for fast
  `open`, logs and metrics for the hoster, and the reference client the language SDKs grow from.
- **[Examples](./examples.md)**, worked, end-to-end walkthroughs covering untrusted code execution, host-side observation, agent containment, binary analysis, and CI job sandboxing.
- **[Host-side observability & enforcement](./probes.md)**, the eBPF half: syscall tracing,
  per-VM network flows on the tap, in-kernel egress enforcement, and per-sandbox resource
  accounting, each with a live demo.
- **[Threat model](./threat-model.md)**, what is trusted, host hardening baseline, supply-chain provenance, and residual risk.
- **[Security](./security.md)**, what counts as a security bug, the current limits, and how to
  report one.
- **[Contributing](./contributing.md)**, invariants, developer tools, CI gates, testing, and fuzzing.

## Status

Early, under active development, nothing here is production yet. Every
completed milestone ships a working demo, so each capability documented in this book is proven
running end to end, not just asserted.

The source for this book lives in the repository's
[`docs/` directory](https://github.com/packsixfour/ekvm/tree/main/docs) and contributions are
welcome, see [Contributing](./contributing.md).
