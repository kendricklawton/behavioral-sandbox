# Introduction

**agent** *(working name)* is a self-hostable engine for running untrusted code in hardware
isolation, with a tamper-evident record of exactly what it did that you can trust without trusting
the code. The code runs inside a **Firecracker** microVM (hardware isolation via KVM);
**host-side eBPF** (**aya**) watches and enforces what it does, syscalls, its network, its
cgroup, from *outside* the guest, where the code can't see or subvert it.

Any time you run code you don't fully trust (a third-party binary, a CI job from a fork, a
dependency's install script, an AI-generated snippet, a sample under analysis) you want two things
at once: strong isolation, and a trustworthy account of what the code actually did. This is the
engine for exactly that, the code stays on your own infrastructure (air-gapped or regulated is
fine), and the watching and the policy live in the host kernel, outside the guest, so the record
can't be forged by the code it is recording. The finished record is also **host-signed**, so
alteration after the run is detectable off-host (verify with `agent verify`); see the [threat
model](./threat-model.md#record-integrity-beyond-the-guest) for exactly what that does and does not
prove.

The engine can be driven three ways: as the **`agent` CLI** (one sandbox per command), as a
**Rust library** embedded in a larger application, or programmatically over a unix socket through
the **`agent` daemon** and its versioned wire API.

## How it fits together

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc/XDP) · its cgroup
      → per-run audit record (network flows · notable syscalls · resources · denials)
```

The guest runs the code; the **host kernel** sees and governs it. That split, hardware isolation
*plus* out-of-guest observability and enforcement, is the whole idea. Four properties every
change protects:

- **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. The trust
  boundary is the CPU, not guest-side software.
- **Observe & enforce from the host.** Visibility and policy live in host-side eBPF, the guest
  cannot disable what it cannot reach. In-guest agents exist for convenience (exec/IO), never
  for security.
- **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal
  capability; every allowance is explicit and recorded.
- **Measured, not marketed.** Boot, snapshot-restore, memory-sharing, and eBPF overhead are
  benchmarked with percentiles, never hand-waved.

And one scope rule: **engine, not platform.** This is a runtime plus a clean driver API you
self-host. Multi-tenant auth, billing, fleet scheduling, and dashboards belong to whatever *hosts*
the engine, and the model driving an agent is always the *caller*, never an engine component; the
full non-goals list is in [Using the engine API](./embedding.md).

## Reading this book

- **[Using the agent CLI](./cli.md)**, how to run the engine: [install the
  prerequisites](./cli-install.md) and stand it up with one `cargo xtask self-host`, then run
  untrusted code with `agent run` and hold interactive sessions with `agent shell`. Start here.
- **[Using the engine API](./embedding.md)**, the embedder's contract: the `Sandbox` lifecycle,
  sessions, budgets, typed errors, snapshots and the pre-warmed pool, and where the engine
  deliberately ends.
- **[Using the `agent serve` daemon](./daemon.md)**, drive the engine over a unix socket: the versioned
  wire API (`open`/`exec`/`put`/`get`/`snapshot`/`trace`/`trace_summary`/`close`), the pre-warmed pool for fast
  `open`, logs and metrics for the hoster, and the reference client the language SDKs grow from.
- **[Examples](./examples.md)**, worked, end-to-end walkthroughs: [running untrusted
  code](./examples-untrusted-code.md), [observing a run from the
  host](./examples-observe-a-run.md), [containing an agent](./examples-agent-containment.md),
  [analyzing an untrusted binary](./examples-untrusted-binary.md), and [running a CI job from a
  fork](./examples-ci-job.md).
- **[Host-side observability & enforcement](./probes.md)**, the eBPF half: syscall tracing,
  per-VM network flows on the tap, in-kernel egress enforcement, and per-sandbox resource
  accounting, each with a live demo.
- **[Threat model](./threat-model.md)**, what is trusted, what the adversary is assumed to control,
  and the assumptions the guarantees rest on.
- **[Security](./security.md)**, what counts as a security bug, the current limits, and how to
  report one.
- **[Contributing](./contributing.md)**, how the work is organized, [building](./contributing-building.md),
  [testing](./contributing-testing.md), and the invariants.

## Status

Early, under active development, nothing here is production yet. The staged plan and live
progress live in [`ROADMAP.md`](https://github.com/k-henry-org/agent/blob/main/ROADMAP.md)
(its checkboxes are the state); hard-to-reverse choices are recorded as dated
[decision records](./adr/README.md). Every
completed phase ships a working demo, so each capability documented in this book is proven
running end to end, not just asserted.

The source for this book lives in the repository's
[`docs/` directory](https://github.com/k-henry-org/agent/tree/main/docs) and contributions are
welcome, see [Contributing](./contributing.md).
