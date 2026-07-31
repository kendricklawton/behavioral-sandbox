# Introduction

**ekvm** is a self-hostable engine for running untrusted code in hardware
isolation, with a host-observed record of what the host was able to see it do. The code runs inside a **Firecracker** microVM (hardware isolation via KVM);
**host-side eBPF** (**aya**) watches and enforces what it does, syscalls, its network, its
cgroup, from the host side of the KVM boundary, outside the guest's address space.

It exists for the usual suspects: a third-party binary, a fork's CI job, a dependency's install
script, an AI-generated snippet, a sample under analysis. The code stays on your own
infrastructure (air-gapped or regulated is fine), and the watching and the policy live in the host
kernel, outside the guest, so the record is produced by code the guest does not run. The finished record is **host-signed** (`ekvm verify`); the
[threat model](./security-threat-model.md#record-integrity-beyond-the-guest) states exactly what that does
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

Untrusted code executes within the microVM while the host kernel observes and enforces policy from
the host side of that boundary. Six design rules govern every change, and a change that breaks one
is treated as a design error rather than a trade-off; they are stated in full, with the mechanism
serving each, in [Architecture and design](./architecture.md#design-rules). They are deliberately
not repeated here, because a third copy is a third thing to drift.

One of them sets the project's scope and is worth stating up front: **engine, not platform.** This
is a runtime plus a clean driver API you self-host. Multi-tenant auth, billing, fleet scheduling,
and dashboards belong to whatever *hosts* the engine, and the model driving an agent is always the
*caller*, never an engine component; the full non-goals list is in
[Where the engine ends](./embedding-scope.md).

## Reading this book

- **[Architecture and design](./architecture.md)**, the six design rules, how the engine integrates
  with the host, what the crates are for and the order things happen in during a run, and the
  numbered decisions with their rationale.
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
- **[Threat model](./security-threat-model.md)**, what is trusted, host hardening baseline, supply-chain provenance, and residual risk.
- **[Security](./security.md)**, what counts as a security bug, the current limits, and how to
  report one.
- **[Contributing](./contributing.md)**, invariants, developer tools, CI gates, testing, and fuzzing.

## Status

**Pre-release, unreleased, unaudited.** Version `0.0.0`, no tag, no published artifact. One
maintainer, and nothing here has been reviewed by anyone outside the project. Nothing in this book is
a promise: it describes how the engine is built and what has been exercised. Anything can change
without notice, so if you build on this, pin a git rev. Release mechanics and the planned support
policy are in [RELEASES.md](../RELEASES.md), none of which is in force yet.

Each milestone ships with a demo that exercises it, so most of what this book describes has been run
rather than only reasoned about. "Most" is load-bearing there: the release install path, the Red Hat
rows, and aarch64 are described here and have not been run. Which is worth being precise about:

**What a passing test is worth.** A passing test shows that the case it constructs behaved as
described, on the host that ran it, at the revision it ran against. It does not show that the
property holds for cases the test does not construct. Throughout this book, a named test is a pointer
to a scenario you can read and re-run, not a proof of a general property. Two consequences: evidence
expires, so a gate that passed in July is evidence about July's revision on July's host; and a test
is only as good as its assertions, which is why a commit titled "stop two tests from passing on
something other than their subject" exists in this history.

### What has not been done

Stated because their absence is the honest counterweight to everything else in this book:

- **No external security review or audit.** The threat model is the author's own reasoning about the
  author's own code. See [Threat model](./security-threat-model.md).
- **Two kernels.** The CO-RE/BTF portability described in [Host-side observability &
  enforcement](./probes.md) is a property of the mechanism rather than a broadly tested claim: the
  probes have been loaded on the Arch development box and on the Ubuntu 24.04 runner the privileged
  suite uses nightly. Two is not a matrix, and no enterprise kernel is among them.
- **No Red Hat host has been run.** RHEL 9 and 10 are intended targets, and `ekvm doctor` probes for
  `cgroup.kill` rather than a version number, which is what admits a patched kernel whose version
  string sits below the fallback floor. But nothing has booted, gated, or attached a probe there, and
  SELinux in particular is unexercised.
- **No published benchmark numbers.** See [Benchmarks](./benchmarks.md) for why they were withdrawn
  and what has to happen before they return.
- **No fuzzing at scale.** Ten libFuzzer targets exist and run nightly, but not continuously (no
  OSS-Fuzz or equivalent), and two targets have thin corpora.
- **No outside users.** Nobody has installed or run this who did not build it.
- **`x86_64` only.** aarch64 needs hardware and a privileged CI lane before anything about it could
  be claimed.

The source for this book lives in the repository's
[`docs/` directory](https://github.com/packsixfour/ekvm/tree/main/docs) and contributions are
welcome, see [Contributing](./contributing.md).
