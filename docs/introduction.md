# Introduction

**eKVM** is a self-hostable engine for running untrusted code in hardware
isolation, with a host-observed record of what the host was able to see it do. The code runs inside a **Firecracker** microVM (hardware isolation via KVM);
**host-side eBPF** (**aya**) watches and enforces what it does from the host side of the KVM
boundary, outside the guest's address space: its network and its cgroup directly, its syscalls only
as the VMM's host footprint.

It exists for the usual suspects: a third-party binary, a fork's CI job, a dependency's install
script, an AI-generated snippet, a sample under analysis. The code stays on your own
infrastructure (air-gapped or regulated is fine), and the watching and the policy live in the host
kernel, outside the guest, so the record is produced by code the guest does not run. The paths that
persist a record sign it with a host key (`--record`, an operator's `records_dir`, the daemon's
`trace`), and `ekvm verify` checks one; the
[threat model](./security-threat-model.md#record-integrity-beyond-the-guest) states exactly what that does
and does not prove.

The engine can be driven three ways: as the **`ekvm` CLI** (one sandbox per command), as a
**Rust library** embedded in a larger application, or programmatically over a unix socket through
the **`ekvm` daemon** and its versioned wire API.

## How it fits together

```text
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): the VM's tap device (tc clsact) · its cgroup · the VMM's host syscalls
      → per-run audit record (network flows · resources · notable host syscalls · denials)
```

Untrusted code executes within the microVM while the host kernel observes and enforces policy from
the host side of that boundary. Six design rules govern every change, and a change that breaks one
is treated as a design error rather than a trade-off; they are stated in full, with the mechanism
serving each, in [Architecture and design](./architecture.md#design-rules). They are deliberately
not repeated here, because a third copy is a third thing to drift.

One of them sets the project's scope and is worth stating up front: **engine, not platform.** This
is a runtime plus a clean driver API you self-host, and the model driving an agent is always the
*caller*, never an engine component. What belongs to whatever *hosts* the engine instead is listed in
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
- **[Host-side observability & enforcement](./probes.md)**, the eBPF half: syscall tracing,
  per-VM network flows on the tap, in-kernel egress enforcement, and per-sandbox resource
  accounting, each pinned by a privileged test.
- **[Benchmarks](./benchmarks.md)**, why no numbers are published at present and what a returning
  number must carry.
- **[Threat model](./security-threat-model.md)**, what is trusted, host hardening baseline, supply-chain provenance, and residual risk.
- **[Security](./security.md)**, what counts as a security bug, the current limits, and how to
  report one.

The source for this book lives in the repository's
[`docs/` directory](https://github.com/ekvm-rs/ekvm/tree/main/docs). `AGENTS.md` in the
repository root is the operating manual: the design rules, the two gates, and the commit
conventions.

## License

eKVM is licensed under the **Apache License 2.0**, copyright 2026 Kendrick Lawton. The full text is
[`LICENSE`](https://github.com/ekvm-rs/ekvm/blob/main/LICENSE) in the repository. Contributions
are accepted inbound under that same license, and a pull request asserts that per commit with a
`Signed-off-by` line under the [Developer Certificate of
Origin](https://developercertificate.org/). The project's own history predates that ask and is
mostly unsigned; nothing in CI checks for the line.
