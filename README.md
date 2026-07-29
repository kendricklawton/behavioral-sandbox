# eKVM

[![CI](https://github.com/packsixfour/ekvm/actions/workflows/ci.yml/badge.svg)](https://github.com/packsixfour/ekvm/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**A self-hostable engine for running untrusted code in a hardware-isolated microVM, with a
host-observed record of exactly what it did.**

## What is eKVM?

eKVM runs untrusted code inside a **Firecracker** microVM, so the boundary is enforced by the CPU
through KVM rather than by guest-side software. Around that microVM, **host-side eBPF** (via
**aya**) watches and enforces what the code does, its syscalls, its network, its cgroup, from the
host side of that boundary: the programs are loaded by a host process and attached to host-kernel
hooks. Every run yields a host-observed, **host-signed** **audit record** (verify with
`ekvm verify`) of what the host was able to see: the network flows, the notable syscalls, the
resources used, and any egress that was denied.

It is an **engine, not a platform**: a runtime plus a driver API you self-host, with no
multi-tenant auth, billing, fleet scheduling, or dashboard. A sandbox with no explicit policy is
configured with no route out and minimal capability, and each allowance is recorded. Boot,
snapshot-restore, memory-sharing, and probe overhead are reported as nearest-rank percentiles with
the host and date; numbers that cannot be defended are withdrawn rather than published.

Built in the open, milestone by milestone, each one shipping as a working demo.

## Getting started

**Requirements:** Linux with `/dev/kvm`, an `x86_64` host, kernel
**≥ 5.15**, and [Firecracker](https://github.com/firecracker-microvm/firecracker/releases) on
`PATH` (v1.15 through v1.16 supported, v1.16.1 pinned and tested; the engine drives it, it
doesn't bundle it). Starting from a bare machine,
[Preparing the host](docs/cli-install.md#preparing-the-host) is the copy-pasteable version of all of
that; `cargo xtask setup` (or `ekvm doctor` once built) then reports exactly what your host is still
missing before the first sandbox.

```console
git clone https://github.com/packsixfour/ekvm && cd ekvm
cargo xtask self-host                                   # build + install ekvm, boot a proof sandbox
ekvm run --unjailed -- python3 -c 'print(2 ** 100)'    # run untrusted code in a microVM
```

`--unjailed` is the explicit opt-out from the default jailer for a dev box without real root; the
guest still sits behind the KVM boundary. [Installation](docs/cli-install.md) walks the same path
in full, and [the CLI chapter](docs/cli.md) shows how to ask for the host-observed record of what
the code actually did.

## Documentation

The guide lives in [`docs/`](docs/SUMMARY.md) (an mdBook, `mdbook serve docs`, or read the
Markdown in place):

- **[Introduction](docs/introduction.md)**, what this is and how the pieces fit.
- **[Design specification](docs/design.md)**, full architectural design, component model, host integration, and system properties.
- **[Using the eKVM CLI](docs/cli.md)**, how to run the engine:
  [installation](docs/cli-install.md), building the guest artifacts, `ekvm run`, `ekvm shell`.
- **[Using the engine API](docs/embedding.md)**, the embedder's contract: the `Sandbox`
  lifecycle, budgets, typed errors, snapshots/pool, and semver stability rules.
- **[Examples](docs/examples.md)**, worked end-to-end walkthroughs.
- **[Host-side observability & enforcement](docs/probes.md)**, the eBPF half: syscall tracing,
  per-VM network flows, in-kernel egress enforcement, resource accounting, each with a live demo.
- **[Security](docs/security.md)**, the security model: threat model, host hardening baseline, and supply chain provenance.
- **[Contributing](docs/contributing.md)**, invariants, developer tools, CI gates, testing, and fuzzing.

## Status

**Early, under active development, nothing here is production yet.** Version `0.0.0`, no tag, no
release, no external review. The full verification record, including what has *not* been done, is
[docs/status.md](docs/status.md). So far: a microVM boots
to userspace and runs real Python, Node, and static binaries from a purpose-built rootfs with
captured stdout/stderr/exit; gets a per-VM deny-by-default network; snapshots and restores from a
pre-warmed pool; runs confined under the jailer (chroot, dropped privileges,
cgroup limits, seccomp); and is wrapped in the embedder-facing `Sandbox` lifecycle
([docs/embedding.md](docs/embedding.md)). The host-side eBPF track observes a running sandbox's
host syscall footprint and its per-VM network flows, enforces deny-by-default egress in the
kernel at its tap, and meters its CPU/memory/IO ([docs/probes.md](docs/probes.md)), each with a
live demo. Benchmark result tables are currently withdrawn pending a re-measurement on a verified
host ([docs/benchmarks.md](docs/benchmarks.md)). The audit log that fuses these into one host-observed per-run
record is surfaced through the CLI (`--trace`/`--record`/`--watch`) and the `ekvm serve` daemon.

**Pre-1.0, expect breaking changes.** Until the first tagged release, nothing here
carries a compatibility guarantee: the `Sandbox`/`vmm` API, the `ekvm serve` wire protocol (and its
`protocol` crate), the audit-log/record format, and the crate names can all change without
notice. If you build on it, pin to a specific git rev. The first tagged release, `v0.1.0`, will pin
the driver API and wire protocol under the support policy in [RELEASES.md](RELEASES.md); no date is
promised. The project is developed by a small group: **only project collaborators commit code**
(the repo is not open to outside pull requests yet, see [CONTRIBUTING](CONTRIBUTING.md)).

**Verified on:** the host-safe gate (build, tests, lints) runs in CI on **Ubuntu 24.04** `x86_64`
on every change; the privileged path (microVM boot, the jailer, the eBPF probes, the integration
suite) runs nightly in CI on a GitHub-hosted **Ubuntu 24.04** `x86_64` runner (nested KVM) and is
hand-verified on **Arch Linux** during development, both with **Firecracker v1.16**. `x86_64` is the
only supported architecture: nothing untestable is claimed, and aarch64 returns only with hardware
and a privileged CI lane behind it. `ekvm doctor` reports your own host's
readiness. See [Supported platforms](docs/cli-install.md#supported-platforms).

## Scope and releases

There is no published roadmap. What the engine will never do is recorded in the
[non-goals](docs/embedding.md); what it does today is this documentation. A capability becomes a
feature when it ships with a working demo and defensible measurements, and is not announced before
that. Release mechanics, host requirements, and the support policy live in
[RELEASES.md](RELEASES.md).

## How it fits together

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc/XDP) · its cgroup
      → per-run audit log (network flows · notable syscalls · resources · denials)
```

Untrusted code executes within the microVM while the host kernel observes and enforces policy from the host side of that boundary.

## Layout

| Path | Role |
|------|------|
| `crates/vmm` | The Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, the `Sandbox` API. |
| `crates/channel` | The host↔guest wire protocol: dependency-free length-prefixed framing, shared by driver + agent. |
| `crates/guest-agent` | The in-guest agent (`guest-agent`): runs one command per connection, streams stdout/stderr/exit. Exec/IO only, not the trust boundary. |
| `crates/probes` | The eBPF programs (`no_std`, built for `bpfel-unknown-none` with aya). |
| `crates/probes-common` | The `#[repr(C)]` event/policy records shared across the eBPF boundary, single-sourced. |
| `crates/probes-loader` | Userspace: load/attach the probes, read their maps, stream events. |
| `crates/cli` | The `ekvm` CLI (also installed as `ekvm`): `run`, `shell`, `doctor` plus the `ekvm serve` driver daemon. |
| `docs` | This documentation, as an mdBook. |
| `xtask` | Dev orchestration, `cargo xtask ci`, the eBPF object build, the rootfs build. Never shipped. |

## Scope, engine, not platform

**In scope:** the sandbox runtime (Firecracker), host-side observability + enforcement (eBPF),
the sandbox lifecycle API, a self-hostable driver daemon, and the benchmark methodology behind the
claims. **Out of scope, by design:** multi-tenant auth, billing, fleet scheduling, and a web
dashboard, that's whatever *hosts* the engine. The lifecycle
contract and the full non-goals list live in [docs/embedding.md](docs/embedding.md).

**Adjacent (planned, none built yet):** the language SDKs, which would pin this engine's public API and wire
protocol rather than living inside its trust boundary.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the contributing chapters of the
[documentation](docs/contributing.md). The operating manual for agents is [`AGENTS.md`](AGENTS.md).


## License

Apache-2.0, see [`LICENSE`](LICENSE).
