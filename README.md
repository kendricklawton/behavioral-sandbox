# agent *(working name)*

**A self-hostable engine for running untrusted code in a hardware-isolated microVM, with a
host-observed record of exactly what it did.**

## What is agent?

agent runs untrusted code inside a **Firecracker** microVM, so the trust boundary is the CPU (KVM),
not guest-side software. Around that microVM, **host-side eBPF** (via **aya**) watches and enforces
what the code does, its syscalls, its network, its cgroup, from *outside* the guest, where the code
can't see or subvert it. Every run yields a tamper-evident **audit record**, host-observed, of
exactly what happened: the network flows, the notable syscalls, the resources it used, and any
egress that was denied.

It is an **engine, not a platform**: a runtime plus a clean driver API you self-host, with no
multi-tenant auth, billing, fleet scheduling, or dashboard. A sandbox with no explicit policy
reaches no network and holds minimal capability; every allowance is explicit and recorded. Boot,
snapshot-restore, memory-sharing, and eBPF overhead are benchmarked with percentiles.

Built in the open, milestone by milestone, each one shipping as a working demo.

## Getting started

**Requirements:** Linux with `/dev/kvm` (it needs KVM), an `x86_64` or `aarch64` host, kernel
**≥ 5.15**, and [Firecracker](https://github.com/firecracker-microvm/firecracker/releases) v1.9 on
`PATH` (the engine drives it, it doesn't bundle it). `cargo xtask setup` (or `agent doctor` once
built) reports exactly what your host is missing before the first sandbox.

```console
git clone https://github.com/kendricklawton/agent && cd agent
cargo xtask self-host                                   # build + install agent/agentd, boot a proof sandbox
agent run --unjailed -- python3 -c 'print(2 ** 100)'    # run untrusted code in a microVM
```

`--unjailed` is the explicit opt-out from the default jailer for a dev box without real root; the
guest still sits behind the KVM boundary. [Installation](docs/cli-install.md) walks the same path
in full, and [the CLI chapter](docs/cli.md) shows how to ask for the host-observed record of what
the code actually did.

## Documentation

The guide lives in [`docs/`](docs/SUMMARY.md) (an mdBook, `mdbook serve docs`, or read the
Markdown in place):

- **[Introduction](docs/introduction.md)**, what this is and how the pieces fit.
- **[Using the agent CLI](docs/cli.md)**, how to run the engine:
  [installation](docs/cli-install.md), building the guest artifacts, `agent run`, `agent shell`.
- **[Using the engine API](docs/embedding.md)**, the embedder's contract: the `Sandbox`
  lifecycle, budgets, typed errors, snapshots/pool, and the engine's deliberate non-goals.
- **[Examples](docs/examples.md)**, worked walkthroughs: [running untrusted
  code](docs/examples-untrusted-code.md), [observing a run](docs/examples-observe-a-run.md).
- **[Host-side observability & enforcement](docs/probes.md)**, the eBPF half: syscall tracing,
  per-VM network flows, in-kernel egress enforcement, resource accounting, each with a live demo.
- **[Security](docs/security.md)**, the security model: what's trusted, what counts as a bug,
  how to report one.
- **[Contributing](docs/contributing.md)**, orientation, the
  [architecture overview](docs/contributing-architecture.md) and the
  [decision records](docs/adr/README.md) (each hard-to-reverse choice as one ADR: its rationale
  and the alternatives that lost), [building](docs/contributing-building.md),
  [testing](docs/contributing-testing.md), [fuzzing](docs/contributing-fuzzing.md).

## Status

**Early, under active development, nothing here is production yet.** The staged plan and live
progress are in [`ROADMAP.md`](ROADMAP.md); its checkboxes are the state. So far: a microVM boots
to userspace and runs real Python, Node, and static binaries from a purpose-built rootfs with
captured stdout/stderr/exit; gets a per-VM deny-by-default network; snapshots and restores from a
pre-warmed pool in milliseconds; runs confined under the jailer (chroot, dropped privileges,
cgroup limits, seccomp); and is wrapped in the embedder-facing `Sandbox` lifecycle
([docs/embedding.md](docs/embedding.md)). The host-side eBPF track observes a running sandbox's
host syscall footprint and its per-VM network flows, enforces deny-by-default egress in the
kernel at its tap, and meters its CPU/memory/IO ([docs/probes.md](docs/probes.md)), each with a
measured overhead and a live demo. The audit log that fuses these into one host-observed per-run
record is surfaced through the CLI (`--trace`/`--record`/`--watch`) and the `agentd` daemon.

## How it fits together

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc/XDP) · its cgroup
      → per-run audit log (network flows · notable syscalls · resources · denials)
```

The guest runs the code; the **host kernel** sees and governs it. That split, hardware
isolation *plus* out-of-guest observability and enforcement, is the whole idea.

## Layout

| Path | Role |
|------|------|
| `crates/vmm` | The Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, the `Sandbox` API. |
| `crates/channel` | The host↔guest wire protocol: dependency-free length-prefixed framing, shared by driver + agent. |
| `crates/guest-agent` | The in-guest agent (`agent-guest`): runs one command per connection, streams stdout/stderr/exit. Exec/IO only, never the trust boundary. |
| `crates/probes` | The eBPF programs (`no_std`, built for `bpfel-unknown-none` with aya). |
| `crates/probes-common` | The `#[repr(C)]` event/policy records shared across the eBPF boundary, single-sourced. |
| `crates/probes-loader` | Userspace: load/attach the probes, read their maps, stream events. |
| `crates/cli` | Two binaries: the `agent` CLI (`run`, `shell`, `doctor`) and the `agentd` driver daemon. |
| `docs` | This documentation, as an mdBook. |
| `xtask` | Dev orchestration, `cargo xtask ci`, the eBPF object build, the rootfs build. Never shipped. |

## Scope, engine, not platform

**In scope:** the sandbox runtime (Firecracker), host-side observability + enforcement (eBPF),
the sandbox lifecycle API, a self-hostable driver daemon, and the benchmarks that back the
claims. **Out of scope, by design:** multi-tenant auth, billing, fleet scheduling, and a web
dashboard, that's whatever *hosts* the engine. The lifecycle
contract and the full non-goals list live in [docs/embedding.md](docs/embedding.md).

**Adjacent (separate repos, post-`v0.1.0`):** language SDKs (Go · Python · Node · C#) that drive
the engine's wire API, and a Wasmtime-based *software-isolation* sibling built to compare both
boundaries. Each is its own repo built on this engine's frozen wire API, thin clients / a sibling,
never part of its trust boundary, and never traded against the hardware-isolation guarantee. See
[`ROADMAP.md`](ROADMAP.md) Phases 20–21.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the contributing chapters of the
[documentation](docs/contributing.md). The operating manual for agents is [`.rules`](.rules); each hard-to-reverse choice is recorded as one ADR under [`docs/adr/`](docs/adr/README.md).

## License

Apache-2.0, see [`LICENSE`](LICENSE).
