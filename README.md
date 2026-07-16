# agent *(working name)*

**A self-hostable engine for running untrusted code in hardware isolation, with a tamper-evident
record of exactly what it did that you can trust without trusting the code.** The code runs inside
a **Firecracker** microVM (hardware isolation via KVM); **host-side eBPF** (**aya**) watches and
enforces what it does (syscalls, its network, its cgroup) from *outside* the guest, where the code
can't see or subvert it. Every run yields a host-observed **audit log** of exactly what
happened.

Built in the open, milestone by milestone: each one ships as a working demo, from the
hardware-isolation boundary up to the syscall/network boundary.

## Why

Any time you run code you don't fully trust (a third-party binary, a CI job from a fork, a
dependency's install script, an AI-generated snippet, a sample under analysis) you want two things
at once: strong isolation, and a trustworthy account of what the code actually did. This is the
**self-hostable engine** for exactly that: the code stays on your own infrastructure (air-gapped or
regulated is fine), and the watching and the policy live in the host kernel, outside the guest, so
the record can't be forged by the code it is recording.

- **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. The trust
  boundary is the CPU, not guest-side software.
- **Observe & enforce from the host.** Visibility and policy live in host-side eBPF — the guest
  cannot disable what it cannot reach. In-guest agents exist for convenience (exec/IO), never
  for security.
- **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal
  capability; every allowance is explicit and recorded.
- **Engine, not platform.** A runtime + a clean driver API you self-host. *It's an engine, not a
  PaaS.*
- **Measured, not marketed.** Boot, snapshot-restore, memory-sharing, and eBPF overhead are
  benchmarked with percentiles — never hand-waved.

## Status

**Early, under active development.** The staged plan and live progress are in [`ROADMAP.md`](ROADMAP.md);
its checkboxes are the state. So far (Phases 1 through 7) a microVM boots to userspace, runs commands
with captured stdout/stderr/exit, runs real Python, Node, and static binaries from a purpose-built
rootfs, gets a per-VM deny-by-default network, snapshots and restores from a pre-warmed pool in
milliseconds, runs confined under the jailer (chroot, dropped privileges, cgroup limits, seccomp),
and is wrapped in the embedder-facing `Sandbox` lifecycle: jailed by default, per-exec files + env
under a tested secret-hygiene contract, stateful sessions (the VM is the session), budget knobs,
and a structured result — the contract is written up in [`ENGINE.md`](ENGINE.md). The host-side
eBPF observability has begun ([`PROBES.md`](PROBES.md): a Rust program loads, attaches, and reports
from the host, out of the guest's reach); the audit log that fuses it with the driver into a
per-run record of what a run did is the track that follows. Nothing here is production yet; the
point is depth, done in the open.

## How it fits together

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc/XDP) · its cgroup
      → per-run audit log (network flows · notable syscalls · resources · denials)
```

The guest runs the code; the **host kernel** sees and governs it. That split — hardware
isolation *plus* out-of-guest observability and enforcement — is the whole idea.

## Layout

| Path | Role |
|------|------|
| `crates/vmm` | The Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, the `Sandbox` API. |
| `crates/channel` | The host↔guest wire protocol: dependency-free length-prefixed framing, shared by driver + agent. |
| `crates/guest-agent` | The in-guest agent (`agent-guest`): runs one command per connection, streams stdout/stderr/exit. Exec/IO only, never the trust boundary. |
| `crates/probes` | The eBPF programs (`no_std`, built for `bpfel-unknown-none` with aya). |
| `crates/probes-loader` | Userspace: load/attach the probes, read their maps, stream events. |
| `crates/cli` | The `agent` binary (`run`, `shell`, `--log`) and later the `agentd` daemon. |
| `xtask` | Dev orchestration — `cargo xtask ci`, the eBPF object build, the rootfs build. Never shipped. |

## Scope — engine, not platform

**In scope:** the sandbox runtime (Firecracker), host-side observability + enforcement (eBPF),
the sandbox lifecycle API, a self-hostable driver daemon, and the benchmarks that back the
claims. **Out of scope, by design:** multi-tenant auth, billing, fleet scheduling, and a web
dashboard — that's whatever *hosts* the engine. The lifecycle
contract and the full non-goals list live in [`ENGINE.md`](ENGINE.md).

**Adjacent (separate repos, post-`v0.1.0`):** language SDKs (Go · Python · Node · C#) that drive
the engine's wire API, and a Wasmtime-based *software-isolation* sibling built to compare both
boundaries. Each is its own repo built on this engine's frozen wire API — thin clients / a sibling,
never part of its trust boundary, and never traded against the hardware-isolation guarantee. See
[`ROADMAP.md`](ROADMAP.md) Phases 19–20.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) — the prerequisites (KVM, `firecracker`, the aya
toolchain), the local gate, the testing approach, and the invariants. The operating manual is
[`.rules`](.rules); the staged plan is [`ROADMAP.md`](ROADMAP.md).

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
