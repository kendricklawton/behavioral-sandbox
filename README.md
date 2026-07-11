# agent *(working name)*

**A self-hostable engine for running untrusted code — with a record of what it did that you
can trust without trusting the code.** Untrusted code runs inside a **Firecracker** microVM
(hardware isolation via KVM); **host-side eBPF** (**aya**) watches and enforces what it does —
syscalls, its network, its cgroup — from *outside* the guest, where the code can't see or
subvert you. Every run yields a tamper-resistant, host-observed **flight recorder** of exactly
what happened.

Built in the open as a **Linux-internals deep-dive** — each milestone is a working demo and a
writeup, from the hardware-isolation boundary up to the syscall/network boundary.

## Why

Running untrusted or AI-generated code safely is a real problem, and the honest answers are
heavy VMs (E2B/Firecracker in the cloud) or shared-kernel containers (weaker isolation). This
is the **self-hostable engine** underneath that kind of product:

- **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. The trust
  boundary is the CPU, not guest-side software.
- **Observe & enforce from the host.** Visibility and policy live in host-side eBPF — the guest
  cannot disable what it cannot reach. In-guest agents exist for convenience (exec/IO), never
  for security.
- **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal
  capability; every allowance is explicit and recorded.
- **Engine, not platform.** A runtime + a clean driver API you self-host. *Kubernetes is not a
  PaaS, and neither is this.*
- **Measured, not marketed.** Boot, snapshot-restore, density, and eBPF overhead are
  benchmarked with percentiles — never hand-waved.

## Status

**Early and learning-driven.** The direction is set in [`ROADMAP.md`](ROADMAP.md); the build
starts at Phase 1 (boot a real microVM from `cargo run` and read its console). Nothing here is
production yet — the point is depth, done in the open.

## How it fits together

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc/XDP) · its cgroup
      → per-run flight recorder (network flows · notable syscalls · resources · denials)
```

The guest runs the code; the **host kernel** sees and governs it. That split — hardware
isolation *plus* out-of-guest observability and enforcement — is the whole idea.

## Layout

| Path | Role |
|------|------|
| `crates/vmm` | The Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, the `Sandbox` API. |
| `crates/probes` | The eBPF programs (`no_std`, built for `bpfel-unknown-none` with aya). |
| `crates/probes-loader` | Userspace: load/attach the probes, read their maps, stream events. |
| `crates/cli` | The `agent` binary (`run`, `shell`, `--trace`) and later the `agentd` daemon. |
| `xtask` | Dev orchestration — `cargo xtask ci`, the eBPF object build, the rootfs build. Never shipped. |

## Scope — engine, not platform

**In scope:** the sandbox runtime (Firecracker), host-side observability + enforcement (eBPF),
the sandbox lifecycle API, a self-hostable driver daemon, and the benchmarks that back the
claims. **Out of scope, by design:** multi-tenant auth, billing, fleet scheduling, and a web
dashboard — that's whatever *hosts* the engine. `containerd`, not Docker Cloud.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) — the prerequisites (KVM, `firecracker`, the aya
toolchain), the local gate, the testing approach, and the invariants. The operating manual is
[`.rules`](.rules); the staged plan is [`ROADMAP.md`](ROADMAP.md).

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
