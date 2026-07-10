# Contributing

Thanks for your interest. **agent** (working name) is a self-hostable, isolated
**code-execution sandbox**: untrusted code runs in a **Firecracker** microVM (KVM hardware
isolation), and **host-side eBPF** (**aya**) observes and enforces what it does — syscalls, its
network, its cgroup — from outside the guest. It's built in the open as a **Linux-internals
deep-dive**: every phase ships a working demo and a writeup.

> Read [**`.rules`**](./.rules) first — the operating manual and the invariants that must never
> be traded away (`CLAUDE.md` and `AGENTS.md` both point there). The staged plan is in
> [**`ROADMAP.md`**](./ROADMAP.md); its checkboxes are the state.

## Prerequisites

This is **Linux-only** (it needs KVM). You'll need:

- **A Linux host with `/dev/kvm`** and your user in the `kvm` group (or root). A reasonably
  recent kernel with **BTF** is required for CO-RE eBPF (most modern distros ship it).
- **Rust, stable** ([`rustup`](https://www.rust-lang.org/tools/install)) for the host/driver.
  The eBPF programs additionally need **`bpf-linker`** and the aya build toolchain
  (`cargo install bpf-linker`; the eBPF crate targets `bpfel-unknown-none`).
- **`firecracker`** + its **jailer** binary (pinned version — see below), a guest **kernel
  image** (`vmlinux`), and the ability to build a minimal **rootfs**.
- **Elevated capabilities** for the parts that touch the kernel: creating **tap** devices
  (`CAP_NET_ADMIN`) and loading eBPF (`CAP_BPF`/`CAP_PERFMON`, or root). Day-to-day dev uses an
  `xtask`/`just` wrapper so it isn't `sudo cargo` roulette.

`cargo xtask setup` checks the host can do KVM + eBPF and reports what's missing.

## Quick start

```console
git clone <repo> && cd <repo>
cargo xtask setup            # verify KVM, BTF, firecracker, bpf-linker, caps
cargo build

# Boot a microVM and read its console (ROADMAP Phase 1):
cargo run -p agent-cli -- run --demo-boot

# Later: run a command inside a microVM and capture its output (Phase 2+):
cargo run -p agent-cli -- run -- python -c 'print(2 + 2)'

# Later still: run it and print the eBPF-observed flight recorder (Phase 13+):
cargo run -p agent-cli -- run --trace -- <cmd>
```

## Before you push — the local gate

```console
cargo install bpf-linker cargo-deny cargo-hack   # one-time
cargo xtask ci                                    # fmt + clippy -D warnings + build + test
                                                  # + docs + deny + the eBPF object build
```

`cargo xtask ci` runs the host-safe gate everywhere: fmt · clippy `-D warnings` · build · unit
tests · docs · `cargo deny` · and it **builds the eBPF programs** for their own target so a
verifier-breaking change fails fast.

**The privileged tests are separate.** Booting a microVM and loading/attaching eBPF need
`/dev/kvm` and elevated caps, so the **integration tests** (VM boot, exec, tap networking,
probe attach) are marked and run under `cargo xtask ci-privileged` on a machine that has them
(your dev box, or a bare-metal/nested-virt CI runner — a stock cloud VM usually can't nest KVM).
Never gate the everyday loop on a privileged runner.

## The testing approach

1. **Unit / pure:** driver config assembly, protocol framing, policy-map encoding, error
   mapping — no VM, no root.
2. **eBPF object build:** the probes compile for `bpfel-unknown-none` in the gate; a program the
   verifier would reject fails the build.
3. **Privileged integration:** boot a real microVM → `exec` → tap networking → attach probes →
   assert the flight recorder shows exactly what the workload did. Needs KVM + caps.
4. **Benchmarks:** cold boot, snapshot restore, warm-pool `exec` latency (p50/p99), density, and
   probe overhead — reported with percentiles, tracked over time.

## The invariants (never trade these away)

- **Isolation is hardware.** Untrusted code runs in a KVM microVM; the trust boundary is the
  CPU, not guest-side software.
- **Observe & enforce from the host.** Visibility and policy live in host-side eBPF the guest
  can't reach; in-guest agents are for convenience (exec/IO), never for security.
- **Engine, not platform.** A self-hostable runtime + a driver API. Auth, billing, fleet
  scheduling, and dashboards are **out of scope** — the hoster's job.
- **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal
  capability; every allowance is explicit and recorded.
- **No-panic on the host path.** A hostile or crashing guest, a failed probe, or a broken
  channel is a typed error — never a host panic, hang, or leak.
- **Measured, not marketed.** Boot/restore/density/overhead are benchmarked with percentiles.
- **Teach as you go.** Every phase ships a writeup; the *why* is a first-class deliverable.

## Phases & decisions

Work is organized into sequentially-gated phases in [`ROADMAP.md`](./ROADMAP.md) — the **single
source of truth for progress**. Work the first unchecked box in ID order, one item per
iteration; a phase isn't left until its **Exit gate** passes (a working demo *and* a writeup).
Items tagged `(decision)` record the hard-to-reverse choice in `ARCHITECTURE.md` so the *why*
outlives the diff.

## Commit & PR conventions

- One logical change per commit; **imperative** subject describing **what was done** ("Boot a
  microVM from the driver", not "added VM boot"). Don't reference roadmap phase IDs — the
  roadmap can change.
- **Never add an AI co-author or attribution trailer** — no `Co-Authored-By: Claude …` or
  similar. Never commit built rootfs/kernel images or generated eBPF objects.
- Every PR must pass the host-safe gate (`cargo xtask ci`); privileged integration runs where
  KVM + caps exist.

## License

By contributing you agree your contributions are licensed under **Apache-2.0**, the project's
license (see [`LICENSE`](./LICENSE)).
