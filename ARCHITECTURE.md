# Architecture decisions

The record [`ROADMAP.md`](./ROADMAP.md) references: every roadmap item tagged `(decision)`
produces a dated, numbered entry here — the decision, the alternatives considered, and the why —
so the reasoning outlives the diff. Entries are append-only; reversing one is a new entry, not an
edit. (Roadmap *re-scopes* — cut phases and why — live in the roadmap's tombstones, not here.)

**Pivot, 2026-07-10 — the Firecracker + aya sandbox engine.** The project was re-scoped from the
`agent scan` wasm secrets scanner to a self-hostable, isolated **code-execution sandbox**:
**Firecracker** microVMs for hardware isolation, **aya/eBPF** for host-side observability and
enforcement (see `.rules`, `ROADMAP.md`). The decision log **restarts here** — the prior
scanner-era decisions (core-wasm ABI, instance-per-call, PII locale) and the earlier
trading-engine log describe retired designs and **live in git history** if ever needed. The
guiding properties are now the spine's four: *isolation is hardware · observe & enforce from the
host · engine not platform · measured and taught.*

Decisions queued by the (sandbox) roadmap, to be recorded here as they're made:

- **P1.1** — how to drive Firecracker: its **HTTP API over a unix socket** vs invoking the
  `firecracker` binary vs embedding the `rust-vmm` crates directly.
- **P2.1** — the host↔guest channel: **vsock** vs a serial protocol vs a bespoke guest agent.
- **P4.3** — the egress model: NAT-to-the-world vs **deny-by-default** with an explicit allow-list
  (enforced in the eBPF track).
- **P6.5** — the per-run resource-policy shape (the cpu/mem/wall/net knobs the engine exposes).
- **P11.6** — where egress policy lives and its schema (engine *mechanism*, not org policy).
- **P15.6** — the security boundary and its trust assumptions (what's trusted: CPU/KVM/host
  kernel; what isn't: the guest).
- **P16.2** — the driver daemon's wire API surface: JSON-over-unix-socket vs gRPC.
- **P0.6** — the project's working name (kept `agent` umbrella vs a codename).

---

## Repo layout

One Cargo workspace; each crate has a single job, split along the isolation/observability/driver
seams:

- `crates/vmm` — the **Firecracker driver**: microVM lifecycle (boot/exec/shutdown), rootfs and
  networking (tap), snapshots and the warm pool, jailer/cgroup confinement, and the `Sandbox`
  lifecycle API. No `unsafe` on the host path; a hostile guest is a typed error.
- `crates/probes` — the **eBPF programs** (`#![no_std]`, built for `bpfel-unknown-none` via
  `bpf-linker`): syscall tracepoints, tc/XDP on the VM's tap, cgroup accounting. CO-RE/BTF.
- `crates/probes-loader` — the **userspace loader** (aya): attaches the probes to a specific
  sandbox, reads their maps, and streams events into the flight recorder.
- `crates/cli` — the `agent` binary (`run`, `shell`, `--trace`) and later the `agentd` daemon.
- `xtask` — dev orchestration; `cargo xtask ci` runs the host-safe gate and builds the eBPF
  object, `ci-privileged` runs the VM-boot + probe-attach integration tests, `setup` verifies the
  host, and the rootfs/kernel build lives here. Never shipped.

*(The first real decision entry — **001** — will be recorded when Phase 1's `(decision)` P1.1
lands.)*
