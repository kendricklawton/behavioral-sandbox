# Architecture decisions

The record [`ROADMAP.md`](../ROADMAP.md) references: every roadmap item tagged `(decision)`
produces a dated, numbered entry here, the decision, the alternatives considered, and the why,
so the reasoning outlives the diff. Each entry is keyed by its own number and date (not a phase),
so it stands on its own as the roadmap evolves. Entries are append-only; reversing one is a new entry, not an
edit. (Roadmap *re-scopes*, cut phases and why, live in the roadmap's notes, not here.)

**The Firecracker + aya sandbox engine.** This decision log covers the self-hostable, isolated
**code-execution sandbox**: **Firecracker** microVMs for hardware isolation, **aya/eBPF** for
host-side observability and enforcement (see `.rules`, `ROADMAP.md`). The guiding properties are
the four core properties: *isolation is hardware · observe & enforce from the host · engine not platform ·
measured, not marketed.*

Decisions queued by the (sandbox) roadmap, to be recorded here as they're made:

- **P11.6**, where egress policy lives and its schema (engine *mechanism*, not org policy).
- **P15.6**, the security boundary and its trust assumptions (what's trusted: CPU/KVM/host
  kernel; what isn't: the guest).
- **P16.2**, the driver daemon's wire API surface: JSON-over-unix-socket vs gRPC.
- **P20.1**, freeze + version the wire API as the language-agnostic **SDK contract** (schema,
  error taxonomy, semver compat policy). *(vNext; the SDKs live in their own repos, see roadmap
  Phase 20.)*
- **P21.1**, the **Wasmtime sibling** is a separate repo that reuses the driver API + audit-log
  format, **not a plug-in backend** here (so *isolation is hardware* is never traded in
  this engine). *(vNext, see roadmap Phase 21.)*

---

## Repo layout

One Cargo workspace; each crate has a single job, split along the isolation/observability/driver
boundaries:

- `crates/vmm`, the **Firecracker driver**: microVM lifecycle (boot/exec/shutdown), rootfs and
  networking (tap), snapshots and the pre-warmed pool, jailer/cgroup confinement, and the `Sandbox`
  lifecycle API. No `unsafe` on the host path; a hostile guest is a typed error.
- `crates/channel`, the **host↔guest wire protocol**: dependency-free length-prefixed framing over
  `Read`/`Write`, shared by the driver and the guest agent (see decision 002).
- `crates/guest-agent`, the **in-guest agent** (`agent-guest`): runs one command per connection and
  streams stdout/stderr/exit over `channel`. Built static (musl), baked into the rootfs at Phase 3.
  Exec/IO convenience only, never the security boundary.
- `crates/probes`, the **eBPF programs** (`#![no_std]`, built for `bpfel-unknown-none` via
  `bpf-linker`): syscall tracepoints, tc/XDP on the VM's tap, cgroup accounting. CO-RE/BTF.
- `crates/probes-loader`, the **userspace loader** (aya): attaches the probes to a specific
  sandbox, reads their maps, and streams events into the audit log.
- `crates/cli`, the `agent` binary (`run`, `shell`, `--trace`) and later the `agentd` daemon.
- `xtask`, dev orchestration; `cargo xtask ci` runs the host-safe gate and builds the eBPF
  object, `ci-privileged` runs the VM-boot + probe-attach integration tests, `setup` verifies the
  host, and the rootfs/kernel build lives here. Never shipped.

---

## Recorded decisions

The decisions are recorded as **ADRs**, one file per decision, under [`docs/adr/`](./adr/README.md): each hard-to-reverse choice is a numbered `NNN-*.md` entry (the decision, the alternatives, the why). See [the ADR index](./adr/README.md) for the full list; a new decision is a new ADR, and the roadmap's `(decision)` tags point at these numbers.
