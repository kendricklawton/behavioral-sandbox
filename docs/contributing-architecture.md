# Architecture overview

The engine's shape in one page: the crates, and how the isolation / observability / driver
boundaries divide them. The hard-to-reverse **decisions** (each one's rationale, the alternatives
considered, and the why) live separately as **ADRs** under [`docs/adr/`](./adr/README.md), one
dated, numbered `NNN-*.md` file per choice; the roadmap's `(decision)` tags point at those numbers,
and reversing one is a new ADR, not an edit.

**The Firecracker + aya sandbox engine.** A self-hostable, isolated **code-execution sandbox**:
**Firecracker** microVMs for hardware isolation, **aya/eBPF** for host-side observability and
enforcement (see `.rules`, `ROADMAP.md`). The guiding properties are the four core properties:
*isolation is hardware · observe & enforce from the host · engine not platform · measured, not
marketed.*

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
  streams stdout/stderr/exit over `channel`. Built static (musl), baked into the rootfs by the build.
  Exec/IO convenience only, never the security boundary.
- `crates/probes`, the **eBPF programs** (`#![no_std]`, built for `bpfel-unknown-none` via
  `bpf-linker`): syscall tracepoints, tc/XDP on the VM's tap, cgroup accounting. CO-RE/BTF.
- `crates/probes-loader`, the **userspace loader** (aya): attaches the probes to a specific
  sandbox, reads their maps, and streams events into the audit log.
- `crates/cli`, the single `agent` binary: the CLI (`run`, `shell`, `--trace`) plus the
  `agent serve` driver daemon.
- `xtask`, dev orchestration; `cargo xtask ci` runs the host-safe gate and builds the eBPF
  object, `ci-privileged` runs the VM-boot + probe-attach integration tests, `setup` verifies the
  host, and the rootfs/kernel build lives here. Never shipped.
