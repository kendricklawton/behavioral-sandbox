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

---

## Recorded decisions

### 001 — Drive Firecracker via its HTTP API over a unix socket *(2026-07-10, P1.1)*

**Decision.** The `vmm` driver spawns a `firecracker` child with `--api-sock` and configures the
boot over that socket's **HTTP/1.1 REST API** — `PUT /boot-source`, `/drives/{id}`,
`/machine-config`, then `/actions {InstanceStart}`. We speak HTTP with a small **hand-rolled
client over `std::os::unix::net::UnixStream`** (serde for the JSON bodies): one fresh connection
per request, `Content-Length`-framed responses, read/write timeouts. No async runtime, no HTTP
crate; the driver's only new deps are `serde`/`serde_json`/`tracing`, and the host path stays
`#![forbid(unsafe_code)]`.

**Alternatives considered.**
- **`firecracker --config-file`** (boot the whole VM from one JSON file, zero API calls) — simpler
  for a first boot, but there's no handle to *drive* the running VM, and pause/snapshot/restore
  (Phase 5) and clean shutdown need the socket regardless. Kept as a manual bring-up smoke test,
  not the mechanism.
- **Embedding `rust-vmm` crates** (build our own VMM) — maximal control, but pulls substantial
  `unsafe` into our process and reimplements what Firecracker already hardened. Rejected: it
  violates *isolation is hardware / no-unsafe-on-the-host-path* for no Phase-1 gain.

**Why.** The API socket is Firecracker's stable, documented control surface and the only one that
carries the whole lifecycle we'll need; hand-rolling the sliver of HTTP those ~5 calls require
keeps us dependency-light and `unsafe`-free, and the raw request/response framing is itself the
Linux lesson.

**Consequences / tombstones.**
- **Pinned to Firecracker v1.9's API schema.** Field names (`vcpu_count`, `mem_size_mib`,
  `is_root_device`, …) have drifted across releases; a version bump means re-checking the request
  bodies in `crates/vmm/src/firecracker.rs`.
- **Serial-console-on-stdout is an unjailed convenience.** We read the guest console from the
  `firecracker` child's stdout. The jailer (Phase 6) changes that wiring, so console capture sits
  behind a small internal seam to swap later.
- **`SendCtrlAltDel` graceful shutdown is x86-only** (i8042); the guaranteed teardown is
  `kill()` + scratch-dir removal, so no leak depends on the guest cooperating.

### 002 — Host↔guest channel: vsock + a tiny guest agent *(2026-07-10, P2.1)*

**Decision.** `exec` talks to the guest over **virtio-vsock**: a minimal, statically-linked
**guest agent** (started by the guest's init) listens on a vsock port, runs the requested command,
and streams `stdout`/`stderr`/exit back; the host reaches it through the **unix-domain socket
Firecracker exposes for vsock** (a `CONNECT <port>\n` handshake, then a raw bidirectional stream —
the same host-side shape as decision 001). Over that stream we speak **our own framed protocol**:
a small versioned header, then **length-prefixed messages** (start-request, stdin chunk, stdout/
stderr chunk, exit) — never a read-to-EOF or a delimiter scan. The guest agent carries exec/IO
**only**; it is a convenience, never part of the trust boundary (spine property 2 — a compromised
agent must not be able to escape the microVM, because containment is the CPU/KVM boundary, not the
agent).

**Alternatives considered.**
- **A protocol over a second serial port (`ttyS1`).** Needs no guest driver beyond the UART we
  already use for the console, and no vsock in the machine config. Rejected as the transport: a
  serial line is a *single, un-flow-controlled byte stream*, so multiplexing stdin + stdout +
  stderr + control means hand-rolling framing **and** back-pressure over a slow channel that
  already carries the boot console — all the work of a real protocol with none of the socket
  semantics. Kept only as a fallback if a guest kernel lacks `vhost-vsock`.
- **Network + SSH / a TCP agent.** Reuse an existing, battle-tested protocol. Rejected: it drags
  Phase 4 (tap/virtio-net) forward before we have egress control, so it would violate
  *deny-by-default* (invariant 6) — the guest would need a network purely to be driven — and it
  is a large attack surface and dependency for "run one command." vsock needs **no guest
  networking at all**, which keeps the deny-by-default posture intact through Phase 2.
- **Firecracker's own logger/metrics or the API socket.** Those are host-side control/observability
  surfaces; none carries guest stdin/stdout. Not a channel.

**Why.** vsock is the purpose-built host↔guest transport: addressed by `(CID, port)`, no IP/DHCP/
tap, and it gives us **real stream semantics** — connection lifecycle, back-pressure, and multiple
ports — which the serial byte-shovel does not. Firecracker supports it natively and the host side
is a unix socket, so it composes with the `unsafe`-free, UDS-over-`std` client pattern already
established in decision 001. The three review lenses shaped the *shape* of the channel, not just
the transport pick:
- **Reliability & bounded failure (DDIA / invariant 5).** The channel is a **new fault domain** —
  a guest that never connects, an agent that dies mid-command, a hung command, a half-written
  frame, a flooding writer. Each must be a **deadline-bounded, typed** failure, never a host hang
  or unbounded buffer. Length-prefixed framing (the same discipline as the HTTP `Content-Length`
  reads in `crates/vmm/src/firecracker.rs`) means a hostile or buggy guest cannot drive an
  unbounded read; every wait carries a deadline as the boot path already does.
- **Evolvability (DDIA).** The host driver and the in-guest agent are **separately built and
  versioned** binaries, so the wire protocol gets an explicit **version header** and additive,
  tag-length-value message framing — host and agent can skew across rebuilds without a silent
  mis-parse (contrast decision 001's Firecracker-schema pin, which we do *not* own).
- **Error taxonomy & API (Rust for Rustaceans / ZtP).** This implies extending the `#[non_exhaustive]`
  `VmmError` with additive channel/guest-failure variants (e.g. a channel/transport failure vs. a
  guest-agent crash vs. an exec timeout) so callers can distinguish "the VM broke" from "your
  command exited non-zero," and an `exec(cmd, stdin) -> Result<Output, VmmError>` surface (P2.4)
  whose `Output` mirrors the existing `RunResult`.
- **Telemetry & testability (ZtP).** The frame **codec is pure and unit-testable without KVM**
  (encode/decode round-trips, truncated-frame and oversized-length rejection — mirroring the
  existing HTTP-framing tests), while the live vsock transport is exercised behind
  `ci-privileged`; each `exec` runs under a child of the per-VM `boot` tracing span so guest
  activity stays attributable.

**Consequences / tombstones.**
- **Adds a guest-side component to build and trust-scope.** The agent must be **statically linked**
  (musl, no libc surprises) and **baked into the rootfs** — so P2.2 (the agent) and P3.1 (the
  reproducible rootfs build) are coupled, and the agent's protocol version is pinned alongside the
  image. It runs in-guest, so it is inside the isolation boundary and outside the trust boundary.
- **Requires `vhost-vsock` in the guest kernel** and a vsock device in the machine config; a guest
  kernel built without it falls back to the serial protocol above. The guest **CID** must be unique
  per VM (a uniqueness concern that returns, with entropy and network identity, when snapshots
  clone VMs in Phase 5 — see P5.5).
- **The host connects to a Firecracker-managed UDS with a `CONNECT <port>` handshake** — a
  Firecracker convention, pinned the way the API schema is in decision 001; a version bump means
  re-checking it.
- **The agent is exec/IO convenience, never containment.** If a later phase is ever tempted to move
  a security check into the guest agent, the design is wrong (spine property 2, tombstone).
- **The channel's public API is type-state, not free functions.** `ClientConnection`/
  `ServerConnection` perform the handshake on construction and expose only their role's operations,
  so a message-before-handshake or a client/server role mix-up is a *compile* error; the raw codec
  is `pub(crate)`. Chosen while the only callers were the guest agent and tests — cheap to commit to
  before the host side (P2.3) adopts it.
- **Liveness is the transport's responsibility, not the channel's.** The framing is transport-
  agnostic and sets no timeouts itself; every connection (the unix harness now, the vsock device +
  the host response read in P2.3) must set read/write deadlines on the concrete socket before
  wrapping it, so a dead-or-stalled peer is a typed timeout, never a hang. The guest agent's
  unconditional pipe-drain only bounds the guest *given* that write deadline. A silent hung *command*
  is a separate axis, bounded by the exec wall-timeout (P2.6).
