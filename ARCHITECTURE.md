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
- **P19.1** — freeze + version the wire API as the language-agnostic **SDK contract** (schema,
  error taxonomy, semver compat policy). *(vNext; the SDKs live in their own repos — see roadmap
  Phase 19.)*
- **P20.1** — the **Wasmtime sibling** is a separate repo that reuses the driver API + flight-
  recorder format, **not a plug-in backend** here (so *isolation is hardware* is never traded in
  this engine). *(vNext — see roadmap Phase 20.)*

---

## Repo layout

One Cargo workspace; each crate has a single job, split along the isolation/observability/driver
seams:

- `crates/vmm` — the **Firecracker driver**: microVM lifecycle (boot/exec/shutdown), rootfs and
  networking (tap), snapshots and the warm pool, jailer/cgroup confinement, and the `Sandbox`
  lifecycle API. No `unsafe` on the host path; a hostile guest is a typed error.
- `crates/channel` — the **host↔guest wire protocol**: dependency-free length-prefixed framing over
  `Read`/`Write`, shared by the driver and the guest agent (see decision 002).
- `crates/guest-agent` — the **in-guest agent** (`agent-guest`): runs one command per connection and
  streams stdout/stderr/exit over `channel`. Built static (musl), baked into the rootfs at Phase 3.
  Exec/IO convenience only — never the security boundary.
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

### 003 — The guest rootfs: a pinned Alpine base, assembled with the agent baked in *(2026-07-12, P3.1)*

**Decision.** The guest rootfs is **built, not fetched**: `cargo xtask build-rootfs` extracts a
**sha256-pinned Alpine minirootfs** (a real musl + busybox userland), bakes the static guest agent
in at `/usr/local/bin/agent-guest`, installs a minimal init, and assembles an ext4 image
(`artifacts/rootfs-agent.ext4`) with **`mke2fs -d`** — populating the filesystem from a staging dir
with **no root and no loopback mount**. A *distinct* output from the pinned Ubuntu boot rootfs Phase
1 used, so the `ci-privileged` hash-guard and the Phase-1 `login:` boot test are untouched. Two
hard-to-reverse pieces ride along:

- **Init model: busybox `init` is PID 1**, with a custom `/etc/inittab` (replacing Alpine's OpenRC)
  that mounts `devtmpfs`/`proc`/`sysfs` in `sysinit` and `respawn`s the agent on vsock port 1024
  (`AGENT_VSOCK_PORT`) attached to `ttyS0`. The agent is deliberately **not** PID 1: it has no
  orphan-reaping loop (a killed command's grandchildren reparent to PID 1 — busybox reaps them; the
  `forbid(unsafe_code)` agent would leak zombies), and a PID-1 crash panics the kernel, which must
  never be the fate of the respawnable exec surface.
- **Readiness contract: the agent emits the sentinel, post-`bind`.** The agent prints
  `GUEST_READY_MARKER` (`agent_channel`) to stdout — the serial console — *after* its vsock listener
  is bound, and `Vm::boot` returns only once it scans that line. So "userspace ready" means "the
  agent is accepting," eliminating the connect-before-listen race. (Emitting it from init before
  spawning the agent would reintroduce that race.)

**Alternatives considered.**
- **Scratch + a static busybox.** Most minimal and educational, but no `/etc` skeleton, no musl
  loader, no package manager — and the next boxes (P3.2 Python, P3.9 Node) want a real libc
  userland; static CPython on scratch is genuinely painful. Rejected as the base; the scratch lesson
  survives in P3.9's static Go/Rust ELF, which runs on this same image.
- **`docker export` of an image.** Needs the Docker daemon at build time and is less reproducible
  than a pinned tarball + scripted assembly. Rejected.
- **Overwrite `rootfs.ext4` / flip `BootConfig::default().rootfs` to Alpine.** Tempting ("`exec`
  just works"), but it breaks the `ci-privileged` sha256 guard (pins the Ubuntu hash) and the
  Phase-1 `login:` test in the same change. Kept **additive**: distinct filename, the test points at
  it explicitly. Retiring Ubuntu is a deliberate later change.

**Why.** Alpine is a pinned, ~5 MB, musl userland that boots with busybox and scales to Python/Node
via `apk` — the pragmatic base for the *runtime-agnostic* rootfs the Phase-3 goal calls for.
`mke2fs -d` keeps the whole build rootless and one-command, matching the "no `sudo cargo` roulette"
discipline. The agent as a baked-in, busybox-supervised child (never PID 1, never the containment
boundary) preserves spine property 2. This closes decision 002's P2.2 ↔ P3.1 coupling and its
`vhost-vsock` prerequisite: the pinned Firecracker CI kernel (`vmlinux-6.1.102`) carries the guest
vsock transport + `CONFIG_DEVTMPFS_MOUNT` — proven by the in-VM `exec("echo hi") → hi, exit 0`
round trip.

**Consequences / tombstones.**
- **P3.1's reproducibility bar is "pinned inputs + a fixed UUID + one scripted command," not
  byte-identical.** A content-manifest hash + any `SOURCE_DATE_EPOCH`/`hash_seed` byte-for-byte
  polish is **P3.6**.
- **The agent now depends on the `vsock` crate** (guest-agent-only; the host still reaches
  Firecracker's vsock over a plain `UnixStream`). Its tree is MIT/Apache and it doesn't breach the
  agent's own `forbid(unsafe_code)`.
- **The Alpine version + sha256 are pinned in `xtask`.** A bump means re-pinning the hash (the URL
  is replaceable, the hash is the contract — the decision-001 discipline).
- **A default-rootfs flip (Alpine replaces Ubuntu as the boot default) is a separate future change**,
  touching the default marker, the `ci-privileged` guard, and the Phase-1 boot test together.

### 004 — Read-only base rootfs + a per-run tmpfs overlay *(2026-07-12, P3.3)*

**Decision.** When `BootConfig.read_only_root` is set, the driver attaches the base rootfs
**read-only and shared** (no per-VM copy — Firecracker opens it `O_RDONLY`, so the guest can't mutate
it), and the guest stacks a **per-run tmpfs overlay** over it so `/` is writable but ephemeral. A
baked `/sbin/overlay-init` (PID 1, via `init=/sbin/overlay-init` the driver appends) mounts a
size-capped tmpfs, builds `overlayfs` with the RO base as lowerdir and the tmpfs as upper+work,
`pivot_root`s into it, and `exec`s the real init. **Read-only base and overlay are one concept, not
two knobs**: a RO `/` without the overlay would break the agent's `/tmp` working dir (`EROFS`), so
the single flag implies both.

**Alternatives considered.**
- **A second writable block device as the overlay upper.** Rejected for P3.3: heavier (a per-VM image
  to create/format on the host) and it consumes the exact mechanism P3.4/P3.5 own (injecting a per-run
  working dir via a second block device). tmpfs keeps P3.3 to the overlay lesson and is density-optimal
  — the base is shared read-only (page-cache-deduped across VMs) and the overlay costs only the RAM a
  run actually writes, vs. today's full ~50 MB copy per boot.
- **An initramfs that sets up the overlay before pivoting** ("initramfs vs rootfs"). Rejected:
  `BootSource` has no `initrd_path`, so it means a second CPIO artifact to build, pin, and hash-guard
  for zero benefit when a baked `/sbin/overlay-init` reuses the single ext4 we already assemble. The
  lesson is satisfied by documenting the choice.
- **`switch_root` instead of `pivot_root`.** Rejected: `switch_root` expects to *free* the old root,
  but ours is the RO base still in use as the overlay lowerdir. `pivot_root` keeps it mounted, shadowed
  at `/rom`.

**Why.** Runs are disposable, so an ephemeral RAM overlay is the natural writable layer, and sharing
one read-only base is the density win Phase 5 is measured against. The tmpfs cap is **half of guest
RAM** (`mem_mib / 2`), passed on the kernel command line as `overlay_size=<N>M` — the kernel routes
`key=value` cmdline tokens into PID 1's environment, so `overlay-init` reads `$overlay_size` without
mounting `/proc` first. A guest has **no swap**, so a tmpfs sized near RAM would drive the OOM-killer
rather than bound a runaway write. `/overlay` is **baked into the image** because the root is read-only
when `overlay-init` runs — you can't `mkdir` a mountpoint on a read-only `/`.

**Consequences / tombstones.**
- **Additive, not a flip.** `read_only_root` defaults `false` and is **not** an `AGENT_*` env key — it's
  set in code where the agent image is chosen as a bundle (the test's `agent_rootfs_config`), so the
  multi-env footprint doesn't grow. The stock (Ubuntu) config still copies + boots read-write. Making
  the agent rootfs the read-only default is still the separate flip this file's decision 003 reserved.
- **Snapshot/restore (Phase 5):** the tmpfs upper lives in guest RAM, so it is captured by a memory
  snapshot, and a restore requires the same read-only base present at the same host path.
- **A read-only rootfs must ship `/sbin/overlay-init` + a `/overlay` mountpoint** (both baked by
  `build-rootfs`); pointing `read_only_root` at an image without them is a bounded boot failure (typed
  `VmmError`, `panic=1` → Firecracker exits → console tail), not a hang.

### 005 — Bulk input via a read-only second block device *(2026-07-12, P3.4)*

**Decision.** When `BootConfig.input_dir` is set, the driver builds a **read-only** ext4 from that
host directory (rootless `mke2fs -d` into the per-VM scratch dir) and attaches it as a second block
device (`/dev/vdb`, `is_read_only: true`); the agent rootfs mounts it read-only at `/input` via a
best-effort `sysinit` line, so a command reads bulk input as `/input/...`. This is the
whole-working-dir / large-file path — the vsock channel's `PutFile` carries only small `≤1 MiB`
per-frame files. **No guest-agent change**: `/input` is a mounted dir the command references; the
agent's per-exec `/tmp` `RunDir` is untouched.

**Alternatives considered.**
- **A read-write "working dir" block device** (the device *is* the writable cwd; outputs land there).
  Rejected: that's P3.5 (pull artifacts back) done early, and it detonates P3.5's hardest problem now
  — `teardown` hard-kills Firecracker, so the guest never cleanly unmounts, and reading that ext4
  back host-side would be a dirty, un-replayed filesystem. It would also force the agent's `RunDir`
  into a sometimes-`/input`-sometimes-`/tmp` mode, breaking the per-exec isolation `RunDir` exists for
  and front-running Phase-7 stateful sessions. Read-only keeps the input **provably immutable**
  (`O_RDONLY` — the same primitive the P3.3 overlay guarantee rests on) and the writable working dir
  stays the P3.3 overlay `/tmp`.
- **A prebuilt image path** instead of a host directory. Deferred: a directory is the ergonomic match
  to "inject a working dir," and an `input_image` escape hatch is trivial to add later.

**Why.** Injecting a directory the driver turns into a block device is the standard bulk host→guest
path; it carries what a 1 MiB frame provably can't, at near-disk speed, with no channel round trips.
`is_read_only: true` is load-bearing: it makes the input immutable and sidesteps the dirty-ext4
read-back hazard. Symlinks in the input are copied verbatim by `mke2fs -d`, so a link resolves inside
the *guest's* filesystem, never the host's — no traversal escape.

**Consequences / tombstones.**
- **A new runtime tool dependency on the driver host** (`mke2fs` + `truncate`): previously the driver
  spawned only `firecracker`. A missing tool is a typed `VmmError::Artifact`, and `xtask setup`
  checks for `mke2fs`.
- **Boot-latency cost:** building the image (`truncate` + `mke2fs -d`) is on the boot path — bounded,
  but it belongs behind the warm-pool pre-build once Phase 5 lands.
- **`/dev/vdb` naming is order-dependent.** Fine for a single input device; if P3.5 adds a third
  (writable output) drive, prefer mounting by filesystem label/UUID.
- **The image is sized generously** from the input's byte total + a `-N` inode count (many tiny files
  exhaust inodes, not bytes); an input past a 2 GiB ceiling is a typed error, not a giant image.
