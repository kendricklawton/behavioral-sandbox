# Architecture decisions

The record [`ROADMAP.md`](../ROADMAP.md) references: every roadmap item tagged `(decision)`
produces a dated, numbered entry here — the decision, the alternatives considered, and the why —
so the reasoning outlives the diff. Each entry is keyed by its own number and date (not a phase),
so it stands on its own as the roadmap evolves. Entries are append-only; reversing one is a new entry, not an
edit. (Roadmap *re-scopes* — cut phases and why — live in the roadmap's notes, not here.)

**The Firecracker + aya sandbox engine.** This decision log covers the self-hostable, isolated
**code-execution sandbox**: **Firecracker** microVMs for hardware isolation, **aya/eBPF** for
host-side observability and enforcement (see `.rules`, `ROADMAP.md`). The guiding properties are
the four core properties: *isolation is hardware · observe & enforce from the host · engine not platform ·
measured, not marketed.*

Decisions queued by the (sandbox) roadmap, to be recorded here as they're made:

- **P11.6** — where egress policy lives and its schema (engine *mechanism*, not org policy).
- **P15.6** — the security boundary and its trust assumptions (what's trusted: CPU/KVM/host
  kernel; what isn't: the guest).
- **P16.2** — the driver daemon's wire API surface: JSON-over-unix-socket vs gRPC.
- **P20.1** — freeze + version the wire API as the language-agnostic **SDK contract** (schema,
  error taxonomy, semver compat policy). *(vNext; the SDKs live in their own repos — see roadmap
  Phase 20.)*
- **P21.1** — the **Wasmtime sibling** is a separate repo that reuses the driver API + audit-log
  format, **not a plug-in backend** here (so *isolation is hardware* is never traded in
  this engine). *(vNext — see roadmap Phase 21.)*

---

## Repo layout

One Cargo workspace; each crate has a single job, split along the isolation/observability/driver
boundaries:

- `crates/vmm` — the **Firecracker driver**: microVM lifecycle (boot/exec/shutdown), rootfs and
  networking (tap), snapshots and the pre-warmed pool, jailer/cgroup confinement, and the `Sandbox`
  lifecycle API. No `unsafe` on the host path; a hostile guest is a typed error.
- `crates/channel` — the **host↔guest wire protocol**: dependency-free length-prefixed framing over
  `Read`/`Write`, shared by the driver and the guest agent (see decision 002).
- `crates/guest-agent` — the **in-guest agent** (`agent-guest`): runs one command per connection and
  streams stdout/stderr/exit over `channel`. Built static (musl), baked into the rootfs at Phase 3.
  Exec/IO convenience only — never the security boundary.
- `crates/probes` — the **eBPF programs** (`#![no_std]`, built for `bpfel-unknown-none` via
  `bpf-linker`): syscall tracepoints, tc/XDP on the VM's tap, cgroup accounting. CO-RE/BTF.
- `crates/probes-loader` — the **userspace loader** (aya): attaches the probes to a specific
  sandbox, reads their maps, and streams events into the audit log.
- `crates/cli` — the `agent` binary (`run`, `shell`, `--trace`) and later the `agentd` daemon.
- `xtask` — dev orchestration; `cargo xtask ci` runs the host-safe gate and builds the eBPF
  object, `ci-privileged` runs the VM-boot + probe-attach integration tests, `setup` verifies the
  host, and the rootfs/kernel build lives here. Never shipped.

---

## Recorded decisions

### 001 — Drive Firecracker via its HTTP API over a unix socket *(2026-07-10)*

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
keeps us dependency-light and `unsafe`-free, and the raw request/response framing stays small.

**Consequences and notes.**
- **Pinned to Firecracker v1.9's API schema.** Field names (`vcpu_count`, `mem_size_mib`,
  `is_root_device`, …) have drifted across releases; a version bump means re-checking the request
  bodies in `crates/vmm/src/firecracker.rs`.
- **Serial-console-on-stdout is an unjailed convenience.** We read the guest console from the
  `firecracker` child's stdout. The jailer (Phase 6) changes that wiring, so console capture sits
  behind a small internal boundary to swap later.
- **`SendCtrlAltDel` graceful shutdown is x86-only** (i8042); the guaranteed teardown is
  `kill()` + scratch-dir removal, so no leak depends on the guest cooperating.

### 002 — Host↔guest channel: vsock + a tiny guest agent *(2026-07-10)*

**Decision.** `exec` talks to the guest over **virtio-vsock**: a minimal, statically-linked
**guest agent** (started by the guest's init) listens on a vsock port, runs the requested command,
and streams `stdout`/`stderr`/exit back; the host reaches it through the **unix-domain socket
Firecracker exposes for vsock** (a `CONNECT <port>\n` handshake, then a raw bidirectional stream —
the same host-side shape as decision 001). Over that stream we speak **our own framed protocol**:
a small versioned header, then **length-prefixed messages** (start-request, stdin chunk, stdout/
stderr chunk, exit) — never a read-to-EOF or a delimiter scan. The guest agent carries exec/IO
**only**; it is a convenience, never part of the trust boundary (core property 2 — a compromised
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

**Consequences and notes.**
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
  a security check into the guest agent, the design is wrong (core property 2, recorded).
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

### 003 — The guest rootfs: a pinned Alpine base, assembled with the agent baked in *(2026-07-12)*

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
  userland; static CPython on scratch is genuinely painful. Rejected as the base; the scratch approach
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
boundary) preserves core property 2. This closes decision 002's P2.2 ↔ P3.1 coupling and its
`vhost-vsock` prerequisite: the pinned Firecracker CI kernel (`vmlinux-6.1.102`) carries the guest
vsock transport + `CONFIG_DEVTMPFS_MOUNT` — proven by the in-VM `exec("echo hi") → hi, exit 0`
round trip.

**Consequences and notes.**
- **P3.1's reproducibility bar was "pinned inputs + a fixed UUID + one scripted command," not
  byte-identical.** ~~A content-manifest hash + any `SOURCE_DATE_EPOCH`/`hash_seed` byte-for-byte
  polish is **P3.6**.~~ **Resolved in P3.6 (decision 007):** `SOURCE_DATE_EPOCH` + a fixed htree hash
  seed + dropping apk's wall-clock install log make two builds byte-identical, verified by a gate; a
  committed lockfile records the resolved package closure.
- **The agent now depends on the `vsock` crate** (guest-agent-only; the host still reaches
  Firecracker's vsock over a plain `UnixStream`). Its tree is MIT/Apache and it doesn't breach the
  agent's own `forbid(unsafe_code)`.
- **The Alpine version + sha256 are pinned in `xtask`.** A bump means re-pinning the hash (the URL
  is replaceable, the hash is the contract — the decision-001 discipline).
- **A default-rootfs flip (Alpine replaces Ubuntu as the boot default) is a separate future change**,
  touching the default marker, the `ci-privileged` guard, and the Phase-1 boot test together.

### 004 — Read-only base rootfs + a per-run tmpfs overlay *(2026-07-12)*

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
  working dir via a second block device). tmpfs keeps P3.3 to the overlay approach and is sharing-optimal
  — the base is shared read-only (page-cache-deduped across VMs) and the overlay costs only the RAM a
  run actually writes, vs. today's full ~50 MB copy per boot.
- **An initramfs that sets up the overlay before pivoting** ("initramfs vs rootfs"). Rejected:
  `BootSource` has no `initrd_path`, so it means a second CPIO artifact to build, pin, and hash-guard
  for zero benefit when a baked `/sbin/overlay-init` reuses the single ext4 we already assemble.
  Documenting the choice suffices.
- **`switch_root` instead of `pivot_root`.** Rejected: `switch_root` expects to *free* the old root,
  but ours is the RO base still in use as the overlay lowerdir. `pivot_root` keeps it mounted, shadowed
  at `/rom`.

**Why.** Runs are disposable, so an ephemeral RAM overlay is the natural writable layer, and sharing
one read-only base is the memory-sharing win Phase 5 is measured against. The tmpfs cap is **half of guest
RAM** (`mem_mib / 2`), passed on the kernel command line as `overlay_size=<N>M` — the kernel routes
`key=value` cmdline tokens into PID 1's environment, so `overlay-init` reads `$overlay_size` without
mounting `/proc` first. A guest has **no swap**, so a tmpfs sized near RAM would drive the OOM-killer
rather than bound a runaway write. `/overlay` is **baked into the image** because the root is read-only
when `overlay-init` runs — you can't `mkdir` a mountpoint on a read-only `/`.

**Consequences and notes.**
- **Additive, not a flip.** `read_only_root` defaults `false` and is **not** an `AGENT_*` env key — it's
  set in code where the agent image is chosen as a bundle (the test's `agent_rootfs_config`), so the
  multi-env footprint doesn't grow. The stock (Ubuntu) config still copies + boots read-write. Making
  the agent rootfs the read-only default is still the separate flip this file's decision 003 reserved.
- **Snapshot/restore (Phase 5):** the tmpfs upper lives in guest RAM, so it is captured by a memory
  snapshot, and a restore requires the same read-only base present at the same host path.
- **A read-only rootfs must ship `/sbin/overlay-init` + a `/overlay` mountpoint** (both baked by
  `build-rootfs`); pointing `read_only_root` at an image without them is a bounded boot failure (typed
  `VmmError`, `panic=1` → Firecracker exits → console tail), not a hang.

### 005 — Bulk input via a read-only second block device *(2026-07-12)*

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

**Consequences and notes.**
- **A new runtime tool dependency on the driver host** (`mke2fs` + `truncate`): previously the driver
  spawned only `firecracker`. A missing tool is a typed `VmmError::Artifact`, and `xtask setup`
  checks for `mke2fs`.
- **Boot-latency cost:** building the image (`truncate` + `mke2fs -d`) is on the boot path — bounded,
  but it belongs behind the pre-warmed-pool pre-build once Phase 5 lands.
- **`/dev/vdb` naming was order-dependent.** ~~Fine for a single input device; if P3.5 adds a third
  (writable output) drive, prefer mounting by filesystem label/UUID.~~ **Resolved in P3.5:** the
  guest now mounts both data devices by filesystem **label** (`agent-input`/`agent-output`, stamped
  with `mke2fs -L`, resolved with `findfs`), so the `/dev/vdX` letter — which shifts when output is
  present but input isn't — no longer matters. The input image gained an `agent-input` label and the
  `sysinit` line became `/sbin/mount-drives`.
- **The image is sized generously** from the input's byte total + a `-N` inode count (many tiny files
  exhaust inodes, not bytes); an input past a 2 GiB ceiling is a typed error, not a giant image.

### 006 — Bulk output via a read-after-death writable block device *(2026-07-12)*

**Decision.** When `BootConfig.output_dir` is set, the driver attaches a **blank, writable** ext4 as
a third block device (labelled `agent-output`, `is_read_only: false`); the guest mounts it read-write
at `/output`, so a command's files under `/output/...` are the bulk-output surface. `RunningVm::`
`collect_outputs` (consumes the VM) then reads that image back into the host directory. It is the
whole-working-dir / large-file counterpart to the vsock channel's per-frame `Response::File`
artifacts (P2.5), which carry only small files. Readback is **rootless** and happens **after the VMM
has exited**: stop the VM (cooperative `SendCtrlAltDel`, then a hard kill), `e2fsck -fy` the image to
recover the journal, then `debugfs rdump` the tree out — no loopback, no `mount`, no `sudo`.

**Alternatives considered.**
- **Read the writable image while the VMM is live** (a `&self` method). Rejected: Firecracker holds
  the file open and the guest may still be writing, so `e2fsck` (which *writes* journal replay) would
  race the VMM and could corrupt the image. `collect_outputs` therefore consumes the VM and stops it
  first — the fd must be closed before we touch the file.
- **Stream the output over the vsock channel** (a `tar` the guest pipes back). Rejected for the bulk
  path: it re-imposes the channel's framing/round-trip cost and forces a guest-agent change; the block
  device carries what the channel can't at near-disk speed, with **no guest-agent change** (the
  command writes to `/output`; a wedged grandchild can't wedge the agent).
- **Loop-mount the image host-side** and copy. Rejected: `mount` needs root/`CAP_SYS_ADMIN`, breaking
  the rootless discipline P3.4 set. `debugfs rdump` reads an ext4 without mounting, mirroring how
  `mke2fs -d` *writes* one without mounting.
- **`fuse2fs` + `cp --sparse=always`.** Not available on the reference host (no `fuse2fs` binary), and
  it adds a `/dev/fuse` dependency and a real mount to unwind; `debugfs` keeps deps to e2fsprogs.

**Why.** Symmetry with the input side, at the cost the input side deferred here. Durability of the
guest's writes is the `/output` `-o sync` mount (each write flushed through to the image) plus the
guest's clean `::shutdown:/bin/umount -a -r`; `e2fsck` then makes even a hard-killed, dirty image
consistent before extraction. The image is built with `lazy_itable_init=0` so the guest kernel never
lazily zeroes the inode table at runtime — which would balloon the sparse image toward its full
256 MiB on the host regardless of what the command wrote.

**Security — the inverse of 005's symlink note.** `mke2fs -d` resolves *input* links inside the guest
image; `debugfs rdump` recreates *output* links verbatim as **host** symlinks, so an un-sanitised
`link -> /etc/shadow` in `/output` would make a later host read of the results read host files.
`collect_outputs` therefore **drops every symlink whose target escapes the destination** (absolute, or
`..` climbing out), keeping only in-tree links, before returning. The guest only ever writes through
the guest kernel's ext4 driver (never raw block access), so the on-host image is always a well-formed,
crash-consistent, kernel-produced filesystem — the residual adversary controls contents, names, and
link targets, not the metadata `e2fsck`/`debugfs` parse.

**Consequences and notes.**
- **New runtime tool dependencies** (`e2fsck` + `debugfs`, both e2fsprogs — the same package as
  `mke2fs`, so no *new* package): a missing binary is a typed `VmmError::Artifact`, and `xtask setup`
  checks for both.
- **`debugfs rdump` materialises filesystem holes as real zeros**, so a sparse file staged in the
  capped image could inflate the readback. The extraction is bounded by a watcher on the destination's
  **allocated** bytes (`OUTPUT_EXTRACT_CAP`, 512 MiB) and a wall-clock deadline
  (`OUTPUT_READBACK_TIMEOUT`); a breach is a typed `OutputCap`/`Timeout`, never unbounded host disk.
- **`-o sync` trades throughput for durability.** Fine for the "a few large files" mechanism; a
  future optimisation is an async mount + an explicit guest `sync` on teardown (needs a guest-agent
  touch, so deferred).
- **The 256 MiB image is a fixed cap**, the natural bulk-output bound (the guest can't write more than
  the filesystem holds), mirroring the channel path's 16 MiB. It becomes a `BootConfig` knob when the
  per-run resource policy lands.
- **`Sandbox` plumbing is deferred** (as `input_dir` was): `output_dir`/`collect_outputs` live at the
  `RunningVm` layer for now; a `Sandbox::collect_outputs` + `agent run --output-dir` follow-up is
  noted in the roadmap.

### 007 — A byte-for-byte reproducible rootfs build *(2026-07-12)*

**Decision.** `cargo xtask build-rootfs` is **deterministic**: two builds from the same inputs produce
a byte-identical `rootfs-agent.ext4`. Three non-determinism sources are pinned:
- **`mke2fs` timestamps + directory-hash seed.** `SOURCE_DATE_EPOCH` (a fixed constant, scoped to the
  `mke2fs` child) stamps the superblock create/write/check times and clamps every `-d`-copied file
  mtime down to it; `-E hash_seed=<fixed UUID>` fixes the htree seed (otherwise random per build);
  `lazy_itable_init=0` writes the inode table eagerly so its bytes are fixed here, not finished
  non-deterministically by the guest kernel on first mount.
- **apk's install log.** `/var/log/apk.log` records each action with a **wall-clock** timestamp — the
  one install artifact that isn't reproducible (the package db content is deterministic). It has no
  runtime purpose, so the build removes it. (Found by diffing two builds' extracted trees, not by
  the `mke2fs` polish alone.)
- **The guest agent binary** is already reproducible (pinned `rust-toolchain.toml` + `--locked`) — so
  no `--remap-path-prefix` is needed.

A committed **package lockfile** (`xtask/rootfs-packages.lock`) records the exact resolved closure
(`name-version-rN`, base + `apk add` deps). `build-rootfs --verify` (which `ci-privileged` runs)
builds twice, asserts byte-identical, and fails on closure drift; `--update-lock` re-records after an
upstream bump. The default `build-rootfs` stays one command (deterministic image; warns on drift).

**Alternatives considered.**
- **Exact-pin the packages (`apk add python3=<ver>`) as the reproducibility contract.** Rejected —
  the tempting analogy to the sha-pinned *tarball* is false. The minirootfs lives at a stable
  *release* URL (its bytes stay fetchable forever), but Alpine **branch** repos keep only the latest
  revision and **delete** the old `.apk` on every bump. So an exact pin doesn't reproduce the old
  build — it **fails** it the day upstream moves, and churns the repo with a lockfile commit per
  patch. A floating install that *records* the closure and *detects* drift keeps the everyday build
  working while still flagging when the image would change.
- **Vendor the `.apk` closure as sha-pinned artifacts** (hash-pin each of the ~33 packages, install
  offline). The genuinely durable end state — it closes the one security-relevant input still
  fetched-not-pinned — but it's a phase's worth of fetch/verify/offline-install rework. **Deferred**
  as the later hardening, out of scope for the byte-for-byte polish.
- **A separate content-manifest file** re-listing the Alpine/apk-tools shas + branch + target.
  Rejected: those are already source-of-truth constants in `xtask`; a second copy just drifts. The
  only thing not already captured is the resolved closure — which *is* the lockfile.

**Why.** Reproducibility is a first-class "measured, not marketed" property: a build you can't
reproduce is a claim you can't check. `SOURCE_DATE_EPOCH`/`hash_seed`/`lazy_itable_init=0` are the
standard ext4 determinism levers; the apk-log removal was the non-obvious last mile. The lockfile
makes package drift *visible* without making the build *brittle*.

**Consequences and notes.**
- **Reproducibility is a `ci-privileged`-guarded property**, not the everyday `ci` gate's — it needs
  the musl target + network + `mke2fs`, so `--verify` runs where the boot tests already do.
- **The lockfile drifts only on an Alpine package bump**, never on guest-agent code changes (the
  closure is independent of the agent binary) — so it isn't a per-commit chore.
- **Durable over-time reproducibility still rests on Alpine's CDN** until the `.apk` closure is
  vendored (the deferred hardening); today a bump makes `--verify` fail loudly with a re-pin hint.
- **The same availability class covers `fetch-artifacts`' inputs** (P6.9d): the pinned guest kernel
  and Ubuntu boot rootfs come from the Firecracker CI S3 bucket, sha256-pinned — so tamper-*safe*
  but availability-*fragile*. A deleted bucket (or a retired Alpine branch) bricks **fresh-host
  setup** while existing `artifacts/` dirs keep working, and nothing upstream owes these URLs
  permanence. The failure is loud (a hash-checked fetch fails, it never silently substitutes), and
  the durable fix — vendoring the kernel, base images, and `.apk` closure as release artifacts of
  this repo — rides the P19.1 packaging work, where a self-host bundle needs them offline anyway.
- **A fixed htree hash seed is safe here** — the seed only matters against adversarial directory-hash
  flooding, which a trusted, pinned, build-time image doesn't face.
- **The guarantee is same-host determinism, not cross-machine bit-reproducibility.** The rootless
  build stages files owned by the *build user's* uid/gid, and `mke2fs -d` copies that ownership into
  the image, so an image built by a different user (or from a different checkout path, which can leak
  into the agent binary's debug strings) differs byte-for-byte. `--verify` builds twice as the same
  user from the same path back to back, so it proves the build is deterministic *on this host*, which
  is what catches an accidental non-determinism regression. Cross-host reproducibility (normalize
  ownership to `0:0`, `--remap-path-prefix` the binary) is a separate, deferred hardening.

### 008 — Guest networking is deny-by-default: a tap with no route to the world *(2026-07-12)*

**Decision.** When Phase 4 gives the guest a NIC, the per-VM tap device defaults to **no route to the
outside world** — host-local reachability only (host↔guest over the tap's own subnet), with any egress
to the wider network being an **explicit, recorded** allowance, never the default. The driver installs
**no** `MASQUERADE`/general-forward rule as part of standing a VM up. Every routing/netfilter rule the
driver *does* install is enumerated in code and recorded (feeding the audit log, P4.8), so the
network posture of a running sandbox is auditable from the host. This **resolves the direction of the
queued P4.3 decision** (deny-by-default over NAT-to-world) and makes **P4.3 blocking on P4.1** — the
addressing/tap work lands already denying, not opened-then-restricted.

**Alternatives considered.**
- **Default `MASQUERADE` to give the guest general egress (the "it just works" NAT).** Rejected: it is
  the fastest way to make a P4.7-style "guest reaches an allowed endpoint" test pass, but it opens
  *general* egress and **breaks guardrail #4** (deny-by-default). Worse, the real enforcement
  mechanism — host-side eBPF on the tap (Phase 8) — does not exist yet, so a default-open tap would be
  *unenforced* open egress for four phases. Opening later behind an allow-list is a one-way door only
  if we start closed.
- **Wire an allow-list now, in the driver, ahead of eBPF.** Rejected as scope/placement error: policy
  enforcement belongs in host-side eBPF (guardrail #2), not in ad-hoc driver-installed `iptables`
  rules that would then have to be unwound in Phase 8. P4 gives the guest an address and a host-local
  path; P8 is where allow/deny egress policy is *enforced and observed* from the host.

**Why.** Deny-by-default is a core property, and today it holds only *by construction* — the guest
has no NIC at all (no `/network-interfaces` PUT, no `ip=` boot arg). Phase 4 flips that to "a NIC
exists," and the safe flip is closed-by-default: the guest can talk to its host (enough for the P4
addressing/routing demo) but reaches nothing beyond it until an explicit, host-enforced policy says so.
This keeps the security boundary on the host and out of the guest's reach, and keeps the "every
allowance is recorded" invariant true from the first tap.

**Consequences and notes.**
- **The tap is the first per-VM resource that lives *outside* the workdir**, so teardown must delete it
  (and its routes) on every path — a hard requirement carried by P4.1/P4.5, not this decision.
- **P4.7's "reaches an allowed endpoint" is deferred to real enforcement**: until eBPF (P8), "allowed"
  means host-local; world-egress allow-listing is an eBPF-enforced, recorded policy, not a driver NAT
  rule. The bench/demo for P4 proves host↔guest reachability and that the guest reaches *nothing else*.
- **No default masquerade is a standing rule**, not a P4-only stopgap: if a hoster wants NAT egress,
  that is an explicit configured allowance the audit log captures, consistent with guardrail #3
  (the hoster's policy, enabled explicitly), never an engine default.

**As shipped.** The addressing/tap work (P4.1/P4.2) implements this directly: the guest's `eth0` is
configured via the kernel `ip=` param with an **empty gateway field**, so the kernel installs only the
connected /30 route and **no default route**, and the driver installs no masquerade and never enables
`ip_forward`. Net effect: the guest reaches its host end of the /30 and nothing else. Proven by the
`addresses_the_guest_and_routes_host_to_guest` integration test, which asserts the guest carries its
address, reaches the host tap IP, and gets a fast `ENETUNREACH` (not a timeout) for an off-subnet
address. So this decision is realized, not just intended.

### 009 — The per-VM tap: shelled out to `ip`, deleted on every teardown path *(2026-07-12)*

**Decision.** With `BootConfig.enable_network`, the driver gives the guest a virtio-net `eth0` backed
by a per-VM host **tap**. Mechanism:
- **Create by shelling out to `ip` (iproute2)**, not a netlink crate — the same convention the driver
  already uses for `mke2fs`/`truncate`/`e2fsck`/`debugfs`. Creating a tap needs `CAP_NET_ADMIN`, so
  this is a privileged operation (like `/dev/kvm`); the integration test skips without the capability.
- **Host-global unique name via create-and-retry.** The name is `fc<hex>` (≤14 bytes, within the
  15-byte `IFNAMSIZ` limit), seeded from a PID-mixed counter. Uniqueness across concurrent driver
  processes rests on `ip tuntap add` failing on an already-taken name as the **atomic reservation**
  (detected by asking netlink whether the interface now exists, since `ip tuntap` fails with `EBUSY`,
  not the RTNETLINK `EEXIST`, on a collision) — the same
  fail-if-exists-then-retry pattern as `create_workdir`, never a `/sys/class/net` scan (which would
  race between check and create).
- **A locally-administered unicast MAC** (`02:00:xx:xx:xx:xx`) derived from the per-VM index: first
  octet sets the LAA bit and clears the multicast bit, so every VM gets a distinct, valid NIC address.
- **Attach** via `PUT /network-interfaces/eth0` (`host_dev_name` + `guest_mac`), a sixth API body
  struct mirroring the vsock block.
- **Delete on every teardown path.** A tap lives **outside** the per-VM scratch dir, so
  `remove_dir_all(workdir)` cannot reclaim it. The `Tap` handle is threaded through `Spawned` and
  `RunningVm` (like `vsock_uds`/`output`) and deleted (`ip link del`) in all three reclamation paths —
  `RunningVm::drop`, `Spawned::drop`, and `Spawned::abort` — so a boot that fails *after* tap-create
  still cleans up. Deletion is best-effort (`tracing::warn!` on failure, never a panic — the host path
  is `#![forbid(unsafe_code)]`/no-panic).

**Alternatives considered.**
- **`rtnetlink` (a netlink crate) instead of shelling `ip`.** Rejected: it pulls an async dependency
  tree through `cargo deny` for no benefit; the driver's whole style is dependency-light shell-outs to
  host tools, and `ip` is already a documented `ci-privileged` requirement.
- **Encode VM identity in the tap name.** Rejected: `IFNAMSIZ` is 15 bytes and a PID+sequence blows
  the budget. The name is just a claimed host-global token; per-VM identity is the MAC (and, later, the
  subnet/CID the allocator will derive from the same index).
- **A `Drop` on `Tap`.** Rejected: `Spawned`/`RunningVm` already own the guaranteed-teardown `Drop`s;
  a second `Drop` would risk double-delete noise. One owner, explicit delete in the three paths.

**Why.** The tap is the first per-VM resource that isn't inside the scratch dir, so it's the first
thing the "everything reclaimable lives in `workdir`" teardown model doesn't cover — hence threading a
handle and deleting on every path is load-bearing, not incidental (decision 008's note flagged
exactly this). Shelling to `ip` keeps the driver dependency-light and `unsafe`-free.

**Consequences and notes.**
- **The allocator now yields name + MAC + a point-to-point /30** (`subnet_for`, added by P4.2): from
  `10.200.0.0/16`, host = block+1, guest = block+2, with the /30 index folding the PID bits down so
  concurrent processes don't collide at `NET_SEQ=0`. Guest addressing is the kernel `ip=` param
  (`CONFIG_IP_PNP`, present in the pinned kernel), so it needs no rootfs change; the host end is
  assigned in `Tap::create` and cascades away on `ip link del`. Still open on the same index: the
  guest **CID** (still the hardcoded `DEFAULT_GUEST_CID = 3`).
- **The /30 is atomically unique per VM** (P4.4): the PID-fold only makes a same-`NET_SEQ` collision
  *unlikely*, and folding 64 bits to a 14-bit index means two distinct tap names can still map to one
  /30. So `Tap::create` makes the **host-address assignment the reservation**: `ip addr add` fails when
  another VM already holds that /30 (checked with `host_addr_exists`, netlink-truthy, not a string
  match), and the loop reclaims the tap and retries with a fresh token (the same fail-if-taken pattern
  as the name). Two concurrent sandboxes therefore never share a subnet, which is what keeps one VM off
  another's tap (proven by `two_vms_cannot_reach_each_others_tap`).
- **Per-VM network-namespace isolation is deferred, by design.** ***(Resolved: decision 017 moved the
  tap into a per-VM netns at P7.0c; the unique-/30 allocator below is retired — every VM now reuses one
  fixed /30, isolated by its namespace.)*** P4.4's bar is met at L3: with no
  default route a guest can only address its own /30, so it can't even name another VM's tap, and the
  unique-/30 reservation removes the one way subnets could overlap. Putting each tap in its own netns
  (and running the VMM inside it) is stronger defence-in-depth but couples to running the VMM under the
  Phase-6 **jailer**; it's recorded here as that phase's work, not built in Phase 4.
- **Deny-by-default holds by construction:** with P4.2 the guest is addressed on the /30 and can reach
  the host end — but the `ip=` gateway field is **empty**, so the kernel installs only the connected
  route, **no default route**, and the driver installs no masquerade or `ip_forward`. So the guest
  reaches the host and nothing else, until eBPF-enforced egress policy (decision 008) opens anything.
- **A hard-killed driver can still orphan a tap** (no `Drop`-of-temp-dir safety net, unlike the
  scratch dir) — the same class of gap as P6.7's SIGKILL-leaks-a-VM, and the reason the leak test scans
  for orphaned `fc*` interfaces. The durable owner is the Phase-6 jailer/cgroup model.
- **Kernel `ip=` addressing is cold-boot-only by nature** (learned at P5.5): it runs exactly once,
  before userspace, so it cannot re-address a snapshot-restored clone. That is not a defect in this
  decision, it is the boundary of what boot-time config can do; restore identity is decision 011's
  runtime path (the guest agent applies a fresh address over vsock). `ip=` stays the zero-overhead
  cold-boot mechanism; if the runtime path ever proves cleaner for cold boot too, unify then, with
  evidence.

### 010 — Snapshots are self-contained bundles restored by staging the disk *(2026-07-12)*

**Decision.** A microVM snapshot is a **self-contained bundle** in one directory: the vCPU/device
**state** file, the full guest **memory** file, and a **point-in-time copy of the root disk**.
- **Take it paused, copy the disk in the paused window.** `RunningVm::snapshot` does `PATCH /vm
  {Paused}` (freeze vCPUs) then `PUT /snapshot/create {Full}`, and copies the root disk *while paused*
  so the on-disk bytes agree with the frozen memory image, then `PATCH /vm {Resumed}`. A create
  failure still falls through to the resume, so a failed snapshot never leaves the guest frozen (the
  no-hang discipline).
- **Restore stages the disk at the recorded path, then unlinks it.** Firecracker opens each drive's
  backing file **during `PUT /snapshot/load`**, at the path baked into the snapshot, *before* any
  `PATCH /drives` can repoint it (learned by trying the rebase-after-load path and watching the load
  fail on the source's since-reclaimed scratch path). So `Vm::restore` copies the bundle's private disk
  to that recorded path, loads with `resume_vm:true`, then **unlinks** the staged file once the VMM
  holds the fd. The restored clone gets its own disk **inode** (the open fd keeps it alive for the VM's
  lifetime), shares no writable backing with its source, and leaves nothing outside its own scratch
  dir. Staging refuses to overwrite an existing file, so a still-live source's disk is never clobbered.
- **The API client gained `patch`** (Firecracker uses `PATCH` for in-place changes to a configured VM)
  and typed bodies for `/vm`, `/snapshot/create`, `/snapshot/load`, with the closed-set discriminants
  (`Paused`/`Resumed`, `Full`, `File`) modelled as enums, the same wire-discriminant discipline as
  `Action` (decision 001).

**Alternatives considered.**
- **Rebase the drive after load (`PATCH /drives`).** Rejected because it doesn't work: Firecracker
  opens the backing file at load, so the recorded path must be valid *then*; a post-load patch is too
  late. Staging-then-unlink is the workaround that keeps the bundle portable.
- **Reference a read-only shared base instead of copying the disk.** The right long-term shape for
  memory-sharing (many clones over one base), but it needs the source booted `read_only_root`, which needs the
  agent rootfs, which needs vsock to reach its readiness marker, and a vsock/NIC snapshot can't yet
  recreate its host endpoints on restore. So the read-write, private-copy path is the P5.1/P5.2 scope;
  read-only-base pre-warmed snapshots are P5.3/P5.4.

**Why.** A self-contained bundle can be moved or kept after the source VM is gone, which is what makes
"snapshot then restore N clones" (P5.4) and a pre-warmed pool (P5.6) tractable. The staging trick is the
minimal correct way to honour Firecracker's load-time drive-open contract without a shared mutable
backing file.

**Consequences and notes.**
- **Restore is dramatically faster than cold boot:** dev box, ~1.57 s cold vs **~8.9 ms** restore
  (≈177×). This is the fast-start reason the phase exists; the tracked p50/p99 benchmark is P5.7.
- **Snapshotting is scoped to a root-disk-only, read-write boot.** A VM with vsock, a NIC, or an output
  device is a typed error today (its host endpoints can't be recreated on restore yet, P5.4/P5.5), and
  a read-only shared base is deferred (P5.3/P5.4). The guard is structural (the root backing must live
  inside the VM's scratch dir), so it can't silently produce an unrestorable bundle.
- **The restored VM has no exec channel yet.** vsock-over-snapshot (so a restored pre-warmed VM can run code)
  is P5.8; today restore exposes liveness + teardown, and `boot_latency()` on a restored VM holds the
  restore latency.
- **Bundle size is state + ~guest-RAM memory + a full root-disk copy.** Copying the whole disk per
  snapshot is the honest cost of a portable, read-write bundle; diff snapshots and base-sharing (memory-sharing
  over the pre-warmed pool) are the P5.3/P5.4/P5.7 optimizations.

**Pre-warmed snapshots + concurrent clones (P5.3/P5.4, 2026-07-12).** Extended to snapshot a
`read_only_root` VM carrying the vsock exec channel, and to restore many exec-ready clones from it:
- **The read-only base is referenced, not copied.** A `read_only_root` boot's disk is the shared
  pinned base at a persistent path, so the bundle records it in place (no per-VM copy) and restore
  opens it read-only; N clones share one base (page-cache-deduped memory-sharing) while each gets its own
  in-RAM overlay from its own restored memory image. The structural test is which side of the scratch
  dir the disk lives on. A read-write boot keeps the copy-and-stage path.
- **Concurrent clones needed a per-clone vsock socket, solved without the jailer.** A first probe
  confirmed empirically that clones restored concurrently **collide** on the socket path baked into the
  snapshot (`Address in use`), because Firecracker re-binds the vsock listener at the recorded path on
  load. Fix: bind vsock at a **relative** name (`v.sock`) and run each VMM with its scratch dir as
  **cwd**, so the recorded relative path resolves per-clone. This is lighter than the Phase-6 jailer's
  per-VM mount namespace and doesn't block the pre-warmed pool on it. Consequence: every *file* path handed
  to Firecracker must now be **absolute** (its cwd is no longer the driver's), a small resolve-to-
  absolute pass on kernel/rootfs/bundle paths; the vsock path is the one deliberate exception.
- **Restore waits for exec-readiness.** A just-resumed guest agent needs a moment before its vsock
  listener is reachable again, so restore polls a connect until it succeeds (bounded by the deadline)
  before returning, its analogue of boot's userspace-marker wait. Restore of a pre-warmed agent VM measured
  ~8 ms vs ~300 ms cold boot, then the clone runs code.
- **Still deferred:** a snapshot with an **input or output device** is a typed error (per-clone
  images a restore can't yet recreate). A **NIC** is no longer deferred: decision 011 restores
  networked clones with a fresh identity. `ci-privileged` now runs the VM tests serially (they boot
  real microVMs and some assert on host-global leak state).
- **Jailed restore stages the bundle into the chroot** *(2026-07-14, P7.0e)*: with `BootConfig.jail`
  set, the clone spawns under the jailer and this decision's staging happens chroot-relative — the
  state file copied in, the memory file and a shared base disk **bind-mounted read-only** (clones
  keep sharing one page cache), a private disk copy staged at the baked-in path resolved inside the
  chroot and unstaged once the VMM holds the fd. **Snapshotting a jailed VM is refused**, deliberately,
  not just deferred: its disk lives at a chroot-relative path inside a torn-down-with-the-VM chroot,
  so a bundle would record an unrestorable backing — and the clone story doesn't need it. Snapshot an
  *unjailed* pre-warmed source (it runs only the embedder's warm-up), restore **jailed** clones from it:
  the untrusted code runs confined, and the confined pre-warmed `Pool` falls out of the same approach.

### 011 — Restore identity: the agent re-addresses the clone; VMGenID reseeds it *(2026-07-12)*

**Problem.** Restore hands every clone a byte-identical copy of one guest memory image, so anything
that must be unique per VM but was frozen into that image is now shared: the guest's **network
identity** (IP/MAC/routes), its **RNG state**, and its **clocks**. Network identity is the
load-bearing one here because Phase 4 addresses the guest via the kernel `ip=` parameter (decision
009), which runs exactly once, before userspace, at the *source's* boot; it cannot re-fire on
restore, so a clone wakes still holding the snapshot's baked-in address on a link it no longer
matches.

**Decision (network): keep `ip=` for cold boot; the guest agent applies a fresh identity on restore.**
- **Cold boot is unchanged.** `ip=` stays the cold-boot fast path: zero overhead, no rootfs change,
  and nothing about restore makes it worse at that job.
- **On restore of a networked snapshot**, the driver recreates the snapshot's recorded tap (see the
  v1.9 constraint below), assigns its host end a **fresh /30** from the same allocator cold boot uses,
  and then the **guest agent replaces the baked-in `eth0` address** with the new one, one
  `sh -c "ip addr flush … && ip addr add <fresh>/30 …"` over the vsock exec channel, after the
  exec-readiness poll. This is the runtime counterpart of boot-time `ip=`: same address shape, same
  **empty-gateway invariant** (`ip addr add` installs only the connected /30 route, so deny-by-default
  (decision 008) holds for clones exactly as for cold boots, proven by the off-subnet check in
  `restored_networked_clone_gets_a_fresh_identity`).
- **Core-property check:** this puts network *configuration* in the guest agent, acceptable because the agent
  is exec/IO convenience (core property 2) and enforcement never moves in-guest: policy stays host-side (the
  route shape today, eBPF at the tap from Phase 11). A guest that tampers with its own address gains
  nothing: the host end of the /30 and the tap it enforces on are outside its reach.
- **MAC is deliberately not changed.** The clone keeps the snapshot's MAC; each clone sits on its own
  point-to-point tap (a separate L2 segment), so MAC uniqueness across taps is irrelevant, and on
  v1.9 only one networked clone can be live at a time anyway.
- A **networked snapshot without vsock is refused** (typed): there would be no channel to re-address
  its clone, which would otherwise wake permanently mis-addressed.

**The v1.9 constraint (probed, not assumed).** `PUT /snapshot/load` on the pinned Firecracker v1.9
rejects `network_overrides` ("unknown field", probed against the real binary), so the snapshot's
recorded `host_dev_name` is fixed: restore must present a tap with **exactly that name**. Consequence at
the time: **only one networked clone can be live at a time** on v1.9. ***(Resolved: decision 017 (P7.0c)
gives each clone its own network namespace, so all recreate the same baked-in tap name without colliding
— concurrent networked clones now run, and `Tap::create_named` + the in-guest re-addressing below are
deleted.)*** Concurrent networked clones needed either a Firecracker with `network_overrides` (a
deliberate version bump) or per-VM network namespaces (the Phase-6 jailer), deferred to whichever lands
first — the netns route landed. Non-networked pre-warmed clones keep their unbounded concurrency (P5.4).

**Decision (entropy): rely on VMGenID, and prove it.** Both halves are already in the pinned stack:
Firecracker v1.9 ships the VMGenID device and bumps the generation on snapshot restore, and the
pinned 6.1.102 guest kernel carries the `vmgenid` driver (present in 5.18+), which reseeds the kernel
CRNG on a generation bump. `restored_clones_do_not_share_entropy_or_freeze_the_clock` proves it end
to end: two clones restored from one snapshot draw 16 bytes from `getrandom` immediately after
restore, the dangerous window, before any natural interrupt-entropy reseed, and the draws differ.
No engine mechanism was added because none is needed; if a future kernel/VMM pin loses either half,
that test fails and the gap is visible, not silent.

**Decision (clocks): document the staleness; don't fix it up.** kvm-clock keeps the monotonic clock
sane across restore, but the guest's **wall clock lags by the snapshot's age** (measured: a clone
restored ~9 s after its snapshot reports a wall clock ~9 s behind the host). The engine does not
reach into the guest to set the time: a fix-up belongs to the workload or a later phase's explicit
mechanism (and the audit log timestamps host-side, so the audit trail never depends on guest
clocks). Recorded as a documented limitation the pre-warmed-pool docs must carry: code that trusts guest
wall-clock time (TLS validity windows, token expiry) can misbehave in a clone until it resyncs.

**Alternatives considered (network).**
- **MMDS (Firecracker's metadata service) + in-guest fetch.** Cloud-init-style: bake a fetch-and-apply
  step into the rootfs, host writes per-clone metadata. Rejected: a second in-guest config surface and
  a rootfs change, to deliver exactly what the existing exec channel already delivers with one
  command; MMDS earns its keep only when clones need richer metadata than an address.
- **A tiny DHCP server per tap.** Rejected: a persistent host-side daemon per VM (or a shared one
  with per-tap scoping) is a heavy, stateful addition for a two-address /30 whose contents the driver
  already knows; and the guest would need a DHCP client re-trigger on restore anyway, the same
  "poke the guest after resume" shape as the agent path, plus a daemon.
- **Reuse the source's /30 for the clone.** Rejected: only ever works for a single sequential clone,
  couples the clone's identity to the source's lifetime, and silently breaks the moment two clones
  overlap; a fresh /30 keeps the isolation story uniform with cold boots.

**Consequences and notes.**
- `Snapshot` records the tap name; `Tap::create_named` reserves a fixed name with a fresh /30
  (`ip addr add` remains the /30's atomic reservation, as in decision 009).
- The **guest `ip` tool is now load-bearing for restore** (busybox `ip` in the agent rootfs); a future
  rootfs slimming that drops it would break networked restore; the typed error from the identity
  step names the guest's stderr, so the failure is legible.
- **Decision 009 addendum:** boot-time `ip=` is cold-boot-only by nature; restore identity is this
  decision's runtime path. If that runtime path ever proves cleaner for cold boot too, unify then,
  with evidence, not speculatively.

### 012 — Confine the VMM: run Firecracker under its jailer *(2026-07-14)*

**Problem.** Hardware isolation (KVM) contains the *guest*, but the *VMM process* still runs on the
host with the driver's privileges. A Firecracker bug, or a guest that breaks out into the VMM, would
land in that context. The jailer is the host-side confinement: a chroot, a uid/gid drop, and a mount
namespace around Firecracker.

**Decision.** An **opt-in** [`BootConfig::jail`] runs Firecracker under Firecracker's `jailer` for a
plain read-write cold boot. Opt-in, not the new default, because the whole FC track was built
unjailed and every existing path (memory-sharing's shared read-only base, snapshot bundles, the pre-warmed pool,
the tap, bulk I/O) needs chroot-relative staging or a netns that later Phase-6 boxes add. This box
lands the mechanism on the simplest boot; the rest migrates behind it.
- **Chroot inside the scratch dir.** `--chroot-base-dir` is the VM's own `/tmp/agent-<pid>-<n>`
  scratch dir, so the jail is `<scratch>/firecracker/<id>/root/` and teardown's `remove_dir_all`
  reclaims the whole thing — no `/srv/jailer` residue. The jailer builds the chroot, `mknod`s the
  device nodes, places the process in a cgroup, `chroot`s, drops to the configured uid/gid, and
  `exec`s Firecracker (same pid, so the driver's `Child` is Firecracker and kill/reap are unchanged).
- **Stage resources after the socket is up, name them chroot-relative.** Firecracker opens the
  kernel and rootfs only on `PUT /boot-source` / `PUT /drives`, *after* the driver connects to the
  API socket — which only exists once the jailer has finished building the chroot. So the driver
  stages the kernel (`/kernel`, `0444`) and a read-write rootfs copy (`/rootfs.ext4`, `0600`) into
  the chroot at that point, `chown`ed to the jailed uid so the dropped-privilege VMM can open them,
  and names them by their chroot-relative path in the API. Staging-after-socket needs no hook into
  the jailer and never races its chroot construction (the mirror of how the vsock socket is dialed
  only after Firecracker binds it, decision 010).
- **Console survives.** The jailer is run **without `--daemonize`**, so Firecracker keeps the driver's
  piped stdout and the guest serial console still reaches [`crate::console`] — the coupling the old
  module doc feared the jailer would break is preserved by choice.
- **cgroup is read, not assumed.** The jailer always creates the microVM's cgroup (there is no
  opt-out); on this cgroup-v2-only host it is passed `--cgroup-version 2` (the v1 default would fail
  to find the hierarchy). The exact cgroup dir is learned from `/proc/<pid>/cgroup` once the VMM is up
  (version-independent, no guess about the jailer's parent-cgroup layout) and removed (best-effort) on
  teardown, since it lives outside the scratch dir — like the tap. cgroup *limits* are P6.2.
- **Needs real root; refuses half-confinement.** The jailer's `mknod` of device nodes is `EPERM` in a
  non-initial user namespace even with `CAP_MKNOD`, so a jailed boot needs real root — the
  `unshare -Urn --map-root-user` trick that carries the other privileged tests is not enough (the
  test gates on real root and skips otherwise; validated in a privileged container). Combining `jail`
  with vsock, a NIC, the overlay, or bulk I/O is a typed error (deny-by-default over a half-jailed VM),
  and snapshotting a jailed VM is refused (its disk lives in the chroot).

**Alternatives considered.**
- **Jail by default.** Rejected for this box: it would force every existing path chroot-relative at
  once (P6.1–P6.7 in one change) and break the 23 unjailed privileged tests / the `unshare` dev flow.
  The additive `#[non_exhaustive]` knob is the same discipline every prior phase used
  (`read_only_root`, `enable_network`, …).
- **Hardlink / bind-mount resources instead of copying.** Hardlink `EXDEV`s across the `/tmp` (tmpfs)
  boundary; bind-mounting into the chroot wants the jailer's mount namespace we don't drive. Copying is
  the honest P6.1 cost; zero-copy staging of a shared read-only base rides with the overlay-under-jailer
  step, alongside snapshot memory-sharing.
- **`--daemonize`.** Rejected: it redirects stdio to `/dev/null`, which would sever the serial console
  the boot-readiness wait depends on.

**Consequences and notes.**
- **A jailed cold boot copies the kernel and rootfs into the chroot per VM** (measured ~4 s for a
  jailed plain-rootfs boot in a privileged container). Sharing-preserving staging (shared RO base) and
  jailed **snapshot/restore/pool**, **vsock/exec**, **networking**, and **bulk I/O** are later Phase-6
  steps behind this knob.
- **cgroup lifecycle is best-effort here.** Teardown reaps the VMM's (now-empty) cgroup; leak-proof,
  cgroup-**owned** lifetime (host-process death can't leak a VM) is **P6.7**, resource *limits* are
  **P6.2**, and Firecracker's seccomp filters are **P6.3**.
- **The jailer's netns is the sanctioned path to concurrent networked clones** (decisions 009/011's
  note): once networking is jailed, each VM's tap in its own netns removes the one-live-networked-
  clone limit. Kept on the Phase-6 radar.
- **`BootConfig` gained a public field**, but it is not one of the API-pinned types (`Sandbox`,
  `Limits`, `RunResult`, `VmmError`, the channel wire), and the jailer path is opt-in, so no downstream
  pin bump is forced.

**cgroup limits + seccomp (P6.2/P6.3 addendum, 2026-07-14).** The jailer already gives each VMM its
own cgroup; these two boxes fill it in.
- **CPU/memory limits via the jailer's `--cgroup`.** The driver derives the cap from the guest's own
  envelope: `cpu.max = <vcpus × 100000> 100000` (exactly `vcpus` cores) and `memory.max =
  (mem_mib + 128 MiB)` bytes. The 128 MiB overhead is the VMM's host-side footprint above guest RAM;
  guest RAM is the hard floor a full-guest workload needs, and the rootfs page cache above it is
  reclaimable, so the cap bounds a runaway without OOM-killing a normal boot (a 256 MiB guest was
  measured peaking ~82 MiB). **Delegation is required and gracefully optional:** the jailer sets
  limits by enabling controllers down from the cgroup v2 root, which only works when `cpu`+`memory`
  are already in the root's `subtree_control` and the root has no internal processes (a systemd host;
  a bare container fails the `subtree_control` write with `EBUSY`). So the driver probes
  `cgroup.subtree_control` first: if the controllers aren't delegated it logs a warning and passes no
  `--cgroup` (the jailed boot still runs, unlimited) rather than letting the jailer fail. `xtask setup`
  reports whether they're delegated. Enforcement *under load* (a mem-hog/fork-bomb actually bounded)
  is P6.4; the configurable policy shape is P6.5.
- **Seccomp is on by default; we just don't disable it.** Firecracker installs its built-in per-thread
  filters (advanced level: an allowlist per API/VMM/vCPU thread, `SIGSYS` on violation) at
  `InstanceStart`. We never pass `--no-seccomp`, so every boot is filtered. Verified by probing
  `/proc/<pid>/task/*/status`: pre-boot the process shows `Seccomp: 0`, but a running VM shows
  `Seccomp: 2` on every thread. This is why the jailer test asserts `Seccomp: 2` on the running VMM.
- **Guest-side process-tree reaping (P6.4, the P2.6 fix).** Separate from the host jailer cgroup: the
  *guest agent* now runs each command in its own **guest** cgroup (a `cgroup2` mount added to the
  rootfs init) and reaps the whole tree with `cgroup.kill` after the command exits or times out.
  cgroup membership is inherited by every fork and can't be escaped by `setsid`, so a double-forked
  grandchild or daemon that inherited the output pipe is killed rather than left holding it open (which
  used to wedge the agent's exec connection, since the pumps never saw EOF). Chosen over `killpg`
  precisely because a `setsid` daemon escapes the process group but not the cgroup; and it needs no
  controller delegation (no limits, just `cgroup.kill`), so it works even though the guest root cgroup
  holds processes. Best-effort: a guest without cgroup v2 falls back to the old direct-child kill.
  **Enrollment is child-side, via a trampoline (P6.8 hardening).** The first cut wrote the child's pid
  to `cgroup.procs` from the *agent* right after `spawn` — which **races the child's own forks**: on a
  1-vCPU guest the child usually runs first, so anything it forked before the write landed (a daemon,
  a fork storm's spinners) escaped the cgroup, survived `cgroup.kill`, and wedged the connection
  anyway. P6.8's fork-storm test caught this (the P6.4 daemon test had been winning the race). The fix
  is a tiny `sh` trampoline: the agent spawns `sh -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"'`,
  so the child **enrolls itself and only then `exec`s the real command** (same pid — wait/kill are
  untouched; argv is passed as real argv, never interpolated). Enrollment now strictly precedes the
  first instruction of the command, so the race cannot exist. The agent pre-resolves the program
  (`execvp`-style) so "no such binary" still reports as the typed `GuestExec` error rather than the
  trampoline's shell-style 127.
- **Alternatives considered.** Writing the cgroup limits ourselves (instead of `--cgroup`) was
  rejected: it would re-implement the jailer's controller-delegation dance for no gain and the same
  delegation dependency. A custom seccomp filter (`--seccomp-filter`) was rejected: Firecracker's
  built-in advanced filters are the maintained, audited default; a bespoke filter is only worth it to
  *tighten* beyond them, which nothing here needs.

**Isolation verified, not assumed (P6.6 addendum, 2026-07-14).** The jail is only worth what's actually
in force on the running VMM, so `boots_under_the_jailer` reads the live `/proc/<pid>` and asserts each
wall independently: the VMM is **chrooted** (its root's `(st_dev, st_ino)` via `/proc/<pid>/root/`
differs from the host root's — the link *text* renders as `/` after the jailer's pivot_root, so
identity, not path, is what's checked), runs as the **dropped uid** (not root), holds **no effective capabilities** (`CapEff` all
zeros, cleared by the setuid off root), runs under **`no_new_privs`** (so no setuid binary regains
privilege) and **seccomp filter mode**, and lives in its **own mount namespace** and **cgroup**. Layered
with KVM this is the second wall: a guest that breached hardware isolation into the VMM would land in
that box, able to name no host path, hold no capability, and make no syscall outside the filter. The
**deny-by-default** complement is verified host-safe: `Vm::boot` **refuses** `jail` combined with any
not-yet-jailed feature (a NIC, the overlay, bulk I/O) with a typed error before it probes for
KVM, so there is no half-confined escape hatch (a `jail_refuses_half_confined_boots` unit test in the
everyday gate; decision 013's "the isolation boundary never half-degrades"). Running a *hostile workload
inside* a jailed guest waited on exec-under-jail, since landed (P7.0a composed the jail with the vsock
exec channel), so P6.6's bar was the VMM-side confinement layers plus the refusal, not an in-guest exploit.

### 013 — Per-run resource policy: one `Limits` struct of quantities, enforced at the host cgroup, failing open *(2026-07-14)*

**Problem.** P6.1–P6.4 gave each VMM a cgroup with `cpu.max`/`memory.max` and a boot deadline, but
the knobs are scattered: [`Limits`] `{ vcpus, mem_mib, wall }` rides the boot path while a fixed
`DEFAULT_EXEC_TIMEOUT` and `MAX_EXEC_OUTPUT` sit buried in exec. P7.3 will surface "per-sandbox limits
as **one options struct**"; this decision fixes the *shape* that struct commits to, so P7.3 is wiring,
not design.

**Decision.** The per-run resource policy is the one already-public, API-pinned, `#[non_exhaustive]`
struct [`Limits`], carrying **resource quantities**, never mechanism. Its knobs:
- **`vcpus: u32`** sets the guest's vCPU count *and* the host cgroup `cpu.max` (exactly `vcpus` cores:
  `vcpus × 100000` per 100000us period). One number caps both what the guest sees and what the VMM may
  burn.
- **`mem_mib: u32`** sets guest RAM *and* `memory.max = (mem_mib + 128 MiB)` (the measured host-side VMM
  overhead above guest RAM), so the guest is never handed RAM its own cgroup would then OOM.
- **`wall: Duration`** is today the boot-to-userspace deadline; **P7.3 extends it to the exec wall-clock
  budget** (the internal `DEFAULT_EXEC_TIMEOUT` becomes settable) so one `wall` means the whole run, not
  just boot.
- the **exec output cap** (today the fixed `MAX_EXEC_OUTPUT`, already surfaced on the wire as
  `OutputCap { limit }`) becomes the fourth knob in P7.3.

Two things it deliberately is **not**:
- **Not network policy.** The "net policy" in P7.3's phrasing is a *capability* (deny-by-default egress,
  decision 008), not a numeric budget: it stays a separate boolean / eBPF-enforced concern and does not
  become a `Limits` field. Quantities here, capabilities there.
- **Not per-exec.** The policy binds at the **host VMM cgroup** (per-VM, created by the jailer), the
  single choke point that caps the whole guest + VMM together. The guest-side per-exec cgroup (P6.4) is
  a *reaping* mechanism (`cgroup.kill`), not a second policy surface: it sets no limits.

**Degradation is fail-open, and recorded.** The cgroup caps need the v2 `cpu`+`memory` controllers
delegated to the root; where they aren't (a bare container), the driver logs a warning and boots
**without** limits rather than refusing. This is the one place the engine fails *open*, and it is
deliberate: resource caps are DoS / fairness mitigation, not the isolation boundary. The isolation
boundary (KVM, and the jailer's chroot + uid-drop + seccomp) **never** degrades: a jail that can't be
built is a hard error, never a quiet half-confinement (the `Vm::boot` refusal of jail + vsock/NIC/
overlay/bulk-I/O, verified host-safe in P6.6). A strict embedder wanting "no limits ⇒ no boot" is a
future `require_limits`-style toggle, deferred here, not built.

**Defaults are a load-bearing floor.** `Limits::default()` (1 vCPU, 256 MiB, 30 s) is conservative on
purpose: an embedder pinning this crate relies on a default run staying small. **Raising** a default (or
the fixed output cap) hands every default run more resource and is a breaking, `api:`-marked change;
**lowering** one, or adding a field (the struct is `#[non_exhaustive]`), is safe.

**Alternatives considered.**
- **A separate `ResourcePolicy` type distinct from `Limits`.** Rejected: `Limits` already *is* the
  per-run budget the public API pins and embedders read; a parallel type would split one concept in two and
  force a second public API surface. Grow the one struct.
- **Fold network egress into the same struct.** Rejected: a quantity struct that also carries a
  capability flag invites "set `mem_mib` and `net` in one call" ergonomics that blur the deny-by-default
  line; egress is enforced in a different layer (eBPF), on a different schedule (Phase 11).
- **Fail closed on missing delegation.** Rejected as the *default* (a self-hoster on a bare container
  could then never boot), kept as the future opt-in above for embedders who would rather refuse than run
  uncapped.

**Consequences.** P7.3 becomes wiring, not design: add the exec-wall and output-cap knobs to `Limits`,
thread them to the existing `DEFAULT_EXEC_TIMEOUT` / `MAX_EXEC_OUTPUT` sites, and keep today's timeout
semantics (cooperative `ExecTimeout`, `ExecUnresponsive` as the liveness backstop). No new type, no new
enforcement point. The `require_limits` strict toggle and any per-knob validation ride P7.3.
**Done** *(2026-07-15, P7.3)*: `wall` extended to the exec budget (`with_limits` folds it into both
the boot deadline and each exec's budget; `BootConfig` keeps a `boot_timeout`/`exec_wall` split
beneath the public API), `output_cap` added as the fourth knob, defaults unchanged (30 s / 16 MiB), the
whole timeout ladder (socket idle, guest kill, host backstop) derived from the configured value.
`require_limits` was **not** built: no embedder has asked to fail closed yet, so its note stands.

**`pids.max` added as host-side defense in depth** *(2026-07-16, P15.7)*: the per-VM cgroup now also
sets `pids.max` (a fixed 1024, gated on the `pids` controller being delegated, warning + skipping if
not — fail-open *per controller*, so a host with cpu/memory but not pids keeps those caps). It is
**not** a `Limits` knob and does not touch the public API: a guest fork-bomb is already bounded by
`memory.max` and lives in the guest's own kernel (P6.8), so this only caps the narrow case of a
hypervisor-level exploit forking *host* processes. The arg builder was made pure (`cgroup_args_for`)
so the per-controller fail-open is host-gate unit-tested; the remaining IO-bandwidth leg is P15.7.

### 014 — Cgroup-owned VM lifetime: a sentinel that outlives the driver, and a file-based kill handle *(2026-07-14)*

**Problem.** Teardown was `Drop`-based: correct on every path the driver survives, but a `SIGKILL`ed,
OOM-killed, or Ctrl-C'd driver never runs `Drop`, and its Firecracker children lived on as orphans
holding KVM memory. No in-process fix exists (a signal handler can't catch `SIGKILL`, and would only
paper over `SIGINT`). Separately, an embedder blocked in `exec` (`&self`) had no way to force a wedged
run down: `shutdown` consumes `self`, which the blocked call still borrows.

**Decision.** Crash-only design: the VM's lifetime is owned by things that survive the driver's death,
all built from the cgroup the VM already has.
- **A per-VM lifetime cgroup.** Every directly-spawned VMM is enrolled (via `cgroup.procs`) in a fresh
  child of the *driver's own* cgroup — the one place an unprivileged process is guaranteed write access
  when anything is (its delegated systemd session scope; the same no-controllers trick as the guest
  agent's exec cgroups, decision 012 addendum, so no delegation needed and no internal-process rule).
  The cgroup gives the whole VMM one kernel handle: `cgroup.kill` SIGKILLs every member atomically, no
  pid races. A **jailed** VMM is *not* enrolled — the jailer moves it into its own cgroup, and a second
  `cgroup.procs` write would race that placement (last write wins membership and could yank the VMM out
  of its limits); instead the driver precomputes the jailer's cgroup path (`<root>/<exec-name>/<id>`,
  stable because the jailer requires the exec name to contain "firecracker") and cross-checks it against
  `/proc` after boot, warning on a mismatch.
- **A sentinel that outlives the driver.** A tiny `sh` child per VM, in its **own process group** (a
  terminal Ctrl-C signals the driver's group; the sentinel must survive it to act), blocks reading a
  pipe whose write end only the driver holds. The kernel closes that write end on *any* driver death —
  clean exit, `SIGKILL`, OOM — so EOF **is** the death notification: no polling, no daemon, no signals.
  The sentinel then writes `cgroup.kill` on the VM's cgroup(s) and removes them (bounded retries). On a
  clean teardown the dirs are already gone when its EOF arrives, and it exits without acting; teardown
  reaps it with a bounded wait (a wedged sentinel is killed, never waited on forever).
- **A [`KillHandle`]** (public, cheap `Clone`, `Send + Sync`): kills through the same `cgroup.kill`
  file — which is why it needs no reference to the `Child` and no `unsafe` — so any thread can force a
  VM down; the blocked `exec` returns a typed error when the vsock peer closes. Where no cgroup exists
  it falls back to signalling the pid (safe while the VM is unreaped; a `torn_down` flag set *before*
  the reap makes late kills no-ops, so a recycled pid is never signalled). Surfaced on `RunningVm` now,
  on `Sandbox` in P7.

**Alternatives considered.**
- **`PR_SET_PDEATHSIG` on the child.** The classic answer, rejected: it needs a `pre_exec` hook
  (`unsafe`, forbidden on the host path), and it is delivered on the death of the spawning *thread*, not
  the process (a dying spawner thread would kill a healthy driver's VM).
- **A janitor daemon / pid files.** Rejected: a daemon is platform territory (guardrail 4), and pid
  files race pid recycling. The sentinel is per-VM, ephemeral, and dies right after cleanup.
- **A signal handler.** Rejected as the mechanism (only papers over `SIGINT`; `SIGKILL`/OOM remain) —
  which is exactly why the roadmap deferred this box until the cgroup existed.
- **`kill(2)` from the handle.** Needs `unsafe` (or a libc shim); the cgroup file is the safe,
  aliasable kill switch the cgroup already gave us — the handle holds a path, not a process.

**Consequences and notes.**
- Proven by a real crash, not simulation: `driver_death_cannot_leak_a_vm` SIGKILLs a subprocess driver
  mid-run and watches the sentinel kill the VMM and remove its cgroup (~1 s). The sentinel's EOF
  mechanism and the kill handle's semantics are also unit-tested in the everyday host gate against
  stand-in directories (no VM, no privileges).
- The unprotected windows, stated honestly: spawn → enrollment (microseconds, unjailed) and spawn → the
  jailer's self-placement (milliseconds, jailed) — a driver killed inside them leaks that one VMM, as
  before. A host with no writable cgroup v2 degrades to `Drop`-only teardown with a warning (fail-open,
  decision 013: this is leak-proofing, not the isolation boundary).
- The sentinel owns the VM *process tree* and its cgroups; a crashed driver's scratch dirs and taps are
  inert residue (no CPU, no RAM, no KVM), left to the next boot's leak checks or a sweep — deliberately
  not the sentinel's job, to keep it too simple to be wrong.
- The host now needs `sh` at runtime (the sentinel, and the kill handle's pid fallback). Precedent: the
  driver already shells out to `ip` for taps.

### 015 — Jailed execution is the convergence target; the Sandbox surface jails by default *(2026-07-14)*

**Problem.** P6.1 landed the jailer on a plain read-write cold boot, and decisions 012/013 make a
jailed boot **refuse** vsock, a NIC, the overlay, and bulk I/O with a typed error. So the confinement
Phase 6 proves (chroot, uid/gid drop, seccomp, no effective caps, `no_new_privs`, cgroup) applies only
to a VM that **cannot run code**: the exec channel (vsock) and the jail are mutually exclusive today.
You get either a code channel (unjailed) or VMM confinement (codeless), never both in one run. Every
P6.x box is checked, so the migration that unifies them ("exec under the jailer") is tracked only in
prose annotations (ROADMAP P6.6/P6.8) with no box or decision owning it. Left there it can quietly
evaporate, and worse, Phase 7 would build the public `Sandbox` lifecycle surface on the **unjailed**
exec path and then have to retrofit confinement under a frozen, pinned public API.

**Decision.** Jailed exec is a **Phase 7 prerequisite**, and the public surface jails by default.
- **Convergence lands as explicit boxes, not prose.** Staging the vsock UDS, the tap, the overlay, and
  the input/output devices chroot-relative and jailed-uid-owned (so the jail composes with the exec
  channel) is tracked as ROADMAP boxes at the Phase 7 head (P7.0a to P7.0e), sequenced **before** the
  `Sandbox` API is frozen, not as prose.
- **`Sandbox::exec` runs jailed.** The engine's headline "run untrusted code" path is the confined one:
  the `Sandbox` layer defaults `jail` on, with an explicit opt-out for the unjailed path the FC track
  was built on. This flag-polarity flip (jail becomes the default the public surface presents) is the
  hard-to-reverse bit recorded here.
- **The exec channel + cgroup is the non-negotiable minimum.** vsock (to run code) plus the host VMM
  cgroup (to bound it) must compose with the jail. A path that proves too costly to stage chroot-relative
  on the pinned Firecracker (a candidate: bulk I/O) may stay opt-in unjailed behind a recorded typed
  refusal, but exec-under-jail is not optional.
- **Until convergence lands, the mutual exclusion stays a typed error** (decision 012), never a silent
  half-jail.

**Alternatives considered.**
- **Leave it as prose annotations.** Rejected: an unchecked-but-real gap tracked only in prose is exactly
  the silent-omission failure this class of review flags. It evaporates, and Phase 7 inherits an unjailed
  default by accident rather than by decision.
- **Build Phase 7's `Sandbox` on the unjailed exec path and jail later.** Rejected: retrofitting
  confinement under a frozen public API (the API-pinned `Sandbox`) is the expensive, one-way-door
  version. Ordering the jailer into Phase 6 was meant precisely to have confinement in hand before the
  surface is drawn.
- **Make jailed exec its own full phase.** Rejected as over-scoped: it is a staging and ownership
  migration of paths that already exist (vsock, tap, overlay, drives), not new mechanism. A handful of
  boxes, not a phase.

**Why.** The engine's reason to exist is running untrusted code behind **both** walls: hardware
isolation (KVM) and host-side VMM confinement (the jailer). Demonstrating each wall alone (KVM in P1 to
P5, the jailer in P6 on a codeless boot) is real progress, but the product claim is the two **composed**,
on the path a real workload takes. Sequencing the convergence before the `Sandbox` API freeze keeps the
default run confined and avoids a retrofit under a pinned public API.

**Consequences and notes.**
- ROADMAP gains explicit convergence boxes (P7.0a to P7.0e); the P6.6/P6.8 annotations that say "a later
  migration" now point at those boxes instead of at prose.
- Phase 7's `Limits`/`Sandbox` work assumes the jailed exec path exists; `require_limits` (decision 013's
  note) and jailed-by-default land together as the confined default surface.
- Jailed snapshot/restore and the pre-warmed pool under the jailer remain downstream of exec under the jailer
  (a jailed VM's disk lives in the chroot, decision 010), tracked with the same boxes.
- **Status: the P7.0a-e convergence is complete.** `jail` composes with every boot feature and with
  restore. Vsock: the socket binds chroot-relative at `/run/v.sock` (`jailed_exec_runs_a_command`).
  Overlay: the shared base bind-mounts into the chroot (shared-base path, propagated into the jailer's
  `MS_SLAVE` mount namespace; `jailed_overlay_is_dense_and_base_is_untouched`). NIC: the tap lives in a
  per-VM netns the jailer joins via `--netns` (decision 017). Bulk I/O: the input/output images are
  built in place inside the chroot (`jailed_bulk_io_round_trips_through_the_chroot`) — with it, the
  mutual exclusion of the opening paragraph is fully retired and `Vm::boot`'s refusal block itself is
  gone. Restore: the bundle stages into the chroot (state copied; memory + shared base disk
  bind-mounted read-only), so pre-warmed clones and the `Pool` run confined
  (`restores_prewarmed_clones_under_the_jailer_and_pools_them`); snapshotting a *jailed* VM stays a typed
  refusal — snapshot an unjailed pre-warmed source, restore jailed clones (decision 010 consequence). The
  flag-polarity flip itself landed at P7.1: `Sandbox::open`/`Sandbox::boot` default `jail` on, and
  the opt-out is the differently-named `Sandbox::open_unjailed` constructor (mirrored by the CLI's
  `--unjailed`), so an unconfined sandbox is grep-visible in the caller's source, never a forgotten
  flag (`sandbox_opens_jailed_by_default`). **This decision is fully discharged.**
- The jailer's per-VM netns (decisions 009/011's note for concurrent networked clones) rides the
  jailed-networking box: once the tap is staged into the jail, its netns removes the one-live-networked-
  clone limit.

### 016 — The engine/hoster security line: the engine's tools can't be weaponized; deploying them is the hoster's *(2026-07-14)*

**Problem.** The orphan sweep (P6.9a, decision 014's GC) is the engine's first **privileged tool that
acts on a shared, world-writable surface**: it runs with `CAP_NET_ADMIN`/root and deletes host
interfaces + directories under the scratch base (`/tmp` by default). A design that decided what to
reclaim by the *name* of a dir or the *contents* of its tap-record file would let any local user plant
a dead-looking `agent-<pid>-<n>/` whose record names a **victim's live tap**, turning the hoster's
janitor into an unprivileged user's cross-tenant kill switch. This forced the general question the
project had only answered implicitly: where does the engine's responsibility end and the hoster's begin
when the host is shared and not everyone on it is trusted?

**Decision.** Draw the line by *category of guarantee*, and put each obligation on the side that can
actually hold it.
- **The engine guarantees its own privileged tools cannot be weaponized — unconditionally, like the
  isolation boundary.** Concretely for the sweep: it reclaims **only dirs owned by the calling euid**
  (`create_workdir`'s `0700` driver-owned dirs are the unforgeable authorship proof), hard-validates any
  tap-record before it can reach `ip link del`, keys liveness on the recorded **pid** not a resource
  name (names outlive and betray their makers — a restored clone's tap carries its dead source's token,
  decision 011), and **refuses to run** if it can't establish its own identity. This is an *authorship*
  check, not a *policy* check: the engine knows which residue it authored, and touching nothing else is a
  property of the tool, not a decision about who may run what.
- **The hoster owns deployment — as whom, when, over what, and how a shared resource is divided.** Four
  calls only they can make, so the engine **exposes and documents** them and builds none: (1) *schedule*
  the sweep (a self-refilling janitor daemon is Phase-16/platform, not the library); (2) run *one sweep
  per identity*, since it reclaims only the calling euid's residue (the direct, correct consequence of
  the anti-weaponization rule — a root sweep covering a user driver's dirs would *be* the hole);
  (3) *harden the scratch base* (point `AGENT_SCRATCH_DIR` at an engine-user-owned dir so no decoy can be
  planted at all); (4) *divide the finite `10.200/16` pool* across tenants (quota/fairness is carving a
  shared resource — the definition of the PaaS layer above the engine).

**Why.** The core properties already said "engine, not platform," but tenancy was framed as *features we don't
build* (auth, billing, scheduling). The sweep showed the subtler edge: a tool we **do** build and ship
with privilege must not become the lever that breaks a hoster's isolation *for* them, regardless of how
they arrange tenancy. So the rule isn't "we don't touch multi-tenant concerns" — it's "we guarantee our
privileged surface is safe at any privilege on any host; the hoster decides everything about how it's
deployed." That keeps the boundary on the host side (core properties 2/3) without the engine ever needing to
know who the tenants are.

**Alternatives considered.**
- **Make the sweep policy-aware** (a config of who-owns-what, allow/deny lists). Rejected: that is
  tenancy state inside the engine (guardrail 4), and it's strictly weaker than the euid check, which
  needs no configuration and can't be misconfigured into unsafety.
- **Have the engine harden the base itself** (refuse a world-writable scratch dir, or `chmod` it).
  Rejected as the *default*: `/tmp` is the zero-config dev default and the ownership check already makes
  a world-writable base safe (a decoy is rejected on ownership), so a hard refusal would break dev for a
  risk the engine already neutralizes. Surfaced as a hardening *recommendation* in `agent setup` instead.
- **A single privileged sweep that reclaims every uid's residue.** Rejected: it is exactly the
  weaponization the euid check exists to prevent (it would act on dirs it didn't author). The per-identity
  cost is the price of that safety, and it's the hoster's to absorb.

**Consequences and notes.**
- Surfaced where a self-hoster looks: `agent setup` prints a "Hardening — the hoster's responsibility"
  section (the four calls above), alongside the P6.9b degradation matrix; `sweep_orphans`' rustdoc
  carries the same four for an embedder.
- **This is a seed of P15.6, not its closure.** P15.6 records the *whole* security boundary (what's
  trusted: CPU/KVM/host kernel; what isn't: the guest) with the Phase-15 adversarial suite behind it;
  this entry records the one facet the sweep forced early, which the P15.5 threat model
  builds on. The box stays unchecked until Phase 15.
- The engine/hoster split now has a concrete precedent to reuse: any future privileged tool
  (a future `agent gc`, daemon-side reconcilers) inherits the same "authorship not policy, euid-scoped,
  refuse-without-identity" rule.

### 017 — Per-VM network namespace: the tap lives in the VM's netns, not the host's *(2026-07-14; supersedes the 009/011 netns notes)*

**Problem.** Two forces converged. (1) The jailer confines the VMM but a networked jailed boot needs its
tap reachable from *inside* the jail's isolation, and the jailer runs the VMM unprivileged — it can't
create or attach a host tap. (2) Decision 011's one-live-networked-clone limit: v1.9 has no
`network_overrides`, so restore must present a tap with the snapshot's **baked-in name**, which in a
single shared host netns can exist only once — so only one networked clone could ever be live. Both
decisions 009 and 011 deferred the same fix: **per-VM network namespaces**.

**Decision.** Every networked VM runs its tap in its **own network namespace**. The driver creates the
netns (`ip netns add <name>`, named after the VM's scratch dir), creates the tap inside it, and the VMM
joins it: the jailer via its `--netns` flag (it `setns`es as root before dropping privileges), a direct
boot via `ip netns exec <ns> firecracker …` (which `setns`es then execs, so the child pid *is*
firecracker). Teardown is one op: `ip netns del <name>` cascades the tap away.
- **Fixed identity, no allocator.** Because the tap is namespaced, every VM reuses the *same* fixed tap
  name (`fc0`), MAC, and `/30` (`10.200.0.1`/`.2`). The host-global name/MAC/subnet allocator, the
  `ip addr add`-as-/30-reservation retry (old decision 009), and `Tap::create_named` all go away.
- **The clone limit is retired.** N clones each recreate the baked-in `fc0` in their own netns; the
  baked-in guest address/MAC/routes are already correct there, so **restore no longer re-addresses the
  guest** (decision 011's `apply_guest_net_identity` is deleted) and a networked snapshot **no longer
  requires vsock** (that requirement existed only to carry the re-addressing).
- **Isolation is kernel-enforced.** Per-VM netns replaces P4.4's unique-/30-reservation with a stronger
  boundary: two VMs holding identically-named taps on the same `/30` share no path, because each is its
  own network stack. Deny-by-default is unchanged (empty `ip=` gateway → connected route only), and now
  the host's *own* netns can't reach the guest either — the driver only ever talks to it over vsock.
- **The jailed tap is uid-owned.** A jailed Firecracker holds no `CAP_NET_ADMIN`, so it can only attach
  a tap it owns; the driver creates the jailed VM's tap with `user`/`group` set to the jailed uid.

**The propagation fact this rests on (probed, not assumed).** The jailer runs the VMM in an `MS_SLAVE`
mount namespace; `ip netns exec` and `--netns` both `setns` into a netns the driver created in the host
netns. Verified locally: `ip netns` handles live at `/run/netns/<name>`, and two netns hold
identically-named taps on one `/30` without collision. The whole unjailed path (boot, restore, two
concurrent clones, the sweep) is proven end-to-end with real Firecracker VMs under `unshare -Urn`; the
jailer's `--netns` (real root) is proven by the `ci-privileged` gate.

**Alternatives considered.**
- **Keep the tap in the host netns, bridge per-VM with veth + unique /30s.** Rejected: reintroduces the
  host-global allocator and the clone-name collision, is weaker isolation (shared stack), and is more
  moving parts than one netns per VM.
- **Bump Firecracker for `network_overrides`.** Rejected as the sole fix: it addresses only the clone
  limit, not jailed networking or kernel-level isolation, and a version bump is its own decision (011).
- **Keep decision 011's re-addressing under netns.** Rejected: pointless work — the baked-in identity is
  already collision-free in a private netns, so re-addressing would flush and re-add the same address.

**Consequences and notes.**
- Resolves the netns notes in decisions **009** ("per-VM network-namespace isolation is deferred")
  and **011** ("only one networked clone can be live … per-VM network namespaces … deferred").
- The orphan sweep (P6.9a) now reclaims an orphaned **netns** (named after the dead dir) instead of an
  orphaned host tap; its `tap`-record file is gone (the netns name is derivable from the dir). The
  finite-`/16`-pool DoS the sweep guarded against is *eliminated* (every netns reuses one `/30`), so the
  sweep's network role is residue hygiene, not pool-exhaustion defence. `SweepReport.taps_reclaimed`
  became `netns_reclaimed`.
- `RunningVm` gains `netns()`; the Phase-8 eBPF loader must **enter the netns** to attach to the tap
  (`tap_name()` resolves inside it, not the host netns).
- Jailed snapshot/restore (P7.0e) inherits this: a jailed networked clone stages its netns the same way.

### 018 — Per-exec inputs (files + env) ride the exec channel under a pinned secret-hygiene contract *(2026-07-14)*

**Problem.** A real workload needs configuration and credentials in the guest: input files (landed
P2.5) and environment variables (new at P7.1). Env could ride several paths — baked into the rootfs,
written as a file the command sources, exported into the guest agent's own process, or carried
per-exec on the wire. And whatever carries secrets must *state* what the engine does with them:
logs, error renderings, and the serial console are host-observable surfaces an embedder will ship
into its own telemetry, so "we probably don't log it" is not a contract an SDK can be built on.

**Decision.**
- **Env is a per-exec field on `Request::Exec`** (wire protocol **v2**), applied by the guest agent
  to the **spawned command only** (`Command::env`, inherited across the cgroup trampoline's `exec`) —
  never `set_var` into the agent's own process, so one run's secrets cannot reach the agent or a
  later run on a long-lived (pre-warmed/pooled) VM. Bounded like `stdin`: the whole request is one
  `≤ MAX_PAYLOAD` frame.
- **The protocol version gates the skew.** Adding the field changes the `Exec` frame, and an old
  agent would parse the new frame and silently run the command *without* its env (the body cursor
  ignores trailing bytes). For secrets/config that silent degradation is a correctness failure, so
  `PROTOCOL_VERSION` bumped 1→2 and a stale rootfs is a typed handshake error, not a quiet
  half-configured run.
- **The secret-hygiene contract is pinned** (doc'd on `RunningVm::exec_with_files`, enforced by leak
  tests): injected file contents and env **values** never appear in an engine log line, in any
  `VmmError`'s `Display`/`Debug`, or on the serial console; an error path may name a file *path* or
  an env *key*, never a value (the guest agent logs only the env *count* — a bulk key dump is a
  fingerprinting surface). Host-side wire copies the engine builds are **zero-wiped after send** —
  the channel's serialized payload buffer and the driver's request clones — best-effort by
  declaration: the caller's own buffers and the kernel's socket buffers are out of the engine's
  reach. The run's own `RunResult` is the one surface allowed to carry input bytes (it is the
  caller's data). The audit log (P13) inherits the contract: it records *that* inputs were
  injected (paths/keys/sizes or hashes), never contents.

**Alternatives considered.**
- **Agent-process or rootfs-baked env.** Rejected: process-level env outlives the exec (a pooled
  clone would hand run A's secrets to run B), and image-baked env makes secrets build-time state.
- **Env as an injected file the command sources.** Rejected as the default: it forces a shell
  wrapper, parks secrets on the run's filesystem for its whole lifetime, and needs the same hygiene
  contract anyway. (An embedder who wants it can still do it with `PutFile`.)
- **Appending env without a version bump** (an old agent tolerates trailing bytes). Rejected: that
  tolerance is exactly the silent-degradation path — the command runs without its env and nobody is
  told. The handshake exists to make skew loud.
- **A zeroizing-buffer crate.** Rejected for now: `fill(0)` at the two sites the engine owns covers
  the promise as stated; a compiler-elision-proof `zeroize` can be revisited if the public API ever
  carries higher-assurance requirements.

**Why.** The public API is embedder-driven: every SDK-shaped caller passes files + env, and the engine's
observable surfaces are precisely where a hoster's log pipeline would exfiltrate a leaked value.
Making non-leakage a *tested contract* — a sentinel grepped out of every surface, with a positive
control proving the console capture is real — is what lets a downstream pin this crate and pass
production credentials through it.

**Consequences and notes.**
- `Sandbox` is the lifecycle surface (`open → exec_with_files → collect_outputs → snapshot →
  shutdown`, plus `kill_handle`/`vmm_pid`), jailed by default per decision 015; an embedder never
  reaches `RunningVm`.
- The leak tests are the contract's pin: `injected_secrets_reach_no_observable_surface` (no VM —
  host logs at TRACE, the real in-process agent's logs, every error rendering) and
  `injected_secrets_never_reach_the_console_or_host_logs` (real VM — console, host logs, the
  failing-injection error path). A new log line or error variant that touches exec inputs must keep
  values out; extending these tests is the review bar.
- `stdin` is deliberately *outside* the contract's never-log set today (nothing logs it either, but
  only file contents and env values are promised); widening the promise to stdin is a doc-plus-test
  change, not a design change.

### 019 — The VM is the session: one persistent in-guest working directory per agent process *(2026-07-15)*

**Problem.** A stateful session — install a package, write a file, use both three execs later — needs
somewhere for state to live and a rule for when it dies. The guest filesystem already persists for
the VM's lifetime (the overlay), but the agent gave every exec a **fresh, removed-afterwards working
directory**, so the most natural composition (`echo hi > x`, then `cat x`) broke at the layer users
touch first, and injected files evaporated after the exec they rode in on.

**Decision.** **Session identity is VM identity.** The in-VM agent serves every connection from one
persistent per-process working directory (`serve_session(stream, dir)`, called by the in-VM binary
with a single fixed dir for its whole life): injected files, written files, and artifacts all share
it across execs. No session ids, no session protocol messages, no per-session dirs inside one VM —
an embedder that wants two isolated sessions boots two VMs (which is exactly the isolation story the
engine sells; P7.8 tests it). State's lifetime is the VM's: teardown discards the overlay, so
nothing outlives the session, and a snapshot clone gets a copy-on-write view of the source's
accumulated state (N clones of one pre-warmed session diverge independently — that falls out of the
existing snapshot machinery, nothing new). The library-level `serve` keeps the fresh-dir one-shot
semantics: host-side unit tests run many serves in one process and must not share (or race on) a
dir; the session default is the *in-VM binary's* choice, where one process = one VM = one tenant.

**Alternatives considered.**
- **Per-exec fresh dirs, state only via absolute guest paths.** Rejected: it makes the obvious
  composition fail and forces every SDK to warn "your files vanish unless you `cd /somewhere`".
- **A session id in the protocol** (per-session dirs, host-managed lifecycle). Rejected: it invents
  a second session concept inside the one the VM already provides, adds protocol surface, and its
  isolation between sessions would be agent-enforced — the agent is exec/IO convenience, never a
  boundary (core property 2). Hardware-isolated sessions are VMs.
- **Reuse one connection for many execs** instead of one-command-per-connection. Rejected here:
  orthogonal transport churn; sessions are about *state*, not connection count.

**Why.** "The VM is the session" keeps the trust story unchanged (isolation between sessions is KVM,
not agent bookkeeping), costs zero new protocol, and gives the pre-warmed-pool path its natural meaning: a
pooled clone *is* a pre-warmed session.

**Consequences and notes.**
- P7.8's two-concurrent-sessions test is two VMs, by construction.
- A future "reset the session without rebooting" (wipe the dir) would be a new agent request type —
  additive (a new tag), not a redesign.
- The session dir lives on the overlay like everything else, so a `read_only_root` boot bounds
  session state by the overlay's size (`overlay_size` ≈ half guest RAM) — bulk data still belongs on
  the block-device paths.

### 020 — The eBPF loader: aya, an object loaded from a path, and links that drop with the loader *(2026-07-15)*

**Problem.** The eBPF track needs a shape for three things at once: what library builds and loads the
programs, how the compiled object reaches the loader, and who owns the in-kernel objects' lifetime.
Each has a wrong default that would leak into every later phase (P9 syscalls, P10/P11 tap, P12
cgroup). The object question is the sharp one: the idiomatic aya path (`aya-build` in a `build.rs`, or
`include_bytes_aligned!`) compiles the eBPF crate during a normal `cargo build`, which would drag
**nightly + `build-std` + `bpf-linker` into the everyday host gate** and break "the workspace is
stable and `cargo xtask ci` runs everywhere" (P8.1).

**Decision.** Three coupled choices:
- **aya, both sides.** `aya-ebpf` in `crates/probes` (in-kernel), `aya` (userspace, **sync** — no
  async runtime, matching the driver's no-background-threads posture) in `crates/probes-loader`. The
  loader's public shape is a typed handle (`ExecveCounter::{load, count}`) returning a typed
  `ProbeError`, the eBPF analogue of `VmmError` (no panic on the host path).
- **The object is a runtime-loaded build artifact, found by path.** `cargo xtask build-probes` builds
  it (separate nightly target); the loader reads the bytes at runtime from a path
  (`AGENT_PROBES_OBJECT` override, else the `build-probes` output). It is **not** linked into the
  loader binary (`include_bytes`) nor built by a `build.rs`, so the host workspace stays on stable and
  the CI gate stays runnable everywhere; the object is deployed alongside the guest kernel/rootfs.
- **Links drop with the loader; nothing is pinned.** The aya `Ebpf` owns the program, map, and
  attachment; its `Drop` detaches and frees them. Nothing is pinned into `/sys/fs/bpf`, so a crashed
  loader leaves no kernel residue — the eBPF analogue of the driver's no-leak teardown. Pinning stays
  opt-in, added only where a program must outlive its loader (not on the current path).

**Alternatives considered.**
- **`aya-build`/`include_bytes_aligned!` (the aya template default).** Rejected: it pulls the nightly
  eBPF build into every `cargo build`, breaking the stable-workspace / gate-everywhere split. The
  path-load costs a runtime file read and a deploy-time artifact, which the engine already has for the
  kernel/rootfs.
- **Pinning programs/maps into `/sys/fs/bpf` for a stable handle.** Rejected as the default: a pin
  outlives the process and is exactly the residue the no-leak guarantee forbids; it becomes opt-in only
  where lifetime genuinely must exceed the loader.
- **libbpf-rs instead of aya.** Rejected: aya is pure-Rust (no C toolchain / libbpf build), which fits
  the workspace's build story (nothing to vendor, stable-toolchain host path).

**Why.** The path-load is the one non-obvious call, and it is what preserves P8.1's stable-workspace
invariant while still giving the loader real bytes to load. aya + sync + typed errors + drop-owned
lifetime keeps the eBPF side isomorphic to the driver side (typed errors, no panic, no leak), so the
two halves of the engine share the same discipline.

**Consequences and notes.**
- Adding `aya` put `foldhash` (Zlib) in the tree; `deny.toml` gained `Zlib` deliberately, with a
  reason, when aya entered (the allowlist's stated policy).
- P10/P11 attach programs to real per-VM **taps** (in the driver's netns): the same drop-owned,
  no-pin lifetime must hold there, so a torn-down sandbox leaves no dangling `tc`/XDP filter — it
  composes with the netns teardown the driver already guards (decision 017).
- The `sys_enter_execve` counter is the host's footprint, not the guest's: a microVM services its own
  syscalls in-guest, so they never trap to these host tracepoints (the network + cgroup signals, not
  syscalls, are the strong cross-boundary ones — P10/P12).
- **BTF is a build requirement, not a default** (P8.5): the object carries BTF (the CO-RE portability
  path) only because the profile keeps `debug = true` *and* the target passes `bpf-linker`'s `--btf`
  link-arg — both off by default would ship a legacy-only, non-portable object. `build-probes` asserts
  the `.BTF` section is present so a regression fails the build, not a downstream kernel.

### 021 — Syscall observability: a ring buffer of per-event records, a shared POD type, and an in-kernel filter *(2026-07-15)*

**Problem.** Phase 8's counter answers "how many `execve`s"; Phase 9 needs "which syscall, by whom,
on what" — a **stream of per-event records** (pid, cgroup, `comm`, the opened path / connected
address), scoped to *one* sandbox's host workers, not the whole machine's. Three shapes have to be
chosen together: how events cross the kernel→userspace boundary, how the record type stays consistent
across that boundary, and where the "watch one sandbox" filter lives.

**Decision.** Three coupled choices, extending decision 020's loader:
- **A ring buffer (`BPF_MAP_TYPE_RINGBUF`), not a perf event array.** The three `sys_enter_*`
  tracepoint programs `output` a fixed-size record into one MPSC `EVENTS` ring buffer; the loader
  drains it with a single in-order consumer ([`SyscallTracer::drain`]). The ring buffer is the modern
  (5.8+) replacement for per-CPU perf buffers: one shared queue, ordered, no per-CPU reassembly. A
  full buffer drops new events (best-effort observability, never blocking a syscall). Draining is
  **non-blocking** (returns 0 when empty); an `epoll`-backed blocking wait is the P9.3 consumer's job.
- **The wire record is one shared, dependency-free POD crate.** `crates/probes-common` holds the
  `#[repr(C)]`, padding-free `SyscallEvent` (and its safe `from_bytes` reader), depended on by both
  the kernel writer (`crates/probes`) and the userspace reader (`crates/probes-loader`). Single-
  sourcing the layout is what prevents the classic FFI-struct drift: a field reordered on one side
  only would otherwise be a silent garbage read. `#![no_std]` + zero deps so it compiles unchanged for
  the BPF target; a `std` feature (loader-only) adds ergonomic helpers. The reader parses field by
  field with `from_ne_bytes` (same host, shared byte order) — no `unsafe`, no transmute, keeping the
  host path `unsafe`-free.
- **The filter is a two-slot `Array` map the loader writes, consulted in-kernel.** Slot 0 a target
  tgid, slot 1 a target cgroup id; `0` disables that axis, so the load-time default (a zeroed map)
  observes everything, and every allowance is explicit (deny-by-default's spirit for observation
  scope). Filtering **in the program** — dropping the event before it reaches the ring buffer — keeps
  the buffer and userspace uncluttered by other processes' syscalls.

**Alternatives considered.**
- **Perf event array (`PerfEventArray`).** Rejected: per-CPU buffers the consumer must poll and
  reassemble, the pre-5.8 pattern the ring buffer was designed to replace; no ordering, more userspace
  bookkeeping for no gain here.
- **Duplicate the event struct on each side (no shared crate).** Rejected: the two definitions drift
  silently, and the failure mode (misread fields) is data corruption, not a compile error — exactly
  what a shared POD crate makes impossible.
- **Filter in userspace after draining.** Rejected: it ships every process's events through the ring
  buffer and burns buffer space + read work on records that are immediately discarded; the kernel is
  where the cheap, early drop belongs.
- **Read the path with a field-offset CO-RE relocation.** Not needed yet: the syscall arg is at a
  stable tracepoint offset read with `read_at` + `bpf_probe_read_user_*`; genuine `vmlinux`-struct
  field reads (and their relocations) arrive when a later phase reads kernel structs.

**Why.** The ring buffer + shared-POD pair keeps the eBPF side isomorphic to the driver side
(typed, ordered, no silent corruption, no leak), and the in-kernel filter is what makes "watch one
sandbox" honest rather than a userspace afterthought. The `execve`/`openat`/`connect` set is the
smallest that shows all three record shapes (a program path, a file path, a socket address).

**Consequences and notes.**
- This is still the **host's** footprint, not the guest's (decision 020's honest limit stands): a
  microVM services its syscalls in-guest. The filter's cgroup axis is how P9.4 attributes events to a
  specific sandbox: `cgroup_id_of_pid` resolves a VMM pid to its cgroup id (the inode of the cgroup
  dir, which equals `bpf_get_current_cgroup_id`), and `watch_cgroup` scopes the trace to it. The bridge
  to the Firecracker track is plain `u32`/`u64` values, so `probes-loader` stays independent of `vmm`.
- `SyscallEvent` is an **internal** kernel↔loader contract, *not* the frozen public wire API (the
  `channel` protocol + audit-log format); it can change without an `api:` marker.
- The `detail` blob is bounded (128 bytes): long paths truncate, and a `connect` captures only the
  leading sockaddr bytes (a full IPv4 address; IPv6 partially) to avoid over-reading a short user
  buffer. Phase 9 is now complete: the streaming consumer (P9.3, a poll-with-sleep [`SyscallTracer::stream`]
  rather than the `epoll` wait sketched above, keeping the crate sync + `unsafe`-free), cgroup
  attribution (P9.4, `cgroup_id_of_pid`), the measured per-syscall overhead (`cargo xtask bench-trace`,
  P9.5), and the attributed-workload test (P9.6) all landed, with `cargo xtask trace-sandbox` (boot a
  real sandbox, stream its cgroup-attributed host footprint) as the exit-gate demo.

### 022 — Multi-tenant safety is airtight per-run isolation, proven by the containment suite *(2026-07-15)*

**Problem.** A hoster wants to place untrusted code from mutually-distrusting callers on one shared
host. The engine must make that safe **without ever learning about tenants**: no team / account /
tenant concept may enter this repo (that is the hoster's control plane). The open questions are what
the engine owes, and how "safe for multi-tenant hosting" is defined and proven.

**Decision.** Multi-tenant safety is **airtight per-run isolation, not tenant awareness.** The engine's
contract is "any run is fully contained from every other run and from the host"; the hoster decides
whose run is whose. The confinement stack that delivers it is already built and tenant-agnostic:
- **Jailer** — Firecracker runs under its jailer: chroot, uid/gid drop, PID/mount/network namespaces,
  seccomp (decision 012); the `Sandbox` surface jails by default (decision 015).
- **cgroups** — a per-VM v2 cgroup caps `cpu.max` + `memory.max` (decision 013), with a whole-tree
  `cgroup.kill` (decision 014). `pids.max` is now added too (host-side defense in depth: a guest
  fork-bomb is already memory-bounded, P6.8, but a hypervisor-level exploit forking *host* processes is
  capped). The last leg, bounding guest **IO bandwidth** so a disk-thrashing run can't starve a
  co-resident one, is P15.7 (Firecracker's per-drive rate limiter, or host `io.max`).
- **Network** — deny-by-default egress: a tap with no route to the world, allow-listed explicitly
  (decision 008).
- **No-leak teardown** — cgroup-owned VM lifetime + a sentinel that outlives the driver + the orphan
  sweep, so a killed / panicked / timed-out run releases its VMM, jail, cgroup, and scratch (decision
  014; P6.9a).
- **Engine/hoster line** — the engine's privileged tools can't be weaponized; deployment (scheduling,
  per-identity GC, base hardening, dividing the address pool) is the hoster's (decision 016).

**"Safe for multi-tenant hosting" is defined as exactly one thing: the containment suite is green**
(Phase 15). A single hostile guest tries to escape the VM, reach the network, exceed its cpu / mem /
pid / io caps, exhaust the host, and interfere with a co-resident run — and each attempt must fail. The
constituents already pass individually (P6.6 escape, P6.8 fork-bomb / mem-hog, P4.7 egress, P6.7 /
P6.9a no-leak); Phase 15 consolidates them and adds the co-resident-interference assertion (P15.8).

**The public contract is preserved.** No tenant field anywhere. `Sandbox::boot` / `exec` /
`exec_with_files`, `RunResult`, `VmmError` + `ErrorKind` (Infra / Transport / Guest), and `Limits` are
unchanged. The `pids.max` / `io.max` caps land as **internal, derived defaults**, not new `Limits`
knobs, so nothing breaks; surfacing them as fields later would be an additive, marked `api:` change.

**Why.** Per-run isolation is the whole leverage: it lets a hoster multiplex distrusting callers with
zero engine-side tenancy, keeping the engine embeddable and self-hostable — it works on a lone KVM host
with no cloud at all. Defining safety as "the suite is green" makes the gate objective and testable
rather than asserted.

**Alternatives considered.**
- **A tenant / team id in the engine (per-tenant cgroup trees, tenant-scoped policy).** Rejected: it
  moves the security boundary into a tenant concept the engine must never hold, and couples the engine
  to one hoster's control plane. Isolation is per *run*; the hoster maps runs to tenants.
- **Treat "microVM boundary only" as sufficient for multi-tenant.** Rejected: a Firecracker-level
  exploit, a resource storm, or a leaked VMM crosses to the host or a co-resident run. The jailer +
  cgroups + no-leak teardown are what make the microVM boundary trustworthy under a hostile guest.
- **Expose `pids`/`io` as `Limits` knobs now.** Deferred: a hard internal default contains the host
  without a public-API change; a caller-tunable knob can be added additively later if a real need
  appears.

### 023 — Network observation: `tc`/clsact on the tap, a per-flow 5-tuple map, observe-only *(2026-07-16)*

**Problem.** Phase 10 needs per-microVM network visibility: every packet a guest sends or receives,
counted at the host. Three shapes must be chosen together (as decisions 020/021 did for the loader and
the syscall record): the attach mechanism, the per-flow record the kernel writes and the loader reads,
and where the "watch one sandbox" scoping lives.

**Decision.** Three coupled choices, extending decision 020's loader.
- **`tc`/clsact, not XDP.** The guest's traffic crosses its tap on the host, so a `tc` classifier on the
  tap sees it. clsact is chosen because it gives one device **both** an ingress and an egress hook
  uniformly (`tap_ingress`/`tap_egress`), on any device and any BPF-capable kernel (no driver XDP
  support needed); generic XDP is RX/ingress-only, so it can't see egress-to-guest and would need `tc`
  for that half anyway. `tc` is also the natural home for Phase 11 enforcement (a denied flow returns
  `TC_ACT_SHOT`); P10 is **observe-only**, both hooks return `TC_ACT_OK`.
- **The record is a shared, dependency-free POD, read as raw bytes.** `crates/probes-common` gains
  `FlowKey` (the IPv4 5-tuple, host byte order, `#[repr(C)]` and padding-free with an explicit zeroed
  `_pad`, because it is a hash-map **key**: uninitialized padding would make two identical flows hash
  apart) and `FlowCounts` (per-direction packets + bytes), single-sourced across the kernel writer and
  the loader like `SyscallEvent`. The loader opens the map as raw `[u8; N]` key/value arrays and decodes
  them with `FlowKey::from_bytes`/`FlowCounts::from_bytes`, so it needs no `unsafe impl aya::Pod` and
  both crates keep `#![forbid(unsafe_code)]`. The header offsets are shared consts, and a pure
  `parse_ipv4_5tuple` (host-unit-tested) is mirrored in-kernel by `ctx.load` at those same offsets, so
  the two parsers can't drift.
- **Scoping is by interface, and (later) by netns.** P10.1/P10.2 attach by interface **name in the
  current netns**. Because a sandbox's tap lives in its **own** netns (decision 017), binding to the
  specific `fc0` for one sandbox means entering that netns — deferred to **P10.4**; the clean
  attach/detach on sandbox open/close is **P10.5**.

**Alternatives considered.**
- **XDP instead of `tc`.** Rejected: generic XDP is ingress-only and driver-dependent, so it can't
  count egress-to-guest and buys no portability over `tc` here; `tc`/clsact covers both directions on
  every device and is where enforcement will live.
- **A `PerCpuHashMap` for contention-free exact counts.** Deferred: the plain `HashMap` with a
  best-effort non-atomic read-modify-write matches `EXECVE_BY_PID` and is fine for observability; a
  per-CPU map is the accuracy upgrade if a later phase needs exactness.
- **Fold direction into the key** (`(flow, dir) -> {pkts, bytes}`). Rejected: rx/tx on the value is the
  more useful shape (one lookup gives a flow's both directions), and a directional 5-tuple already
  encodes its direction by which hook it crossed.
- **`unsafe impl aya::Pod` for `FlowKey`/`FlowCounts`** (so the loader could type the map directly).
  Rejected: it needs `unsafe` in one of the two `forbid(unsafe_code)` crates (the orphan rule forbids it
  in the loader); reading the map as `[u8; N]` and decoding with the shared `from_bytes` is unsafe-free
  and keeps the record single-sourced.

**Consequences and notes.**
- **IPv4 only for now.** A non-IPv4 (or truncated) frame is skipped, counted nowhere; IPv6 is a later,
  additive widening of `FlowKey` and the parser.
- **This is the guest's own traffic**, unlike the syscall tracepoints (decision 021's honest limit): a
  microVM's packets cross its tap on the host, so network is the strong cross-boundary signal core
  property 1 leaves intact.
- **No leaked filter.** The classifier links are drop-owned (decision 020, nothing pinned), and a
  sandbox's netns teardown (`ip netns del`, decision 017) cascades the tap, its clsact qdisc, and the
  filters away — so a torn-down sandbox leaves no dangling `tc` program even if the loader is gone.
- **`FlowKey`/`FlowCounts` are an internal kernel↔loader contract**, not the frozen public wire API, so
  they can change without an `api:` marker (like `SyscallEvent`).
- P10.3 (export the per-VM stats), P10.4 (bind to the sandbox's netns tap), P10.5 (attach/detach on
  open/close), and P10.6 (the live guest-traffic test) build on this; the exit gate is live per-microVM
  network visibility.

### 024 — Bind the tap monitor to a sandbox by entering its network namespace *(2026-07-16)*

**Problem.** P10.1/P10.2's `TapMonitor` attaches to an interface *in the current netns*, but a
sandbox's tap (`fc0`) lives inside that sandbox's **own** network namespace (decision 017). To bind the
monitor to one specific sandbox's traffic (P10.4), the loader must attach the `tc` programs to `fc0`
*inside* that netns — and aya resolves the interface and opens its netlink socket in the **calling
thread's** netns, so the attach has to run there. The driver's netns tooling (`ip netns exec`, the
jailer's `--netns`) all shells out or spawns a child, which can't hold a live, in-process eBPF
attachment the loader then reads a map from.

**Decision.** The loader **enters the sandbox's netns in-process for the attach only**, via `setns`.
- **Load in the host netns, attach in the sandbox's netns.** Creating the maps and loading/verifying
  the programs is namespace-independent (global fds), so it happens first, in the caller's netns. Only
  the netns-scoped step — adding the clsact qdisc and attaching the two classifiers — runs inside the
  sandbox's netns. Reading the flow map afterward is namespace-independent again (a map fd is not
  netns-scoped), so it happens back in the caller's netns.
- **Enter and restore on the *same thread*, always.** `TapMonitor::attach_in_netns(netns, iface)` opens
  the host netns handle (`/proc/self/ns/net`) and the target (`/run/netns/<netns>`, the driver's own
  `netns_path`), `setns`es the calling thread into the target, runs the attach, then `setns`es back —
  the restore runs even if the attach fails, so a failure never strands the thread. Only the calling
  thread moves (briefly); the rest of the process is unaffected.
- **`setns` via nix's *safe* wrapper.** `std` has no `setns`, so the loader takes a minimal `nix`
  dependency (`sched` feature only) whose `setns` is a safe function — the loader stays
  `#![forbid(unsafe_code)]`, no `unsafe` block of ours. This is the first in-process netns entry in the
  repo; the driver's shell-out model can't carry a live attachment, so it doesn't apply here.
- **Cleanup is netns teardown, not the loader's drop.** The in-kernel `tc` filter lives in the
  sandbox's netns; the sandbox's teardown (`ip netns del`, decision 017) cascades the tap, its clsact
  qdisc, and the filters away. So dropping the monitor frees only its userspace fds (the map, the
  programs), and a torn-down sandbox leaves no dangling filter even if the loader is gone — the same
  no-pin, no-leak model as decisions 020/023. (The loader's own drop-detach targets the caller's netns,
  where the filter isn't, so it is a harmless no-op; the netns is the real reclaimer.)

**Alternatives considered.**
- **`ip netns exec <ns> <helper>` that pins the program + map to bpffs**, with the main loader reading
  the pinned map. Rejected: it reintroduces **pinned residue** (against decision 020's no-pin default),
  needs an attach subcommand on the loader binary, and complicates teardown (unpin). `setns` keeps the
  drop-owned, no-pin lifetime.
- **Move the whole process (or a dedicated long-lived thread) into the netns.** Rejected: the process
  must keep reading the map and serving other sandboxes from the host netns; a per-monitor parked
  thread is more machinery than a scoped enter-and-restore on one call.
- **A netlink crate that targets a netns fd directly (no `setns`).** Rejected: aya's tc attach has no
  netns parameter, and pulling in a second netlink stack to avoid one `setns` call is a bigger, not
  smaller, dependency than nix's `sched` feature.

**Consequences and notes.**
- **`setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN`/root**, which the loader already effectively needs
  alongside `CAP_BPF`+`CAP_NET_ADMIN`; a host that can't enter the netns gets a typed
  `ProbeError::Attach` naming it.
- **The two tracks stay decoupled by plain values.** The loader takes a **netns name** and an
  **interface name** (`String`s), which the driver hands over via `Sandbox::netns`/`Sandbox::tap_name`
  (added here, additive `api:`); `probes-loader` gains no dependency on `vmm`. The P10.6 end-to-end
  test uses `agent-vmm` as a **dev-dependency** only.
- **`nix` is MIT** (already in the license allow-list) and pulled with default features off, `sched`
  only. First `nix`/`setns` use in the tree.
- P10.3 is the userspace export surface (`flows` per 5-tuple, `totals` as the per-VM `NetStats`
  rollup); P10.5 is this attach-on-open / teardown-on-close lifecycle; P10.6 proves guest traffic lands
  in the counters, and `cargo xtask watch-sandbox` is the live exit-gate demo.

### 025 — Egress policy: a per-VM allow-list in an eBPF map, deny-by-default, enforced at the tap *(2026-07-16)*

**Problem.** Phase 11 turns the tap observation (decision 023) into **enforcement**: which world
endpoints a sandbox may reach. This needs a place the policy *lives*, a *schema* for it, and a rule for
*where it is applied*. The engine must supply the **mechanism** (allow/deny a destination, per VM,
host-enforced and recorded) without absorbing **org policy** (who is allowed what, tenancy, quotas) —
that is the hoster's, per guardrail 4. This decision fixes the mechanism so the schema doesn't churn.

**Decision.** Policy is a **per-VM allow-list of destination rules in an eBPF map, consulted by the tap's
ingress classifier, deny-by-default, opt-in per monitor**.
- **Where it lives: two `#[map]`s per loaded object.** `POLICY`, a fixed `MAX_POLICY_RULES` (16) array of
  `PolicyRule`, and `ENFORCE`, a one-slot toggle. Because each `TapMonitor` loads its own object, the
  maps are **naturally per VM** — no shared table, no tenant key. Single-sourced in `crates/probes-common`
  next to the flow record (decision 023), so the kernel writer and host reader can't drift.
- **The schema: a masked-CIDR 5-tuple prefix.** A `PolicyRule` is `{ addr, prefix_len, port, proto,
  active }` — a destination **CIDR** (`0` prefix = any address) with an optional **port** and **protocol**
  (`0` = any). A packet is allowed iff its destination matches **any** active rule (`rule_matches`, shared
  by the kernel scan and the host-tested `egress_allowed`). An explicit `active` byte distinguishes an
  empty slot from a `0.0.0.0/0` allow-all, so a zeroed map is deny-all, never accidental allow-all.
- **The userspace surface is typed, not stringly/magic.** The loader exposes an ergonomic builder
  (`EgressPolicy::deny_all().allow_host(ip, Some(port), Some(Protocol::Udp))` / `.allow(cidr, port,
  proto)`) that lowers to the wire `PolicyRule`s. The types carry the intent the raw record can't:
  `Protocol` is an enum (no magic `6`/`17`), the port and protocol are `Option` (`None` = the wildcard,
  no `0`-sentinel at the API), and a CIDR is a validated `Ipv4Cidr` whose prefix is guaranteed `0..=32`
  by construction (`parse, don't validate` — an out-of-range prefix is a typed `PolicyError`, never a
  silent clamp). `TapMonitor::set_egress_policy` applies it to an attached monitor;
  `TapMonitor::enforce_in_netns` applies it **at launch**, arming the maps *before* the tc programs go
  live so there is no un-enforced window (the first guest packet is already policed). On the kernel side
  the classifier's logic speaks a `Verdict` enum (`Pass`/`Drop`), lowering to the `tc` ABI only at the
  return, so no bare action number leaks into the decision code.
- **Applied at the *ingress* hook (guest → world), not egress.** Egress policy governs what the guest
  *sends*, which on a tap is the ingress hook (decision 023). The egress hook (reply → guest) always
  accepts, so replies to allowed traffic return without connection tracking. **ARP is always allowed** —
  the guest must resolve its on-link gateway (`10.200.0.1`, decision 017) before it can reach anything,
  so dropping ARP would make deny-by-default trivially deny-everything.
- **Deny-by-default, opt-in enforcement.** `ENFORCE` off (the load default) is observe-only, preserving
  Phase 10. `ENFORCE` on with no rules drops everything: a sandbox launched with no explicit allowance
  reaches nothing (P11.4). This is the eBPF, host-observed complement to the **driver's** deny-by-default
  (decision 008 gives the guest no route to the world); the tap layer drops anything unlisted where the
  host can see and record it.
- **Denials are recorded (P11.5).** A dropped IPv4 packet is counted per destination in a `DENIALS` map
  before the drop, read back by `TapMonitor::denials` — the audit trail of blocked endpoints Phase 13
  folds into the per-run record.

**Alternatives considered.**
- **An LPM-trie map (`BPF_MAP_TYPE_LPM_TRIE`) keyed by CIDR.** Rejected: it does longest-prefix address
  matching well but doesn't carry **port/proto** in the key, and a per-sandbox allow-list is a handful of
  rules where a bounded linear scan is simpler, verifier-friendly, and keeps CIDR+port+proto in one
  record. The trie is the upgrade if allow-lists ever grow large.
- **Enforce with the driver's netfilter/routing instead of eBPF.** Rejected: decision 008 already keeps
  the driver rules minimal (no MASQUERADE, host-local only), and putting allow-listing in netfilter would
  split enforcement across two systems and lose the host-eBPF observation (core property 2). One tap hook
  both observes and enforces.
- **Store richer, higher-level policy (names, tenants, quotas) in the engine.** Rejected: that is org
  policy (guardrail 4). The engine's schema is destination CIDR/port/proto; a hoster maps its own policy
  onto that.
- **Enforce on the egress (reply) hook too / stateful conntrack.** Rejected for now: egress policy is
  about what the guest *sends*; stateful return-path filtering is more machinery than the allow-list
  mechanism needs. Accepting replies is the stateless, correct default.

**Consequences and notes.**
- **Per-VM, no shared state**, so enforcement scales with monitors and one sandbox's policy can't affect
  another's — the same per-object isolation as the flow map (decision 023).
- **The mask shift is built to stay `< 32`** (`prefix_len == 0` → zero mask, out-of-range → no match), so
  the kernel scan has no undefined shift and the verifier accepts the bounded loop.
- **Not the pinned public API.** The policy surface is on `probes-loader` (`EgressPolicy`,
  `set_egress_policy`, `enforce_in_netns`, `denials`), not `vmm`'s `Sandbox`, so this is **not** an
  `api:` change. Folding attach-and-enforce into `Sandbox::open` is Phase 13's convergence.
- P11.7 (`net_enforce.rs`, ignored/privileged) proves a guest reaches an allow-listed endpoint and is
  denied every other, and `cargo xtask enforce-sandbox` is the live exit-gate demo.

### 026 — Resource accounting: one shared `sched_switch` program metering a cgroup set, CPU from eBPF, memory/IO from cgroup v2 *(2026-07-16)*

**Problem.** Phase 12 meters what a sandbox *costs* — host CPU, memory, IO — as the metering primitive
the hoster bills on (the engine measures; billing is the hoster's, guardrail 4/3). A microVM services
its own syscalls in-guest, so the strong host-side signal is the **cgroup** the VMM runs in (decision
014/P6.7): its host CPU (running the vCPUs), its charged memory, its IO. This decision fixes *how* that
is measured and *how it scales* to many concurrent sandboxes.

**Decision.** **CPU rides one shared eBPF `sched_switch` program metering a *set* of cgroups; memory and
IO ride the kernel's native cgroup v2 counters.**
- **CPU: a `sched/sched_switch` tracepoint, one program, attached once.** On every context switch it
  charges the on-CPU nanoseconds the outgoing task just ran to that task's cgroup id in the `CPU_NS`
  hash map. It is correct because at that tracepoint the scheduler has not yet swapped `current` (it
  still points at the task leaving the CPU), so `bpf_get_current_cgroup_id()` is exactly the cgroup
  whose slice ended; a per-CPU `LAST_SWITCH` cursor is always restamped so intervals stay exact across
  the metered/not-metered branch.
- **A target *set* (`METER_TARGETS`), not a program-per-sandbox.** `sched_switch` is a *global*
  tracepoint: attaching one program per sandbox would run **every** attached program on **every**
  context switch (O(sandboxes) per switch). Instead one program consults a `cgroup_id -> 1` set the
  loader writes; the hot path is a single hash lookup, and `CPU_NS` only ever holds the registered
  cgroups. Adding a sandbox is one map insert, not one more attached program — so accounting stays
  bounded and sane under many concurrent sandboxes (P12.4, measured by `bench-meter`). A `METER_ALL`
  toggle is the whole-host escape hatch for a snapshot or a test, not the per-sandbox path.
- **Memory/IO: the kernel's own cgroup v2 counters, not a probe.** `memory.peak`/`memory.current`,
  `io.stat` (rbytes/wbytes), and `cpu.stat`'s `usage_usec` (an independent cross-check on the eBPF CPU
  total) are maintained by the kernel per cgroup; `CgroupStats::read` reads them from the cgroup dir,
  best-effort (every field an `Option`, a missing controller/older kernel is `None`, never an error —
  accounting fails open, decision 013). This is the "cgroup-bpf **or** cgroup + tracepoints" the phase
  allows: eBPF where per-event timing earns its keep (CPU), the kernel's counters where they already
  exist (memory, IO).
- **Correlated by the FC per-VM cgroup (P12.2).** `cgroup_id_of_pid(vmm_pid)` resolves the id for the
  CPU meter and `cgroup_dir_of_pid(vmm_pid)` the dir for `CgroupStats`, so a sandbox's VMM pid (the
  Firecracker track's `vmm_pid`) scopes all three axes to that one sandbox's cgroup.
  `ResourceMeter::summary_for_pid` rolls them into a `ResourceSummary` (P12.3).

**Alternatives considered.**
- **Read only cgroup v2 files, no eBPF.** Rejected as the CPU story: `cpu.stat` gives a coarse total,
  but the phase is "resource accounting **via cgroup-bpf**", and the scheduler tracepoint gives precise,
  event-driven, per-cgroup CPU attribution that generalizes to per-task/percentile views later.
  `cpu.stat`'s `usage_usec` is kept as a cross-check, not the source.
- **A program attached per sandbox (mirroring `TapMonitor`'s per-tap attach).** Rejected: a tap only
  sees its own sandbox's packets, but `sched_switch` is global, so per-sandbox programs are O(N) per
  switch. One shared program + a target set is the scalable shape.
- **Track memory via BPF (page-fault/rss hooks).** Rejected: memory is a gauge the kernel already keeps
  per cgroup (`memory.peak` is the meaningful high-water mark); a BPF reimplementation would be noisier
  and slower than reading the counter.

**Consequences and notes.**
- **Not the pinned public API.** The surface is on `probes-loader` (`ResourceMeter`, `CgroupStats`,
  `ResourceSummary`, `cgroup_dir_of_pid`), not `vmm`'s `Sandbox`, so this is **not** an `api:` change.
  Folding the `ResourceSummary` into the persisted per-run audit record (fused with the network denials
  and the syscall trace) is Phase 13's convergence — kept out of `agent-vmm` so the driver stays
  independent of the eBPF loader (they bridge only by plain values).
- **Best-effort accuracy.** The `CPU_NS` accumulate is per-CPU-serialized by the scheduler hook but not
  atomic across CPUs, so a heavily-parallel cgroup can undercount by a hair — fine for a metering
  signal (the same posture as the flow counters, decision 023).
- P12.5 (`resource_meter.rs`, ignored/privileged) proves a CPU-heavy run reports far more CPU than an
  idle one, attributed to the sandbox's cgroup; `cargo xtask meter-sandbox` is the live exit-gate demo.

### 027 — The per-run audit record lives in `probes-loader`, out of `agent-vmm`; a two-phase arm/bind attach reconciles tracer-before-boot with on-open *(2026-07-17)*

Phase 13 fuses the three host-side probes into one **per-run audit record** and attaches them to a
sandbox at launch. Two questions had to be settled: *where* the record and the attach machinery live,
and *how* "attach on `Sandbox::open`" is realized given the probes' conflicting timing.

**Where.** The record type (`RunRecord`) and its aggregation live in **`probes-loader`** (new modules
`record.rs` + `observer.rs`), **not** in `agent-vmm`. Decisions 024 and 026 already bind this: the
driver must gain no dependency on the eBPF loader, and the two tracks bridge only by plain values. So
`agent-vmm` is untouched; the bundle takes the plain values `Sandbox` already exposes (`vmm_pid()` →
its cgroup for the syscall tracer and the CPU meter, `netns()` + `tap_name()` for the network monitor)
and never a `Sandbox`. The composition — a short launch sequence around `open` — is the *caller's*
(the CLI/daemon later), never the driver's. `record.rs` is pure (no aya, no vmm), so its whole
aggregation is unit-tested on the host gate with synthetic inputs.

**How (two phases).** A single post-`open` constructor can't attach all three: the syscall tracer must
attach *before* boot (the jailer creates the sandbox's cgroup *during* boot, so its id isn't knowable
up front — the tracer watches host-wide, then scopes to the cgroup and filters the buffered boot window
post-hoc, the Phase-9 pattern), while the tap monitor and meter need the netns/cgroup to already exist,
so they bind *after* boot. Hence `ArmedProbes::arm()` (pre-boot) → `ArmedProbes::bind(...)` (post-boot)
→ `SandboxProbes::collect(timing)`. "On `Sandbox::open`" is that three-call sequence around `open`, not
a constructor inside `vmm`.

**The record.** Its **core is network + resources + denials** — the signals host eBPF observes strongly
across the hardware boundary. `host_syscalls` is explicitly the **VMM's host footprint**, not in-guest
syscalls. It is bounded two ways (repetition collapses into a hit count; the distinct set caps at
`MAX_NOTABLE = 64`, flagging truncation) and every collection is deterministically sorted, so a record
built from the same observations is byte-stable (the property the Phase-14 JSON output relies on).

**The meter is shared, not per-VM.** A fresh `ResourceMeter` per sandbox would re-instantiate the
global `sched_switch` program per VM — the O(N)-per-context-switch shape decision 026 rejects. So the
bundle registers its cgroup as a *target* on a caller-owned `SharedMeter` and unregisters on drop; the
tracer and tap are legitimately per-VM and owned by the bundle. (A shared syscall-tracer fan-out is the
clean P13.5 follow-up, deliberately not built here.)

**Consequences and notes.**
- **Not the pinned public API.** All new surface is on `probes-loader`; `vmm`'s `Sandbox`/`RunResult`
  are untouched — **not** an `api:` change. Timing enters `collect` as plain `Duration`s the caller
  lifts from `Sandbox::boot_latency` + `RunResult::metrics.wall`, so the record never depends on `vmm`.
- **Fail-open.** Each axis degrades independently to a recorded `AxisGap`; a host missing caps/BTF/the
  object still runs the sandbox and yields a thinner, honestly-annotated record (the decision-013 posture).
- **Deferred.** Detach/finalize-on-close beyond the drop `remove_target` (P13.3), the deterministic JSON
  *output* surface (P13.4), the overhead bound (P13.5), the privileged end-to-end proof (P13.6), and the
  CLI `agent run --trace` (Phase 14) all build on this record without reshaping it.

### 028 — The audit record converges: a shared syscall tracer, a single post-boot attach, and deterministic JSON *(2026-07-17)*

Phase 13 closes the audit log: detach + finalize on close (P13.3), a structured JSON surface (P13.4),
a bound on the overhead under concurrency (P13.5), and the end-to-end proof (P13.6). Three shape
choices are worth pinning; the first **supersedes the two-phase arm/bind of decision 027**.

**The syscall tracer is shared, not per-VM (P13.5) — this retires the two-phase attach.** Decision 027
kept a per-VM `SyscallTracer` and reconciled "attach before boot" (to catch the boot window) with the
tap/meter's "attach after boot" via `ArmedProbes::arm()` → `bind()`. But a tracer per sandbox attaches
*N* copies of each `sys_enter_*` tracepoint and runs all of them on **every** matching host syscall —
the O(sandboxes)-per-event shape decision 026 already rejected for `sched_switch`. So the tracer now
takes the *same* treatment as the meter: a `TRACE_TARGETS` cgroup **set** + a `TRACE_SET` mode toggle
in the kernel program (the exact `METER_TARGETS`/`METER_ALL` pattern), one shared `SyscallTracer`
loaded once for the host, and every sandbox registers its cgroup as a target. One shared drain routes
each event to that cgroup's private `SyscallFold`, so concurrent sandboxes stay independent (a sandbox
reads only its own footprint; unregistering one leaves the others untouched) and both the per-event
cost and the ring-buffer volume stay bounded (a single hash lookup, only target cgroups emitted). The
CPU meter was already shared this way, so **both** host-wide probes are now loaded once
(`SharedTracer` + `SharedMeter`) and only the per-VM tap is owned by the bundle.

Because nothing per-VM has to pre-attach anymore, the two-phase `arm`/`bind` **collapses to a single
post-boot `SandboxProbes::attach`** — simpler, and still "on `Sandbox::open`" (the caller's
arm-free sequence). The one consequence: `host_syscalls` now covers from **registration (just after
boot) onward**, not the pre-boot boot window. That window is the VMM/jailer's own host setup, not
guest-attributable behaviour, and the record's core (network + resources + denials) is unaffected — a
deliberate trade of exact-boot-window capture for bounded overhead. `TRACE_SET` defaults off, so the
single-target `watch_pid`/`watch_cgroup` path (Phase 9 tests, benches, demos) is byte-for-byte
unchanged; set mode is opt-in and used only by `SharedTracer`.

**Detach + finalize on close (P13.3).** `collect(timing)` is the close-time finalize: it reads the
three probes into the record **and** unregisters this run's cgroup from the shared tracer + meter, all
while the sandbox is still alive (the cgroup dir + map fds must be live). `Drop` is the abandoned-path
safety net — detach only, no record — and is a no-op after `collect`. So a bundle always leaves the
shared sets clean whether it is finalized or dropped.

**Deterministic JSON (P13.4).** `RunRecord::to_json` is hand-rolled, dependency-free, and compact — the
same reasoning as the hand-framed wire (decision 002): the audit-log format is a contract the language
SDKs parse, so the exact bytes are pinned here (a golden test), not left to a derive's field order.
It is byte-stable (fixed key order; every array already sorted by its builder), float-free (durations
are integer nanoseconds), and renders addresses/protocols/syscalls by name. Phase 14 pretty-prints it
for people and exports it; this is the machine surface underneath.

**Not the pinned public API.** All of this is on `probes-loader`; `agent-vmm`'s `Sandbox`/`RunResult`
are untouched — **not** an `api:` change. The privileged end-to-end test drives the real launch sequence
(load shared probes → boot → `attach` → run → `collect` → JSON) and asserts the guest's network touch
shows up *exactly*, while its in-guest file read correctly does **not** appear in the host-syscall axis
(the isolation working, not a gap).

**Hardening pass (same day, pre-ship).** A review of the fresh implementation tightened five things
while the format was still unpublished; they are part of this decision's shape:

- **Denials aggregate by destination.** The kernel keys `DENIALS` by the dropped packet's full
  5-tuple, so retries from different guest source ports arrive as separate entries; sorting them by
  destination alone was not a total order (byte-stability broke on ties, and the JSON showed
  duplicate-looking rows). `NetSection::from_tap` now sums per `(dst, port, proto)` — one row per
  blocked endpoint, totally ordered, matching the JSON surface.
- **Loss is counted, never silent.** A full ring buffer drops events by design; the kernel now counts
  those drops (`EVENT_DROPS`), and the bundle snapshots the counter at attach and reports a nonzero
  delta at collect as a coverage gap. The buffer is drained at `SharedTracer::load` (clearing the
  unfiltered load-window baseline), at every registration, and on demand (`poll`) for long-lived hosts.
- **Every axis records its gap.** A poisoned meter/tracer lock, a failed resource read, or a failed
  tap-map read each produce a specific `AxisGap` — a record showing zero CPU or an empty footprint
  means the sandbox was quiet, never that a read silently failed. A failed flow/denial read keeps the
  rest of the network section and names exactly what was lost.
- **Truncation is exact.** `overflow_events` (né `distinct_dropped`, renamed before anything parsed
  it) counts every event past the notable cap, so `total - overflow_events` is the exactly-attributed
  share; the kept set is documented as first-by-arrival. JSON durations clamp to u64 nanoseconds — a
  documented ceiling consumers can parse with ordinary 64-bit integers.
- **Filter modes can't half-apply.** The `watch_*` setters switch the tracer back to single-filter
  mode just as `add_target` switches it to set mode, so the active model always matches the last
  setter used; folds are created fresh at registration (a recycled cgroup id can't inherit a dead
  run's events).

### 029 — The observability face: the CLI carries the audit surface on flags, the live view draws on stderr *(2026-07-17)*

**Decision.** What a run did becomes *legible* at the CLI, on three composable `run` flags over one
mechanism: `--trace` (the human-readable trail, on **stdout** after the run), `--record FILE` (the
deterministic JSON record, the machine surface), and `--watch` (a live full-screen view, on
**stderr**, while the command runs). A fourth flag, `--net`, boots the sandbox with its NIC so
there is a tap to observe (deny-by-default unchanged: no allowance means nothing past the host /30).
Any of the three audit flags triggers the same launch sequence decision 028 defined — load the
shared tracer + meter, boot, `SandboxProbes::attach` by plain values, exec, `collect` while the
sandbox is alive — composed **in the CLI**, never in `agent-vmm` (decisions 024/026 hold: the two
tracks still bridge only by `vmm_pid`/`netns`/`tap_name`).

**Stream discipline decides where each face lives.** The house rule is "stderr carries diagnostics,
stdout carries the run's result, so a pipeline stays clean". So: the live TUI is *interactive
diagnostics* → it draws on **stderr** (ratatui over a stderr backend; stdout still relays the
guest's output afterwards, `--watch --json` composes). The trail and the record are *requested run
output* → stdout / a file. `--trace` conflicts with `--json` (two formats interleaved on one stream
helps no one); machine consumers combine `--json --record FILE` instead. The pretty trail makes
**no stability promise** — the byte-stable contract is `RunRecord::to_json` alone (decision 028),
and the trail says so in the docs rather than growing a second frozen format.

**The live view is a reader, and the record stays authoritative.** `--watch` polls a new
non-destructive `SandboxProbes::snapshot` (`LiveSnapshot`: the tap's flows/denials now, the meter's
summary now, a *finished clone* of the syscall fold-so-far) while the exec runs on a worker thread
that owns the `Sandbox` — so watching can never disturb the fold, the maps, or the final `collect`,
and closing the view (`q`) never cancels the run. The timeline panel is derived by *diffing
successive snapshots* (new flow / denial delta / new notable syscall), pure and host-safe-tested;
terminal state is restored by a drop guard on every exit path, and a broken TUI degrades to a
headless run (logged), never a failed one — the no-panic discipline extended to the screen.

**Fail-open extends to the CLI.** A host without BTF/caps/the object still runs `--trace`: the
shared probes load fail-open and an unattached run yields the honest empty record with every absent
axis explained in coverage — a working command with a thin record, never a refused run.

**`--net` lands here, policy projection stays later.** The live view and the drill-down are about
the *network* above all, so the NIC flag could not wait for the fuller CLI-completeness phase; it
boots observe-only (no `EgressPolicy`, so the denial trail is structurally empty until `--allow`
lands with the policy projection). That later phase inherits `--net` already shipped.

**Alternative rejected.** A structured *stream* (NDJSON events during the run) instead of a TUI:
less code, pipeable — but it is a second machine surface to freeze prematurely, and the phase's
point is the *demo you show people*. The record file already serves machines; a stream can join the
daemon later if embedders want push-style events.

### 030 — `--allow` projects the egress policy: enforcement is a typed refusal, never a degradation *(2026-07-17)*

**Decision.** `agent run --allow IP[/CIDR][:PORT][/PROTO]` (repeatable, `requires` `--net`) projects
the `EgressPolicy` onto the CLI, completing the network half decision 029 pulled forward observe-only.
Each value parses into one validated allow-rule (`parse_allow`, right-to-left so the numeric CIDR
prefix and the `/tcp`|`/udp` suffix can't be confused); the rules fold into a deny-by-default policy
(`build_egress`, capped at `MAX_POLICY_RULES` with a typed refusal), which the audit-bundle launch
sequence hands to `SandboxProbes::attach` as `Some(policy)` — so it is armed on the tap *before* the
tc programs go live (the no-unpoliced-window property, decision 025). Every allowance is explicit on
the command line (guardrail 3's greppable audit line), and what the policy drops lands in the record's
denials.

**Enforcement does not fail open.** Observation degrades to a recorded coverage gap on a capless host
(a `--trace` run still works, decision 029). A *policy* can't: a run that asked to enforce one and
couldn't arm the tap would silently ignore the operator's allow-list, so it is a **typed refusal**
instead. Two layers realize this: a cheap pre-boot `check_support()` when `--allow` is present (catches
the missing-BTF/`CAP_BPF`/`CAP_PERFMON` case before paying a boot), and a post-attach check in the CLI's
`Observability::attach` that refuses if the *network* axis gapped (the residual `CAP_NET_ADMIN`/tc-attach
case the pre-flight can't see). `--allow` without `--net` is refused by clap. The split is deliberate:
the enforcement check keys on the network axis alone, so a poisoned syscall/CPU probe still degrades
observation to a gap without blocking a policed run.

**Scope.** This closes the network projection of the CLI-completeness interphase; the config-file layer,
`agent doctor`, and the JSON schema version remain. `--allow` is `run`-only, where `--net` lives (the
interactive `shell` has no network face).

### 031 — The `.agent.toml` config file layer: nearest-up-from-cwd, env-mirrored keys, typos are errors *(2026-07-17)*

**Decision.** The config precedence `flags > env (AGENT_*) > file > defaults` becomes real by inserting
a `.agent.toml` **file** layer between the environment and the defaults. Discovery is the **nearest
`.agent.toml` walking up from the cwd** (the `.gitignore`/`.editorconfig` convention), so a project
pins its engine config beside its code and a nearer file shadows a farther one. The file's keys
**mirror the `AGENT_*` env names 1:1** (minus the prefix, lowercased: `kernel`, `rootfs`, `marker`,
`scratch_dir`, `firecracker`, `log`), so a value is spelled the same across all three lower layers —
one vocabulary. **Unknown keys are a typed error** (`serde(deny_unknown_fields)`): a typo like
`kernal` fails loudly, naming the valid keys, rather than silently no-opping.

**The layering reuses the engine, it doesn't reimplement it.** `agent-vmm::BootConfig::from_env_with`
(made public for this) takes a lookup closure; the CLI composes `std::env::var_os(key).or_else(|| file.env_value(key))`,
which resolves `env > file > defaults` for every artifact/scratch key with **zero duplication** of the
engine's env-key handling or its pinned defaults. The one config value with no `BootConfig` field —
`log` (it drives `tracing`, not the engine) — is resolved by a parallel `flag > env > file > default`
helper in the CLI. This keeps the file layer entirely in the CLI (the reference embedder); a library
embedder builds `BootConfig` programmatically and is unaffected. Making `from_env_with` public is an
additive change to `agent-vmm`, not to the enumerated pinned items (`Sandbox`/`Limits`/`RunResult`/
`VmmError`/`channel`).

### 032 — `agent doctor` shares one host-check implementation; the JSON surfaces are versioned before anyone parses them *(2026-07-17)*

**Doctor.** The host readiness check ships as an engine subcommand, `agent doctor`, so an operator on
a fresh host reads what will work, degrade, or refuse *before* the first sandbox. The **one
implementation** lives in `agent-vmm::doctor` (structured `Vec<Check>` with an `Ok`/`Warn`/`Fail`
status + the degradation matrix), where the engine-runtime prerequisites (KVM, jailer, real-root,
firecracker, iproute2/e2fsprogs, cgroup delegation, kernel version, boot artifacts) are its domain;
both `agent doctor` and `cargo xtask setup` render it, so the dev-box check and the operator's can't
drift. The status split mirrors the engine's own error discipline: the isolation boundary (`/dev/kvm`)
and the boot artifacts are **hard** (`Fail` → non-zero exit, so `agent doctor && agent run …` gates),
while the jailer, resource caps, and networking/bulk-I/O tools **fail open** (`Warn` with a named
consequence). The eBPF-capability row (`CAP_BPF`/`CAP_PERFMON` + BTF) stays in the probe loader, out of
`agent-vmm` (decisions 024/026); each entry point appends it. `xtask setup` keeps its dev-only rows
(bpf-linker, nightly, readelf) local — an operator running the shipped engine doesn't need them.

**Versioned JSON.** Both machine JSON surfaces carry a leading integer `schema` field: the `--json`
run result (`RUN_RESULT_SCHEMA`) and the audit record (`AUDIT_SCHEMA_VERSION`), each starting at `1`
and **versioned independently** — two contracts, two versions. The **compatibility policy**: within a
version, changes are *additive only* (a new field a consumer can ignore); renaming/removing a field or
changing a value's meaning **bumps** the integer. This lands *before* anything external parses the
bytes (the wire API and the SDK freeze harden a stable contract, not a moving one). The audit record's
previously-open field questions were already settled by decision 028's hardening pass
(`overflow_events` semantics, the u64-nanosecond ceiling), so v1 is a considered shape, not a
placeholder.

### 033 — The whole security boundary: what's trusted, what the adversary is, and what's assumed sound *(2026-07-17)*

**Problem.** The trust boundary had been stated in pieces — "isolation is hardware" as a core
property, decision 016's engine/hoster line (one facet the orphan sweep forced), decision 022's
"multi-tenant safety *is* the containment suite" — but never written down whole: the complete set of
what the engine trusts, the adversary it assumes, and the risks it explicitly does **not** cover. A
security engine whose boundary lives only in scattered implications can't be audited, and a hoster
can't reason about what they're taking on. With the Phase-15 adversarial suite now green, the boundary
is provable, so it should be recorded as one thing.

**Decision.** Fix the boundary at the CPU, and state all three faces of it explicitly. This is the
recorded rationale; the reader-facing companion is `docs/threat-model.md` (P15.5), and the two are
kept in sync.

- **Trusted (inside the boundary):** the host CPU's virtualization (KVM), the host kernel (including
  its eBPF and cgroup implementations), and the driver on the host — the VMM process, the jailer, and
  the host-side eBPF probes. All security-relevant observation and policy live here.
- **Not trusted (outside):** everything in the guest — the untrusted code, the **guest kernel**, and
  the in-guest agent. The agent carries exec/IO for convenience and is **never** a security boundary;
  a hostile guest is assumed to own it and its kernel completely.
- **The adversary:** a single fully-hostile guest that tries to escape the VM, exhaust or crash the
  host, exfiltrate or flood the network, interfere with a co-resident run, and blind or forge the
  host's observation. It does **not** include a party with host access, a KVM/host-kernel zero-day, or
  physical/micro-architectural side-channel attacks (see assumptions).

**Why this shape.** Each obligation sits on the side that can hold it. The guest kernel is *inside* the
untrusted set precisely because a microVM gives the guest its own kernel — which is also why host-side
syscall visibility is coarse (the guest services its own syscalls; their absence at a host tracepoint
is the isolation working, decision 021/027), and why the strong signals are the ones the host mediates
directly: the guest's network at its tap and its resources at its cgroup. "Trusted" here means
*assumed sound*, not *audited* — the jailer + seccomp narrow the VMM's own attack surface as defense
in depth, but they are not a substitute for KVM.

**What proves it.** The boundary is not asserted, it is exercised (a core property). Escape → the
`vmm` jail-escape tests (P6.6); resource exhaustion → the cgroup caps (`memory.max`/`cpu.max`/
`pids.max`, P6.8) plus the derived per-drive **IO-bandwidth bound** (P15.7, decision 013's
"derived defaults, not `Limits` knobs" — a virtio-blk rate limiter so a disk-thrashing guest can't
starve a co-resident run); network exfiltration/flood → deny-by-default egress enforced at the tap
(decision 025, P4.7/P15.3); observation evasion → the guest can't reach host-kernel eBPF (P15.2);
leak-on-death → the cgroup-owned lifetime + sweep (decisions 014/016); clone state-bleed → per-clone
overlay + RAM (P15.4). The consolidated proof is that these hold **together** against one hostile
guest doing its worst on every axis at once (P15.1, P15.3).

**Assumptions and residual risk (explicitly out of the boundary).** KVM and the host CPU's
virtualization; the host kernel; micro-architectural side channels (Spectre-class, timing) between
co-resident guests, which a hoster placing high-sensitivity workloads accounts for at the scheduling
layer it owns; and *fair* scheduling across runs — the engine bounds a run's resource use but does not
promise fairness, which is the hoster's scheduler.

**Relationship to prior decisions.** This closes what decision 016 (the engine/hoster line) and
decision 022 (multi-tenant safety = per-run isolation, proven by the suite) opened: 016 is one facet
(privileged tools can't be weaponized), 022 defined the multi-tenant *claim*, and this records the
*whole* boundary the claim rests on. Any future privileged surface inherits it; any change that moves
observation or policy *into* the guest, or trusts guest-side software for a security property,
contradicts this decision by construction.

### 034 — The wire API is versioned newline-JSON in a shared `agentd-protocol` crate, not gRPC *(2026-07-17)*

**Decision.** `agentd`'s wire API — the SDK contract Phase 20 freezes — is **newline-delimited JSON
over a unix socket**, and every message (request *and* response) carries a leading `schema` field.
The full verb set is the sandbox lifecycle: `open` → (`exec` | `put` | `get` | `snapshot` | `trace`)\*
→ `close`. It is **not gRPC**.

**Why JSON, not gRPC.** The daemon is synchronous, thread-per-connection, with **no async runtime** on
the host path (the same posture the `Pool` doc restates as an invariant); gRPC would drag `tonic` /
`prost` and a `tokio` stack into that posture for no gain here. The peer is a **local, trusted-ish
client** the hoster runs — not the untrusted guest — so hand-debuggability (`socat`/`nc` by hand) and
"any language with a JSON library and a unix socket can drive it" outweigh a compact wire. The one
adversarial concern that still applies is guardrail 5: every decode is bounded by a message-size cap
and returns a typed error, never a panic/hang/unbounded allocation.

**Why a `schema` field now, when the shape isn't frozen.** Precisely *because* it isn't frozen yet:
stamping `schema: 1` on every message and rejecting a mismatch **up front, before the body is
trusted**, means a client built against a future revision fails loudly instead of being
half-understood. The stamp is the seam Phase 20 freezes against. (It is distinct from the audit
record's own `schema` and the CLI's `--json` run-result `schema`: three surfaces, three independent
versions.)

**Why a shared `agentd-protocol` crate (serde-only, no `agent-vmm`).** The wire is the contract, not
shared Rust internals. Putting the `Request`/`Response`/`Envelope` shapes and the bounded line codec
in their own **engine-free** crate means the daemon and the **reference client** (`agentd-client`)
share one source of truth, while a non-Rust SDK reimplements the same JSON shapes with only a JSON
library — the proof a caller needs nothing of the engine but the wire. The reference client depends on
`agentd-protocol` and a JSON value **only, never `agent-vmm`**; if it ever linked the engine, that
proof would be void.

**Verb semantics (faithful to the engine, no new machinery).** `put`/`get` write/read a
working-directory file by riding the engine's only file seam — a no-op `exec` that injects a file or
returns an artifact — since the engine stages files *around* an exec, never standalone. `snapshot`
calls `Sandbox::snapshot`, so a **jailed** session is a typed refusal (its disk is in the chroot),
exactly as the library behaves; the client gets the bundle's **daemon-host directory**, not its bytes
(bulk bytes stay off this line). `trace` returns the host-observed `RunRecord` built **non-destructively**
from a live probe snapshot, so a client may ask repeatedly mid-session without finalizing observation;
it is fail-open (a capability-less host answers a coverage-gapped record, never an error). The
pre-warmed **pool** (`--prewarm N`) serves only a **bare-default** `open` (the pool's clones carry the
default profile); any custom resource knob cold-boots.

**Scope, unchanged.** Still engine, not platform: no auth (socket-directory permissions are the
hoster's access control), no tenancy, no billing, no scheduler. The daemon shares nothing with the
`agent` CLI bin beyond the crate's small shared library (the `audit` composition both bins reuse); the
pinned `agent-vmm` API (`Sandbox`/`Limits`/`RunResult`/`VmmError`/`channel`) is untouched — the daemon
only *consumes* it.

### 035 — The AI-scope boundary: the model is always the caller, never an engine component *(2026-07-17)*

**Problem.** Phase 18 makes AI-generated code and autonomous agents a first-class workload, and the pull
the instant you say "AI-native" is to reach for a model *inside* the engine: a model that judges whether
a run is safe, classifies the audit record, or adapts the policy. That pull has to be refused explicitly
and on the record, before the Phase-18 surfaces are built on top of it — or "AI-native" quietly becomes
"has an LLM in it," and the four core properties erode one commit at a time into a slap-on nobody
decided to make.

**Decision.** The model is always the **caller**, never an engine component. For an AI workload the
engine's contribution is exactly what it is for any untrusted workload — hardware containment (a KVM
microVM) plus a host-observed, tamper-resistant audit record — plus, new in Phase 18, a **model-legible
projection** of that record (P18.2). Nothing in the host path runs inference, holds a provider key, or
lets a model decide a security question. The reference agent-containment example (P18.4) drives the
engine with a **deterministic scripted agent** — a fixed stand-in for an LLM's tool loop — so the demo
is CI-reproducible and needs no model, no secrets, and no network to a provider.

**Why a model *in* the engine breaks the invariants.** Each failure lands on a different core property,
which is why the line is drawn at the engine's edge and not somewhere softer:

- **Isolation is hardware (invariant 1).** A model gating what a run may do is a *software* trust
  boundary, and a probabilistic one — the exact thing the CPU-is-the-boundary property exists to rule
  out. The moment a model's output decides containment, the boundary is no longer the KVM line; it's a
  prompt.
- **Engine, not platform (invariant 3).** Inference, prompt management, provider keys, and model-driven
  policy are platform concerns — the caller's or hoster's, alongside tenancy, billing, and scheduling.
  Pulling them into the engine is the same category error as bundling a dashboard.
- **Measured, not marketed (invariant 4).** A model call is unbounded and un-benchmarkable: there is no
  honest p99 for "ask an LLM." An engine that made inference part of a run could no longer
  percentile-report the run — every headline latency would carry an unmeasurable tail.

**Why invariant 2 is untouched — and is the whole point.** Observe-and-enforce-from-the-host is not
strained by this line; it is *served* by it. The model-legible record (P18.2) is a **projection of the
record host-side eBPF already built** (decisions 027/028): the model reads a *face* of the host's
observation, it does not help produce it. Observation and enforcement stay entirely host-side, out of
the guest and out of any model. So the AI-native surface adds a **reader**, never a new **authority** —
which is precisely what lets it exist without touching the security boundary.

**Why a scripted agent for the reference example, not a live model.** Three reasons, each an
invariant-preservation and not a convenience. It keeps the containment claim **exercised, not asserted**
(invariant 4): a deterministic agent lets P18.4's "one allowed tool call, one denied, the record proves
which" run in CI on every push, where a live provider would be flaky, keyed, and non-reproducible. It
keeps a model and its secrets out of the repo and the host path (invariants 1/3). And it isolates
*what's being proven* — the engine's containment of agent-generated behavior — from the variance of a
real model. A live model is the caller's to bring; the engine's job is proven without one.

**What this gives an agent supervisor.** The value the thesis promises for this workload: a
tamper-resistant, host-observed record of exactly what an agent's code *reached* and what was *blocked*,
observed from outside the guest where neither the agent nor its generated code can forge it — the trust
substrate a supervisor needs that a pure-execution sandbox can't offer. The model consumes that record
to decide its next action; the engine guarantees the record is true.

**Relationship to prior decisions.** This is the AI-workload face of decision 016 (the engine/hoster
line) and decision 033 (the whole security boundary): the model sits with the hoster and the caller,
*outside* the trust boundary, exactly where tenancy and scheduling already sit. Any change that puts a
model in the host path, gives the engine a provider key, or lets a model's output gate containment or
policy contradicts this decision by construction — the same test the boundary decisions already apply.

### 036 — Supported platforms: two architectures, a security-maintained host-kernel floor, and pinned upstream versions *(2026-07-17)*

**Problem.** The engine ran wherever it happened to boot: `agent doctor` gated many host prerequisites,
but every version-shaped check (`firecracker` v1.9, kernel ≥ 5.14 for `cgroup.kill`) was a *fail-open
degradation*, and there was no written statement of what the engine actually supports. For a **security**
engine that runs untrusted code, that gap is itself a risk: an end-of-life host kernel carries unpatched
KVM CVEs, and KVM is the trust boundary (decision 033) — so "it still booted" is exactly the wrong
posture. And the upstream inputs move underneath us: Firecracker periodically **drops guest-kernel
support** (it retired 4.14; the supported set is now ~5.10/6.1), so a pinned guest kernel that falls off
their list would silently stop restoring on a Firecracker bump. The supported platform needs to be a
stated, auditable line, with the security-relevant parts **hard**.

**Decision.** Fix the supported platform, and split its checks into *refuse* vs *degrade* on the same
principle the rest of the engine uses — the isolation boundary is never a degradation.

- **Architectures: `x86_64` and `aarch64`** — Firecracker's two, and the only targets the engine builds
  (the eBPF object, the guest rootfs, the binaries). Any other arch is a **hard** refusal. For a shipped
  binary this is settled at compile time; the `doctor` check names an unsupported cross-compile rather
  than letting it fail obscurely at first boot.
- **Host kernel: a security-maintained LTS floor, `MIN_KERNEL` (currently 5.15)** — a **hard** floor, not
  a degradation. 5.15 is a maintained LTS (so it still receives KVM security fixes) and subsumes the 5.14
  `cgroup.kill` requirement (decision 014); it does not exclude common fleets (Ubuntu 22.04 ships 5.15).
  The floor is one constant, bumped to tighten (e.g. to 6.1) as older LTSes reach end of life. **Not
  boot-enforced:** `doctor` is the enforcement surface (it exits non-zero and names the miss), but a boot
  does not hard-refuse on a version *string* — distro backports make the number an unreliable proxy, and
  the real boundary (KVM) is already hard. The policy is stated and operator-checkable; it is not a
  brittle runtime string-compare in the hot path.
- **Firecracker: pinned v1.9 (decision 001), a degradation off-pin** — a different version boots with a
  warning (API bodies may not match), because it often works; the *tested* version is v1.9, stated here.
- **Guest kernel: pinned to a Firecracker-supported version**, built into the rootfs by `xtask`. This is
  the one that tracks Firecracker's support list: when Firecracker drops a guest-kernel version, the
  pinned build must move to one they still support (the same maintenance discipline as the sha-pinned
  upstream inputs, P6.9d / P19.1). Recorded so the coupling is not discovered as a broken restore.
- **cgroup v2 controller delegation stays a *degradation*** (decision 013): resource caps are fairness
  hygiene, not the isolation boundary, so their absence warns and runs uncapped rather than refusing.
  This is deliberately *not* promoted to the hard floor — doing so would contradict decision 013.
- **eBPF observability/enforcement stays fail-open for observation, hard-refuse for enforcement**
  (decisions 025/033): no BTF/caps degrades `--trace`/`--watch` to a coverage gap, but `--allow`
  enforcement refuses rather than running unenforced. Unchanged; restated here as part of the matrix.

**Why a floor at all, when so much fails open.** The fail-open items are *features* — a missing tap tool
only fails `--net` runs. The platform floor is the *substrate*: architecture and a patched kernel are
what the isolation-and-audit thesis rests on, so they sit with `/dev/kvm` and the boot artifacts on the
hard side of the line. Running untrusted code on an unsupported arch or an EOL kernel is a threat-model
hole, and the engine should say so, not shrug and boot.

**Relationship to prior decisions.** This extends the host-check surface (P14.9d) and the degradation
matrix (P6.9b) with an explicit floor, and it names the maintenance coupling P6.9d recorded (un-vendored
upstream inputs) for the guest kernel specifically. It respects decision 013 (caps fail open) and
decision 033 (KVM/host-kernel are trusted-*assumed-sound* — this floor is how "assumed sound" is kept
honest over time). The reader-facing statement is the *Supported platforms* section of
`docs/cli-install.md`; the two are kept in sync.
