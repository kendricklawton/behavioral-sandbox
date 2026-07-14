# Architecture decisions

The record [`ROADMAP.md`](./ROADMAP.md) references: every roadmap item tagged `(decision)`
produces a dated, numbered entry here — the decision, the alternatives considered, and the why —
so the reasoning outlives the diff. Entries are append-only; reversing one is a new entry, not an
edit. (Roadmap *re-scopes* — cut phases and why — live in the roadmap's tombstones, not here.)

**The Firecracker + aya sandbox engine.** This decision log covers the self-hostable, isolated
**code-execution sandbox**: **Firecracker** microVMs for hardware isolation, **aya/eBPF** for
host-side observability and enforcement (see `.rules`, `ROADMAP.md`). The guiding properties are
the spine's four: *isolation is hardware · observe & enforce from the host · engine not platform ·
measured and taught.*

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
- **`/dev/vdb` naming was order-dependent.** ~~Fine for a single input device; if P3.5 adds a third
  (writable output) drive, prefer mounting by filesystem label/UUID.~~ **Resolved in P3.5:** the
  guest now mounts both data devices by filesystem **label** (`agent-input`/`agent-output`, stamped
  with `mke2fs -L`, resolved with `findfs`), so the `/dev/vdX` letter — which shifts when output is
  present but input isn't — no longer matters. The input image gained an `agent-input` label and the
  `sysinit` line became `/sbin/mount-drives`.
- **The image is sized generously** from the input's byte total + a `-N` inode count (many tiny files
  exhaust inodes, not bytes); an input past a 2 GiB ceiling is a typed error, not a giant image.

### 006 — Bulk output via a read-after-death writable block device *(2026-07-12, P3.5)*

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

**Consequences / tombstones.**
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

### 007 — A byte-for-byte reproducible rootfs build *(2026-07-12, P3.6)*

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
  fetched-not-pinned — but it's a phase's worth of fetch/verify/offline-install rework. **Tombstoned**
  as the later hardening, out of scope for the byte-for-byte polish.
- **A separate content-manifest file** re-listing the Alpine/apk-tools shas + branch + target.
  Rejected: those are already source-of-truth constants in `xtask`; a second copy just drifts. The
  only thing not already captured is the resolved closure — which *is* the lockfile.

**Why.** Reproducibility is a first-class "measured, not marketed" property: a build you can't
reproduce is a claim you can't check. `SOURCE_DATE_EPOCH`/`hash_seed`/`lazy_itable_init=0` are the
standard ext4 determinism levers; the apk-log removal was the non-obvious last mile. The lockfile
makes package drift *visible* without making the build *brittle*.

**Consequences / tombstones.**
- **Reproducibility is a `ci-privileged`-guarded property**, not the everyday `ci` gate's — it needs
  the musl target + network + `mke2fs`, so `--verify` runs where the boot tests already do.
- **The lockfile drifts only on an Alpine package bump**, never on guest-agent code changes (the
  closure is independent of the agent binary) — so it isn't a per-commit chore.
- **Durable over-time reproducibility still rests on Alpine's CDN** until the `.apk` closure is
  vendored (the tombstoned hardening); today a bump makes `--verify` fail loudly with a re-pin hint.
- **A fixed htree hash seed is safe here** — the seed only matters against adversarial directory-hash
  flooding, which a trusted, pinned, build-time image doesn't face.
- **The guarantee is same-host determinism, not cross-machine bit-reproducibility.** The rootless
  build stages files owned by the *build user's* uid/gid, and `mke2fs -d` copies that ownership into
  the image, so an image built by a different user (or from a different checkout path, which can leak
  into the agent binary's debug strings) differs byte-for-byte. `--verify` builds twice as the same
  user from the same path back to back, so it proves the build is deterministic *on this host*, which
  is what catches an accidental non-determinism regression. Cross-host reproducibility (normalize
  ownership to `0:0`, `--remap-path-prefix` the binary) is a separate, tombstoned hardening.

### 008 — Guest networking is deny-by-default: a tap with no route to the world *(2026-07-12, P4.3)*

**Decision.** When Phase 4 gives the guest a NIC, the per-VM tap device defaults to **no route to the
outside world** — host-local reachability only (host↔guest over the tap's own subnet), with any egress
to the wider network being an **explicit, recorded** allowance, never the default. The driver installs
**no** `MASQUERADE`/general-forward rule as part of standing a VM up. Every routing/netfilter rule the
driver *does* install is enumerated in code and recorded (feeding the flight recorder, P4.8), so the
network posture of a running sandbox is auditable from the host. This **resolves the direction of the
queued P4.3 decision** (deny-by-default over NAT-to-world) and makes **P4.3 blocking on P4.1** — the
addressing/tap work lands already denying, not opened-then-restricted.

**Alternatives considered.**
- **Default `MASQUERADE` to give the guest general egress (the "it just works" NAT).** Rejected: it is
  the fastest way to make a P4.7-style "guest reaches an allowed endpoint" test pass, but it opens
  *general* egress and **breaks spine guardrail #4** (deny-by-default). Worse, the real enforcement
  mechanism — host-side eBPF on the tap (Phase 8) — does not exist yet, so a default-open tap would be
  *unenforced* open egress for four phases. Opening later behind an allow-list is a one-way door only
  if we start closed.
- **Wire an allow-list now, in the driver, ahead of eBPF.** Rejected as scope/placement error: policy
  enforcement belongs in host-side eBPF (guardrail #2), not in ad-hoc driver-installed `iptables`
  rules that would then have to be unwound in Phase 8. P4 gives the guest an address and a host-local
  path; P8 is where allow/deny egress policy is *enforced and observed* from the host.

**Why.** Deny-by-default is a spine property, and today it holds only *by construction* — the guest
has no NIC at all (no `/network-interfaces` PUT, no `ip=` boot arg). Phase 4 flips that to "a NIC
exists," and the safe flip is closed-by-default: the guest can talk to its host (enough for the P4
addressing/routing demo) but reaches nothing beyond it until an explicit, host-enforced policy says so.
This keeps the security boundary on the host and out of the guest's reach, and keeps the "every
allowance is recorded" invariant true from the first tap.

**Consequences / tombstones.**
- **The tap is the first per-VM resource that lives *outside* the workdir**, so teardown must delete it
  (and its routes) on every path — a hard requirement carried by P4.1/P4.5, not this decision.
- **P4.7's "reaches an allowed endpoint" is deferred to real enforcement**: until eBPF (P8), "allowed"
  means host-local; world-egress allow-listing is an eBPF-enforced, recorded policy, not a driver NAT
  rule. The bench/demo for P4 proves host↔guest reachability and that the guest reaches *nothing else*.
- **No default masquerade is a standing rule**, not a P4-only stopgap: if a hoster wants NAT egress,
  that is an explicit configured allowance the flight recorder captures, consistent with guardrail #3
  (the hoster's policy, enabled explicitly), never an engine default.

**As shipped.** The addressing/tap work (P4.1/P4.2) implements this directly: the guest's `eth0` is
configured via the kernel `ip=` param with an **empty gateway field**, so the kernel installs only the
connected /30 route and **no default route**, and the driver installs no masquerade and never enables
`ip_forward`. Net effect: the guest reaches its host end of the /30 and nothing else. Proven by the
`addresses_the_guest_and_routes_host_to_guest` integration test, which asserts the guest carries its
address, reaches the host tap IP, and gets a fast `ENETUNREACH` (not a timeout) for an off-subnet
address. So this decision is realized, not just intended.

### 009 — The per-VM tap: shelled out to `ip`, deleted on every teardown path *(2026-07-12, P4.1)*

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
handle and deleting on every path is load-bearing, not incidental (decision 008's tombstone flagged
exactly this). Shelling to `ip` keeps the driver dependency-light and `unsafe`-free.

**Consequences / tombstones.**
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
- **Per-VM network-namespace isolation is deferred, by design.** P4.4's bar is met at L3: with no
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

### 010 — Snapshots are self-contained bundles restored by staging the disk *(2026-07-12, P5.1/P5.2)*

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
  density (many clones over one base), but it needs the source booted `read_only_root`, which needs the
  agent rootfs, which needs vsock to reach its readiness marker, and a vsock/NIC snapshot can't yet
  recreate its host endpoints on restore. So the read-write, private-copy path is the P5.1/P5.2 scope;
  read-only-base warm snapshots are P5.3/P5.4.

**Why.** A self-contained bundle can be moved or kept after the source VM is gone, which is what makes
"snapshot then restore N clones" (P5.4) and a warm pool (P5.6) tractable. The staging trick is the
minimal correct way to honour Firecracker's load-time drive-open contract without a shared mutable
backing file.

**Consequences / tombstones.**
- **Restore is dramatically faster than cold boot:** dev box, ~1.57 s cold vs **~8.9 ms** restore
  (≈177×). This is the fast-start reason the phase exists; the tracked p50/p99 benchmark is P5.7.
- **Snapshotting is scoped to a root-disk-only, read-write boot.** A VM with vsock, a NIC, or an output
  device is a typed error today (its host endpoints can't be recreated on restore yet, P5.4/P5.5), and
  a read-only shared base is deferred (P5.3/P5.4). The guard is structural (the root backing must live
  inside the VM's scratch dir), so it can't silently produce an unrestorable bundle.
- **The restored VM has no exec channel yet.** vsock-over-snapshot (so a restored warm VM can run code)
  is P5.8; today restore exposes liveness + teardown, and `boot_latency()` on a restored VM holds the
  restore latency.
- **Bundle size is state + ~guest-RAM memory + a full root-disk copy.** Copying the whole disk per
  snapshot is the honest cost of a portable, read-write bundle; diff snapshots and base-sharing (density
  over the warm pool) are the P5.3/P5.4/P5.7 optimizations.

**Warm snapshots + concurrent clones (P5.3/P5.4, 2026-07-12).** Extended to snapshot a
`read_only_root` VM carrying the vsock exec channel, and to restore many exec-ready clones from it:
- **The read-only base is referenced, not copied.** A `read_only_root` boot's disk is the shared
  pinned base at a persistent path, so the bundle records it in place (no per-VM copy) and restore
  opens it read-only; N clones share one base (page-cache-deduped density) while each gets its own
  in-RAM overlay from its own restored memory image. The structural test is which side of the scratch
  dir the disk lives on. A read-write boot keeps the copy-and-stage path.
- **Concurrent clones needed a per-clone vsock socket, solved without the jailer.** A first probe
  confirmed empirically that clones restored concurrently **collide** on the socket path baked into the
  snapshot (`Address in use`), because Firecracker re-binds the vsock listener at the recorded path on
  load. Fix: bind vsock at a **relative** name (`v.sock`) and run each VMM with its scratch dir as
  **cwd**, so the recorded relative path resolves per-clone. This is lighter than the Phase-6 jailer's
  per-VM mount namespace and doesn't block the warm pool on it. Consequence: every *file* path handed
  to Firecracker must now be **absolute** (its cwd is no longer the driver's), a small resolve-to-
  absolute pass on kernel/rootfs/bundle paths; the vsock path is the one deliberate exception.
- **Restore waits for exec-readiness.** A just-resumed guest agent needs a moment before its vsock
  listener is reachable again, so restore polls a connect until it succeeds (bounded by the deadline)
  before returning, its analogue of boot's userspace-marker wait. Restore of a warm agent VM measured
  ~8 ms vs ~300 ms cold boot, then the clone runs code.
- **Still deferred:** a snapshot with an **input or output device** is a typed error (per-clone
  images a restore can't yet recreate). A **NIC** is no longer deferred: decision 011 restores
  networked clones with a fresh identity. `ci-privileged` now runs the VM tests serially (they boot
  real microVMs and some assert on host-global leak state).

### 011 — Restore identity: the agent re-addresses the clone; VMGenID reseeds it *(2026-07-12, P5.5)*

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
- **Spine check:** this puts network *configuration* in the guest agent, acceptable because the agent
  is exec/IO convenience (spine #2) and enforcement never moves in-guest: policy stays host-side (the
  route shape today, eBPF at the tap from Phase 11). A guest that tampers with its own address gains
  nothing: the host end of the /30 and the tap it enforces on are outside its reach.
- **MAC is deliberately not changed.** The clone keeps the snapshot's MAC; each clone sits on its own
  point-to-point tap (a separate L2 segment), so MAC uniqueness across taps is irrelevant, and on
  v1.9 only one networked clone can be live at a time anyway.
- A **networked snapshot without vsock is refused** (typed): there would be no channel to re-address
  its clone, which would otherwise wake permanently mis-addressed.

**The v1.9 constraint (probed, not assumed).** `PUT /snapshot/load` on the pinned Firecracker v1.9
rejects `network_overrides` ("unknown field", probed against the real binary), so the snapshot's
recorded `host_dev_name` is fixed: restore must present a tap with **exactly that name**, which the
driver recreates via `Tap::create_named` (a taken name is a typed error, it means the source or an
earlier clone is still alive, and restoring anyway would hijack its link). Consequence: **only one
networked clone can be live at a time** on v1.9. Concurrent networked clones need either a Firecracker
with `network_overrides` (a deliberate version bump, revisiting this decision) or per-VM network
namespaces (the Phase-6 jailer), tombstoned to whichever lands first. Non-networked warm clones keep
their unbounded concurrency (P5.4).

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
mechanism (and the flight recorder timestamps host-side, so the audit trail never depends on guest
clocks). Recorded as a documented limitation the warm-pool docs must carry: code that trusts guest
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

**Consequences / tombstones.**
- `Snapshot` records the tap name; `Tap::create_named` reserves a fixed name with a fresh /30
  (`ip addr add` remains the /30's atomic reservation, as in decision 009).
- The **guest `ip` tool is now load-bearing for restore** (busybox `ip` in the agent rootfs); a future
  rootfs slimming that drops it would break networked restore; the typed error from the identity
  step names the guest's stderr, so the failure is legible.
- **Decision 009 addendum:** boot-time `ip=` is cold-boot-only by nature; restore identity is this
  decision's runtime path. If that runtime path ever proves cleaner for cold boot too, unify then,
  with evidence, not speculatively.

### 012 — Confine the VMM: run Firecracker under its jailer *(2026-07-14, P6.1)*

**Problem.** Hardware isolation (KVM) contains the *guest*, but the *VMM process* still runs on the
host with the driver's privileges. A Firecracker bug, or a guest that breaks out into the VMM, would
land in that context. The jailer is the host-side confinement: a chroot, a uid/gid drop, and a mount
namespace around Firecracker.

**Decision.** An **opt-in** [`BootConfig::jail`] runs Firecracker under Firecracker's `jailer` for a
plain read-write cold boot. Opt-in, not the new default, because the whole FC track was built
unjailed and every existing path (density's shared read-only base, snapshot bundles, the warm pool,
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
  step, alongside snapshot density.
- **`--daemonize`.** Rejected: it redirects stdio to `/dev/null`, which would sever the serial console
  the boot-readiness wait depends on.

**Consequences / tombstones.**
- **A jailed cold boot copies the kernel and rootfs into the chroot per VM** (measured ~4 s for a
  jailed plain-rootfs boot in a privileged container). Density-preserving staging (shared RO base) and
  jailed **snapshot/restore/pool**, **vsock/exec**, **networking**, and **bulk I/O** are later Phase-6
  steps behind this knob.
- **cgroup lifecycle is best-effort here.** Teardown reaps the VMM's (now-empty) cgroup; leak-proof,
  cgroup-**owned** lifetime (host-process death can't leak a VM) is **P6.7**, resource *limits* are
  **P6.2**, and Firecracker's seccomp filters are **P6.3**.
- **The jailer's netns is the sanctioned path to concurrent networked clones** (decisions 009/011's
  tombstone): once networking is jailed, each VM's tap in its own netns removes the one-live-networked-
  clone limit. Kept on the Phase-6 radar.
- **`BootConfig` gained a public field**, but it is not one of the seam-pinned types (`Sandbox`,
  `Limits`, `RunResult`, `VmmError`, the channel wire), and the jailer path is opt-in, so no downstream
  pin bump is forced.
