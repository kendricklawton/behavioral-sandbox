# Roadmap

> **What we're building:** a self-hostable, isolated **code-execution sandbox** — **Firecracker**
> microVMs for hardware isolation, **aya/eBPF** for observability and network policy at the *host*
> boundary (where the guest can't tamper with you). Run untrusted code in a microVM; watch and
> enforce what it does from the kernel, outside the guest.
>
> **Why:** any time you run code you don't fully trust, you want two things at once: strong
> isolation, and a trustworthy account of what it did. This is the self-hostable, embeddable core for
> exactly that: hardware isolation plus a host-observed audit log the code can't forge, run on your
> own infrastructure. **Every phase ships a working demo, so each capability is proven running.**
>
> **The line (an engine, not a PaaS):** we build the **engine**, a runtime you self-host.
> Multi-tenant auth, billing, scheduling across a fleet, a web dashboard: **out of scope**, the
> hoster's job.
>
> **Scope of this repo:** the **core engine** — the Firecracker + eBPF sandbox of **Phases 0–19**,
> defined by the four core properties (§0). The **vNext tracks** (Phases 20–21: the polyglot SDKs
> and the software-isolation Wasmtime sibling) are **adjacent repos** — they build on this engine's
> frozen wire API + audit-log format, but their code lives **outside** this repo and is
> tracked here only as a forward map. This repo never trades its core properties to accommodate them: the
> Wasmtime variant is a *sibling, not a backend* (Phase 21), so *isolation is hardware* holds here
> without exception.
>
> This file is the **single source of truth for progress** — of the core engine, and a map to its
> sibling repos. Its checkboxes are the state.

## §0 The core properties

Four properties every phase must protect:

1. **Isolation is hardware, not software.** Untrusted code runs in a Firecracker microVM (KVM).
   The host trusts the CPU boundary, not the guest.
2. **Observe & enforce from the host.** Visibility and policy live in **host-side eBPF** (syscalls,
   the microVM's tap device, its cgroup) — the guest cannot see or subvert them.
3. **Engine, not platform.** A self-hostable runtime + a clean driver API. No auth/billing/
   dashboard/fleet-scheduler in this repo (note: that's the hoster's).
4. **Measured, not marketed.** Boot time, memory-sharing, and eBPF overhead are benchmarked with
   percentiles, never hand-waved.

## §0.5 How to work this roadmap (the working loop)

- **Sequentially gated.** Never start a phase before the prior phase's **Exit gate** passes.
- **First unchecked box, in ID order.** One item per iteration.
- **Two tracks, one core.** **FC** (Firecracker) and **BPF** (aya/eBPF) can be worked somewhat
  in parallel, but the **Convergence** phases need both, so the gate order still holds.
- **Every phase exits on a demo.** The exit gate is "I can show it running." Design notes are
  recorded in the root `.md` files: the box annotations here + `docs/contributing-architecture.md`'s decision log.
- **Hard-to-reverse choices** (tagged `(decision)`) land as dated entries in `docs/contributing-architecture.md`.
- **Git is human-driven.** The user makes every commit/branch/push; the coding agent's job ends at
  changes made, demo working, box checked in the working tree.

## §0.6 Versioning (the finish line)

- **`v0.1.0` is the finish line** — the first real release, cut only once **every phase below is
  green** (a microVM boots, runs code, is enforced + recorded, self-hostable, documented; this is
  P19.8).
- **The vNext tracks (Phases 20–21) are post-`v0.1.0`** and do **not** gate that tag. The **polyglot
  SDKs** extend the engine outward (more callers) and the **Wasmtime sibling** extends it sideways
  (a second isolation boundary). Both presuppose the frozen wire API of Phase 16;
  neither pulls tenancy/billing/scheduling into scope, and the Wasmtime sibling never dilutes this
  engine's core properties (it's a separate artifact — see Phase 21).
- **Everything until then is a pre-release `v0.0.x`.** Tag the foundation baseline (the engine
  boots and tears down microVMs) as an internal **`v0.0.1`**; later milestones bump the `0.0.x`
  patch as they land. These are checkpoints, not releases — no stability promise.
- Tags are a **human git step** (§0.5): the coding agent checks boxes; the user cuts the tag.
- **No `CHANGELOG.md` until `v0.1.0`.** In the pre-release line the roadmap checkboxes and
  `docs/contributing-architecture.md`'s decision log *are* the change record; a curated
  changelog is written once, for the first real release, rather than churned every `v0.0.x`.

## §0.75 Dev environment (one-time)

A modern Linux box with `/dev/kvm` (the dev machine already has a bleeding-edge kernel + BTF —
ideal for both KVM and CO-RE eBPF). Prerequisites the first phase pins down: the `firecracker`
binary + jailer, a guest kernel (`vmlinux`), a way to build a rootfs, and the aya toolchain
(`bpf-linker`, the `bpfel-unknown-none` target, `CAP_BPF`/root for loading).

---

## Phase 0 — Reset the repo to the sandbox engine

Stand up the Firecracker + aya sandbox engine's workspace and gates; keep the git history.

- [x] **P0.1** (human git step) Start `main` clean for the sandbox engine, preserving the earlier
      tree on an archive branch. *(Done; the prior history is preserved at `f54d353` on
      `origin/main`.)*
- [x] **P0.2** New workspace layout: `crates/vmm` (Firecracker driver), `crates/probes` (aya
      eBPF programs, `no_std`, excluded), `crates/probes-loader` (userspace loader), `crates/cli`
      (`agent`), `xtask`.
- [x] **P0.3** Rewrite `.rules` / `README.md` / `CONTRIBUTING.md` / `docs/contributing-architecture.md` to the
      sandbox-engine identity and the four core properties.
- [x] **P0.4** Prerequisites pinned in `CONTRIBUTING.md` (KVM, BTF, `firecracker`+jailer, aya
      toolchain, caps); `cargo xtask setup` checks the host and reports what's missing.
- [x] **P0.5** `cargo xtask ci` skeleton: fmt · clippy `-D warnings` · build · test · docs · deny
      (the eBPF crate builds for its own target, gated separately — see P8).
- [x] **P0.6** Naming: keep the `agent` umbrella (binary + repo); crates are
      `vmm`/`probes`/`probes-loader`/`cli`.
- [x] **P0.7** A home for the per-phase notes each phase feeds. *(No `CHANGELOG.md`
      in the pre-release `v0.0.x` line — the roadmap's checkboxes are the record; the changelog is
      first written at `v0.1.0`. See §0.6. Design notes live in the root `.md` files: these annotations
      + the decision log, per §0.5.)*
- [x] **P0.8** `cargo xtask ci-privileged` runs the KVM/eBPF (`#[ignore]`d) tests behind a
      `/dev/kvm` guard, so day-to-day dev isn't `sudo cargo` roulette.
- **Exit gate:** `cargo xtask ci` green on an empty-but-scaffolded tree; `xtask setup` verifies the
  host can do KVM + eBPF; docs describe the engine.

---

## Firecracker track — hardware isolation

## Phase 1 — Boot a microVM from Rust

The "hello, KVM" moment: a program that boots a real Linux microVM and reads its console.

- [x] **P1.1** `(decision)` how to drive Firecracker: its **HTTP API over a unix socket** vs the
      `firecracker` binary vs embedding `rust-vmm` crates → `docs/contributing-architecture.md`. (Default: API socket.)
      *(Recorded as decision 001: API socket, hand-rolled HTTP/1.1 over `UnixStream`, `unsafe`-free.)*
- [x] **P1.2** Fetch/pin a guest kernel (`vmlinux`) and a minimal rootfs image for first boot.
      *(Firecracker v1.9 CI artifacts, sha256-pinned; `cargo xtask fetch-artifacts`, gitignored.)*
- [x] **P1.3** `crates/vmm`: start a `firecracker` process with a jailer-free config for dev;
      talk to its API socket.
- [x] **P1.4** Configure the boot source (kernel + boot args) and a root block device via the API.
- [x] **P1.5** Set the machine config (vcpus, mem) and `InstanceStart`.
- [x] **P1.6** Capture the serial console to the host; assert the guest reached userspace.
      *(`login:` marker; reader thread drains stdout before `InstanceStart` to avoid a pipe deadlock.)*
- [x] **P1.7** Clean shutdown + teardown (kill VMM, remove socket/artifacts); no leaks between runs.
      *(Guaranteed teardown in `Drop`; per-VM short scratch dir; boots a rootfs copy, base stays pinned.)*
- [x] **P1.8** A `Vm::boot(config) -> RunningVm` / `RunningVm::shutdown()` API over all of the above.
- [x] **P1.9** Timing: measure and log boot-to-userspace latency (the number that matters).
      *(Dev box, n=10 sequential cold boots: p50 2.6 s, p90 3.4 s, best isolated ~1.2 s; logged
      every run, printed by `--demo-boot`. Excludes driver setup.)*
- [x] **P1.10** Test: boot → see the login/init banner → shut down, repeatable.
      *(`crates/vmm/tests/boot.rs`, `#[ignore]`d; two cycles asserting no leaked scratch dirs.)*
- **Exit gate:** a microVM boots to userspace from `cargo run` and shuts down clean.
  *(Demo: `agent run --demo-boot`, recorded in the box annotations above and decision 001.)*

## Phase 2 — Run code in the guest & get results back

Turn "a VM boots" into "I handed it a command and captured stdout + exit code."

- [x] **P2.1** `(decision)` host↔guest channel: **vsock** vs a serial protocol vs a guest agent →
      `docs/contributing-architecture.md`. (Default: vsock + a tiny guest agent.)
      *(Recorded as decision 002: vsock + a statically-linked guest agent, a versioned
      length-prefixed protocol over Firecracker's vsock UDS; serial kept as a fallback, network/SSH
      rejected to preserve deny-by-default. Agent is exec/IO convenience, never containment.)*
- [x] **P2.2** A minimal **guest init/agent** (statically-linked Rust) that runs a command and
      reports stdout/stderr/exit over the channel.
      *(`crates/guest-agent` + the shared `crates/channel` wire protocol, whose public API is a
      type-state `ClientConnection`/`ServerConnection`. `serve` is transport-agnostic (any
      `Read`+`Write`); it drains the child's pipes to discard-on-forward-error so a dead-or-stalled
      host — **given the connection's read/write deadlines** — is a typed error, not a hang, and it
      maps signal death to `128+sig`. Static build (verified) via `cargo xtask build-guest-agent`;
      unix-socket harness now, vsock transport in P2.3.)*
- [x] **P2.3** Wire vsock in the VMM config; host side connects and speaks the protocol.
      *(`BootConfig.guest_cid` adds a virtio-vsock device via `PUT /vsock`; `RunningVm::connect_agent`
      dials Firecracker's vsock socket, speaks the `CONNECT <port>` handshake (ack read byte-by-byte
      so it can't swallow the guest's channel handshake), sets read/write deadlines, and returns a
      protocol-ready `ClientConnection`. Tested end-to-end KVM-free against the real guest agent
      behind a fake vsock socket; a privileged smoke test confirms real Firecracker boots with the
      device. Full host→guest round trip needs the agent in the rootfs — P3.)*
- [x] **P2.4** `RunningVm::exec(cmd, stdin) -> {stdout, stderr, exit}`.
      *(`exec(argv, stdin)` connects over vsock and speaks the protocol: sends a bounded up-front
      stdin buffer, aggregates stdout/stderr/exit into `RunResult` under a 16 MiB output cap (a
      flooding guest can't grow host memory). Guest agent feeds stdin on its own thread, closing it
      for EOF. `Sandbox` now boots with vsock and wires `exec`. Tested KVM-free (echo + `cat`
      stdin) against the real agent; full in-VM run needs the agent in the rootfs — P3.)*
- [x] **P2.5** Push richer inputs in (injected files) and pull artifacts out — over the channel.
      *(New `PutFile` request + `File` response frames; the agent gives each run a working dir,
      writes injected files in (path-checked against `..`/absolute escapes), runs the command with
      that cwd, and returns the requested `artifacts` — collected into `RunResult.files` under the
      shared output cap. `exec_with_files` is the richer entry; plain `exec` stays. Unknown request
      tags now decode to `Request::Unknown` so the agent replies a typed "unsupported" instead of a
      fatal protocol error (the flagged forward-compat fix). Each file is one `≤1 MiB` frame;
      **streaming/large I/O (chunked, whole working-dir) is the block-device path — P3.4/P3.5**.)*
- [x] **P2.6** Timeouts + kill: a hung command is bounded and reaps cleanly.
      *(Guest-side self-timeout: the host sends a per-exec `timeout_ms`; the agent replaces the
      unbounded `child.wait()` with a deadline-polling `wait_bounded` that SIGKILLs + reaps the
      child past the deadline and replies `Response::TimedOut`, which the host maps to
      `VmmError::Timeout`. Clamped to an agent-side ceiling (a buggy host can't ask for ∞); the
      host's exec read timeout is set longer than the command budget so a quiet-but-running command
      isn't cut off and the `TimedOut` reply arrives. Frees the accept loop for the direct-child
      hang. **Known gap:** `kill` hits only the direct child, so a command that double-forks a
      grandchild holding the stdout pipe still wedges the agent's connection until the grandchild
      exits (the host stays bounded); the definitive fix is the cgroup killing the whole tree — see
      Phase 6. Timeout is the distinct `VmmError::ExecTimeout`; the guest also self-clamps the
      budget. Also folded in the P2.5 review fixes: the output cap counts artifact `path` bytes +
      a per-frame floor (no empty/all-path flood), and an over-cap artifact is skipped, not fatal.)*
- [x] **P2.7** Error taxonomy for the driver (boot failure, channel failure, guest crash) — typed,
      no panics on the host.
      *(`VmmError` already carried the variants; this pass makes the taxonomy **legible** — a doc
      that sorts every variant into three buckets: **boot/infra** (`NoKvm`/`Artifact`/`Timeout`/
      `Vmm`, which also holds vsock **establishment** failures — connect + `CONNECT` ack + channel
      handshake — since "the agent isn't listening yet" is infra), **channel/transport**
      (`Channel`, reserved for a **steady-state** framing/IO fault mid-exec), and **guest fault**
      (`GuestExec`/`ExecTimeout`/`OutputCap`). States the load-bearing semantic: a command that
      merely exits non-zero **or dies by signal** (`128+sig`) is a faithful `RunResult`, not an
      error. No-panic is gate-enforced (`#![forbid(unsafe_code)]` + clippy denies `unwrap`/`expect`
      outside tests). Fixed a real bug: the stale `# Errors` rustdoc on `exec`/`exec_with_files`
      claimed `Vmm` for guest-can't-run/output-cap. Deferred, safe under `#[non_exhaustive]`: a
      `GuestUnavailable` variant (first retry/pre-warmed-pool caller, ~P5) and a `kind()` classifier
      (first caller that branches on bucket).)*
- [x] **P2.8** Test: `exec("echo hi")` → `hi`, exit 0; a crashing command → typed error.
      *(Happy path `exec_over_fake_vsock_runs_a_command` drives `echo hi` through the **real** agent
      → `hi\n`, exit 0. "Crashing → typed error" is disambiguated with two tests that pin the
      boundary: a command the guest can't spawn → `VmmError::GuestExec` (typed error), and
      `kill -9 $$` → `RunResult{exit_code:137}` (a faithful result, **not** an error — the
      host-side mapping, distinct from the guest-agent-layer signal-death test). Added the
      previously-untested channel bucket: a guest that drops mid-exec →
      `VmmError::Channel` with `is_disconnect()`. All KVM-free, in the host gate.)*
- **Exit gate:** `agent`-driven `exec` in a microVM returns real output.
  *(Recorded in the box annotations above and decision 002. The exec **engine** is
  complete and tested against the real guest agent (only the Firecracker vsock UDS is faked) + a privileged vsock-device boot smoke
  test. The **"in a microVM" clause was provisional** here — the agent wasn't baked into the rootfs
  or binding `AF_VSOCK` yet — and is now **closed by P3.1**: the literal in-VM `exec("echo hi") → hi,
  exit 0` runs against a real microVM.)*

## Phase 3 — Rootfs & the language runtime

Build the disk the guest runs, with a real runtime inside, natively. Python is
the exit-gate demo, but the rootfs is **runtime-agnostic**: a real kernel + rootfs runs *any* Linux
binary, so adding a runtime is a packaging step, not an engine change.

- [x] **P3.1** Reproducible **rootfs build**: a minimal ext4 image (busybox/alpine or a scratch
      base) + the guest agent baked in.
      *(`cargo xtask build-rootfs` → `artifacts/rootfs-agent.ext4`: a sha256-pinned Alpine
      minirootfs (`decision 003`) with the static agent baked in at `/usr/local/bin`, a minimal
      busybox-init `/etc/inittab` that mounts the pseudo-fs and respawns the agent on vsock, built
      with `mke2fs -d` — **rootless, no loopback, one command**. To make "agent baked in" real, the
      agent gained its **`AF_VSOCK` listener** (the `vsock` crate; `vsock:<port>` in `main`), and it
      prints the shared `GUEST_READY_MARKER` to the console **after `bind`** so boot-readiness means
      "the agent is accepting" (no connect-before-listen race). **Closes Phase 2's provisional gate:**
      a new privileged test boots this rootfs and runs `exec("echo hi") → hi, exit 0` **inside a real
      microVM** (~3.5 s), wired via `ci-privileged` (which builds the agent + rootfs before the
      `#[ignore]` tests). Additive — the Ubuntu boot rootfs + its hash-guard + the `login:` test are
      untouched. Reproducibility rigor (content hash / byte-identical) is P3.6.)*
- [x] **P3.2** Add the reference language runtime (**Python**) to the rootfs; prove
      `exec("python -c 'print(2+2)')`.
      *(`build-rootfs` now installs `python3` into the staging root with a **sha256-pinned static
      `apk`** (`apk-tools-static`) — still rootless, on any host distro; packages are
      signature-verified against the keys the minirootfs itself ships. `--no-scripts` because
      install scripts need a chroot (root); the in-VM test proves the payload runs. Versions float
      *within* the pinned `v3.24` branch — Alpine branch repos carry only the latest revision per
      package, so an exact `pkg=ver-rN` pin would *break* the build on every upstream patch bump
      rather than reproduce it; **P3.6** instead records the resolved closure in a lockfile and detects
      drift. Image: 33 packages, ~50 MB in the 128 MiB ext4. Proof:
      `execs_python_in_the_microvm` boots the image and `exec("python3 -c 'print(2+2)'") → 4`,
      exit 0, in a real microVM.)*
- [x] **P3.3** Read-only base rootfs + a writable overlay per run (so runs don't mutate the base).
      *(New `BootConfig.read_only_root` (decision 004): attaches the base **read-only and shared**
      (no per-VM copy — Firecracker opens it `O_RDONLY`), and the guest stacks a **per-run tmpfs
      overlay** so `/` is writable but ephemeral. `build-rootfs` bakes `/sbin/overlay-init` (mounts a
      tmpfs, builds overlayfs lower=RO-base/upper=tmpfs, `pivot_root`s, `exec`s the real init) + the
      baked `/overlay` mountpoint (can't `mkdir` on a read-only `/`). Cap = `mem_mib/2` via an
      `overlay_size=` cmdline token the kernel routes into PID 1's env (guests have no swap → a
      near-RAM tmpfs OOMs). Read-only-base **implies** overlay (one flag: a bare read-only `/` would
      break the agent's `/tmp` workdir). **Additive** — set in code (`agent_rootfs_config`), not an
      env var; the stock Ubuntu tests still boot copy+read-write. Proof: `overlay_is_writable_and_base_is_untouched`
      writes to `/etc` in-guest (works via the overlay) and asserts the base file's size+mtime are
      unchanged after two boots; the exec/python tests now run overlay-backed. Memory-sharing: the per-VM
      scratch dir no longer holds a rootfs copy. Second-block-device path stays for P3.4; byte-level
      reproducibility for P3.6.)*
- [x] **P3.4** Inject a per-run working dir / files via a second **block device** (the
      channel path — small per-file injection — already landed in P2.5; this is the whole-working-dir
      / large-file mechanism).
      *(New `BootConfig.input_dir` (decision 005): the driver builds a **read-only** ext4 from a host
      dir (rootless `mke2fs -d`, in the per-VM scratch dir, sized from the tree + `-N` inodes) and
      attaches it as `/dev/vdb` `is_read_only:true`; the agent rootfs mounts it RO at `/input` via a
      best-effort `sysinit` line (baked `/input` mountpoint). Read-**only**, not a read-write working
      dir: RW would front-run P3.5 and its dirty-ext4-on-hard-kill readback problem, and `O_RDONLY`
      makes the input provably immutable. **No guest-agent change** — `/input` is a path the command
      references; the per-exec `/tmp` `RunDir` is untouched. Proof: `injects_a_large_file_via_block_device`
      injects a **4 MiB** file (4× the 1 MiB channel frame cap) and the guest reads it back from
      `/input` with a matching byte count + sha256. New runtime dep (`mke2fs`/`truncate`, typed error
      + `setup` check); boot-path build cost moves behind the pre-warmed pool at P5. Pulling large outputs
      back is P3.5.)*
- [x] **P3.5** Pull artifacts back out at **working-dir / large-file** scale (the per-file channel
      path landed in P2.5; here it's the block-device / bulk mechanism).
      *(New `BootConfig.output_dir` (decision 006): the driver attaches a blank **writable** ext4 as a
      third block device (labelled `agent-output`, `lazy_itable_init=0` so it stays sparse); the guest
      mounts it read-write `-o sync` at `/output`. `RunningVm::collect_outputs` (consumes the VM) stops
      the VMM, then reads the image back **rootless** — `e2fsck -fy` to recover the journal, `debugfs
      rdump` to extract — **after** the VMM has exited (a live `e2fsck` would race Firecracker). The
      counterpart to P2.5's per-frame `Response::File`; **no guest-agent change** — `/output` is a path
      the command writes. Order-robust: both data devices now mount by **label** (`findfs`), retiring
      005's `/dev/vdb` order-dependence — so the P3.4 input mount moved to the same `/sbin/mount-drives`.
      Guest-controlled tree is sanitised: `lost+found` pruned and **host-escaping symlinks dropped**
      (`debugfs` recreates a guest `link -> /etc/shadow` as a live host symlink otherwise), and the
      extraction is byte- and time-capped so a sparse-file image can't exhaust host disk. New runtime
      deps (`e2fsck`/`debugfs`, e2fsprogs; typed error + `setup` check). Proof:
      `collects_outputs_via_block_device` writes a **4 MiB** file (4× the 1 MiB channel frame cap) + a
      nested file + an escaping symlink into `/output`, pulls the tree back with a matching sha256, and
      asserts the escaping symlink and `lost+found` are gone. `Sandbox`/`agent run --output-dir`
      plumbing deferred, as `input_dir`'s was.)*
- [x] **P3.6** Pin the rootfs build in `xtask` so it's one command + reproducible.
      *(`cargo xtask build-rootfs` is now **byte-for-byte deterministic** (decision 007): two builds
      produce an identical `rootfs-agent.ext4`. `SOURCE_DATE_EPOCH` (fixed, scoped to `mke2fs`) stamps
      the superblock times and clamps `-d` file mtimes; `-E hash_seed=<UUID>,lazy_itable_init=0` fixes
      the htree seed + eagerly writes the inode table; apk's wall-clock `/var/log/apk.log` is dropped
      (the last non-obvious source, found by diffing two builds' trees); the musl agent binary was
      already reproducible (`--locked` + pinned toolchain). A committed `xtask/rootfs-packages.lock`
      records the exact 33-package closure; `build-rootfs --verify` (run by `ci-privileged`) builds
      twice, asserts byte-identical, and fails on closure drift, `--update-lock` re-pins. **Exact
      version pinning was rejected** — Alpine branch repos delete old `.apk`s on a bump, so a pin would
      *fail* the build, not reproduce it; the durable fix (vendoring the `.apk` closure as sha-pinned
      artifacts) is deferred. Default `build-rootfs` stays one command.)*
- [x] **P3.7** Size/boot budget: keep the base small; measure its effect on boot time.
      *(**Size budget:** `build-rootfs` reports the base's real footprint (~69 MiB used: Alpine +
      python3 + agent) and **fails past a 96 MiB budget** — a regression guard against accidental
      bloat (Node/Go in P3.9 will raise it + the image size deliberately). **Boot measurement:** new
      `cargo xtask bench-boot [--runs N]` (needs KVM) times boot-to-userspace over N runs on **both**
      the P3.3 read-only shared base *and* a read-write per-VM copy, reporting min/p50/p90/p99/max —
      "measured, not marketed" (percentiles, nearest-rank, no averages). **The finding:** at 69 MiB
      both paths boot in **~0.5 s p50** (copy p50 ~520 ms, shared ~540 ms); the copy is *cheap* (the
      host page cache serves it) so the base size barely moves boot latency, and the shared path's
      slightly higher tail is **overlay-setup** variance, not size. So keeping the base small mainly
      buys **memory-sharing** (page-cache dedup across VMs + disk), not boot time — the honest, measured
      result, not the assumed "bigger base = slower boot." Cold-boot p50/p99 as a tracked benchmark
      is P17.1; the reusable harness is P17.5.)*
- [x] **P3.8** Test: run Python + a small script that writes a file → capture the file.
      *(Privileged `python_script_writes_a_file_and_we_capture_it`: injects a small Python script as a
      file (`PutFile`), runs the **real** interpreter on it in a microVM (`python3 script.py`, using
      the `json` stdlib), and pulls back the `result.json` it wrote — the exec surface's
      inject → run → capture loop end to end with an actual language runtime, not a shell builtin.
      Uses the per-file **channel** path (`exec_with_files`, P2.5); the bulk block-device paths are
      P3.4/P3.5. Asserts the captured file holds what the script computed. 9 privileged tests now.)*
- [x] **P3.9** **Runtime-agnostic proof:** a second, *differently-shaped* runtime runs unchanged
      through the same `exec` path — a **static Go/Rust ELF** (no interpreter, no libc) and **Node**
      (a different interpreter) — showing the rootfs isn't Python-specific and the engine runs any
      Linux binary. (Contrast the Wasmtime sibling, which needs code recompiled to wasm32.)
      *(Two proofs. **Static native ELF:** a fully-static musl Rust binary (`guest-agent`'s
      `examples/writefile`, no `NEEDED`/`PT_INTERP` — verified) is **injected at runtime** on the
      read-only `/input` device (P3.4, exec'd directly — the mount is `-o ro`, not `noexec`), writes
      to the `/output` device, and the file is captured host-side (P3.5) — the engine runs **any**
      binary handed in, no pre-provisioning. **Node:** `nodejs` joins the base (a **baked** interpreter,
      since it's a 44-package closure); a `.js` runs via the channel path and its output is captured,
      like the Python test. Baking Node grew the image ~69→132 MiB, so `ROOTFS_SIZE_MIB` 128→256 and
      the budget 96→160 moved deliberately (P3.7's pre-authorized bump), the lockfile regenerated (44
      pkgs, no npm), and P3.6 determinism re-verified byte-identical. Boot re-measured (n=100 so p99
      is real, not max relabelled): ~380 ms p50, median copy≈shared — doubling the base didn't slow
      boot (page cache serves the copy), reinforcing P3.7; the shared/overlay path carries a heavier
      p99 (~670 vs ~410 ms) from per-run overlay setup, not image size.
      Tests: `runs_a_static_native_binary_and_captures_its_artifact`, `runs_node_a_second_interpreter`
      (11 privileged tests now). **Phase-3 exit gate met:** Python + a native binary + Node all produce
      captured artifacts; the design notes (ext4 `mke2fs -d`, overlayfs, initramfs-vs-rootfs,
      reproducibility, static-vs-dynamic linking, inject-vs-bake) are recorded in these annotations
      and decisions 006/007.)*
- **Exit gate:** real Python **and a static native binary + Node** run in the microVM and
  produce artifacts — the rootfs is runtime-agnostic.

## Phase 4 — Networking

Give the microVM a network with per-VM isolation — the classic tap/bridge setup.

- [x] **P4.1** Create a **tap device** per VM on the host; attach it as virtio-net in the VMM config.
      *(New `BootConfig.enable_network` (decision 009): the driver creates a per-VM host tap by shelling
      out to `ip tuntap` (needs `CAP_NET_ADMIN`, like `/dev/kvm`), names it `fc<hex>` host-globally via
      `ip tuntap add` failing on an already-taken name as the atomic reservation (the `create_workdir` pattern),
      gives it a locally-administered unicast MAC (`02:00:xx:xx:xx:xx`) from a per-VM index, and attaches
      it as `eth0` via a new `PUT /network-interfaces` (a sixth API body struct mirroring `Vsock`). The
      `Tap` handle is threaded through `Spawned`/`RunningVm` (like `vsock_uds`/`output`) and deleted
      (`ip link del`, best-effort) on **all three** teardown paths, since the tap lives outside the
      scratch dir that `remove_dir_all` reclaims (closes the P4.5 leak requirement for the tap itself).
      **Deny-by-default:** the guest gets an *unconfigured* `eth0` (no `ip=` boot arg, no host address,
      no route, no masquerade), so it reaches nothing until addressing (P4.2). The allocator yields name
      + MAC only; subnet + CID are deterministic functions of the same index, grown at P4.2/P4.4/P4.6.
      Proof: `attaches_a_tap_and_the_guest_sees_a_deny_by_default_nic` boots with a NIC and asserts the
      guest's `eth0` carries the LAA MAC and has no default route; `repeated_boots_leave_no_leaks` now
      also asserts no orphaned `fc*` interfaces. Both are `CAP_NET_ADMIN`-gated (skip without it; verified
      under a user+net namespace). New host dep `ip` (iproute2; `setup` check). P4.3's direction was
      settled up front by decision 008.)*
- [x] **P4.2** Address the guest (static or a tiny DHCP) and route host↔guest.
      *(Static, via the kernel `ip=` param — the pinned kernel has `CONFIG_IP_PNP` (verified: the
      `IP-Config:` strings are baked into `vmlinux`), so the guest configures `eth0` before userspace
      with **no rootfs change**. The P4.1 per-VM index now also yields a point-to-point **/30** from
      `10.200.0.0/16` (`subnet_for`: host = block+1, guest = block+2; the index folds the PID bits down
      so two processes both at `NET_SEQ=0` don't pick the same block). `Tap::create` assigns the host
      end (`ip addr add host_ip/30 dev tap`, which installs the connected route so the host reaches the
      guest), and `run_boot` appends `ip=<guest_ip>:::255.255.255.252::eth0:off` — the **empty gateway**
      is the deny-by-default lever: the kernel installs only the connected /30 route, **no default
      route**, so host↔guest works and the guest reaches nothing else. No new `BootConfig` knob (rides
      `enable_network`); `RunningVm::host_ip()`/`guest_ip()` expose the pair. Teardown is unchanged —
      `ip link del` cascades away the address + route. Proof:
      `addresses_the_guest_and_routes_host_to_guest` asserts the guest has its IP, can ping the host
      end, and **cannot** reach an off-subnet address (RFC 5737 TEST-NET-1) — a fast `ENETUNREACH`, not
      a timeout. `CAP_NET_ADMIN`-gated (skips without it; verified under a user+net namespace). Base
      `10.200/16` dodges the common host defaults; making it a hoster knob and per-VM netns isolation
      are P4.3/P4.4.)*
- [x] **P4.3** `(decision)` egress model: **NAT to the world** vs **deny-by-default** →
      `docs/contributing-architecture.md`. (Default: deny-by-default; explicit allow later, enforced in BPF track.)
      *(Direction **pre-recorded as decision 008** (2026-07-12): deny-by-default, tap has no world
      route, no default masquerade until eBPF enforcement (P8) — so this **blocks P4.1** (build denying,
      not opened-then-restricted). Closed here: decision 008 gained an "As shipped" note pinning the
      concrete mechanism (empty `ip=` gateway, so a connected-route-only guest with no default route, no
      masquerade, no `ip_forward`) and citing the `addresses_the_guest_and_routes_host_to_guest` proof.
      Rationale finalized with the P4.1/P4.2 implementation.)*
- [x] **P4.4** Per-VM isolation: one VM cannot reach another's tap.
      *(Two levers, both host-side: with no default route a guest can only address its own connected
      /30 (so it can't even name another VM's tap), and the /30 is now **atomically unique**: the tap
      name was already reserved by create-and-retry, but the 14-bit folded index could still alias, so
      `Tap::create` makes the host-address assignment the reservation (`ip addr add` clash → reclaim the
      tap and retry with a fresh token, clash detected via netlink `host_addr_exists`, not a string
      match). Proven by `two_vms_cannot_reach_each_others_tap`: two concurrent networked VMs get disjoint
      addresses and neither can ping the other's host or guest end (fast `ENETUNREACH`). Per-VM netns is
      deferred to the Phase-6 jailer as defence-in-depth (decision 009). Guest **CID** stays the
      hardcoded `DEFAULT_GUEST_CID`, fine because each VMM has its own vsock socket.)*
- [x] **P4.5** Teardown removes the tap + routes; no orphaned interfaces after many runs.
      *(Delivered across P4.1/P4.2 and finished here: the tap is the first per-VM resource **outside
      `workdir`**, so it's deleted (with its address + connected route, which `ip link del` cascades
      away) in **all three** teardown paths (`RunningVm::drop`, `Spawned::drop`, `Spawned::abort`) — a
      boot that fails *after* tap-create still cleans up. Best-effort (`ip link del` can fail), no
      `Drop`-of-temp-dir safety net, which reinforces the Phase-6 jailer/cgroup ownership model.
      `repeated_boots_leave_no_leaks` now asserts **all three** leak dimensions after two cycles: no
      per-VM scratch dir, no orphaned `fc*` interface, and no orphaned **firecracker VMM process** (the
      new `RunningVm::vmm_pid()` records each VMM's pid; the check keys on that specific pid via
      `/proc/<pid>/comm`, so it's non-flaky under the parallel test harness). Verified under a user+net
      namespace. `vmm_pid()` is also the accessor Phase 6 will use to place the VMM in a cgroup.)*
- [x] **P4.6** Name/track each tap so the eBPF track can bind policy to a specific VM later.
      *(Each VM already owns a host-globally-reserved tap name (`fc<hex>`); P4.6 exposes it as
      `RunningVm::tap_name()`, the handle the Phase-8 loader binds to (resolve name → ifindex via
      `if_nametoindex`, attach `tc`/XDP to *that* sandbox's traffic). Deliberately hands out the name,
      not a stored ifindex: names don't churn if an interface is recreated, and reading ifindex from
      `/sys/class/net` is netns-fragile, so the loader resolves the index at attach. Asserted by the
      P4.1 tap test: `tap_name()` is a live, `fc`-prefixed host interface.)*
- [x] **P4.7** Test: guest can (optionally) reach an allowed host endpoint; cannot reach a blocked one.
      *(`guest_reaches_an_allowed_host_endpoint_but_not_a_blocked_one` proves it at the transport
      layer, not just ICMP: a real `TcpListener` bound on the host tap IP is reachable (the guest's
      python3 `connect` exits 0), while an off-subnet endpoint (RFC 5737 TEST-NET-1) has no route and
      fails. Per decision 008, "allowed" in this phase is host-local; world-egress allow-listing is the
      eBPF-enforced, recorded policy of P8. `have_net_admin()`-gated.)*
- [x] **P4.8** Document the netfilter/routing rules the driver installs.
      *(Enumerated as an audit table: per networked VM the driver runs
      exactly `ip tuntap add` / `ip link set up` / `ip addr add <host>/30` plus the kernel `ip=` guest
      config, and installs **no** default route, **no** `MASQUERADE`/`nat`/`forward` rule, **no**
      `ip_forward`, no bridge, no netns. Teardown is the inverse of one line (`ip link del`). The
      point: the full host-side network change set is small and enumerable, which is what makes
      deny-by-default auditable, cross-referenced from decisions 008/009.)*
- **Exit gate:** a microVM has controlled network.
  *(Done: recorded in decisions 008/009 and the box annotations above: the tap backend (and
  why not a bridge/veth), virtio-net host-tap-to-guest-`eth0`, kernel `ip=`/`CONFIG_IP_PNP` static
  addressing with no rootfs change, the connected-route-is-the-whole-security-model lever with
  NAT/forwarding as the road not taken, the atomic per-VM /30, and the P4.8 audit table. Working
  demo: the three `ci-privileged` network tests.)*

## Phase 5 — Snapshots & pre-warmed start

The fast-start magic: pause, snapshot, and restore — fork many VMs from one pre-warmed image.

> **Design for the Phase-6 jailer now.** Snapshot save/restore takes host paths for the mem file,
> state file, and block devices; under Phase 6's jailer those become chroot-relative and jailed-uid-
> owned. Lay out the snapshot + pre-warmed-pool files **chroot-relative from the start** so the jailer
> doesn't force a rework of this phase. (Ordering is deliberate: snapshots are the motivating
> fast-start capability; jailing is the confinement chore that follows.)

- [x] **P5.1** Pause a booted VM and take a **full snapshot** (memory + state) via the API.
      *(`RunningVm::snapshot(dir)` (decision 010): `PATCH /vm {Paused}` freezes the vCPUs, `PUT
      /snapshot/create {Full}` writes the vCPU/device **state** + full guest **memory**, then `PATCH
      /vm {Resumed}` continues the VM (a create failure still falls through to the resume, so a failed
      snapshot never leaves the guest frozen). The result is a **self-contained bundle**: state + memory
      + a point-in-time **copy of the root disk** taken inside the paused window (so disk and memory
      agree), referencing nothing outside its directory. The API client gained `patch` (Firecracker
      uses `PATCH` for in-place state) and typed bodies for `/vm`, `/snapshot/create`, `/snapshot/load`
      (closed-set enums for the wire discriminants, like `Action`). Scoped to a read-write root boot
      whose backing is a private, disposable copy; a read-only shared base is deferred to the pre-warmed
      snapshot (P5.3/P5.4) and vsock/NIC/output-device snapshots to P5.4/P5.5 (both a typed error now,
      never an unrestorable bundle). Proof: `snapshots_a_running_microvm` boots, snapshots, asserts the
      three bundle files exist (memory ≈ guest RAM), and shuts down clean post-resume.)*
- [x] **P5.2** Restore a VM from a snapshot; measure restore latency vs cold boot.
      *(`Vm::restore(&snapshot, &config)` on a **fresh** VMM (`spawn_fc`, extracted from `launch` and
      shared with the cold-boot path). The load wrinkle that shaped the design: Firecracker opens each
      drive's backing file **at `PUT /snapshot/load`**, from the path baked into the snapshot, *before*
      any `PATCH /drives` could rebase it. So the driver **stages** the bundle's private disk copy at
      that recorded path, loads with `resume_vm:true`, then **unlinks** the staged file once the VMM
      holds the fd: the restored clone gets its own disk inode (shares no writable backing with its
      source, which may be gone) and nothing lingers outside its scratch dir. Guarded against clobbering
      a still-live source's disk. **Measured** (n=1, dev box): cold boot ~1.57 s vs snapshot restore
      **~8.9 ms** (≈177×), the fast-start payoff this phase exists for; the tracked p50/p99 benchmark is
      P5.7. The restored VM has no exec channel wired yet (vsock-over-snapshot is P5.8). Proof:
      `restores_a_snapshot_onto_a_fresh_vmm` snapshots, drops the source entirely (proving the bundle is
      self-contained), restores, and asserts the VMM loads, resumes, and stays alive.)*
- [x] **P5.3** A "pre-warmed" snapshot: boot + runtime loaded (e.g. Python imported), snapshot *that*.
      *(`snapshot()` extended to the two things a pre-warmed snapshot needs (decision 010): a
      **`read_only_root`** boot (the disk is the shared pinned base at a persistent path, so the bundle
      **references it in place**, no per-VM copy) and the **vsock exec channel** (so a restored clone
      can run code). The warm-up runs the runtime once before snapshotting (`python3 -c "import ..."`),
      so the image captures a guest with Python resident, not a bare boot. Restore comes back
      **exec-ready**: Firecracker re-binds the guest agent's vsock listener on load, and `run_restore`
      polls until the agent is reachable before returning (restore's analogue of the boot
      userspace-marker wait). **Measured** (dev box): ~300 ms cold boot vs **~8 ms** restore, then Python
      runs on the clone. Closes P5.8's pre-warmed-restore-runs-code for the single clone. Proof:
      `prewarmed_snapshot_restores_and_runs_code` warms, snapshots, drops the source, restores, and runs
      `python3` to `4`.)*
- [x] **P5.4** Restore N clones from one pre-warmed snapshot; each gets a fresh overlay/tap.
      *(N clones restored from one pre-warmed bundle, **all alive at once**, each an independent VM: its own
      in-RAM overlay (independent memory image) and its own vsock socket, while sharing the read-only
      base (page-cache-deduped memory-sharing). The socket is the hard part, solved without the jailer: a
      first probe showed concurrent clones **collide** on the source's baked-in absolute socket path
      (`Address in use`), so the driver now binds vsock at a **relative** name and runs each VMM with
      its scratch dir as cwd (decision 010), so each clone re-binds its own `v.sock` in its own dir.
      That made every *file* path handed to Firecracker need to be absolute (its cwd moved), a small
      resolved-to-absolute pass. The **"fresh tap"** half is a networked snapshot, still deferred with
      network identity to P5.5. Proof: `restores_concurrent_clones_from_one_prewarmed_snapshot` restores 3
      clones and keeps all three alive at once, asserts distinct live VMMs, and runs a distinct
      computation on each concurrently-alive clone, getting each clone's own answer. `ci-privileged` now runs the VM tests serially
      (real-VM integration is boot-I/O-bound and some assert on host-global leak state).)*
- [x] **P5.5** `(decision)` Handle the uniqueness problems restore creates (network identity,
      entropy, clocks) → `docs/contributing-architecture.md`.
      *(Recorded as **decision 011**, all three implemented-or-measured. **Network identity** (the
      load-bearing one): keep `ip=` as the zero-overhead cold-boot path, and on restore the **guest
      agent applies the clone's fresh address over vsock** (flush the baked-in `eth0` addr, add the
      fresh /30's guest end), the runtime counterpart of boot-time `ip=`, with the empty-gateway
      deny-by-default invariant carried over (config rides the agent; enforcement stays host-side,
      core property 2). MMDS and per-tap DHCP rejected (a second in-guest config surface / a daemon, for what
      the existing exec channel does in one command). The driver recreates the snapshot's recorded tap
      with a fresh /30 (`Tap::create_named`); a networked snapshot without vsock is refused (no channel
      to re-address its clone). **Probed constraint:** Firecracker v1.9 rejects `network_overrides` on
      load ("unknown field", against the real binary), so the tap *name* is baked, so only **one
      networked clone can be live at a time** on this pin; concurrent networked clones need an FC bump
      or the Phase-6 jailer's netns (deferred; non-networked clones keep unbounded concurrency).
      **Entropy:** rely on **VMGenID** (FC v1.9 ships the device and bumps the generation on restore;
      the pinned 6.1.102 kernel's `vmgenid` driver reseeds the CRNG): no engine mechanism added, and
      the property is **proven, not assumed**: two clones' first-window `getrandom` draws differ, and a
      future pin that loses either half fails the test visibly. **Clocks:** kvm-clock keeps monotonic
      sane; the wall clock **lags by the snapshot's age** (measured ~9 s for a ~9 s-old snapshot) and
      the engine deliberately doesn't reach in to fix it (documented limitation; the audit log
      timestamps host-side). Decision 009 gained the "`ip=` is cold-boot-only by nature" addendum.
      Proof: `restored_networked_clone_gets_a_fresh_identity` (fresh /30 applied in-guest, old address
      gone, TCP-reachable on the new link, still deny-by-default, no-vsock refusal) and
      `restored_clones_do_not_share_entropy_or_freeze_the_clock` (urandom draws differ; skew reported).
      21 privileged tests, all run (not skipped) under a user+net namespace.)*
- [x] **P5.6** `Pool` that keeps pre-warmed restores ready so `exec` starts in ms. *(First pre-warmed-pool/retry
      caller: lands the `GuestUnavailable` variant + `kind()` classifier deferred at P2.7, so a
      restore that isn't accepting yet is a typed, retryable error, not an infra failure.)*
      *(`agent_vmm::Pool` (`pool.rs`): prefill `target` clones from one pre-warmed snapshot; `take()` pops
      LIFO stock and **health-probes** each candidate before handing it out (`probe_agent`, a short
      connect+handshake), discarding a clone that died while pooled and serving the next; a dry pool
      **restores inline** rather than failing a take a fresh clone could serve; `refill()` is the
      explicit top-up so the restore cost is paid at the caller's chosen moment. **Synchronous by
      design**: no background threads in the library (the self-refilling pool is the Phase-16
      daemon's job). Measured (dev box): `take()` from ready stock in **~1.1 ms** vs ~650 ms cold
      boot, ~600×: the fast-start payoff, exec-ready. **Closes the P2.7 deferral for real:**
      `VmmError::GuestUnavailable` now types the "nothing listening" establishment failures (vsock
      peer-closed-before-ack, refused port, a dead VMM's stale socket refusing connect), bucketed
      `Infra` in `kind()` (the pinned bucket test grew its row); the pool consumes it as the
      discard-and-retry signal. Networked snapshots pool at `target <= 1` (decision 011's tap-name
      limit; the typed error surfaces on deeper prefill). Proof:
      `pool_serves_prewarmed_clones_and_discards_dead_ones`: prefill 2, timed take + exec, SIGKILL a
      pooled clone's VMM behind the pool's back, next take discards the corpse and serves a fresh
      restore, refill tops back to target. 22 privileged tests.)*
- [x] **P5.7** Benchmark: cold boot vs snapshot restore vs pre-warmed-pool `exec` latency. *(Baseline
      to beat: Phase 1 boots a full rootfs copy in `/tmp` — on a tmpfs host that's ≈300 MB of RAM
      per sandbox on top of guest memory; overlays should collapse that.)*
      *(`cargo xtask bench-warm [--runs N]`: **time-to-first-result** (start a sandbox → a Python
      one-liner's output back on the host) on the three start paths, reusing `bench-boot`'s honest
      percentile reporting (nearest-rank, no `p99` under n=100); every sample verifies the answer
      actually came back, and teardown/pool-refill run off the clock (the between-requests cost).
      One pre-warmed snapshot feeds the restore and pool paths. Measured (dev box, n=100 per path): cold
      boot + exec on a per-VM rootfs copy (the Phase-1-style baseline) **p50 689 / p99 943 ms**;
      pre-warmed restore + exec **p50 105 / p99 172 ms**; pool take + exec **p50 45 / p99 90 ms**: ~6.6x
      and ~15x at p50, and most of the remaining pre-warmed-path time is Python itself, not the engine.
      The footprint baseline falls too: the cold path copies the 132 MiB image per VM, a pre-warmed clone
      copies nothing (the shared read-only base is referenced in place and the bundle's one 256 MiB
      memory file is mapped by every clone, both page-cache-shared; a clone's private cost is its
      copy-on-write dirty pages).)*
- [x] **P5.8** Test: restore a pre-warmed Python snapshot, run code, get output in ≪ cold-boot time.
      *(`prewarmed_restore_returns_output_in_far_under_cold_boot`: warms + snapshots a Python source,
      then times restore → exec → output-verified on a fresh clone and asserts it lands with at
      least a **2x margin under the source's cold-boot latency**: a generous bound against the
      measured ~6.6x, and `cold_boot` itself understates the cold path, which pays boot *plus* the
      same exec (one observed run: 85 ms to output vs a 367 ms cold boot). The phase's payoff is
      now asserted in `ci-privileged`, not just printed by the bench. 23 privileged tests.)*
- **Exit gate:** pre-warmed restores make runs start in ms.
  *(Done: recorded in decisions 010/011 and the box annotations above: what a snapshot is
  (vCPU/device state + the guest-memory file, disk copied in the paused window), how clones share
  memory through a copy-on-write mmap and the page cache, the stage-then-unlink disk contract and
  the relative-vsock cwd trick, and the three restore fix-ups (agent-applied network identity, the
  VMGenID entropy reseed proven by test, the documented wall-clock lag). Working demo:
  `cargo xtask bench-warm` plus the eight snapshot/restore/pool tests in `ci-privileged`.)*

## Phase 6 — Confinement: jailer, cgroups, seccomp

Confine the VMM itself — the other half of the isolation story, and pure Linux internals.

- [x] **P6.1** Run Firecracker under its **jailer** (chroot, uid/gid drop, namespaces).
      *(New opt-in `BootConfig.jail` (decision 012): the driver spawns Firecracker's `jailer`, which
      builds a chroot at `<scratch>/firecracker/<id>/root`, `mknod`s the device nodes, places the VMM
      in a cgroup, drops to a configurable uid/gid, and `exec`s Firecracker inside the mount namespace.
      The kernel + a read-write rootfs copy are **staged into the chroot after the API socket is up**
      (so no race with the jailer's construction) and named by their chroot-relative path, `chown`ed to
      the jailed uid; the socket is the chroot's `run/firecracker.socket`. No `--daemonize`, so the
      serial console still reaches the host. The jailer's cgroup is learned from `/proc/<pid>/cgroup`
      and removed on teardown; the chroot rides inside the scratch dir that `remove_dir_all` reclaims.
      **Opt-in** so the 23 unjailed tests and the memory-sharing/snapshot paths are untouched; scoped to a
      **plain read-write cold boot** (jail + vsock/NIC/overlay/bulk-I/O is a typed error, snapshot of a
      jailed VM is refused: all later Phase-6 steps). **Needs real root** — the jailer's `mknod`
      `EPERM`s in a non-initial userns, so the `unshare -Urn` trick can't run it; `boots_under_the_jailer`
      gates on real root and skips otherwise. Proof: the full privileged suite (now **24 tests**) passes
      as real root in a privileged container, jailed boot ~4 s. Leak-proof cgroup-**owned** teardown
      (host death can't leak a VM) is P6.7.)*
- [x] **P6.2** Put each VMM in its own **cgroup**; set CPU/memory limits.
      *(The jailer already puts each VMM in its own cgroup (P6.1); this sets the limits. The driver
      derives them from the guest's own envelope and passes them via the jailer's `--cgroup`:
      `cpu.max` caps total CPU at exactly `vcpus` cores (`vcpus × 100ms` quota per 100ms period), and
      `memory.max` at the guest RAM plus a fixed 128 MiB host-side overhead. A 256 MiB guest booting to
      userspace was **measured** at ~82 MiB (guests touch little of their RAM, and the rootfs page cache
      above guest RAM is reclaimable), so the cap never OOMs a legitimate boot while still bounding a
      runaway. Requires the cgroup v2 `cpu`+`memory` controllers delegated to the cgroup root (a systemd
      host does this out of the box); where they aren't, the driver detects it, warns, and boots
      **without** limits rather than failing (passing `--cgroup` would otherwise make the jailer fail).
      Proof: `boots_under_the_jailer` asserts the VMM's cgroup carries a finite `memory.max` in the
      guest-RAM-plus-overhead band and a `cpu.max` of exactly `vcpus` cores. These are hard cgroup
      limits the kernel enforces by construction; the adversarial mem-hog / fork-bomb "host
      unaffected" proof (a guest actually held to them under load) is P6.8.)*
- [x] **P6.3** Apply Firecracker's **seccomp** filters; understand what syscalls it needs.
      *(Firecracker installs its built-in per-thread seccomp filters by default (the "advanced" level:
      a curated syscall allowlist per thread category — API, VMM, vCPU — with a `SIGSYS` kill on
      anything else). We simply never pass `--no-seccomp`, so every boot (jailed or not) is filtered.
      The filters install at `InstanceStart`: the idle pre-boot process shows `Seccomp: 0`, but a
      running VM shows `Seccomp: 2` (filter mode) on **every** thread, **verified** by probing
      `/proc/<pid>/task/*/status` (`firecracker`, `fc_api`, `fc_vcpu`). Note: the API thread needs
      a broader set to configure the VM, the vCPU threads a narrow KVM-ioctl-centric set, and the filter
      is the last line if the guest breaks into the VMM. Proof: `boots_under_the_jailer` asserts the
      running VMM is in seccomp filter mode (`Seccomp: 2`).)*
- [x] **P6.4** Resource caps enforced: a VM can't exceed its cgroup memory/CPU. *(Two halves.
      **Memory/CPU** are the host VMM cgroup from P6.2 (`memory.max`/`cpu.max` on the jailed VMM):
      cgroup v2 enforces them by construction, so a guest can't push the VMM past them (the
      adversarial mem-hog / fork-bomb "host unaffected" proof is P6.8). **Process-tree reaping closes
      the P2.6 gap** and is the concrete new code: the guest agent now runs each command in its **own
      guest cgroup** (a `cgroup2` mount added to the rootfs init) and reaps the **whole tree** with
      `cgroup.kill` after the command exits or times out. cgroup membership is inherited by every fork
      and can't be escaped by `setsid`, so a double-forked grandchild or daemon that inherited the
      stdout/stderr pipe is killed rather than left holding it open — which is exactly what used to
      wedge the agent's exec connection (the output pumps never saw EOF), on **both** the exit and
      timeout paths. `cgroup.kill` is what a direct-child `kill` and even a `killpg` (a `setsid`
      daemon escapes the process group) miss. Best-effort: a guest without cgroup v2 falls back to the
      old direct-child kill. Proof: `reaps_the_whole_process_tree_so_a_daemon_cannot_wedge_exec` runs
      a `fork`→`setsid`→`exec sleep 30` daemon that inherits stdout while its parent exits 0; the exec
      returns in well under the daemon's lifetime with exit 0, and no `sleep` survives in the guest.
      Full privileged suite now **25 tests**, green.)*
- [x] **P6.5** `(decision)` per-run resource policy shape (the knobs the engine exposes) →
      `docs/contributing-architecture.md`. *(Decision 013: the per-run policy is the one already-public, API-pinned
      `Limits` struct carrying **quantities** (`vcpus` → guest vCPUs + `cpu.max`; `mem_mib` → guest RAM
      + `memory.max`; `wall` → boot deadline today, exec budget in P7.3) plus the exec **output cap**
      (P7.3), never capabilities: network egress stays a separate eBPF-enforced concern (decision 008),
      not a `Limits` field. Enforced at the **host VMM cgroup** (one choke point for guest + VMM), not
      per-exec. **Fails open, recorded:** missing cgroup delegation logs a warning and boots uncapped,
      because resource caps are DoS mitigation, not the isolation boundary (which never degrades: a jail
      that can't be built is a hard error). Defaults stay a conservative, `api:`-marked floor. So P7.3
      is wiring, not design: no new type, no new enforcement point. A strict `require_limits` fail-closed
      toggle is deferred for P7.3.)*
- [x] **P6.6** Verify isolation: a hostile guest + a hostile-ish workload can't escape the jail.
      *(Two proofs. **The confinement is in force, read off the live VMM:** `boots_under_the_jailer` now
      asserts the running Firecracker is **chrooted** (its root's `(st_dev, st_ino)` differs from the
      host root's; the `/proc/<pid>/root` link *text* renders as `/` after the jailer's pivot_root, so
      identity is checked, not path), runs as the **dropped uid** (not root), holds **no effective capabilities**
      (`CapEff` all zeros), runs under **`no_new_privs`** and **seccomp filter mode**, and lives in its
      **own mount namespace** (on top of the existing cgroup-cap asserts). Layered with KVM this is the
      second wall: a guest that breached hardware isolation into the VMM lands in that box, naming no host
      path, holding no capability, making no out-of-filter syscall. **No half-confined escape hatch:**
      `Vm::boot` refuses `jail` + any not-yet-jailed feature (NIC, overlay, bulk I/O) with a typed
      error *before* the KVM probe, so the refusal is host-safe: a `jail_refuses_half_confined_boots`
      unit test runs in the everyday gate (the isolation boundary never half-degrades, decision 013).
      Running a hostile workload *inside* a jailed guest is now possible (P7.0a composed the jail with
      the vsock exec channel, `jailed_exec_runs_a_command`); at the time this box landed that waited on
      exec-under-jail, so the bar here was the VMM-side confinement layers plus the refusal.)*
- [x] **P6.7** Clean cgroup/namespace teardown per run — and the leak-proofing this buys:
      **host-process death (Ctrl-C, SIGKILL, OOM) cannot leak a VM**, because the cgroup owns its
      lifetime from outside the driver. (Until here, teardown is `Drop`-based: killing the driver
      mid-run leaks the VMM — a signal handler would only paper over SIGINT, so we wait for the
      real mechanism.) *(**Embedder kill handle:** expose a cheap, cloneable **cancellation token**
      that forces VM teardown from outside a blocked `exec` (the host-gave-up path, since
      `Sandbox::exec` borrows `&self` and `shutdown` consumes `self`, so a blocking caller can't
      currently stop a wedged run). It gets real teeth here: cgroup-owned lifetime makes a forced kill
      leak-free even if the embedder's own thread is wedged. The settable exec deadline (P7.3) covers
      the common timeout case; the token covers the host-abandons-the-run case. Surfaced on `Sandbox`
      in P7.)*
      *(Decision 014, crash-only design. **Namespaces need no explicit teardown**: the jailer's mount
      namespace (and every namespace a VMM holds) is reclaimed by the kernel with its last member
      process, so killing the VM's cgroup *is* the namespace cleanup; cgroup dirs are the one part the
      kernel won't reap for us. So: every directly-spawned VMM (cold boots, restores, pre-warmed-pool
      clones) is enrolled at spawn in a per-VM **lifetime cgroup** under the driver's own cgroup (no
      controllers, so no delegation needed), and a per-VM **sentinel** — a `sh` child in its own process
      group, blocked reading a pipe only the driver holds — wakes on the EOF the kernel delivers at
      *any* driver death, `cgroup.kill`s the VM's cgroup(s), and removes them; a jailed VMM's sentinel
      watches the jailer's precomputed cgroup instead (enrolling would race the jailer's own placement).
      Clean teardown removes the cgroup first, so the disarmed sentinel wakes to nothing and exits.
      The **`KillHandle`** (public on `RunningVm`; `Sandbox` in P7) kills through the same `cgroup.kill`
      file — cloneable, `Send + Sync`, no `unsafe` — with a pid fallback for cgroup-less hosts and a
      torn-down flag set before the reap so a late kill can't signal a recycled pid. **Proof:** the
      sentinel mechanism is unit-tested in the host gate (EOF → kill written, disarm → no action);
      `driver_death_cannot_leak_a_vm` SIGKILLs a real subprocess driver mid-run and the VMM dies + its
      cgroup vanishes in ~1 s; `kill_handle_unblocks_a_wedged_exec` frees a thread blocked in a 30 s
      exec in ~2 s. Degradations recorded, not hidden: no writable cgroup v2 → warn + Drop-only teardown;
      the spawn→enrollment window (μs) and a crashed driver's inert scratch/tap residue are documented
      notes, not claims.)*
- [x] **P6.8** Test: a fork-bomb / mem-hog in the guest is bounded by the cgroup, host unaffected.
      *(Both run against the exec-capable agent rootfs with the VMM under the **engine-derived** caps
      (`cpu.max` = vcpus cores, `memory.max` = guest RAM + 128 MiB — the P6.2 derivation, pinned by the
      test since exec-under-jail was then a later migration, P7.0a/decision 015; real-root + delegation gated,
      skips elsewhere).
      **Mem-hog** (Python allocating touched pages until the guest dies): the guest's *own* OOM killer
      eats the hog (exit 137) inside the hardware boundary; the host cgroup **measured** peaking at
      ~208 MiB against the 384 MiB cap, zero host-side `oom_kill` events (the 128 MiB overhead budget
      held under worst-case load), and the VM stays exec-responsive. **Fork storm** (100 spinning
      background shells for 3 s, deliberately bounded so the run is measurable — the unbounded classic
      would starve the guest agent, a guest-availability non-goal): the VMM's host thread count stays
      **4 → 4** (guest processes don't exist on the host: the hardware-isolation property, observed) and
      the storm burned 3.79 s of host CPU against a 5.85 s quota-derived bound; the orphaned spinners
      are then reaped by P6.4's tree kill and a follow-up exec answers immediately. **The adversarial
      test earned its keep:** the storm exposed a real P6.4 race — the agent's parent-side
      `cgroup.procs` write landed *after* the already-running command's first forks (on 1 vCPU the
      child usually runs first), so pre-write forks escaped `cgroup.kill` and re-wedged the exec
      connection. Fixed by a `sh` **trampoline**: the child enrolls *itself* in the cgroup, then
      `exec`s the real command (same pid; argv passed as argv, never interpolated), making
      enrollment-before-first-fork structural rather than lucky; the agent pre-resolves the program so
      "no such binary" stays the typed `GuestExec` error. Full privileged suite now **30 tests**,
      green; rootfs rebuilt, still byte-reproducible.)*
- **Exit gate:** the VMM runs jailed + cgroup-limited (namespaces, cgroups v2, seccomp, and
  capabilities: the container-isolation primitives, via Firecracker).

## Phase 6.9 — Field robustness (interphase: the engine survives long-lived hosts)

An audit of Phases 0–6 found failure modes that live in none of the feature phases: residue that
accumulates across embedder crashes until a *healthy* host refuses work, and dependency drift that
fails cryptically instead of legibly. This is core **runtime** work, not platform creep: the
garbage collection and dependency-version validation any long-running runtime owes a host, the
boring janitorial contract for a host that stays up for months. It lands **before**
Phase 7 because the sweep and the guards become part of the operational contract the `Sandbox`
surface freezes.

- [x] **P6.9a** Orphan sweep (the runtime's GC). Decision 014 leaves a crashed driver's scratch dirs
      and taps as residue for "a sweep" that nothing owns — and the tap half is **not** inert: an
      orphaned `fc*` interface still holds its `/30` host-address reservation (the allocator's
      atomicity, decision 009), so accumulated crashes clog the finite `10.200/16` pool until the
      allocator's bounded retry exhausts and **every networked boot on a healthy host fails**. Land a
      library sweep (public on the engine surface; `agent sweep` CLI wiring rides P7.4): enumerate
      `fc*` interfaces and per-VM scratch dirs, reclaim only those whose owning driver is **dead**
      (liveness keyed on the recorded pid via `/proc/<pid>` + comm, the same key the leak test uses)
      — never a live sibling's resources (safe by ownership check, not locks). Caller-owned snapshot
      bundle dirs are out of scope (the caller chose where to put them). **Exit:** SIGKILL a driver
      mid-networked-run, sweep, and the tap + scratch dir are reclaimed while a concurrently *live*
      VM's are untouched; the allocator stays healthy across a crash loop.
      *(`agent_vmm::sweep_orphans(scratch_base) -> SweepReport` (`sweep.rs`). **Ownership is the
      dir, never the tap name:** the driver records the tap into its scratch dir (`<workdir>/tap`)
      at creation — the name itself lies about ownership, since a restored clone's tap carries the
      possibly-dead *source's* token (decision 011) — and the dir's `agent-<pid>-<n>` name carries
      the owner. Deliberately no comm check on the driver pid: the embedder's process name is
      unknowable, so a recycled pid reads as alive and its dir is *kept* (the error direction is
      always retained-too-long, reclaimed by a later sweep, never a live VM's resources). Four
      conservative guards: only dirs **owned by the sweeping euid** are candidates at all — the
      scratch base is world-writable, so an unowned candidate set would be an attacker-writable
      kill list (a hostile local user plants a dead-looking dir whose record names a victim's
      live tap); `create_workdir`'s `0700` driver-owned dirs make ownership the authorship proof,
      at the deliberate cost that each uid sweeps only its own residue. Then: a live pid's dirs
      are skipped wholesale; a dead dir's recorded tap is left if any *live* dir records the same
      name; and a dead dir with a still-running VMM (the degraded-sentinel corner) is skipped
      loudly — the sweep owns fs/net residue, processes stay the sentinel's (decision 014), it
      never kills. The record is validated before it can reach
      `ip link del` (`fc`+hex, ≤ IFNAMSIZ-1; parse, don't trust), VMM-liveness is `(st_dev,
      st_ino)` identity through `/proc/<pid>/cwd` (the P6.6 finding: link text lies after
      pivot_root; unjailed cwd = workdir, jailed cwd = the chroot root), and per-entry failures
      warn + continue (one undeletable dir can't shadow the sweep). Proof:
      `sweep_reclaims_a_crashed_drivers_tap_and_scratch_dir` SIGKILLs a subprocess driver
      mid-networked-run and the sweep reclaims its tap + dir while a concurrently-live VM's stay
      untouched and functional; `driver_death_cannot_leak_a_vm` now dogfoods the sweep for its
      post-crash cleanup; the ownership/validation rules are unit-tested in the host gate. 32
      privileged tests.)*
- [x] **P6.9b** Dependency guards: make the pins legible. Decision 001 pins the driver to
      Firecracker v1.9's API schema, but nothing checks the binary: a v1.13 on `PATH` fails
      mid-boot with cryptic API errors (or silently different semantics — the class of drift the
      `network_overrides` probe proved is real). Probe `firecracker --version` in `xtask setup`
      **and** once per driver process at first spawn: an unexpected major/minor logs a loud, typed
      warning naming the pin (warn, not refuse — an embedder may knowingly run a compatible build).
      Alongside it, `setup` reports the host-kernel features the engine degrades on (`cgroup.kill`
      needs ≥ 5.14; BTF and delegation are already checked) and prints the **degradation matrix** in
      one place: what fails open with a warning (resource caps, sentinel teardown, decision 013/014)
      vs what hard-errors (the jail, KVM). **Exit:** `setup` on a mismatched host names every
      degradation before the first boot does.
      *(Both halves. **Driver:** `warn_on_unpinned_firecracker` (`spawn.rs`) probes the configured
      binary once per process (`std::sync::Once` — the pin is process-wide, the probe costs a child
      spawn) at the head of `launch` and `launch_for_restore`, covering cold, jailed, and restore
      paths; a non-1.9 major/minor or an unparseable banner is a loud `tracing::warn!` naming the
      pin and decision 001, and a *missing* binary stays silent there because the spawn itself fails
      typed and legible moments later. Warn-not-refuse per the box (a knowingly-compatible build is
      the embedder's call). **Setup:** two new checklist lines — the pinned-v1.9 probe and
      `kernel >= 5.14` (`cgroup.kill`, from `/proc/sys/kernel/osrelease`) — plus the printed
      degradation matrix splitting fail-open (delegation → uncapped jailed VMs; unwritable cgroup2 →
      Drop-only teardown; pre-5.14 → no sentinel kill; unpinned FC → warned boots) from hard-error
      (no KVM, an unbuildable jail, missing host tools), the decision-013 line rendered as one
      screen. Parse is shared-shape (`Firecracker vX.Y`), unit-tested against real and garbage
      banners.)*
- [x] **P6.9c** The per-sandbox fd budget, measured and stated. Each live VM holds several host fds
      (child pipes, vsock UDS, the clones' mmap'd memory file, an API-socket connection per request);
      at the default 1024 soft `ulimit -n`, a few hundred concurrent VMs hit `EMFILE` mid-boot in
      whatever syscall lands first — typed, but illegible. Measure the footprint per start path
      (cold, pre-warmed clone, networked), document it as the budget P7.6's pool bound must respect
      (`pool_target × fds_per_vm < ulimit`, with headroom), and pin it with a test so it can't
      silently grow. No new mechanism: this is a number, stated honestly (core property 4).
      *(**Measured: 2 fds per live VM, on all three start paths** (cold, networked, pre-warmed restore;
      dev box) — the console reader's pipe and the lifetime sentinel's pipe write end; the mmap'd
      memory file and the API/vsock connections turn out to be Firecracker's fds or transient, not
      held by the driver. Published as `agent_vmm::FDS_PER_VM = 8` (budget deliberately above the
      measurement so an fd added for cause is a visible constant bump, never silent growth), with
      the sizing rule on the `Pool` doc: `target × FDS_PER_VM` under `ulimit -n` with headroom.
      Pinned by `fd_footprint_per_vm_stays_within_budget_and_never_leaks`, which also asserts the
      other half — **teardown returns to the exact fd baseline** on every path, since a per-run
      leak would walk a long-lived embedder into `EMFILE` regardless of the per-VM number. 33
      privileged tests.)*
- [x] **P6.9d** Record the un-vendored upstream inputs as a note. A fresh host's
      `fetch-artifacts`/`build-rootfs` depend on the Firecracker CI S3 bucket and the Alpine CDN:
      sha256-pinned (tamper-safe) but **availability-fragile** — a deleted bucket bricks new-host
      setup while existing artifact dirs keep working. Record the failure mode + the vendoring plan
      (decision 007 already notes the `.apk` closure half; this adds the kernel/base-image
      half), pointing at P19.1 where vendored artifacts ride the packaging work. Docs only.
      *(Recorded as a decision-007 consequence bullet: the kernel/base-image half joins the `.apk`
      half in the same availability class — loud failure (hash-checked fetches never silently
      substitute), fresh-host-only blast radius, vendored as release artifacts at P19.1 where the
      self-host bundle needs them offline anyway.)*
- **Exit gate:** a crash-looped host stays serviceable (sweep demo) and a mismatched host
  explains itself (`setup` demo).
  *(Done. Demos: `sweep_reclaims_a_crashed_drivers_tap_and_scratch_dir` (a real SIGKILLed driver,
  its tap + dir reclaimed, a live sibling spared and still functional) and `cargo xtask setup`
  (version/kernel checks + the printed degradation matrix). The rationale is recorded in the box
  annotations above: GC is core runtime behavior because *not all residue is inert* — a scratch
  dir merely holds disk, but an orphaned tap holds a **reservation** out of a finite pool, so
  accumulation becomes denial-of-service against future work on a healthy host; and ownership
  must key on **liveness** (the dir's embedded pid), never on resource names, because names can
  outlive and betray their creators (a restored clone's tap carries the dead source's token).
  Full suite: host gate + 33 privileged tests, green.)*

## Phase 7 — The sandbox lifecycle API (the engine surface)

Wrap the FC track into a clean, self-hostable engine API.

> **Downstream public API (a real embedder pins `vmm` by git rev).** This phase lands the embedder-driven
> public API capabilities, each with the embedder's acceptance criteria as its exit gate: per-exec **inputs**
> (files + `env`) with a **secret-hygiene contract** (P7.1), the exec **wall-clock and output-cap
> budgets as knobs** (P7.3), and a **kill handle** for the host-gave-up path (P6.7, surfaced on
> `Sandbox` here). Every addition stays a generic library capability (engine, not platform): nothing
> below knows who embeds it. `VmmError::kind()` (the bucket classifier) and the conservative,
> documented `Limits::default()` contract already landed as out-of-band public API hardening.

> **Jailed exec is a prerequisite (decision 015).** Phase 6 landed the jailer on a *codeless* boot: a
> jailed VM refuses vsock/NIC/overlay/bulk-I/O (decisions 012/013), so today you get a code channel
> **or** VMM confinement, never both. Before the `Sandbox` surface freezes on the unjailed exec path,
> the convergence below composes the jail with the exec channel, and `Sandbox::exec` jails by default.

- [x] **P7.0a** Stage the vsock exec channel into the chroot (jailed-uid-owned, socket path
      chroot-relative) so `jail` composes with vsock. Proof: a real-root `jailed_exec_runs_a_command`
      boots jailed and returns `exec("echo hi") -> hi`, exit 0. Retires the P6.6 "exec-under-jail is a
      later migration" annotation.
      *(Done. `Vm::boot` no longer refuses `jail` + `guest_cid`: under the jailer Firecracker binds
      the vsock unix socket at the chroot-relative `/run/v.sock` (cwd = chroot root, `/run` writable by
      the dropped uid, and that path is shorter than the API socket already bounds-checked, so no
      extra `check_sun_path`); the host dials the same file at its absolute path under the chroot.
      `launch_jailed` sets `vsock_uds` when `guest_cid` is set, `run_boot` picks the jailed vs scratch
      relative socket name by whether a chroot is present, and the deny-by-default refusal still hard-
      errors on a NIC / overlay / bulk I/O under the jail (isolation never half-degrades, decision
      013). The `jailed_exec_runs_a_command` test asserts the exec'ing VMM runs as the dropped jail
      uid, so it proves confinement + code together, not a plain boot that happens to exec. The
      still-full-rootfs-copy under the jail is P7.0b's memory-sharing concern, not a correctness gap here.)*
- [x] **P7.0b** Jailed overlay: read-only base + per-run tmpfs overlay under the chroot, so a jailed
      boot runs on the shared-base path, not a full rootfs copy.
      *(Done. `Vm::boot` no longer refuses `jail` + `read_only_root`. The overlay itself runs
      guest-side (`overlay-init` over the virtio-blk root), so the host change is the staging: a
      `read_only_root` jailed boot **bind-mounts** the shared base into the chroot (`stage_ro_base_into_chroot`)
      instead of copying it, so every jailed VM shares the base's inode and page cache, exactly like
      the unjailed shared-base path. The bind mount is made in the host mount namespace; the jailer runs
      the VMM in an `MS_SLAVE` namespace, so a mount under a **shared** host mount propagates in
      (verified: `/` and `/tmp` are `shared`, and a post-unshare bind mount reaches a slave child).
      When the scratch dir isn't a shared mount (a hoster pointed it at a private mount, so
      propagation can't reach the jailer) it falls back to a read-only **copy**: correct and
      base-immutable, just not page-cache-deduped (memory-sharing is best-effort, isolation is not,
      decision 013/014). The bind mount adds a teardown duty: a bind-mounted file `EBUSY`s
      `remove_dir_all`, so `teardown`/`abort` unmount it (lazy) before reclaiming the scratch dir, and
      the orphan sweep detaches any mount under a dead driver's dir first. Proof:
      `jailed_overlay_is_dense_and_base_is_untouched` (real-root gated) asserts the chroot base is a
      read-only mount sharing the base's very inode (a bind mount, not a 256 MiB copy), the guest can
      write a normally-read-only path via the overlay, the base file is byte-for-byte untouched, and
      teardown left no mount behind. The `shared:`-tag parser has CI-safe unit tests.)*
- [x] **P7.0c** Jailed networking: stage the tap into the VM's netns under the jailer; retire the
      one-live-networked-clone limit (decisions 009/011 note).
      *(Done, as the per-VM network-namespace model, decision 017 — supersedes the 009/011 netns
      notes. Every networked VM now runs its tap in its **own netns** (`ip netns add`, named after
      the scratch dir): the jailer joins it via `--netns` (it `setns`es as root before dropping
      privileges), a direct boot via `ip netns exec <ns> firecracker` (the child pid is firecracker).
      The jailed tap is created `user`/`group`-owned by the jailed uid, since a jailed Firecracker holds
      no `CAP_NET_ADMIN` and can only attach a tap it owns. Because the tap is namespaced, the whole
      host-global allocator collapses to a **fixed** name/MAC/`/30` (`fc0` / `10.200.0.1`/`.2`), and the
      **one-live-clone limit is retired**: N clones recreate the same baked-in tap name in their own
      netns, the baked-in guest identity is already correct there, so restore no longer re-addresses the
      guest (`apply_guest_net_identity` deleted) and a networked snapshot no longer needs vsock.
      Isolation is now kernel-enforced (separate stacks), replacing P4.4's unique-/30. Teardown is one
      op (`ip netns del`); the orphan sweep reclaims an orphaned **netns** (dir-named, no `tap` record),
      and the finite-/16-pool DoS it guarded against is *eliminated* (every netns reuses one /30).
      `RunningVm::netns()` added for the Phase-8 loader to enter. Proof: the unjailed path (boot,
      restore, **two concurrent networked clones**, isolation, the sweep, the leak test) is validated
      end-to-end with real Firecracker VMs under `unshare -Urn`; the jailer `--netns` is real-root
      gated. Tests reworked: `two_networked_vms_run_in_isolated_netns`,
      `restored_networked_clones_coexist_each_in_its_own_netns`,
      `sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir`, and the in-netns host-endpoint listener.)*
- [x] **P7.0d** Jailed bulk I/O: input/output block devices staged chroot-relative and read back
      post-teardown, or a recorded typed refusal if staging isn't worth it.
      *(Done, staged — and cheaper than the box feared: the images are **built in place inside the
      chroot** (the P3.4/P3.5 builders are rootless `mke2fs` runs that take a target dir, so pointing
      them at the chroot root costs no copy and no mount), then handed to the jailed uid
      (`give_to_jail`, input 0444 / output 0600) and named chroot-relative in the API. Built in
      `run_boot`, not `launch` — the chroot only exists once the jailer has run, and the API socket
      answering is the proof. `collect_outputs` is unchanged: the image's host-side path is under the
      workdir (the chroot nests in it), read after the VMM exits. This was the **last refused
      combination**, so `Vm::boot`'s deny-by-default refusal block and its
      `jail_refuses_half_confined_boots` unit test retired with it: the jail now composes with every
      boot feature (a future unjailed feature must reinstate the refusal, decision 013). Proof:
      `jailed_bulk_io_round_trips_through_the_chroot` (real-root gated) drives the full jailed matrix
      at once — overlay + vsock + input + output — injecting a 2 MiB payload (past the vsock frame
      cap, so provably the block path) and capturing it back byte-for-byte from a confined VM.)*
- [x] **P7.0e** Jailed snapshot/restore + pre-warmed pool: the bundle disk lives in the chroot (decision 010),
      so restore stages it jailed. Unblocks a confined pre-warmed pool.
      *(Done. `Vm::restore` honors `BootConfig.jail`: the clone spawns under the jailer and the bundle
      is staged into the chroot once the API socket proves it exists — the state file copied in
      (small, 0444), the guest **memory bind-mounted read-only** (a per-clone copy would erase the
      pre-warmed-restore latency win and the clones' shared page cache; the P7.0b bind-or-copy machinery is
      reused, `Chroot.base_mount` generalized to a `mounts` vec), and the disk placed at the
      **baked-in path resolved inside the chroot** (Firecracker reopens the drive from the path in the
      state file): a shared base bind-mounted read-only there, a private copy staged, jailed-uid-owned,
      and unstaged once the VMM holds the fd. The baked-in relative `v.sock` re-binds at the jailed
      cwd (the chroot root, chowned to the jailed uid so the bind can't EPERM); a networked clone's
      netns is joined via `--netns` (decision 017). **Snapshotting a jailed VM stays a typed
      refusal**, deliberately: the clone story is snapshot an *unjailed* pre-warmed source (it runs only the
      embedder's warm-up) and restore **jailed** clones — the untrusted code runs confined (decision
      010 consequence). Cgroup **resource caps** are not applied on jailed restore (the guest's
      envelope lives in the snapshot, not restore's config; a documented fail-open on the cap side
      only, decisions 013/014 — caps join when P7.1's `Limits` ride the snapshot); every isolation
      wall is present. The confined pre-warmed pool falls out: `Pool` restores through `Vm::restore`, so
      `jail` on its config confines every pooled clone. Proof:
      `restores_prewarmed_clones_under_the_jailer_and_pools_them` (real-root gated) — a direct jailed
      restore (dropped uid + pre-warmed Python exec) and a 2-deep jailed `Pool` whose taken clone execs.)*
- [x] **P7.1** `Sandbox` lifecycle: `open → exec → put/get files → snapshot → close`, with **inputs at
      the public API**. *(Assumes the jailed exec path (P7.0a); `Sandbox::exec` jails by default, decision 015.)* *(Lifts the bulk block-device file paths — P3.4 `input_dir`, P3.5
      `output_dir`/`RunningVm::collect_outputs` — onto the `Sandbox` surface, since P3.4/P3.5 keep them
      at the low-level `RunningVm` layer. **Embedder inputs:** promote `exec_with_files(argv, stdin,
      files, artifacts)` onto `Sandbox` so an embedder never reaches into `RunningVm`; add an **`env`**
      field to `Request::Exec` (bounded like `stdin`, set on the **spawned command only**, never the
      agent's own process); and pin a **secret-hygiene contract**: injected file contents and env
      values never appear in an engine log line, a [`VmmError`] Display, or `console()` (error paths
      may name a file path or an env key, never a value), and host-side copies of injected bytes are
      wiped after send where practical. When the audit log lands (P13), it records *that* inputs
      were injected (paths/keys/sizes or hashes), never their contents. **Exit gate:** `Sandbox`
      exposes an exec taking files + env; a run receives both in-guest; the call stays synchronous and
      returns the same `RunResult` shape; and a **leak test** greps an injected sentinel value out of
      every observable surface (logs, every `VmmError` Display, `console()`) and finds nothing.)*
      *(Landed as `Sandbox::open(BootConfig)` — **jailed by default**: an unset `jail` becomes
      `Jail::default()`, and the opt-out is the differently-named `Sandbox::open_unjailed` (plus the
      CLI's `--unjailed`), so an unconfined sandbox is greppable, never a forgotten flag; `boot(limits)`
      delegates to `open` and flips with it. Inputs: `exec_with_files(argv, stdin, files, env,
      artifacts)` on `Sandbox` and `RunningVm`; `env` rides `Request::Exec` as **protocol v2** — the
      handshake version gates the skew, because an old agent parses the new frame and silently runs
      *without* the env, which for secrets/config is a correctness failure, not compat (decision 019) —
      and the guest applies it via `Command::env` on the spawned command only, never its own process
      (proven in-process by `env_reaches_the_command_but_never_the_agents_own_process` and against a
      real guest by the per-exec-scope assertion in the leak test). `collect_outputs`, `snapshot`,
      `kill_handle`, and `vmm_pid` are surfaced on `Sandbox`, so an embedder never reaches into
      `RunningVm`. Secret hygiene pinned on `RunningVm::exec_with_files` and recorded as decision 019;
      the wire copies (the channel's serialized payload, the driver's request clones) are zero-wiped
      after send. Exit gate: `sandbox_opens_jailed_by_default` (real-root, self-skips) proves the
      polarity flip; `lifecycle_runs_inputs_and_collects_outputs` +
      `snapshot_yields_a_restorable_bundle` drive the full lifecycle; the leak test runs
      twice — `injected_secrets_reach_no_observable_surface` (no VM: host logs at TRACE, the real
      in-process agent's logs, every error's Display/Debug) and
      `injected_secrets_never_reach_the_console_or_host_logs` (real VM: the serial console with a
      positive control proving the agent's log lines do land there, host logs, the failing-injection
      error path) — and finds the sentinel only in `RunResult`, the caller's own data.)*
- [x] **P7.2** Stateful sessions: multiple `exec`s against one VM with a persistent overlay.
      *(The VM **is** the session (decision 019): the in-guest agent now serves every connection
      from **one persistent working directory** (`serve_session`, a stable dir the in-VM binary
      passes for its whole life) instead of a fresh-and-removed per-exec dir, so a file injected or
      written by one exec is visible to the next — and the boot's tmpfs overlay already made the
      wider guest filesystem accumulate. State's lifetime is the VM's: teardown discards the
      overlay, and snapshot clones each get their own copy-on-write view of the source's state. The
      library `serve` keeps the fresh-dir one-shot semantics for harness/test callers. Proven at the
      agent layer (`session_state_persists_across_connections`, no VM) and against a real guest
      (`session_state_persists_across_execs`: injected file + written file + `/root` state all
      visible to a later exec).)*
- [x] **P7.3** Per-sandbox limits (cpu/mem/wall/net policy) as **one options struct**, its shape
      settled by the P6.5 resource-policy decision. *(Turns two fixed internal budgets into **knobs**:
      the **exec wall-clock budget** (today the internal `DEFAULT_EXEC_TIMEOUT`; make it settable per
      call or on the struct so a host's run budget is enforced end to end, so `Limits.wall` stops
      meaning boot-only), and the **exec output cap** (today the fixed `MAX_EXEC_OUTPUT`, already surfaced as
      `OutputCap { limit }`). A wall breach keeps today's semantics: cooperative `ExecTimeout`, with
      `ExecUnresponsive` as the liveness backstop. `Limits::default()` stays conservative and its
      load-bearing-defaults doc already landed. **Exit gate:** the exec deadline is settable per run
      with unchanged timeout semantics, and the output cap is settable.)*
      *(Landed on the struct, in decision 013's exact shape: `Limits.wall` now means the **whole
      run** — `with_limits` folds it into both the boot deadline and the per-exec budget — and
      `Limits` gains `output_cap` as the fourth knob; both ride the existing fold (`Limits` →
      `BootConfig` → `RunningVm`), so every exec on that sandbox enforces them, and the restore path
      takes them from the restoring caller's config (the budgets are the host's, not the
      snapshot's). `BootConfig` keeps a driver-level `boot_timeout`/`exec_wall` split beneath the
      public API for a caller who needs different ceilings. Both the socket idle timeout and the host's
      `ExecUnresponsive` give-up deadline derive from the configured budget plus kill slack, exactly
      as the old const's doc demanded, so a raised budget moves the whole ladder and timeout
      semantics are unchanged (guest-cooperative `ExecTimeout` first, host backstop after). Defaults
      are the old constants (30 s, 16 MiB): no default run got more or less. The CLI exposes both as
      `--wall` / `--output-cap`. Proven by `exec_budgets_are_per_sandbox_knobs`: a 2 s wall turns
      `sleep 30` into `ExecTimeout{2s}` promptly, a 4 KiB cap turns a `seq` flood into
      `OutputCap{4096}`, and a modest exec passes both.)*
- [x] **P7.4** `agent run <cmd>` / `agent shell` CLI over the lifecycle.
      *(`agent run` now drives the whole public API from flags: piped **stdin** is forwarded (terminal
      stdin stays empty so an interactive run doesn't block), `--env KEY=VALUE` (repeatable,
      clap-validated, values never logged), `--put <file>` injects host files, `--get <path>`
      requests artifacts and writes them under the cwd (absolute/`..` names refused), and
      `--wall` / `--output-cap` surface the P7.3 knobs; jailed by default with `--unjailed` as
      the loud opt-out, and exec still needs the agent rootfs (`AGENT_ROOTFS`/`AGENT_MARKER`).
      `agent shell` replaces its "not implemented" stub with an interactive **stateful session** on
      one held-open sandbox: one `sh -c` exec per line, prompt and diagnostics on stderr, command
      output on stdout, files persisting across lines (P7.2; shell *process* state like `cd` does
      not — each line is its own exec, stated in the help). A guest fault (timeout, cap,
      unrunnable) belongs to its line and the session survives; an infra/transport fault ends the
      session with the typed error, branching on `VmmError::kind()`.)*
- [x] **P7.5** Structured run result (stdout/stderr/exit/artifacts/metrics).
      *(`RunResult` gains the missing leg: a `metrics: ExecMetrics` field — host-measured, so a
      hostile guest can't lie about it — starting with `wall`, the request-to-terminal-frame time
      an embedder can bill on; `#[non_exhaustive]`, so cgroup cpu time and the audit log's
      numbers land as fields, not breaks. `agent run --json` emits the whole structured result as
      one JSON object on **stdout** (exit code, lossy stdout/stderr, artifact list with sizes,
      `boot_ms` + `exec_wall_ms`), making the "stdout carries a run's structured result" convention
      real; raw-relay stays the default.)*
- [x] **P7.6** Concurrency: many sandboxes at once; a bounded pool; no interference. *(The pool
      bound respects the measured per-sandbox fd budget from P6.9c: `target × fds_per_vm` stays
      under `ulimit -n` with headroom, stated in the docs, not discovered via `EMFILE`.)*
      *(`many_sandboxes_run_concurrently_without_interference` boots three sandboxes from three
      threads at once — genuinely overlapping boots, not sequential — and each exec's result is
      exactly its own (concurrent *clones* were already proven in tests/snapshot.rs; this is the
      embedder's independent-sandbox fan-out). The fd rule is now *stated by the engine, not just
      the docs*: `Pool::new` reads the soft `ulimit -n` from `/proc/self/limits` (unsafe-free; the
      pure parser is unit-tested) and logs one warning naming target, `FDS_PER_VM`, headroom, and
      the fix when a target oversubscribes the budget — a warning, not a refusal, the decision-013
      fail-open posture, since sizing is fairness hygiene, not the isolation boundary. The formula
      also lives in the `Pool` rustdoc and `docs/embedding.md`.)*
- [x] **P7.7** Docs: the engine API and the explicit *non-goals* (no auth/billing/scheduler).
      *(**`docs/embedding.md`**, the embedder's document and this phase's design doc in one: the lifecycle
      contract step by step against the real API (confined-by-default open and the named-constructor
      opt-out, exec's result-vs-error semantics and bounds, the secret-hygiene contract, sessions,
      the budget struct and its fail-open line, the three error buckets as a table, the no-leak
      lifetime ladder, the unjailed-source→jailed-clones pre-warmed-start story, the fd sizing rule, the
      CLI as reference embedder) and then the engine/PaaS line: the non-goals stated as design
      refusals (no tenancy/auth, no billing, no fleet scheduling, no dashboard or network API), what
      the engine *does* owe a long-lived host (decision 016's split), and what lives downstream of
      the public API. README's Status and Scope sections link it.)*
- [x] **P7.8** Test: two concurrent stateful sessions stay isolated and correct.
      *(`two_concurrent_stateful_sessions_stay_isolated`: two sandboxes live simultaneously, execs
      interleaved A1→B1→A2→B2 on the *same* relative filename, each session reads back exactly its
      own accumulated state, and a file that exists only in B is absent in A — plus the negative
      probe exits non-zero. Two sessions are two VMs by construction (decision 019), so the
      isolation being pinned is KVM, not agent bookkeeping.)*
- **Exit gate:** a clean `Sandbox` engine anyone can embed/self-host.
  *(Passed: the lifecycle demo is the CLI (`agent run` with stdin/files/env/knobs/`--json`,
  `agent shell` as a held-open session) and the tests/sandbox.rs suite (open jailed by default,
  inputs at the public API, sessions, budgets, snapshot, leak checks, concurrency, session isolation);
  documented in [`docs/embedding.md`](docs/embedding.md). Phase 7 is complete.)*

---

## eBPF / aya track — see and enforce from the host

## Phase 8 — aya "hello, verifier"

The eBPF foundation: build, load, and read a map from a trivial program.

- [x] **P8.1** `crates/probes` (`no_std`, `bpfel-unknown-none`) + `crates/probes-loader`
      (userspace, aya) scaffolding; `bpf-linker` wired into `xtask`.
      *(Landed: `crates/probes` is a real `#![no_std]`/`#![no_main]` aya-ebpf crate with its own
      nightly toolchain + `.cargo/config.toml` (`build-std = ["core"]`), building a valid BPF ELF
      via `bpf-linker` — one placeholder tracepoint proves a program section is emitted end to end;
      the counter is P8.2. `cargo xtask build-probes` drives that build via `rustup run nightly`
      (robust against the parent gate's `RUSTUP_TOOLCHAIN=stable`), guarded to skip cleanly when
      `bpf-linker`/`rustup` are absent so `ci` still runs everywhere; it folds **into** `ci` at
      P8.6. `setup` now reports the nightly+`rust-src` prereq. `crates/probes-loader` stays a
      skeleton pointing at the now-real object; `aya` (userspace) is added when first used at P8.3,
      not before — the supply-chain gate keeps the tree minimal. Host gate green.)*
- [x] **P8.2** A tracepoint/kprobe that **counts** an event (e.g. `sys_enter_execve`) into a map.
      *(Landed: `crates/probes` `count_execve` attaches to `syscalls/sys_enter_execve` and bumps a
      single-slot **per-CPU** `PerCpuArray<u64>` — per-CPU so the increment needs no atomic. The
      built object carries the `tracepoint` program section, the `maps` section (`EXECVE_COUNT`), and
      the relocation linking them.)*
- [x] **P8.3** Loader attaches it, reads the map, prints counts.
      *(Landed: `agent-probes-loader`'s `ExecveCounter::{load, count}` (aya, userspace, sync) loads
      the object, attaches the tracepoint, and sums the per-CPU slots; a typed `ProbeError` (the
      loader's `VmmError`) on every failure. The object is a runtime-loaded build artifact found by
      path (`AGENT_PROBES_OBJECT`, else the `build-probes` output), not `include_bytes`/`build.rs`, so
      the host workspace stays on stable (decision 020). Demo: `examples/count_execve.rs` prints the
      total and its delta. Test: `execve_counter_counts_host_execve_events` (privileged) spawns N
      processes and asserts the count rose by ≥ N.)*
- [x] **P8.4** Lifetime: the loader owns its programs/maps/links so they **drop with it** (no pinned
      residue in `/sys/fs/bpf`, no dangling attachment) unless pinning is explicitly asked for. The
      eBPF analogue of the FC track's no-leak teardown, set here at the foundation before Phase 10
      attaches to the real per-VM taps whose netns teardown the driver already guards.
      *(Landed: the aya `Ebpf` owns the program/map/link and its `Drop` detaches + frees them; nothing
      is pinned (decision 020). Test: `counter_drops_without_pinned_residue` (privileged) asserts a
      load+drop leaves `/sys/fs/bpf` unchanged and a second load after the drop still succeeds. The
      privileged gate builds the object (`ci-privileged` calls `build-probes`) before these run.)*
- [x] **P8.5** CO-RE/BTF: build against BTF so it's portable across kernels.
      *(Landed: the object now carries `.BTF`/`.BTF.ext` — `bpf-linker --btf` (passed via a
      `[target.bpfel-unknown-none]` link-arg) plus `debug = true` in the profile, which the linker
      derives BTF from. aya relocates the object against the running kernel's BTF at load, so one
      compiled object is portable across kernels. `build-probes` asserts the `.BTF` section is present
      (a regressed link-arg fails the build). The program reads no kernel struct fields yet, so it
      needs no field-offset relocations — those arrive with Phase 9's struct reads; here BTF is the map
      typing + load-time relocation path.)*
- [x] **P8.6** Handle the verifier: bounded loops, map access patterns — its rules, hit on purpose.
      *(Landed: `count_execve` gained a **bounded loop** (walk the fixed 16-byte `comm` to its NUL —
      the bound is a compile-time const, so termination is provable; an unbounded `while` is rejected)
      and a **map access pattern** (per-PID `HashMap` lookup-or-init, where the lookup result is only
      dereferenced inside the `Option` null-check the verifier demands). Surfaced as
      `ExecveCounter::counts_by_pid`; the privileged test asserts the per-PID counts cover the spawns.
      The verifier runs at load, so the proof is the privileged test passing.)*
- [x] **P8.7** `xtask` builds the eBPF object as part of the CI gate (separate target).
      *(Landed: `ci` now calls `build_probes()` after `deny` — guarded, so a host without
      `bpf-linker`/`rustup` skips it and the CI gate still runs everywhere, but a set-up dev box now fails
      the CI gate on a probe that won't compile or that drops its BTF. `ci-privileged` already built it
      before the probe tests.)*
- [x] **P8.8** Caps: load with `CAP_BPF` (not full root) where possible; document what's needed.
      *(Landed: loading + attaching needs only `CAP_BPF` + `CAP_PERFMON` (the two that split out of
      `CAP_SYS_ADMIN` in 5.8), not full root. The loader reads its effective set from
      `/proc/self/status` `CapEff` (no libc, no unsafe) and the tests/demo are capability-aware, so a
      `setcap cap_bpf,cap_perfmon+ep` binary runs unprivileged. The `CapEff` parse + the two-bit check
      are a pure `parse_cap_eff`/`mask_has_load_caps` pair, unit-tested on the host gate; the
      end-to-end unprivileged load is verified by the `setcap` run (the privileged CI tests run as
      root, whose mask has every bit, so they can't prove "not root" by themselves). Documented in
      the docs (`docs/cli-install.md`, `docs/probes.md`), `setup`, and the demo.)*
- [x] **P8.9** Support probe: detect BTF (`/sys/kernel/btf/vmlinux`) and the kernel/verifier features
      the probes need **at load**, and fail (or degrade) with a **legible typed error** naming the
      requirement rather than a cryptic verifier reject (the eBPF analogue of P6.9b's
      Firecracker-version guard, so a host that can't run the probes says so plainly).
      *(Landed: `check_support()` checks BTF then the caps and returns `ProbeError::Unsupported`
      naming the first missing prerequisite; `ExecveCounter::load` runs it first, so a BTF-less or
      under-privileged host gets a legible error, not an `EPERM`/verifier reject deep in the load.)*
- [x] **P8.10** Test: run a known program, assert the counter moved.
      *(Landed: `execve_counter_counts_host_execve_events` (privileged) spawns N processes and asserts
      the per-CPU total rose by ≥ N and the per-PID map covered them; `counter_drops_without_pinned_residue`
      covers P8.4. Both self-skip via the cap-aware `check_support`.)*
- **Exit gate:** a Rust eBPF program loads and reports.
  *(Passed: the demo is `agent-probes-loader`'s `count_execve` example (loads, attaches, reports the
  host execve total + per-PID breakdown) and the privileged `counter` tests; documented in
  [`docs/probes.md`](docs/probes.md), the host-observability counterpart to `docs/embedding.md`, covering program types,
  maps, the verifier, CO-RE/BTF, the no-pin lifetime, caps, and the hardware-isolation limit. Phase 8
  is complete.)*

## Phase 9 — Syscall observability

Trace what a process (a firecracker/vhost worker, or the guest-adjacent host side) actually does.

> **What host eBPF can and cannot see (the hardware-isolation consequence).** The guest runs its
> *own* kernel, so untrusted code's syscalls are serviced in-guest and **never trap to the host**:
> host tracepoints on `sys_enter_execve` etc. see only the **VMM's host footprint** (Firecracker/
> vhost threads, KVM ioctls, block I/O), not in-guest syscalls. This is the price of core property 1: the
> strong host-side signals are **network** (the tap, P10/P11) and **resources** (the cgroup, P12);
> syscall-level visibility is inherently coarse for a microVM. Say so plainly (measured, not
> marketed); do not promise in-guest syscall introspection this boundary cannot deliver.

- [x] **P9.1** Tracepoints for `execve`/`openat`/`connect` with per-event data via a **ring buffer**.
      *(Landed: three tracepoint programs (`trace_execve`/`trace_openat`/`trace_connect`, on the
      matching `sys_enter_*` hooks) `output` a whole `SyscallEvent` — pid, tid, cgroup id, `comm`, and
      the opened path or connected sockaddr — into one 256 KiB `BPF_MAP_TYPE_RINGBUF`; the loader
      drains it in order with `SyscallTracer::drain` (a single persistent consumer, so its position
      stays coherent across calls). The record type is single-sourced in a new dependency-free
      `crates/probes-common` so the kernel writer and userspace reader can't drift. The P8
      `count_execve` counter is untouched and coexists in the same object. Decision 021.)*
- [x] **P9.2** Filter to a target PID/cgroup (so you watch *one* sandbox's host footprint).
      *(Landed: a two-slot `FILTER` array (target tgid, target cgroup id; `0` = don't filter that
      axis) is consulted **in the program**, so a non-matching event is dropped before it reaches the
      ring buffer; `SyscallTracer::watch_pid`/`watch_cgroup`/`watch_all` set it, default observes the
      whole host. Proven by the `#[ignore]`d `tracer` integration tests (per-event path capture, the
      connect sockaddr decode, filter exclude-then-include) and the `trace_syscalls` example.)*
- [x] **P9.3** Userspace consumer: stream events, decode, print a live trace.
      *(Landed: `SyscallTracer::stream(idle, keep_going, on_event)` loops, draining greedily and
      sleeping `idle` only when the buffer is empty, until the caller predicate stops it (a deadline or
      a Ctrl-C flag). The decode is centralized on the event — `SyscallEvent::describe` /
      `detail_display` / `syscall_name` render a path (execve/openat) or an `a.b.c.d:port` sockaddr
      (connect) — so a consumer prints one line each. The `trace_syscalls` example is now the live
      trace. Poll-with-sleep, not `epoll`, keeps the crate sync + `unsafe`-free + dependency-light; the
      fd is on `AsRawFd` for a zero-idle-latency consumer later.)*
- [x] **P9.4** Attribute events to a sandbox (via cgroup id / PID from the FC track).
      *(Landed: `cgroup_id_of_pid(pid)` reads the process's unified cgroup path from
      `/proc/<pid>/cgroup` and returns the inode of `/sys/fs/cgroup/<path>` — for cgroup v2 that inode
      *is* the `bpf_get_current_cgroup_id` a program stamps on events. Hand it the Firecracker track's
      VMM pid, `watch_cgroup` the result, and the trace is scoped to exactly that sandbox. Pure `std`
      fs, no crate coupling to `vmm` (plain `u32`/`u64` bridge the two tracks). Proven by a host-gate
      unit test (the resolver returns a real id on a v2 host) and a privileged test asserting our own
      cgroup's events come back carrying that id.)*
- [x] **P9.5** Bounded overhead: measure the tracing cost.
      *(Landed: `cargo xtask bench-trace` times the same `openat` micro-workload in three conditions:
      **baseline** (no probes), **unwatched** (probes attached but the `FILTER` excludes us, so the
      programs fire and drop ours in-kernel: the cost every other process pays), and **watched** (the
      filter includes us, so each `openat` writes a whole `SyscallEvent` to the ring buffer, drained
      off the timed path so it never overflows mid-burst). It reports ns/openat percentiles for each
      and the p50 delta over baseline: the measured, per-syscall overhead the attached tracepoint adds,
      small for unwatched processes and paid in full only for the one sandbox you watch. Needs
      `CAP_BPF`+`CAP_PERFMON` + the built object, not KVM.)*
- [x] **P9.6** Test: launch a workload, assert its `execve`/`open` events show up attributed.
      *(Landed: the `#[ignore]`d `a_workload_child_shows_up_attributed_to_its_cgroup` spawns a `cat`
      workload (one child that `execve`s itself and `openat`s a known path) under a `watch_cgroup` of
      our cgroup id, then asserts every captured event carries that id, the child's execve (a pid other
      than ours) shows up, and its `openat` of the marker path shows up: the whole P9.4 attribution
      bridge proven end to end on a real subprocess.)*
- **Exit gate:** a live syscall trace of a running sandbox.
  *(Demo: `cargo xtask trace-sandbox` boots a real sandbox (jailed as root, else the unjailed opt-out),
  resolves its VMM cgroup id via the Firecracker track's `vmm_pid`, and streams that sandbox's
  cgroup-attributed host syscall footprint (the jailer/Firecracker execve, the drive/tap/socket
  openats), honestly labeled as the VMM's host footprint since the guest's own syscalls never trap to
  the host. The `trace_syscalls` example (point it at a booted VMM's pid) and the P9.6 test are the
  other two faces of the same demo. Run on a KVM + `CAP_BPF` host.)*

## Phase 10 — Network observability on the tap (tc/XDP)

Watch every packet a microVM sends/receives — at its tap device, in the kernel.

- [x] **P10.1** Attach a **tc** (or XDP) program to a VM's tap device.
      *(Landed: `TapMonitor::attach(interface)` adds a **clsact** qdisc and attaches two `tc`
      classifiers — `tap_ingress`/`tap_egress`, the ingress and egress hooks clsact provides — to a tap
      via aya `SchedClassifier`. `tc`/clsact over XDP so both directions are covered uniformly and
      Phase 11 enforcement can live at the same hook (decision 023). Drop-owned links, nothing pinned
      (decision 020); attaches by interface name in the current netns, with binding to a sandbox's own
      netns `fc0` (decision 017) deferred to P10.4. Proven by the `#[ignore]`d
      `attaches_to_a_tap_and_reads_the_flow_map` (create a tap, attach both hooks, read the map back).)*
- [x] **P10.2** Parse L3/L4 headers; count bytes/packets per direction, per flow.
      *(Landed: each classifier reads the frame's IPv4 5-tuple with `ctx.load` and adds `skb->len` to
      that flow's per-direction counters in the `FLOWS` map, keyed by `FlowKey` (5-tuple) → `FlowCounts`
      (ingress/egress packets+bytes), single-sourced in `crates/probes-common`. The parse is mirrored by
      a pure `parse_ipv4_5tuple` at the same shared offsets, host-unit-tested on crafted TCP/UDP/ARP/
      truncated frames; the loader reads the map as raw bytes and decodes with the shared `from_bytes`,
      so both crates stay `unsafe`-free. IPv4 only for now; best-effort counters like `EXECVE_BY_PID`.
      The live "guest traffic shows up in the counters" proof is P10.6.)*
- [x] **P10.3** Export per-VM network stats to userspace via a map.
      *(Landed: `TapMonitor::flows` reads the `FLOWS` map into `(FlowKey, FlowCounts)` pairs (per
      5-tuple), and `totals` sums them into a per-VM `NetStats` rollup (ingress/egress packets+bytes) —
      the two userspace export surfaces, per-flow detail and the sandbox-level summary a caller ships.)*
- [x] **P10.4** Bind the program to the *specific* tap the FC track named for a sandbox.
      *(Landed: `TapMonitor::attach_in_netns(netns, iface)` enters the sandbox's own network namespace
      (decision 017) via `setns` (nix's safe wrapper, so the loader stays `#![forbid(unsafe_code)]`),
      attaches the classifiers to its `fc0` there, and returns the thread to the caller's netns; the map
      is read back from the host netns (map fds aren't namespace-scoped). The driver hands over the netns
      and tap names via the new `Sandbox::netns`/`Sandbox::tap_name` (additive `api:`), keeping
      `probes-loader` independent of `vmm`. Decision 024.)*
- [x] **P10.5** Handle attach/detach cleanly on sandbox open/close.
      *(Landed: attach-on-open is `attach_in_netns`; on close, dropping the monitor frees its userspace
      handles and the sandbox's netns teardown (`ip netns del`, decision 017) cascades the tap, clsact
      qdisc, and `tc` filters away — no pinned residue (decision 020/023), no dangling filter even if the
      loader died first. Proven by the P10.6 test's clean shutdown.)*
- [x] **P10.6** Test: traffic from a guest shows up in the per-VM counters.
      *(Landed: the `#[ignore]`d `guest_traffic_shows_up_in_the_per_vm_counters` boots a networked agent
      microVM, attaches the monitor to its netns tap, has the guest fire UDP at its host end
      (`10.200.0.1:9999`), and asserts that flow's ingress packets and the per-VM ingress total are both
      nonzero. Uses `agent-vmm` as a dev-dependency only, so the loader library stays decoupled.)*
- **Exit gate:** live per-microVM network visibility.
  *(Demo: `cargo xtask watch-sandbox` boots a real networked sandbox (jailed as root, else the unjailed
  opt-out), attaches a `tc` monitor to its tap inside its netns, drives guest traffic in rounds, and
  prints the per-VM totals climbing plus the per-flow breakdown — the guest's own packets, observed at
  its tap from the host and scoped by netns. Run on a KVM + `CAP_BPF`+`CAP_NET_ADMIN` host.)*

## Phase 11 — Enforcement: egress policy in the kernel

Turn observation into control — deny-by-default egress, allow-listed, enforced at the tap.

- [x] **P11.1** A policy map (allowed CIDRs/ports) the tc/XDP program consults.
      *(Landed: a `POLICY` map of `PolicyRule` (destination CIDR + optional port/proto, a padding-free
      12-byte record) plus an `ENFORCE` toggle, both `#[map]`s the ingress classifier reads. The rule
      record and its matcher (`rule_matches`, a masked-CIDR + wildcard-port/proto compare) are
      single-sourced in `crates/probes-common` next to the flow record, so the in-kernel scan and the
      host-unit-tested `egress_allowed` can't drift. `TapMonitor::set_egress_policy` fills the map (as raw
      bytes via `PolicyRule::to_bytes`, no `unsafe` aya::Pod). Both maps are per-object, so the policy is
      naturally per VM. Matcher logic host-tested: /32 exact, CIDR ranges, wildcards, out-of-range prefix,
      deny-by-default.)*
- [x] **P11.2** Drop packets that don't match; allow those that do — per VM.
      *(Landed: with `ENFORCE` on, the ingress hook (a frame the guest sends) returns `TC_ACT_SHOT` for a
      guest-sent IPv4 packet whose destination matches no active rule and `TC_ACT_OK` for a match, scanning
      the fixed rule array in a verifier-bounded loop (the mask built so the shift is always `< 32`).
      Opt-in and per VM: a monitor that never sets a policy stays observe-only (both hooks accept, the
      Phase 10 behavior); `clear_egress_policy` disarms. Two carve-outs keep deny-by-default from being
      deny-everything: ARP is always allowed (the guest must resolve its gateway) and the egress hook
      (reply → guest) always accepts. The launch-time API (P11.3), deny-by-default default (P11.4), denial
      logging (P11.5), the schema decision (P11.6), and the live allowed-vs-blocked test (P11.7) remain.)*
- [x] **P11.3** Userspace API to set a sandbox's egress policy at launch.
      *(Landed: `EgressPolicy`, the userspace allow-list schema, built from friendly `Ipv4Addr`
      CIDRs/ports (`deny_all().allow_host(..)/.allow_cidr(..)`) and lowered to the `PolicyRule`s the map
      holds (prefix clamped to /32). `TapMonitor::set_egress_policy(&EgressPolicy)` applies it to an
      attached monitor; `TapMonitor::enforce_in_netns(netns, iface, &policy)` applies it **at launch** —
      arming the `POLICY`/`ENFORCE` maps *before* the tc programs attach to the tap, so there is no window
      where the tap is live but un-policed (the first guest packet is already policed). Rules written as
      raw bytes, no `unsafe` aya::Pod. Host-tested: building, chaining, prefix clamp, per-rule verdicts.
      Folding this into `Sandbox::open` is Phase 13's convergence; the launch primitive lives here.)*
- [x] **P11.4** Deny-by-default: a sandbox with no policy reaches nothing.
      *(Landed: `EgressPolicy::deny_all()` (also the `Default`) is the empty allow-list, so a sandbox
      launched with no explicit allowance drops every guest-sent packet once enforced — you must add each
      endpoint. This is the eBPF, host-observed complement to the driver's no-route-to-the-world
      deny-by-default (decision 008): the driver gives the guest no route out, and the tap drops anything
      unlisted where the host can see it. Host-tested that the default/`deny_all` allow nothing. The live
      allowed-vs-blocked proof is P11.7.)*
- [x] **P11.5** Log denials (the audit trail feeds the audit log, Phase 13).
      *(Landed: a dropped IPv4 packet is counted per destination in a `DENIALS` map (keyed by the denied
      `FlowKey`) before the drop, read back by `TapMonitor::denials()` as `(FlowKey, count)` pairs — the
      host-observed audit trail of which endpoints a sandbox was blocked from. Best-effort like `FLOWS`;
      empty until enforcement drops something. Non-IPv4/truncated drops have no 5-tuple to key on, so the
      denial log is the meaningful policy-miss case. Phase 13 folds this into the per-run record.)*
- [x] **P11.6** `(decision)` where policy lives + its schema (still *engine* mechanism, not org
      policy) → `docs/contributing-architecture.md`.
      *(Landed: decision 025. Policy is a per-VM allow-list in two eBPF maps (`POLICY` array of
      `PolicyRule` + `ENFORCE` toggle), schema = destination CIDR + optional port/proto (deny-by-default,
      an explicit `active` byte so a zeroed map is deny-all not allow-all), consulted at the ingress
      (guest-sent) hook, ARP always allowed, replies always accepted, denials recorded. Engine mechanism
      only (guardrail 4): the schema is CIDR/port/proto, a hoster maps its own org policy onto that.
      Records why over an LPM trie, netfilter, richer in-engine policy, or stateful return-path filtering,
      and the complement to the driver's decision 008.)*
- [x] **P11.7** Test: a guest can reach an allow-listed endpoint and is blocked from everything else.
      *(Landed: the `#[ignore]`d `a_guest_reaches_the_allow_listed_endpoint_and_is_blocked_from_the_rest`
      (`net_enforce.rs`) boots a networked sandbox, `enforce_in_netns` with an allow-list of exactly one
      endpoint (host end UDP 9999), and has the guest send to that port and a blocked one (8888). Asserts
      the blocked port appears in `denials` (dropped at the tap) and the allowed port never does, and that
      the allowed flow shows in the counters (sent and let through). `agent-vmm` a dev-dependency only.)*
- **Exit gate:** kernel-enforced per-sandbox egress.
  *(Demo: `cargo xtask enforce-sandbox` boots a real networked sandbox, arms a deny-by-default egress
  policy allowing only its host end on UDP 9999, has the guest send to that endpoint and a blocked one,
  and prints the denials audit trail plus the per-flow allow/deny verdicts — the allow-listed traffic
  passes, everything else is dropped at the tap by host-side eBPF and recorded. Run on a KVM +
  `CAP_BPF`+`CAP_NET_ADMIN` host.)*

## Phase 12 — Resource accounting via cgroup-bpf

Per-sandbox CPU/mem/IO accounting from the kernel — the metering primitive (engine, not billing).

- [x] **P12.1** cgroup-attached eBPF (or cgroup + tracepoints) for per-sandbox CPU/mem/IO.
      *(Landed: the CPU axis is eBPF — `account_sched_switch` attaches to the `sched/sched_switch`
      tracepoint and charges each context switch's on-CPU nanoseconds to the outgoing task's cgroup in a
      `CPU_NS` map (keyed by cgroup id). It's correct because at that tracepoint the scheduler hasn't yet
      swapped `current` (still `prev`), so `bpf_get_current_cgroup_id` is the cgroup whose slice just
      ended; a per-CPU `LAST_SWITCH` cursor is always restamped so intervals stay exact, and a
      `METER_TARGETS` *set* scopes accounting to the registered sandboxes — one shared program on the
      global tracepoint, a hash lookup per switch regardless of sandbox count (P12.4). The loader's
      `ResourceMeter` loads/attaches it, `add_target(id)` registers a sandbox, and `cpu_time(id)` reads
      the total; `id` is exactly what `cgroup_id_of_pid(vmm_pid)` resolves. Memory/IO ride the kernel's native cgroup v2
      counters (`CgroupStats::read`: `memory.peak`/`memory.current`, `io.stat` rbytes/wbytes, `cpu.stat`
      usage_usec as a cross-check), best-effort/`Option` so a missing controller fails open (decision
      013) — the "or cgroup + tracepoints" half the box allows. The cgroup-file parsers are host-unit-
      tested (`cpu.stat`/`io.stat`/single-int + a synthetic-dir `CgroupStats::read`); the live per-cgroup
      CPU accounting needs a privileged runner (P12.5). Correlating to the FC per-VM cgroup is P12.2, the
      run-result summary P12.3.)*
- [x] **P12.2** Correlate with the FC track's per-VM cgroup.
      *(Landed: `cgroup_dir_of_pid(pid)` joins the existing `cgroup_id_of_pid(pid)` so a sandbox's VMM
      pid (the FC track's `vmm_pid`, its VMM in the per-VM lifetime cgroup, P6.7) resolves to both the
      cgroup **id** the eBPF CPU meter keys on and the cgroup **dir** the native memory/IO counters are
      read from. `ResourceMeter::add_target(cgroup_id_of_pid(vmm_pid))` scopes the CPU accounting to that
      one sandbox; the id equals the `bpf_get_current_cgroup_id` the kernel program records, so the two
      tracks line up exactly. `probes-loader` stays decoupled from `vmm` (bridged by plain values).)*
- [x] **P12.3** Expose a per-run resource summary in the run result.
      *(Landed: `ResourceSummary { cpu_time, cgroup: CgroupStats }` — the eBPF-measured CPU plus the
      kernel's cgroup v2 memory/IO — assembled by `ResourceMeter::summary_for_pid(vmm_pid)`. It is the
      per-run summary a caller ships with the run; folding it into the *persisted* per-run audit record
      (fused with the network denials and syscall trace) is Phase 13's convergence, kept out of
      `agent-vmm` so the driver stays independent of the eBPF loader. Decision 026.)*
- [x] **P12.4** Bounded overhead; sane under many concurrent sandboxes.
      *(Landed by design + measurement: **one** program attached to the global `sched_switch`, metering a
      *set* (`METER_TARGETS`), so the per-switch cost is a single hash lookup regardless of how many
      sandboxes are metered — a program-per-sandbox would run every program on every switch (O(N)).
      `CPU_NS` holds only the registered cgroups. `cargo xtask bench-meter` measures the honest
      per-context-switch overhead in three conditions (no meter / attached-not-metering-us /
      attached-metering-us) on a ping-pong micro-workload, mirroring `bench-trace`. Decision 026.)*
- [x] **P12.5** Test: a CPU-heavy run reports higher CPU than an idle one, attributed correctly.
      *(Landed: the `#[ignore]`d `a_cpu_heavy_run_reports_more_cpu_than_an_idle_one_attributed_to_the_sandbox`
      (`resource_meter.rs`) boots a sandbox, meters its cgroup, and runs an idle guest then a CPU-heavy
      one (both Python — `time.sleep` vs a vCPU-pegging loop — so only the workload differs) over equal
      windows, reading each total after a short settle (a slice posts at **switch-out**, when
      `sched_switch` fires, so a pegged vCPU's whole window lands only once the guest idles and the vCPU
      thread blocks). Asserts the busy run charged far more host CPU (≥ half the wall window, > 3× idle)
      and that the CPU map holds **exactly one** entry — this sandbox's cgroup, carrying the charge: the
      exclusivity is the attribution proof. `agent-vmm` a dev-dependency only.)*
- **Exit gate:** per-sandbox resource metrics from eBPF (the engine *measures*, the hoster *bills*).
  *(Demo: `cargo xtask meter-sandbox` boots a real sandbox (jailed as root, else the unjailed opt-out),
  meters its cgroup, and shows an idle guest charging near-zero host CPU while a CPU-heavy guest charges
  most of a core, then prints the per-run `ResourceSummary` (CPU from the eBPF sched_switch meter,
  memory/IO from the kernel's cgroup v2 counters) — per-sandbox resource metrics, host-measured. Run on a
  KVM + `CAP_BPF`+`CAP_PERFMON` host.)*

---

## Convergence — the fused engine

## Phase 13 — The audit log

Attach the eBPF programs to a sandbox at launch and produce a per-run **audit trail**.

- [x] **P13.1** On `Sandbox::open`, attach syscall + network + accounting probes bound to that VM.
      *(Landed: `agent-probes-loader`'s new `observer` module — `ArmedProbes::arm()` (pre-boot: load the
      syscall tracer host-wide, clear the baseline) → `bind(vmm_pid, netns, tap, egress, meter)`
      (post-boot: scope the tracer to the VMM's cgroup and fold the boot window, attach a per-VM
      `TapMonitor` in the netns — enforcing when a policy is given — and register the cgroup as a target
      on a shared `ResourceMeter`). Two-phase because the tracer must attach before boot but the tap/meter
      need the netns/cgroup that only exist after; "on `Sandbox::open`" is the caller's arm→open→bind
      sequence, kept **out of `agent-vmm`** (bridged only by the plain values `Sandbox` exposes:
      `vmm_pid`/`netns`/`tap_name`), decisions 024/026/027. The meter is **shared** (one `sched_switch`
      program metering a set), not per-VM, so it stays O(1) per switch; the bundle holds a target ticket
      and `remove_target`s on drop. Every axis is fail-open (a missing cap/BTF/object → a recorded
      `AxisGap`, never a blocked run). **P13.5 later converged this**: the syscall tracer became shared
      too (`SharedTracer`), so the two-phase `arm`/`bind` collapsed to a single post-boot
      `SandboxProbes::attach(vmm_pid, netns, tap, egress, &tracer, &meter)` — decision 028 supersedes the
      two-phase note here.)*
- [x] **P13.2** Aggregate into one per-run record: network flows, resources, egress denials, timing,
      and notable **host-side** syscalls (the VMM's footprint, not in-guest syscalls; see Phase 9).
      The record's core is network + resources + denials, the signals host eBPF observes strongly
      across the hardware boundary.
      *(Landed: `agent-probes-loader`'s new `record` module — `RunRecord { network: Option<NetSection>,
      resources: ResourceSummary, host_syscalls: SyscallFootprint, timing: Timing, coverage: Vec<AxisGap> }`,
      assembled by `SandboxProbes::collect(timing)` from the three probes (timing supplied as plain
      `Duration`s the caller lifts from `Sandbox::boot_latency` + `RunResult::metrics.wall`, so the record
      never depends on `vmm`). `host_syscalls` is bounded (repeat events collapse to a hit count; distinct
      events cap at `MAX_NOTABLE = 64` by arrival order, with `overflow_events` counting every event past
      the cap so `total - overflow_events` is the exactly-attributed share) and every collection is
      deterministically sorted with a **total** order — denials aggregate by destination triple (one row
      per blocked endpoint, summed across guest source ports) — so the record is byte-stable. Pure module
      (no aya, no vmm): host-safe unit tests cover counts-by-kind incl. unknown, foreign-cgroup filtering,
      dedup+cap, overflow accounting, denial aggregation, deterministic sort, full-record equality across
      shuffled input, the no-network `None` case, and timing/resources passthrough.
      Decision 027. The deterministic JSON *output* surface is P13.4; the privileged end-to-end proof is
      P13.6.)*
- [x] **P13.3** Detach + finalize the record on `close`.
      *(Landed: `SandboxProbes::collect(timing)` is the close-time finalize — it reads the three probes
      into the `RunRecord` **and** unregisters this run's cgroup from the shared tracer + meter, while the
      sandbox is still alive (cgroup dir + map fds must be live). `Drop` is the abandoned-path safety net
      (detach only, no record) and a no-op after `collect`, so the shared sets never accumulate dead
      cgroups whether the bundle is finalized or dropped. Decision 028.)*
- [x] **P13.4** Deterministic, structured output (JSON) of "what this run did," from *outside* the guest.
      *(Landed: `RunRecord::to_json` — a hand-rolled, dependency-free, compact serializer (the hand-framed
      wire reasoning of decision 002: the audit-log format is a contract the SDKs parse, so the exact
      bytes are pinned by a golden test, not a derive). Byte-stable (fixed key order; arrays pre-sorted by
      their builders), float-free (durations as integer nanoseconds, clamped to u64 so consumers parse
      with ordinary 64-bit integers), addresses/protocols/syscalls by name. Phase 14 pretty-prints +
      exports it; this is the machine surface. Decision 028.)*
- [x] **P13.5** Bound the overhead; keep concurrent sandboxes independent.
      *(Landed: the syscall tracer now gets the meter's shared treatment (decision 026) — a `TRACE_TARGETS`
      cgroup **set** + a `TRACE_SET` mode toggle in the kernel program, one shared `SyscallTracer` loaded
      once, every sandbox registering its cgroup. So one attachment serves all sandboxes (a program-per-VM
      would run *N* copies of each `sys_enter_*` on every syscall — O(sandboxes)); the per-event cost is a
      single hash lookup and only target cgroups are emitted. A single drain routes each event to that
      cgroup's private `SyscallFold`, so concurrent sandboxes stay independent — proven host-safe by
      `concurrent_folds_stay_independent`, and the two-phase attach collapses to one post-boot
      `SandboxProbes::attach`. `TRACE_SET` defaults off (the `watch_*` setters switch back, so the mode
      always matches the last setter used and neither filter model can silently no-op). Loss is honest:
      the kernel counts ring-buffer drops (`EVENT_DROPS`), the bundle snapshots the counter around each
      run and reports a nonzero delta as a coverage gap, the buffer is drained at load (the unfiltered
      load-window baseline), at every attach, and on demand via `SharedTracer::poll`. Decision 028.)*
- [x] **P13.6** Test: run a workload that touches network + files → the record shows exactly that.
      *(Landed: the `#[ignore]`d `a_networked_file_touching_run_yields_a_faithful_audit_record`
      (`audit_record.rs`) drives the real launch sequence — load the shared tracer + meter, boot a
      networked sandbox, `attach` the bundle by plain values, run a guest workload that reads `/etc/hostname`
      and sends UDP to the host end, then `collect` the record and serialize it. Asserts the guest's network
      touch shows up **exactly** in the record's flows + per-VM totals, every axis bound (no coverage gap),
      and the deterministic JSON shows the flow. The guest's in-guest file read correctly does **not**
      appear in the host-syscall axis (a microVM services its own syscalls, Phase 9 — the isolation working,
      not a gap): the host observes the guest's network strongly and the VMM's host footprint, never the
      guest's syscalls. `agent-vmm` a dev-dependency only.)*
- **Exit gate:** every run yields a tamper-resistant, host-observed audit trail (microVM + eBPF
  observability as one system).
  *(Met: `SandboxProbes::attach` binds the three host-side probes to a launched sandbox and
  `collect` fuses them into one deterministic, host-observed `RunRecord` — network flows + egress denials
  (tap), CPU + memory/IO (shared meter + cgroup v2), and the VMM's host-syscall footprint (shared tracer),
  serialized to stable JSON — all from **outside** the guest, where the code can't see or subvert it. The
  privileged P13.6 test proves it end to end: the microVM and the eBPF observability as one system. The
  live view + `agent run --trace` are the Phase 14 face.)*

## Phase 14 — Observability output (a face for it)

Make what a run did *legible* — the payoff demo.

- [x] **P14.1** A live TUI (ratatui) or structured stream: sandboxes, their syscalls, network, resources.
      *(Landed: `agent run --watch` — a ratatui full-screen live view over the running sandbox, drawn on
      **stderr** so stdout stays the run's result (the pipe-clean rule extended to the screen; decision
      029). Panels: the sandbox (pid, boot, elapsed, state), its network, its resources, the VMM's
      host-syscall footprint. Fed by a new **non-destructive** `SandboxProbes::snapshot() ->
      LiveSnapshot` poll (tap reads, meter summary, a finished *clone* of the syscall fold), so watching
      never disturbs the record `collect` finalizes; the exec runs on a worker thread that owns the
      `Sandbox`. `q` closes the view, the run continues; terminal state restores via a drop guard on
      every exit path, and a broken TUI degrades to a headless run, never a failed one. The structured
      *stream* alternative was rejected as a second premature machine contract — decision 029.)*
- [x] **P14.2** Per-sandbox drill-down: this run's flows, denials, timeline.
      *(Landed: the live view's detail panes — the per-flow table (5-tuple + per-direction
      packets/bytes), the denial rows (blocked endpoint + drop count, red), and a **timeline** derived
      by diffing successive snapshots: each new flow, denial-count delta, and new distinct notable
      syscall becomes one timestamped entry (pure, host-safe-tested `Timeline::observe`); boot/finish
      are lifecycle entries. The CLI drives one sandbox per run, so the drill-down *is* the screen;
      many-sandbox rollup is the daemon's later.)*
- [x] **P14.3** `agent run --trace` prints the audit log after a run.
      *(Landed: `--trace` binds the probes at launch (the decision-028 sequence composed in the CLI —
      load shared tracer+meter, `attach` by plain values, `collect` while the sandbox is alive) and
      prints the human-readable trail on **stdout** after the guest's own output: timing, per-flow
      traffic, denials, resources, notable host syscalls (labeled the VMM's, not the guest's), and a
      `gap` line per unbound axis. Fail-open end to end: a capless host still runs and the trail
      explains every absence. Conflicts with `--json` (machine consumers take `--record`); the pretty
      trail makes no byte-stability promise — that contract stays `to_json`'s alone. New `--net` flag
      boots the NIC so there is a tap to observe (observe-only; the `--allow` policy projection stays
      in the CLI-completeness phase, which inherits `--net` shipped).)*
- [x] **P14.4** Export the record (JSON) for later inspection.
      *(Landed: `--record FILE` writes the run's `RunRecord::to_json` — one line, deterministic,
      byte-stable (the machine surface the SDKs will parse) — composable with `--json`, `--trace`,
      and `--watch`.)*
- [x] **P14.5** Test/demo: run something interesting, watch it live, read the trace after.
      *(Landed: the demo is one command — `agent run --unjailed --net --watch --trace --record
      run.json -- python3 …` (docs/cli.md + docs/examples-observe-a-run.md, "The whole run, fused") —
      watch the flows/denials/resources/syscalls live, read the trail after, keep the JSON. Proven by
      the `#[ignore]`d CLI e2e `run_with_trace_and_record_yields_trail_and_json` (`ci-privileged`):
      drives the **built `agent` binary** on a real networked sandbox and asserts the guest output +
      trail render on stdout, the record parses, and every axis binds (no coverage gap). Host-safe
      unit tests pin the trail's golden text and the timeline diffing.)*
- **Exit gate:** a compelling live view of hardware-isolated runs; the demo you show people.
  *(Met: one flag set on `agent run` shows a hardware-isolated run live — its flows as the guest
  makes them, denials as policy drops them, resources, the VMM's footprint, a timeline — then leaves
  behind the human trail and the machine record, all host-observed from outside the guest.
  Decision 029.)*

## Phase 14.9 — CLI completeness (interphase: the reference embedder, finished)

The CLI is the **reference embedder**, and the bar for a reference is *projection completeness*:
every engine capability reachable from the command line through a few orthogonal verbs — never flag
sprawl, never platform features. Today three library capabilities have no CLI face (limits, network
+ egress policy, host diagnosis), the config file layer is still a promise, and the JSON the CLI
emits is an unversioned de-facto contract. This interphase closes exactly that gap and nothing
more. The deliberate exclusions stay excluded: snapshot/pool verbs are the daemon's (P16.3 — a warm
pool is a long-lived-process concern, wrong for a one-shot CLI), the wire API is P16.2, and image/
registry management is platform territory (guardrail 4) that never lands. The design rule this
phase pins: **grow verbs, not modes** — `run`, `shell`, `doctor`, later `agentd`; not twenty
interacting flags on `run`.

- [x] **P14.9a** Project `Limits` onto the CLI: `--vcpus N` / `--mem MIB` on `run` and `shell`,
      with clap ranges matching the `NonZeroU8`/`NonZeroU32` types so a refused value is a typed
      CLI error, never a silent clamp. `--json` reports the effective limits back.
      *(Landed: `--vcpus N` / `--mem MIB` on both `run` and `shell`, parsed by `parse_vcpus` /
      `parse_mem_mib` straight into the `Limits` non-zero types — parsing *into* `NonZeroU8`/
      `NonZeroU32` rejects `0` (and non-numbers / overflow) as a typed clap error, and `--vcpus`
      additionally caps at 32 (`MAX_VCPUS`, the pinned Firecracker v1.9 microVM ceiling, decision
      001). A refused value is an error at parse, never a silent clamp nor a late boot-time API
      failure. `limits_with(vcpus, mem)` folds the two overrides onto the conservative defaults (the
      shared knobs of `run` and `shell`; `run` layers `--wall`/`--output-cap` on top), and `--json`
      echoes the **effective** limits back (`vcpus`, `mem_mib`, `wall_ms`, `output_cap_bytes`) so a
      caller sees what it got. Host-safe unit tests cover the parse domain (0/33/300/non-number
      refused, 1 and 32 accepted, 1 MiB floor) and the default-fold precedence.)*
- [x] **P14.9b** Project the network + egress policy: `--net` boots with a NIC (unchanged
      deny-by-default: a `--net` run with no allowance reaches nothing but the host /30 — **this
      half already landed with the observability face**, P14.3/decision 029, observe-only), and a
      repeatable `--allow IP[/CIDR][:PORT][/PROTO]` builds the `EgressPolicy`, armed **before** the
      tap goes live (the no-unpoliced-window property, decision 025). Every allowance is explicit
      on the command line — the greppable audit line guardrail 3 asks for — and lands in the run's
      denial/flow record. This is the CLI composing both tracks (driver + probes) the way the
      audit-bundle launch sequence does; `--allow` without `--net`, or enforcement without the
      needed caps, is a typed refusal, not a degradation.
      *(Landed: repeatable `--allow` on `run`, `requires` `--net` at clap. `parse_allow` reads
      `IP[/CIDR][:PORT][/PROTO]` right-to-left (the `/tcp`|`/udp` suffix first, so a numeric CIDR
      prefix can't be mistaken for it) into a validated `AllowRule`, each malformed field a typed
      CLI error naming the token; `build_egress` folds them into a deny-by-default `EgressPolicy`,
      capped at `MAX_POLICY_RULES` with a typed refusal. The CLI hands the policy to
      `SandboxProbes::attach` as `Some(...)`, arming enforcement on the tap before the tc programs go
      live (decision 025). **Enforcement doesn't fail open** (unlike observation, decision 029): a
      cheap pre-boot `check_support()` refuses on a host missing BTF/`CAP_BPF`/`CAP_PERFMON`, and the
      CLI's `Observability::attach` refuses post-attach if the *network* axis gapped (the residual
      `CAP_NET_ADMIN`/tc case) — a policed run that can't arm is a typed error, never a silent
      unenforced run. Host-safe unit tests cover the parse grammar (every field combination + each
      malformed field), the deny-by-default fold + rule cap, and the enforcement-refusal keying on
      the network axis alone; the `#[ignore]`d CLI e2e
      `allow_enforces_egress_and_the_record_shows_the_allowed_flow_and_the_denial` boots a real
      networked sandbox, allows the fixed host end `10.200.0.1` on one UDP port, and asserts the
      allowed flow **and** the denial for the blocked port land in the `--record` JSON. Decision 030.)*
- [x] **P14.9c** The `.agent.toml` file layer: **flags > env (`AGENT_*`) > file > defaults**
      becomes real. Discovery and precedence are a `(decision)` (proposed: nearest `.agent.toml`
      up from the cwd, keys mirroring the env names 1:1 so the three layers stay one vocabulary);
      unknown keys are a typed error (config typos must not silently no-op). Precedence proven by
      unit tests per layer pair.
      *(Landed: `agent-cli`'s new `config` module — the nearest `.agent.toml` walking up from the cwd,
      `serde(deny_unknown_fields)` so a typo is a typed error naming the valid keys (not a silent
      no-op), keys mirroring the `AGENT_*` names 1:1. The layering reuses the engine, not a
      reimplementation: `BootConfig::from_env_with` is made public and the CLI composes
      `env.or(file)` into its lookup, resolving `env > file > defaults` with zero duplication of the
      engine's env-key logic or pinned defaults; the fieldless `log` value gets a parallel
      `flag > env > file > default` resolver. Host-safe unit tests cover each layer pair (env>file,
      file>default), the deny-unknown-fields error, and nearest-up-from-cwd discovery. Decision 031.)*
- [x] **P14.9d** `agent doctor`: ship the host check as an engine subcommand — KVM, the jailer
      binary + real-root, iproute2/e2fsprogs, kernel BTF + `CAP_BPF`/`CAP_PERFMON`, artifact
      presence, and the degrades-vs-hard-errors matrix (P6.9b's content, today locked in dev-only
      `xtask setup`). An operator on a fresh host runs `agent doctor` *before* the first sandbox
      and reads exactly what will work, degrade, or refuse. `xtask setup` delegates to it (one
      implementation, two entry points).
      *(Landed: the shared implementation is `agent-vmm::doctor` — a structured `Vec<Check>` with an
      `Ok`/`Warn`/`Fail` status + the degradation matrix, the engine-runtime prerequisites in the
      engine's own crate. `agent doctor` renders it + the eBPF-capability row (from the probe loader,
      out of `agent-vmm`, decisions 024/026) and exits non-zero on any hard `Fail` so
      `agent doctor && agent run …` gates; `xtask setup` renders the **same** checks + its dev-only
      toolchain rows (bpf-linker/nightly/readelf). The status split mirrors the engine's error
      discipline: `/dev/kvm` + artifacts are hard, the jailer/caps/tools fail open with a named
      consequence. Host-safe unit tests cover the status classification, `can_boot`, and the check
      set. Decision 032.)*
- [x] **P14.9e** Version the JSON surface: a `schema` field (integer, starting at `1`) on the
      `--json` run result **and** the audit-record JSON, plus a written compatibility policy
      (additive within a version; field rename/removal bumps it). This is the seed the wire API
      (P16.2) and the SDK freeze (Phase 20) harden — versioning lands *before* anything external
      parses these bytes, not after. (The audit record's open field questions are already settled:
      `overflow_events` semantics and the u64-nanosecond ceiling, decision 028's hardening pass.)
      *(Landed: a leading `schema` field on both surfaces — `RUN_RESULT_SCHEMA` on the `--json` run
      result and `AUDIT_SCHEMA_VERSION` on `RunRecord::to_json`, each starting at `1` and versioned
      independently (two contracts). The compatibility policy — additive within a version, a
      rename/removal bumps it — is written in `docs/cli.md`. The audit-record golden test pins the
      new leading bytes. Decision 032.)*
- [x] **P14.9f** Prove completeness end to end: on a fresh host, `agent doctor` → one `agent run`
      driving every projection at once (limits + `--net`/`--allow` + `--put`/`--get` + stdin +
      `--json`, with `--trace` if P14.3 has landed) — and `docs/cli.md` rewritten to document the
      finished surface, including the capability↔flag map and the explicit "daemon-scoped, by
      design" list (snapshots, pool, wire API) so absence reads as intent, not omission.
      *(Landed: the `#[ignore]`d CLI e2e `doctor_passes_then_one_run_drives_every_projection_at_once`
      (`ci-privileged`) runs `agent doctor` (asserts ready, exit 0) then one `agent run` folding
      `--vcpus`/`--mem` + `--net`/`--allow` + `--put`/`--get` + piped stdin + `--json` through the
      built binary, asserting the schema-versioned result echoes the effective limits and the
      injected file + stdin round-trip back through `--get`. `docs/cli.md` gains the capability↔flag
      map and the explicit daemon-scoped/platform exclusions list (snapshots, pool, wire API,
      tenancy) so absence reads as intent.)*
- **Exit gate:** every engine capability is reachable from the CLI or named as deliberately
  daemon-scoped; config layers all four levels; a fresh host self-diagnoses with `agent doctor`;
  and the JSON the CLI emits is a versioned contract.
  *(Met: the capability↔flag map in `docs/cli.md` accounts for every library capability — projected
  as a flag/verb, or named daemon-scoped/platform; `flags > env > .agent.toml > defaults` layers all
  four levels; `agent doctor` self-diagnoses a fresh host (and gates via its exit code); both `--json`
  and the audit record carry a versioned `schema`. Decisions 031, 032.)*

## Phase 15 — Hardening & the trust story (multi-tenant safety)

Prove the isolation + observation claims hold under adversarial workloads: that **any run is fully
contained from every other run and from the host**, so a hoster can place mutually-distrusting callers
on one shared host. This is the *consolidated* adversarial suite. Its constituents already pass
individually — jail escape (P6.6), fork-bomb / mem-hog bounded by the cgroup (P6.8), deny-by-default
egress with an allow-listed exception (P4.7), no-leak teardown of a killed/crashed run (P6.7, P6.9a) —
and this phase runs them as one hostile guest and closes the last gaps. Tenant-agnostic throughout: the
engine guarantees per-run containment; whose run is whose is the hoster's (decisions 016, 022).

- [x] **P15.1** Adversarial suite: guest tries to escape/DoS/exfiltrate → contained + recorded.
      *(Landed as `probes-loader/tests/hardening.rs::a_hostile_guest_is_contained_and_the_record_shows_it`:
      one hostile guest **exfiltrates** to a blocked endpoint (dropped at the tap, the drop recorded in
      the fused `RunRecord`'s denial trail) and **DoS**es the host with a 50-process fork storm (which
      creates zero host threads — hardware isolation), while the allow-listed exception and a clean
      coverage set show in the *same* record and the VM stays exec-responsive afterward. The cgroup
      cpu/mem/pid caps under real hostile load are the `agent-vmm` confinement suite's real-root
      mem-hog/fork-bomb (P6.8) and full VM/jail escape is P6.6; this consolidates the observed-and-
      recorded dimensions on the probe-capability path, adding the part those pieces lack — the record
      as the evidence.)*
- [x] **P15.2** Confirm the guest cannot see or disable the host-side probes.
      *(Landed as `hardening.rs::a_guest_cannot_see_or_disable_the_host_side_probes`: the guest runs its
      **own** kernel inside the microVM while the eBPF lives in the **host** kernel and the tap monitor
      sits on the host end of the VM's tap — outside the guest — so a guest that hunts for the
      observability (finds zero BPF objects in its view) and then sends identifiable traffic is **still
      fully recorded** with clean coverage. It can't disable what it can't reach; the proof is
      behavioural — the host keeps recording across the guest's attempts.)*
- [x] **P15.3** Resource-exhaustion, fork-bomb, network-flood → bounded by cgroup + egress policy.
      *(Landed as `hardening.rs::all_exhaustion_vectors_are_bounded_by_the_cgroup_and_egress_policy`:
      one hostile guest under both a cgroup cap and an enforcing egress policy hits every axis at once
      — a memory hog (stays under `memory.max`, no host OOM-kill of the VMM), a fork storm (zero host
      threads, host CPU within the `cpu.max` quota), and a 200-packet network flood to a blocked
      endpoint (dropped at the tap at volume, a high denial count in the record) — while the
      allow-listed endpoint keeps working and the VM stays responsive. Real-root + probe-caps gated,
      skips with a reason otherwise. The two enforcement mechanisms bound all three vectors together.)*
- [x] **P15.4** Snapshot-restore correctness under load (no state bleed between clones).
      *(Landed as `snapshot.rs::restored_clones_do_not_bleed_state_under_load`: N clones restored from
      one prewarmed snapshot each write a **distinct** secret to the same guest path and read it back,
      all in flight at once (each clone drives its own thread). A shared writable disk would let a
      sibling's concurrent write clobber the path; instead each reads back exactly its own — per-clone
      in-RAM overlay + guest RAM, shared base read-only, no bleed. Guards against a vacuous pass by
      asserting the secrets were distinct.)*
- [x] **P15.5** Document the **threat model**: what's trusted (CPU/KVM/host kernel), what isn't.
      *(Landed as `docs/threat-model.md` (linked under Security in `SUMMARY.md`): assets in priority
      order, the trusted/untrusted boundary, the fully-hostile-guest adversary, an attack-class →
      mechanism → proving-test table, and the explicit assumptions/residual risk (KVM + host-kernel
      soundness, side channels) and out-of-scope (engine, not platform). `security.md` now points at
      it as its companion. The `(decision)` recording the boundary is P15.6, still open.)*
- [x] **P15.6** `(decision)` the security boundary + assumptions → `docs/contributing-architecture.md`. *(Seeded early
      by decision 016, the engine/hoster line the P6.9a sweep forced: the engine guarantees its
      privileged tools can't be weaponized (euid-scoped, authorship not policy), the hoster owns
      deployment (scheduling, per-identity sweeps, base hardening, dividing the /16 pool). **Closed as
      decision 033**: the whole boundary written down — trusted (CPU/KVM/host kernel/driver/host-eBPF)
      vs not (the guest incl. its own kernel + the in-guest agent), the fully-hostile-guest adversary,
      the assumptions/residual risk (KVM + host-kernel soundness, side channels, fair scheduling), and
      the map from each attack class to the test that proves it. `docs/threat-model.md` (P15.5) is its
      reader-facing companion; decision 016 is one worked facet, 022 the multi-tenant claim, 033 the
      closure.)*
- [x] **P15.7** Close the cgroup matrix. **`pids.max` is done** (`jail.rs`, added to the per-VM cgroup
      alongside `cpu.max`/`memory.max`, fail-open per controller, host-gate unit-tested; a privileged
      readback stays pending). It is host-side *defense in depth*: a guest fork-bomb is already bounded
      by `memory.max` and never reaches the host (P6.8), but a hypervisor-level exploit that forked
      *host* processes is now capped. **IO bandwidth is now bounded** via Firecracker's per-drive
      **virtio-blk rate limiter** (the engine-native control, not host `io.max`): a derived default
      (`RateLimiter::default_guest_io` — 256 MiB/s with a 1 GiB `one_time_burst` sized past any rootfs,
      so a cold boot's read fits the burst and runs unthrottled *by construction*; only *sustained*
      thrashing is throttled), set on every drive at cold-boot `put_drive`, host-safe unit-tested for
      both the wire shape and the numbers. It **rides restore**: a clone reopens the drive from the
      snapshot state file, which carries the limiter. (The cgroup caps used *not* to ride restore — a
      pre-existing gap now closed under P15.8.) An **internal derived default,
      not a new `Limits` knob** (decision 013), so the public contract is unchanged and this is
      non-`api:`; the measured boot-latency-is-unchanged confirmation and a throttle readback stay
      pending on a privileged host, like `pids.max`. Decision 033 records the boundary this sits in.
- [x] **P15.8** **Co-resident interference test:** launch a hostile run (cpu/mem/pid/io/network storm)
      alongside a well-behaved run on the same host and assert the victim run is not starved, slowed
      past a bound, or observable by the attacker — the explicitly multi-tenant assertion the hoster
      gates on (still tenant-agnostic: two *runs*, no tenant concept).
      *(Two parts. First, the **prerequisite fix**: a jailed **restore** now re-applies the cgroup caps
      (`spawn.rs`), so a restored clone — where untrusted code runs — is confined, not just isolated.
      Both caps derive from the *snapshot's* true envelope, never `config`'s declaration (the clone's
      vCPUs and RAM come from the snapshot state; restore issues no `PUT /machine-config`): `memory.max`
      from the memory file's true guest RAM (`jail::restore_mem_mib`, unit-tested — the old OOM hazard),
      `cpu.max` from the vCPU count recorded in the bundle (`Snapshot::vcpus`, so a config defaulting to
      fewer vCPUs than the source can't silently throttle a clone — proven by
      `snapshot.rs::restored_clone_cpu_cap_follows_the_snapshot_not_the_config`), constant `pids.max`.
      Then the test,
      `confinement.rs::a_hostile_run_cannot_starve_or_observe_a_co_resident_run`: two co-resident runs
      each in its own capped cgroup; the attacker storms 100 spinning processes while the victim reruns
      a CPU-bound workload, and the victim's result stays **correct** and within a generous wall-clock
      ceiling, while the attacker's host CPU stays **within its cgroup quota** (so it can't monopolize
      the host — the victim's share is protected by construction). Distinct VMMs prove non-observability
      of the process; network non-observability between runs is the per-VM netns (net.rs, decision 017).
      Real-root + delegated-cgroups gated.)*
- [x] **P15.9** **Fuzz the untrusted-input boundary:** the host↔guest channel decoders, where a hostile
      guest chooses the bytes the host parses. *(Landed early as a Phase-15 constituent, like the jail/
      cgroup/egress checks the intro lists. Two tiers: a **dependency-free property harness in the `ci`
      gate** (`crates/channel` `fuzz_tests`: arbitrary bytes, well-framed random bodies, encode/decode
      round-trips, and every truncation of a valid frame, asserting the decoders never panic, hang, or
      allocate past `MAX_PAYLOAD` — guardrail 5, on stable, deterministic seeds so it can't flake); and
      a **`cargo fuzz` (libFuzzer) harness** in the workspace-excluded `fuzz/` crate for deep nightly
      runs (`cargo xtask fuzz`), reaching the decoders via the channel crate's off-by-default `fuzzing`
      feature so the wire crate stays dependency-free. Documented in `docs/contributing-fuzzing.md`.)*
- **Exit gate:** the **containment suite is green** — one hostile guest tries to escape the VM, reach
  the network, exceed its cpu/mem/pid/io caps, exhaust the host, and interfere with a co-resident run,
  and **each attempt fails** — so the engine is safe to host mutually-distrusting callers on a shared
  host; the **threat model** is documented. ("Safe for multi-tenant hosting" means exactly this suite
  green, nothing less.)

---

## Cross-cutting

## Phase 16 — The driver daemon + wire API (the engine's interface)

A local daemon others drive over a socket: still engine, not PaaS.

- [ ] **P16.1** `agentd`: a long-lived daemon exposing the sandbox lifecycle over a unix socket.
- [ ] **P16.2** A **versioned** wire API (JSON/gRPC — `(decision)`): open/exec/put/get/snapshot/
      close/trace. This is the **SDK contract** — Phase 20 freezes and spec's it.
- [ ] **P16.3** Pre-warmed-pool management lives in the daemon (fast `exec`).
- [ ] **P16.4** A **reference (Rust) client** proving a non-Rust caller can drive `agentd` over the
      wire API — the seed the **polyglot SDKs (Phase 20)** harden into Go/Python/Node/C#. (The full
      SDK set is post-`v0.1.0`.)
- [ ] **P16.5** Structured logs + a metrics endpoint (Prometheus) — for the *hoster* to scrape.
- [ ] **P16.6** Explicitly document the non-goals again at the API layer (no tenancy/auth/billing).
- [ ] **P16.7** Golden: the CLI and the daemon API produce identical run results.
- **Exit gate:** a self-hostable sandbox daemon with a clean API; the client/server boundary, and
  where a PaaS would begin (and why it's not here), are documented.

## Phase 17 — Performance & scale

Make the numbers real — the benchmarks that back every claim.

- [ ] **P17.1** Benchmarks: cold boot, snapshot restore, pre-warmed-pool `exec` latency (p50/p99).
- [ ] **P17.2** Memory-sharing: how many concurrent microVMs per host before it degrades.
- [ ] **P17.3** eBPF overhead: cost of the probes under load.
- [ ] **P17.4** Memory footprint per sandbox; the effect of overlay/rootfs choices.
- [ ] **P17.5** A reproducible bench harness + a results report vs the honest baselines.
- [ ] **P17.6** Find + fix the top bottleneck the numbers reveal.
- **Exit gate:** documented latency/memory-sharing/overhead numbers, with the methodology stated
  (percentiles, not averages).

## Phase 18 — AI-native surfaces (the runtime for agent-generated code)

The engine's highest-value untrusted workload is **AI-generated code and autonomous agents** — the
dynamic, possibly-misaligned input the isolation-and-audit thesis was built to contain. Make that a
first-class fit **without embedding a model.** A model in the host path is not an isolation boundary
(invariant 1), and dragging inference (unbounded, un-benchmarkable) or model-driven policy into the
engine would break "engine, not platform" and "measured, not marketed" (invariants 3, 4). So the
model always stays the **caller's**; the engine stays the containment-and-audit substrate it already
is. This phase puts a **model-legible face** on the record the engine already builds and proves the
containment story end to end — no new isolation, no bundled model — leaning on the documented threat
model (Phase 15) and the daemon + wire API (Phase 16) an agent drives it through.

- [ ] **P18.1** `(decision)` **The AI-scope boundary** → `docs/contributing-architecture.md`: the
      model is always the **caller**, never an engine component; the engine's whole contribution is
      hardware containment plus a host-observed, **model-legible** record; the reference example
      drives the engine with a **deterministic scripted agent**, not a live model (so the demo is
      CI-reproducible and needs no API keys). Records why embedding a model, or letting one decide
      policy, would break invariants 1 / 3 / 4 — so the line is auditable and can't drift into a
      slap-on.
- [ ] **P18.2** A **model-legible projection of the audit record** — a third face alongside `--trace`
      (human) and `--record` (machine JSON), surfaced as `agent run --record-summary FILE` and a
      `RunRecord` method: a compact, semantically-labelled summary shaped to feed straight back into
      an agent's observe→act loop (what it read/wrote, which flows it opened, what egress was
      **denied**, its resource envelope, and any coverage gap). A **view of the existing `RunRecord`**,
      not new machinery: deterministic, byte-stable, carrying its own leading `schema` field, and
      **golden-tested** like the full record. Its size is **measured and bounded** against the full
      record, so "compact" is a number, not a claim (invariant 4).
- [ ] **P18.3** The projection joins the **wire API** (P16.2), so the daemon serves it and the
      **Phase 20 SDKs** expose it as part of the SDK contract — an agent driving `agentd` from any
      language reads the same model-legible observation the CLI writes, not a CLI-only convenience.
- [ ] **P18.4** A **reference agent-containment example** (`docs/examples`): a **scripted agent** (a
      deterministic stand-in for an LLM's tool loop — no model, no secrets) runs inside a sandbox,
      egress-policed with `--allow` to only its permitted tool / MCP endpoints, makes one allowed call
      and one that is **denied**, and the host-observed record + projection prove **exactly what it
      reached and what was blocked**. Uses only surfaces the engine already ships (`--net` / `--allow`
      / `--record` + P18.2). This is the thesis applied to the workload of the moment — the
      tamper-resistant, host-observed audit trail a supervisor needs to trust an agent, which the
      pure-execution sandboxes can't offer.
- **Exit gate:** the scripted agent runs contained and **CI-reproducibly** — its egress policed to an
  allow-list, one permitted tool call succeeding and one denied — and the **model-legible record**
  (from the CLI and over the wire API) shows what it did and what was blocked, its size measured
  against the full record, **with no model anywhere in the host path.**

## Phase 19 — Packaging & docs

Ship it as a thing others can run: packaged, documented, and self-hostable.

- [ ] **P19.1** Single-command self-host: build the rootfs/kernel, install the daemon, run a sandbox.
      *(Includes vendoring the sha-pinned upstream inputs — the Firecracker CI kernel/rootfs and the
      `.apk` closure (decision 007's note, P6.9d's recording) — so a fresh host's setup no longer
      depends on the FC S3 bucket or the Alpine CDN staying alive.)*
- [ ] **P19.2** `curl | sh` / container / release binaries with checksums.
- [ ] **P19.3** Docs site: quickstart, the engine API, the threat model, the non-goals.
- [ ] **P19.4** A **launch announcement**: what it is, the threat model, and how to self-host it.
- [ ] **P19.5** A **reference integration**: a small host application embedding the engine end to end.
- [ ] **P19.6** Example workloads (run untrusted Python, an untrusted binary, a CI job) as demos.
- [ ] **P19.7** Security policy + responsible-disclosure notes.
- [ ] **P19.8** v0.1 tag: boots a microVM, runs code, enforces + records it, self-hostable, documented.
- **Exit gate:** a stranger can `git clone`, self-host the engine, run untrusted code in a microVM,
  and read the eBPF-observed audit trail.

---

## Post-v0.1.0 — vNext tracks

> These land **after** the `v0.1.0` finish line (P19.8) and **do not gate that tag** (§0.6). They
> extend the engine **outward** (more callers) and **sideways** (a second isolation boundary)
> — without pulling tenancy/billing/scheduling into scope, and without diluting the
> core properties. Both depend on Phase 16's daemon + wire API.
>
> **Each ships as its own repository** — the four SDKs and the Wasmtime engine are all separate
> repos. This repo owns only the **contract** they build against: the versioned wire API, the
> cross-language conformance suite, and a reference Rust client. So the boxes below track *that
> contract (and its certification) landing here* — the SDK/engine **code lives in its sibling
> repo**, gated by the conformance suite this repo publishes.

## Phase 20 — Polyglot SDKs (Go · Python · C# · Node.js)

Thin, idiomatic clients so non-Rust callers can drive `agentd` — a client-SDK surface, still
**engine, not platform**.

- [ ] **P20.1** `(decision)` Freeze + version the P16 wire API as a **language-agnostic spec** (the
      SDK contract): message schema, the error taxonomy, and a semver compat policy → `docs/contributing-architecture.md`.
- [ ] **P20.2** A **cross-language conformance suite** (golden request/response + audit-log
      round-trips) every SDK must pass — the single source of SDK correctness, run in CI.
- [ ] **P20.3** **Go** SDK (own repo): open/exec/put/get/snapshot/close/trace against `agentd`.
- [ ] **P20.4** **Python** SDK (own repo; sync + async).
- [ ] **P20.5** **Node.js / TypeScript** SDK (own repo).
- [ ] **P20.6** **C# / .NET** SDK (own repo).
- [ ] **P20.7** Every SDK is **its own repository** (out of this Rust workspace + host gate), pinned
      to a wire-API version, certified by the P20.2 conformance suite, and published to its language
      registry with checksums.
- [ ] **P20.8** Each SDK is a **thin protocol client** — no tenancy/auth/billing/scheduling; deny-by-
      default and the non-goals hold at the SDK layer too (note).
- **Exit gate:** four languages run the same golden `exec` and read the same host-observed
  audit log through `agentd`, against one stable polyglot wire API with a shared conformance suite.

## Phase 21 — The Wasmtime sibling (a second isolation boundary)

A **separate** engine that reuses this one's driver API + audit-log format but swaps the
isolation boundary from **hardware (KVM)** to **software (Wasmtime SFI)** — a second isolation
option, not a replacement for this repo.

- [ ] **P21.1** `(decision)` **Sibling repo, not a backend here.** Core property 1 (*isolation is
      hardware*) is never traded in this engine; the wasm variant carries a **different, weaker**
      guarantee, so it's a distinct artifact that *shares the API*, not a plug-in backend →
      `docs/contributing-architecture.md`.
- [ ] **P21.2** Wasmtime embedding: `Engine`/`Store`/`Module` with **fuel + epoch** (CPU/timeout) and
      a `ResourceLimiter` (memory) → typed limits, mirroring the FC engine's no-hang/no-leak contract.
- [ ] **P21.3** The **host-function (WASI) shim layer** = capabilities + policy + audit log:
      enforcement moves from host-side eBPF to the **import boundary** (the module has zero ambient
      authority; deny-by-default becomes "link no imports").
- [ ] **P21.4** Reuse the `Sandbox` lifecycle shape + the audit-log **JSON schema**, so a caller
      (and the Phase 20 SDKs) can drive either engine.
- [ ] **P21.5** Comparative benchmarks: **instantiate latency + fuel overhead + memory-sharing** vs the
      microVM's boot/restore/memory-sharing — same harness, honest numbers.
- [ ] **P21.6** Test: the same untrusted program on both engines yields comparable audit-log
      records; where they *can't* be comparable, document why.
- **Exit gate:** two engines, one API, two isolation boundaries, with a documented **hardware vs
  software** comparison: TCB size, startup, memory-sharing, scope, and threat model.

---

## Architectural invariants (never traded away)

1. **Isolation is hardware.** Untrusted code runs in a KVM microVM; the trust boundary is the CPU,
   not guest-side software.
2. **Observe & enforce from the host.** Visibility and policy live in host-side eBPF, which the
   guest cannot see or disable. In-guest agents are for convenience (exec/IO), never for security.
3. **Engine, not platform.** A self-hostable runtime + a driver API. Multi-tenant auth, billing,
   fleet scheduling, and dashboards are **out of scope** — the hoster's job. (A recorded non-goal.)
4. **Measured, not marketed.** Boot/restore/memory-sharing/overhead are benchmarked with percentiles; no
   hand-waved performance claims.
5. **No-panic on the host path.** A hostile or crashing guest, a failed probe, or a broken channel
   is a typed error, never a host panic, hang, or leak.
6. **Deny by default.** A sandbox with no explicit policy reaches no network and has minimal
   capability; every allowance is explicit and recorded.
7. **Git is human-driven.** The user makes every commit/branch/push; the coding agent stops at
   changes made, demo working, box checked in the working tree.
