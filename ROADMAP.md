# Roadmap

> **What we're building:** a self-hostable, isolated **code-execution sandbox** — **Firecracker**
> microVMs for hardware isolation, **aya/eBPF** for observability and network policy at the *host*
> boundary (where the guest can't tamper with you). Run untrusted code in a microVM; watch and
> enforce what it does from the kernel, outside the guest.
>
> **Why:** this is a **Linux-mastery vehicle** on the path to Principal Platform Engineer — not a
> business. Firecracker + aya together teach Linux from the hardware-isolation boundary up to the
> syscall/network boundary: the rarest, hardest-to-fake systems depth on a platform team. **Every
> phase ships a working demo, a Linux-internals lesson worth a blog post, and a design-doc seed.**
>
> **The line (K8s is not a PaaS, and neither is this):** we build the **engine** — a runtime you
> self-host. Multi-tenant auth, billing, scheduling across a fleet, a web dashboard — **out of
> scope**, the hoster's job. `containerd`, not Docker Cloud.
>
> **Scope of this repo:** the **core engine** — the Firecracker + eBPF sandbox of **Phases 0–18**,
> defined by the four spine properties (§0). The **vNext tracks** (Phases 19–20: the polyglot SDKs
> and the software-isolation Wasmtime sibling) are **adjacent repos** — they build on this engine's
> frozen wire API + flight-recorder format, but their code lives **outside** this repo and is
> tracked here only as a forward map. This repo never trades its spine to accommodate them: the
> Wasmtime variant is a *sibling, not a backend* (Phase 20), so *isolation is hardware* holds here
> without exception.
>
> This file is the **single source of truth for progress** — of the core engine, and a map to its
> sibling repos. Its checkboxes are the state.

## §0 The spine

Four properties every phase must protect:

1. **Isolation is hardware, not software.** Untrusted code runs in a Firecracker microVM (KVM).
   The host trusts the CPU boundary, not the guest.
2. **Observe & enforce from the host.** Visibility and policy live in **host-side eBPF** (syscalls,
   the microVM's tap device, its cgroup) — the guest cannot see or subvert them.
3. **Engine, not platform.** A self-hostable runtime + a clean driver API. No auth/billing/
   dashboard/fleet-scheduler in this repo (tombstone: that's the hoster's).
4. **Measured, and taught.** Boot time, density, and eBPF overhead are benchmarked, not claimed;
   every phase produces a writeup so the learning outlives the diff.

## §0.5 How to work this roadmap (the working loop)

- **Sequentially gated.** Never start a phase before the prior phase's **Exit gate** passes.
- **First unchecked box, in ID order.** One item per iteration.
- **Two tracks, one spine.** **FC** (Firecracker) and **BPF** (aya/eBPF) can be learned somewhat
  in parallel, but the **Convergence** phases need both, so the gate order still holds.
- **Every phase exits on a demo + a lesson.** The exit gate is "I can show it running *and* write
  up the Linux mechanism it taught me."
- **Hard-to-reverse choices** (tagged `(decision)`) land as dated entries in `ARCHITECTURE.md`.
- **Git is human-driven.** The user makes every commit/branch/push; the coding agent's job ends at
  changes made, demo working, box checked in the working tree.

## §0.6 Versioning (the finish line)

- **`v0.1.0` is the finish line** — the first real release, cut only once **every phase below is
  green** (a microVM boots, runs code, is enforced + recorded, self-hostable, documented; this is
  P18.8).
- **The vNext tracks (Phases 19–20) are post-`v0.1.0`** and do **not** gate that tag. The **polyglot
  SDKs** extend the engine outward (more callers) and the **Wasmtime sibling** extends it sideways
  (a second isolation boundary, to master both). Both presuppose the frozen wire API of Phase 16;
  neither pulls tenancy/billing/scheduling into scope, and the Wasmtime sibling never dilutes this
  engine's spine (it's a separate artifact — see Phase 20).
- **Everything until then is a pre-release `v0.0.x`.** Tag the foundation baseline (the engine
  boots and tears down microVMs) as an internal **`v0.0.1`**; later milestones bump the `0.0.x`
  patch as they land. These are checkpoints, not releases — no stability promise.
- Tags are a **human git step** (§0.5): the coding agent checks boxes; the user cuts the tag.
- **No `CHANGELOG.md` until `v0.1.0`.** In the pre-release line the roadmap checkboxes, the
  `docs/` writeups, and `ARCHITECTURE.md`'s decision log *are* the change record; a curated
  changelog is written once, for the first real release, rather than churned every `v0.0.x`.

## §0.75 Dev environment (one-time)

A modern Linux box with `/dev/kvm` (the dev machine already has a bleeding-edge kernel + BTF —
ideal for both KVM and CO-RE eBPF). Prerequisites the first phase pins down: the `firecracker`
binary + jailer, a guest kernel (`vmlinux`), a way to build a rootfs, and the aya toolchain
(`bpf-linker`, the `bpfel-unknown-none` target, `CAP_BPF`/root for loading).

---

## Phase 0 — Reset the repo to the sandbox engine

Turn `agent` from the wasm scanner into the Firecracker + aya sandbox; keep the git history.

- [x] **P0.1** (human git step) Shelve the wasm/scanner work on a branch, then gut `main`: remove
      `crates/{abi,host,detectors,sandbox}`, `detectors/`. *(Gut done; scanner preserved at
      `f54d353` on `origin/main` — create `archive/wasm-scanner` to name the point.)*
- [x] **P0.2** New workspace layout: `crates/vmm` (Firecracker driver), `crates/probes` (aya
      eBPF programs, `no_std`, excluded), `crates/probes-loader` (userspace loader), `crates/cli`
      (`agent`), `xtask`.
- [x] **P0.3** Rewrite `.rules` / `README.md` / `CONTRIBUTING.md` / `ARCHITECTURE.md` to the
      sandbox-engine identity and the four spine properties; drop the detector/`Verdict`/feed framing.
- [x] **P0.4** Prerequisites pinned in `CONTRIBUTING.md` (KVM, BTF, `firecracker`+jailer, aya
      toolchain, caps); `cargo xtask setup` checks the host and reports what's missing.
- [x] **P0.5** `cargo xtask ci` skeleton: fmt · clippy `-D warnings` · build · test · docs · deny
      (the eBPF crate builds for its own target, gated separately — see P8).
- [x] **P0.6** Naming: keep the `agent` umbrella (binary + repo); crates are
      `vmm`/`probes`/`probes-loader`/`cli`.
- [x] **P0.7** A short `docs/` for the per-phase writeups each phase feeds. *(No `CHANGELOG.md`
      in the pre-release `v0.0.x` line — the roadmap's checkboxes and `docs/` are the record; the
      changelog is first written at `v0.1.0`. See §0.6.)*
- [x] **P0.8** `cargo xtask ci-privileged` runs the KVM/eBPF (`#[ignore]`d) tests behind a
      `/dev/kvm` guard, so day-to-day dev isn't `sudo cargo` roulette.
- **Exit gate:** `cargo xtask ci` green on an empty-but-scaffolded tree; `xtask setup` verifies the
  host can do KVM + eBPF; docs describe the engine, not the scanner.

---

## Firecracker track — hardware isolation

## Phase 1 — Boot a microVM from Rust

The "hello, KVM" moment: a program that boots a real Linux microVM and reads its console.

- [x] **P1.1** `(decision)` how to drive Firecracker: its **HTTP API over a unix socket** vs the
      `firecracker` binary vs embedding `rust-vmm` crates → `ARCHITECTURE.md`. (Default: API socket.)
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
      every run, printed by `--demo-boot`. Excludes driver setup — see docs/001.)*
- [x] **P1.10** Test: boot → see the login/init banner → shut down, repeatable.
      *(`crates/vmm/tests/boot.rs`, `#[ignore]`d; two cycles asserting no leaked scratch dirs.)*
- **Exit gate + lesson:** a microVM boots to userspace from `cargo run` and shuts down clean; write
  up the **boot protocol** (kernel + boot args + virtio-block rootfs) and the microVM lifecycle.
  *(Demo: `agent run --demo-boot`. Writeup: `docs/001-boot-a-microvm.md`.)*

## Phase 2 — Run code in the guest & get results back

Turn "a VM boots" into "I handed it a command and captured stdout + exit code."

- [x] **P2.1** `(decision)` host↔guest channel: **vsock** vs a serial protocol vs a guest agent →
      `ARCHITECTURE.md`. (Default: vsock + a tiny guest agent.)
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
      `GuestUnavailable` variant (first retry/warm-pool caller, ~P5) and a `kind()` classifier
      (first caller that branches on bucket).)*
- [x] **P2.8** Test: `exec("echo hi")` → `hi`, exit 0; a crashing command → typed error.
      *(Happy path `exec_over_fake_vsock_runs_a_command` drives `echo hi` through the **real** agent
      → `hi\n`, exit 0. "Crashing → typed error" is disambiguated with two tests that pin the
      boundary: a command the guest can't spawn → `VmmError::GuestExec` (typed error), and
      `kill -9 $$` → `RunResult{exit_code:137}` (a faithful result, **not** an error — the
      host-side mapping, distinct from the guest-agent-layer signal-death test). Added the
      previously-untested channel bucket: a guest that drops mid-exec →
      `VmmError::Channel` with `is_disconnect()`. All KVM-free, in the host gate.)*
- **Exit gate + lesson:** `agent`-driven `exec` in a microVM returns real output; write up **vsock /
  guest agents** and how host↔guest comms actually work.
  *(Writeup: `docs/002-host-guest-comms.md`. The exec **engine** is complete and tested against the
  real guest agent (only the Firecracker vsock UDS is faked) + a privileged vsock-device boot smoke
  test. The **"in a microVM" clause was provisional** here — the agent wasn't baked into the rootfs
  or binding `AF_VSOCK` yet — and is now **closed by P3.1**: the literal in-VM `exec("echo hi") → hi,
  exit 0` runs against a real microVM. See `docs/002` "What's still stubbed".)*

## Phase 3 — Rootfs & the language runtime

Build the disk the guest runs, with a real runtime inside — natively, no wasm gymnastics. Python is
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
      unchanged after two boots; the exec/python tests now run overlay-backed. Density: the per-VM
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
      + `setup` check); boot-path build cost moves behind the warm pool at P5. Pulling large outputs
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
      artifacts) is tombstoned. Default `build-rootfs` stays one command.)*
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
      buys **density** (page-cache dedup across VMs + disk), not boot time — the honest, measured
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
      captured artifacts; writeup in `docs/003-rootfs-and-runtimes.md` (ext4 `mke2fs -d`, overlayfs,
      initramfs-vs-rootfs, reproducibility, static-vs-dynamic linking, inject-vs-bake).)*
- **Exit gate + lesson:** real Python **and a static native binary + Node** run in the microVM and
  produce artifacts — the rootfs is runtime-agnostic; write up **filesystems, ext4 images, overlayfs,
  initramfs vs rootfs, and static vs dynamic linking in a minimal rootfs.**

## Phase 4 — Networking

Give the microVM a network with per-VM isolation — the classic tap/bridge lesson.

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
      `ARCHITECTURE.md`. (Default: deny-by-default; explicit allow later, enforced in BPF track.)
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
      *(Enumerated in `docs/004-guest-networking.md` as an audit table: per networked VM the driver runs
      exactly `ip tuntap add` / `ip link set up` / `ip addr add <host>/30` plus the kernel `ip=` guest
      config, and installs **no** default route, **no** `MASQUERADE`/`nat`/`forward` rule, **no**
      `ip_forward`, no bridge, no netns. Teardown is the inverse of one line (`ip link del`). The
      point: the full host-side network change set is small and enumerable, which is what makes
      deny-by-default auditable, cross-referenced from decisions 008/009.)*
- **Exit gate + lesson:** a microVM has controlled network; write up **tap devices, bridges,
  netfilter/NAT, and virtio-net.**
  *(Done: `docs/004-guest-networking.md` teaches the tap backend (and why not a bridge/veth), virtio-net
  host-tap-to-guest-`eth0`, kernel `ip=`/`CONFIG_IP_PNP` static addressing with no rootfs change, the
  connected-route-is-the-whole-security-model lever with NAT/forwarding as the road not taken, the
  atomic per-VM /30, and the audit table. Working demo: the three `ci-privileged` network tests.
  Indexed in `docs/README.md`.)*

## Phase 5 — Snapshots & warm start

The fast-start magic: pause, snapshot, and restore — fork many VMs from one warm image.

> **Design for the Phase-6 jailer now.** Snapshot save/restore takes host paths for the mem file,
> state file, and block devices; under Phase 6's jailer those become chroot-relative and jailed-uid-
> owned. Lay out the snapshot + warm-pool files **chroot-relative from the start** so the jailer
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
      whose backing is a private, disposable copy; a read-only shared base is deferred to the warm
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
- [x] **P5.3** A "warm" snapshot: boot + runtime loaded (e.g. Python imported), snapshot *that*.
      *(`snapshot()` extended to the two things a warm snapshot needs (decision 010): a
      **`read_only_root`** boot (the disk is the shared pinned base at a persistent path, so the bundle
      **references it in place**, no per-VM copy) and the **vsock exec channel** (so a restored clone
      can run code). The warm-up runs the runtime once before snapshotting (`python3 -c "import ..."`),
      so the image captures a guest with Python resident, not a bare boot. Restore comes back
      **exec-ready**: Firecracker re-binds the guest agent's vsock listener on load, and `run_restore`
      polls until the agent is reachable before returning (restore's analogue of the boot
      userspace-marker wait). **Measured** (dev box): ~300 ms cold boot vs **~8 ms** restore, then Python
      runs on the clone. Closes P5.8's warm-restore-runs-code for the single clone. Proof:
      `warm_snapshot_restores_and_runs_code` warms, snapshots, drops the source, restores, and runs
      `python3` to `4`.)*
- [x] **P5.4** Restore N clones from one warm snapshot; each gets a fresh overlay/tap.
      *(N clones restored from one warm bundle, **all alive at once**, each an independent VM: its own
      in-RAM overlay (independent memory image) and its own vsock socket, while sharing the read-only
      base (page-cache-deduped density). The socket is the hard part, solved without the jailer: a
      first probe showed concurrent clones **collide** on the source's baked-in absolute socket path
      (`Address in use`), so the driver now binds vsock at a **relative** name and runs each VMM with
      its scratch dir as cwd (decision 010), so each clone re-binds its own `v.sock` in its own dir.
      That made every *file* path handed to Firecracker need to be absolute (its cwd moved), a small
      resolved-to-absolute pass. The **"fresh tap"** half is a networked snapshot, still deferred with
      network identity to P5.5. Proof: `restores_concurrent_clones_from_one_warm_snapshot` restores 3
      clones and keeps all three alive at once, asserts distinct live VMMs, and runs a distinct
      computation on each concurrently-alive clone, getting each clone's own answer. `ci-privileged` now runs the VM tests serially
      (real-VM integration is boot-I/O-bound and some assert on host-global leak state).)*
- [x] **P5.5** `(decision)` Handle the uniqueness problems restore creates (network identity,
      entropy, clocks) → `ARCHITECTURE.md`.
      *(Recorded as **decision 011**, all three implemented-or-measured. **Network identity** (the
      load-bearing one): keep `ip=` as the zero-overhead cold-boot path, and on restore the **guest
      agent applies the clone's fresh address over vsock** (flush the baked-in `eth0` addr, add the
      fresh /30's guest end), the runtime counterpart of boot-time `ip=`, with the empty-gateway
      deny-by-default invariant carried over (config rides the agent; enforcement stays host-side,
      spine #2). MMDS and per-tap DHCP rejected (a second in-guest config surface / a daemon, for what
      the existing exec channel does in one command). The driver recreates the snapshot's recorded tap
      with a fresh /30 (`Tap::create_named`); a networked snapshot without vsock is refused (no channel
      to re-address its clone). **Probed constraint:** Firecracker v1.9 rejects `network_overrides` on
      load ("unknown field", against the real binary), so the tap *name* is baked, so only **one
      networked clone can be live at a time** on this pin; concurrent networked clones need an FC bump
      or the Phase-6 jailer's netns (tombstoned; non-networked clones keep unbounded concurrency).
      **Entropy:** rely on **VMGenID** (FC v1.9 ships the device and bumps the generation on restore;
      the pinned 6.1.102 kernel's `vmgenid` driver reseeds the CRNG): no engine mechanism added, and
      the property is **proven, not assumed**: two clones' first-window `getrandom` draws differ, and a
      future pin that loses either half fails the test visibly. **Clocks:** kvm-clock keeps monotonic
      sane; the wall clock **lags by the snapshot's age** (measured ~9 s for a ~9 s-old snapshot) and
      the engine deliberately doesn't reach in to fix it (documented limitation; the flight recorder
      timestamps host-side). Decision 009 gained the "`ip=` is cold-boot-only by nature" addendum.
      Proof: `restored_networked_clone_gets_a_fresh_identity` (fresh /30 applied in-guest, old address
      gone, TCP-reachable on the new link, still deny-by-default, no-vsock refusal) and
      `restored_clones_do_not_share_entropy_or_freeze_the_clock` (urandom draws differ; skew reported).
      21 privileged tests, all run (not skipped) under a user+net namespace.)*
- [x] **P5.6** `Pool` that keeps warm restores ready so `exec` starts in ms. *(First warm-pool/retry
      caller: lands the `GuestUnavailable` variant + `kind()` classifier deferred at P2.7, so a
      restore that isn't accepting yet is a typed, retryable error, not an infra failure.)*
      *(`agent_vmm::Pool` (`pool.rs`): prefill `target` clones from one warm snapshot; `take()` pops
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
      `pool_serves_warm_clones_and_discards_dead_ones`: prefill 2, timed take + exec, SIGKILL a
      pooled clone's VMM behind the pool's back, next take discards the corpse and serves a fresh
      restore, refill tops back to target. 22 privileged tests.)*
- [x] **P5.7** Benchmark: cold boot vs snapshot restore vs warm-pool `exec` latency. *(Baseline
      to beat: Phase 1 boots a full rootfs copy in `/tmp` — on a tmpfs host that's ≈300 MB of RAM
      per sandbox on top of guest memory; overlays should collapse that.)*
      *(`cargo xtask bench-warm [--runs N]`: **time-to-first-result** (start a sandbox → a Python
      one-liner's output back on the host) on the three start paths, reusing `bench-boot`'s honest
      percentile reporting (nearest-rank, no `p99` under n=100); every sample verifies the answer
      actually came back, and teardown/pool-refill run off the clock (the between-requests cost).
      One warm snapshot feeds the restore and pool paths. Measured (dev box, n=100 per path): cold
      boot + exec on a per-VM rootfs copy (the Phase-1-style baseline) **p50 689 / p99 943 ms**;
      warm restore + exec **p50 105 / p99 172 ms**; pool take + exec **p50 45 / p99 90 ms**: ~6.6x
      and ~15x at p50, and most of the remaining warm-path time is Python itself, not the engine.
      The footprint baseline falls too: the cold path copies the 132 MiB image per VM, a warm clone
      copies nothing (the shared read-only base is referenced in place and the bundle's one 256 MiB
      memory file is mapped by every clone, both page-cache-shared; a clone's private cost is its
      copy-on-write dirty pages).)*
- [x] **P5.8** Test: restore a warm Python snapshot, run code, get output in ≪ cold-boot time.
      *(`warm_restore_returns_output_in_far_under_cold_boot`: warms + snapshots a Python source,
      then times restore → exec → output-verified on a fresh clone and asserts it lands with at
      least a **2x margin under the source's cold-boot latency**: a generous bound against the
      measured ~6.6x, and `cold_boot` itself understates the cold path, which pays boot *plus* the
      same exec (one observed run: 85 ms to output vs a 367 ms cold boot). The phase's payoff is
      now asserted in `ci-privileged`, not just printed by the bench. 23 privileged tests.)*
- **Exit gate + lesson:** warm restores make runs start in ms; write up **snapshotting, guest
  memory, and the state you must fix up on restore.**

## Phase 6 — Confinement: jailer, cgroups, seccomp

Confine the VMM itself — the other half of the isolation story, and pure Linux internals.

- [ ] **P6.1** Run Firecracker under its **jailer** (chroot, uid/gid drop, namespaces).
- [ ] **P6.2** Put each VMM in its own **cgroup**; set CPU/memory limits.
- [ ] **P6.3** Apply Firecracker's **seccomp** filters; understand what syscalls it needs.
- [ ] **P6.4** Resource caps enforced: a VM can't exceed its cgroup memory/CPU. *(Also closes the
      P2.6 gap: killing the guest's cgroup reaps a command's whole process tree — grandchildren and
      `setsid` daemons that a direct-child `kill` misses — so a double-forking command can't wedge
      the guest agent's exec connection.)*
- [ ] **P6.5** `(decision)` per-run resource policy shape (the knobs the engine exposes) →
      `ARCHITECTURE.md`.
- [ ] **P6.6** Verify isolation: a hostile guest + a hostile-ish workload can't escape the jail.
- [ ] **P6.7** Clean cgroup/namespace teardown per run — and the leak-proofing this buys:
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
- [ ] **P6.8** Test: a fork-bomb / mem-hog in the guest is bounded by the cgroup, host unaffected.
- **Exit gate + lesson:** the VMM runs jailed + cgroup-limited; write up **namespaces, cgroups v2,
  seccomp, and capabilities** — the container-isolation primitives, seen through Firecracker.

## Phase 7 — The sandbox lifecycle API (the engine surface)

Wrap the FC track into a clean, self-hostable engine API.

> **Downstream seam (a real embedder pins `vmm` by git rev).** This phase lands the embedder-driven
> seam capabilities, each with the embedder's acceptance criteria as its exit gate: per-exec **inputs**
> (files + `env`) with a **secret-hygiene contract** (P7.1), the exec **wall-clock and output-cap
> budgets as knobs** (P7.3), and a **kill handle** for the host-gave-up path (P6.7, surfaced on
> `Sandbox` here). Every addition stays a generic library capability (engine, not platform): nothing
> below knows who embeds it. `VmmError::kind()` (the bucket classifier) and the conservative,
> documented `Limits::default()` contract already landed as out-of-band seam hardening.

- [ ] **P7.1** `Sandbox` lifecycle: `open → exec → put/get files → snapshot → close`, with **inputs at
      the seam**. *(Lifts the bulk block-device file paths — P3.4 `input_dir`, P3.5
      `output_dir`/`RunningVm::collect_outputs` — onto the `Sandbox` surface, since P3.4/P3.5 keep them
      at the low-level `RunningVm` layer. **Embedder inputs:** promote `exec_with_files(argv, stdin,
      files, artifacts)` onto `Sandbox` so an embedder never reaches into `RunningVm`; add an **`env`**
      field to `Request::Exec` (bounded like `stdin`, set on the **spawned command only**, never the
      agent's own process); and pin a **secret-hygiene contract**: injected file contents and env
      values never appear in an engine log line, a [`VmmError`] Display, or `console()` (error paths
      may name a file path or an env key, never a value), and host-side copies of injected bytes are
      wiped after send where practical. When the flight recorder lands (P13), it records *that* inputs
      were injected (paths/keys/sizes or hashes), never their contents. **Exit gate:** `Sandbox`
      exposes an exec taking files + env; a run receives both in-guest; the call stays synchronous and
      returns the same `RunResult` shape; and a **leak test** greps an injected sentinel value out of
      every observable surface (logs, every `VmmError` Display, `console()`) and finds nothing.)*
- [ ] **P7.2** Stateful sessions: multiple `exec`s against one VM with a persistent overlay.
- [ ] **P7.3** Per-sandbox limits (cpu/mem/wall/net policy) as **one options struct**, its shape
      settled by the P6.5 resource-policy decision. *(Turns two fixed internal budgets into **knobs**:
      the **exec wall-clock budget** (today the internal `DEFAULT_EXEC_TIMEOUT`; make it settable per
      call or on the struct so a host's run budget is enforced end to end, so `Limits.wall` stops
      meaning boot-only), and the **exec output cap** (today the fixed `MAX_EXEC_OUTPUT`, already surfaced as
      `OutputCap { limit }`). A wall breach keeps today's semantics: cooperative `ExecTimeout`, with
      `ExecUnresponsive` as the liveness backstop. `Limits::default()` stays conservative and its
      load-bearing-defaults doc already landed. **Exit gate:** the exec deadline is settable per run
      with unchanged timeout semantics, and the output cap is settable.)*
- [ ] **P7.4** `agent run <cmd>` / `agent shell` CLI over the lifecycle.
- [ ] **P7.5** Structured run result (stdout/stderr/exit/artifacts/metrics).
- [ ] **P7.6** Concurrency: many sandboxes at once; a bounded pool; no interference.
- [ ] **P7.7** Docs: the engine API and the explicit *non-goals* (no auth/billing/scheduler).
- [ ] **P7.8** Test: two concurrent stateful sessions stay isolated and correct.
- **Exit gate + lesson:** a clean `Sandbox` engine anyone can embed/self-host; write up **the
  sandbox-lifecycle contract** and where the engine/PaaS line sits.

---

## eBPF / aya track — see and enforce from the host

## Phase 8 — aya "hello, verifier"

The eBPF on-ramp: build, load, and read a map from a trivial program.

- [ ] **P8.1** `crates/probes` (`no_std`, `bpfel-unknown-none`) + `crates/probes-loader`
      (userspace, aya) scaffolding; `bpf-linker` wired into `xtask`.
- [ ] **P8.2** A tracepoint/kprobe that **counts** an event (e.g. `sys_enter_execve`) into a map.
- [ ] **P8.3** Loader attaches it, reads the map, prints counts.
- [ ] **P8.4** CO-RE/BTF: build against BTF so it's portable across kernels.
- [ ] **P8.5** Handle the verifier: bounded loops, map access patterns — learn its rules by hitting them.
- [ ] **P8.6** `xtask` builds the eBPF object as part of the gate (separate target).
- [ ] **P8.7** Caps: load with `CAP_BPF` (not full root) where possible; document what's needed.
- [ ] **P8.8** Test: run a known program, assert the counter moved.
- **Exit gate + lesson:** a Rust eBPF program loads and reports; write up **eBPF program types,
  maps, the verifier, and CO-RE/BTF.**

## Phase 9 — Syscall observability

Trace what a process (a firecracker/vhost worker, or the guest-adjacent host side) actually does.

> **What host eBPF can and cannot see (the hardware-isolation consequence).** The guest runs its
> *own* kernel, so untrusted code's syscalls are serviced in-guest and **never trap to the host**:
> host tracepoints on `sys_enter_execve` etc. see only the **VMM's host footprint** (Firecracker/
> vhost threads, KVM ioctls, block I/O), not in-guest syscalls. This is the price of spine #1: the
> strong host-side signals are **network** (the tap, P10/P11) and **resources** (the cgroup, P12);
> syscall-level visibility is inherently coarse for a microVM. Say so plainly (measured, not
> marketed); do not promise in-guest syscall introspection this boundary cannot deliver.

- [ ] **P9.1** Tracepoints for `execve`/`openat`/`connect` with per-event data via a **ring buffer**.
- [ ] **P9.2** Filter to a target PID/cgroup (so you watch *one* sandbox's host footprint).
- [ ] **P9.3** Userspace consumer: stream events, decode, print a live trace.
- [ ] **P9.4** Attribute events to a sandbox (via cgroup id / PID from the FC track).
- [ ] **P9.5** Bounded overhead: measure the tracing cost.
- [ ] **P9.6** Test: launch a workload, assert its `execve`/`open` events show up attributed.
- **Exit gate + lesson:** a live syscall trace of a running sandbox; write up **tracepoints vs
  kprobes, ring buffers, and per-cgroup filtering.**

## Phase 10 — Network observability on the tap (tc/XDP)

Watch every packet a microVM sends/receives — at its tap device, in the kernel.

- [ ] **P10.1** Attach a **tc** (or XDP) program to a VM's tap device.
- [ ] **P10.2** Parse L3/L4 headers; count bytes/packets per direction, per flow.
- [ ] **P10.3** Export per-VM network stats to userspace via a map.
- [ ] **P10.4** Bind the program to the *specific* tap the FC track named for a sandbox.
- [ ] **P10.5** Handle attach/detach cleanly on sandbox open/close.
- [ ] **P10.6** Test: traffic from a guest shows up in the per-VM counters.
- **Exit gate + lesson:** live per-microVM network visibility; write up **tc vs XDP, the packet
  path, and eBPF at the traffic-control layer.**

## Phase 11 — Enforcement: egress policy in the kernel

Turn observation into control — deny-by-default egress, allow-listed, enforced at the tap.

- [ ] **P11.1** A policy map (allowed CIDRs/ports) the tc/XDP program consults.
- [ ] **P11.2** Drop packets that don't match; allow those that do — per VM.
- [ ] **P11.3** Userspace API to set a sandbox's egress policy at launch.
- [ ] **P11.4** Deny-by-default: a sandbox with no policy reaches nothing.
- [ ] **P11.5** Log denials (the audit trail feeds the flight recorder, Phase 13).
- [ ] **P11.6** `(decision)` where policy lives + its schema (still *engine* mechanism, not org
      policy) → `ARCHITECTURE.md`.
- [ ] **P11.7** Test: a guest can reach an allow-listed endpoint and is blocked from everything else.
- **Exit gate + lesson:** kernel-enforced per-sandbox egress; write up **eBPF as an enforcement
  plane and why host-side beats in-guest.**

## Phase 12 — Resource accounting via cgroup-bpf

Per-sandbox CPU/mem/IO accounting from the kernel — the metering primitive (engine, not billing).

- [ ] **P12.1** cgroup-attached eBPF (or cgroup + tracepoints) for per-sandbox CPU/mem/IO.
- [ ] **P12.2** Correlate with the FC track's per-VM cgroup.
- [ ] **P12.3** Expose a per-run resource summary in the run result.
- [ ] **P12.4** Bounded overhead; sane under many concurrent sandboxes.
- [ ] **P12.5** Test: a CPU-heavy run reports higher CPU than an idle one, attributed correctly.
- **Exit gate + lesson:** per-sandbox resource metrics from eBPF; write up **cgroups v2 + BPF
  accounting** (and note: the engine *measures*, the hoster *bills*).

---

## Convergence — the fused engine

## Phase 13 — The flight recorder

Attach the eBPF programs to a sandbox at launch and produce a per-run **audit trail**.

- [ ] **P13.1** On `Sandbox::open`, attach syscall + network + accounting probes bound to that VM.
- [ ] **P13.2** Aggregate into one per-run record: network flows, resources, egress denials, timing,
      and notable **host-side** syscalls (the VMM's footprint, not in-guest syscalls; see Phase 9).
      The record's spine is network + resources + denials, the signals host eBPF observes strongly
      across the hardware boundary.
- [ ] **P13.3** Detach + finalize the record on `close`.
- [ ] **P13.4** Deterministic, structured output (JSON) of "what this run did," from *outside* the guest.
- [ ] **P13.5** Bound the overhead; keep concurrent sandboxes independent.
- [ ] **P13.6** Test: run a workload that touches network + files → the record shows exactly that.
- **Exit gate + lesson:** every run yields a tamper-resistant, host-observed audit trail; write up
  **the whole picture — microVM + eBPF observability as one system.**

## Phase 14 — Observability output (a face for it)

Make what a run did *legible* — the payoff demo.

- [ ] **P14.1** A live TUI (ratatui) or structured stream: sandboxes, their syscalls, network, resources.
- [ ] **P14.2** Per-sandbox drill-down: this run's flows, denials, timeline.
- [ ] **P14.3** `agent run --trace` prints the flight recorder after a run.
- [ ] **P14.4** Export the record (JSON) for later inspection.
- [ ] **P14.5** Test/demo: run something interesting, watch it live, read the trace after.
- **Exit gate + lesson:** a compelling live view of hardware-isolated runs; the demo you show people.

## Phase 15 — Hardening & the trust story

Prove the isolation + observation claims hold under adversarial workloads.

- [ ] **P15.1** Adversarial suite: guest tries to escape/DoS/exfiltrate → contained + recorded.
- [ ] **P15.2** Confirm the guest cannot see or disable the host-side probes.
- [ ] **P15.3** Resource-exhaustion, fork-bomb, network-flood → bounded by cgroup + egress policy.
- [ ] **P15.4** Snapshot-restore correctness under load (no state bleed between clones).
- [ ] **P15.5** Document the **threat model**: what's trusted (CPU/KVM/host kernel), what isn't.
- [ ] **P15.6** `(decision)` the security boundary + assumptions → `ARCHITECTURE.md`.
- **Exit gate + lesson:** the isolation + observability claims survive an adversary; write up the
  **threat model** — a genuine Principal-level design doc.

---

## Cross-cutting

## Phase 16 — The driver daemon + wire API (the engine's interface)

The containerd-style boundary: a local daemon others drive — still engine, not PaaS.

- [ ] **P16.1** `agentd`: a long-lived daemon exposing the sandbox lifecycle over a unix socket.
- [ ] **P16.2** A **versioned** wire API (JSON/gRPC — `(decision)`): open/exec/put/get/snapshot/
      close/trace. This is the **SDK contract** — Phase 19 freezes and spec's it.
- [ ] **P16.3** Warm-pool management lives in the daemon (fast `exec`).
- [ ] **P16.4** A **reference (Rust) client** proving a non-Rust caller can drive `agentd` over the
      wire API — the seed the **polyglot SDKs (Phase 19)** harden into Go/Python/Node/C#. (The full
      SDK set is post-`v0.1.0`.)
- [ ] **P16.5** Structured logs + a metrics endpoint (Prometheus) — for the *hoster* to scrape.
- [ ] **P16.6** Explicitly document the non-goals again at the API layer (no tenancy/auth/billing).
- [ ] **P16.7** Golden: the CLI and the daemon API produce identical run results.
- **Exit gate + lesson:** a self-hostable sandbox daemon with a clean API; write up **daemon design,
  the client/server boundary, and where a PaaS would begin (and why it's not here).**

## Phase 17 — Performance & scale

Make the numbers real — the benchmarks that back every claim.

- [ ] **P17.1** Benchmarks: cold boot, snapshot restore, warm-pool `exec` latency (p50/p99).
- [ ] **P17.2** Density: how many concurrent microVMs per host before it degrades.
- [ ] **P17.3** eBPF overhead: cost of the probes under load.
- [ ] **P17.4** Memory footprint per sandbox; the effect of overlay/rootfs choices.
- [ ] **P17.5** A reproducible bench harness + a results writeup vs the honest baselines.
- [ ] **P17.6** Find + fix the top bottleneck the numbers reveal.
- **Exit gate + lesson:** documented latency/density/overhead numbers; write up **performance
  methodology** (percentiles, not averages).

## Phase 18 — Packaging, docs & the blog series

Ship it as a thing others can run — and turn the journey into the career artifacts.

- [ ] **P18.1** Single-command self-host: build the rootfs/kernel, install the daemon, run a sandbox.
- [ ] **P18.2** `curl | sh` / container / release binaries with checksums.
- [ ] **P18.3** Docs site: quickstart, the engine API, the threat model, the non-goals.
- [ ] **P18.4** The **blog series** assembled from each phase's writeup (the visibility that promotes).
- [ ] **P18.5** A **Honeywell design-doc** applying the threat model + isolation to a real internal need.
- [ ] **P18.6** Example workloads (run untrusted Python, an untrusted binary, a CI job) as demos.
- [ ] **P18.7** Security policy + responsible-disclosure notes.
- [ ] **P18.8** v0.1 tag: boots a microVM, runs code, enforces + records it, self-hostable, documented.
- **Exit gate:** a stranger can `git clone`, self-host the engine, run untrusted code in a microVM,
  and read the eBPF-observed audit trail — and the blog series tells the whole Linux story.

---

## Post-v0.1.0 — vNext tracks

> These land **after** the `v0.1.0` finish line (P18.8) and **do not gate that tag** (§0.6). They
> extend the engine **outward** (more callers) and **sideways** (a second isolation boundary, to
> master both) — without pulling tenancy/billing/scheduling into scope, and without diluting the
> spine. Both depend on Phase 16's daemon + wire API.
>
> **Each ships as its own repository** — the four SDKs and the Wasmtime engine are all separate
> repos. This repo owns only the **contract** they build against: the versioned wire API, the
> cross-language conformance suite, and a reference Rust client. So the boxes below track *that
> contract (and its certification) landing here* — the SDK/engine **code lives in its sibling
> repo**, gated by the conformance suite this repo publishes.

## Phase 19 — Polyglot SDKs (Go · Python · C# · Node.js)

Thin, idiomatic clients so non-Rust callers can drive `agentd` — the E2B-style surface, still
**engine, not platform**.

- [ ] **P19.1** `(decision)` Freeze + version the P16 wire API as a **language-agnostic spec** (the
      SDK contract): message schema, the error taxonomy, and a semver compat policy → `ARCHITECTURE.md`.
- [ ] **P19.2** A **cross-language conformance suite** (golden request/response + flight-recorder
      round-trips) every SDK must pass — the single source of SDK correctness, run in CI.
- [ ] **P19.3** **Go** SDK (own repo): open/exec/put/get/snapshot/close/trace against `agentd`.
- [ ] **P19.4** **Python** SDK (own repo; sync + async).
- [ ] **P19.5** **Node.js / TypeScript** SDK (own repo).
- [ ] **P19.6** **C# / .NET** SDK (own repo).
- [ ] **P19.7** Every SDK is **its own repository** (out of this Rust workspace + host gate), pinned
      to a wire-API version, certified by the P19.2 conformance suite, and published to its language
      registry with checksums.
- [ ] **P19.8** Each SDK is a **thin protocol client** — no tenancy/auth/billing/scheduling; deny-by-
      default and the non-goals hold at the SDK layer too (tombstone).
- **Exit gate + lesson:** four languages run the same golden `exec` and read the same host-observed
  flight recorder through `agentd`; write up **designing a stable polyglot wire API + conformance
  testing across language runtimes.**

## Phase 20 — The Wasmtime sibling (master both boundaries)

A **separate** engine that reuses this one's driver API + flight-recorder format but swaps the
isolation boundary from **hardware (KVM)** to **software (Wasmtime SFI)** — built to master both,
not to replace this repo.

- [ ] **P20.1** `(decision)` **Sibling repo, not a backend here.** Spine property 1 (*isolation is
      hardware*) is never traded in this engine; the wasm variant carries a **different, weaker**
      guarantee, so it's a distinct artifact that *shares the API*, not a plug-in backend →
      `ARCHITECTURE.md`.
- [ ] **P20.2** Wasmtime embedding: `Engine`/`Store`/`Module` with **fuel + epoch** (CPU/timeout) and
      a `ResourceLimiter` (memory) → typed limits, mirroring the FC engine's no-hang/no-leak contract.
- [ ] **P20.3** The **host-function (WASI) shim layer** = capabilities + policy + flight recorder:
      enforcement moves from host-side eBPF to the **import boundary** (the module has zero ambient
      authority; deny-by-default becomes "link no imports").
- [ ] **P20.4** Reuse the `Sandbox` lifecycle shape + the flight-recorder **JSON schema**, so a caller
      (and the Phase 19 SDKs) can drive either engine.
- [ ] **P20.5** Comparative benchmarks: **instantiate latency + fuel overhead + density** vs the
      microVM's boot/restore/density — same harness, honest numbers.
- [ ] **P20.6** Test: the same untrusted program on both engines yields comparable flight-recorder
      records; where they *can't* be comparable, document why.
- **Exit gate + lesson:** two engines, one API, two isolation boundaries; write up **hardware vs
  software isolation — TCB size, startup, density, scope, and threat model** (the capstone
  comparison that proves you mastered both).

---

## Architectural invariants (never traded away)

1. **Isolation is hardware.** Untrusted code runs in a KVM microVM; the trust boundary is the CPU,
   not guest-side software.
2. **Observe & enforce from the host.** Visibility and policy live in host-side eBPF, which the
   guest cannot see or disable. In-guest agents are for convenience (exec/IO), never for security.
3. **Engine, not platform.** A self-hostable runtime + a driver API. Multi-tenant auth, billing,
   fleet scheduling, and dashboards are **out of scope** — the hoster's job. (Tombstone.)
4. **Measured, not marketed.** Boot/restore/density/overhead are benchmarked with percentiles; no
   hand-waved performance claims.
5. **No-panic on the host path.** A hostile or crashing guest, a failed probe, or a broken channel
   is a typed error, never a host panic, hang, or leak.
6. **Deny by default.** A sandbox with no explicit policy reaches no network and has minimal
   capability; every allowance is explicit and recorded.
7. **Teach as you go.** Every phase produces a writeup; the point is Linux mastery, so the *why*
   is a first-class deliverable.
8. **Git is human-driven.** The user makes every commit/branch/push; the coding agent stops at
   changes made, demo working, box checked in the working tree.
