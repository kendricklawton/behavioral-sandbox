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
> This file is the **single source of truth for progress**. Its checkboxes are the state.

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
- [ ] **P2.5** Push richer inputs in (streaming stdin, injected files) and pull artifacts out.
      *(P2.4 already carries a bounded up-front stdin buffer; this phase adds files and larger/
      streaming I/O. Adding the second request type is also when to handle an unknown/additive
      request tag gracefully — the framing layer surfaces it so the agent replies with a typed
      "unsupported" rather than a fatal protocol error, closing the forward-compat gap the guest's
      `_` arm can't reach today.)*
- [ ] **P2.6** Timeouts + kill: a hung command is bounded and reaps cleanly.
      *(Must include a **guest-side self-timeout**: today `serve`'s `child.wait()` is unbounded, so a
      silent hung command (`sleep infinity`) wedges the agent — and the serial accept loop then
      blocks every later connection. Bound it (kill + a typed timeout / `Response::Error`); don't
      rely only on host-side VM teardown.)*
- [ ] **P2.7** Error taxonomy for the driver (boot failure, channel failure, guest crash) — typed,
      no panics on the host.
- [ ] **P2.8** Test: `exec("echo hi")` → `hi`, exit 0; a crashing command → typed error.
- **Exit gate + lesson:** `agent`-driven `exec` in a microVM returns real output; write up **vsock /
  guest agents** and how host↔guest comms actually work.

## Phase 3 — Rootfs & the language runtime

Build the disk the guest runs, with a real runtime (e.g. Python) inside — natively, no wasm gymnastics.

- [ ] **P3.1** Reproducible **rootfs build**: a minimal ext4 image (busybox/alpine or a scratch
      base) + the guest agent baked in.
- [ ] **P3.2** Add a language runtime (Python) to the rootfs; prove `exec("python -c 'print(2+2)')`.
- [ ] **P3.3** Read-only base rootfs + a writable overlay per run (so runs don't mutate the base).
- [ ] **P3.4** Inject a per-run working dir / files via a second block device or the channel.
- [ ] **P3.5** Pull artifacts (files the run produced) back out.
- [ ] **P3.6** Pin the rootfs build in `xtask` so it's one command + reproducible.
- [ ] **P3.7** Size/boot budget: keep the base small; measure its effect on boot time.
- [ ] **P3.8** Test: run Python + a small script that writes a file → capture the file.
- **Exit gate + lesson:** real Python runs in the microVM and produces artifacts; write up
  **filesystems, ext4 images, overlayfs, and initramfs vs rootfs.**

## Phase 4 — Networking

Give the microVM a network with per-VM isolation — the classic tap/bridge lesson.

- [ ] **P4.1** Create a **tap device** per VM on the host; attach it as virtio-net in the VMM config.
- [ ] **P4.2** Address the guest (static or a tiny DHCP) and route host↔guest.
- [ ] **P4.3** `(decision)` egress model: **NAT to the world** vs **deny-by-default** →
      `ARCHITECTURE.md`. (Default: deny-by-default; explicit allow later, enforced in BPF track.)
- [ ] **P4.4** Per-VM isolation: one VM cannot reach another's tap.
- [ ] **P4.5** Teardown removes the tap + routes; no orphaned interfaces after many runs.
- [ ] **P4.6** Name/track each tap so the eBPF track can bind policy to a specific VM later.
- [ ] **P4.7** Test: guest can (optionally) reach an allowed host endpoint; cannot reach a blocked one.
- [ ] **P4.8** Document the netfilter/routing rules the driver installs.
- **Exit gate + lesson:** a microVM has controlled network; write up **tap devices, bridges,
  netfilter/NAT, and virtio-net.**

## Phase 5 — Snapshots & warm start

The fast-start magic: pause, snapshot, and restore — fork many VMs from one warm image.

- [ ] **P5.1** Pause a booted VM and take a **full snapshot** (memory + state) via the API.
- [ ] **P5.2** Restore a VM from a snapshot; measure restore latency vs cold boot.
- [ ] **P5.3** A "warm" snapshot: boot + runtime loaded (e.g. Python imported), snapshot *that*.
- [ ] **P5.4** Restore N clones from one warm snapshot; each gets a fresh overlay/tap.
- [ ] **P5.5** Handle the uniqueness problems restore creates (network identity, entropy, clocks).
- [ ] **P5.6** `Pool` that keeps warm restores ready so `exec` starts in ms.
- [ ] **P5.7** Benchmark: cold boot vs snapshot restore vs warm-pool `exec` latency. *(Baseline
      to beat: Phase 1 boots a full rootfs copy in `/tmp` — on a tmpfs host that's ≈300 MB of RAM
      per sandbox on top of guest memory; overlays should collapse that.)*
- [ ] **P5.8** Test: restore a warm Python snapshot, run code, get output in ≪ cold-boot time.
- **Exit gate + lesson:** warm restores make runs start in ms; write up **snapshotting, guest
  memory, and the state you must fix up on restore.**

## Phase 6 — Confinement: jailer, cgroups, seccomp

Confine the VMM itself — the other half of the isolation story, and pure Linux internals.

- [ ] **P6.1** Run Firecracker under its **jailer** (chroot, uid/gid drop, namespaces).
- [ ] **P6.2** Put each VMM in its own **cgroup**; set CPU/memory limits.
- [ ] **P6.3** Apply Firecracker's **seccomp** filters; understand what syscalls it needs.
- [ ] **P6.4** Resource caps enforced: a VM can't exceed its cgroup memory/CPU.
- [ ] **P6.5** `(decision)` per-run resource policy shape (the knobs the engine exposes) →
      `ARCHITECTURE.md`.
- [ ] **P6.6** Verify isolation: a hostile guest + a hostile-ish workload can't escape the jail.
- [ ] **P6.7** Clean cgroup/namespace teardown per run — and the leak-proofing this buys:
      **host-process death (Ctrl-C, SIGKILL, OOM) cannot leak a VM**, because the cgroup owns its
      lifetime from outside the driver. (Until here, teardown is `Drop`-based: killing the driver
      mid-run leaks the VMM — a signal handler would only paper over SIGINT, so we wait for the
      real mechanism.)
- [ ] **P6.8** Test: a fork-bomb / mem-hog in the guest is bounded by the cgroup, host unaffected.
- **Exit gate + lesson:** the VMM runs jailed + cgroup-limited; write up **namespaces, cgroups v2,
  seccomp, and capabilities** — the container-isolation primitives, seen through Firecracker.

## Phase 7 — The sandbox lifecycle API (the engine surface)

Wrap the FC track into a clean, self-hostable engine API.

- [ ] **P7.1** `Sandbox` lifecycle: `open → exec → put/get files → snapshot → close`.
- [ ] **P7.2** Stateful sessions: multiple `exec`s against one VM with a persistent overlay.
- [ ] **P7.3** Per-sandbox limits (cpu/mem/wall/net policy) as one options struct.
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
- [ ] **P13.2** Aggregate into one per-run record: network flows, notable syscalls, resources,
      egress denials, timing.
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
- [ ] **P16.2** A simple wire API (JSON/gRPC — `(decision)`) : open/exec/put/get/snapshot/close/trace.
- [ ] **P16.3** Warm-pool management lives in the daemon (fast `exec`).
- [ ] **P16.4** A thin client + a Python/Go binding so non-Rust callers can drive it.
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
