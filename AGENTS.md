# eKVM: engineering disciplines

**A self-hostable, isolated code-execution sandbox.** Untrusted code runs inside a
**Firecracker** microVM (hardware isolation via KVM); **host-side eBPF** (**aya**) observes and
enforces what it does, syscalls, its network, its cgroup, from *outside* the guest, where the
code can't see or subvert you. Every run yields a tamper-resistant, host-observed **audit log** of exactly what happened (host-signed for off-host detection). This file is the operating manual, read it every session.

**Scope: the engine, not the platform.** A runtime + a clean driver API you self-host: the boring,
embeddable, self-hostable core for running untrusted code with hardware isolation and a host-observed
audit log. **This is an engine, not a PaaS**, multi-tenant auth, billing, fleet scheduling, and a
dashboard are the *hoster's* job, out of scope. The **AI model / agent loop is out too**: the model
is always the *caller* driving the engine from outside, never an engine component; the
engine's job is to contain what the model's code does and hand back the record. If a change pulls
tenancy/billing/scheduling or a model into this repo, or moves the security boundary into the guest,
the design is wrong.

**Why this exists.** A self-hostable, embeddable engine for running untrusted code with hardware
isolation and a trustworthy, host-observed audit log isn't something you can pull off the shelf. This
fills that gap. Every phase ships a **working demo**, so each capability is proven running end to end,
not just asserted.

## The core properties (every change protects all four)

1. **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM; the trust
   boundary is the CPU, not guest-side software.
2. **Observe & enforce from the host.** Visibility and policy live in host-side eBPF the guest
   cannot reach. In-guest agents exist for convenience (exec/IO), **never** for security.
3. **Engine, not platform.** A self-hostable runtime + a driver API; tenancy/billing/scheduling/
   dashboards are the hoster's. (A recorded non-goal.)
4. **Measured, not marketed.** Boot, snapshot-restore, memory-sharing, and eBPF overhead are
   benchmarked with percentiles, never hand-waved.

## Repo layout

```
crates/
  vmm/           the Firecracker driver: microVM lifecycle (boot/exec/shutdown), rootfs and
                 tap networking, snapshots + the pre-warmed pool, jailer/cgroup confinement, and the
                 `Sandbox` lifecycle API. No `unsafe` on the host path; a hostile guest is a
                 typed error, never a panic/hang/leak.
  channel/       the host↔guest wire protocol (dependency-free framing over `Read`/`Write`),
                 shared by the driver and the guest agent.
  guest-agent/   the in-guest agent (`guest-agent`): runs one command per connection and streams
                 stdout/stderr/exit over `channel`. Built static (musl), baked into the rootfs.
                 Exec/IO convenience only, never the security boundary.
  probes/        the eBPF programs (`#![no_std]`, built for `bpfel-unknown-none` via
                 `bpf-linker`): syscall tracepoints, tc/XDP on the VM's tap, cgroup accounting.
                 CO-RE/BTF so they're portable across kernels.
  probes-common/ the plain-old-data types shared across the eBPF boundary (`#![no_std]`, zero deps):
                 the `#[repr(C)]` event records the kernel writes and the loader reads, single-sourced
                 so the two sides can't drift.
  probes-loader/ the userspace loader (aya): attach probes to a specific sandbox, read their
                 maps, stream events into the audit log.
  cli/           one entrypoint, the `ekvm` CLI (also installed as `ekvm`): (`run`,
                 `shell`, `doctor`; the audit record on
                 `--trace`/`--record`/`--record-summary`/`--watch`) plus `ekvm serve`, the driver
                 daemon (the versioned newline-JSON wire API over a unix socket).
docs/            the documentation, as an mdBook (`SUMMARY.md` is the index): design spec
                 (`design.md`), running the engine (`cli*.md`), the embedder contract
                 (`embedding.md`), the eBPF half (`probes.md`), and the contributing chapters.
                 Root keeps only the standard meta files (README/CONTRIBUTING/SECURITY/…).
xtask/           dev orchestration, `cargo xtask ci` (host-safe gate; + eBPF build at P8),
                 `ci-privileged` (VM-boot + probe-attach integration), `setup` (host check),
                 and the rootfs/kernel build. Never shipped.
```

## Guardrails (non-negotiable)

1. **Isolation is hardware.** Untrusted code runs in a KVM microVM. Never weaken this to a
   shared-kernel shortcut to "make it simpler."
2. **Observe & enforce from the host.** Security-relevant visibility and policy live in
   host-side eBPF, out of the guest's reach. A guest agent may carry exec/IO, but must never be
   the thing that *contains* the guest.
3. **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal
   capability; every allowance is explicit and **recorded** in the audit log.
4. **Engine, not platform.** No tenancy, auth, billing, fleet scheduler, or dashboard in this
   repo. Those belong to whatever hosts the engine.
5. **No-panic on the host path.** A hostile or crashing guest, a failed probe, or a broken
   channel is a typed error, never a host panic, hang, or leak.
6. **Measured, not marketed.** Boot/restore/memory-sharing/overhead are benchmarked with percentiles;
   no hand-waved performance claims.

## Conventions

- **Rust**, stable, one workspace. Linux-only (it needs KVM), `x86_64` only; host kernel
  **≥ 5.15** (a security-maintained LTS floor, untrusted code on an unpatched kernel is a
  threat-model hole; `ekvm doctor` enforces it). The eBPF programs build for their
  own target (`bpfel-unknown-none`, `bpf-linker`); keep the host path `unsafe`-free.
- **Two gates.** `cargo xtask ci` is host-safe (fmt · the prose-drift lint · clippy `-D warnings` ·
  build · unit tests · docs · `deny` · eBPF object build) and runs everywhere.

  `cargo xtask ci-privileged` runs
  the VM-boot + eBPF-load integration tests and needs `/dev/kvm` + real root, run it under `sudo`
  (your dev box or a bare-metal/nested-virt runner, a stock cloud VM can't nest KVM). The gate
  *refuses* to run without root, BTF, or the eBPF object rather than letting the capability-gated
  tests skip themselves into a hollow green (a skipped test is a pass to cargo). Never gate
  the everyday loop on a privileged runner.
- `tracing` logs to stderr; a run's structured result/audit-log to stdout, so
  `ekvm run … 2>/dev/null` stays pipe-clean. Config is layered **flags > env (`EKVM_*`) >
  file (`.ekvm.toml`, the nearest one walking up from the cwd) > defaults**.
- Don't commit built rootfs/kernel images or generated eBPF objects, they're built by `xtask`.
- **A comment earns its lines.** A comment states a constraint, threat, or intent the code can't
  show, in the fewest sentences that carry it; it never restates what the next lines visibly do.
  A prose *promise* ("can't drift", "never logged") belongs in a type or a test, with the comment
  pointing at it; a mechanical claim (a repo path, a Markdown link)
  is checked by the gate's prose-drift lint. State the threat-model framing once per module
  (rustdoc on the item that owns it), not at every call site.
- **No em-dashes in prose.** Repo docs, code comments, and commit messages use
  colons, commas, or parentheses instead of em-dashes (`—`). A genuine separator or placeholder
  inside a code block or shown output (e.g. `—` for "no data") stays; user-facing output *strings*
  are a separate call, not covered here.
- **Git is human-driven.** The user makes every commit, push, and **pull request**; the **coding
  agent** (Claude, Gemini, Codex, as opposed to `ekvm`/ekvm, this project) never runs `git commit` /
  `git push`, never opens, approves, or merges a PR (`gh pr create` / `gh pr merge` / review
  approvals included), and never takes any other CI-triggering action. The coding agent's job ends
  at: changes made, demo working, and, **only when asked**, a commit message or PR description
  drafted (Conventional Commits per the next bullet; never an AI co-author/attribution trailer).
- **Commit messages follow Conventional Commits.** `type(scope)?: subject` with the standard types
  (`feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, `build`). The subject stays
  imperative and describes **what was done** ("fix: bound session reads by a deadline", not "fixed
  timeouts"). A mixed change takes its most significant type (`fix` over `refactor` over `test`)
  rather than splitting hairs.
- **Public-API changes carry the `api` scope.** The engine is embedded downstream at the `vmm`
  library's public API, pinned by git rev, so a change to that API (`Sandbox`, `Limits`,
  `RunResult`, `VmmError` including its variants *or* the `kind()` bucket mapping, or the `channel`
  wire protocol) is committed as `feat(api):` / `fix(api):` (with `!` appended when the change is
  incompatible), so a downstream pin bump is auditable from the log alone. Internal-only changes
  don't use the scope. This is about legibility, not a new process: still one imperative subject,
  still human-committed.
- **Preserve Backwards Compatibility.** Keep public struct fields private using the builder pattern,
  annotate public enums with `#[non_exhaustive]`, and use `#[serde(default)]` for optional wire fields.
  Verify Rust API stability with `cargo semver-checks check-release --baseline-rev v0.1.0` post-launch.
- **External Client SDKs Live In Separate Repos.** Non-Rust SDKs (`ekvm-python`, `ekvm-node`, `ekvm-go`)
  live in external companion repositories; do not pull Python, Node, or Go build tooling into this workspace.
- **Release Branching Strategy.** Production releases land on `main` and are tagged. Patch fixes for a
  released minor series are backported to a dedicated release branch (e.g. `release-v0.1` for `v0.1.1`).

## Build order

Development proceeds iteratively with every capability proven running end to end.
