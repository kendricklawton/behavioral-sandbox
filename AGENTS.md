# eKVM: engineering disciplines

**A self-hostable, isolated code-execution sandbox.** Untrusted code runs inside a
**Firecracker** microVM (hardware isolation via KVM); **host-side eBPF** (**aya**) observes and
enforces what it does, syscalls, its network, its cgroup, from the host side of the KVM boundary,
where the programs live outside the guest's address space and outside any namespace it can enter.
Every run yields a host-observed, host-signed **audit log** of what the host was able to see. This
file is the operating manual, read it every session.

**Voice: claim nothing the project cannot back.** Pre-release, unaudited, one maintainer, no
external review. Describe mechanisms (falsifiable by a diff) and state measurements with their date
and host. Do not write outcome guarantees ("tamper-resistant", "never leaks", "the guest cannot
subvert it", "guaranteed"), in docs, comments, or commit messages. Where a test backs a statement,
make the test the subject: "`driver_death_cannot_leak_a_vm` kills a driver mid-boot and asserts no
VMM, netns, or scratch dir survives." An absolute is fine when the sentence names its enforcer
(`#![forbid(unsafe_code)]`, a wildcard-free `match`, an ordering inside one function); it is not
fine when the enforcer is "the implementation being correct". Full rationale: `docs/status.md`.

**Scope: the engine, not the platform.** A runtime + a clean driver API you self-host: the boring,
embeddable, self-hostable core for running untrusted code with hardware isolation and a host-observed
audit log. **This is an engine, not a PaaS**, multi-tenant auth, billing, fleet scheduling, and a
dashboard are the *hoster's* job, out of scope. The **AI model / agent loop is out too**: the model
is always the *caller* driving the engine from outside, never an engine component; the
engine's job is to contain what the model's code does and hand back the record. If a change pulls
tenancy/billing/scheduling or a model into this repo, or moves the security boundary into the guest,
the design is wrong.

## Design rules (every change holds to all six)

The single source. `docs/design.md` restates these for readers; nothing else should. They state
intent and the mechanism serving it, so a change that breaks one is recognisable as a design error
rather than a trade-off.

1. **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. Moving the
   boundary into guest-side software is a design error, not an optimisation, and a shared-kernel
   shortcut taken to "make it simpler" is the same error.
2. **Observe and enforce from the host.** Visibility and policy belong in host-side eBPF attached to
   host-kernel hooks. The in-guest agent carries exec and IO framing; making it responsible for
   containing the guest is a design error.
3. **Deny by default.** A sandbox with no explicit policy is configured with no route out and
   minimal capability, and each allowance is recorded in the audit log.
4. **Engine, not platform.** A self-hostable runtime and a driver API; tenancy, billing, scheduling,
   and dashboards are the hoster's. A recorded non-goal.
5. **No panic, hang, or leak on the host path.** A hostile or crashing guest, a failed probe, or a
   broken channel should surface as a typed error. This is the rule the code is written against and
   the property the confinement suite exercises; it is an aim, not a proven property.
6. **Measure rather than assert.** Boot, restore, memory sharing, and overhead are reported as
   nearest-rank percentiles with the host and date. A number that cannot be defended is withdrawn.

## Repo layout

```
crates/
  vmm/           the Firecracker driver: microVM lifecycle (boot/exec/shutdown), rootfs and
                 tap networking, snapshots + the pre-warmed pool, jailer/cgroup confinement, and the
                 `Sandbox` lifecycle API. `#![forbid(unsafe_code)]` on the host path; a hostile
                 guest is meant to surface as a typed error, not a panic, hang, or leak.
  channel/       the host↔guest wire protocol (dependency-free framing over `Read`/`Write`),
                 shared by the driver and the guest agent.
  guest-agent/   the in-guest agent (`guest-agent`): runs one command per connection and streams
                 stdout/stderr/exit over `channel`. Built static (musl), baked into the rootfs.
                 Exec/IO convenience only, not the security boundary.
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

## Conventions

- **Rust**, stable, one workspace. Linux-only (it needs KVM), `x86_64` only; host kernel
  providing `cgroup.kill`, else **≥ 5.15** as a fallback where there
  is no cgroup v2 to probe. Untrusted code on an unpatched kernel is a threat-model hole, but a
  version number is the wrong proxy for it on enterprise kernels; `ekvm doctor` probes the
  primitive. State the requirement as the capability, never as a distro that happens to satisfy it. The eBPF programs build for their
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
- **Target kernels, not distros.** Never read `/etc/os-release`, branch on a distro name, or add a
  per-distro code path. Ask the kernel what it can *do*: `cgroup.kill` rather than `>= 5.15`,
  `/sys/kernel/security/lsm` rather than "is this RHEL". A capability probe is bounded (a distro
  list is not: Rocky, Alma, CentOS Stream, Oracle and Amazon Linux are all RHEL), and it is testable
  on a host that lacks the capability, since the probe takes a path. Host variance lives in
  `doctor.rs` preflight, never in the boot path: a conditional in `spawn.rs`/`jail.rs` creates N
  boot paths and leaves N-1 untested. The shipped binary is static musl for the same reason, no host
  libc to mismatch. Full rationale: `docs/design.md`, decision 8.
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
