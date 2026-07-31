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
fine when the enforcer is "the implementation being correct". Full rationale:
`docs/contributing-development-process.md`.

**Scope: the engine, not the platform.** A runtime + a clean driver API you self-host: the boring,
embeddable, self-hostable core for running untrusted code with hardware isolation and a host-observed
audit log. **This is an engine, not a PaaS**, multi-tenant auth, billing, fleet scheduling, and a
dashboard are the *hoster's* job, out of scope. The **AI model / agent loop is out too**: the model
is always the *caller* driving the engine from outside, never an engine component; the
engine's job is to contain what the model's code does and hand back the record. If a change pulls
tenancy/billing/scheduling or a model into this repo, or moves the security boundary into the guest,
the design is wrong.

## Design rules (every change holds to all six)

The single source. Exactly two places restate them for readers: `docs/architecture.md` for the book, and
`README.md` for someone who never clones. Nothing else should, since a third copy is a third thing to
drift. They state intent and the mechanism serving it, so a change that breaks one is recognisable as
a design error rather than a trade-off.

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

One workspace. For the types worth knowing before editing, the boot sequence, and the teardown
layers, read `docs/architecture.md` before a non-trivial change to `vmm`.

| Path | What it is |
|---|---|
| `crates/vmm` | The engine: microVM lifecycle, jail, networking, snapshots, the pool, the `Sandbox` API. `#![forbid(unsafe_code)]`. |
| `crates/channel` | Host↔guest framing. Zero dependencies, shared verbatim by driver and agent, so the two can't drift. |
| `crates/guest-agent` | In-guest exec and IO. Static musl, baked into the rootfs. Not the security boundary. |
| `crates/probes` | The eBPF programs (`#![no_std]`, `bpfel-unknown-none` via `bpf-linker`). The only crate allowed `unsafe`. |
| `crates/probes-common` | The `#[repr(C)]` records crossing the eBPF boundary. Zero deps, single-sourced. |
| `crates/probes-loader` | aya userspace: attach to one sandbox, read the maps, assemble and sign the record. |
| `crates/protocol` | The daemon's wire types, versioned. |
| `crates/client` | Rust reference client for `ekvm serve`. |
| `crates/cli` | The `ekvm` binary (`run`/`shell`/`doctor`/`verify`) plus `ekvm serve`. Package name `ekvm`, directory `cli`. |
| `crates/test-support` | Test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, the real-root guard. |
| `xtask` | Dev orchestration: the gates, artifact builds, benchmarks, packaging. Never shipped. |
| `docs/` | mdBook, `SUMMARY.md` is the index. Flat `topic-subtopic.md` names; the hierarchy lives in `SUMMARY.md`, not in directories. |

## Conventions

- **Rust**, stable, one workspace, pinned exactly in `rust-toolchain.toml` so a lint can't pass
  locally and fail CI. Linux-only (it needs KVM), `x86_64` only. Keep the host path `unsafe`-free;
  the eBPF crate builds for its own target (`bpfel-unknown-none`, `bpf-linker`).
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
  per-distro code path (a gate test greps for this). Ask the kernel what it can *do*: `cgroup.kill`
  rather than `>= 5.15`, `/sys/kernel/security/lsm` rather than "is this RHEL". A capability probe is
  bounded (a distro list is not: Rocky, Alma, CentOS Stream, Oracle and Amazon Linux are all RHEL),
  and it is testable on a host that lacks the capability, since the probe takes a path. **State a
  requirement as the capability, never as a distro that happens to satisfy it.** Host variance lives
  in `doctor.rs` preflight, never in the boot path: a conditional in `spawn.rs`/`jail.rs` creates N
  boot paths and leaves N-1 untested. The shipped binary is static musl for the same reason, no host
  libc to mismatch. Full rationale: `docs/architecture.md`, decision 8.
- Don't commit built rootfs/kernel images or generated eBPF objects, they're built by `xtask`.
- **On a panicking test, re-run it with `RUST_BACKTRACE=1`** rather than reasoning about the failure
  from the assertion line alone. The frame that panicked is often several calls below the test.
- **A test must be shown to fail.** Break the behavior under test, watch the new assertion fail, then
  revert. A test never seen failing is not yet evidence, and this repo has a commit whose whole
  purpose was two tests that passed on something other than their subject.
- **A comment earns its lines.** A comment states a constraint, threat, or intent the code can't
  show, in the fewest sentences that carry it; it never restates what the next lines visibly do.
  A prose *promise* ("can't drift", "never logged") belongs in a type or a test, with the comment
  pointing at it; a mechanical claim (a repo path, a Markdown link) is checked by the gate's
  prose-drift lint, which covers paths and links but **not anchors**, so a `#section` link is yours
  to verify. State the threat-model framing once per module (rustdoc on the item that owns it), not
  at every call site.
- **No em-dashes in prose.** Repo docs, code comments, and commit messages use
  colons, commas, or parentheses instead of em-dashes (`—`). A genuine separator or placeholder
  inside a code block or shown output (e.g. `—` for "no data") stays; user-facing output *strings*
  are a separate call, not covered here.
- **Pull requests are human-owned. Commits and pushes are the operator's call.** A **coding agent**
  (Claude, Gemini, Codex, as opposed to the `ekvm` binary this repo builds) **never** opens,
  approves, or merges a pull request (`gh pr create` / `gh pr merge` / review approvals included).
  Asking another human to accept work, and reviewing it, are human steps, and that part is not
  configurable. Whether an agent runs `git commit` and `git push` is up to whoever is running it, so
  do it when asked and not otherwise. When committing: one logical change per commit, Conventional
  Commits per the next bullet, **never an AI co-author or attribution trailer**, and branch first if
  the checkout is on the default branch. Release tags stay a human step (`RELEASES.md`).
- **Commit messages follow Conventional Commits.** `type(scope)?: subject` with the standard types
  (`feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, `build`). The subject stays
  imperative and describes **what was done** ("fix: bound session reads by a deadline", not "fixed
  timeouts"). A mixed change takes its most significant type (`fix` over `refactor` over `test`)
  rather than splitting hairs.
- **Public-API changes carry the `api` scope.** The engine is embedded downstream at the `vmm`
  library's public API, pinned by git rev, so a change to that API (`Sandbox`, `Limits`,
  `RunResult`, `VmmError` including its variants *or* the `kind()` bucket mapping, the `channel`
  wire protocol, or the daemon's `protocol` wire types) is committed as
  `feat(api):` / `fix(api):` (with `!` appended when the change is
  incompatible), so a downstream pin bump is auditable from the log alone. Internal-only changes
  don't use the scope. This is about legibility, not a new process: still one imperative subject,
  still human-committed.
- **Preserve Backwards Compatibility.** Keep public struct fields private using the builder pattern,
  annotate public enums with `#[non_exhaustive]`, and use `#[serde(default)]` for optional wire fields.
  Verify Rust API stability with `cargo semver-checks check-release --baseline-rev v0.1.0` post-launch.
- **External Client SDKs Live In Separate Repos.** Non-Rust SDKs (`ekvm-python`, `ekvm-node`, `ekvm-go`)
  live in external companion repositories; do not pull Python, Node, or Go build tooling into this workspace.
