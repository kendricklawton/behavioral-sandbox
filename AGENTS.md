# eKVM: engineering disciplines

**A self-hostable, isolated code-execution sandbox.** Untrusted code runs inside a
**Firecracker** microVM (hardware isolation via KVM); **host-side eBPF** (**aya**) observes and
enforces what it does from the host side of the KVM boundary: its network and its cgroup directly,
its syscalls only as the VMM's host footprint, since a microVM services guest syscalls in its own
kernel. The programs live outside the guest's address space and outside any namespace it can enter.
Every run yields a host-observed **audit record** of what the host was able to see, and the paths
that persist one sign it with a host key (`--record`, an operator's `records_dir`, the daemon's
`trace`). This file is the operating manual, read it every session.

Rust, stable, one workspace, pinned in `rust-toolchain.toml`. Linux and `x86_64` only (it needs
KVM). The host path is `#![forbid(unsafe_code)]`; `crates/probes` is the one exception and builds
for its own target.

**Voice: claim nothing the project cannot back.** Pre-release, unaudited, one maintainer, no
external review. Describe mechanisms (falsifiable by a diff) and state measurements with their date
and host. Do not write outcome guarantees ("tamper-resistant", "never leaks", "the guest cannot
subvert it", "guaranteed"), in docs, comments, or commit messages. Where a test backs a statement,
make the test the subject: "`driver_death_cannot_leak_a_vm` kills a driver mid-boot and asserts no
VMM, netns, or scratch dir survives." An absolute is fine when the sentence names its enforcer
(`#![forbid(unsafe_code)]`, a wildcard-free `match`, an ordering inside one function); it is not
fine when the enforcer is "the implementation being correct".

The same rule runs the other way: do not write for users who do not exist. Migration notes, upgrade
paths, and "if you pinned an older rev" guidance imply an installed base, which is a claim about
adoption. Nobody outside this project has run it.

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
   and dashboards are the hoster's. The **AI model is out too**: it is always the *caller* driving
   the engine from outside, never an engine component. A recorded non-goal.
5. **No panic, hang, or leak on the host path.** A hostile or crashing guest, a failed probe, or a
   broken channel should surface as a typed error. This is the rule the code is written against and
   the property the confinement suite exercises; it is an aim, not a proven property.
6. **Measure rather than assert.** Boot, restore, memory sharing, and overhead are reported as
   nearest-rank percentiles with the host and date. A number that cannot be defended is withdrawn.

## Repo layout

One workspace. **Directories stay short and packages carry the `ekvm-` prefix**, so a package name is
its directory plus that prefix, with **exactly one exception**: `crates/cli` builds `ekvm`, because
the bare name goes to the thing a user types. That one row is why `-p` takes the **package**
(`-p ekvm-engine`) and paths take the **directory** (`crates/engine`). `cargo xtask ci` checks every
`-p` in every tracked text file against the real package list, so a stale one fails the gate rather
than a reader's terminal. Before a non-trivial change to `ekvm-engine`, read `docs/architecture.md`
for the types worth knowing, the boot sequence, and the teardown layers.

| Path | Package | What it is |
|---|---|---|
| `crates/engine` | `ekvm-engine` | The engine: microVM lifecycle, jail, networking, snapshots, the pool, the `Sandbox` API. `#![forbid(unsafe_code)]`. |
| `crates/channel` | `ekvm-channel` | Host↔guest framing. Near dependency-free (`zeroize`, for the secret wipe, is the one dependency), shared verbatim by driver and agent, so a wire change reaches both in one commit. |
| `crates/guest-agent` | `ekvm-guest-agent` | In-guest exec and IO. Static musl, baked into the rootfs. Not the security boundary. Its binary keeps the bare name `guest-agent`: that is the path the rootfs build bakes in. |
| `crates/probes` | `ekvm-probes` | The eBPF programs (`#![no_std]`, `bpfel-unknown-none` via `bpf-linker`). The only crate allowed `unsafe`. Its binary keeps the bare name `probes`: that is the object filename the loader looks for. |
| `crates/probes-common` | `ekvm-probes-common` | The `#[repr(C)]` records crossing the eBPF boundary. Zero deps, single-sourced. |
| `crates/probes-loader` | `ekvm-probes-loader` | aya userspace: attach to one sandbox, read the maps, assemble the record. |
| `crates/record` | `ekvm-record` | The signed audit record: its types, deterministic JSON, and ed25519 signing/verification. No aya, so a record verifies off-host. |
| `crates/protocol` | `ekvm-protocol` | The daemon's wire types, versioned. |
| `crates/client` | `ekvm-client` | Rust reference client for `ekvm serve`. |
| `crates/cli` | `ekvm` | The `ekvm` binary (`run`/`shell`/`doctor`/`verify`) plus `ekvm serve`. Package, binary, and command are all `ekvm`; its library half is the CLI's own internals, not the engine. |
| `crates/test-support` | `ekvm-test-support` | Test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, the real-root guard. |
| `xtask` | `xtask` | Dev orchestration: the gates, artifact builds, benchmarks, packaging. Never shipped, never renamed (`cargo xtask` is a `--package xtask` alias). |
| `docs/` | | mdBook, `SUMMARY.md` is the index. Flat `topic-subtopic.md` names; the hierarchy lives in `SUMMARY.md`, not in directories. |

## Building from source

Preparing a *host* (KVM access, Firecracker, the host tools) is `docs/cli-install.md`; this is the
developer's side. `cargo xtask setup` is the first command on a new machine.

```console
rustup target add x86_64-unknown-linux-musl   # the static in-guest agent
cargo install cargo-deny                      # run by the host-safe gate
```

The eBPF toolchain is needed only for the probes, and both pieces are **pinned** deliberately: they
install out of band, so an unpinned install takes whatever shipped that morning and a compiler
change breaks the build with no commit from anyone. `bpf-linker` links against the pinned nightly's
LLVM, so the two move together. The nightly's single source is `crates/probes/rust-toolchain.toml`,
`bpf-linker`'s is `xtask`, and `ebpf_toolchain_pins_are_single_sourced` holds the workflows and this
page's `bpf-linker` line to them.

```console
cargo install bpf-linker --locked --version 0.10.3
rustup toolchain install nightly-2026-07-20 --profile minimal --component rust-src
```

```console
cargo xtask setup            # verify KVM, BTF, Firecracker, bpf-linker, caps
cargo xtask fetch-artifacts  # download the sha-pinned guest kernel and boot rootfs
cargo xtask build-rootfs     # build the guest rootfs (Alpine + the GUEST_PACKAGES runtimes + static agent)
cargo xtask build-probes     # build the eBPF object (target: bpfel-unknown-none)
```

## Conventions

- **Two gates.** `cargo xtask ci` is host-safe (fmt · the prose-drift lint · clippy `-D warnings` ·
  build · unit tests · docs · `deny` · eBPF object build) and runs everywhere. `cargo xtask
  ci-privileged` runs the VM-boot + eBPF-load integration tests and needs `/dev/kvm` + real root
  (a stock cloud VM can't nest KVM). It *refuses* to run without root, BTF, or the eBPF object
  rather than letting the capability-gated tests skip themselves into a hollow green, since a
  skipped test is a pass to cargo. Never gate the everyday loop on a privileged runner.
- **A test must be shown to fail.** Break the behavior under test, watch the new assertion fail, then
  revert. A test never seen failing is not yet evidence, and this repo has a commit whose whole
  purpose was two tests that passed on something other than their subject.
- **Target kernels, not distros.** Never read `/etc/os-release`, branch on a distro name, or add a
  per-distro code path (a gate test greps for this). Ask the kernel what it can *do*: `cgroup.kill`
  rather than `>= 5.15`, `/sys/kernel/security/lsm` rather than "is this RHEL". A capability probe is
  bounded, a distro list is not, and the probe is testable on a host that lacks the capability.
  Host variance lives in `doctor.rs` preflight, never in the boot path: a conditional in
  `spawn.rs`/`jail.rs` creates N boot paths and leaves N-1 untested. Full rationale:
  `docs/architecture-decisions.md`, decision 8.
- **A comment earns its lines.** A comment states a constraint, threat, or intent the code can't
  show, in the fewest sentences that carry it; it never restates what the next lines visibly do.
  A prose *promise* ("can't drift", "never logged") belongs in a type or a test, with the comment
  pointing at it. A drift claim that *enumerates* what it covers ("shared by A, B and C") has made
  one more copy, the list, and it drifts like every copy: name the mechanism a reader can grep
  instead and let the set be whatever that admits. State the threat-model framing once per module
  (rustdoc on the item that owns it), not at every call site.
- `tracing` logs to stderr; a run's structured result/audit-log to stdout, so
  `ekvm run … 2>/dev/null` stays pipe-clean. Config is layered **flags > env (`EKVM_*`) >
  file (`.ekvm.toml`, the nearest one walking up from the cwd) > defaults**.
- **No em-dashes in prose.** Repo docs, code comments, and commit messages use colons, commas, or
  parentheses instead. A genuine separator inside a code block or shown output stays; user-facing
  output *strings* are a separate call.
- **Pull requests are human-owned. Commits and pushes are the operator's call.** A **coding agent**
  never opens, approves, or merges a pull request (`gh pr create` / `gh pr merge` / review approvals
  included); that part is not configurable. Whether an agent runs `git commit` and `git push` is up
  to whoever is running it, so do it when asked and not otherwise. Commits go to `main`. One logical
  change per commit, **never an AI co-author or attribution trailer**. Release tags stay a human
  step (`RELEASES.md`).
- **Commit messages follow Conventional Commits.** `type(scope)?: subject` with the standard types
  (`feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, `build`). Imperative, describing
  **what was done** ("fix: bound session reads by a deadline"). A mixed change takes its most
  significant type (`fix` over `refactor` over `test`). **Public-API changes carry the `api` scope**
  (`feat(api):` / `fix(api)!:`), so a downstream pin bump is auditable from the log alone. The
  surface is `ekvm-engine`'s public API, the `ekvm-channel` wire framing, `ekvm-protocol`'s wire
  types, and `ekvm-record`'s signed-envelope surface; `docs/embedding-scope.md` names it exactly.
- **Backwards compatibility follows the data's direction.** Structs the caller constructs
  (`Limits`, `BootConfig`) take a builder or `Default`, so a new knob is additive and invariants stay
  checkable. Structs the engine returns (`RunResult`, `Artifact`, `ExecMetrics`) keep public fields,
  so a caller can move the data out and new measurements land as new fields. Everything public is
  `#[non_exhaustive]`; optional wire fields carry `#[serde(default)]`. Verify with
  `cargo semver-checks check-release --baseline-rev v0.1.0` post-launch.
- **Non-Rust SDKs live in separate repos** (`ekvm-python`, `ekvm-node`, `ekvm-go`); do not pull
  Python, Node, or Go build tooling into this workspace.
