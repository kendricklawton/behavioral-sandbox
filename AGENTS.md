# BSX: engineering disciplines

**A self-hostable, isolated code-execution sandbox.** Untrusted code runs in a **Firecracker**
microVM. KVM gives the hardware isolation. **Host-side eBPF** (**aya**) observes and enforces the
behavior of the guest from the host side of the KVM boundary. It sees the network and the cgroup of
the guest directly. It sees the syscalls only as the host footprint of the VMM, because a microVM
serves its guest syscalls in its own kernel. The eBPF programs stay outside the address space of the
guest, and outside each namespace that the guest can enter. Each run makes a host-observed **audit
record** of what the host saw. The paths that keep a record sign it with a host key (`--record`, the
`records_dir` of an operator, the daemon's `trace`). This file is the operating manual. Read it every
session.

The project uses stable Rust in one workspace. `rust-toolchain.toml` pins the version. It runs on
Linux and `x86_64` only, because it needs KVM. The host path is `#![forbid(unsafe_code)]`.
`crates/probes` is the one exception: it builds for its own target on its own pinned nightly, and it
takes one unstable feature (`core_intrinsics`, for the BPF atomic add that `core::sync::atomic`
cannot express on a target rustc marks `atomic-cas: false`).

**Voice: claim nothing the project cannot back.** The project is pre-release and unaudited. It has
one maintainer and no external review. Describe mechanisms that a diff can disprove. State each
measurement with its date and host. Do not write outcome guarantees in docs, comments, or commit
messages. Examples of such guarantees are "tamper-resistant", "never leaks", "the guest cannot
subvert it", and "guaranteed". When a test backs a statement, make the test the subject. For example:
"`driver_death_cannot_leak_a_vm` kills a driver during boot and asserts that no VMM, netns, or
scratch dir stays." An absolute is correct when the sentence names its enforcer, for example
`#![forbid(unsafe_code)]`, a wildcard-free `match`, or an order inside one function. An absolute is
not correct when the enforcer is only "the implementation is correct".

The same rule runs the other way. Do not write for users who do not exist. Migration notes, upgrade
paths, and "if you pinned an older rev" guidance imply an installed base. An installed base is a
claim about adoption. No one outside this project has run it.

## Design rules (every change holds to all six)

This is the single source of the design rules. Two other places restate them for readers.
`docs/architecture.md` restates them for the book. `README.md` restates them for a person who never
clones the repo. No other place restates them, because a third copy is a third thing that can drift.
Each rule states an intent and the mechanism for that intent. Therefore a change that breaks one rule
shows as a design error, not as a trade-off.

1. **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. If you move the
   boundary into guest-side software, this is a design error, not an optimisation. A shared-kernel
   shortcut that you take to "make it simpler" is the same error.
2. **Observe and enforce from the host.** Put the visibility and the policy in host-side eBPF on
   host-kernel hooks. The in-guest agent carries the exec and IO framing. If you make the agent
   responsible to contain the guest, this is a design error.
3. **Deny by default.** A sandbox with no explicit policy has no route out and minimum capability.
   The engine records each allowance in the audit log.
4. **Engine, not platform.** The project is a self-hostable runtime and a driver API. **The unit of
   isolation is the sandbox, not the tenant.** The engine isolates each sandbox. It records nothing
   about the owner of a sandbox. Therefore a hoster maps its tenants onto sandboxes and deploys many
   tenants, and the engine never learns what a tenant is. Mechanism that makes such a deployment safe
   is engine work. Policy that must know who pays is the work of the hoster. This policy includes
   tenancy, auth, billing, fleet scheduling, and image management. `docs/embedding-scope.md` draws
   that line exactly. The **AI model is also outside the engine**. It is always the *caller*. It
   drives the engine from outside. It is never a component of the engine.
5. **No panic, hang, or leak on the host path.** A hostile guest, a guest that crashes, a probe that
   fails, or a channel that breaks must show as a typed error. The code is written to this rule, and
   the confinement suite tests this property. It is an aim, not a proven property.
6. **Measure, do not assert.** Report boot, restore, memory sharing, and overhead as nearest-rank
   percentiles. Give the host and the date with each number. Withdraw a number that you cannot
   defend.

## Repo layout

The project is one workspace. **Directories stay short, and packages carry the `bsx-` prefix.** Thus
a package name is its directory plus that prefix. There is **exactly one exception**: `crates/cli`
builds `bsx`, because the bare name is the word that a user types. This one exception is the reason
that `-p` takes the **package** (`-p bsx-engine`) and that paths take the **directory**
(`crates/engine`). `cargo xtask ci` checks every `-p` in every tracked text file against the real
list of packages. Therefore a stale `-p` fails the gate, not the terminal of a reader. Before you
make a large change to `bsx-engine`, read `docs/architecture.md`. It gives the types that you must
know, the boot sequence, and the teardown layers.

| Path | Package | What it is |
|---|---|---|
| `crates/engine` | `bsx-engine` | The engine: microVM lifecycle, jail, networking, snapshots, the pool, and the `Sandbox` API. `#![forbid(unsafe_code)]`. |
| `crates/channel` | `bsx-channel` | Host↔guest framing. It has almost no dependencies. `zeroize` (for the secret wipe) is the one dependency. The driver and the agent share it without change, so a wire change reaches both in one commit. |
| `crates/guest-agent` | `bsx-guest-agent` | In-guest exec and IO. It is static musl and is baked into the rootfs. It is not the security boundary. Its binary keeps the bare name `guest-agent`, because the rootfs build bakes in that path. |
| `crates/probes` | `bsx-probes` | The eBPF programs (`#![no_std]`, `bpfel-unknown-none` through `bpf-linker`). It is the only crate that can use `unsafe`. Its binary keeps the bare name `probes`, because the loader looks for that object filename. |
| `crates/probes-common` | `bsx-probes-common` | The `#[repr(C)]` records that cross the eBPF boundary. Zero dependencies, one source. |
| `crates/probes-loader` | `bsx-probes-loader` | aya userspace. It attaches to one sandbox, reads the maps, and assembles the record. |
| `crates/record` | `bsx-record` | The signed audit record: its types, deterministic JSON, and Ed25519 signing and verification. It has no aya, so a record verifies off-host. |
| `crates/protocol` | `bsx-protocol` | The wire types of the daemon, with versions. |
| `crates/client` | `bsx-client` | Rust reference client for `bsx serve`. |
| `crates/cli` | `bsx` | The `bsx` binary (`run`/`shell`/`doctor`/`verify`) and `bsx serve`. The package, the binary, and the command are all `bsx`. Its library half is the internals of the CLI, not the engine. |
| `crates/test-support` | `bsx-test-support` | Test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, and the real-root guard. |
| `xtask` | `xtask` | Dev orchestration: the gates, artifact builds, benchmarks, and packaging. It is never shipped and never renamed (`cargo xtask` is a `--package xtask` alias). |
| `docs/` | | mdBook. `SUMMARY.md` is the index. The names are flat `topic-subtopic.md`. The hierarchy is in `SUMMARY.md`, not in directories. |

## Building from source

`docs/cli-install.md` tells you how to prepare a *host* (KVM access, Firecracker, the host tools).
This section is the developer's side. `cargo xtask setup` is the first command on a new machine.

Run these **from inside the clone**, because `rust-toolchain.toml` pins the stable version and
`rustup target add` adds the target to whichever toolchain is active where you run it. Outside the
repo that is your default toolchain, and `build-rootfs` then fails with a missing musl target on a
box where `rustup target list --installed` shows it present.

```console
rustup target add x86_64-unknown-linux-musl   # the static in-guest agent
cargo install cargo-deny                      # run by the host-safe gate
```

Two host tools are dev-toolchain rows in `cargo xtask setup` and are needed before `build-rootfs`:
**`fakeroot`** (the rootfs is built with uid-0 ownership without root) and **`binutils`** for
`readelf` (verifies the in-guest agent is really static). Both are absent from a minimal cloud
image. `readelf` is a soft skip, so a build without it prints a note and proceeds unverified.

You need the eBPF toolchain only for the probes. Both pieces are **pinned** on purpose. They install
out of band. Thus an unpinned install takes the version that shipped that morning, and a compiler
change breaks the build with no commit from a person. `bpf-linker` links against the LLVM of the
pinned nightly, so the two move together. The single source of the nightly is
`crates/probes/rust-toolchain.toml`. The single source of `bpf-linker` is `xtask`.
`ebpf_toolchain_pins_are_single_sourced` holds the workflows and the `bpf-linker` line on this page
to these sources.

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

- **Two gates.** `cargo xtask ci` is host-safe and runs everywhere. It does fmt, the prose-drift
  lint, clippy `-D warnings`, build, unit tests, docs, `deny`, and the eBPF object build.
  `cargo xtask ci-privileged` runs the VM-boot and eBPF-load integration tests. It needs `/dev/kvm`
  and real root. A standard cloud VM cannot nest KVM. This gate *refuses* to run without root, BTF,
  or the eBPF object. If it ran, the capability-gated tests would skip themselves into a hollow
  green, because cargo counts a skipped test as a pass. Never gate the everyday loop on a privileged
  runner.
- **You must show that a test can fail.** Break the behavior under test. Watch the new assertion
  fail. Then revert. A test that you never saw fail is not yet evidence. This repo has a commit for
  two tests that passed on something other than their subject.
- **Target kernels, not distros.** Never read `/etc/os-release`. Never branch on the name of a
  distro. Never add a per-distro code path. A gate test greps for this. Ask the kernel what it can
  *do*. Use `cgroup.kill`, not ">= 5.15". Use `/sys/kernel/security/lsm`, not "is this RHEL". A
  capability probe is bounded, but a distro list is not. You can test the probe on a host that does
  not have the capability. Host variance lives in the `doctor.rs` preflight, never in the boot path.
  A conditional in `spawn.rs` or `jail.rs` makes N boot paths and leaves N-1 untested. For the full
  reason, see `docs/architecture-decisions.md`, decision 8.
- **A comment must earn its lines. `crates/channel` and `crates/client` are the reference.** Read
  these two crates before you comment a third. The rustdoc of an item starts with **one line** in
  the third-person indicative, for example "Writes a single length-prefixed protocol frame." or
  "Returns `true` if the failure was caused by clean EOF or disconnect." Put any constraint in that
  line or in a trailing clause, for example "...to prevent unbounded allocations." or "Must fit in
  the 16-byte limit of ext4." Keep the constraint, but cut the essay. Do not write a separate
  rationale paragraph on an item. The reader needs the sentence that names the threat, and git
  already holds the argument for it. Write a **body** comment only where it states something that the
  code cannot show: an order, a kernel constraint, or the reason that the obvious form is wrong.
  Remove a body comment that only narrates what the next lines show. State the threat-model framing
  one time for each module, in the `//!` header, as a short bullet list with bold labels. Do not
  state it at each call site. A prose *promise*, for example "can't drift" or "never logged", belongs
  in a type or a test, not in prose that asserts it. A drift claim that lists what it covers, for
  example "shared by A, B and C", makes one more copy: the list. This list drifts like every copy.
  Name a mechanism that a reader can grep instead, and let the mechanism define the set. A comment
  states its constraint in the **present tense**. It never tells the story of how you found it.
  Past-tense narration of earlier code ("the earlier design", "used to", "no longer", "this
  replaced"), incident anecdotes, and regression backstories belong in the commit that fixed them.
  Git keeps them attached to the diff there.
- `tracing` logs to stderr. A run writes its structured result and audit log to stdout, so
  `bsx run … 2>/dev/null` stays pipe-clean. Config is layered: flags, then env (`BSX_*`), then the
  nearest `.bsx.toml` above the cwd, then `~/.bsx.toml`, then defaults. The project file carries the
  house defaults, the ceilings, and the postures. The keys that name a host binary, a guest image, a
  key, a write root, or a jail id are read from the user file, because a file above the cwd can
  arrive with the code it configures.
- **An em-dash is the exception, not the default.** Repo docs, code comments, and commit messages
  use a colon, a comma, or parentheses first. Use an em-dash only where those marks are ambiguous or
  too weak: to set off material that carries its own commas, or to make a break that is sharper than
  a colon makes. Use one em-dash or one em-dash pair in a sentence, because a second one reads as the
  close of the first. A true separator in a code block or in shown output stays. User-facing output
  *strings* are a separate case.
- **A human owns the pull requests. The operator decides the commits and the pushes.** A **coding
  agent** never opens, approves, or merges a pull request. This includes `gh pr create`,
  `gh pr merge`, and review approvals. You cannot configure this part. The person who runs an agent
  decides if the agent runs `git commit` and `git push`. Do it when the person asks, and not at other
  times. Commits go to `main`. Make one logical change for each commit. Never add an AI co-author or
  an attribution trailer. A human makes the release tags (`RELEASES.md`).
- **Commit messages follow Conventional Commits.** Use `type(scope)?: subject` with the standard
  types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, and `build`. Use the
  imperative and describe **what you did** ("fix: bound session reads by a deadline"). A mixed change
  takes its most significant type (`fix` before `refactor` before `test`). **Public-API changes carry
  the `api` scope** (`feat(api):` or `fix(api)!:`), so you can audit a downstream pin bump from the
  log alone. The surface is the public API of `bsx-engine`, the wire framing of `bsx-channel`, the
  wire types of `bsx-protocol`, and the signed-envelope surface of `bsx-record`.
  `docs/embedding-scope.md` names it exactly.
- **Backwards compatibility follows the direction of the data.** Structs that the caller constructs
  (`Limits`, `BootConfig`) take a builder or `Default`, so a new knob is additive and you can still
  check the invariants. Structs that the engine returns (`RunResult`, `Artifact`, `ExecMetrics`) keep
  their public fields, so a caller can move the data out and new measurements arrive as new fields.
  Everything public is `#[non_exhaustive]`. Optional wire fields carry `#[serde(default)]`. Verify
  with `cargo xtask semver-check`, which names each crate. If you run `cargo-semver-checks` bare, it
  drops every `publish = false` package (all of them) and exits `0` with nothing checked. It is also
  inert until `0.1.0`, because cargo treats every `0.0.x` bump as already breaking.
- **The wire carries no identity.** By design, anything that authenticates *users* stays out of
  `bsx-protocol`. The access control of the daemon is the permissions of the socket. This is a
  recorded non-goal on the flags of `serve`.
