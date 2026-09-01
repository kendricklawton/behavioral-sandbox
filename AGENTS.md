# BSX: engineering disciplines

**A local-first desktop sandbox.** Untrusted code runs in a virtual machine through **libkrun**, a
library that makes the calling process the virtual machine monitor. Hardware virtualization gives
the isolation: KVM on Linux, Hypervisor.framework on macOS. `krun_start_enter` does not return, so a
VM **is** a process: every VM is a helper the supervisor spawned and reaps. The product is a GUI
application with a CLI beside it, both on one machine. This file is the operating manual. Read it
every session.

The project uses stable Rust in one workspace. `rust-toolchain.toml` pins the version. It targets
Linux on `x86_64` and macOS on ARM64, because those are where libkrun has a hypervisor. The host
path is `#![forbid(unsafe_code)]`. The raw libkrun bindings are the one exception, because the
library is C.

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

## Where this is mid-flight

`scratch/ROADMAP.md` is the plan, and its checkboxes are the state. Read it before a large change.
It is gitignored working state, not a tracked file, so a fresh clone will not have one.
A checkbox there means done **and** evidenced, never merely attempted.

**Nothing in the tree boots a VM.** The Firecracker engine was deleted rather than carried alongside
its replacement, and the libkrun supervisor is phase 2. `bsx` builds and has no verbs. This manual
describes the rules a change is held to, not a running system.

## Design rules (every change holds to all six)

This is the single source of the design rules. Two other places restate them for readers.
`docs/architecture.md` restates them for the book. `README.md` restates them for a person who never
clones the repo. No other place restates them, because a third copy is a third thing that can drift.
Each rule states an intent and the mechanism for that intent. Therefore a change that breaks one rule
shows as a design error, not as a trade-off.

1. **Isolation is hardware, not software.** Untrusted code runs in a VM under KVM or
   Hypervisor.framework. If you move the boundary into guest-side software, this is a design error,
   not an optimisation. A shared-kernel shortcut that you take to "make it simpler" is the same
   error.
2. **Local-first. Nothing leaves the machine.** No account, no telemetry, no control plane, no
   licence check that needs a server. A feature that cannot work on a laptop with the network off
   belongs to a different product. This rule is what decides a feature, not taste.
3. **Deny by default.** A sandbox with no explicit configuration shares no host directory and has no
   network. What is shared **is** the policy: no in-kernel enforcer sits behind it, so the set of
   virtiofs tags and the network backend are settled before the VM starts and are visible to the
   person starting it.
4. **An application, not a platform.** The product is a program on one person's machine. The unit is
   the sandbox. There is no tenant, no account, and no fleet. Mechanism that makes one machine's
   sandboxes work is this project's; anything that must know who is paying is a different product.
   The **AI model is a caller**, never a component: it drives the app from outside.
5. **No panic, hang, or leak on the host path.** A hostile guest, a guest that crashes, or a helper
   that dies must show as a typed error. A leak here is a stranded VM holding somebody's laptop RAM,
   not a server you can reboot. The code is written to this rule, and the confinement suite tests
   this property. It is an aim, not a proven property.
6. **Measure, do not assert.** Report boot, memory, and frame timings as nearest-rank percentiles.
   Give the host and the date with each number. Withdraw a number that you cannot defend. libkrun has
   no snapshot surface, so every boot is a cold boot and the number that matters is the one a user
   waits for.

## Repo layout

The project is one workspace. **Directories stay short, and packages carry the `bsx-` prefix.** Thus
a package name is its directory plus that prefix. There is **exactly one exception**: `crates/cli`
builds `bsx`, because the bare name is the word that a user types. This one exception is the reason
that `-p` takes the **package** (`-p bsx-channel`) and that paths take the **directory**
(`crates/channel`). `cargo xtask ci` checks every `-p` in every tracked text file against the real
list of packages. Therefore a stale `-p` fails the gate, not the terminal of a reader.

| Path | Package | What it is |
|---|---|---|
| `crates/supervisor` | `bsx-supervisor` | Spawn, track, stop and reap the helper processes that **are** VMs. One `Vm` per live helper, `Drop` tears it down. Writes the helper argv that `crates/cli` parses. |
| `crates/krun` | `bsx-krun` | The safe wrapper over libkrun: a builder that puts the library's call-ordering rules in types, and its negative-errno returns into a typed error. The raw declarations sit under it in a **private** module, so this API is the only way to reach libkrun. **The one crate that may use `unsafe`**, because the library is C. |
| `crates/channel` | `bsx-channel` | Host↔guest framing. It has almost no dependencies. `zeroize` (for the secret wipe) is the one dependency. Both ends share it without change, so a wire change reaches both in one commit. |
| `crates/guest-agent` | `bsx-guest-agent` | In-guest exec and IO: it binds a socket, accepts a connection, and serves repeated execs from one session directory. It does no init work and is not the security boundary. Static musl, baked into the guest image. Its binary keeps the bare name `guest-agent`, because the image build bakes in that path. |
| `crates/cli` | `bsx` | The `bsx` binary. The package, the binary, and the command are all `bsx`. **No verbs today**: the supervisor they call is phase 2. Its library half is the internals of the CLI, not a public API. |
| `crates/test-support` | `bsx-test-support` | Test fixtures: a self-reclaiming scratch dir, a log sink, and the deterministic generator the in-gate fuzz suites use. |
| `xtask` | `xtask` | Dev orchestration: the gate, artifact builds, benchmarks, and packaging. It is never shipped and never renamed (`cargo xtask` is a `--package xtask` alias). |
| `docs/` | | mdBook. `SUMMARY.md` is the index. The names are flat `topic-subtopic.md`. The hierarchy is in `SUMMARY.md`, not in directories. |

**Two binaries will ship**, from one workspace: `bsx` (the CLI, which also carries the hidden
helper subcommand that becomes a VM) and the GUI application. Today only `bsx` exists, and it has no
verbs. Neither is a daemon. A VM registers a socket
under the runtime directory, and both binaries find live VMs by reading it, so a VM started by one
is visible to the other. `scratch/ROADMAP.md` holds the reasoning.

## Building from source

`cargo xtask setup` is the first command on a new machine. It checks `/dev/kvm` and the dev
toolchain; it does not yet probe libkrun, because nothing links it (phase 2.1). libkrun and its
guest-kernel payload install from the system package manager: they are a C library and a shared
object holding a Linux kernel, so neither arrives through cargo.

```console
sudo pacman -S libkrun libkrunfw          # Arch; Fedora and openSUSE package both too
rustup target add x86_64-unknown-linux-musl   # the static in-guest agent
cargo install cargo-deny                      # run by the gate
```

`/dev/kvm` must be readable and writable by your user, which usually means membership of the `kvm`
group. No part of the build or the run needs root.

```console
cargo xtask setup            # what this host can and cannot do
cargo xtask ci               # the gate
cargo xtask build-rootfs     # the guest image (Alpine + the GUEST_PACKAGES runtimes + static agent)
```

## Conventions

- **One gate.** `cargo xtask ci` runs everywhere and needs no privilege: fmt, the prose-drift lint,
  clippy `-D warnings`, build, unit tests, docs, and `deny`. Anything that boots a guest needs
  `/dev/kvm`, so it is skipped where the device is absent. A skipped test is not a passing test:
  when a suite can self-skip, print what was skipped and why, because cargo counts a skipped test as
  a pass and that reads as coverage.
- **You must show that a test can fail.** Break the behavior under test. Watch the new assertion
  fail. Then revert. A test that you never saw fail is not yet evidence. This repo has a commit for
  two tests that passed on something other than their subject.
- **Target kernels, not distros.** Never read `/etc/os-release`. Never branch on the name of a
  distro. Never add a per-distro code path. A gate test greps for this. Ask the system what it can
  *do*. Use `cgroup.kill`, not ">= 5.15". Use `krun_has_feature`, not a libkrun version number. The
  same rule crosses platforms: ask whether a hypervisor answers, not whether `/dev/kvm` exists, or
  the macOS path is a second untested branch. A capability probe is bounded, but a platform list is
  not. Host variance lives in the preflight, never in the boot path, because a conditional there
  makes N boot paths and leaves N-1 untested.
- **A comment must earn its lines. `crates/channel` is the reference.** Read it
  before you comment another crate. The rustdoc of an item starts with **one line** in
  the third-person indicative, for example "Writes a single length-prefixed protocol frame." or
  "Returns `true` if the failure was caused by clean EOF or disconnect." Put any constraint in that
  line or in a trailing clause, for example "...to prevent unbounded allocations." Keep the
  constraint, but cut the essay. Do not write a separate
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
- `tracing` logs to stderr. A run writes its structured result to stdout, so a `bsx … 2>/dev/null`
  stays pipe-clean. Config is layered: flags, then env (`BSX_*`), then the nearest `.bsx.toml` above
  the cwd, then `~/.bsx.toml`, then defaults. The project file carries the house defaults and the
  ceilings. The keys that name a host binary, a guest image, or a write root are read from the user
  file, because a file above the cwd can arrive with the code it configures.
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
  an attribution trailer. A human makes the release tags.
- **Commit messages follow Conventional Commits.** Use `type(scope)?: subject` with the standard
  types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, and `build`. Use the
  imperative and describe **what you did** ("fix: bound session reads by a deadline"). A mixed change
  takes its most significant type (`fix` before `refactor` before `test`). **Public-API changes carry
  the `api` scope** (`feat(api):` or `fix(api)!:`), so you can audit a downstream pin bump from the
  log alone. The surface is the wire framing of `bsx-channel` and the spawn and discovery API of
  `bsx-supervisor`; `PINNED_SURFACE_CRATES` in `xtask/src/main.rs` is the list
  `the_manual_names_the_whole_pinned_surface` holds this page to.
- **Backwards compatibility follows the direction of the data.** Structs that the caller constructs
  (`Limits`, `BootConfig`) take a builder or `Default`, so a new knob is additive and you can still
  check the invariants. Structs that the code returns (`RunResult`, `Artifact`, `ExecMetrics`) keep
  their public fields, so a caller can move the data out and new measurements arrive as new fields.
  Everything public is `#[non_exhaustive]`. Optional wire fields carry `#[serde(default)]`. Verify
  with `cargo xtask semver-check`, which names each crate. If you run `cargo-semver-checks` bare, it
  drops every `publish = false` package (all of them) and exits `0` with nothing checked. It is also
  inert until `0.1.0`, because cargo treats every `0.0.x` bump as already breaking.
