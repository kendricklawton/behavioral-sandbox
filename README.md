<div align="center">
  <h1>Behavioral Sandbox</h1>

  <p>
    <strong>A local-first desktop sandbox for running untrusted code in a hardware-isolated
    virtual machine, on
    <a href="https://github.com/containers/libkrun">libkrun</a></strong>
  </p>

  <p>
    <a href="https://github.com/kendricklawton/behavioral-sandbox/actions/workflows/ci.yml"><img src="https://github.com/kendricklawton/behavioral-sandbox/actions/workflows/ci.yml/badge.svg" alt="build status" /></a>
    <img src="https://img.shields.io/badge/status-pre--release-orange.svg" alt="pre-release" />
    <img src="https://img.shields.io/badge/rustc-1.97%2B-green.svg" alt="supported rustc 1.97+" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="Apache-2.0" /></a>
  </p>

  <h3>
    <a href="docs/SUMMARY.md">Guide</a>
    <span> | </span>
    <a href="docs/architecture.md">Architecture</a>
    <span> | </span>
    <a href="CONTRIBUTING.md">Contributing</a>
  </h3>
</div>

## Where this is

**Sandboxes run; nothing is released.**

What is here, on a host whose hypervisor answers (`/dev/kvm` on Linux, Hypervisor.framework on
macOS ARM64) and a guest image the tree builds: `bsx run` runs one command in a sandbox and exits
with its status, `bsx shell` opens a session on a pty inside the guest, `bsx up` starts a sandbox
that outlives the command that started it, `bsx ls`, `bsx exec` and `bsx stop` reach a sandbox this
process did not start, `bsx show`, `bsx rm` and `bsx export` read, remove and package what a run
left behind, and `--display WIDTHxHEIGHT` shows a guest's screen in a window whose keyboard and
pointer go to the guest, and the desktop image boots to a terminal in a Wayland session there, with
`--sound` for audio. `bsx-app` is the notebook: every run on the machine, live and past, with its
posture, output and results; a live run's display in the window with your keyboard and pointer
going in; a form that shows a sandbox's posture before it boots. It opens on a menu naming the
`bsx` and guest root it found, exports a run to one tar file, clears the ended history behind a
confirm, and keeps a theme pick across launches.

On macOS ARM64 the same tree builds, signs (`cargo xtask sign`) and boots the same sandboxes under
Hypervisor.framework. Its libkrun build carries no `--sound` and no guest keyboard or pointer
backend, and the display helper's own window is compiled out there, so a guest's display on macOS
is viewed in `bsx-app`. What is not here on any platform: GPU acceleration for the guest.

There are no users, no installed base, and no release to install. Nothing below is an invitation to
depend on this yet.

## What it is

A desktop application for running untrusted code, on one person's machine, with a CLI beside it.
Untrusted code runs inside a virtual machine, so the isolation boundary is the CPU's, enforced by
hardware virtualization: KVM on Linux, Hypervisor.framework on macOS ARM64.

libkrun makes the calling process the virtual machine monitor. `krun_start_enter` never returns, so
a VM **is** a process: every VM is a helper the supervisor spawned and reaps.

## Design rules

Six rules. A change that breaks one is a design error, not a trade-off. Each states an intent and
the mechanism serving it; the full text is [docs/architecture.md](docs/architecture.md).

* **Isolation is hardware, not software**: untrusted code runs in a VM under KVM or
  Hypervisor.framework, never behind a guest-side check.
* **Local-first**: no account, no telemetry, no control plane. A feature that cannot work with the
  network off belongs to a different product.
* **Deny by default**: no explicit configuration means no shared directory and no network. What is
  shared *is* the policy, settled before the VM starts.
* **An application, not a platform**: a program on one person's machine. There is no tenant, no
  account, and no fleet. An AI model is a caller, never a component.
* **No panic, hang, or leak on the host path**: a hostile guest or a dead helper surfaces as a typed
  error. The rule the code is written against; an aim, not a proven property.
* **Measure rather than assert**: percentiles with the host and date, and a number that cannot be
  defended is withdrawn. libkrun has no snapshot surface, so every boot is a cold boot.

The host path is `#![forbid(unsafe_code)]`, enforced by the compiler in every crate and checked by
`every_crate_forbids_unsafe` in the gate. `bsx-krun`, the libkrun wrapper, is the one exception,
because the library is C; the gate asserts that list exactly, so a second one cannot appear quietly.

## Building

On Linux, `/dev/kvm` must be readable and writable by your user, which usually means membership of
the `kvm` group. On macOS, Hypervisor.framework refuses a process without the
`com.apple.security.hypervisor` entitlement: `cargo xtask sign` applies it ad hoc, and a signature
does not reliably outlive the next cargo build, so re-sign after building. No part of the build or
the run needs root on either platform.

libkrun and its kernel payload install from the system package manager (`pacman -S libkrun
libkrunfw` on Arch; `brew tap slp/krun && brew install libkrun libkrunfw` on macOS): a C library
and a shared object holding a Linux kernel, so neither arrives through cargo. The guest image is
built on Linux, for either architecture (`--arch aarch64`), because what executes during the build
is `apk.static`, a Linux binary.

```console
cargo xtask setup            # what this host can and cannot do
cargo xtask ci               # the gate: fmt, prose drift, clippy, build, test, docs, deny
cargo xtask sign             # macOS: re-entitle the built bsx after any other build
cargo xtask build-rootfs     # the guest image (Alpine + runtimes + the static agent)
cargo xtask build-rootfs --desktop   # the desktop image (+ a Wayland compositor and a terminal)
```

## Repo layout

Directories stay short and packages carry the `bsx-` prefix, so a package is its directory plus that
prefix, with one exception: `crates/cli` builds `bsx`, the bare name going to the command a user
types. `cargo … -p` takes the package, a path takes the directory.

| Path | Package | Role |
|------|---------|------|
| `crates/supervisor` | `bsx-supervisor` | Spawn, track, stop and reap the helper processes that are VMs. One value per live VM; `Drop` tears it down. |
| `crates/krun` | `bsx-krun` | The safe wrapper over libkrun, with the raw declarations private beneath it. The one crate that may use `unsafe`, because the library is C. |
| `crates/channel` | `bsx-channel` | The host↔guest wire protocol: nearly dependency-free length-prefixed framing (`zeroize`, for the post-send secret wipe, is the one dependency), shared by both ends. |
| `crates/guest-agent` | `bsx-guest-agent` | The in-guest agent: runs one command per connection, streams stdout/stderr/exit. Exec/IO only, not the trust boundary. |
| `crates/record` | `bsx-record` | The run record the notebook keeps: posture, captured output, and the guest's `/results`, one directory per run, exportable as one tar file. |
| `crates/input` | `bsx-input` | The guest's keyboard and pointer: device shapes, reports, and the line grammar the replay file and the control socket feed. |
| `crates/cli` | `bsx` | The `bsx` CLI and its verbs. The binary on `PATH` is `bsx`. |
| `crates/app` | `bsx-app` | The GUI application, on iced: the notebook of runs behind a menu, a run's record with its display and output, a start form, stop, re-run, delete, export, clear history, a persisted theme, and a shell in your terminal. |
| `crates/test-support` | `bsx-test-support` | Shared test fixtures: a self-reclaiming scratch dir, a log sink, a deterministic generator. Dev-only, never shipped. |
| `docs` | | This documentation, as an mdBook. |
| `xtask` | `xtask` | Dev orchestration: `cargo xtask ci`, the guest image build, the vendor mirror. Never shipped. |

## Verified on

The gate (`cargo xtask ci`: build, tests, lints, docs, dependency audit) runs in CI on Ubuntu 24.04
`x86_64` on every change and needs no privilege, and a smoke lane runs the wire-protocol fuzz
targets from their committed seeds. **No CI lane boots a VM.** The suites that boot one run where a
hypervisor answers, and skip saying so where none does. Development happens on Arch Linux `x86_64`
and a MacBook Air M1 (macOS ARM64).

## Releases and scope

There is no published roadmap and no promised date. A capability becomes a feature when a test
exercises it end to end, and is not announced before that. The first supported release, `v0.1.0`,
will pin the host↔guest wire framing and the supervisor API; until then everything, including the
crate names, changes without notice.

The project is **open to outside pull requests**, though everything here is pre-`v0.1.0` and
changes without notice. A pull request signs its commits off (`git commit -s`). The terms are in
[`CONTRIBUTING.md`](CONTRIBUTING.md), and [`AGENTS.md`](AGENTS.md) is the operating manual.

## License

Apache-2.0. See [LICENSE](LICENSE).
