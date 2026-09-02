<div align="center">
  <h1>Behavioral Sandbox</h1>

  <p>
    <strong>A local-first desktop sandbox for running untrusted code in a hardware-isolated
    virtual machine, on
    <a href="https://github.com/containers/libkrun">libkrun</a></strong>
  </p>

  <p>
    <a href="https://github.com/kendricklawton/behavioral-sandbox/actions/workflows/ci.yml"><img src="https://github.com/kendricklawton/behavioral-sandbox/actions/workflows/ci.yml/badge.svg" alt="build status" /></a>
    <img src="https://img.shields.io/badge/status-rebuilding-red.svg" alt="rebuilding" />
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

**Sandboxes run; nothing is released.** BSX was built on Firecracker with a host-side eBPF
observer. That design was abandoned in favour of a local-first desktop application on **libkrun**,
and the engine implementing the old one was **deleted** rather than carried alongside a replacement
that did not exist yet.

What is here, on Linux with `/dev/kvm` and a guest image the tree builds: `bsx run` runs one command
in a sandbox and exits with its status, `bsx shell` opens a session on a pty inside the guest,
`bsx up` starts a sandbox that outlives the command that started it, and `bsx ls`, `bsx exec` and
`bsx stop` reach a sandbox this process did not start, and `--display WIDTHxHEIGHT` shows a guest's
screen in a window whose keyboard and pointer go to the guest, and the desktop image boots to a
terminal in a Wayland session there. What is not here: the GUI application, GPU acceleration, and macOS. If you want
the Firecracker engine, it is in git history.

There are no users, no installed base, and no release to install. Nothing below is an invitation to
depend on this yet.

## What it is, when it exists

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

`/dev/kvm` must be readable and writable by your user, which usually means membership of the `kvm`
group. No part of the build needs root.

```console
cargo xtask setup            # what this host can and cannot do
cargo xtask ci               # the gate: fmt, prose drift, clippy, build, test, docs, deny
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
| `crates/cli` | `bsx` | The `bsx` CLI. No verbs today. The binary on `PATH` is `bsx`. |
| `crates/test-support` | `bsx-test-support` | Shared test fixtures: a self-reclaiming scratch dir, a log sink, a deterministic generator. Dev-only, never shipped. |
| `docs` | | This documentation, as an mdBook. |
| `xtask` | `xtask` | Dev orchestration: `cargo xtask ci`, the guest image build, the vendor mirror. Never shipped. |

## Verified on

The gate (`cargo xtask ci`: build, tests, lints, docs, dependency audit) runs in CI on Ubuntu 24.04
`x86_64` on every change and needs no privilege. **No CI lane boots a VM, and neither does anything
in this tree.** Development happens on Arch Linux `x86_64`.

## Releases and scope

There is no published roadmap and no promised date. A capability becomes a feature when a test
exercises it end to end, and is not announced before that. The first supported release, `v0.1.0`,
will pin the host↔guest wire framing and the supervisor API; until then everything, including the
crate names, changes without notice.

The project is **open to outside pull requests**, though this is a poor moment to send one: the
surface is being rebuilt. A pull request signs its commits off (`git commit -s`). The terms are in
[`CONTRIBUTING.md`](CONTRIBUTING.md), and [`AGENTS.md`](AGENTS.md) is the operating manual.

## License

Apache-2.0. See [LICENSE](LICENSE).
