<div align="center">
  <h1>Behavioral Sandbox</h1>

  <p>
    <strong>A self-hostable sandbox for running untrusted code in a hardware-isolated
    <a href="https://github.com/firecracker-microvm/firecracker">Firecracker</a> microVM,
    with a host-observed record of exactly what it did</strong>
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

## Warning

Behavioral Sandbox (**BSX**) is pre-release and unaudited. Version `0.0.4` is a checkpoint that
exercises the release path, not a supported release: one maintainer, no external review, and no
outside users. The API changes without notice, so if you build on it, pin a git rev. It has been
run on three kernels, none of them enterprise. Cold boot latency is published with its host and
date; every other benchmark number is withdrawn pending re-measurement.

**Use it only if you are willing to read the code you are trusting.** That is the honest bar for a
sandbox at this stage, and everything below is written to make that possible.

## What it is

```text
                     CONSUMER ENTRY POINTS & API SURFACES

    [ Rust Embedder ]                                        [ CLI user ]
            |                                                     |
            v (In-Process)                                        v
     `bsx-engine`                                            `bsx` CLI
   (Sandbox, BootConfig, Vm)                     (a thin host of the same engine)
            |                                                     |
            +----------------------------+------------------------+
                                         |
                                         v
                              Firecracker microVM
                            +-----------------------+
                            | KVM Hardware Isolation|
                            | In-Guest Agent        |
                            +-----------------------+
                                 (`bsx-channel` framing over vsock)
```

BSX runs untrusted code inside a microVM, so the boundary is enforced by the CPU through hardware
virtualization rather than by guest-side software. What a sandbox can reach is decided before it
starts: with no explicit configuration it shares no host directory and has no network.

## Installation

Today the supported path is from source. The engine drives Firecracker, it does not bundle it, so
you supply that binary and an upstream security patch never waits on a release of this engine.

```console
git clone https://github.com/kendricklawton/behavioral-sandbox && cd behavioral-sandbox
cargo xtask self-host       # build + install bsx, then boot a proof sandbox
```

**Requirements:** Linux on `x86_64` with `/dev/kvm`, a kernel providing `cgroup.kill`, and
Firecracker v1.15 through v1.16 on `PATH` (v1.16.1 is pinned and tested).
`bsx doctor` probes for each capability rather than trusting a version string or a distro name, and
prints the fix for whatever your host is missing. Starting from a bare machine,
[Preparing the host](docs/cli-install.md#preparing-the-host) is the copy-pasteable version.

The release tarball and `install.sh` are built by `cargo xtask dist` and described
in [Installation](docs/cli-install.md); a `Containerfile` consumes the tarball for an image you
build yourself. `v0.0.3` is the first tag whose assets carry this name, and it is a checkpoint that
exercises the release path rather than a supported release.

## Example

Run some untrusted code. The default is **jailed**, the supported posture:

```console
sudo -E bsx run -- python3 -c 'print(2 ** 100)'
```

On a dev box without real root, `--unjailed` is the explicit opt-out:

```console
bsx run --unjailed -- python3 -c 'print(2 ** 100)'
```

Either way:

```text
1267650600228229401496703205376
```

The difference is what confines the **VMM process**, not what confines the guest. Jailed, Firecracker
itself runs under its jailer: a chroot, dropped uid/gid, its own namespaces, and a cgroup, which is
why it needs real root and the `jailer` binary. Firecracker's own built-in seccomp filters apply
either way, because the driver never passes `--no-seccomp`. Unjailed, that process runs unconfined on the
host. In both cases the untrusted code stays behind the same KVM boundary, because that boundary is
the CPU's, not the jailer's. A host can withdraw the opt-out entirely with `require_jail`
([configuration](docs/cli-config.md#setting-require_jail)).

[The CLI chapter](docs/cli.md) has the full surface.

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
  account, and no fleet: a recorded [non-goal][embedding], not a gap.
* **No panic, hang, or leak on the host path**: a hostile guest or a dead helper surfaces as a typed
  error. The rule the code is written against and the confinement suite exercises; an aim, not a
  proven property.
* **[Measure rather than assert][benchmarks]**: percentiles with the host and date, and a number
  that cannot be defended is withdrawn.

The host path is `#![forbid(unsafe_code)]`, enforced by the compiler in every crate and checked by
`every_crate_forbids_unsafe` in the gate.

[embedding]: docs/embedding.md
[embedding-scope]: docs/embedding-scope.md
[benchmarks]: docs/benchmarks.md

## Embedding

The engine is consumed in two shapes, both of which exist today:

* **Rust**, the `bsx-engine` crate's public API (`Sandbox`, `Limits`, `RunResult`, `VmmError`), depended
  on by git rev: `bsx-engine = { git = "https://github.com/kendricklawton/behavioral-sandbox", rev =
  "…" }`. It is not distributed through crates.io **by decision, not pending**: an immutable
  registry version would outlive this engine's support window, which is computed from Firecracker's,
  so a name held there is a `0.0.0` placeholder rather than a release ([the
  reasoning][embedding-scope]). A change to that API is committed with an `api` scope, so a pin bump
  is auditable from the log alone. The contract is [docs/embedding.md][embedding].

## Documentation

The guide is an mdBook in [`docs/`](docs/SUMMARY.md), rendered by the `Docs` workflow at
[kendricklawton.github.io/behavioral-sandbox](https://kendricklawton.github.io/behavioral-sandbox).
Run `mdbook serve docs` to read it locally, or read the Markdown in place.

- **[Introduction](docs/introduction.md)**, what this is and how the pieces fit.
- **[Architecture and design](docs/architecture.md)**, the six design rules, how the engine
  integrates with the host, what the crates are for, and the numbered decisions with their
  rationale.
- **[Using the `bsx` CLI](docs/cli.md)**, including [installation](docs/cli-install.md).
- **[Using the engine API](docs/embedding.md)**, the embedder's contract and the non-goals.
- **[Benchmarks](docs/benchmarks.md)**, the methodology and how to run it yourself.
- **[Security](docs/security.md)** and the **[threat model](docs/security-threat-model.md)**.

## Getting help

There is no chat server and no forum: one maintainer, and a channel nobody answers is worse than no
channel. Everything routes through the repository, where the answer stays searchable.

- **A question, or something that does not work**: ask in [Q&A
  Discussions](https://github.com/kendricklawton/behavioral-sandbox/discussions/categories/q-a). The
  form asks for your `bsx doctor` output, which is usually what identifies the problem. If the docs
  did not answer it, that is a docs bug worth fixing, so [open an
  issue](https://github.com/kendricklawton/behavioral-sandbox/issues/new/choose) too.
- **A suspected vulnerability**: use the [private advisory
  form](https://github.com/kendricklawton/behavioral-sandbox/security/advisories/new), never a
  public issue. [`SECURITY.md`](SECURITY.md) states what counts as one.
- **A change you want to make**: read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Bug fixes, tests,
  and docs can go straight to a pull request; anything larger starts with an issue, because the API
  is still moving and an issue is how you avoid building against a shape that is about to change.

## Repo layout

Directories stay short and packages carry the `bsx-` prefix, so a package is its directory plus that
prefix, with one exception: `crates/cli` builds `bsx`, the bare name going to the command a user
types. `cargo … -p` takes the package, a path takes the directory.

| Path | Package | Role |
|------|---------|------|
| `crates/engine` | `bsx-engine` | The Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, the `Sandbox` API. |
| `crates/channel` | `bsx-channel` | The host↔guest wire protocol: nearly dependency-free length-prefixed framing (`zeroize`, for the post-send secret wipe, is the one dependency), shared by driver + agent. |
| `crates/guest-agent` | `bsx-guest-agent` | The in-guest agent: runs one command per connection, streams stdout/stderr/exit. Exec/IO only, not the trust boundary. |
| `crates/cli` | `bsx` | The `bsx` CLI: `run`, `shell`, `doctor`, `verify`. The binary on `PATH` is `bsx`. |
| `crates/test-support` | `bsx-test-support` | Shared test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, the real-root guard. Dev-only, never shipped. |
| `docs` | | This documentation, as an mdBook. |
| `xtask` | `xtask` | Dev orchestration: `cargo xtask ci`, the eBPF object build, the rootfs build. Never shipped. |

## Verified on

The gate (`cargo xtask ci`: build, tests, lints, docs, dependency audit) runs in CI on Ubuntu 24.04
`x86_64` on every change and needs no privilege. Anything that boots a microVM needs `/dev/kvm`, so
it is skipped where the device is absent and hand-verified on Arch Linux during development. `bsx doctor` reports your own host's readiness, and
[Supported platforms](docs/cli-install.md#supported-platforms) records which hosts have actually
been run.

## Releases and scope

There is no published roadmap and no promised date. A capability becomes a feature when a test
exercises it end to end (the privileged suite, for anything that boots a VM or attaches a probe),
and is not announced before that. The first supported release, `v0.1.0`, will pin
the driver API and the host↔guest wire framing; until then the `Sandbox`/`bsx-engine` API, the
record format, and the crate names can all change without notice.

The project is **open to outside pull requests**. Bug fixes, tests, and documentation can go
straight to one; anything larger starts with an issue, since the surface above is still moving.
A pull request signs its commits off (`git commit -s`). The terms are in [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
developer manual is [`AGENTS.md`](AGENTS.md), which coding agents working in this repo follow too.

Security issues: [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0, see [`LICENSE`](LICENSE).
