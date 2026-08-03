<div align="center">
  <h1><code>eKVM</code></h1>

  <p>
    <strong>A self-hostable sandbox for running untrusted code in a hardware-isolated
    <a href="https://github.com/firecracker-microvm/firecracker">Firecracker</a> microVM,
    with a host-observed record of exactly what it did</strong>
  </p>

  <p>
    <a href="https://github.com/packsixfour/ekvm/actions/workflows/ci.yml"><img src="https://github.com/packsixfour/ekvm/actions/workflows/ci.yml/badge.svg" alt="build status" /></a>
    <img src="https://img.shields.io/badge/status-pre--release-orange.svg" alt="pre-release" />
    <img src="https://img.shields.io/badge/rustc-1.97%2B-green.svg" alt="supported rustc 1.97+" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="Apache-2.0" /></a>
  </p>

  <h3>
    <a href="docs/SUMMARY.md">Guide</a>
    <span> | </span>
    <a href="docs/architecture.md">Architecture</a>
    <span> | </span>
    <a href="docs/introduction.md#status">Status</a>
    <span> | </span>
    <a href="CONTRIBUTING.md">Contributing</a>
  </h3>
</div>

## Warning

eKVM is pre-release and unaudited. Version `0.0.1` is a checkpoint that exercises the release path,
not a supported release: one maintainer, no external review, and no outside users. The API changes
without notice, so if you build on it, pin a git rev. It has been run on two kernels, neither of
them enterprise. Benchmark numbers are withdrawn pending re-measurement.

**Use it only if you are willing to read the code you are trusting.** That is the honest bar for a
sandbox at this stage, and everything below is written to make that possible: the full verification
record, including [what has *not* been done](docs/introduction.md#what-has-not-been-done), is in
[Status](docs/introduction.md#status).

## What it is

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc clsact) · its cgroup
      → per-run audit record (network flows · notable syscalls · resources · denials)
```

eKVM runs untrusted code inside a Firecracker microVM, so the boundary is enforced by the CPU
through KVM rather than by guest-side software. Around that microVM, host-side eBPF (via
[aya](https://aya-rs.dev/)) observes and enforces what the code does, its syscalls, its network, and
its cgroup, from the host side of that boundary: the programs are loaded by a host process and
attached to host-kernel hooks, where they sit outside the guest's address space and outside any
namespace it can enter.

Every run yields a host-observed audit record of what the host was able to see: the
network flows, the notable syscalls, the resources used, and any egress that was denied. That record
is the product. A run that persists one signs it with a host key (`--record`, or an operator's
`records_dir`, or the daemon's `trace`), and `ekvm verify` checks that signature.

## Installation

Today the supported path is from source. The engine drives Firecracker, it does not bundle it, so
you supply that binary and an upstream security patch never waits on a release of this engine.

```console
git clone https://github.com/packsixfour/ekvm && cd ekvm
cargo xtask self-host       # build + install ekvm, then boot a proof sandbox
```

**Requirements:** Linux on `x86_64` with `/dev/kvm`, a kernel providing `cgroup.kill`, and
Firecracker v1.15 through v1.16 on `PATH` (v1.16.1 is pinned and tested).
`ekvm doctor` probes for each capability rather than trusting a version string or a distro name, and
prints the fix for whatever your host is missing. Starting from a bare machine,
[Preparing the host](docs/cli-install.md#preparing-the-host) is the copy-pasteable version.

The release tarball and `install.sh` are built by `cargo xtask dist` and described
in [Installation](docs/cli-install.md); a `Containerfile` consumes the tarball for an image you
build yourself. `v0.0.1` publishes the release assets, so those paths resolve, but it is a
checkpoint that exercises the release path rather than a supported release.

## Example

Run some untrusted code. The default is **jailed**, the supported posture:

```console
sudo -E ekvm run -- python3 -c 'print(2 ** 100)'
```

On a dev box without real root, `--unjailed` is the explicit opt-out:

```console
ekvm run --unjailed -- python3 -c 'print(2 ** 100)'
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

The output is the boring half. Ask instead what the code *did*:

```console
sudo -E ekvm run --trace --record run.json -- python3 untrusted.py
```

`--trace` renders the run's audit trail on stdout; `--record` writes the signed machine-readable
record for later inspection or `ekvm verify`. Both attach the host-side probes and fail open: a host
without eBPF capabilities still runs the sandbox and annotates the coverage gap in the record rather
than presenting a thinner record as a complete one. [The CLI chapter](docs/cli.md) has the full
surface, including `--record-summary` for an agent loop and `--watch` for a live view.

## Design rules

Six rules. A change that breaks one is a design error, not a trade-off. Each states an intent and
the mechanism serving it; the full text is [docs/architecture.md](docs/architecture.md).

* **Isolation is hardware, not software**: untrusted code runs in a KVM microVM, never behind a
  guest-side check.
* **[Observe and enforce from the host][probes]**: visibility and policy are host-side eBPF on
  host-kernel hooks; the in-guest agent carries exec and IO, never containment.
* **Deny by default**: no explicit policy means no route out and minimal capability, and every
  allowance lands in the record.
* **Engine, not platform**: a runtime and a driver API. Tenancy, billing, scheduling, and
  dashboards are the hoster's: a recorded [non-goal][embedding], not a gap.
* **No panic, hang, or leak on the host path**: a hostile guest, a failed probe, or a broken
  channel surfaces as a typed error. The rule the code is written against and the confinement suite
  exercises; an aim, not a proven property.
* **[Measure rather than assert][benchmarks]**: percentiles with the host and date, and a number
  that cannot be defended is withdrawn. Which is why the tables are withdrawn right now.

The host path is `#![forbid(unsafe_code)]`, enforced by the compiler in every crate but the eBPF
one. Those programs build for `bpfel-unknown-none` and carry BTF, which is what CO-RE relocation
needs; no program reads kernel struct fields yet, so no field relocations are in play and the
portability is so far a property of the toolchain rather than something exercised. It has been
loaded on two kernels, which
[what has not been done](docs/introduction.md#what-has-not-been-done) says plainly.

[probes]: docs/probes.md
[embedding]: docs/embedding.md
[embedding-scope]: docs/embedding-scope.md
[benchmarks]: docs/benchmarks.md

## Embedding

The engine is consumed in three shapes, one of which exists today:

* **Rust**, the `ekvm-engine` crate's public API (`Sandbox`, `Limits`, `RunResult`, `VmmError`), depended
  on by git rev:
  `ekvm-engine = { git = "https://github.com/packsixfour/ekvm", rev = "…" }`. It is not distributed through
  crates.io **by decision, not pending**: an immutable registry version would outlive this engine's
  support window, which is computed from Firecracker's, so a name held there is a `0.0.0` placeholder
  rather than a release ([the reasoning][embedding-scope]). A change to that API is
  committed with an `api` scope, so a pin bump is auditable from the log alone. The contract is
  [docs/embedding.md][embedding].

* **Any language**, over the `ekvm serve` daemon: a versioned newline-delimited JSON wire protocol
  on a unix socket, documented in [docs/daemon.md](docs/daemon.md). `ekvm-client` (in
  `crates/client`) is a dependency-light Rust reference client for it.

* **Language SDKs** (`ekvm-python`, `ekvm-go`, `ekvm-node`, in that order), planned in separate companion
  repositories so their build tooling stays out of this workspace. **None are built yet.**

## Documentation

The guide is an mdBook in [`docs/`](docs/SUMMARY.md). Run `mdbook serve docs`, or read the Markdown
in place. It is not published as a site until the first release.

- **[Introduction](docs/introduction.md)**, what this is and how the pieces fit.
- **[Architecture and design](docs/architecture.md)**, the six design rules, how the engine
  integrates with the host, what the crates are for, and the numbered decisions with their
  rationale.
- **[Using the eKVM CLI](docs/cli.md)**, including [installation](docs/cli-install.md).
- **[Using the `ekvm serve` daemon](docs/daemon.md)**, the wire API.
- **[Using the engine API](docs/embedding.md)**, the embedder's contract and the non-goals.
- **[Host-side observability & enforcement](docs/probes.md)**, the eBPF half: syscall tracing,
  per-VM network flows, in-kernel egress enforcement, resource accounting, each pinned by a
  privileged test.
- **[Benchmarks](docs/benchmarks.md)**, the methodology and how to run it yourself.
- **[Security](docs/security.md)** and the **[threat model](docs/security-threat-model.md)**.

## Getting help

There is no chat server and no forum: one maintainer, and a channel nobody answers is worse than no
channel. Everything routes through the repository, where the answer stays searchable.

- **A question, or something that does not work**: [open an
  issue](https://github.com/packsixfour/ekvm/issues/new/choose). Questions are welcome as issues;
  if the docs did not answer it, that is usually a docs bug worth fixing.
- **A suspected vulnerability**: use the [private advisory
  form](https://github.com/packsixfour/ekvm/security/advisories/new), never a public issue.
  [`SECURITY.md`](SECURITY.md) states what counts as one.
- **A change you want to make**: read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Bug fixes, tests,
  and docs can go straight to a pull request; anything larger starts with an issue, because the API
  is still moving and an issue is how you avoid building against a shape that is about to change.

## Repo layout

Directories stay short and packages carry the `ekvm-` prefix, so a package is its directory plus that
prefix, with one exception: `crates/cli` builds `ekvm`, the bare name going to the command a user
types. `cargo … -p` takes the package, a path takes the directory.

| Path | Package | Role |
|------|---------|------|
| `crates/engine` | `ekvm-engine` | The Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, the `Sandbox` API. |
| `crates/channel` | `ekvm-channel` | The host↔guest wire protocol: near dependency-free length-prefixed framing (`zeroize`, for the post-send secret wipe, is the one dependency), shared by driver + agent. |
| `crates/guest-agent` | `ekvm-guest-agent` | The in-guest agent: runs one command per connection, streams stdout/stderr/exit. Exec/IO only, not the trust boundary. |
| `crates/probes` | `ekvm-probes` | The eBPF programs (`no_std`, built for `bpfel-unknown-none` with aya). |
| `crates/probes-common` | `ekvm-probes-common` | The `#[repr(C)]` event/policy records shared across the eBPF boundary, single-sourced. |
| `crates/probes-loader` | `ekvm-probes-loader` | Userspace: load/attach the probes, read their maps, stream events into the record. |
| `crates/protocol` | `ekvm-protocol` | The daemon wire types, versioned. |
| `crates/client` | `ekvm-client` | The Rust reference client for `ekvm serve`. |
| `crates/cli` | `ekvm` | The `ekvm` CLI: `run`, `shell`, `doctor`, `verify`, plus the `ekvm serve` daemon. The binary on `PATH` is `ekvm`. |
| `crates/test-support` | `ekvm-test-support` | Shared test fixtures: scratch dirs, small filesystems for disk-full cases, cgroup helpers, the real-root guard. Dev-only, never shipped. |
| `docs` | | This documentation, as an mdBook. |
| `xtask` | `xtask` | Dev orchestration: `cargo xtask ci`, the eBPF object build, the rootfs build. Never shipped. |

## Verified on

The host-safe gate (`cargo xtask ci`: build, tests, lints, docs, dependency audit, eBPF object
build) runs in CI on Ubuntu 24.04 `x86_64` on every change. The privileged path (microVM boot, the
jailer, the eBPF probes, the integration suite) needs `/dev/kvm` and real root: it runs nightly on a
GitHub-hosted Ubuntu 24.04 runner under nested KVM, and is hand-verified on Arch Linux during
development. `x86_64` is the only supported architecture; aarch64 returns only with hardware and a
privileged CI lane behind it. `ekvm doctor` reports your own host's readiness, and
[Supported platforms](docs/cli-install.md#supported-platforms) records which hosts have actually
been run.

## Releases and scope

There is no published roadmap and no promised date. A capability becomes a feature when a test
exercises it end to end (the privileged suite, for anything that boots a VM or attaches a probe),
and is not announced before that. The first supported release, `v0.1.0`, will pin
the driver API and the wire protocol under the support policy in [RELEASES.md](RELEASES.md); until
then the `Sandbox`/`ekvm-engine` API, the daemon protocol, the record format, and the crate names can all
change without notice.

The project is **open to outside pull requests**. Bug fixes, tests, and documentation can go
straight to one; anything larger starts with an issue, since the surface above is still moving.
Commits carry a `Signed-off-by` line. The terms are in [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
developer manual is [`AGENTS.md`](AGENTS.md), which coding agents working in this repo follow too.

Security issues: [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0, see [`LICENSE`](LICENSE).
