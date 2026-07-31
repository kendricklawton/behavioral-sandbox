<div align="center">
  <h1><code>ekvm</code></h1>

  <p>
    <strong>A self-hostable engine for running untrusted code in a hardware-isolated
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
    <a href="docs/architecture.md">Design</a>
    <span> | </span>
    <a href="docs/introduction.md#status">Status</a>
    <span> | </span>
    <a href="CONTRIBUTING.md">Contributing</a>
  </h3>
</div>

> **Pre-release, unreleased, unaudited.** Version `0.0.0`, no tag, no published artifact, one
> maintainer, no external review. Nothing here carries a compatibility guarantee: if you build on it,
> pin a git rev. The full verification record, including what has *not* been done, is
> [docs/introduction.md#status](docs/introduction.md#status).

## What it is

```
untrusted code
      → Firecracker microVM (KVM: hardware isolation, jailer, cgroups, snapshots)
      → host-side eBPF (aya): syscalls · the VM's tap device (tc/XDP) · its cgroup
      → per-run audit record (network flows · notable syscalls · resources · denials)
```

eKVM runs untrusted code inside a Firecracker microVM, so the boundary is enforced by the CPU
through KVM rather than by guest-side software. Around that microVM, host-side eBPF (via
[aya](https://aya-rs.dev/)) observes and enforces what the code does, its syscalls, its network, and
its cgroup, from the host side of that boundary: the programs are loaded by a host process and
attached to host-kernel hooks, where they sit outside the guest's address space and outside any
namespace it can enter.

Every run yields a host-observed, host-signed audit record of what the host was able to see: the
network flows, the notable syscalls, the resources used, and any egress that was denied. That record
is the product, and `ekvm verify` checks its signature.

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

The release tarball, `install.sh`, and container image are built by `cargo xtask dist` and described
in [Installation](docs/cli-install.md), but **no release has been published yet**, so those paths do
not resolve until the first tag.

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
itself runs under its jailer: a chroot, dropped uid/gid, its own namespaces, seccomp, and a cgroup,
which is why it needs real root and the `jailer` binary. Unjailed, that process runs unconfined on the
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

Six rules, each stating an intent and the mechanism serving it, so a change that breaks one is
recognisable as a design error rather than a trade-off. The full text is
[docs/architecture.md](docs/architecture.md).

* **Isolation is hardware, not software.** Untrusted code runs in a KVM microVM. Moving the boundary
  into guest-side software is a design error, not an optimisation, and a shared-kernel shortcut taken
  to make things simpler is the same error.

* **[Observe and enforce from the host][probes].** Visibility and policy belong in host-side eBPF
  attached to host-kernel hooks. The in-guest agent carries exec and IO framing; making it
  responsible for containing the guest is a design error.

* **Deny by default.** A sandbox with no explicit policy is configured with no route out and minimal
  capability, and each allowance is recorded in the audit record.

* **Engine, not platform.** A self-hostable runtime and a driver API. Multi-tenant auth, billing,
  fleet scheduling, and dashboards belong to whatever *hosts* the engine: a recorded non-goal, not a
  gap. The [non-goals list][embedding] is explicit about it.

* **No panic, hang, or leak on the host path.** A hostile or crashing guest, a failed probe, or a
  broken channel should surface as a typed error. This is the rule the code is written against and
  the property the confinement suite exercises; it is an aim, not a proven property.

* **[Measure rather than assert][benchmarks].** Boot, restore, memory sharing, and overhead are
  reported as nearest-rank percentiles with the host and date. A number that cannot be defended is
  withdrawn, which is why the result tables are currently withdrawn pending a re-measurement on a
  verified host.

The host path is `#![forbid(unsafe_code)]`. The eBPF programs build for their own target
(`bpfel-unknown-none`) and use CO-RE/BTF, which is a portability *mechanism*; the claim that it is
portable across kernels is tested on one kernel so far, and
[what has not been done](docs/introduction.md#what-has-not-been-done) says so.

[probes]: docs/probes.md
[embedding]: docs/embedding.md
[benchmarks]: docs/benchmarks.md

## Embedding

The engine is consumed in three shapes, one of which exists today:

* **Rust**, the `vmm` crate's public API (`Sandbox`, `Limits`, `RunResult`, `VmmError`). Not on
  crates.io yet, so depend on it by git rev. A change to that API is committed with an `api` scope,
  so a pin bump is auditable from the log alone. The contract is [docs/embedding.md][embedding].

* **Any language**, over the `ekvm serve` daemon: a versioned newline-delimited JSON wire protocol
  on a unix socket, documented in [docs/daemon.md](docs/daemon.md). `crates/client` is a
  dependency-light Rust reference client for it.

* **Language SDKs** (`ekvm-python`, `ekvm-node`, `ekvm-go`), planned in separate companion
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
- **[Examples](docs/examples.md)**, worked end-to-end walkthroughs.
- **[Host-side observability & enforcement](docs/probes.md)**, the eBPF half: syscall tracing,
  per-VM network flows, in-kernel egress enforcement, resource accounting, each with a live demo.
- **[Benchmarks](docs/benchmarks.md)**, the methodology and how to run it yourself.
- **[Security](docs/security.md)** and the **[threat model](docs/security-threat-model.md)**.
- **[Contributing](docs/contributing.md)**, invariants, developer tools, CI gates, testing, fuzzing.

## Repo layout

| Path | Role |
|------|------|
| `crates/vmm` | The Firecracker driver: microVM lifecycle, rootfs, networking, snapshots, the `Sandbox` API. |
| `crates/channel` | The host↔guest wire protocol: dependency-free length-prefixed framing, shared by driver + agent. |
| `crates/guest-agent` | The in-guest agent: runs one command per connection, streams stdout/stderr/exit. Exec/IO only, not the trust boundary. |
| `crates/probes` | The eBPF programs (`no_std`, built for `bpfel-unknown-none` with aya). |
| `crates/probes-common` | The `#[repr(C)]` event/policy records shared across the eBPF boundary, single-sourced. |
| `crates/probes-loader` | Userspace: load/attach the probes, read their maps, stream events into the record. |
| `crates/protocol` | The daemon wire types, versioned. |
| `crates/client` | The Rust reference client for `ekvm serve`. |
| `crates/cli` | The `ekvm` CLI: `run`, `shell`, `doctor`, plus the `ekvm serve` daemon. |
| `docs` | This documentation, as an mdBook. |
| `xtask` | Dev orchestration: `cargo xtask ci`, the eBPF object build, the rootfs build. Never shipped. |

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

There is no published roadmap and no promised date. A capability becomes a feature when it ships
with a working demo, and is not announced before that. The first tagged release, `v0.1.0`, will pin
the driver API and the wire protocol under the support policy in [RELEASES.md](RELEASES.md); until
then the `Sandbox`/`vmm` API, the daemon protocol, the record format, and the crate names can all
change without notice.

The project is **open to outside pull requests**. Bug fixes, tests, and documentation can go
straight to one; anything larger starts with an issue, since the surface above is still moving.
Commits carry a `Signed-off-by` line. The terms are in [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
developer manual is the [contributing chapters](docs/contributing.md). Coding agents working in this
repo follow [`AGENTS.md`](AGENTS.md).

Security issues: [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0, see [`LICENSE`](LICENSE).
