# Releases

> **Nothing in this file is in force.** No release has been tagged and no artifact published, so
> the API surface, host requirements, support policy, and Rust policy below describe what is
> *planned* for the first release, not commitments that apply today. See
> [docs/introduction.md#status](docs/introduction.md#status).

## v0.1.0 (Unreleased, planned)

The first supported release of eKVM: a self-hostable engine that boots a hardware-isolated Firecracker microVM, executes untrusted code, enforces host-side eBPF policy, and emits a host-signed audit record.

### Added
- **Hardware Isolation Driver (`ekvm-engine`, `crates/vmm`)**: `Sandbox` lifecycle API managing Firecracker microVM boot, jailed execution, disk staging, and teardown.
- **Host eBPF Observability (`ekvm-probes` & `ekvm-probes-loader`)**: `aya`-based eBPF probes for out-of-guest syscall tracing, TAP network flow monitoring, and cgroup v2 resource accounting.
- **Daemon Wire Interface (`ekvm-protocol` & `ekvm`)**: Versioned newline-delimited JSON wire API (`schema: 1`) served by `ekvm serve` over Unix domain sockets.
- **Audit Records**: Host-observed, Ed25519-signed JSON audit logs (`RunRecord`) with a hash-chained `trace`. What a signature establishes is in [docs/security-threat-model.md](docs/security-threat-model.md#record-integrity-beyond-the-guest).
- **Reference Rust Client (`ekvm-client`, `crates/client`)**: Dependency-light reference client driving `ekvm serve` over Unix sockets.
- **Pre-warmed Sandbox Pool**: Snapshot-restore pool for warm sandbox starts. Latency figures are withdrawn pending a re-measurement on a verified host; see [docs/benchmarks.md](docs/benchmarks.md).
- **Host Diagnostics (`ekvm doctor`)**: Pre-flight host verification for `/dev/kvm`, the host-kernel floor (a probed `cgroup.kill`, else >= 5.15), cgroup v2, and BTF eBPF support.
- **Distribution Tooling (`xtask`)**: Release packaging (`cargo xtask dist`) producing release tarballs (`ekvm-0.1.0-x86_64-linux.tar.gz`), a signed `SHA256SUMS` manifest, and single-command installer (`install.sh`).

### Planned pinned API surface (v0.1.0)
The same surface `AGENTS.md`'s `api`-scope rule and
[the Semver section](docs/embedding-scope.md#semver--api-stability) name, restated here as what a
tag would freeze.
- **Rust Driver API** (`ekvm-engine`): `Sandbox`, `Limits`, `RunResult`, `VmmError` (`kind() -> ErrorKind`).
- **Host↔guest framing** (`ekvm-channel`): the length-prefixed exec protocol the driver and the
  in-guest agent share.
- **Daemon wire protocol** (`ekvm-protocol`): line-delimited JSON (`schema: 1`).

### Planned host requirements (v0.1.0)
- **Host**: Linux `x86_64` with `/dev/kvm`, cgroup v2, and kernel BTF; a kernel providing
  `cgroup.kill`, else >= 5.15 where there is no cgroup v2 hierarchy to probe
  (`/sys/kernel/btf/vmlinux`). `ekvm doctor` verifies all of it and prints the fix for
  whatever is missing.
- **Firecracker**: v1.15 through v1.16 supported (upstream's current support window);
  v1.16.1 is the pinned, tested, hash-verified release. The operator installs the binary
  (see [docs/cli-install.md](docs/cli-install.md)), so an upstream security patch never
  waits on a release of this engine.

---

## The Finish Line & Pre-Release Policy

`v0.1.0` is cut once every planned phase gate passes (`cargo xtask ci` and `cargo xtask ci-privileged`).

### Release Signing (prerequisite for every tagged release)

`SHA256SUMS` ships with a detached ed25519 signature made by the release key. Before the first
tag (and after any rotation), the operator ceremony is:

1. `cargo xtask release-key --path <file outside the repo>` mints (or shows) the key and prints
   its SPKI PEM.
2. Pin the public key: commit the PEM as `release-key.pem` (repo root) **and** into the
   `install.sh` heredoc (a dist test asserts the two are byte-identical).
3. `gh secret set EKVM_RELEASE_SIGNING_KEY < <file>` wires the private key into release CI.

Tag builds hard-fail without the secret, and the attach step refuses to publish without
`SHA256SUMS.sig`: a mis-wired secret cannot ship an unsigned release. `workflow_dispatch` dry
runs build unsigned and publish nothing. Key custody stays with the operator; the private key
never enters the repo or `dist/`.

- **Pre-release Checkpoints (`v0.0.x`)**: Pre-release tags start at `v0.0.1`. These are disposable git checkpoint tags pinned by git rev with no stability promises.
- **Production Releases (`v0.1.0`+)**: Tagged on `main`. Patch fixes for a release line are backported to its dedicated release branch (e.g., `release-v0.1` for `v0.1.1`).
- **Tags are a Human Step**: The user cuts every release tag (see [`AGENTS.md`](AGENTS.md)).
- **Full Stability & SemVer Policy**: See [docs/embedding-scope.md](docs/embedding-scope.md#semver--api-stability).

---

## Support policy (planned, takes effect at the first tag)

- **Latest minor**: fixes and features, on `main`.
- **Previous minor**: security and serious-bug backports only, on its release branch
  (`release-vX.Y`, patch tags `vX.Y.1`, `vX.Y.2`, ...).
- **Older minors**: unsupported.

**The previous minor's window is computed, not dated.** Each release line supports a
Firecracker range, floor through pin (v0.1.0 supports v1.15 through v1.16). The line stays
supported for as long as any Firecracker series in that range is still under upstream
support; once the last of them ages out (about one Firecracker release cycle, roughly six
months, after the next eKVM minor ships), every VMM the line can drive is unpatched, and
continuing to "support" it would bless untrusted code on an unmaintained isolation
boundary, the same threat-model reasoning behind `ekvm doctor`'s host kernel floor. The
weekly `firecracker-pin` workflow watches upstream's support table, so the end of a window
is observed, not remembered.

---

## Rust Version Support

- **Policy**: Supported Rust is current stable, pinned exactly in `rust-toolchain.toml` and mirrored in the workspace package `rust-version`.
- **The eBPF crate (`ekvm-probes`, `crates/probes`)**: Nightly by construction, targeting `bpfel-unknown-none` via `bpf-linker`.
- **Bumping Rust**: Update `rust-toolchain.toml` and `Cargo.toml` together, verify `cargo xtask ci` passes, and document in release notes.
