# Releases

Release notes for eKVM releases are documented below.

## v0.1.0 (Unreleased)

The initial stable release of eKVM: a self-hostable engine that boots a hardware-isolated Firecracker microVM, executes untrusted code, enforces host-side eBPF policy, and emits a host-signed audit record.

### Added
- **Hardware Isolation Driver (`crates/vmm`)**: `Sandbox` lifecycle API managing Firecracker microVM boot, jailed execution, disk staging, and teardown.
- **Host eBPF Observability (`crates/probes` & `crates/probes-loader`)**: `aya`-based eBPF probes for out-of-guest syscall tracing, TAP network flow monitoring, and cgroup v2 resource accounting.
- **Daemon Wire Interface (`crates/protocol` & `crates/cli`)**: Versioned newline-delimited JSON wire API (`schema: 1`) served by `ekvm serve` over Unix domain sockets.
- **Tamper-Evident Audit Records**: Host-observed Ed25519-signed JSON audit logs (`RunRecord`) with hash-chain verification (`trace`).
- **Reference Rust Client (`crates/client`)**: Dependency-light reference client driving `ekvm serve` over Unix sockets.
- **Pre-warmed Sandbox Pool**: Snapshot-restore pool for warm sandbox starts (pool take p50 under 1 ms; restore-to-first-result p50 ~100 ms; see [docs/benchmarks.md](docs/benchmarks.md) for the measured percentiles).
- **Host Diagnostics (`ekvm doctor`)**: Pre-flight host verification for `/dev/kvm`, Linux kernel floor >= 5.15, cgroup v2, and BTF eBPF support.
- **Distribution Tooling (`xtask`)**: Release packaging (`cargo xtask dist`) producing release tarballs (`ekvm-0.1.0-x86_64-linux.tar.gz`), a signed `SHA256SUMS` manifest, and single-command installer (`install.sh`).

### Pinned API Surface (v0.1.0)
- **Rust Driver API**: `Sandbox`, `Limits`, `RunResult`, `VmmError` (`kind() -> ErrorKind`).
- **Wire Protocol**: Line-delimited JSON format (`schema: 1`).

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
- **Full Stability & SemVer Policy**: See [docs/embedding.md](docs/embedding.md#semver--api-stability).

---

## Rust Version Support

- **Policy**: Supported Rust is current stable, pinned exactly in `rust-toolchain.toml` and mirrored in the workspace package `rust-version`.
- **The eBPF Crate (`crates/probes`)**: Nightly by construction, targeting `bpfel-unknown-none` via `bpf-linker`.
- **Bumping Rust**: Update `rust-toolchain.toml` and `Cargo.toml` together, verify `cargo xtask ci` passes, and document in release notes.
