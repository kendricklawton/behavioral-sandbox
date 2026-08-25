# Releases

> **Only the release mechanics below are in force.** The `v0.0.x` tags are checkpoints that exercise
> them: the tag-triggered build, signing, the manifest, draft-then-publish, and `install.sh`'s
> download path. The API surface, host requirements, support policy, and Rust policy still describe
> what is *planned* for `v0.1.0`, not commitments that apply today.

## v0.1.0 (Unreleased, planned)

The first supported release of BSX: a self-hostable engine that boots a hardware-isolated Firecracker microVM, executes untrusted code, enforces host-side eBPF policy, and emits a host-signed audit record.

### Added
- **Hardware Isolation Driver (`bsx-engine`, `crates/engine`)**: `Sandbox` lifecycle API managing Firecracker microVM boot, jailed execution, disk staging, and teardown.
- **Host eBPF Observability (`bsx-probes` & `bsx-probes-loader`)**: `aya`-based eBPF probes for out-of-guest syscall tracing, TAP network flow monitoring, and cgroup v2 resource accounting.
- **Daemon Wire Interface (`bsx-protocol` & `bsx`)**: Versioned newline-delimited JSON wire API (`schema: 1`) served by `bsx serve` over Unix domain sockets.
- **Audit Records**: Host-observed, Ed25519-signed JSON audit logs (`RunRecord`) with a hash-chained `trace`. What a signature establishes is in [docs/security-threat-model.md](docs/security-threat-model.md#record-integrity-beyond-the-guest).
- **Reference Rust Client (`bsx-client`, `crates/client`)**: Dependency-light reference client driving `bsx serve` over Unix sockets.
- **Pre-warmed Sandbox Pool**: Snapshot-restore pool for warm sandbox starts. Latency figures are withdrawn pending a re-measurement on a verified host; see [docs/benchmarks.md](docs/benchmarks.md).
- **Host Diagnostics (`bsx doctor`)**: Pre-flight host verification for `/dev/kvm`, the host-kernel floor (a probed `cgroup.kill`, else >= 5.15), cgroup v2, and BTF eBPF support.
- **Distribution Tooling (`xtask`)**: Release packaging (`cargo xtask dist`) producing release tarballs (`bsx-0.1.0-x86_64-linux.tar.gz`), a signed `SHA256SUMS` manifest, and single-command installer (`install.sh`).

### Planned pinned API surface (v0.1.0)
The same surface `AGENTS.md`'s `api`-scope rule and
[the Semver section](docs/embedding-scope.md#semver--api-stability) name, restated here as what a
tag would freeze.
- **Rust Driver API** (`bsx-engine`): `Sandbox`, `Limits`, `RunResult`, `VmmError` (`kind() -> ErrorKind`).
- **Host↔guest framing** (`bsx-channel`): the length-prefixed exec protocol the driver and the
  in-guest agent share.
- **Daemon wire protocol** (`bsx-protocol`): line-delimited JSON (`schema: 1`).
- **Signed audit record** (`bsx-record`): the record's shape, its canonical JSON, and the
  signature envelope (`verify`, `verify_entry`, `verify_chain`, `record_hash`). The one contract
  here whose breakage reaches backwards, since it invalidates records already written.

### Planned host requirements (v0.1.0)
- **Host**: Linux `x86_64` with `/dev/kvm`, cgroup v2, and kernel BTF (`/sys/kernel/btf/vmlinux`);
  a kernel providing `cgroup.kill`, else >= 5.15 where there is no cgroup v2 hierarchy to probe.
  `bsx doctor` verifies all of it and prints the fix for whatever is missing.
- **Firecracker**: v1.15 through v1.16 supported (upstream's current support window); v1.16.1 is
  the pinned, tested, hash-verified release. One measured difference on v1.15: the `clock_realtime`
  snapshot-load flag is v1.16+, and the engine withholds it from an older VMM rather than failing
  the restore, so a clone restored on v1.15 wakes with its clock still at snapshot time. That is
  the only red test there (`restored_clones_do_not_share_entropy_or_freeze_the_clock`, failing by
  exactly the snapshot's age); the rest of the privileged gate passed against v1.15.1 on the
  development host, 2026-08-04. Warm-pool workflows that need wall time to survive a restore need
  v1.16. The operator installs the binary ([docs/cli-install.md](docs/cli-install.md)), so an
  upstream security patch never waits on a release of this engine.

---

## v0.0.4 (2026-08-18, checkpoint)

The boot-budget checkpoint: cold boot is measured on a host that can boot, and the first benchmark
table returns from withdrawal. Still not a supported release; pin a git rev.

### Changed
- **`quiet` in the guest's boot arguments**, which is the whole of the boot win. Measured on
  exec-01 (bare metal, Xeon E-2176G, Linux 7.0.0-28-generic, Firecracker v1.16.1, release build,
  load average 0.02, n=100 per arm, 2026-08-16), against the same binary and guest image with the
  one token removed:

  | p50, read-only shared base | without `quiet` | with `quiet` |
  |---|---|---|
  | wall (`Vm::boot`) | 304 ms | **100 ms** |
  | guest boot | 294 ms | **91 ms** |
  | host staging | 9 ms | **9 ms** |

  Host staging does not move on either rootfs path, which is what says the win is guest-side rather
  than asserting it. Through the jailed CLI the same posture measures 88 ms p50 (n=20), so the
  jailer costs nothing measurable on this clock. Full tables, including the read-write copy path and
  the counterfactual arm, are in [docs/benchmarks.md](docs/benchmarks.md).
- **The CLI and the daemon boot the shared read-only base** (`apply_posture`), so a one-shot
  `bsx run` no longer duplicates the 132 MiB base per boot. That copy costs 49 ms of a 149 ms p50
  cold boot on the same host. `BootConfig::default()` stays on the copy path, which boots any
  rootfs; the overlay path needs the agent image's overlay init.
- **`bench-boot` reports three series per rootfs path** (wall, guest boot, host staging), the
  staging one subtracted per boot rather than per percentile, so a staging percentile is a real
  boot's staging.
- **Guest package closure drift is reported, not fatal, in the privileged gate.** That build
  resolves fresh from the Alpine branch either way, so failing on drift forfeited a whole run's test
  results without producing a reviewed image. `.github/workflows/rootfs-packages.yml` remains the
  enforcer, weekly, where re-pinning is a person reading the diff.
- **The guest package closure is re-pinned**: `python3` 3.14.5-r0 to 3.14.7-r1 (with `pyc`,
  `python3-pyc`, `python3-pycache-pyc0` alongside it). Boot did not move across that change, which
  the counterfactual arm above establishes on the same host.

### Documentation
- **The cold-boot tables are published** with their host and date, after being withdrawn since
  2026-07-29. Every other table stays withdrawn: two reporting defects are open against the suite
  (`bench-all` does not record the scratch filesystem three of its sections argue from, and
  `bench-meter` does not separate its conditions), and neither reaches `bench-boot`. The boot run
  recorded its scratch filesystem by hand.

### Fixed
- A stale kernel count in `README.md` (two, now three: the development laptop, the CI runner, and
  exec-01) and a stale example range in `doctor.rs`'s `supported_range` doc comment.

---

## v0.0.3 (2026-08-07, checkpoint)

The rename checkpoint: the crates, the binary, and the configuration surface are `bsx`. Still not a
supported release; pin a git rev.

### Changed
- **BREAKING: every package name and the binary.** The `ekvm-*` crates are `bsx-*` and the `ekvm`
  binary is `bsx`. Nothing moved inside the pinned surface (`bsx-engine`, `bsx-channel`,
  `bsx-protocol`, `bsx-record`): no type, function, or wire shape changed along with the names. The
  one type that was renamed, `EkvmToml` to `BsxToml`, is in the CLI's own internals.
- **BREAKING: the configuration surface.** `EKVM_*` environment variables are `BSX_*`, and the file
  the CLI walks up from the cwd for is `.bsx.toml`. The secret the tag build reads for release
  signing is `BSX_RELEASE_SIGNING_KEY`.
- **BREAKING: the guest data-disk labels.** `INPUT_LABEL` and `OUTPUT_LABEL` are `bsx-input` and
  `bsx-output`, single-sourced in `bsx-channel` so the driver that stamps a label and the guest that
  resolves it cannot disagree. `injects_a_large_file_via_block_device` and
  `collects_outputs_via_block_device` boot a guest that mounts both by label and round-trip a file
  larger than the channel's frame cap.
- **The repository is `kendricklawton/behavioral-sandbox`**, and release assets are named
  `bsx-<version>-x86_64-linux.tar.gz`. The `v0.0.1` and `v0.0.2` assets carry the previous name.
- **BREAKING: the release signing key is rotated.** `release-key.pem`, and the copy pinned in
  `install.sh` that `install_sh_pinned_key_matches_release_key_pem` holds byte-identical to it,
  carry a new public key. A signature made by the previous key does not verify against this repo's
  pinned copy, and the `v0.0.1` and `v0.0.2` assets were signed by that previous key.
- **The signed record format is unchanged**: `AUDIT_SCHEMA_VERSION` 1, envelope `schema` 2. A
  `sandbox_id` carries a `bsx-` prefix, which is a value rather than a schema field, so
  `crates/record/tests/durability.rs` still holds today's canonicalization to an envelope signed
  2026-08-03 and that envelope still verifies.

---

## v0.0.2 (2026-08-02, checkpoint)

A second checkpoint, cut because `v0.0.1` shipped two defects worth correcting before anyone
installs from a link. Still not a supported release; pin a git rev.

### Fixed
- **The reported version.** `v0.0.1` named its tarball from the pushed tag while the workspace was
  still `0.0.0`, so a binary installed from that tag's tarball answered `--version` with `0.0.0`.
- **A truncated `curl … | sh`.** `sh` reading from a pipe executes as it reads, so a connection
  dropping mid-transfer ran a prefix of `install.sh`: the binary landed, the kernel, rootfs and
  probes object did not, and it exited 0. Every filesystem-touching statement now runs from a
  `main()` invoked on the last line, so a truncated stream is a no-op
  (`installer_body_is_deferred_to_a_main_guard`).

### Changed
- Documentation only, otherwise: no behavioral change to the engine or the CLI. Every changed line
  under `crates/**/*.rs` between the two tags is a comment.

---

## v0.0.1 (2026-08-02, checkpoint)

A disposable pre-release checkpoint, not a supported release: it exists to have exercised the
release path end to end (the tag-triggered build, ed25519 signing of `SHA256SUMS`,
draft-then-publish, and an `install.sh` install from the published assets). Nothing about its API
or behavior is pinned; pin a git rev.

---

## The Finish Line & Pre-Release Policy

`v0.1.0` is cut once every planned phase gate passes (`cargo xtask ci` and `cargo xtask ci-privileged`).

### Release Signing (prerequisite for every tagged release)

`SHA256SUMS` ships with a detached Ed25519 signature made by the release key. Before the first
tag (and after any rotation), the operator ceremony is:

1. `cargo xtask release-key --path <file outside the repo>` mints (or shows) the key and prints
   its SPKI PEM.
2. Pin the public key: commit the PEM as `release-key.pem` (repo root) **and** into the
   `install.sh` heredoc (a dist test asserts the two are byte-identical).
3. `gh secret set BSX_RELEASE_SIGNING_KEY < <file>` wires the private key into release CI.

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

**The previous minor's window is computed, not dated.** Each release line supports a Firecracker
range, floor through pin (v0.1.0 supports v1.15 through v1.16), and stays supported while any series
in that range is still under upstream support. Once the last ages out, every VMM the line can drive
is unpatched, which is the reasoning behind `bsx doctor`'s host kernel floor as well. The weekly
`firecracker-pin` workflow watches upstream's support table, so the end of a window is observed
rather than remembered.

---

## Rust Version Support

- **Policy**: Supported Rust is current stable, pinned exactly in `rust-toolchain.toml` and mirrored in the workspace package `rust-version`.
- **The eBPF crate (`bsx-probes`, `crates/probes`)**: Nightly by construction, targeting `bpfel-unknown-none` via `bpf-linker`.
- **Bumping Rust**: Update `rust-toolchain.toml` and `Cargo.toml` together, verify `cargo xtask ci` passes, and document in release notes.
