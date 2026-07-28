# Contributing Guide

Contributions are welcome! This chapter covers system invariants, developer setup, CI gates, testing, and commit conventions.

The canonical operating manual for humans and coding agents alike is [`AGENTS.md`](https://github.com/packsixfour/ekvm/blob/main/AGENTS.md) at the repo root.

---

## 1. System Invariants (Never trade these away)

- **Isolation is hardware.** Untrusted code runs in a KVM microVM; the trust boundary is the CPU, not guest software.
- **Observe & enforce from the host.** Visibility and policy live in host-side eBPF (`aya`) that the guest cannot reach.
- **Engine, not platform.** A self-hostable runtime + a clean driver API. Auth, billing, scheduling, and dashboards are out of scope.
- **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal capabilities.
- **No-panic on the host path.** A hostile or crashing guest is a typed error (`VmmError`), never a host panic, hang, or leak.
- **Measured, not marketed.** Boot, snapshot-restore, and eBPF overhead are benchmarked with percentiles.

---

## 2. Prerequisites & Quickstart

- **Rust (Stable)**: Minimum supported Rust version tracks current stable (`rust-toolchain.toml`).
- **musl Target**: Required for static in-guest agent builds:
  ```console
  rustup target add x86_64-unknown-linux-musl
  ```
- **eBPF Toolchain** (optional, for eBPF probes). Both are pinned: unlike `aya`, which is a Cargo
  dependency held by `Cargo.lock`, these are installed out of band, so an unpinned install takes
  whatever shipped today and a compiler change can break the build with no commit from anyone.
  `bpf-linker` links against the pinned nightly's LLVM, so the two move together.
  ```console
  cargo install cargo-deny
  cargo install bpf-linker --locked --version 0.10.3
  rustup toolchain install nightly-2026-07-20 --profile minimal --component rust-src
  ```
  The nightly is pinned in `crates/probes/rust-toolchain.toml` and `bpf-linker` in `xtask`; a gate
  test compares every copy of both against those sources.

### Developer Setup Commands

```console
git clone https://github.com/packsixfour/ekvm && cd ekvm
cargo xtask setup            # Verify KVM, BTF, Firecracker, bpf-linker, caps
cargo xtask fetch-artifacts  # Download pinned guest kernel & boot rootfs
cargo xtask build-rootfs     # Build reproducible guest rootfs (Alpine + python3 + static agent)
cargo xtask build-probes     # Build eBPF object (target: bpfel-unknown-none)
```

---

## 3. Developer Workflows & CI Gates

- **Fast Inner Loop**: `cargo xtask check` (Format + prose-drift + Clippy `-D warnings`; skips tests for instant feedback ~4s).
- **Host-Safe Gate**: `cargo xtask ci` (Runs everywhere without root or KVM: clippy, formatting, prose links, unit tests, cargo deny, eBPF build).
- **Privileged Gate**: `sudo -E ./ci-privileged.sh` (Runs VM-boot, exec, TAP networking, and eBPF probe attachment integration tests under KVM).

---

## 4. Testing Strategy & Benchmarks

The testing strategy spans 4 primary layers:
1. **Unit Tests**: Driver config assembly, protocol framing, error mappings (`cargo xtask ci`).
2. **eBPF Build Verification**: Probes compile with `.BTF` debug sections enabled.
3. **Privileged Integration**: End-to-end VM boot, exec, TAP network filtering, and audit probe checks (`sudo -E ./ci-privileged.sh`).
4. **Benchmarks**: Measured latency, density, and overhead percentiles:
   ```console
   cargo xtask bench-boot     # Latency: cold boot vs per-VM copy
   cargo xtask bench-warm     # Latency: snapshot restore vs pre-warmed pool
   cargo xtask bench-density  # Memory-sharing: RSS vs PSS under load
   cargo xtask bench-trace    # Syscall trace overhead
   cargo xtask bench-all      # Run complete benchmark suite
   ```

---

## 5. Fuzzing

Fuzz targets protect boundaries where untrusted or external bytes enter the host process:
- `channel` decoder framing
- Wire daemon JSON protocol
- Signed audit record envelopes
- eBPF ring-buffer event deserializers

Run seeded fuzzing locally via `cargo fuzz run <target>`.

---

## 6. Commit & Public API Conventions

- **Conventional Commits**: Format commit subjects as `type(scope)?: imperative subject` (e.g. `feat: add vsock timeout handling`).
- **Public API Scope (`api`)**: Any change to `vmm` public types (`Sandbox`, `Limits`, `RunResult`, `VmmError`) or wire protocols must carry the `api` scope (`feat(api):` or `fix(api)!:`).
- **No AI Co-Author Trailers**: Keep git logs clean; do not add AI attribution trailers.

---

## 7. Firecracker Version Policy

Firecracker is the isolation boundary and it is **not a crate**: no advisory database,
`cargo deny` run, or Dependabot PR will ever mention it. Everything in this section exists
because nothing else watches it.

### Two constants, two different questions

Both live in `crates/vmm/src/spawn.rs`:

| Constant | Question it answers | Moves when |
|---|---|---|
| `MIN_SUPPORTED_FC_VERSION` | What is the oldest release we accept? | a series ages out of upstream's support table |
| `PINNED_FC_VERSION` | What do we test and hash? | we choose to move to a newer release |

The floor tracks upstream's window rather than our convenience, in both directions. It
exists to reject *unpatched* VMMs, not old ones: the same threat-model argument behind
`ekvm doctor`'s host kernel floor obliges us to accept any release upstream still patches.
A floor above their oldest supported series refuses a patched release for no safety gain;
a floor below it silently blesses an unpatched one.

### A new API field may not raise the floor

A request field newer than the floor is sent conditionally, gated on the probed binary's
version, with a `_SINCE` constant recording where it arrived (see `clock_realtime` in
`crates/vmm/src/spawn.rs`). Sending it unconditionally silently drags the real floor up to
that field's release: that exact mistake broke restore on supported releases once. Each
gate carries a test asserting its `_SINCE` sits above the floor, so when the floor later
rises past it, the test fails, names the gate dead code, and forces its deletion. Compat
code for dead series is deleted from `main`; release branches are where it survives.

### What runs on its own

`.github/workflows/firecracker-pin.yml` runs weekly and asks both questions: are we behind
the latest release (a `PINNED_FC_VERSION` prompt), and is our floor still the oldest
series in upstream's support table (a `MIN_SUPPORTED_FC_VERSION` prompt, either
direction). It parses upstream's table directly rather than re-deriving their policy, and
its parsers fail loudly if the format moves instead of silently matching nothing.

### Raising the floor (when the weekly job goes red)

1. Set `MIN_SUPPORTED_FC_VERSION` to the oldest series still marked Supported upstream.
2. Delete dead gates: the `_SINCE` assertions fail on exactly the conditionals that are
   now dead, so make those fields unconditional.
3. Drop `doctor.rs` sha256 entries for series that left support.
4. Update the host-requirements prose (`RELEASES.md`, `docs/cli-install.md`).
5. `cargo xtask ci`, then the privileged gate against the pinned binary.
6. Commit as `feat(api)!` and tag the next minor: a floor raise is always a breaking
   change. The outgoing minor's release branch keeps the old floor and receives security
   backports under the support policy in `RELEASES.md`.

### Raising the pin (by choice)

Upstream's cadence is roughly one minor per quarter, so a quarter is the comfortable
rhythm and the support window is the hard deadline. Read the release notes for API and
snapshot-format changes, and re-read their swagger API definition rather than only the
changelog (fields get deprecated before they are removed, and the changelog does not
always say which). Hash the new binary, add its sha256 alongside the ones still in
support, bump `PINNED_FC_VERSION`, and run the privileged gate against the new binary.
