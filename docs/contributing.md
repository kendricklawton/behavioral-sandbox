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
