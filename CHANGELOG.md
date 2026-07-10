# Changelog

Notable changes to `agent` — the self-hostable Firecracker + aya code-execution sandbox. Format
follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Boot a real Firecracker microVM from Rust: `agent run --demo-boot` boots a guest under KVM,
  reads its serial console until userspace, reports boot-to-userspace latency, and shuts down
  clean (~1.2 s cold boot on the dev box). The driver talks to Firecracker's HTTP API over a
  unix socket with a small hand-rolled client — no async runtime, `unsafe`-free.
- `cargo xtask fetch-artifacts` downloads and sha256-verifies the pinned guest kernel + rootfs
  into `artifacts/` (never committed); `cargo xtask setup` now also reports their presence, and
  `ci-privileged` guards on them.

### Changed
- Re-scoped the project from the retired `agent scan` wasm secrets scanner to a self-hostable,
  isolated **code-execution sandbox**: Firecracker microVMs for hardware isolation, aya/eBPF for
  host-side observability and enforcement. The scanner lives on in git history (and the
  `archive/wasm-scanner` ref).
- Reset the workspace to the sandbox skeleton: `crates/{vmm,probes,probes-loader,cli}` + `xtask`.
