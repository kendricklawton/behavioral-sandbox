# Changelog

Notable changes to `agent` — the self-hostable Firecracker + aya code-execution sandbox. Format
follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [Unreleased]

### Changed
- Re-scoped the project from the retired `agent scan` wasm secrets scanner to a self-hostable,
  isolated **code-execution sandbox**: Firecracker microVMs for hardware isolation, aya/eBPF for
  host-side observability and enforcement. The scanner lives on in git history (and the
  `archive/wasm-scanner` ref).
- Reset the workspace to the sandbox skeleton: `crates/{vmm,probes,probes-loader,cli}` + `xtask`.
