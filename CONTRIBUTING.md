# Contributing to agent

Thanks for your interest, contributions are welcome. This project follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

Everything you need lives in the [contributing chapters of the documentation](docs/contributing.md):

- [Contributing](docs/contributing.md), how the work is organized (the roadmap's phases, the
  decision log), the invariants, and the commit/PR conventions.
- [Building](docs/contributing-building.md), the toolchain, `cargo xtask ci` (the host-safe gate
  every PR must pass), and `cargo xtask ci-privileged` (the KVM + eBPF integration gate).
- [Testing](docs/contributing-testing.md), the four-layer testing approach and the benchmarks.

Host prerequisites and first-run instructions are in
[Installation](docs/cli-install.md). The operating manual, the rules read every session, is
[`.rules`](.rules); the staged plan is [`ROADMAP.md`](ROADMAP.md).

By contributing you agree your contributions are licensed under **Apache-2.0**, the project's
license (see [`LICENSE`](LICENSE)).
