# Contributing to agent

Thanks for your interest. A heads-up on where things stand: this project is in **early, pre-1.0
development** and is **not open to outside code contributions yet**. Only project collaborators commit
code, and pull requests from non-collaborators aren't being merged while the core is still churning,
the `Sandbox`/`vmm` API, the `agent serve` wire protocol, the audit-log/record format, and even the
crate and project names all still change without notice, and will until the first stable release
(planned, but not yet scheduled). You're very welcome to read the code, run it, and open issues; direct
code contribution opens up once the surface stabilizes. This project follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

The chapters below are the working manual for **collaborators** (and for reading along):
[contributing chapters of the documentation](docs/contributing.md):

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
