# Contributing to ekvm

Thanks for your interest. A heads-up on where things stand: this project is in **early, pre-1.0
development** and is **not open to outside code contributions yet**. Only project collaborators commit
code, and pull requests from non-collaborators aren't being merged while the core is still churning,
the `Sandbox`/`vmm` API, the `ekvm serve` wire protocol, the audit-log/record format, and even the
crate and project names all still change without notice, and will until the first stable release
(planned, but not yet scheduled). You're very welcome to read the code, run it, and open issues; direct
code contribution opens up once the surface stabilizes. This project follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

The developer instructions are consolidated in [docs/contributing.md](docs/contributing.md):
invariants, toolchain requirements, CI gates (`cargo xtask ci` / `cargo xtask ci-privileged`), testing, benchmarks, and fuzzing.

Host prerequisites and first-run instructions are in
[Installation](docs/cli-install.md). The operating manual, the rules read every session, is
[`AGENTS.md`](AGENTS.md).

By contributing you agree your contributions are licensed under **Apache-2.0**, the project's
license (see [`LICENSE`](LICENSE)).
