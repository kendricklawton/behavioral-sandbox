# Contributing to BSX

Thanks for your interest. **Outside contributions are welcome.** A few things are worth knowing
before you spend time on one.

**Open an issue first for anything non-trivial.** Bug fixes, tests, and documentation can go
straight to a pull request. For a new capability, a change to a public API, or a refactor that moves
code between crates, open an issue and settle the shape first. That is not gatekeeping: the project
is pre-1.0 and the surface still moves (the `Sandbox`/`bsx-engine` API, the `bsx serve` wire protocol, the
audit-record format, and the crate names all change without notice until the first supported release, `v0.1.0`),
and an issue is how you avoid building against a shape that is about to change under you.

**Six design rules govern every change**, and the first question in review is which rule a change
touches. They are in [Architecture and design](docs/architecture.md), with the reasoning behind
each. A change that breaks one is declined as a design error rather than weighed as a trade-off,
however good the code is, so they are worth reading before starting anything large.

**Sign your commits off.** `git commit -s` adds a `Signed-off-by:` line: your assertion, under the
[Developer Certificate of Origin](https://developercertificate.org/), that you wrote the patch or
otherwise have the right to submit it under the project's license. Contributions are licensed under
**Apache-2.0**, the project's license (see [`LICENSE`](LICENSE)).

**What a pull request needs.** `cargo xtask ci` green locally (fmt, the prose-drift lint, clippy
`-D warnings`, build, tests, docs, `deny`, and the eBPF object build), and
[Conventional Commits](https://www.conventionalcommits.org/) subjects. New behavior needs a test,
and the repo's standard for a test is that it was watched failing before it passed: break the
behavior under test, see the assertion fire, then revert.

**The privileged gate is the one thing you probably cannot run.** `cargo xtask ci-privileged` boots
real microVMs and loads real eBPF programs, so it needs `/dev/kvm` and real root, and by design it
does not run on pull requests from forks (a fork gets no secrets and no privileged runner). A
maintainer runs it before merge. If you do have a machine that can run it, say so in the pull
request and save a round trip.

**Expect review to take a while.** One maintainer, no service commitment, and a security-sensitive
core that gets read slowly on purpose.

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Suspected vulnerabilities go to the
private advisory form described in [`SECURITY.md`](SECURITY.md), never to a public issue or pull
request.

The developer instructions are consolidated in [`AGENTS.md`](AGENTS.md): the design rules, the repo
layout, building from source with the pinned toolchains, the two gates (`cargo xtask ci` /
`cargo xtask ci-privileged`), and the commit conventions.

Host prerequisites and first-run instructions are in [Installation](docs/cli-install.md).

If you drive a coding agent in this repo, point it at [`AGENTS.md`](AGENTS.md): the same ground
rules, written as standing instructions for a machine. Until the book regrows a Contributing
chapter, it doubles as the consolidated developer reference for a person too, which is why the
paragraph above points there.
