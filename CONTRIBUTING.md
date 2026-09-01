# Contributing to BSX

Thanks for your interest. **Outside contributions are welcome.** A few things are worth knowing
before you spend time on one.

**Open an issue first for anything non-trivial.** Bug fixes, tests, and documentation can go
straight to a pull request. For a new capability, a change to a public API, or a refactor that moves
code between crates, open an issue and settle the shape first. That is not gatekeeping: the project
is pre-1.0 and the surface is actively being rebuilt on libkrun (the `bsx-channel` framing, the
supervisor that does not exist yet, and the crate names all change without notice until the first
supported release, `v0.1.0`), and an issue is how you avoid building against a shape that is about
to change under you.

**Six design rules govern every change**, and the first question in review is which rule a change
touches. They are in [Architecture and design](docs/architecture.md), with the reasoning behind
each. A change that breaks one is declined as a design error rather than weighed as a trade-off,
however good the code is, so they are worth reading before starting anything large.

**Sign your commits off.** `git commit -s` adds a `Signed-off-by:` line: your assertion, under the
[Developer Certificate of Origin](https://developercertificate.org/), that you wrote the patch or
otherwise have the right to submit it under the project's license. Contributions are licensed under
**Apache-2.0**, the project's license (see [`LICENSE`](LICENSE)).

**What a pull request needs.** `cargo xtask ci` green locally (fmt, the prose-drift lint, clippy
`-D warnings`, build, tests, docs, and `deny`), and
[Conventional Commits](https://www.conventionalcommits.org/) subjects. New behavior needs a test,
and the repo's standard for a test is that it was watched failing before it passed: break the
behavior under test, see the assertion fire, then revert.

**Nothing in the tree boots a VM right now.** The Firecracker engine was deleted in the move to
libkrun and the supervisor replacing it is not written, so `cargo xtask ci` is the whole test story
today and it needs no privilege. `cargo xtask setup` reports what your host can do. When the tests
that boot a guest come back, they will be `#[ignore]`d and each will name its own prerequisite,
because a test whose prerequisite is missing skips itself and cargo counts a skipped test as a
pass.

**Expect review to take a while.** One maintainer, no service commitment, and a security-sensitive
core that gets read slowly on purpose.

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Suspected vulnerabilities go to the
private advisory form described in [`SECURITY.md`](SECURITY.md), never to a public issue or pull
request.

The developer instructions are consolidated in [`AGENTS.md`](AGENTS.md): the design rules, the repo
layout, building from source with the pinned toolchains, the gate (`cargo xtask ci`), and the
commit conventions.

If you drive a coding agent in this repo, point it at [`AGENTS.md`](AGENTS.md): the same ground
rules, written as standing instructions for a machine. Until the book regrows a Contributing
chapter, it doubles as the consolidated developer reference for a person too, which is why the
paragraph above points there.
