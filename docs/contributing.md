# Contributing

The canonical operating manual for humans and coding agents alike is
[`AGENTS.md`](https://github.com/packsixfour/ekvm/blob/main/AGENTS.md) at the repo root. This section
of the book expands on it.

The repository **is not open to outside pull requests yet**; only project collaborators commit code.
The pages below are written for them, and for anyone reading to understand how the project is
maintained.

- **[Architecture](./contributing-architecture.md)**, what the crates are for, the types worth knowing
  before reading code, and the order things happen in during a run. Start here.
- **[Building](./contributing-building.md)**, prerequisites, the pinned toolchains, and the commands
  that produce the guest artifacts and the eBPF object.
- **[Coding guidelines](./contributing-coding-guidelines.md)**, rustfmt, the denied Clippy lints and
  the design rule behind them, MSRV pinning, dependencies, crate organization, and the `unsafe`
  policy.
- **[CI gates](./contributing-ci.md)**, the fast inner loop, the host-safe gate, and the privileged
  gate that needs `/dev/kvm` and real root.
- **[Testing](./contributing-testing.md)**, the four layers, the benchmarks, and coverage.
- **[Fuzzing](./contributing-fuzzing.md)**, which boundaries have targets and how the two tiers run.
- **[Development process](./contributing-development-process.md)**, commit conventions, the `api`
  scope, and who performs git operations.
- **[Firecracker version policy](./contributing-firecracker-policy.md)**, the floor and the pin, why
  they answer different questions, and the procedure when either moves.

## Design rules (never trade these away)

Every change is measured against six design rules. They state intent and the mechanism serving it, so
a change that breaks one is a design error rather than a trade-off, and the first question in review
is which rule a change touches.

They are single-sourced in [`AGENTS.md`](https://github.com/packsixfour/ekvm/blob/main/AGENTS.md) and
restated for readers in the [design specification](./design.md#design-rules). Deliberately not
restated here: a third copy is a third thing to drift.
