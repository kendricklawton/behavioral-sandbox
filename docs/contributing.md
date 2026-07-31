# Contributing

This section of the book is the developer manual: what the crates are for, how to build them, the
gates a change passes, and the conventions it is held to.

The repository is **open to outside pull requests**. Bug fixes, tests, and documentation can go
straight to one; anything larger starts with an issue, because the pre-1.0 surface still moves.
[`CONTRIBUTING.md`](https://github.com/packsixfour/ekvm/blob/main/CONTRIBUTING.md) has the terms,
including the `Signed-off-by` requirement and why the privileged gate cannot run on a fork's pull
request. The pages below are the developer instructions themselves.

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

Read them in the [design specification](./design.md#design-rules), which carries the reasoning
behind each. They are single-sourced in
[`AGENTS.md`](https://github.com/packsixfour/ekvm/blob/main/AGENTS.md), the standing instructions
coding agents in this repo are held to, and deliberately not restated here: a third copy is a third
thing to drift.
