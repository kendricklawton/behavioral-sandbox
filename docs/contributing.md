# Contributing

The canonical operating manual for humans and coding agents alike is
[`AGENTS.md`](https://github.com/packsixfour/ekvm/blob/main/AGENTS.md) at the repo root. This section
of the book expands on it.

The repository **is not open to outside pull requests yet**; only project collaborators commit code.
The pages below are written for them, and for anyone reading to understand how the project is
maintained.

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

These are the rules a change is measured against. They state intent and the mechanism serving it, so a
change that breaks one is a design error rather than a trade-off. The full list with rationale is in
[`AGENTS.md`](https://github.com/packsixfour/ekvm/blob/main/AGENTS.md) and restated for readers in the
[design specification](./design.md); the summary:

- **Isolation is hardware.** Untrusted code runs in a KVM microVM; the boundary is the CPU, not guest software.
- **Observe and enforce from the host.** Visibility and policy belong in host-side eBPF (`aya`) attached to host-kernel hooks.
- **Deny by default.** A sandbox with no explicit policy is configured with no route out and minimal capabilities.
- **Engine, not platform.** A self-hostable runtime and a driver API. Auth, billing, scheduling, and dashboards are out of scope.
- **No panic, hang, or leak on the host path.** A hostile or crashing guest should surface as a typed `VmmError`. This is what the code is written against and what the confinement suite exercises; it is an aim, not a proven property.
- **Measure rather than assert.** Boot, snapshot-restore, and eBPF overhead are reported as percentiles with the host and date. A number that cannot be defended is withdrawn.
