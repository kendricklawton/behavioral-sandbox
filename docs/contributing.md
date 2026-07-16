# Contributing

Contributions are welcome. This chapter is the orientation; [Building](./contributing-building.md)
covers the toolchain and the CI gates, and [Testing](./contributing-testing.md) covers the testing
approach. The operating manual — read every session by humans and coding agents alike — is
[`.rules`](https://github.com/kendricklawton/agent/blob/main/.rules) at the repo root.

## How the work is organized

Work is organized into sequentially-gated phases in
[`ROADMAP.md`](https://github.com/kendricklawton/agent/blob/main/ROADMAP.md) — the **single source
of truth for progress** (its checkboxes are the state). Work the first unchecked box in ID order,
one item per iteration; a phase isn't left until its **Exit gate** passes (a working demo). Items
tagged `(decision)` record the hard-to-reverse choice as a dated, numbered entry in
[Architecture decisions](./architecture.md), so the reasoning outlives the diff.

## The invariants (never trade these away)

- **Isolation is hardware.** Untrusted code runs in a KVM microVM; the trust boundary is the
  CPU, not guest-side software.
- **Observe & enforce from the host.** Visibility and policy live in host-side eBPF the guest
  can't reach; in-guest agents are for convenience (exec/IO), never for security.
- **Engine, not platform.** A self-hostable runtime + a driver API. Auth, billing, fleet
  scheduling, and dashboards are **out of scope** — the hoster's job.
- **Deny by default.** A sandbox with no explicit policy reaches no network and holds minimal
  capability; every allowance is explicit and recorded.
- **No-panic on the host path.** A hostile or crashing guest, a failed probe, or a broken
  channel is a typed error — never a host panic, hang, or leak.
- **Measured, not marketed.** Boot/restore/memory-sharing/overhead are benchmarked with percentiles.

## Commit & PR conventions

- One logical change per commit; **imperative** subject describing **what was done** ("Boot a
  microVM from the driver", not "added VM boot"). Don't reference roadmap phase IDs — the
  roadmap can change.
- **Public-API changes are called out in the commit subject** with a leading `api:` marker: the
  engine is embedded downstream at the `vmm` library's public API (`Sandbox`, `Limits`,
  `RunResult`, `VmmError` including its `kind()` mapping, the `channel` wire protocol), pinned by
  git rev, so a downstream pin bump must be auditable from the log alone.
- **Never add an AI co-author or attribution trailer.** Never commit built rootfs/kernel images
  or generated eBPF objects — they're built by `xtask`.
- Every PR must pass the host-safe gate (`cargo xtask ci`); privileged integration runs where
  KVM + caps exist. See [Building](./contributing-building.md).

## License

By contributing you agree your contributions are licensed under **Apache-2.0**, the project's
license (see [`LICENSE`](https://github.com/kendricklawton/agent/blob/main/LICENSE)).
