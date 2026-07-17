# Releases

**No releases yet.** The first tagged release will be `v0.1.0`.

## The finish line: `v0.1.0`

`v0.1.0` is the first real release: an engine that **boots a microVM, runs code, enforces and
records what it did, self-hostable and documented**. It is cut only once every planned phase is
green, so the tag means the whole story works end to end, not a subset.

- **The vNext tracks do not gate `v0.1.0`.** The polyglot SDKs (extending the engine outward, to
  more callers) and the Wasmtime sibling (extending it sideways, to a second isolation boundary)
  land *after* the tag. Both presuppose the frozen wire API; neither pulls tenancy/billing/
  scheduling into scope, and the Wasmtime sibling never dilutes the core properties (it ships as a
  separate artifact with a weaker, clearly-labelled guarantee).
- **Everything until then is a pre-release `v0.0.x`.** The foundation baseline (the engine boots
  and tears down microVMs) is tagged internally as `v0.0.1`; later milestones bump the `0.0.x`
  patch as they land. These are checkpoints, not releases: no stability promise.
- **Tags are a human git step.** The coding agent's job ends at the working tree; the user cuts
  every tag (see [`.rules`](https://github.com/kendricklawton/agent/blob/main/.rules)).

## Why there's no changelog yet

**No `CHANGELOG.md` until `v0.1.0`.** In the pre-release line the record of what changed and why is
deliberately not a curated changelog, which would only churn every `v0.0.x`. Instead:

- [docs/contributing-architecture.md](docs/contributing-architecture.md) — dated, numbered decision
  entries for every hard-to-reverse choice, so the reasoning outlives the diff.
- The git log — one imperative subject per logical change; changes to the pinned public API carry a
  leading `api:` marker so downstream pin bumps are auditable from the log alone.
- [`ROADMAP.md`](ROADMAP.md), while it exists — the staged plan whose checkboxes track the remaining
  work toward the tag.

Curated release notes start accumulating in this file with `v0.1.0`.
