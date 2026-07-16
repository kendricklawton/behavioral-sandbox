# Releases

**No releases yet.** The first tagged release will be `v0.1.0` — an engine that boots a microVM,
runs code, enforces and records what it did, self-hostable and documented (the finish line defined
in [`ROADMAP.md`](ROADMAP.md), Phase 18).

Until then, the record of what changed and why is deliberately not a changelog:

- [`ROADMAP.md`](ROADMAP.md) — the staged plan; its checkboxes are the live state.
- [docs/contributing-architecture.md](docs/contributing-architecture.md) — dated, numbered decision entries for every
  hard-to-reverse choice.
- The git log — one imperative subject per logical change; changes to the pinned public API carry
  a leading `api:` marker so downstream pin bumps are auditable from the log alone.

Release notes start accumulating in this file with `v0.1.0`.
