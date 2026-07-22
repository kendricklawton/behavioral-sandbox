# 036. AGENTS.md is the canonical operating manual, the dotfile is retired *(2026-07-21)*

**Context.** The engineering rules, the operating manual every human and coding agent reads each
session, lived in a bespoke dotfile at the repo root, with `CLAUDE.md` and `AGENTS.md` as thin
pointers that both just re-imported it (`@`-include). Two costs came with that shape. First, the
canonical file was invisible to tooling: no assistant reads a custom dotfile natively (which is why
the pointers existed at all), and a dotfile is easy for a newcomer or a fresh agent to miss.
Second, the structure was inverted: the ecosystem already converges on `AGENTS.md` as the file
agents look for, and the repo even acknowledged that (the pointer text named `AGENTS.md` as the
lingua franca), yet the *real* content sat elsewhere behind a redundant hop.

**Decision.** Promote `AGENTS.md` to the canonical file and retire the dotfile. Concretely:

```
.rules            (retired)  ->  AGENTS.md   (the content, git-renamed to preserve history)
AGENTS.md         (pointer)  ->  removed     (collapsed into the content above)
CLAUDE.md         (pointer)  ->  @AGENTS.md  (still a one-line forward, now to the canonical file)
```

`AGENTS.md` **is** the operating manual; `CLAUDE.md` stays a one-line pointer so a Claude session
resolves the same content. Every reference across the tree (README, CONTRIBUTING, the docs set, the
Copilot instructions, the config comments) repoints to `AGENTS.md`, and the prose-drift lint drops
its special-case for the old extension (the manual is now an ordinary `.md`, already scanned).

**Alternatives considered.**
- **Keep the dotfile canonical, keep the two pointers.** Rejected: it is the inverted structure
  above, one redundant file and a name no tool reads natively, for no benefit over the standard.
- **Make `AGENTS.md` canonical but keep the retired dotfile as a second pointer.** Rejected: that
  just re-adds the redundant hop in the other direction; one canonical file plus one `CLAUDE.md`
  forward is the minimum that covers both the standard and the Claude-specific lookup.
- **Fold everything into `CLAUDE.md`.** Rejected: `CLAUDE.md` is Claude-specific; the manual is for
  every agent, so the canonical name should be the ecosystem-neutral one.

**Consequences.** This is a naming and discoverability change, not a capability one: the manual's
content is unchanged, and nothing in the build or runtime depends on the filename. The only
mechanical follow-ons are the reference repoints and the lint's dropped special-case, both landed
here. The pre-rename working-name gate (decision 035) is untouched: this renames a doc file, not
the project.
