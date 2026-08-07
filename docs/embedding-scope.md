# Where the engine ends

The line this project refuses to cross, and the surface it intends to pin. A runtime that quietly grows platform features stops being embeddable.

## Where the engine ends (the engine/PaaS line)

**This is an engine, not a PaaS.** The engine is the boring, embeddable core:
a runtime plus a clean driver API you self-host. The moment it grows opinions about *whose* code
runs and *who pays*, it stops being embeddable in anything with its own opinions. So, explicit
non-goals, these belong to whatever hosts the engine, and PRs adding them are wrong by design:

- **No tenancy or auth.** The engine trusts its caller completely. Multi-user identity, quotas,
  and authorization live in the hoster's layer.
- **No billing or metering policy.** The engine *measures* (host-observed metrics, benchmarked
  percentiles). Charging for it is the hoster's.
- **No fleet scheduling.** One engine drives sandboxes on one host. Bin-packing across hosts,
  queues, and autoscaling are the hoster's: the engine runs sandboxes on its host, it does not
  schedule a cluster.
- **No image or registry management.** The engine boots the rootfs it is handed (a path, via
  `BootConfig` or `BSX_ROOTFS`). It does not build, fetch, cache, or version images, and it speaks
  no registry protocol. `cargo xtask build-rootfs` produces one, but that is dev tooling in this
  repo, not a runtime feature.
- **No platform API.** The programmatic surface is the Rust library, the CLI, and
  the [`bsx` daemon](./daemon.md), a *local* driver daemon over a unix socket, a thin host of
  the same library's public API, with no auth and no tenancy (access control is the socket
  directory's permissions). A daemon that grows multi-tenant identity or a public HTTP surface is
  a *hoster*, not this repo.

The line is a security boundary too: everything the engine ships is inert without host
privileges the *hoster* grants, it self-limits (deny-by-default network, dropped-uid jail,
own-euid sweep), and turning its tools into a multi-tenant service safely is the hoster's job.

What the engine *does* owe a long-lived host, and ships: typed errors instead of panics on every
hostile-guest path, GC for crashed embedders' residue (`sweep_orphans`), dependency guards that
fail legibly (`xtask setup`'s degradation matrix, the pinned Firecracker probe), measured budgets
(fd, boot, restore, memory-sharing), and a wire protocol whose version handshake makes skew a typed error
instead of a silent misbehavior.

Downstream of the public API there are two consumers, and they couple to this repo in different ways.

An **embedder** is a Rust program that links `bsx-engine` and drives sandboxes in its own process. It pins
this crate's git rev, so it is coupled to the library surface the [Semver
section](#semver--api-stability) below describes.

A **non-Rust client** is not, and cannot be: a Python or Node package has no way to pin a Rust
crate. It drives the [daemon's wire protocol](./daemon-protocol.md) over a unix socket and never
links anything here, which is what `bsx-client` exists to demonstrate. Its whole coupling is the
`schema` handshake.

Who such a client serves is worth naming, because it bounds how much of one is worth building:
someone who installed the engine on their own machine and wants to drive it from that language on
that same machine. A hosted product's customers are not that person. They call whatever API the
hoster exposes, and the engine's socket is deliberately local, so a client for it never reaches
them.

**Nothing here is distributed through crates.io** (`publish = false` across the workspace), a
decision, not a gap. A crates.io version is immutable and available forever, but this engine's
support window is computed from Firecracker's and deliberately ends: an old published version
would sit on the registry looking usable long after every VMM it can drive stopped receiving
patches. Distribution stays the signed release package for operators and the git-rev pin for
embedders, both of which the support policy in `RELEASES.md` can actually govern.

Holding a name and shipping through it are separate things, and this project does the first and not
the second. The names reserved on crates.io under this project are the binary (`bsx`) and the
packages carrying a pinned surface or a client: `bsx-engine`, `bsx-channel`, `bsx-protocol`,
`bsx-record`, and `bsx-client`. Each is a **reserved placeholder**: no dependencies, no code, and a
description saying exactly that. They exist because the registry is a flat namespace and the
alternative to holding a name is someone else holding it. Finding one is not evidence that this
paragraph is stale, and its version number carries no signal: a placeholder is identified by being
empty, not by sitting at some particular version. A real release would arrive with code in it, and
it would arrive with a decision recorded here first.

---

## Semver & API stability

> **Not yet in force.** The tags so far, `v0.0.1` through `v0.0.3`, are checkpoints that exercised the
> release path, not supported releases, so nothing below governs anything today. This section describes the
> boundary the project intends to pin at `v0.1.0`; until that tag, every item on it can change
> without notice. Pin a git rev.

The `bsx-engine` public library API and the two wire protocols are the surface the project intends to pin
as its stability boundary. This list, `AGENTS.md`'s `api`-scope rule, and
[RELEASES.md](https://github.com/kendricklawton/behavioral-sandbox/blob/main/RELEASES.md) name the same surface, since a commit scope that does not match the
policy it audits is worse than no scope at all:
- **`Sandbox`**, **`Limits`**, **`RunResult`**
- **`VmmError`**, including variants and the `kind()` -> `ErrorKind` bucket mapping
- The **`bsx-channel`** host↔guest wire framing protocol
- The daemon's **`bsx-protocol`** wire types, the newline-JSON contract at `schema: 1`
  ([Wire protocol](./daemon-protocol.md)), which a non-Rust client couples to instead of the library
- The **`bsx-record`** signed-envelope surface (`verify`, `verify_chain`, `record_hash`, and the
  record's schema versions): the one contract whose breakage reaches *backwards*, invalidating
  records that already sit on disk, so it pins with the wire protocols rather than the library

The list above names the headline types; the enforced boundary is wider and mechanical: **every
public item of the four crates `cargo xtask semver-check` names** (`bsx-engine`, `bsx-channel`,
`bsx-protocol`, `bsx-record`), because that is what the tool actually checks. For `bsx-engine`
that includes the raw `Vm`/`RunningVm` layer under `Sandbox` ([Embedding recipes](./embedding-recipes.md)), `Pool`,
`sweep_orphans`, the `doctor` preflight module, and the jail/vsock constants: public deliberately
(the CLI and the daemon are built on those seams, and an embedder building a pool or a preflight
needs the same ones), and pinned *because* they are public, so there is no public-but-unpinned
tier to guess about. The `bsx` CLI package is not on the list: its library target is empty
without the off-by-default `fuzzing` feature, so a pin of it reaches the binary and nothing else.

### Versioning rules
- **MAJOR**: Breaking changes to the pinned surface (removed/renamed `VmmError` variants, changed `kind()` bucket mappings, breaking channel wire protocol changes, or raising `Limits` defaults).
- **MINOR**: Additive changes (new API methods, new `#[non_exhaustive]` error variants, new optional fields).
- **Commit Tags**: Changes touching this surface are marked with `feat(api):` or `fix(api)!:` in commit subjects for clear auditability.
