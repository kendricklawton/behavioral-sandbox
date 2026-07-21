# 035. Distribution: a checksummed tarball, an installer script, and a container image; nothing that freezes the working name *(2026-07-21)*

**Context.** The engine is self-hostable from source (decision 033), but "others can run it" also
means a packaged path: download something, verify it, run it. Two forces shape that path. First,
the project still carries a working name, and every distribution surface a stranger consumes
(package-manager entries, published crates, promoted install one-liners) socially freezes that
name; the rename must land before anything freezes it (the standing pre-`v0.1.0` gate). Second,
what ships must carry the same integrity discipline the build inputs already have: the sha256 is
the contract for every pinned upstream (decisions 001/007), and a shipped package that is *less*
verifiable than its own inputs would be backwards.

**Decision.** Distribution is three artifacts assembled by one command, `cargo xtask dist`, and
nothing that freezes the name:

- **A release tarball + `SHA256SUMS`.** `dist` builds the release binary and the three runtime
  artifacts (guest kernel, agent rootfs, eBPF object, built at package time, never carried in the
  source tree), stages them as `bin/` + `share/agent/`, writes a per-file `MANIFEST.sha256` inside
  the package, and tars deterministically (sorted names, zero owners, `SOURCE_DATE_EPOCH`-pinned
  mtimes when set). The eBPF object is **required**: a package without the audit half is not the
  product, so `dist` hard-fails where the everyday gate would soft-skip. x86_64 only, matching the
  supported platform (decision 032).
- **`install.sh`**, the `curl | sh` face, also packed into the tarball so a hand-downloaded package
  installs itself. It verifies at both layers before touching the system: the tarball against
  `SHA256SUMS`, then every extracted file against `MANIFEST.sha256`; nothing installs unverified.
  Layout: the binary into `~/.local/bin` (the `self-host` precedent), artifacts into
  `$XDG_DATA_HOME/agent` (default `~/.local/share/agent`), and a starter `~/.agent.toml`
  (kernel/rootfs paths) written **only if none exists**, the nearest-up-from-cwd discovery
  (decision 027) makes it apply anywhere under `$HOME`. Firecracker stays the host's to install
  (decision 001: the engine drives it, it doesn't bundle it), except:
- **A container image** (`Containerfile`), the one place bundling the pinned Firecracker v1.9 is
  right, because an image *is* a closed filesystem: a runtime-only image assembled `FROM` the dist
  stage, Firecracker fetched at build with a pinned sha256 (the same contract as every upstream
  input). The KVM boundary cannot come from the image: it runs with the host's `/dev/kvm`
  (`--device /dev/kvm`), and the jailed default / eBPF caps remain host-privilege calls the image
  documents rather than makes. The runtime base tracks the release builder's glibc.
- **Releases stay human.** The release workflow (tag-triggered; tags are the user's act,
  RELEASES.md) assembles `dist` and attaches it to a **draft** release, so publishing is a second
  human step, the same discipline as commits and tags. Pre-rename releases are disposable `v0.0.x`
  checkpoints: **no package managers (Homebrew/AUR/apt/nix), no crates.io, no promotion of the
  install one-liner** until the real name lands; each of those would freeze the working name.

**Alternatives considered.**
- **Package managers now.** Rejected: a submitted formula freezes the working name in a public
  namespace, and "agent" would collide anyway; they become worthwhile only after the rename.
- **A static musl release binary** (base-image-independent). Deferred, not rejected: glibc on a
  pinned builder plus a matching runtime base is sufficient today, and the musl build changes the
  shipped binary's runtime characteristics untested; revisit if the base coupling ever bites.
- **Bundling Firecracker in the tarball.** Rejected: on a host, the VMM is a host prerequisite the
  hoster patches on their own cadence (decision 001); the container is the exception because its
  filesystem is closed and rebuilt, not patched in place.

**Consequences.** `dist/` is gitignored, assembled per package. The installer's every knob is an
`AGENT_*` env (repo, version, tarball, prefix, data dir), so the rename sweep is a defaults change.
Verification is testable offline end to end (`AGENT_DIST_TARBALL` mode), which is also how the
exit proof runs: package, install into a fresh `$HOME`, boot a sandbox from the installed layout.
