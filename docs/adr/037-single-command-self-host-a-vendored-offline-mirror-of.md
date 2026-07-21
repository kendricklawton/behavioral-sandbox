# 037. Single-command self-host + a vendored offline mirror of every pinned input *(2026-07-17)*

**Context.** "Self-hostable" is a core property, not a slogan, and two forces shape what it has to
mean here. First, standing the engine up must be one command a self-hoster can actually run, not a
sequence of build steps to assemble by hand. Second, that command must not silently depend on two
third-party CDNs (the Firecracker CI S3 bucket and the Alpine CDN) staying up: the build pulls
sha-pinned upstream inputs, but decision 007 left the resolved `.apk` package closure
fetched-not-pinned, the last input a self-hoster could not reproduce from a mirror they control. A
reproducible, offline-verifiable build closes that gap.

**Decision.** Standing the engine up is one command, `cargo xtask self-host`: it obtains the pinned
guest kernel + rootfs, builds the guest image and the eBPF probe object, installs the `agent`
binary into a prefix (`~/.local/bin` by default), and, on a KVM host, boots one sandbox
to prove it end to end (`--no-run` prints the proof command instead). It is orchestration over the
already-tested `xtask` steps, not a second code path.

The **vendoring** half closes the item decision 007 deferred: `cargo xtask vendor` snapshots every
sha-pinned upstream input, the Firecracker CI kernel + rootfs, the Alpine minirootfs, the static
`apk` tool, **and** the resolved `.apk` package closure (the piece decision 007 flagged as
"fetched-not-pinned"), into a local mirror, sha-verified, with a `vendor-manifest.txt` recording
each file's hash. Setting `AGENT_VENDOR_DIR` to that dir takes every build path offline in one move:
`fetch_one` restores the binary artifacts from the mirror instead of `curl`ing them, and the rootfs
build installs the packages from the vendored apk cache (`apk.static --cache-dir … --no-network`)
instead of the Alpine CDN. So a fresh host builds with the FC S3 bucket and the Alpine CDN both dark.

Mechanics that matter:
- **The vendor-aware seam is `fetch_one`, not the call sites.** `fetch_one` branches on
  `AGENT_VENDOR_DIR` (restore-from-mirror vs `download_one`); `build-rootfs`, `fetch-artifacts`, and
  `self-host` all route through it, so offline mode is one env var with zero call-site churn.
- **The `.apk` closure is pinned at vendor time, not in the tree.** `apk` branch repos delete old
  revisions on every bump (decision 007), so there is no stable per-package URL to hash-pin in
  source. `vendor` runs one online `apk add` into a throwaway root with `--cache-dir`, capturing the
  exact `.apk`s + `APKINDEX`; the manifest hashes them. An offline build then resolves from that
  frozen cache, so it is *more* reproducible than the floating CDN install, and the package lockfile
  (decision 007) still matches.
- **The mirror is gitignored, never committed.** It holds downloaded images, so it sits with
  `artifacts/` on the wrong side of the "don't commit built/downloaded images" guardrail. The
  *manifest* is the audit trail; it lives in the mirror it describes, not in source.
- **The boot proof runs `--unjailed`.** The jailed default needs real root; the proof's job is "the
  stack boots a VM and runs code," not "jailing works," so it stays rootless and KVM-gated.

**Alternatives considered.**
- **Commit the vendored blobs (or a `git-lfs` bundle) so `git clone` is self-contained.** Rejected,
  it directly breaks the guardrail against carrying built/downloaded images in the tree, and bloats
  every clone with hundreds of MiB most contributors never boot. The mirror is a self-hoster's
  offline convenience, produced once, not a source artifact.
- **Reimplement a signed local apk repo (build an `APKINDEX`, sign it).** Rejected, `apk`'s own
  `--cache-dir` + `--no-network` is the supported offline-install path and needs no signing rework;
  re-deriving apk's index/signature format in `xtask` would be fragile and redundant.
- **A `curl | sh` installer as the single command instead of an `xtask` subcommand.** Deferred to
  release packaging. `self-host` builds from source, which is what a from-a-clone self-hoster
  has today; the shell installer ships the *built* binaries, a packaging concern layered on top.

**Consequences.** Vendoring turns the last fetched-not-pinned input into a sha-pinned,
offline-verifiable one, so the whole build is reproducible from a mirror the self-hoster controls,
with both CDNs dark. The cost: the mirror is produced once and lives outside source, so its manifest
(not the tree) is the audit trail, and a self-hoster who never vendors still depends on the two CDNs
at build time. The reader-facing statement is the *Self-host* and *Vendoring* sections of
`docs/cli-install.md`; the two are kept in sync.
