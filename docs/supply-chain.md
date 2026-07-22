# Supply-chain provenance

Running untrusted code is only as trustworthy as the pieces you built the runtime from. This page is
the one place that states, end to end, **what the engine pins, what it verifies, and how you reproduce
it**. The reasoning behind each piece lives in its decision record; this is the reader's map.

## What is pinned and verified today

- **The guest kernel and boot rootfs** are pinned by sha256 and fetched by hash, not by trusting a
  URL: a corrupt or substituted file fails the build hard (`xtask/src/artifacts.rs`). The sha256 is
  the contract; the download location is replaceable.
- **The guest image is byte-for-byte reproducible.** The Alpine base, `apk-tools`, and the resolved
  package closure are all pinned, and CI builds the rootfs twice and asserts the two are identical
  (`xtask/src/rootfs.rs`,
  [decision 007](./adr/007-a-byte-for-byte-reproducible-rootfs-build.md)).
- **Every pinned input can be mirrored and re-verified offline.** `cargo xtask vendor` snapshots all
  the sha-pinned inputs into a local mirror with a manifest, and re-checks that mirror in **both**
  directions, missing files and stray unaudited files both fail (`xtask/src/vendor.rs`,
  [decision 033](./adr/033-single-command-self-host-a-vendored-offline-mirror-of.md)).
- **The release tarball is deterministic and double-checksummed.** An outer `SHA256SUMS` covers the
  tarball and an inner per-file manifest covers every staged file; `install.sh` verifies both and
  installs nothing unverified (`xtask/src/dist.rs`,
  [decision 035](./adr/035-distribution-is-a-checksummed-tarball-an-installer.md)).
- **The Rust dependency tree is gated.** `cargo deny` fails CI on an advisory, and the build is
  `--locked` against a pinned toolchain (see [Stability & releases](./stability.md)).
- **The audit record is host-signed.** Separate from build provenance, each finalized record carries
  an `ed25519` signature so tampering after the producing host is detectable
  ([decision 034](./adr/034-the-integrity-model-a-host-signed-record-and-the.md)).

## What is being closed

Two provenance gaps are recorded in
[decision 040](./adr/040-supply-chain-provenance-pinning-and-release-signing.md) and tracked as
roadmap work:

- **Pinning the Firecracker binary.** Firecracker is the trust boundary, so an unverified boundary
  binary undercuts the isolation claim. The container image already bundles a sha-pinned Firecracker;
  the tarball and self-host paths will pin its sha256 alongside the kernel and rootfs, verify it in
  `install.sh`, and have `agent doctor` advise on the installed binary's hash (advisory, so a
  locally-built Firecracker warns rather than refuses).
- **Signing the release manifest.** The `SHA256SUMS` file will itself be signed, so a downloader
  verifies provenance against a published key rather than trusting the release host and its transport.

**Deferred to the release process** (post-`v0.1.0`, not a pre-tag box): SLSA provenance, an SBOM, and
in-toto attestation. They attach to a release pipeline that does not exist yet, and belong to the
process defined at the tag.

## Reproducing a build

- `cargo xtask vendor` to snapshot every pinned input, then `cargo xtask vendor --verify` to re-check
  the mirror offline.
- Point `AGENT_VENDOR_DIR` at the mirror and the whole build runs with the upstream CDNs dark; see the
  Self-host and Vendoring sections of [Installation](./cli-install.md).
