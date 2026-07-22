# 040. Supply-chain provenance: pin the Firecracker binary, sign the release manifest *(2026-07-22)*

**Context.** Build-input provenance is already strong. The guest kernel and boot rootfs are pinned by
sha256 (`xtask/src/artifacts.rs`); the Alpine base, `apk-tools`, and the resolved package closure are
pinned and the rootfs is byte-for-byte reproducible (`xtask/src/rootfs.rs`, decision 007); a
`cargo xtask vendor` mirror re-verifies every pinned input offline in both directions
(`xtask/src/vendor.rs`, decision 033); the release tarball is deterministic and double-checksummed,
an outer `SHA256SUMS` over the tarball and an inner per-file manifest, verified by `install.sh`
(`xtask/src/dist.rs`, decision 035). Against that, an evaluator finds two real holes.

1. **The Firecracker and jailer binaries are not pinned or verified.** `install.sh` tells the operator
   to install Firecracker v1.9 on `PATH`; the self-host path drives whatever binary it finds. The
   container image bundles a sha-pinned Firecracker (decision 035), but the tarball and self-host
   paths verify nothing. And Firecracker *is* the trust boundary: an unverified boundary binary
   undercuts the entire isolation claim, no matter how well the guest image is pinned.
2. **The release `SHA256SUMS` is itself unsigned.** The tarball's integrity is checksummed, but the
   checksum file's authenticity rests on GitHub-release plus TLS trust, not on a signature a
   downloader can verify against a known key.

**Decision.** Close both, and record the boundary of what is deferred.

- **Pin and verify the Firecracker/jailer binary by sha256.** A pinned hash lives alongside the
  kernel and rootfs pins in `xtask/src/artifacts.rs` (the sha256 is the contract; the URL is
  replaceable). `install.sh` verifies a fetched-or-operator-provided binary against it, and
  `agent doctor` gains a check on the installed binary's hash. That check is **advisory**: an operator
  may legitimately run a locally-built or distro-packaged Firecracker, so a mismatch **warns** rather
  than refuses; the pinned hash is the supported, verified default, not a hard gate (the same posture
  decision 038 takes for host hardening).
- **Sign the release `SHA256SUMS`.** The finalized checksum file is signed with the same host
  `ed25519` signing core the audit record already uses (decision 034), or an equivalent minisign key,
  so a downloader verifies provenance against a published key without trusting the release host or its
  transport. `install.sh` verifies the signature when a trusted public key is present.
- **SLSA provenance, SBOM, and in-toto attestation are recorded as post-tag work, not a pre-tag box.**
  They are valuable, but they attach to a release *pipeline* that does not exist before `v0.1.0`
  (`RELEASES.md`: no releases yet). They belong to the release process defined at the tag, not to a
  box that would build pipeline machinery with nothing to run it on.

**Alternatives considered.**
- **Bundle Firecracker in every distribution, like the container does.** Rejected. The tarball and
  self-host paths deliberately do not bundle Firecracker (KVM is always the host's, and decision 035
  keeps the one bundling exception to the container image). Pinning and verifying the operator's
  binary buys the same integrity as bundling without taking on Firecracker's size and its
  host-coupling in every artifact.
- **Leave Firecracker unpinned and trust `PATH`.** Rejected. Of every supply-chain input, the boundary
  binary is the one where an unverified substitution actually defeats the product. Verifying the guest
  kernel and rootfs while trusting an unchecked Firecracker is a locked door next to an open window.
- **Do full SLSA/SBOM now.** Rejected as pre-tag scope creep, and recorded above so the deferral is a
  decision, not a silent gap.

**Consequences and notes.**
- **Two boxes, tracked.** The Firecracker-binary pin (`xtask/src/artifacts.rs` + `install.sh` +
  `agent doctor`) and the `SHA256SUMS` signing (`xtask/src/dist.rs` + `install.sh`) are their own
  roadmap boxes, so this decision's implementation is queued, not buried in prose.
- **One reader page.** Provenance was spread across decisions 007, 033, 034, and 035 plus
  `docs/cli-install.md`. `docs/supply-chain.md` consolidates "what is pinned, what is verified, how to
  reproduce it" into a single page an evaluator can read end to end, with this decision as its anchor.

**As shipped.** This decision and `docs/supply-chain.md` ship as documentation, consolidating the
existing pinning story and recording the two closures above; the Firecracker-binary pin and the
release-manifest signing are tracked as roadmap boxes.
