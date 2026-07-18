# 007. A byte-for-byte reproducible rootfs build *(2026-07-12)*

**Decision.** `cargo xtask build-rootfs` is **deterministic**: two builds from the same inputs produce
a byte-identical `rootfs-agent.ext4`. Three non-determinism sources are pinned:
- **`mke2fs` timestamps + directory-hash seed.** `SOURCE_DATE_EPOCH` (a fixed constant, scoped to the
  `mke2fs` child) stamps the superblock create/write/check times and clamps every `-d`-copied file
  mtime down to it; `-E hash_seed=<fixed UUID>` fixes the htree seed (otherwise random per build);
  `lazy_itable_init=0` writes the inode table eagerly so its bytes are fixed here, not finished
  non-deterministically by the guest kernel on first mount.
- **apk's install log.** `/var/log/apk.log` records each action with a **wall-clock** timestamp, the
  one install artifact that isn't reproducible (the package db content is deterministic). It has no
  runtime purpose, so the build removes it. (Found by diffing two builds' extracted trees, not by
  the `mke2fs` polish alone.)
- **The guest agent binary** is already reproducible (pinned `rust-toolchain.toml` + `--locked`), so
  no `--remap-path-prefix` is needed.

A committed **package lockfile** (`xtask/rootfs-packages.lock`) records the exact resolved closure
(`name-version-rN`, base + `apk add` deps). `build-rootfs --verify` (which `ci-privileged` runs)
builds twice, asserts byte-identical, and fails on closure drift; `--update-lock` re-records after an
upstream bump. The default `build-rootfs` stays one command (deterministic image; warns on drift).

**Alternatives considered.**
- **Exact-pin the packages (`apk add python3=<ver>`) as the reproducibility contract.** Rejected,
  the tempting analogy to the sha-pinned *tarball* is false. The minirootfs lives at a stable
  *release* URL (its bytes stay fetchable forever), but Alpine **branch** repos keep only the latest
  revision and **delete** the old `.apk` on every bump. So an exact pin doesn't reproduce the old
  build, it **fails** it the day upstream moves, and churns the repo with a lockfile commit per
  patch. A floating install that *records* the closure and *detects* drift keeps the everyday build
  working while still flagging when the image would change.
- **Vendor the `.apk` closure as sha-pinned artifacts** (hash-pin each of the ~33 packages, install
  offline). The genuinely durable end state, it closes the one security-relevant input still
  fetched-not-pinned, but it's a phase's worth of fetch/verify/offline-install rework. **Deferred**
  as the later hardening, out of scope for the byte-for-byte polish.
- **A separate content-manifest file** re-listing the Alpine/apk-tools shas + branch + target.
  Rejected: those are already source-of-truth constants in `xtask`; a second copy just drifts. The
  only thing not already captured is the resolved closure, which *is* the lockfile.

**Why.** Reproducibility is a first-class "measured, not marketed" property: a build you can't
reproduce is a claim you can't check. `SOURCE_DATE_EPOCH`/`hash_seed`/`lazy_itable_init=0` are the
standard ext4 determinism levers; the apk-log removal was the non-obvious last mile. The lockfile
makes package drift *visible* without making the build *brittle*.

**Consequences and notes.**
- **Reproducibility is a `ci-privileged`-guarded property**, not the everyday `ci` gate's, it needs
  the musl target + network + `mke2fs`, so `--verify` runs where the boot tests already do.
- **The lockfile drifts only on an Alpine package bump**, never on guest-agent code changes (the
  closure is independent of the agent binary), so it isn't a per-commit chore.
- **Durable over-time reproducibility still rests on Alpine's CDN** until the `.apk` closure is
  vendored (the deferred hardening); today a bump makes `--verify` fail loudly with a re-pin hint.
- **The same availability class covers `fetch-artifacts`' inputs** (P6.9d): the pinned guest kernel
  and Ubuntu boot rootfs come from the Firecracker CI S3 bucket, sha256-pinned, so tamper-*safe*
  but availability-*fragile*. A deleted bucket (or a retired Alpine branch) bricks **fresh-host
  setup** while existing `artifacts/` dirs keep working, and nothing upstream owes these URLs
  permanence. The failure is loud (a hash-checked fetch fails, it never silently substitutes), and
  the durable fix, vendoring the kernel, base images, and `.apk` closure as release artifacts of
  this repo, rides the P19.1 packaging work, where a self-host bundle needs them offline anyway.
- **A fixed htree hash seed is safe here**, the seed only matters against adversarial directory-hash
  flooding, which a trusted, pinned, build-time image doesn't face.
- **The guarantee is same-host determinism, not cross-machine bit-reproducibility.** The rootless
  build stages files owned by the *build user's* uid/gid, and `mke2fs -d` copies that ownership into
  the image, so an image built by a different user (or from a different checkout path, which can leak
  into the agent binary's debug strings) differs byte-for-byte. `--verify` builds twice as the same
  user from the same path back to back, so it proves the build is deterministic *on this host*, which
  is what catches an accidental non-determinism regression. Cross-host reproducibility (normalize
  ownership to `0:0`, `--remap-path-prefix` the binary) is a separate, deferred hardening.
