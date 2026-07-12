# 003: The disk the guest runs (rootfs, ext4, and runtime-agnosticism)

> Phase 3 of the sandbox engine. Phase 1 booted a microVM; Phase 2 handed it a command and captured
> the result. Phase 3 builds the **disk that guest runs from**, a real Linux userland with real
> language runtimes, and proves the engine runs *any* Linux binary, not a Python-shaped one.

```rust
// All three run unchanged through the same exec path; the rootfs isn't runtime-specific.
sandbox.exec(&["python3".into(), "-c".into(), "print(2+2)".into()], b"")?;      // an interpreter
sandbox.exec(&["node".into(), "script.js".into()], b"")?;                       // a *different* interpreter
sandbox.exec(&["/input/writefile".into(), "/output/answer.txt".into()], b"")?;  // a static native ELF, injected
```

A microVM with no disk is a kernel with nothing to run. Phase 3 gives it one: `cargo xtask
build-rootfs` assembles `artifacts/rootfs-agent.ext4`, a pinned Alpine userland with the guest agent
baked in, Python and Node installed, and an init that brings the agent up on vsock. The lessons are
all about **filesystems**: how you build one without root, how you keep the base read-only but let a
run write, how you make the build reproducible to the byte, and what "static vs dynamic linking"
actually buys in a minimal image.

## Build the rootfs, don't fetch one

A prebuilt cloud image is a black box: you don't know what's in it, it's big, and it isn't
reproducible. So we build from a **sha256-pinned Alpine minirootfs** (a ~5 MB musl + busybox
userland) and assemble everything on top with a script. Alpine because musl is small and static
linking is first-class, and because `apk` scales the same base from busybox to Python to Node.

The whole build is **rootless**: no `sudo`, no loopback mount. That's the `mke2fs -d` trick (below),
plus a pinned static `apk` that installs packages into a staging *directory* (`--root`) rather than a
mounted filesystem. The one-command, no-privilege build is a deliberate discipline: the same "no
`sudo cargo` roulette" rule the rest of the engine follows.

## The filesystem: an ext4 image, assembled rootless

An ext4 image is normally made by `mkfs` on a block device (or a loopback-mounted file), then
`cp`-ing files in as root. Both need privilege. `mke2fs -d <dir>` sidesteps both: it **populates the
new filesystem directly from a staging directory**, in userspace, copying the tree's files, modes,
and symlinks into the image without ever mounting it. Combined with `truncate -s` to size a sparse
image first, the entire rootfs is built by an unprivileged process:

```
truncate -s 256M rootfs-agent.ext4
mke2fs -F -q -t ext4 -d staging/ rootfs-agent.ext4
```

That `-d` is the hinge of the whole phase: it's why "build a Linux disk image" doesn't require root.
The same primitive builds the bulk-input block device (Phase 3.4): a host directory becomes a
read-only ext4 the guest mounts, modes preserved, so an injected `0755` binary is executable in the
guest.

## Read-only base, writable per run: overlayfs

The base image is a shared, pinned artifact: many VMs boot the *same* file, and a run must never
mutate it. But a running program needs to write (its `/tmp`, its working dir). The answer is a
**tmpfs overlay** (`overlayfs`): the read-only base is the `lowerdir`, a per-run tmpfs is the
`upperdir`, and the guest sees a unified `/` where reads fall through to the base and writes land in
the (ephemeral) tmpfs. When the VM dies, the tmpfs is gone; the base is untouched, bit for bit.

The guest sets this up as PID 1 (`/sbin/overlay-init`): mount the tmpfs, stack the overlay,
`pivot_root` into it, then `exec` the real init. `pivot_root`, not `switch_root`: the base stays
mounted underneath (as the overlay's lowerdir), shadowed at `/rom`, so nothing tries to free a
still-in-use root. Firecracker opens the base `O_RDONLY`, so the "base never changes" guarantee is
enforced by the kernel, not by hope.

## initramfs vs rootfs

Linux can boot two ways: an **initramfs** (a cpio archive the kernel unpacks into a RAM
filesystem and runs from) or a **rootfs on a block device** (the kernel mounts `root=/dev/vda` and
runs `/sbin/init`). We use a block-device rootfs. Why: an initramfs lives entirely in guest RAM, so a
100 MB userland would cost 100 MB of guest memory before the program even starts, and Firecracker's
`BootSource` has no `initrd_path` in our config anyway. A virtio-blk rootfs is demand-paged: the
guest reads the blocks it touches, the host page cache serves them, and unused files (most of the
image) never occupy guest RAM. For a base that carries Python *and* Node, that's the difference
between a 256 MB guest and an impossible one.

## Reproducible to the byte

"Pinned inputs" isn't the same as "byte-identical output." Two builds of the same inputs still
differed, and chasing that down (Phase 3.6) is a tour of where non-determinism hides in a
filesystem:

- **`mke2fs` timestamps.** The superblock records create/write/check times. `SOURCE_DATE_EPOCH`
  (a fixed constant) pins them, and also **clamps every copied file's mtime** down to it.
- **The directory hash seed.** ext4 htree directories use a random per-filesystem seed. `-E
  hash_seed=<fixed-uuid>` pins it. (Safe here: the seed only matters against adversarial hash
  flooding, which a trusted, pinned, build-time image doesn't face.)
- **`lazy_itable_init`.** By default the inode table is zeroed lazily *by the guest kernel on first
  mount*, so its bytes aren't fixed at build time. `lazy_itable_init=0` writes it eagerly.
- **`/var/log/apk.log`.** The non-obvious one. `apk` logs each install with a **wall-clock
  timestamp**; the package database is deterministic, but this log isn't. It has no runtime purpose,
  so the build deletes it. (Found by diffing two builds' *extracted trees*, not the superblock.)

With those pinned, two builds are byte-identical, checked by `build-rootfs --verify` (build twice,
compare). The exact package set floats within Alpine's stable branch (the branch repo only keeps the
latest revision, so an exact pin would *fail* the build on an upstream bump, not reproduce it), so a
committed `rootfs-packages.lock` **records** the resolved closure and `--verify` flags drift.

One honest caveat: this is reproducibility *given the same input `.apk`s*. The packages are fetched
from Alpine's CDN and verified against the keys the minirootfs ships, so tampering is caught, but a
build is only bit-for-bit repeatable while those exact revisions are still served. When the branch
bumps a package, the old `.apk` is gone and the closure drifts (which `--verify` reports). The durable
fix, vendoring the resolved `.apk` closure as sha-pinned artifacts, is deliberately deferred.

## Static vs dynamic linking in a minimal rootfs

This is where a minimal userland teaches you what linking actually means:

- **The guest agent** is a **fully static** musl binary: no `NEEDED` shared objects, no
  `PT_INTERP`. It runs on *any* Linux with a compatible kernel, no loader, no libc in the image. A
  build check (`readelf -d` + `readelf -l`) fails the build if a shared-object dependency or an
  interpreter ever creeps back in.
- **Python and Node** are **dynamically linked** against musl and a pile of shared libraries
  (`libssl`, `icu-libs`, `libstdc++`, …). They only run *because* the Alpine base provides the musl
  loader and those `.so`s. That's the whole reason we chose a real userland base and not `scratch`.
- **The injected `writefile` ELF** (Phase 3.9) is static like the agent, which is exactly why it can
  be handed to a *bare* guest and run with nothing else present.

So the image carries two kinds of program: the ones that bring their whole world with them (static),
and the ones that lean on the userland (dynamic). A sandbox base has to serve both.

## Runtime-agnostic: bake an interpreter, or inject a binary

The engine runs a Linux binary; it has no idea what language wrote it. Phase 3 proves that two ways:

- **Bake the interpreter.** Python (3.2) and Node (3.9) are installed into the base. A script is
  injected over the channel, the interpreter runs it, and the file it writes is captured. Two
  *different* interpreters, the same `exec` path: the rootfs isn't Python-specific.
- **Inject the binary.** The static `writefile` ELF isn't in the image at all. It's handed in at
  runtime on a read-only block device, exec'd from `/input`, and writes to the `/output` device we
  read back host-side. This is the stronger claim: the engine runs *any* binary you give it, no
  pre-provisioning. (Contrast the Wasmtime sibling, which needs code recompiled to `wasm32`: a
  different, software-isolation boundary, deliberately a separate repo.)

Baking suits a multi-file runtime with a dependency closure (Node is 44 packages); injection suits a
self-contained binary. Both flow through the one `exec` surface.

## Size and boot, measured

"Keep the base small" is a real budget: `build-rootfs` reports the image's footprint and fails past a
ceiling, a guard against accidental bloat. Adding Node was a *deliberate* bump: python3 alone is
~51 MiB of packages, Node's closure (`icu-libs`, `simdjson`, `ada-libs`, …) adds ~64 MiB, so the
image went from ~69 MiB to ~132 MiB and the budget/size constants moved with it, on purpose.

Does a bigger base boot slower? Measured (`cargo xtask bench-boot`, 100 boots per path, enough that
`p99` is a real observation rather than the slowest sample relabelled, nearest-rank, not averages):

```
agent rootfs 132 MiB
  read-only shared base    p50 388  p90 412  p99 667   (ms, n=100)
  read-write per-VM copy   p50 371  p90 392  p99 413   (ms, n=100)
```

At the **median** the two paths are within ~5%, and doubling the base didn't slow boot: the copy path
duplicates the whole image per VM, but the **host page cache** serves those reads, so image size
barely moves boot latency. The honest surprise is in the **tail**: the read-only *shared* path has a
markedly heavier `p99` (667 ms vs 413 ms), not from image size (it copies *less*), but from **per-run
overlay setup** (mounting the tmpfs + stacking overlayfs + `pivot_root`), which the copy path skips.
So keeping the base small mainly buys **density** (page-cache dedup across many VMs, disk), not boot
time; if anything, the density path pays a little tail latency for the overlay. (Absolute numbers move
with cache warmth and host load; cold-boot percentiles as a tracked benchmark are Phase 17; this is
the Phase-3-scoped measurement.)

## Try it

```console
cargo xtask build-rootfs            # rootless, reproducible; prints the image sha256 + size
cargo xtask build-rootfs --verify   # build twice, assert byte-identical
cargo xtask bench-boot              # boot-latency percentiles vs the base size

# run each runtime in a real microVM (needs KVM):
cargo xtask ci-privileged           # boots the rootfs; runs python, node, and a native ELF end to end
```

Phase 3 leaves the engine with a real disk, real runtimes, and a build you can reproduce and measure.
Next: give the guest a **network** it can actually use, and the tap device the eBPF track will watch.
