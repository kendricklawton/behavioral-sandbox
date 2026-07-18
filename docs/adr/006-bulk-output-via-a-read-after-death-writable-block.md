# 006. Bulk output via a read-after-death writable block device *(2026-07-12)*

**Decision.** When `BootConfig.output_dir` is set, the driver attaches a **blank, writable** ext4 as
a third block device (labelled `agent-output`, `is_read_only: false`); the guest mounts it read-write
at `/output`, so a command's files under `/output/...` are the bulk-output surface. `RunningVm::`
`collect_outputs` (consumes the VM) then reads that image back into the host directory. It is the
whole-working-dir / large-file counterpart to the vsock channel's per-frame `Response::File`
artifacts (P2.5), which carry only small files. Readback is **rootless** and happens **after the VMM
has exited**: stop the VM (cooperative `SendCtrlAltDel`, then a hard kill), `e2fsck -fy` the image to
recover the journal, then `debugfs rdump` the tree out, no loopback, no `mount`, no `sudo`.

**Alternatives considered.**
- **Read the writable image while the VMM is live** (a `&self` method). Rejected: Firecracker holds
  the file open and the guest may still be writing, so `e2fsck` (which *writes* journal replay) would
  race the VMM and could corrupt the image. `collect_outputs` therefore consumes the VM and stops it
  first, the fd must be closed before we touch the file.
- **Stream the output over the vsock channel** (a `tar` the guest pipes back). Rejected for the bulk
  path: it re-imposes the channel's framing/round-trip cost and forces a guest-agent change; the block
  device carries what the channel can't at near-disk speed, with **no guest-agent change** (the
  command writes to `/output`; a wedged grandchild can't wedge the agent).
- **Loop-mount the image host-side** and copy. Rejected: `mount` needs root/`CAP_SYS_ADMIN`, breaking
  the rootless discipline P3.4 set. `debugfs rdump` reads an ext4 without mounting, mirroring how
  `mke2fs -d` *writes* one without mounting.
- **`fuse2fs` + `cp --sparse=always`.** Not available on the reference host (no `fuse2fs` binary), and
  it adds a `/dev/fuse` dependency and a real mount to unwind; `debugfs` keeps deps to e2fsprogs.

**Why.** Symmetry with the input side, at the cost the input side deferred here. Durability of the
guest's writes is the `/output` `-o sync` mount (each write flushed through to the image) plus the
guest's clean `::shutdown:/bin/umount -a -r`; `e2fsck` then makes even a hard-killed, dirty image
consistent before extraction. The image is built with `lazy_itable_init=0` so the guest kernel never
lazily zeroes the inode table at runtime, which would balloon the sparse image toward its full
256 MiB on the host regardless of what the command wrote.

**Security, the inverse of 005's symlink note.** `mke2fs -d` resolves *input* links inside the guest
image; `debugfs rdump` recreates *output* links verbatim as **host** symlinks, so an un-sanitised
`link -> /etc/shadow` in `/output` would make a later host read of the results read host files.
`collect_outputs` therefore **drops every symlink whose target escapes the destination** (absolute, or
`..` climbing out), keeping only in-tree links, before returning. The guest only ever writes through
the guest kernel's ext4 driver (never raw block access), so the on-host image is always a well-formed,
crash-consistent, kernel-produced filesystem, the residual adversary controls contents, names, and
link targets, not the metadata `e2fsck`/`debugfs` parse.

**Consequences and notes.**
- **New runtime tool dependencies** (`e2fsck` + `debugfs`, both e2fsprogs, the same package as
  `mke2fs`, so no *new* package): a missing binary is a typed `VmmError::Artifact`, and `xtask setup`
  checks for both.
- **`debugfs rdump` materialises filesystem holes as real zeros**, so a sparse file staged in the
  capped image could inflate the readback. The extraction is bounded by a watcher on the destination's
  **allocated** bytes (`OUTPUT_EXTRACT_CAP`, 512 MiB) and a wall-clock deadline
  (`OUTPUT_READBACK_TIMEOUT`); a breach is a typed `OutputCap`/`Timeout`, never unbounded host disk.
- **`-o sync` trades throughput for durability.** Fine for the "a few large files" mechanism; a
  future optimisation is an async mount + an explicit guest `sync` on teardown (needs a guest-agent
  touch, so deferred).
- **The 256 MiB image is a fixed cap**, the natural bulk-output bound (the guest can't write more than
  the filesystem holds), mirroring the channel path's 16 MiB. It becomes a `BootConfig` knob when the
  per-run resource policy lands.
- **`Sandbox` plumbing is deferred** (as `input_dir` was): `output_dir`/`collect_outputs` live at the
  `RunningVm` layer for now; a `Sandbox::collect_outputs` + `agent run --output-dir` follow-up is
  noted in the roadmap.
