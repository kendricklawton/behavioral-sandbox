# docs

Per-phase writeups. The point of this project is **Linux mastery**, so every ROADMAP phase exits
on *a working demo **and** a writeup*: the writeup is a first-class deliverable, not an
afterthought.

Each writeup explains the Linux mechanism a phase taught (the boot protocol, vsock, tap
networking, snapshots, cgroups/seccomp, the eBPF verifier, tc/XDP, …), so the *why* outlives the
diff and the series doubles as a blog / design-doc seed.

- `NNN-<slug>.md`: one file per phase's lesson (added as phases land).

The writeups so far:

- [001: Booting a microVM from Rust](001-boot-a-microvm.md): the Firecracker boot protocol, over its HTTP API.
- [002: Talking to the guest over vsock and a tiny agent](002-host-guest-comms.md): the host to guest channel.
- [003: The disk the guest runs](003-rootfs-and-runtimes.md): rootfs, ext4, and runtime-agnosticism.
- [004: The network the guest gets](004-guest-networking.md): tap, virtio-net, and deny-by-default.
