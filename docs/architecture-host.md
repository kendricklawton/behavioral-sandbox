# Host integration

Where the pieces sit, and which boundaries a run crosses:

```text
LINUX HOST  (a kernel providing cgroup.kill, else >= 5.15)

  HOST USERSPACE
    ekvm CLI / client SDK
        |  unix socket wire API
        v
    ekvm serve daemon  <-------------------------------+
        |  ekvm-engine API                             |
        v                                    ring buffer, flow and
    Firecracker VMM (jailed, chrooted)         deny events
        |  KVM ioctl                                   |
        v                                              |
  HOST KERNEL                                          |
    Linux KVM (/dev/kvm)                    HOST-SIDE eBPF (aya)
        |  hardware exec                      sys_enter_* tracepoints
        |                                     tc clsact egress classifier
        |                                     sched_switch CPU meter
        |                                              ^
        |                                              |
        |                              host syscalls (the VMM's own),
        |                              tap packets, per-sandbox cgroup
        v                                              |
  ================= KVM HARDWARE BOUNDARY =============|=============
        |                                              |
    GUEST MEMORY AND OS                                 (observed from
      guest kernel                                       the host side)
      guest-agent (static musl)  <--- vsock / channel ---> daemon
        |  execve, stdio
        v
      untrusted code
```

The eBPF programs sit on the **host** side of that boundary: they attach to host-kernel hooks and
observe the VMM's host footprint, the guest's tap, and its cgroup, never the guest's own syscalls
(a microVM services those in its own kernel).

## Host requirements

- **OS & Kernel**: Linux host with a kernel providing `cgroup.kill`. `ekvm doctor` probes for the primitive rather than trusting a version string, falling back to `>= 5.15` only where there is no cgroup v2 hierarchy to probe.
- **Architecture**: `x86_64` with hardware virtualization extensions (`/dev/kvm`).
- **Permissions**: real root (euid 0) for jailed boots, because the jailer mknod's device nodes into its chroot; `CAP_NET_ADMIN` for the per-VM netns and tap; `CAP_BPF` + `CAP_PERFMON` plus kernel BTF for the eBPF observability. `ekvm doctor` renders each as its own row.

## Networking

Each sandbox gets its own network namespace, with a tap device (`fc0`) inside it as the guest's
only path out. By default that path leads nowhere (deny-by-default); with `--net` and `--allow`,
host-side eBPF `tc` programs inspect every packet at the tap and enforce the destination
allow-list.

The namespace holds exactly `lo` and the tap, so a guest with no `--gateway` reaches only the host
end of its /30 and an off-link destination fails at its own routing table before a packet is
emitted. `--gateway` fills the field the kernel `ip=` parameter otherwise leaves empty, which lets
the guest emit those packets so the classifier can judge them; it builds nothing. Attaching an
uplink to the namespace and allocating the addresses that takes is the hoster's, per
[decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster).

```text
PER-VM NETWORK NAMESPACE          |  HOST-SIDE ENFORCEMENT
                                  |
  untrusted guest app             |
        |                         |
        v                         |
  eth0 (10.200.0.2/30)            |
        |                         |
        v                         |
  fc0 tap (10.200.0.1/30)  ---->  |  tc clsact egress hook
                                  |        |  look up the destination
                                  |        v
                                  |  eBPF hash map
                                  |  (IP / CIDR / port allow rules)
                                  |        |
                                  |        +-- match  --> host network / uplink
                                  |        |
                                  |        +-- no match (deny by default)
                                  |                 --> dropped, and the denial
                                  |                     lands in the audit record
```

## Storage

The guest root comes from one Alpine base image with the static `guest-agent` baked in, attached one
of two ways. By default each VM gets its **own read-write copy** of that base in its workdir,
reclaimed with the workdir at teardown. A `read_only_root` boot instead hands Firecracker the base
`O_RDONLY` and lets every sandbox share it, with the guest's writable layer supplied by a per-run
`tmpfs` overlay; that is the mode the snapshot and pool paths use, and it is what makes one base
image serve many concurrent VMs. Either way nothing a run changes outlives it unless explicitly
collected. Bulk data rides block devices instead: a read-only ext4 built from
`input_dir`, and a writable one extracted after teardown for `output_dir`. `read_only_root`,
`input_dir`, and `output_dir` are all embedding-API fields rather than CLI flags.

```text
SANDBOX STORAGE LAYERING  (a read_only_root boot; the default gives each VM its
                           own read-write copy of the base instead)

  read-only base rootfs                per-run writable tmpfs overlay
  (artifacts/rootfs-guest.ext4)        (capped at 50% of guest RAM)
            |                                       |
            +--------- lower layer   upper layer ---+
                             |
                             v
                merged guest root (/), by overlay-init

  input block device                    output block device
  (read-only ext4 from input_dir,       (writable ext4 for output_dir, mounted by
   /dev/vdb)                             the label ekvm-output: the /dev/vdX
            |                            letter varies)
            v                                       |
        /input in the guest                         v
                                            /output in the guest
```
