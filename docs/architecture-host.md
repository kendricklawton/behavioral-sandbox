# Host integration

Where the pieces sit, and which boundaries a run crosses:

```mermaid
flowchart TB
    subgraph Host["Linux Host (cgroup.kill, else Kernel >= 5.15)"]
        subgraph Userspace["Host Userspace"]
            Client["ekvm CLI / Client SDK"]
            Daemon["ekvm serve Daemon"]
            VMM["Firecracker VMM (Jailed & Chrooted)"]
        end

        subgraph HostKernel["Host Kernel Space"]
            KVM["Linux KVM (/dev/kvm)"]
            
            subgraph eBPF["Host-Side eBPF (aya)"]
                Tracepoints["sys_enter_* Tracepoints"]
                TCEnforcer["tc/XDP Egress Classifier"]
                CPUMeter["sched_switch CPU Meter"]
            end
        end

        subgraph MicroVM["KVM Hardware Boundary"]
            subgraph GuestSpace["Guest Memory & OS"]
                GuestKernel["Guest Kernel"]
                GuestAgent["guest-agent (static musl)"]
                UntrustedCode["Untrusted Code"]
            end
        end
    end

    Client -->|Unix Socket Wire API| Daemon
    Daemon -->|ekvm-engine API| VMM
    VMM -->|KVM ioctl| KVM
    KVM -->|Hardware Exec| MicroVM
    Daemon <-->|vsock / channel| GuestAgent
    GuestAgent -->|execve / stdio| UntrustedCode
    MicroVM -->|Host Syscalls| Tracepoints
    MicroVM -->|TAP Packets| TCEnforcer
    Tracepoints -->|Ring Buffer| Daemon
    TCEnforcer -->|Flow & Deny Events| Daemon
```

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

```mermaid
flowchart LR
    subgraph GuestNetns["Per-VM Network Namespace"]
        GuestApp["Untrusted Guest App"]
        Eth0["eth0 (10.200.0.2/30)"]
        Tap["fc0 TAP (10.200.0.1/30)"]
    end

    subgraph HostNet["Host Network Enforcement"]
        TCLink["tc clsact Egress Hook"]
        Map["eBPF BPF_MAP_TYPE_HASH\n(IP / CIDR / Port Allow Rules)"]
        HostInterface["Host Network / Internet"]
        AuditLog["Audit Record (Denial Event)"]
    end

    GuestApp --> Eth0
    Eth0 --> Tap
    Tap --> TCLink
    TCLink -->|Lookup Destination| Map
    Map -->|Match Allowed Rule| HostInterface
    Map -->|No Match (Deny)| AuditLog
```

## Storage

The guest root is a read-only base image (Alpine, with the static `guest-agent` baked in), shared
across sandboxes, with a writable `tmpfs` overlay per run, so nothing a run changes outlives it
unless explicitly collected. Bulk data rides block devices instead: a read-only ext4 built from
`input_dir`, and a writable one extracted after teardown for `output_dir`. Both are embedding-API
fields rather than CLI flags.

```mermaid
flowchart TB
    subgraph StorageLayout["Sandbox Storage Layering"]
        BaseFS["Read-Only Base Rootfs\n(artifacts/rootfs-guest.ext4)"]
        TmpfsOverlay["Per-Run Writable tmpfs Overlay\n(Size capped at 50% RAM)"]
        MergedRoot["Merged Guest Root (/)\noverlay-init"]
        
        InputBlock["Input Block Device\n(read-only ext4 from input_dir, /dev/vdb)"]
        OutputBlock["Output Block Device\n(writable ext4 for output_dir,\nmounted by label ekvm-output: the /dev/vdX letter varies)"]
    end

    BaseFS -->|Lower Layer| MergedRoot
    TmpfsOverlay -->|Upper Layer| MergedRoot
    InputBlock -->|Mounted at| GuestInput["/input"]
    OutputBlock -->|Mounted at| GuestOutput["/output"]
```
