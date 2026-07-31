# The eBPF half

Three crates, split by what can depend on what:

- **`probes`** is the eBPF programs themselves: `#![no_std]`, built for `bpfel-unknown-none` via
  `bpf-linker`, using CO-RE and BTF so one object loads across kernel versions. Syscall tracepoints, a
  tc/XDP classifier on the VM's tap, and cgroup accounting.
- **`probes-common`** holds the `#[repr(C)]` plain-old-data records that cross the kernel/user
  boundary. **Zero dependencies, single-sourced**, so the program writing a record and the loader
  reading it cannot disagree about layout.
- **`probes-loader`** is the userspace half, on `aya`: attach to a specific sandbox, read the maps,
  fold events, and assemble the signed `RunRecord`.

`probes-loader` is one module per subsystem, which is the map to read it by:

| Module | What it owns |
|---|---|
| `tracer.rs` | `ExecveCounter`, `SyscallTracer`: the syscall tracepoints |
| `tap.rs` | `TapMonitor`, `NetStats`: the tc classifiers, the flow and denial maps, the netns join |
| `egress.rs` | `EgressPolicy`, `Ipv4Cidr`, `Ipv6Cidr`: **no eBPF**, just what an `--allow` string parses into, separately fuzzed |
| `meter.rs` | `ResourceMeter`, `CgroupStats`: the shared CPU meter and cgroup counters |
| `observer.rs` | the per-sandbox bundle over the three probes, and the `AxisGap` machinery |
| `record.rs`, `summary.rs`, `json.rs`, `signing.rs` | the record, its projections, and its signature |
| `lib.rs` | the error types, object-path resolution, cgroup id helpers, the capability check |

Three design decisions in `observer.rs` are worth understanding before changing anything there:

**The syscall tracer and CPU meter are host-global, not per-VM.** A fresh copy per sandbox would run
*N* programs on every context switch and every syscall, which is O(sandboxes) on the hottest path in
the kernel. Instead each is loaded **once** for the host, and every sandbox registers its cgroup as a
*target*, so per-event cost stays a single hash lookup no matter how many sandboxes are live. The tap
monitor is legitimately per-VM, since there is one tap per sandbox.

**One post-boot attach.** Because the shared probes are already attached and a sandbox only registers
its cgroup, which exists once the jailer creates it, there is no per-VM program to stand up before
boot. The trade is explicit: the syscall axis observes from *registration* onward, not the pre-boot
window. The record's core (network, resources, denials) is unaffected.

**Observation fails open; enforcement does not.** Every axis degrades independently to a recorded
`AxisGap`, so a host without BTF or `CAP_BPF` still runs the sandbox and produces a thinner record that
*says* it is thinner. The invariant to preserve when touching this code is that a lost fold or a
poisoned lock is a **recorded gap, never an empty footprint passed off as a quiet run**. Egress
enforcement is the opposite: `--allow` on a host that cannot load the probes is a typed refusal, since
silently not enforcing a security control is the worst available outcome.

Finalized records are signed with an `ed25519` host key the guest never sees, and within a session each
record commits to the previous one's hash, so a *sequence* is tamper-evident and not just a single
record. What that does and does not establish is in
[the threat model](./security-threat-model.md#record-integrity-beyond-the-guest).
