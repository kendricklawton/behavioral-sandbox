# Threat model

This is the engine's threat model: the assets it protects, the boundary it trusts, the adversary it
assumes, and, attack class by attack class, how each is contained and where that containment is
proven. It is deliberately concrete: every claim points at the mechanism that enforces it and the
test that exercises it, because the security model is measured, not asserted (a core property).

The one-line version: **untrusted code runs inside a KVM microVM, and everything that observes or
constrains it lives on the host, outside the guest's reach.** The trust boundary is the CPU, not any
software inside the guest.

## Assets

What the engine is protecting, in priority order:

1. **The host.** A run cannot escape its microVM, exhaust the host, or leak host resources, even
   when its driver process dies without cleanup.
2. **Every other run.** Runs are contained from each other: no state, memory, network, or resource
   bleed between two sandboxes on one host. (This is what lets a hoster place mutually-distrusting
   callers on shared hardware; *whose* run is whose is the hoster's concern, not the engine's.)
3. **The audit record's integrity.** What the host reports a run did is truthful: the guest can
   neither forge, evade, nor disable the observation.
4. **Deny-by-default.** A run with no explicit policy reaches no network and holds minimal
   capability; every allowance is explicit and recorded.

## The trust boundary

- **Trusted** (inside the boundary): the host CPU's virtualization (KVM), the host kernel, and the
  driver running on the host, the VMM process, the jailer, and the host-side eBPF probes. All
  security-relevant observation and policy live here.
- **Not trusted** (outside): everything inside the guest. The untrusted code, the guest kernel, and
  the in-guest agent that carries exec and I/O. **The in-guest agent is a convenience, never a
  security boundary**: a hostile guest is assumed to control it, and its own guest kernel, completely.

A direct consequence shapes what the host can see. Host-side **syscall** visibility is coarse for a
microVM: the guest services its own syscalls in its own kernel, so they never trap to a host
tracepoint (their absence there is the isolation working, not a blind spot). The strong
cross-boundary signals are the ones the host mediates directly: the guest's **network**, at its tap
device, and its **resource use**, at its cgroup.

## The adversary

A single **fully hostile guest**: it controls all code in the VM including the guest kernel and the
in-guest agent, and it actively tries to escape the VM, exhaust or crash the host, exfiltrate over
the network, interfere with a co-resident run, and blind or forge the host's observation of it. The
adversary does **not** include a party with host access, a KVM or host-kernel zero-day (see
Assumptions), or physical/side-channel attacks.

## Attack classes and how each is contained

| Attack | Contained by | Proven in |
|--------|--------------|-----------|
| Escape the isolation boundary | Hardware virtualization (KVM); the jailer (chroot, uid/gid drop, seccomp, namespaces) as defense in depth | the jail-escape tests in `vmm`'s `confinement.rs` |
| Resource exhaustion (memory / CPU / pids / IO) | The per-VM cgroup (`memory.max`, `cpu.max`, `pids.max`); a derived per-drive IO-bandwidth bound (a virtio-blk rate limiter, so a disk-thrasher can't starve a co-resident run); guest processes never become host threads | the fork-bomb/mem-hog and consolidated exhaustion tests in `confinement.rs` |
| Network exfiltration / flood | Deny-by-default egress policy enforced in-kernel at the tap, armed before the guest's first packet; drops are counted | `net_enforce.rs`; the hostile-guest and flood tests in `confinement.rs` |
| Evade / disable the observation | The probes run in the **host** kernel and the tap monitor on the **host** end of the tap, the guest has no handle to reach them | `hardening.rs` |
| Leak a run on driver death | A cgroup-owned lifetime + sentinel kills the VM when its driver dies; an own-euid orphan sweep reclaims residue | the sentinel and orphan-sweep tests in `confinement.rs` |
| State bleed between clones | Each restored clone has its own in-RAM overlay and guest RAM; the shared base is read-only | `snapshot.rs` |
| Secret disclosure | Injected `--env` values and file contents are never logged or written to the serial console | driver + CLI secret-handling tests |

The **consolidated** proof is that these hold *together*, against one hostile guest doing its worst
on every axis at once: it exfiltrates (denied and recorded), floods the network (dropped at volume),
exhausts memory and forks a storm (bounded by the cgroup, zero host threads), and hunts for the
probes (finds nothing, and is recorded anyway), and each attempt fails while the run stays
contained and usable. "Safe for multi-tenant hosting" means exactly this suite green, nothing less.

## Assumptions and residual risk

The boundary is only as strong as what it trusts. Explicitly assumed sound, and therefore *out* of
the boundary:

- **KVM and the host CPU's virtualization.** A hypervisor-level or CPU vulnerability that breaks VM
  isolation is outside this model; the jailer + seccomp are defense in depth that narrow the VMM's
  own attack surface, not a substitute for KVM.
- **The host kernel**, including its eBPF and cgroup implementations.
- **Micro-architectural side channels** (Spectre-class, timing) between co-resident guests are not
  addressed here; a hoster placing high-sensitivity workloads should account for them at the
  scheduling layer it owns.
- **Availability of a co-resident run under contention** is bounded (cgroup + egress caps), but the
  engine does not promise fair scheduling across runs, that is the hoster's scheduler.

## Out of scope (engine, not platform)

The engine guarantees **per-run containment**; it is not a multi-tenant platform. Tenant
authentication, authorization, quotas, billing, fleet scheduling, and a management dashboard are the
**hoster's** responsibility, not a vulnerability in the engine. The engine's own commitment is
narrower and testable: its privileged tools cannot be weaponized (euid-scoped, authorship not
policy), and it self-limits by default (deny-by-default network, a dropped-uid jail, an own-euid
sweep). Turning that into a safe multi-tenant service is the hoster's job.

See [Security](./security.md) for what counts as a security bug and how to report one.
