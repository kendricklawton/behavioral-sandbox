# 033. The whole security boundary: what's trusted, what the adversary is, and what's assumed sound *(2026-07-17)*

**Problem.** The trust boundary had been stated in pieces, "isolation is hardware" as a core
property, decision 016's engine/hoster line (one facet the orphan sweep forced), decision 022's
"multi-tenant safety *is* the containment suite", but never written down whole: the complete set of
what the engine trusts, the adversary it assumes, and the risks it explicitly does **not** cover. A
security engine whose boundary lives only in scattered implications can't be audited, and a hoster
can't reason about what they're taking on. With the Phase-15 adversarial suite now green, the boundary
is provable, so it should be recorded as one thing.

**Decision.** Fix the boundary at the CPU, and state all three faces of it explicitly. This is the
recorded rationale; the reader-facing companion is `docs/threat-model.md` (P15.5), and the two are
kept in sync.

- **Trusted (inside the boundary):** the host CPU's virtualization (KVM), the host kernel (including
  its eBPF and cgroup implementations), and the driver on the host, the VMM process, the jailer, and
  the host-side eBPF probes. All security-relevant observation and policy live here.
- **Not trusted (outside):** everything in the guest, the untrusted code, the **guest kernel**, and
  the in-guest agent. The agent carries exec/IO for convenience and is **never** a security boundary;
  a hostile guest is assumed to own it and its kernel completely.
- **The adversary:** a single fully-hostile guest that tries to escape the VM, exhaust or crash the
  host, exfiltrate or flood the network, interfere with a co-resident run, and blind or forge the
  host's observation. It does **not** include a party with host access, a KVM/host-kernel zero-day, or
  physical/micro-architectural side-channel attacks (see assumptions).

**Why this shape.** Each obligation sits on the side that can hold it. The guest kernel is *inside* the
untrusted set precisely because a microVM gives the guest its own kernel, which is also why host-side
syscall visibility is coarse (the guest services its own syscalls; their absence at a host tracepoint
is the isolation working, decision 021/027), and why the strong signals are the ones the host mediates
directly: the guest's network at its tap and its resources at its cgroup. "Trusted" here means
*assumed sound*, not *audited*, the jailer + seccomp narrow the VMM's own attack surface as defense
in depth, but they are not a substitute for KVM.

**What proves it.** The boundary is not asserted, it is exercised (a core property). Escape → the
`vmm` jail-escape tests (P6.6); resource exhaustion → the cgroup caps (`memory.max`/`cpu.max`/
`pids.max`, P6.8) plus the derived per-drive **IO-bandwidth bound** (P15.7, decision 013's
"derived defaults, not `Limits` knobs", a virtio-blk rate limiter so a disk-thrashing guest can't
starve a co-resident run); network exfiltration/flood → deny-by-default egress enforced at the tap
(decision 025, P4.7/P15.3); observation evasion → the guest can't reach host-kernel eBPF (P15.2);
leak-on-death → the cgroup-owned lifetime + sweep (decisions 014/016); clone state-bleed → per-clone
overlay + RAM (P15.4). The consolidated proof is that these hold **together** against one hostile
guest doing its worst on every axis at once (P15.1, P15.3).

**Assumptions and residual risk (explicitly out of the boundary).** KVM and the host CPU's
virtualization; the host kernel; micro-architectural side channels (Spectre-class, timing) between
co-resident guests, which a hoster placing high-sensitivity workloads accounts for at the scheduling
layer it owns; and *fair* scheduling across runs, the engine bounds a run's resource use but does not
promise fairness, which is the hoster's scheduler.

**Relationship to prior decisions.** This closes what decision 016 (the engine/hoster line) and
decision 022 (multi-tenant safety = per-run isolation, proven by the suite) opened: 016 is one facet
(privileged tools can't be weaponized), 022 defined the multi-tenant *claim*, and this records the
*whole* boundary the claim rests on. Any future privileged surface inherits it; any change that moves
observation or policy *into* the guest, or trusts guest-side software for a security property,
contradicts this decision by construction.
