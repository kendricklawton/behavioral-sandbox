# 038. Host hardening is the hoster's baseline; the engine advises, it does not enforce *(2026-07-22)*

**Context.** The [threat model](../threat-model.md) is honest that two things sit *outside* the
engine's boundary: micro-architectural side channels (Spectre-class, timing) between co-resident
guests, and fair scheduling across runs under contention. Both are the hoster's, at the scheduling
and placement layer it owns (decision 029; the "engine, not platform" property). That is correct,
but it is stated only as an *exclusion*. An operator about to place mutually-distrusting tenants on
shared hardware reads "not addressed here" and is left with no answer to the next question: what,
concretely, should the host underneath the engine be doing? Firecracker itself publishes a
production-host security checklist for exactly this reason; this engine has shipped none. To an
evaluator, "documented as out of scope" and "we have no posture" look identical, and the second is
worse than the first.

**Decision.** Keep the boundary where it is (host hardening is the hoster's), but stop shipping it
as a bare exclusion: **document a recommended baseline, and have `agent doctor` advise on it.** The
engine does not, and cannot, enforce micro-architectural isolation from where it sits (host-side
eBPF observes syscalls, the tap, and the cgroup, not cache timing), so this is advice and a
recommended floor, never an enforced control. The baseline a hoster running mutually-distrusting
tenants should meet:

- **A dedicated, single-purpose worker host.** The privileged half (the jailer, the VMM, the
  host-side probes) runs on a host whose only job is running sandboxes, so a host compromise has no
  other tenant to reach.
- **SMT off, or core scheduling on.** Sibling hyperthreads share micro-architectural state; either
  disable SMT, or use the kernel's core scheduling so two mutually-distrusting guests never share a
  physical core.
- **KSM off.** Kernel same-page merging across guests is a documented timing side channel; the
  engine already gets its cross-clone memory sharing from a read-only base disk and a copy-on-write
  snapshot file (decision 009), so KSM buys it nothing and costs isolation.
- **CPU-vulnerability mitigations left on.** Do not boot the worker with `mitigations=off`; keep the
  microcode current.
- **A patched host kernel within the supported floor.** The floor (`x86_64`, kernel >= 5.15) is
  already hard in `agent doctor` (decision 032); *patching* the substrate within that floor is the
  operator's half of the contract (this is the same line `security.md` already draws).

`agent doctor` gains an **advisory** surface for the machine-checkable parts of this: it reads
`/sys/devices/system/cpu/vulnerabilities/*`, the SMT state, and the KSM state, and **warns** on an
unmitigated or side-channel-exposed host. It is advisory on purpose: a single-tenant dev box with
SMT on is perfectly fine, so a hard refusal there would be security theater that breaks the common
case. The existing hard-floor rows (architecture, kernel LTS) stay hard; these new rows advise.

**Alternatives considered.**
- **Enforce it: refuse to boot on an unhardened host.** Rejected. The engine cannot verify true
  micro-architectural isolation from the host side, so a refusal would rest on proxy signals (is SMT
  on?) that are legitimate to trip on a single-tenant host. A hard gate here claims a guarantee the
  engine does not have and breaks honest use; an advisory tells the truth.
- **Stay silent (the status quo).** Rejected. "Out of scope" with no baseline reads as a gap to any
  serious evaluator. A recommended baseline plus a doctor advisory closes the gap without
  overclaiming a control the engine does not hold.
- **Ship a full CIS-style host benchmark.** Rejected as platform scope creep. The baseline here is
  the short list of controls that actually bound *cross-tenant* leakage for this specific engine, not
  a general-purpose hardening guide the hoster can get elsewhere.

**Consequences and notes.**
- **Recorded won't-dos (the scheduling layer stays the hoster's).** RAM/CPU oversubscription ratios,
  NUMA pinning, and placement/packing are the hoster's scheduler, not engine work, and get no box.
  The engine *measures* density (the memory-sharing curve in `docs/benchmarks.md`) so a hoster can
  size its own packing; it does not schedule. This is the same line the threat model already draws
  for co-resident fairness.
- **The advisory is the only new code, and it is a box, not this change.** This decision and its
  reader page (`docs/host-hardening.md`) ship as prose now; the `agent doctor` rows (reading
  `/sys/devices/system/cpu/vulnerabilities/*`, SMT, KSM off `crates/vmm/src/doctor.rs`) are their own
  roadmap box, so the deferral is tracked, not buried in this annotation.
- **No boundary moved.** Nothing here puts a security control inside the guest or claims the engine
  now defends a channel it does not. The trust root is unchanged: trust the host, and this is guidance
  on making that host worth trusting.

**As shipped.** `docs/host-hardening.md` (the reader-facing baseline checklist) and this decision
ship as documentation; the machine-checkable advisory in `agent doctor` is tracked as a roadmap box.
