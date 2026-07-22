# Host hardening

The engine isolates each run behind a KVM microVM and observes it from the host. What it cannot do,
from where it sits, is defend against **micro-architectural side channels** between two guests that
share physical CPU resources, or promise **fair scheduling** across runs under contention. Both live
in the layer *beneath* the engine, the host and its scheduler, which is the hoster's (see the
[threat model](./threat-model.md#assumptions-and-residual-risk) and
[decision 029](./adr/029-the-whole-security-boundary-what-s-trusted-what-the.md)). This page is the
recommended baseline for that layer when you place **mutually-distrusting tenants on shared hardware**.

It is advice, not an enforced control: the engine measures and observes, it does not reach into the
CPU's micro-architecture. `agent doctor` will **advise** on the machine-checkable parts (it warns; it
does not refuse), because a single-tenant dev box that trips these is perfectly fine. The rationale is
[decision 038](./adr/038-host-hardening-is-the-hosters-baseline-doctor-advises.md).

## The baseline

- **Run on a dedicated, single-purpose worker.** The privileged half (the jailer, the VMM, the
  host-side probes) belongs on a host whose only job is running sandboxes, so a host compromise has
  no other tenant to reach.
- **Disable SMT, or enable core scheduling.** Sibling hyperthreads share micro-architectural state.
  Either turn SMT off, or use the kernel's core scheduling so two mutually-distrusting guests never
  share a physical core.
- **Turn KSM off.** Kernel same-page merging across guests is a documented timing side channel, and
  the engine does not need it: cross-clone memory sharing already comes from a read-only base disk and
  a copy-on-write snapshot file
  ([decision 009](./adr/009-snapshots-are-self-contained-bundles-restored-by.md)), so KSM only costs
  isolation.
- **Leave CPU-vulnerability mitigations on.** Do not boot the worker with `mitigations=off`, and keep
  the microcode current.
- **Patch the host kernel.** The supported floor (`x86_64`, kernel >= 5.15) is enforced hard by
  `agent doctor` ([decision 032](./adr/032-supported-platforms-two-architectures-a-security.md));
  keeping it *patched* within that floor is your half of the contract, the same line
  [Security](./security.md#what-is-not-a-security-bug) already draws.

## What stays yours (the scheduling layer)

The engine gives you the containment primitive and the measurements to size a fleet; it does not
schedule one. **Oversubscription ratios, NUMA pinning, and placement/packing** are your scheduler's
job, not the engine's. The engine measures memory-sharing density so you can size your own packing
(see [Benchmarks](./benchmarks.md#memory-sharing-density-how-many-concurrent-microvms-before-it-degrades)),
but which run lands on which core, and how far you overcommit, is a policy only you can set. This is
the same "engine, not platform" line the threat model draws for co-resident fairness.

## Where the engine helps

- `agent doctor` reports the hard floor (architecture, kernel LTS) and will **advise** on the SMT,
  KSM, and CPU-vulnerability state of the host.
- The audit record is host-signed
  ([decision 034](./adr/034-the-integrity-model-a-host-signed-record-and-the.md)), so what a run did
  is verifiable off-host even if the record is later relayed through untrusted hands. Custody of the
  signing key is yours; see the [threat model](./threat-model.md#record-integrity-beyond-the-guest).
