# 019. Multi-tenant safety is airtight per-run isolation, proven by the containment suite *(2026-07-15)*

**Context.** A hoster places untrusted code from mutually-distrusting callers on one shared host, and
the engine has to make that safe while staying ignorant of tenants: no team / account / tenant concept
enters this repo, because that is the hoster's control plane. Two questions fall out of that constraint,
what the engine owes a hoster who multiplexes distrusting callers, and how "safe for multi-tenant
hosting" is defined so it can be proven rather than asserted.

The pull of the obvious alternatives is real. A tenant or team id inside the engine would let it build
per-tenant cgroup trees and tenant-scoped policy, but it moves the security boundary into a concept the
engine must never hold and couples the engine to one hoster's control plane. Leaning on the microVM
boundary alone is the other temptation, but a Firecracker-level exploit, a resource storm, or a leaked
VMM crosses to the host or a co-resident run. Per-run isolation is the leverage that resolves both: it
lets a hoster multiplex distrusting callers with zero engine-side tenancy, keeping the engine embeddable
and self-hostable, it works on a lone KVM host with no cloud at all.

**Decision.** Multi-tenant safety is **airtight per-run isolation, not tenant awareness.** The engine's
contract is "any run is fully contained from every other run and from the host"; the hoster decides
whose run is whose. The confinement stack that delivers it is tenant-agnostic by construction:
- **Jailer**, Firecracker runs under its jailer: chroot, uid/gid drop, PID/mount/network namespaces,
  seccomp; the `Sandbox` surface jails by default (decision 012).
- **cgroups**, a per-VM v2 cgroup caps `cpu.max` + `memory.max` (decision 010), with a whole-tree
  `cgroup.kill` (decision 011). `pids.max` is added too (host-side defense in depth: a guest fork-bomb
  is already memory-bounded, but a hypervisor-level exploit forking *host* processes is capped). The
  last leg, bounding guest **IO bandwidth** so a disk-thrashing run can't starve a co-resident one, is
  still to land (Firecracker's per-drive rate limiter, or host `io.max`).
- **Network**, deny-by-default egress: a tap with no route to the world, allow-listed explicitly
  (decision 008).
- **No-leak teardown**, cgroup-owned VM lifetime + a sentinel that outlives the driver + the orphan
  sweep, so a killed / panicked / timed-out run releases its VMM, jail, cgroup, and scratch (decision
  011).
- **Engine/hoster line**, the engine's privileged tools can't be weaponized; deployment (scheduling,
  per-identity GC, base hardening, dividing the address pool) is the hoster's (decision 013).

**"Safe for multi-tenant hosting" is defined as exactly one thing: the containment suite is green.** A
single hostile guest tries to escape the VM, reach the network, exceed its cpu / mem / pid / io caps,
exhaust the host, and interfere with a co-resident run, and each attempt must fail. The constituents
pass individually already (escape, fork-bomb / mem-hog, egress, no-leak teardown); the suite
consolidates them and adds the co-resident-interference assertion. Defining safety this way makes the
gate objective and testable rather than asserted.

**Consequences.** The public contract is preserved. No tenant field anywhere. `Sandbox::boot` / `exec`
/ `exec_with_files`, `RunResult`, `VmmError` + `ErrorKind` (Infra / Transport / Guest), and `Limits`
are unchanged. The `pids.max` / `io.max` caps land as **internal, derived defaults**, not new `Limits`
knobs, so nothing breaks; surfacing them as fields later would be an additive, marked `api:` change. The
residual gap is the IO-bandwidth cap, which stays open until the per-drive rate limiter lands: until
then a disk-thrashing run can still contend for host IO with a co-resident one. Everything else in the
stack fails closed, the containment suite is what keeps that honest.

**Alternatives considered.**
- **A tenant / team id in the engine (per-tenant cgroup trees, tenant-scoped policy).** Rejected: it
  moves the security boundary into a tenant concept the engine must never hold, and couples the engine
  to one hoster's control plane. Isolation is per *run*; the hoster maps runs to tenants.
- **Treat "microVM boundary only" as sufficient for multi-tenant.** Rejected: a Firecracker-level
  exploit, a resource storm, or a leaked VMM crosses to the host or a co-resident run. The jailer +
  cgroups + no-leak teardown are what make the microVM boundary trustworthy under a hostile guest.
- **Expose `pids`/`io` as `Limits` knobs now.** Deferred: a hard internal default contains the host
  without a public-API change; a caller-tunable knob can be added additively later if a real need
  appears.
