# 022. Multi-tenant safety is airtight per-run isolation, proven by the containment suite *(2026-07-15)*

**Problem.** A hoster wants to place untrusted code from mutually-distrusting callers on one shared
host. The engine must make that safe **without ever learning about tenants**: no team / account /
tenant concept may enter this repo (that is the hoster's control plane). The open questions are what
the engine owes, and how "safe for multi-tenant hosting" is defined and proven.

**Decision.** Multi-tenant safety is **airtight per-run isolation, not tenant awareness.** The engine's
contract is "any run is fully contained from every other run and from the host"; the hoster decides
whose run is whose. The confinement stack that delivers it is already built and tenant-agnostic:
- **Jailer**, Firecracker runs under its jailer: chroot, uid/gid drop, PID/mount/network namespaces,
  seccomp (decision 012); the `Sandbox` surface jails by default (decision 015).
- **cgroups**, a per-VM v2 cgroup caps `cpu.max` + `memory.max` (decision 013), with a whole-tree
  `cgroup.kill` (decision 014). `pids.max` is now added too (host-side defense in depth: a guest
  fork-bomb is already memory-bounded, P6.8, but a hypervisor-level exploit forking *host* processes is
  capped). The last leg, bounding guest **IO bandwidth** so a disk-thrashing run can't starve a
  co-resident one, is P15.7 (Firecracker's per-drive rate limiter, or host `io.max`).
- **Network**, deny-by-default egress: a tap with no route to the world, allow-listed explicitly
  (decision 008).
- **No-leak teardown**, cgroup-owned VM lifetime + a sentinel that outlives the driver + the orphan
  sweep, so a killed / panicked / timed-out run releases its VMM, jail, cgroup, and scratch (decision
  014; P6.9a).
- **Engine/hoster line**, the engine's privileged tools can't be weaponized; deployment (scheduling,
  per-identity GC, base hardening, dividing the address pool) is the hoster's (decision 016).

**"Safe for multi-tenant hosting" is defined as exactly one thing: the containment suite is green**
(Phase 15). A single hostile guest tries to escape the VM, reach the network, exceed its cpu / mem /
pid / io caps, exhaust the host, and interfere with a co-resident run, and each attempt must fail. The
constituents already pass individually (P6.6 escape, P6.8 fork-bomb / mem-hog, P4.7 egress, P6.7 /
P6.9a no-leak); Phase 15 consolidates them and adds the co-resident-interference assertion (P15.8).

**The public contract is preserved.** No tenant field anywhere. `Sandbox::boot` / `exec` /
`exec_with_files`, `RunResult`, `VmmError` + `ErrorKind` (Infra / Transport / Guest), and `Limits` are
unchanged. The `pids.max` / `io.max` caps land as **internal, derived defaults**, not new `Limits`
knobs, so nothing breaks; surfacing them as fields later would be an additive, marked `api:` change.

**Why.** Per-run isolation is the whole leverage: it lets a hoster multiplex distrusting callers with
zero engine-side tenancy, keeping the engine embeddable and self-hostable, it works on a lone KVM host
with no cloud at all. Defining safety as "the suite is green" makes the gate objective and testable
rather than asserted.

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
