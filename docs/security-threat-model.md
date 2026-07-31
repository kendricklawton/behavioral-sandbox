# Threat model

This is the model the engine is *designed against*: the assets it aims to protect, the boundary it
trusts, the adversary it assumes, and, attack class by attack class, the mechanism intended to
contain it and the test that exercises that mechanism today.

The core model: **untrusted code runs inside a KVM microVM, and everything that observes or
constrains it runs on the host.** The boundary itself is enforced by the CPU through KVM, which this
project depends on rather than establishes.

## Status of this model

Nothing in this document has been reviewed by anyone outside the project. There has been no external
security audit and no independent adversarial testing. The engine has one maintainer, no tagged
release, and no production use.

A threat model is a hypothesis about what an attacker will try. The classes below are the ones
considered so far, not a demonstration that the list is complete, and the mechanisms below are the
ones intended to contain them, not mechanisms proven sufficient. The single most likely defect in
this page is an attack class nobody thought of.

Read [Assumptions and residual risk](#assumptions-and-residual-risk) before relying on anything here.

## Objectives

What the engine is trying to achieve, in priority order. These are the aims the design serves, not
properties established by this document:

1. **The host.** A run should not be able to escape its microVM, exhaust the host, or leave host
   resources behind, including when its driver process dies without cleanup.
2. **Every other run.** Runs should be contained from each other: no state, memory, network, or
   resource bleed between two sandboxes on one host. (*Whose* run is whose is the hoster's concern,
   not the engine's.)
3. **The audit record's integrity.** What the host reports a run did should reflect what the host
   observed, and once finalized the record is **host-signed**, so a consumer can detect alteration
   made after it leaves the producing host (see [Record integrity beyond the
   guest](#record-integrity-beyond-the-guest) for what that does and does not establish).
4. **Deny-by-default.** A run with no explicit policy is configured to reach no network and hold
   minimal capability, and each allowance is recorded.

## The trust boundary

- **Trusted** (inside the boundary): the host CPU's virtualization (KVM), the host kernel, and the
  driver running on the host, the VMM process, the jailer, and the host-side eBPF probes. All
  security-relevant observation and policy live here.
- **Not trusted** (outside): everything inside the guest. The untrusted code, the guest kernel, and
  the in-guest agent that carries exec and I/O. **The in-guest agent is a convenience, never a
  security boundary**: a hostile guest is assumed to control it, and its own guest kernel, completely.

The boundary and the crossings the host mediates, as a picture:

```
        HOST  (trusted)                  boundary             GUEST  (untrusted)
   ----------------------------      = the CPU (KVM) =      ----------------------------
    driver + VMM + jailer                  |                 untrusted code
    host-side eBPF probes                  |                 guest kernel
    cgroup controller                      |                 in-guest agent (convenience)
                                           |
    crossings the host mediates:           |
      vsock    exec + stdio        <------->|   carried by the in-guest agent
      tap      all guest packets   <------->|   observed by tc/eBPF, policed deny-by-default
      block    rootfs RO / in RO / out RAD >|   no host filesystem is handed to the guest
      cgroup   mem/cpu/pids/io caps ------->|   CPU is also metered from eBPF
   ----------------------------                       ----------------------------
   Every security-relevant observation and policy sits on the HOST side of every crossing.
```

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

Each row names the mechanism intended to contain the attack and the test that exercises it. What
none of these rows cover is in [Assumptions and residual
risk](#assumptions-and-residual-risk); a passing test is scoped as described in [Status](./introduction.md#status).

| Attack | Contained by | Exercised by |
|--------|--------------|-----------|
| Escape the isolation boundary | Hardware virtualization (KVM); the jailer (chroot, uid/gid drop, seccomp, namespaces) as defense in depth | the jail-escape tests in `vmm`'s `confinement.rs` |
| Resource exhaustion (memory / CPU / pids / IO) | The per-VM cgroup (`memory.max`, `cpu.max`, `pids.max`); a derived per-drive IO-bandwidth bound (a virtio-blk rate limiter); guest processes run against the guest kernel's scheduler, not as host threads | the fork-bomb/mem-hog and consolidated exhaustion tests in `confinement.rs` |
| Network exfiltration / flood | Deny-by-default egress policy enforced in-kernel at the tap, armed before the guest's first packet; drops are counted | `net_enforce.rs`; the hostile-guest and flood tests in `confinement.rs` |
| Evade / disable the observation | The probes run in the **host** kernel and the tap monitor on the **host** end of the tap; the guest's four crossings (vsock, tap, block devices, cgroup) name no BPF program or map | `hardening.rs` |
| Leak a run on driver death | A cgroup-owned lifetime + sentinel kills the VM when its driver dies; an own-euid orphan sweep reclaims residue | the sentinel and orphan-sweep tests in `confinement.rs` |
| State bleed between clones | Each restored clone has its own in-RAM overlay and guest RAM; the shared base is read-only | `snapshot.rs` |
| Secret disclosure | The code paths that log or render a run omit injected `--env` values and file contents | driver + CLI secret-handling tests |

**Note on Snapshot CPU Portability:** Firecracker snapshots preserve the producing host's vCPU CPUID state (`cpu_template` is unset by default). Cross-host snapshot restore requires matching CPU models or an explicit CPU template to avoid guest illegal instruction faults.


The consolidated suite runs these controls concurrently against one hostile guest attacking every
axis at once. Passing it is a floor, not a clearance: it exercises the attacks listed above, on the
host that ran it. Nothing here has been reviewed outside the project, and the project does not
recommend placing mutually-distrusting workloads on this engine before `v0.1.0`.

## Verify it yourself

The table above is only as useful as your ability to re-run it: the integration suite re-runs these
same checks on your own host instead of asking you to take this page's word for it. What each test
exercises is listed above; what none of them cover is in [Assumptions and residual
risk](#assumptions-and-residual-risk).

The suite is **privileged**: it boots real microVMs and attaches real probes, so it needs a host with
`/dev/kvm`, real root, `CAP_BPF` + `CAP_PERFMON`, and kernel BTF. From the repo root:

```console
sudo -E ./ci-privileged.sh
```

The wrapper handles the environment a `sudo` run otherwise stacks by hand, and the gate *refuses*
to run misconfigured rather than letting capability-gated tests skip themselves into a hollow
green. The mechanics live in
[CI gates](./contributing-ci.md).

This runs the VM-boot and probe-attach integration tests, including the containment suite. The
everyday `cargo xtask ci` gate is host-safe
and runs everywhere, but it does **not** include this suite; the containment suite lives behind the
privileged lane.

What each claim maps to:

- **Escape, exhaustion, egress, co-resident interference** are `crates/vmm/tests/confinement.rs`:
  `driver_death_cannot_leak_a_vm`, `kill_handle_unblocks_a_wedged_exec`,
  `guest_mem_hog_is_bounded_by_the_cgroup`, `guest_fork_bomb_is_bounded_by_the_cgroup`,
  `sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir`, and the consolidated
  `a_hostile_run_cannot_starve_or_observe_a_co_resident_run` (one hostile guest attacking every axis
  at once).
- **No host leak across runs** is `crates/vmm/tests/boot.rs`: `repeated_boots_leave_no_leaks` (scratch
  dirs, orphan VMMs, netns, process-local fds and threads all return to baseline) and
  `fd_footprint_per_vm_stays_within_budget_and_never_leaks`.

## Record integrity beyond the guest

The property above (the guest can neither forge nor evade the observation) is one half of
"tamper-evident." The other half concerns a **different** adversary than the hostile guest this model
otherwise assumes: a party that alters the record **after** it leaves the producing host, a
compromised relay, an operator, or the transport a supervisor reads it over. To close that gap the
loader **signs** each finalized record with a host key the guest never sees (an `ed25519` detached
signature over the canonical record bytes), and ships a verify path (`ekvm verify`, the
library `verify`, and the daemon's signed `trace` reply).

- **What the signature proves:** the record was not altered after the producing host signed it.
- **What it does not prove:** that a **compromised producing host** told the truth. A host that holds
  the signing key at signing time can sign a consistent lie; the signature authenticates *"this host
  attests to these bytes,"* not *"these bytes are true."* This is the same trust root the boundary
  already fixes (trust the host, not the guest), now verifiable off-host, not a new anchor. Detecting a
  lying host is the hoster's key custody and host hardening, outside this engine.
- **Custody is the hoster's** (engine, not platform): the engine generates a host key on first use and
  signs; tenant keys, a KMS, key distribution, and revocation are the hoster's. A record's `key_id`
  names the signing key, so a rotated key doesn't invalidate records already signed.
- **Append-only, so tail truncation is undetectable in isolation.** A session's records form a
  hash chain (each commits to the prior record's hash), so an edited, reordered, inserted, or
  middle-deleted run is caught. What the chain alone cannot catch is **truncation of the tail**: a
  consumer handed only a truncated prefix cannot distinguish it from the whole sequence, since every
  link it holds is intact. Detecting a dropped tail needs an out-of-band anchor, the latest expected
  record hash or run count tracked by the consumer, which is the hoster's, the same custody line as
  the signing key.

See [`ekvm verify`](./cli-commands.md#ekvm-verify) for the verify path.

## Assumptions and residual risk

Explicitly assumed sound, and therefore *out* of the boundary:

- **KVM and the host CPU's virtualization.** A hypervisor-level or CPU vulnerability that breaks VM
  isolation is outside this model; the jailer + seccomp are defense in depth that narrow the VMM's
  own attack surface, not a substitute for KVM.
- **The host kernel**, including its eBPF and cgroup implementations.
- **Micro-architectural side channels** (Spectre-class, timing) between co-resident guests are not
  addressed here; a hoster placing high-sensitivity workloads should account for them at the
  scheduling layer it owns.
- **Availability of a co-resident run under contention** is bounded (cgroup + egress caps), but the
  engine does not promise fair scheduling across runs, that is the hoster's scheduler.
- **The e2fsprogs output-extraction tools.** Bulk outputs come back by running `e2fsck` and
  `debugfs` over a guest-written ext4 image: complex C parsers fed attacker-controlled bytes, with
  the driver's own privileges. The calls are bounded in wall time and output bytes, and the
  extracted tree is symlink-sanitized, but a memory-corruption bug in those tools is not contained
  today. Running them under dropped privileges is a planned hardening step (using an external `setpriv`-style dependency or dedicated helper).

## Out of scope (engine, not platform)

Per-run containment is the engine's concern; tenancy is not. Tenant authentication, authorization,
quotas, billing, fleet scheduling, and a management dashboard are the **hoster's** responsibility,
not a gap in the engine. The engine's own scope is narrower and mechanical: its privileged tools are
euid-scoped, and its defaults self-limit (no network route out, a dropped-uid jail, an own-euid
sweep). Turning that into a multi-tenant service is the hoster's job, and this project makes no claim
about whether the result would be safe.

See [Security](./security.md) for what counts as a security bug and how to report one.

---

## Host hardening baseline

When hosting mutually-distrusting workloads on shared hardware: dedicate the worker to sandbox
execution; disable SMT or enable core scheduling, so microVMs can't share a physical core's
micro-architectural state; keep KSM off, so page dedup can't become a cross-VM timing channel; and
keep CPU mitigations (`mitigations=auto`) and host microcode current. These are the hoster's
knobs, not the engine's (side channels sit in residual risk above); `ekvm doctor` flags each one
it can check.

---

## Supply chain & provenance

The guest kernel and the Alpine base rootfs are pinned by sha256 and verified on fetch
(`xtask/src/artifacts.rs`). The package closure installed on top of that base is **not** hash-pinned
on the live-CDN path: it floats within one Alpine branch, because branch repos carry only the latest
revision per package, so an exact `pkg=ver-rN` pin would fail the build the day upstream bumps rather
than reproduce it (`GUEST_PACKAGES` in `xtask/src/rootfs.rs`). What holds instead is a record and two
checks on it: `xtask/rootfs-packages.lock` carries the resolved closure, `build-rootfs --verify` (run
by the privileged gate) fails on any drift from it, and `.github/workflows/rootfs-packages.yml`
rebuilds weekly so a bump arrives on a schedule. `--verify` also builds the image twice and compares
hashes, so one host reproduces its own build; across hosts the image hash still follows the mke2fs
version.

`cargo xtask vendor` snapshots the whole input set, the resolved `.apk` closure included, into an
offline mirror with a sha256 manifest. That is where the packages do get pinned by hash, so an
air-gapped rebuild is both independent of the network and more reproducible than the live-CDN one.

A guest package is on the untrusted side of the KVM boundary: a compromised interpreter in the guest
is what the sandbox is built to contain, not a break of it. The exposure it does carry is
distribution. `cargo xtask dist` bakes `rootfs-guest.ext4` into the signed release tarball, so
operators run the image from the last release until the next one, and nothing here scans that closure
against Alpine's security database.
- **Dependency Auditing**: CI runs `cargo deny` to check for security advisories and enforce license policy across the dependency tree.
