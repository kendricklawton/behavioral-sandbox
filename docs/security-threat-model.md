# Threat model

This is the model the engine is *designed against*: the assets it aims to protect, the boundary it
trusts, the adversary it assumes, and, attack class by attack class, the mechanism intended to
contain it and the test that exercises that mechanism today.

The core model: **untrusted code runs inside a KVM microVM, and everything that observes or
constrains it runs on the host.** The boundary itself is enforced by the CPU through KVM, which this
project depends on rather than establishes.

## Objectives

What the engine is trying to achieve, in priority order. These are the aims the design serves, not
properties established by this document:

1. **The host.** A run should not be able to escape its microVM, exhaust the host, or leave host
   resources behind, including when its driver process dies without cleanup.
2. **Every other run.** Runs should be contained from each other: no state, memory, network, or
   resource bleed between two sandboxes on one host. (*Whose* run is whose is the hoster's concern,
   not the engine's.)
3. **The audit record's integrity.** What the host reports a run did should reflect what the host
   observed, and a finalized record can be **host-signed** (the CLI's `--record` and the daemon's
   `trace` do sign; the library hands back an unsigned record), so a consumer can detect alteration
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

```text
        HOST  (trusted)                  boundary             GUEST  (untrusted)
   ----------------------------      = the CPU (KVM) =      ----------------------------
    driver + VMM + jailer                  |                 untrusted code
    host-side eBPF probes                  |                 guest kernel
    cgroup controller                      |                 in-guest agent (convenience)
                                           |
    crossings the host mediates:           |
      vsock    exec + stdio        <------->|   carried by the in-guest agent
      tap      all guest packets   <------->|   observed by tc/eBPF, policed deny-by-default
      block    rootfs / in RO / out RW     >|   ext4 images the engine builds, never a host dir
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
risk](#assumptions-and-residual-risk).

| Attack | Contained by | Exercised by |
|--------|--------------|-----------|
| Escape the isolation boundary | Hardware virtualization (KVM); the jailer (chroot, uid/gid drop, namespaces) plus Firecracker's own built-in per-thread seccomp filters, which the driver never disables (it passes no `--no-seccomp`), as defense in depth | `boots_under_the_jailer` (`bsx-engine`'s `boot.rs`) reads the running VMM's `/proc` and asserts each wall separately: a dropped uid, `Seccomp: 2`, an empty capability set, `NoNewPrivs`, and its own mount namespace and cgroup. It reports that the walls are in force; it does not attempt an escape, and KVM escape itself is an assumption rather than something this suite tests |
| Resource exhaustion (memory / CPU / pids / IO) | The per-VM cgroup (`memory.max`, `cpu.max`, `pids.max`); a derived per-drive IO-bandwidth bound (a virtio-blk rate limiter); guest processes run against the guest kernel's scheduler, not as host threads | the fork-bomb/mem-hog tests in `confinement.rs`; `all_exhaustion_vectors_are_bounded_by_the_cgroup_and_egress_policy` in `bsx-probes-loader`'s `hardening.rs` |
| Network exfiltration / flood | Deny-by-default egress policy enforced in-kernel at the tap, armed before the guest's first packet; drops are counted | `net_enforce.rs`; the hostile-guest and flood tests in `confinement.rs` |
| Evade / disable the observation | The probes run in the **host** kernel and the tap monitor on the **host** end of the tap, so no guest crossing addresses a BPF program or map | `a_guest_cannot_see_or_disable_the_host_side_probes` (`hardening.rs`) boots a guest, has it list `/sys/fs/bpf` (0 entries), and asserts its UDP flow was still recorded with no coverage gap |
| Leak a run on driver death | A cgroup-owned lifetime + sentinel kills the VM when its driver dies; an own-euid orphan sweep reclaims residue | the sentinel and orphan-sweep tests in `confinement.rs` |
| State bleed between clones | Each restored clone has its own in-RAM overlay and guest RAM; the shared base is read-only | `snapshot.rs` |
| Secret disclosure | The code paths that log or render a run omit injected `--env` values and file contents | `injected_secrets_reach_no_observable_surface` (`crates/engine/src/exec.rs`) and `injected_secrets_never_reach_the_console_or_host_logs` (`crates/engine/tests/sandbox.rs`), both engine-side; the CLI's own `--env` rendering has no test of its own |

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
green. The mechanics live in `AGENTS.md`.

This runs the VM-boot and probe-attach integration tests, including the containment suite. The
everyday `cargo xtask ci` gate is host-safe
and runs everywhere, but it does **not** include this suite; the containment suite lives behind the
privileged lane.

What each claim maps to:

- **Escape, exhaustion, egress, co-resident interference** are `crates/engine/tests/confinement.rs`:
  `driver_death_cannot_leak_a_vm`, `kill_handle_unblocks_a_wedged_exec`,
  `guest_mem_hog_is_bounded_by_the_cgroup`, `guest_fork_bomb_is_bounded_by_the_cgroup`,
  `sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir`, and the consolidated
  `a_hostile_run_cannot_starve_or_observe_a_co_resident_run` (one hostile guest attacking every axis
  at once).
- **No host leak across runs** is `crates/engine/tests/boot.rs`: `repeated_boots_leave_no_leaks` (scratch
  dirs, orphan VMMs, netns, process-local fds and threads all return to baseline) and
  `fd_footprint_per_vm_stays_within_budget_and_never_leaks`.

## Record integrity beyond the guest

The row above (observation the guest does not address) is one half of
"tamper-evident." The other half concerns a **different** adversary than the hostile guest this model
otherwise assumes: a party that alters the record **after** it leaves the producing host, a
compromised relay, an operator, or the transport a supervisor reads it over. To close that gap, a
finalized record is **signed with a host key the guest has no path to** (an `Ed25519` detached
signature over the canonical record bytes), and a verify path ships with it (`bsx verify`, the
library `verify`, and the daemon's signed `trace` reply).

Signing is the *caller's* step, not the loader's: `SandboxProbes::collect` returns an unsigned
`RunRecord`, and `HostKey` signs it in the CLI's record path and in the daemon's `trace`. An
embedder driving `bsx-probes-loader` directly gets no signature. A run signs when it writes a
record at all, which is `--record` or an operator's `records_dir`.

- **What a verifier establishes:** `verify_entry` fails closed on a bad signature, a malformed
  envelope, or a `key_id` outside the trusted set, so a record it accepts was not altered after the
  producing host signed it. That is conditional on the consumer holding the right trusted key.
- **What it does not prove:** that a **compromised producing host** told the truth. A host that holds
  the signing key at signing time can sign a consistent lie; the signature authenticates *"this host
  attests to these bytes,"* not *"these bytes are true."* This is the same trust root the boundary
  already fixes (trust the host, not the guest), now verifiable off-host, not a new anchor. Detecting a
  lying host is the hoster's key custody and host hardening, outside this engine.
- **Custody is the hoster's** (engine, not platform): the engine generates a host key on first use and
  signs; tenant keys, a KMS, key distribution, and revocation are the hoster's. A record's `key_id`
  names the signing key, so a rotated key doesn't invalidate records already signed. What the engine
  does check is the key *file*: another local user's key, one others can read, one in a directory
  others can write, and a non-regular file at the path are each a refusal before the boot, on the
  same terms as the config file that names it. See
  [Setting `signing_key`](./cli-config.md#setting-signing_key).
- **Append-only, so tail truncation is undetectable in isolation.** A daemon session's records form
  a hash chain: the first is an unchained anchor and each one after it commits to the prior record's
  hash, so `verify_chain` rejects an edited, reordered, inserted, or middle-deleted run — `bsx
  verify` runs that check on a file holding the sequence one envelope per line, and the library
  form is `verify_chain` in `bsx-record`. One limit on the chain's reach: only the daemon's
  `trace` path chains (`bsx run --record` writes one standalone record). What the chain
  cannot catch even then is **truncation of the tail**: a
  consumer handed only a truncated prefix cannot distinguish it from the whole sequence, since every
  link it holds is intact. Detecting a dropped tail needs an out-of-band anchor, the latest expected
  record hash or run count tracked by the consumer, which is the hoster's, the same custody line as
  the signing key.

See [`bsx verify`](./cli-commands.md#bsx-verify) for the verify path.

## Assumptions and residual risk

Explicitly assumed sound, and therefore *out* of the boundary:

- **KVM and the host CPU's virtualization.** A hypervisor-level or CPU vulnerability that breaks VM
  isolation is outside this model; the jailer and Firecracker's own seccomp filters are defense in
  depth that narrow the VMM's own attack surface, not a substitute for KVM.
- **The host kernel**, including its eBPF and cgroup implementations.
- **Micro-architectural side channels** (Spectre-class, timing) between co-resident guests are not
  addressed here; a hoster placing high-sensitivity workloads should account for them at the
  scheduling layer it owns.
- **Availability of a co-resident run under contention** is bounded (cgroup + egress caps), but the
  engine does not promise fair scheduling across runs, that is the hoster's scheduler.
- **What a configured egress path does not bound.** A run given a gateway
  ([decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster))
  is policed at the tap by destination address, port, and protocol, which leaves four things to
  whatever built the uplink. Hostnames are not expressible at that layer, so a CDN behind rotating
  addresses cannot be allow-listed by name and **DNS tunnelling through an allowed resolver is not
  addressed**; hostname policy belongs in a hoster's proxy. The rule table is a fixed size, because
  the classifier's loop bound must be a compile-time constant. Non-first IP fragments arrive with no
  port, so a port-qualified rule denies them (closed, but surprising). And the tap's world-to-guest
  direction passes unconditionally, so what can reach a guest is whatever the uplink exposes. Two
  sandboxes sharing a hoster's bridge are separated by that bridge's configuration and by each
  sandbox's own egress policy, not by anything the engine does.
- **The bulk-output image parser.** Bulk outputs come back by parsing a wholly guest-written ext4
  image, which is attacker-chosen bytes fed to a filesystem parser. That parser is `ext4-view`, read
  only and `#![forbid(unsafe_code)]`, running in-process on the host path, so the surface is a
  memory-safe reader rather than `e2fsck` and `debugfs` holding the driver's privileges; `cargo
  xtask fuzz output_image` is what exercises it on malformed images. The walk the engine puts on top
  is bounded in bytes, entries, depth, and wall time, and the extracted tree is symlink-sanitized.

  **Memory safety does not exclude an allocation sized from attacker bytes, and that class is not
  hypothetical here.** The parser reads through a trait, so it never learns an image's real length
  and sizes its block-group table from the superblock's own claim; separately, `read_link` sizes a
  buffer from an inode's claimed length. Either allocation **aborts** the process rather than
  unwinding, which no `catch_unwind` converts back into a typed error and which takes every sandbox
  sharing that driver down with it. Both are refused before they reach an allocator:
  `refuse_impossible_geometry` rejects a filesystem larger than the file holding it, and the walk
  skips a symlink claiming a target longer than `PATH_MAX`. `cargo xtask fuzz output_image` applies
  the same two bounds through `bsx-engine`'s `fuzzing` feature rather than its own copies, so a
  target cannot go green on a bound production has lost. Both were found by that target.

  What remains: further logic bugs in the reader or the walk, and upstream does not fuzz, so the
  coverage here is this repo's target and nothing more.
- **Observation fails open, so a thin record is not a quiet run.** Each axis that cannot attach
  (no BTF, no `CAP_BPF`/`CAP_PERFMON`, no object built) degrades to a recorded `AxisGap` and the run
  proceeds, so a record can cover less than the table above implies. It says so in its own coverage
  section, and a reader must actually check that section rather than read an empty axis as quiet.
  Egress *enforcement* is the deliberate exception: `--allow` that cannot arm the tap is a refusal.
- **Fuzzing is nightly, not continuous.** The libFuzzer targets `FUZZ_TARGETS` in
  `xtask/src/main.rs` names cover the untrusted-input decoders (the guest channel, the daemon wire,
  the signed-record envelope, the eBPF-boundary parsers, the egress rule parser, the guest-written
  output image, and the `.bsx.toml` config parser) on a nightly schedule, bounded per target at
  fifteen minutes. There is no OSS-Fuzz or equivalent
  continuous tier, and some corpora are thin, so depth on any one target is limited.

## Out of scope (engine, not platform)

Per-run containment is the engine's concern; tenancy is not. The platform layer above it, enumerated
once in [Where the engine ends](./embedding-scope.md), is the **hoster's** responsibility, not a gap
in the engine. The engine's own scope is narrower and mechanical: its privileged tools are
euid-scoped, and its defaults self-limit (no network route out unless one is configured, a
dropped-uid jail, an own-euid sweep). Turning that into a multi-tenant service is the hoster's job, and this project makes no claim
about whether the result would be safe.

See [Security](./security.md) for what counts as a security bug and how to report one.

---

## Host hardening baseline

When hosting mutually-distrusting workloads on shared hardware: dedicate the worker to sandbox
execution; disable SMT or enable core scheduling, so microVMs can't share a physical core's
micro-architectural state; keep KSM off, so page dedup can't become a cross-VM timing channel; and
keep CPU mitigations (`mitigations=auto`) and host microcode current. These are the hoster's
knobs, not the engine's (side channels sit in residual risk above); `bsx doctor` flags each one
it can check.

---

## Supply chain & provenance

Every *artifact* the build downloads is pinned by sha256 and verified on fetch: the guest kernel and
the demo boot rootfs (`xtask/src/artifacts.rs`), the Alpine minirootfs and `apk-tools-static`
(`xtask/src/rootfs.rs`). The guest package closure `apk` then installs on top of that base is the
exception, covered below. The Firecracker binary is pinned too but never fetched by this project:
the operator installs it, and `bsx doctor` compares what is on `PATH` against the pin.

One of them is served from this project rather than from its origin. `apk-tools-static` is the
static `apk` the build executes on the host to populate the guest image, and an Alpine branch repo
keeps only the newest revision of each package, so a pinned filename 404s the day upstream bumps: it
did on 2026-08-02, breaking every fresh clone while cached machines kept building. It now comes from
this repo's `build-inputs` release. Mirroring changed no bytes, and the pinned sha256 is the one that
was there when the file came from Alpine, so the copy is checkable against upstream rather than
trusted on this project's word. The trade is explicit: availability of a build input now depends on
this repo, and a reader auditing the supply chain should count that as one more thing to trust.

The package closure installed on top of that base is **not** hash-pinned
on the live-CDN path: it floats within one Alpine branch, because branch repos carry only the latest
revision per package, so an exact `pkg=ver-rN` pin would fail the build the day upstream bumps rather
than reproduce it (`GUEST_PACKAGES` in `xtask/src/rootfs.rs`). What holds instead is a record and two
checks on it: `xtask/rootfs-packages.lock` carries the resolved closure, `build-rootfs --verify`
fails on any drift from it, and `.github/workflows/rootfs-packages.yml`
rebuilds weekly so a bump arrives on a schedule. `--verify` also builds the image twice and compares
hashes, so one host reproduces its own build. Both run nightly: `privileged_preflight` builds the
rootfs with verify on, so `cargo xtask ci-privileged` is the gate that enforces them.

Across hosts is a weaker claim, and until 2026-08-02 it was weaker than this page said. Two hosts on
the same commit and the same pinned toolchain built images that differed, because a release build
bakes in `panic!` location strings even with debug info off, and for std and every registry
dependency those were absolute paths under the building host's `CARGO_HOME` and rustup directory.
`xtask` now builds the guest agent under `--remap-path-prefix` for both (`cargo_reproducible` in
`xtask/src/main.rs`), mapping the toolchain's vendored std sources back onto the `/rustc/<commit>`
token rustc itself uses, which removes the builder's `CARGO_HOME` and rustup paths from the emitted
bytes.

**That was not sufficient, and the measurement says so.** On 2026-08-02, with the remap in place, an
Arch dev box (rolling, kernel 7.0.11) and the `ubuntu-24.04` runner still built different images from
the same commit. Something outside `CARGO_HOME` and the toolchain sources varies between them and has
not been identified. The leading candidate is now a specific, testable difference rather than a
vague one: the two hosts ran **different `e2fsprogs`**, the dev box 1.47.4 and the runner a
source-built 1.47.2 (the workflow builds it because the stock image sits below the
`SOURCE_DATE_EPOCH` floor). Two minor releases of the tool that writes the image, never tested
against each other. Every build now prints its `mke2fs` version beside the hash, so the comparison
is a diff of two logs rather than an archaeology exercise. A **same-host** rebuild is also not
established across time: on 2026-08-03 the same Arch box produced a different image from a tree whose
guest-agent sources, `Cargo.lock` entries for that binary, and resolved package closure were all
unchanged, and the cause of that is open too. So the property this project claims is the narrow one
`--verify` actually checks: **one host reproduces its own build, in one sitting**. Reproducibility
beyond that is an open problem here, not a feature, and an independent rebuild is not expected to
match the shipped image.

**No image hash is quoted on this page, deliberately.** The value moves with the host's filesystem
tooling and the guest package closure, so a hash written here would be a number a reader could not
reproduce and this project could not defend. `--verify` compares two builds on the spot instead,
which is a check rather than a claim.
What the release does rest on is the signed manifest: `install.sh` verifies `SHA256SUMS.sig` against
a pinned public key and never rebuilds anything. That pin ships in the same repo as the script, so
it defeats a tampered release *asset*, not a compromised repo, and
`BSX_INSECURE_SKIP_SIGNATURE=1` turns the check off for anyone who sets it. `BSX_RELEASE_PUBKEY`,
supplied out of band, is the stronger anchor.

`cargo xtask vendor` snapshots the whole input set, the resolved `.apk` closure included, into an
offline mirror with a sha256 manifest. That is where the packages do get pinned by hash, so an
air-gapped rebuild is both independent of the network and more reproducible than the live-CDN one.

A guest package is on the untrusted side of the KVM boundary: a compromised interpreter in the guest
is what the sandbox is built to contain, not a break of it. The exposure it does carry is
distribution. `cargo xtask dist` bakes `rootfs-guest.ext4` into the signed release tarball, so
operators run the image from the last release until the next one, and nothing here scans that closure
against Alpine's security database.
Rust dependencies are audited by `cargo deny` in the host-safe gate, but not uniformly, and the
difference matters: the root workspace gets the full set (advisories, bans, licenses, sources),
while each workspace `exclude`d from it gets **advisories only**. License and ban policy is
therefore enforced on the root tree alone. Which workspaces those are is derived from `Cargo.toml`
by `detached_workspaces_are_all_scanned` rather than restated anywhere, because both of them went
unscanned entirely from the day they were excluded until 2026-08-02, and nothing said so.
`audit.yml` re-runs the advisory scan daily against the pinned lockfile, so a newly disclosed
advisory surfaces without anyone committing.
