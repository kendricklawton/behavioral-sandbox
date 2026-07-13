# REVIEW.md: manual checklist before Phase 6

A working checklist for the things only you (the human) should do before starting **Phase 6
(confinement: jailer, cgroups, seccomp)**. The coding agent has landed all of Phase 5 (snapshots
and warm start, P5.1 through P5.8); this file puts a human's eyes on that work before Phase 6
jails the VMM those snapshots run on. It is a working note, not a permanent doc; delete it once
you have worked through it.

Tick each box as you go. Anything that fails is a stop: fix or file it before Phase 6.

## Git state

The tree is **clean** and every Phase 5 box is committed; this is a retrospective review
(`git show <sha>`), not an uncommitted-diff review. There are still **no tags**. The commits under
review (newest first):

| commit    | subject                                                                  | phase work                          |
|-----------|--------------------------------------------------------------------------|-------------------------------------|
| `8ad02e3` | Benchmark the three start paths and assert warm restore beats cold boot  | P5.7 bench + P5.8 test              |
| `8ff6b79` | seam: add a warm Pool and type agent-unavailable errors as retryable     | P5.6 + the P2.7 `GuestUnavailable` closure |
| `660a1b5` | seam: restore networked clones with a fresh identity, reseeded entropy   | P5.5 / decision 011                 |
| `902ca84` | seam: restore warm snapshots as exec-ready concurrent clones             | P5.3 + P5.4                         |
| `3f027ce` | seam: add microVM snapshot/restore and a VmmError bucket classifier      | P5.1 + P5.2, `kind()`, `Limits` docs, the `.rules` seam convention |

Four of five carry the `seam:` marker because each changed the public `vmm` surface a downstream
pin sees (`Snapshot`/`restore`, new `VmmError` variants, `kind()`, `Pool`). `8ad02e3` doesn't, and
shouldn't (xtask + a test). Sanity-check that split reads right from `git log --oneline` alone;
that legibility is the whole point of the convention.

**One thing is genuinely outstanding: the Phase 5 exit-gate writeup (`docs/005-*.md`) does not
exist yet.** See section 4. The working-demo half of the gate is done (the bench + 23 privileged
tests); the phase is not closed until the writeup lands.

## 0. Confirm the host can still do the work

- [ ] `cargo xtask setup` reports every item green (KVM writable, BTF, firecracker **and jailer**
      binaries, the rootfs tools, `ip`, fetched artifacts). The jailer line matters now: Phase 6
      starts with it.
- [ ] Disk headroom for snapshot work: every full snapshot writes a memory file the size of guest
      RAM (256 MiB at `Limits::default().mem_mib`), plus a disk copy for read-write-root bundles.
      The bench and tests clean up after themselves, but check `df /tmp` is comfortable.

## 1. Operate the engine (see it actually run, not just pass tests)

Snapshots have **no CLI surface yet** (Sandbox-level warm start is Phase 7), so operating Phase 5
means the bench and the tests. Run from the repo root.

- [ ] **The phase's demo:** `cargo xtask bench-warm` (needs `/dev/kvm`, the built agent rootfs, a
      couple of minutes). Reference numbers from this box (n=100 per path, time-to-first-result):
      cold boot + exec **p50 689 / p99 943 ms**, warm restore + exec **p50 105 / p99 172 ms**, pool
      take + exec **p50 45 / p99 90 ms**. Yours should be the same shape: warm paths several times
      under cold, pool under restore. Record your numbers; they seed the `docs/005` writeup.
- [ ] **Footprint claim:** the bench's closing note (cold copies the 132 MiB image per VM; a warm
      clone copies nothing) matches what you see: while it runs, `ls /tmp/agent-*` shows clone
      scratch dirs without private rootfs copies during the warm-path runs.
- [ ] **Cold paths still work:** `cargo run -p agent-cli -- run --demo-boot` still boots and prints
      its one result line on stdout (pipe hygiene unchanged), and
      `AGENT_ROOTFS="$PWD/artifacts/rootfs-agent.ext4" cargo run -p agent-cli -- run -- echo hi`
      still execs. Phase 5 refactored the boot path (`spawn_fc`, absolute paths, per-VMM cwd), so
      confirm the pre-snapshot surface didn't regress in the operator's hands.

## 2. Run both gates

- [ ] **Host gate:** `cargo xtask ci` green. The `kind_buckets_every_variant` pinned bucket test
      and the vsock ack unit tests (`connect_ack_*_is_typed_error`, now pinned to
      `GuestUnavailable`) run here.
- [ ] **Privileged gate:** `cargo xtask ci-privileged` green: **23 tests, run serially**
      (`--test-threads=1`; real-VM tests assert on host-global leak state). Without ambient caps:
      `unshare -Urn --map-root-user sh -c 'ip link set lo up; cargo test -p agent-vmm --test boot -- --ignored --test-threads=1'`.
- [ ] **The network-gated tests must run, not skip silently.** `have_net_admin()` gating means
      they pass vacuously without `CAP_NET_ADMIN`. Confirm no "skipping" lines and that these say
      `ok`: the four Phase 4 network tests plus Phase 5's
      `restored_networked_clone_gets_a_fresh_identity`.
- [ ] **Leak check by hand, outside the namespace:** `ls /tmp/agent-* 2>/dev/null` empty,
      `ip -o link show | grep -E '\bfc[0-9a-f]+'` empty. Phase 5 multiplied the things that could
      leak (bundles, staged disk copies, pooled VMMs), so this check earns its keep now.

## 3. Review the committed Phase 5 work

`git show <sha>` for each; the heavy reading is `crates/vmm/src/vm.rs`.

- [ ] **Snapshot correctness** (`3f027ce`): `RunningVm::snapshot` (`vm.rs:635`) pauses, creates,
      and **resumes even if create fails** (a failed snapshot never leaves a frozen guest); the
      disk copy happens inside the paused window so memory and disk agree; restored VMs,
      input/output devices, and NIC-without-vsock are refused with typed errors, never an
      unrestorable bundle.
- [ ] **Restore staging** (`3f027ce`, decision 010): Firecracker opens drive backing files at
      `PUT /snapshot/load` from paths baked into the snapshot, so `Vm::restore` (`vm.rs:424`)
      stages the private disk copy at the recorded path and unlinks it once the VMM holds the fd
      (`stage_restore_disk`, `vm.rs:1404`: atomic `create_new` reservation, self-cleaning). Confirm
      no fallible call sits between stage and unstage that could strand the copy.
- [ ] **Concurrent clones** (`902ca84`): vsock binds a **relative** `v.sock` with each VMM run in
      its own scratch cwd (`spawn_fc`, `vm.rs:1506`), which is why every file path handed to FC is
      now absolutized (`absolute`, `vm.rs:2210`). The one deliberate relative path is the socket;
      convince yourself nothing else depends on cwd.
- [ ] **Restore identity** (`660a1b5`, decision 011): the guest agent re-addresses the clone's
      `eth0` over vsock (`apply_guest_net_identity`, `vm.rs:1470`); the driver recreates the
      snapshot's recorded tap name with a fresh /30 (`Tap::create_named`, `vm.rs:1674`); entropy is
      VMGenID-reseeded and **proven by test**, not assumed; the wall clock lags snapshot age and
      the engine deliberately leaves it.
- [ ] **The Pool** (`8ff6b79`, `crates/vmm/src/pool.rs`): `take()` health-probes before handing out
      (`probe_agent`, `vm.rs:509`), discards corpses, restores inline when dry; refill is explicit;
      no background threads. `GuestUnavailable` (`lib.rs:125`) types the nothing-listening
      establishment failures, bucketed `Infra` in `kind()` (`lib.rs:209`).
- [ ] **The bench** (`8ad02e3`, `xtask/src/main.rs:741`): every sample verifies the output arrived;
      teardown/refill are off the clock; percentile honesty reused from `bench-boot` (no `p99`
      under n=100).

### Judgment calls the agent made that deserve a human yes

- [ ] **One live networked clone per snapshot** on the pinned FC v1.9 (`network_overrides` probed
      and rejected, so the tap name is baked into the snapshot). Tombstoned to an FC bump or the
      Phase 6 jailer's netns. Accept living with it through Phase 6, since P6.1 is the natural fix
      point.
- [ ] **Wall-clock drift on restore is documented, not fixed.** Restored guests' `time.time()`
      lags by snapshot age; monotonic clocks are sane; the flight recorder will timestamp
      host-side. If an embedder use case needs correct in-guest wall time, this posture is wrong;
      say so now.
- [ ] **The Pool is synchronous by design** (no self-refilling thread in the library; that is the
      Phase 16 daemon's job). The cost: a caller who never calls `refill()` pays an inline restore
      on every dry take. Confirm you buy the "library stays thread-free" line.
- [ ] **Drop-based teardown still holds everything.** SIGKILL of the *host* process mid-restore or
      with a full pool leaks VMMs and staged files until P6.7 hands lifetime to the cgroup. Known,
      accepted, and precisely what Phase 6 exists to fix; confirm it is understood, since the pool
      widens the window (N live VMMs held by one process).
- [ ] **P5.8's assertion margin:** restore-to-output must beat **half** the source's cold-boot
      latency (measured headroom ~6.6x). Loose enough to survive a loaded CI box, tight enough to
      mean "far under". Tighten or loosen if your box disagrees.

### Known coverage gaps to accept or close

- [ ] **Clock skew is printed, not asserted**
      (`restored_clones_do_not_share_entropy_or_freeze_the_clock`, `boot.rs:431`): no test bounds
      the wall-clock lag, it only reports it. Fine while the posture is "documented limitation";
      revisit if that changes.
- [ ] **Networked pooling at `target <= 1` is documented, not tested:** no test builds a Pool over
      a networked snapshot and asserts the deeper-prefill typed error (it falls out of
      `Tap::create_named`'s tested taken-name error, one layer down). Add the direct test now, or
      leave it to Phase 6, whose netns work rewrites the constraint anyway.
- [ ] **The bench times a dev-profile driver.** Timings are dominated by VM boot/restore I/O, so
      this barely moves the numbers, but the tracked Phase 17 benchmark should pick a profile
      explicitly.

## 4. Review the writeups and decisions

- [ ] `ARCHITECTURE.md` decision **010** (snapshot bundles + disk staging, `ARCHITECTURE.md:559`)
      and **011** (restore identity: the agent re-addresses, VMGenID reseeds,
      `ARCHITECTURE.md:634`) describe the mechanism actually in the tree, including the probed
      v1.9 constraint and the rejected alternatives (MMDS, per-tap DHCP, reusing the source's /30).
- [ ] `ROADMAP.md` Phase 5: all eight boxes checked, annotations match the code and carry the
      measured numbers (no aspirational claims).
- [ ] **STOP: the exit-gate writeup is missing.** Phase 5's gate is a working demo **and** a
      writeup on **snapshotting, guest memory, and the state you must fix up on restore**; there is
      no `docs/005-*.md` and no `docs/README.md` entry for it. Have the agent draft it (the
      material exists: decisions 010/011, the bench numbers, the VMGenID/clock findings) or write
      it yourself. Phase 6 does not start until this is committed.

## 5. Human git steps

- [ ] Commit the `docs/005` writeup once it exists and reads true (imperative, phase-free,
      attribution-free subject; docs only, so no `seam:` marker).
- [ ] Consider a `v0.0.x` checkpoint tag now that the engine snapshots, restores, and pools
      (`git tag` is still empty; `ROADMAP.md` §0.6). Still no `CHANGELOG.md` until `v0.1.0`.
- [ ] Delete this file when done (throwaway; not part of the engine).

## 6. Phase 6 readiness gate

Do not start **P6.1** (run Firecracker under its jailer) until:

- [ ] Sections 0 through 5 are clean, including the committed `docs/005` writeup.
- [ ] Both gates are green on this box.
- [ ] You have read `ROADMAP.md` Phase 6 (P6.1 to P6.8), in particular the two forward notes it
      carries: **P6.4** also closes the P2.6 process-tree-reaping gap (a cgroup kill reaps the
      grandchildren and `setsid` daemons a direct kill misses), and **P6.7** is where the
      embedder-requested **kill handle** gets real teeth (cgroup-owned lifetime makes forced
      teardown leak-free).
- [ ] **The chroot-relative check:** Phase 5's design note said to lay snapshot/warm-pool files
      out so the jailer doesn't force a rework. The relative vsock + per-VMM cwd is exactly that
      shape, but snapshot bundles still record **absolute host paths** (state, mem, disk backing),
      and restore stages at the recorded path. Under the jailer those paths must resolve inside
      the chroot. Read `Snapshot`'s fields with that lens before P6.1; expect the staging path to
      be the first thing the jailer bends.
- [ ] **Test environment reality:** the `unshare -Urn` trick has carried every privileged test so
      far, but the jailer wants real uid/gid drops, a chroot, and cgroup writes. Expect Phase 6's
      integration tests to need actual root (or a delegated cgroup subtree) rather than a user
      namespace; decide where those will run before writing them.
- [ ] Decision 011's netns tombstone is on the Phase 6 radar: the jailer's network namespace is
      the sanctioned path to concurrent networked clones. Keep it in scope when shaping P6.1
      rather than rediscovering it at Phase 8.
