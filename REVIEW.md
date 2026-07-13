# REVIEW.md: the between-phases review log

One entry per completed phase: the manual gate a human works before the next phase starts, kept
for the life of the project. The engine exists to teach Linux mastery, so this file is where the
*operator's* half of that happens: run it, read it, question it, and explain it back, before
building on top of it. Entries are **appended, never rewritten**; a ticked entry is the durable
record of what was reviewed, ratified, and consciously deferred. If a past entry turns out wrong,
add a dated correction line under it rather than editing history.

## How to work an entry

- When the coding agent declares a phase complete, have it append the next entry here (same
  skeleton, fresh anchors and numbers). Review its claims against the tree; the entry is itself
  agent output and deserves the same skepticism as the code.
- Work top to bottom. **Any failed box is a stop**: fix it or file it before the next phase. The
  roadmap's own rule (never start a phase before the prior exit gate passes) is enforced *here*.
- Line anchors (`file.rs:NNN`) point at the tree as of the entry's writing; refactors move them.
  Trust the symbol name over the number.

## The entry skeleton

Every entry covers the same eight angles, so nothing relies on remembering to ask:

0. **Host check**: the box can still do the work (`cargo xtask setup`, disk/RAM headroom).
1. **Operate it**: run the phase's demo by hand; watching it run catches what asserts don't.
2. **Gates**: `cargo xtask ci` and `ci-privileged` green; capability-gated tests genuinely ran
   (no silent skips); leak check by hand.
3. **Read the work**: the mechanisms per commit, the judgment calls that deserve a human yes,
   and the coverage gaps to accept or close.
4. **Writeups and decisions**: the `ARCHITECTURE.md` decisions and the `ROADMAP.md` annotations
   record the phase's lesson and describe the tree as it is; the exit gate (demo + recorded
   lesson) is genuinely met. All documentation lives in the root `.md` files; no `docs/` dir.
5. **Human git steps**: what to commit or tag (git stays human-driven).
6. **Next-phase readiness**: the forward notes, environment realities, and tombstones the next
   phase must pick up.
7. **Teach-back**: the mastery check. Explain the phase's core mechanisms aloud, from memory,
   as if teaching them. If an explanation won't come, the phase isn't done with *you* yet;
   reread the writeup or interrogate the agent until it will.

---

## Entry 1: before Phase 6 (Phase 5 under review: snapshots and warm start)

The coding agent has landed all of Phase 5 (P5.1 through P5.8: snapshot, restore, warm snapshots,
concurrent clones, restore identity, the warm `Pool`, the bench, the timed proof), recorded the
exit-gate lesson in the decision log, and split `vm.rs` / `tests/boot.rs` / xtask into modules by
concern. Phase 6 (jailer,
cgroups, seccomp) confines the VMM those snapshots run on; this entry is the gate in between.

### 0. Host check

- [ ] `cargo xtask setup` reports every item green (KVM writable, BTF, firecracker **and jailer**
      binaries, the rootfs tools, `ip`, fetched artifacts). The jailer line matters now: Phase 6
      starts with it.
- [ ] Disk headroom for snapshot work: every full snapshot writes a memory file the size of guest
      RAM (256 MiB at `Limits::default().mem_mib`), plus a disk copy for read-write-root bundles.
      The bench and tests clean up after themselves, but check `df /tmp` is comfortable.

### 1. Operate the engine

Snapshots have **no CLI surface yet** (Sandbox-level warm start is Phase 7), so operating Phase 5
means the bench and the tests. Run from the repo root.

- [ ] **The phase's demo:** `cargo xtask bench-warm` (needs `/dev/kvm`, the built agent rootfs, a
      couple of minutes). Reference numbers from this box (n=100 per path, time-to-first-result):
      cold boot + exec **p50 689 / p99 943 ms**, warm restore + exec **p50 105 / p99 172 ms**, pool
      take + exec **p50 45 / p99 90 ms**. Yours should be the same shape: warm paths several times
      under cold, pool under restore.
- [ ] **Footprint claim:** the bench's closing note (cold copies the 132 MiB image per VM; a warm
      clone copies nothing) matches what you see: while it runs, `ls /tmp/agent-*` shows clone
      scratch dirs without private rootfs copies during the warm-path runs.
- [ ] **Cold paths still work:** `cargo run -p agent-cli -- run --demo-boot` still boots and prints
      its one result line on stdout (pipe hygiene unchanged), and
      `AGENT_ROOTFS="$PWD/artifacts/rootfs-agent.ext4" cargo run -p agent-cli -- run -- echo hi`
      still execs. Phase 5 refactored the boot path (`spawn_fc`, absolute paths, per-VMM cwd), so
      confirm the pre-snapshot surface didn't regress in the operator's hands.

### 2. Gates

- [ ] **Host gate:** `cargo xtask ci` green. The `kind_buckets_every_variant` pinned bucket test
      and the vsock ack unit tests (`connect_ack_*_is_typed_error`, now pinned to
      `GuestUnavailable`) run here.
- [ ] **Privileged gate:** `cargo xtask ci-privileged` green: **23 tests across four binaries**
      (`tests/{boot,exec,net,snapshot}.rs`), run serially (`--test-threads=1`; real-VM tests
      assert on host-global leak state). Without ambient caps:
      `unshare -Urn --map-root-user sh -c 'ip link set lo up; cargo test -p agent-vmm --tests -- --ignored --test-threads=1'`.
- [ ] **The network-gated tests must run, not skip silently.** `have_net_admin()` gating means
      they pass vacuously without `CAP_NET_ADMIN`. Confirm no "skipping" lines and that these say
      `ok`: the four tests in `tests/net.rs` plus `restored_networked_clone_gets_a_fresh_identity`
      in `tests/snapshot.rs`.
- [ ] **Leak check by hand, outside the namespace:** `ls /tmp/agent-* 2>/dev/null` empty,
      `ip -o link show | grep -E '\bfc[0-9a-f]+'` empty. Phase 5 multiplied the things that could
      leak (bundles, staged disk copies, pooled VMMs), so this check earns its keep now.

### 3. Read the work

`git show <sha>` for each. Since these commits landed, `vm.rs`, `tests/boot.rs`, and xtask were
split into modules by concern, so the anchors point at the *current* tree, not the commit-time
layout: the driver is now `vm.rs` (lifecycle) + `net.rs` + `exec.rs` + `console.rs` + `drives.rs`
+ `pool.rs`.

- [ ] **Snapshot correctness** (`3f027ce`): `RunningVm::snapshot` (`vm.rs:565`) pauses, creates,
      and **resumes even if create fails** (a failed snapshot never leaves a frozen guest); the
      disk copy happens inside the paused window so memory and disk agree; restored VMs,
      input/output devices, and NIC-without-vsock are refused with typed errors, never an
      unrestorable bundle.
- [ ] **Restore staging** (`3f027ce`, decision 010): Firecracker opens drive backing files at
      `PUT /snapshot/load` from paths baked into the snapshot, so `Vm::restore` (`vm.rs:354`)
      stages the private disk copy at the recorded path and unlinks it once the VMM holds the fd
      (`stage_restore_disk`, `vm.rs:1334`: atomic `create_new` reservation, self-cleaning). Confirm
      no fallible call sits between stage and unstage that could strand the copy.
- [ ] **Concurrent clones** (`902ca84`): vsock binds a **relative** `v.sock` with each VMM run in
      its own scratch cwd (`spawn_fc`, `vm.rs:1396`), which is why every file path handed to FC is
      now absolutized (`absolute`, `vm.rs:1494`). The one deliberate relative path is the socket;
      convince yourself nothing else depends on cwd.
- [ ] **Restore identity** (`660a1b5`, decision 011): the guest agent re-addresses the clone's
      `eth0` over vsock (`apply_guest_net_identity`, `net.rs:29`); the driver recreates the
      snapshot's recorded tap name with a fresh /30 (`Tap::create_named`, `net.rs:150`); entropy is
      VMGenID-reseeded and **proven by test**, not assumed; the wall clock lags snapshot age and
      the engine deliberately leaves it.
- [ ] **The Pool** (`8ff6b79`, `crates/vmm/src/pool.rs`): `take()` health-probes before handing out
      (`probe_agent`, `vm.rs:439`), discards corpses, restores inline when dry; refill is explicit;
      no background threads. `GuestUnavailable` (`lib.rs:131`) types the nothing-listening
      establishment failures, bucketed `Infra` in `kind()` (`lib.rs:215`).
- [ ] **The bench** (`8ad02e3`, `xtask/src/bench.rs:116`): every sample verifies the output
      arrived; teardown/refill are off the clock; percentile honesty reused from `bench-boot` (no
      `p99` under n=100).
- [ ] **The module splits** (uncommitted, see section 5): mechanical moves only. Spot-check that
      the new module boundaries read sensibly (`net`/`exec`/`console`/`drives` in the driver;
      topic files under `tests/`; `bench`/`rootfs`/`guest_bins`/`artifacts` in xtask) and that
      nothing gained visibility beyond `pub(crate)`.

#### Judgment calls the agent made that deserve a human yes

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

#### Known coverage gaps to accept or close

- [ ] **Clock skew is printed, not asserted**
      (`restored_clones_do_not_share_entropy_or_freeze_the_clock`, `tests/snapshot.rs:299`): no
      test bounds the wall-clock lag, it only reports it. Fine while the posture is "documented
      limitation"; revisit if that changes.
- [ ] **Networked pooling at `target <= 1` is documented, not tested:** no test builds a Pool over
      a networked snapshot and asserts the deeper-prefill typed error (it falls out of
      `Tap::create_named`'s tested taken-name error, one layer down). Add the direct test now, or
      leave it to Phase 6, whose netns work rewrites the constraint anyway.
- [ ] **The bench times a dev-profile driver.** Timings are dominated by VM boot/restore I/O, so
      this barely moves the numbers, but the tracked Phase 17 benchmark should pick a profile
      explicitly.

### 4. Writeups and decisions

- [ ] `ARCHITECTURE.md` decision **010** (snapshot bundles + disk staging) and **011** (restore
      identity: the agent re-addresses, VMGenID reseeds) describe the mechanism actually in the
      tree, including the probed v1.9 constraint and the rejected alternatives (MMDS, per-tap
      DHCP, reusing the source's /30).
- [ ] `ROADMAP.md` Phase 5: all eight boxes checked, annotations match the code and carry the
      measured numbers (no aspirational claims), and the exit-gate bullet carries its `(Done:)`
      note.
- [ ] The Phase 5 lesson is fully recorded in the root files (the `docs/` directory is retired):
      decisions 010/011 carry what a snapshot is, stage-then-unlink, and the three restore
      fix-ups; the ROADMAP P5.7 annotation carries the measured table and the copy-on-write
      memory economics. Confirm nothing of the lesson lived *only* in the retired writeup. This
      closes the Phase 5 exit gate (demo + recorded lesson).

### 5. Human git steps

- [ ] Commit the module-split refactor sitting in the working tree (driver split into
      `net`/`exec`/`console`/`drives` + shared `test_util`; `tests/boot.rs` split into four topic
      binaries + `common/`; xtask split; stale doc commands and this file's anchors fixed).
      Internal-only, so no `seam:` marker; something like `Split the vmm driver and its
      integration tests into modules by concern`.
- [ ] Consider a `v0.0.x` checkpoint tag now that the engine snapshots, restores, and pools
      (`git tag` is still empty; `ROADMAP.md` §0.6). Still no `CHANGELOG.md` until `v0.1.0`.

### 6. Phase 6 readiness

Do not start **P6.1** (run Firecracker under its jailer) until:

- [ ] Sections 0 through 5 are clean and both gates are green on this box.
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

### 7. Teach-back (Phase 5 mastery)

Explain each aloud, from memory; `ARCHITECTURE.md` decisions 010 and 011 are the answer key.

- [ ] Why must the root-disk copy happen **inside the paused window**, and what silent corruption
      does copying from a running guest invite?
- [ ] Firecracker opens drive backing files at `PUT /snapshot/load`, from the recorded path. Walk
      through stage-then-unlink: why does the restored clone's disk survive the unlink, and what
      Unix semantics make that safe?
- [ ] What does the copy-on-write mmap of the memory file buy? Explain restore-in-milliseconds,
      page-cache sharing across clones, and "dirty pages are the real per-clone cost" as one
      coherent story.
- [ ] Why can't kernel `ip=` address a restored clone, and why is "the guest agent applies the
      identity, the host keeps enforcement" consistent with spine #2?
- [ ] What goes wrong if two clones share CRNG state, and how does VMGenID close it? What would
      break silently if a future kernel pin dropped the `vmgenid` driver, and which test catches
      it?
- [ ] Why is the guest wall clock behind after restore, why is monotonic time fine, and why does
      the engine refuse to fix the wall clock itself?
- [ ] Why does the pool health-probe on `take()` instead of trusting its stock, and why is
      `GuestUnavailable` bucketed as retryable `Infra` rather than a `Guest` fault?
- [ ] Why does `report_percentiles` refuse to print a `p99` below n=100, and what claim would a
      10-sample "p99" actually be making?

---

*(Next entry: appended when Phase 6 exits, before Phase 7. Ask the agent to draft it from the
skeleton above; review its claims like code.)*
