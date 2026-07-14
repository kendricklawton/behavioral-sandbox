# REVIEW.md: the between-phases review log

The manual gate a human works before the next phase starts, kept for the life of the project. The
engine exists to teach Linux mastery, so this file is where the *operator's* half of that happens:
run it, read it, question it, and explain it back, before building on top of it. Entries are
**appended, never rewritten**; a ticked entry is the durable record of what was reviewed,
ratified, and consciously deferred. If a past entry turns out wrong, add a dated correction line
under it rather than editing history.

**One entry per gate, not per box.** Normally that means one entry per completed phase. The first
entry is the exception: the log was started at the Phase 5 → 6 boundary, after Phases 0 through 5
had already landed, so **Entry 1 is a backfill** that reviews the whole engine built so far,
phase by phase. Every entry after it covers a single phase.

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
   lesson) is genuinely met. All documentation lives in the root `.md` files.
5. **Human git steps**: what to commit or tag (git stays human-driven).
6. **Next-phase readiness**: the forward notes, environment realities, and tombstones the next
   phase must pick up.
7. **Teach-back**: the mastery check. Explain the phase's core mechanisms aloud, from memory,
   as if teaching them. If an explanation won't come, the phase isn't done with *you* yet;
   reread the annotations/decisions or interrogate the agent until it will.

In this backfill entry the whole-tree angles (0 host check, 2 gates, 5 git steps, 6 readiness) are
worked once against the current tree; the per-phase angles (1 operate, 3 read, 4 decisions, 7
teach-back) are worked once per phase, Phase 0 through Phase 5. Later single-phase entries collapse
back to a flat eight sections.

---

## Entry 1: the engine through Phase 5 (backfill, before Phase 6)

The coding agent has landed Phases 0 through 5: the repo reset onto the sandbox engine (P0), a
microVM that boots from Rust (P1), `exec` in the guest over vsock (P2), a real rootfs with Python,
Node, and a static ELF (P3), per-VM deny-by-default networking (P4), and snapshots + warm restore +
a pool (P5). Since then the driver, its integration tests, and xtask were split into modules by
concern. Phase 6 (jailer, cgroups, seccomp) confines the VMM all of this runs on; this entry is the
gate in between, and it reviews everything underneath it, not just the last phase.

The tree as it stands: the driver is `crates/vmm/src/` = `vm.rs` (lifecycle) + `net.rs` + `exec.rs`
+ `console.rs` + `drives.rs` + `pool.rs` + `test_util.rs`, over the `crates/channel` wire protocol
and the `crates/guest-agent` in-guest agent; the privileged tests are `crates/vmm/tests/{boot,exec,
net,snapshot}.rs` + `common/`; xtask is `main` + `bench`/`rootfs`/`guest_bins`/`artifacts`; the CLI
is `crates/cli`. Eleven decisions (001–011) are on record.

### 0. Host check (whole tree)

- [ ] `cargo xtask setup` reports every item green: KVM writable, BTF present, `firecracker`
      **and jailer** binaries, the rootfs tools (`mke2fs`/`truncate`/`e2fsck`/`debugfs`/`apk`),
      `ip`, and the fetched artifacts. The jailer line matters now: Phase 6 starts with it.
- [ ] Disk headroom: every full snapshot writes a memory file the size of guest RAM (256 MiB at
      `Limits::default().mem_mib`) plus a disk copy for read-write-root bundles, and the rootfs
      build stages ~132 MiB. The bench and tests clean up after themselves, but check `df /tmp` is
      comfortable before a bench run.
- [ ] The artifacts are the pinned ones: `cargo xtask fetch-artifacts` is idempotent (sha256
      guard), and `artifacts/rootfs-agent.ext4` exists (built by `cargo xtask build-rootfs`, not
      fetched, and gitignored).

### 1. Operate it (per phase)

Run everything from the repo root. Snapshots and networking have **no CLI surface yet**
(Sandbox-level warm start and richer flags are Phase 7+), so the later phases are operated through
the bench and the tests.

- [ ] **P0 (the gates exist):** `cargo xtask setup` and `cargo xtask ci` both run and report; the
      workspace builds. `cargo tree` shows the sandbox-engine crates
      (`vmm`/`channel`/`guest-agent`/`probes-loader`/`cli` + `xtask`) and nothing else.
- [ ] **P1 (boot):** `cargo run -p agent-cli -- run --demo-boot` boots a microVM to userspace and
      prints one line (`booted microVM to userspace in NNN ms`) on **stdout**, with logs on stderr,
      so `... --demo-boot 2>/dev/null` stays a clean single line. Run it twice back to back; the
      second boot proves the first tore down.
- [ ] **P2 (exec):** `AGENT_ROOTFS="$PWD/artifacts/rootfs-agent.ext4" cargo run -p agent-cli -- run
      -- echo hi` prints `hi`, exit 0. The guest's stdout is relayed on the host's stdout, its exit
      code is the process exit code.
- [ ] **P3 (rootfs + runtimes):** the same `run --` form with `-- python3 -c 'print(2+2)'` prints
      `4`; `cargo xtask build-rootfs --verify` builds twice and asserts byte-identical (the
      reproducibility demo) and prints the base footprint under its budget.
- [ ] **P4 (networking):** the network demo is the privileged tests (below); by hand, a networked
      boot's guest reaches its host `/30` end and nothing off-subnet. Needs `CAP_NET_ADMIN`
      (`unshare -Urn --map-root-user`, see gates).
- [ ] **P5 (snapshots):** `cargo xtask bench-warm` (needs `/dev/kvm` + the agent rootfs, a couple
      of minutes). Reference numbers (dev box, n=100 per path, time-to-first-result): cold boot +
      exec **p50 689 / p99 943 ms**, warm restore + exec **p50 105 / p99 172 ms**, pool take + exec
      **p50 45 / p99 90 ms**. Yours should be the same shape: warm several times under cold, pool
      under restore. While it runs, `ls /tmp/agent-*` shows warm clones without private rootfs
      copies (the footprint claim: cold copies the 132 MiB image, a warm clone copies nothing).

### 2. Gates (whole tree)

- [ ] **Host gate:** `cargo xtask ci` green (fmt · clippy `-D warnings` · build · unit tests ·
      docs · deny). The unit tests that pin taxonomy live here: `kind_buckets_every_variant`
      (bucket mapping) and the vsock ack tests (`connect_ack_*_is_typed_error`, pinned to
      `GuestUnavailable`). This gate runs everywhere and needs no privileges.
- [ ] **Privileged gate:** `cargo xtask ci-privileged` green: **23 integration tests across four
      binaries** (`tests/{boot,exec,net,snapshot}.rs` = 4 + 7 + 4 + 8), run serially
      (`--test-threads=1`; real-VM tests assert on host-global leak state). Without ambient caps:
      `unshare -Urn --map-root-user sh -c 'ip link set lo up; cargo test -p agent-vmm --tests -- --ignored --test-threads=1'`.
      Note `--tests` (all four binaries), not `--test boot` (which now runs only 4 of the 23).
- [ ] **The capability-gated tests must run, not skip silently.** `have_net_admin()` gating means
      they pass vacuously without `CAP_NET_ADMIN`. Confirm no "skipping" lines and that these say
      `ok`: the four tests in `tests/net.rs` plus `restored_networked_clone_gets_a_fresh_identity`
      in `tests/snapshot.rs`.
- [ ] **Leak check by hand, outside the namespace:** after a full privileged run,
      `ls /tmp/agent-* 2>/dev/null` is empty and `ip -o link show | grep -E '\bfc[0-9a-f]+'` is
      empty. Every phase added something that could leak (scratch dirs, taps, VMM processes,
      snapshot bundles, staged disk copies, pooled VMMs); this one check covers all of them.

### 3. Read the work (per phase)

`git show <sha>` for each. Anchors point at the *current* tree (post module split), so they cite
file + symbol; trust the symbol over any line number.

#### 3.0 — Phase 0: the scaffold

- [ ] The workspace is the sandbox-engine layout (`vmm`/`channel`/`guest-agent`/`probes`/
      `probes-loader`/`cli` + `xtask`), each crate with a single job along the
      isolation/observability/driver seams. The two-gate split (`ci` host-safe, `ci-privileged` behind
      `/dev/kvm`) is the shape everything below relies on.

#### 3.1 — Phase 1: boot (decision 001)

- [ ] **The driver talks to Firecracker over its API socket** (`vm.rs`, the HTTP-over-`UnixStream`
      client): hand-rolled HTTP/1.1, `unsafe`-free, closed-set enums for the wire discriminants
      (`Action`). Boot configures the boot source + root block device, sets the machine config,
      and `InstanceStart`s.
- [ ] **The console reader thread drains stdout before `InstanceStart`** so the guest can't deadlock
      on a full pipe; boot returns only after the userspace marker (`login:`) is seen. `Vm::boot`
      / `RunningVm::shutdown` is the whole lifecycle; teardown is guaranteed in `Drop`.
- [ ] **Judgment call (settled):** each cold boot copies the rootfs into a per-VM scratch dir so
      the base stays pinned; P3.3's read-only base later removed the copy for the shared path.

#### 3.2 — Phase 2: exec (decision 002)

- [ ] **The wire protocol** (`crates/channel`): dependency-free length-prefixed framing over any
      `Read`+`Write`, a versioned handshake, type-state `ClientConnection`/`ServerConnection`.
      `serve` is transport-agnostic and drains the child's pipes so a dead/stalled host is a typed
      error under the connection deadlines, never a hang; signal death maps to `128+sig`.
- [ ] **The guest agent** (`crates/guest-agent`): static musl, binds `AF_VSOCK`, runs one command
      per connection, streams stdout/stderr/exit. `exec(argv, stdin) -> RunResult` (`exec.rs`)
      aggregates under a **16 MiB output cap** so a flooding guest can't grow host memory;
      `PutFile`/`File` frames inject/collect small files under the same cap.
- [ ] **Timeout + kill** (`exec.rs` bounds + the guest's `wait_bounded`): the host sends a per-exec
      `timeout_ms`, the guest SIGKILLs + reaps past the deadline and replies `TimedOut`, clamped to
      an agent ceiling. The host's read timeout is set longer than the command budget so the reply
      arrives.
- [ ] **The error taxonomy** (`VmmError`, `lib.rs`): three buckets, boot/infra vs channel/transport
      vs guest-fault, enforced no-panic by `#![forbid(unsafe_code)]` + clippy denying
      `unwrap`/`expect` outside tests. A non-zero exit or signal death is a faithful `RunResult`,
      not an error.
- [ ] **Known gap carried forward:** `kill` reaches only the direct child, so a command that
      double-forks a grandchild holding the stdout pipe wedges the *agent's connection* (the host
      stays bounded) until that grandchild exits. The definitive fix is the cgroup kill of the whole
      tree in **Phase 6 (P6.4)**. Confirm you still accept this through Phase 6.

#### 3.3 — Phase 3: rootfs (decisions 003–007)

- [ ] **The rootfs build** (`xtask/src/rootfs.rs`): a sha256-pinned Alpine minirootfs with the
      static agent baked in, assembled rootless with `mke2fs -d` (no loopback, one command), a
      busybox init that mounts the pseudo-fs and respawns the agent on vsock. Python and Node are
      baked (a 44-package closure); a static native ELF is *injected* at runtime, proving the engine
      runs any Linux binary, not just baked ones.
- [ ] **Read-only base + per-run overlay** (decision 004): the base attaches read-only + shared (no
      copy), the guest stacks a tmpfs overlay so `/` is writable but ephemeral; `/sbin/overlay-init`
      pivots into it. Cap = `mem_mib/2` (guests have no swap). The block-device I/O paths
      (`drives.rs`): a read-only `/input` image (decision 005) and a writable `/output` image read
      back **after the VMM exits** via `e2fsck` + `debugfs rdump` (decision 006), with host-escaping
      symlinks and `lost+found` sanitised out and a byte/time cap on extraction.
- [ ] **Reproducibility** (decision 007): `SOURCE_DATE_EPOCH` + a fixed htree hash seed +
      `lazy_itable_init=0` + dropping apk's wall-clock log make `build-rootfs` byte-for-byte
      deterministic; a committed lockfile records the 33/44-package closure and `--verify` fails on
      drift. Exact version pinning was *rejected* (Alpine branch repos delete old `.apk`s on a bump).
- [ ] **Judgment call (settled, measured):** at this base size both the copy and shared paths boot
      in ~0.4–0.5 s p50 (the host page cache serves the copy), so a small base buys **density**, not
      boot time. The honest, measured result, not the assumed one.

#### 3.4 — Phase 4: networking (decisions 008–009)

- [ ] **The per-VM tap** (`net.rs`, `Tap::create`): shelled out to `ip tuntap`, named `fc<hex>`
      host-globally (create-and-retry is the atomic name reservation), an LAA MAC, attached as
      `eth0` via `PUT /network-interfaces`. The `Tap` handle is threaded onto `RunningVm` and
      deleted (`ip link del`) on **all three** teardown paths, since the tap lives outside the
      scratch dir that `remove_dir_all` reclaims.
- [ ] **Deny-by-default addressing** (decision 008): a deterministic `/30` from the per-VM index
      (`subnet_for`), the host end assigned (which installs the connected route), and the kernel
      `ip=` arg with an **empty gateway** so the guest gets a connected-route-only NIC: it reaches
      its host end and nothing else. No default route, no MASQUERADE, no `ip_forward`, no bridge,
      no netns. The `ip addr add` clash is the atomic `/30` reservation (`host_addr_exists`), so two
      VMs can't alias a subnet.
- [ ] **The eBPF-binding handle** (P4.6): `RunningVm::tap_name()` hands out the stable name (not a
      stored ifindex, which is netns-fragile) so the Phase 8 loader resolves the index at attach.
- [ ] **Coverage note:** "allowed" in Phase 4 legitimately means **host-local** (reaching a real
      `TcpListener` on the host `/30` end); world-egress allow-listing is the eBPF-enforced,
      recorded policy of Phase 8. Per-VM netns isolation is tombstoned to the Phase 6 jailer as
      defence-in-depth. Confirm you accept L3-unreachability + a unique `/30` as the Phase 4 bar.

#### 3.5 — Phase 5: snapshots (decisions 010–011)

- [ ] **Snapshot correctness** (`RunningVm::snapshot`, `vm.rs:565`): pauses, creates, and
      **resumes even if create fails** (a failed snapshot never leaves a frozen guest); the disk
      copy happens inside the paused window so memory and disk agree; restored VMs, input/output
      devices, and NIC-without-vsock are refused with typed errors, never an unrestorable bundle.
- [ ] **Restore staging** (`Vm::restore`, `vm.rs:354`; `stage_restore_disk`, `vm.rs:1334`;
      decision 010): Firecracker opens drive backing files at `PUT /snapshot/load` from the baked-in
      path, so the driver stages the private disk copy at that path and unlinks it once the VMM
      holds the fd (atomic `create_new` reservation, self-cleaning). Confirm no fallible call sits
      between stage and unstage that could strand the copy.
- [ ] **Concurrent clones** (`spawn_fc`, `vm.rs:1396`): vsock binds a **relative** `v.sock` with
      each VMM run in its own scratch cwd, which is why every *file* path handed to FC is now
      absolutized (`absolute`, `vm.rs:1494`). The one deliberate relative path is the socket;
      convince yourself nothing else depends on cwd.
- [ ] **Restore identity** (decision 011): the guest agent re-addresses the clone's `eth0` over
      vsock (`apply_guest_net_identity`, `net.rs:29`); the driver recreates the recorded tap name
      with a fresh `/30` (`Tap::create_named`, `net.rs:150`); entropy is VMGenID-reseeded and
      **proven by test**; the wall clock lags snapshot age and the engine deliberately leaves it.
- [ ] **The Pool** (`crates/vmm/src/pool.rs`): `take()` health-probes before handing out
      (`probe_agent`, `vm.rs:439`), discards corpses, restores inline when dry; refill is explicit;
      no background threads. `GuestUnavailable` (`lib.rs:131`) types the nothing-listening
      establishment failures, bucketed `Infra` in `kind()` (`lib.rs:215`).
- [ ] **The bench** (`xtask/src/bench.rs:116`): every sample verifies the output arrived;
      teardown/refill are off the clock; percentile honesty reused from `bench-boot` (no `p99`
      under n=100). The timed proof `warm_restore_returns_output_in_far_under_cold_boot` asserts a
      2x margin under cold boot.

#### Judgment calls the agent made that still deserve a human yes

- [ ] **One live networked clone per snapshot** on FC v1.9 (`network_overrides` probed and rejected,
      so the tap name is baked). Tombstoned to an FC bump or the Phase 6 jailer's netns; P6.1 is the
      natural fix point.
- [ ] **Wall-clock drift on restore is documented, not fixed.** Restored guests' `time.time()`
      lags by snapshot age; monotonic is sane; the flight recorder timestamps host-side. Wrong only
      if an embedder needs correct in-guest wall time; say so now if so.
- [ ] **The Pool is synchronous by design** (no self-refilling thread; that is the Phase 16
      daemon's job). Cost: a caller who never calls `refill()` pays an inline restore on every dry
      take. Buy the "library stays thread-free" line, or don't.
- [ ] **Drop-based teardown holds everything.** SIGKILL of the *host* process mid-restore or with a
      full pool leaks VMMs, taps, and staged files until P6.7 hands lifetime to the cgroup. The pool
      widens this window (N live VMMs held by one process). Known, accepted, and precisely what
      Phase 6 exists to fix.
- [ ] **P2's grandchild-reaping gap** (3.2 above) and **P4's host-local-only "allowed"** (3.4) are
      the two other deferrals riding into Phase 6/8. Confirm both are still consciously accepted.

#### Known coverage gaps to accept or close

- [ ] **Clock skew is printed, not asserted** (`restored_clones_do_not_share_entropy_or_freeze_the_clock`,
      `tests/snapshot.rs:299`): no test bounds the lag, it only reports it. Fine while the posture is
      "documented limitation".
- [ ] **Networked pooling at `target <= 1` is documented, not directly tested:** it falls out of
      `Tap::create_named`'s tested taken-name error one layer down. Add the direct test now or leave
      it to Phase 6, whose netns work rewrites the constraint anyway.
- [ ] **The bench times a dev-profile driver.** Timings are boot/restore-I/O-dominated so profile
      barely moves them, but the tracked Phase 17 benchmark should pick one explicitly.

### 4. Writeups and decisions (per phase)

The lesson for every phase lives in the root `.md` files: the `ROADMAP.md` box annotations + the
`ARCHITECTURE.md` decision log. Confirm each phase's exit-gate bullet carries its `(Done:)` note and
that the annotations match the code and carry measured numbers, not aspirational claims.

- [ ] **P1 → decision 001** (API socket, hand-rolled HTTP): the boot-protocol + lifecycle lesson.
- [ ] **P2 → decision 002** (vsock + guest agent): the host↔guest comms lesson, incl. the three-bucket
      error taxonomy.
- [ ] **P3 → decisions 003–007** (Alpine base, overlay, input/output block devices, reproducible
      build): ext4 `mke2fs -d`, overlayfs, initramfs-vs-rootfs, static-vs-dynamic linking,
      reproducibility.
- [ ] **P4 → decisions 008–009** (deny-by-default egress, the tap): tap-vs-bridge/veth, virtio-net,
      kernel `ip=`/`CONFIG_IP_PNP`, the connected-route-is-the-whole-security-model lever, the P4.8
      audit table.
- [ ] **P5 → decisions 010–011** (snapshot bundles + staging, restore identity): what a snapshot is,
      stage-then-unlink, copy-on-write memory economics, the three restore fix-ups. The ROADMAP P5.7
      annotation carries the measured table.

### 5. Human git steps (whole tree)

- [ ] Commit the module-split refactor + docs-retirement sitting in the working tree (driver split
      into `net`/`exec`/`console`/`drives` + shared `test_util`; `tests/boot.rs` split into four
      topic binaries + `common/`; xtask split; the `docs/` writeup directory retired into the root
      `.md` files; this file's anchors and stale test commands fixed). Internal-only, so **no
      `seam:` marker**.
- [ ] Consider a `v0.0.x` checkpoint tag now that the engine boots, execs, networks, snapshots, and
      pools (`git tag` is still empty; `ROADMAP.md` §0.6). Still no `CHANGELOG.md` until `v0.1.0`.

### 6. Phase 6 readiness (whole tree)

Do not start **P6.1** (run Firecracker under its jailer) until:

- [ ] Sections 0 through 5 are clean and both gates are green on this box.
- [ ] You have read `ROADMAP.md` Phase 6 (P6.1 to P6.8), in particular the two forward notes it
      carries: **P6.4** also closes the P2.6 process-tree-reaping gap (3.2 above: a cgroup kill
      reaps the grandchildren and `setsid` daemons a direct kill misses), and **P6.7** is where the
      embedder-requested **kill handle** gets real teeth (cgroup-owned lifetime makes forced
      teardown leak-free).
- [ ] **The chroot-relative check:** Phase 5's design note said to lay snapshot/warm-pool files out
      so the jailer doesn't force a rework. The relative vsock + per-VMM cwd is exactly that shape,
      but snapshot bundles still record **absolute host paths** (state, mem, disk backing) and
      restore stages at the recorded path. Under the jailer those must resolve inside the chroot.
      Read `Snapshot`'s fields with that lens before P6.1; expect the staging path to be the first
      thing the jailer bends.
- [ ] **Test environment reality:** the `unshare -Urn` trick has carried every privileged test so
      far, but the jailer wants real uid/gid drops, a chroot, and cgroup writes. Expect Phase 6's
      integration tests to need actual root (or a delegated cgroup subtree) rather than a user
      namespace; decide where those run before writing them.
- [ ] **The two networking tombstones** land on Phase 6: decision 011's netns path to concurrent
      networked clones, and decision 009's per-VM netns as isolation defence-in-depth. Keep both in
      scope when shaping P6.1 rather than rediscovering them at Phase 8.

### 7. Teach-back (per phase)

Explain each aloud, from memory. The cited decisions are the answer key. If an explanation won't
come, that phase isn't done with *you* yet.

**P1 — boot (decision 001)**

- [ ] Why does the console reader thread have to be draining stdout *before* `InstanceStart`, and
      what deadlocks if it isn't?
- [ ] Why drive Firecracker over its API socket rather than embedding `rust-vmm`, and what does that
      buy the "no `unsafe` on the host path" rule?

**P2 — exec (decision 002)**

- [ ] Why vsock + a guest agent instead of SSH or a serial protocol, and why is the agent explicitly
      *not* the security boundary?
- [ ] Walk the three error buckets (boot/infra, channel/transport, guest-fault). Why is `exit 137`
      from `kill -9 $$` a faithful `RunResult` and not an error?
- [ ] Where exactly does a double-forked grandchild wedge things, why does the *host* stay bounded
      anyway, and which phase fixes it for real?

**P3 — rootfs (decisions 003–007)**

- [ ] Why does `mke2fs -d` let the build stay rootless with no loopback, and what would a loopback
      mount have cost?
- [ ] Explain the read-only base + tmpfs overlay: what makes `/` writable in-guest while the host
      base file is provably unchanged?
- [ ] Why must `/output` be read back **after the VMM exits**, and what races a live `e2fsck`?
- [ ] Why was exact `.apk` version pinning *rejected* in favour of `SOURCE_DATE_EPOCH` + a lockfile?

**P4 — networking (decisions 008–009)**

- [ ] The empty `ip=` gateway is the whole deny-by-default lever. Explain how "connected route only,
      no default route" reduces to "reaches its host end and nothing else."
- [ ] Why a tap per VM and not a bridge or veth pair for a single VMM?
- [ ] Why is the `ip addr add` clash (not just the tap name) the atomic `/30` reservation, and what
      isolation breaks if two VMs alias a subnet?

**P5 — snapshots (decisions 010–011)**

- [ ] Why must the root-disk copy happen **inside the paused window**, and what silent corruption
      does copying from a running guest invite?
- [ ] Walk stage-then-unlink: why does the restored clone's disk survive the unlink, and what Unix
      semantics make that safe?
- [ ] What does the copy-on-write mmap of the memory file buy? Tie restore-in-milliseconds,
      page-cache sharing across clones, and "dirty pages are the real per-clone cost" into one story.
- [ ] Why can't kernel `ip=` address a restored clone, and why is "the agent applies the identity,
      the host keeps enforcement" consistent with spine #2?
- [ ] What breaks if two clones share CRNG state, how does VMGenID close it, and which test catches a
      future kernel pin that drops the `vmgenid` driver?
- [ ] Why does the pool health-probe on `take()` instead of trusting its stock, and why is
      `GuestUnavailable` a retryable `Infra` fault rather than a `Guest` one?
- [ ] Why does `report_percentiles` refuse a `p99` below n=100, and what claim would a 10-sample
      "p99" actually be making?

---

*(Next entry: appended when Phase 6 exits, before Phase 7, as a flat single-phase entry over the
eight-angle skeleton. Ask the agent to draft it; review its claims like code.)*
