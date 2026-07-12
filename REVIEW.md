# REVIEW.md: manual checklist before Phase 5

A working checklist for the things only you (the human) should do before starting **Phase 5
(snapshots and warm start)**. The coding agent has landed Phase 4 (guest networking) plus a
codebase-wide review/cleanup pass. This file is the "operate it, review it, close it out" pass that
puts a human's eyes on that work before the next phase builds on top of it. It is a working note,
not a permanent doc; delete it once you have worked through it.

Tick each box as you go. Anything that fails is a stop: fix or file it before Phase 5.

## Git state (read this first, the earlier draft was wrong)

The Phase 4 work is **already committed**, so this is a *retrospective* review, not an
uncommitted-diff review. As of writing, `git status` is clean except for two files:

- `ROADMAP.md` (modified): this session's roadmap refinement (Phase 5/9/13 clarifications), **not**
  Phase 4. Uncommitted.
- `REVIEW.md` (untracked): this file. Throwaway.

The commits this checklist is reviewing (newest first, `git log --oneline`):

| commit    | subject                                                     | phase work                          |
|-----------|-------------------------------------------------------------|-------------------------------------|
| `f6f4be0` | Centralize closed-set strings and remove duplicated code    | the cleanup/refactor pass           |
| `52673cb` | Isolate and document each microVM's network tap             | P4.1/4.2/4.4/4.6/4.7/4.8 + docs/004 |
| `2088e41` | Assert torn-down VMMs leave no orphaned process             | P4.5 leak-proofing                  |
| `07a33fd` | Bound exec with a host wall-clock deadline; set egress posture | exec deadline + P4.3 decision 008 |

So: the "review" section below reads *committed* code (`git show <sha>`), and the "commit" section
shrinks to just the roadmap refinement plus an optional tag. There is no Phase 4 code left to
commit.

## 0. Confirm the host can still do the work

- [ ] `cargo xtask setup` reports every item green (KVM writable, BTF, firecracker + jailer, the
      rootfs tools `mke2fs`/`e2fsck`/`debugfs`/`truncate`/`apk`, `ip`, and the fetched artifacts). A
      red line here explains any skipped test in section 2.

## 1. Operate the engine (see it actually run, not just pass tests)

The `agent` CLI (`crates/cli`, binary name `agent`) exposes **boot** and **exec** today; networking,
file injection, and artifact collection are engine features with **no CLI flag yet** (they are set in
code and proven by the privileged tests in section 2). Run these from the repo root.

- [ ] **Phase 1 boot demo:** `cargo run -p agent-cli -- run --demo-boot` prints
      `booted microVM to userspace in <N> ms` and exits 0.
- [ ] **Pipe hygiene (the `.rules` stdout-is-result contract):**
      `cargo run -p agent-cli -- run --demo-boot 2>/dev/null` prints *only* that one result line on
      stdout; all logs are on stderr. And `... --demo-boot | head -0` must exit cleanly, not panic on
      the closed pipe (the CLI uses `writeln!`, not `println!`, for exactly this).
- [ ] **Real exec end to end:** the default `Sandbox::boot` points at `artifacts/rootfs.ext4` (the
      no-agent boot image), so you must point it at the agent rootfs. Build it once if needed
      (`cargo xtask build-rootfs`), then:
      `AGENT_ROOTFS="$PWD/artifacts/rootfs-agent.ext4" cargo run -p agent-cli -- run -- echo hi`
      prints `hi` on stdout and exits 0. This is the exec surface driven from the CLI, not a test.
- [ ] **No-panic on the sad paths (host-path guarantee, spine #5):**
      - `cargo run -p agent-cli -- shell` prints `agent: not implemented yet: agent shell (ROADMAP
        Phase 7)` and exits 2 (a typed `VmmError::Unimplemented`, not a panic).
      - `cargo run -p agent-cli -- run -- echo hi` against the **default** rootfs (no `AGENT_ROOTFS`)
        reports a typed "guest agent not listening"-class error and exits 2. Note it may take until
        the boot/exec wall deadline (`Limits::default().wall`, 30 s) before it gives up: that is the
        deadline doing its job, not a hang.
- [ ] **Latency + teardown sanity:** the boot number is in the sub-second-to-few-seconds range you
      expect on this box; a second run tears down clean (no leftover `/tmp/agent-*`, checked in
      section 2).

## 2. Run both gates

- [ ] **Host gate:** `cargo xtask ci` is green (fmt, clippy `-D warnings`, build, unit tests, docs,
      cargo-deny). The `subnet_for` uniqueness unit tests and the guest-agent `parse_listen` tests
      run here.
- [ ] **Privileged gate:** `cargo xtask ci-privileged` is green. It needs `/dev/kvm` plus
      `CAP_NET_ADMIN`/`CAP_BPF`. Note this gate **already** builds the agent rootfs with `--verify`
      (reproducibility) and the P3.9 native fixture before running `cargo test --workspace --locked --
      --ignored`, so it subsumes the standalone reproducibility check below. On a box without ambient
      caps, the namespace trick works and also grants a writable `/dev/kvm`:
      `unshare -Urn --map-root-user cargo test -p agent-vmm --test boot -- --ignored`.
- [ ] **The network tests must run, not skip silently.** They are `have_net_admin()`-gated, so
      without `CAP_NET_ADMIN` they pass vacuously. Confirm each says `ok` (16 `#[ignore]` boot tests
      total):
      - `attaches_a_tap_and_the_guest_sees_a_deny_by_default_nic`
      - `addresses_the_guest_and_routes_host_to_guest`
      - `two_vms_cannot_reach_each_others_tap`
      - `guest_reaches_an_allowed_host_endpoint_but_not_a_blocked_one`
      - `repeated_boots_leave_no_leaks` (asserts all three leak dimensions: no scratch dir, no `fc*`
        interface, no orphaned firecracker pid)
- [ ] **(Optional) standalone reproducibility:** `cargo xtask build-rootfs --verify` builds twice and
      asserts byte-identical (and flags package-closure drift). Redundant with `ci-privileged` but
      quick to run alone.
- [ ] **(Optional) boot bench:** `cargo xtask bench-boot` prints sane percentiles on both the
      read-only shared base and the read-write copy. This is the baseline Phase 5 snapshot-restore
      must beat, so it is worth recording the numbers now.
- [ ] **Leak check by hand** after the runs: `ls /tmp/agent-* 2>/dev/null` is empty, and
      `ip -o link show | grep -E '\bfc[0-9a-f]+' ` shows no orphaned taps. (Do this *outside* the
      `unshare` namespace, where a leaked tap would actually persist.)

## 3. Review the committed Phase 4 + cleanup work

Read the four commits above. `git show 52673cb` and `git show f6f4be0` are the two substantive ones.

- [ ] **P4 network mechanism** (`git show 52673cb`, mostly `crates/vmm/src/vm.rs`):
      - `subnet_for` (`vm.rs:1157`) and `HOST_PREFIX` (`vm.rs:1142`): each VM gets a point-to-point
        /30 from `10.200.0.0/16`; confirm the folded-index math can't hand two VMs the same block.
      - `Tap::create` + `host_addr_exists` (`vm.rs:1214`): the /30 is made atomically unique by
        making `ip addr add` the reservation (clash detected via netlink, not stderr string-match),
        mirroring the tap-name create-and-retry.
      - The `ip=` wiring in `run_boot` (search `ip=` / `IFACE_ID` at `vm.rs:72`): the **empty
        gateway** is the whole deny-by-default lever (connected /30 route only, no default route).
        Confirm the deny-by-default story reads the way the tests prove it.
      - Teardown: `ip_link_del` (`vm.rs:1115`) is called on all three teardown paths, since the tap
        lives outside the scratch dir. Confirm no path creates a tap it doesn't also delete.
- [ ] **Cleanup refactors** (`git show f6f4be0`; behavior-preserving, confirm you like the shape):
      - `enum Action { InstanceStart, SendCtrlAltDel }` + `put<B: Serialize>` in
        `crates/vmm/src/firecracker.rs:188` (was a stringly-typed `action_type`).
      - `crates/channel/src/lib.rs`: the `within_cap` deletion (the `write_frame` guard at ~`:223`
        was byte-identical, so it was a duplicated check, not a lost one) and the new `put_u32`
        (`:253`) mirroring the read-side decoder.
      - `crates/vmm/src/vm.rs`: `power_off_and_wait` (`:486`) shared by stop/shutdown,
        `require_vsock` (`:384`), `put_drive` (`:716`), `ip_link_del` (`:1115`), `still_before`
        (`:1577`, promoted to module scope), `IFACE_ID`/`HOST_PREFIX` consts.
      - `xtask/src/main.rs`: the `kernel_path`/`*_rootfs_path` helpers and
        `enum GuestBin { Agent, Example }` + `build_guest_musl` (replacing the two near-duplicate
        build fns).
      - `crates/guest-agent/src/main.rs`: the `VSOCK_SCHEME`/`UNIX_SCHEME`/`EXIT_OPERATIONAL` consts
        and the const-in-pattern `parse_listen`.

### Two judgment calls the agent left for you (in `52673cb`/`f6f4be0`)

- [ ] **Per-boot allocation vs static literal.** `IFACE_ID` (`vm.rs:72`) and `put_drive`
      (`vm.rs:716`) build their API paths with `format!` (one small alloc per boot, on a cold path)
      so the URL and the body id can't drift. Accept it, or ask for the full-path-const alternative.
- [ ] **`Display` restating `source()`.** `VmmError::Channel` (`crates/vmm/src/lib.rs`) and
      `ChannelError::Io` (`crates/channel/src/lib.rs:142`, whose `source()` is at `:157`) both
      interpolate the inner error into their `Display`. Left as-is because every reporter here is
      Display-only (the CLI at `crates/cli/src/main.rs:53`), so there is no double-print and slimming
      it would *lose* detail. Only revisit if you adopt a source-chain-walking reporter.

### Known coverage gap to accept or close

- [ ] The `/30` **clash-retry** path in `Tap::create` (the `ip addr add` reservation via
      `host_addr_exists`) has no direct test: it is covered by inspection plus the identical, tested
      tap-name retry. `two_vms_cannot_reach_each_others_tap` proves the *outcome* (distinct /30s) but
      not the *retry branch*. Decide whether to add a token-injection test now or defer it (a
      forced-collision test would need to seed two allocations onto the same folded index).

## 4. Review the writeups and decisions

- [ ] `ROADMAP.md` Phase 4: every box is checked and its annotation matches what the code does (no
      aspirational claims). Also skim this session's **uncommitted** Phase 5/9/13 refinement so you
      agree with it before it gets committed (see section 5).
- [ ] `ARCHITECTURE.md` decisions **008** (deny-by-default egress) and **009** (the per-VM tap),
      including the "as shipped" notes: they should describe the mechanism really in the tree (empty
      `ip=` gateway, connected-route-only, atomic /30, netns deferred to Phase 6).
- [ ] `docs/004-guest-networking.md` reads as a standalone lesson, makes no unmeasured performance
      claim (the "near-native throughput" line was removed), and keeps policy on the hoster's side
      (engine, not platform).

## 5. Commit (human git steps only)

There is no Phase 4 code left to commit; that is done. What remains uncommitted is small:

- [ ] The `ROADMAP.md` refinement from this session (Phase 5 network-identity `(decision)` + jailer
      note, the Phase 9 "host eBPF can't see in-guest syscalls" callout, the P13.2 reword). Commit it
      on its own with an imperative, phase-free, attribution-free message. Ask the agent to draft one
      if you want.
- [ ] Decide what to do with `REVIEW.md`: it is a throwaway working note. Either leave it untracked
      and delete it when done, or do not commit it. It is not part of the engine.
- [ ] Consider tagging a `v0.0.x` checkpoint per `ROADMAP.md` §0.6 now that Phase 4 is green (there
      are **no tags yet**: `git tag` is empty). No `CHANGELOG.md` yet (first written at `v0.1.0`).
      Tags are a human git step; the agent never runs `git tag`/`commit`/`push`.

## 6. Phase 5 readiness gate

Do not start **P5.1** (pause a booted VM and take a full memory + state snapshot) until:

- [ ] Phase 4's exit gate is genuinely met: a working demo (the three network tests under the
      privileged gate) *and* the `docs/004` writeup, both committed. (They are; this box is a
      final confirmation.)
- [ ] The tree is clean, or the only remaining WIP is the intentional roadmap refinement from
      section 5.
- [ ] `cargo xtask ci` and `cargo xtask ci-privileged` are both green on this box.
- [ ] **Snapshot headroom:** the pinned Firecracker (v1.9) supports the snapshot API, and there is
      disk for full-memory snapshot files (a snapshot is roughly the guest's RAM, so plan
      `mem_mib` per snapshot: `Limits::default().mem_mib` is 256 MiB today).
- [ ] You have read `ROADMAP.md` Phase 5 (P5.1 to P5.8) so the first box's scope is clear, in
      particular the two things this session flagged for that phase: the **network-identity on
      restore** `(decision)` (kernel `ip=` runs once at boot, so N clones can't be freshly addressed
      that way, see P5.5) and the **design-for-the-jailer** note (lay snapshot/warm-pool files out
      chroot-relative now so Phase 6 does not force a rewrite).
