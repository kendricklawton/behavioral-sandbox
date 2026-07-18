# 012. Confine the VMM: run Firecracker under its jailer *(2026-07-14)*

**Problem.** Hardware isolation (KVM) contains the *guest*, but the *VMM process* still runs on the
host with the driver's privileges. A Firecracker bug, or a guest that breaks out into the VMM, would
land in that context. The jailer is the host-side confinement: a chroot, a uid/gid drop, and a mount
namespace around Firecracker.

**Decision.** An **opt-in** [`BootConfig::jail`] runs Firecracker under Firecracker's `jailer` for a
plain read-write cold boot. Opt-in, not the new default, because the whole FC track was built
unjailed and every existing path (memory-sharing's shared read-only base, snapshot bundles, the pre-warmed pool,
the tap, bulk I/O) needs chroot-relative staging or a netns that later Phase-6 boxes add. This box
lands the mechanism on the simplest boot; the rest migrates behind it.
- **Chroot inside the scratch dir.** `--chroot-base-dir` is the VM's own `/tmp/agent-<pid>-<n>`
  scratch dir, so the jail is `<scratch>/firecracker/<id>/root/` and teardown's `remove_dir_all`
  reclaims the whole thing, no `/srv/jailer` residue. The jailer builds the chroot, `mknod`s the
  device nodes, places the process in a cgroup, `chroot`s, drops to the configured uid/gid, and
  `exec`s Firecracker (same pid, so the driver's `Child` is Firecracker and kill/reap are unchanged).
- **Stage resources after the socket is up, name them chroot-relative.** Firecracker opens the
  kernel and rootfs only on `PUT /boot-source` / `PUT /drives`, *after* the driver connects to the
  API socket, which only exists once the jailer has finished building the chroot. So the driver
  stages the kernel (`/kernel`, `0444`) and a read-write rootfs copy (`/rootfs.ext4`, `0600`) into
  the chroot at that point, `chown`ed to the jailed uid so the dropped-privilege VMM can open them,
  and names them by their chroot-relative path in the API. Staging-after-socket needs no hook into
  the jailer and never races its chroot construction (the mirror of how the vsock socket is dialed
  only after Firecracker binds it, decision 010).
- **Console survives.** The jailer is run **without `--daemonize`**, so Firecracker keeps the driver's
  piped stdout and the guest serial console still reaches [`crate::console`], the coupling the old
  module doc feared the jailer would break is preserved by choice.
- **cgroup is read, not assumed.** The jailer always creates the microVM's cgroup (there is no
  opt-out); on this cgroup-v2-only host it is passed `--cgroup-version 2` (the v1 default would fail
  to find the hierarchy). The exact cgroup dir is learned from `/proc/<pid>/cgroup` once the VMM is up
  (version-independent, no guess about the jailer's parent-cgroup layout) and removed (best-effort) on
  teardown, since it lives outside the scratch dir, like the tap. cgroup *limits* are P6.2.
- **Needs real root; refuses half-confinement.** The jailer's `mknod` of device nodes is `EPERM` in a
  non-initial user namespace even with `CAP_MKNOD`, so a jailed boot needs real root, the
  `unshare -Urn --map-root-user` trick that carries the other privileged tests is not enough (the
  test gates on real root and skips otherwise; validated in a privileged container). Combining `jail`
  with vsock, a NIC, the overlay, or bulk I/O is a typed error (deny-by-default over a half-jailed VM),
  and snapshotting a jailed VM is refused (its disk lives in the chroot).

**Alternatives considered.**
- **Jail by default.** Rejected for this box: it would force every existing path chroot-relative at
  once (P6.1–P6.7 in one change) and break the 23 unjailed privileged tests / the `unshare` dev flow.
  The additive `#[non_exhaustive]` knob is the same discipline every prior phase used
  (`read_only_root`, `enable_network`, …).
- **Hardlink / bind-mount resources instead of copying.** Hardlink `EXDEV`s across the `/tmp` (tmpfs)
  boundary; bind-mounting into the chroot wants the jailer's mount namespace we don't drive. Copying is
  the honest P6.1 cost; zero-copy staging of a shared read-only base rides with the overlay-under-jailer
  step, alongside snapshot memory-sharing.
- **`--daemonize`.** Rejected: it redirects stdio to `/dev/null`, which would sever the serial console
  the boot-readiness wait depends on.

**Consequences and notes.**
- **A jailed cold boot copies the kernel and rootfs into the chroot per VM** (measured ~4 s for a
  jailed plain-rootfs boot in a privileged container). Sharing-preserving staging (shared RO base) and
  jailed **snapshot/restore/pool**, **vsock/exec**, **networking**, and **bulk I/O** are later Phase-6
  steps behind this knob.
- **cgroup lifecycle is best-effort here.** Teardown reaps the VMM's (now-empty) cgroup; leak-proof,
  cgroup-**owned** lifetime (host-process death can't leak a VM) is **P6.7**, resource *limits* are
  **P6.2**, and Firecracker's seccomp filters are **P6.3**.
- **The jailer's netns is the sanctioned path to concurrent networked clones** (decisions 009/011's
  note): once networking is jailed, each VM's tap in its own netns removes the one-live-networked-
  clone limit. Kept on the Phase-6 radar.
- **`BootConfig` gained a public field**, but it is not one of the API-pinned types (`Sandbox`,
  `Limits`, `RunResult`, `VmmError`, the channel wire), and the jailer path is opt-in, so no downstream
  pin bump is forced.

**cgroup limits + seccomp (P6.2/P6.3 addendum, 2026-07-14).** The jailer already gives each VMM its
own cgroup; these two boxes fill it in.
- **CPU/memory limits via the jailer's `--cgroup`.** The driver derives the cap from the guest's own
  envelope: `cpu.max = <vcpus × 100000> 100000` (exactly `vcpus` cores) and `memory.max =
  (mem_mib + 128 MiB)` bytes. The 128 MiB overhead is the VMM's host-side footprint above guest RAM;
  guest RAM is the hard floor a full-guest workload needs, and the rootfs page cache above it is
  reclaimable, so the cap bounds a runaway without OOM-killing a normal boot (a 256 MiB guest was
  measured peaking ~82 MiB). **Delegation is required and gracefully optional:** the jailer sets
  limits by enabling controllers down from the cgroup v2 root, which only works when `cpu`+`memory`
  are already in the root's `subtree_control` and the root has no internal processes (a systemd host;
  a bare container fails the `subtree_control` write with `EBUSY`). So the driver probes
  `cgroup.subtree_control` first: if the controllers aren't delegated it logs a warning and passes no
  `--cgroup` (the jailed boot still runs, unlimited) rather than letting the jailer fail. `xtask setup`
  reports whether they're delegated. Enforcement *under load* (a mem-hog/fork-bomb actually bounded)
  is P6.4; the configurable policy shape is P6.5.
- **Seccomp is on by default; we just don't disable it.** Firecracker installs its built-in per-thread
  filters (advanced level: an allowlist per API/VMM/vCPU thread, `SIGSYS` on violation) at
  `InstanceStart`. We never pass `--no-seccomp`, so every boot is filtered. Verified by probing
  `/proc/<pid>/task/*/status`: pre-boot the process shows `Seccomp: 0`, but a running VM shows
  `Seccomp: 2` on every thread. This is why the jailer test asserts `Seccomp: 2` on the running VMM.
- **Guest-side process-tree reaping (P6.4, the P2.6 fix).** Separate from the host jailer cgroup: the
  *guest agent* now runs each command in its own **guest** cgroup (a `cgroup2` mount added to the
  rootfs init) and reaps the whole tree with `cgroup.kill` after the command exits or times out.
  cgroup membership is inherited by every fork and can't be escaped by `setsid`, so a double-forked
  grandchild or daemon that inherited the output pipe is killed rather than left holding it open (which
  used to wedge the agent's exec connection, since the pumps never saw EOF). Chosen over `killpg`
  precisely because a `setsid` daemon escapes the process group but not the cgroup; and it needs no
  controller delegation (no limits, just `cgroup.kill`), so it works even though the guest root cgroup
  holds processes. Best-effort: a guest without cgroup v2 falls back to the old direct-child kill.
  **Enrollment is child-side, via a trampoline (P6.8 hardening).** The first cut wrote the child's pid
  to `cgroup.procs` from the *agent* right after `spawn`, which **races the child's own forks**: on a
  1-vCPU guest the child usually runs first, so anything it forked before the write landed (a daemon,
  a fork storm's spinners) escaped the cgroup, survived `cgroup.kill`, and wedged the connection
  anyway. P6.8's fork-storm test caught this (the P6.4 daemon test had been winning the race). The fix
  is a tiny `sh` trampoline: the agent spawns `sh -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"'`,
  so the child **enrolls itself and only then `exec`s the real command** (same pid, wait/kill are
  untouched; argv is passed as real argv, never interpolated). Enrollment now strictly precedes the
  first instruction of the command, so the race cannot exist. The agent pre-resolves the program
  (`execvp`-style) so "no such binary" still reports as the typed `GuestExec` error rather than the
  trampoline's shell-style 127.
- **Alternatives considered.** Writing the cgroup limits ourselves (instead of `--cgroup`) was
  rejected: it would re-implement the jailer's controller-delegation dance for no gain and the same
  delegation dependency. A custom seccomp filter (`--seccomp-filter`) was rejected: Firecracker's
  built-in advanced filters are the maintained, audited default; a bespoke filter is only worth it to
  *tighten* beyond them, which nothing here needs.

**Isolation verified, not assumed (P6.6 addendum, 2026-07-14).** The jail is only worth what's actually
in force on the running VMM, so `boots_under_the_jailer` reads the live `/proc/<pid>` and asserts each
wall independently: the VMM is **chrooted** (its root's `(st_dev, st_ino)` via `/proc/<pid>/root/`
differs from the host root's, the link *text* renders as `/` after the jailer's pivot_root, so
identity, not path, is what's checked), runs as the **dropped uid** (not root), holds **no effective capabilities** (`CapEff` all
zeros, cleared by the setuid off root), runs under **`no_new_privs`** (so no setuid binary regains
privilege) and **seccomp filter mode**, and lives in its **own mount namespace** and **cgroup**. Layered
with KVM this is the second wall: a guest that breached hardware isolation into the VMM would land in
that box, able to name no host path, hold no capability, and make no syscall outside the filter. The
**deny-by-default** complement is verified host-safe: `Vm::boot` **refuses** `jail` combined with any
not-yet-jailed feature (a NIC, the overlay, bulk I/O) with a typed error before it probes for
KVM, so there is no half-confined escape hatch (a `jail_refuses_half_confined_boots` unit test in the
everyday gate; decision 013's "the isolation boundary never half-degrades"). Running a *hostile workload
inside* a jailed guest waited on exec-under-jail, since landed (P7.0a composed the jail with the vsock
exec channel), so P6.6's bar was the VMM-side confinement layers plus the refusal, not an in-guest exploit.
