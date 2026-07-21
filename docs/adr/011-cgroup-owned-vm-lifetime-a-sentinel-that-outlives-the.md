# 011. Cgroup-owned VM lifetime: a sentinel that outlives the driver, and a file-based kill handle *(2026-07-14)*

**Context.** A VMM outlives nothing it does not force to die. The obvious teardown path, `Drop`, is
correct on every path the driver survives, but the driver does not always survive: a `SIGKILL`, an OOM
kill, or a Ctrl-C leaves `Drop` unrun, and the Firecracker children live on as orphans holding KVM
memory. No in-process mechanism closes this: a signal handler cannot catch `SIGKILL`, and would only
paper over `SIGINT`. So VM lifetime cannot be owned by anything inside the driver process; it has to be
owned by something the kernel keeps after the driver is gone. A second force pulls the same way: an
embedder blocked in `exec` (`&self`) needs a way to force a wedged run down, yet `shutdown` consumes
`self`, which the blocked call still borrows, so the kill switch cannot be the shutdown path either.

**Decision.** Crash-only design: the VM's lifetime is owned by things that survive the driver's death,
all built from the cgroup the VM already has.
- **A per-VM lifetime cgroup.** Every directly-spawned VMM is enrolled (via `cgroup.procs`) in a fresh
  child of the *driver's own* cgroup, the one place an unprivileged process is guaranteed write access
  when anything is (its delegated systemd session scope; the same no-controllers trick as the guest
  agent's exec cgroups, decision 010, so no delegation needed and no internal-process rule).
  The cgroup gives the whole VMM one kernel handle: `cgroup.kill` SIGKILLs every member atomically, no
  pid races. A **jailed** VMM is *not* enrolled, the jailer moves it into its own cgroup, and a second
  `cgroup.procs` write would race that placement (last write wins membership and could yank the VMM out
  of its limits); instead the driver precomputes the jailer's cgroup path (`<root>/<exec-name>/<id>`,
  stable because the jailer requires the exec name to contain "firecracker") and cross-checks it against
  `/proc` after boot, warning on a mismatch.
- **A sentinel that outlives the driver.** A tiny `sh` child per VM, in its **own process group** (a
  terminal Ctrl-C signals the driver's group; the sentinel must survive it to act), blocks reading a
  pipe whose write end only the driver holds. The kernel closes that write end on *any* driver death,
  clean exit, `SIGKILL`, OOM, so EOF **is** the death notification: no polling, no daemon, no signals.
  The sentinel then writes `cgroup.kill` on the VM's cgroup(s) and removes them (bounded retries). On a
  clean teardown the dirs are already gone when its EOF arrives, and it exits without acting; teardown
  reaps it with a bounded wait (a wedged sentinel is killed, never waited on forever).
- **A [`KillHandle`]** (public, cheap `Clone`, `Send + Sync`): kills through the same `cgroup.kill`
  file, which is why it needs no reference to the `Child` and no `unsafe`, so any thread can force a
  VM down; the blocked `exec` returns a typed error when the vsock peer closes. Where no cgroup exists
  it falls back to signalling the pid (safe while the VM is unreaped; a `torn_down` flag set *before*
  the reap makes late kills no-ops, so a recycled pid is never signalled). Surfaced on `RunningVm`
  and, since the sandbox lifecycle API landed, on `Sandbox` (`kill_handle`).

**Alternatives considered.**
- **`PR_SET_PDEATHSIG` on the child.** The classic answer, rejected: it needs a `pre_exec` hook
  (`unsafe`, forbidden on the host path), and it is delivered on the death of the spawning *thread*, not
  the process (a dying spawner thread would kill a healthy driver's VM).
- **A janitor daemon / pid files.** Rejected: a daemon is platform territory (guardrail 4), and pid
  files race pid recycling. The sentinel is per-VM, ephemeral, and dies right after cleanup.
- **A signal handler.** Rejected as the mechanism (only papers over `SIGINT`; `SIGKILL`/OOM remain),
  which is exactly why this work waited until the cgroup existed to build on.
- **`kill(2)` from the handle.** Needs `unsafe` (or a libc shim); the cgroup file is the safe,
  aliasable kill switch the cgroup already gave us, the handle holds a path, not a process.

**Consequences and notes.**
- Proven by a real crash, not simulation: `driver_death_cannot_leak_a_vm` SIGKILLs a subprocess driver
  mid-run and watches the sentinel kill the VMM and remove its cgroup (~1 s). The sentinel's EOF
  mechanism and the kill handle's semantics are also unit-tested in the everyday host gate against
  stand-in directories (no VM, no privileges).
- The unprotected windows, stated honestly: spawn → enrollment (microseconds, unjailed) and spawn → the
  jailer's self-placement (milliseconds, jailed), a driver killed inside them leaks that one VMM, as
  before. A host with no writable cgroup v2 degrades to `Drop`-only teardown with a warning (fail-open,
  decision 010: this is leak-proofing, not the isolation boundary).
- The sentinel owns the VM *process tree* and its cgroups; a crashed driver's scratch dirs and netns
  (holding its tap) are inert residue (no CPU, no RAM, no KVM), left to the next boot's leak checks
  or a sweep, deliberately not the sentinel's job, to keep it too simple to be wrong.
- The host now needs `sh` at runtime (the sentinel, and the kill handle's pid fallback). Precedent: the
  driver already shells out to `ip` for taps.
