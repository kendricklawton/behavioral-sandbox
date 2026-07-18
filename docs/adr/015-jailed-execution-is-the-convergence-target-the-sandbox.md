# 015. Jailed execution is the convergence target; the Sandbox surface jails by default *(2026-07-14)*

**Problem.** P6.1 landed the jailer on a plain read-write cold boot, and decisions 012/013 make a
jailed boot **refuse** vsock, a NIC, the overlay, and bulk I/O with a typed error. So the confinement
Phase 6 proves (chroot, uid/gid drop, seccomp, no effective caps, `no_new_privs`, cgroup) applies only
to a VM that **cannot run code**: the exec channel (vsock) and the jail are mutually exclusive today.
You get either a code channel (unjailed) or VMM confinement (codeless), never both in one run. Every
P6.x box is checked, so the migration that unifies them ("exec under the jailer") is tracked only in
prose annotations (ROADMAP P6.6/P6.8) with no box or decision owning it. Left there it can quietly
evaporate, and worse, Phase 7 would build the public `Sandbox` lifecycle surface on the **unjailed**
exec path and then have to retrofit confinement under a frozen, pinned public API.

**Decision.** Jailed exec is a **Phase 7 prerequisite**, and the public surface jails by default.
- **Convergence lands as explicit boxes, not prose.** Staging the vsock UDS, the tap, the overlay, and
  the input/output devices chroot-relative and jailed-uid-owned (so the jail composes with the exec
  channel) is tracked as ROADMAP boxes at the Phase 7 head (P7.0a to P7.0e), sequenced **before** the
  `Sandbox` API is frozen, not as prose.
- **`Sandbox::exec` runs jailed.** The engine's headline "run untrusted code" path is the confined one:
  the `Sandbox` layer defaults `jail` on, with an explicit opt-out for the unjailed path the FC track
  was built on. This flag-polarity flip (jail becomes the default the public surface presents) is the
  hard-to-reverse bit recorded here.
- **The exec channel + cgroup is the non-negotiable minimum.** vsock (to run code) plus the host VMM
  cgroup (to bound it) must compose with the jail. A path that proves too costly to stage chroot-relative
  on the pinned Firecracker (a candidate: bulk I/O) may stay opt-in unjailed behind a recorded typed
  refusal, but exec-under-jail is not optional.
- **Until convergence lands, the mutual exclusion stays a typed error** (decision 012), never a silent
  half-jail.

**Alternatives considered.**
- **Leave it as prose annotations.** Rejected: an unchecked-but-real gap tracked only in prose is exactly
  the silent-omission failure this class of review flags. It evaporates, and Phase 7 inherits an unjailed
  default by accident rather than by decision.
- **Build Phase 7's `Sandbox` on the unjailed exec path and jail later.** Rejected: retrofitting
  confinement under a frozen public API (the API-pinned `Sandbox`) is the expensive, one-way-door
  version. Ordering the jailer into Phase 6 was meant precisely to have confinement in hand before the
  surface is drawn.
- **Make jailed exec its own full phase.** Rejected as over-scoped: it is a staging and ownership
  migration of paths that already exist (vsock, tap, overlay, drives), not new mechanism. A handful of
  boxes, not a phase.

**Why.** The engine's reason to exist is running untrusted code behind **both** walls: hardware
isolation (KVM) and host-side VMM confinement (the jailer). Demonstrating each wall alone (KVM in P1 to
P5, the jailer in P6 on a codeless boot) is real progress, but the product claim is the two **composed**,
on the path a real workload takes. Sequencing the convergence before the `Sandbox` API freeze keeps the
default run confined and avoids a retrofit under a pinned public API.

**Consequences and notes.**
- ROADMAP gains explicit convergence boxes (P7.0a to P7.0e); the P6.6/P6.8 annotations that say "a later
  migration" now point at those boxes instead of at prose.
- Phase 7's `Limits`/`Sandbox` work assumes the jailed exec path exists; `require_limits` (decision 013's
  note) and jailed-by-default land together as the confined default surface.
- Jailed snapshot/restore and the pre-warmed pool under the jailer remain downstream of exec under the jailer
  (a jailed VM's disk lives in the chroot, decision 010), tracked with the same boxes.
- **Status: the P7.0a-e convergence is complete.** `jail` composes with every boot feature and with
  restore. Vsock: the socket binds chroot-relative at `/run/v.sock` (`jailed_exec_runs_a_command`).
  Overlay: the shared base bind-mounts into the chroot (shared-base path, propagated into the jailer's
  `MS_SLAVE` mount namespace; `jailed_overlay_is_dense_and_base_is_untouched`). NIC: the tap lives in a
  per-VM netns the jailer joins via `--netns` (decision 017). Bulk I/O: the input/output images are
  built in place inside the chroot (`jailed_bulk_io_round_trips_through_the_chroot`), with it, the
  mutual exclusion of the opening paragraph is fully retired and `Vm::boot`'s refusal block itself is
  gone. Restore: the bundle stages into the chroot (state copied; memory + shared base disk
  bind-mounted read-only), so pre-warmed clones and the `Pool` run confined
  (`restores_prewarmed_clones_under_the_jailer_and_pools_them`); snapshotting a *jailed* VM stays a typed
  refusal, snapshot an unjailed pre-warmed source, restore jailed clones (decision 010 consequence). The
  flag-polarity flip itself landed at P7.1: `Sandbox::open`/`Sandbox::boot` default `jail` on, and
  the opt-out is the differently-named `Sandbox::open_unjailed` constructor (mirrored by the CLI's
  `--unjailed`), so an unconfined sandbox is grep-visible in the caller's source, never a forgotten
  flag (`sandbox_opens_jailed_by_default`). **This decision is fully discharged.**
- The jailer's per-VM netns (decisions 009/011's note for concurrent networked clones) rides the
  jailed-networking box: once the tap is staged into the jail, its netns removes the one-live-networked-
  clone limit.
