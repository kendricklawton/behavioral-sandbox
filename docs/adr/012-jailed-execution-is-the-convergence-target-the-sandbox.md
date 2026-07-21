# 012. Jailed execution is the convergence target; the Sandbox surface jails by default *(2026-07-14)*

**Context.** The engine's reason to exist is running untrusted code behind **both** walls at once:
hardware isolation (KVM) and host-side VMM confinement (the jailer). Each wall has been shown alone,
KVM in the driver's early lifecycle work, the jailer later on a codeless boot, and that is real
progress, but the product claim is the two **composed**, on the path a real workload takes. Two facts
put the walls in tension. The jailer runs on a plain read-write cold boot, and decision 010's
no-half-confinement rule makes a jailed boot **refuse** vsock, a NIC, the overlay, and bulk I/O with a
typed error. So the confinement
the jailer work proves (chroot, uid/gid drop, seccomp, no effective caps, `no_new_privs`, cgroup)
applies only to a VM that **cannot run code**: the exec channel (vsock) and the jail are mutually
exclusive. A run gives either a code channel (unjailed) or VMM confinement (codeless), never both.

The migration that unifies them ("exec under the jailer") is a staging and ownership change of paths
that already exist (vsock, tap, overlay, drives), not new mechanism. Left tracked only in prose
annotations, with no box or decision owning it, it can quietly evaporate, and the public `Sandbox`
lifecycle surface would then be built on the **unjailed** exec path and have to retrofit confinement
under a frozen, pinned public API. That retrofit is the expensive, one-way-door version; ordering the
jailer in before the surface is drawn was meant precisely to have confinement in hand first. Making the
convergence its own full phase over-scopes it: it is a handful of boxes, not new mechanism.

**Decision.** Jailed exec is a prerequisite for the public `Sandbox` surface, and that surface jails by
default.
- **Convergence lands as explicit boxes, not prose.** Staging the vsock UDS, the tap, the overlay, and
  the input/output devices chroot-relative and jailed-uid-owned (so the jail composes with the exec
  channel) is tracked as explicit roadmap boxes at the head of the `Sandbox`-surface work, sequenced
  **before** the `Sandbox` API is frozen, not as prose.
- **`Sandbox::exec` runs jailed.** The engine's headline "run untrusted code" path is the confined one:
  the `Sandbox` layer defaults `jail` on, with an explicit opt-out for the unjailed path the Firecracker
  track was built on. This flag-polarity flip (jail becomes the default the public surface presents) is
  the hard-to-reverse bit recorded here.
- **The exec channel + cgroup is the non-negotiable minimum.** vsock (to run code) plus the host VMM
  cgroup (to bound it) must compose with the jail. A path that proves too costly to stage chroot-relative
  on the pinned Firecracker (a candidate: bulk I/O) may stay opt-in unjailed behind a recorded typed
  refusal, but exec-under-jail is not optional.
- **Until convergence lands, the mutual exclusion stays a typed error**, never a silent half-jail.

**Consequences.**
- The roadmap gains explicit convergence boxes; the annotations that once said "a later migration" now
  point at those boxes instead of at prose.
- The `Limits`/`Sandbox` work assumes the jailed exec path exists; `require_limits` (decision 010's
  note) and jailed-by-default land together as the confined default surface.
- Jailed snapshot/restore and the pre-warmed pool under the jailer remain downstream of exec under the
  jailer (a jailed VM's disk lives in the chroot, decision 009), tracked with the same boxes.
- The jailer's per-VM netns (decision 014's answer for concurrent networked clones) rides the
  jailed-networking box: once the tap is staged into the jail, its netns removes the
  one-live-networked-clone limit.
- In the current tree the convergence is complete: `jail` composes with every boot feature and with
  restore. Vsock: the socket binds chroot-relative at `/run/v.sock` (`jailed_exec_runs_a_command`).
  Overlay: the shared base bind-mounts into the chroot (shared-base path, propagated into the jailer's
  `MS_SLAVE` mount namespace; `jailed_overlay_is_dense_and_base_is_untouched`). NIC: the tap lives in a
  per-VM netns the jailer joins via `--netns` (decision 014). Bulk I/O: the input/output images are
  built in place inside the chroot (`jailed_bulk_io_round_trips_through_the_chroot`), with it, the
  mutual exclusion of the opening paragraphs is fully retired and `Vm::boot`'s refusal block itself is
  gone. Restore: the bundle stages into the chroot (state copied; memory + shared base disk
  bind-mounted read-only), so pre-warmed clones and the `Pool` run confined
  (`restores_prewarmed_clones_under_the_jailer_and_pools_them`); snapshotting a *jailed* VM stays a
  typed refusal, snapshot an unjailed pre-warmed source, restore jailed clones (decision 009
  consequence). The flag-polarity flip landed with the surface: `Sandbox::open`/`Sandbox::boot` default
  `jail` on, and the opt-out is the differently-named `Sandbox::open_unjailed` constructor (mirrored by
  the CLI's `--unjailed`), so an unconfined sandbox is grep-visible in the caller's source, never a
  forgotten flag (`sandbox_opens_jailed_by_default`). This decision is fully discharged.
