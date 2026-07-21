# 014. Per-VM network namespace: the tap lives in the VM's netns, not the host's *(2026-07-14; supersedes the earlier tap and restore-identity netns notes)*

**Context.** A networked VM boots either jailed or direct, and both paths constrain where its
tap can live. Two standing forces set the requirement. First, the jailer confines the VMM but runs it
unprivileged, so a networked jailed boot needs its tap reachable from *inside* the jail's isolation,
while the VMM itself holds no privilege to create or attach a host tap. Second, snapshot restore's
one-live-networked-clone limit: Firecracker v1.9 has no `network_overrides`, so restore must present a
tap with the snapshot's **baked-in name**, and in a single shared host netns that name can exist only
once, so only one networked clone could ever be live. The per-VM tap and restore-identity decisions
both deferred the same answer: **per-VM network namespaces**. What is at stake is the whole networked story (jailed boot,
concurrent clones, and kernel-level isolation between VMs) resting on one placement choice.

**Decision.** Every networked VM runs its tap in its **own network namespace**. The driver creates the
netns (`ip netns add <name>`, named after the VM's scratch dir), creates the tap inside it, and the VMM
joins it: the jailer via its `--netns` flag (it `setns`es as root before dropping privileges), a direct
boot via `ip netns exec <ns> firecracker …` (which `setns`es then execs, so the child pid *is*
firecracker). Teardown is one op: `ip netns del <name>` cascades the tap away.
- **Fixed identity, no allocator.** Because the tap is namespaced, every VM reuses the *same* fixed tap
  name (`fc0`), MAC, and `/30` (`10.200.0.1`/`.2`). The host-global name/MAC/subnet allocator, the
  `ip addr add`-as-/30-reservation retry, and `Tap::create_named` all go away.
- **The clone limit is retired.** N clones each recreate the baked-in `fc0` in their own netns; the
  baked-in guest address/MAC/routes are already correct there, so **restore no longer re-addresses the
  guest** (`apply_guest_net_identity` is deleted) and a networked snapshot **no longer
  requires vsock** (that requirement existed only to carry the re-addressing).
- **Isolation is kernel-enforced.** Per-VM netns replaces the earlier unique-/30 reservation with a
  stronger boundary: two VMs holding identically-named taps on the same `/30` share no path, because each
  is its own network stack. Deny-by-default is unchanged (empty `ip=` gateway → connected route only), and
  now the host's *own* netns can't reach the guest either, the driver only ever talks to it over vsock.
- **The jailed tap is uid-owned.** A jailed Firecracker holds no `CAP_NET_ADMIN`, so it can only attach
  a tap it owns; the driver creates the jailed VM's tap with `user`/`group` set to the jailed uid.

**The propagation fact this rests on (probed, not assumed).** The jailer runs the VMM in an `MS_SLAVE`
mount namespace; `ip netns exec` and `--netns` both `setns` into a netns the driver created in the host
netns. Verified locally: `ip netns` handles live at `/run/netns/<name>`, and two netns hold
identically-named taps on one `/30` without collision. The whole unjailed path (boot, restore, two
concurrent clones, the sweep) is proven end-to-end with real Firecracker VMs under `unshare -Urn`; the
jailer's `--netns` (real root) is proven by the `ci-privileged` gate.

**Alternatives considered.**
- **Keep the tap in the host netns, bridge per-VM with veth + unique /30s.** Rejected: reintroduces the
  host-global allocator and the clone-name collision, is weaker isolation (shared stack), and is more
  moving parts than one netns per VM.
- **Bump Firecracker for `network_overrides`.** Rejected as the sole fix: it addresses only the clone
  limit, not jailed networking or kernel-level isolation, and a version bump is its own decision.
- **Keep the in-guest re-addressing under netns.** Rejected: pointless work, the baked-in identity is
  already collision-free in a private netns, so re-addressing would flush and re-add the same address.

**Consequences.**
- The orphan sweep now reclaims an orphaned **netns** (named after the dead dir) instead of an orphaned
  host tap; its `tap`-record file is gone (the netns name is derivable from the dir). The
  finite-`/16`-pool DoS the sweep guarded against is *eliminated* (every netns reuses one `/30`), so the
  sweep's network role is residue hygiene, not pool-exhaustion defence. `SweepReport.taps_reclaimed`
  became `netns_reclaimed`.
- `RunningVm` gains `netns()`; the eBPF loader must **enter the netns** to attach to the tap
  (`tap_name()` resolves inside it, not the host netns).
- Jailed snapshot/restore inherits this: a jailed networked clone stages its netns the same way.

**Relationship to prior decisions.** Resolves the netns notes the earlier per-VM tap and
restore-identity decisions deferred ("per-VM network-namespace isolation is deferred"; "only one
networked clone can be live … per-VM network namespaces … deferred"); both records are since retired.
