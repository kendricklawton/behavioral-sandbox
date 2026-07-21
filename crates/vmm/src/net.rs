//! Per-VM guest networking, host side: a **per-VM network namespace** holding the tap that backs
//! virtio-net (ADRs 008 and 014: deny-by-default, and the netns model that retired the earlier
//! one-live-networked-clone limit).
//!
//! Each networked VM gets its own netns (`ip netns add <name>`); the tap lives *inside* it, and the
//! VMM runs there too (the jailer's `--netns`, or `ip netns exec` for a direct boot). Because the tap
//! is namespaced, every VM reuses the **same fixed** name/MAC/`/30`/v6-link without any host-global
//! allocator: two VMs holding an identically-named tap on `10.200.0.1/30` (and `fd00:200::1/64`)
//! never collide, and a restored clone wakes with the snapshot's baked-in identity already correct in
//! its own netns (no re-addressing). The link is **dual-stack** (ADR 008): v4 and v6 are both
//! deny-by-default, each with a connected-prefix route only and no default route.
//! That is what retires the one-live-networked-clone limit (v1.9 has no `network_overrides`, so restore
//! must present the baked tap name, fine when each clone owns a private netns). Teardown is one op:
//! `ip netns del <name>` reclaims the netns and the tap in it.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::drives::tool_spawn_error;
use crate::VmmError;

/// The tap name inside every per-VM netns. Fixed (not allocated): the netns makes it unique, and the
/// `fc` prefix keeps the eBPF-binding handle contract ([`RunningVm::tap_name`](crate::RunningVm)).
pub(crate) const TAP_NAME: &str = "fc0";

/// The guest NIC's MAC: a locally-administered unicast address (first octet `0x02`: LAA bit set,
/// multicast bit clear). Fixed per VM, each tap is its own L2 segment in its own netns, so MAC
/// uniqueness across VMs is irrelevant.
const GUEST_MAC: &str = "02:00:00:00:00:02";

/// The host end of the point-to-point link, assigned to the tap inside the netns. The guest reaches
/// this (and nothing else, deny-by-default, ADR 008); it is unreachable from the host's own
/// netns, which is by design (the driver talks to the guest over vsock, never IP).
const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// The guest end of the /30, configured on the guest's `eth0` (via the kernel `ip=` param at cold
/// boot, or already baked into a restored snapshot's memory image).
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);

/// The prefix length of each per-VM link: a `/30` (netmask `255.255.255.252`), the smallest subnet
/// that holds two usable hosts (the host end and the guest end) and nothing else.
pub(crate) const HOST_PREFIX: u8 = 30;

/// The host end of the per-VM link's **IPv6** ULA (`fc00::/7`, RFC 4193), the v6 analogue of
/// [`HOST_IP`]. Fixed per netns, exactly like the v4 identity: the per-VM netns provides uniqueness,
/// so every VM reuses the same address without a host-global allocator. The guest reaches this and
/// nothing else (deny-by-default, ADR 008): the tap carries only the connected-prefix route, and no
/// v6 default route is ever installed, so v6 egress is denied by construction just as v4 is.
const HOST_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 1);

/// The guest end of the per-VM v6 link, the v6 analogue of [`GUEST_IP`]. The kernel `ip=` boot param
/// (`CONFIG_IP_PNP`) is IPv4-only, so unlike the v4 end this cannot ride `ip=`: the driver passes it
/// as the `agent_guest_ip6=<addr>/<plen>` cmdline token (`spawn.rs`) and a guest sysinit step applies
/// it (`rootfs.rs`). Sourced here so the host stays the single owner of the address (no guest-baked
/// literal to drift from this one).
pub(crate) const GUEST_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 2);

/// The prefix length of the per-VM v6 link: a `/64`, the conventional IPv6 link size. Deny-by-default
/// does not rest on the prefix length (a v6 link is a /64 by convention, not a /127): it rests on the
/// **absent v6 default route**, exactly as the v4 `/30` link's does, so the guest can reach only the
/// connected host end.
pub(crate) const HOST_PREFIX6: u8 = 64;

/// A per-VM **network namespace** holding the tap that backs the guest's virtio-net. The driver
/// creates the netns and the tap inside it (`ip`, needs `CAP_NET_ADMIN`), the VMM joins the netns (the
/// jailer's `--netns`, or `ip netns exec` for a direct boot), and every teardown path deletes the
/// netns (`ip netns del`, which cascades the tap away). Named after the VM's scratch dir, so a crashed
/// driver's orphaned netns is reclaimable by the same dir-keyed sweep as its scratch dir.
/// A per-VM point-to-point IP link: the **host end** (assigned to the tap, inside the netns) and the
/// **guest end** (on the guest's `eth0`), plus the prefix length. Generic over the address family, so
/// v4 and v6 are the *same shape*: a v6 link is just another `GuestLink`, present only when v6 is
/// actually live (see [`RunningVm::ipv6`](crate::RunningVm::ipv6)). The guest reaches the host end and
/// nothing beyond it (deny-by-default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuestLink<A> {
    /// The host end (on the tap).
    pub host: A,
    /// The guest end (on the guest's `eth0`).
    pub guest: A,
    /// The link's prefix length (`/30` for v4, `/64` for v6).
    pub prefix_len: u8,
}

impl<A> GuestLink<A> {
    /// Construct a link from its two ends and prefix length (crate-internal: only the driver mints
    /// these; downstream reads them off a [`RunningVm`](crate::RunningVm)).
    pub(crate) fn new(host: A, guest: A, prefix_len: u8) -> Self {
        Self {
            host,
            guest,
            prefix_len,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Tap {
    /// The network namespace name (the VM's scratch-dir name), also the `/run/netns/<name>` handle.
    pub(crate) netns: String,
    /// The tap interface name inside the netns (`fc0`, the eBPF-binding handle the loader resolves
    /// *within* the netns).
    pub(crate) name: String,
    /// The guest NIC's MAC.
    pub(crate) mac: String,
    /// The IPv4 link (host + guest ends of the `/30`). Always present on a networked VM.
    pub(crate) v4: GuestLink<Ipv4Addr>,
    /// The IPv6 link, `Some` **iff** the host v6 address was assigned. IPv6 is best-effort (absent on
    /// an IPv6-disabled host, [`add_host_v6`]), so `None` means v6 is not live, callers get honest
    /// availability rather than an address that silently doesn't work.
    pub(crate) v6: Option<GuestLink<Ipv6Addr>>,
}

impl Tap {
    /// Create the per-VM netns `name`, then the tap inside it with the host ends of the v4 /30 and
    /// the v6 link assigned (the v6 end best-effort, see [`add_host_v6`]).
    /// Shells out to `ip` (iproute2), consistent with the driver's other host-tool calls; needs
    /// `CAP_NET_ADMIN`, so this only succeeds under the privileged test/runtime tier.
    ///
    /// `owner` sets the tap's `user`/`group` to the jailed uid/gid when the VMM is jailed: a jailed
    /// Firecracker runs unprivileged (no `CAP_NET_ADMIN`), so it can only attach a tap it owns. A
    /// direct boot runs Firecracker with the driver's own privilege, which can attach any tap, so it
    /// passes `None` (root-owned). On any setup failure the half-built netns is reclaimed, so a failed
    /// create never leaks a netns or tap.
    pub(crate) fn create(netns: &str, owner: Option<(u32, u32)>) -> Result<Tap, VmmError> {
        netns_add(netns)?;
        let v6_up = match Self::build_tap(netns, owner) {
            Ok(up) => up,
            Err(e) => {
                // Reclaim the netns (and any tap already added in it) so a failed create leaks nothing.
                netns_del(netns);
                return Err(e);
            }
        };
        Ok(Tap {
            netns: netns.to_string(),
            name: TAP_NAME.to_string(),
            mac: GUEST_MAC.to_string(),
            v4: GuestLink::new(HOST_IP, GUEST_IP, HOST_PREFIX),
            // The v6 link is present only when its host end actually landed on the tap.
            v6: v6_up.then(|| GuestLink::new(HOST_IP6, GUEST_IP6, HOST_PREFIX6)),
        })
    }

    /// Bring up `lo`, create + up the tap, and assign the host end of the v4 /30, all *inside* the
    /// netns. Returns whether the **v6** host end was also assigned (best-effort, [`add_host_v6`]).
    fn build_tap(netns: &str, owner: Option<(u32, u32)>) -> Result<bool, VmmError> {
        ip_in_ns(netns, &["link", "set", "dev", "lo", "up"])?;
        let (uid, gid);
        let mut add = vec!["tuntap", "add", "dev", TAP_NAME, "mode", "tap"];
        if let Some((u, g)) = owner {
            uid = u.to_string();
            gid = g.to_string();
            add.extend_from_slice(&["user", &uid, "group", &gid]);
        }
        ip_in_ns(netns, &add)?;
        ip_in_ns(netns, &["link", "set", "dev", TAP_NAME, "up"])?;
        let cidr = format!("{HOST_IP}/{HOST_PREFIX}");
        ip_in_ns(netns, &["addr", "add", &cidr, "dev", TAP_NAME])?;
        Ok(add_host_v6(netns))
    }

    /// The `/run/netns/<name>` handle to pass the jailer as `--netns`, so it joins this netns before
    /// dropping privileges and exec'ing Firecracker.
    pub(crate) fn netns_path(&self) -> PathBuf {
        netns_path(&self.netns)
    }

    /// Best-effort delete for teardown/`Drop` context: remove the whole netns (which cascades the tap,
    /// its address, and its route away). A failure is logged, never propagated or panicked (the host
    /// path is `#![forbid(unsafe_code)]` and must not panic on teardown).
    pub(crate) fn delete(&self) {
        netns_del(&self.netns);
    }

    /// Whether this VM's netns still exists, teardown checks it after [`delete`](Self::delete) so it
    /// only reclaims the scratch dir once the netns is confirmed gone (an undeleted netns must keep
    /// its dir to stay visible to the dir-keyed orphan sweep).
    pub(crate) fn netns_exists(&self) -> bool {
        netns_exists(&self.netns)
    }
}

/// The `/run/netns/<name>` path `ip netns` bind-mounts a namespace handle at, and the jailer's
/// `--netns` argument.
pub(crate) fn netns_path(name: &str) -> PathBuf {
    Path::new("/run/netns").join(name)
}

/// `ip netns add <name>`, creating the per-VM network namespace. The name is `agent-<pid>-<seq>` with
/// **our own** pid (`std::process::id()`), so a collision can only be residue from a *prior* process
/// that shared our pid, necessarily dead, since pids are unique among the living, and its teardown
/// left the netns behind (e.g. a dir-less orphan the sweep never saw). So on collision we reclaim the
/// stale namespace and retry once: this can never delete a live peer's netns (the name embeds our pid),
/// and it stops an unreclaimed orphan from permanently blocking pid reuse with a "File exists". A
/// second failure, or a failure that is *not* a collision (perms, missing `ip`), is the typed error.
fn netns_add(name: &str) -> Result<(), VmmError> {
    match ip_netns_add(name) {
        Ok(()) => Ok(()),
        Err(first) => {
            // Only a name collision is retryable; anything else (no `CAP_NET_ADMIN`, missing binary)
            // is a real failure. `netns_exists` tells them apart without parsing `ip`'s message.
            if !netns_exists(name) {
                return Err(first);
            }
            tracing::warn!(
                netns = %name,
                "netns name already exists (residue from a dead prior incarnation of this pid); \
                 reclaiming it and retrying"
            );
            netns_del(name);
            ip_netns_add(name)
        }
    }
}

/// The raw `ip netns add <name>` command, mapping a spawn failure or nonzero exit to a typed error.
/// Split from [`netns_add`] so the reclaim-and-retry policy lives in one place.
fn ip_netns_add(name: &str) -> Result<(), VmmError> {
    let out = Command::new("ip")
        .args(["netns", "add", name])
        .output()
        .map_err(|e| tool_spawn_error("ip", e))?;
    if out.status.success() {
        return Ok(());
    }
    Err(VmmError::Vmm(format!(
        "ip netns add {name}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

/// `ip netns del <name>`, best-effort: every teardown and half-configured-boot cleanup routes through
/// here (and the orphan sweep, for a dead driver's netns). Deleting the netns cascades away the tap in
/// it. A failure is logged, never propagated or panicked (the no-panic host path), so an orphaned netns
/// is at least visible.
pub(crate) fn netns_del(name: &str) {
    // Bounded, because this runs inside teardown/`Drop`: `ip netns del` can wedge in the kernel (rtnl
    // lock, a device that won't release its refcount), and a plain `.output()` would hang `Drop`. On
    // timeout `run_bounded` detaches; the netns then lingers, which `reclaim_scratch` already handles
    // by keeping the scratch dir so the orphan sweep reclaims the pair (a failed delete's existing path).
    let mut cmd = Command::new("ip");
    cmd.args(["netns", "del", name]);
    match crate::proc::run_bounded(cmd, crate::proc::TEARDOWN_HELPER_TIMEOUT, "ip netns del") {
        crate::proc::Bounded::Exited { success: true, .. } => {}
        crate::proc::Bounded::Exited { stderr, .. } => tracing::warn!(
            netns = %name,
            error = %stderr.trim(),
            "failed to delete network namespace"
        ),
        // Detached (wedged past the wall, or spawn/poll failed): logged inside `run_bounded`; the
        // namespace is left behind for the sweep, exactly as a failed delete would leave it.
        crate::proc::Bounded::Detached => {}
    }
}

/// Whether a network namespace named `name` currently exists, via `ip netns list` membership. Used by
/// the orphan sweep to tell a dead driver's leaked netns (reclaim it) from one already gone.
pub(crate) fn netns_exists(name: &str) -> bool {
    netns_path(name).exists()
}

/// Run `ip <args>` inside network namespace `netns` (`ip netns exec <netns> ip <args>`), mapping a
/// missing binary or a nonzero exit to a typed error. `ip netns exec` `setns`es into the namespace
/// then execs, so the tap operations land in the VM's netns, not the host's.
fn ip_in_ns(netns: &str, args: &[&str]) -> Result<(), VmmError> {
    let mut full = vec!["netns", "exec", netns, "ip"];
    full.extend_from_slice(args);
    run_ip(&full)
}

/// Assign the host end of the v6 link to the tap, **best-effort**. Unlike the v4 `/30` (every Linux
/// host has IPv4), IPv6 can be administratively off on the host: `ipv6.disable=1` on the host kernel,
/// `net.ipv6.conf.all.disable_ipv6=1`, or a kernel without `CONFIG_IPV6`, any of which makes
/// `ip -6 addr add` fail. That must **not** fail the whole networked boot, doing so would regress even
/// v4-only sandboxes on an IPv6-off host. Isolation does not rest on this address: deny-by-default is
/// the absent v6 default route plus the eBPF egress hook (ADR 008), neither of which needs the tap to
/// hold a v6 address. So per ADR 032 (fail-open-for-observation) this warns and returns on failure,
/// leaving the v6 link simply absent while v4 and isolation are unaffected.
///
/// `nodad` skips duplicate-address detection: the point-to-point link has exactly one other endpoint
/// (the guest, on a different address), so DAD would only add link-up multicast chatter with nothing
/// to detect. A DAD-less `nodad`-unaware `ip` just falls into the same best-effort warning.
///
/// Returns whether the address landed, so the caller records the v6 link as present only when it is
/// actually live (the guest cmdline token and [`RunningVm::ipv6`](crate::RunningVm) both key off this).
fn add_host_v6(netns: &str) -> bool {
    let cidr6 = format!("{HOST_IP6}/{HOST_PREFIX6}");
    match ip_in_ns(
        netns,
        &["-6", "addr", "add", &cidr6, "dev", TAP_NAME, "nodad"],
    ) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                netns = %netns,
                error = %e,
                "could not assign the host IPv6 address to the tap; the v6 link is absent on this host \
                 (IPv6 disabled in the host kernel?). The v4 link and isolation are unaffected."
            );
            false
        }
    }
}

/// Run `ip <args>`, mapping a missing binary or a nonzero exit to a typed error.
fn run_ip(args: &[&str]) -> Result<(), VmmError> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| tool_spawn_error("ip", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(VmmError::Vmm(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_identity_is_well_formed() {
        // The tap name keeps the `fc` prefix the eBPF-binding handle contract promises.
        assert!(TAP_NAME.starts_with("fc"));
        assert!(TAP_NAME.len() <= 15, "within IFNAMSIZ-1");
        // A locally-administered unicast MAC: LAA bit (0x02) set, multicast bit (0x01) clear.
        assert!(GUEST_MAC.starts_with("02:"));
        // A point-to-point /30: the guest is the host end's immediate neighbour.
        assert_eq!(HOST_PREFIX, 30);
        assert_eq!(u32::from(GUEST_IP), u32::from(HOST_IP) + 1);
        assert_eq!(HOST_IP.octets()[0..2], [10, 200]);
        // The v6 link mirrors the v4 one: a ULA (`fc00::/7`, so the top 7 bits are `1111110`), the
        // guest one address above the host end, on a conventional /64. (`is_unique_local` is still
        // unstable on `Ipv6Addr`, so this checks the prefix by octet.)
        assert_eq!(HOST_PREFIX6, 64);
        assert_eq!(HOST_IP6.octets()[0] & 0xfe, 0xfc);
        assert_eq!(GUEST_IP6.octets()[0] & 0xfe, 0xfc);
        assert_eq!(u128::from(GUEST_IP6), u128::from(HOST_IP6) + 1);
    }

    #[test]
    fn netns_path_is_the_iproute2_handle() {
        assert_eq!(netns_path("agent-42-0"), Path::new("/run/netns/agent-42-0"));
    }
}
