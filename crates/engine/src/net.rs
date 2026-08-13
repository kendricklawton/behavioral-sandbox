//! Per-VM guest networking, host side: a **per-VM network namespace** holding the tap that backs
//! virtio-net, deny-by-default.
//!
//! - **Namespaced identity.** The tap lives *inside* the netns and the VMM runs there too, so every
//!   VM reuses the same fixed name, MAC, `/30`, and v6 link with no host-global allocator, and a
//!   restored clone wakes with the snapshot's baked-in identity already correct.
//! - **Dual-stack, deny-by-default.** Each family gets a connected-prefix route, no default route.
//! - **Teardown is one op.** `ip netns del <name>` reclaims the netns and the tap in it.
//!
//! The pinned Firecracker *can* rename a restored clone's host tap, so the namespace is not a
//! workaround for a missing API: it keeps every clone off one shared host netns and routing table,
//! gives the eBPF egress hook a per-VM interface to bind, and keeps restore on cold boot's path.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::VmmError;

/// The tap name inside every per-VM netns. Fixed, not allocated: the netns makes it unique, and the
/// `fc` prefix keeps the eBPF-binding handle contract
/// ([`RunningVm::tap_name`](crate::RunningVm)).
pub(crate) const TAP_NAME: &str = "fc0";

/// The guest NIC's MAC: a locally-administered unicast address (first octet `0x02`: LAA bit set,
/// multicast bit clear). Fixed, since each tap is its own L2 segment in its own netns.
const GUEST_MAC: &str = "02:00:00:00:00:02";

/// The host end of the point-to-point link, assigned to the tap inside the netns. Unreachable from
/// the host's own netns, which is by design: the driver talks to the guest over vsock, never IP.
const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// The guest end of the /30, configured on the guest's `eth0` (via the kernel `ip=` param at cold
/// boot, or already baked into a restored snapshot's memory image).
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);

/// The prefix length of each per-VM link: a `/30` (netmask `255.255.255.252`), the smallest subnet
/// that holds two usable hosts (the host end and the guest end) and nothing else.
pub(crate) const HOST_PREFIX: u8 = 30;

/// The host end of the per-VM link's **IPv6** ULA (`fc00::/7`, RFC 4193), the v6 analogue of
/// [`HOST_IP`]. Fixed per netns like the v4 identity, and the only v6 address the guest reaches.
const HOST_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 1);

/// The guest end of the per-VM v6 link, the v6 analogue of [`GUEST_IP`]. The kernel `ip=` param
/// (`CONFIG_IP_PNP`) is IPv4-only, so this rides the `guest_ip6=<addr>/<plen>` cmdline token
/// (`spawn.rs`) that a guest sysinit step applies (`rootfs.rs`).
pub(crate) const GUEST_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, 2);

/// The prefix length of the per-VM v6 link: a `/64`, the conventional IPv6 link size.
/// Deny-by-default rests on the **absent v6 default route**, not on this length.
pub(crate) const HOST_PREFIX6: u8 = 64;

/// A per-VM point-to-point IP link: the **host end** (on the tap, inside the netns), the **guest
/// end** (on the guest's `eth0`), and the prefix length. Generic over the address family, so a v6
/// link is just another `GuestLink`, present only when v6 is live (see
/// [`RunningVm::ipv6`](crate::RunningVm::ipv6)).
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
    /// Construct a link from its two ends and prefix length.
    pub(crate) fn new(host: A, guest: A, prefix_len: u8) -> Self {
        Self {
            host,
            guest,
            prefix_len,
        }
    }
}

impl GuestLink<Ipv4Addr> {
    /// The link's netmask in dotted-quad form, the only shape the kernel's `ip=` boot parameter
    /// takes (`CONFIG_IP_PNP` has no prefix-length form), rendered from `prefix_len` so the guest's
    /// mask and the host tap's prefix stay one value. A `prefix_len` past 32 saturates to `/32`,
    /// because saturating the other way would widen what the guest treats as on-link.
    pub(crate) fn netmask(&self) -> Ipv4Addr {
        // `u32::MAX << 32` is an overflowing shift, and design rule 5 leaves no room for a panic on
        // the boot path, so /0 is `checked_shl`'s `None` rather than a branch.
        let host_bits = 32u32.saturating_sub(u32::from(self.prefix_len));
        Ipv4Addr::from(u32::MAX.checked_shl(host_bits).unwrap_or(0))
    }

    /// Whether `addr` sits on this link, i.e. whether the guest can reach it without a router: an
    /// off-link gateway is one the guest cannot ARP, so the kernel refuses the route.
    pub(crate) fn on_link(&self, addr: Ipv4Addr) -> bool {
        let mask = u32::from(self.netmask());
        (u32::from(addr) & mask) == (u32::from(self.guest) & mask)
    }
}

/// The fixed v4 link every sandbox gets, shared by the tap builder and the boot-time gateway check.
pub(crate) fn v4_link() -> GuestLink<Ipv4Addr> {
    GuestLink::new(HOST_IP, GUEST_IP, HOST_PREFIX)
}

/// Where a guest should send traffic bound past its own /30, and who it should ask for names. Set
/// it on [`BootConfig::egress`](crate::BootConfig::egress); unset (the default) leaves the guest
/// with its connected route only.
///
/// **This names a path; it does not build one.** The engine puts these two addresses in the guest's
/// `ip=` boot parameter and does nothing else: no veth, no bridge, no forwarding, no NAT.
/// Furnishing the netns so the gateway leads somewhere is the hoster's (design decision 9), so on a
/// host that
/// furnished nothing the guest reaches what it reached before and only its attempts become visible
/// at the tap. Policy is unaffected: the eBPF classifier still starts deny-all, so a gateway widens
/// what the guest can *attempt*, never what it is permitted. **Both are host constants, not
/// per-sandbox values**, which keeps them snapshot-safe: a restored clone re-uses the addressing
/// baked into the snapshot and does no in-guest re-addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestEgress {
    gateway: Ipv4Addr,
    resolver: Option<Ipv4Addr>,
}

impl GuestEgress {
    /// Route the guest's off-link traffic at `gateway`, with no resolver configured. It **must be
    /// on the guest's own link**, which for the shipped `/30` leaves exactly one usable value: the
    /// host end of the tap ([`RunningVm::ipv4`](crate::RunningVm::ipv4)'s `host`). Anything else
    /// the guest cannot ARP, so the kernel refuses the default route and the sandbox comes up
    /// sealed.
    #[must_use]
    pub fn via(gateway: Ipv4Addr) -> Self {
        Self {
            gateway,
            resolver: None,
        }
    }

    /// Also tell the guest to resolve names at `resolver`. Reaching it still needs an allowance
    /// like any other destination, and the engine runs no resolver of its own. Settable only
    /// alongside a gateway, since an unroutable resolver would be inert.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Ipv4Addr) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The configured default route.
    #[must_use]
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// The configured resolver, if any.
    #[must_use]
    pub fn resolver(&self) -> Option<Ipv4Addr> {
        self.resolver
    }
}

/// A per-VM **network namespace** and the tap inside it that backs the guest's virtio-net. The
/// driver creates both (`ip`, needs `CAP_NET_ADMIN`), the VMM joins the netns (the jailer's
/// `--netns`, or `ip netns exec` for a direct boot), and teardown deletes the netns. Named after
/// the VM's scratch dir, so a crashed driver's orphan is reclaimable by the same dir-keyed sweep.
#[derive(Debug, Clone)]
pub(crate) struct Tap {
    /// The network namespace name (the VM's scratch-dir name), also the `/run/netns/<name>` handle.
    pub(crate) netns: String,
    /// The tap interface name inside the netns (`fc0`), the handle the eBPF loader resolves there.
    pub(crate) name: String,
    /// The guest NIC's MAC.
    pub(crate) mac: String,
    /// The IPv4 link (host + guest ends of the `/30`). Always present on a networked VM.
    pub(crate) v4: GuestLink<Ipv4Addr>,
    /// The IPv6 link, `Some` **iff** the host v6 address was assigned ([`add_host_v6`] is
    /// best-effort), so `None` means v6 is not live on this host.
    pub(crate) v6: Option<GuestLink<Ipv6Addr>>,
}

impl Tap {
    /// Create the per-VM netns `name`, then the tap inside it with the host ends of the v4 /30 and
    /// the v6 link assigned (the v6 end best-effort, see [`add_host_v6`]). Shells out to `ip` and
    /// needs `CAP_NET_ADMIN`. `owner` sets the tap's `user`/`group` to the jailed uid/gid, since a
    /// jailed Firecracker runs without `CAP_NET_ADMIN` and can only attach a tap it owns; a direct
    /// boot passes `None`. Any setup failure reclaims the half-built netns and the tap in it.
    pub(crate) fn create(netns: &str, owner: Option<(u32, u32)>) -> Result<Tap, VmmError> {
        netns_add(netns)?;
        let v6_up = match Self::build_tap(netns, owner) {
            Ok(up) => up,
            Err(e) => {
                netns_del(netns);
                return Err(e);
            }
        };
        Ok(Tap {
            netns: netns.to_string(),
            name: TAP_NAME.to_string(),
            mac: GUEST_MAC.to_string(),
            v4: v4_link(),
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

    /// The `/run/netns/<name>` handle to pass the jailer as `--netns`, so it joins this netns
    /// before dropping privileges and exec'ing Firecracker.
    pub(crate) fn netns_path(&self) -> PathBuf {
        netns_path(&self.netns)
    }

    /// Best-effort delete for teardown/`Drop` context: removes the whole netns, cascading the tap,
    /// its address, and its route away. A failure is logged, never propagated or panicked.
    pub(crate) fn delete(&self) {
        netns_del(&self.netns);
    }

    /// Whether this VM's netns still exists; teardown reclaims the scratch dir only once it is
    /// gone, since an undeleted netns must keep its dir to stay visible to the orphan sweep.
    pub(crate) fn netns_exists(&self) -> bool {
        netns_exists(&self.netns)
    }
}

/// The `/run/netns/<name>` path `ip netns` bind-mounts a handle at, also the jailer's `--netns`.
pub(crate) fn netns_path(name: &str) -> PathBuf {
    Path::new("/run/netns").join(name)
}

/// `ip netns add <name>`, creating the per-VM network namespace. The name embeds **our own** pid,
/// so a collision is residue from a prior process that shared it (dead, since pids are unique among
/// the living): a collision reclaims the stale namespace and retries once, which can never delete a
/// live peer's netns. A second failure, or one that is not a collision, is the typed error.
fn netns_add(name: &str) -> Result<(), VmmError> {
    match ip_netns_add(name) {
        Ok(()) => Ok(()),
        Err(first) => {
            // Only a name collision is retryable; anything else (no `CAP_NET_ADMIN`, no binary)
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

/// The raw `ip netns add <name>`, mapping a spawn failure or nonzero exit to a typed error.
fn ip_netns_add(name: &str) -> Result<(), VmmError> {
    run_ip(&["netns", "add", name])
}

/// `ip netns del <name>`, best-effort and shared by teardown, half-configured-boot cleanup, and the
/// orphan sweep. Deleting the netns cascades the tap away. A failure is logged, never propagated.
pub(crate) fn netns_del(name: &str) {
    // Bounded, because this runs inside teardown/`Drop`: `ip netns del` can wedge in the kernel
    // (rtnl lock, a device that won't release its refcount) and a plain `.output()` would hang.
    // On timeout `run_bounded` detaches and `reclaim_scratch` keeps the dir for the orphan sweep.
    let mut cmd = Command::new("ip");
    cmd.args(["netns", "del", name]);
    match crate::proc::run_bounded(cmd, crate::proc::TEARDOWN_HELPER_TIMEOUT, "ip netns del") {
        crate::proc::Bounded::Exited { success: true, .. } => {}
        crate::proc::Bounded::Exited { stderr, .. } => tracing::warn!(
            netns = %name,
            error = %stderr.trim(),
            "failed to delete network namespace"
        ),
        // Detached: logged inside `run_bounded`, and the namespace is left for the sweep.
        crate::proc::Bounded::Detached => {}
    }
}

/// Whether a network namespace named `name` currently exists, by its `/run/netns` handle. Used by
/// the orphan sweep to tell a dead driver's leaked netns (reclaim it) from one already gone.
pub(crate) fn netns_exists(name: &str) -> bool {
    netns_path(name).exists()
}

/// Run `ip <args>` inside network namespace `netns` (`ip netns exec <netns> ip <args>`), mapping a
/// missing binary or a nonzero exit to a typed error. `setns` then exec, so the tap operations land
/// in the VM's netns, not the host's.
fn ip_in_ns(netns: &str, args: &[&str]) -> Result<(), VmmError> {
    let mut full = vec!["netns", "exec", netns, "ip"];
    full.extend_from_slice(args);
    run_ip(&full)
}

/// Assign the host end of the v6 link to the tap, **best-effort**, returning whether it landed so
/// the caller records the v6 link as present only when it is live (the guest cmdline token and
/// [`RunningVm::ipv6`](crate::RunningVm) both key off this). IPv6 can be administratively off on
/// the host (`ipv6.disable=1`, `net.ipv6.conf.all.disable_ipv6=1`, no `CONFIG_IPV6` at all), any
/// of which fails `ip -6 addr add`; failing the boot on that would regress even v4-only sandboxes,
/// and isolation does not rest on this address (deny-by-default is the absent v6 default route plus
/// the eBPF egress hook), so a failure warns and leaves the v6 link absent. `nodad` skips
/// duplicate-address detection, which on a link with one other endpoint would only add multicast
/// chatter with nothing to detect; a `nodad`-unaware `ip` falls into the same warning.
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

/// Run `ip <args>`, mapping a missing binary, a nonzero exit, or a wedge to a typed error. Bounded
/// like `netns_del`: the boot deadline is checked only *between* steps and cannot interrupt one, so
/// an `ip` blocked on the rtnl lock would stall the boot with no error at all.
fn run_ip(args: &[&str]) -> Result<(), VmmError> {
    let mut cmd = Command::new("ip");
    cmd.args(args);
    let (status, stderr) = crate::proc::output_bounded(cmd, crate::proc::IP_TIMEOUT, "ip")?;
    if status.success() {
        Ok(())
    } else {
        Err(VmmError::Vmm(format!(
            "ip {}: {}",
            args.join(" "),
            // Status as the fallback: `ip` killed by a signal says nothing on stderr, and a
            // message ending in a bare colon would name no cause at all.
            crate::proc::failure_detail(status, &stderr)
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
        // The v6 link mirrors the v4 one: a ULA (`fc00::/7`, top 7 bits `1111110`), the guest one
        // address above the host end. (`is_unique_local` is unstable, so the prefix goes by octet.)
        assert_eq!(HOST_PREFIX6, 64);
        assert_eq!(HOST_IP6.octets()[0] & 0xfe, 0xfc);
        assert_eq!(GUEST_IP6.octets()[0] & 0xfe, 0xfc);
        assert_eq!(u128::from(GUEST_IP6), u128::from(HOST_IP6) + 1);
    }

    #[test]
    fn netns_path_is_the_iproute2_handle() {
        assert_eq!(netns_path("bsx-42-0"), Path::new("/run/netns/bsx-42-0"));
    }
}
