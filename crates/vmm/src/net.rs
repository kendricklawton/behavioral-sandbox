//! Per-VM guest networking, host side: the tap device backing virtio-net, the /30 allocator with
//! its atomic reservations, and the fresh network identity the guest agent applies to a restored
//! clone (decisions 008, 009, and 011).

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agent_channel::AGENT_VSOCK_PORT;

use crate::drives::tool_spawn_error;
use crate::exec::{connect_agent_at, run_exec, ExecBounds, EXEC_KILL_SLACK, VSOCK_TIMEOUT};
use crate::VmmError;

/// Wall-clock budget for the in-guest network-identity command on restore. Two `ip` invocations on a
/// live guest; seconds would already mean something is broken, so the budget is short and a breach is
/// a typed error, not a stall on the restore path.
const NET_IDENTITY_TIMEOUT: Duration = Duration::from_secs(10);

/// Apply a restored clone's fresh network identity in-guest (decision 011): flush the snapshot's
/// baked-in `eth0` address and install `guest_ip/30`, via the guest agent over vsock. `ip addr add`
/// installs the connected /30 route with it, and the **empty gateway invariant carries over** — no
/// default route is added, so deny-by-default (decision 008) holds for clones exactly as for cold
/// boots. Runs as one `sh -c` so flush+add is a single guest command; a non-zero exit is a typed
/// error naming the guest's stderr (the values interpolated are our own `Ipv4Addr`/const, not caller
/// input).
pub(crate) fn apply_guest_net_identity(uds: &Path, guest_ip: Ipv4Addr) -> Result<(), VmmError> {
    let mut conn = connect_agent_at(uds, AGENT_VSOCK_PORT, VSOCK_TIMEOUT)?;
    // `eth0` here is the guest kernel's enumerated NIC name — the same other-namespace literal the
    // `ip=` boot arg uses — deliberately not `IFACE_ID` (the Firecracker device id; see its doc).
    let cmd = format!("ip addr flush dev eth0 && ip addr add {guest_ip}/{HOST_PREFIX} dev eth0");
    let argv = ["/bin/sh".to_string(), "-c".to_string(), cmd];
    let result = run_exec(
        &mut conn,
        &argv,
        &[],
        &[],
        &[],
        ExecBounds {
            timeout: NET_IDENTITY_TIMEOUT,
            wall: NET_IDENTITY_TIMEOUT.saturating_add(EXEC_KILL_SLACK),
            max_output: 64 * 1024, // two `ip` calls; anything past diagnostics-sized is noise
        },
    )?;
    if result.exit_code != 0 {
        return Err(VmmError::Vmm(format!(
            "guest failed to apply its restored network identity (exit {}): {}",
            result.exit_code,
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    Ok(())
}
/// Names the next per-VM tap/MAC within this process. Host-global uniqueness rests on `ip tuntap
/// add` failing on an already-taken name as an atomic reservation (like [`create_workdir`]); this counter,
/// mixed with the PID, just keeps candidates distinct so a cross-process collision is rare.
static NET_SEQ: AtomicU64 = AtomicU64::new(0);

/// A per-VM host **tap** backing the guest's virtio-net (P4.1) with the host end of a point-to-point
/// /30 assigned (P4.2). The driver creates it (`ip tuntap`, needs `CAP_NET_ADMIN`), names it on the
/// `PUT /network-interfaces`, addresses the host end, and deletes it on every teardown path — it
/// lives **outside** the scratch dir, so `remove_dir_all` can't reclaim it (and `ip link del`
/// cascades away its address + connected route, so addressing adds no teardown burden).
#[derive(Debug, Clone)]
pub(crate) struct Tap {
    /// Host interface name (`fc<hex>`, ≤ `IFNAMSIZ`-1 = 15 bytes).
    pub(crate) name: String,
    /// The guest NIC's MAC: a locally-administered unicast address, distinct per VM.
    pub(crate) mac: String,
    /// The host end of the point-to-point /30 (assigned to the tap).
    pub(crate) host_ip: Ipv4Addr,
    /// The guest end of the /30 (configured on the guest's `eth0` via the kernel `ip=` param).
    pub(crate) guest_ip: Ipv4Addr,
}

impl Tap {
    /// Create a uniquely-named tap, bring it up, and assign the host end of the per-VM /30. Shells
    /// out to `ip` (iproute2), consistent with the driver's other host-tool calls (`mke2fs`/`e2fsck`);
    /// needs `CAP_NET_ADMIN`, so this only succeeds under the privileged test/runtime tier.
    pub(crate) fn create() -> Result<Tap, VmmError> {
        for _ in 0..1024 {
            // Mix the PID in so two driver processes rarely pick the same name/MAC/subnet; the `ip
            // tuntap add` name-taken retry below is the real cross-process reservation for the name.
            let token =
                (u64::from(std::process::id()) << 20) ^ NET_SEQ.fetch_add(1, Ordering::Relaxed);
            let name = tap_name(token);
            match tap_add(&name)? {
                TapAdd::Exists => {
                    // Raced or stale: another VM (or a leaked tap) holds this name. Try the next
                    // candidate. Logged so allocator contention is visible, not silent.
                    tracing::debug!(tap = %name, "tap name already taken, retrying with a fresh token");
                    continue;
                }
                TapAdd::Created => {}
            }
            // A half-configured tap must not leak if bring-up or addressing fails.
            let (host_ip, guest_ip) = subnet_for(token);
            if let Err(e) = run_ip(&["link", "set", "dev", &name, "up"]) {
                ip_link_del(&name);
                return Err(e);
            }
            // Assign the host end of the /30. This auto-installs the connected route so the host
            // reaches the guest (the only route on the link). Deny-by-default (decision 008): no
            // default route, no masquerade, no ip_forward; `ip link del` removes this on teardown.
            //
            // The assignment is also the /30's atomic reservation. `subnet_for` folds the token to a
            // 14-bit index, so two tokens that won distinct tap names can still land on the same /30;
            // that clash surfaces here as `ip addr add` failing because the address is already held.
            // When that's the cause (another VM owns this /30), reclaim the tap and retry with a fresh
            // token (the same fail-if-taken-then-retry the name uses), so two concurrent sandboxes
            // never share a subnet and can't reach each other's tap (P4.4). Any other failure is real.
            if let Err(e) = run_ip(&[
                "addr",
                "add",
                &format!("{host_ip}/{HOST_PREFIX}"),
                "dev",
                &name,
            ]) {
                ip_link_del(&name);
                if host_addr_exists(host_ip) {
                    // Another VM already owns this /30 (the folded index collided). Retry with a
                    // fresh token; log it so subnet contention is observable.
                    tracing::debug!(%host_ip, "/30 already reserved by another VM, retrying with a fresh token");
                    continue;
                }
                return Err(e);
            }
            #[allow(clippy::cast_possible_truncation)]
            let mac = mac_for(token as u32);
            return Ok(Tap {
                name,
                mac,
                host_ip,
                guest_ip,
            });
        }
        Err(VmmError::Vmm(
            "could not allocate a unique tap (name + /30) after 1024 attempts".into(),
        ))
    }

    /// Recreate a tap with a **fixed** name (a snapshot's recorded `host_dev_name` — the pinned
    /// Firecracker v1.9 has no `network_overrides`, so restore must present the exact tap name the
    /// snapshot baked in) and assign its host end a **fresh** /30. Unlike [`create`](Tap::create), a
    /// taken name is a typed error, not a retry: the name is the snapshot's, and "taken" means the
    /// source VM (or an earlier clone) is still alive — restoring anyway would hijack its link.
    /// Only the /30 is allocated fresh, with the same `ip addr add`-as-reservation retry as `create`.
    pub(crate) fn create_named(name: &str) -> Result<Tap, VmmError> {
        match tap_add(name)? {
            TapAdd::Exists => {
                return Err(VmmError::Vmm(format!(
                    "tap {name} is still in use; shut down the source VM (or a prior clone) before \
                     restoring its networked snapshot"
                )));
            }
            TapAdd::Created => {}
        }
        if let Err(e) = run_ip(&["link", "set", "dev", name, "up"]) {
            ip_link_del(name);
            return Err(e);
        }
        for _ in 0..1024 {
            let token =
                (u64::from(std::process::id()) << 20) ^ NET_SEQ.fetch_add(1, Ordering::Relaxed);
            let (host_ip, guest_ip) = subnet_for(token);
            if let Err(e) = run_ip(&[
                "addr",
                "add",
                &format!("{host_ip}/{HOST_PREFIX}"),
                "dev",
                name,
            ]) {
                if host_addr_exists(host_ip) {
                    // Another VM owns this /30; the name is ours and fixed, so retry the address only.
                    tracing::debug!(%host_ip, "/30 already reserved by another VM, retrying with a fresh token");
                    continue;
                }
                ip_link_del(name);
                return Err(e);
            }
            // The guest NIC's MAC is restored from the snapshot, not this token's; recorded here only
            // so the handle is well-formed (nothing reads it on the restore path).
            #[allow(clippy::cast_possible_truncation)]
            let mac = mac_for(token as u32);
            return Ok(Tap {
                name: name.to_string(),
                mac,
                host_ip,
                guest_ip,
            });
        }
        ip_link_del(name);
        Err(VmmError::Vmm(
            "could not allocate a unique /30 for the restored tap after 1024 attempts".into(),
        ))
    }

    /// Best-effort delete for teardown/`Drop` context: a failure is logged, never propagated or
    /// panicked (the host path is `#![forbid(unsafe_code)]` and must not panic on teardown). Removing
    /// the interface also removes its address and connected route.
    pub(crate) fn delete(&self) {
        ip_link_del(&self.name);
    }
}

/// `ip link del dev <name>`, best-effort: the tap has no `Drop` safety net, so every teardown and
/// half-configured-boot cleanup routes through here, and a failure is logged (never propagated or
/// panicked, per the no-panic host path) so an orphaned interface is at least visible.
fn ip_link_del(name: &str) {
    if let Err(e) = run_ip(&["link", "del", "dev", name]) {
        tracing::warn!(tap = %name, error = %e, "failed to delete tap");
    }
}

/// The tap name for a token: `fc` + up to 12 hex digits (48 bits) = ≤ 14 bytes, within the 15-byte
/// `IFNAMSIZ` limit. Factored out so the length bound is unit-testable.
fn tap_name(token: u64) -> String {
    format!("fc{:x}", token & 0xffff_ffff_ffff)
}

/// A locally-administered **unicast** MAC derived from a per-VM value. The first octet `0x02` sets
/// the locally-administered bit (`0x02`) and clears the multicast bit (`0x01`); the low four bytes
/// carry the value, so each VM gets a distinct, valid NIC address.
fn mac_for(v: u32) -> String {
    let b = v.to_be_bytes();
    format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3])
}

/// The two high octets of the per-VM address space: `10.200.0.0/16`, carved into 16384 point-to-point
/// /30 blocks. An RFC1918 range chosen to dodge the defaults a host is likely to already route
/// (Docker `172.17+`, libvirt `192.168.122`, home routers `192.168.0/1`, plain `10.0.0/24`).
const NET_BASE: [u8; 2] = [10, 200];

/// The prefix length of each per-VM link: a `/30` (netmask `255.255.255.252`), the smallest subnet
/// that holds two usable hosts (the host end and the guest end) and nothing else.
pub(crate) const HOST_PREFIX: u8 = 30;

/// Fold a 64-bit token down to a 14-bit /30 index. The token is `(pid << 20) ^ NET_SEQ`, so its PID
/// entropy lives in bits ≥ 20; a plain `token & 0x3fff` would drop all of it and collapse to
/// `NET_SEQ & 0x3fff`, making two driver processes both at `NET_SEQ = 0` pick the *same* /30 in the
/// shared host netns. XOR-folding the high bits down mixes the PID back into the index.
fn subnet_index(token: u64) -> u16 {
    ((token ^ (token >> 14) ^ (token >> 28) ^ (token >> 42)) & 0x3fff) as u16
}

/// The `(host_ip, guest_ip)` ends of the per-VM point-to-point [`HOST_PREFIX`] (`/30`) for `token`,
/// derived from the same token that won the tap name/MAC so a VM's identity is consistent. Within the
/// 4-address block (`index * 4`): `+1` is the host end, `+2` the guest end. `index ∈ [0, 16383]` ⇒
/// `block ∈ {0, 4, …, 65532}` ⇒ the low octet is a multiple of 4 in `[0, 252]`, so `+1`/`+2` never
/// overflow an octet.
fn subnet_for(token: u64) -> (Ipv4Addr, Ipv4Addr) {
    let block = u32::from(subnet_index(token)) << 2; // index * 4
    let o3 = (block >> 8) as u8;
    let o4 = (block & 0xff) as u8;
    let host = Ipv4Addr::new(NET_BASE[0], NET_BASE[1], o3, o4 + 1);
    let guest = Ipv4Addr::new(NET_BASE[0], NET_BASE[1], o3, o4 + 2);
    (host, guest)
}

/// Outcome of `ip tuntap add`: a taken name is the retryable case (another VM or a stale tap holds
/// it), distinct from a real failure.
enum TapAdd {
    Created,
    Exists,
}

/// `ip tuntap add <name> mode tap`, classifying a name already taken (retry) apart from a real error.
/// The name-taken case *is* the atomic host-global reservation across concurrent processes. We
/// classify it by *asking netlink whether the interface now exists* rather than parsing the error
/// string: `ip tuntap` creates via the `TUNSETIFF` ioctl, which fails with `EBUSY` ("Device or
/// resource busy") on a collision — not the RTNETLINK `EEXIST` ("File exists") — so a message match
/// would be both wrong and locale-fragile. The existence probe is exit-code- and namespace-based.
fn tap_add(name: &str) -> Result<TapAdd, VmmError> {
    let out = Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tap"])
        .output()
        .map_err(|e| tool_spawn_error("ip", e))?;
    if out.status.success() {
        return Ok(TapAdd::Created);
    }
    // A failure whose cause is "the name is taken" leaves the interface present; anything else
    // (e.g. EPERM without CAP_NET_ADMIN) does not, and must surface — never retry it.
    if iface_exists(name) {
        return Ok(TapAdd::Exists);
    }
    Err(VmmError::Vmm(format!(
        "ip tuntap add {name}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

/// Whether a network interface named `name` exists in the current network namespace, via
/// `ip link show` (exit 0 = present). Netlink-based, so it's correct inside a network namespace where
/// `/sys/class/net` may reflect a different one, and it keys on the exit code, not a localized string.
fn iface_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether IPv4 `addr` is already assigned to some interface in the current network namespace, via
/// `ip -o -4 addr show to <addr>/32`; non-empty output means present. Netlink-based like
/// [`iface_exists`], so it's namespace-correct and locale-independent (it keys on whether any line
/// was printed, not on a message). Used to tell "this /30 is already held by another VM" (retry the
/// allocation) apart from a genuine `ip addr add` failure (surface it).
fn host_addr_exists(addr: Ipv4Addr) -> bool {
    Command::new("ip")
        .args(["-o", "-4", "addr", "show", "to", &format!("{addr}/32")])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

/// Run `ip <args>`, mapping a missing binary or a nonzero exit to a typed error. Used for tap
/// bring-up and delete; tap *creation* is [`tap_add`] (it must classify the retryable name-taken case).
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
    fn tap_name_fits_ifnamsiz_and_is_prefixed() {
        // The name must stay within IFNAMSIZ-1 (15 bytes) for any token, including the max, and be
        // distinct per token so the create-and-retry loop actually advances.
        for token in [0u64, 1, 42, 0xffff_ffff, u64::MAX] {
            let name = tap_name(token);
            assert!(name.starts_with("fc"), "{name}");
            assert!(name.len() <= 15, "{name} is {} bytes", name.len());
        }
        assert_ne!(tap_name(0), tap_name(1));
    }

    #[test]
    fn mac_for_is_locally_administered_unicast_and_unique() {
        let mac = mac_for(0x0102_0304);
        assert_eq!(mac, "02:00:01:02:03:04");
        // First octet 0x02: locally-administered bit (0x02) set, multicast bit (0x01) clear.
        assert_eq!(0x02 & 0x02, 0x02);
        assert_eq!(0x02 & 0x01, 0x00);
        assert_ne!(mac_for(0), mac_for(1), "distinct values → distinct MACs");
    }

    #[test]
    fn subnet_for_carves_a_point_to_point_30() {
        assert_eq!(HOST_PREFIX, 30, "a point-to-point link is the smallest /30");
        let (host, guest) = subnet_for(0);
        // Both ends live in 10.200.0.0/16, and the guest is the host's neighbour (host + 1).
        assert_eq!(host.octets()[0..2], [10, 200]);
        assert_eq!(guest.octets()[0..2], [10, 200]);
        assert_eq!(u32::from(guest), u32::from(host) + 1);
        // The block base is a multiple of 4, so host/guest are the .1/.2 of their /30 (never the
        // network .0 or broadcast .3) and the low octet can't overflow.
        assert_eq!(u32::from(host) % 4, 1);
    }

    #[test]
    fn subnet_index_folds_pid_bits_so_processes_dont_collide_at_seq_zero() {
        // The real token is `(pid << 20) ^ seq`. Two processes both at seq 0 must land on different
        // /30s — a plain low-bit mask would collapse to `seq & mask` (identical). The fold mixes the
        // PID (bits ≥ 20) back into the 14-bit index.
        let token = |pid: u64, seq: u64| (pid << 20) ^ seq;
        assert_ne!(
            subnet_index(token(1234, 0)),
            subnet_index(token(5678, 0)),
            "distinct PIDs → distinct blocks at seq 0"
        );
        // Successive sequence numbers within one process also differ.
        assert_ne!(subnet_index(token(1234, 0)), subnet_index(token(1234, 1)));
    }

    #[test]
    fn subnet_for_gives_a_distinct_30_to_every_vm_in_a_process_run() {
        // How the driver actually allocates: one PID, `NET_SEQ` climbing 0, 1, 2, … . Every VM in a
        // run must get its own /30, or two guests would share a subnet and reach each other's tap
        // (P4.4). The `ip addr add` reservation in `Tap::create` is the cross-process backstop; this
        // asserts the common single-process path never needs it — no two host ends collide.
        let token = |seq: u64| (u64::from(std::process::id()) << 20) ^ seq;
        let mut seen = std::collections::BTreeSet::new();
        for seq in 0..4096 {
            let (host, _guest) = subnet_for(token(seq));
            assert!(
                seen.insert(host),
                "duplicate host /30 end {host} at seq {seq}"
            );
        }
    }
}
