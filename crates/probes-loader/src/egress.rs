//! The egress policy and its address types.
//!
//! Deliberately **no eBPF here**: these are the plain data types an `--allow` string parses into,
//! which `tap` then writes into the policy maps. They carry their own fuzz target (`egress_rule`),
//! and keeping them out of the loader is what lets that stay true.

use super::*;

/// A rejected egress-policy input, caught by construction (`parse, don't validate`) so an illegal policy
/// can't reach the kernel map: an out-of-range CIDR prefix, or more rules than the map holds. Distinct
/// from [`ProbeError`]'s eBPF-runtime failures. `#[non_exhaustive]`: a richer policy vocabulary adds
/// new rejection classes as new variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// A CIDR prefix length over its family maximum (the given value): rejected by [`Ipv4Cidr::new`]
    /// (max 32) or [`Ipv6Cidr::new`] (max 128).
    PrefixTooLong(u8),
    /// More allow-rules than the kernel `POLICY` map holds: the requested count and the cap.
    TooManyRules {
        /// The number of rules the caller supplied.
        got: usize,
        /// The fixed cap ([`MAX_POLICY_RULES`]).
        max: usize,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrefixTooLong(len) => {
                write!(
                    f,
                    "CIDR prefix length {len} is over its family maximum (/32 for IPv4, /128 for IPv6)"
                )
            }
            Self::TooManyRules { got, max } => {
                write!(f, "egress policy has {got} rules, over the {max}-rule cap")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// A sandbox's **egress allow-list**, the userspace schema for what the guest may reach, built
/// from friendly [`Ipv4Addr`] CIDRs and ports and lowered to the [`PolicyRule`]s the kernel map holds.
/// **Deny-by-default:** the empty policy ([`deny_all`](Self::deny_all) / [`Default`]) allows
/// nothing, so a sandbox launched with no explicit allowance reaches nothing, you have to add each
/// endpoint. This is the eBPF, host-observed complement to the driver's deny-by-default routing:
/// the driver gives the guest no route to the world, and this drops anything unlisted at
/// the tap, where the host can see and record it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    rules: Vec<PolicyRule>,
    rules6: Vec<PolicyRule6>,
}

/// A validated IPv4 **CIDR**, a network address and a prefix length that is guaranteed `0..=32` by
/// construction. Parse, don't validate: an out-of-range prefix can't exist as an `Ipv4Cidr`, so it can
/// never reach the kernel policy map. Build one with [`new`](Self::new) (fallible) or [`host`](Self::host)
/// (an infallible `/32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// A CIDR `network/prefix_len`, or [`PolicyError::PrefixTooLong`] if `prefix_len > 32`. The network is
    /// taken as given (the kernel matcher masks it to `prefix_len`, so unmasked host bits don't matter).
    ///
    /// # Errors
    /// [`PolicyError::PrefixTooLong`] when `prefix_len` exceeds 32.
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Result<Self, PolicyError> {
        if prefix_len > 32 {
            return Err(PolicyError::PrefixTooLong(prefix_len));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// The `/32` CIDR of a single host, infallible, since `32` is always in range.
    #[must_use]
    pub fn host(addr: Ipv4Addr) -> Self {
        Self {
            network: addr,
            prefix_len: 32,
        }
    }

    /// The network address of this CIDR.
    #[must_use]
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// The prefix length (0..=32) of this CIDR.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `self` contains `other` (i.e. `other` is equal to or narrower than `self`).
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        if other.prefix_len < self.prefix_len {
            return false;
        }
        if self.prefix_len == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - self.prefix_len);
        (u32::from(self.network) & mask) == (u32::from(other.network) & mask)
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// A validated IPv6 **CIDR**, the v6 twin of [`Ipv4Cidr`]: prefix length guaranteed `0..=128` by
/// construction, so an out-of-range prefix can never reach the kernel `POLICY6` map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Cidr {
    /// A CIDR `network/prefix_len`, or [`PolicyError::PrefixTooLong`] if `prefix_len > 128`.
    ///
    /// # Errors
    /// [`PolicyError::PrefixTooLong`] when `prefix_len` exceeds 128.
    pub fn new(network: Ipv6Addr, prefix_len: u8) -> Result<Self, PolicyError> {
        if prefix_len > 128 {
            return Err(PolicyError::PrefixTooLong(prefix_len));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// The `/128` CIDR of a single v6 host, infallible.
    #[must_use]
    pub fn host(addr: Ipv6Addr) -> Self {
        Self {
            network: addr,
            prefix_len: 128,
        }
    }

    /// The network address of this CIDR.
    #[must_use]
    pub fn network(&self) -> Ipv6Addr {
        self.network
    }

    /// The prefix length (0..=128) of this CIDR.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `self` contains `other` (i.e. `other` is equal to or narrower than `self`).
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        if other.prefix_len < self.prefix_len {
            return false;
        }
        if self.prefix_len == 0 {
            return true;
        }
        let self_u128 = u128::from(self.network);
        let other_u128 = u128::from(other.network);
        let mask = u128::MAX << (128 - self.prefix_len);
        (self_u128 & mask) == (other_u128 & mask)
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl EgressPolicy {
    /// The **deny-everything** policy: no rules (v4 or v6), so every guest-sent packet is dropped
    /// once enforced. The safe default, build up from here by adding explicit allowances.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Allow a destination [`Ipv4Cidr`] on an optional `port` and `proto` ([`None`] = any), consuming and
    /// returning `self` for chaining. `None` reads as a wildcard (the kernel's `0`), so
    /// `allow(cidr, None, None)` admits the whole CIDR on any port and protocol. The address goes in host
    /// byte order (as [`Ipv4Addr`] naturally converts), matching the kernel matcher.
    #[must_use]
    pub fn allow(mut self, cidr: Ipv4Cidr, port: Option<u16>, proto: Option<Protocol>) -> Self {
        self.rules.push(PolicyRule::allow(
            u32::from(cidr.network),
            cidr.prefix_len,
            port.unwrap_or(0),
            proto.map_or(0, Protocol::as_u8),
        ));
        self
    }

    /// Allow a single destination **host** (`/32`) on an optional `port`/`proto`, the common case, sugar
    /// over [`allow`](Self::allow) with [`Ipv4Cidr::host`].
    #[must_use]
    pub fn allow_host(self, host: Ipv4Addr, port: Option<u16>, proto: Option<Protocol>) -> Self {
        self.allow(Ipv4Cidr::host(host), port, proto)
    }

    /// Allow a destination [`Ipv6Cidr`] on an optional `port`/`proto`, the v6 twin of
    /// [`allow`](Self::allow). The address goes in as its network-order octets (`Ipv6Addr::octets`),
    /// matching the kernel's byte-wise matcher.
    #[must_use]
    pub fn allow6(mut self, cidr: Ipv6Cidr, port: Option<u16>, proto: Option<Protocol>) -> Self {
        self.rules6.push(PolicyRule6::allow(
            cidr.network.octets(),
            cidr.prefix_len,
            port.unwrap_or(0),
            proto.map_or(0, Protocol::as_u8),
        ));
        self
    }

    /// Allow a single v6 destination **host** (`/128`), sugar over [`allow6`](Self::allow6).
    #[must_use]
    pub fn allow_host6(self, host: Ipv6Addr, port: Option<u16>, proto: Option<Protocol>) -> Self {
        self.allow6(Ipv6Cidr::host(host), port, proto)
    }

    /// The lowered [`PolicyRule`]s, as written into the kernel `POLICY` map.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// The lowered [`PolicyRule6`]s, as written into the kernel `POLICY6` map.
    #[must_use]
    pub fn rules6(&self) -> &[PolicyRule6] {
        &self.rules6
    }

    /// Whether this policy allows nothing (deny-by-default): no v4 **and** no v6 rules. `true` for
    /// [`deny_all`](Self::deny_all) and the [`Default`].
    #[must_use]
    pub fn is_deny_all(&self) -> bool {
        self.rules.is_empty() && self.rules6.is_empty()
    }

    /// Reconstruct the requested IPv4 CIDRs contained in this policy's rules.
    #[must_use]
    pub fn cidrs_v4(&self) -> Vec<Ipv4Cidr> {
        self.rules
            .iter()
            .filter_map(|r| Ipv4Cidr::new(Ipv4Addr::from(r.addr), r.prefix_len).ok())
            .collect()
    }

    /// Reconstruct the requested IPv6 CIDRs contained in this policy's rules.
    #[must_use]
    pub fn cidrs_v6(&self) -> Vec<Ipv6Cidr> {
        self.rules6
            .iter()
            .filter_map(|r| Ipv6Cidr::new(Ipv6Addr::from(r.addr), r.prefix_len).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    // The userspace schema, host-testable without a live map.
    use super::*;
    use probes_common::egress_allowed;

    /// A dotted-quad as the host-order `u32` the matcher takes.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn protocol_round_trips_and_single_sources_the_wire_numbers() {
        assert_eq!(Protocol::Tcp.as_u8(), 6);
        assert_eq!(Protocol::Udp.as_u8(), 17);
        assert_eq!(Protocol::from_u8(17), Some(Protocol::Udp));
        assert_eq!(Protocol::from_u8(6), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_u8(1), None); // ICMP: parsed for no ports, so "any / other"
    }

    #[test]
    fn ipv4_cidr_rejects_an_out_of_range_prefix() {
        // parse-don't-validate: an over-/32 prefix can't be constructed, so it never reaches the map.
        assert_eq!(
            Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 40),
            Err(PolicyError::PrefixTooLong(40))
        );
        assert!(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).is_ok());
        assert!(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 32).is_ok());
    }

    #[test]
    fn deny_all_is_the_default_and_allows_nothing() {
        // No policy = reaches nothing. The default and `deny_all` are the same empty allow-list.
        let p = EgressPolicy::default();
        assert!(p.is_deny_all());
        assert_eq!(p, EgressPolicy::deny_all());
        assert!(p.rules().is_empty());
        assert!(!egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            9999,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn allow_host_builds_a_slash32_rule() {
        let host = Ipv4Addr::new(10, 200, 0, 1);
        let p = EgressPolicy::deny_all().allow_host(host, Some(9999), Some(Protocol::Udp));
        assert!(!p.is_deny_all());
        let rule = p.rules()[0];
        assert_eq!(rule.active, 1);
        assert_eq!(rule.prefix_len, 32);
        assert_eq!(rule.addr, u32::from(host));
        assert_eq!(rule.port, 9999);
        assert_eq!(rule.proto, Protocol::Udp.as_u8());
        // Only that exact host/port/proto is admitted; everything else is denied.
        assert!(egress_allowed(
            p.rules(),
            u32::from(host),
            9999,
            Protocol::Udp.as_u8()
        ));
        assert!(!egress_allowed(
            p.rules(),
            ip(10, 200, 0, 2),
            9999,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn ipv6_cidr_rejects_an_out_of_range_prefix() {
        assert_eq!(
            Ipv6Cidr::new("fd00:200::".parse().unwrap(), 200),
            Err(PolicyError::PrefixTooLong(200))
        );
        assert!(Ipv6Cidr::new("fd00:200::".parse().unwrap(), 64).is_ok());
        assert!(Ipv6Cidr::new("fd00:200::1".parse().unwrap(), 128).is_ok());
    }

    #[test]
    fn allow_host6_builds_a_slash128_rule_and_counts_toward_deny_all() {
        let host: Ipv6Addr = "fd00:200::1".parse().unwrap();
        // A v6-only policy is *not* deny-all (is_deny_all must consider both families).
        let p = EgressPolicy::deny_all().allow_host6(host, Some(9999), Some(Protocol::Udp));
        assert!(!p.is_deny_all());
        assert!(p.rules().is_empty(), "no v4 rules");
        let rule = p.rules6()[0];
        assert_eq!(rule.active, 1);
        assert_eq!(rule.prefix_len, 128);
        assert_eq!(rule.addr, host.octets());
        assert_eq!(rule.port, 9999);
        // Only that exact v6 host/port/proto is admitted; another v6 host is denied.
        assert!(probes_common::egress_allowed6(
            p.rules6(),
            host.octets(),
            9999,
            Protocol::Udp.as_u8()
        ));
        let other: Ipv6Addr = "fd00:200::2".parse().unwrap();
        assert!(!probes_common::egress_allowed6(
            p.rules6(),
            other.octets(),
            9999,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn none_port_and_proto_lower_to_the_any_wildcard() {
        // `None` is the typed "any", lowering to the kernel's `0` sentinel, no magic 0 at the API.
        let p = EgressPolicy::deny_all().allow_host(Ipv4Addr::new(10, 200, 0, 1), None, None);
        let rule = p.rules()[0];
        assert_eq!(rule.port, 0);
        assert_eq!(rule.proto, 0);
        // Any port and any protocol to that host is admitted.
        assert!(egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            1234,
            Protocol::Tcp.as_u8()
        ));
        assert!(egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            53,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn allow_chains_cidr_and_host() {
        let p = EgressPolicy::deny_all()
            .allow(
                Ipv4Cidr::new(Ipv4Addr::new(93, 184, 216, 0), 24).expect("valid /24"),
                Some(443),
                Some(Protocol::Tcp),
            )
            .allow_host(Ipv4Addr::new(10, 200, 0, 1), None, None); // any port/proto to the gateway
        assert_eq!(p.rules().len(), 2);
        // The chained policy admits both the subnet and the gateway, and nothing else.
        assert!(egress_allowed(
            p.rules(),
            ip(93, 184, 216, 34),
            443,
            Protocol::Tcp.as_u8()
        ));
        assert!(egress_allowed(
            p.rules(),
            ip(10, 200, 0, 1),
            1234,
            Protocol::Udp.as_u8()
        ));
        assert!(!egress_allowed(
            p.rules(),
            ip(8, 8, 8, 8),
            53,
            Protocol::Udp.as_u8()
        ));
    }

    // --- Resource accounting: the cgroup v2 file parsers, host-testable without a live cgroup ---
}
