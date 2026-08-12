//! The egress policy and its address types.
//!
//! Deliberately **no eBPF here**: these are the plain data types an `--allow` string parses into, which
//! `tap` then writes into the policy maps, so they carry their own fuzz target. The import list below is
//! what keeps that checkable, since a change reaching for `aya` or a loader item has to add an import
//! here to compile.

use std::net::{Ipv4Addr, Ipv6Addr};

use bsx_probes_common::{PolicyRule, PolicyRule6, Protocol};

/// A rejected egress-policy input, refused before it can reach the kernel map. An out-of-range
/// CIDR prefix is caught at construction (`parse, don't validate`: [`Cidr::new`]); a rule count
/// over the map's capacity is caught when the policy is installed, before any rule is written
/// ([`EgressPolicy`]'s `allow` builders are infallible). Distinct from [`crate::ProbeError`]'s
/// eBPF-runtime failures. `#[non_exhaustive]`: a richer policy vocabulary adds new rejection
/// classes as new variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// A CIDR prefix length over its family maximum: rejected by [`Cidr::new`].
    PrefixTooLong {
        /// The prefix length the caller supplied.
        got: u8,
        /// The family maximum it exceeded (32 for IPv4, 128 for IPv6).
        max: u8,
    },
    /// More allow-rules than the kernel `POLICY` map holds: the requested count and the cap.
    TooManyRules {
        /// The number of rules the caller supplied.
        got: usize,
        /// The fixed cap ([`crate::MAX_POLICY_RULES`]).
        max: usize,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrefixTooLong { got, max } => {
                write!(
                    f,
                    "CIDR prefix length {got} is over its family maximum /{max}"
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

/// A validated **CIDR**, a network address and a prefix length that is guaranteed
/// `0..=A::MAX_PREFIX` by construction. Parse rather than validate: an out-of-range prefix can't
/// exist as a `Cidr`, so it never reaches a kernel policy map. Build one with [`new`](Self::new)
/// or [`host`](Self::host) (an infallible single-address CIDR). One body for both address
/// families, so the mask math cannot drift between them; [`Ipv4Cidr`] and [`Ipv6Cidr`] are its
/// two names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr<A> {
    network: A,
    prefix_len: u8,
}

/// A validated IPv4 CIDR: prefix length guaranteed `0..=32` by construction.
pub type Ipv4Cidr = Cidr<Ipv4Addr>;

/// A validated IPv6 CIDR: prefix length guaranteed `0..=128` by construction.
pub type Ipv6Cidr = Cidr<Ipv6Addr>;

/// The per-family pieces [`Cidr`] needs: the prefix ceiling and the address's integer bits for
/// the mask comparison. Sealed to [`Ipv4Addr`] and [`Ipv6Addr`], the two families the kernel
/// maps hold.
pub trait CidrAddr: Copy + Eq + std::fmt::Display + sealed::Sealed {
    /// The family's maximum prefix length (32 or 128).
    const MAX_PREFIX: u8;
    /// The address as integer bits (zero-extended for IPv4), for the mask comparison.
    fn bits(self) -> u128;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for std::net::Ipv4Addr {}
    impl Sealed for std::net::Ipv6Addr {}
}

impl CidrAddr for Ipv4Addr {
    const MAX_PREFIX: u8 = 32;
    fn bits(self) -> u128 {
        u128::from(u32::from(self))
    }
}

impl CidrAddr for Ipv6Addr {
    const MAX_PREFIX: u8 = 128;
    fn bits(self) -> u128 {
        u128::from(self)
    }
}

impl<A: CidrAddr> Cidr<A> {
    /// A CIDR `network/prefix_len`, or [`PolicyError::PrefixTooLong`] past the family maximum. The
    /// network is taken as given, since the kernel matcher masks it to `prefix_len`.
    ///
    /// # Errors
    /// [`PolicyError::PrefixTooLong`] when `prefix_len` exceeds `A::MAX_PREFIX`.
    pub fn new(network: A, prefix_len: u8) -> Result<Self, PolicyError> {
        if prefix_len > A::MAX_PREFIX {
            return Err(PolicyError::PrefixTooLong {
                got: prefix_len,
                max: A::MAX_PREFIX,
            });
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// The single-address CIDR (`/32` or `/128`), infallible, since the maximum is always in range.
    #[must_use]
    pub fn host(addr: A) -> Self {
        Self {
            network: addr,
            prefix_len: A::MAX_PREFIX,
        }
    }

    /// The network address of this CIDR.
    #[must_use]
    pub fn network(&self) -> A {
        self.network
    }

    /// The prefix length (`0..=A::MAX_PREFIX`) of this CIDR.
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
        // Widening to u128 keeps the comparison the family's own: the bits past `A::MAX_PREFIX`
        // are ones in the mask and zeros in both addresses, so they cannot break the equality.
        let mask = u128::MAX << (A::MAX_PREFIX - self.prefix_len);
        (self.network.bits() & mask) == (other.network.bits() & mask)
    }
}

impl<A: CidrAddr> std::fmt::Display for Cidr<A> {
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

    /// Allows a destination [`Ipv4Cidr`] on an optional `port` and `proto`, consuming and
    /// returning `self` for chaining. `None` reads as a wildcard (the kernel's `0`), so
    /// `allow(cidr, None, None)` admits the whole CIDR on any port and protocol. `Some(0)` lowers
    /// to that same `0`, so it also means any port, never literal port 0 (which is not an
    /// addressable destination); pass `None` to say so
    /// (`some_zero_port_lowers_to_the_same_wildcard_as_none` pins the equivalence). The address
    /// goes in host byte order (as [`Ipv4Addr`] naturally converts), matching the kernel matcher.
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

    /// Allows a single destination **host** (`/32`) on an optional `port` and `proto`, the common case and sugar
    /// over [`allow`](Self::allow) with [`Cidr::host`].
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
    use bsx_probes_common::egress_allowed;

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
        // An over-`/32` prefix can't be constructed, so it never reaches the map.
        let err = Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 40).expect_err("40 is over /32");
        assert_eq!(err, PolicyError::PrefixTooLong { got: 40, max: 32 });
        // The error names the family maximum it exceeded, not a both-families hedge.
        assert!(
            err.to_string().contains("maximum /32"),
            "a v4 prefix error names /32, got: {err}"
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
        let err = Ipv6Cidr::new("fd00:200::".parse().unwrap(), 200).expect_err("200 is over /128");
        assert_eq!(err, PolicyError::PrefixTooLong { got: 200, max: 128 });
        // The error names the family maximum it exceeded, not a both-families hedge.
        assert!(
            err.to_string().contains("maximum /128"),
            "a v6 prefix error names /128, got: {err}"
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
        assert!(bsx_probes_common::egress_allowed6(
            p.rules6(),
            host.octets(),
            9999,
            Protocol::Udp.as_u8()
        ));
        let other: Ipv6Addr = "fd00:200::2".parse().unwrap();
        assert!(!bsx_probes_common::egress_allowed6(
            p.rules6(),
            other.octets(),
            9999,
            Protocol::Udp.as_u8()
        ));
    }

    #[test]
    fn some_zero_port_lowers_to_the_same_wildcard_as_none() {
        // The kernel's 0 sentinel means "any port", so `Some(0)` cannot mean literal port 0 (not
        // an addressable destination); the two spellings must lower to identical rules.
        let host = Ipv4Addr::new(10, 200, 0, 1);
        assert_eq!(
            EgressPolicy::deny_all().allow_host(host, Some(0), None),
            EgressPolicy::deny_all().allow_host(host, None, None)
        );
        let host6: Ipv6Addr = "fd00:200::1".parse().unwrap();
        assert_eq!(
            EgressPolicy::deny_all().allow_host6(host6, Some(0), None),
            EgressPolicy::deny_all().allow_host6(host6, None, None)
        );
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
}
