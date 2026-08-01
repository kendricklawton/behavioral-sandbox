//! Operator policy: the host's per-run defaults, its ceilings, and the postures a caller may tighten
//! but never loosen.
//!
//! **Where this binds, and where it is only a guardrail.** A caller of the CLI is *trusted* (see
//! `docs/security.md`, "the caller harming the caller" is not a security bug): they own the config
//! file and the environment, so policy there is a house default that keeps honest runs consistent,
//! not a boundary. The boundary is `ekvm serve`: its clients arrive over a socket
//! and control neither the daemon's environment nor its `.ekvm.toml`, so the same policy applied to
//! a client's `open` is real enforcement. That asymmetry is deliberate, and it is why the resolution
//! below lives in one shared place instead of in flag parsing.
//!
//! **Why a ceiling is not just another config value.** The layering is flags > env > file,
//! so a plain config value is a *default a caller overrides*. That is right for
//! defaults and wrong for ceilings, which exist precisely to bound what a caller may ask for. So
//! ceilings do not participate in that precedence: they bound the resolved value, and exceeding one
//! is a **typed refusal**, never a silent clamp: quietly handing back 4 vCPUs to a caller who
//! asked for 32 is the silent degradation a refusal exists to forbid.

use std::fmt;
use std::net::Ipv4Addr;
use std::num::{NonZeroU32, NonZeroU8};
use std::path::PathBuf;
use std::time::Duration;

use ekvm::Limits;
use ekvm_probes_loader::{EgressPolicy, Ipv4Cidr, Ipv6Cidr, Protocol};

/// One parsed `--allow` allowance: a validated destination CIDR with optional port/protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowRule {
    pub cidr: Ipv4Cidr,
    pub port: Option<u16>,
    pub proto: Option<Protocol>,
}

/// Parse one `--allow` value, `IP[/CIDR][:PORT][/PROTO]`, into an [`AllowRule`]. Parsed
/// right-to-left so the grammar is unambiguous.
pub fn parse_allow(s: &str) -> Result<AllowRule, String> {
    let (head, proto) = match s.rsplit_once('/') {
        Some((rest, tail)) if tail.eq_ignore_ascii_case("tcp") => (rest, Some(Protocol::Tcp)),
        Some((rest, tail)) if tail.eq_ignore_ascii_case("udp") => (rest, Some(Protocol::Udp)),
        _ => (s, None),
    };
    let (addr_cidr, port) = match head.rsplit_once(':') {
        Some((addr, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("invalid port {p:?} in --allow {s:?}"))?;
            (addr, Some(port))
        }
        None => (head, None),
    };
    let cidr = match addr_cidr.split_once('/') {
        Some((ip, prefix)) => {
            let ip: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("invalid IPv4 address {ip:?} in --allow {s:?}"))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("invalid CIDR prefix {prefix:?} in --allow {s:?}"))?;
            Ipv4Cidr::new(ip, prefix).map_err(|e| format!("--allow {s:?}: {e}"))?
        }
        None => Ipv4Cidr::host(
            addr_cidr
                .parse()
                .map_err(|_| format!("invalid IPv4 address {addr_cidr:?} in --allow {s:?}"))?,
        ),
    };
    Ok(AllowRule { cidr, port, proto })
}

/// What a caller asked for. `None` means "unspecified", which takes the operator default (else the
/// engine's conservative [`Limits`] default).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Requested {
    /// Requested vCPUs.
    pub vcpus: Option<NonZeroU8>,
    /// Requested guest memory, MiB.
    pub mem_mib: Option<NonZeroU32>,
    /// Requested wall-clock budget, seconds.
    pub wall_secs: Option<u64>,
    /// Requested captured-output cap, bytes.
    pub output_cap: Option<usize>,
}

/// The operator's policy for this host: defaults, ceilings, and postures.
/// Every field is optional/false by default, so an absent `.ekvm.toml` leaves the engine's existing
/// behavior exactly as it was.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Policy {
    /// House default vCPUs when a caller does not ask.
    pub vcpus: Option<NonZeroU8>,
    /// House default memory, MiB.
    pub mem_mib: Option<NonZeroU32>,
    /// House default wall-clock budget, seconds.
    pub wall_secs: Option<u64>,
    /// House default output cap, bytes.
    pub output_cap: Option<usize>,

    /// Ceiling on vCPUs; a caller asking for more is refused.
    pub max_vcpus: Option<NonZeroU8>,
    /// Ceiling on memory, MiB.
    pub max_mem_mib: Option<NonZeroU32>,
    /// Ceiling on the wall-clock budget, seconds.
    pub max_wall_secs: Option<u64>,
    /// Ceiling on the output cap, bytes.
    pub max_output_cap: Option<usize>,

    /// Refuse an unjailed boot: the `--unjailed` opt-out. is withdrawn on this host.
    /// Monotone, a caller can ask for the jail, never ask it away.
    pub require_jail: bool,
    /// Whether a caller may attach a NIC at all. `false` refuses `--net` outright; it does not change
    /// the deny-by-default egress policy a NIC still gets.
    pub allow_net: Option<bool>,

    /// Refuse a run without an audit record on this host.
    pub require_record: bool,
    /// Directory where required audit records are stored by default.
    pub records_dir: Option<PathBuf>,

    /// Operator ceiling on allowed IPv4 egress CIDRs. Empty means no restriction.
    pub max_egress_v4: Vec<Ipv4Cidr>,
    /// Operator ceiling on allowed IPv6 egress CIDRs. Empty means no restriction.
    pub max_egress_v6: Vec<Ipv6Cidr>,
}

/// A run refused because it asked past the operator's policy. Carries the knob, what was asked, and
/// the bound, so the message can name the fix rather than just saying no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A resource request exceeded its ceiling.
    Ceiling {
        /// The knob's name as an operator writes it in `.ekvm.toml`.
        knob: &'static str,
        /// What the caller asked for.
        asked: u64,
        /// The operator's ceiling.
        ceiling: u64,
    },
    /// `--unjailed` was asked for on a host that requires the jail.
    JailRequired,
    /// `--net` was asked for on a host that forbids guest NICs.
    NetForbidden,
    /// `--record` was omitted on a host that requires an audit record.
    RecordRequired,
    /// An `--allow` egress CIDR rule extends beyond the operator's approved range.
    EgressNotAllowed {
        /// The requested CIDR string that was outside the operator's ceiling.
        asked: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ceiling {
                knob,
                asked,
                ceiling,
            } => write!(
                f,
                "{knob} {asked} exceeds this host's limit of {ceiling} (operator policy: \
                 `max_{knob}` in .ekvm.toml)"
            ),
            Self::JailRequired => f.write_str(
                "this host requires the jail: `--unjailed` is refused (operator policy: \
                 `require_jail` in .ekvm.toml)",
            ),
            Self::NetForbidden => f.write_str(
                "this host does not permit guest networking: `--net` is refused (operator policy: \
                 `allow_net = false` in .ekvm.toml)",
            ),
            Self::RecordRequired => f.write_str(
                "this host requires an audit record: omitting --record is refused (operator policy: \
                 `require_record = true` in .ekvm.toml)",
            ),
            Self::EgressNotAllowed { asked } => write!(
                f,
                "requested egress CIDR {asked} extends beyond this host's operator ceiling \
                 (operator policy: `max_egress_v4`/`max_egress_v6` in .ekvm.toml)"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Resolve a caller's request against this policy into concrete [`Limits`].
    /// Two different things happen to an over-large value, and the difference is whether a caller
    /// actually asked for it:
    /// - **An explicit request above a ceiling is refused.** The caller asked for something this host
    ///   does not permit; silently serving them less is the degradation a refusal exists to forbid.
    /// - **A *default* above a ceiling is clamped to the ceiling.** Nobody asked for it, so there is
    ///   no caller intent to contradict, and refusing would be absurd: setting only `max_wall_secs`
    ///   would otherwise refuse every bare run, because the engine's own 30s default exceeds it. This
    ///   also means a self-inconsistent policy (a default above its own ceiling) resolves to the
    ///   ceiling, the operator's stronger statement, rather than failing every run.
    /// # Errors
    /// [`PolicyError::Ceiling`] when a value the **caller explicitly requested** exceeds its ceiling.
    pub fn resolve(&self, req: &Requested) -> Result<Limits, PolicyError> {
        let mut limits = Limits::default();

        let max_vcpus = self.max_vcpus.map(|v| u64::from(v.get()));
        let vcpus = resolve_knob(
            "vcpus",
            req.vcpus.map(|v| u64::from(v.get())),
            self.vcpus.map(|v| u64::from(v.get())),
            u64::from(limits.vcpus.get()),
            max_vcpus,
        )?;
        limits.vcpus = u8::try_from(vcpus)
            .ok()
            .and_then(NonZeroU8::new)
            .unwrap_or(limits.vcpus);

        let max_mem = self.max_mem_mib.map(|v| u64::from(v.get()));
        let mem = resolve_knob(
            "mem_mib",
            req.mem_mib.map(|v| u64::from(v.get())),
            self.mem_mib.map(|v| u64::from(v.get())),
            u64::from(limits.mem_mib.get()),
            max_mem,
        )?;
        limits.mem_mib = u32::try_from(mem)
            .ok()
            .and_then(NonZeroU32::new)
            .unwrap_or(limits.mem_mib);

        let wall = resolve_knob(
            "wall_secs",
            req.wall_secs,
            self.wall_secs,
            limits.wall.as_secs(),
            self.max_wall_secs,
        )?;
        limits.wall = Duration::from_secs(wall);

        let cap = resolve_knob(
            "output_cap",
            req.output_cap.map(|c| c as u64),
            self.output_cap.map(|c| c as u64),
            limits.output_cap as u64,
            self.max_output_cap.map(|c| c as u64),
        )?;
        limits.output_cap = usize::try_from(cap).unwrap_or(limits.output_cap);

        Ok(limits)
    }

    /// Refuse an unjailed boot when the host requires the jail. Monotone: a caller never loosens it.
    /// # Errors
    /// [`PolicyError::JailRequired`] when `unjailed` is asked for under `require_jail`.
    pub fn check_jail(&self, unjailed: bool) -> Result<(), PolicyError> {
        if unjailed && self.require_jail {
            return Err(PolicyError::JailRequired);
        }
        Ok(())
    }

    /// Refuse a NIC when the host forbids guest networking. Absent policy permits it, so an unset
    /// `allow_net` leaves today's behavior untouched.
    /// # Errors
    /// [`PolicyError::NetForbidden`] when `net` is asked for under `allow_net = false`.
    pub fn check_net(&self, net: bool) -> Result<(), PolicyError> {
        if net && self.allow_net == Some(false) {
            return Err(PolicyError::NetForbidden);
        }
        Ok(())
    }

    /// Refuse an egress policy whose requested CIDR rules extend beyond the operator's approved CIDR ceilings.
    /// # Errors
    /// [`PolicyError::EgressNotAllowed`] when a requested CIDR is not contained within the operator's allowed list.
    pub fn check_egress(&self, egress: &EgressPolicy) -> Result<(), PolicyError> {
        if !self.max_egress_v4.is_empty() {
            for asked in egress.cidrs_v4() {
                if !self
                    .max_egress_v4
                    .iter()
                    .any(|allowed| allowed.contains(&asked))
                {
                    return Err(PolicyError::EgressNotAllowed {
                        asked: asked.to_string(),
                    });
                }
            }
        }
        if !self.max_egress_v6.is_empty() {
            for asked in egress.cidrs_v6() {
                if !self
                    .max_egress_v6
                    .iter()
                    .any(|allowed| allowed.contains(&asked))
                {
                    return Err(PolicyError::EgressNotAllowed {
                        asked: asked.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Refuse a run without an audit record on a host that requires recording.
    /// # Errors
    /// [`PolicyError::RecordRequired`] when recording is omitted under `require_record = true`.
    pub fn check_record(&self, recording: bool) -> Result<(), PolicyError> {
        if !recording && self.require_record {
            return Err(PolicyError::RecordRequired);
        }
        Ok(())
    }
}

/// Resolve one knob: refuse an explicit over-ask, clamp an unasked-for default, and otherwise take
/// the first of caller / operator default / engine default. Naming the knob lets the refusal point at
/// the exact config key to change.
fn resolve_knob(
    knob: &'static str,
    asked: Option<u64>,
    operator_default: Option<u64>,
    engine_default: u64,
    ceiling: Option<u64>,
) -> Result<u64, PolicyError> {
    if let (Some(a), Some(c)) = (asked, ceiling) {
        if a > c {
            return Err(PolicyError::Ceiling {
                knob,
                asked: a,
                ceiling: c,
            });
        }
    }
    let value = asked.or(operator_default).unwrap_or(engine_default);
    Ok(match ceiling {
        Some(c) => value.min(c),
        None => value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz8(v: u8) -> Option<NonZeroU8> {
        NonZeroU8::new(v)
    }
    fn nz32(v: u32) -> Option<NonZeroU32> {
        NonZeroU32::new(v)
    }

    #[test]
    fn an_empty_policy_changes_nothing() {
        let got = Policy::default()
            .resolve(&Requested::default())
            .expect("no policy, no refusal");
        let want = Limits::default();
        // Field-wise: `Limits` is deliberately not `PartialEq` (it is `#[non_exhaustive]` and pinned,
        // so a derive would be an api-surface promise), and this asserts the whole struct anyway.
        assert_eq!(
            got.vcpus, want.vcpus,
            "absent config leaves the engine default"
        );
        assert_eq!(got.mem_mib, want.mem_mib);
        assert_eq!(got.wall, want.wall);
        assert_eq!(got.output_cap, want.output_cap);
    }

    #[test]
    fn caller_beats_operator_default_which_beats_the_engine_default() {
        let policy = Policy {
            vcpus: nz8(4),
            ..Policy::default()
        };
        // Operator default applies when the caller is silent.
        let quiet = policy
            .resolve(&Requested::default())
            .expect("within policy");
        assert_eq!(quiet.vcpus.get(), 4);
        // The caller still wins over a *default* (that is what a default means).
        let loud = policy
            .resolve(&Requested {
                vcpus: nz8(2),
                ..Requested::default()
            })
            .expect("within policy");
        assert_eq!(loud.vcpus.get(), 2);
        // And nothing else moved off the engine default.
        assert_eq!(quiet.mem_mib, Limits::default().mem_mib);
    }

    #[test]
    fn a_ceiling_refuses_rather_than_clamps() {
        let policy = Policy {
            max_vcpus: nz8(4),
            ..Policy::default()
        };
        let err = policy
            .resolve(&Requested {
                vcpus: nz8(32),
                ..Requested::default()
            })
            .expect_err("32 vCPUs is past the ceiling");
        assert_eq!(
            err,
            PolicyError::Ceiling {
                knob: "vcpus",
                asked: 32,
                ceiling: 4
            },
            "the refusal names the knob, the ask, and the bound"
        );
        // Silently returning 4 here would be a silent clamp, not the typed refusal enforcement requires.
        assert!(
            policy
                .resolve(&Requested {
                    vcpus: nz8(4),
                    ..Requested::default()
                })
                .is_ok(),
            "exactly at the ceiling is allowed"
        );
    }

    #[test]
    fn an_unasked_for_default_is_clamped_not_refused() {
        // The distinction that makes ceilings usable. Setting only a ceiling must not refuse every
        // bare run just because the *engine's* default sits above it: nobody asked for 30s.
        let policy = Policy {
            max_wall_secs: Some(10),
            ..Policy::default()
        };
        let got = policy
            .resolve(&Requested::default())
            .expect("a bare run is served, not refused");
        assert_eq!(got.wall, Duration::from_secs(10), "clamped to the ceiling");

        // A self-inconsistent policy resolves to the ceiling, the operator's stronger statement.
        let inconsistent = Policy {
            vcpus: nz8(8),
            max_vcpus: nz8(4),
            ..Policy::default()
        };
        let got = inconsistent
            .resolve(&Requested::default())
            .expect("still serves");
        assert_eq!(got.vcpus.get(), 4);
    }

    #[test]
    fn asking_beats_defaulting_even_at_the_same_value() {
        // The two paths must not be conflated: 32 asked-for is a refusal, 32 defaulted-into is a
        // clamp. Same number, opposite outcomes, because only one of them is a caller's intent.
        let policy = Policy {
            wall_secs: Some(32),
            max_wall_secs: Some(16),
            ..Policy::default()
        };
        assert_eq!(
            policy.resolve(&Requested::default()).map(|l| l.wall),
            Ok(Duration::from_secs(16)),
            "the operator's own default is clamped"
        );
        assert_eq!(
            policy
                .resolve(&Requested {
                    wall_secs: Some(32),
                    ..Requested::default()
                })
                .map(|l| l.wall),
            Err(PolicyError::Ceiling {
                knob: "wall_secs",
                asked: 32,
                ceiling: 16
            }),
            "the same value, explicitly asked for, is refused"
        );
    }

    #[test]
    fn every_knob_has_a_working_ceiling() {
        let policy = Policy {
            max_vcpus: nz8(2),
            max_mem_mib: nz32(256),
            max_wall_secs: Some(10),
            max_output_cap: Some(1024),
            ..Policy::default()
        };
        let cases: [(Requested, &str); 4] = [
            (
                Requested {
                    vcpus: nz8(3),
                    ..Requested::default()
                },
                "vcpus",
            ),
            (
                Requested {
                    mem_mib: nz32(512),
                    ..Requested::default()
                },
                "mem_mib",
            ),
            (
                Requested {
                    wall_secs: Some(11),
                    ..Requested::default()
                },
                "wall_secs",
            ),
            (
                Requested {
                    output_cap: Some(2048),
                    ..Requested::default()
                },
                "output_cap",
            ),
        ];
        for (req, knob) in cases {
            assert!(
                matches!(
                    policy.resolve(&req),
                    Err(PolicyError::Ceiling { knob: got, .. }) if got == knob
                ),
                "the {knob} ceiling must refuse, naming {knob}"
            );
        }
    }

    #[test]
    fn jail_posture_is_monotone() {
        let off = Policy::default();
        assert!(
            off.check_jail(true).is_ok(),
            "unset policy keeps the opt-out"
        );
        let on = Policy {
            require_jail: true,
            ..Policy::default()
        };
        assert_eq!(on.check_jail(true), Err(PolicyError::JailRequired));
        assert!(
            on.check_jail(false).is_ok(),
            "asking for the jail is always fine, the posture only ever tightens"
        );
    }

    #[test]
    fn net_is_permitted_unless_the_operator_forbids_it() {
        assert!(Policy::default().check_net(true).is_ok(), "unset permits");
        let allowed = Policy {
            allow_net: Some(true),
            ..Policy::default()
        };
        assert!(allowed.check_net(true).is_ok());
        let denied = Policy {
            allow_net: Some(false),
            ..Policy::default()
        };
        assert_eq!(denied.check_net(true), Err(PolicyError::NetForbidden));
        assert!(
            denied.check_net(false).is_ok(),
            "a run that wants no NIC is unaffected"
        );
    }

    #[test]
    fn egress_ceiling_permits_narrowing_and_refuses_widening() {
        use std::net::Ipv4Addr;

        let ceiling = Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap();
        let policy = Policy {
            max_egress_v4: vec![ceiling],
            ..Policy::default()
        };

        // Narrowing (host inside 10.0.0.0/8) is allowed
        let allowed_rule =
            EgressPolicy::deny_all().allow_host(Ipv4Addr::new(10, 1, 2, 3), Some(443), None);
        assert!(
            policy.check_egress(&allowed_rule).is_ok(),
            "narrowed host inside 10.0.0.0/8 is permitted"
        );

        // Widening (asking for 192.168.1.1) is refused
        let widened_rule =
            EgressPolicy::deny_all().allow_host(Ipv4Addr::new(192, 168, 1, 1), None, None);
        assert!(
            matches!(
                policy.check_egress(&widened_rule),
                Err(PolicyError::EgressNotAllowed { .. })
            ),
            "asking outside 10.0.0.0/8 is refused"
        );
    }

    #[test]
    fn record_posture_refuses_unrecorded_runs() {
        let off = Policy::default();
        assert!(
            off.check_record(false).is_ok(),
            "default permits unrecorded runs"
        );

        let on = Policy {
            require_record: true,
            ..Policy::default()
        };
        assert_eq!(on.check_record(false), Err(PolicyError::RecordRequired));
        assert!(on.check_record(true).is_ok(), "recorded runs are permitted");
    }
}
