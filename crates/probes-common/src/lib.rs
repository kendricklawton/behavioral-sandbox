//! Plain-old-data shared across the eBPF boundary. The kernel programs in `crates/probes` write a
//! [`SyscallEvent`] into a ring buffer; the userspace loader in `crates/probes-loader` reads the raw
//! bytes back and reconstructs it with [`SyscallEvent::from_bytes`]. Defining the record **once**,
//! here, is what keeps the writer and the reader from drifting: a field reordered or resized on one
//! side but not the other would otherwise be a silent garbage read, the classic FFI-struct bug.
//!
//! The type is `#[repr(C)]` with fields ordered large-to-small so the layout is padding-free and
//! stable, and both sides run on the same host (one kernel, one userspace) so native byte order is
//! shared, [`from_bytes`](SyscallEvent::from_bytes) reads each field with `from_ne_bytes`, no
//! `unsafe`, no transmute. `#![no_std]` with zero dependencies so it compiles for the BPF target
//! unchanged; the `std` feature (enabled by the userspace loader, and by the crate's own tests) opts
//! back into `std` for the ergonomic [`SyscallEvent::comm_lossy`] helper.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

/// The fixed capture width of a process's `comm` (the kernel's own 16-byte `TASK_COMM_LEN`).
pub const COMM_CAP: usize = 16;

/// The fixed capture width of the per-event detail blob: an `openat`/`execve` path, or the leading
/// bytes of a `connect` sockaddr. Bounded because an eBPF program writes into a fixed stack buffer and
/// the record is a fixed-size ring-buffer entry; a longer path is truncated to this many bytes.
pub const DETAIL_CAP: usize = 128;

/// How many leading bytes of a `connect` sockaddr the probe copies into [`SyscallEvent::detail`].
/// 28 is `sizeof(struct sockaddr_in6)` (family + port + flowinfo + the 16-byte address + scope), so a
/// full **IPv6** address is captured, not just its first 8 bytes (ADR 008 dual-stack). A `sockaddr_in`
/// (IPv4) is only 16 bytes, so the probe falls back to [`SOCKADDR_SNAP_V4`] when the full read would
/// run past a short user buffer, no v4 capture regresses.
pub const SOCKADDR_SNAP: usize = 28;

/// The IPv4 `sockaddr_in` size (family + port + 4-byte address), the probe's fallback copy length when
/// the full [`SOCKADDR_SNAP`] read faults on a buffer only big enough for a v4 address.
pub const SOCKADDR_SNAP_V4: usize = 16;

/// Which syscall a [`SyscallEvent`] records. The wire field is a raw [`u32`]
/// ([`SyscallEvent::syscall`]) rather than this enum, so reconstructing an event from arbitrary bytes
/// can never form an invalid discriminant; [`SyscallEvent::kind`] maps it back, returning `None` for
/// an unknown value.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    /// `execve` (`sys_enter_execve`): detail holds the program path.
    Execve = 0,
    /// `openat` (`sys_enter_openat`): detail holds the opened path.
    Openat = 1,
    /// `connect` (`sys_enter_connect`): detail holds the leading [`SOCKADDR_SNAP`] sockaddr bytes.
    Connect = 2,
}

/// One host syscall observed by the probes, as written into the ring buffer. `#[repr(C)]` and
/// padding-free (fields large-to-small: the `u64` first, then the `u32`s, then the byte arrays), so
/// [`from_bytes`](Self::from_bytes) can read it field by field at fixed offsets. This is the **host's**
/// footprint (a microVM services its own syscalls in-guest and they never trap here, see the crate
/// docs).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallEvent {
    /// The cgroup id of the process that made the syscall (`bpf_get_current_cgroup_id`), the axis a
    /// sandbox's host footprint is attributed and filtered on.
    pub cgroup_id: u64,
    /// The thread-group id (the userspace "pid") of the process.
    pub pid: u32,
    /// The thread id (the kernel task's `pid`); equals `pid` for a single-threaded process.
    pub tid: u32,
    /// Which syscall this is, as a [`Syscall`] discriminant; decode with [`kind`](Self::kind).
    pub syscall: u32,
    /// Valid byte count in [`detail`](Self::detail) (0 when the detail couldn't be read); always
    /// `<= DETAIL_CAP`.
    pub detail_len: u32,
    /// The process's `comm` (NUL-padded), captured by `bpf_get_current_comm`.
    pub comm: [u8; COMM_CAP],
    /// Syscall-specific detail: a path (`execve`/`openat`) or leading sockaddr bytes (`connect`). Read
    /// the valid prefix with [`detail`](Self::detail).
    pub detail: [u8; DETAIL_CAP],
}

/// The exact on-wire size of a [`SyscallEvent`] (the ring-buffer entry length the reader expects).
pub const EVENT_SIZE: usize = core::mem::size_of::<SyscallEvent>();

impl SyscallEvent {
    /// Reconstruct an event from a ring-buffer record's raw bytes, or `None` if the slice is too
    /// short. Reads each field at its `#[repr(C)]` offset with `from_ne_bytes`, safe, no
    /// transmute. The offsets are **derived from the struct itself** (`core::mem::offset_of!`),
    /// not hand-coded, so even a same-size field reorder cannot make the reader and the kernel
    /// writer disagree (a resize is caught by the [`EVENT_SIZE`] check; the offsets close the
    /// remaining drift hole).
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < EVENT_SIZE {
            return None;
        }
        const CGROUP_ID: usize = core::mem::offset_of!(SyscallEvent, cgroup_id);
        const PID: usize = core::mem::offset_of!(SyscallEvent, pid);
        const TID: usize = core::mem::offset_of!(SyscallEvent, tid);
        const SYSCALL: usize = core::mem::offset_of!(SyscallEvent, syscall);
        const DETAIL_LEN: usize = core::mem::offset_of!(SyscallEvent, detail_len);
        const COMM: usize = core::mem::offset_of!(SyscallEvent, comm);
        const DETAIL: usize = core::mem::offset_of!(SyscallEvent, detail);
        let cgroup_id = u64::from_ne_bytes(b.get(CGROUP_ID..CGROUP_ID + 8)?.try_into().ok()?);
        let pid = u32::from_ne_bytes(b.get(PID..PID + 4)?.try_into().ok()?);
        let tid = u32::from_ne_bytes(b.get(TID..TID + 4)?.try_into().ok()?);
        let syscall = u32::from_ne_bytes(b.get(SYSCALL..SYSCALL + 4)?.try_into().ok()?);
        let detail_len = u32::from_ne_bytes(b.get(DETAIL_LEN..DETAIL_LEN + 4)?.try_into().ok()?);
        let mut comm = [0u8; COMM_CAP];
        comm.copy_from_slice(b.get(COMM..COMM + COMM_CAP)?);
        let mut detail = [0u8; DETAIL_CAP];
        detail.copy_from_slice(b.get(DETAIL..DETAIL + DETAIL_CAP)?);
        Some(Self {
            cgroup_id,
            pid,
            tid,
            syscall,
            detail_len,
            comm,
            detail,
        })
    }

    /// The syscall as a typed [`Syscall`], or `None` for an unrecognized discriminant.
    #[must_use]
    pub fn kind(&self) -> Option<Syscall> {
        match self.syscall {
            0 => Some(Syscall::Execve),
            1 => Some(Syscall::Openat),
            2 => Some(Syscall::Connect),
            _ => None,
        }
    }

    /// The valid prefix of [`detail`](Self::detail) (`detail_len` bytes, clamped to [`DETAIL_CAP`]).
    #[must_use]
    pub fn detail(&self) -> &[u8] {
        let n = (self.detail_len as usize).min(DETAIL_CAP);
        &self.detail[..n]
    }

    /// The `comm` as a `&str` up to its first NUL, lossily (non-UTF-8 bytes become replacement
    /// characters); `std`-only, since it allocates on the lossy path.
    #[cfg(any(feature = "std", test))]
    #[must_use]
    pub fn comm_lossy(&self) -> std::borrow::Cow<'_, str> {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(COMM_CAP);
        String::from_utf8_lossy(&self.comm[..end])
    }

    /// The short syscall name (`execve`/`openat`/`connect`, or `?` for an unknown discriminant), for a
    /// trace line. `no_std`-friendly (all string literals).
    #[must_use]
    pub fn syscall_name(&self) -> &'static str {
        match self.kind() {
            Some(Syscall::Execve) => "execve",
            Some(Syscall::Openat) => "openat",
            Some(Syscall::Connect) => "connect",
            None => "?",
        }
    }

    /// The event's detail blob decoded for display: the path (`execve`/`openat`, lossy UTF-8) or the
    /// `connect` address (`AF_INET` as `a.b.c.d:port`, other families by number). Centralized here so
    /// every consumer decodes the same way (`std`-only).
    ///
    /// Returns a [`Cow`](std::borrow::Cow): **borrowed** for the common case (a valid-UTF-8 path,
    /// no allocation), owned only when rendering must build a string (a `connect` sockaddr, or
    /// lossy replacement characters). A per-event fold probes its dedup map with this without
    /// paying an allocation per repeat; take [`detail_display`](Self::detail_display) when an owned
    /// `String` is wanted anyway.
    #[cfg(any(feature = "std", test))]
    #[must_use]
    pub fn detail_display_cow(&self) -> std::borrow::Cow<'_, str> {
        let d = self.detail();
        match self.kind() {
            Some(Syscall::Connect) => std::borrow::Cow::Owned(describe_sockaddr(d)),
            _ => String::from_utf8_lossy(d),
        }
    }

    /// [`detail_display_cow`](Self::detail_display_cow), owned. The two stay one decoder: this is
    /// just `.into_owned()`.
    #[cfg(any(feature = "std", test))]
    #[must_use]
    pub fn detail_display(&self) -> String {
        self.detail_display_cow().into_owned()
    }

    /// One decoded trace line: `pid=<pid> comm=<comm> <syscall> <detail>` (`std`-only). The streaming
    /// consumer prints this directly.
    #[cfg(any(feature = "std", test))]
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "pid={} comm={} {} {}",
            self.pid,
            self.comm_lossy(),
            self.syscall_name(),
            self.detail_display()
        )
    }
}

/// A best-effort human form of the leading sockaddr bytes: `AF_INET` yields `a.b.c.d:port`, `AF_INET6`
/// yields `[v6]:port`, other families name the family number, and a too-short capture says so.
#[cfg(any(feature = "std", test))]
fn describe_sockaddr(bytes: &[u8]) -> String {
    // sa_family is a native-endian u16. AF_INET == 2 (sockaddr_in: family, be16 port, 4-byte addr);
    // AF_INET6 == 10 (sockaddr_in6: family, be16 port, 4-byte flowinfo, then the 16-byte addr at 8).
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    if bytes.len() >= 8 {
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family == AF_INET {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            return format!("{}.{}.{}.{}:{port}", bytes[4], bytes[5], bytes[6], bytes[7]);
        }
        if family == AF_INET6 && bytes.len() >= 24 {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[8..24]);
            return format!("[{}]:{port}", std::net::Ipv6Addr::from(addr));
        }
        return format!("<sockaddr family {family}>");
    }
    "<sockaddr: too short>".to_string()
}

// ---------------------------------------------------------------------------
// Network flows: the per-flow record the tc program on a VM's tap writes.
// ---------------------------------------------------------------------------

/// Ethernet header length (dst MAC + src MAC + EtherType), the offset the IPv4 header starts at.
/// Shared by the tc program (`crates/probes`, which reads with `ctx.load`) and the host-side
/// [`parse_ipv4_5tuple`], so the two can't disagree on where a field lives (the single-sourcing that
/// keeps [`SyscallEvent`] honest, applied to packet offsets).
pub const ETH_HLEN: usize = 14;
/// Byte offset of the EtherType in an Ethernet frame.
pub const ETHERTYPE_OFFSET: usize = 12;
/// EtherType for IPv4.
pub const ETH_P_IP: u16 = 0x0800;
/// EtherType for ARP. Egress enforcement lets ARP through even under deny-by-default: the guest must
/// resolve its on-link gateway (`10.200.0.1`, ADR 014) before it can reach *any* allowed endpoint.
pub const ETH_P_ARP: u16 = 0x0806;
/// EtherType for IPv6, and for an 802.1Q VLAN tag. The tap parser handles only IPv4, so a frame with
/// either of these is *unrepresentable* as a flow: the kernel counts it (as an honest coverage
/// signal) rather than dropping it from the record silently. Neither is expected on a sandbox's
/// IPv4-only tap (ADR 014), unlike ARP, which is why ARP is not counted here.
pub const ETH_P_IPV6: u16 = 0x86dd;
/// See [`ETH_P_IPV6`].
pub const ETH_P_8021Q: u16 = 0x8100;
/// An L4 protocol an egress rule (or a flow) is matched on, the typed face of the raw IP protocol
/// number the wire carries. A caller writes `Protocol::Udp`, never `17`. Only the two protocols the
/// parser reads ports for; "any protocol" is [`None`], not a variant (see [`PolicyRule`]). `#[repr(u8)]`
/// with the on-wire IP protocol number as the discriminant, so [`as_u8`](Self::as_u8) is the value the
/// kernel and the map already use.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP: its L4 header starts with a 16-bit source then destination port.
    Tcp = 6,
    /// UDP: same leading source/destination port layout as TCP.
    Udp = 17,
}

impl Protocol {
    /// The on-wire IP protocol number (`6`/`17`), the byte the kernel matches and the map stores.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The typed protocol for an IP protocol number, or `None` for one this engine doesn't parse ports
    /// for (the "any / other protocol" case a rule expresses as a `0` wire value).
    #[must_use]
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            IPPROTO_TCP => Some(Self::Tcp),
            IPPROTO_UDP => Some(Self::Udp),
            _ => None,
        }
    }
}

/// IP protocol number for TCP (its L4 header starts with a 16-bit source then destination port).
/// Single-sourced from [`Protocol::Tcp`] so the constant and the enum can't disagree.
pub const IPPROTO_TCP: u8 = Protocol::Tcp as u8;
/// IP protocol number for UDP (same leading source/destination port layout as TCP).
pub const IPPROTO_UDP: u8 = Protocol::Udp as u8;

/// IP protocol number for **ICMPv6** (next-header 58). Egress enforcement always lets it through under
/// v6, the way it always lets ARP through under v4: the guest needs neighbor discovery (NS/NA) to
/// resolve its on-link host end, and multicast-listener (MLD) messages to join the solicited-node
/// group, before it can reach *any* allowed v6 endpoint. Link-local ICMPv6 can't route off the link
/// anyway (no v6 default route), so allowing it does not widen egress.
pub const IPPROTO_ICMPV6: u8 = 58;

/// One **directional** network flow's identity: the IPv4 5-tuple, in host byte order (so a consumer
/// formats `src_addr` straight to dotted-quad). `#[repr(C)]` and padding-free, the trailing `_pad` is
/// explicit and always zero because this is a BPF **hash-map key**: an uninitialized pad byte would
/// make two identical flows hash to different slots. 16 bytes; build it with [`FlowKey::new`], which
/// zeroes the pad.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FlowKey {
    /// Source IPv4 address, host byte order.
    pub src_addr: u32,
    /// Destination IPv4 address, host byte order.
    pub dst_addr: u32,
    /// Source L4 port (0 for a non-TCP/UDP protocol).
    pub src_port: u16,
    /// Destination L4 port (0 for a non-TCP/UDP protocol).
    pub dst_port: u16,
    /// IP protocol number ([`IPPROTO_TCP`] / [`IPPROTO_UDP`] / …).
    pub proto: u8,
    /// Explicit zeroed padding to a stable, hashable 16-byte key (see the type doc).
    pub _pad: [u8; 3],
}

/// The on-wire size of a [`FlowKey`] (the map key length the loader reads).
pub const FLOW_KEY_SIZE: usize = core::mem::size_of::<FlowKey>();

impl FlowKey {
    /// Build a key from the 5-tuple, zeroing the padding so it hashes deterministically.
    #[must_use]
    pub fn new(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            proto,
            _pad: [0; 3],
        }
    }

    /// Reconstruct a key from a map key's raw bytes (as the loader reads them), or `None` if the slice
    /// is too short. Reads each field at its fixed `#[repr(C)]` offset with `from_ne_bytes` (same host,
    /// shared byte order), no `unsafe`, no transmute, defined next to the fields so it can't drift from
    /// the kernel writer.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < FLOW_KEY_SIZE {
            return None;
        }
        Some(Self::new(
            u32::from_ne_bytes(b.get(0..4)?.try_into().ok()?),
            u32::from_ne_bytes(b.get(4..8)?.try_into().ok()?),
            u16::from_ne_bytes(b.get(8..10)?.try_into().ok()?),
            u16::from_ne_bytes(b.get(10..12)?.try_into().ok()?),
            *b.get(12)?,
        ))
    }
}

impl core::fmt::Display for FlowKey {
    /// `a.b.c.d:sport -> e.f.g.h:dport <proto>`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.src_addr.to_be_bytes();
        let d = self.dst_addr.to_be_bytes();
        write!(
            f,
            "{}.{}.{}.{}:{} -> {}.{}.{}.{}:{} ",
            s[0], s[1], s[2], s[3], self.src_port, d[0], d[1], d[2], d[3], self.dst_port
        )?;
        match self.proto {
            IPPROTO_TCP => f.write_str("tcp"),
            IPPROTO_UDP => f.write_str("udp"),
            p => write!(f, "proto {p}"),
        }
    }
}

/// Per-direction packet/byte counters for one [`FlowKey`], from the tap's perspective: **ingress** is a
/// frame the guest sent (arriving at the tap), **egress** a frame delivered to the guest. `#[repr(C)]`,
/// 32 bytes, padding-free (four `u64`s).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FlowCounts {
    /// Packets seen on the tap's ingress hook (guest → world).
    pub ingress_packets: u64,
    /// Bytes (skb length) seen on ingress.
    pub ingress_bytes: u64,
    /// Packets seen on the tap's egress hook (world → guest).
    pub egress_packets: u64,
    /// Bytes seen on egress.
    pub egress_bytes: u64,
}

/// The on-wire size of a [`FlowCounts`] (the map value length the loader reads).
pub const FLOW_COUNTS_SIZE: usize = core::mem::size_of::<FlowCounts>();

impl FlowCounts {
    /// Reconstruct counters from a map value's raw bytes, or `None` if the slice is too short.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < FLOW_COUNTS_SIZE {
            return None;
        }
        Some(Self {
            ingress_packets: u64::from_ne_bytes(b.get(0..8)?.try_into().ok()?),
            ingress_bytes: u64::from_ne_bytes(b.get(8..16)?.try_into().ok()?),
            egress_packets: u64::from_ne_bytes(b.get(16..24)?.try_into().ok()?),
            egress_bytes: u64::from_ne_bytes(b.get(24..32)?.try_into().ok()?),
        })
    }
}

/// Parse the IPv4 5-tuple out of an Ethernet `frame` (addresses and ports in host order), or `None` if
/// it is not IPv4-over-Ethernet or is truncated. TCP/UDP carry their ports; any other protocol reports
/// ports 0. The tc program in `crates/probes` mirrors this exact logic with `ctx.load` at the same
/// offsets (single-sourced so the kernel and this can't drift); this pure, slice-based form is what the
/// host gate unit-tests, since the in-kernel reads need a live packet and the verifier.
#[must_use]
pub fn parse_ipv4_5tuple(frame: &[u8]) -> Option<FlowKey> {
    let ethertype = u16::from_be_bytes([
        *frame.get(ETHERTYPE_OFFSET)?,
        *frame.get(ETHERTYPE_OFFSET + 1)?,
    ]);
    if ethertype != ETH_P_IP {
        return None;
    }
    let ip = frame.get(ETH_HLEN..)?;
    let ihl = ((*ip.first()? & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let proto = *ip.get(9)?;
    let src = u32::from_be_bytes(ip.get(12..16)?.try_into().ok()?);
    let dst = u32::from_be_bytes(ip.get(16..20)?.try_into().ok()?);
    // The low 13 bits of the flags/fragment-offset field (bytes 6..8) are the fragment offset. A
    // non-first fragment (offset != 0) carries no L4 header, so reading "ports" there would just
    // interpret payload bytes, letting a guest mint bogus 5-tuples. Leave the ports zero for it.
    let frag_off = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x1fff;
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if frag_off == 0 && (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        let l4 = ip.get(ihl..)?;
        src_port = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
        dst_port = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    }
    Some(FlowKey::new(src, dst, src_port, dst_port, proto))
}

// ---------------------------------------------------------------------------
// Egress policy: the allow-list the tc program on a VM's tap consults to drop or accept
// a guest-sent packet. Single-sourced here so the in-kernel matcher and the host-tested one can't drift.
// ---------------------------------------------------------------------------

/// How many egress allow-rules a sandbox's policy holds, a fixed bound, because the tc program scans
/// the whole array in a **bounded loop** (the verifier needs a compile-time cap) and BPF maps are sized
/// at load. Comfortably covers a per-sandbox allow-list of a handful of endpoints.
pub const MAX_POLICY_RULES: usize = 16;

/// One entry in a sandbox's egress allow-list: a destination **CIDR** plus optional port and
/// protocol. A guest-sent IPv4 packet is allowed if its destination matches **any** `active` rule (see
/// [`rule_matches`] / [`egress_allowed`]); with no rule matching, deny-by-default drops it. `#[repr(C)]`
/// and padding-free (an explicit zeroed `_pad`) so it is a stable 12-byte map value the loader writes
/// and the kernel reads without either side guessing the layout.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PolicyRule {
    /// Allowed destination network, **host byte order** (compared masked to `prefix_len`).
    pub addr: u32,
    /// Allowed destination port, or `0` for "any port".
    pub port: u16,
    /// Prefix length in bits, `0..=32`; `0` matches any address (a `0.0.0.0/0` allow-all).
    pub prefix_len: u8,
    /// IP protocol to match ([`IPPROTO_TCP`] / [`IPPROTO_UDP`]), or `0` for "any protocol".
    pub proto: u8,
    /// `1` if this slot holds a real rule, `0` if it is empty. Explicit because the policy is a
    /// fixed-size array: an all-zero (empty) slot must **not** read as an allow-all `0.0.0.0/0` rule.
    pub active: u8,
    /// Zeroed padding to a stable 12-byte record (see the type doc).
    pub _pad: [u8; 3],
}

/// The on-wire size of a [`PolicyRule`] (the map value length the loader writes).
pub const POLICY_RULE_SIZE: usize = core::mem::size_of::<PolicyRule>();

impl PolicyRule {
    /// Build an **active** allow-rule for `addr/prefix_len`, optional `port` (`0` = any) and `proto`
    /// (`0` = any), zeroing the padding so it is a byte-stable map value.
    #[must_use]
    pub fn allow(addr: u32, prefix_len: u8, port: u16, proto: u8) -> Self {
        Self {
            addr,
            port,
            prefix_len,
            proto,
            active: 1,
            _pad: [0; 3],
        }
    }

    /// Serialize to the map value's raw native bytes, so the loader can write the policy without an
    /// `unsafe` [`aya::Pod`](https://docs.rs/aya) binding (the write-side twin of [`FlowKey::from_bytes`]).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; POLICY_RULE_SIZE] {
        let mut b = [0u8; POLICY_RULE_SIZE];
        b[0..4].copy_from_slice(&self.addr.to_ne_bytes());
        b[4..6].copy_from_slice(&self.port.to_ne_bytes());
        b[6] = self.prefix_len;
        b[7] = self.proto;
        b[8] = self.active;
        b
    }

    /// Reconstruct a rule from a map value's raw bytes, or `None` if the slice is too short, the
    /// read-side twin of [`to_bytes`](Self::to_bytes), defined next to the fields so it can't drift.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < POLICY_RULE_SIZE {
            return None;
        }
        Some(Self {
            addr: u32::from_ne_bytes(b.get(0..4)?.try_into().ok()?),
            port: u16::from_ne_bytes(b.get(4..6)?.try_into().ok()?),
            prefix_len: *b.get(6)?,
            proto: *b.get(7)?,
            active: *b.get(8)?,
            _pad: [0; 3],
        })
    }
}

/// Whether one [`PolicyRule`] admits the destination `(dst_addr, dst_port, proto)` (all host byte
/// order). A rule matches when it is `active`, its CIDR contains `dst_addr`, and its port and protocol
/// match (a `0` port or proto is a wildcard). Single-sourced: the tc program in `crates/probes` calls
/// this per rule, and [`egress_allowed`] loops it, so kernel and host can't disagree on the verdict.
///
/// The mask is built so the shift operand is always `< 32` (an out-of-range shift is UB in the kernel
/// and rejected by the verifier): `prefix_len == 0` yields an all-zero mask (match any), `32` an
/// all-ones mask, and an out-of-range `prefix_len` is treated as no match.
#[must_use]
pub fn rule_matches(rule: &PolicyRule, dst_addr: u32, dst_port: u16, proto: u8) -> bool {
    if rule.active == 0 || rule.prefix_len > 32 {
        return false;
    }
    let shift = 32u32 - u32::from(rule.prefix_len); // 0..=32, since prefix_len is 0..=32 here
    let mask = if shift >= 32 { 0 } else { u32::MAX << shift };
    (dst_addr & mask) == (rule.addr & mask)
        && (rule.port == 0 || rule.port == dst_port)
        && (rule.proto == 0 || rule.proto == proto)
}

/// Whether a sandbox's egress allow-list `rules` admits the destination `(dst_addr, dst_port, proto)`:
/// **any** active rule matching means allow, none matching means deny (deny-by-default). The
/// host-side convenience over [`rule_matches`]; the tc program applies the same any-match logic reading
/// its policy map. An empty allow-list allows nothing.
#[must_use]
pub fn egress_allowed(rules: &[PolicyRule], dst_addr: u32, dst_port: u16, proto: u8) -> bool {
    rules
        .iter()
        .any(|r| rule_matches(r, dst_addr, dst_port, proto))
}

// ---------------------------------------------------------------------------
// IPv6: the v6 twins of the flow key, parser, and egress policy above. Deliberately **parallel**
// types and maps rather than widening the v4 ones, so the proven v4 datapath stays byte-for-byte
// unchanged (ADR 008 dual-stack). Addresses are `[u8; 16]` in **network byte order** and all address
// math is **byte-wise**: the eBPF target has no native `u128` (`bpf-linker` would emit compiler-rt
// calls that don't exist there), so a shared `u128` matcher couldn't run in the kernel. The byte-wise
// form runs identically in the kernel and in these host tests, single-sourced so they can't drift.
// ---------------------------------------------------------------------------

/// One **directional** IPv6 network flow's identity: the v6 5-tuple, addresses in network byte order.
/// `#[repr(C)]` and padding-free (an explicit zeroed `_pad`), a stable 40-byte BPF **hash-map key**
/// exactly like [`FlowKey`]: an uninitialized pad byte would make two identical flows hash to
/// different slots. Build it with [`FlowKey6::new`], which zeroes the pad.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FlowKey6 {
    /// Source IPv6 address, network byte order (the 16 octets as they appear on the wire).
    pub src_addr: [u8; 16],
    /// Destination IPv6 address, network byte order.
    pub dst_addr: [u8; 16],
    /// Source L4 port (0 for a non-TCP/UDP next-header).
    pub src_port: u16,
    /// Destination L4 port (0 for a non-TCP/UDP next-header).
    pub dst_port: u16,
    /// The IPv6 **next-header** value at the fixed header (TCP/UDP, or an extension-header number when
    /// the chain isn't walked, in which case the ports are 0).
    pub proto: u8,
    /// Explicit zeroed padding to a stable, hashable 40-byte key (see the type doc).
    pub _pad: [u8; 3],
}

/// The on-wire size of a [`FlowKey6`] (the map key length the loader reads).
pub const FLOW_KEY6_SIZE: usize = core::mem::size_of::<FlowKey6>();

impl FlowKey6 {
    /// Build a v6 key from the 5-tuple, zeroing the padding so it hashes deterministically.
    #[must_use]
    pub fn new(
        src_addr: [u8; 16],
        dst_addr: [u8; 16],
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            proto,
            _pad: [0; 3],
        }
    }

    /// Reconstruct a key from a map key's raw bytes (as the loader reads them), or `None` if the slice
    /// is too short. Reads each field at its fixed `#[repr(C)]` offset, the v6 twin of
    /// [`FlowKey::from_bytes`], defined next to the fields so it can't drift from the kernel writer.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < FLOW_KEY6_SIZE {
            return None;
        }
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(b.get(0..16)?);
        dst.copy_from_slice(b.get(16..32)?);
        Some(Self::new(
            src,
            dst,
            u16::from_ne_bytes(b.get(32..34)?.try_into().ok()?),
            u16::from_ne_bytes(b.get(34..36)?.try_into().ok()?),
            *b.get(36)?,
        ))
    }
}

impl core::fmt::Display for FlowKey6 {
    /// `[src]:sport -> [dst]:dport <proto>`, addresses via [`core::net::Ipv6Addr`].
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let src = core::net::Ipv6Addr::from(self.src_addr);
        let dst = core::net::Ipv6Addr::from(self.dst_addr);
        write!(f, "[{src}]:{} -> [{dst}]:{} ", self.src_port, self.dst_port)?;
        match self.proto {
            IPPROTO_TCP => f.write_str("tcp"),
            IPPROTO_UDP => f.write_str("udp"),
            p => write!(f, "proto {p}"),
        }
    }
}

/// Parse the IPv6 5-tuple out of an Ethernet `frame` (addresses network order, ports host order), or
/// `None` if it is not IPv6-over-Ethernet or is truncated. TCP/UDP directly after the fixed 40-byte
/// header carry their ports; **extension headers are not walked** (a first cut), so a frame whose
/// next-header is an extension (or a fragment) reports ports 0 and `proto` = that next-header value,
/// still a recorded flow, never silently dropped, mirroring how the v4 parser leaves fragment ports 0.
/// The tc program in `crates/probes` mirrors this at the same offsets (single-sourced), this pure form
/// is what the host gate unit-tests.
#[must_use]
pub fn parse_ipv6_5tuple(frame: &[u8]) -> Option<FlowKey6> {
    let ethertype = u16::from_be_bytes([
        *frame.get(ETHERTYPE_OFFSET)?,
        *frame.get(ETHERTYPE_OFFSET + 1)?,
    ]);
    if ethertype != ETH_P_IPV6 {
        return None;
    }
    let ip = frame.get(ETH_HLEN..)?;
    // The fixed IPv6 header is 40 bytes: next-header at offset 6, src at 8..24, dst at 24..40.
    let next_header = *ip.get(6)?;
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(ip.get(8..24)?);
    dst.copy_from_slice(ip.get(24..40)?);
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if next_header == IPPROTO_TCP || next_header == IPPROTO_UDP {
        let l4 = ip.get(40..)?;
        src_port = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
        dst_port = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    }
    Some(FlowKey6::new(src, dst, src_port, dst_port, next_header))
}

/// One entry in a sandbox's **IPv6** egress allow-list: a destination v6 CIDR plus optional port and
/// protocol, the v6 twin of [`PolicyRule`]. `#[repr(C)]` and padding-free (explicit zeroed `_pad`), a
/// stable 24-byte map value. `addr` is network byte order and matched byte-wise to `prefix_len` (no
/// `u128`, see the module note above).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PolicyRule6 {
    /// Allowed destination network, network byte order (compared byte-wise, masked to `prefix_len`).
    pub addr: [u8; 16],
    /// Allowed destination port, or `0` for "any port".
    pub port: u16,
    /// Prefix length in bits, `0..=128`; `0` matches any address (a `::/0` allow-all).
    pub prefix_len: u8,
    /// IP protocol to match ([`IPPROTO_TCP`] / [`IPPROTO_UDP`]), or `0` for "any protocol".
    pub proto: u8,
    /// `1` if this slot holds a real rule, `0` if empty (an all-zero slot must not read as `::/0`).
    pub active: u8,
    /// Zeroed padding to a stable 24-byte record.
    pub _pad: [u8; 3],
}

/// The on-wire size of a [`PolicyRule6`] (the map value length the loader writes).
pub const POLICY_RULE6_SIZE: usize = core::mem::size_of::<PolicyRule6>();

impl PolicyRule6 {
    /// Build an **active** v6 allow-rule for `addr/prefix_len`, optional `port`/`proto` (`0` = any),
    /// zeroing the padding so it is a byte-stable map value.
    #[must_use]
    pub fn allow(addr: [u8; 16], prefix_len: u8, port: u16, proto: u8) -> Self {
        Self {
            addr,
            port,
            prefix_len,
            proto,
            active: 1,
            _pad: [0; 3],
        }
    }

    /// Serialize to the map value's raw native bytes (the write-side twin of [`FlowKey6::from_bytes`]),
    /// so the loader writes the policy without an `unsafe` `aya::Pod` binding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; POLICY_RULE6_SIZE] {
        let mut b = [0u8; POLICY_RULE6_SIZE];
        b[0..16].copy_from_slice(&self.addr);
        b[16..18].copy_from_slice(&self.port.to_ne_bytes());
        b[18] = self.prefix_len;
        b[19] = self.proto;
        b[20] = self.active;
        b
    }
}

/// Whether IPv6 address `addr` lies in `net/prefix_len`, compared **byte-wise** (no `u128`, so this
/// runs in the eBPF kernel too). Loops a **compile-time-bounded** 16 bytes for the verifier; a
/// `prefix_len > 128` is treated as no match by the caller.
#[must_use]
pub fn addr6_in_prefix(addr: [u8; 16], net: [u8; 16], prefix_len: u8) -> bool {
    let full = (prefix_len / 8) as usize; // whole bytes that must match exactly
    let rem = prefix_len % 8; // leftover high bits of the next byte
    let mut i = 0usize;
    while i < 16 {
        if i < full && addr[i] != net[i] {
            return false;
        }
        // The one partial byte: compare only its top `rem` bits.
        if i == full && rem != 0 {
            let mask = 0xffu8 << (8 - rem);
            if (addr[i] & mask) != (net[i] & mask) {
                return false;
            }
        }
        i += 1;
    }
    true
}

/// Whether one [`PolicyRule6`] admits `(dst_addr, dst_port, proto)` (address network order), the v6
/// twin of [`rule_matches`]: `active`, its CIDR contains the address (byte-wise), and its port/proto
/// match (a `0` port or proto is a wildcard). Single-sourced so the tc program and this agree.
#[must_use]
pub fn rule_matches6(rule: &PolicyRule6, dst_addr: [u8; 16], dst_port: u16, proto: u8) -> bool {
    if rule.active == 0 || rule.prefix_len > 128 {
        return false;
    }
    addr6_in_prefix(dst_addr, rule.addr, rule.prefix_len)
        && (rule.port == 0 || rule.port == dst_port)
        && (rule.proto == 0 || rule.proto == proto)
}

/// Whether a sandbox's IPv6 allow-list `rules` admits `(dst_addr, dst_port, proto)`: any active rule
/// matching means allow, none means deny (deny-by-default). The v6 twin of [`egress_allowed`].
#[must_use]
pub fn egress_allowed6(
    rules: &[PolicyRule6],
    dst_addr: [u8; 16],
    dst_port: u16,
    proto: u8,
) -> bool {
    rules
        .iter()
        .any(|r| rule_matches6(r, dst_addr, dst_port, proto))
}

#[cfg(test)]
mod flow_tests {
    use super::*;

    /// A minimal Ethernet+IPv4+L4 frame: 12 B of MACs, the EtherType, a 20-byte IPv4 header (ihl=5),
    /// then the 4 port bytes.
    fn frame(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HLEN];
        f[ETHERTYPE_OFFSET] = 0x08; // ETH_P_IP, big-endian
        f[ETHERTYPE_OFFSET + 1] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // version 4, ihl 5 (× 4 = 20 bytes, no options)
        ip[9] = proto;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f
    }

    #[test]
    fn flow_layout_is_padding_free_and_known_size() {
        assert_eq!(FLOW_KEY_SIZE, 16);
        assert_eq!(FLOW_COUNTS_SIZE, 32);
        assert_eq!(core::mem::align_of::<FlowCounts>(), 8);
        // `new` zeroes the pad, so two equal 5-tuples are byte-identical keys (hash to the same slot).
        let a = FlowKey::new(1, 2, 3, 4, IPPROTO_TCP);
        assert_eq!(a, FlowKey::new(1, 2, 3, 4, IPPROTO_TCP));
        assert_eq!(a._pad, [0, 0, 0]);
    }

    #[test]
    fn parses_a_tcp_5tuple() {
        let f = frame(IPPROTO_TCP, [10, 200, 0, 2], [93, 184, 216, 34], 51000, 443);
        let key = parse_ipv4_5tuple(&f).expect("a well-formed IPv4/TCP frame parses");
        assert_eq!(key.src_addr.to_be_bytes(), [10, 200, 0, 2]);
        assert_eq!(key.dst_addr.to_be_bytes(), [93, 184, 216, 34]);
        assert_eq!(key.src_port, 51000);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.proto, IPPROTO_TCP);
    }

    #[test]
    fn parses_udp_and_skips_non_ip_or_truncated() {
        let u = frame(IPPROTO_UDP, [10, 200, 0, 2], [1, 1, 1, 1], 5353, 53);
        assert_eq!(parse_ipv4_5tuple(&u).expect("udp parses").dst_port, 53);
        // A non-IPv4 EtherType (ARP, 0x0806) is skipped.
        let mut arp = u.clone();
        arp[ETHERTYPE_OFFSET + 1] = 0x06;
        assert!(parse_ipv4_5tuple(&arp).is_none());
        // Truncated below a full IPv4 header (and the empty slice) are skipped, never a panic.
        assert!(parse_ipv4_5tuple(&u[..ETH_HLEN + 10]).is_none());
        assert!(parse_ipv4_5tuple(&[]).is_none());
    }

    #[test]
    fn non_first_fragment_has_no_ports() {
        // A non-first IP fragment (fragment-offset != 0) carries no L4 header, so what sits at the
        // port offsets is payload; the parser must zero the ports, else a guest mints bogus 5-tuples.
        // The flags/fragment-offset field is IP-header bytes 6..8 (absolute `ETH_HLEN + 6`).
        let mut frag = frame(IPPROTO_TCP, [10, 200, 0, 2], [9, 9, 9, 9], 51000, 443);
        frag[ETH_HLEN + 6] = 0x00;
        frag[ETH_HLEN + 7] = 0xb9; // fragment offset 185 (nonzero)
        let key = parse_ipv4_5tuple(&frag).expect("a fragment still parses its addresses");
        assert_eq!(key.dst_addr.to_be_bytes(), [9, 9, 9, 9]);
        assert_eq!(key.proto, IPPROTO_TCP);
        assert_eq!(key.src_port, 0, "non-first fragment ports must be zero");
        assert_eq!(key.dst_port, 0, "non-first fragment ports must be zero");
        // A *first* fragment (offset 0, More-Fragments bit set) still has its L4 header, keep ports.
        let mut first = frame(IPPROTO_TCP, [10, 200, 0, 2], [9, 9, 9, 9], 51000, 443);
        first[ETH_HLEN + 6] = 0x20; // MF flag, offset 0
        first[ETH_HLEN + 7] = 0x00;
        assert_eq!(
            parse_ipv4_5tuple(&first)
                .expect("first fragment parses")
                .dst_port,
            443
        );
    }

    #[test]
    fn key_bytes_round_trip_and_display() {
        let key = FlowKey::new(
            u32::from_be_bytes([10, 200, 0, 2]),
            u32::from_be_bytes([8, 8, 8, 8]),
            1234,
            53,
            IPPROTO_UDP,
        );
        // The loader reads a map key as raw native bytes; `from_bytes` must reconstruct it.
        let mut bytes = [0u8; FLOW_KEY_SIZE];
        bytes[0..4].copy_from_slice(&key.src_addr.to_ne_bytes());
        bytes[4..8].copy_from_slice(&key.dst_addr.to_ne_bytes());
        bytes[8..10].copy_from_slice(&key.src_port.to_ne_bytes());
        bytes[10..12].copy_from_slice(&key.dst_port.to_ne_bytes());
        bytes[12] = key.proto;
        assert_eq!(FlowKey::from_bytes(&bytes), Some(key));
        assert_eq!(key.to_string(), "10.200.0.2:1234 -> 8.8.8.8:53 udp");
    }

    #[test]
    fn counts_bytes_round_trip() {
        let c = FlowCounts {
            ingress_packets: 3,
            ingress_bytes: 180,
            egress_packets: 2,
            egress_bytes: 120,
        };
        let mut b = [0u8; FLOW_COUNTS_SIZE];
        b[0..8].copy_from_slice(&c.ingress_packets.to_ne_bytes());
        b[8..16].copy_from_slice(&c.ingress_bytes.to_ne_bytes());
        b[16..24].copy_from_slice(&c.egress_packets.to_ne_bytes());
        b[24..32].copy_from_slice(&c.egress_bytes.to_ne_bytes());
        assert_eq!(FlowCounts::from_bytes(&b), Some(c));
        assert!(FlowCounts::from_bytes(&b[..31]).is_none());
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    /// A dotted-quad as the host-order `u32` the parser and policy use.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    #[test]
    fn rule_layout_is_padding_free_and_known_size() {
        assert_eq!(POLICY_RULE_SIZE, 12);
        // An empty (all-zero) slot must NOT admit anything: `active == 0` short-circuits, so a fixed
        // array of zeroed rules is deny-all, never an accidental `0.0.0.0/0` allow-all.
        let empty = PolicyRule::default();
        assert_eq!(empty.active, 0);
        assert!(!rule_matches(&empty, ip(8, 8, 8, 8), 53, IPPROTO_UDP));
    }

    #[test]
    fn host_only_prefix_matches_exactly_one_address() {
        // Allow only 10.200.0.1:9999/udp (the netns host end), /32.
        let rule = PolicyRule::allow(ip(10, 200, 0, 1), 32, 9999, IPPROTO_UDP);
        assert!(rule_matches(&rule, ip(10, 200, 0, 1), 9999, IPPROTO_UDP));
        assert!(!rule_matches(&rule, ip(10, 200, 0, 2), 9999, IPPROTO_UDP)); // other host
        assert!(!rule_matches(&rule, ip(10, 200, 0, 1), 9998, IPPROTO_UDP)); // other port
        assert!(!rule_matches(&rule, ip(10, 200, 0, 1), 9999, IPPROTO_TCP)); // other proto
    }

    #[test]
    fn cidr_and_wildcards_match_ranges() {
        // A /24 with wildcard port and proto (0 = any) admits the whole subnet on any port/proto.
        let subnet = PolicyRule::allow(ip(93, 184, 216, 0), 24, 0, 0);
        assert!(rule_matches(
            &subnet,
            ip(93, 184, 216, 34),
            443,
            IPPROTO_TCP
        ));
        assert!(rule_matches(&subnet, ip(93, 184, 216, 1), 80, IPPROTO_TCP));
        assert!(!rule_matches(
            &subnet,
            ip(93, 184, 217, 1),
            443,
            IPPROTO_TCP
        )); // outside /24
            // prefix_len 0 is an explicit allow-all address (still gated by port/proto if set).
        let any = PolicyRule::allow(0, 0, 443, IPPROTO_TCP);
        assert!(rule_matches(&any, ip(1, 2, 3, 4), 443, IPPROTO_TCP));
        assert!(!rule_matches(&any, ip(1, 2, 3, 4), 80, IPPROTO_TCP));
    }

    #[test]
    fn out_of_range_prefix_never_matches() {
        // A malformed rule (prefix_len > 32, e.g. a garbled map write) is treated as no match, never a
        // shift-overflow or an accidental allow.
        let bad = PolicyRule {
            prefix_len: 40,
            ..PolicyRule::allow(ip(10, 0, 0, 0), 8, 0, 0)
        };
        assert!(!rule_matches(&bad, ip(10, 0, 0, 1), 443, IPPROTO_TCP));
    }

    #[test]
    fn egress_allowed_is_any_match_and_deny_by_default() {
        let rules = [
            PolicyRule::allow(ip(10, 200, 0, 1), 32, 9999, IPPROTO_UDP),
            PolicyRule::allow(ip(93, 184, 216, 0), 24, 443, IPPROTO_TCP),
        ];
        assert!(egress_allowed(&rules, ip(10, 200, 0, 1), 9999, IPPROTO_UDP));
        assert!(egress_allowed(
            &rules,
            ip(93, 184, 216, 34),
            443,
            IPPROTO_TCP
        ));
        assert!(!egress_allowed(&rules, ip(8, 8, 8, 8), 53, IPPROTO_UDP)); // matches nothing
        assert!(!egress_allowed(&[], ip(10, 200, 0, 1), 9999, IPPROTO_UDP)); // empty = deny-all
    }

    #[test]
    fn rule_bytes_round_trip() {
        let rule = PolicyRule::allow(ip(93, 184, 216, 0), 24, 443, IPPROTO_TCP);
        assert_eq!(PolicyRule::from_bytes(&rule.to_bytes()), Some(rule));
        assert!(PolicyRule::from_bytes(&rule.to_bytes()[..POLICY_RULE_SIZE - 1]).is_none());
    }
}

#[cfg(test)]
mod v6_tests {
    use super::*;

    /// A minimal Ethernet+IPv6+L4 frame: 12 B of MACs, the IPv6 EtherType, a 40-byte fixed IPv6 header
    /// (`next_header` at offset 6, src at 8..24, dst at 24..40), then the 4 port bytes.
    fn frame6(next: u8, src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HLEN];
        f[ETHERTYPE_OFFSET] = 0x86; // ETH_P_IPV6, big-endian
        f[ETHERTYPE_OFFSET + 1] = 0xdd;
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60; // version 6
        ip[6] = next;
        ip[8..24].copy_from_slice(&src);
        ip[24..40].copy_from_slice(&dst);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f
    }

    /// `fd00:200::N` as its 16 network-order octets (the sandbox's ULA link): first hextet `fd00`
    /// (bytes 0,1), second hextet `0200` (bytes 2,3), host byte last.
    fn ula(n: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0xfd;
        a[2] = 0x02; // second hextet 0x0200
        a[15] = n;
        a
    }

    #[test]
    fn v6_layout_is_padding_free_and_known_size() {
        assert_eq!(FLOW_KEY6_SIZE, 40);
        assert_eq!(POLICY_RULE6_SIZE, 24);
        let a = FlowKey6::new(ula(2), ula(1), 3, 4, IPPROTO_TCP);
        assert_eq!(a, FlowKey6::new(ula(2), ula(1), 3, 4, IPPROTO_TCP));
        assert_eq!(a._pad, [0, 0, 0]);
        assert_eq!(PolicyRule6::default().active, 0);
    }

    #[test]
    fn parses_a_v6_tcp_5tuple() {
        let f = frame6(IPPROTO_TCP, ula(2), ula(1), 51000, 443);
        let key = parse_ipv6_5tuple(&f).expect("a well-formed IPv6/TCP frame parses");
        assert_eq!(key.src_addr, ula(2));
        assert_eq!(key.dst_addr, ula(1));
        assert_eq!(key.src_port, 51000);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.proto, IPPROTO_TCP);
    }

    #[test]
    fn skips_non_v6_truncated_and_leaves_ext_header_ports_zero() {
        // An IPv4 EtherType is not our v6 frame.
        let mut v4 = frame6(IPPROTO_UDP, ula(2), ula(1), 53, 53);
        v4[ETHERTYPE_OFFSET] = 0x08;
        v4[ETHERTYPE_OFFSET + 1] = 0x00;
        assert!(parse_ipv6_5tuple(&v4).is_none());
        // Truncated below a full 40-byte header (and the empty slice) are skipped, never a panic.
        let ok = frame6(IPPROTO_UDP, ula(2), ula(1), 53, 53);
        assert!(parse_ipv6_5tuple(&ok[..ETH_HLEN + 30]).is_none());
        assert!(parse_ipv6_5tuple(&[]).is_none());
        // A next-header that is an extension header (0 = hop-by-hop) is not walked: addresses parse,
        // proto is the next-header value, and ports stay 0 (honest, never a bogus port from options).
        let hbh = frame6(0, ula(2), ula(1), 51000, 443);
        let key = parse_ipv6_5tuple(&hbh).expect("addresses still parse");
        assert_eq!(key.proto, 0);
        assert_eq!(key.src_port, 0);
        assert_eq!(key.dst_port, 0);
    }

    #[test]
    fn addr6_prefix_covers_full_partial_and_wildcard() {
        let host = ula(1);
        // /128 matches exactly one address.
        assert!(addr6_in_prefix(host, ula(1), 128));
        assert!(!addr6_in_prefix(host, ula(2), 128));
        // /0 matches anything.
        assert!(addr6_in_prefix(host, [0u8; 16], 0));
        // /64 matches the whole link (host bits differ, network bits equal).
        assert!(addr6_in_prefix(ula(2), ula(1), 64));
        // A partial byte: /125 keeps the low 3 bits free, so ::1..=::7 match ::0/125 but ::8 does not.
        let net = ula(0);
        assert!(addr6_in_prefix(ula(7), net, 125));
        assert!(!addr6_in_prefix(ula(8), net, 125));
        // A different high byte fails even a short prefix.
        let mut other = ula(1);
        other[0] = 0xfe;
        assert!(!addr6_in_prefix(other, ula(1), 16));
    }

    #[test]
    fn rule_matches6_and_deny_by_default() {
        // Allow only the host end on udp/9999, /128.
        let rule = PolicyRule6::allow(ula(1), 128, 9999, IPPROTO_UDP);
        assert!(rule_matches6(&rule, ula(1), 9999, IPPROTO_UDP));
        assert!(!rule_matches6(&rule, ula(2), 9999, IPPROTO_UDP)); // other host
        assert!(!rule_matches6(&rule, ula(1), 9998, IPPROTO_UDP)); // other port
        assert!(!rule_matches6(&rule, ula(1), 9999, IPPROTO_TCP)); // other proto
                                                                   // An out-of-range prefix (a garbled write) never matches, no panic.
        let bad = PolicyRule6 {
            prefix_len: 200,
            ..PolicyRule6::allow(ula(0), 64, 0, 0)
        };
        assert!(!rule_matches6(&bad, ula(1), 443, IPPROTO_TCP));
        // any-match + deny-by-default over a list, and an empty list denies all.
        let rules = [PolicyRule6::allow(ula(0), 64, 0, 0)];
        assert!(egress_allowed6(&rules, ula(9), 80, IPPROTO_TCP));
        assert!(!egress_allowed6(&[], ula(1), 9999, IPPROTO_UDP));
    }

    #[test]
    fn v6_bytes_round_trip_and_display() {
        let key = FlowKey6::new(ula(2), ula(1), 1234, 53, IPPROTO_UDP);
        // The loader reads a v6 map key as raw native bytes; `from_bytes` must reconstruct it.
        let mut bytes = [0u8; FLOW_KEY6_SIZE];
        bytes[0..16].copy_from_slice(&key.src_addr);
        bytes[16..32].copy_from_slice(&key.dst_addr);
        bytes[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
        bytes[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
        bytes[36] = key.proto;
        assert_eq!(FlowKey6::from_bytes(&bytes), Some(key));
        assert!(FlowKey6::from_bytes(&bytes[..FLOW_KEY6_SIZE - 1]).is_none());
        assert_eq!(
            key.to_string(),
            "[fd00:200::2]:1234 -> [fd00:200::1]:53 udp"
        );
        // The policy value round-trips through its native bytes too.
        let rule = PolicyRule6::allow(ula(0), 64, 443, IPPROTO_TCP);
        assert_eq!(&rule.to_bytes()[0..16], &ula(0));
        assert_eq!(rule.to_bytes()[18], 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_padding_free_and_known_size() {
        // Catch a field resize here; the per-field offsets below catch a same-size reorder.
        assert_eq!(EVENT_SIZE, 168);
        assert_eq!(core::mem::align_of::<SyscallEvent>(), 8);
    }

    #[test]
    fn layout_offsets_are_the_wire_contract() {
        // The eBPF object is built separately from the loader (its own toolchain, its own time), so
        // the struct layout *is* the wire format between two independently-built artifacts. Pin every
        // field offset: `from_bytes` derives its reads from `offset_of!` (it cannot drift from this
        // struct), but an accidental layout change would silently change the wire, and a stale probe
        // object on disk would then read as garbage. This test makes that change loud instead.
        assert_eq!(core::mem::offset_of!(SyscallEvent, cgroup_id), 0);
        assert_eq!(core::mem::offset_of!(SyscallEvent, pid), 8);
        assert_eq!(core::mem::offset_of!(SyscallEvent, tid), 12);
        assert_eq!(core::mem::offset_of!(SyscallEvent, syscall), 16);
        assert_eq!(core::mem::offset_of!(SyscallEvent, detail_len), 20);
        assert_eq!(core::mem::offset_of!(SyscallEvent, comm), 24);
        assert_eq!(core::mem::offset_of!(SyscallEvent, detail), 40);
    }

    #[test]
    fn from_bytes_round_trips_a_written_event() {
        let mut detail = [0u8; DETAIL_CAP];
        detail[..5].copy_from_slice(b"/etc\0");
        let mut comm = [0u8; COMM_CAP];
        comm[..2].copy_from_slice(b"sh");
        let ev = SyscallEvent {
            cgroup_id: 0xdead_beef_0000_0042,
            pid: 4321,
            tid: 4325,
            syscall: Syscall::Openat as u32,
            detail_len: 4,
            comm,
            detail,
        };
        // Mirror the kernel writer: the ring-buffer record is the struct's raw native bytes.
        let bytes = event_to_ne_bytes(&ev);
        let back = SyscallEvent::from_bytes(&bytes).expect("parse a full-size record");
        assert_eq!(back.cgroup_id, ev.cgroup_id);
        assert_eq!(back.pid, ev.pid);
        assert_eq!(back.tid, ev.tid);
        assert_eq!(back.kind(), Some(Syscall::Openat));
        assert_eq!(back.detail(), b"/etc");
        assert_eq!(back.comm_lossy(), "sh");
    }

    #[test]
    fn short_slice_is_none_not_a_panic() {
        assert!(SyscallEvent::from_bytes(&[0u8; EVENT_SIZE - 1]).is_none());
        assert!(SyscallEvent::from_bytes(&[]).is_none());
    }

    #[test]
    fn decodes_a_trace_line_for_each_syscall() {
        let ev = |syscall: Syscall, detail: &[u8]| {
            let mut d = [0u8; DETAIL_CAP];
            d[..detail.len()].copy_from_slice(detail);
            let mut comm = [0u8; COMM_CAP];
            comm[..2].copy_from_slice(b"sh");
            SyscallEvent {
                cgroup_id: 0,
                pid: 7,
                tid: 7,
                syscall: syscall as u32,
                detail_len: detail.len() as u32,
                comm,
                detail: d,
            }
        };
        assert_eq!(
            ev(Syscall::Openat, b"/etc/hostname").detail_display(),
            "/etc/hostname"
        );
        // A 127.0.0.1:9 sockaddr_in: AF_INET (native u16 = 2), be16 port 9, then 127.0.0.1.
        let mut sa = vec![2u8, 0, 0, 9, 127, 0, 0, 1];
        sa.resize(16, 0);
        assert_eq!(ev(Syscall::Connect, &sa).detail_display(), "127.0.0.1:9");
        // An [fd00:200::1]:443 sockaddr_in6: AF_INET6 (native u16 = 10), be16 port 443, 4 B flowinfo,
        // then the 16-byte address (a full v6 capture, SOCKADDR_SNAP = 28).
        let mut sa6 = vec![10u8, 0, 0x01, 0xbb, 0, 0, 0, 0];
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[2] = 0x02;
        addr[15] = 0x01;
        sa6.extend_from_slice(&addr);
        assert_eq!(
            ev(Syscall::Connect, &sa6).detail_display(),
            "[fd00:200::1]:443"
        );
        assert_eq!(
            ev(Syscall::Execve, b"/bin/true").describe(),
            "pid=7 comm=sh execve /bin/true"
        );
        assert_eq!(ev(Syscall::Connect, &sa).syscall_name(), "connect");
    }

    #[test]
    fn unknown_discriminant_decodes_to_none() {
        let bytes = {
            let mut b = [0u8; EVENT_SIZE];
            b[16..20].copy_from_slice(&99u32.to_ne_bytes());
            b
        };
        let ev = SyscallEvent::from_bytes(&bytes).expect("parse");
        assert_eq!(ev.kind(), None);
    }

    #[test]
    fn detail_len_is_clamped_to_the_buffer() {
        let mut b = [0u8; EVENT_SIZE];
        b[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // absurd length
        let ev = SyscallEvent::from_bytes(&b).expect("parse");
        assert_eq!(ev.detail().len(), DETAIL_CAP); // clamped, not out-of-bounds
    }

    /// Serialize an event the way the kernel ring-buffer writer does: its raw `#[repr(C)]` native
    /// bytes. Kept in the test module (the kernel side writes the struct directly via aya).
    fn event_to_ne_bytes(ev: &SyscallEvent) -> [u8; EVENT_SIZE] {
        let mut b = [0u8; EVENT_SIZE];
        b[0..8].copy_from_slice(&ev.cgroup_id.to_ne_bytes());
        b[8..12].copy_from_slice(&ev.pid.to_ne_bytes());
        b[12..16].copy_from_slice(&ev.tid.to_ne_bytes());
        b[16..20].copy_from_slice(&ev.syscall.to_ne_bytes());
        b[20..24].copy_from_slice(&ev.detail_len.to_ne_bytes());
        b[24..40].copy_from_slice(&ev.comm);
        b[40..168].copy_from_slice(&ev.detail);
        b
    }
}
