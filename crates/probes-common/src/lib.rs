//! Plain-old-data shared across the eBPF boundary: the records `crates/probes` writes into its maps
//! and `crates/probes-loader` reads back. Each record is defined **once**, because a field
//! reordered or resized on one side only would be a silent garbage read.
//!
//! - **Layout:** every shared type is `#[repr(C)]` and padding-free, with explicit zeroed `_pad`
//!   where a type is a BPF hash-map key (an uninitialized pad byte would split identical keys).
//! - **Decoding:** both sides run on the same host, so each `from_bytes` reads field by field with
//!   `from_ne_bytes`, no `unsafe`.
//! - **Offsets come from the struct** (`core::mem::offset_of!`), never written out: one end reads
//!   each record as a struct, the other as bytes, so a hand-written position that stopped matching
//!   its field would reinterpret the record with nothing erroring. The
//!   `*_offsets_are_the_wire_contract` tests pin the layout itself against the separately-built,
//!   possibly stale eBPF object on disk.
//! - **Address math is byte-wise:** the eBPF target has no native `u128`, so the v6 matchers loop
//!   bytes and run identically in the kernel and in these host tests.
//! - **`#![no_std]`, zero dependencies**, so it compiles for the BPF target unchanged; the `std`
//!   feature opts back into the display helpers.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

/// The fixed capture width of a process's `comm` (the kernel's own 16-byte `TASK_COMM_LEN`).
pub const COMM_CAP: usize = 16;

/// The fixed capture width of the per-event detail blob: an `openat`/`execve` path, or the leading
/// bytes of a `connect` sockaddr. Bounded because an eBPF program writes into a fixed stack buffer and
/// the record is a fixed-size ring-buffer entry; a longer path is truncated to this many bytes.
pub const DETAIL_CAP: usize = 128;

/// The **maximum** leading bytes of a `connect` sockaddr the probe copies into
/// [`SyscallEvent::detail`]: `sizeof(struct sockaddr_in6)`, so a full IPv6 address is captured. The
/// probe picks between this and [`SOCKADDR_SNAP_V4`] by the caller's own `addrlen`, so a 16-byte
/// `sockaddr_in` is not over-read.
pub const SOCKADDR_SNAP: usize = 28;

/// The IPv4 `sockaddr_in` size, the copy length the probe uses for any `addrlen` below
/// [`SOCKADDR_SNAP`]. For a shorter family (`sockaddr_nl` is 12), `detail_len` reports the caller's
/// `addrlen` instead, so the record shows the family rather than claiming bytes that were never the
/// address.
pub const SOCKADDR_SNAP_V4: usize = 16;

/// Which syscall a [`SyscallEvent`] records. The wire field is a raw [`u32`], not this enum, so
/// decoding arbitrary bytes can never form an invalid discriminant; `Ord` compares the explicit
/// discriminants, so the audit record's `notable` ordering is tied to the wire numbering
/// (`notable_kinds_are_ordered_by_the_syscall_discriminants` in `bsx-record` holds it).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Syscall {
    /// `execve` (`sys_enter_execve`): detail holds the program path.
    Execve = 0,
    /// `openat` (`sys_enter_openat`): detail holds the opened path.
    Openat = 1,
    /// `connect` (`sys_enter_connect`): detail holds the leading [`SOCKADDR_SNAP`] sockaddr bytes.
    Connect = 2,
}

impl Syscall {
    /// The short name every rendering surface uses, one table so they cannot disagree.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Syscall::Execve => "execve",
            Syscall::Openat => "openat",
            Syscall::Connect => "connect",
        }
    }
}

/// One host syscall observed by the probes, as written into the ring buffer. Fields run
/// large-to-small so the `#[repr(C)]` layout is padding-free. This is the **host's** footprint: a
/// microVM services its own syscalls in-guest and they never trap here.
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
    /// Reconstructs an event from a ring-buffer record's raw bytes, or `None` if the slice is too
    /// short. Offsets come from the struct (see the crate docs); a resize is caught by the
    /// [`EVENT_SIZE`] check.
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

    /// Whether this event's **path** ran past [`DETAIL_CAP`] and was cut, so a consumer never shows
    /// a prefix as though it were the whole path. A full buffer is the signal
    /// (`bpf_probe_read_user_str` NUL-terminates within it), so a path of exactly `DETAIL_CAP - 1`
    /// bytes also reports truncated: over-stating doubt about an audit record is safe. Path-like
    /// syscalls only, since a sockaddr snapshot can never reach the cap.
    #[must_use]
    pub fn detail_truncated(&self) -> bool {
        matches!(self.kind(), Some(Syscall::Execve | Syscall::Openat))
            && (self.detail_len as usize) >= DETAIL_CAP - 1
    }

    /// The `comm` as a `&str` up to its first NUL, lossily (non-UTF-8 bytes become replacement
    /// characters); `std`-only, since it allocates on the lossy path.
    #[cfg(any(feature = "std", test))]
    #[must_use]
    pub fn comm_lossy(&self) -> std::borrow::Cow<'_, str> {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(COMM_CAP);
        String::from_utf8_lossy(&self.comm[..end])
    }

    /// The short syscall name, or `?` for an unknown discriminant.
    #[must_use]
    pub fn syscall_name(&self) -> &'static str {
        self.kind().map_or("?", Syscall::name)
    }

    /// The event's detail blob decoded for display, one decoder for every consumer: the path
    /// (lossy UTF-8) or the `connect` address. Borrowed for a valid-UTF-8 path, so a per-event
    /// fold can probe its dedup map without an allocation per repeat.
    #[cfg(any(feature = "std", test))]
    #[must_use]
    pub fn detail_display_cow(&self) -> std::borrow::Cow<'_, str> {
        let d = self.detail();
        match self.kind() {
            Some(Syscall::Connect) => std::borrow::Cow::Owned(describe_sockaddr(d)),
            _ => String::from_utf8_lossy(d),
        }
    }

    /// [`detail_display_cow`](Self::detail_display_cow), owned.
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
// Syscall tracepoint arguments: where in the kernel's tracepoint record each
// argument the tracers read sits.
// ---------------------------------------------------------------------------

/// One `sys_enter_*` argument a tracer reads: a byte offset into the tracepoint record plus the
/// name the kernel's own `format` file gives it, shared by the kernel program and the loader's
/// pre-attach `format` check so neither side can name a position the other does not check.
///
/// The offset is an **ABI assumption, not a relocation**: BTF does not relocate argument-area
/// reads, so a kernel that laid the record out differently would hand the probe an unrelated `u64`
/// to follow as a user pointer, with nothing erroring. The `format` check makes that a typed
/// refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TracepointArg {
    /// The event under the `syscalls` category whose record this offset is into.
    pub event: &'static str,
    /// The field name as `events/syscalls/<event>/format` spells it.
    pub field: &'static str,
    /// Byte offset from the start of the tracepoint record.
    pub offset: usize,
}

/// The width of one syscall-argument slot in a `sys_enter_*` record, which is what
/// `read_at::<u64>` assumes. Every argument occupies a full slot whatever its C type, so the loader
/// checks the declared size against this as well as the offset.
pub const ARG_SLOT: usize = 8;

/// Slot of the target **tgid** in the `FILTER` array, and slot of the target **cgroup id**. A zero
/// slot means "do not filter on this axis"; the map is zero-initialized, so the load-time default is
/// observe-all.
///
/// Single-sourced because the kernel program reads these positions and the loader writes them: if
/// the two disagreed, `watch_cgroup` would put a cgroup inode in the tgid slot, `passes_filter`
/// would compare it against a tgid and never match, and the run would report an empty footprint
/// with no error and no drop counted.
pub const FILTER_TGID: u32 = 0;
/// See [`FILTER_TGID`].
pub const FILTER_CGROUP: u32 = 1;

/// Slot of the filter-mode toggle in the `TRACE_SET` array: `0` (the load-time default) selects the
/// single-target `FILTER`, `1` selects the `TRACE_TARGETS` set. Single-sourced for the same reason
/// as [`FILTER_TGID`]: a loader writing a slot the program does not read leaves the program on its
/// all-zero `FILTER`, which observes every process on the host.
pub const FILTER_MODE_SLOT: u32 = 0;

/// `execve`'s `const char *filename` (argument 0), past the 8-byte common header and the
/// `__syscall_nr` slot.
pub const EXECVE_FILENAME_ARG: TracepointArg = TracepointArg {
    event: "sys_enter_execve",
    field: "filename",
    offset: 16,
};

/// `openat`'s `const char *filename` (argument 1), one slot past the `int dfd`.
pub const OPENAT_FILENAME_ARG: TracepointArg = TracepointArg {
    event: "sys_enter_openat",
    field: "filename",
    offset: 24,
};

/// `connect`'s `struct sockaddr *uservaddr` (argument 1), one slot past the `int fd`.
pub const CONNECT_USERVADDR_ARG: TracepointArg = TracepointArg {
    event: "sys_enter_connect",
    field: "uservaddr",
    offset: 24,
};

/// `connect`'s `int addrlen` (argument 2), which bounds the sockaddr copy.
pub const CONNECT_ADDRLEN_ARG: TracepointArg = TracepointArg {
    event: "sys_enter_connect",
    field: "addrlen",
    offset: 32,
};

/// Every offset the syscall tracers read, which is the list the loader's pre-attach check walks. A
/// [`TracepointArg`] declared above but missing here is verified nowhere, so
/// `every_tracepoint_arg_is_checked_before_the_attach` in `xtask` holds the two together.
pub const TRACEPOINT_ARGS: [TracepointArg; 4] = [
    EXECVE_FILENAME_ARG,
    OPENAT_FILENAME_ARG,
    CONNECT_USERVADDR_ARG,
    CONNECT_ADDRLEN_ARG,
];

// ---------------------------------------------------------------------------
// Network flows: the per-flow record the tc program on a VM's tap writes.
// ---------------------------------------------------------------------------

/// Ethernet header length, the offset the IP header starts at. Shared by the tc program (which reads
/// with `ctx.load` at absolute offsets) and the host-side parsers (which read through a slice), so
/// the two can't disagree on where a field lives.
pub const ETH_HLEN: usize = 14;
/// Byte offset of the EtherType in an Ethernet frame.
pub const ETHERTYPE_OFFSET: usize = 12;

/// Offset of the flags/fragment-offset field within the IPv4 header (which starts at [`ETH_HLEN`]).
/// Named here for the same single-sourcing reason as [`ETH_HLEN`].
pub const IPV4_FRAG_OFFSET: usize = 6;
/// Offset of the protocol byte in an IPv4 header. See [`IPV4_FRAG_OFFSET`].
pub const IPV4_PROTO_OFFSET: usize = 9;
/// Offset of the source address in an IPv4 header. See [`IPV4_FRAG_OFFSET`].
pub const IPV4_SRC_OFFSET: usize = 12;
/// Offset of the destination address in an IPv4 header. See [`IPV4_FRAG_OFFSET`].
pub const IPV4_DST_OFFSET: usize = 16;
/// Smallest valid IPv4 header (no options). A shorter `ihl` is a malformed packet, and both
/// parsers refuse it rather than reading an L4 header that would fall inside the IP header.
pub const IPV4_MIN_IHL: usize = 20;

/// Offset of the next-header byte within the fixed IPv6 header. IPv6 has no `ihl`: the header is
/// always [`IPV6_HLEN`] bytes and extension headers chain after it (neither parser walks them).
pub const IPV6_NEXT_HEADER_OFFSET: usize = 6;
/// Offset of the source address in an IPv6 header. See [`IPV6_NEXT_HEADER_OFFSET`].
pub const IPV6_SRC_OFFSET: usize = 8;
/// Offset of the destination address in an IPv6 header. See [`IPV6_NEXT_HEADER_OFFSET`].
pub const IPV6_DST_OFFSET: usize = 24;
/// The fixed IPv6 header length, so the L4 header starts at `ETH_HLEN + IPV6_HLEN`.
pub const IPV6_HLEN: usize = 40;
/// EtherType for IPv4.
pub const ETH_P_IP: u16 = 0x0800;
/// EtherType for ARP. Egress enforcement lets ARP through even under deny-by-default: the guest must
/// resolve its on-link gateway before it can reach *any* allowed endpoint.
pub const ETH_P_ARP: u16 = 0x0806;
/// EtherType for IPv6, parsed into its own flow key by [`parse_ipv6_5tuple`]. A *truncated* v6 frame
/// is counted as unparsed rather than dropped from the record silently.
pub const ETH_P_IPV6: u16 = 0x86dd;
/// EtherType for an 802.1Q VLAN tag, which neither parser handles, so such a frame is
/// unrepresentable as a flow and counted as unparsed. Not expected on a sandbox's tap, unlike ARP,
/// which is why ARP is not counted.
pub const ETH_P_8021Q: u16 = 0x8100;
/// An L4 protocol a rule or flow is matched on, the typed face of the raw IP protocol number, so a
/// caller writes `Protocol::Udp` and never `17`. Only the two protocols the parser reads ports
/// for; "any protocol" is [`None`], not a variant. The discriminant *is* the on-wire number.
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

/// An IP protocol number rendered for a human: `tcp`, `udp`, or `proto <n>` for one this engine does
/// not name. The one rendering, so the flow keys, the signed record and the CLI's trail cannot
/// disagree about what a protocol is called; `core::fmt` only, so the `#![no_std]` half can use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtoName(pub u8);

impl core::fmt::Display for ProtoName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            IPPROTO_TCP => f.write_str("tcp"),
            IPPROTO_UDP => f.write_str("udp"),
            p => write!(f, "proto {p}"),
        }
    }
}

/// IP protocol number for **ICMPv6**. Unlike ARP (its own v4 ethertype, cleanly separable from
/// routable IP), ICMPv6 rides the IPv6 ethertype and can carry a routable Echo, so egress enforcement
/// spares it only to **on-link** destinations ([`icmp6_dst_on_link`]) and polices the rest like any
/// other v6 flow.
pub const IPPROTO_ICMPV6: u8 = 58;

/// One **directional** network flow's identity: the IPv4 5-tuple, in host byte order so a consumer
/// formats `src_addr` straight to dotted-quad. A 16-byte BPF hash-map key; build it with
/// [`FlowKey::new`], which zeroes the pad.
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
    /// Builds a key from the 5-tuple, zeroing the padding so it hashes deterministically.
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

    /// Reconstructs a key from a map key's raw bytes, or `None` if the slice is too short; offsets
    /// come from the struct (see the crate docs).
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < FLOW_KEY_SIZE {
            return None;
        }
        const SRC_ADDR: usize = core::mem::offset_of!(FlowKey, src_addr);
        const DST_ADDR: usize = core::mem::offset_of!(FlowKey, dst_addr);
        const SRC_PORT: usize = core::mem::offset_of!(FlowKey, src_port);
        const DST_PORT: usize = core::mem::offset_of!(FlowKey, dst_port);
        const PROTO: usize = core::mem::offset_of!(FlowKey, proto);
        Some(Self::new(
            u32::from_ne_bytes(b.get(SRC_ADDR..SRC_ADDR + 4)?.try_into().ok()?),
            u32::from_ne_bytes(b.get(DST_ADDR..DST_ADDR + 4)?.try_into().ok()?),
            u16::from_ne_bytes(b.get(SRC_PORT..SRC_PORT + 2)?.try_into().ok()?),
            u16::from_ne_bytes(b.get(DST_PORT..DST_PORT + 2)?.try_into().ok()?),
            *b.get(PROTO)?,
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
        write!(f, "{}", ProtoName(self.proto))
    }
}

/// Per-direction packet/byte counters for one [`FlowKey`], from the tap's perspective: **ingress** is a
/// frame the guest sent, **egress** one delivered to the guest.
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
    /// Reconstructs counters from a map value's raw bytes, or `None` if the slice is too short;
    /// offsets come from the struct the kernel writes through.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < FLOW_COUNTS_SIZE {
            return None;
        }
        const IN_PACKETS: usize = core::mem::offset_of!(FlowCounts, ingress_packets);
        const IN_BYTES: usize = core::mem::offset_of!(FlowCounts, ingress_bytes);
        const OUT_PACKETS: usize = core::mem::offset_of!(FlowCounts, egress_packets);
        const OUT_BYTES: usize = core::mem::offset_of!(FlowCounts, egress_bytes);
        Some(Self {
            ingress_packets: u64::from_ne_bytes(
                b.get(IN_PACKETS..IN_PACKETS + 8)?.try_into().ok()?,
            ),
            ingress_bytes: u64::from_ne_bytes(b.get(IN_BYTES..IN_BYTES + 8)?.try_into().ok()?),
            egress_packets: u64::from_ne_bytes(
                b.get(OUT_PACKETS..OUT_PACKETS + 8)?.try_into().ok()?,
            ),
            egress_bytes: u64::from_ne_bytes(b.get(OUT_BYTES..OUT_BYTES + 8)?.try_into().ok()?),
        })
    }
}

/// Parses the IPv4 5-tuple out of an Ethernet `frame` (addresses and ports in host order), or `None`
/// if it is not IPv4-over-Ethernet or is truncated; a non-TCP/UDP protocol reports ports 0. The tc
/// program reads the same offset `const`s, and `crates/probes-loader/tests/differential.rs` runs
/// this pure form as its oracle.
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
    if ihl < IPV4_MIN_IHL {
        return None;
    }
    let proto = *ip.get(IPV4_PROTO_OFFSET)?;
    let src = u32::from_be_bytes(ip.get(IPV4_SRC_OFFSET..IPV4_DST_OFFSET)?.try_into().ok()?);
    let dst = u32::from_be_bytes(ip.get(IPV4_DST_OFFSET..IPV4_MIN_IHL)?.try_into().ok()?);
    // The low 13 bits of the flags/fragment-offset field are the fragment offset. A non-first
    // fragment carries no L4 header, so reading "ports" there would interpret payload bytes and let a
    // guest mint bogus 5-tuples.
    let frag_off =
        u16::from_be_bytes([*ip.get(IPV4_FRAG_OFFSET)?, *ip.get(IPV4_FRAG_OFFSET + 1)?]) & 0x1fff;
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

/// How many egress allow-rules a sandbox's policy holds, fixed because the tc program scans the whole
/// array in a bounded loop (the verifier needs a compile-time cap) and BPF maps are sized at load.
pub const MAX_POLICY_RULES: usize = 16;

/// One entry in a sandbox's egress allow-list: a destination **CIDR** plus optional port and protocol.
/// A guest-sent IPv4 packet is allowed if its destination matches **any** `active` rule, and
/// deny-by-default drops it otherwise. A stable 12-byte map value.
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
    /// Builds an **active** allow-rule for `addr/prefix_len`, optional `port` and `proto` (`0` = any),
    /// zeroing the padding so it is a byte-stable map value.
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

    /// Serializes to the map value's raw native bytes, so the loader writes the policy without an
    /// `unsafe` `aya::Pod` binding. The write half of the wire: the tc program reads the slot back
    /// through the struct layout, so the offsets come from the struct, or a drifted position would
    /// reinterpret an operator's rule with nothing erroring.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; POLICY_RULE_SIZE] {
        let mut b = [0u8; POLICY_RULE_SIZE];
        b[Self::ADDR..Self::ADDR + 4].copy_from_slice(&self.addr.to_ne_bytes());
        b[Self::PORT..Self::PORT + 2].copy_from_slice(&self.port.to_ne_bytes());
        b[Self::PREFIX_LEN] = self.prefix_len;
        b[Self::PROTO] = self.proto;
        b[Self::ACTIVE] = self.active;
        b
    }

    /// Where each field sits, from the struct, shared by both halves of the codec.
    const ADDR: usize = core::mem::offset_of!(PolicyRule, addr);
    const PORT: usize = core::mem::offset_of!(PolicyRule, port);
    const PREFIX_LEN: usize = core::mem::offset_of!(PolicyRule, prefix_len);
    const PROTO: usize = core::mem::offset_of!(PolicyRule, proto);
    const ACTIVE: usize = core::mem::offset_of!(PolicyRule, active);

    /// Reconstructs a rule from a map value's raw bytes, or `None` if the slice is too short. The
    /// read-side twin of [`to_bytes`](Self::to_bytes), defined beside it so the two can't drift.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < POLICY_RULE_SIZE {
            return None;
        }
        Some(Self {
            addr: u32::from_ne_bytes(b.get(Self::ADDR..Self::ADDR + 4)?.try_into().ok()?),
            port: u16::from_ne_bytes(b.get(Self::PORT..Self::PORT + 2)?.try_into().ok()?),
            prefix_len: *b.get(Self::PREFIX_LEN)?,
            proto: *b.get(Self::PROTO)?,
            active: *b.get(Self::ACTIVE)?,
            _pad: [0; 3],
        })
    }
}

/// Whether one [`PolicyRule`] admits the destination `(dst_addr, dst_port, proto)` (all host byte
/// order): `active`, its CIDR contains `dst_addr`, and port and protocol match (`0` is a wildcard).
/// Called per rule by the tc program and looped by [`egress_allowed`], so kernel and host can't
/// disagree. The mask keeps the shift operand `< 32` (an out-of-range shift is UB in the kernel);
/// an out-of-range `prefix_len` is no match.
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

/// Whether a sandbox's egress allow-list admits the destination `(dst_addr, dst_port, proto)`: any
/// active rule matching means allow, none means deny. An empty allow-list allows nothing. The tc
/// program applies the same any-match logic over its policy map, and
/// `crates/probes-loader/tests/differential.rs` runs this as the oracle for that verdict.
#[must_use]
pub fn egress_allowed(rules: &[PolicyRule], dst_addr: u32, dst_port: u16, proto: u8) -> bool {
    rules
        .iter()
        .any(|r| rule_matches(r, dst_addr, dst_port, proto))
}

// ---------------------------------------------------------------------------
// IPv6: the v6 twins of the flow key, parser, and egress policy above. Deliberately **parallel**
// types and maps rather than widening the v4 ones, so the proven v4 datapath stays byte-for-byte
// unchanged. Addresses are `[u8; 16]` in network byte order, matched byte-wise (see the crate docs).
// ---------------------------------------------------------------------------

/// One **directional** IPv6 network flow's identity: the v6 5-tuple, addresses in network byte order.
/// A stable 40-byte BPF hash-map key like [`FlowKey`]; build it with [`FlowKey6::new`], which zeroes
/// the pad.
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
    /// Builds a v6 key from the 5-tuple, zeroing the padding so it hashes deterministically.
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

    /// Reconstructs a key from a map key's raw bytes, or `None` if the slice is too short. The v6 twin
    /// of [`FlowKey::from_bytes`], reading offsets from the struct for the same reason.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < FLOW_KEY6_SIZE {
            return None;
        }
        const SRC_ADDR: usize = core::mem::offset_of!(FlowKey6, src_addr);
        const DST_ADDR: usize = core::mem::offset_of!(FlowKey6, dst_addr);
        const SRC_PORT: usize = core::mem::offset_of!(FlowKey6, src_port);
        const DST_PORT: usize = core::mem::offset_of!(FlowKey6, dst_port);
        const PROTO: usize = core::mem::offset_of!(FlowKey6, proto);
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(b.get(SRC_ADDR..SRC_ADDR + 16)?);
        dst.copy_from_slice(b.get(DST_ADDR..DST_ADDR + 16)?);
        Some(Self::new(
            src,
            dst,
            u16::from_ne_bytes(b.get(SRC_PORT..SRC_PORT + 2)?.try_into().ok()?),
            u16::from_ne_bytes(b.get(DST_PORT..DST_PORT + 2)?.try_into().ok()?),
            *b.get(PROTO)?,
        ))
    }
}

impl core::fmt::Display for FlowKey6 {
    /// `[src]:sport -> [dst]:dport <proto>`, addresses via [`core::net::Ipv6Addr`].
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let src = core::net::Ipv6Addr::from(self.src_addr);
        let dst = core::net::Ipv6Addr::from(self.dst_addr);
        write!(f, "[{src}]:{} -> [{dst}]:{} ", self.src_port, self.dst_port)?;
        write!(f, "{}", ProtoName(self.proto))
    }
}

/// Parses the IPv6 5-tuple out of an Ethernet `frame` (addresses network order, ports host order),
/// or `None` if it is not IPv6-over-Ethernet or is truncated. **Extension headers are not walked**:
/// such a frame reports ports 0 and `proto` = the next-header value, a recorded flow rather than a
/// silent drop. The tc program reads the same offsets.
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
    let next_header = *ip.get(IPV6_NEXT_HEADER_OFFSET)?;
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(ip.get(IPV6_SRC_OFFSET..IPV6_DST_OFFSET)?);
    dst.copy_from_slice(ip.get(IPV6_DST_OFFSET..IPV6_HLEN)?);
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if next_header == IPPROTO_TCP || next_header == IPPROTO_UDP {
        let l4 = ip.get(IPV6_HLEN..)?;
        src_port = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
        dst_port = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    }
    Some(FlowKey6::new(src, dst, src_port, dst_port, next_header))
}

/// One entry in a sandbox's **IPv6** egress allow-list: a destination v6 CIDR plus optional port and
/// protocol, the v6 twin of [`PolicyRule`]. A stable 24-byte map value, with `addr` in network byte
/// order and matched byte-wise to `prefix_len`.
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
    /// Builds an **active** v6 allow-rule for `addr/prefix_len`, optional `port`/`proto` (`0` = any),
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

    /// Serializes to the map value's raw native bytes, so the loader writes the policy without an
    /// `unsafe` `aya::Pod` binding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; POLICY_RULE6_SIZE] {
        let mut b = [0u8; POLICY_RULE6_SIZE];
        b[Self::ADDR..Self::ADDR + 16].copy_from_slice(&self.addr);
        b[Self::PORT..Self::PORT + 2].copy_from_slice(&self.port.to_ne_bytes());
        b[Self::PREFIX_LEN] = self.prefix_len;
        b[Self::PROTO] = self.proto;
        b[Self::ACTIVE] = self.active;
        b
    }

    /// Where each field sits, from the struct, shared by both halves of the codec. See
    /// [`PolicyRule::to_bytes`] for why these are derived rather than written out.
    const ADDR: usize = core::mem::offset_of!(PolicyRule6, addr);
    const PORT: usize = core::mem::offset_of!(PolicyRule6, port);
    const PREFIX_LEN: usize = core::mem::offset_of!(PolicyRule6, prefix_len);
    const PROTO: usize = core::mem::offset_of!(PolicyRule6, proto);
    const ACTIVE: usize = core::mem::offset_of!(PolicyRule6, active);

    /// Reconstructs from a map value's raw native bytes, the read-side twin of
    /// [`to_bytes`](Self::to_bytes). `None` for a short slice, so a map whose value size no longer
    /// matches the record fails loudly.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < POLICY_RULE6_SIZE {
            return None;
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(b.get(Self::ADDR..Self::ADDR + 16)?);
        Some(Self {
            addr,
            port: u16::from_ne_bytes(b.get(Self::PORT..Self::PORT + 2)?.try_into().ok()?),
            prefix_len: *b.get(Self::PREFIX_LEN)?,
            proto: *b.get(Self::PROTO)?,
            active: *b.get(Self::ACTIVE)?,
            _pad: [0; 3],
        })
    }
}

/// Whether IPv6 address `addr` lies in `net/prefix_len`, compared byte-wise so it runs in the eBPF
/// kernel too. Loops a compile-time-bounded 16 bytes for the verifier; a `prefix_len > 128` is treated
/// as no match by the caller.
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
/// twin of [`rule_matches`]. Single-sourced, so the tc program and this agree.
#[must_use]
pub fn rule_matches6(rule: &PolicyRule6, dst_addr: [u8; 16], dst_port: u16, proto: u8) -> bool {
    if rule.active == 0 || rule.prefix_len > 128 {
        return false;
    }
    addr6_in_prefix(dst_addr, rule.addr, rule.prefix_len)
        && (rule.port == 0 || rule.port == dst_port)
        && (rule.proto == 0 || rule.proto == proto)
}

/// Whether a sandbox's IPv6 allow-list admits `(dst_addr, dst_port, proto)`, the v6 twin of
/// [`egress_allowed`].
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

/// The per-VM IPv6 link every sandbox reuses, as a `(network, prefix_len)` pair. Fixed rather than
/// per-sandbox because the per-VM netns supplies uniqueness, which is what lets a `#![no_std]`
/// in-kernel program know the link without a map lookup. The engine owns the addresses themselves, and
/// `the_guest_v6_link_is_the_same_in_the_engine_and_the_probes` in `xtask` fails if the two disagree.
pub const GUEST_LINK6: ([u8; 16], u8) = (
    [0xfd, 0x00, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    64,
);

/// Whether `dst` is an **on-link** IPv6 scope that guest-originated ICMPv6 must reach for neighbor
/// discovery / MLD / NUD, and only those: link-local unicast (`fe80::/10`), link-scoped multicast
/// (`ff02::/16`), or the guest's own link ([`GUEST_LINK6`]). None of these route off the connected
/// link.
///
/// **Deliberately the one `/64`, not `fc00::/7`.** RFC 4193 addresses are routable *within a site*, so
/// sparing the whole ULA range would hand a guest an unpoliced ICMPv6 channel (Echo carries payload) to
/// every internal endpoint a furnished uplink can reach, with [`egress_allowed6`] never consulted.
#[must_use]
pub fn icmp6_dst_on_link(dst: [u8; 16]) -> bool {
    const LINK_LOCAL: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // fe80::/10
    const LINK_MCAST: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // ff02::/16
    let (link, link_len) = GUEST_LINK6;
    addr6_in_prefix(dst, LINK_LOCAL, 10)
        || addr6_in_prefix(dst, LINK_MCAST, 16)
        || addr6_in_prefix(dst, link, link_len)
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
        let mut arp = u.clone();
        arp[ETHERTYPE_OFFSET + 1] = 0x06;
        assert!(parse_ipv4_5tuple(&arp).is_none());
        // A truncated frame is skipped, never a panic.
        assert!(parse_ipv4_5tuple(&u[..ETH_HLEN + 10]).is_none());
        assert!(parse_ipv4_5tuple(&[]).is_none());
    }

    #[test]
    fn non_first_fragment_has_no_ports() {
        // A non-first fragment carries no L4 header, so what sits at the port offsets is payload: the
        // parser must zero the ports, else a guest mints bogus 5-tuples.
        let mut frag = frame(IPPROTO_TCP, [10, 200, 0, 2], [9, 9, 9, 9], 51000, 443);
        frag[ETH_HLEN + 6] = 0x00;
        frag[ETH_HLEN + 7] = 0xb9; // fragment offset 185 (nonzero)
        let key = parse_ipv4_5tuple(&frag).expect("a fragment still parses its addresses");
        assert_eq!(key.dst_addr.to_be_bytes(), [9, 9, 9, 9]);
        assert_eq!(key.proto, IPPROTO_TCP);
        assert_eq!(key.src_port, 0, "non-first fragment ports must be zero");
        assert_eq!(key.dst_port, 0, "non-first fragment ports must be zero");
        // A *first* fragment still has its L4 header, so its ports are real.
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
    /// The one protocol rendering every surface now reaches for: the flow keys' `Display`, the
    /// signed record's JSON, and the CLI's audit trail. An unnamed protocol keeps its **number**,
    /// which is what an operator needs to look it up; the CLI's own copy used to drop it.
    #[test]
    fn a_protocol_number_renders_the_same_wherever_it_is_named() {
        assert_eq!(ProtoName(IPPROTO_TCP).to_string(), "tcp");
        assert_eq!(ProtoName(IPPROTO_UDP).to_string(), "udp");
        assert_eq!(ProtoName(IPPROTO_ICMPV6).to_string(), "proto 58");
        assert_eq!(ProtoName(0).to_string(), "proto 0");

        // The flow keys render through it rather than beside it, so a key and a record naming the
        // same flow cannot disagree about the protocol.
        let v4 = FlowKey::new(0, 0, 0, 443, IPPROTO_TCP).to_string();
        assert!(v4.ends_with("tcp"), "{v4}");
        let v6 = FlowKey6::new([0u8; 16], [0u8; 16], 0, 443, IPPROTO_ICMPV6).to_string();
        assert!(v6.ends_with("proto 58"), "{v6}");
    }

    use super::*;

    /// A dotted-quad as the host-order `u32` the parser and policy use.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    #[test]
    fn rule_layout_is_padding_free_and_known_size() {
        assert_eq!(POLICY_RULE_SIZE, 12);
        // An all-zero slot must not admit anything, so a fixed array of zeroed rules is deny-all rather
        // than an accidental `0.0.0.0/0`.
        let empty = PolicyRule::default();
        assert_eq!(empty.active, 0);
        assert!(!rule_matches(&empty, ip(8, 8, 8, 8), 53, IPPROTO_UDP));
    }

    #[test]
    fn host_only_prefix_matches_exactly_one_address() {
        let rule = PolicyRule::allow(ip(10, 200, 0, 1), 32, 9999, IPPROTO_UDP);
        assert!(rule_matches(&rule, ip(10, 200, 0, 1), 9999, IPPROTO_UDP));
        assert!(!rule_matches(&rule, ip(10, 200, 0, 2), 9999, IPPROTO_UDP)); // other host
        assert!(!rule_matches(&rule, ip(10, 200, 0, 1), 9998, IPPROTO_UDP)); // other port
        assert!(!rule_matches(&rule, ip(10, 200, 0, 1), 9999, IPPROTO_TCP)); // other proto
    }

    #[test]
    fn cidr_and_wildcards_match_ranges() {
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
        // A `prefix_len` of 0 is allow-all on the address, still gated by port and proto.
        let any = PolicyRule::allow(0, 0, 443, IPPROTO_TCP);
        assert!(rule_matches(&any, ip(1, 2, 3, 4), 443, IPPROTO_TCP));
        assert!(!rule_matches(&any, ip(1, 2, 3, 4), 80, IPPROTO_TCP));
    }

    #[test]
    fn out_of_range_prefix_never_matches() {
        // A garbled map write must be no match, never a shift-overflow or an accidental allow.
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
        let mut v4 = frame6(IPPROTO_UDP, ula(2), ula(1), 53, 53);
        v4[ETHERTYPE_OFFSET] = 0x08;
        v4[ETHERTYPE_OFFSET + 1] = 0x00;
        assert!(parse_ipv6_5tuple(&v4).is_none());
        // A truncated frame is skipped, never a panic.
        let ok = frame6(IPPROTO_UDP, ula(2), ula(1), 53, 53);
        assert!(parse_ipv6_5tuple(&ok[..ETH_HLEN + 30]).is_none());
        assert!(parse_ipv6_5tuple(&[]).is_none());
        // An extension next-header is not walked, so the ports stay 0 rather than reading options as
        // ports.
        let hbh = frame6(0, ula(2), ula(1), 51000, 443);
        let key = parse_ipv6_5tuple(&hbh).expect("addresses still parse");
        assert_eq!(key.proto, 0);
        assert_eq!(key.src_port, 0);
        assert_eq!(key.dst_port, 0);
    }

    #[test]
    fn addr6_prefix_covers_full_partial_and_wildcard() {
        let host = ula(1);
        assert!(addr6_in_prefix(host, ula(1), 128));
        assert!(!addr6_in_prefix(host, ula(2), 128));
        assert!(addr6_in_prefix(host, [0u8; 16], 0));
        assert!(addr6_in_prefix(ula(2), ula(1), 64));
        // The partial-byte path: /125 leaves the low 3 bits free.
        let net = ula(0);
        assert!(addr6_in_prefix(ula(7), net, 125));
        assert!(!addr6_in_prefix(ula(8), net, 125));
        let mut other = ula(1);
        other[0] = 0xfe;
        assert!(!addr6_in_prefix(other, ula(1), 16));
    }

    #[test]
    fn rule_matches6_and_deny_by_default() {
        let rule = PolicyRule6::allow(ula(1), 128, 9999, IPPROTO_UDP);
        assert!(rule_matches6(&rule, ula(1), 9999, IPPROTO_UDP));
        assert!(!rule_matches6(&rule, ula(2), 9999, IPPROTO_UDP)); // other host
        assert!(!rule_matches6(&rule, ula(1), 9998, IPPROTO_UDP)); // other port
        assert!(!rule_matches6(&rule, ula(1), 9999, IPPROTO_TCP)); // other proto
        // A garbled write must be no match, never a panic.
        let bad = PolicyRule6 {
            prefix_len: 200,
            ..PolicyRule6::allow(ula(0), 64, 0, 0)
        };
        assert!(!rule_matches6(&bad, ula(1), 443, IPPROTO_TCP));
        let rules = [PolicyRule6::allow(ula(0), 64, 0, 0)];
        assert!(egress_allowed6(&rules, ula(9), 80, IPPROTO_TCP));
        assert!(!egress_allowed6(&[], ula(1), 9999, IPPROTO_UDP));
    }

    #[test]
    fn icmp6_on_link_scopes_spared_routable_policed() {
        let a = |s: &str| s.parse::<core::net::Ipv6Addr>().unwrap().octets();
        // Spared: link-local, link-scoped multicast, and the guest's own /64.
        assert!(icmp6_dst_on_link(a("fe80::1"))); // NDP link-local unicast
        assert!(icmp6_dst_on_link(a("febf::1"))); // fe80::/10 upper edge
        assert!(icmp6_dst_on_link(a("ff02::1"))); // all-nodes
        assert!(icmp6_dst_on_link(a("ff02::2"))); // all-routers (RS)
        assert!(icmp6_dst_on_link(a("ff02::1:ff00:1"))); // solicited-node (NS)
        assert!(icmp6_dst_on_link(a("ff02::16"))); // MLDv2 report
        assert!(icmp6_dst_on_link(ula(1))); // this engine's on-link host end (fd00:200::1)
        assert!(icmp6_dst_on_link(ula(2))); // the guest's own end, same /64

        // Policed: global unicast, and wider-scope multicast a multicast router could carry off-link.
        assert!(!icmp6_dst_on_link(a("2606:4700:4700::1111"))); // global unicast (the exfil case)
        assert!(!icmp6_dst_on_link(a("2001:4860:4860::8888"))); // global unicast
        assert!(!icmp6_dst_on_link(a("fec0::1"))); // fec0::/10, outside fe80::/10
        assert!(!icmp6_dst_on_link(a("ff0e::1"))); // global-scope multicast
        assert!(!icmp6_dst_on_link(a("ff05::1"))); // site-scope multicast
        assert!(!icmp6_dst_on_link(a("::1"))); // loopback (never a guest egress dst)
    }

    #[test]
    fn a_ula_outside_the_guests_own_link_is_policed_not_spared() {
        // The spare covers one `/64`, not `fc00::/7`: a ULA is routable within a site, so sparing the
        // whole range would carry an Echo's payload to internal infrastructure without `POLICY6` ever
        // being consulted.
        let a = |s: &str| s.parse::<core::net::Ipv6Addr>().unwrap().octets();
        assert!(
            !icmp6_dst_on_link(a("fc00::1")),
            "a ULA in another prefix is a routable destination, not this link"
        );
        assert!(
            !icmp6_dst_on_link(a("fd00:999::1")),
            "a neighbouring fd00::/8 ULA is still off this link"
        );
        assert!(
            !icmp6_dst_on_link(a("fd00:200:0:1::1")),
            "the adjacent /64 is off-link: the guest's link is fd00:200::/64, not fd00:200::/48"
        );
        // The host end and everything else on the guest's own /64 stay spared, so NUD is unaffected.
        assert!(icmp6_dst_on_link(a("fd00:200::1")));
        assert!(icmp6_dst_on_link(a("fd00:200::ffff")));
    }

    #[test]
    fn v6_bytes_round_trip_and_display() {
        let key = FlowKey6::new(ula(2), ula(1), 1234, 53, IPPROTO_UDP);
        // Mirror the kernel writer: the loader reads a map key as raw native bytes.
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
        // Catches a field resize; the per-field offsets below catch a same-size reorder.
        assert_eq!(EVENT_SIZE, 168);
        assert_eq!(core::mem::align_of::<SyscallEvent>(), 8);
    }

    #[test]
    fn layout_offsets_are_the_wire_contract() {
        // The eBPF object is built separately from the loader, so this layout *is* the wire format
        // between two independently-built artifacts: a layout change would silently make a stale
        // probe object on disk read as garbage.
        assert_eq!(core::mem::offset_of!(SyscallEvent, cgroup_id), 0);
        assert_eq!(core::mem::offset_of!(SyscallEvent, pid), 8);
        assert_eq!(core::mem::offset_of!(SyscallEvent, tid), 12);
        assert_eq!(core::mem::offset_of!(SyscallEvent, syscall), 16);
        assert_eq!(core::mem::offset_of!(SyscallEvent, detail_len), 20);
        assert_eq!(core::mem::offset_of!(SyscallEvent, comm), 24);
        assert_eq!(core::mem::offset_of!(SyscallEvent, detail), 40);
    }

    // Each record below carries the same contract for the same reason. The codecs read their
    // offsets from the struct, so a reorder keeps the two *ends* agreeing and cannot corrupt a
    // freshly built pair. What it does corrupt is a **stale** eBPF object: the probes are built
    // separately (`cargo xtask build-probes`, or an installed copy under the data dir) and loaded at
    // runtime, so a reordered struct plus yesterday's object is one artifact writing fields the
    // other reads elsewhere, with no size change to catch it. These pins make that reorder a
    // decision someone has to take rather than one they can make by accident.

    #[test]
    fn flow_key_offsets_are_the_wire_contract() {
        assert_eq!(core::mem::offset_of!(FlowKey, src_addr), 0);
        assert_eq!(core::mem::offset_of!(FlowKey, dst_addr), 4);
        assert_eq!(core::mem::offset_of!(FlowKey, src_port), 8);
        assert_eq!(core::mem::offset_of!(FlowKey, dst_port), 10);
        assert_eq!(core::mem::offset_of!(FlowKey, proto), 12);
        assert_eq!(core::mem::offset_of!(FlowKey, _pad), 13);
    }

    #[test]
    fn flow_counts_offsets_are_the_wire_contract() {
        assert_eq!(core::mem::offset_of!(FlowCounts, ingress_packets), 0);
        assert_eq!(core::mem::offset_of!(FlowCounts, ingress_bytes), 8);
        assert_eq!(core::mem::offset_of!(FlowCounts, egress_packets), 16);
        assert_eq!(core::mem::offset_of!(FlowCounts, egress_bytes), 24);
    }

    #[test]
    fn flow_key6_offsets_are_the_wire_contract() {
        assert_eq!(core::mem::offset_of!(FlowKey6, src_addr), 0);
        assert_eq!(core::mem::offset_of!(FlowKey6, dst_addr), 16);
        assert_eq!(core::mem::offset_of!(FlowKey6, src_port), 32);
        assert_eq!(core::mem::offset_of!(FlowKey6, dst_port), 34);
        assert_eq!(core::mem::offset_of!(FlowKey6, proto), 36);
        assert_eq!(core::mem::offset_of!(FlowKey6, _pad), 37);
    }

    #[test]
    fn policy_rule_offsets_are_the_wire_contract() {
        // The rule the operator writes: a reorder here changes what a `/24 tcp` allowance means to
        // the classifier, which is the one record where a silent reinterpretation is a policy
        // decision nobody made.
        assert_eq!(core::mem::offset_of!(PolicyRule, addr), 0);
        assert_eq!(core::mem::offset_of!(PolicyRule, port), 4);
        assert_eq!(core::mem::offset_of!(PolicyRule, prefix_len), 6);
        assert_eq!(core::mem::offset_of!(PolicyRule, proto), 7);
        assert_eq!(core::mem::offset_of!(PolicyRule, active), 8);
        assert_eq!(core::mem::offset_of!(PolicyRule, _pad), 9);
    }

    #[test]
    fn policy_rule6_offsets_are_the_wire_contract() {
        assert_eq!(core::mem::offset_of!(PolicyRule6, addr), 0);
        assert_eq!(core::mem::offset_of!(PolicyRule6, port), 16);
        assert_eq!(core::mem::offset_of!(PolicyRule6, prefix_len), 18);
        assert_eq!(core::mem::offset_of!(PolicyRule6, proto), 19);
        assert_eq!(core::mem::offset_of!(PolicyRule6, active), 20);
        assert_eq!(core::mem::offset_of!(PolicyRule6, _pad), 21);
    }

    #[test]
    fn every_record_codec_reads_the_byte_positions_the_struct_declares() {
        // The other half of the contract: the codecs must agree with the layout, not merely with
        // themselves. Each record is built, serialized where it has a writer, and read back through
        // the *struct* the way the kernel reads a map value, so a codec that wandered off the field
        // it names is a mismatch here rather than a wrong rule in production.
        let rule = PolicyRule::allow(0x5db8_d800, 24, 443, IPPROTO_TCP);
        let via_bytes = PolicyRule::from_bytes(&rule.to_bytes()).expect("a full-size rule decodes");
        assert_eq!(via_bytes, rule);
        assert_eq!(
            rule.to_bytes()[core::mem::offset_of!(PolicyRule, prefix_len)],
            24,
            "`to_bytes` must put prefix_len where the struct keeps it, or the classifier reads \
             another field as the CIDR length"
        );
        assert_eq!(
            rule.to_bytes()[core::mem::offset_of!(PolicyRule, proto)],
            IPPROTO_TCP
        );

        let rule6 = PolicyRule6::allow([0x20; 16], 64, 443, IPPROTO_UDP);
        assert_eq!(
            PolicyRule6::from_bytes(&rule6.to_bytes()).expect("a full-size v6 rule decodes"),
            rule6
        );
        assert_eq!(
            rule6.to_bytes()[core::mem::offset_of!(PolicyRule6, prefix_len)],
            64
        );
        assert_eq!(
            rule6.to_bytes()[core::mem::offset_of!(PolicyRule6, proto)],
            IPPROTO_UDP
        );

        // The read-only records have no writer here (the kernel is the writer), so lay the bytes out
        // by the struct's own offsets and check the decode lands each field.
        let mut key = [0u8; FLOW_KEY_SIZE];
        key[core::mem::offset_of!(FlowKey, proto)] = IPPROTO_UDP;
        key[core::mem::offset_of!(FlowKey, dst_port)] = 0x35; // 53, little end first
        let decoded = FlowKey::from_bytes(&key).expect("a full-size key decodes");
        assert_eq!(decoded.proto, IPPROTO_UDP);
        assert_eq!(decoded.dst_port, 53);

        let mut counts = [0u8; FLOW_COUNTS_SIZE];
        counts[core::mem::offset_of!(FlowCounts, egress_bytes)] = 9;
        let decoded = FlowCounts::from_bytes(&counts).expect("a full-size value decodes");
        assert_eq!(decoded.egress_bytes, 9);
        assert_eq!(decoded.ingress_bytes, 0);

        let mut key6 = [0u8; FLOW_KEY6_SIZE];
        key6[core::mem::offset_of!(FlowKey6, proto)] = IPPROTO_TCP;
        key6[core::mem::offset_of!(FlowKey6, dst_addr)] = 0xfe;
        let decoded = FlowKey6::from_bytes(&key6).expect("a full-size v6 key decodes");
        assert_eq!(decoded.proto, IPPROTO_TCP);
        assert_eq!(decoded.dst_addr[0], 0xfe);
        assert_eq!(decoded.src_addr, [0u8; 16]);
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

    /// The in-gate half of this crate's fuzzing (the deep `cargo fuzz` half is the `syscall_event`
    /// target in `fuzz/`). `parse_ipv4_5tuple` reads a **guest-crafted** Ethernet frame off the tap,
    /// so every parser here must return a value or `None` on any input, never panic.
    #[test]
    fn parsers_never_panic_on_arbitrary_bytes() {
        // xorshift64*: deterministic and dependency-free, with a fixed seed so it never flakes.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for _ in 0..50_000 {
            // Lengths straddle the record size and the L2/L3/L4 header boundaries, so mid-field EOF
            // (a truncated frame, an oversized `detail_len`) is stressed, not just full buffers.
            let len = (next() % 200) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() >> 33) as u8).collect();
            if let Some(ev) = SyscallEvent::from_bytes(&buf) {
                // `detail_len` is attacker-influenced; the accessors must *clamp*, asserted as a
                // bound, not just absence of panic: an out-of-range length yields a capped slice.
                assert!(
                    ev.detail().len() <= DETAIL_CAP,
                    "detail() must clamp to DETAIL_CAP, got {} (detail_len {})",
                    ev.detail().len(),
                    ev.detail_len
                );
                assert!(
                    ev.comm_lossy().len() <= COMM_CAP * 4,
                    "comm_lossy() reads at most the 16-byte comm field (x4 for replacement chars)"
                );
                let _ = ev.describe();
            }
            let _ = parse_ipv4_5tuple(&buf);
        }
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
