//! Plain-old-data shared across the eBPF boundary. The kernel programs in `crates/probes` write a
//! [`SyscallEvent`] into a ring buffer; the userspace loader in `crates/probes-loader` reads the raw
//! bytes back and reconstructs it with [`SyscallEvent::from_bytes`]. Defining the record **once**,
//! here, is what keeps the writer and the reader from drifting: a field reordered or resized on one
//! side but not the other would otherwise be a silent garbage read, the classic FFI-struct bug.
//!
//! The type is `#[repr(C)]` with fields ordered large-to-small so the layout is padding-free and
//! stable, and both sides run on the same host (one kernel, one userspace) so native byte order is
//! shared — [`from_bytes`](SyscallEvent::from_bytes) reads each field with `from_ne_bytes`, no
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
/// 16 is `sizeof(struct sockaddr_in)` — a full IPv4 address (family + port + addr); an IPv6 sockaddr
/// is captured only up to here (family + port + the first 8 bytes), enough to identify the family and
/// port without risking an over-read past a short user buffer.
pub const SOCKADDR_SNAP: usize = 16;

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
/// footprint (a microVM services its own syscalls in-guest and they never trap here — see the crate
/// and ROADMAP Phase 9).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallEvent {
    /// The cgroup id of the process that made the syscall (`bpf_get_current_cgroup_id`) — the axis a
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
    /// short. Reads each field at its fixed `#[repr(C)]` offset with `from_ne_bytes` — safe, no
    /// transmute, and defined next to the field list so it can't drift from the kernel writer.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < EVENT_SIZE {
            return None;
        }
        // Offsets follow the padding-free `#[repr(C)]` layout: cgroup_id@0, pid@8, tid@12,
        // syscall@16, detail_len@20, comm@24, detail@40 (EVENT_SIZE == 168).
        let cgroup_id = u64::from_ne_bytes(b.get(0..8)?.try_into().ok()?);
        let pid = u32::from_ne_bytes(b.get(8..12)?.try_into().ok()?);
        let tid = u32::from_ne_bytes(b.get(12..16)?.try_into().ok()?);
        let syscall = u32::from_ne_bytes(b.get(16..20)?.try_into().ok()?);
        let detail_len = u32::from_ne_bytes(b.get(20..24)?.try_into().ok()?);
        let mut comm = [0u8; COMM_CAP];
        comm.copy_from_slice(b.get(24..24 + COMM_CAP)?);
        let mut detail = [0u8; DETAIL_CAP];
        detail.copy_from_slice(b.get(40..40 + DETAIL_CAP)?);
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
    #[cfg(any(feature = "std", test))]
    #[must_use]
    pub fn detail_display(&self) -> String {
        let d = self.detail();
        match self.kind() {
            Some(Syscall::Connect) => describe_sockaddr(d),
            _ => String::from_utf8_lossy(d).into_owned(),
        }
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

/// A best-effort human form of the leading sockaddr bytes: `AF_INET` yields `a.b.c.d:port`, other
/// families name the family number, and a too-short capture says so.
#[cfg(any(feature = "std", test))]
fn describe_sockaddr(bytes: &[u8]) -> String {
    // sa_family is a native-endian u16; AF_INET == 2, its sockaddr_in is family, be16 port, 4-byte ip.
    const AF_INET: u16 = 2;
    if bytes.len() >= 8 {
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family == AF_INET {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            return format!("{}.{}.{}.{}:{port}", bytes[4], bytes[5], bytes[6], bytes[7]);
        }
        return format!("<sockaddr family {family}>");
    }
    "<sockaddr: too short>".to_string()
}

// ---------------------------------------------------------------------------
// Network flows (P10.2): the per-flow record the tc program on a VM's tap writes.
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
/// IP protocol number for TCP (its L4 header starts with a 16-bit source then destination port).
pub const IPPROTO_TCP: u8 = 6;
/// IP protocol number for UDP (same leading source/destination port layout as TCP).
pub const IPPROTO_UDP: u8 = 17;

/// One **directional** network flow's identity: the IPv4 5-tuple, in host byte order (so a consumer
/// formats `src_addr` straight to dotted-quad). `#[repr(C)]` and padding-free — the trailing `_pad` is
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
    /// shared byte order) — no `unsafe`, no transmute, defined next to the fields so it can't drift from
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
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        let l4 = ip.get(ihl..)?;
        src_port = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
        dst_port = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    }
    Some(FlowKey::new(src, dst, src_port, dst_port, proto))
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
mod tests {
    use super::*;

    #[test]
    fn layout_is_padding_free_and_known_size() {
        // The parser's fixed offsets assume this exact size; catch a field reorder/resize here.
        assert_eq!(EVENT_SIZE, 168);
        assert_eq!(core::mem::align_of::<SyscallEvent>(), 8);
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
