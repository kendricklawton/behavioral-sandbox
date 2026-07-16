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
