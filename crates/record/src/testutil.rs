//! Synthetic inputs shared by the unit tests in `record`, `json`, and `summary`.
//!
//! These build `#[repr(C)]` wire structs field by field, so a new field on one of them is a change
//! every builder has to answer. Held once here so the answer is given once, rather than
//! per test module where the copies drift apart.
//!
//! Nothing here reaches the kernel. `SyscallEvent`'s fields are public, so a test can name the
//! bytes the probe would have written without eBPF, KVM, or caps.

use std::time::Duration;

use bsx_probes_common::{COMM_CAP, DETAIL_CAP, FlowCounts, FlowKey, IPPROTO_TCP, SyscallEvent};

use crate::record::{NetSection, RecordSubject, RunRecord, SyscallFootprint, Timing};
use crate::{AxisGap, CgroupStats, NetStats, ResourceSummary};

/// One synthetic event. `syscall` is the **raw discriminant**, not a [`Syscall`], so a test can
/// feed a value that decodes to nothing and exercise the unknown-kind path.
///
/// `detail` and `comm` are truncated to their caps rather than rejected, which is what the probe's
/// fixed buffers do to an over-long path.
///
/// [`Syscall`]: bsx_probes_common::Syscall
pub(crate) fn ev(syscall: u32, cgroup: u64, detail: &[u8], comm: &str) -> SyscallEvent {
    let mut d = [0u8; DETAIL_CAP];
    let n = detail.len().min(d.len());
    d[..n].copy_from_slice(&detail[..n]);
    let mut c = [0u8; COMM_CAP];
    let m = comm.len().min(c.len());
    c[..m].copy_from_slice(&comm.as_bytes()[..m]);
    SyscallEvent {
        cgroup_id: cgroup,
        pid: 7,
        tid: 7,
        syscall,
        detail_len: n as u32,
        comm: c,
        detail: d,
    }
}

/// One flow key with fixed counters: the endpoints are the variable under test, the byte and packet
/// counts never are.
pub(crate) fn flow(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    proto: u8,
) -> (FlowKey, FlowCounts) {
    (
        FlowKey::new(
            u32::from_be_bytes(src),
            u32::from_be_bytes(dst),
            sport,
            dport,
            proto,
        ),
        FlowCounts {
            ingress_packets: 2,
            ingress_bytes: 120,
            egress_packets: 3,
            egress_bytes: 200,
        },
    )
}

/// A whole record over the given flows, with every other axis populated: a denial, resource
/// counters, a coverage gap, and a syscall footprint whose events (execve once, openat twice on one
/// path) exercise the notable de-dup and sort. This is what the JSON and summary goldens render.
pub(crate) fn sample(flows: Vec<(FlowKey, FlowCounts)>) -> RunRecord {
    let totals = NetStats {
        ingress_packets: 2,
        ingress_bytes: 120,
        egress_packets: 3,
        egress_bytes: 200,
    };
    let denials = vec![(
        FlowKey::new(0, u32::from_be_bytes([9, 9, 9, 9]), 0, 443, IPPROTO_TCP),
        4,
    )];
    let resources = ResourceSummary {
        cpu_time: Duration::from_nanos(5_000),
        cgroup: CgroupStats {
            cpu_usage_usec: Some(6),
            memory_current: Some(1024),
            memory_peak: Some(4096),
            io_rbytes: None,
            io_wbytes: Some(512),
        },
    };
    let host_syscalls = SyscallFootprint::from_events(
        0x42,
        &[
            ev(0, 0x42, b"/bin/sh", "sh"),
            ev(1, 0x42, b"/etc/hosts", "sh"),
            ev(1, 0x42, b"/etc/hosts", "sh"),
        ],
    );
    RunRecord::from_parts(
        RecordSubject::new("bsx-4242-0".into(), 1_700_000_000_000_000_000),
        Some(NetSection::from_tap(flows, totals, denials, 0, 0)),
        resources,
        host_syscalls,
        Timing::new(Duration::from_millis(120), Duration::from_millis(42)),
        vec![AxisGap::Cpu("meter lock poisoned".into())],
    )
}
