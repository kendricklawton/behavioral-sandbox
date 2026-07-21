# 018. Syscall observability: a ring buffer of per-event records, a shared POD type, and an in-kernel filter *(2026-07-15)*

**Context.** The engine observes a sandbox's host footprint from outside the guest, and a bare
syscall counter answers only "how many `execve`s". Real observability needs a **stream of per-event
records** (pid, cgroup, `comm`, the opened path / connected address), scoped to *one* sandbox's host
workers rather than the whole machine's. That requirement forces three shapes to be chosen together:
how events cross the kernel→userspace boundary, how the record type stays consistent across that
boundary, and where the "watch one sandbox" filter lives. Each has a force pulling on it: the
boundary crossing must be ordered and non-blocking (best-effort observability must never stall a
syscall); the record type must not drift silently across an FFI boundary, where a misread is data
corruption, not a compile error; and the scoping filter must make "watch one sandbox" honest rather
than a userspace afterthought. The `execve`/`openat`/`connect` set is the smallest that exercises all
three record shapes (a program path, a file path, a socket address), and a ring buffer paired with a
shared POD type is what keeps the eBPF side isomorphic to the driver side: typed, ordered, no silent
corruption, no leak.

**Decision.** Three coupled choices, extending decision 017's loader:
- **A ring buffer (`BPF_MAP_TYPE_RINGBUF`), not a perf event array.** The three `sys_enter_*`
  tracepoint programs `output` a fixed-size record into one MPSC `EVENTS` ring buffer; the loader
  drains it with a single in-order consumer ([`SyscallTracer::drain`]). The ring buffer is the modern
  (5.8+) replacement for per-CPU perf buffers: one shared queue, ordered, no per-CPU reassembly. A
  full buffer drops new events (best-effort observability, never blocking a syscall). Draining is
  **non-blocking** (returns 0 when empty); an `epoll`-backed blocking wait is the streaming consumer's
  job.
- **The wire record is one shared, dependency-free POD crate.** `crates/probes-common` holds the
  `#[repr(C)]`, padding-free `SyscallEvent` (and its safe `from_bytes` reader), depended on by both
  the kernel writer (`crates/probes`) and the userspace reader (`crates/probes-loader`). Single-
  sourcing the layout is what prevents the classic FFI-struct drift: a field reordered on one side
  only would otherwise be a silent garbage read. `#![no_std]` + zero deps so it compiles unchanged for
  the BPF target; a `std` feature (loader-only) adds ergonomic helpers. The reader parses field by
  field with `from_ne_bytes` (same host, shared byte order), no `unsafe`, no transmute, keeping the
  host path `unsafe`-free.
- **The filter is a two-slot `Array` map the loader writes, consulted in-kernel.** Slot 0 a target
  tgid, slot 1 a target cgroup id; `0` disables that axis, so the load-time default (a zeroed map)
  observes everything, and every allowance is explicit (deny-by-default's spirit for observation
  scope). Filtering **in the program**, dropping the event before it reaches the ring buffer, keeps
  the buffer and userspace uncluttered by other processes' syscalls.

**Alternatives considered.**
- **Perf event array (`PerfEventArray`).** Rejected: per-CPU buffers the consumer must poll and
  reassemble, the pre-5.8 pattern the ring buffer was designed to replace; no ordering, more userspace
  bookkeeping for no gain here.
- **Duplicate the event struct on each side (no shared crate).** Rejected: the two definitions drift
  silently, and the failure mode (misread fields) is data corruption, not a compile error, exactly
  what a shared POD crate makes impossible.
- **Filter in userspace after draining.** Rejected: it ships every process's events through the ring
  buffer and burns buffer space + read work on records that are immediately discarded; the kernel is
  where the cheap, early drop belongs.
- **Read the path with a field-offset CO-RE relocation.** Not needed yet: the syscall arg is at a
  stable tracepoint offset read with `read_at` + `bpf_probe_read_user_*`; genuine `vmlinux`-struct
  field reads (and their relocations) arrive when a later phase reads kernel structs.

**Consequences and notes.**
- This is still the **host's** footprint, not the guest's (decision 017's honest limit stands): a
  microVM services its syscalls in-guest. The filter's cgroup axis is how events are attributed to a
  specific sandbox: `cgroup_id_of_pid` resolves a VMM pid to its cgroup id (the inode of the cgroup
  dir, which equals `bpf_get_current_cgroup_id`), and `watch_cgroup` scopes the trace to it. The bridge
  to the Firecracker track is plain `u32`/`u64` values, so `probes-loader` stays independent of `vmm`.
- `SyscallEvent` is an **internal** kernel↔loader contract, *not* the frozen public wire API (the
  `channel` protocol + audit-log format); it can change without an `api:` marker.
- The `detail` blob is bounded (128 bytes): long paths truncate, and a `connect` captures the leading
  sockaddr bytes (a full IPv4 `sockaddr_in`, or a full IPv6 `sockaddr_in6` including the 16-byte
  address; ADR 008), falling back to the shorter v4 read if the full copy would over-read a short user
  buffer. The streaming consumer is a poll-with-sleep [`SyscallTracer::stream`] rather than the
  `epoll` wait sketched above, keeping the crate sync + `unsafe`-free; cgroup attribution rests on
  `cgroup_id_of_pid`; the per-syscall overhead is measured (`cargo xtask bench-trace`); and an
  attributed-workload test plus `cargo xtask trace-sandbox` (boot a real sandbox, stream its
  cgroup-attributed host footprint) exercise the whole path end to end.
