# 021. Syscall observability: a ring buffer of per-event records, a shared POD type, and an in-kernel filter *(2026-07-15)*

**Problem.** Phase 8's counter answers "how many `execve`s"; Phase 9 needs "which syscall, by whom,
on what", a **stream of per-event records** (pid, cgroup, `comm`, the opened path / connected
address), scoped to *one* sandbox's host workers, not the whole machine's. Three shapes have to be
chosen together: how events cross the kernel→userspace boundary, how the record type stays consistent
across that boundary, and where the "watch one sandbox" filter lives.

**Decision.** Three coupled choices, extending decision 020's loader:
- **A ring buffer (`BPF_MAP_TYPE_RINGBUF`), not a perf event array.** The three `sys_enter_*`
  tracepoint programs `output` a fixed-size record into one MPSC `EVENTS` ring buffer; the loader
  drains it with a single in-order consumer ([`SyscallTracer::drain`]). The ring buffer is the modern
  (5.8+) replacement for per-CPU perf buffers: one shared queue, ordered, no per-CPU reassembly. A
  full buffer drops new events (best-effort observability, never blocking a syscall). Draining is
  **non-blocking** (returns 0 when empty); an `epoll`-backed blocking wait is the P9.3 consumer's job.
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

**Why.** The ring buffer + shared-POD pair keeps the eBPF side isomorphic to the driver side
(typed, ordered, no silent corruption, no leak), and the in-kernel filter is what makes "watch one
sandbox" honest rather than a userspace afterthought. The `execve`/`openat`/`connect` set is the
smallest that shows all three record shapes (a program path, a file path, a socket address).

**Consequences and notes.**
- This is still the **host's** footprint, not the guest's (decision 020's honest limit stands): a
  microVM services its syscalls in-guest. The filter's cgroup axis is how P9.4 attributes events to a
  specific sandbox: `cgroup_id_of_pid` resolves a VMM pid to its cgroup id (the inode of the cgroup
  dir, which equals `bpf_get_current_cgroup_id`), and `watch_cgroup` scopes the trace to it. The bridge
  to the Firecracker track is plain `u32`/`u64` values, so `probes-loader` stays independent of `vmm`.
- `SyscallEvent` is an **internal** kernel↔loader contract, *not* the frozen public wire API (the
  `channel` protocol + audit-log format); it can change without an `api:` marker.
- The `detail` blob is bounded (128 bytes): long paths truncate, and a `connect` captures only the
  leading sockaddr bytes (a full IPv4 address; IPv6 partially) to avoid over-reading a short user
  buffer. Phase 9 is now complete: the streaming consumer (P9.3, a poll-with-sleep [`SyscallTracer::stream`]
  rather than the `epoll` wait sketched above, keeping the crate sync + `unsafe`-free), cgroup
  attribution (P9.4, `cgroup_id_of_pid`), the measured per-syscall overhead (`cargo xtask bench-trace`,
  P9.5), and the attributed-workload test (P9.6) all landed, with `cargo xtask trace-sandbox` (boot a
  real sandbox, stream its cgroup-attributed host footprint) as the exit-gate demo.
