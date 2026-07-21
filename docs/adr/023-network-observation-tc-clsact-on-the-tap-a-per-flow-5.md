# 023. Network observation: `tc`/clsact on the tap, a per-flow 5-tuple map, observe-only *(2026-07-16)*

**Context.** The engine needs per-microVM network visibility: every packet a guest sends or receives,
counted at the host. Unlike the syscall tracepoints (decision 021's honest limit), this is the guest's
**own** traffic: a microVM's packets cross its tap on the host, so network is the strong cross-boundary
signal that core property 1 leaves intact. Three shapes have to be chosen together (as decisions 020/021
did for the loader and the syscall record), and each pulls in its own direction: the attach mechanism
(host-visible on every BPF-capable kernel, and the natural home for later enforcement), the per-flow
record the kernel writes and the loader reads (single-sourced so the two sides can't drift, and
`unsafe`-free in both crates), and where the "watch one sandbox" scoping lives (a sandbox's tap sits in
its own netns, decision 017, so scoping is entangled with netns entry).

**Decision.** Three coupled choices, extending decision 020's loader.
- **`tc`/clsact, not XDP.** The guest's traffic crosses its tap on the host, so a `tc` classifier on the
  tap sees it. clsact is chosen because it gives one device **both** an ingress and an egress hook
  uniformly (`tap_ingress`/`tap_egress`), on any device and any BPF-capable kernel (no driver XDP
  support needed); generic XDP is RX/ingress-only, so it can't see egress-to-guest and would need `tc`
  for that half anyway. `tc` is also the natural home for later enforcement (a denied flow returns
  `TC_ACT_SHOT`); this decision is **observe-only**, both hooks return `TC_ACT_OK`.
- **The record is a shared, dependency-free POD, read as raw bytes.** `crates/probes-common` gains
  `FlowKey` (the IPv4 5-tuple, host byte order, `#[repr(C)]` and padding-free with an explicit zeroed
  `_pad`, because it is a hash-map **key**: uninitialized padding would make two identical flows hash
  apart) and `FlowCounts` (per-direction packets + bytes), single-sourced across the kernel writer and
  the loader like `SyscallEvent`. The loader opens the map as raw `[u8; N]` key/value arrays and decodes
  them with `FlowKey::from_bytes`/`FlowCounts::from_bytes`, so it needs no `unsafe impl aya::Pod` and
  both crates keep `#![forbid(unsafe_code)]`. The header offsets are shared consts, and a pure
  `parse_ipv4_5tuple` (host-unit-tested) is mirrored in-kernel by `ctx.load` at those same offsets, so
  the two parsers can't drift.
- **Scoping is by interface, and (later) by netns.** The first cut attaches by interface **name in the
  current netns**. Because a sandbox's tap lives in its **own** netns (decision 017), binding to the
  specific `fc0` for one sandbox means entering that netns, deferred to a later step; the clean
  attach/detach on sandbox open/close follows.

**Alternatives considered.**
- **XDP instead of `tc`.** Rejected: generic XDP is ingress-only and driver-dependent, so it can't
  count egress-to-guest and buys no portability over `tc` here; `tc`/clsact covers both directions on
  every device and is where enforcement will live.
- **A `PerCpuHashMap` for contention-free exact counts.** Deferred: the plain `HashMap` with a
  best-effort non-atomic read-modify-write matches `EXECVE_BY_PID` and is fine for observability; a
  per-CPU map is the accuracy upgrade if a later phase needs exactness.
- **Fold direction into the key** (`(flow, dir) -> {pkts, bytes}`). Rejected: rx/tx on the value is the
  more useful shape (one lookup gives a flow's both directions), and a directional 5-tuple already
  encodes its direction by which hook it crossed.
- **`unsafe impl aya::Pod` for `FlowKey`/`FlowCounts`** (so the loader could type the map directly).
  Rejected: it needs `unsafe` in one of the two `forbid(unsafe_code)` crates (the orphan rule forbids it
  in the loader); reading the map as `[u8; N]` and decoding with the shared `from_bytes` is unsafe-free
  and keeps the record single-sourced.

**Consequences and notes.**
- **Dual-stack (IPv4 and IPv6).** IPv4 parses into `FlowKey`/`FLOWS` and IPv6 into a parallel
  `FlowKey6`/`FLOWS6` (parallel types and maps, not a widened key, so the v4 path is unchanged; ADR
  008). A VLAN-tagged or truncated frame is still skipped and counted as an unparsed-L3 coverage
  signal, never silently dropped.
- **No leaked filter.** The classifier links are drop-owned (decision 020, nothing pinned), and a
  sandbox's netns teardown (`ip netns del`, decision 017) cascades the tap, its clsact qdisc, and the
  filters away, so a torn-down sandbox leaves no dangling `tc` program even if the loader is gone.
- **`FlowKey`/`FlowCounts` are an internal kernel↔loader contract**, not the frozen public wire API, so
  they can change without an `api:` marker (like `SyscallEvent`).
- Exporting the per-VM stats, binding to the sandbox's netns tap, attaching/detaching on open/close, and
  a live guest-traffic test build on this; the exit gate is live per-microVM network visibility.
