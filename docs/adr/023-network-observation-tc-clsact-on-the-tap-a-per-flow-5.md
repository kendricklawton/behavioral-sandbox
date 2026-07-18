# 023. Network observation: `tc`/clsact on the tap, a per-flow 5-tuple map, observe-only *(2026-07-16)*

**Problem.** Phase 10 needs per-microVM network visibility: every packet a guest sends or receives,
counted at the host. Three shapes must be chosen together (as decisions 020/021 did for the loader and
the syscall record): the attach mechanism, the per-flow record the kernel writes and the loader reads,
and where the "watch one sandbox" scoping lives.

**Decision.** Three coupled choices, extending decision 020's loader.
- **`tc`/clsact, not XDP.** The guest's traffic crosses its tap on the host, so a `tc` classifier on the
  tap sees it. clsact is chosen because it gives one device **both** an ingress and an egress hook
  uniformly (`tap_ingress`/`tap_egress`), on any device and any BPF-capable kernel (no driver XDP
  support needed); generic XDP is RX/ingress-only, so it can't see egress-to-guest and would need `tc`
  for that half anyway. `tc` is also the natural home for Phase 11 enforcement (a denied flow returns
  `TC_ACT_SHOT`); P10 is **observe-only**, both hooks return `TC_ACT_OK`.
- **The record is a shared, dependency-free POD, read as raw bytes.** `crates/probes-common` gains
  `FlowKey` (the IPv4 5-tuple, host byte order, `#[repr(C)]` and padding-free with an explicit zeroed
  `_pad`, because it is a hash-map **key**: uninitialized padding would make two identical flows hash
  apart) and `FlowCounts` (per-direction packets + bytes), single-sourced across the kernel writer and
  the loader like `SyscallEvent`. The loader opens the map as raw `[u8; N]` key/value arrays and decodes
  them with `FlowKey::from_bytes`/`FlowCounts::from_bytes`, so it needs no `unsafe impl aya::Pod` and
  both crates keep `#![forbid(unsafe_code)]`. The header offsets are shared consts, and a pure
  `parse_ipv4_5tuple` (host-unit-tested) is mirrored in-kernel by `ctx.load` at those same offsets, so
  the two parsers can't drift.
- **Scoping is by interface, and (later) by netns.** P10.1/P10.2 attach by interface **name in the
  current netns**. Because a sandbox's tap lives in its **own** netns (decision 017), binding to the
  specific `fc0` for one sandbox means entering that netns, deferred to **P10.4**; the clean
  attach/detach on sandbox open/close is **P10.5**.

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
- **IPv4 only for now.** A non-IPv4 (or truncated) frame is skipped, counted nowhere; IPv6 is a later,
  additive widening of `FlowKey` and the parser.
- **This is the guest's own traffic**, unlike the syscall tracepoints (decision 021's honest limit): a
  microVM's packets cross its tap on the host, so network is the strong cross-boundary signal core
  property 1 leaves intact.
- **No leaked filter.** The classifier links are drop-owned (decision 020, nothing pinned), and a
  sandbox's netns teardown (`ip netns del`, decision 017) cascades the tap, its clsact qdisc, and the
  filters away, so a torn-down sandbox leaves no dangling `tc` program even if the loader is gone.
- **`FlowKey`/`FlowCounts` are an internal kernel↔loader contract**, not the frozen public wire API, so
  they can change without an `api:` marker (like `SyscallEvent`).
- P10.3 (export the per-VM stats), P10.4 (bind to the sandbox's netns tap), P10.5 (attach/detach on
  open/close), and P10.6 (the live guest-traffic test) build on this; the exit gate is live per-microVM
  network visibility.
