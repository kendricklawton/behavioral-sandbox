# 002 — Talking to the guest: vsock and a tiny agent

> Phase 2 of the sandbox engine. Phase 1 booted a microVM and read its serial console; Phase 2
> turns "a VM boots" into "I handed it a command and captured stdout, stderr, and the exit code."
> The host reaches a small in-guest **agent** over **vsock** and speaks a framed protocol:
> `exec(argv, stdin)` in, a `RunResult` out.

```rust
let sandbox = Sandbox::boot(Limits::default())?;
let out = sandbox.exec(&["echo".into(), "hi".into()], b"")?;
assert_eq!(out.stdout, b"hi\n");
assert_eq!(out.exit_code, 0);
```

This is the engine's first real *interaction* with the guest. Everything later — a language
runtime (Phase 3), a network policy the guest can actually exercise (Phase 4), the eBPF flight
recorder watching a real workload (Phase 8+) — needs a way to put work in and get results out. That
way is this chapter.

> **Honest status.** The whole exec path — the vsock `CONNECT` handshake, the channel handshake,
> the request/response round trip, timeouts, injected files, artifacts — is built and tested
> **against the real guest agent**, with only the Firecracker vsock socket faked (a unix
> socketpair). A privileged smoke test proves real Firecracker boots with the vsock device
> attached. The one thing not yet wired end to end is the agent running *inside the guest*: it
> isn't baked into the rootfs until Phase 3, and it only learns to bind vsock (rather than a unix
> socket) there too. So the literal in-microVM `exec("echo hi")` transcript is the **first Phase 3
> demo** — the exec engine is done here; the last inch is a rootfs concern. See "What's still
> stubbed" below.
>
> *(Update, P3.1: closed. `cargo xtask build-rootfs` bakes the agent — now with an `AF_VSOCK`
> listener — into an Alpine-based image, and `exec("echo hi") → hi, exit 0` runs in a real microVM.
> See `ARCHITECTURE.md` decision 003.)*

## Why not just use the serial console?

Phase 1 already reads the guest over a serial port (`ttyS0`), so the cheap move is to open a
*second* serial port and shovel commands over it. We rejected that as the transport (decision 002).

A serial line is a **single, un-flow-controlled byte stream**. To drive commands over it you'd have
to multiplex stdin, stdout, stderr, and control messages onto one wire, invent your own framing
*and* back-pressure, and share the line with the boot console — all the work of a real protocol
with none of the machinery. The other obvious option, **networking + SSH**, is worse for us: it
drags tap/virtio-net forward (Phase 4) before we have any egress control, so the guest would need a
network *just to be driven* — a direct hit to **deny-by-default** (a sandbox with no policy should
reach nothing). It's also a large attack surface for "run one command."

**vsock** is the purpose-built answer. It's a socket family (`AF_VSOCK`) designed for host↔guest
comms: no IP, no DHCP, no tap, no guest networking at all. A guest is addressed by a **context ID**
(`CID`) and a **port**, exactly like `(IP, port)` but on a virtio transport the hypervisor
mediates. Deny-by-default stays intact — the guest can talk to the host and nothing else.

## The transport: virtio-vsock, and a socket on each side

Firecracker implements vsock as a virtio device. Enabling it is one more API `PUT`, alongside the
Phase 1 boot calls:

```
PUT /vsock  { guest_cid: 3, uds_path: "<scratch>/v.sock" }
```

Two things fall out of that config:

- **The guest** gets a vsock device. Our agent binds `AF_VSOCK` port **1024** (`AGENT_VSOCK_PORT`)
  and accepts connections. (`guest_cid: 3` — CIDs 0–2 are reserved; 3 is the conventional first
  guest.)
- **The host** doesn't speak `AF_VSOCK` directly. Firecracker multiplexes all guest vsock traffic
  through the **unix domain socket** named by `uds_path`. This is the same shape as the Phase 1 API
  socket: a `UnixStream` over `std`, no new dependency, host path still `unsafe`-free.

To open a connection to a guest port, Firecracker defines a tiny text handshake on that UDS: the
host connects, writes `CONNECT 1024\n`, and Firecracker replies `OK <host_port>\n` once the guest
side is accepted (or closes the connection if nothing is listening on that port). After the `OK`
line, the socket is a **raw bidirectional byte stream** straight to the agent.

### The one-byte-at-a-time ack read (a real bug, avoided)

There's a sharp edge in reading that `OK <port>\n` line. The natural thing is a buffered read —
grab a chunk, find the newline. But the guest agent sends *its* first protocol bytes (the channel
handshake, below) **immediately** after the connection is established. A buffered read of the ack
would happily pull those bytes into its buffer too, and then the channel layer — reading the same
stream — would find the handshake already gone. Desync on the very first message.

So `read_connect_ack` (`crates/vmm/src/vm.rs`) reads the ack **one byte at a time** and stops the
instant it sees `\n`, leaving every subsequent byte for the channel. It's slower by a few syscalls,
on a line that's ~12 bytes, once per exec — a non-issue — and it's the only correct framing when
two protocols share a stream with no delimiter between them.

## The channel: a small framed protocol

Once the raw stream is up, host and guest speak a protocol of our own (`crates/channel`). It's
deliberately tiny and dependency-free — no serde, no async — because both endpoints must stay
small (the guest agent) and `unsafe`-free (the host).

**Handshake.** Each side opens with 6 bytes: a 4-byte magic `AGCH` and a 2-byte little-endian
**version** (currently `1`). A mismatched magic or version is a typed error, not a mis-parse. This
matters because the host driver and the guest agent are **separately built binaries** that can skew
across rebuilds — the version byte turns "silent garbage" into "refused, clearly."

**Frames.** After the handshake, every message is length-prefixed:

```
| tag: u8 | len: u32 (LE) | payload: [u8; len] |
```

`len` is bounded by `MAX_PAYLOAD` (1 MiB); an oversized length is rejected before a single byte of
payload is read, so a hostile or buggy guest **cannot drive an unbounded allocation**. This is the
same discipline as Phase 1's HTTP `Content-Length` reads: never read to EOF, never trust a
delimiter, always frame by a bounded length. The tag says what the frame is:

| tag | direction | message |
|----:|-----------|---------|
| 1 | host→guest | `Exec { argv, stdin, artifacts, timeout_ms }` |
| 6 | host→guest | `PutFile { path, data }` — inject a file into the run's working dir |
| 2 | guest→host | `Stdout(bytes)` |
| 3 | guest→host | `Stderr(bytes)` |
| 7 | guest→host | `File { path, data }` — a requested artifact |
| 4 | guest→host | `Exit { code }` — terminal |
| 8 | guest→host | `TimedOut { elapsed_ms }` — terminal |
| 5 | guest→host | `Error(msg)` — terminal |

A run is: optional `PutFile`s, then one `Exec`, then a stream of `Stdout`/`Stderr`/`File` frames,
ended by exactly one terminal frame. The host aggregates the stream into a `RunResult { exit_code,
stdout, stderr, files }`, bounded by a 16 MiB output cap (`MAX_EXEC_OUTPUT`) so a flooding guest
can't grow host memory.

**Type-state, not free functions.** The public API is `ClientConnection` / `ServerConnection`: the
handshake happens *on construction*, and each type exposes only its role's operations. Sending a
message before the handshake, or mixing up client/server roles, is a **compile error**. The raw
codec stays `pub(crate)`.

## The guest agent — convenience, never containment

The in-guest half (`crates/guest-agent`, the `agent-guest` binary) is a small, statically-linked
(musl) Rust program. Per connection it: reads any `PutFile`s into a fresh per-run working directory
(path-checked against `..`/absolute escapes), spawns the `Exec` command with that cwd, feeds it
`stdin` on its own thread, drains stdout/stderr on two more (a single-threaded read-then-forward
would deadlock on output past a pipe buffer), and reports the terminal frame.

The load-bearing rule, and a **spine tombstone**: the agent carries exec and I/O **only**. It is a
convenience, never part of the trust boundary. Containment is the CPU/KVM boundary — a compromised
agent must not be able to escape the microVM, because it was never what held the guest in. If a
future phase is ever tempted to move a *security* check into the agent, the design is wrong.

## Failure is a fault domain: the error taxonomy (P2.7)

A new channel is a new way for things to break — a guest that never connects, an agent that dies
mid-command, a hung command, a half-written frame, a flooding writer. The invariant (spine property
five) is that **every one of these is a typed, deadline-bounded `VmmError` — never a host panic,
hang, or leak.** The host path is `#![forbid(unsafe_code)]` and the CI gate denies `unwrap`/`expect`
outside tests, so "no panic" is enforced mechanically; the taxonomy makes the *failures*
legible. `VmmError` sorts them into three buckets:

- **Boot / infra** (`NoKvm`, `Artifact`, `Timeout`, `Vmm`) — the host couldn't stand the VM up. A
  subtle member: vsock **establishment** failures (the socket connect, the `CONNECT` ack, *and the
  channel handshake*) live here too. Establishment is infra — it's where "the guest agent isn't
  listening yet" shows up — even though the handshake is technically protocol-layer.
- **Channel / transport** (`Channel`) — a **steady-state** framing/IO fault on an
  already-established connection: a `send_request`/`recv_response` that hits EOF or a bad frame
  mid-exec. Preserves the underlying `ChannelError` source.
- **Guest fault** (`GuestExec` — the agent couldn't run the command; `ExecTimeout` — it outran its
  wall-clock budget and was killed; `OutputCap` — it flooded output past the cap).

The distinction that took the most care: **a crash is not an error.** A command that merely exits
non-zero — *including dying by signal*, which the agent reports as exit code `128 + signal` (a
SIGKILLed process comes back as `137`) — is a faithful `RunResult`, not a `VmmError`. A segfault
inside the sandbox is a *result the caller inspects*, not a failure of the engine. Typed errors are
reserved for infra, transport, and guest-agent faults. P2.8 pins exactly this boundary with two
tests: a command the guest can't spawn → `VmmError::GuestExec` (a typed error), and `kill -9 $$` →
`RunResult { exit_code: 137 }` (a faithful result).

Two refinements are deliberately deferred, and safe to add later because `VmmError` is
`#[non_exhaustive]`: a dedicated `GuestUnavailable` variant (splitting "agent not listening yet"
out of `Vmm`), which the first retry/warm-pool caller in Phase 5 will want; and a `kind()` category
classifier, for the first caller that needs to *branch* on bucket (today `agent run` just renders
the error to a human and exits 2).

## Liveness is the transport's job

The framing layer sets **no timeouts** — it's transport-agnostic. Every connection instead sets
read/write **deadlines on the concrete socket** before wrapping it, so a dead-or-stalled peer
surfaces as a typed timeout rather than a hung thread. The guest agent's unconditional pipe-drain
only bounds the guest *given* that write deadline (a host that stops reading makes the agent's
forward time out → drain-and-discard → the child exits). A silent hung *command* is a separate axis,
bounded by the per-exec **wall-clock timeout** (`timeout_ms` in the `Exec` request): the agent
polls its child against a deadline, SIGKILLs and reaps it past the deadline, and replies `TimedOut`,
which the host maps to `VmmError::ExecTimeout`. The host self-clamps to a ceiling, so a buggy caller
can't ask for an infinite budget.

## What's still stubbed (and who owns it)

- **The agent isn't in the rootfs, and doesn't bind vsock yet.** Today the `agent-guest` binary
  listens on a **unix socket** (which makes the entire exec path runnable and testable on the host,
  no VM), and rejects a `vsock:` listen spec. Baking the static agent into the rootfs and teaching
  it `AF_VSOCK` is a Phase 3 concern (P3.1's reproducible rootfs build). That's why the demo at the
  top of this page is a KVM-free test against the real agent, and the true in-microVM transcript is
  the first Phase 3 deliverable.
- **Large / streaming I/O.** Each injected file or artifact is one `≤1 MiB` frame. Whole-working-dir
  and chunked transfer are the block-device path (P3.4/P3.5), not the channel.
- **Process-tree kill.** The timeout SIGKILLs the *direct* child; a command that double-forks a
  grandchild holding the stdout pipe can still wedge the agent's connection until the grandchild
  exits (the host stays bounded throughout). The definitive fix is the cgroup killing the whole
  tree — Phase 6.

## Try it

```console
cargo test -p agent-vmm            # the exec path, KVM-free, against the real agent
cargo test -p agent-guest          # the guest agent's own integration tests
cargo xtask ci-privileged          # boots real Firecracker with the vsock device (needs /dev/kvm)
```

The KVM-free tests are the honest core of this phase: `exec_over_fake_vsock_runs_a_command` drives
`echo hi` through the real agent over a real `CONNECT` handshake and a real channel round trip, and
asserts `hi\n`, exit 0. The rest of the taxonomy — a guest that drops mid-exec (`Channel`), a
command that can't spawn (`GuestExec`), a signal-killed command (a faithful `RunResult`), an output
flood (`OutputCap`), a guest timeout (`ExecTimeout`) — each has its own test. Only the guest's
*location* (inside the VM vs. behind a fake socket) is stubbed, and Phase 3 closes that.
