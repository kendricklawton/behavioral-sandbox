# Fuzzing

Fuzzing here defends one specific, load-bearing invariant rather than the whole codebase. Because
isolation is hardware (a KVM microVM), a parser bug in our code is not an isolation escape the way it
would be in a software sandbox: the guest is already contained by the CPU. What a parser bug *can* do
is break guardrail 5, "a hostile or crashing guest, a failed probe, or a broken channel is a typed
error, never a host panic, hang, or leak." So the fuzzing target is the place where attacker-chosen
bytes meet the host path.

## What is fuzzed, and why

The **host↔guest channel decoders** (`crates/channel`). A hostile guest fully controls the in-guest
agent, so every time the host reads a `Response` it is parsing bytes an attacker chose. The decoders
must, for *any* input, return a value or a typed `ChannelError`, and never panic, loop unboundedly,
or allocate past `MAX_PAYLOAD`. The guest-side `Request` decoder is fuzzed too as defense in depth
(the host is trusted, but the in-guest agent should be just as unpanicky).

Lower-value targets (the Firecracker HTTP response parser, the eBPF record parsers) read
host/kernel-sourced input, not attacker-controlled input, so they are robustness hygiene, not a
security boundary, and are not fuzzed today.

## Two tiers

**In the gate, dependency-free (`crates/channel` `fuzz_tests`).** A property test that runs as part of
`cargo xtask ci` on stable, every time. It uses a tiny deterministic PRNG (no `proptest`/`arbitrary`
dependency, keeping the wire crate dependency-free and the supply-chain gate clean) to throw tens of
thousands of inputs at the decoders each run: arbitrary bytes, well-framed frames with random bodies
(to reach the message-body parsers), encode/decode round-trips, and every truncation of a valid
frame. Fixed seeds make any failure reproduce exactly, so it never flakes. This is the continuous
guard.

**Deep, scheduled + on demand (`fuzz/`, nightly + libFuzzer).** A `cargo fuzz` harness for long,
coverage-guided runs that explore far more of the input space than the in-gate pass. It lives in
`fuzz/`, a crate
**excluded from the workspace** with its own `[workspace]` table, so nightly and libFuzzer never touch
the everyday stable gate. It reaches the internal decoders through the channel crate's off-by-default
`fuzzing` feature (module `agent_channel::fuzz`), which exposes them without changing the default
build or the wire contract. CI runs this tier every night (`.github/workflows/fuzz.yml`): a bounded
15 minutes per target through the same `cargo xtask fuzz` a dev box uses; a crash fails the run and
uploads the reproducing input as a workflow artifact.

## Running it

The in-gate tier needs nothing extra:

```console
cargo test -p agent-channel        # includes the fuzz_tests property suite
```

The deep tier needs the toolchain once, then run a target:

```console
cargo install cargo-fuzz                 # one-time
rustup toolchain install nightly         # one-time

cargo xtask fuzz                         # channel_response, 60s (the default)
cargo xtask fuzz channel_request --seconds 300
cargo xtask fuzz channel_frame --seconds 0     # run until a crash or Ctrl-C
```

The targets are `channel_response` (host reads guest, the highest-value one), `channel_request`
(guest reads host), `channel_frame` (the shared framing), and `channel_handshake` (the magic +
version exchanged before any message). A crash is written under `fuzz/artifacts/` and replays with
`cargo fuzz run <target> fuzz/artifacts/<file>`; feed a minimized reproducer back as a
`crates/channel` unit test when you fix it.
