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

The **daemon's client wire** (`crates/agent-protocol`, `read_message`). `agent serve` decodes these
bytes off its unix socket from *any* client: the outermost untrusted-input boundary the engine
exposes, and higher-value than the channel decoder, which only ever sees a guest already contained
inside a VM. The hand-rolled line reader (bounded at `MAX_MESSAGE_BYTES`) and the schema gate that
run before `serde_json` must, for any input, return a value or a typed `ProtocolError`, never panic,
loop unboundedly, or buffer past the cap.

The **signed-record envelope** (`crates/probes-loader`, `verify`/`verify_chain`). A record is
verified precisely when the host that delivered it is *not* trusted (decision 034), so the envelope
bytes are attacker-relayed by design. The verifier must, for any input, return the canonical record
or a typed `VerifyError`, bounded at `MAX_ENVELOPE_BYTES`, and never panic.

The **eBPF-boundary parsers** (`crates/probes-common`, `SyscallEvent::from_bytes` and
`parse_ipv4_5tuple`) are fuzzed as defense in depth. The syscall record is kernel-written (trusted),
but `parse_ipv4_5tuple` reads a **guest-crafted** Ethernet frame off the tap, so the frame bytes are
attacker-controlled; both must be a value-or-`None` on any input, and the string-building accessors
must clamp on an attacker-influenced `detail_len` rather than read past the buffer.

The one remaining decode surface deliberately *not* fuzzed is the Firecracker HTTP response parser:
it reads bytes from the host-side, trusted VMM process, not attacker-controlled input, so it is
robustness hygiene rather than a security boundary.

## Three tiers

**In the gate, dependency-free (`crates/channel` `fuzz_tests`).** A property test that runs as part of
`cargo xtask ci` on stable, every time. It uses a tiny deterministic PRNG (no `proptest`/`arbitrary`
dependency, keeping the wire crate dependency-free and the supply-chain gate clean) to throw tens of
thousands of inputs at the decoders each run: arbitrary bytes, well-framed frames with random bodies
(to reach the message-body parsers), encode/decode round-trips, and every truncation of a valid
frame. Fixed seeds make any failure reproduce exactly, so it never flakes. This is the continuous
guard. The other three surfaces carry the same discipline, each a deterministic in-gate property
test: the envelope verifier in `crates/probes-loader` (byte flips, truncations, splices of a valid
envelope), the daemon wire in `crates/agent-protocol` (random bytes with injected newlines,
encode/decode round-trips, truncations, and the over-cap line bound), and the eBPF-boundary parsers
in `crates/probes-common` (arbitrary-length buffers at `from_bytes` and `parse_ipv4_5tuple` plus the
string accessors). `agent-protocol` uses `serde_json` (already a dependency) to build valid seeds;
`probes-common` stays zero-dependency with an inline PRNG.

**Deep, scheduled + on demand (`fuzz/`, nightly + libFuzzer).** A `cargo fuzz` harness for long,
coverage-guided runs that explore far more of the input space than the in-gate pass. It lives in
`fuzz/`, a crate
**excluded from the workspace** with its own `[workspace]` table, so nightly and libFuzzer never touch
the everyday stable gate. It reaches the internal decoders through each crate's off-by-default
`fuzzing` feature (`agent_channel::fuzz`, `agent_protocol::fuzz`) or the already-public parse surface
(`agent-probes-loader`, `agent-probes-common`), without changing any default build or the wire
contract. Each target is seeded from a committed `fuzz/seeds/<target>/` corpus of valid inputs (a
signed envelope, real protocol messages, a well-formed frame), so a fresh run starts *past* the
first-byte reject and spends its budget in the decode logic instead of rediscovering message shape;
`cargo xtask fuzz` folds those seeds in automatically. CI runs this tier every night
(`.github/workflows/fuzz.yml`): a bounded 15 minutes per target through the same `cargo xtask fuzz` a
dev box uses; a crash fails the run and uploads the reproducing input as a workflow artifact.

**Per-PR smoke (`cargo xtask fuzz-smoke`, on every pull request).** The middle tier, between the
in-gate property tests (every push, no toolchain) and the deep nightly run: the *real* fuzzer over
*every* target for a short bounded time (60s each, seeded), so a change that breaks a decoder is
caught on the PR that introduced it, not only that night. `.github/workflows/fuzz-smoke.yml` runs it
on `pull_request` and pushes to `main`; a dev runs the same command before pushing. This mirrors the
per-PR fuzzing rust-vmm and Cloud Hypervisor run on their device models, applied to our host-side
decoders. It is still nightly + libFuzzer, so it is **not** part of the host-safe `ci` gate.

**Seeing what a run reached.** `cargo xtask fuzz-coverage <target>` runs the target over its corpus
and seeds and writes a `coverage.profdata` (needs the nightly `llvm-tools` component:
`rustup component add llvm-tools --toolchain nightly`); a low reached-fraction means the target is
bouncing off an early check (stale seeds, an over-tight guard) rather than exercising the decode
logic, which a green run alone can't reveal. `cargo xtask fuzz-cmin <target>` minimizes a target's accumulated
on-disk corpus (one input per coverage feature) so replays stay fast; run it periodically and, if a
minimized input reaches a genuinely new path, promote it into the committed `fuzz/seeds/<target>/`.

## Running it

The in-gate tier needs nothing extra:

```console
cargo test -p agent-channel                # includes the fuzz_tests property suite
cargo test -p agent-probes-loader --lib    # includes the envelope mutation test
cargo test -p agent-protocol               # includes the daemon-wire property suite
cargo test -p agent-probes-common          # includes the eBPF-boundary parser property test
```

The deep tier needs the toolchain once, then run a target:

```console
cargo install cargo-fuzz                 # one-time
rustup toolchain install nightly         # one-time: libFuzzer's sanitizer flags are nightly-only

cargo xtask fuzz                         # channel_response, 60s (the default)
cargo xtask fuzz channel_request --seconds 300
cargo xtask fuzz channel_frame --seconds 0     # run until a crash or Ctrl-C

cargo xtask fuzz-smoke                    # every target, 60s each (the per-PR smoke)
cargo xtask fuzz-coverage protocol_message   # what did the corpus reach?
cargo xtask fuzz-cmin protocol_message       # shrink the accumulated corpus
```

You only need nightly *installed*, not as your default: `cargo xtask fuzz` invokes cargo-fuzz under
`+nightly` for you, so your default toolchain stays stable. The nightly CI job
(`.github/workflows/fuzz.yml`) runs the exact same `cargo xtask fuzz` command, so a green local run
and a green CI run mean the same thing.

The targets are `protocol_message` (the daemon reads any client's bytes, the outermost boundary),
`channel_response` (host reads guest), `signing_envelope` (the record verifier reading an envelope
relayed by an untrusted host), `channel_request` (guest reads host), `channel_frame` (the shared
framing), `channel_handshake` (the magic + version exchanged before any message), and `syscall_event`
(the eBPF-boundary parsers, defense in depth). A crash is written under `fuzz/artifacts/` and replays
with `cargo +nightly fuzz run <target> fuzz/artifacts/<file>` (libFuzzer needs nightly, which is why
`cargo xtask fuzz` selects it for you); feed a minimized reproducer back as an in-gate property test
in the target's crate when you fix it.
