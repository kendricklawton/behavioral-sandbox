# Fuzzing

Fuzz targets guard the boundaries where **untrusted or external bytes enter the host process**. That
is the selection rule: if a parser reads bytes the host did not author, it wants a target.

The boundaries with targets today:

- The `ekvm-channel` decoder's framing, which is what a compromised in-guest agent talks to.
- The daemon's newline-JSON wire protocol.
- Signed audit-record envelopes, including the verifier's behavior on arbitrary mutations.
- The eBPF ring-buffer event deserializers.
- Config and policy parsing (`.ekvm.toml`, egress rules, agent config).

Run one locally against its corpus:

```console
cargo fuzz run <target>
cargo xtask fuzz-coverage <target>   # what that corpus actually reaches
```

## Two tiers in CI

- **`fuzz-smoke.yml`** runs per PR: a short, bounded run of *every* target, so a change that makes a
  parser instantly crash cannot land. It is a smoke test, not a search.
- **`fuzz.yml`** is the deep tier: coverage-guided runs over the accumulated corpora, on a schedule.

Neither is continuous. There is no OSS-Fuzz or equivalent wired up, which is recorded as a known gap
in the [introduction](./introduction.md#what-has-not-been-done).

## Corpus health

Corpus size is worth checking before trusting a target: a corpus of a handful of inputs means the
fuzzer has barely explored the input space, whatever the target's age suggests. Two targets are
currently thin, and the `ekvm-channel` handshake is one of them, which matters because it is the first thing
a compromised guest agent talks to on the host.

A crash reproducer belongs in the corpus permanently, alongside a unit test that pins the same case,
so the fix is protected by something cheaper than a fuzz run.

The `ekvm-channel` and `ekvm-protocol` crates also carry in-gate, dependency-free mutation tests as a
counterpart to libFuzzer, so the host-safe gate exercises the same parsers without the fuzzing
toolchain installed.
