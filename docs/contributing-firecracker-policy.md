# Firecracker version policy

Firecracker is the isolation boundary and it is **not a crate**: no advisory database, `cargo deny`
run, or Dependabot PR will ever mention it. Everything on this page exists because nothing else
watches it.

## Two constants, two different questions

Both live in `crates/vmm/src/spawn.rs`:

| Constant | Question it answers | Moves when |
|---|---|---|
| `MIN_SUPPORTED_FC_VERSION` | What is the oldest release we accept? | a series ages out of upstream's support table |
| `PINNED_FC_VERSION` | What do we test and hash? | we choose to move to a newer release |

The floor tracks upstream's window rather than our convenience, in both directions. It exists to reject
*unpatched* VMMs, not old ones: the same threat-model argument behind `ekvm doctor`'s host kernel floor
obliges us to accept any release upstream still patches. A floor above their oldest supported series
refuses a patched release for no safety gain; a floor below it silently blesses an unpatched one.

The pin appears in more than one place (the driver, `doctor.rs`'s sha256 set, `install.sh`, the
`Containerfile`, the CI workflows). **Every copy is held to the driver's constant by a gate test**,
because vigilance is not a mechanism: two copies once drifted for 21 months, and the container image
was later found shipping a release below the engine's own floor.

## A new API field may not raise the floor

A request field newer than the floor is sent **conditionally**, gated on the probed binary's version,
with a `_SINCE` constant recording where it arrived (see `clock_realtime` in
`crates/vmm/src/spawn.rs`). Sending it unconditionally silently drags the real floor up to that field's
release: that exact mistake broke restore on supported releases once.

Each gate carries a test asserting its `_SINCE` sits above the floor, so when the floor later rises past
it, the test fails, names the gate as dead code, and forces its deletion. Compat code for dead series is
deleted from `main`; release branches are where it survives.

## What runs on its own

`.github/workflows/firecracker-pin.yml` runs weekly and asks both questions: are we behind the latest
release (a `PINNED_FC_VERSION` prompt), and is our floor still the oldest series in upstream's support
table (a `MIN_SUPPORTED_FC_VERSION` prompt, in either direction). It parses upstream's table directly
rather than re-deriving their policy, and its parsers **fail loudly if the format moves** instead of
silently matching nothing.

## Raising the floor (when the weekly job goes red)

1. Set `MIN_SUPPORTED_FC_VERSION` to the oldest series still marked Supported upstream.
2. Delete dead gates: the `_SINCE` assertions fail on exactly the conditionals that are now dead, so
   make those fields unconditional.
3. Drop `doctor.rs` sha256 entries for series that left support.
4. Update the host-requirements prose (`README.md`, `RELEASES.md`, `docs/cli-install.md`).
5. `cargo xtask ci`, then the privileged gate against the pinned binary.
6. Commit as `feat(api)!` and tag the next minor: a floor raise is always a breaking change. The
   outgoing minor's release branch keeps the old floor and receives security backports under the support
   policy in [RELEASES.md](../RELEASES.md).

## Raising the pin (by choice)

Upstream's cadence is roughly one minor per quarter, so a quarter is the comfortable rhythm and the
support window is the hard deadline.

Read the release notes for API and snapshot-format changes, and re-read their swagger API definition
rather than only the changelog: fields get deprecated before they are removed, and the changelog does
not always say which. Hash the new binary, add its sha256 alongside the ones still in support, bump
`PINNED_FC_VERSION`, and run the privileged gate against the new binary. The gate tests will name every
other copy of the pin that needs to move with it.
