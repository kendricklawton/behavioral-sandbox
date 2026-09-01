# Security

The engine's whole reason to exist is running code you don't trust and getting a truthful account of
what it did. This page states what is trusted, what counts as a security bug (and what does not),
how to report one, and what happens after a report. The reporting mechanism also lives in
[`SECURITY.md`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/SECURITY.md) at the
repo root (GitHub surfaces it in the Security tab).

## No supported release yet

Until the first supported release (`v0.1.0`), every version is a development snapshot: no version
receives backported fixes, and nothing here should be treated as production-ready. This page states
the current stance, not a finished audit; the full **[threat model](./security-threat-model.md)** is its
companion.

## What is trusted, and what is not

The trust boundary is the CPU, not any software inside the guest: KVM, the host kernel, and the
driver running on the host (the VMM process, the jailer, the eBPF probes) are trusted; everything
inside the guest, including the in-guest agent, is not. The full boundary, its consequences, and
the attack-class-by-attack-class containment are the [threat model](./security-threat-model.md)'s, stated
once there. The posture that follows it everywhere: a sandbox with no explicit policy reaches no
network and holds minimal capability, and every allowance is explicit and recorded.

## Record integrity (host-signed)

The finalized audit record is signed with an Ed25519 host key. Verification via `bsx verify <record>` validates signature validity against the host key. The threat model details [record verification boundaries](./security-threat-model.md#record-integrity-beyond-the-guest).

Each record includes `sandbox_id` and `started_unix_ns` in the signed payload to correlate the audit event with host execution state.

## Release integrity (signed manifest)

Every release's `SHA256SUMS` carries a **detached Ed25519 signature** (`SHA256SUMS.sig`) made by
the release key. `install.sh` verifies it with the host's own `openssl` (never a binary from the
artifact being verified) against the public key pinned inside the script, before trusting the
manifest, hashing the tarball, or extracting anything; a download without a valid signature is a
hard fail. The pinned copy also lives at `release-key.pem` in the repo, and a test keeps the two
byte-identical.

The trust boundary of this scheme:

- **The anchor is the GitHub repo plus its Actions secrets.** A `curl | sh` of `install.sh` is
  same-origin with the pin, so the pin defeats a tampered *release asset*, not a compromised
  repo or CI secret. Supplying `BSX_RELEASE_PUBKEY` out of band is the stronger anchor.
- **No rollback or freshness protection.** An attacker controlling the download path can serve
  an older, validly signed release wholesale.
- **No revocation or expiry.** Rotation is committing a new pin; installers already distributed
  keep trusting the old key.
- **Self-attested modes.** Installing from an extracted package verifies only the per-file
  manifest inside the artifact (and says so); a local dev tarball without a sibling `.sig`
  verifies hashes only.
- `BSX_INSECURE_SKIP_SIGNATURE=1` is the explicit, loudly-warned opt-out (deny by default,
  every allowance explicit), needed only for pre-scheme releases.

## What counts as a security bug

Given those aims, a security bug is anything that breaks one of them:

- A guest escaping or weakening the KVM/jailer isolation boundary.
- A guest reaching the network past a deny-by-default (or explicitly configured) egress policy.
- A guest evading, disabling, or forging the host-side observation (the eBPF probes or the records
  they produce).
- A signed record that verifies **after** being altered, or a forged signature accepted by
  `bsx verify` without the host key (the record-integrity aim).
- A hostile guest causing a host panic, hang, or resource leak through the driver's public API. The engine is written against a no-panic rule on the host path; a case that breaks it is a bug worth reporting, not an expected limitation.
- Injected secrets (`--env` values, injected file contents) appearing in logs, errors, or the
  serial console.

Because this is an **engine, not a platform**, the multi-tenant concerns it deliberately does not own
are the hoster's responsibility, not a bug here; the line is the threat model's
[out-of-scope section](./security-threat-model.md#out-of-scope-engine-not-platform).

## What is not a security bug

The mirror list, so reports stay signal:

- **Anything that starts from a compromised host.** The host kernel, KVM, and the engine's own
  uid are trusted; an attacker who already has them has everything, no sandbox can claim
  otherwise.
- **Hosts below the supported floor.** An unsupported architecture, or a host kernel with neither
  `cgroup.kill` nor a version above the fallback floor, is refused by `bsx doctor`; weaknesses that require running there
  anyway are the operator's acceptance, not an engine bug. The same goes for an *unpatched* host
  kernel within the floor: patching the substrate is the operator's half of the contract.
- **`--unjailed` weakening the VMM's own confinement.** That flag is the documented dev-box
  opt-out: the guest stays behind KVM, but the VMM process runs unconfined. A jailer escape *with*
  the jail on is very much in scope; the absence of the jail after explicitly opting out is not.
- **The caller harming the caller.** The embedder and CLI user are trusted: budgets (`Limits`) and
  policy bind the *guest*. An embedder pointing the engine at a bad rootfs, exhausting their own
  host with a thousand sandboxes, or writing `RunResult` bytes somewhere unwise is misuse, not a
  vulnerability (the admission cap and typed errors are there to make misuse hard, not to defend
  against the owner). A `.bsx.toml` inside a tree you cloned is **not** the caller, which is why the
  keys that reach host execution and host trust are read from `~/.bsx.toml` rather than from a file
  found above the working directory ([Configuration](./cli-config.md)).
- **A hostile guest controlling the in-guest agent.** Assumed, by design; only effects that cross
  the boundary (escape, policy bypass, record forgery, host panic/hang/leak, secret exposure)
  count.
- **A guest burning its own budget.** CPU/memory/IO pressure *inside* the configured limits is the
  containment working and being metered, not a finding.
- **Dependency advisories with no path through the engine.** CI runs `cargo deny` (the full checks
  on the root workspace, an advisories-only pass on the detached eBPF and fuzz workspaces); an
  advisory in a dependency is handled in the open unless untrusted guest input can actually
  reach the vulnerable code, in which case it is a report like any other.

## After a report: how a fix ships

The reporting mechanics and response expectations live in
[`SECURITY.md`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/SECURITY.md) (private
GitHub advisory, acknowledgement within about a week, no bounty). What happens next, honestly scoped
to a pre-`v0.1.0` single-maintainer project:

1. **Confirm** the report against the model above, with a reproduction where possible; the
   discussion stays in the private advisory.
2. **Fix on `main`.** There are no release branches or backports before `v0.1.0`: the fix is a
   regular commit, with a regression test on the gate wherever the bug class allows one.
3. **Disclose together.** The timeline is agreed upon with the reporter in the advisory; the default
   ask is that the fix lands before publication. When it does, the GitHub advisory is published,
   and the reporter is credited if they want to be.

## Reporting a vulnerability

Report privately via GitHub's security advisories: the [Security
tab](https://github.com/kendricklawton/behavioral-sandbox/security), or [this direct
link](https://github.com/kendricklawton/behavioral-sandbox/security/advisories/new) to the reporting
form. Please do not open a public issue for a suspected vulnerability.
