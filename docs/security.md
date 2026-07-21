# Security

The engine's whole reason to exist is running code you don't trust and getting a truthful account
of what it did, so the security model is the product, not an afterthought. This page states what is
trusted, what counts as a security bug (and what does not), how to report one, and what happens
after a report. The reporting mechanism also lives
in [`SECURITY.md`](https://github.com/kendricklawton/agent/blob/main/SECURITY.md) at the repo root
(GitHub surfaces it in the Security tab).

## No supported release yet

Until the first tagged release (`v0.1.0`), every version is a development snapshot: no version
receives backported fixes, and nothing here should be treated as production-ready. This page states
the current stance, not a finished audit; the full **[threat model](./threat-model.md)** (assets, the
trust boundary, the adversary, and the attack-class-by-attack-class containment with the tests that
prove it) is its companion.

## What is trusted, and what is not

The trust boundary is the CPU, not any software inside the guest:

- **Trusted:** the host CPU's virtualization (KVM), the host kernel, and the driver running on the
  host (the VMM process, the jailer, and the host-side eBPF). The security-relevant observation and
  policy live here, out of the guest's reach.
- **Not trusted:** everything inside the guest, the untrusted code, and the in-guest agent that
  carries exec and I/O. The in-guest agent is a convenience, never a security boundary; a hostile
  guest is assumed to control it completely.

Two consequences follow directly. Host-side **syscall** visibility is coarse for a microVM (the
guest runs its own kernel, so its syscalls are serviced in-guest and never trap to a host
tracepoint); the strong cross-boundary signals are the guest's **network** (its tap device) and its
**resource use** (its cgroup), which the host observes directly. And a sandbox with no explicit
policy reaches no network and holds minimal capability: every allowance is explicit and recorded.

## Record integrity (host-signed)

The finalized audit record is **signed** with a host key the guest never sees (an `ed25519` detached
signature over the canonical record bytes, decision 034), so a consumer detects any alteration made
*after* the producing host. Verify a record with `agent verify <record>` (or against the trusted
public key directly). The trust root is the host signing key: this makes "tamper-evident" hold
off-host, but it does **not** protect against a *compromised producing host*, which can sign a
consistent lie (that is the hoster's key custody, and a compromised host is out of scope below). See
the [threat model](./threat-model.md#record-integrity-beyond-the-guest) for the full boundary.

## What counts as a security bug

Given those guarantees, a security bug is anything that breaks one of them:

- A guest escaping or weakening the KVM/jailer isolation boundary.
- A guest reaching the network past a deny-by-default (or explicitly configured) egress policy.
- A guest evading, disabling, or forging the host-side observation (the eBPF probes or the records
  they produce).
- A signed record that verifies **after** being altered, or a forged signature accepted by
  `agent verify` without the host key (the record-integrity guarantee, decision 034).
- A hostile guest causing a host panic, hang, or resource leak through the driver's public API.
- Injected secrets (`--env` values, injected file contents) appearing in logs, errors, or the
  serial console.

Because this is an **engine, not a platform**, multi-tenant concerns it deliberately does not own
(tenant authentication, quotas, billing) are the hoster's responsibility, not a bug here. The
engine's job is that its own tools cannot be weaponized and that it self-limits (deny-by-default
network, a dropped-uid jail, an own-euid orphan sweep); turning them into a safe multi-tenant
service is the hoster's.

## What is not a security bug

The mirror list, so reports stay signal. These are out of scope by the model above, not by
dismissal:

- **Anything that starts from a compromised host.** The host kernel, KVM, and the engine's own
  uid are trusted; an attacker who already has them has everything, no sandbox can claim
  otherwise.
- **Hosts below the supported floor.** An unsupported architecture or a host kernel older than the
  LTS floor is refused by `agent doctor` (decision 032); weaknesses that require running there
  anyway are the operator's acceptance, not an engine bug. The same goes for an *unpatched* host
  kernel within the floor: patching the substrate is the operator's half of the contract.
- **`--unjailed` weakening the VMM's own confinement.** That flag is the documented dev-box
  opt-out: the guest stays behind KVM, but the VMM process runs unconfined. A jailer escape *with*
  the jail on is very much in scope; the absence of the jail after explicitly opting out is not.
- **The caller harming the caller.** The embedder and CLI user are trusted: budgets (`Limits`) and
  policy bind the *guest*. An embedder pointing the engine at a bad rootfs, exhausting their own
  host with a thousand sandboxes, or writing `RunResult` bytes somewhere unwise is misuse, not a
  vulnerability (the admission cap and typed errors are there to make misuse hard, not to defend
  against the owner).
- **A hostile guest controlling the in-guest agent.** Assumed, by design; only effects that cross
  the boundary (escape, policy bypass, record forgery, host panic/hang/leak, secret exposure)
  count.
- **A guest burning its own budget.** CPU/memory/IO pressure *inside* the configured limits is the
  containment working and being metered, not a finding.
- **Dependency advisories with no path through the engine.** `cargo deny` gates the tree in CI;
  an advisory in a dependency is handled in the open unless untrusted guest input can actually
  reach the vulnerable code, in which case it is a report like any other.

## After a report: how a fix ships

The reporting mechanics and response expectations live in
[`SECURITY.md`](https://github.com/kendricklawton/agent/blob/main/SECURITY.md) (private GitHub
advisory, acknowledgement within about a week, no bounty). What happens next, honestly scoped to a
pre-`v0.1.0` single-maintainer project:

1. **Confirm** the report against the model above, with a reproduction where possible; the
   discussion stays in the private advisory.
2. **Fix on `main`.** There are no release branches or backports before `v0.1.0`: the fix is a
   regular commit, with a regression test on the gate wherever the bug class allows one.
3. **Disclose together.** The timeline is agreed with the reporter in the advisory; the default
   ask is that the fix lands before publication. When it does, the GitHub advisory is published,
   [`RELEASES.md`](https://github.com/kendricklawton/agent/blob/main/RELEASES.md) notes it, and
   the reporter is credited if they want to be.

## Reporting a vulnerability

Report privately via GitHub's security advisories: the
[Security tab](https://github.com/kendricklawton/agent/security), or
[this direct link](https://github.com/kendricklawton/agent/security/advisories/new) to the
reporting form. Please do not open a public issue for a suspected vulnerability.
