# Security

The engine's whole reason to exist is running code you don't trust and getting a truthful account
of what it did, so the security model is the product, not an afterthought. This page states what is
trusted, what counts as a security bug, and how to report one. The reporting mechanism also lives
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
- **Not trusted:** everything inside the guest — the untrusted code, and the in-guest agent that
  carries exec and I/O. The in-guest agent is a convenience, never a security boundary; a hostile
  guest is assumed to control it completely.

Two consequences follow directly. Host-side **syscall** visibility is coarse for a microVM (the
guest runs its own kernel, so its syscalls are serviced in-guest and never trap to a host
tracepoint); the strong cross-boundary signals are the guest's **network** (its tap device) and its
**resource use** (its cgroup), which the host observes directly. And a sandbox with no explicit
policy reaches no network and holds minimal capability: every allowance is explicit and recorded.

## What counts as a security bug

Given those guarantees, a security bug is anything that breaks one of them:

- A guest escaping or weakening the KVM/jailer isolation boundary.
- A guest reaching the network past a deny-by-default (or explicitly configured) egress policy.
- A guest evading, disabling, or forging the host-side observation (the eBPF probes or the records
  they produce).
- A hostile guest causing a host panic, hang, or resource leak through the driver's public API.
- Injected secrets (`--env` values, injected file contents) appearing in logs, errors, or the
  serial console.

Because this is an **engine, not a platform**, multi-tenant concerns it deliberately does not own
(tenant authentication, quotas, billing) are the hoster's responsibility, not a bug here. The
engine's job is that its own tools cannot be weaponized and that it self-limits (deny-by-default
network, a dropped-uid jail, an own-euid orphan sweep); turning them into a safe multi-tenant
service is the deployer's.

## Reporting a vulnerability

Report privately via GitHub's security advisories: the
[Security tab](https://github.com/kendricklawton/agent/security), or
[this direct link](https://github.com/kendricklawton/agent/security/advisories/new) to the
reporting form. Please do not open a public issue for a suspected vulnerability.
