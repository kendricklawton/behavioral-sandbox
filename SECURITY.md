# Security Policy

This project is a sandbox engine — isolation and a trustworthy audit trail are the product — so
security reports are taken seriously even this early.

**There is no supported release yet.** Until the first tagged release (`v0.1.0`), every version
is a development snapshot: no version receives backported fixes, and nothing should be treated as
production-ready. The threat model (what's trusted: the CPU/KVM and the host kernel; what isn't:
everything inside the guest) will be documented as part of the hardening milestone in
[`ROADMAP.md`](ROADMAP.md).

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's security advisories: the
[Security tab](https://github.com/kendricklawton/agent/security), or
[this direct link](https://github.com/kendricklawton/agent/security/advisories/new) to the
reporting form. Please do not open a public issue for a suspected vulnerability.

What counts as a security bug here, given the project's own guarantees:

- A guest escaping or weakening the KVM/jailer isolation boundary.
- A guest reaching the network past a deny-by-default (or explicitly configured) egress policy.
- A guest evading, disabling, or forging the host-side observation (the eBPF probes or the
  records they produce).
- A hostile guest causing a host panic, hang, or resource leak through the driver's public API.
- Injected secrets (`--env` values, injected file contents) appearing in logs, errors, or the
  serial console.
