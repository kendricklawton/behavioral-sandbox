# Security Policy

This project is a sandbox engine: isolation and a trustworthy audit trail are the product, so
security reports are taken seriously even this early. The security **model** (what is trusted, what
counts as a security bug and what does not, and how a fix ships) is documented in
[`docs/security.md`](docs/security.md).

**There is no supported release yet.** Until the first tagged release (`v0.1.0`), every version is
a development snapshot: no version receives backported fixes, and nothing should be treated as
production-ready.

## Reporting a vulnerability

Report privately via GitHub's security advisories: the
[Security tab](https://github.com/k-henry-org/agent/security), or
[this direct link](https://github.com/k-henry-org/agent/security/advisories/new) to the
reporting form. Please do not open a public issue for a suspected vulnerability.

## What to expect

This is an early, single-maintainer project, so the promise is honest rather than enterprise-grade:
expect an acknowledgement within about a week, and a good-faith effort to confirm the issue, agree a
disclosure timeline with you, and credit you (if you want it) when a fix lands. There is no bounty.
Coordinated disclosure is preferred: please give the fix a chance to land before going public.
