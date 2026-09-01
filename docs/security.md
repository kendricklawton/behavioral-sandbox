# Security

BSX's whole reason to exist is running code you don't trust. This page states what is trusted, what
counts as a security bug (and what does not), how to report one, and what happens after a report.
The reporting mechanism also lives in
[`SECURITY.md`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/SECURITY.md) at the
repo root (GitHub surfaces it in the Security tab).

## Nothing here runs a guest today

The Firecracker engine that enforced everything below was deleted when the project moved to libkrun,
and its replacement is not written yet. **There is no sandbox in this tree to attack.** This page
states the posture the replacement is being built to; it is not a description of running code, and
it is not an audit.

Until the first supported release (`v0.1.0`), every version is a development snapshot: no version
receives backported fixes, and nothing here should be treated as production-ready.

## What is trusted, and what is not

The trust boundary is the CPU, not any software inside the guest. KVM (or Hypervisor.framework), the
host kernel, and the host-side process acting as the virtual machine monitor are trusted; everything
inside the guest, including the in-guest agent, is not.

The posture that follows from it: a sandbox with no explicit configuration shares no host directory
and reaches no network, and what is shared **is** the policy, settled before the VM starts.

## What counts as a security bug

Once there is something to run, these are the reports worth making:

- A guest reaching the host filesystem, network, or another sandbox outside what was configured.
- A hostile guest causing a host panic, hang, or resource leak through the supervisor. The host path
  is written against a no-panic rule; a case that breaks it is a bug, not an expected limitation.
- Injected secrets (environment values, injected file contents) appearing in logs, errors, or the
  console.

Because this is an **application, not a platform**, multi-tenant concerns it deliberately does not
own are not bugs here.

## What is not a security bug

The mirror list, so reports stay signal:

- **Anything that starts from a compromised host.** The host kernel, the hypervisor, and the
  process's own uid are trusted; an attacker who already has them has everything, and no sandbox can
  claim otherwise.
- **Hosts below the supported floor.** A host without a working hypervisor is refused; weaknesses
  that require running there anyway are the operator's acceptance. The same goes for an *unpatched*
  host kernel: patching the substrate is the operator's half of the contract.
- **The caller harming the caller.** The person running BSX is trusted; policy binds the *guest*.
  Pointing it at a bad image, or exhausting your own machine with a thousand sandboxes, is misuse
  rather than a vulnerability.
- **A hostile guest controlling the in-guest agent.** Assumed, by design; only effects that cross
  the boundary count.
- **A guest burning its own budget.** Resource pressure *inside* the configured limits is the
  containment working, not a finding.
- **Dependency advisories with no path through the code.** CI runs `cargo deny`; an advisory in a
  dependency is handled in the open unless untrusted guest input can actually reach the vulnerable
  code, in which case it is a report like any other.

## After a report: how a fix ships

The reporting mechanics and response expectations live in
[`SECURITY.md`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/SECURITY.md) (private
GitHub advisory, acknowledgement within about a week, no bounty). What happens next, honestly scoped
to a pre-`v0.1.0` single-maintainer project:

1. **Confirm** the report against the model above, with a reproduction where possible; the
   discussion stays in the private advisory.
2. **Fix on `main`.** There are no release branches or backports before `v0.1.0`: the fix is a
   regular commit, with a regression test on the gate wherever the bug class allows one.
3. **Disclose together.** The timeline is agreed with the reporter in the advisory; the default ask
   is that the fix lands before publication. When it does, the GitHub advisory is published, and the
   reporter is credited if they want to be.

## Reporting a vulnerability

Report privately via GitHub's security advisories: the [Security
tab](https://github.com/kendricklawton/behavioral-sandbox/security), or [this direct
link](https://github.com/kendricklawton/behavioral-sandbox/security/advisories/new) to the reporting
form. Please do not open a public issue for a suspected vulnerability.
