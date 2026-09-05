# Security

BSX's whole reason to exist is running code you don't trust. This page states what is trusted, what
counts as a security bug (and what does not), how to report one, and what happens after a report.
The reporting mechanism also lives in
[`SECURITY.md`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/SECURITY.md) at the
repo root (GitHub surfaces it in the Security tab).

## The tree runs guests, and has never been audited

The libkrun supervisor boots sandboxes: `bsx run`, `shell`, `up`, `exec` and `stop` work on a host
whose hypervisor answers (`/dev/kvm` on Linux, Hypervisor.framework on macOS ARM64) and a guest
image. So there is something here to attack. The host-side decoders of the guest's wire protocol
are fuzzed: cargo-fuzz targets seeded from a committed corpus the encoders generate, with a smoke
lane in CI.

What has not happened: any external review, any audit, any release. There is one maintainer. Until
the first supported release (`v0.1.0`), every version is a development snapshot: no version receives
backported fixes, and nothing here should be treated as production-ready. This page states the
posture the code is written to; it is not evidence that the code achieves it.

## What is trusted, and what is not

The trust boundary is the CPU, not any software inside the guest. KVM (or Hypervisor.framework), the
host kernel, and the host-side process acting as the virtual machine monitor are trusted; everything
inside the guest, including the in-guest agent, is not.

The monitor process is one trusted component with a large surface, and `--display` widens it: a VM
given a display loads virglrenderer and Mesa into the monitor and opens the host GPU's render node,
so guest-controlled data reaches a renderer running with the operator's privileges. That is measured
in [Architecture](./architecture.md) under "What crosses the GPU boundary". A headless VM does not
open it. `--gpu` widens the surface differently and further: a display's guest data reaches
virglrenderer as pixels to decode, while a `--gpu` guest is handed the 3D submission path, so
untrusted code composes virgl (and, where the host renderer carries Venus, Vulkan) commands that a
renderer executes with the operator's privileges. That is why it is a toggle: off by default,
printed in the posture, refused where libkrun lacks the feature. Without `--gpu`, nothing in the
guest gets GPU acceleration, so a display is surface the feature costs, not a capability the
sandbox grants; `--gpu` is the named grant of the wider path.

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
