<!--
Suspected vulnerability? Do not open a pull request. Use the private advisory form:
https://github.com/kendricklawton/behavioral-sandbox/security/advisories/new

Anything larger than a bug fix, a test, or a docs change should start as an issue, so the shape is
settled before you build against a pre-1.0 surface that is still moving. CONTRIBUTING.md has the terms.
-->

## What this changes

<!-- One or two sentences, plus the issue this closes if there is one. -->

## Which design rule it touches

<!--
The six rules are in docs/architecture.md. Name the one this change is closest to and why it holds,
or write "none" if it is a bug fix or a docs change. This is the first question in review either way.
-->

## Checklist

- [ ] `cargo xtask ci` passes locally
- [ ] Commits are signed off (`git commit -s`) and use Conventional Commits subjects
- [ ] New behavior has a test that was watched failing before it passed
- [ ] A public API change (`Sandbox`, `Limits`, `RunResult`, `VmmError`, the `bsx-channel`
      framing) carries the `api` scope, with `!` if it is incompatible

## Booting a guest

<!--
Anything that boots a microVM needs /dev/kvm, which pull requests from forks do not have. Say here
whether you were able to run it, and on what host and kernel.
-->
