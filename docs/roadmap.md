# Roadmap: deferred capabilities

This chapter records where the engine is headed, the way the
[non-goals list](./embedding.md) records where it will never go. Each entry is an
engine capability: single-host, driver-API-shaped, usable by whatever hosts the
engine. None of them adds tenancy, billing, scheduling, or a dashboard, and none
of them runs a workload outside a microVM; an entry that needed to would be
wrong by design and belongs on the non-goals list instead.

Order here is rough priority, not a promise. A capability ships the way every
phase ships: with a working demo and, where it makes a performance claim,
benchmarked percentiles. Until an entry has both, it is intent, not a feature.

## Verifiable execution receipts

The audit record, completed into a self-contained proof. The record is already
host-observed and host-signed; the receipt binds it to its inputs by hash
(guest kernel, rootfs, argv, env, injected files) so that the signed object
states: this exact code, in this exact environment, did exactly these things.
A standalone `verify` command checks a receipt off-host with only the public
key, no engine install. The value is that an embedder can hand the receipt to
*their* auditor or customer; the engine stays a single-host runtime that
happens to emit evidence worth forwarding.

## Filesystem diff as a run artifact

Every run already writes through an overlay while the base image stays
untouched. This entry surfaces that overlay as a first-class output: the exact
set of files a run created, modified, or deleted, extractable for review,
discardable, or baked onto a base image to seed the next sandbox. That gives an
embedder inspectable side effects and layer-style image building without the
engine shipping a registry or build system: the diff is an output format, the
same way the audit record is.

## Fork-scale prewarmed clones

The pool restores prewarmed clones today; this entry drives the same snapshot
restore through a page-sharing memory backend so N concurrent clones share the
snapshot's pages copy-on-write instead of each holding a private copy. The
claim worth making (dozens of exec-ready sandboxes in under a second, most
memory shared) is exactly the kind that must arrive with percentiles measured
on the benchmark rig, per the measured-not-marketed rule.

## Policy as a declared, recorded contract

Egress is deny-by-default and every allowance is already explicit and recorded.
This entry gives allowances one declarative surface (endpoints, wall clock,
memory, artifact caps) that compiles down to the existing enforcement
(tc filters on the tap, cgroup limits, exec budgets), with the declared policy
and every violation embedded in the audit record. Nothing new is enforced; the
contract the engine already keeps becomes legible in one place, stated in the
record next to the evidence it produced.

## OCI images as a rootfs input

`run --image <ref>`: flatten an OCI image to an ext4 rootfs (agent baked in, as
with the built rootfs today) so existing container images run under hardware
isolation unchanged. This is an input format, not a platform feature: no
registry hosting, no image builds, no cache fleet. It is the adoption lever,
most code an embedder wants to contain already lives in an image, and it stays
inside the engine line for the same reason rootfs building does.
