# Quickstart

From a fresh clone to a first sandboxed run you can trust, observed from the host. This is the fast
path; each step links to its full chapter.

> **Linux + KVM only.** The engine needs `/dev/kvm` and a supported host (x86_64/aarch64, kernel
> ≥ 5.15). Run [`cargo xtask doctor`](./cli-install.md#supported-platforms), or `agent doctor` once
> built, to see exactly where your host sits before the first sandbox.

## 1. Stand it up

One command builds the guest image + probe object, installs the `agent`/`agentd` binaries, and boots
one sandbox to prove the whole stack works ([details](./cli-install.md#self-host-in-one-command)):

```console
git clone https://github.com/kendricklawton/agent && cd agent
cargo xtask setup        # report what your host is missing (KVM, firecracker, caps, tools)
cargo xtask self-host    # build + install agent/agentd, then boot a proof sandbox
```

Prefer to build without installing? `cargo xtask fetch-artifacts && cargo xtask build-rootfs && cargo
build` leaves `agent`/`agentd` under `target/`. To build with the Firecracker S3 bucket and the
Alpine CDN both offline, snapshot the pinned inputs first with
[`cargo xtask vendor`](./cli-install.md#vendoring-for-offline-builds).

## 2. Run untrusted code

`agent run` boots a microVM, runs one command inside it, and returns its output and exit code. The
sandbox is jailed by default (needs real root); on a dev box, `--unjailed` is the explicit opt-out
(the guest still runs behind KVM):

```console
agent run --unjailed -- python3 -c "print(2 ** 100)"
```

Repeated commands in one long-lived sandbox, a stateful session, are [`agent
shell`](./cli.md); the same lifecycle over a unix socket for any language is the [`agentd`
daemon](./daemon.md); embedding it in a Rust host is the [engine API](./embedding.md).

## 3. See what it did, from the host

The point of the engine is the tamper-evident, host-observed record of what the code actually
touched. Ask for it alongside the run, deny-by-default means it reaches no network unless you allow
it, and every allowance is recorded:

```console
# Allow exactly one egress endpoint; everything else is dropped at the tap and logged.
agent run --unjailed --net --allow 1.1.1.1:53/udp \
  --trace \                       # human-readable audit trail on stdout
  --record-summary run.json \     # compact, model-legible projection (for an agent's loop)
  -- python3 fetch_something.py
```

`--record` writes the full machine JSON; `--record-summary` writes the compact projection (what it
reached, what was **denied**, its resource envelope); `--watch` draws it live. The
[CLI chapter](./cli.md) covers all four faces, and [Observing a run](./examples-observe-a-run.md)
and [Containing an agent](./examples-agent-containment.md) walk real records end to end.

## Where to go next

- **[Using the agent CLI](./cli.md)**, every flag, the four record faces, sessions, `doctor`.
- **[Using the engine API](./embedding.md)**, embed the `Sandbox` lifecycle in a Rust host.
- **[Using the agentd daemon](./daemon.md)**, drive it over a unix socket from any language.
- **[Threat model](./threat-model.md)**, what is trusted, what the adversary is, what is assumed.
- **[Non-goals](./non-goals.md)**, what this engine deliberately is *not*, and why.
