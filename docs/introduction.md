# Introduction

**Behavioral Sandbox** (**BSX**) is a local-first desktop sandbox for running untrusted code in
hardware isolation. Untrusted code runs inside a virtual machine, so the isolation boundary is the
CPU's, enforced by hardware virtualization: KVM on Linux, Hypervisor.framework on macOS. What a
sandbox can reach is settled before it starts, on the host side of that boundary.

It exists for the usual suspects: a third-party binary, a dependency's install script, an
AI-generated snippet, a sample under analysis. Everything stays on your own machine: no account, no
telemetry, no control plane, and nothing that stops working with the network off.

## Where this is, right now

**Sandboxes run, and nothing is released.** BSX runs on
[libkrun](https://github.com/containers/libkrun), a library that makes the calling process the
virtual machine monitor. It runs one command in a sandbox (`bsx run`), a session on a guest pty
(`bsx shell`), and a sandbox that outlives the command that started it (`bsx up`, reached
afterwards with `ls`, `exec` and `stop`), and shows a guest's display in a window whose keyboard
and pointer reach the guest (`--display`), with a desktop image that boots to a terminal in a
Wayland session there, and `--sound` for audio. Every run leaves a record, which `bsx ls --all`,
`show`, `rm` and `export` read, remove and package (one ustar file per run). `bsx-app` is the
notebook: every run, live and past, with its posture, output and results, a live run's display with
your keyboard and pointer going in, and a form that shows a sandbox's posture before it boots. It
opens on a menu naming the `bsx` and guest root it found, exports a run to one tar file, clears the
ended history behind a confirm, and keeps a theme pick across launches. On macOS ARM64 the same
tree signs (`cargo xtask sign`) and boots the same sandboxes under Hypervisor.framework, without
`--sound` or the guest input path (its libkrun builds neither backend) and with a guest's display
viewed in `bsx-app`. GPU acceleration for the guest is not written.

This book is short, and deliberately so: it describes the rules the project is built to, the
crates that are actually in the tree, and how a sandbox is run.

## Reading this book

- **[Running a sandbox](./running.md)**, the verbs, posture flags, configuration layering, what a run leaves behind, and the notebook.
- **[Architecture](./architecture.md)**, the six design rules with the mechanism serving each, and what is in the tree.
- **[Control socket & IPC](./control-ipc.md)**, local process discovery, display leasing, zero-copy memfd sharing, and host↔guest wire framing.
- **[Building guest images](./building-images.md)**, unprivileged rootfs assembly with `apk.static` and `fakeroot`, desktop closures, and lockfile verification.
- **[Security](./security.md)**, what is trusted, what counts as a security bug, and how to report one.

The repository's own operating manual is [`AGENTS.md`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/AGENTS.md)
at the root: the design rules, the repo layout, the build, and the commit conventions. It is written
as standing instructions for a coding agent and doubles as the developer reference.

## License

Apache-2.0.
