# Introduction

**Behavioral Sandbox** (**BSX**) is a local-first desktop sandbox for running untrusted code in
hardware isolation. Untrusted code runs inside a virtual machine, so the isolation boundary is the
CPU's, enforced by hardware virtualization: KVM on Linux, Hypervisor.framework on macOS. What a
sandbox can reach is settled before it starts, on the host side of that boundary.

It exists for the usual suspects: a third-party binary, a dependency's install script, an
AI-generated snippet, a sample under analysis. Everything stays on your own machine: no account, no
telemetry, no control plane, and nothing that stops working with the network off.

## Where this is, right now

**Sandboxes run, on Linux, and nothing is released.** BSX was built on Firecracker with a host-side
eBPF observer. That design was abandoned in favour of a local-first application on
[libkrun](https://github.com/containers/libkrun), and the engine implementing the old one was
deleted rather than carried alongside a replacement that did not exist yet. The replacement runs one
command in a sandbox (`bsx run`), a session on a guest pty (`bsx shell`), and a sandbox that
outlives the command that started it (`bsx up`, reached afterwards with `ls`, `exec` and `stop`),
and shows a guest's display in a window whose keyboard and pointer reach the guest (`--display`). The GUI application, GPU acceleration and
macOS are not written.

This book is short, and deliberately so: it describes the rules the project is built to and the
crates that are actually in the tree. Pages describing the previous design were removed rather than
left to describe code nobody can run. They are in git history if you want them.

## Reading this book

- **[Architecture](./architecture.md)**, the six design rules with the mechanism serving each, and
  what is in the tree.
- **[Security](./security.md)**, what is trusted, what counts as a security bug, and how to report
  one.

The repository's own operating manual is [`AGENTS.md`](https://github.com/kendricklawton/behavioral-sandbox/blob/main/AGENTS.md)
at the root: the design rules, the repo layout, the build, and the commit conventions. It is written
as standing instructions for a coding agent and doubles as the developer reference.

## License

Apache-2.0.
