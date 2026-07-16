# Examples

Worked, end-to-end walkthroughs of using the engine. Where [Using the agent CLI](./cli.md) is the
reference (every flag, the config layering), these are task-shaped: pick the thing you want to do
and follow it through, output and all. They assume you've done [Installation](./cli-install.md) and
built the agent rootfs (`cargo xtask build-rootfs`).

- **[Running untrusted code](./examples-untrusted-code.md)** — run an untrusted script or a static
  binary in a microVM, feed it stdin and files, and read a structured result back.
- **[Observing a run from the host](./examples-observe-a-run.md)** — run something and watch what it
  did from outside the guest: its syscalls, its network, its resource use, and deny-by-default
  egress enforcement.

More example workloads (an untrusted binary under analysis, a CI job) land as the engine reaches
its packaging milestone.
