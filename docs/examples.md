# Examples

Worked, end-to-end walkthroughs of using the engine. Where [Using the agent CLI](./cli.md) is the
reference (every flag, the config layering), these are task-shaped: pick the thing you want to do
and follow it through, output and all. They assume you've done [Installation](./cli-install.md) and
built the agent rootfs (`cargo xtask build-rootfs`).

- **[Running untrusted code](./examples-untrusted-code.md)**, run an untrusted script or a static
  binary in a microVM, feed it stdin and files, and read a structured result back.
- **[Observing a run from the host](./examples-observe-a-run.md)**, run something and watch what it
  did from outside the guest: its syscalls, its network, its resource use, and deny-by-default
  egress enforcement.
- **[Containing an agent](./examples-agent-containment.md)**, run a scripted agent (no model, no
  secrets) egress-policed to one endpoint, and prove from the host record exactly what it reached and
  what was blocked, even though the agent's own transcript can't tell the difference.
- **[Analyzing an untrusted binary](./examples-untrusted-binary.md)**, run a static ELF you have no
  source for and let the host report every file it opened and every address it tried to reach.
- **[Running a CI job from a fork](./examples-ci-job.md)**, run an untrusted pull request's tests in
  a sandbox that is denied the network by default, with a host record proving it couldn't phone home.
