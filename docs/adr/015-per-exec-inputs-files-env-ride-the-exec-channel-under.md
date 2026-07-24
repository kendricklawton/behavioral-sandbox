# 015. Per-exec inputs (files + env) ride the exec channel under a pinned secret-hygiene contract *(2026-07-14)*

**Context.** A real workload needs configuration and credentials inside the guest: input files and
environment variables. Env could ride several paths, baked into the rootfs, written as a file the
command sources, exported into the guest agent's own process, or carried per-exec on the wire, and
each path pulls differently. Process-level or image-baked env turns a run's secrets into state that
outlives the run (or into build-time state), which collides directly with a long-lived
(pre-warmed/pooled) VM where a later run must never inherit an earlier one's credentials. And
whatever carries secrets must *state* what the engine does with them: logs, error renderings, and the
serial console are host-observable surfaces an embedder will ship into its own telemetry, so "we
probably don't log it" is not a contract an SDK can be built on.

**Decision.**
- **Env is a per-exec field on `Request::Exec`** (wire protocol **v2**), applied by the guest agent
  to the **spawned command only** (`Command::env`, inherited across the cgroup trampoline's `exec`),
  never `set_var` into the agent's own process, so one run's secrets cannot reach the agent or a
  later run on a long-lived (pre-warmed/pooled) VM. Bounded like `stdin`: the whole request is one
  `≤ MAX_PAYLOAD` frame.
- **The protocol version gates the skew.** Adding the field changes the `Exec` frame, and an old
  agent would parse the new frame and silently run the command *without* its env (the body cursor
  ignores trailing bytes). For secrets/config that silent degradation is a correctness failure, so
  `PROTOCOL_VERSION` bumped 1→2 and a stale rootfs is a typed handshake error, not a quiet
  half-configured run.
- **The secret-hygiene contract is pinned** (doc'd on `RunningVm::exec_with_files`, enforced by leak
  tests): injected file contents and env **values** never appear in an engine log line, in any
  `VmmError`'s `Display`/`Debug`, or on the serial console; an error path may name a file *path* or
  an env *key*, never a value (the guest agent logs only the env *count*, a bulk key dump is a
  fingerprinting surface). Host-side wire copies the engine builds are **zero-wiped after send**,
  the channel's serialized payload buffer and the driver's request clones, best-effort by
  declaration: the caller's own buffers and the kernel's socket buffers are out of the engine's
  reach. The run's own `RunResult` is the one surface allowed to carry input bytes (it is the
  caller's data). The audit log inherits the contract: it records *that* inputs were injected
  (paths/keys/sizes or hashes), never contents.

**Alternatives considered.**
- **Agent-process or rootfs-baked env.** Rejected: process-level env outlives the exec (a pooled
  clone would hand run A's secrets to run B), and image-baked env makes secrets build-time state.
- **Env as an injected file the command sources.** Rejected as the default: it forces a shell
  wrapper, parks secrets on the run's filesystem for its whole lifetime, and needs the same hygiene
  contract anyway. (An embedder who wants it can still do it with `PutFile`.)
- **Appending env without a version bump** (an old agent tolerates trailing bytes). Rejected: that
  tolerance is exactly the silent-degradation path, the command runs without its env and nobody is
  told. The handshake exists to make skew loud.
- **A zeroizing-buffer crate.** Adopted *2026-07-21* (originally deferred: `fill(0)` at the two
  sites the engine owns was taken to cover the promise as stated). A dependency-audit prompt noted
  that `fill(0)` is dead-store-eligible, so under `--release` the wipe may be elided *entirely*, not
  merely left incomplete: the buffer is dropped on the next line, so the optimizer can prove the
  store is unobservable and delete it. That undercuts even the best-effort claim, so `eke-channel`
  now depends on `zeroize` and the two sites call `payload.zeroize()`, a volatile store the optimizer
  cannot elide. The two doors this was once deferred behind are weighed and settled: `zeroize` is
  `no_std` with zero transitive deps, so pulling it into the guest's static binary is negligible (the
  crate is "near dependency-free," not zero-dep, and says so); and the host path stays `unsafe`-free
  because the volatile write lives inside the audited crate, not our code (the alternative, a
  hand-rolled `write_volatile` loop, is the `unsafe` we declined to author). The socket-buffer and
  caller-buffer copies remain out of the engine's reach, so the wipe is still best-effort *in scope*,
  now elision-proof *within* that scope.

The public API is embedder-driven: every SDK-shaped caller passes files + env, and the engine's
observable surfaces are precisely where a hoster's log pipeline would exfiltrate a leaked value.
Making non-leakage a *tested contract*, a sentinel grepped out of every surface, with a positive
control proving the console capture is real, is what lets a downstream pin this crate and pass
production credentials through it.

**Consequences and notes.**
- `Sandbox` is the lifecycle surface (`open → exec_with_files → collect_outputs → snapshot →
  shutdown`, plus `kill_handle`/`vmm_pid`), jailed by default per decision 012; an embedder never
  reaches `RunningVm`.
- The leak tests are the contract's pin: `injected_secrets_reach_no_observable_surface` (no VM,
  host logs at TRACE, the real in-process agent's logs, every error rendering) and
  `injected_secrets_never_reach_the_console_or_host_logs` (real VM, console, host logs, the
  failing-injection error path). A new log line or error variant that touches exec inputs must keep
  values out; extending these tests is the review bar.
- `stdin` is deliberately *outside* the contract's never-log set today (nothing logs it either, but
  only file contents and env values are promised); widening the promise to stdin is a doc-plus-test
  change, not a design change.
