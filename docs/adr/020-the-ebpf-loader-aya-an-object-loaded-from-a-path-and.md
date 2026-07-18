# 020. The eBPF loader: aya, an object loaded from a path, and links that drop with the loader *(2026-07-15)*

**Problem.** The eBPF track needs a shape for three things at once: what library builds and loads the
programs, how the compiled object reaches the loader, and who owns the in-kernel objects' lifetime.
Each has a wrong default that would leak into every later phase (P9 syscalls, P10/P11 tap, P12
cgroup). The object question is the sharp one: the idiomatic aya path (`aya-build` in a `build.rs`, or
`include_bytes_aligned!`) compiles the eBPF crate during a normal `cargo build`, which would drag
**nightly + `build-std` + `bpf-linker` into the everyday host gate** and break "the workspace is
stable and `cargo xtask ci` runs everywhere" (P8.1).

**Decision.** Three coupled choices:
- **aya, both sides.** `aya-ebpf` in `crates/probes` (in-kernel), `aya` (userspace, **sync**, no
  async runtime, matching the driver's no-background-threads posture) in `crates/probes-loader`. The
  loader's public shape is a typed handle (`ExecveCounter::{load, count}`) returning a typed
  `ProbeError`, the eBPF analogue of `VmmError` (no panic on the host path).
- **The object is a runtime-loaded build artifact, found by path.** `cargo xtask build-probes` builds
  it (separate nightly target); the loader reads the bytes at runtime from a path
  (`AGENT_PROBES_OBJECT` override, else the `build-probes` output). It is **not** linked into the
  loader binary (`include_bytes`) nor built by a `build.rs`, so the host workspace stays on stable and
  the CI gate stays runnable everywhere; the object is deployed alongside the guest kernel/rootfs.
- **Links drop with the loader; nothing is pinned.** The aya `Ebpf` owns the program, map, and
  attachment; its `Drop` detaches and frees them. Nothing is pinned into `/sys/fs/bpf`, so a crashed
  loader leaves no kernel residue, the eBPF analogue of the driver's no-leak teardown. Pinning stays
  opt-in, added only where a program must outlive its loader (not on the current path).

**Alternatives considered.**
- **`aya-build`/`include_bytes_aligned!` (the aya template default).** Rejected: it pulls the nightly
  eBPF build into every `cargo build`, breaking the stable-workspace / gate-everywhere split. The
  path-load costs a runtime file read and a deploy-time artifact, which the engine already has for the
  kernel/rootfs.
- **Pinning programs/maps into `/sys/fs/bpf` for a stable handle.** Rejected as the default: a pin
  outlives the process and is exactly the residue the no-leak guarantee forbids; it becomes opt-in only
  where lifetime genuinely must exceed the loader.
- **libbpf-rs instead of aya.** Rejected: aya is pure-Rust (no C toolchain / libbpf build), which fits
  the workspace's build story (nothing to vendor, stable-toolchain host path).

**Why.** The path-load is the one non-obvious call, and it is what preserves P8.1's stable-workspace
invariant while still giving the loader real bytes to load. aya + sync + typed errors + drop-owned
lifetime keeps the eBPF side isomorphic to the driver side (typed errors, no panic, no leak), so the
two halves of the engine share the same discipline.

**Consequences and notes.**
- Adding `aya` put `foldhash` (Zlib) in the tree; `deny.toml` gained `Zlib` deliberately, with a
  reason, when aya entered (the allowlist's stated policy).
- P10/P11 attach programs to real per-VM **taps** (in the driver's netns): the same drop-owned,
  no-pin lifetime must hold there, so a torn-down sandbox leaves no dangling `tc`/XDP filter, it
  composes with the netns teardown the driver already guards (decision 017).
- The `sys_enter_execve` counter is the host's footprint, not the guest's: a microVM services its own
  syscalls in-guest, so they never trap to these host tracepoints (the network + cgroup signals, not
  syscalls, are the strong cross-boundary ones, P10/P12).
- **BTF is a build requirement, not a default** (P8.5): the object carries BTF (the CO-RE portability
  path) only because the profile keeps `debug = true` *and* the target passes `bpf-linker`'s `--btf`
  link-arg, both off by default would ship a legacy-only, non-portable object. `build-probes` asserts
  the `.BTF` section is present so a regression fails the build, not a downstream kernel.
