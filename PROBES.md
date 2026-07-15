# PROBES.md — host-side eBPF observability (Phase 8 writeup)

The engine has two halves. `ENGINE.md` documents the Firecracker driver: the hardware-isolation
boundary that *contains* untrusted code. This document is the other half: the host-side eBPF that
*observes and enforces* what that code does, from outside the guest where it can't be reached (spine
property 2). Phase 8 is the on-ramp: build, load, attach, and read one trivial program end to end,
and learn the machinery the later phases lean on (syscalls P9, tap network P10/P11, cgroup P12, fused
into the flight recorder P13).

The worked example is a counter: `count_execve` attaches to the `sys_enter_execve` tracepoint and
tallies how many `execve`s the host does, into two maps. It is deliberately small; the point is the
path, not the payload.

## The two crates

- **`crates/probes`** (`#![no_std]`, `#![no_main]`) holds the in-kernel programs. It builds for
  `bpfel-unknown-none`, not the host triple, so it is *excluded* from the workspace and pins its own
  nightly toolchain (`-Z build-std=core`, since rustup ships no prebuilt `core` for the BPF target).
  `bpf-linker` links the LLVM bitcode rustc emits into a BPF ELF. `unsafe` lives here (raw map-pointer
  derefs); the host/driver path stays `#![forbid(unsafe_code)]`.
- **`crates/probes-loader`** is the userspace side, built with **aya** (pure-Rust, no libbpf/C
  toolchain), synchronous (no async runtime, matching the driver). Its public shape is a typed handle
  (`ExecveCounter::{load, count, counts_by_pid}`) returning a typed `ProbeError` — the eBPF analogue
  of the driver's `VmmError`. It reads the compiled object from a **path** (`cargo xtask build-probes`
  output, or `AGENT_PROBES_OBJECT`), never `include_bytes!`/`build.rs`, so the host workspace stays on
  stable and `cargo xtask ci` runs everywhere (decision 020).

## eBPF program types

An eBPF program is attached to a *hook*, and its type is the hook's shape: what context it gets and
what it may do. Phase 8 uses a **tracepoint** (`#[tracepoint]`), a stable kernel-defined event with a
stable argument format — here `syscalls/sys_enter_execve`. Its context is read-only; it returns 0.
The later phases use other types: **tc/`classifier`** and **XDP** on a VM's tap (P10/P11), where the
context is a packet the program may inspect and drop; and **cgroup** hooks for per-sandbox accounting
(P12). Same load/attach/map machinery, different hook.

## Maps

Maps are the shared memory between the kernel program and userspace. Two here:

- **`PerCpuArray<u64>`** (`EXECVE_COUNT`), one slot. **Per-CPU** means each CPU has its own copy of
  the slot, so the program increments with a plain `+= 1` and no cross-CPU atomic (contention-free);
  the loader reads all per-CPU copies and **sums** them. This is the idiomatic pattern for a hot
  counter.
- **`HashMap<u32, u64>`** (`EXECVE_BY_PID`), per-PID counts, bounded at 4096 entries (maps are sized
  at load). A full map drops new keys; the per-CPU total stays authoritative.

Maps are **BTF-defined** (see below), so their key/value types are described in the object's BTF and
aya validates them at load.

## The verifier

Before the kernel runs a BPF program it *verifies* it: every path must be safe and terminate. You
learn its rules by hitting them. Two the counter demonstrates on purpose:

- **Bounded loops.** Walking the fixed 16-byte `comm` buffer to its NUL terminator is a loop whose
  bound is a compile-time constant, so the verifier can prove it terminates even with a data-dependent
  `break`. An *unbounded* `while` would be rejected. (Older kernels rejected all loops; bounded loops
  have been allowed since 5.3.)
- **Map access patterns.** A map lookup returns a pointer that may be null (key absent). The verifier
  **forbids dereferencing it without a null-check first**. `get_ptr_mut` returns an `Option`, so the
  `if let Some(slot) = ...` *is* the mandatory check; the deref happens only inside the `Some` arm,
  and we `insert` only on the miss (lookup-or-init).

The verifier runs **at load**, in the kernel, so a rejection needs a real load to surface — which is
why the verifier proof is a privileged test passing, not a host-gate check.

## CO-RE / BTF

**BTF** (BPF Type Format) is the kernel's compact description of its own types, exposed at
`/sys/kernel/btf/vmlinux`. **CO-RE** (Compile Once, Run Everywhere) uses it so one compiled object
runs across kernels whose structs are laid out differently: the object records *what field of what
type* it wants, and aya **relocates** those accesses against the running kernel's BTF at load. No
per-kernel recompile.

Two non-obvious build facts (a regression here ships a non-portable object, so `build-probes` asserts
the `.BTF` section is present):

- The object carries BTF only because the profile keeps **`debug = true`** (bpf-linker derives BTF
  from debug info) *and* the target passes **`bpf-linker --btf`** (off by default), via a
  `[target.bpfel-unknown-none]` link-arg.
- The counter reads no kernel struct fields yet, so it needs no *field-offset* relocations. Those
  arrive in Phase 9 (reading kernel structs). Here BTF is the map typing plus the load-time relocation
  path — the portability mechanism the later phases build on.

## Lifetime: no pinned residue

The aya `Ebpf` owns the program, its maps, and the live attachment. Dropping the loader (`Drop`)
detaches the program and frees the maps. Nothing is **pinned** into `/sys/fs/bpf`, so a crashed loader
leaves no kernel residue — the eBPF analogue of the driver's no-leak teardown (which reclaims taps,
netns, cgroups, and scratch dirs). Pinning stays opt-in, added only where a program must outlive its
loader (not on this path). This discipline matters more in P10/P11, where a leaked `tc` filter would
dangle on a torn-down sandbox's tap.

## Capabilities and the support probe

Loading and attaching the probes needs **`CAP_BPF`** (load programs/maps, read maps) and
**`CAP_PERFMON`** (attach a tracepoint via `perf_event_open`) — the two that split out of
`CAP_SYS_ADMIN` in Linux 5.8. **Not full root:** grant a loader binary just those with
`setcap cap_bpf,cap_perfmon+ep <binary>`.

`check_support()` is the dependency guard (the eBPF analogue of the driver's Firecracker-version
probe): before a load it checks kernel BTF and the two capabilities and, if either is missing, returns
a **legible typed error naming the requirement** (`ProbeError::Unsupported`) rather than letting the
load fail with a cryptic verifier reject or `EPERM`. A host that can't run the probes says so plainly.

## The hardware-isolation consequence (the honest limit)

`count_execve` counts the **host's** `execve`s, not the guest's. A microVM runs its own kernel, so
untrusted code's syscalls are serviced *in-guest* and never trap to a host tracepoint. This is the
price of spine property 1 (isolation is hardware): host-side syscall visibility is inherently coarse
for a microVM. The strong cross-boundary signals are **network** (the tap, P10/P11) and **resources**
(the cgroup, P12), which the host observes directly. We say this plainly rather than promise in-guest
syscall introspection the boundary can't deliver.

## Try it

```console
cargo xtask build-probes                       # builds the object (with BTF); asserts .BTF present
cargo build -p agent-probes-loader --example count_execve
sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/count_execve
target/debug/examples/count_execve             # unprivileged, with just the two caps
```

Or the privileged test, which spawns processes and asserts the counter moved and that a load+drop
leaves no pinned residue:

```console
cargo test -p agent-probes-loader --test counter --no-run
sudo <the-printed-binary> --ignored --test-threads=1
```
