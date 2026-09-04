# Architecture

What BSX is, the rules it holds itself to, and what is in the tree today.

## Scope

### What this is

BSX is a local-first desktop sandbox. Untrusted code runs inside a virtual machine, with the
isolation boundary enforced by the CPU through hardware virtualization: KVM on Linux,
Hypervisor.framework on macOS. It is a GUI application with a CLI beside it, both on one machine.

### Where this is, right now

**The tree boots sandboxes on Linux, and nothing is released.** BSX was built on Firecracker with a
host-side eBPF observer; that design was abandoned, and the engine implementing it was deleted
rather than carried alongside its replacement. The replacement runs on
[libkrun](https://github.com/containers/libkrun), a library that makes the calling process the
virtual machine monitor.

What is in the tree: the host/guest wire framing (`bsx-channel`), the in-guest agent
(`bsx-guest-agent`), the safe libkrun wrapper (`bsx-krun`), the process supervisor
(`bsx-supervisor`), the `bsx` CLI and its headless verbs, and the guest image build and the gate
(`xtask`), and the display path: a virtio-gpu scanout landing in host RAM and shown in a window
the VM's own process opens, with that window's keyboard and pointer going back as two virtio-input
devices, a second guest image that boots a Wayland compositor on it, and an opt-in virtio-snd card. `bsx-app` is the notebook of those runs, with a live run's display and input in the window and a start form that shows the posture before boot. What is not: GPU acceleration for the guest (see
"What crosses the GPU boundary" below for what does and does not), and macOS.

### Design rules

These are the rules the project holds itself to, stated so a change that breaks one is recognisable
as a design error rather than a trade-off. They describe intent and the mechanism serving it, not a
verified outcome.

1. **Isolation is hardware, not software.** Untrusted code runs in a VM under KVM or
   Hypervisor.framework. A change that moves the boundary into guest-side software is a design
   error, not an optimisation, and a shared-kernel shortcut taken to simplify things is the same
   error.
2. **Local-first. Nothing leaves the machine.** No account, no telemetry, no control plane, and no
   licence check that needs a server. A feature that cannot work on a laptop with the network off
   belongs to a different product.
3. **Deny by default.** A sandbox with no explicit configuration shares no host directory and has no
   network. What is shared **is** the policy: no in-kernel enforcer sits behind it, so the set of
   shared directories and the network backend are settled before the VM starts and are visible to
   the person starting it.
4. **An application, not a platform.** The product is a program on one person's machine. The unit is
   the sandbox; there is no tenant, no account, and no fleet. Mechanism that makes one machine's
   sandboxes work belongs here, and anything that must know who is paying is a different product.
   An AI model is a caller, never a component: it drives the app from outside.
5. **No panic, hang, or leak on the host path.** A hostile or crashing guest, or a helper that dies,
   should surface as a typed error. A leak here is a stranded VM holding somebody's laptop RAM, not
   a server you can reboot. This is what the code is written against; it is an aim, not a proven
   property, and the suite that exercised it went with the engine it tested.
6. **Measure rather than assert.** Boot, memory, and frame timings are reported as nearest-rank
   percentiles with the host and date they were taken on. Where a number cannot be defended, it is
   withdrawn rather than published. libkrun has no snapshot surface, so every boot is a cold boot.

## Index of crates

Directories stay short and packages carry the `bsx-` prefix, so a package is its directory plus that
prefix, with one exception: `crates/cli` builds `bsx`, the bare name going to the command a user
types. `cargo … -p` takes the **package**, a path takes the **directory**.

| Crate | Directory | Role |
|---|---|---|
| `bsx-supervisor` | `crates/supervisor` | Spawn, track, stop and reap the helper processes that are VMs. One value per live VM; `Drop` tears it down. |
| `bsx-krun` | `crates/krun` | The safe wrapper over libkrun, with the raw declarations private beneath it. The one crate that may use `unsafe`, because the library is C. |
| `bsx-channel` | `crates/channel` | The host/guest wire protocol. Nearly dependency-free framing (`zeroize`, for the post-send secret wipe, is the one dependency), shared verbatim by both ends. |
| `bsx-guest-agent` | `crates/guest-agent` | The in-guest agent. One command per connection, static musl, baked into the guest image. Not a security boundary. Its binary keeps the bare name `guest-agent`. |
| `bsx-record` | `crates/record` | The run record: posture, captured output and the guest's `/results`, one directory per run under the local data dir, written by the CLI and read by both binaries. |
| `bsx-input` | `crates/input` | The guest's keyboard and pointer: device shapes, reports, and the line grammar the replay file and the control socket's `input` session feed. |
| `bsx` | `crates/cli` | The `bsx` binary. No verbs today: the supervisor they call is not written. Package, binary, and command all share the name. |
| `bsx-app` | `crates/app` | The GUI application, on iced: the notebook of runs from `bsx-record`, a run's record with its display (leased over the control socket, uploaded to a wgpu texture) and output, a start form, stop, re-run, delete, and a shell in the operator's terminal through `bsx`. |
| `bsx-test-support` | `crates/test-support` | Test fixtures: a self-reclaiming scratch dir, a log sink, and the deterministic generator the in-gate fuzz suites use. |
| `xtask` | `xtask` | Dev orchestration: the gate, the guest image build, the vendor mirror. Never shipped, and never renamed: `cargo xtask` is a `--package xtask` alias. |

## What crosses the GPU boundary

Measured 2026-09-04 on one host: Intel Core i5-10310U with UHD Graphics (i915), Linux 7.2.2,
libkrun 1.19.4, libkrunfw 5.5.0, virglrenderer 1.3.0, Mesa 26.1.6. One host, one date; nothing here
is claimed for any other.

**Only 2D pixels cross, in one direction.** A guest draws into a DRM dumb buffer, its kernel
`virtio_gpu` driver sends the transfer and flush, and the frame arrives in host RAM. No guest
process has ever issued a 3D command, on this host, because no userspace driver in either image can.

### The host uses its GPU; the guest does not

A `--display` VM's monitor process holds seven file descriptors on `/dev/dri/renderD128` (the i915
render node) and maps Mesa's EGL, GLES and GBM alongside `libvirglrenderer`. A headless VM on the
same image holds none, and maps neither EGL nor GLES:

```console
$ bsx up --name gpuprobe --root artifacts/rootfs-guest --display 640x480
$ ls -l /proc/$(pgrep -f 'bsx __vmm')/fd | grep -c renderD128
7
$ awk '{print $6}' /proc/$(pgrep -f 'bsx __vmm')/maps | grep -E 'libEGL|libGLES|virgl' | sort -u
/usr/lib/libEGL_mesa.so.0.0.0
/usr/lib/libGLESv2.so.2.1.0
/usr/lib/libvirglrenderer.so.1.11.0
```

So `--display` is what brings the host GPU into a sandbox's blast radius. This is a property of the
host renderer, not a capability granted to the guest, and it is the reason virglrenderer belongs in
the trusted set on the [Security](./security.md) page.

### What the guest is offered

The guest gets a `virtio_gpu` card and a render node, and the device advertises 3D. Asking the host
renderer for each capset (rather than decoding the `SUPPORTED_CAPSET_IDs` bitmask) is answered for
VIRGL, VIRGL2, VENUS, CROSS_DOMAIN and DRM. `crates/cli/tests/gpu_probe.py` reports it, and
`a_display_guest_is_offered_a_3d_virtio_gpu_it_has_no_driver_for` pins it:

```
PROBE card0_driver virtio_gpu 0.1.0 (virtio GPU)
PROBE card0_param_3D_FEATURES 1
PROBE card0_capsets_answered VIRGL(1) VIRGL2(2) VENUS(4) CROSS_DOMAIN(5) DRM(6)
```

That list is not a statement about what the host can serve. Setting `NO_VIRGL`, which makes every
guest `ResourceCreate2d` fail, leaves the same five capsets answered.

### What did not run, and why

- **OpenGL in the guest.** Alpine's `mesa-dri-gallium` is built with Iris, llvmpipe and radeonsi
  only; `strings libgallium-26.1.6.so` finds no virgl driver. A guest with Mesa installed prints
  `virtio_gpu: driver missing` and falls back to `kms_swrast`, reporting
  `OpenGL core profile renderer: llvmpipe`. Alpine packages no virgl Gallium driver at all, so this
  is not reachable by adding a package.
- **Vulkan in the guest.** `mesa-vulkan-virtio` (Venus) installs its ICD, but `vulkaninfo` gets
  `ERROR_INITIALIZATION_FAILED` with no physical device. The cause is the host: Arch's
  virglrenderer 1.3.0 exports zero `vkr_` symbols and does not link `libvulkan`, i.e. it is built
  without Venus. Passing `VIRGL_RENDERER_VENUS` (`1 << 6`) to `krun_set_gpu_options` changes
  nothing, which is how the host was established as the limit rather than the flag.
- **Compute of any kind.** Follows from both of the above: no GL, no Vulkan, no guest driver.

Both guest-side results were taken against a throwaway image built by installing Mesa into a copy of
the guest tree; that image is a spike and is not in the repo.

### What this settles

GPU acceleration for the guest (phase 5) needs two things this host does not have, and neither is a
BSX code change: a Mesa build carrying the virgl Gallium driver in the guest image, and a
virglrenderer built with Venus on the host. Until both exist, `--display` is a 2D scanout and the
guest's own rendering is software.
