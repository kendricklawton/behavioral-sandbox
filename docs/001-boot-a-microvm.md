# 001: Booting a microVM from Rust

> Phase 1 of the sandbox engine. The demo: `agent run --demo-boot` boots a real Linux microVM
> under KVM, reads its serial console until the guest reaches userspace, prints the
> boot-to-userspace latency, and shuts down clean, repeatably, with no leaked processes or files.
> On the dev box cold boots land around **2–3.5 s** (best observed ~1.2 s; distribution below).

```console
$ AGENT_LOG=info cargo run -q -p agent-cli -- run --demo-boot
 INFO microVM reached userspace boot_ms=1276
booted microVM to userspace in 1276 ms
```

This is the "hello, KVM" moment. Everything the engine will do later (run code, snapshot,
observe with eBPF) stands on this: a hardware-isolated guest that boots and dies on command.

## What actually boots a Linux VM

A VM boot is the same contract as a physical boot, minus the firmware theatrics. Firecracker is a
**VMM** (virtual machine monitor): it asks the Linux kernel's **KVM** subsystem (`/dev/kvm`) for a
hardware-virtualized vCPU, lays out guest memory, loads a kernel into it, and starts executing.
The CPU itself enforces the isolation boundary (Intel VT-x / AMD-V). That's the whole point, and
the first property of the spine: *isolation is hardware, not software.*

Firecracker deliberately has **no BIOS/UEFI and no bootloader**. It uses the Linux **boot
protocol** directly: it loads an uncompressed kernel and jumps into it with a `boot_params`
structure already filled in. Three inputs make a boot:

1. **A kernel image.** It must be an *uncompressed* `vmlinux` (an ELF/PVH image), **not** a
   distro `bzImage` (that's a compressed, real-mode-stub-wrapped image a bootloader unpacks).
   Our pinned artifact is exactly that:

   ```
   $ file artifacts/vmlinux
   ELF 64-bit LSB executable, x86-64, ... statically linked
   ```

2. **A kernel command line** (`boot_args`): the same `console=…`/`root=…` string GRUB would
   pass. We use:

   ```
   console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=on
   ```

   - `console=ttyS0`: send the kernel console to the first **serial port**. There's no screen;
     serial *is* the console (more below).
   - `reboot=k panic=1`: on a panic, reboot after 1 s; `reboot=k` uses the keyboard-controller
     reset, which under Firecracker simply **exits the VMM**. Together they turn "guest died" into
     "process exited," which is exactly what we want for clean teardown.
   - `pci=off`: Firecracker has no PCI bus; skip probing it (faster boot, smaller kernel).
   - `random.trust_cpu=on`: trust the CPU's RDRAND to seed the RNG, so early userspace doesn't
     stall waiting for entropy. Shaves real milliseconds off the number below.

   Notably absent: `root=`. Firecracker **derives `root=/dev/vda`** from the drive we mark as the
   root device, so we don't hand-write it.

3. **A root filesystem** on a block device. Our rootfs is a plain **ext4 image**, a file that
   *is* a filesystem:

   ```
   $ file artifacts/rootfs.ext4
   Linux rev 1.0 ext4 filesystem data, ...
   ```

   Firecracker exposes it to the guest as a **virtio-block** device. `virtio` is the paravirtual
   I/O standard: instead of emulating a real disk controller register-by-register, host and guest
   share ring buffers in memory and just pass descriptors, for near-native I/O with a tiny driver.
   The guest kernel sees it as `/dev/vda`, mounts it as `/`, and runs its `/sbin/init`.

## Driving Firecracker: HTTP over a unix socket

Firecracker doesn't take all this on the command line. It boots into an **idle state** and
exposes a small **REST API on a unix domain socket** (`--api-sock`); you configure the machine
with a few HTTP `PUT`s and then start it. Our boot sequence (`crates/vmm/src/vm.rs`):

```
PUT /boot-source     { kernel_image_path, boot_args }
PUT /drives/rootfs   { drive_id, path_on_host, is_root_device: true, is_read_only: false }
PUT /machine-config  { vcpu_count, mem_size_mib }
PUT /actions         { action_type: "InstanceStart" }     ← the guest starts here
```

We chose this API-socket path deliberately (see `ARCHITECTURE.md` decision 001): it's the only
control surface that also carries pause/snapshot/shutdown, which later phases need.

The lesson hiding in here is **HTTP itself**. Rather than pull in an async runtime and an HTTP
client for five requests, we hand-rolled the sliver of HTTP/1.1 they need over
`std::os::unix::net::UnixStream` (`crates/vmm/src/firecracker.rs`). Doing that teaches you where
the sharp edges are:

- **Keep-alive means "read to EOF" never returns.** HTTP/1.1 connections stay open by default, so
  a client that reads until end-of-stream hangs forever. You frame the response by its
  `Content-Length` header instead, or (as we do) open a **fresh connection per request** and send
  `Connection: close`.
- **Success is `204 No Content`** with an *empty* body. A client that blindly waits for a body
  hangs on every successful call. Errors come back `4xx` with a JSON `{"fault_message": "..."}`,
  which we surface as a typed error.
- **Timeouts are non-negotiable.** Every socket read/write has a deadline, so a wedged VMM is a
  typed `Timeout`, never a hung host thread. (Spine property five: *no panics, hangs, or leaks on
  the host path.*)

## Reading the guest's mind: the serial console

With `console=ttyS0`, the guest writes its console to an emulated **16550 UART**. Firecracker
wires that UART to **its own stdout**. So "read the guest console" is literally "read the child
process's stdout": we spawn `firecracker` with a piped stdout and a background thread drains it
into a buffer.

One subtlety worth internalizing: an OS pipe holds only ~64 KiB. If you start the VM and *then*
begin reading, a chatty boot fills the pipe, the guest's console write **blocks**, and the boot
stalls before you ever read a byte. So the reader thread starts **before** `InstanceStart`.

How do we know the guest reached *userspace* (not just that the kernel is alive)? We watch the
console for a marker. The pinned Ubuntu rootfs runs `init`, which eventually spawns a `getty` that
prints its login prompt:

```
Ubuntu 22.04.5 LTS ubuntu-fc-uvm ttyS0
ubuntu-fc-uvm login:
```

No earlier boot line contains the substring `login:`, so it's an unambiguous "userspace is up"
signal. It's tied to *this* rootfs, though; a different image needs a different marker (hence the
`AGENT_MARKER` override). Phase 2 replaces this console-scraping with a proper host↔guest channel
(vsock + a guest agent), at which point the guest tells us it's ready instead of us guessing.

## The number that matters

Boot-to-userspace is measured from the instant we send `InstanceStart` to the instant `login:`
appears. It deliberately **excludes the driver's setup** (spawning `firecracker`, waiting for
the API socket, and copying the ~300 MB rootfs), so it isolates the *guest's* boot; the
wall-clock a `Sandbox::boot` caller feels is strictly larger. It's the baseline every later
optimization (snapshots, a warm pool) is measured against.

Measured on the dev box (10 sequential cold boots, 1 vCPU / 256 MiB): **p50 2.6 s, p90 3.4 s,
spread 2.0–3.8 s**. Isolated single runs have landed as low as ~1.2 s, which is exactly why a
single number is marketing, not measurement: the spread is the finding. Still comfortably under
a container-cold-start-plus-language-runtime, and snapshots (Phase 5) should cut it to
milliseconds. *Measured, not marketed* (spine property four): the latency is logged on every
run, and the real benchmark harness (percentiles over many runs, tracked over time) lands with
the snapshot/density phases.

## Clean teardown, or it doesn't count

A sandbox that leaks a process or a file per run is useless. Two design choices make teardown
bulletproof:

- **Each VM gets a fresh scratch dir** at a *short* path (`/tmp/agent-<pid>-<n>`). Short matters:
  the unix socket lives there and `sockaddr_un.sun_path` caps at ~108 bytes, so a deep `TMPDIR`
  would make Firecracker's `bind()` fail with `EINVAL`. We boot a **copy** of the rootfs in that
  dir, never the pinned base image, so runs are independent and the base image's sha256 stays
  valid.
- **The guaranteed teardown is in `Drop`.** `shutdown()` politely asks the guest to power off
  (`SendCtrlAltDel`), but the thing that actually reclaims resources is `kill()` + `wait()` +
  `remove_dir_all`, which runs even if a `RunningVm` is dropped on an error path. Losing the value
  can't leak the VMM.

The integration test (`crates/vmm/tests/boot.rs`) runs two full boot→shutdown cycles and asserts
no scratch dirs survive: the second boot only works because the first was fully reclaimed.

## Try it

```console
cargo xtask setup             # confirms /dev/kvm, firecracker, and the artifacts
cargo xtask fetch-artifacts   # downloads + sha256-verifies the kernel + rootfs (once)
cargo run -p agent-cli -- run --demo-boot
cargo xtask ci-privileged     # the real boot test (needs /dev/kvm + artifacts)
```

## What Phase 1 deliberately left out

No networking (the guest has zero egress by construction, *deny by default*), no way to run a
command yet (that's `exec`, Phase 2, over vsock), no jailer/cgroup confinement of the VMM itself
(Phase 6), no snapshots (Phase 5). Two consequences of that scoping, owned by later phases:
teardown is `Drop`-based, so killing the *driver* mid-run (Ctrl-C, SIGKILL) leaks the VMM until
the cgroup owns its lifetime (P6.7: a signal handler would only cover SIGINT, so we wait for the
real mechanism); and each boot copies the full rootfs into `/tmp`, so on a tmpfs host that's
~300 MB of RAM per sandbox, the density baseline Phase 5's overlays are measured against (P5.7).
Phase 1 is the single load-bearing capability everything else hangs off: **a hardware-isolated
guest that boots to userspace and dies on command.**
