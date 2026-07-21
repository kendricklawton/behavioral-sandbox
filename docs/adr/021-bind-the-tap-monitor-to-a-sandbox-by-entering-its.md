# 021. Bind the tap monitor to a sandbox by entering its network namespace *(2026-07-16)*

**Context.** A sandbox's tap (`fc0`) lives inside that sandbox's **own** network namespace
(decision 014), so binding the tap monitor to one specific sandbox's traffic means attaching the `tc`
programs to `fc0` *inside* that netns. Two forces make that awkward. First, aya resolves the interface
and opens its netlink socket in the **calling thread's** netns, so the attach must physically run there.
Second, the driver's existing netns tooling (`ip netns exec`, the jailer's `--netns`) all shells out or
spawns a child, and a child process can't hold a live, in-process eBPF attachment that the loader then
reads a map from. The monitor therefore needs a way to run one namespace-scoped step, the attach, inside
the sandbox's netns while the rest of the loader stays in the host netns.

**Decision.** The loader **enters the sandbox's netns in-process for the attach only**, via `setns`.
- **Load in the host netns, attach in the sandbox's netns.** Creating the maps and loading/verifying
  the programs is namespace-independent (global fds), so it happens first, in the caller's netns. Only
  the netns-scoped step, adding the clsact qdisc and attaching the two classifiers, runs inside the
  sandbox's netns. Reading the flow map afterward is namespace-independent again (a map fd is not
  netns-scoped), so it happens back in the caller's netns.
- **Enter and restore on the *same thread*, always.** `TapMonitor::attach_in_netns(netns, iface)` opens
  the host netns handle (`/proc/self/ns/net`) and the target (`/run/netns/<netns>`, the driver's own
  `netns_path`), `setns`es the calling thread into the target, runs the attach, then `setns`es back,
  the restore runs even if the attach fails, so a failure never strands the thread. Only the calling
  thread moves (briefly); the rest of the process is unaffected.
- **`setns` via nix's *safe* wrapper.** `std` has no `setns`, so the loader takes a minimal `nix`
  dependency (`sched` feature only) whose `setns` is a safe function, the loader stays
  `#![forbid(unsafe_code)]`, no `unsafe` block of ours. This is the first in-process netns entry in the
  repo; the driver's shell-out model can't carry a live attachment, so it doesn't apply here.
- **Cleanup is netns teardown, not the loader's drop.** The in-kernel `tc` filter lives in the
  sandbox's netns; the sandbox's teardown (`ip netns del`, decision 014) cascades the tap, its clsact
  qdisc, and the filters away. So dropping the monitor frees only its userspace fds (the map, the
  programs), and a torn-down sandbox leaves no dangling filter even if the loader is gone, the same
  no-pin, no-leak model as decisions 017/020. (The loader's own drop-detach targets the caller's netns,
  where the filter isn't, so it is a harmless no-op; the netns is the real reclaimer.)

**Alternatives considered.**
- **`ip netns exec <ns> <helper>` that pins the program + map to bpffs**, with the main loader reading
  the pinned map. Rejected: it reintroduces **pinned residue** (against decision 017's no-pin default),
  needs an attach subcommand on the loader binary, and complicates teardown (unpin). `setns` keeps the
  drop-owned, no-pin lifetime.
- **Move the whole process (or a dedicated long-lived thread) into the netns.** Rejected: the process
  must keep reading the map and serving other sandboxes from the host netns; a per-monitor parked
  thread is more machinery than a scoped enter-and-restore on one call.
- **A netlink crate that targets a netns fd directly (no `setns`).** Rejected: aya's tc attach has no
  netns parameter, and pulling in a second netlink stack to avoid one `setns` call is a bigger, not
  smaller, dependency than nix's `sched` feature.

**Consequences and notes.**
- **`setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN`/root**, which the loader already effectively needs
  alongside `CAP_BPF`+`CAP_NET_ADMIN`; a host that can't enter the netns gets a typed
  `ProbeError::Attach` naming it.
- **The two tracks stay decoupled by plain values.** The loader takes a **netns name** and an
  **interface name** (`String`s), which the driver hands over via `Sandbox::netns`/`Sandbox::tap_name`
  (added here, additive `api:`); `probes-loader` gains no dependency on `vmm`. The end-to-end test uses
  `agent-vmm` as a **dev-dependency** only.
- **`nix` is MIT** (already in the license allow-list) and pulled with default features off, `sched`
  only. First `nix`/`setns` use in the tree.
- The userspace export surface (`flows` per 5-tuple, `totals` as the per-VM `NetStats` rollup) feeds
  this attach-on-open / teardown-on-close lifecycle; the end-to-end test proves guest traffic lands in
  the counters, and `cargo xtask watch-sandbox` is the live exit-gate demo.
