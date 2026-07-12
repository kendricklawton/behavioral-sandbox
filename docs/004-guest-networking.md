# 004: The network the guest gets (tap, virtio-net, and deny-by-default)

> Phase 4 of the sandbox engine. Phases 1 to 3 booted a microVM, handed it a command, and gave it a
> real disk. Phase 4 gives it a **network interface**, a host-side tap wired to the guest's `eth0`,
> and then makes the interesting move: the guest can talk to its host and **nothing else**, with the
> block enforced by what routes the host installs, not by anything inside the guest.

```rust
let vm = Vm::boot(BootConfig { enable_network: true, ..cfg })?;
vm.host_ip();   // Some(10.200.x.1): the host end of a per-VM /30
vm.guest_ip();  // Some(10.200.x.2): the guest's eth0
vm.tap_name();  // Some("fc…"):      the host interface the eBPF track will bind to
// the guest reaches host_ip and only host_ip: no default route, no NAT, no forwarding.
```

A microVM with a NIC is easy. A microVM with a NIC that is closed by default, isolated from its
neighbours, and observable from the host is the actual lesson. Phase 4 is a tour of Linux host
networking from the tap up: how a VMM gets a wire, how the guest is addressed without touching its
disk, and why a single missing route is the whole security posture.

## The wire: a tap device

Firecracker's virtio-net needs a host-side backend to move frames in and out of the guest. That
backend is a **tap**: a virtual L2 interface whose "cable" is a file descriptor. Whatever the guest
transmits on `eth0` arrives as a readable frame on the host tap, and whatever is written to the tap
is delivered to the guest. It is the standard way to give a userspace VMM a NIC.

Why a bare tap and not a **bridge** or a **veth pair**? A bridge earns its keep when many interfaces
must share one L2 segment (many VMs on one virtual switch). Here each VM gets its **own** tap on its
**own** point-to-point subnet, so there is nothing to bridge: adding a bridge would only create a
shared segment we then have to re-isolate. A `veth` pair connects two network namespaces; we are not
(yet) putting the guest in its own netns, so a tap, the purpose-built VMM backend, is exactly the
right primitive and nothing more.

Creating a tap needs `CAP_NET_ADMIN`, so it is a privileged operation like opening `/dev/kvm`. The
driver shells out to `ip` (iproute2) rather than pulling a netlink crate, matching the rest of the
driver's dependency-light, `unsafe`-free style. The name is `fc<hex>` (kept inside the 15-byte
`IFNAMSIZ` limit), and the *reservation* is the create call itself: `ip tuntap add` failing on a
taken name is the atomic, cross-process claim, the same fail-if-exists-then-retry the scratch dir
uses.

## virtio-net: host tap to guest eth0

With the tap up on the host, the driver tells Firecracker to attach it as the guest's NIC:

```
PUT /network-interfaces/eth0  { "iface_id": "eth0", "host_dev_name": "fc…", "guest_mac": "02:…" }
```

The guest kernel then sees a virtio-net device and calls it `eth0`, carrying the MAC we chose: a
**locally-administered unicast** address (`02:xx:…`, the `0x02` first octet sets the LAA bit and
clears the multicast bit), derived per VM so every guest has a distinct, valid NIC address.
"virtio" means paravirtualised: the guest's driver knows it is on a hypervisor and moves frames
through shared-memory rings (virtqueues) instead of the VMM trap-and-emulating a real NIC's
registers. Fewer VM exits per packet is the point of the design; the actual throughput numbers are a
benchmarking phase's job, not a claim to make here.

## Addressing without touching the disk: kernel `ip=`

The guest has a NIC; it still needs an address. We could run a DHCP client in the guest, or write an
interfaces file, but both mean **changing the rootfs** for a networking concern. Instead we use a
feature the kernel already has: **`CONFIG_IP_PNP`**, kernel-level IP autoconfiguration driven by an
`ip=` boot parameter. The driver appends one argument to the guest's kernel command line:

```
ip=10.200.x.2:::255.255.255.252::eth0:off
   └ guest   │ │ └ netmask (/30)      │    └ autoconf off (we set it statically)
             │ └ gateway = EMPTY      └ device
             └ NFS server = unused
```

The kernel configures `eth0` with that address at boot, before init runs, and the pinned `vmlinux`
already carries `CONFIG_IP_PNP` (confirmed by the `IP-Config:` strings in the image), so this needs
**no rootfs change at all**. The addressing lives entirely in the kernel command line the host
controls.

The **empty gateway field** is not an oversight. It is the entire deny-by-default posture, see below.

## The subnet: a point-to-point /30 per VM

Each VM gets its own four-address block carved from `10.200.0.0/16` (a base chosen to dodge common
host defaults like `10.0.0.0/24` and `192.168.*`). Within the block: `.1` is the host end (assigned
to the tap), `.2` is the guest end. That is a **/30** (`255.255.255.252`), the smallest subnet that
holds two usable hosts: a textbook point-to-point link, one host and one guest, no room for a third
party.

Uniqueness matters for isolation (two VMs on one subnet could reach each other), so the /30 is
**atomically reserved**, not just probabilistically unique. The index is folded from a PID-mixed
counter, but folding 64 bits into a small index can alias, so the reservation is the **host-address
assignment itself**: `ip addr add` fails if another VM already holds that /30, and the driver treats
that clash exactly like a taken tap name, reclaiming the tap and retrying with a fresh token. Two
concurrent sandboxes therefore never share a subnet.

## The one route that is the whole security model

Here is the crux of the phase. When the driver runs `ip addr add 10.200.x.1/30 dev fc…`, the kernel
installs exactly **one** route as a side effect: the **connected route** for that /30, "to reach
`10.200.x.0/30`, send directly on this link." That is what lets the host reach the guest and the
guest reach the host.

What is **not** there is a **default route**. The guest's `ip=` gateway field was empty, so the guest
kernel installs its own connected /30 route and **no `default` via anything**. A packet to any
address outside the /30 has nowhere to go: the guest gets an immediate `ENETUNREACH`, not a timeout.
No route means no reach.

So the deny-by-default network is not enforced by a firewall rule that could be missing or
misordered. It is enforced by the **absence** of a route, which is a much harder thing to get wrong.
The guest is closed because there is no path out, not because something is actively blocking the
paths.

### The road not taken: NAT, forwarding, a bridge

The "it just works" way to give a guest internet is a masquerade: enable `ip_forward`, add an
`iptables -t nat -A POSTROUTING -j MASQUERADE` rule, and the host NATs the guest's traffic to the
world. We deliberately do **none** of that (recorded as ARCHITECTURE decision 008):

- The driver installs **no `MASQUERADE`, no `POSTROUTING`/`nat` rule, no forward-chain rule**, and
  never enables `net.ipv4.ip_forward`.
- Cross-VM isolation does **not** rest on that sysctl either way. The driver does not own the host's
  `ip_forward` setting (a hoster may run it on for their own reasons, e.g. Docker), so the guarantee
  is made host-independent: a guest has **no route** to any neighbour's /30, so it cannot even emit a
  packet toward another VM's tap, forwarding on or off. The unique-/30 reservation removes the only
  way two guests could end up on one segment. (`two_vms_cannot_reach_each_others_tap` proves it.)
- The default-open NAT would be *unenforced* general egress for four phases, until the real
  mechanism, **host-side eBPF on the tap (Phase 8)**, exists. Opening later behind an allow-list is a
  one-way door only if we start closed. So we start closed.

"Allowed egress" is therefore a Phase-8 concept: an explicit, host-enforced, **recorded** policy on
the tap, not a driver-installed NAT rule. In Phase 4 "allowed" means host-local, and that is proven,
not assumed (`guest_reaches_an_allowed_host_endpoint_but_not_a_blocked_one`).

## Every rule the driver installs (the audit list)

Deny-by-default is only credible if the full set of host-side network changes per VM is small and
enumerable. It is. For one networked VM the driver runs exactly:

| Step        | Command                                        | Effect                                              |
|-------------|------------------------------------------------|-----------------------------------------------------|
| create tap  | `ip tuntap add dev fc<hex> mode tap`           | the virtio-net backend interface                    |
| bring up    | `ip link set dev fc<hex> up`                   | link up                                             |
| host addr   | `ip addr add 10.200.x.1/30 dev fc<hex>`        | host end of the /30 **and its connected route**     |
| guest addr  | kernel `ip=10.200.x.2:::255.255.255.252::eth0:off` | guest `eth0`, **no default route** (empty gateway) |

And, as importantly, what it does **not** touch: no default route, no `MASQUERADE` or any `nat`
table rule, no `filter`/`forward` rule, no `ip_forward` sysctl, no bridge, no netns. There is nothing
else to audit because there is nothing else.

Teardown is the inverse of one line: `ip link del dev fc<hex>` removes the interface, and with it the
address and the connected route cascade away. The tap is the first per-VM resource that lives
**outside** the scratch dir, so it is deleted explicitly on every reclamation path (running drop,
boot-failure drop, abort); a hard-killed driver can still orphan one, which is why the leak test
scans for stray `fc*` interfaces and the durable owner is the Phase-6 jailer.

## Naming the tap for the watcher

The whole point of the host-side wire is that Phase 8 will **observe and enforce** on it with eBPF.
For that, the loader must be able to find *this* VM's tap. So the driver exposes `tap_name()`: the
host-globally-reserved `fc<hex>` name is the handle the eBPF track resolves (name to ifindex via
`if_nametoindex`) and attaches `tc`/XDP programs to. The driver hands out the **name**, not a stored
ifindex, because names do not churn if an interface is recreated and reading an ifindex from
`/sys/class/net` is netns-fragile; the loader resolves the index at attach time.

## Try it

```console
# boots two networked microVMs and proves the posture end to end (needs KVM + CAP_NET_ADMIN):
cargo xtask ci-privileged

# on a box without ambient CAP_NET_ADMIN, a user+net namespace grants it (and a writable /dev/kvm):
unshare -Urn --map-root-user cargo test -p agent-vmm --test boot -- --ignored
```

The privileged tests are the working demo: the guest carries its address and reaches the host end
(`addresses_the_guest_and_routes_host_to_guest`), a real host TCP endpoint is reachable while an
off-subnet one is not (`guest_reaches_an_allowed_host_endpoint_but_not_a_blocked_one`), and two VMs
cannot reach each other's tap (`two_vms_cannot_reach_each_others_tap`).

Phase 4 leaves the guest with a network it can use for exactly one thing: talking to its host. Next,
the eBPF track that turns that host-side tap into a place to **watch and enforce** what the guest
does with it.
