//! Privileged integration tests for the raw microVM lifecycle: boot to userspace, the vsock device,
//! the read-only base + overlay, and the no-leak guarantee across repeated boots.
//!
//! `#[ignore]`d because they need `/dev/kvm` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_vmm::{Jail, Vm, DEFAULT_GUEST_CID, DEFAULT_JAIL_UID};

use common::{
    agent_rootfs_config, config, have_jailer_privileges, have_net_admin, jailed_overlay_config,
};

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn boots_to_userspace_and_shuts_down() {
    let cfg = config();
    let marker = cfg.userspace_marker.clone();
    let vm = Vm::boot(cfg).expect("microVM should boot to userspace");

    // Boot returns only after the marker is seen, so this is guaranteed — but assert it anyway to
    // document what "reached userspace" means, and that the console was actually captured.
    assert!(
        vm.console().contains(&marker),
        "console should show the userspace marker {marker:?}; got:\n{}",
        vm.console()
    );

    let latency = vm.boot_latency();
    assert!(latency > Duration::ZERO, "boot latency should be measured");
    assert!(
        latency < Duration::from_secs(30),
        "boot latency {latency:?} should be well under the deadline"
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn boots_with_a_vsock_device() {
    // Real Firecracker must accept `PUT /vsock` and boot to userspace with the device configured.
    // (This proves just the config path on the stock Ubuntu rootfs; the full host→guest-agent
    // round trip is `execs_a_command_in_the_microvm`, against the agent rootfs.)
    let mut cfg = config();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    let marker = cfg.userspace_marker.clone();

    let vm = Vm::boot(cfg).expect("microVM with vsock should boot to userspace");
    assert!(
        vm.console().contains(&marker),
        "guest should still reach userspace with vsock configured"
    );
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + real root + the jailer (run via `cargo xtask ci-privileged` as root)"]
fn boots_under_the_jailer() {
    // The plain rootfs boots to userspace, but Firecracker now runs confined by its jailer: in a
    // chroot, dropped to an unprivileged uid/gid, inside the jailer's mount namespace, under cgroup
    // cpu/memory limits, with its built-in seccomp filters active. The jailer `mknod`s device nodes,
    // which needs real root (the `unshare -Urn` trick the other privileged tests use can't), so skip
    // rather than fail on a box that can do KVM but not real root.
    //
    // P6.6 verifies the confinement is actually *in force*, not merely configured: below we read the
    // running VMM's `/proc` and assert each wall independently, so a guest that breached KVM into the
    // VMM lands in a chroot, as an unprivileged uid, holding no capabilities, under `no_new_privs` and
    // seccomp, in its own mount namespace and cgroup. None of these can be escaped from inside the VMM.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping boots_under_the_jailer: needs real root (euid 0 in the initial user namespace)"
        );
        return;
    }
    let mut cfg = config();
    cfg.jail = Some(Jail::default());
    let marker = cfg.userspace_marker.clone();
    let (vcpus, mem_mib) = (cfg.vcpus, cfg.mem_mib);

    let vm = Vm::boot(cfg).expect("microVM should boot to userspace under the jailer");
    assert!(
        vm.console().contains(&marker),
        "jailed guest should reach userspace (marker {marker:?}); console:\n{}",
        vm.console()
    );
    assert!(
        vm.boot_latency() > Duration::ZERO,
        "jailed boot latency should be measured"
    );

    // Confinement actually happened, not just "it booted". Read the jailed Firecracker's /proc.
    let pid = vm.vmm_pid();
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read jailed VMM status");
    // The first numeric field of a `Name:\tv...` status line (uid's real id, seccomp's mode).
    let field = |name: &str| -> Option<u32> {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|u| u.parse::<u32>().ok())
    };

    // Uid drop: `Uid:` is real/effective/saved/fs, all the dropped id after the jailer's setuid.
    let uid = field("Uid:").expect("parse jailed VMM uid");
    assert_eq!(
        uid, DEFAULT_JAIL_UID,
        "jailed Firecracker should run as the dropped uid {DEFAULT_JAIL_UID}, not root (got {uid})"
    );

    // Seccomp: Firecracker installs its built-in per-thread filters at InstanceStart, so a running VM
    // is in filter mode (`Seccomp: 2`). We never pass `--no-seccomp`.
    let seccomp = field("Seccomp:").expect("parse jailed VMM seccomp mode");
    assert_eq!(
        seccomp, 2,
        "jailed Firecracker should run in seccomp filter mode (Seccomp: 2), got {seccomp}"
    );

    // Capability drop: setuid from root to the jailed uid clears the cap sets, so the VMM holds no
    // effective capabilities on the host, and a breach out of the guest gains no privileged operations.
    let cap_eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(str::trim)
        .expect("parse jailed VMM CapEff");
    assert_eq!(
        cap_eff, "0000000000000000",
        "jailed Firecracker should hold no effective capabilities, got {cap_eff}"
    );

    // no_new_privs: set before the seccomp install (and required by the kernel for an unprivileged
    // process to install a filter at all), so the VMM can never regain privilege via a setuid binary.
    let nnp = field("NoNewPrivs:").expect("parse jailed VMM NoNewPrivs");
    assert_eq!(
        nnp, 1,
        "jailed Firecracker should run with no_new_privs, got {nnp}"
    );

    // Chroot: the jailer pivot_roots the VMM into its per-VM jail (`<scratch>/firecracker/<id>/root`),
    // so the VMM's filesystem root is not the host `/` and it cannot name a host path. The link *text*
    // of `/proc/<pid>/root` is useless here — after a pivot_root in the VMM's own mount namespace it
    // renders as literally `/` (measured) — so compare filesystem *identity* instead: following the
    // link stats the directory the VMM's root actually is, and its `(st_dev, st_ino)` must differ from
    // this process's root. Same-inode would mean no chroot at all.
    {
        use std::os::unix::fs::MetadataExt;
        let vmm_root =
            std::fs::metadata(format!("/proc/{pid}/root/")).expect("stat jailed VMM root");
        let host_root = std::fs::metadata("/").expect("stat host root");
        assert_ne!(
            (vmm_root.dev(), vmm_root.ino()),
            (host_root.dev(), host_root.ino()),
            "jailed Firecracker should be chrooted, not rooted at the host /"
        );
    }

    // Mount namespace: the jailer builds the chroot in a private mount namespace, so the VMM's mount
    // table is its own (a different namespace than this test process's).
    let vmm_mnt =
        std::fs::read_link(format!("/proc/{pid}/ns/mnt")).expect("read jailed VMM mnt ns");
    let host_mnt = std::fs::read_link("/proc/self/ns/mnt").expect("read test mnt ns");
    assert_ne!(
        vmm_mnt, host_mnt,
        "jailed Firecracker should run in its own mount namespace"
    );

    // cgroup limits: when the host delegates the cgroup v2 controllers (a systemd host and this
    // test's environment do), the VMM's cgroup carries a finite memory.max (guest RAM + bounded
    // overhead) and a cpu.max of exactly `vcpus` cores. Where they aren't delegated the jailed boot
    // still runs without limits (memory.max stays "max"), so only assert when they're actually set.
    let cg_rel = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
        })
        .expect("read jailed VMM cgroup path");
    let cg = std::path::Path::new("/sys/fs/cgroup").join(cg_rel.trim_start_matches('/'));
    let mem_max = std::fs::read_to_string(cg.join("memory.max")).unwrap_or_default();
    let mem_max = mem_max.trim();
    if mem_max != "max" && !mem_max.is_empty() {
        let bytes: u64 = mem_max.parse().expect("parse memory.max");
        let guest = u64::from(mem_mib) * 1024 * 1024;
        assert!(
            bytes >= guest && bytes <= guest + 512 * 1024 * 1024,
            "memory.max {bytes} should be guest RAM plus a bounded overhead (guest {guest})"
        );
        let cpu_max = std::fs::read_to_string(cg.join("cpu.max")).expect("read cpu.max");
        let mut it = cpu_max.split_whitespace();
        let quota: u64 = it
            .next()
            .and_then(|q| q.parse().ok())
            .expect("parse cpu.max quota");
        let period: u64 = it
            .next()
            .and_then(|p| p.parse().ok())
            .expect("parse cpu.max period");
        assert_eq!(
            quota,
            u64::from(vcpus) * period,
            "cpu.max quota should cap the VMM at {vcpus} core(s) ({quota} per {period}us)"
        );
    } else {
        eprintln!("cgroup controllers not delegated here; jailed VM ran without cgroup limits");
    }

    vm.shutdown().expect("jailed shutdown should succeed");

    // Teardown reclaims the chroot (it lives in the scratch dir) and the jailer's cgroup — no
    // `/tmp/agent-<pid>-*` survives.
    let prefix = format!("agent-{}-", std::process::id());
    let scratch_leaks = std::fs::read_dir("/tmp")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        scratch_leaks, 0,
        "jailed boot leaked a scratch dir / chroot"
    );
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn overlay_is_writable_and_base_is_untouched() {
    // P3.3 acceptance: the read-only base is shared (no copy), a per-run tmpfs overlay makes `/`
    // writable in-guest, and the base file on the host is never mutated.
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/rootfs-agent.ext4");
    let before = std::fs::metadata(&base).expect("stat base");
    let (before_len, before_mtime) = (before.len(), before.modified().expect("base mtime"));

    // Boot twice: writing to `/etc` (a path that lives on the read-only base) succeeds only because
    // the overlay redirects the write to the tmpfs upper. A fresh tmpfs per boot, so each is clean.
    for i in 0..2 {
        let vm = Vm::boot(agent_rootfs_config())
            .unwrap_or_else(|e| panic!("overlay microVM boot {i} failed: {e}"));
        let out = vm
            .exec(
                &[
                    "sh".into(),
                    "-c".into(),
                    "echo overlaid > /etc/p3_3 && cat /etc/p3_3".into(),
                ],
                b"",
            )
            .expect("write+read a normally-read-only path via the overlay");
        assert_eq!(
            out.stdout,
            b"overlaid\n",
            "overlay `/etc` should be writable; console:\n{}",
            vm.console()
        );
        assert_eq!(out.exit_code, 0);
        vm.shutdown().expect("shutdown should succeed");
    }

    // The read-only block device makes this a guarantee, not a hope: the guest opened the base
    // `O_RDONLY`, so it cannot have changed size or been rewritten.
    let after = std::fs::metadata(&base).expect("stat base again");
    assert_eq!(after.len(), before_len, "base image size must not change");
    assert_eq!(
        after.modified().expect("base mtime after"),
        before_mtime,
        "base image must not be rewritten"
    );
}

#[test]
#[ignore = "needs /dev/kvm + real root + the jailer (run via `cargo xtask ci-privileged` as root)"]
fn jailed_overlay_is_dense_and_base_is_untouched() {
    // P7.0b: a jailed boot runs the density path, not a full rootfs copy. The read-only shared base is
    // *bind-mounted* into the chroot (same inode, page-cache-deduped across VMs), the guest overlays a
    // per-run tmpfs so `/` is writable, and the base file is never mutated. Needs real root (the
    // jailer `mknod`s device nodes); skip where KVM is available but real root isn't.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping jailed_overlay_is_dense_and_base_is_untouched: needs real root (euid 0, initial userns)"
        );
        return;
    }
    use std::os::unix::fs::MetadataExt;
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/rootfs-agent.ext4");
    let before = std::fs::metadata(&base).expect("stat base");
    let (base_len, base_mtime, base_ino, base_dev) = (
        before.len(),
        before.modified().expect("base mtime"),
        before.ino(),
        before.dev(),
    );

    let vm = Vm::boot(jailed_overlay_config())
        .expect("jailed overlay microVM should boot to the agent's readiness marker");

    // Density, proven three ways: the chroot's root disk is a *mount* at all (a full copy would create
    // none), it is mounted *read-only* (the base can't be mutated through the chroot), and it resolves
    // to the *same inode* as the shared base (a bind mount, so one page cache is shared, not a per-VM
    // 256 MiB copy).
    let bind = jailed_base_mount().expect(
        "a bind mount of the base should exist under the chroot (density path, not a copy)",
    );
    assert!(
        bind.read_only,
        "the staged base must be mounted read-only so it can never be mutated through the chroot"
    );
    let staged = std::fs::metadata(&bind.mount_point).expect("stat the bind-mounted base");
    assert_eq!(
        (staged.ino(), staged.dev()),
        (base_ino, base_dev),
        "the chroot base must be the same inode as the shared base (bind mount), not a per-VM copy"
    );

    // Overlay writable: writing a path that lives on the read-only base succeeds only via the tmpfs
    // upper the guest's `overlay-init` stacks — the same overlay the unjailed density path uses.
    let out = vm
        .exec(
            &[
                "sh".into(),
                "-c".into(),
                "echo overlaid > /etc/p7b && cat /etc/p7b".into(),
            ],
            b"",
        )
        .expect("write+read a normally-read-only path via the jailed overlay");
    assert_eq!(
        out.stdout,
        b"overlaid\n",
        "jailed overlay `/etc` should be writable; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0);

    let mount_point = bind.mount_point.clone();
    vm.shutdown()
        .expect("jailed overlay shutdown should succeed");

    // The base is byte-for-byte untouched, and teardown unmounted the bind mount — no leaked mount, so
    // `remove_dir_all` reclaimed the chroot (a lingering mount would `EBUSY` and leak it).
    let after = std::fs::metadata(&base).expect("stat base again");
    assert_eq!(after.len(), base_len, "base image size must not change");
    assert_eq!(
        after.modified().expect("base mtime after"),
        base_mtime,
        "base image must not be rewritten"
    );
    assert!(
        !path_is_mounted(&mount_point),
        "teardown must unmount the base bind mount (else the chroot leaks on EBUSY)"
    );
}

/// A read-only base bind mount found in `/proc/self/mountinfo`.
struct BaseMount {
    mount_point: PathBuf,
    read_only: bool,
}

/// The read-only base bind mount a jailed overlay boot stages into its chroot, located in
/// `/proc/self/mountinfo` by its `.../firecracker/<id>/root/rootfs.ext4` mount point (field 5). The
/// per-mount options (field 6) carry `ro` for a read-only mount.
fn jailed_base_mount() -> Option<BaseMount> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in info.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 7 {
            continue;
        }
        let mount_point = fields[4];
        if !(mount_point.contains("/firecracker/") && mount_point.ends_with("/root/rootfs.ext4")) {
            continue;
        }
        let read_only = fields[5].split(',').any(|o| o == "ro");
        return Some(BaseMount {
            mount_point: PathBuf::from(mount_point),
            read_only,
        });
    }
    None
}

/// Whether `path` is currently a mount point (its exact path appears as field 5 of a
/// `/proc/self/mountinfo` line). Used to assert teardown detached the base bind mount.
fn path_is_mounted(path: &Path) -> bool {
    let Some(target) = path.to_str() else {
        return false;
    };
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|info| info.lines().any(|l| l.split(' ').nth(4) == Some(target)))
        .unwrap_or(false)
}

/// Host tap interfaces currently present (`fc*`), for the leak assertion below.
fn fc_interfaces() -> std::collections::BTreeSet<String> {
    std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("fc"))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `pid` is still a live `firecracker` process. A reaped child leaves `/proc` entirely, so a
/// `firecracker` still present at a VMM pid we booted means teardown failed to kill+reap it. Keyed on
/// the *specific* pid (via `comm`), not a scan, so it can't be confused by other parallel tests' VMMs
/// (they have different pids); a reaped-then-recycled pid running something else reads as gone.
fn is_firecracker(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "firecracker")
        .unwrap_or(false)
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + artifacts (run via `cargo xtask ci-privileged`)"]
fn repeated_boots_leave_no_leaks() {
    // After two boot/teardown cycles, nothing this test spawned may survive: no per-VM scratch dir,
    // no orphaned firecracker VMM process, and (with CAP_NET_ADMIN) no per-VM tap. The tap is the
    // one resource outside the scratch dir, so it's reclaimed separately from `remove_dir_all`;
    // without the capability, networking is off and this still covers the scratch-dir + process paths.
    let net = have_net_admin();
    let taps_before = fc_interfaces();
    let mut vmm_pids = Vec::new();

    // Two full cycles back to back; the second only works if the first was fully reclaimed.
    for i in 0..2 {
        let mut cfg = config();
        cfg.enable_network = net;
        let vm = Vm::boot(cfg).unwrap_or_else(|e| panic!("boot {i} failed: {e}"));
        vmm_pids.push(vm.vmm_pid());
        // `shutdown` consumes the VM, so its `Drop` (kill + reap + reclaim) has run by the time it
        // returns — the leak checks below therefore observe the fully-torn-down state.
        vm.shutdown()
            .unwrap_or_else(|e| panic!("shutdown {i} failed: {e}"));
    }

    // This process's per-VM scratch dirs (`/tmp/agent-<pid>-<n>`) must all be gone.
    let prefix = format!("agent-{}-", std::process::id());
    let leftovers = std::fs::read_dir("/tmp")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "per-VM scratch dirs should be cleaned up");

    // Every firecracker VMM we booted must have been killed and reaped — no orphaned process.
    let orphans: Vec<_> = vmm_pids
        .iter()
        .copied()
        .filter(|&p| is_firecracker(p))
        .collect();
    assert!(orphans.is_empty(), "orphaned firecracker VMMs: {orphans:?}");

    // No tap interface survived the cycles either (only asserted when networking was enabled).
    if net {
        let leaked: Vec<_> = fc_interfaces().difference(&taps_before).cloned().collect();
        assert!(leaked.is_empty(), "leaked tap interfaces: {leaked:?}");
    }
}

/// Open fds in this process, counted through `/proc/self/fd`. The count includes the read itself
/// (one transient fd), a constant bias that cancels in every delta below.
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count())
        .unwrap_or(0)
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn fd_footprint_per_vm_stays_within_budget_and_never_leaks() {
    // P6.9c: each live VM costs the embedder driver-side fds; at the default 1024 soft ulimit an
    // unstated budget fails as an illegible mid-boot EMFILE a few hundred VMs in. This pins the
    // budget (`FDS_PER_VM`) per start path — cold, networked, warm restore — and, just as
    // load-bearing, asserts teardown hands every fd back (an fd leak per run would walk any
    // long-lived embedder into EMFILE regardless of the per-VM budget).
    use agent_vmm::{sweep_orphans, FDS_PER_VM};

    let baseline = open_fds();

    // Cold boot, plus a second concurrent VM: the marginal cost is what a pool bound multiplies.
    let vm = Vm::boot(config()).expect("cold microVM should boot");
    let cold = open_fds().saturating_sub(baseline);
    let vm2 = Vm::boot(config()).expect("second cold microVM should boot");
    let marginal = open_fds().saturating_sub(baseline + cold);
    eprintln!("fd footprint: cold {cold}, marginal second VM {marginal} (budget {FDS_PER_VM})");
    assert!(
        cold <= FDS_PER_VM,
        "cold boot holds {cold} fds > budget {FDS_PER_VM}"
    );
    assert!(
        marginal <= FDS_PER_VM,
        "second VM holds {marginal} fds > budget {FDS_PER_VM}"
    );
    vm2.shutdown().expect("vm2 shutdown");
    vm.shutdown().expect("vm shutdown");
    assert_eq!(open_fds(), baseline, "cold teardown must return every fd");

    // Networked boot (tap handling is shell-outs, so it should add no held fd).
    if have_net_admin() {
        let mut cfg = config();
        cfg.enable_network = true;
        let vm = Vm::boot(cfg).expect("networked microVM should boot");
        let net = open_fds().saturating_sub(baseline);
        eprintln!("fd footprint: networked {net} (budget {FDS_PER_VM})");
        assert!(
            net <= FDS_PER_VM,
            "networked boot holds {net} fds > budget {FDS_PER_VM}"
        );
        vm.shutdown().expect("networked shutdown");
        assert_eq!(
            open_fds(),
            baseline,
            "networked teardown must return every fd"
        );
    } else {
        eprintln!("fd footprint: skipping the networked leg (no CAP_NET_ADMIN)");
    }

    // Warm restore (the pool's start path — the one an embedder multiplies hardest).
    let agent_rootfs =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/rootfs-agent.ext4");
    if agent_rootfs.is_file() {
        let bundle = common::TmpDir::new("fd-warm");
        let (snap, _cold_latency) = common::warm_python_snapshot(&bundle);
        let warm_baseline = open_fds();
        let clone = Vm::restore(&snap, &agent_rootfs_config()).expect("warm clone should restore");
        let warm = open_fds().saturating_sub(warm_baseline);
        eprintln!("fd footprint: warm clone {warm} (budget {FDS_PER_VM})");
        assert!(
            warm <= FDS_PER_VM,
            "warm clone holds {warm} fds > budget {FDS_PER_VM}"
        );
        clone.shutdown().expect("clone shutdown");
        assert_eq!(
            open_fds(),
            warm_baseline,
            "warm teardown must return every fd"
        );
    } else {
        eprintln!("fd footprint: skipping the warm leg (agent rootfs not built)");
    }

    // Keep the host tidy for the suite's other leak checks (and dogfood the sweep's live-skip).
    let _ = sweep_orphans(&agent_vmm::BootConfig::from_env().scratch_dir);
}
