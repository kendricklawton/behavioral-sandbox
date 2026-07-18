//! Privileged integration tests for snapshots and prewarmed start: the self-contained bundle, restore,
//! concurrent prewarmed clones, the restore fix-ups (network identity, entropy, clocks), the prewarmed
//! `Pool`, and the restore-beats-cold-boot payoff.
//!
//! `#[ignore]`d because they need `/dev/kvm` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::num::NonZeroU8;
use std::time::Duration;

use agent_vmm::{Jail, Pool, Vm, DEFAULT_JAIL_UID};

use common::{
    agent_rootfs_config, cgroup_of, config, have_jailer_privileges, have_net_admin,
    prewarmed_python_snapshot, TmpDir,
};

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn snapshots_a_running_microvm() {
    // Pause a booted VM and take a full snapshot (memory + state) via the API. The bundle is
    // three real files, and the VM is resumed so it stays usable afterward.
    let vm = Vm::boot(config()).expect("microVM should boot to userspace");
    let bundle = TmpDir::new("snap-p51");
    let snap = vm
        .snapshot(bundle.path())
        .expect("pause + full snapshot should succeed");

    for (label, path) in [
        ("state", snap.state_path()),
        ("memory", snap.mem_path()),
        ("root disk", snap.root_drive_path()),
    ] {
        let meta = std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("{label} file {path:?} should exist: {e}"));
        assert!(meta.len() > 0, "{label} file should be non-empty");
    }
    // The memory file is roughly the guest's RAM (256 MiB default), a sanity floor, not an exact
    // size, so this doesn't couple to Firecracker's exact memory-file layout.
    let mem_len = std::fs::metadata(snap.mem_path()).expect("mem meta").len();
    assert!(
        mem_len >= 128 * 1024 * 1024,
        "memory file {mem_len} bytes looks too small for a full snapshot"
    );

    // Resume worked, so the VM is still alive and shuts down cleanly.
    vm.shutdown()
        .expect("post-snapshot shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn restores_a_snapshot_onto_a_fresh_vmm() {
    // Snapshot a VM, throw it away, then restore from the bundle on a fresh VMM and confirm it
    // resumes. Measures restore latency alongside the source's cold boot for the comparison.
    let cfg = config();
    let source = Vm::boot(cfg.clone()).expect("source microVM should boot");
    let cold_boot = source.boot_latency();

    let bundle = TmpDir::new("snap-p52");
    let snap = source
        .snapshot(bundle.path())
        .expect("snapshot should succeed");
    // Drop the source entirely: its scratch dir (and the private rootfs copy it booted from) are
    // reclaimed, so a successful restore proves the bundle is self-contained.
    source.shutdown().expect("source shutdown should succeed");

    let restored = Vm::restore(&snap, &cfg).expect("restore should load and resume");
    let restore_latency = restored.boot_latency();
    assert!(
        restore_latency > Duration::ZERO,
        "restore latency should be measured"
    );

    // Liveness: the restored VMM is a real, running process, and it stays up past resume (a bundle
    // that loaded but instantly died would fail `run_restore`, but assert it held for a beat too).
    let pid = restored.vmm_pid();
    let alive = |pid: u32| std::path::Path::new(&format!("/proc/{pid}")).exists();
    assert!(alive(pid), "restored VMM (pid {pid}) should be alive");
    std::thread::sleep(Duration::from_millis(200));
    assert!(alive(pid), "restored VMM should stay alive after resume");

    eprintln!("cold boot {cold_boot:?} vs snapshot restore {restore_latency:?}");
    restored
        .shutdown()
        .expect("restored shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn prewarmed_snapshot_restores_and_runs_code() {
    // Snapshot a prewarmed agent VM (runtime loaded), throw the source away, restore a clone off the
    // shared read-only base, and run Python on it, the exec channel survives the snapshot (Firecracker
    // re-binds vsock on restore), so a prewarmed clone runs code without paying the cold boot.
    let bundle = TmpDir::new("snap-warm");
    let (snap, cold_boot) = prewarmed_python_snapshot(&bundle);
    // A prewarmed (read_only_root) snapshot references the shared base in place, so the bundle carries no
    // root-disk copy: the disk path points outside the bundle dir, not at a copy within it.
    assert!(
        !snap.root_drive_path().starts_with(bundle.path()),
        "a read_only_root snapshot should reference the shared base, not copy it into the bundle"
    );

    let restored =
        Vm::restore(&snap, &agent_rootfs_config()).expect("prewarmed restore should resume");
    let restore_latency = restored.boot_latency();
    let argv = ["python3", "-c", "print(2 + 2)"].map(String::from);
    let out = restored
        .exec(&argv, &[])
        .expect("exec on the restored prewarmed clone should succeed");
    assert_eq!(out.exit_code, 0, "python should exit 0");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "4",
        "restored prewarmed clone should run Python and return 4"
    );
    // A restored VM's live disk is an anonymous inode with no host path, so re-snapshotting it must be
    // refused, not silently bundle a stale / shared-writable disk.
    let redo = TmpDir::new("snap-warm-redo");
    assert!(
        restored.snapshot(redo.path()).is_err(),
        "re-snapshotting a restored VM should be refused"
    );

    eprintln!("prewarmed: cold boot {cold_boot:?} vs restore {restore_latency:?} + exec");
    restored
        .shutdown()
        .expect("restored shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restores_concurrent_clones_from_one_prewarmed_snapshot() {
    // Restore several clones from one prewarmed snapshot and keep them all alive at once. Each shares
    // the read-only base (memory-sharing) but is an independent VM, its own vsock socket (bound relative to
    // its own scratch dir, so no collision) and its own in-RAM overlay. Prove it by running a distinct
    // computation on each concurrently-alive clone and getting each clone's own answer back.
    const N: usize = 3;
    let bundle = TmpDir::new("snap-warm-clones");
    let (snap, _cold) = prewarmed_python_snapshot(&bundle);

    let clones: Vec<_> = (0..N)
        .map(|i| {
            Vm::restore(&snap, &agent_rootfs_config())
                .unwrap_or_else(|e| panic!("clone {i} should restore concurrently: {e}"))
        })
        .collect();

    // All N are alive simultaneously with distinct VMMs.
    let pids: std::collections::BTreeSet<u32> = clones.iter().map(|c| c.vmm_pid()).collect();
    assert_eq!(
        pids.len(),
        N,
        "each clone should be its own live VMM process"
    );

    // Each clone runs its own code and returns its own result, while the others are still alive.
    for (i, clone) in clones.iter().enumerate() {
        let argv = ["python3", "-c", &format!("print({i} * {i})")].map(String::from);
        let out = clone
            .exec(&argv, &[])
            .unwrap_or_else(|e| panic!("exec on clone {i} should succeed: {e}"));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            (i * i).to_string(),
            "clone {i} should compute its own value independently"
        );
    }

    for clone in clones {
        clone.shutdown().expect("clone shutdown should succeed");
    }
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restored_clones_do_not_bleed_state_under_load() {
    // No state bleed between clones restored from one snapshot, under concurrent load. Each clone
    // shares the read-only base (memory-sharing) but owns its in-RAM overlay and its guest RAM, so a
    // write in one clone is invisible to its siblings. Prove it under load: N clones each write a
    // *distinct* secret to the same guest path and read it back, all in flight at once. If the disk
    // were shared, a sibling's concurrent write would clobber the path and the readback would
    // mismatch; with per-clone isolation each reads back exactly its own.
    const N: usize = 4;
    let bundle = TmpDir::new("snap-bleed");
    let (snap, _cold) = prewarmed_python_snapshot(&bundle);

    let clones: Vec<_> = (0..N)
        .map(|i| {
            Vm::restore(&snap, &agent_rootfs_config())
                .unwrap_or_else(|e| panic!("clone {i} should restore: {e}"))
        })
        .collect();

    // Each clone drives its own thread (ownership moves in), so the writes race concurrently, the
    // "under load" that would expose a shared disk. Spawn all N before joining any.
    let readbacks: Vec<(String, String)> = clones
        .into_iter()
        .enumerate()
        .map(|(i, clone)| {
            std::thread::spawn(move || {
                let secret = format!("bleed-secret-{i}-{}", clone.vmm_pid());
                let write =
                    ["sh", "-c", &format!("printf '%s' '{secret}' > /tmp/bleed")].map(String::from);
                clone
                    .exec(&write, b"")
                    .unwrap_or_else(|e| panic!("clone {i} write: {e}"));
                let read = ["sh", "-c", "cat /tmp/bleed"].map(String::from);
                let out = clone
                    .exec(&read, b"")
                    .unwrap_or_else(|e| panic!("clone {i} read: {e}"));
                clone
                    .shutdown()
                    .unwrap_or_else(|e| panic!("clone {i} shutdown: {e}"));
                (secret, String::from_utf8_lossy(&out.stdout).into_owned())
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().expect("clone thread should not panic"))
        .collect();

    for (secret, readback) in &readbacks {
        assert_eq!(
            readback, secret,
            "each clone must read back only its own write — no state bleed between concurrent clones"
        );
    }
    // Guard against a vacuous pass: the secrets really were distinct across clones.
    let distinct: std::collections::BTreeSet<_> = readbacks.iter().map(|(s, _)| s).collect();
    assert_eq!(
        distinct.len(),
        N,
        "each clone should have had a distinct secret"
    );
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restored_networked_clones_coexist_each_in_its_own_netns() {
    // Retires decision 011's one-live-networked-clone limit. On v1.9 (no `network_overrides`)
    // every clone must present the snapshot's baked-in tap name, which in a shared host netns could
    // exist only once, so only one networked clone could be live. Under the netns model each clone
    // recreates that tap in its **own** network namespace, where the baked-in identity is already
    // correct, so N networked clones run at once. This proves two concurrent networked clones, each
    // isolated in its own netns, each carrying the baked identity, each reaching its own host end.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }

    // Source: networked + vsock + prewarmed. Snapshot it, then drop it, under the netns model neither the
    // tap name nor the /30 is a shared reservation, so the source's lifetime doesn't gate the clones'.
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let source = Vm::boot(cfg.clone()).expect("networked agent microVM should boot");
    let source_guest_ip = source.guest_ip().expect("source guest ip");
    let source_tap = source.tap_name().expect("source tap name").to_string();
    let bundle = TmpDir::new("snap-net-warm");
    let snap = source
        .snapshot(bundle.path())
        .expect("networked prewarmed snapshot should succeed");
    source.shutdown().expect("source shutdown");

    // Two clones, live simultaneously, impossible before this box.
    let clone_a = Vm::restore(&snap, &cfg).expect("networked clone A should resume");
    let clone_b = Vm::restore(&snap, &cfg).expect("networked clone B should resume");

    // Each reuses the snapshot's baked identity (same tap name + guest IP, collision-free because
    // each lives in its own netns), and the two netns are distinct (the isolation boundary).
    for clone in [&clone_a, &clone_b] {
        assert_eq!(
            clone.tap_name(),
            Some(source_tap.as_str()),
            "each clone reuses the snapshot's recorded tap name"
        );
        assert_eq!(
            clone.guest_ip(),
            Some(source_guest_ip),
            "each clone keeps the snapshot's baked-in /30 (correct in its own netns)"
        );
    }
    assert_ne!(
        clone_a.netns(),
        clone_b.netns(),
        "the two live clones must run in distinct network namespaces"
    );

    // Both are actually functional at the same time: each guest reaches its own host end (proving the
    // recreated tap in each netns is live), and stays deny-by-default (no default route).
    for (label, clone) in [("A", &clone_a), ("B", &clone_b)] {
        let host_ip = clone.host_ip().expect("clone host ip").to_string();
        let ping = clone
            .exec(
                &[
                    "ping".into(),
                    "-c".into(),
                    "1".into(),
                    "-W".into(),
                    "1".into(),
                    host_ip.clone(),
                ],
                b"",
            )
            .expect("clone pings its host end");
        assert_eq!(
            ping.exit_code,
            0,
            "clone {label} should reach its host end {host_ip}; console:\n{}",
            clone.console()
        );
        let off = clone
            .exec(
                &[
                    "ping".into(),
                    "-c".into(),
                    "1".into(),
                    "-W".into(),
                    "1".into(),
                    "192.0.2.1".into(),
                ],
                b"",
            )
            .expect("ping an off-subnet address");
        assert_ne!(
            off.exit_code, 0,
            "clone {label} must stay deny-by-default (no default route)"
        );
    }

    clone_a.shutdown().expect("clone A shutdown");
    clone_b.shutdown().expect("clone B shutdown");
}

#[test]
#[ignore = "needs /dev/kvm + real root + the jailer (run via `cargo xtask ci-privileged` as root)"]
fn restores_prewarmed_clones_under_the_jailer_and_pools_them() {
    // Prewarmed start and confinement compose. The prewarmed source runs unjailed, it executes only
    // the embedder's warm-up, and a jailed VM refuses snapshotting, and every *clone* restores
    // under the jailer: the bundle is staged into the chroot (state copied in; the memory file and
    // the shared base disk bind-mounted read-only, so clones keep sharing one page cache), vsock is
    // re-bound inside the chroot, and the VMM runs as the dropped uid. This drives one direct jailed
    // restore, then a jailed `Pool`, so the confined prewarmed pool the box promises is the thing proven.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping restores_prewarmed_clones_under_the_jailer_and_pools_them: needs real root (euid 0)"
        );
        return;
    }
    let bundle = TmpDir::new("snap-jailed");
    let (snap, _cold) = prewarmed_python_snapshot(&bundle);

    let mut cfg = agent_rootfs_config();
    cfg.jail = Some(Jail::default());

    // The VMM behind `pid` runs as the dropped jail uid, the confinement actually holding.
    let vmm_uid = |pid: u32| {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|v| v.split_whitespace().next().map(str::to_string))
            })
    };

    // Direct jailed restore: confined, exec-ready, and actually functional.
    let clone = Vm::restore(&snap, &cfg).expect("jailed prewarmed restore should resume");
    assert_eq!(
        vmm_uid(clone.vmm_pid()).as_deref(),
        Some(DEFAULT_JAIL_UID.to_string()).as_deref(),
        "the restored VMM should run as the dropped jail uid"
    );
    let out = clone
        .exec(&["python3".into(), "-c".into(), "print(6 * 7)".into()], b"")
        .expect("exec python on the jailed prewarmed clone");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "42",
        "jailed clone should run prewarmed Python; console:\n{}",
        clone.console()
    );
    assert_eq!(out.exit_code, 0);
    clone.shutdown().expect("jailed clone shutdown");

    // The confined prewarmed pool: every pooled clone restored under the jailer, health-checked and
    // exec-ready on take.
    let mut pool = Pool::new(snap, cfg, 2).expect("jailed pool should prefill");
    assert_eq!(pool.ready(), 2, "both confined clones should be pooled");
    for pid in pool.vmm_pids() {
        assert_eq!(
            vmm_uid(pid).as_deref(),
            Some(DEFAULT_JAIL_UID.to_string()).as_deref(),
            "every pooled VMM should run as the dropped jail uid"
        );
    }
    let vm = pool.take().expect("take a confined clone");
    let out = vm
        .exec(&["echo".into(), "confined".into()], b"")
        .expect("exec on the pooled confined clone");
    assert_eq!(out.stdout, b"confined\n");
    assert_eq!(out.exit_code, 0);
    vm.shutdown().expect("pooled clone shutdown");
    pool.shutdown();
}

#[test]
#[ignore = "needs /dev/kvm + real root + the jailer + delegated cgroups (run via `cargo xtask ci-privileged` as root)"]
fn restored_clone_cpu_cap_follows_the_snapshot_not_the_config() {
    // The `cpu.max` a jailed restore re-applies must come from the snapshot's **recorded** vCPU
    // count, the clone's true parallelism, since the vCPUs come from the snapshot state (restore
    // issues no `PUT /machine-config`) and nothing forces the restoring `config` to agree. A
    // 2-vCPU source restored under a default (1-vCPU) config must be capped at 2 cores' worth,
    // not silently throttled to 1, the CPU analogue of `restore_mem_mib`'s never-below-the-true-RAM
    // guarantee.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping restored_clone_cpu_cap_follows_the_snapshot_not_the_config: needs real root"
        );
        return;
    }
    let mut src_cfg = agent_rootfs_config();
    src_cfg.vcpus = NonZeroU8::new(2).expect("2 is nonzero");
    let source = Vm::boot(src_cfg).expect("2-vCPU agent microVM should boot");
    let bundle = TmpDir::new("snap-cpu-cap");
    let snap = source
        .snapshot(bundle.path())
        .expect("snapshot the 2-vCPU source");
    assert_eq!(
        snap.vcpus().get(),
        2,
        "the bundle must record the source's vCPU count"
    );
    source.shutdown().expect("source shutdown");

    // Restore with the *default* (1-vCPU) config: the cap must follow the snapshot, not this.
    let mut cfg = agent_rootfs_config();
    cfg.jail = Some(Jail::default());
    assert_eq!(cfg.vcpus.get(), 1, "the restoring config declares 1 vCPU");
    let clone = Vm::restore(&snap, &cfg).expect("jailed restore of the 2-vCPU snapshot");
    let cgroup = cgroup_of(clone.vmm_pid()).expect("the jailed clone lives in a cgroup");
    let cpu_max =
        std::fs::read_to_string(cgroup.join("cpu.max")).expect("read the clone's cpu.max");
    let mut fields = cpu_max.split_whitespace();
    let quota = fields.next().expect("cpu.max quota field");
    if quota == "max" {
        // No cap was written at all, the fail-open path (cpu/memory not delegated). The derivation
        // under test never ran, so skip rather than pass vacuously.
        eprintln!(
            "skipping restored_clone_cpu_cap_follows_the_snapshot_not_the_config: cgroup \
             controllers not delegated (cpu.max is `max`)"
        );
        clone.shutdown().expect("clone shutdown");
        return;
    }
    let quota: u64 = quota.parse().expect("numeric cpu.max quota");
    let period: u64 = fields
        .next()
        .expect("cpu.max period field")
        .parse()
        .expect("numeric cpu.max period");
    assert_eq!(
        quota,
        2 * period,
        "cpu.max must grant the snapshot's 2 vCPUs' worth, not the config's 1 (cpu.max: {})",
        cpu_max.trim()
    );

    // And the mis-declared clone still works: both vCPUs are real, the cap didn't break the run.
    let out = clone
        .exec(&["nproc".into()], b"")
        .expect("exec on the restored clone");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "2",
        "the clone runs the snapshot's 2 vCPUs regardless of the config's declaration"
    );
    clone.shutdown().expect("clone shutdown");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restored_clones_do_not_share_entropy_or_freeze_the_clock() {
    // Decision 011, entropy + clocks. Every clone wakes from the same memory image, so if the
    // kernel CRNG never reseeded, two clones' first `getrandom` draws would be byte-identical, the
    // classic clone-entropy vulnerability (shared session keys/nonces/UUIDs). The pinned stack has
    // both halves of the fix (Firecracker v1.9 ships VMGenID; kernel 6.1 has the vmgenid driver,
    // which reseeds the CRNG on a generation bump): this proves it end to end. Clock skew is
    // measured and reported, not asserted (decision 011 records the posture).
    let bundle = TmpDir::new("snap-entropy");
    let (snap, _cold) = prewarmed_python_snapshot(&bundle);

    let draw = |label: &str| {
        let clone = Vm::restore(&snap, &agent_rootfs_config())
            .unwrap_or_else(|e| panic!("clone {label} should restore: {e}"));
        let out = clone
            .exec(
                &[
                    "python3".into(),
                    "-c".into(),
                    // One read, immediately after restore, the dangerous window, before any natural
                    // interrupt-entropy reseed could paper over shared CRNG state.
                    "import os, time; print(os.urandom(16).hex()); print(int(time.time()))".into(),
                ],
                b"",
            )
            .unwrap_or_else(|e| panic!("clone {label} exec: {e}"));
        assert_eq!(out.exit_code, 0, "clone {label} python should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut lines = stdout.lines();
        let hex = lines.next().unwrap_or_default().trim().to_string();
        let epoch: i64 = lines.next().unwrap_or_default().trim().parse().unwrap_or(0);
        assert_eq!(
            hex.len(),
            32,
            "clone {label} should print 16 random bytes as hex"
        );
        clone
            .shutdown()
            .unwrap_or_else(|e| panic!("clone {label} shutdown: {e}"));
        (hex, epoch)
    };

    let (hex_a, epoch_a) = draw("A");
    let (hex_b, _epoch_b) = draw("B");
    assert_ne!(
        hex_a, hex_b,
        "two clones' first urandom draws must differ (VMGenID must reseed the CRNG on restore)"
    );

    // Clock posture (measured, not asserted): report the restored guest's wall-clock skew vs the
    // host. kvm-clock keeps the monotonic clock sane; CLOCK_REALTIME may lag by the snapshot age.
    let host_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    eprintln!(
        "clock: restored clone A wall-clock skew vs host ≈ {}s",
        host_epoch - epoch_a
    );
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn pool_serves_prewarmed_clones_and_discards_dead_ones() {
    // The prewarmed Pool. Prefill keeps clones exec-ready so `take` is a pop (µs) plus a fast
    // health probe, not a cold boot. A clone that died while pooled is a typed GuestUnavailable
    // from the probe, so `take` discards it and serves the next (or restores inline when dry)
    // instead of surfacing an infra failure, the retry semantics the deferral promised.
    use agent_vmm::Pool;

    let bundle = TmpDir::new("snap-pool");
    let (snap, cold_boot) = prewarmed_python_snapshot(&bundle);

    let mut pool = Pool::new(snap, agent_rootfs_config(), 2)
        .expect("pool should prefill two prewarmed clones");
    assert_eq!(pool.ready(), 2, "prefill should hit the target");

    // Fast path: take a ready clone and run code on it. The take is a pop + probe, so it must come
    // in far under a cold boot (the measured margin is printed, the bound asserted is generous).
    let t0 = std::time::Instant::now();
    let vm = pool.take().expect("take from a full pool");
    let take_latency = t0.elapsed();
    let out = vm
        .exec(&["python3".into(), "-c".into(), "print(1 + 1)".into()], b"")
        .expect("exec on a pooled clone");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
    assert!(
        take_latency < cold_boot,
        "take ({take_latency:?}) should be far under a cold boot ({cold_boot:?})"
    );
    eprintln!("pool: take {take_latency:?} vs cold boot {cold_boot:?}");
    vm.shutdown().expect("pooled clone shutdown");
    assert_eq!(pool.ready(), 1, "take should consume ready stock");

    // Kill the remaining pooled clone's VMM behind the pool's back: the next take must *not* hand
    // out the corpse, the probe fails typed, the corpse is discarded, and (the pool now being dry)
    // a fresh clone is restored inline and served.
    let pids = pool.vmm_pids();
    assert_eq!(pids.len(), 1);
    let killed = std::process::Command::new("kill")
        .args(["-9", &pids[0].to_string()])
        .status()
        .expect("kill the pooled VMM");
    assert!(killed.success(), "SIGKILL the pooled VMM");
    std::thread::sleep(Duration::from_millis(100)); // let the socket die

    let vm2 = pool
        .take()
        .expect("take must discard the dead clone and restore a fresh one");
    let out2 = vm2
        .exec(&["python3".into(), "-c".into(), "print(2 + 2)".into()], b"")
        .expect("exec on the replacement clone");
    assert_eq!(String::from_utf8_lossy(&out2.stdout).trim(), "4");
    vm2.shutdown().expect("replacement clone shutdown");
    assert_eq!(pool.ready(), 0, "the corpse was discarded, not re-pooled");

    // Explicit top-up back to target, then graceful teardown of the stock.
    let restored = pool.refill().expect("refill should restore to target");
    assert_eq!(restored, 2);
    assert_eq!(pool.ready(), 2);
    pool.shutdown();
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn pool_over_a_no_vsock_snapshot_keeps_its_stock() {
    // A snapshot without the vsock exec channel has nothing to health-probe: `probe_agent` would
    // return the permanent `require_vsock` error, a structural condition, not a dead clone. `take`
    // must hand the popped clone out directly instead of reading that error as "unhealthy" and
    // discarding the whole prewarmed inventory (the pre-fix bug tore down every clone on the first take,
    // then restored a fresh unprobed one, leaving `ready()` at 0). Prove the stock survives a take.
    let cfg = config(); // plain rootfs, no `guest_cid` → the snapshot carries no vsock
    let source = Vm::boot(cfg.clone()).expect("source microVM should boot");
    let bundle = TmpDir::new("snap-novsock-pool");
    let snap = source
        .snapshot(bundle.path())
        .expect("snapshot of a no-vsock VM should succeed");
    source.shutdown().expect("source shutdown");

    let mut pool = Pool::new(snap, cfg, 2).expect("prefill two no-vsock clones");
    assert_eq!(pool.ready(), 2, "prefill should hit the target");
    let vm = pool
        .take()
        .expect("take must hand out a clone, not discard the stock on the no-vsock condition");
    assert!(vm.vmm_pid() > 0, "a live clone should be handed out");
    assert_eq!(
        pool.ready(),
        1,
        "take pops exactly one; the rest stay pooled (not torn down)"
    );
    vm.shutdown().expect("clone shutdown");
    pool.shutdown();
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn prewarmed_restore_returns_output_in_far_under_cold_boot() {
    // The prewarm payoff asserted, not eyeballed: from "restore a prewarmed Python snapshot" to
    // "the code's output is back on the host" in well under the source's cold-boot latency. The
    // bound is generous twofold: the asserted 2x margin is far inside the measured ~6.6x (the boot-modes
    // bench, n=100: restore-to-output p50 105 ms vs cold boot + exec p50 689 ms), and `cold_boot`
    // itself understates the cold path, which pays boot *plus* this same exec.
    let bundle = TmpDir::new("snap-warm-fast");
    let (snap, cold_boot) = prewarmed_python_snapshot(&bundle);

    let t0 = std::time::Instant::now();
    let restored =
        Vm::restore(&snap, &agent_rootfs_config()).expect("prewarmed restore should resume");
    let argv = ["python3", "-c", "print(6 * 7)"].map(String::from);
    let out = restored
        .exec(&argv, &[])
        .expect("exec on the restored prewarmed clone should succeed");
    let to_output = t0.elapsed();

    assert_eq!(out.exit_code, 0, "python should exit 0");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "42",
        "the restored clone should compute and return the output"
    );
    assert!(
        to_output * 2 < cold_boot,
        "restore-to-output ({to_output:?}) should be far under a cold boot ({cold_boot:?})"
    );
    eprintln!("prewarmed restore to output {to_output:?} vs cold boot {cold_boot:?}");
    restored
        .shutdown()
        .expect("restored shutdown should succeed");
}
