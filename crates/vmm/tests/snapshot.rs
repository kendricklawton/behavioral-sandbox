//! Privileged integration tests for snapshots and warm start: the self-contained bundle, restore,
//! concurrent warm clones, the restore fix-ups (network identity, entropy, clocks), the warm
//! `Pool`, and the restore-beats-cold-boot payoff.
//!
//! `#[ignore]`d because they need `/dev/kvm` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::time::Duration;

use agent_vmm::Vm;

use common::{agent_rootfs_config, config, have_net_admin, warm_python_snapshot, TmpDir};

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn snapshots_a_running_microvm() {
    // P5.1: pause a booted VM and take a full snapshot (memory + state) via the API. The bundle is
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
    // The memory file is roughly the guest's RAM (256 MiB default) — a sanity floor, not an exact
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
    // P5.2: snapshot a VM, throw it away, then restore from the bundle on a fresh VMM and confirm it
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
fn warm_snapshot_restores_and_runs_code() {
    // P5.3: snapshot a warm agent VM (runtime loaded), throw the source away, restore a clone off the
    // shared read-only base, and run Python on it — the exec channel survives the snapshot (Firecracker
    // re-binds vsock on restore), so a warm clone runs code without paying the cold boot.
    let bundle = TmpDir::new("snap-warm");
    let (snap, cold_boot) = warm_python_snapshot(&bundle);
    // A warm (read_only_root) snapshot references the shared base in place, so the bundle carries no
    // root-disk copy: the disk path points outside the bundle dir, not at a copy within it.
    assert!(
        !snap.root_drive_path().starts_with(bundle.path()),
        "a read_only_root snapshot should reference the shared base, not copy it into the bundle"
    );

    let restored = Vm::restore(&snap, &agent_rootfs_config()).expect("warm restore should resume");
    let restore_latency = restored.boot_latency();
    let argv = ["python3", "-c", "print(2 + 2)"].map(String::from);
    let out = restored
        .exec(&argv, &[])
        .expect("exec on the restored warm clone should succeed");
    assert_eq!(out.exit_code, 0, "python should exit 0");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "4",
        "restored warm clone should run Python and return 4"
    );
    // A restored VM's live disk is an anonymous inode with no host path, so re-snapshotting it must be
    // refused, not silently bundle a stale / shared-writable disk.
    let redo = TmpDir::new("snap-warm-redo");
    assert!(
        restored.snapshot(redo.path()).is_err(),
        "re-snapshotting a restored VM should be refused"
    );

    eprintln!("warm: cold boot {cold_boot:?} vs restore {restore_latency:?} + exec");
    restored
        .shutdown()
        .expect("restored shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restores_concurrent_clones_from_one_warm_snapshot() {
    // P5.4: restore several clones from one warm snapshot and keep them all alive at once. Each shares
    // the read-only base (density) but is an independent VM — its own vsock socket (bound relative to
    // its own scratch dir, so no collision) and its own in-RAM overlay. Prove it by running a distinct
    // computation on each concurrently-alive clone and getting each clone's own answer back.
    const N: usize = 3;
    let bundle = TmpDir::new("snap-warm-clones");
    let (snap, _cold) = warm_python_snapshot(&bundle);

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
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restored_networked_clone_gets_a_fresh_identity() {
    // P5.5 (decision 011), network identity: the kernel `ip=` config runs once at the source's boot
    // and can't re-fire on restore, so the clone would wake with the snapshot's baked-in address on a
    // link it no longer matches. The driver recreates the snapshot's tap (fresh /30 on the host end)
    // and the agent applies the guest's fresh address over vsock — this proves the clone ends up on
    // its NEW /30 (old address gone), reachable at the transport layer, still deny-by-default.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }

    // A networked snapshot without vsock has no channel to re-address the clone: refused, typed.
    // (The stock rootfs config: it boots to `login:` with no vsock, exactly the shape under test —
    // the agent rootfs can't boot vsock-less, since its readiness marker is the agent's post-bind.)
    let mut no_vsock = config();
    no_vsock.enable_network = true;
    let vm = Vm::boot(no_vsock).expect("networked VM without vsock should still boot");
    let refused = TmpDir::new("snap-net-novsock");
    assert!(
        vm.snapshot(refused.path()).is_err(),
        "a networked snapshot without the vsock exec channel must be refused"
    );
    vm.shutdown().expect("no-vsock VM shutdown");

    // Source: networked + vsock + warm. Snapshot it, remember its identity, then drop it (freeing
    // its tap name and /30 — the recreated tap needs the name; the /30 must be provably re-allocated).
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let source = Vm::boot(cfg.clone()).expect("networked agent microVM should boot");
    let source_guest_ip = source.guest_ip().expect("source guest ip");
    let source_tap = source.tap_name().expect("source tap name").to_string();
    let bundle = TmpDir::new("snap-net-warm");
    let snap = source
        .snapshot(bundle.path())
        .expect("networked warm snapshot should succeed");
    source.shutdown().expect("source shutdown");

    let clone = Vm::restore(&snap, &cfg).expect("networked warm restore should resume");

    // Same tap name (the snapshot baked it in; v1.9 has no network_overrides), fresh /30.
    assert_eq!(
        clone.tap_name(),
        Some(source_tap.as_str()),
        "the clone must reuse the snapshot's recorded tap name"
    );
    let clone_guest_ip = clone.guest_ip().expect("clone guest ip");
    assert_ne!(
        clone_guest_ip, source_guest_ip,
        "the clone must get a fresh /30, not the source's baked-in one"
    );

    // In-guest: eth0 carries exactly the new address; the baked-in one is gone.
    let addrs = clone
        .exec(
            &[
                "ip".into(),
                "-4".into(),
                "addr".into(),
                "show".into(),
                "dev".into(),
                "eth0".into(),
            ],
            b"",
        )
        .expect("read the clone's eth0 addresses");
    let addrs = String::from_utf8_lossy(&addrs.stdout).into_owned();
    assert!(
        addrs.contains(&clone_guest_ip.to_string()),
        "clone eth0 should carry its fresh address {clone_guest_ip}; got:\n{addrs}"
    );
    assert!(
        !addrs.contains(&source_guest_ip.to_string()),
        "clone eth0 must not keep the snapshot's baked-in address {source_guest_ip}; got:\n{addrs}"
    );

    // Transport-layer proof on the NEW link: a real host listener on the fresh /30 is reachable.
    let clone_host_ip = clone.host_ip().expect("clone host ip");
    let listener = std::net::TcpListener::bind((clone_host_ip, 0)).expect("bind on the fresh /30");
    let port = listener.local_addr().expect("local addr").port();
    let connect = clone
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!(
                    "import socket; socket.create_connection((\"{clone_host_ip}\", {port}), timeout=3).close()"
                ),
            ],
            b"",
        )
        .expect("guest connect to the fresh host end");
    assert_eq!(
        connect.exit_code,
        0,
        "clone should reach a listener on its fresh /30; console:\n{}",
        clone.console()
    );

    // Deny-by-default carried over the restore: still no default route.
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
        "restored clone must stay deny-by-default (no default route)"
    );

    clone.shutdown().expect("clone shutdown");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restored_clones_do_not_share_entropy_or_freeze_the_clock() {
    // P5.5 (decision 011), entropy + clocks. Every clone wakes from the same memory image, so if the
    // kernel CRNG never reseeded, two clones' first `getrandom` draws would be byte-identical — the
    // classic clone-entropy vulnerability (shared session keys/nonces/UUIDs). The pinned stack has
    // both halves of the fix (Firecracker v1.9 ships VMGenID; kernel 6.1 has the vmgenid driver,
    // which reseeds the CRNG on a generation bump): this proves it end to end. Clock skew is
    // measured and reported, not asserted (decision 011 records the posture).
    let bundle = TmpDir::new("snap-entropy");
    let (snap, _cold) = warm_python_snapshot(&bundle);

    let draw = |label: &str| {
        let clone = Vm::restore(&snap, &agent_rootfs_config())
            .unwrap_or_else(|e| panic!("clone {label} should restore: {e}"));
        let out = clone
            .exec(
                &[
                    "python3".into(),
                    "-c".into(),
                    // One read, immediately after restore — the dangerous window, before any natural
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
fn pool_serves_warm_clones_and_discards_dead_ones() {
    // P5.6: the warm Pool. Prefill keeps clones exec-ready so `take` is a pop (µs) plus a fast
    // health probe — not a cold boot. A clone that died while pooled is a typed GuestUnavailable
    // from the probe, so `take` discards it and serves the next (or restores inline when dry)
    // instead of surfacing an infra failure — the retry semantics the P2.7 deferral promised.
    use agent_vmm::Pool;

    let bundle = TmpDir::new("snap-pool");
    let (snap, cold_boot) = warm_python_snapshot(&bundle);

    let mut pool =
        Pool::new(snap, agent_rootfs_config(), 2).expect("pool should prefill two warm clones");
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
    // out the corpse — the probe fails typed, the corpse is discarded, and (the pool now being dry)
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
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn warm_restore_returns_output_in_far_under_cold_boot() {
    // P5.8: the phase's payoff asserted, not eyeballed: from "restore a warm Python snapshot" to
    // "the code's output is back on the host" in well under the source's cold-boot latency. The
    // bound is generous twofold: the asserted 2x margin is far inside the measured ~6.6x (P5.7's
    // bench, n=100: restore-to-output p50 105 ms vs cold boot + exec p50 689 ms), and `cold_boot`
    // itself understates the cold path, which pays boot *plus* this same exec.
    let bundle = TmpDir::new("snap-warm-fast");
    let (snap, cold_boot) = warm_python_snapshot(&bundle);

    let t0 = std::time::Instant::now();
    let restored = Vm::restore(&snap, &agent_rootfs_config()).expect("warm restore should resume");
    let argv = ["python3", "-c", "print(6 * 7)"].map(String::from);
    let out = restored
        .exec(&argv, &[])
        .expect("exec on the restored warm clone should succeed");
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
    eprintln!("warm restore to output {to_output:?} vs cold boot {cold_boot:?}");
    restored
        .shutdown()
        .expect("restored shutdown should succeed");
}
