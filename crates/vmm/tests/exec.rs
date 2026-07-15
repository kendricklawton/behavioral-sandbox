//! Privileged integration tests for running code in the microVM: exec through the baked-in agent,
//! the Python/Node/static-native runtimes, and the bulk input/output block devices.
//!
//! `#[ignore]`d because they need `/dev/kvm` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use agent_vmm::Vm;

use common::{
    agent_rootfs_config, have_jailer_privileges, jailed_agent_config, sha256_hex, TmpDir,
};

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn execs_a_command_in_the_microvm() {
    // Closes Phase 2's provisional "in a microVM" gate: the agent baked into `rootfs-agent.ext4`
    // actually binds vsock in a real guest, so `exec` round-trips end to end — not against a faked
    // socket. Boot returns once the agent's readiness marker reaches the console, so the connect
    // can't race the bind.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");
    let out = vm
        .exec(&["echo".into(), "hi".into()], b"")
        .expect("exec `echo hi` in the guest");
    assert_eq!(
        out.stdout,
        b"hi\n",
        "guest stdout should be `hi`; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0, "`echo hi` should exit 0");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + real root + the jailer (run via `cargo xtask ci-privileged` as root)"]
fn jailed_exec_runs_a_command() {
    // The convergence proof: a VM confined by the jailer (chroot + dropped uid/gid + mount namespace
    // + cgroup limits + seccomp) can *also* run code. Before this, the exec channel (vsock) and the
    // jail were mutually exclusive — you got a code channel or VMM confinement, never both. Now the
    // vsock unix socket is bound chroot-relative under the dropped uid, so `exec` round-trips through
    // the same jailed VMM. Needs real root (the jailer `mknod`s device nodes); skip rather than fail
    // where KVM is available but real root isn't (the `unshare -Urn` trick can't `mknod`).
    if !have_jailer_privileges() {
        eprintln!("skipping jailed_exec_runs_a_command: needs real root (euid 0, initial userns)");
        return;
    }
    let vm = Vm::boot(jailed_agent_config())
        .expect("jailed agent microVM should boot and announce readiness");
    // The VMM really is jailed (not a plain boot that happens to exec): it runs as the dropped uid.
    let pid = vm.vmm_pid();
    let uid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|v| v.split_whitespace().next().map(str::to_string))
        });
    assert_eq!(
        uid.as_deref(),
        Some(agent_vmm::DEFAULT_JAIL_UID.to_string()).as_deref(),
        "the exec'ing VMM should be the dropped jail uid, proving it is confined"
    );
    let out = vm
        .exec(&["echo".into(), "hi".into()], b"")
        .expect("exec `echo hi` in the jailed guest");
    assert_eq!(
        out.stdout,
        b"hi\n",
        "jailed guest stdout should be `hi`; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0, "`echo hi` should exit 0 under the jailer");
    vm.shutdown().expect("jailed shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn execs_python_in_the_microvm() {
    // The reference language runtime: `build-rootfs` installs python3 from the pinned Alpine
    // branch, and a real interpreter (dynamic musl binary + its stdlib, not a shell builtin) runs
    // in the guest and computes — proving the image carries a working userland, not just busybox.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");
    let out = vm
        .exec(&["python3".into(), "-c".into(), "print(2+2)".into()], b"")
        .expect("exec python in the guest");
    assert_eq!(
        out.stdout,
        b"4\n",
        "python should print 4; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0, "python should exit 0");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn python_script_writes_a_file_and_we_capture_it() {
    // Phase 3's runtime payoff, end to end: inject a small **Python script** as a file, run the real
    // interpreter on it inside a microVM, and pull back the file it wrote — the exec surface's
    // inject → run → capture loop with an actual language runtime (using the stdlib, `json`), not a
    // shell builtin. This is the per-file channel path (P2.5); the bulk block-device paths are
    // P3.4/P3.5.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");

    // A real script: import a stdlib module, compute, and write a file in the working dir.
    let script = "import json\n\
                  with open('result.json', 'w') as f:\n\
                  \x20\x20\x20\x20json.dump({'answer': 6 * 7}, f)\n";

    let out = vm
        .exec_with_files(
            &["python3".into(), "script.py".into()],
            b"",
            &[("script.py".into(), script.as_bytes().to_vec())],
            &["result.json".into()],
        )
        .expect("run the python script and capture its output file");

    assert_eq!(
        out.exit_code,
        0,
        "python should exit 0; console:\n{}",
        vm.console()
    );
    // Exactly the one requested artifact comes back, holding what the script computed.
    assert_eq!(out.files.len(), 1, "one artifact requested and returned");
    let (path, data) = &out.files[0];
    assert_eq!(path, "result.json");
    let text = String::from_utf8_lossy(data);
    assert!(
        text.contains("\"answer\"") && text.contains("42"),
        "captured file should hold the JSON the script wrote; got {text:?}"
    );
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn runs_node_a_second_interpreter() {
    // P3.9 runtime-agnostic proof, second half: a *different* interpreter (Node) runs unchanged
    // through the same exec path as Python — the rootfs isn't Python-specific. Inject a small `.js`,
    // run the real `node` on it, and capture the file it writes (the per-file channel path, P2.5).
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");

    // A real Node script: use the runtime's own APIs (JSON + fs) to write a file.
    let script = "const fs = require('fs');\n\
                  fs.writeFileSync('result.json', JSON.stringify({ answer: 6 * 7 }));\n";

    let out = vm
        .exec_with_files(
            &["node".into(), "script.js".into()],
            b"",
            &[("script.js".into(), script.as_bytes().to_vec())],
            &["result.json".into()],
        )
        .expect("run the node script and capture its output file");

    assert_eq!(
        out.exit_code,
        0,
        "node should exit 0; console:\n{}",
        vm.console()
    );
    assert_eq!(out.files.len(), 1, "one artifact requested and returned");
    let (path, data) = &out.files[0];
    assert_eq!(path, "result.json");
    let text = String::from_utf8_lossy(data);
    assert!(
        text.contains("\"answer\"") && text.contains("42"),
        "captured file should hold the JSON Node wrote; got {text:?}"
    );
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs + the static example (run via `cargo xtask ci-privileged`)"]
fn runs_a_static_native_binary_and_captures_its_artifact() {
    // P3.9 runtime-agnostic proof: a **static native ELF** (no interpreter, no libc, no loader) runs
    // unchanged through the same exec path. Inject the binary read-only via a block device (P3.4),
    // exec it, and capture the file it writes via the output device (P3.5) — showing the engine runs
    // *any* Linux binary handed in at runtime, not just the baked-in interpreters. (Contrast the
    // Wasmtime sibling, which needs code recompiled to wasm32.)
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bin = root.join("target/x86_64-unknown-linux-musl/release/examples/writefile");
    assert!(
        bin.is_file(),
        "missing static example at {} — run `cargo xtask build-guest-example` (ci-privileged does)",
        bin.display()
    );

    let indir = TmpDir::new("p39in");
    let outdir = TmpDir::new("p39out");
    std::fs::create_dir_all(indir.path()).expect("input dir");
    // `fs::copy` preserves the 0755 mode, which `mke2fs -d` carries into the read-only `/input` image,
    // so the guest can exec it directly (the mount is `-o ro`, not `noexec`).
    std::fs::copy(&bin, indir.path().join("writefile")).expect("stage the native binary");

    let mut cfg = agent_rootfs_config();
    cfg.input_dir = Some(indir.path().to_path_buf());
    cfg.output_dir = Some(outdir.path().to_path_buf());
    let vm = Vm::boot(cfg).expect("microVM with input + output devices should boot");
    let out = vm
        .exec(
            &["/input/writefile".into(), "/output/answer.txt".into()],
            b"",
        )
        .expect("run the injected native binary");
    assert_eq!(
        out.exit_code,
        0,
        "native binary should exit 0; console:\n{}",
        vm.console()
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("writefile ok"),
        "native binary should print its marker; got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Consumes the VM: stop it, then read the output device back.
    let captured = vm.collect_outputs().expect("pull /output back");
    assert!(
        captured.iter().any(|p| p == "answer.txt"),
        "the native binary's artifact should be captured; got {captured:?}"
    );
    let text = std::fs::read_to_string(outdir.path().join("answer.txt")).expect("read answer.txt");
    assert!(
        text.contains("6*7=42"),
        "captured file should hold the native binary's payload; got {text:?}"
    );
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn injects_a_large_file_via_block_device() {
    // P3.4: a whole-working-dir / large-file input path the vsock channel can't carry. Stage a file
    // **larger than the 1 MiB channel frame cap** (the whole point) in a host dir, inject it as a
    // read-only block device, and prove the guest reads it back byte-for-byte from `/input`.
    let dir = std::env::temp_dir().join(format!("agent-p34-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("input dir");
    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect(); // 4 MiB, > 1 MiB
    std::fs::write(dir.join("big.bin"), &payload).expect("write input file");

    let mut cfg = agent_rootfs_config();
    cfg.input_dir = Some(dir.clone());
    let vm = Vm::boot(cfg).expect("microVM with an input block device should boot");
    let out = vm
        .exec(
            &[
                "sh".into(),
                "-c".into(),
                "wc -c < /input/big.bin && sha256sum /input/big.bin".into(),
            ],
            b"",
        )
        .expect("read the injected file from /input");
    let _ = std::fs::remove_dir_all(&dir);

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("4194304"),
        "guest should see the 4 MiB file; got:\n{text}\nconsole:\n{}",
        vm.console()
    );
    // Content integrity end to end: the sha256 the guest computed must match the host bytes.
    let mut hasher_input = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sha256sum");
    use std::io::Write as _;
    hasher_input
        .stdin
        .take()
        .expect("stdin")
        .write_all(&payload)
        .expect("feed payload");
    let host_hash = hasher_input.wait_with_output().expect("host sha256");
    let host_hex = String::from_utf8_lossy(&host_hash.stdout);
    let host_hex = host_hex.split_whitespace().next().expect("host hash hex");
    assert!(
        text.contains(host_hex),
        "guest sha256 must match host {host_hex}; guest output:\n{text}"
    );
    assert_eq!(out.exit_code, 0);
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn collects_outputs_via_block_device() {
    // P3.5: the whole-working-dir / large-file *output* path the vsock channel can't carry — the
    // counterpart to `injects_a_large_file_via_block_device`. Boot with a writable output device, have
    // the guest write a file **larger than the 1 MiB channel frame cap**, a nested file, and a
    // host-escaping symlink into `/output`; pull the tree back and prove it arrived byte-for-byte —
    // and that the escaping symlink was dropped, not recreated live on the host.
    let dir = TmpDir::new("p35");

    let mut cfg = agent_rootfs_config();
    cfg.output_dir = Some(dir.path().to_path_buf());
    let vm = Vm::boot(cfg).expect("microVM with an output block device should boot");
    let out = vm
        .exec(
            &[
                "sh".into(),
                "-c".into(),
                "mkdir -p /output/sub \
                 && head -c 4194304 /dev/urandom > /output/big.bin \
                 && printf nested > /output/sub/y \
                 && ln -s /etc/passwd /output/escape \
                 && sha256sum /output/big.bin"
                    .into(),
            ],
            b"",
        )
        .expect("write outputs in the guest");
    assert_eq!(
        out.exit_code,
        0,
        "guest write failed; console:\n{}",
        vm.console()
    );
    let guest_hash = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("guest sha256 hex")
        .to_string();

    // Consumes the VM: stops it, then reads the image back.
    let captured = vm.collect_outputs().expect("pull the output tree back");

    // The large file and the nested file arrived; the escaping symlink is absent from the manifest.
    assert!(
        captured.iter().any(|p| p == "big.bin"),
        "big.bin missing from {captured:?}"
    );
    assert!(
        captured.iter().any(|p| p == "sub/y"),
        "sub/y missing from {captured:?}"
    );
    assert!(
        !captured.iter().any(|p| p == "escape"),
        "escaping symlink should be dropped: {captured:?}"
    );

    // Byte-for-byte integrity of a > 1 MiB file the channel frame can't carry in one piece.
    let big = std::fs::read(dir.path().join("big.bin")).expect("read big.bin back");
    assert_eq!(big.len(), 4 * 1024 * 1024, "big.bin should be 4 MiB");
    assert_eq!(
        sha256_hex(&big),
        guest_hash,
        "host readback must match the guest's sha256"
    );

    let nested = std::fs::read(dir.path().join("sub/y")).expect("read sub/y");
    assert_eq!(nested, b"nested");

    // Security (S1): the `escape -> /etc/passwd` symlink must not exist as a live host symlink, and
    // the ext4 `lost+found` housekeeping dir must be pruned.
    assert!(
        std::fs::symlink_metadata(dir.path().join("escape")).is_err(),
        "host-escaping symlink must be removed, not recreated on the host"
    );
    assert!(
        std::fs::symlink_metadata(dir.path().join("lost+found")).is_err(),
        "lost+found must be pruned"
    );
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn reaps_the_whole_process_tree_so_a_daemon_cannot_wedge_exec() {
    // P6.4 (closes the P2.6 gap): a command double-forks a `setsid` daemon that escapes the process
    // group and inherits the command's stdout, then the parent exits 0. Before P6.4 that daemon kept
    // the stdout pipe's write end open, so the agent's output pumps never saw EOF and the exec wedged
    // until the daemon died (~30s here). Now the agent runs each command in its own cgroup and reaps
    // the whole tree via `cgroup.kill`, so the exec returns immediately with the parent's exit code
    // and the daemon is actually gone. `cgroup.kill` catches the `setsid` process a `killpg` would
    // miss, which is the whole point of using the cgroup rather than the process group.
    let vm = Vm::boot(agent_rootfs_config()).expect("agent microVM should boot");

    // fork -> setsid -> exec `sleep 30` (so its comm is `sleep` and it holds the inherited stdout);
    // the parent exits 0 straight away.
    let daemon = "import os\n\
                  if os.fork() == 0:\n    \
                  os.setsid()\n    \
                  os.execvp(\"sleep\", [\"sleep\", \"30\"])\n\
                  else:\n    \
                  os._exit(0)\n";
    let started = Instant::now();
    let out = vm
        .exec(&["python3".into(), "-c".into(), daemon.into()], b"")
        .expect("exec should return promptly, not wedge on the daemon");
    let elapsed = started.elapsed();
    assert_eq!(
        out.exit_code, 0,
        "the parent process exits 0; got {}",
        out.exit_code
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "exec should return once the tree is reaped, not wait ~30s for the daemon (took {elapsed:?})"
    );

    // The daemon was killed, not merely detached: no `sleep` process survives in the guest. A working
    // second exec also proves the connection wasn't wedged.
    let survivors = vm
        .exec(
            &[
                "sh".into(),
                "-c".into(),
                "grep -l '^sleep$' /proc/[0-9]*/comm 2>/dev/null | wc -l".into(),
            ],
            b"",
        )
        .expect("liveness exec should work (agent not wedged)");
    let n: i64 = String::from_utf8_lossy(&survivors.stdout)
        .trim()
        .parse()
        .unwrap_or(-1);
    assert_eq!(
        n, 0,
        "the daemon's process tree should be reaped; found {n} `sleep` process(es)"
    );

    vm.shutdown().expect("shutdown should succeed");
}
