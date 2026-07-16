//! `cargo xtask <cmd>` — dev orchestration for the agent sandbox engine.
//!
//! - **`ci`** — the host-safe gate (fmt · clippy `-D warnings` · build · test · docs · `deny`).
//!   Runs everywhere, needs no KVM or root, and mirrors `.github/workflows/ci.yml`.
//! - **`ci-privileged`** — the KVM/eBPF integration tests (the `#[ignore]`d ones). Needs
//!   `/dev/kvm` and elevated caps, so it's never part of the everyday loop. Builds the guest
//!   agent + the agent rootfs first, so the in-VM exec test has something to boot.
//! - **`setup`** — checks the host can do KVM + eBPF and reports what's missing.
//! - **`build-probes`** — build the eBPF object (`crates/probes`) for `bpfel-unknown-none` via
//!   `bpf-linker`, under the crate's own nightly toolchain. Host-safe (no KVM); skips with a note
//!   when `bpf-linker`/`rustup` are absent.
//! - **`build-rootfs`** — assemble the reproducible guest rootfs (Alpine base + baked-in agent).
//! - **`bench-boot`** — measure boot-to-userspace latency (percentiles) vs. the base size. Needs KVM.
//! - **`bench-warm`** — time-to-first-result percentiles: cold boot vs prewarmed-snapshot restore vs
//!   prewarmed-pool take. Needs KVM + the built agent rootfs.
//! - **`bench-trace`** — the syscall-tracing overhead (P9.5): per-`openat` cost with no probes vs
//!   attached-but-filtered-out vs attached-and-capturing. Needs `CAP_BPF`+`CAP_PERFMON` + the built
//!   object (not KVM).
//! - **`trace-sandbox`** — the Phase 9 exit-gate demo: boot a real sandbox and stream its
//!   cgroup-attributed host syscall footprint. Needs KVM + the agent rootfs + `CAP_BPF` + the object.
//! - **`watch-sandbox`** — the Phase 10 exit-gate demo: boot a real networked sandbox and watch its
//!   per-VM network flows on the tap. Needs KVM + the agent rootfs + `CAP_BPF`+`CAP_NET_ADMIN` + the object.
//! - **`enforce-sandbox`** — the Phase 11 exit-gate demo: boot a real networked sandbox, arm a
//!   deny-by-default egress policy allowing one endpoint, and show the allow-listed traffic passing while
//!   everything else is dropped at the tap and logged. Same needs as `watch-sandbox`.
//! - **`bench-meter`** — the resource-metering overhead (P12.4): per-context-switch cost with no meter vs
//!   attached-but-not-metering-us vs attached-and-metering-us. Needs `CAP_BPF`+`CAP_PERFMON` + the built
//!   object (not KVM).
//! - **`meter-sandbox`** — the Phase 12 exit-gate demo: boot a real sandbox, meter its cgroup, and show an
//!   idle guest charging near-zero host CPU while a CPU-heavy guest charges most of a core, plus the
//!   per-run resource summary. Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_PERFMON` + the object.
//!
//! Split by concern: `guest_bins` (the static musl in-guest builds), `rootfs` (the reproducible
//! image), `bench` (the latency benchmarks), `artifacts` (the pinned kernel/rootfs fetch); the
//! gates and the shared plumbing (paths, `cargo`/tool runners) live here.
//!
//! The eBPF crate (`crates/probes`) builds for `bpfel-unknown-none` and is excluded from the host
//! workspace; `build-probes` builds its object (with BTF) and is folded **into** `ci` (guarded, so
//! the CI gate still runs on hosts without the eBPF toolchain).
#![forbid(unsafe_code)]

mod artifacts;
mod bench;
mod demo;
mod guest_bins;
mod rootfs;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "dev orchestration for the agent sandbox engine"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host-safe gate: fmt · clippy `-D warnings` · build · test · docs · cargo-deny.
    Ci,
    /// Privileged integration tests (KVM + eBPF) — the `#[ignore]`d tests. Needs `/dev/kvm` + caps.
    CiPrivileged,
    /// Check the host can do KVM + eBPF; report what's missing.
    Setup,
    /// Build the eBPF object (`crates/probes`) for `bpfel-unknown-none` via `bpf-linker`, under the
    /// crate's own nightly toolchain (`build-std`). Host-safe; skips with a note when `bpf-linker` or
    /// `rustup` is missing. The object lands at `crates/probes/target/bpfel-unknown-none/release/probes`.
    BuildProbes,
    /// Download + sha256-verify the pinned guest kernel and rootfs into `artifacts/` (needs `curl`).
    FetchArtifacts,
    /// Build the guest agent as a static musl binary (baked into the rootfs by `build-rootfs`).
    BuildGuestAgent,
    /// Build the P3.9 static native-ELF fixture (`examples/writefile`) for the guest target — the
    /// runtime-agnostic test injects and runs it to prove the engine executes any static Linux binary.
    BuildGuestExample,
    /// Assemble the guest rootfs: a minimal Alpine base + the guest runtimes (python3) + the static
    /// agent + a vsock init, as an ext4 image at `artifacts/rootfs-agent.ext4` (needs `curl`,
    /// `tar`, `mke2fs`, `truncate`). Reproducible: two builds are byte-identical.
    BuildRootfs {
        /// Build a second time and assert the image is byte-identical, and fail if the resolved
        /// package closure has drifted from the committed lockfile. The reproducibility gate.
        #[arg(long)]
        verify: bool,
        /// Re-record the resolved package closure into the committed lockfile — the "re-pin" step
        /// after Alpine's branch repo bumps a package out from under the floating install.
        #[arg(long)]
        update_lock: bool,
    },
    /// Measure boot-to-userspace latency (percentiles) of the agent rootfs, on both the read-only
    /// shared base and the read-write per-VM copy, so the base **size**'s effect on boot is visible
    /// (P3.7). Needs `/dev/kvm` + the built agent rootfs.
    BenchBoot {
        /// How many boots to time per path (more → tighter tail percentiles). Default 100 — the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure time-to-first-result (percentiles) of the three start paths: a cold boot (per-VM
    /// rootfs copy, the Phase-1-style baseline), a prewarmed-snapshot restore, and a prewarmed-pool take,
    /// each timed from "start a sandbox" to "a Python one-liner's output is back on the host"
    /// (P5.7). Needs `/dev/kvm` + the built agent rootfs.
    BenchWarm {
        /// How many runs to time per path (more → tighter tail percentiles). Default 100, the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure the syscall-tracing overhead (P9.5): the per-`openat` cost with no probes attached, vs
    /// probes attached but filtered out, vs probes attached and writing each event to the ring buffer.
    /// The delta is the honest cost of tracing. Needs `CAP_BPF`+`CAP_PERFMON` + `cargo xtask
    /// build-probes` (not KVM).
    BenchTrace {
        /// How many bursts to time per condition (more → tighter tail percentiles). Default 100, the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure the resource-metering overhead (P12.4): the added per-context-switch cost of the attached
    /// `sched_switch` accounting probe, with no meter vs attached-but-not-metering-us vs
    /// attached-and-metering-us, on a ping-pong micro-workload. The delta is the honest cost; one shared
    /// program means it stays bounded under many sandboxes. Needs `CAP_BPF`+`CAP_PERFMON` + `cargo xtask
    /// build-probes` (not KVM).
    BenchMeter {
        /// How many bursts to time per condition (more → tighter tail percentiles). Default 100, the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// The Phase 9 exit-gate demo: boot a real sandbox and stream its host syscall footprint,
    /// attributed to the sandbox's cgroup (the VMM's host syscalls — the guest's stay in-guest).
    /// Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_PERFMON` + `cargo xtask build-probes`.
    TraceSandbox {
        /// Seconds to keep streaming the live trace after the boot+exec window is printed (`0` = just
        /// the boot+exec footprint).
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },
    /// The Phase 10 exit-gate demo: boot a real networked sandbox, attach a `tc` monitor to its tap
    /// inside its netns, drive guest traffic, and print the per-VM network flows and totals it counts.
    /// Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_NET_ADMIN` + `cargo xtask build-probes`.
    WatchSandbox {
        /// How many guest-traffic bursts to send, watching the per-VM counters climb each one.
        /// At least 1, enforced at parse (a zero-round watch would prove nothing).
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..))]
        rounds: u64,
    },
    /// The Phase 11 exit-gate demo: boot a real networked sandbox, arm a deny-by-default egress policy
    /// allowing one endpoint, and show the allow-listed traffic passing while everything else is dropped
    /// at the tap and recorded. Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_NET_ADMIN` + the object.
    EnforceSandbox,
    /// The Phase 12 exit-gate demo: boot a real sandbox, meter its cgroup with the `sched_switch`
    /// accounting probe, and show an idle guest charging near-zero host CPU while a CPU-heavy guest charges
    /// most of a core — plus the per-run resource summary (CPU from eBPF, memory/IO from cgroup v2). Needs
    /// `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_PERFMON` + the object.
    MeterSandbox,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::CiPrivileged => ci_privileged(),
        Cmd::Setup => setup(),
        Cmd::BuildProbes => build_probes(),
        Cmd::FetchArtifacts => artifacts::fetch_artifacts(),
        Cmd::BuildGuestAgent => guest_bins::build_guest_agent().map(|_| ()),
        Cmd::BuildGuestExample => guest_bins::build_guest_example().map(|_| ()),
        Cmd::BuildRootfs {
            verify,
            update_lock,
        } => rootfs::build_rootfs(verify, update_lock),
        Cmd::BenchBoot { runs } => bench::bench_boot(runs),
        Cmd::BenchWarm { runs } => bench::bench_warm(runs),
        Cmd::BenchTrace { runs } => bench::bench_trace(runs),
        Cmd::BenchMeter { runs } => bench::bench_meter(runs),
        Cmd::TraceSandbox { seconds } => demo::trace_sandbox(seconds),
        Cmd::WatchSandbox { rounds } => demo::watch_sandbox(rounds),
        Cmd::EnforceSandbox => demo::enforce_sandbox(),
        Cmd::MeterSandbox => demo::meter_sandbox(),
    }
}

/// The host-safe gate. `--locked` everywhere so a stale `Cargo.lock` fails here, not at release.
fn ci() -> Result<()> {
    cargo(&["fmt", "--all", "--check"])?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ])?;
    // Mirror CI's global `RUSTFLAGS=-D warnings` so the local gate and the runner agree on
    // rustc lints too, not just clippy's.
    cargo_env(
        &["build", "--workspace", "--locked"],
        &[("RUSTFLAGS", "-D warnings")],
    )?;
    cargo_env(
        &["test", "--workspace", "--locked"],
        &[("RUSTFLAGS", "-D warnings")],
    )?;
    cargo_env(
        &["doc", "--no-deps", "--workspace", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    cargo(&["deny", "check"])?;
    // P8.7: the eBPF object build is part of the CI gate. Host-safe and guarded — it skips with a note
    // when `bpf-linker`/`rustup` are absent, so `ci` still runs everywhere, but on a set-up dev box a
    // probe that fails to compile (or drops its BTF) now fails here, not later at load.
    build_probes()?;
    println!("\n✓ all checks passed");
    Ok(())
}

/// Booting a microVM and loading/attaching eBPF need `/dev/kvm` + elevated caps, so those tests are
/// `#[ignore]`d and run only here, on a machine that has them.
fn ci_privileged() -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("/dev/kvm not present — privileged tests need KVM (run on a KVM-capable host)");
    }
    // This gate builds and verifies the static guest agent (below), and that verification is the
    // *only* thing standing between a silently-reintroduced dynamic dependency and a confusing
    // in-guest loader failure. `verify_static` soft-skips when `readelf` is absent (so ad-hoc
    // `build-rootfs` still works), so require it *here* — a missing binutils must fail the CI gate
    // loudly, not quietly disarm the check.
    if !in_path("readelf") {
        bail!(
            "readelf (binutils) not found — the privileged gate verifies the guest agent is \
               statically linked and won't run that check blind; install binutils"
        );
    }
    // The boot tests need the pinned kernel + rootfs; fail with the fix rather than a cryptic
    // boot error. `fetch-artifacts` (not this gate) does the network download; here we verify
    // the hashes too — the sha256 is the contract, and a hand-placed or corrupted artifact
    // should fail this gate, not the boot inside it.
    for a in artifacts::artifacts()? {
        if !a.dest.is_file() {
            bail!(
                "missing artifact {} — run `cargo xtask fetch-artifacts` first",
                a.dest.display()
            );
        }
        let got = artifacts::sha256_of(&a.dest)?;
        if got != a.sha256 {
            bail!(
                "artifact {} does not match its pin (expected {}, got {}) — re-run \
                 `cargo xtask fetch-artifacts`",
                a.dest.display(),
                a.sha256,
                got
            );
        }
    }
    // The in-VM exec test boots a rootfs with the agent baked in — build it here (not from inside a
    // `#[test]`, which mustn't shell out to a musl `cargo build`). Idempotent: the Alpine base is
    // cached by sha256, so this is a rebuild of the agent + the image, not a re-download. `--verify`
    // makes this the reproducibility gate: it builds twice, asserts byte-identical, and fails on
    // package-closure drift from the lockfile.
    rootfs::build_rootfs(true, false)?;
    // The runtime-agnostic test (P3.9) injects a static native binary; build it here (musl), like the
    // agent — the same "don't shell a musl `cargo build` from a `#[test]`" rule. It is a *fixture*,
    // not part of the image, so it's built separately, not baked into the rootfs.
    guest_bins::build_guest_example()?;
    // The eBPF probe tests (P8.3/P8.4) load the object built from `crates/probes`; build it here (the
    // same "don't shell a nightly `cargo build` from a `#[test]`" rule). Guarded, so a privileged host
    // without `bpf-linker` skips the build and the probe tests then self-skip on the missing object.
    build_probes()?;
    // Serial (`--test-threads=1`): these tests each boot a real microVM and some assert on
    // host-global state (no leaked scratch dirs / taps / VMM processes, concurrent prewarmed clones). Run
    // in parallel they contend for KVM and, worse, one test's live scratch dir trips another's
    // leak check. Real-VM integration is I/O-bound on boot anyway, so serial costs little.
    cargo(&[
        "test",
        "--workspace",
        "--locked",
        "--",
        "--ignored",
        "--test-threads=1",
    ])?;
    println!("\n✓ privileged integration passed");
    Ok(())
}

/// Print a checklist of the host prerequisites; read-only, never fails the build.
fn setup() -> Result<()> {
    println!("agent — host capability check\n");
    check("/dev/kvm present", Path::new("/dev/kvm").exists());
    check("/dev/kvm writable (kvm group or root)", kvm_writable());
    check(
        "kernel BTF (/sys/kernel/btf/vmlinux)",
        Path::new("/sys/kernel/btf/vmlinux").exists(),
    );
    check("firecracker in PATH", in_path("firecracker"));
    check(
        "firecracker is the pinned v1.9 (API schema, decision 001)",
        firecracker_version() == Some((1, 9)),
    );
    check("jailer in PATH", in_path("jailer"));
    check(
        "cgroup v2 cpu+memory delegated (jailer resource limits)",
        cgroup_controllers_delegated(),
    );
    check(
        "kernel >= 5.14 (cgroup.kill — crash-safe VM teardown)",
        kernel_at_least(5, 14),
    );
    check("bpf-linker installed", in_path("bpf-linker"));
    check(
        "nightly toolchain + rust-src (eBPF object build: `cargo xtask build-probes`)",
        nightly_ebpf_ready(),
    );
    check("mke2fs (rootfs + input block device)", in_path("mke2fs"));
    check(
        "e2fsck + debugfs (output readback)",
        in_path("e2fsck") && in_path("debugfs"),
    );
    check(
        "readelf (binutils — static-link verification)",
        in_path("readelf"),
    );
    check("ip (iproute2 — per-VM tap device)", in_path("ip"));
    check(
        "guest kernel + rootfs (cargo xtask fetch-artifacts)",
        kernel_path().is_file() && boot_rootfs_path().is_file(),
    );

    // The degradation matrix (P6.9b): what each missing capability above costs, in one place, so
    // a mismatched host explains itself *before* the first boot discovers it. The split is decision
    // 013's: resource caps and leak-proofing fail open (they're DoS mitigation), the isolation
    // boundary never does.
    println!("\nDegradation matrix — what a missing item above means at runtime:");
    println!("  fails open (loud warning, still runs):");
    println!(
        "    cgroup v2 not delegated      -> jailed VMs run WITHOUT cpu/memory caps (decision 013)"
    );
    println!("    cgroup v2 not writable       -> Drop-only teardown; a SIGKILLed driver can leak its VM (decision 014)");
    println!("    kernel < 5.14 (no cgroup.kill) -> the lifetime sentinel cannot kill the VM tree (decision 014)");
    println!("    firecracker not v1.9         -> boots continue with a warning; API bodies may not match (decision 001)");
    println!("  hard errors (typed, never a silent half-measure):");
    println!("    /dev/kvm missing/unwritable  -> every boot fails: NoKvm (isolation is hardware)");
    println!("    jail cannot be built         -> jailed boot fails; never a half-confined VM (decision 013)");
    println!("    host tool missing (ip, mke2fs, e2fsck/debugfs, firecracker) -> typed Artifact/Vmm error");

    // The engine/hoster line (decision 016): the engine guarantees its own privileged tools can't
    // be weaponized; *deploying* them — as whom, when, over what directory — is the hoster's, and
    // these are the four calls only they can make. Surfaced here, in the host-check tool, because
    // that's the one place a self-hoster looks before standing the engine up.
    println!("\nHardening — the hoster's responsibility (the engine can't decide these for you):");
    println!(
        "    scratch base: point AGENT_SCRATCH_DIR at a dir only the engine user owns (not the"
    );
    println!(
        "                  world-writable /tmp default), so no other local user can plant residue"
    );
    println!("    run the sweep: schedule agent_vmm::sweep_orphans() (boot-time + periodic) — the");
    println!("                  engine exposes it; when/how often it runs is your ops call");
    println!("    one sweep per identity: a sweep reclaims only dirs its own euid owns, so if you");
    println!("                  run drivers as several users, each user must run its own sweep");
    println!("    the /16 pool: 10.200.0.0/16 is one finite, shared reservation pool; dividing it");
    println!(
        "                  across tenants (quota/fairness) is platform policy, above the engine"
    );

    println!("\neBPF probes (Phase 8+): loading + attaching needs CAP_BPF + CAP_PERFMON, not full");
    println!("             root — grant a loader binary just those with `setcap cap_bpf,cap_perfmon+ep`.");
    println!(
        "             A host without kernel BTF or those caps is named by a typed error, not a"
    );
    println!("             cryptic verifier reject (agent_probes_loader::check_support).");

    println!("\nMissing items are covered in docs/cli-install.md → Prerequisites.");
    Ok(())
}

/// Build the eBPF object (`crates/probes`) for `bpfel-unknown-none` via `bpf-linker` (P8.1). The
/// crate is **excluded** from the workspace and builds under its own nightly toolchain with
/// `-Z build-std` (rustup ships no prebuilt `core` for the BPF target), so this drives its build
/// directly rather than through the workspace `cargo`.
///
/// Guarded so `cargo xtask` stays runnable everywhere: on a host missing any of the toolchain
/// (`bpf-linker`, `rustup`, or the nightly + `rust-src` the `build-std` build needs), it prints a
/// note and returns `Ok` instead of failing — the everyday host gate must not require the eBPF
/// toolchain. A dev box installs it (`cargo xtask setup` lists the prereqs); this step is folded
/// into the `ci` gate (P8.7), and `ci-privileged` builds it before the probe tests.
fn build_probes() -> Result<()> {
    if !in_path("bpf-linker") {
        println!(
            "· skipping eBPF object build: bpf-linker not found \
             (install it: `cargo install bpf-linker`; see `cargo xtask setup`)"
        );
        return Ok(());
    }
    if !in_path("rustup") {
        println!(
            "· skipping eBPF object build: rustup not found \
             (crates/probes needs a nightly toolchain with `build-std`)"
        );
        return Ok(());
    }
    // The build below runs `rustup run nightly cargo build -Z build-std`, which needs the nightly
    // toolchain *and* its `rust-src` component. A host with `rustup` + `bpf-linker` but no nightly
    // would otherwise fall through to the build and `bail!`, failing the everyday gate — the exact
    // thing this guard exists to prevent (`ci` must run everywhere). Skip cleanly instead.
    if !nightly_ebpf_ready() {
        println!(
            "· skipping eBPF object build: nightly toolchain with `rust-src` not installed \
             (add it: `rustup toolchain install nightly && rustup component add rust-src \
             --toolchain nightly`; see `cargo xtask setup`)"
        );
        return Ok(());
    }
    let dir = workspace_root().join("crates/probes");
    // `rustup run nightly` forces the nightly toolchain the crate's `rust-toolchain.toml` pins: a
    // parent `cargo xtask` leaks `RUSTUP_TOOLCHAIN=stable` into this child, which would otherwise
    // override that file and fail `build-std`. The crate's `.cargo/config.toml` supplies the target +
    // `build-std`; `bpf-linker` (on PATH) links the object. `--locked` holds the probes lockfile.
    println!("$ rustup run nightly cargo build --release --locked  (in crates/probes → bpfel-unknown-none)");
    let status = Command::new("rustup")
        .args(["run", "nightly", "cargo", "build", "--release", "--locked"])
        .current_dir(&dir)
        .status()
        .context("building crates/probes (eBPF object)")?;
    if !status.success() {
        bail!(
            "eBPF object build failed (crates/probes) — a program the verifier would reject, or a \
             missing nightly toolchain / `rust-src` (see `cargo xtask setup`)"
        );
    }
    // P8.5: the object must carry BTF (`bpf-linker --btf`) — the CO-RE portability + BTF map typing
    // that lets aya relocate it against the running kernel. A missing `.BTF` section means the linker
    // arg regressed to a legacy-only, non-portable object; fail loudly rather than shipping it. The
    // check walks the ELF section headers for a section named exactly `.BTF` (not a raw byte scan,
    // which `.BTF.ext` alone or a coincidental byte run could satisfy).
    let obj = dir.join("target/bpfel-unknown-none/release/probes");
    let bytes =
        std::fs::read(&obj).with_context(|| format!("read built object {}", obj.display()))?;
    if !elf_has_section(&bytes, ".BTF") {
        bail!(
            "built eBPF object {} carries no .BTF section — is `-C link-arg=--btf` still set in \
             crates/probes/.cargo/config.toml (and `debug` kept in the profile)?",
            obj.display()
        );
    }
    println!("· eBPF object built (with BTF): {}", obj.display());
    Ok(())
}

/// Whether the ELF object in `bytes` has a section named exactly `name` (e.g. `.BTF`). A
/// dependency-free ELF64 little-endian section-header walk: read the section-header table, resolve
/// each section's name against the section-header string table, and compare. Precise where a raw
/// byte-substring scan is not — `.BTF.ext` alone or a coincidental byte run won't satisfy it. Returns
/// `false` on any malformed or non-ELF64-LE buffer, the safe direction for the build guard (a weird
/// object fails the check rather than passing it).
fn elf_has_section(bytes: &[u8], name: &str) -> bool {
    // All reads are bounds- and overflow-checked (`checked_add` on the end offset), so a corrupt
    // object with an out-of-range or huge offset yields `None` (→ `false`), never an index panic.
    let u16_at = |o: usize| -> Option<u16> {
        bytes
            .get(o..o.checked_add(2)?)
            .map(|s| u16::from_le_bytes([s[0], s[1]]))
    };
    let u32_at = |o: usize| -> Option<u32> {
        bytes
            .get(o..o.checked_add(4)?)?
            .try_into()
            .ok()
            .map(u32::from_le_bytes)
    };
    let u64_at = |o: usize| -> Option<u64> {
        bytes
            .get(o..o.checked_add(8)?)?
            .try_into()
            .ok()
            .map(u64::from_le_bytes)
    };
    let walk = || -> Option<bool> {
        // ELF64, little-endian: magic, then EI_CLASS == 2 (64-bit) and EI_DATA == 1 (LSB).
        if bytes.get(0..4)? != b"\x7fELF" || *bytes.get(4)? != 2 || *bytes.get(5)? != 1 {
            return Some(false);
        }
        let e_shoff = u64_at(0x28)? as usize; // section-header table offset
        let e_shentsize = u16_at(0x3a)? as usize; // bytes per section header
        let e_shnum = u16_at(0x3c)? as usize; // section-header count
        let e_shstrndx = u16_at(0x3e)? as usize; // index of the section-name string table
        if e_shentsize < 0x40 || e_shnum == 0 || e_shstrndx >= e_shnum {
            return Some(false);
        }
        // The string-table section's data holds every section name (NUL-terminated at sh_name).
        let strtab_hdr = e_shoff.checked_add(e_shstrndx.checked_mul(e_shentsize)?)?;
        let str_off = u64_at(strtab_hdr.checked_add(0x18)?)? as usize;
        let str_size = u64_at(strtab_hdr.checked_add(0x20)?)? as usize;
        let strtab = bytes.get(str_off..str_off.checked_add(str_size)?)?;
        for i in 0..e_shnum {
            let hdr = e_shoff.checked_add(i.checked_mul(e_shentsize)?)?;
            let sh_name = u32_at(hdr)? as usize; // offset into the string table
            let rest = strtab.get(sh_name..)?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            if &rest[..end] == name.as_bytes() {
                return Some(true);
            }
        }
        Some(false)
    };
    walk().unwrap_or(false)
}

/// Whether the nightly toolchain with the `rust-src` component (needed to build `crates/probes` with
/// `-Z build-std`) is installed, via `rustup component list --installed`. Informational, for `setup`.
fn nightly_ebpf_ready() -> bool {
    Command::new("rustup")
        .args(["component", "list", "--toolchain", "nightly", "--installed"])
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.trim().starts_with("rust-src"))
        })
        .unwrap_or(false)
}

/// The `(major, minor)` of `firecracker --version` on PATH (first line `Firecracker v1.9.1`), or
/// `None` when it's missing or unparseable. The same parse the driver runs once per process to
/// warn on an unpinned binary; here it feeds the setup checklist.
fn firecracker_version() -> Option<(u64, u64)> {
    let out = Command::new("firecracker").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let rest = text.split("Firecracker v").nth(1)?;
    let mut parts = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Whether the running kernel is at least `major.minor`, from `/proc/sys/kernel/osrelease`.
fn kernel_at_least(major: u64, minor: u64) -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|s| {
            let mut it = s
                .split(|c: char| !c.is_ascii_digit())
                .filter(|t| !t.is_empty());
            Some((
                it.next()?.parse::<u64>().ok()?,
                it.next()?.parse::<u64>().ok()?,
            ))
        })
        .is_some_and(|v| v >= (major, minor))
}

/// The workspace root (not the cwd), so the commands work from anywhere.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
}

/// `artifacts/` under the workspace root.
fn artifacts_dir() -> PathBuf {
    workspace_root().join("artifacts")
}

/// The artifact filenames under [`artifacts_dir`], defined once so the many readers/writers
/// (`build-rootfs`, `bench-boot`, `setup`, `fetch-artifacts`) can't drift apart: the pinned guest
/// kernel, the Phase-1 boot rootfs (fetched), and the agent rootfs (`build-rootfs` output).
fn kernel_path() -> PathBuf {
    artifacts_dir().join("vmlinux")
}
fn boot_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs.ext4")
}
fn agent_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs-agent.ext4")
}

/// Run an external build tool, echoing the command; fail with context if it's missing or errors.
fn run_tool(program: &str, args: &[&OsStr]) -> Result<()> {
    run_tool_env(program, args, &[])
}

/// [`run_tool`] with extra environment scoped to **this child only** (not `std::env::set_var`, which
/// is process-global and would leak into every later tool). Used to hand `mke2fs` its
/// `SOURCE_DATE_EPOCH` without affecting `tar`/`apk`/`truncate`.
fn run_tool_env(program: &str, args: &[&OsStr], env: &[(&str, &str)]) -> Result<()> {
    let shown: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
    println!("$ {program} {}", shown.join(" "));
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running {program} (is it installed?)"))?;
    if !status.success() {
        bail!("{program} failed");
    }
    Ok(())
}

fn check(label: &str, ok: bool) {
    println!("  [{}] {label}", if ok { "✓" } else { " " });
}

fn kvm_writable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

fn in_path(bin: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(bin).is_file())
}

/// Whether the cgroup v2 `cpu`+`memory` controllers are delegated to the cgroup root, so the jailer
/// can set a jailed VM's CPU/memory limits (P6.2). A systemd host enables these by default; where they
/// aren't, jailed boots still run but without limits. Informational only.
fn cgroup_controllers_delegated() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control")
        .map(|s| {
            let toks: Vec<&str> = s.split_whitespace().collect();
            toks.contains(&"cpu") && toks.contains(&"memory")
        })
        .unwrap_or(false)
}

fn cargo(args: &[&str]) -> Result<()> {
    cargo_env(args, &[])
}

fn cargo_env(args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    println!("$ cargo {}", args.join(" "));
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running cargo {}", args.join(" ")))?;
    if !status.success() {
        bail!("cargo {} failed", args.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid ELF64-LE object with three sections: the null section, one named `sec1`, and
    /// `.shstrtab`. Enough to exercise the section-name walk without pulling in an ELF crate.
    fn tiny_elf(sec1: &str) -> Vec<u8> {
        // Section-header string table: "\0" + sec1 + "\0" + ".shstrtab" + "\0".
        let mut strtab = vec![0u8];
        let sec1_name = strtab.len() as u32;
        strtab.extend_from_slice(sec1.as_bytes());
        strtab.push(0);
        let shstrtab_name = strtab.len() as u32;
        strtab.extend_from_slice(b".shstrtab");
        strtab.push(0);

        let e_shoff = 64 + strtab.len();
        let mut buf = vec![0u8; e_shoff + 3 * 64];

        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1; // EV_CURRENT
        buf[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        buf[0x12..0x14].copy_from_slice(&247u16.to_le_bytes()); // EM_BPF
        buf[0x28..0x30].copy_from_slice(&(e_shoff as u64).to_le_bytes()); // e_shoff
        buf[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        buf[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        buf[0x3e..0x40].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx (the .shstrtab index)

        buf[64..64 + strtab.len()].copy_from_slice(&strtab);

        // Section 1: named `sec1`.
        let s1 = e_shoff + 64;
        buf[s1..s1 + 4].copy_from_slice(&sec1_name.to_le_bytes());
        // Section 2: `.shstrtab`, SHT_STRTAB, pointing at the string-table data above.
        let s2 = e_shoff + 128;
        buf[s2..s2 + 4].copy_from_slice(&shstrtab_name.to_le_bytes());
        buf[s2 + 4..s2 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        buf[s2 + 0x18..s2 + 0x20].copy_from_slice(&64u64.to_le_bytes()); // sh_offset
        buf[s2 + 0x20..s2 + 0x28].copy_from_slice(&(strtab.len() as u64).to_le_bytes()); // sh_size
        buf
    }

    #[test]
    fn elf_section_scan_matches_the_exact_name() {
        assert!(elf_has_section(&tiny_elf(".BTF"), ".BTF"));
        assert!(elf_has_section(&tiny_elf(".BTF"), ".shstrtab")); // the string table itself is named
    }

    #[test]
    fn elf_section_scan_rejects_near_misses_and_junk() {
        assert!(!elf_has_section(&tiny_elf(".BTF.ext"), ".BTF")); // the substring scan's false positive
        assert!(!elf_has_section(&tiny_elf(".text"), ".BTF")); // real sections, none named .BTF
        assert!(!elf_has_section(b"not an elf at all", ".BTF"));
        assert!(!elf_has_section(&[], ".BTF"));
    }
}
