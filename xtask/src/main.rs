//! `cargo xtask <cmd>`, dev orchestration for the agent sandbox engine.
//!
//! - **`ci`**, the host-safe gate (fmt · prose-drift · clippy `-D warnings` · build · test ·
//!   docs · `deny`).
//!   Runs everywhere, needs no KVM or root, and mirrors `.github/workflows/ci.yml`.
//! - **`ci-privileged`**, the KVM/eBPF integration tests (the `#[ignore]`d ones). Needs
//!   `/dev/kvm` and elevated caps, so it's never part of the everyday loop. Builds the guest
//!   agent + the agent rootfs first, so the in-VM exec test has something to boot.
//! - **`setup`**, checks the host can do KVM + eBPF and reports what's missing.
//! - **`self-host`**, the single self-host command: obtain the pinned kernel + rootfs, build the
//!   guest image + eBPF object, install `agent`, and (on a KVM host) boot one sandbox to
//!   prove it. Offline when `AGENT_VENDOR_DIR` points at a `vendor` mirror.
//! - **`vendor`**, snapshot every sha-pinned upstream input (kernel/rootfs + the `.apk` closure)
//!   into a local mirror with a sha manifest, so a fresh host builds without the Firecracker S3
//!   bucket or the Alpine CDN; `--verify` re-checks the mirror offline.
//! - **`dist`**, assemble the shippable release package: the release binary + the guest kernel,
//!   rootfs, and eBPF object, staged, sha256-manifested, and tarred into `dist/` with a
//!   `SHA256SUMS`; `install.sh` and the `Containerfile` consume it. Vendor-aware like `self-host`.
//! - **`build-probes`**, build the eBPF object (`crates/probes`) for `bpfel-unknown-none` via
//!   `bpf-linker`, under the crate's own nightly toolchain. Host-safe (no KVM); skips with a note
//!   when `bpf-linker`/`rustup` are absent.
//! - **`build-rootfs`**, assemble the reproducible guest rootfs (Alpine base + baked-in agent).
//! - **`bench-boot`**, measure boot-to-userspace latency (percentiles) vs. the base size. Needs KVM.
//! - **`bench-warm`**, the three start paths' latency percentiles: cold boot vs prewarmed-snapshot
//!   restore vs prewarmed-pool take, each split into its isolated start and its time-to-first-result.
//!   Needs KVM + the built agent rootfs.
//! - **`bench-density`**, memory-sharing under concurrency: summed Rss vs Pss as prewarmed clones
//!   stack up, and how many fit before it degrades. Needs KVM + the built agent rootfs.
//! - **`bench-footprint`**, per-sandbox memory footprint and the overlay/rootfs choice's effect:
//!   per-VM Pss + whole-host cost per sandbox for cold RW-copy vs cold shared-base vs restore. Needs
//!   KVM + the built agent rootfs.
//! - **`bench-all`**, the whole suite as one reproducible report, methodology stated + host recorded;
//!   sections whose prerequisite is missing are skipped with the reason. The written report is
//!   `docs/benchmarks.md`.
//! - **`bench-trace`**, the syscall-tracing overhead: per-`openat` cost with no probes vs
//!   attached-but-filtered-out vs attached-and-capturing. Needs `CAP_BPF`+`CAP_PERFMON` + the built
//!   object (not KVM).
//! - **`trace-sandbox`**, the syscall-trace demo: boot a real sandbox and stream its
//!   cgroup-attributed host syscall footprint. Needs KVM + the agent rootfs + `CAP_BPF` + the object.
//! - **`watch-sandbox`**, the network-observability demo: boot a real networked sandbox and watch its
//!   per-VM network flows on the tap. Needs KVM + the agent rootfs + `CAP_BPF`+`CAP_NET_ADMIN` + the object.
//! - **`enforce-sandbox`**, the egress-enforcement demo: boot a real networked sandbox, arm a
//!   deny-by-default egress policy allowing one endpoint, and show the allow-listed traffic passing while
//!   everything else is dropped at the tap and logged. Same needs as `watch-sandbox`.
//! - **`bench-meter`**, the resource-metering overhead: per-context-switch cost with no meter vs
//!   attached-but-not-metering-us vs attached-and-metering-us. Needs `CAP_BPF`+`CAP_PERFMON` + the built
//!   object (not KVM).
//! - **`bench-scale`**, the probe overhead *under load*: per-event cost as the watched-target set
//!   (concurrent sandboxes) grows 1 → 512, showing it stays flat (O(1) lookup). Same needs as
//!   `bench-meter`.
//! - **`bench-sign`**, the record-signing overhead: per-record `ed25519` sign/verify + the SHA-256
//!   chain hash (decision 034), sub-millisecond and off the boot path. Host-only (no KVM/eBPF).
//! - **`meter-sandbox`**, the resource-metering demo: boot a real sandbox, meter its cgroup, and show an
//!   idle guest charging near-zero host CPU while a CPU-heavy guest charges most of a core, plus the
//!   per-run resource summary. Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_PERFMON` + the object.
//! - **`fuzz`**, deep `cargo fuzz` (libFuzzer) runs against the untrusted-input decoders: the
//!   host↔guest channel (the guest→host boundary), the daemon's client wire (`agent serve`'s socket,
//!   the outermost boundary), the signed-record envelope (attacker-relayed by design), and the
//!   eBPF-boundary parsers. Nightly + `cargo install cargo-fuzz`; never part of `ci` (the in-gate
//!   coverage is the crates' own dependency-light mutation tests).
//!
//! Split by concern: `guest_bins` (the static musl in-guest builds), `rootfs` (the reproducible
//! image), `bench` (the latency benchmarks), `artifacts` (the pinned kernel/rootfs fetch), `vendor`
//! (the offline mirror of all pinned inputs), `selfhost` (the single stand-up command); the gates
//! and the shared plumbing (paths, `cargo`/tool runners) live here.
//!
//! The eBPF crate (`crates/probes`) builds for `bpfel-unknown-none` and is excluded from the host
//! workspace; `build-probes` builds its object (with BTF) and is folded **into** `ci` (guarded, so
//! the CI gate still runs on hosts without the eBPF toolchain).
#![forbid(unsafe_code)]

mod artifacts;
mod bench;
mod demo;
mod dist;
mod drift;
mod guest_bins;
mod rootfs;
mod selfhost;
mod vendor;

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
    /// Host-safe gate: fmt · prose-drift · clippy `-D warnings` · build · test · docs · cargo-deny.
    Ci,
    /// Fast inner loop: fmt · prose-drift · clippy `-D warnings`. Runs **no tests** (that is what
    /// makes it fast: ~4s vs ~17s), so it says the code compiles and lints, not that it works.
    Check,
    /// Privileged integration tests (KVM + eBPF), the `#[ignore]`d tests. Needs `/dev/kvm` + caps.
    CiPrivileged,
    /// Check the host can do KVM + eBPF; report what's missing.
    Setup,
    /// Single-command self-host: obtain the pinned kernel + rootfs, build the guest image + eBPF
    /// object, install the `agent` binary, and (on a KVM host) boot one sandbox to prove
    /// it. Offline when `AGENT_VENDOR_DIR` points at a `cargo xtask vendor` mirror.
    SelfHost {
        /// Where to install the `agent` binary (default `~/.local/bin`).
        #[arg(long, value_name = "DIR")]
        prefix: Option<PathBuf>,
        /// Build + install only; skip the sandbox boot proof (it just prints the command).
        #[arg(long)]
        no_run: bool,
    },
    /// Snapshot every sha-pinned upstream input (guest kernel + rootfs, Alpine base, the `.apk`
    /// closure) into a local mirror, so a fresh host builds offline, no Firecracker S3 bucket, no
    /// Alpine CDN. Writes a sha manifest; re-verify it offline with `--verify`.
    Vendor {
        /// The mirror directory to populate or verify (default `vendor/` under the workspace root).
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        /// Re-verify an existing mirror against its manifest (every file must still match its hash)
        /// instead of (re)downloading, an offline integrity check, no upstream contact.
        #[arg(long)]
        verify: bool,
    },
    /// Build the eBPF object (`crates/probes`) for `bpfel-unknown-none` via `bpf-linker`, under the
    /// crate's own nightly toolchain (`build-std`). Host-safe; skips with a note when `bpf-linker` or
    /// `rustup` is missing. The object lands at `crates/probes/target/bpfel-unknown-none/release/probes`.
    BuildProbes,
    /// Download + sha256-verify the pinned guest kernel and rootfs into `artifacts/` (needs `curl`).
    FetchArtifacts,
    /// Assemble the shippable release package: the release binary + the guest kernel, rootfs, and
    /// eBPF object, staged, sha256-manifested, and tarred into `dist/` with a `SHA256SUMS`
    /// (decision 035). Vendor-aware via `AGENT_VENDOR_DIR`; the eBPF toolchain is required (a
    /// package without the audit half is not the product).
    Dist {
        /// The package version (release CI passes the pushed tag). Default: `git describe --tags`
        /// against the `v0.0.x` checkpoint line, `v` stripped.
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
    },
    /// Build the guest agent as a static musl binary (baked into the rootfs by `build-rootfs`).
    BuildGuestAgent,
    /// Build the static native-ELF fixture (`examples/writefile`) for the guest target, the
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
        /// Re-record the resolved package closure into the committed lockfile, the "re-pin" step
        /// after Alpine's branch repo bumps a package out from under the floating install.
        #[arg(long)]
        update_lock: bool,
    },
    /// Measure boot-to-userspace latency (percentiles) of the agent rootfs, on both the read-only
    /// shared base and the read-write per-VM copy, so the base **size**'s effect on boot is visible
    ///. Needs `/dev/kvm` + the built agent rootfs.
    BenchBoot {
        /// How many boots to time per path (more → tighter tail percentiles). Default 100, the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure the latency (percentiles) of the three start paths: a cold boot (per-VM rootfs copy,
    /// the full-copy baseline), a prewarmed-snapshot restore, and a prewarmed-pool take, each
    /// decomposed into its isolated start (begin a sandbox → exec-ready) and its time-to-first-result
    /// (start + a Python one-liner's output back on the host). Needs `/dev/kvm` + the built agent
    /// rootfs.
    BenchWarm {
        /// How many runs to time per path (more → tighter tail percentiles). Default 100, the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure memory-sharing under concurrency: restore prewarmed clones one at a time (each sharing
    /// the read-only base disk and the snapshot memory file) and, keeping them all alive, sample the
    /// summed Rss (naive) vs Pss (true, shared pages divided) plus host MemAvailable. Reports how many
    /// concurrent microVMs fit before it degrades (target / restore failure / a memory floor) and the
    /// sharing density. Needs `/dev/kvm` + the built agent rootfs.
    BenchDensity {
        /// Target number of concurrent clones to stack (it stops earlier on a restore failure or the
        /// memory floor, whichever comes first).
        #[arg(long, default_value_t = 64)]
        count: usize,
    },
    /// Measure the per-sandbox memory footprint and how the overlay/rootfs choice moves it: bring up a
    /// cohort per strategy (cold boot with a per-VM RW copy, cold boot on the shared RO base, snapshot
    /// restore) and report the per-VM Pss (percentiles) plus the whole-host MemAvailable drop per
    /// sandbox. The RW-copy-vs-shared-base gap is the rootfs choice made a number. Needs `/dev/kvm` +
    /// the built agent rootfs.
    BenchFootprint {
        /// How many identical sandboxes to bring up per strategy (it stops earlier at the memory
        /// floor). Default 4.
        #[arg(long, default_value_t = 4)]
        count: usize,
    },
    /// Run the whole benchmark suite as one reproducible report: boot, warm, footprint, density, and
    /// the three probe benches, in order, with the methodology stated and the host recorded. Sections
    /// whose host prerequisite is missing (`/dev/kvm`, or `CAP_BPF`+`CAP_PERFMON` + the built object)
    /// are skipped with the reason, never silently dropped. The written report is `docs/benchmarks.md`.
    BenchAll {
        /// How many runs/bursts for the percentile benches (the concurrency benches use fixed cohort
        /// sizes). Default 30 to keep the full suite tractable; bump the individual command for tails.
        #[arg(long, default_value_t = 30)]
        runs: usize,
    },
    /// Measure the syscall-tracing overhead: the per-`openat` cost with no probes attached, vs
    /// probes attached but filtered out, vs probes attached and writing each event to the ring buffer.
    /// The delta is the honest cost of tracing. Needs `CAP_BPF`+`CAP_PERFMON` + `cargo xtask
    /// build-probes` (not KVM).
    BenchTrace {
        /// How many bursts to time per condition (more → tighter tail percentiles). Default 100, the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure the resource-metering overhead: the added per-context-switch cost of the attached
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
    /// Measure the eBPF overhead under load: sweep the watched-target-set size (1 → 512) for the shared
    /// syscall tracer and `sched_switch` meter and show the per-event cost stays flat, an O(1) map
    /// lookup, so overhead scales with the event rate, not the number of concurrent sandboxes. Needs
    /// `CAP_BPF`+`CAP_PERFMON` + `cargo xtask build-probes` (not KVM).
    BenchScale {
        /// How many bursts to time per set size (more → steadier p50). Default 100.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure the record-signing overhead (decision 034): the per-record cost of one `ed25519` sign
    /// over already-canonical bytes, plus verify, the SHA-256 chain hash, and a chained sign, so the
    /// integrity step is measured like everything else. Host-only (no KVM, no eBPF); the point is
    /// that it is sub-millisecond and off the boot/exec path.
    BenchSign {
        /// How many iterations to time per operation (more → tighter tail percentiles). Default 1000.
        #[arg(long, default_value_t = 1000)]
        runs: usize,
    },
    /// The syscall-trace demo: boot a real sandbox and stream its host syscall footprint,
    /// attributed to the sandbox's cgroup (the VMM's host syscalls, the guest's stay in-guest).
    /// Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_PERFMON` + `cargo xtask build-probes`.
    TraceSandbox {
        /// Seconds to keep streaming the live trace after the boot+exec window is printed (`0` = just
        /// the boot+exec footprint).
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },
    /// The network-observability demo: boot a real networked sandbox, attach a `tc` monitor to its tap
    /// inside its netns, drive guest traffic, and print the per-VM network flows and totals it counts.
    /// Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_NET_ADMIN` + `cargo xtask build-probes`.
    WatchSandbox {
        /// How many guest-traffic bursts to send, watching the per-VM counters climb each one.
        /// At least 1, enforced at parse (a zero-round watch would prove nothing).
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..))]
        rounds: u64,
    },
    /// The egress-enforcement demo: boot a real networked sandbox, arm a deny-by-default egress policy
    /// allowing one endpoint, and show the allow-listed traffic passing while everything else is dropped
    /// at the tap and recorded. Needs `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_NET_ADMIN` + the object.
    EnforceSandbox,
    /// The resource-metering demo: boot a real sandbox, meter its cgroup with the `sched_switch`
    /// accounting probe, and show an idle guest charging near-zero host CPU while a CPU-heavy guest charges
    /// most of a core, plus the per-run resource summary (CPU from eBPF, memory/IO from cgroup v2). Needs
    /// `/dev/kvm` + the agent rootfs + `CAP_BPF`+`CAP_PERFMON` + the object.
    MeterSandbox,
    /// Fuzz the untrusted-input decoders (the host↔guest channel, the daemon's client wire, the
    /// signed-record envelope, the eBPF-boundary parsers) with `cargo fuzz` (libFuzzer), the deep,
    /// nightly-only counterpart to the in-gate mutation tests. Seeds are folded in from
    /// `fuzz/seeds/<target>/`. Needs `cargo install cargo-fuzz` + a nightly toolchain; never part of
    /// `ci`. Targets: `channel_response` (default), `channel_request`, `channel_frame`,
    /// `channel_handshake`, `signing_envelope`, `protocol_message`, `syscall_event`.
    Fuzz {
        /// The libFuzzer target to run.
        #[arg(default_value = "channel_response")]
        target: String,
        /// Wall-clock seconds to fuzz before stopping (`0` runs until it finds a crash or you Ctrl-C).
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    /// Fuzz **every** target briefly (seeded), the per-PR smoke: a change that breaks a decoder is
    /// caught before it lands, not only on the nightly deep run. Fail-fast on the first crash, whose
    /// input lands under `fuzz/artifacts/`. Same install needs as `fuzz`; never part of `ci`. Wired
    /// to the `fuzz-smoke` CI job on pull requests.
    FuzzSmoke {
        /// Wall-clock seconds per target.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    /// Measure a target's line coverage over its corpus + seeds (`cargo fuzz coverage`), so a target
    /// stuck bouncing off an early check shows as low coverage instead of a hollow green. Prints where
    /// the profile landed and how to render a report.
    FuzzCoverage {
        #[arg(default_value = "channel_response")]
        target: String,
    },
    /// Minimize a target's on-disk corpus (`cargo fuzz cmin`): drop inputs that add no coverage so the
    /// corpus (and each run's replay) stays small. A periodic maintenance step, not part of a run.
    FuzzCmin {
        #[arg(default_value = "channel_response")]
        target: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::Check => fast_check(),
        Cmd::CiPrivileged => ci_privileged(),
        Cmd::Setup => setup(),
        Cmd::SelfHost { prefix, no_run } => selfhost::self_host(prefix, no_run),
        Cmd::Vendor { dir, verify } => {
            if verify {
                vendor::verify(&dir.unwrap_or_else(vendor::default_vendor_dir))
            } else {
                vendor::vendor(dir)
            }
        }
        Cmd::BuildProbes => build_probes(),
        Cmd::FetchArtifacts => artifacts::fetch_artifacts(),
        Cmd::Dist { version } => dist::dist(version),
        Cmd::BuildGuestAgent => guest_bins::build_guest_agent().map(|_| ()),
        Cmd::BuildGuestExample => guest_bins::build_guest_example().map(|_| ()),
        Cmd::BuildRootfs {
            verify,
            update_lock,
        } => rootfs::build_rootfs(verify, update_lock),
        Cmd::BenchBoot { runs } => bench::bench_boot(runs),
        Cmd::BenchWarm { runs } => bench::bench_warm(runs),
        Cmd::BenchDensity { count } => bench::bench_density(count),
        Cmd::BenchFootprint { count } => bench::bench_footprint(count),
        Cmd::BenchAll { runs } => bench::bench_all(runs),
        Cmd::BenchTrace { runs } => bench::bench_trace(runs),
        Cmd::BenchMeter { runs } => bench::bench_meter(runs),
        Cmd::BenchScale { runs } => bench::bench_scale(runs),
        Cmd::BenchSign { runs } => bench::bench_sign(runs),
        Cmd::TraceSandbox { seconds } => demo::trace_sandbox(seconds),
        Cmd::WatchSandbox { rounds } => demo::watch_sandbox(rounds),
        Cmd::EnforceSandbox => demo::enforce_sandbox(),
        Cmd::MeterSandbox => demo::meter_sandbox(),
        Cmd::Fuzz { target, seconds } => fuzz(&target, seconds),
        Cmd::FuzzSmoke { seconds } => fuzz_smoke(seconds),
        Cmd::FuzzCoverage { target } => fuzz_coverage(&target),
        Cmd::FuzzCmin { target } => fuzz_cmin(&target),
    }
}

/// Every libFuzzer target in `fuzz/`, ordered by value (outermost untrusted boundary first). The
/// single source of truth the smoke run iterates; the nightly matrix and the docs mirror it.
const FUZZ_TARGETS: &[&str] = &[
    "protocol_message",
    "channel_response",
    "signing_envelope",
    "channel_request",
    "channel_frame",
    "channel_handshake",
    "syscall_event",
];

/// cargo-fuzz drives libFuzzer under a nightly toolchain, both opt-in installs, so bail with guidance
/// rather than pretending. Fuzzing is never wired into `ci` (the in-gate coverage is the crates' own
/// dependency-light mutation tests). See `docs/contributing-fuzzing.md`.
fn require_cargo_fuzz() -> Result<()> {
    if cargo_fuzz_available() {
        return Ok(());
    }
    bail!(
        "cargo-fuzz not found — install it with `cargo install cargo-fuzz` and add a nightly \
         toolchain (`rustup toolchain install nightly`). See docs/contributing-fuzzing.md."
    )
}

/// Build the shared `+nightly fuzz <sub> <target> <corpus> [seeds]` argv. The writable corpus
/// (libFuzzer accumulates new inputs here; generated, gitignored) is created so naming it explicitly
/// (which we must, to also pass the seeds) doesn't trip cargo-fuzz's default. `with_seeds` folds in
/// the committed read-only seed corpus, so `run`/`coverage` start *past* the first-byte reject (real
/// inputs reaching the decode logic); `cmin` minimizes only the accumulated corpus, so it omits them.
fn cargo_fuzz_argv(sub: &str, target: &str, root: &Path, with_seeds: bool) -> Result<Vec<String>> {
    let corpus = root.join("fuzz/corpus").join(target);
    std::fs::create_dir_all(&corpus).context("create the fuzz corpus dir")?;
    let mut args: Vec<String> = ["+nightly", "fuzz", sub, target]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    args.push(corpus.to_string_lossy().into_owned());
    let seeds = root.join("fuzz/seeds").join(target);
    if with_seeds && seeds.is_dir() {
        args.push(seeds.to_string_lossy().into_owned());
    }
    Ok(args)
}

/// Invoke `cargo <args>` from the repo root (cargo-fuzz discovers the `fuzz/` crate there). The
/// `+nightly` in `args` forces the nightly toolchain via the rustup proxy: libFuzzer builds with
/// `-Zsanitizer=address`, nightly-only, so inheriting a stable default would fail with "the option
/// `Z` is only accepted on the nightly compiler". rustup propagates the selection to the inner build.
fn run_cargo_fuzz(args: &[String], root: &Path) -> Result<()> {
    println!("$ cargo {}", args.join(" "));
    let status = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .status()
        .context("running cargo fuzz")?;
    if !status.success() {
        bail!(
            "`cargo {}` reported a failure — see the output above (a crash input, if any, lands \
             under fuzz/artifacts/)",
            args.join(" ")
        );
    }
    Ok(())
}

/// `cargo fuzz coverage` renders its profile with `llvm-profdata` from the nightly `llvm-tools`
/// component, an opt-in install like cargo-fuzz itself, so check for it up front and bail with the
/// one-line fix rather than letting the run fail cryptically at the merge step.
fn require_llvm_tools() -> Result<()> {
    let installed = Command::new("rustup")
        .args(["component", "list", "--toolchain", "nightly", "--installed"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("llvm-tools"))
        .unwrap_or(false);
    if installed {
        return Ok(());
    }
    bail!(
        "llvm-tools not installed — `cargo fuzz coverage` needs it to merge the profile: \
         `rustup component add llvm-tools --toolchain nightly`. See docs/contributing-fuzzing.md."
    )
}

/// Run one `cargo fuzz` (libFuzzer) target against the untrusted-input decoders, seeded. A positive
/// `seconds` bounds the run (`0` runs until a crash or Ctrl-C).
fn fuzz(target: &str, seconds: u64) -> Result<()> {
    require_cargo_fuzz()?;
    let root = workspace_root();
    let mut args = cargo_fuzz_argv("run", target, root, true)?;
    args.push("--".to_owned());
    args.push(format!("-max_total_time={seconds}"));
    run_cargo_fuzz(&args, root)
}

/// The per-PR smoke: fuzz every [`FUZZ_TARGETS`] target for a bounded time, seeded, fail-fast. Cheap
/// enough to run before a push (7 targets x the default 60s) yet enough to catch a decoder a change
/// just broke, the gap between "green nightly" and "this PR regressed a parser".
fn fuzz_smoke(seconds: u64) -> Result<()> {
    require_cargo_fuzz()?;
    println!(
        "fuzz-smoke: {} targets x {seconds}s each (seeded)",
        FUZZ_TARGETS.len()
    );
    for (i, target) in FUZZ_TARGETS.iter().enumerate() {
        println!("── [{}/{}] {target} ──", i + 1, FUZZ_TARGETS.len());
        fuzz(target, seconds)?;
    }
    println!(
        "✓ fuzz-smoke: no crashes across {} targets at {seconds}s each",
        FUZZ_TARGETS.len()
    );
    Ok(())
}

/// Measure a target's coverage over its corpus + seeds. cargo-fuzz writes a `coverage.profdata`; a
/// low reached-fraction means the target is bouncing off an early check (bad seeds, an over-tight
/// guard) rather than exercising the decode logic, which a green run alone can't reveal.
fn fuzz_coverage(target: &str) -> Result<()> {
    require_cargo_fuzz()?;
    require_llvm_tools()?;
    let root = workspace_root();
    let args = cargo_fuzz_argv("coverage", target, root, true)?;
    run_cargo_fuzz(&args, root)?;
    let profdata = root
        .join("fuzz/coverage")
        .join(target)
        .join("coverage.profdata");
    println!("\ncoverage profile written: {}", profdata.display());
    println!(
        "render a report (needs `cargo install cargo-binutils`): `cargo cov -- show` / `report` \
         against the target binary under fuzz/target/<triple>/coverage with \
         `-instr-profile={}`. See docs/contributing-fuzzing.md and the Rust Fuzz Book.",
        profdata.display()
    );
    Ok(())
}

/// Minimize a target's on-disk corpus in place, keeping one input per coverage feature. A periodic
/// maintenance step so a corpus that grew over many runs stays fast to replay.
fn fuzz_cmin(target: &str) -> Result<()> {
    require_cargo_fuzz()?;
    let root = workspace_root();
    let args = cargo_fuzz_argv("cmin", target, root, false)?;
    run_cargo_fuzz(&args, root)
}

/// This process's effective uid, read from `/proc/self/status` (`Uid:` line, second value), so the
/// check needs no libc call.
fn effective_uid() -> Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    parse_effective_uid(&status).context("parse the effective uid from /proc/self/status")
}

/// The euid (second value of the `Uid:` line) from a `/proc/<pid>/status` body, or `None` if the
/// format isn't what we expect. Split out pure so the parse is unit-testable: a wrongly-`None`
/// result turns into a loud gate refusal, never a silent skip, but it should still be correct.
fn parse_effective_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(2)
        .and_then(|f| f.parse().ok())
}

/// Is `cargo fuzz` installed? (Probed once, cheaply, so a missing tool is a clear message.)
fn cargo_fuzz_available() -> bool {
    Command::new("cargo")
        .args(["fuzz", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The host-safe gate. `--locked` everywhere so a stale `Cargo.lock` fails here, not at release.
fn ci() -> Result<()> {
    cargo(&["fmt", "--all", "--check"])?;
    // The prose-drift lint runs early: it is sub-second, and a broken decision citation or a
    // comment pointing at a renamed file should surface before the slow compile steps.
    drift::check(workspace_root())?;
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
    // The eBPF object build is part of the CI gate. Host-safe and guarded, it skips with a note
    // when `bpf-linker`/`rustup` are absent, so `ci` still runs everywhere, but on a set-up dev box a
    // probe that fails to compile (or drops its BTF) now fails here, not later at load.
    build_probes()?;
    println!("\n✓ all checks passed");
    Ok(())
}

/// The fast inner loop: does it format, lint, and compile. **Deliberately runs no tests**, which is
/// the whole point, measured on this workspace, the test step is ~16s of a ~17s `ci` and everything
/// else rounds to nothing, so dropping it is the only thing that makes a faster loop (~4s). Skipping
/// docs and `cargo deny` saves nothing once they're warm; they're left out only because a
/// no-test run can't honestly claim to be the gate anyway.
///
/// Not a substitute for [`ci`]: it cannot tell you the code *works*. Run the gate before handing
/// work over.
///
/// Each step it does share with `ci` is byte-identical, flags *and* environment: a differing
/// `RUSTFLAGS` would give the two commands separate build fingerprints, so alternating between them
/// would rebuild the world each time and make the fast loop the slow one.
fn fast_check() -> Result<()> {
    cargo(&["fmt", "--all", "--check"])?;
    drift::check(workspace_root())?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ])?;
    println!(
        "\n✓ check passed: formats, lints, compiles. No tests ran, the gate is `cargo xtask ci`"
    );
    Ok(())
}

/// Booting a microVM and loading/attaching eBPF need `/dev/kvm` + elevated caps, so those tests are
/// `#[ignore]`d and run only here, on a machine that has them.
fn ci_privileged() -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("/dev/kvm not present — privileged tests need KVM (run on a KVM-capable host)");
    }
    // Every privileged test skip-guards itself, and a skipped body is a *pass* to cargo, so a gate
    // run without the capabilities would print green while the jailer, cgroup, and eBPF halves
    // silently test nothing. Refuse loudly instead: real root covers CAP_NET_ADMIN/CAP_BPF/
    // CAP_PERFMON and is what the jailer tests need outright.
    if effective_uid()? != 0 {
        bail!(
            "cargo xtask ci-privileged needs real root (run it under sudo): without it the \
             jailer, cgroup, and network tests skip themselves, and a skipped test looks like \
             a pass"
        );
    }
    // Running as root without CARGO_TARGET_DIR leaves root-owned artifacts in ./target that block
    // every later non-root `cargo build`. Refuse rather than warn: the redirect has to be on the
    // *outer* cargo (which built this binary) to keep ./target clean at all, so it can only ever be
    // the caller's invocation, and a warning here just documents the damage after it starts.
    if std::env::var_os("CARGO_TARGET_DIR").is_none() {
        bail!(
            "refusing to run as root without CARGO_TARGET_DIR: the build would leave root-owned \
             artifacts in ./target and block later non-root `cargo` builds.\n  Re-run as:\n    \
             sudo -E env CARGO_TARGET_DIR=\"$PWD/target-privileged\" cargo xtask ci-privileged\n  \
             (if ./target is already root-owned from this attempt: sudo chown -R \"$USER:$USER\" target)"
        );
    }
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!(
            "/sys/kernel/btf/vmlinux not present — the eBPF probe tests skip themselves without \
             BTF, and a skipped test looks like a pass (need a CONFIG_DEBUG_INFO_BTF=y kernel)"
        );
    }
    // This gate builds and verifies the static guest agent (below), and that verification is the
    // *only* thing standing between a silently-reintroduced dynamic dependency and a confusing
    // in-guest loader failure. `verify_static` soft-skips when `readelf` is absent (so ad-hoc
    // `build-rootfs` still works), so require it *here*, a missing binutils must fail the CI gate
    // loudly, not quietly disarm the check.
    if !in_path("readelf") {
        bail!(
            "readelf (binutils) not found — the privileged gate verifies the guest agent is \
               statically linked and won't run that check blind; install binutils"
        );
    }
    // The boot tests need the pinned kernel + rootfs; fail with the fix rather than a cryptic
    // boot error. `fetch-artifacts` (not this gate) does the network download; here we verify
    // the hashes too, the sha256 is the contract, and a hand-placed or corrupted artifact
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
    // The in-VM exec test boots a rootfs with the agent baked in, build it here (not from inside a
    // `#[test]`, which mustn't shell out to a musl `cargo build`). Idempotent: the Alpine base is
    // cached by sha256, so this is a rebuild of the agent + the image, not a re-download. `--verify`
    // makes this the reproducibility gate: it builds twice, asserts byte-identical, and fails on
    // package-closure drift from the lockfile.
    rootfs::build_rootfs(true, false)?;
    // The runtime-agnostic test injects a static native binary; build it here (musl), like the
    // agent, the same "don't shell a musl `cargo build` from a `#[test]`" rule. It is a *fixture*,
    // not part of the image, so it's built separately, not baked into the rootfs.
    guest_bins::build_guest_example()?;
    // The eBPF probe tests load the object built from `crates/probes`; build it here (the
    // same "don't shell a nightly `cargo build` from a `#[test]`" rule). `build_probes` soft-skips
    // without the eBPF toolchain (the everyday gate must stay host-safe), but *this* gate exists to
    // prove the observe-and-enforce half, so a missing object must fail loudly here, exactly like
    // the `readelf` check above: the probe tests would otherwise self-skip and look like passes.
    build_probes()?;
    let object = workspace_root().join("crates/probes/target/bpfel-unknown-none/release/probes");
    if !object.is_file() {
        bail!(
            "eBPF object not built ({}) — the probe tests skip themselves without it, and a \
             skipped test looks like a pass; install bpf-linker + the nightly toolchain (see \
             docs/contributing-building.md)",
            object.display()
        );
    }
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
    println!("agent: host capability check\n");

    // The runtime host checks are the *same* implementation `agent doctor` renders (decision 028): one
    // source of truth for what "ready" means, so the dev-box check and the operator's can't drift.
    // The artifact paths come from the env-layered config (the workspace `artifacts/` defaults),
    // matching what a dev boot resolves.
    let config = agent_vmm::BootConfig::from_env();
    for c in agent_vmm::doctor::checks(&config) {
        let ok = c.status == agent_vmm::doctor::CheckStatus::Ok;
        check(&c.label, ok);
    }
    // The eBPF-observability capability row (owned by the probe loader, out of `agent-vmm`).
    check(
        "eBPF observability (CAP_BPF + CAP_PERFMON + kernel BTF)",
        agent_probes_loader::check_support().is_ok(),
    );

    // Dev-toolchain checks, only `xtask` needs these (building the eBPF object, the guest agent,
    // verifying static links); an operator running the shipped engine does not, so they are not in
    // the shared `agent doctor` set.
    println!("\ndev toolchain (for building, not running):");
    check(
        "bpf-linker installed",
        dev_tool_path("bpf-linker").is_some(),
    );
    check(
        "nightly toolchain + rust-src (eBPF object build: `cargo xtask build-probes`)",
        nightly_ebpf_ready(),
    );
    check(
        "readelf (binutils: static-link verification)",
        dev_tool_path("readelf").is_some(),
    );
    check(
        "mke2fs >= 1.47.1 (reproducible rootfs: SOURCE_DATE_EPOCH honoured)",
        matches!(rootfs::mke2fs_version(), Some(v) if v >= rootfs::MKE2FS_SOURCE_DATE_EPOCH_MIN),
    );

    // The degradation matrix, the same fails-open-vs-hard split `agent doctor` prints, from the one
    // shared source, so a mismatched host explains itself *before* the first boot discovers it.
    println!("\nDegradation matrix: what a missing item above means at runtime:");
    for line in agent_vmm::doctor::matrix() {
        println!("  {line}");
    }

    // The engine/hoster line (decision 013): the engine guarantees its own privileged tools can't
    // be weaponized; *deploying* them, as whom, when, over what directory, is the hoster's, and
    // these are the calls only they can make. Surfaced here, in the host-check tool, because
    // that's the one place a self-hoster looks before standing the engine up.
    println!("\nHardening: the hoster's responsibility (the engine can't decide these for you):");
    println!(
        "    scratch base: point AGENT_SCRATCH_DIR at a dir only the engine user owns (not the"
    );
    println!(
        "                  world-writable /tmp default), so no other local user can plant residue"
    );
    println!("    run the sweep: schedule agent_vmm::sweep_orphans() (boot-time + periodic), the");
    println!("                  engine exposes it; when/how often it runs is your ops call");
    println!("    one sweep per identity: a sweep reclaims only dirs its own euid owns, so if you");
    println!("                  run drivers as several users, each user must run its own sweep");

    println!("\neBPF probes: loading + attaching needs CAP_BPF + CAP_PERFMON, not full");
    println!(
        "             root: grant a loader binary just those with `setcap cap_bpf,cap_perfmon+ep`."
    );
    println!(
        "             A host without kernel BTF or those caps is named by a typed error, not a"
    );
    println!("             cryptic verifier reject (agent_probes_loader::check_support).");

    println!("\nMissing items are covered in docs/cli-install.md -> Prerequisites.");
    Ok(())
}

/// Build the eBPF object (`crates/probes`) for `bpfel-unknown-none` via `bpf-linker`. The
/// crate is **excluded** from the workspace and builds under its own nightly toolchain with
/// `-Z build-std` (rustup ships no prebuilt `core` for the BPF target), so this drives its build
/// directly rather than through the workspace `cargo`.
///
/// Guarded so `cargo xtask` stays runnable everywhere: on a host missing any of the toolchain
/// (`bpf-linker`, `rustup`, or the nightly + `rust-src` the `build-std` build needs), it prints a
/// note and returns `Ok` instead of failing, the everyday host gate must not require the eBPF
/// toolchain. A dev box installs it (`cargo xtask setup` lists the prereqs); this step is folded
/// into the `ci` gate, and `ci-privileged` builds it before the probe tests.
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
    // would otherwise fall through to the build and `bail!`, failing the everyday gate, the exact
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
    // The object must carry BTF (`bpf-linker --btf`), the CO-RE portability + BTF map typing
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
/// byte-substring scan is not, `.BTF.ext` alone or a coincidental byte run won't satisfy it. Returns
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
    // Resolve `rustup` the sudo-aware way too (it is also a per-user `~/.cargo/bin` tool), so a
    // `sudo cargo xtask setup` doesn't misreport the toolchain as absent, see `dev_tool_path`.
    let Some(rustup) = dev_tool_path("rustup") else {
        return false;
    };
    let mut cmd = Command::new(rustup);
    cmd.args(["component", "list", "--toolchain", "nightly", "--installed"]);
    // Under a sudo that reset `$HOME` to root's, `rustup` would read root's empty `~/.rustup` and
    // report no nightly. Point it at the *invoking* user's toolchain home so the row is honest
    // whichever way setup is run (only when `RUSTUP_HOME` isn't already pinned by the environment).
    if std::env::var_os("RUSTUP_HOME").is_none() {
        if let Some(user) = std::env::var_os("SUDO_USER") {
            if let Some(home) = user_home(&user) {
                cmd.env("RUSTUP_HOME", home.join(".rustup"));
            }
        }
    }
    cmd.output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.trim().starts_with("rust-src"))
        })
        .unwrap_or(false)
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

/// Bail unless `/dev/kvm` is present: the shared guard every VM-booting subcommand runs first, so the
/// "needs a KVM host" refusal reads identically across the bench and demo sections. `what` names the
/// caller (e.g. `"bench-boot"`) for the message.
fn require_kvm(what: &str) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("{what} needs /dev/kvm (run on a KVM-capable host)");
    }
    Ok(())
}

/// The local vendor mirror, if the operator set `AGENT_VENDOR_DIR`: the offline source for every
/// sha-pinned upstream input (`cargo xtask vendor`), so a build never reaches the Firecracker S3
/// bucket or the Alpine CDN. `None` means fetch from pinned upstream (the default).
fn vendor_dir() -> Option<PathBuf> {
    std::env::var_os("AGENT_VENDOR_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The artifact filenames under [`artifacts_dir`], defined once so the many readers/writers
/// (`build-rootfs`, `bench-boot`, `setup`, `fetch-artifacts`) can't drift apart: the pinned guest
/// kernel, the minimal boot rootfs (fetched), and the agent rootfs (`build-rootfs` output).
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

fn in_path(bin: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(bin).is_file())
}

/// Resolve a per-user dev-toolchain binary: `$PATH` first, then the cargo bin dirs. `cargo install`
/// places these build-only tools (`bpf-linker`, `rustup`) in `~/.cargo/bin`, which `sudo` drops from
/// root's PATH, so the natural `sudo cargo xtask setup` (run to green the *runtime* rows) would
/// otherwise report an installed tool as missing. Checking the cargo bin dirs, including the
/// *invoking* user's under sudo, keeps the dev-toolchain rows honest whichever way setup is invoked.
fn dev_tool_path(bin: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        if let Some(hit) = std::env::split_paths(&path)
            .map(|dir| dir.join(bin))
            .find(|p| p.is_file())
        {
            return Some(hit);
        }
    }
    cargo_bin_dirs()
        .into_iter()
        .map(|dir| dir.join(bin))
        .find(|p| p.is_file())
}

/// The cargo bin dirs to search beyond `$PATH`: `$CARGO_HOME/bin`, `$HOME/.cargo/bin`, and, when
/// running under `sudo`, the *invoking* user's `~/.cargo/bin` (their `$HOME` is often root's here).
fn cargo_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
        dirs.push(PathBuf::from(cargo_home).join("bin"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".cargo").join("bin"));
    }
    if let Some(user) = std::env::var_os("SUDO_USER") {
        if let Some(home) = user_home(&user) {
            dirs.push(home.join(".cargo").join("bin"));
        }
    }
    dirs
}

/// The home directory of `user`, from `getent passwd` (field 6), falling back to `/home/<user>` if
/// `getent` is unavailable, so the sudo path in [`cargo_bin_dirs`] never hardcodes the home layout.
fn user_home(user: &OsStr) -> Option<PathBuf> {
    if let Ok(out) = Command::new("getent").arg("passwd").arg(user).output() {
        if out.status.success() {
            if let Some(home) = String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .and_then(|l| l.split(':').nth(5))
                .filter(|h| !h.is_empty())
            {
                return Some(PathBuf::from(home));
            }
        }
    }
    Some(PathBuf::from("/home").join(user.to_str()?))
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

    #[test]
    fn effective_uid_parses_the_second_uid_field_and_rejects_drift() {
        // The privileged gate's root check keys off this parse; the failure direction is a loud
        // refusal either way, but the euid must come from the right field.
        let status = "Name:\tcargo\nUid:\t1000\t0\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(
            parse_effective_uid(status),
            Some(0),
            "second field is the euid"
        );
        assert_eq!(
            parse_effective_uid("Name:\tcargo\nUid:\t1000\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(parse_effective_uid("Name:\tcargo\n"), None, "no Uid line");
        assert_eq!(
            parse_effective_uid("Uid:\t1000\n"),
            None,
            "a truncated Uid line is a parse failure, not a guess"
        );
        // And the live read on this host parses (format drift would surface here).
        assert!(effective_uid().is_ok());
    }

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
