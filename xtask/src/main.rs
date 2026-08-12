//! `cargo xtask <cmd>`, dev orchestration for the agent sandbox engine.
//!
//! The command list lives on the `Cmd` enum below and renders as `cargo xtask --help`, so this header
//! keeps no second copy of it. Each module carries its own `//!` header; the gates and the shared
//! plumbing (paths, `cargo` and tool runners) live here.
//!
//! The eBPF crate (`crates/probes`) builds for `bpfel-unknown-none` and is excluded from the host
//! workspace; `build-probes` builds its object (with BTF) and is folded **into** `ci` (guarded, so
//! the CI gate still runs on hosts without the eBPF toolchain).
#![forbid(unsafe_code)]

mod artifacts;
mod bench;
mod dist;
mod drift;
mod guest_bins;
mod rootfs;
mod selfhost;
mod vendor;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    version,
    about = "dev orchestration for the agent sandbox engine",
    // Bare `cargo xtask` prints the command list instead of a terse "subcommand required" error.
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host-safe gate: fmt · prose-drift · clippy `-D warnings` · build · test · docs · cargo-deny.
    Ci,
    /// Privileged integration tests (KVM + eBPF), the `#[ignore]`d tests. Needs `/dev/kvm` + caps.
    #[command(visible_alias = "ci-priv")]
    CiPrivileged {
        /// Run the test phase this many times (setup runs once): the release-readiness soak, so
        /// "N consecutive clean privileged runs" is one command. Fails fast, naming the run that
        /// broke.
        #[arg(long, value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        repeat: u32,
    },
    /// Check the host can do KVM + eBPF; report what's missing.
    Setup,
    /// Single-command self-host: obtain the pinned kernel + rootfs, build the guest image + eBPF
    /// object, install the `bsx` binary, and (on a KVM host) boot one sandbox to prove
    /// it. Offline when `BSX_VENDOR_DIR` points at a `cargo xtask vendor` mirror.
    SelfHost {
        /// Where to install the `bsx` binary (default `~/.local/bin`).
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
    #[command(visible_alias = "probes")]
    BuildProbes,
    /// Check the pinned API surface against a baseline git rev with `cargo-semver-checks`, naming
    /// each crate explicitly (the default set silently drops every `publish = false` package, which
    /// is all of them). Refuses rather than reporting a pass it did not earn. Needs
    /// `cargo-semver-checks`; not part of `ci` (it builds rustdoc for two trees).
    SemverCheck {
        /// The git rev to compare against (default: the latest `v*` tag).
        #[arg(long, value_name = "REV")]
        baseline: Option<String>,
    },
    /// Download + sha256-verify the pinned guest kernel and rootfs into `artifacts/` (needs `curl`).
    FetchArtifacts,
    /// Assemble the shippable release package: the release binary + the guest kernel, rootfs, and
    /// eBPF object, staged, sha256-manifested, and tarred into `dist/` with a `SHA256SUMS`.
    /// Vendor-aware via `BSX_VENDOR_DIR`; the eBPF toolchain is required (a
    /// package without the audit half is not the product).
    Dist {
        /// The package version (release CI passes the pushed tag). Default: `git describe --tags`
        /// against the `v0.0.x` checkpoint line, `v` stripped.
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
    },
    /// Mint (or show) the release signing key and print the pin-and-secret ceremony: pin the
    /// public key (`release-key.pem` + the `install.sh` heredoc), set the
    /// `BSX_RELEASE_SIGNING_KEY` CI secret. The private key lives at `--path`, outside the repo.
    ReleaseKey {
        /// Where the private key file lives (created `0600` on first use; never under `dist/`).
        #[arg(long, value_name = "FILE")]
        path: PathBuf,
    },
    /// Build the static native-ELF fixture (`examples/writefile`) for the guest target, the
    /// runtime-agnostic test injects and runs it to prove the engine executes any static Linux binary.
    BuildGuestExample,
    /// Assemble the guest rootfs: a minimal Alpine base + the guest runtimes (python3) + the static
    /// agent + a vsock init, as an ext4 image at `artifacts/rootfs-guest.ext4` (needs `curl`,
    /// `tar`, `mke2fs`, `truncate`). Reproducible: two builds are byte-identical.
    #[command(visible_alias = "rootfs")]
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
    /// Measure boot-to-userspace latency (percentiles) of the guest rootfs, on both the read-only
    /// shared base and the read-write per-VM copy, so the base **size**'s effect on boot is visible
    ///. Needs `/dev/kvm` + the built guest rootfs.
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
    /// sharing density. Needs `/dev/kvm` + the built guest rootfs.
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
    /// the built guest rootfs.
    BenchFootprint {
        /// How many identical sandboxes to bring up per strategy (it stops earlier at the memory
        /// floor). Default 4.
        #[arg(long, default_value_t = 4)]
        count: usize,
    },
    /// Run the whole benchmark suite as one report to stdout, every section in order, with the
    /// methodology stated and the host recorded. Sections whose host prerequisite is missing
    /// (`/dev/kvm`, or `CAP_BPF`+`CAP_PERFMON` + the built object) are skipped with the reason
    /// printed. `docs/benchmarks.md` explains why no numbers are published at present.
    #[command(visible_alias = "bench")]
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
    /// Measure the record-signing overhead: the per-record cost of one `ed25519` sign
    /// over already-canonical bytes, plus verify, the SHA-256 chain hash, and a chained sign, so the
    /// integrity step is measured like everything else. Host-only (no KVM, no eBPF); the point is
    /// that it is sub-millisecond and off the boot/exec path.
    BenchSign {
        /// How many iterations to time per operation (more → tighter tail percentiles). Default 1000.
        #[arg(long, default_value_t = 1000)]
        runs: usize,
    },
    /// Fuzz the untrusted-input decoders (the host↔guest channel, the daemon's client wire, the
    /// signed-record envelope, the eBPF-boundary parsers) with `cargo fuzz` (libFuzzer), the deep,
    /// nightly-only counterpart to the in-gate mutation tests. Seeds are folded in from
    /// `fuzz/seeds/<target>/`. Needs `cargo install cargo-fuzz` + a nightly toolchain; never part of
    /// `ci`. `--help` lists the targets, generated from [`FUZZ_TARGETS`] rather than restated
    /// here, where the copy would drift.
    Fuzz {
        /// The libFuzzer target to run.
        #[arg(default_value = "channel_response", value_parser = fuzz_target_parser())]
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
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::CiPrivileged { repeat } => ci_privileged(repeat),
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
        Cmd::SemverCheck { baseline } => semver_check(baseline.as_deref()),
        Cmd::FetchArtifacts => artifacts::fetch_artifacts(),
        Cmd::Dist { version } => dist::dist(version),
        Cmd::ReleaseKey { path } => dist::release_key(&path),
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
        Cmd::Fuzz { target, seconds } => fuzz(&target, seconds),
        Cmd::FuzzSmoke { seconds } => fuzz_smoke(seconds),
    }
}

/// Accept only a real target, and let clap print the list in `--help` rather than a doc comment
/// restating it. The three fuzz subcommands share this so [`FUZZ_TARGETS`] is the only place a
/// target is named in this file, and an unknown one is an error at the edge instead of a
/// cargo-fuzz failure several steps in.
fn fuzz_target_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(FUZZ_TARGETS)
}

/// Every libFuzzer target in `fuzz/`, ordered by value (outermost untrusted boundary first). The
/// single source of truth: the smoke run iterates it and `--help` is generated from it, so neither
/// can drift by construction. Three copies can, because neither a workflow file nor a cargo manifest
/// can resolve a Rust constant: `fuzz/Cargo.toml`'s `[[bin]]` entries, the sources in
/// `fuzz/fuzz_targets/`, and the nightly matrix in `.github/workflows/fuzz.yml`.
/// `fuzz_targets_are_single_sourced` is what holds those three to this list.
const FUZZ_TARGETS: &[&str] = &[
    "protocol_message",
    "channel_response",
    "signing_envelope",
    "channel_request",
    "channel_frame",
    "channel_handshake",
    "syscall_event",
    "egress_rule",
    "audit_record",
    "bsx_config",
    "output_image",
];

/// cargo-fuzz drives libFuzzer under a nightly toolchain, both opt-in installs, so bail with guidance
/// rather than pretending. Fuzzing is never wired into `ci` (the in-gate coverage is the crates' own
/// dependency-light mutation tests).
fn require_cargo_fuzz() -> Result<()> {
    if cargo_fuzz_available() {
        return Ok(());
    }
    let nightly = probes_nightly().unwrap_or("<unreadable pin>");
    bail!(
        "cargo-fuzz not found — install it with `cargo install cargo-fuzz --locked` and add the \
         pinned toolchain (`rustup toolchain install {nightly} --profile minimal`)."
    )
}

/// Build the `+<pinned nightly> fuzz run <target> <corpus> <seeds>` argv. The writable corpus
/// (libFuzzer accumulates new inputs here; generated, gitignored) is created so naming it explicitly
/// (which we must, to also pass the seeds) doesn't trip cargo-fuzz's default. The committed
/// read-only seed corpus is folded in so a run starts *past* the first-byte reject, with real
/// inputs reaching the decode logic.
fn cargo_fuzz_run_argv(target: &str, root: &Path) -> Result<Vec<String>> {
    let corpus = root.join("fuzz/corpus").join(target);
    std::fs::create_dir_all(&corpus).context("create the fuzz corpus dir")?;
    // `+<pinned>`, not a bare `+nightly`: the alias is whatever the last `rustup update` fetched, so
    // a bare `+nightly` would ignore the pin entirely and a crash found here could be unreproducible
    // on the next machine. One nightly serves the whole repo (see [`probes_nightly`]).
    let toolchain = format!("+{}", probes_nightly()?);
    let mut args: Vec<String> = [toolchain.as_str(), "fuzz", "run", target]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    args.push(corpus.to_string_lossy().into_owned());
    let seeds = root.join("fuzz/seeds").join(target);
    if seeds.is_dir() {
        args.push(seeds.to_string_lossy().into_owned());
    }
    Ok(args)
}

/// Invoke `cargo <args>` from the repo root (cargo-fuzz discovers the `fuzz/` crate there). The
/// leading `+<pinned nightly>` in `args` forces that toolchain via the rustup proxy: libFuzzer builds
/// with `-Zsanitizer=address`, nightly-only, so inheriting a stable default would fail with "the
/// option `Z` is only accepted on the nightly compiler". rustup propagates the selection to the
/// inner build.
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

/// Run one `cargo fuzz` (libFuzzer) target against the untrusted-input decoders, seeded. A positive
/// `seconds` bounds the run (`0` runs until a crash or Ctrl-C).
fn fuzz(target: &str, seconds: u64) -> Result<()> {
    require_cargo_fuzz()?;
    let root = workspace_root();
    let mut args = cargo_fuzz_run_argv(target, root)?;
    args.push("--".to_owned());
    args.push(format!("-max_total_time={seconds}"));
    run_cargo_fuzz(&args, root)
}

/// Warn about a `fuzz/corpus/<name>` directory that is not a [`FUZZ_TARGETS`] entry, with how many
/// inputs it holds. Renaming a target leaves its corpus behind under the old name and cargo-fuzz
/// starts the new one from empty, so accumulated coverage goes *quiet* rather than missing: the
/// inputs are still on disk, just under a name nothing reads.
///
/// A warning from a dev command rather than an assertion in `ci`, because `fuzz/corpus/` is
/// gitignored working data. A gate reading it would pass or fail on whatever the developer happened
/// to have run locally, and would fail on a fresh clone that has no corpus at all.
fn warn_orphan_corpora(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root.join("fuzz/corpus")) else {
        return; // nothing fuzzed here yet
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if FUZZ_TARGETS.contains(&name) || !entry.path().is_dir() {
            continue;
        }
        let inputs = std::fs::read_dir(entry.path()).map_or(0, Iterator::count);
        println!(
            "  ! fuzz/corpus/{name} holds {inputs} input(s) but names no target. Renamed? The \
             filenames are content hashes, so `cp -n {name}/* <new-target>/` merges and dedupes in \
             one step; deleting it instead throws the accumulated coverage away."
        );
    }
}

/// The per-PR smoke: fuzz every [`FUZZ_TARGETS`] target for a bounded time, seeded, fail-fast. Cheap
/// enough to run before a push (every target x the default 60s) yet enough to catch a decoder a change
/// just broke, the gap between "green nightly" and "this PR regressed a parser".
fn fuzz_smoke(seconds: u64) -> Result<()> {
    require_cargo_fuzz()?;
    warn_orphan_corpora(workspace_root());
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

/// This process's effective uid, read from `/proc/self/status` (`Uid:` line, second value), so the
/// check needs no libc call.
/// The controllers the cgroup-enforcement tests need but `subtree` (the root
/// `cgroup.subtree_control` text) does not delegate, or `None` when both are there. A word match,
/// not a substring one, because `cpuset` must never satisfy `cpu`.
fn missing_cgroup_controllers(subtree: &str) -> Option<String> {
    let missing: Vec<&str> = ["cpu", "memory"]
        .into_iter()
        .filter(|c| !subtree.split_whitespace().any(|w| w == *c))
        .collect();
    (!missing.is_empty()).then(|| missing.join(" and "))
}

pub(crate) fn effective_uid() -> Result<u32> {
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
    // The prose-drift lint runs early: it is sub-second, and a comment pointing at a renamed
    // repo path or a dead Markdown link should surface before the slow compile steps.
    drift::check(workspace_root())?;
    // The pinned stable toolchain and the declared MSRV floor are kept in step by hand;
    // catch a bump that moved only one before the compile, not after a downstream MSRV surprise.
    toolchain_msrv_agree(workspace_root())?;
    // The detached fuzz workspace's lockfile: nothing else in the tree checks it, and it had
    // already stopped resolving. Cheap and early, next to the other pin checks.
    fuzz_lockfile_resolves(workspace_root())?;
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
    // What this step buys is `-D warnings` over rustdoc's lints, above all
    // `broken_intra_doc_links`: a `[`Type`]` that no longer resolves is a dead pointer in prose,
    // the same class the drift lint catches for repo paths. The rendered HTML is not the point and
    // is never published (`.github/workflows/docs.yml` builds the mdBook, not rustdoc).
    //
    // A bin and a lib both named `bsx` in *different* packages would render to the same path and
    // collide here. Both live in the CLI package, where cargo resolves them, so `target/doc/` holds
    // one directory per crate and nothing is suppressed.
    cargo_env(
        &["doc", "--no-deps", "--workspace", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    cargo(&["deny", "check"])?;
    deny_detached_workspaces(workspace_root())?;
    lint_detached_workspaces(workspace_root())?;
    // The eBPF object build is part of the CI gate. Host-safe and guarded, it skips with a note
    // when `bpf-linker`/`rustup` are absent, so `ci` still runs everywhere, but on a set-up dev box a
    // probe that fails to compile (or drops its BTF) now fails here, not later at load.
    build_probes()?;
    println!("\n✓ all checks passed");
    Ok(())
}

/// The manifests `cargo deny check` at the root cannot reach: every path in the root workspace's
/// `exclude`, read from the tree rather than listed here.
///
/// A hand-written list is the thing that rots. `detached_workspaces_are_all_scanned` holds this to
/// `exclude`, so a third detached workspace has to be decided about instead of defaulting into an
/// unscanned gap, which is how the first two got there.
fn detached_manifests(root: &Path) -> Result<Vec<PathBuf>> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .context("read the root Cargo.toml to find the excluded workspaces")?;
    Ok(excluded_dirs(&manifest)
        .into_iter()
        .map(|d| root.join(d).join("Cargo.toml"))
        .collect())
}

/// The `exclude = [...]` entries of a workspace manifest, in order.
fn excluded_dirs(manifest: &str) -> Vec<String> {
    let Some(rest) = manifest.split_once("exclude = [").map(|(_, r)| r) else {
        return Vec::new();
    };
    let Some((list, _)) = rest.split_once(']') else {
        return Vec::new();
    };
    list.split(',')
        .filter_map(|e| {
            let e = e.trim().trim_matches('"');
            (!e.is_empty()).then(|| e.to_string())
        })
        .collect()
}

/// The `[workspace.lints.clippy]` entries the root manifest sets to `deny`, as `-D` flags.
///
/// Read from the root manifest so the detached workspaces cannot carry a second, drifting copy of
/// the list. They are `exclude`d, so `[lints] workspace = true` is not available to them: cargo
/// only inherits lints for members. Passing the same denies on the command line is the way to give
/// one policy to both halves of the tree.
fn workspace_clippy_denies(root: &Path) -> Result<Vec<String>> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .context("read the root Cargo.toml for its clippy lint policy")?;
    let Some((_, rest)) = manifest.split_once("[workspace.lints.clippy]") else {
        return Ok(Vec::new());
    };
    let body = rest.split("\n[").next().unwrap_or(rest);
    Ok(body
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(_, v)| v.trim().trim_matches('"') == "deny")
        .map(|(k, _)| format!("-Dclippy::{}", k.trim()))
        .collect())
}

/// `cargo fmt --check` and `cargo clippy -D warnings` for the detached workspaces.
///
/// `crates/probes` is the crate that matters here: it is the only one allowed `unsafe` and its object ships
/// in the release tarball, yet a root-workspace `clippy` walks neither detached workspace.
///
/// Each command runs with the cwd **inside** its workspace, so rustup honours that directory's own
/// `rust-toolchain.toml`: `crates/probes` pins a nightly and the root pins stable, and linting the probes
/// with the root's stable would fail on features the crate needs. Clippy on `crates/probes` skips cleanly
/// when that nightly is absent, the same guard and reason as [`build_probes`], since the everyday gate has
/// to run everywhere.
fn lint_detached_workspaces(root: &Path) -> Result<()> {
    let denies = workspace_clippy_denies(root)?;
    for manifest in detached_manifests(root)? {
        let dir = manifest.parent().unwrap_or(root).to_path_buf();
        let shown = dir.strip_prefix(root).unwrap_or(&dir).display().to_string();
        // Only `crates/probes` pins its own channel; `fuzz` builds on whatever the caller has.
        //
        // The nightly is installed `--profile minimal`, so the toolchain being present does not
        // mean it can lint: `rustfmt` and `clippy` are separate components. Skip on either being
        // absent rather than failing, the same call [`build_probes`] makes, and name the fix.
        let toolchain = if dir.ends_with("probes") {
            let nightly = probes_nightly()?;
            let missing: Vec<&str> = ["rustfmt", "clippy"]
                .into_iter()
                .filter(|c| !nightly_has_component(c))
                .collect();
            if !nightly_ebpf_ready() || !missing.is_empty() {
                println!(
                    "· skipping fmt/clippy for {shown}: {nightly} lacks {} (add it: `rustup \
                     component add --toolchain {nightly} {}`)",
                    if missing.is_empty() {
                        "the pinned toolchain".to_string()
                    } else {
                        missing.join(" and ")
                    },
                    missing.join(" ")
                );
                continue;
            }
            Some(nightly)
        } else {
            None
        };
        run_in(&dir, toolchain, &["fmt", "--check"], &shown)?;
        // No `--all-targets`: it adds a test harness, and `crates/probes` is `no_std` for a target
        // with no `test` crate and no panic handler, so the harness cannot build at all. The
        // default targets are the ones that ship.
        let mut args = vec!["clippy", "--", "-Dwarnings"];
        args.extend(denies.iter().map(String::as_str));
        run_in(&dir, toolchain, &args, &shown)?;
    }
    Ok(())
}

/// One cargo invocation inside `dir`, under the toolchain that directory pins.
///
/// `toolchain` names it explicitly rather than letting the `rust-toolchain.toml` in `dir` be found,
/// because a parent `cargo xtask` leaks `RUSTUP_TOOLCHAIN=stable` into every child and that
/// overrides the file. [`build_probes`] hit this first and solved it the same way; the difference
/// here is that it cost a debugging round because the command passed by hand and failed from the
/// gate, which is the signature of an inherited variable rather than a broken command.
fn run_in(dir: &Path, toolchain: Option<&str>, args: &[&str], shown: &str) -> Result<()> {
    let mut cmd = match toolchain {
        Some(t) => {
            println!("$ rustup run {t} cargo {}  (in {shown})", args.join(" "));
            let mut c = Command::new("rustup");
            c.args(["run", t, "cargo"]);
            c
        }
        None => {
            println!("$ cargo {}  (in {shown})", args.join(" "));
            Command::new(env!("CARGO"))
        }
    };
    let status = cmd
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| format!("running cargo {} in {shown}", args.join(" ")))?;
    if !status.success() {
        bail!("cargo {} failed in {shown}", args.join(" "));
    }
    Ok(())
}

/// `cargo deny check advisories` for the workspaces the root check cannot see.
///
/// `crates/probes` and `fuzz` carry their own `[workspace]` and lockfile and are excluded from the root
/// one, so `cargo deny check` walks neither. `crates/probes` is the crate that matters, being the only one
/// allowed `unsafe` and the one whose object ships in the tarball.
///
/// Advisories only: bans, licenses, and sources describe the shipped dependency graph the root check
/// already owns, and re-running them here would mean a second policy to keep in step for no coverage.
///
/// **No `--config`, deliberately.** Pointing these at the root `deny.toml` buys one line over cargo-deny's
/// defaults (`yanked = "deny"` instead of `warn`) and costs a version-sensitive argument: `--config`
/// belongs to the `check` subcommand in some releases and is global in others, which passes on a dev box
/// and fails CI. Vulnerabilities are denied by default, which is why this scan exists; a yanked crate here
/// warning rather than failing is an accepted trade.
fn deny_detached_workspaces(root: &Path) -> Result<()> {
    for manifest in detached_manifests(root)? {
        let shown = manifest.strip_prefix(root).unwrap_or(&manifest);
        println!(
            "$ cargo deny --manifest-path {} check advisories",
            shown.display()
        );
        let status = Command::new(env!("CARGO"))
            .args(["deny", "--manifest-path"])
            .arg(&manifest)
            .args(["check", "advisories"])
            .status()
            .with_context(|| format!("running cargo deny for {}", shown.display()))?;
        if !status.success() {
            bail!("cargo deny check advisories failed for {}", shown.display());
        }
    }
    Ok(())
}

/// Asserts `fuzz/Cargo.lock` still resolves. That workspace is **detached**, with its own `[workspace]` and
/// lockfile, and takes the rest of the tree by path, so a dependency edit in the main workspace ages it.
/// `cargo xtask fuzz` lets cargo repair the lockfile in place, which turns drift into a silent rewrite
/// rather than a report. `crates/probes` is detached the same way but its build passes `--locked`, so only
/// this one can rot unobserved.
///
/// Resolution is the whole check: building the targets needs nightly plus cargo-fuzz, neither of which
/// belongs in a gate that has to run everywhere.
fn fuzz_lockfile_resolves(root: &Path) -> Result<()> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .arg("--manifest-path")
        .arg(root.join("fuzz/Cargo.toml"))
        .output()
        .context("running `cargo metadata` for fuzz/")?;
    if !out.status.success() {
        bail!(
            "fuzz/Cargo.lock does not resolve with --locked. Regenerate it with:\n    \
             cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null\n\
             cargo said:\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    println!("· fuzz/Cargo.lock resolves with --locked");
    Ok(())
}

/// Assert the pinned stable toolchain (`rust-toolchain.toml`'s `channel`) and the declared MSRV
/// floor (`[workspace.package] rust-version` in the root `Cargo.toml`) agree at `major.minor`. They
/// are kept in step by hand, so a bump touching only one silently makes the gate build at
/// a compiler that differs from the floor it advertises, and a downstream pinning our MSRV would
/// then build against a Rust we never test. A named channel (`stable`/`nightly`) carries no version
/// to compare, so the numeric check is skipped there; today's pin is numeric.
fn toolchain_msrv_agree(root: &Path) -> Result<()> {
    let toolchain = std::fs::read_to_string(root.join("rust-toolchain.toml"))
        .context("reading rust-toolchain.toml")?;
    let cargo =
        std::fs::read_to_string(root.join("Cargo.toml")).context("reading the root Cargo.toml")?;
    let channel =
        toml_string_value(&toolchain, "channel").context("no `channel` in rust-toolchain.toml")?;
    let msrv = toml_string_value(&cargo, "rust-version")
        .context("no `rust-version` in the root Cargo.toml")?;
    let Some(chan) = major_minor(&channel) else {
        // A named channel, not a version pin: nothing numeric to hold the floor against.
        println!(
            "· toolchain/MSRV: channel `{channel}` is not version-pinned; agreement not checked"
        );
        return Ok(());
    };
    let Some(floor) = major_minor(&msrv) else {
        bail!("Cargo.toml rust-version `{msrv}` is not a `MAJOR.MINOR` version");
    };
    if chan != floor {
        bail!(
            "toolchain/MSRV drift: rust-toolchain.toml pins `{channel}` but Cargo.toml \
             rust-version is `{msrv}`; keep them in step (major.minor must match)"
        );
    }
    println!(
        "· toolchain/MSRV: rust-toolchain.toml and Cargo.toml agree at {}.{}",
        floor.0, floor.1
    );
    Ok(())
}

/// The first `key = "value"` assignment's value (quotes stripped), scanning trimmed, non-comment
/// lines. A tiny hand parser: xtask has no TOML dependency, and each key we read is the sole such
/// string assignment in its file (`channel` in `[toolchain]`, `rust-version` in
/// `[workspace.package]`).
fn toml_string_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        return Some(rest.trim().trim_matches('"').to_string());
    }
    None
}

/// `(major, minor)` parsed from a `MAJOR.MINOR[.PATCH]` version, or `None` when the string is not
/// numeric (a named channel such as `stable`).
fn major_minor(v: &str) -> Option<(u32, u32)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Booting a microVM and loading/attaching eBPF need `/dev/kvm` + elevated caps, so those tests are
/// `#[ignore]`d and run only here, on a machine that has them.
fn ci_privileged(repeat: u32) -> Result<()> {
    privileged_preflight()?;
    // Serial (`--test-threads=1`): these tests each boot a real microVM and some assert on
    // host-global state (no leaked scratch dirs / taps / VMM processes, concurrent prewarmed clones). Run
    // in parallel they contend for KVM and, worse, one test's live scratch dir trips another's
    // leak check. Real-VM integration is I/O-bound on boot anyway, so serial costs little.
    // `--repeat N` loops only this phase (setup above ran once): the soak that makes "N
    // consecutive clean runs" a single command, for chasing intermittent failures. Fail fast so
    // the broken run's logs sit right above the error.
    for run in 1..=repeat {
        if repeat > 1 {
            println!("\n== privileged run {run}/{repeat} ==");
        }
        cargo(&[
            "test",
            "--workspace",
            "--locked",
            "--",
            "--ignored",
            "--test-threads=1",
        ])
        .with_context(|| format!("privileged run {run}/{repeat} failed"))?;
        if repeat > 1 {
            println!("privileged run {run}/{repeat}: ok");
        }
    }
    println!("\n✓ privileged integration passed");
    Ok(())
}

/// Everything a privileged test run needs before a single test executes: the host refusals, then the
/// artifacts the tests load, split out so what the gate demands of the host stays one readable
/// block rather than checks scattered through `ci_privileged`.
fn privileged_preflight() -> Result<()> {
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
    // The cgroup-enforcement tests build their limit cgroup under /sys/fs/cgroup, and real root
    // (checked above) is not what that needs: it is cgroup v2 with `cpu` and `memory` delegated at
    // the root. A v1/hybrid host presents that path as ordinary files, so the fixture refuses (and
    // its callers skip) — and a skipped test looks like a pass. Asked of the kernel, not a distro
    // list: the delegation file either exists and names the controllers, or the host cannot run
    // these tests.
    match std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control") {
        Err(_) => bail!(
            "/sys/fs/cgroup is not a cgroup v2 mount (no cgroup.subtree_control) — the cgroup \
             enforcement tests would skip themselves, and a skipped test looks like a pass \
             (mount cgroup2 on /sys/fs/cgroup)"
        ),
        Ok(subtree) => {
            if let Some(missing) = missing_cgroup_controllers(&subtree) {
                bail!(
                    "{missing} not delegated in /sys/fs/cgroup/cgroup.subtree_control — the \
                     cgroup enforcement tests would skip themselves, and a skipped test looks \
                     like a pass.\n  Delegate with:\n    echo '+cpu +memory' | sudo tee \
                     /sys/fs/cgroup/cgroup.subtree_control"
                );
            }
        }
    }
    // The jailed-boot tests build a chroot under the scratch dir (mknod'd /dev/kvm, an exec'd
    // firecracker copy); on a `nodev` mount (every systemd `/tmp` default) or a `noexec` one
    // (hardened baselines) they fail *deep in the run* with `ScratchDirNodev`/`ScratchDirNoexec`,
    // reading like an engine bug rather than the one-line host fix it is (the engine carries its
    // own boot-time refusal; this is the gate's up-front one). Same loud-up-front discipline as the
    // checks above, reusing the doctor's tested detector against the exact scratch dir the tests
    // will resolve (`BootConfig::from_env`, so an `BSX_SCRATCH_DIR` override clears it).
    let scratch = bsx_engine::BootConfig::from_env().scratch_dir;
    let flags = bsx_engine::doctor::scratch_mount_flags(&scratch);
    if flags.is_some_and(bsx_engine::doctor::MountFlags::blocks_jail) {
        let flag = if flags.is_some_and(|f| f.nodev) {
            "nodev"
        } else {
            "noexec"
        };
        bail!(
            "scratch dir {} is on a `{flag}` mount: the jailer's chroot can't open its /dev/kvm or \
             exec its firecracker copy there, so the jailed-boot tests fail deep in the run.\n  \
             Point it off {flag} (e.g. /var/tmp) — or \
             use ./ci-privileged.sh, which sets all three env concerns:\n    \
             sudo -E env CARGO_TARGET_DIR=\"$PWD/target-privileged\" \
             BSX_SCRATCH_DIR=/var/tmp/bsx cargo xtask ci-privileged",
            scratch.display()
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
             AGENTS.md)",
            object.display()
        );
    }
    Ok(())
}

/// Print a checklist of the host prerequisites; read-only, never fails the build.
fn setup() -> Result<()> {
    println!("agent: host capability check\n");

    // The runtime host checks are the *same* implementation `bsx doctor` renders: one
    // source of truth for what "ready" means, so the dev-box check and the operator's can't drift.
    // The artifact paths come from the env-layered config (the workspace `artifacts/` defaults),
    // matching what a dev boot resolves.
    let config = bsx_engine::BootConfig::from_env();
    for c in bsx_engine::doctor::checks(&config) {
        let ok = c.status == bsx_engine::doctor::CheckStatus::Ok;
        check(&c.label, ok);
    }
    // The eBPF-observability capability row (owned by the probe loader, out of `bsx`).
    check(
        "eBPF observability (CAP_BPF + CAP_PERFMON + kernel BTF)",
        bsx_probes_loader::check_support().is_ok(),
    );

    // Dev-toolchain checks, only `xtask` needs these (building the eBPF object, the guest agent,
    // verifying static links); an operator running the shipped engine does not, so they are not in
    // the shared `bsx doctor` set.
    println!("\ndev toolchain (for building, not running):");
    // Verified, not just announced: a row that printed the pin while any version satisfied it would
    // be the same hollow-green this gate exists to refuse.
    check(
        &format!(
            "bpf-linker installed, pinned {BPF_LINKER_VERSION} (found {})",
            bpf_linker_version().unwrap_or_else(|| "none".into())
        ),
        bpf_linker_version().as_deref() == Some(BPF_LINKER_VERSION),
    );
    check(
        &format!(
            "pinned nightly {} + rust-src (eBPF object build: `cargo xtask build-probes`)",
            // The gate test guarantees this parses, so the fallback is unreachable in a checked-out
            // tree; it exists so a setup *report* never fails outright over a display string.
            probes_nightly().unwrap_or("<unreadable pin>")
        ),
        nightly_ebpf_ready(),
    );
    check(
        &format!(
            "guest musl target ({}): the static guest agent build (`cargo xtask build-rootfs`)",
            guest_bins::GUEST_TARGET
        ),
        guest_bins::guest_target_installed(),
    );
    // Not optional for an unprivileged rootfs build: without it the staged tree is owned by the
    // builder's uid rather than 0, and the image hash then depends on who ran the build.
    check(
        "fakeroot (guest rootfs ownership: uid 0, not yours)",
        dev_tool_path("fakeroot").is_some(),
    );
    check(
        "readelf (binutils: static-link verification)",
        dev_tool_path("readelf").is_some(),
    );
    check(
        "mke2fs >= 1.47.1 (reproducible rootfs: SOURCE_DATE_EPOCH honoured)",
        matches!(rootfs::mke2fs_version(), Some(v) if v >= rootfs::MKE2FS_SOURCE_DATE_EPOCH_MIN),
    );

    // The degradation matrix, the same fails-open-vs-hard split `bsx doctor` prints, from the one
    // shared source, so a mismatched host explains itself *before* the first boot discovers it.
    println!("\nDegradation matrix: what a missing item above means at runtime:");
    for line in bsx_engine::doctor::matrix() {
        println!("  {line}");
    }

    // The engine/hoster line: the engine guarantees its own privileged tools can't
    // be weaponized; *deploying* them, as whom, when, over what directory, is the hoster's, and
    // these are the calls only they can make. Surfaced here, in the host-check tool, because
    // that's the one place a self-hoster looks before standing the engine up.
    println!("\nHardening: the hoster's responsibility (the engine can't decide these for you):");
    println!("    scratch base: point BSX_SCRATCH_DIR at a dir only the engine user owns (not the");
    println!(
        "                  world-writable /tmp default), so no other local user can plant residue"
    );
    println!("    run the sweep: schedule bsx_engine::sweep_orphans() (boot-time + periodic), the");
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
    println!("             cryptic verifier reject (bsx_probes_loader::check_support).");

    println!("\nMissing items are covered in docs/cli-install.md -> Prerequisites.");
    Ok(())
}

/// Builds the eBPF object for `bpfel-unknown-none` via `bpf-linker`. The crate is **excluded** from the
/// workspace and builds under its own nightly with `-Z build-std`, since rustup ships no prebuilt `core`
/// for the BPF target, so this drives its build directly rather than through the workspace `cargo`.
///
/// Guarded so `cargo xtask` stays runnable everywhere: on a host missing any of the toolchain it prints a
/// note and returns `Ok` rather than failing, because the everyday host gate must not require the eBPF
/// toolchain. This step is folded into `ci`, and `ci-privileged` builds it before the probe tests.
/// The crates whose public API a `v0.1.0` tag would freeze: the surface `AGENTS.md`'s `api`-scope
/// rule, `docs/embedding-scope.md`, and `RELEASES.md` all name.
/// `pinned_surface_is_named_the_same_in_every_doc` holds those three to this list, so a crate can't
/// join the surface in one document and be missing from the tag's own release notes.
const PINNED_SURFACE_CRATES: [&str; 4] =
    ["bsx-engine", "bsx-channel", "bsx-protocol", "bsx-record"];

/// `cargo xtask semver-check`: the pinned surface against a baseline rev.
///
/// **Every crate is named with its own `-p`**, because `cargo-semver-checks` drops
/// `publish = false` packages from its default set without saying so, and every crate here is
/// `publish = false` by decision (`docs/embedding-scope.md`). Run bare against this workspace it
/// prints one "Cloning" line, checks nothing, and exits `0`: a pass that verified nothing, which is
/// the hollow green the two gates exist to prevent. This refuses that outcome instead of reporting
/// it, so a green here means checks actually ran.
fn semver_check(baseline: Option<&str>) -> Result<()> {
    if !in_path("cargo-semver-checks") {
        bail!(
            "cargo-semver-checks is not installed (`cargo install cargo-semver-checks --locked`)"
        );
    }
    let root = workspace_root();
    let baseline = match baseline {
        Some(rev) => rev.to_string(),
        None => latest_version_tag(root)?,
    };

    // At `0.0.x` cargo's own rules make every bump a major one, so no change can be a violation and
    // every lint is skipped: the run is green no matter what the diff did. Say so rather than
    // print a pass that means nothing.
    let version = toml_string_value(
        &std::fs::read_to_string(root.join("Cargo.toml")).context("reading the root Cargo.toml")?,
        "version",
    )
    .unwrap_or_default();
    if version.starts_with("0.0.") {
        bail!(
            "the workspace is {version}: under cargo's semver rules every 0.0.x bump is already a \
             major change, so cargo-semver-checks skips every lint and reports a pass it did not \
             earn. This command becomes meaningful at 0.1.0 (see RELEASES.md)."
        );
    }

    println!(
        "· baseline {baseline}, {} crates",
        PINNED_SURFACE_CRATES.len()
    );
    for krate in PINNED_SURFACE_CRATES {
        let shown = format!("cargo semver-checks --baseline-rev {baseline} -p {krate}");
        println!("$ {shown}");
        let status = Command::new("cargo")
            .args(["semver-checks", "--baseline-rev", &baseline, "-p", krate])
            .current_dir(root)
            .status()
            .with_context(|| format!("running {shown}"))?;
        if !status.success() {
            bail!("{krate} fails semver against {baseline}");
        }
    }
    println!("\n✓ the pinned surface is compatible with {baseline}");
    Ok(())
}

/// The newest `v*` tag by version order, the default semver baseline. An error when the repo has
/// none, since silently comparing against nothing is the failure this command exists to refuse.
fn latest_version_tag(root: &Path) -> Result<String> {
    let out = Command::new("git")
        .args(["tag", "--list", "v*", "--sort=-v:refname"])
        .current_dir(root)
        .output()
        .context("listing git tags for the semver baseline")?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .context("no `v*` tag to use as a semver baseline; pass --baseline <rev>")
}

fn build_probes() -> Result<()> {
    if !in_path("bpf-linker") {
        println!(
            "· skipping eBPF object build: bpf-linker not found (install it: \
             `cargo install bpf-linker --locked --version {BPF_LINKER_VERSION}`; \
             see `cargo xtask setup`)"
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
        let nightly = probes_nightly()?;
        println!(
            "· skipping eBPF object build: the pinned toolchain {nightly} with `rust-src` is not \
             installed (add it: `rustup toolchain install {nightly} --profile minimal \
             --component rust-src`; see `cargo xtask setup`)"
        );
        return Ok(());
    }
    let dir = workspace_root().join("crates/probes");
    // `rustup run <pinned nightly>` names the toolchain explicitly because a parent `cargo xtask`
    // leaks `RUSTUP_TOOLCHAIN=stable` into this child, which would otherwise override the crate's
    // `rust-toolchain.toml` and fail `build-std`. The channel comes *from* that file
    // ([`probes_nightly`]) rather than a literal, so naming it here can't drift from the pin. The
    // crate's `.cargo/config.toml` supplies the target + `build-std`; `bpf-linker` (on PATH) links
    // the object. `--locked` holds the probes lockfile.
    let nightly = probes_nightly()?;
    println!(
        "$ rustup run {nightly} cargo build --release --locked  (in crates/probes → bpfel-unknown-none)"
    );
    let status = Command::new("rustup")
        .args(["run", nightly, "cargo", "build", "--release", "--locked"])
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
    // The *pinned* toolchain, not the `nightly` alias: with an exact date pinned, having some
    // nightly installed says nothing about having this one, and reporting ready on the wrong
    // toolchain would turn a clean skip into a confusing build failure.
    let Ok(nightly) = probes_nightly() else {
        return false;
    };
    let mut cmd = Command::new(rustup);
    cmd.args(["component", "list", "--toolchain", nightly, "--installed"]);
    // Under a sudo that reset `$HOME` to root's, `rustup` would read root's empty `~/.rustup` and
    // report no nightly. Point it at the *invoking* user's toolchain home so the row is honest
    // whichever way setup is run (only when `RUSTUP_HOME` isn't already pinned by the environment).
    if std::env::var_os("RUSTUP_HOME").is_none()
        && let Some(user) = std::env::var_os("SUDO_USER")
        && let Some(home) = user_home(&user)
    {
        cmd.env("RUSTUP_HOME", home.join(".rustup"));
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

/// Whether the pinned nightly carries `component`, asked the same sudo-aware way as
/// [`nightly_ebpf_ready`].
///
/// The nightly is installed `--profile minimal`, which carries neither `rustfmt` nor `clippy`, so
/// having the toolchain says nothing about being able to lint with it. CI learned this the hard
/// way: the detached-workspace lint passed on a dev box that happened to have both and failed the
/// gate with "'cargo-fmt' is not installed for the toolchain".
fn nightly_has_component(component: &str) -> bool {
    let Some(rustup) = dev_tool_path("rustup") else {
        return false;
    };
    let Ok(nightly) = probes_nightly() else {
        return false;
    };
    let mut cmd = Command::new(rustup);
    cmd.args(["component", "list", "--toolchain", nightly, "--installed"]);
    if std::env::var_os("RUSTUP_HOME").is_none()
        && let Some(user) = std::env::var_os("SUDO_USER")
        && let Some(home) = user_home(&user)
    {
        cmd.env("RUSTUP_HOME", home.join(".rustup"));
    }
    cmd.output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.trim().starts_with(component))
        })
        .unwrap_or(false)
}

/// The exact nightly `crates/probes` builds with, read out of its `rust-toolchain.toml` at compile
/// time. **That file is the single source**: `rustup run <channel>` with a literal `nightly` here
/// would silently override the pin (an explicit toolchain argument outranks the file), which is the
/// same second-copy drift that let the Firecracker pin sit 21 months stale. Parsed rather than
/// duplicated so the two can't disagree; `ebpf_toolchain_pins_are_single_sourced` extends that to
/// the CI workflows, which cannot read the file at all.
/// A malformed toolchain file is an error, never a silent fall back to the floating `nightly`
/// channel: falling back would build with an unpinned compiler while every message still claimed
/// the pin, which is worse than not pinning at all. `ebpf_toolchain_pins_are_single_sourced` fails
/// the gate long before this could fire.
fn probes_nightly() -> Result<&'static str> {
    toolchain_channel(include_str!("../../crates/probes/rust-toolchain.toml")).context(
        "crates/probes/rust-toolchain.toml does not declare a [toolchain] channel: the eBPF \
         nightly pin is unreadable",
    )
}

/// The `channel = "..."` value out of a `rust-toolchain.toml`. Deliberately a line scan, not a TOML
/// parse: `xtask` is dev tooling and this is one unambiguous key, so the dependency isn't worth it.
fn toolchain_channel(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        // Skip the comment prose above the table, which also contains the word `channel`.
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix("channel"))?
        .trim_start()
        .strip_prefix('=')?
        .trim()
        .trim_matches('"')
        .into()
}

/// The `bpf-linker` version the eBPF object is linked with. Unlike `aya` (a Cargo dependency, so
/// `Cargo.lock` pins it), this is a **host binary installed out of band**, and
/// `cargo install bpf-linker --locked` locks bpf-linker's *dependencies*, not bpf-linker itself, so
/// without this every install takes whatever is newest. It links against the pinned nightly's LLVM,
/// so the pair moves together: bump both, or neither.
const BPF_LINKER_VERSION: &str = "0.10.3";

/// The installed `bpf-linker`'s version (`bpf-linker 0.10.3` on stdout), or `None` if it isn't
/// installed or won't report one. Resolved the sudo-aware way, like the other `~/.cargo/bin` dev
/// tools, so `sudo cargo xtask setup` doesn't misreport it as absent.
fn bpf_linker_version() -> Option<String> {
    let out = Command::new(dev_tool_path("bpf-linker")?)
        .arg("--version")
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(1)
        .map(str::to_string)
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

/// Bail unless `/dev/kvm` is present: the shared guard every VM-booting bench runs first, so the
/// "needs a KVM host" refusal reads identically across them. `what` names the caller (e.g.
/// `"bench-boot"`) for the message.
fn require_kvm(what: &str) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("{what} needs /dev/kvm (run on a KVM-capable host)");
    }
    Ok(())
}

/// The local vendor mirror, if the operator set `BSX_VENDOR_DIR`: the offline source for every
/// sha-pinned upstream input (`cargo xtask vendor`), so a build never reaches the Firecracker S3
/// bucket or the Alpine CDN. `None` means fetch from pinned upstream (the default).
fn vendor_dir() -> Option<PathBuf> {
    std::env::var_os("BSX_VENDOR_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The artifact filenames under [`artifacts_dir`], defined once so every reader and writer resolves
/// the same path: the pinned guest kernel, the minimal boot rootfs (fetched), and the guest rootfs
/// (`build-rootfs` output). Deliberately not a list of the callers, which is a copy that goes stale:
/// this comment carried one naming four subcommands when seven modules already called these.
fn kernel_path() -> PathBuf {
    artifacts_dir().join("vmlinux")
}
fn boot_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs.ext4")
}
fn guest_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs-guest.ext4")
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
pub(crate) fn dev_tool_path(bin: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH")
        && let Some(hit) = std::env::split_paths(&path)
            .map(|dir| dir.join(bin))
            .find(|p| p.is_file())
    {
        return Some(hit);
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
    if let Some(user) = std::env::var_os("SUDO_USER")
        && let Some(home) = user_home(&user)
    {
        dirs.push(home.join(".cargo").join("bin"));
    }
    dirs
}

/// The home directory of `user`, from `getent passwd` (field 6), falling back to `/home/<user>` if
/// `getent` is unavailable, so the sudo path in [`cargo_bin_dirs`] never hardcodes the home layout.
fn user_home(user: &OsStr) -> Option<PathBuf> {
    if let Ok(out) = Command::new("getent").arg("passwd").arg(user).output()
        && out.status.success()
        && let Some(home) = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .and_then(|l| l.split(':').nth(5))
            .filter(|h| !h.is_empty())
    {
        return Some(PathBuf::from(home));
    }
    Some(PathBuf::from("/home").join(user.to_str()?))
}

fn cargo(args: &[&str]) -> Result<()> {
    cargo_env(args, &[])
}

/// Run cargo with this host's identity remapped out of whatever it builds. For the binaries a
/// release ships, never for a build a developer runs and debugs.
///
/// A release build carries no debug info, but `panic!` location strings are baked in regardless, and for
/// std and every registry dependency those are absolute paths under this host's `CARGO_HOME` and rustup
/// directory. Two hosts building the same commit therefore emit different bytes, enough on its own to give
/// `rootfs-guest.ext4` a different hash under the same pinned toolchain and package closure.
///
/// Uses `CARGO_ENCODED_RUSTFLAGS` rather than `RUSTFLAGS`, so a home directory containing a space cannot
/// split one flag into two. Either form *replaces* configured `rustflags` rather than appending, which is
/// why this stays on the packaging paths and out of the gate.
fn cargo_reproducible(args: &[&str]) -> Result<()> {
    let flags = remap_flags(
        &cargo_home(),
        &rustc_sysroot()?,
        rustc_commit_hash().as_deref(),
    );
    cargo_env(args, &[("CARGO_ENCODED_RUSTFLAGS", &flags.join("\x1f"))])
}

/// The `--remap-path-prefix` flags [`cargo_reproducible`] passes: `CARGO_HOME` and the toolchain's
/// vendored std sources, each onto a fixed token.
///
/// The std mapping is the subtle one. rustc ships std with its paths already remapped to
/// `/rustc/<commit>/…`, but rewrites them back to the local checkout whenever the `rust-src`
/// component is installed, so a host carrying that component disagrees with one that does not, on
/// the same toolchain. Mapping the checkout onto `/rustc/<commit>` is what makes the two agree.
/// Without a commit hash there is no canonical form to map onto, so that flag is dropped rather
/// than invented: a wrong token would make every host agree with itself and none with upstream.
fn remap_flags(cargo_home: &Path, sysroot: &Path, commit_hash: Option<&str>) -> Vec<String> {
    let mut flags = vec![format!(
        "--remap-path-prefix={}=/cargo",
        cargo_home.display()
    )];
    if let Some(hash) = commit_hash {
        let src = sysroot.join("lib/rustlib/src/rust");
        flags.push(format!(
            "--remap-path-prefix={}=/rustc/{hash}",
            src.display()
        ));
    }
    flags
}

/// This host's `CARGO_HOME`, by cargo's own resolution order.
fn cargo_home() -> PathBuf {
    std::env::var_os("CARGO_HOME").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cargo"),
        PathBuf::from,
    )
}

/// The active toolchain's sysroot, asked of the same `rustc` the build will use (so a leaked
/// `RUSTUP_TOOLCHAIN` moves this answer with it rather than past it).
fn rustc_sysroot() -> Result<PathBuf> {
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .context("running rustc --print sysroot")?;
    if !out.status.success() {
        bail!("rustc --print sysroot exited {:?}", out.status.code());
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    ))
}

/// The rustc commit hash, or `None` when this build of rustc does not carry one (`unknown`, which
/// distro-built toolchains do report). `None` costs one remap, not correctness.
fn rustc_commit_hash() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("commit-hash: "))
        .map(str::trim)
        .filter(|h| !h.is_empty() && *h != "unknown")
        .map(str::to_string)
}

fn cargo_env(args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    println!("$ cargo {}", args.join(" "));
    let mut cmd = Command::new(env!("CARGO"));
    // From the workspace root regardless of the invoker's cwd. Cargo's own subcommands walk up to
    // the workspace on their own, but plugins resolve from the cwd (`cargo deny check` looks for
    // ./Cargo.toml there), so a `cargo xtask ci` run from a subdirectory died at exactly that step.
    cmd.current_dir(workspace_root());
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
    use std::collections::{BTreeMap, BTreeSet};

    use clap::CommandFactory;

    use super::*;

    /// The clap command tree is internally consistent: no colliding subcommand alias, no malformed
    /// argument. `debug_assert` is clap's own audit of the definition, so a bad `visible_alias` or
    /// `value_parser` fails a unit test instead of the first person to type `--help`.
    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Every workspace the root `cargo deny check` cannot walk must still get an advisory scan.
    ///
    /// Both detached workspaces went unscanned from the day they were excluded, and nothing said
    /// so: `audit.yml` is named "audit" and reads like it covers the repo. Deriving the set from
    /// `exclude` means a third one cannot repeat that silently.
    #[test]
    fn detached_workspaces_are_all_scanned() {
        let root = workspace_root();
        let excluded = excluded_dirs(&std::fs::read_to_string(root.join("Cargo.toml")).unwrap());
        assert!(
            !excluded.is_empty(),
            "the root manifest should still exclude the detached workspaces"
        );
        let scanned = detached_manifests(root).unwrap();
        assert_eq!(
            scanned.len(),
            excluded.len(),
            "every excluded workspace needs an advisory scan, got {scanned:?} for {excluded:?}"
        );
        for m in &scanned {
            assert!(m.is_file(), "{} should exist to be scanned", m.display());
        }
    }

    #[test]
    fn excluded_dirs_reads_the_list_and_ignores_the_members() {
        let manifest = r#"
[workspace]
members = ["crates/engine", "xtask"]
exclude = ["crates/probes", "fuzz"]
"#;
        assert_eq!(excluded_dirs(manifest), vec!["crates/probes", "fuzz"]);
        assert!(excluded_dirs("[workspace]\nmembers = [\"a\"]\n").is_empty());
    }

    #[test]
    fn toml_string_value_reads_the_key_and_skips_comments() {
        let toolchain = "# Floating `channel = \"stable\"` only holds if current.\n[toolchain]\nchannel = \"1.97.0\"\ncomponents = [\"rustfmt\"]\n";
        assert_eq!(
            toml_string_value(toolchain, "channel").as_deref(),
            Some("1.97.0"),
            "the assignment wins over the same text inside a `#` comment"
        );
        let cargo = "[workspace.package]\nedition = \"2021\"\nrust-version = \"1.97\"\n";
        assert_eq!(
            toml_string_value(cargo, "rust-version").as_deref(),
            Some("1.97")
        );
        assert_eq!(toml_string_value(cargo, "channel"), None, "absent key");
    }

    #[test]
    fn major_minor_parses_versions_and_rejects_named_channels() {
        assert_eq!(major_minor("1.97.0"), Some((1, 97)), "patch is ignored");
        assert_eq!(major_minor("1.97"), Some((1, 97)));
        assert_eq!(
            major_minor("stable"),
            None,
            "a named channel has no version"
        );
        assert_eq!(major_minor("nightly-2026-01-01"), None);
    }

    /// The delegation gate is a word match: `cpuset` in the root's subtree_control must never
    /// satisfy `cpu`, or a host with cpuset-only delegation sails past the preflight and the
    /// cgroup suites skip into a hollow green.
    #[test]
    fn the_delegation_check_matches_controller_words_not_substrings() {
        assert_eq!(
            super::missing_cgroup_controllers("cpuset cpu io memory hugetlb pids"),
            None,
            "a typical delegated root passes"
        );
        assert_eq!(
            super::missing_cgroup_controllers("cpuset io memory"),
            Some("cpu".to_string()),
            "cpuset must not pass for cpu"
        );
        assert_eq!(
            super::missing_cgroup_controllers(""),
            Some("cpu and memory".to_string()),
            "an empty delegation names both"
        );
    }

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

    /// The repo-layout table is restated in three places for three audiences: `AGENTS.md` for an
    /// agent, `README.md` for someone who never clones, and `docs/architecture.md` for the book.
    /// Three hand-maintained copies of one list drift, and this one did: `README.md` silently
    /// omitted `bsx-test-support` while the other two carried all ten.
    ///
    /// Asserts each table names every workspace package, and that the directory it pairs with is
    /// the real one, so a rename cannot leave a table half-updated. The tables may say anything
    /// else they like; only the name/directory pairing is pinned here.
    #[test]
    fn every_layout_table_lists_every_package() {
        let root = workspace_root();
        let real: BTreeMap<String, String> = workspace_packages(root);
        assert!(
            real.len() >= 10,
            "expected the full workspace, got {real:?}"
        );

        for page in ["AGENTS.md", "README.md", "docs/architecture.md"] {
            let text = std::fs::read_to_string(root.join(page)).unwrap();
            let mut seen = BTreeSet::new();
            for line in text.lines().filter(|l| l.starts_with('|')) {
                let cells: Vec<_> = line
                    .split('|')
                    .map(|c| c.trim().trim_matches('`').to_string())
                    .collect();
                for name in cells.iter().filter(|c| real.contains_key(*c)) {
                    seen.insert(name.clone());
                    // The row must also carry that package's real directory, in either column
                    // order (the three tables do not agree on which comes first).
                    let dir = &real[name];
                    let paired = cells.iter().any(|c| {
                        c == dir
                            || c.rsplit('/')
                                .next()
                                .is_some_and(|tail| tail == dir && c.starts_with("crates/"))
                    });
                    assert!(
                        paired,
                        "{page}: the row for `{name}` does not name its directory `{dir}`"
                    );
                }
            }
            let missing: Vec<_> = real.keys().filter(|k| !seen.contains(*k)).collect();
            assert!(
                missing.is_empty(),
                "{page}'s layout table omits {missing:?}"
            );
        }
    }

    /// The pinned API surface is stated in three places for three audiences, and **`RELEASES.md`
    /// asserts the three are the same list**. That claim drifted the moment it was written down:
    /// `bsx-record` joined the surface in `AGENTS.md` and `docs/embedding-scope.md` and was left
    /// out of `RELEASES.md`, which is the copy a tag freezes.
    ///
    /// Asserts every crate in [`PINNED_SURFACE_CRATES`] is named in all three. The prose around the
    /// names is free to differ (each audience needs a different sentence); only the membership is
    /// pinned, which is the part the three documents claim to agree on.
    #[test]
    fn pinned_surface_is_named_the_same_in_every_doc() {
        let root = workspace_root();
        for page in ["AGENTS.md", "RELEASES.md", "docs/embedding-scope.md"] {
            let text = std::fs::read_to_string(root.join(page)).unwrap();
            let missing: Vec<_> = PINNED_SURFACE_CRATES
                .iter()
                .filter(|krate| !text.contains(**krate))
                .collect();
            assert!(
                missing.is_empty(),
                "{page} does not name {missing:?} in the pinned API surface, but the three \
                 documents claim to name the same one"
            );
        }
    }

    /// `bsx-record` exists so a consumer can parse and verify a signed record **off-host**: an
    /// auditor's machine, a CI job, no eBPF, no root. That is only true while its dependency
    /// closure stays free of `aya` (the eBPF loader) and `nix` (the loader's netns join), so this
    /// walks the closure out of `Cargo.lock` and holds the line. The crate docs' "no aya, no nix"
    /// claim points here.
    #[test]
    fn record_crate_is_aya_free() {
        let lock =
            std::fs::read_to_string(workspace_root().join("Cargo.lock")).expect("Cargo.lock");
        // name -> direct dependency names, from the lockfile's [[package]] blocks. A dependency
        // entry may carry a version ("foo 1.2.3"); the name is the first token. A lockfile can
        // hold two versions of one name; their lists are merged, so the walk over-approximates,
        // the safe direction for a denylist.
        let mut packages = BTreeSet::new();
        let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut name: Option<String> = None;
        let mut in_deps = false;
        // A dependencies array whose package name hasn't been seen would mean entries silently
        // dropped, an under-approximated closure, and a false pass; panic instead of skipping.
        let owner = |name: &Option<String>| -> String {
            name.clone()
                .expect("Cargo.lock has a dependencies array before its package's name")
        };
        for line in lock.lines() {
            let line = line.trim();
            if line == "[[package]]" {
                name = None;
                in_deps = false;
            } else if let Some(n) = line.strip_prefix("name = ") {
                let n = n.trim_matches('"').to_string();
                packages.insert(n.clone());
                name = Some(n);
            } else if line.starts_with("dependencies = [") {
                in_deps = !line.ends_with(']');
                if !in_deps {
                    // single-line form: dependencies = ["a", "b"]
                    let inner = line
                        .trim_start_matches("dependencies = [")
                        .trim_end_matches(']');
                    let list = inner
                        .split(',')
                        .filter_map(|d| d.trim().trim_matches('"').split(' ').next())
                        .filter(|d| !d.is_empty())
                        .map(str::to_string);
                    deps.entry(owner(&name)).or_default().extend(list);
                }
            } else if in_deps {
                if line == "]" {
                    in_deps = false;
                } else {
                    let dep = line.trim_matches(',').trim_matches('"');
                    if let Some(first) = dep.split(' ').next().filter(|d| !d.is_empty()) {
                        deps.entry(owner(&name))
                            .or_default()
                            .push(first.to_string());
                    }
                }
            }
        }
        assert!(
            packages.contains("bsx-record"),
            "Cargo.lock has no bsx-record package (stale lockfile?)"
        );

        let mut queue = vec!["bsx-record".to_string()];
        let mut closure = BTreeSet::new();
        while let Some(pkg) = queue.pop() {
            if closure.insert(pkg.clone()) {
                queue.extend(deps.get(&pkg).cloned().unwrap_or_default());
            }
        }
        for forbidden in ["aya", "nix"] {
            assert!(
                !closure.contains(forbidden),
                "bsx-record's dependency closure contains `{forbidden}`; the crate exists so \
                 record verification runs off-host without linking an eBPF loader"
            );
        }
    }

    /// Package name -> directory name, read from the manifests rather than from `cargo metadata`.
    /// Two reasons: `metadata`'s JSON repeats `"name"` for every *target* as well as every package,
    /// which is what made the first cut of this test report `exec` and `tracer` as missing packages;
    /// and `crates/probes` is excluded from the workspace, so `metadata` never sees it while the
    /// layout tables rightly list it.
    fn workspace_packages(root: &Path) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
            .expect("crates/")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        dirs.push(root.join("xtask"));
        for dir in dirs {
            let manifest = dir.join("Cargo.toml");
            let Ok(text) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            // The `[package]` table comes first, so its `name` is the one this returns; a later
            // `[[bin]] name` cannot shadow it.
            let Some(name) = toml_string_value(&text, "name") else {
                continue;
            };
            if let Some(d) = dir.file_name() {
                map.insert(name, d.to_string_lossy().into_owned());
            }
        }
        map
    }

    /// Every workspace crate forbids `unsafe` except `crates/probes`, which builds for the BPF
    /// target where reading a map value means dereferencing a raw pointer the verifier has already
    /// bounded. Two doc pages state that rule; this is what makes it a checked claim rather than a
    /// list, after both pages spent an unknown stretch naming five of the six crates that carried
    /// the attribute and asserting a universal ("every shipped host crate") that three crates did
    /// not satisfy.
    ///
    /// Derived from the tree, so a new crate fails here until someone decides which side it is on.
    #[test]
    fn every_crate_forbids_unsafe_except_the_bpf_one() {
        let root = workspace_root();
        let mut forbids = Vec::new();
        let mut allows = Vec::new();
        for entry in std::fs::read_dir(root.join("crates")).unwrap() {
            let dir = entry.unwrap().path();
            if !dir.is_dir() {
                continue;
            }
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            // A crate declares the attribute in whichever roots it has; `forbid` is per-crate, so
            // a package with both a lib and a bin has to carry it in both to be covered.
            let roots: Vec<_> = ["src/lib.rs", "src/main.rs"]
                .iter()
                .map(|r| dir.join(r))
                .filter(|p| p.is_file())
                .collect();
            assert!(!roots.is_empty(), "crates/{name} has no lib.rs or main.rs");
            let all = roots.iter().all(|p| {
                std::fs::read_to_string(p)
                    .unwrap()
                    .lines()
                    .any(|l| l.trim() == "#![forbid(unsafe_code)]")
            });
            if all {
                forbids.push(name)
            } else {
                allows.push(name)
            }
        }
        forbids.sort();
        allows.sort();
        assert_eq!(
            allows,
            vec!["probes".to_string()],
            "exactly one crate may go without `#![forbid(unsafe_code)]`, and it is the BPF one. \
             Forbidding: {forbids:?}"
        );
    }

    /// The three copies of [`FUZZ_TARGETS`] that no constant can reach: a cargo manifest and a
    /// workflow file cannot read a Rust `const`, and a target's source file is named by the
    /// filesystem. Each drifts in its own direction and each failure is silent. A target in the
    /// constant but not the workflow never runs its nightly 15 minutes, so a boundary reads as
    /// fuzzed while nothing fuzzes it; one in the workflow but not `fuzz/Cargo.toml` fails the
    /// nightly run on a target cargo-fuzz cannot build.
    ///
    /// Compared as sorted sets, since [`FUZZ_TARGETS`] is ordered by value and the others are not.
    #[test]
    fn fuzz_targets_are_single_sourced() {
        let root = workspace_root();
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let expected = sorted(FUZZ_TARGETS.iter().map(|t| (*t).to_string()).collect());

        // `fuzz/Cargo.toml`: the `name` of each `[[bin]]`, skipping the package's own `[package]`
        // name. Section-tracked rather than grepped for `name = `, which would take both.
        let manifest = std::fs::read_to_string(root.join("fuzz/Cargo.toml")).unwrap();
        let mut in_bin = false;
        let mut bins = Vec::new();
        for line in manifest.lines().map(str::trim) {
            if line.starts_with('[') {
                in_bin = line == "[[bin]]";
            } else if in_bin
                && let Some(name) = line
                    .strip_prefix("name = \"")
                    .and_then(|n| n.strip_suffix('"'))
            {
                bins.push(name.to_string());
            }
        }
        assert_eq!(
            sorted(bins),
            expected,
            "fuzz/Cargo.toml's [[bin]] targets drifted from FUZZ_TARGETS"
        );

        // The sources on disk.
        let mut files = Vec::new();
        for entry in std::fs::read_dir(root.join("fuzz/fuzz_targets")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "rs")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                files.push(stem.to_string());
            }
        }
        assert_eq!(
            sorted(files),
            expected,
            "fuzz/fuzz_targets/*.rs drifted from FUZZ_TARGETS"
        );

        // The nightly matrix: a single-line YAML flow sequence, `target: [a, b, c]`.
        let workflow = std::fs::read_to_string(root.join(".github/workflows/fuzz.yml")).unwrap();
        let matrix = workflow
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("target: [")?.strip_suffix(']'))
            .expect("fuzz.yml declares the matrix as a one-line `target: [...]` flow sequence");
        assert_eq!(
            sorted(matrix.split(',').map(|t| t.trim().to_string()).collect()),
            expected,
            ".github/workflows/fuzz.yml's matrix drifted from FUZZ_TARGETS"
        );
    }

    /// No flag may carry a path that only exists on the machine that built the artifact.
    ///
    /// This is the whole point of the remap, and it is the part a plausible-looking edit breaks
    /// silently: the build still succeeds, the binary still runs, and the divergence only shows up
    /// as two hosts disagreeing on an image hash weeks later.
    #[test]
    fn remap_flags_leave_no_host_path_in_the_build() {
        let flags = remap_flags(
            Path::new("/home/alice/.cargo"),
            Path::new("/home/alice/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu"),
            Some("2d8144b7880597b6e6d3dfd63a9a9efae3f533d3"),
        );
        for flag in &flags {
            let target = flag.rsplit_once('=').expect("a remap flag is from=to").1;
            assert!(
                !target.contains("alice"),
                "{flag} maps onto a path carrying the build host's identity"
            );
        }
    }

    /// The std remap has to land on exactly the token rustc uses when `rust-src` is absent, or it
    /// buys nothing: the two hosts still disagree, just in a new spelling.
    #[test]
    fn the_std_remap_reconstructs_the_upstream_rustc_token() {
        let hash = "2d8144b7880597b6e6d3dfd63a9a9efae3f533d3";
        let flags = remap_flags(
            Path::new("/home/alice/.cargo"),
            Path::new("/home/alice/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu"),
            Some(hash),
        );
        assert!(
            flags.iter().any(|f| f
                == &format!(
                    "--remap-path-prefix=/home/alice/.rustup/toolchains/\
                     1.97.0-x86_64-unknown-linux-gnu/lib/rustlib/src/rust=/rustc/{hash}"
                )),
            "std sources are not mapped onto /rustc/<commit>: {flags:?}"
        );
    }

    /// A rustc without a commit hash drops that flag rather than inventing a token: agreeing with
    /// upstream is the goal, and no token at all is closer to it than a made-up one.
    #[test]
    fn a_hashless_rustc_drops_the_std_remap_rather_than_guessing() {
        let flags = remap_flags(
            Path::new("/home/alice/.cargo"),
            Path::new("/opt/rust"),
            None,
        );
        assert_eq!(
            flags,
            vec!["--remap-path-prefix=/home/alice/.cargo=/cargo".to_string()]
        );
    }
}
