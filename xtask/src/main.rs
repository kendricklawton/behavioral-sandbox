//! `cargo xtask <cmd>`, dev orchestration for the agent sandbox engine.
//!
//! The command list lives on the `Cmd` enum below and renders as `cargo xtask --help`, so this header
//! keeps no second copy of it. Each module carries its own `//!` header; the gates and the shared
//! plumbing (paths, `cargo` and tool runners) live here.
//!
#![forbid(unsafe_code)]

mod artifacts;
mod bench;
mod drift;
mod guest_bins;
mod lints;
mod rootfs;
mod sign;
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
    /// Check whether a hypervisor answers here and the dev toolchain is present; report what is
    /// missing. Asks this host's own question, so it names KVM on Linux and Hypervisor.framework
    /// on macOS rather than a device one of them has not got.
    Setup,
    /// Sign the built `bsx` for Hypervisor.framework so it can start a VM (macOS). A later cargo
    /// build or test replaces the binary and the signature with it, so this runs after a build
    /// rather than once. Elsewhere it says there is nothing to sign and exits.
    Sign {
        /// Sign the release build rather than the debug one.
        #[arg(long)]
        release: bool,
    },
    /// Snapshot every sha-pinned upstream input (the Alpine base, the static `apk`, the `.apk`
    /// closure) into a local mirror, so a fresh host builds offline without the Alpine CDN.
    /// Writes a sha manifest; re-verify it offline with `--verify`.
    Vendor {
        /// The mirror directory to populate or verify (default `vendor/` under the workspace root).
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        /// Re-verify an existing mirror against its manifest (every file must still match its hash)
        /// instead of (re)downloading, an offline integrity check, no upstream contact.
        #[arg(long)]
        verify: bool,
    },
    /// Check the pinned API surface against a baseline git rev, naming each crate explicitly
    /// since the default set silently drops every `publish = false` package. Needs
    /// `cargo-semver-checks`; not part of `ci`, building rustdoc for two trees.
    SemverCheck {
        /// The git rev to compare against (default: the latest `v*` tag).
        #[arg(long, value_name = "REV")]
        baseline: Option<String>,
    },
    /// Assemble the guest rootfs: a minimal Alpine base + the guest runtimes (python3) + the
    /// static agent, as a directory tree at `artifacts/rootfs-guest` (needs `curl` and `tar`), the
    /// shape libkrun's virtiofs root takes. Reproducible: two builds hash identically.
    #[command(visible_alias = "rootfs")]
    BuildRootfs {
        /// Build the desktop image instead, at `artifacts/rootfs-desktop`: the base plus a
        /// Wayland compositor (cage), a terminal (foot), seatd and udev, and the `bsx-session`
        /// program that starts them under `--display`.
        #[arg(long)]
        desktop: bool,
        /// Build a second time and assert the image is byte-identical, and fail if the resolved
        /// package closure has drifted from the committed lockfile. The reproducibility gate.
        #[arg(long)]
        verify: bool,
        /// Re-record the resolved package closure into the committed lockfile, the "re-pin" step
        /// after Alpine's branch repo bumps a package out from under the floating install.
        #[arg(long)]
        update_lock: bool,
        /// The guest image's architecture (`x86_64` or `aarch64`), defaulting to this host's.
        /// `apk` installs by unpacking and the install runs `--no-scripts`, so a Linux builder of
        /// either arch can produce an image for the other; `apk.static` itself still has to run
        /// here, so the builder's own arch must be one with a pinned tool.
        #[arg(long, value_name = "ARCH")]
        arch: Option<String>,
    },
    /// Measure cold-boot latency as nearest-rank percentiles: spawn → a running vCPU, and
    /// spawn → the exit of a guest running `/bin/true`. Needs `/dev/kvm`, the guest tree and a
    /// **release** `bsx`.
    BenchBoot {
        /// How many boots to time. Default 100, the floor at which a `p99` has any sample above
        /// it; below that it prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
    /// Measure the per-sandbox memory footprint of a cohort of idle VMs kept alive together:
    /// per-VMM Pss and Rss as percentiles, plus the whole-host `MemAvailable` drop per VM. Needs
    /// `/dev/kvm`, the guest tree and a **release** `bsx`.
    BenchFootprint {
        /// How many idle VMs to bring up (stops earlier at the memory floor). Default 8.
        #[arg(long, default_value_t = 8)]
        count: usize,
        /// Seconds to wait after the last vCPU before sampling, so the youngest guest has
        /// finished booting and is as idle as the oldest. Default 10.
        #[arg(long, default_value_t = 10)]
        settle_secs: u64,
    },
    /// Measure the guest-to-host frame path: frame arrival intervals as percentiles, with the
    /// guest's own view beside them. Headless, so it measures throughput into the host process,
    /// not presentation. Needs `/dev/kvm`, the guest tree and a **release** `bsx`.
    BenchFrames {
        /// The display the guest gets, `WIDTHxHEIGHT[@HZ]`; `@HZ` is what the guest paces its
        /// page flips to. Default 640x480.
        #[arg(long, default_value = "640x480")]
        display: String,
        /// Frames per run. Default 300.
        #[arg(long, default_value_t = 300)]
        frames: usize,
        /// Also run the frames through `bsx-app`, which opens a window on this desktop.
        #[arg(long)]
        app: bool,
    },
    /// Fuzz the untrusted-input decoders with `cargo fuzz`, the nightly-only counterpart to the
    /// in-gate mutation tests, seeded from `fuzz/seeds/<target>/`. Needs cargo-fuzz and a nightly
    /// toolchain; never part of `ci`. `--help` lists the targets from [`FUZZ_TARGETS`].
    Fuzz {
        /// The libFuzzer target to run.
        #[arg(default_value = "channel_response", value_parser = fuzz_target_parser())]
        target: String,
        /// Wall-clock seconds to fuzz before stopping (`0` runs until it finds a crash or you Ctrl-C).
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    /// Fuzz **every** target briefly, the per-PR smoke, so a broken decoder is caught before it
    /// lands. Fail-fast, the crashing input landing under `fuzz/artifacts/`. Same install needs as
    /// `fuzz`; never part of `ci`.
    FuzzSmoke {
        /// Wall-clock seconds per target.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::Setup => setup(),
        Cmd::Sign { release } => sign::sign_for_hypervisor(release),
        Cmd::Vendor { dir, verify } => {
            if verify {
                vendor::verify(&dir.unwrap_or_else(vendor::default_vendor_dir))
            } else {
                vendor::vendor(dir)
            }
        }
        Cmd::SemverCheck { baseline } => semver_check(baseline.as_deref()),
        Cmd::BuildRootfs {
            desktop,
            verify,
            update_lock,
            arch,
        } => {
            let arch = match arch.as_deref() {
                Some(name) => rootfs::GuestArch::parse(name)?,
                None => rootfs::GuestArch::host()?,
            };
            rootfs::build_rootfs(
                if desktop {
                    &rootfs::DESKTOP
                } else {
                    &rootfs::GUEST
                },
                verify,
                update_lock,
                arch,
            )
        }
        Cmd::BenchBoot { runs } => bench::bench_boot(runs),
        Cmd::BenchFootprint { count, settle_secs } => {
            bench::bench_footprint(count, std::time::Duration::from_secs(settle_secs))
        }
        Cmd::BenchFrames {
            display,
            frames,
            app,
        } => bench::bench_frames(&display, frames, app),
        Cmd::Fuzz { target, seconds } => fuzz(&target, seconds),
        Cmd::FuzzSmoke { seconds } => fuzz_smoke(seconds),
    }
}

/// Accepts only a real target, letting clap print the list in `--help`. Shared by the three fuzz
/// subcommands, so [`FUZZ_TARGETS`] is the only place a target is named and an unknown one fails
/// at the edge.
fn fuzz_target_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(FUZZ_TARGETS)
}

/// Every libFuzzer target in `fuzz/`, outermost untrusted boundary first, and the source the
/// smoke run and `--help` are generated from. Three copies cannot read a Rust constant, so
/// `fuzz_targets_are_single_sourced` holds them to this list.
const FUZZ_TARGETS: &[&str] = &[
    "channel_response",
    "channel_request",
    "channel_frame",
    "channel_handshake",
];

/// The pinned nightly `cargo fuzz` runs under: a bare `+nightly` would take whatever the last
/// `rustup update` fetched, so a crash found here could be unreproducible elsewhere.
const FUZZ_NIGHTLY: &str = "nightly-2026-07-20";

/// Bails with guidance when cargo-fuzz or its nightly is absent, both being opt-in installs.
/// Fuzzing is never wired into `ci`, whose coverage is the crates' own mutation tests.
fn require_cargo_fuzz() -> Result<()> {
    if cargo_fuzz_available() {
        return Ok(());
    }
    let nightly = FUZZ_NIGHTLY;
    bail!(
        "cargo-fuzz not found — install it with `cargo install cargo-fuzz --locked` and add the \
         pinned toolchain (`rustup toolchain install {nightly} --profile minimal`)."
    )
}

/// Builds the `+<pinned nightly> fuzz run <target> <corpus> <seeds>` argv. The writable corpus is
/// created, since naming it explicitly is what passing the seeds costs, and the committed seeds are
/// folded in so a run starts past the first-byte reject.
fn cargo_fuzz_run_argv(target: &str, root: &Path) -> Result<Vec<String>> {
    let corpus = root.join("fuzz/corpus").join(target);
    std::fs::create_dir_all(&corpus).context("create the fuzz corpus dir")?;
    // `+<pinned>`, not the `nightly` alias, which is whatever the last `rustup update` fetched.
    let toolchain = format!("+{FUZZ_NIGHTLY}");
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

/// Invokes `cargo <args>` from the repo root, where cargo-fuzz discovers the `fuzz/` crate. The
/// leading `+<pinned nightly>` forces that toolchain, since `-Zsanitizer=address` is nightly-only.
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

/// Warns about a `fuzz/corpus/<name>` directory no [`FUZZ_TARGETS`] entry names: a renamed target
/// starts from empty, so coverage goes quiet. A warning, not a gate assertion, `fuzz/corpus/`
/// being gitignored working data.
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

/// This process's effective uid. Through `rustix` rather than `/proc/self/status`, which only
/// Linux has; the call cannot fail, so the `Result` is the caller's shape, not a real error path.
pub(crate) fn effective_uid() -> Result<u32> {
    Ok(rustix::process::geteuid().as_raw())
}

/// Is `cargo fuzz` installed? (Probed once, cheaply, so a missing tool is a clear message.)
fn cargo_fuzz_available() -> bool {
    Command::new("cargo")
        .args(["fuzz", "--version"])
        .output()
        .is_ok_and(|o| o.status.success())
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
    // For `-D warnings` over rustdoc's lints, above all `broken_intra_doc_links`: an unresolved
    // `[`Type`]` is a dead pointer in prose. The rendered HTML is never published.
    cargo_env(
        &["doc", "--no-deps", "--workspace", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    cargo(&["deny", "check"])?;
    deny_detached_workspaces(workspace_root())?;
    lint_detached_workspaces(workspace_root())?;
    // Last, because a signature does not reliably outlive a later cargo command: `codesign` writes
    // a new inode, breaking the hardlink `target/debug/bsx` is uplifted from, and cargo sometimes
    // re-links the unsigned artifact over it. Signing earlier signs something a later step may
    // replace.
    sign::sign_for_hypervisor(false)?;
    announce_compiled_out();
    println!("\n✓ all checks passed");
    Ok(())
}

/// What a green run on this host did **not** cover, printed rather than inferred: cargo counts a
/// crate that compiles to nothing as passing, and that reads as coverage.
fn announce_compiled_out() {
    if !cfg!(target_os = "linux") {
        println!(
            "\nnot covered on this host: bsx-guest-agent and its four suites compile to nothing \
             off Linux, because the agent reaps through a pidfd and listens on AF_VSOCK. The \
             helper's own window is compiled out too: its event loop needs a thread other than \
             the main one, which X11 and Wayland allow and macOS does not. The benches read \
             `/proc` throughout, so the vCPU predicate's own test is compiled out with them \
             (roadmap 6.9)."
        );
    }
}

/// The manifests `cargo deny check` at the root cannot reach: every path in the root workspace's
/// `exclude`, read from the tree. `detached_workspaces_are_all_scanned` holds it there, so a third
/// one has to be decided about rather than defaulting into a gap.
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
/// Read from the root, since an `exclude`d workspace cannot inherit `[lints]` and would otherwise
/// carry a drifting copy.
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

/// `cargo fmt --check` and `cargo clippy -D warnings` for the detached workspaces, which a
/// root-workspace clippy does not walk. The cwd is **inside** each, so rustup honours its own
/// `rust-toolchain.toml`; a missing toolchain skips.
fn lint_detached_workspaces(root: &Path) -> Result<()> {
    let denies = workspace_clippy_denies(root)?;
    for manifest in detached_manifests(root)? {
        let dir = manifest.parent().unwrap_or(root).to_path_buf();
        let shown = dir.strip_prefix(root).unwrap_or(&dir).display().to_string();
        // `fuzz` builds on whatever toolchain the caller has.
        let toolchain: Option<&str> = None;
        run_in(&dir, toolchain, &["fmt", "--check"], &shown)?;
        // No `--all-targets`: the test harness it adds cannot build for a `no_std` target.
        let mut args = vec!["clippy", "--", "-Dwarnings"];
        args.extend(denies.iter().map(String::as_str));
        run_in(&dir, toolchain, &args, &shown)?;
    }
    Ok(())
}

/// One cargo invocation inside `dir`, under the toolchain that directory pins.
///
/// Named explicitly rather than found, because a parent `cargo xtask` leaks `RUSTUP_TOOLCHAIN`
/// into every child and that overrides the file.
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
/// Advisories only, the rest describing the shipped graph the root check owns. **No `--config`**,
/// whose place moved between releases, so a yanked crate warning here is the trade.
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

/// Asserts `fuzz/Cargo.lock` still resolves: that workspace is detached and takes the tree by path,
/// so a dependency edit ages it, and `cargo xtask fuzz` would repair it silently.
///
/// Resolution is the whole check; building the targets needs nightly and cargo-fuzz.
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

/// Asserts the pinned toolchain and the declared MSRV floor agree at `major.minor`: kept in step
/// by hand, so a one-sided bump builds the gate at a compiler the floor does not advertise. A
/// named channel carries no version, so the check is skipped there.
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

/// The first `key = "value"` assignment's value, quotes stripped. A hand parser, xtask carrying
/// no TOML dependency, and each key read is the only such assignment in its file.
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

/// Whether a hypervisor answers here, and the question that was put to it.
///
/// **The one place a platform branch is allowed to live** (`AGENTS.md`: host variance in the
/// preflight, never in the boot path), and even here what is asked is a capability: Linux opens the
/// device, macOS asks the kernel whether it supports virtualization at all. Neither reads a distro,
/// a release file, or a version.
fn hypervisor_answers() -> (bool, &'static str) {
    #[cfg(target_os = "linux")]
    {
        (
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .is_ok(),
            "/dev/kvm readable and writable (hardware virtualization)",
        )
    }
    #[cfg(target_os = "macos")]
    {
        // `kern.hv_support` is the kernel's own answer to "can this machine virtualise", which is
        // the same question `/dev/kvm` answers by opening. Reaching Hypervisor.framework directly
        // would need this binary to carry the entitlement, and `xtask` is never signed.
        let answers = Command::new("sysctl")
            .args(["-n", "kern.hv_support"])
            .output()
            .is_ok_and(|out| out.status.success() && out.stdout.starts_with(b"1"));
        (
            answers,
            "Hypervisor.framework answers (kern.hv_support: hardware virtualization)",
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        (false, "a hypervisor this project knows how to reach")
    }
}

/// Print a checklist of the host prerequisites; read-only, never fails the build.
fn setup() -> Result<()> {
    println!("bsx: host capability check\n");

    let (answers, asked) = hypervisor_answers();
    check(asked, answers);

    // Everything a macOS host needs beyond the hypervisor, because a green preflight there and a
    // sandbox that cannot boot is the failure this section exists to prevent.
    if cfg!(target_os = "macos") {
        check(
            "codesign (the hypervisor entitlement: `cargo xtask sign`)",
            dev_tool_path("codesign").is_some(),
        );
        check(
            &match bsx_krun::KRUNFW_DIR {
                Some(dir) => format!("libkrunfw found, at {dir} (libkrun's kernel payload)"),
                None => "libkrunfw (libkrun's kernel payload; set BSX_KRUNFW_LIB_DIR)".to_string(),
            },
            bsx_krun::KRUNFW_DIR.is_some(),
        );
    }

    // Verified, not announced: a row printing the pin while any version satisfied it is hollow.
    println!("\ndev toolchain (for building, not running):");
    check(
        &format!("pinned nightly {FUZZ_NIGHTLY} (`cargo xtask fuzz`)"),
        nightly_ready(),
    );
    let guest_arch = rootfs::GuestArch::host()?;
    check(
        &format!(
            "guest musl target ({}): the static guest agent build (`cargo xtask build-rootfs`)",
            guest_arch.musl_target()
        ),
        guest_bins::guest_target_installed(guest_arch),
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

    println!("\nMissing items are covered in AGENTS.md -> Building from source.");
    Ok(())
}

/// The crates whose public API a `v0.1.0` tag would freeze: the surface `AGENTS.md`'s `api`-scope
/// rule names. The wire framing, and the spawn/discovery API both shipped binaries drive their
/// VMs through.
const PINNED_SURFACE_CRATES: [&str; 2] = ["bsx-channel", "bsx-supervisor"];

/// `cargo xtask semver-check`: the pinned surface against a baseline rev.
///
/// **Every crate is named with its own `-p`**: `cargo-semver-checks` silently drops
/// `publish = false` packages, which all of these are, and exits `0` having checked nothing.
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

    // At `0.0.x` every bump is major by cargo's rules, so every lint is skipped and the run is
    // green whatever the diff did.
    let version = toml_string_value(
        &std::fs::read_to_string(root.join("Cargo.toml")).context("reading the root Cargo.toml")?,
        "version",
    )
    .unwrap_or_default();
    if version.starts_with("0.0.") {
        bail!(
            "the workspace is {version}: under cargo's semver rules every 0.0.x bump is already a \
             major change, so cargo-semver-checks skips every lint and reports a pass it did not \
             earn. This command becomes meaningful at 0.1.0."
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

/// Whether the pinned nightly toolchain is installed, via `rustup component list --installed`.
/// Informational, for `setup`.
fn nightly_ready() -> bool {
    // Resolve `rustup` the sudo-aware way too (it is also a per-user `~/.cargo/bin` tool), so a
    // `sudo cargo xtask setup` doesn't misreport the toolchain as absent, see `dev_tool_path`.
    let Some(rustup) = dev_tool_path("rustup") else {
        return false;
    };
    // The pinned toolchain, not the alias: having some nightly says nothing about having this one.
    let nightly = FUZZ_NIGHTLY;
    let mut cmd = Command::new(rustup);
    cmd.args(["component", "list", "--toolchain", nightly, "--installed"]);
    // Under a sudo that reset `$HOME`, rustup reads root's empty `~/.rustup`: point it at the
    // invoking user's, unless the environment already pinned one.
    if std::env::var_os("RUSTUP_HOME").is_none()
        && let Some(user) = std::env::var_os("SUDO_USER")
        && let Some(home) = user_home(&user)
    {
        cmd.env("RUSTUP_HOME", home.join(".rustup"));
    }
    cmd.output().is_ok_and(|o| {
        o.status.success()
            && String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.trim().starts_with("rust-src"))
    })
}

/// The workspace root (not the cwd), so the commands work from anywhere.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
}

/// Where cargo actually places a build: `CARGO_TARGET_DIR` when set, else `target/` under the
/// workspace root.
fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from)
}

/// `artifacts/` under the workspace root.
fn artifacts_dir() -> PathBuf {
    workspace_root().join("artifacts")
}

/// The local vendor mirror, if the operator set `BSX_VENDOR_DIR`: the offline source for every
/// sha-pinned upstream input (`cargo xtask vendor`), so a build never reaches the Alpine CDN.
/// `None` means fetch from pinned upstream (the default).
fn vendor_dir() -> Option<PathBuf> {
    std::env::var_os("BSX_VENDOR_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The guest rootfs (`build-rootfs` output) under [`artifacts_dir`], defined once so every reader
/// and writer resolves the same path. A **directory**, which is what libkrun's virtiofs root takes.
fn guest_rootfs_path() -> PathBuf {
    artifacts_dir().join(rootfs::GUEST.name)
}

/// Run an external build tool, echoing the command; fail with context if it's missing or errors.
fn run_tool(program: &str, args: &[&OsStr]) -> Result<()> {
    run_tool_env(program, args, &[])
}

/// [`run_tool`] with extra environment scoped to **this child only** (not `std::env::set_var`, which
/// is process-global and would leak into every later tool). Used to hand a build tool its
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

/// Resolves a per-user dev-toolchain binary: `$PATH`, then the cargo bin dirs, including the
/// invoking user's under sudo, which drops `~/.cargo/bin` from root's `PATH`.
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

/// Runs cargo with this host's identity remapped out of what it builds, for release binaries only:
/// `panic!` locations are baked in regardless of debug info. `CARGO_ENCODED_RUSTFLAGS` *replaces*
/// configured `rustflags`, which is why this stays off the gate.
fn cargo_reproducible(args: &[&str]) -> Result<()> {
    let flags = remap_flags(
        &cargo_home(),
        &rustc_sysroot()?,
        rustc_commit_hash().as_deref(),
    );
    cargo_env(args, &[("CARGO_ENCODED_RUSTFLAGS", &flags.join("\x1f"))])
}

/// The `--remap-path-prefix` flags [`cargo_reproducible`] passes, onto fixed tokens.
///
/// rustc rewrites std's paths back to the local checkout wherever `rust-src` is installed, so the
/// checkout maps onto `/rustc/<commit>`; without a commit hash the flag is dropped.
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
    // From the workspace root: cargo's own subcommands walk up, but a plugin resolves from the cwd.
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

    /// Every workspace the root `cargo deny check` cannot walk still gets an advisory scan.
    /// Derived from `exclude`, so a third detached workspace cannot go unscanned silently.
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
members = ["crates/example", "xtask"]
exclude = ["fuzz"]
"#;
        assert_eq!(excluded_dirs(manifest), vec!["fuzz"]);
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

    #[test]
    fn the_fakeroot_decision_reads_through_the_shared_parse() {
        // Only the live read here; the parse is pinned in the CLI's ids tests. Format drift
        // surfaces loudly rather than as a rootfs build deciding it is already root.
        assert!(effective_uid().is_ok());
    }

    /// The repo-layout table is restated in three places for three audiences, and three copies
    /// drift. Asserts each names every workspace package against its real directory; only the
    /// name/directory pairing is pinned.
    #[test]
    fn every_layout_table_lists_every_package() {
        let root = workspace_root();
        let real: BTreeMap<String, String> = workspace_packages(root);
        assert!(real.len() >= 5, "expected the full workspace, got {real:?}");

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

    /// `AGENTS.md` is now the only document naming the pinned surface, so this asserts that one
    /// membership rather than an agreement between two: the page that tells a contributor which
    /// change takes the `api` scope must name every crate on the list the scope refers to.
    #[test]
    fn the_manual_names_the_whole_pinned_surface() {
        let root = workspace_root();
        let text = std::fs::read_to_string(root.join("AGENTS.md")).expect("AGENTS.md");
        let missing: Vec<_> = PINNED_SURFACE_CRATES
            .iter()
            .filter(|krate| !text.contains(**krate))
            .collect();
        assert!(
            missing.is_empty(),
            "AGENTS.md does not name {missing:?}, but the `api` commit scope refers to them"
        );
    }

    /// Package name to directory name, from the manifests rather than `cargo metadata`, whose
    /// JSON repeats `"name"` per target and never sees the excluded `fuzz` workspace.
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

    /// The preflight asks a question *this* host can answer. What this replaced printed
    /// `/dev/kvm` on a machine that has no such device, which reads as a missing prerequisite
    /// rather than as a check that does not apply here.
    #[test]
    fn the_preflight_asks_a_question_this_host_can_answer() {
        let (_, asked) = super::hypervisor_answers();
        assert!(!asked.is_empty(), "a row with no question is not a check");
        #[cfg(target_os = "macos")]
        {
            assert!(
                !asked.contains("/dev/kvm"),
                "{asked:?} names a device this host has not got"
            );
            assert!(
                asked.contains("kern.hv_support"),
                "{asked:?} must name what was actually asked"
            );
        }
        #[cfg(target_os = "linux")]
        assert!(asked.contains("/dev/kvm"), "{asked:?}");
    }

    /// Every workspace crate forbids `unsafe` except the raw libkrun bindings, which two doc pages
    /// state and this checks. An **equality**, so a new crate must be decided about either way.
    #[test]
    fn every_crate_forbids_unsafe() {
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
            [UNSAFE_CRATE],
            "`{UNSAFE_CRATE}` is the one crate that may use `unsafe`, because libkrun is a C \
             library. Forbidding: {forbids:?}"
        );
    }

    /// The single directory under `crates/` exempt from `#![forbid(unsafe_code)]`.
    const UNSAFE_CRATE: &str = "krun";

    /// The three copies of [`FUZZ_TARGETS`] no constant can reach, each drifting silently: a
    /// target missing from the workflow never runs, so a boundary reads as fuzzed while nothing
    /// fuzzes it. Compared as sorted sets, since only the constant is ordered.
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

    /// No flag may carry a path that exists only on the machine that built the artifact: a broken
    /// remap still builds and still runs, and shows up as two hosts disagreeing weeks later.
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
