//! `cargo xtask <cmd>`, dev orchestration for the agent sandbox engine.
//!
//! The command list lives on the `Cmd` enum below and renders as `cargo xtask --help`, so this header
//! keeps no second copy of it. Each module carries its own `//!` header; the gates and the shared
//! plumbing (paths, `cargo` and tool runners) live here.
//!
#![forbid(unsafe_code)]

mod artifacts;
mod drift;
mod guest_bins;
mod lints;
mod rootfs;
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
    /// Check the host can do KVM; report what's missing.
    Setup,
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
    /// Check the pinned API surface against a baseline git rev with `cargo-semver-checks`, naming
    /// each crate explicitly (the default set silently drops every `publish = false` package, which
    /// is all of them). Refuses rather than reporting a pass it did not earn. Needs
    /// `cargo-semver-checks`; not part of `ci` (it builds rustdoc for two trees).
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
        /// Build a second time and assert the image is byte-identical, and fail if the resolved
        /// package closure has drifted from the committed lockfile. The reproducibility gate.
        #[arg(long)]
        verify: bool,
        /// Re-record the resolved package closure into the committed lockfile, the "re-pin" step
        /// after Alpine's branch repo bumps a package out from under the floating install.
        #[arg(long)]
        update_lock: bool,
    },
    /// Fuzz the untrusted-input decoders (the host↔guest channel, the
    /// config parser) with `cargo fuzz` (libFuzzer), the deep,
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
        Cmd::Setup => setup(),
        Cmd::Vendor { dir, verify } => {
            if verify {
                vendor::verify(&dir.unwrap_or_else(vendor::default_vendor_dir))
            } else {
                vendor::vendor(dir)
            }
        }
        Cmd::SemverCheck { baseline } => semver_check(baseline.as_deref()),
        Cmd::BuildRootfs {
            verify,
            update_lock,
        } => rootfs::build_rootfs(verify, update_lock),
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
    "channel_response",
    "channel_request",
    "channel_frame",
    "channel_handshake",
];

/// cargo-fuzz drives libFuzzer under a nightly toolchain, both opt-in installs, so bail with guidance
/// rather than pretending. Fuzzing is never wired into `ci` (the in-gate coverage is the crates' own
/// dependency-light mutation tests).
/// The pinned nightly `cargo fuzz` runs under. Single-sourced here: a bare `+nightly` would take
/// whatever the last `rustup update` fetched, so a crash found here could be unreproducible on the
/// next machine.
const FUZZ_NIGHTLY: &str = "nightly-2026-07-20";

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
pub(crate) fn effective_uid() -> Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|f| f.parse().ok())
        .context("read the effective uid from /proc/self/status")
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
/// The detached workspaces are linted under the toolchain each one pins
/// in the release tarball, yet a root-workspace `clippy` walks neither detached workspace.
///
/// Each command runs with the cwd **inside** its workspace, so rustup honours that directory's own
/// `rust-toolchain.toml`. Clippy on a detached workspace skips cleanly when its toolchain is
/// absent, since the everyday gate has to run everywhere.
fn lint_detached_workspaces(root: &Path) -> Result<()> {
    let denies = workspace_clippy_denies(root)?;
    for manifest in detached_manifests(root)? {
        let dir = manifest.parent().unwrap_or(root).to_path_buf();
        let shown = dir.strip_prefix(root).unwrap_or(&dir).display().to_string();
        // `fuzz` builds on whatever toolchain the caller has.
        let toolchain: Option<&str> = None;
        run_in(&dir, toolchain, &["fmt", "--check"], &shown)?;
        // No `--all-targets`: it adds a test harness, and a detached crate may be `no_std` for a target
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
/// overrides the file. A command that passes by hand and fails from the gate is the signature of
/// an inherited variable rather than a broken command.
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
/// `fuzz` carries its own `[workspace]` and lockfile and is excluded from the root
/// one, so `cargo deny check` walks it separately. It matters, being the one
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
/// rather than a report. The detached workspace's build passes `--locked`, so only
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

/// Print a checklist of the host prerequisites; read-only, never fails the build.
fn setup() -> Result<()> {
    println!("bsx: host capability check\n");

    // Asked of the host, not of a distro list: the device either opens read-write or it does not.
    // This is the whole runtime check today. The engine's checklist went with the engine, and its
    // libkrun successor arrives with the supervisor (`scratch/ROADMAP.md` phase 2), so this refuses
    // to print rows it cannot stand behind.
    check(
        "/dev/kvm readable and writable (hardware virtualization)",
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok(),
    );

    // Dev-toolchain checks, only `xtask` needs these (building the guest agent, verifying static
    // links). Verified, not just announced: a row that printed the pin while any version satisfied
    // it would be the same hollow green this command exists to refuse.
    println!("\ndev toolchain (for building, not running):");
    check(
        &format!("pinned nightly {FUZZ_NIGHTLY} (`cargo xtask fuzz`)"),
        nightly_ready(),
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

    println!("\nMissing items are covered in docs/cli-install.md -> Prerequisites.");
    Ok(())
}

/// The crates whose public API a `v0.1.0` tag would freeze: the surface `AGENTS.md`'s `api`-scope
/// rule names. One today, since the engine that carried the other was deleted; the supervisor that
/// replaces it joins this list when it exists.
const PINNED_SURFACE_CRATES: [&str; 1] = ["bsx-channel"];

/// `cargo xtask semver-check`: the pinned surface against a baseline rev.
///
/// **Every crate is named with its own `-p`**, because `cargo-semver-checks` drops
/// `publish = false` packages from its default set without saying so, and every crate here is
/// `publish = false` by decision. Run bare against this workspace it
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
    // The *pinned* toolchain, not the `nightly` alias: with an exact date pinned, having some
    // nightly installed says nothing about having this one, and reporting ready on the wrong
    // toolchain would turn a clean skip into a confusing build failure.
    let nightly = FUZZ_NIGHTLY;
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
    artifacts_dir().join("rootfs-guest")
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

/// Resolve a per-user dev-toolchain binary: `$PATH` first, then the cargo bin dirs. `cargo install`
/// places these build-only tools (`rustup`, `cargo-fuzz`) in `~/.cargo/bin`, which `sudo` drops from
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
/// the guest tree a different hash under the same pinned toolchain and package closure.
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
        // The field-index discipline (the setuid-shaped line a live read cannot produce) is
        // pinned where the parse lives, in the CLI's ids tests; here only the live read, so
        // format drift on this host surfaces as a loud error rather than a rootfs build that
        // silently decides it is already root.
        assert!(effective_uid().is_ok());
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

    /// Package name -> directory name, read from the manifests rather than from `cargo metadata`.
    /// Two reasons: `metadata`'s JSON repeats `"name"` for every *target* as well as every package,
    /// which is what made the first cut of this test report `exec` and `tracer` as missing packages;
    /// and `fuzz` is excluded from the workspace, so `metadata` never sees it while the
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

    /// Every workspace crate forbids `unsafe`. Two doc pages state that rule; this is what makes it
    /// a checked claim rather than a list.
    ///
    /// Derived from the tree, so a new crate fails here until someone decides which side it is on.
    /// The raw libkrun bindings will be the one exception when they land, because the library is C,
    /// and adding them means changing this assertion deliberately rather than by accident.
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
        assert!(
            allows.is_empty(),
            "every crate must carry `#![forbid(unsafe_code)]`; these do not: {allows:?}. \
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
