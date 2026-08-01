//! `cargo xtask coverage`: the workspace's own line coverage, the number neither gate produces.
//!
//! `fuzz-coverage` measures a libFuzzer target against its corpus, which says nothing about the
//! rest of the engine. This measures the **test suite** against the whole workspace, so "which code
//! do the ~100 privileged tests never reach" stops being an impression and becomes a list.
//!
//! **One instrumented run, not two.** The interesting number is the union of the host-safe gate and
//! the privileged one, and merging two profiles taken by two different uids into one target dir is
//! an ownership mess for no gain. So this runs the whole suite once, `--include-ignored`, as root.
//! The consequence is that unit tests written for an unprivileged process run privileged here; a
//! test whose meaning changes under `sudo` must say so with an explicit
//! `ekvm_test_support::have_real_root()` guard rather than quietly asserting something else.
//!
//! Never part of a gate: no threshold, no CI job. A coverage percentage that blocks a merge gets
//! gamed with tests written for the number; this exists to be read.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};

use crate::{dev_tool_path, toolchain_channel, workspace_root};

/// Where the rendered report lands, and nothing else. The instrumented build tree needs no dir of
/// its own: cargo-llvm-cov self-isolates it in `<CARGO_TARGET_DIR>/llvm-cov-target/`, so the
/// caller's target dir is never polluted with instrumented artifacts. Overriding the target dir
/// here anyway is the mistake this constant used to encode: the fixtures the preflight builds
/// (the static guest example) are resolved by the tests **through `CARGO_TARGET_DIR` at runtime**,
/// so a coverage-private target dir sent the tests looking where nothing was ever built.
const COVERAGE_DIR: &str = "target-coverage";

/// Paths held out of the measurement: neither ships. `xtask` is dev orchestration whose benches and
/// demos are driven by hand, and `ekvm-test-support` is the fixtures themselves. Counting them answers
/// "how much of this repo do the tests run", which is not the question; the question is how much of
/// the **engine** they reach, and 2.5k lines of never-covered-by-design tooling buries that.
///
/// Unanchored on purpose: llvm-cov matches this against the **absolute** path, so a `^` here would
/// silently match nothing and quietly put the tooling back in the number.
const NOT_SHIPPED: &str = "/(xtask|crates/test-support)/";

/// Measure the test suite's coverage of the workspace and render a report.
pub fn coverage(host_only: bool) -> Result<()> {
    let llvm_cov = require_cargo_llvm_cov()?;
    require_llvm_tools_stable()?;

    let root = workspace_root();
    let report_dir = root.join(COVERAGE_DIR);
    let html_dir = report_dir.join("html");

    if host_only {
        // The privileged tests are the ones that reach the boot, jailer, and probe paths, so a
        // host-only number understates the engine's real coverage by most of its interesting half.
        println!(
            "coverage: host-safe tests only (--host-only), the boot/jailer/probe paths are not \
             exercised — the number below is a floor, not the workspace's coverage"
        );
    } else {
        crate::privileged_preflight()?;
    }

    // Three invocations, one test run: `--no-report` banks the profile, then each `report` renders
    // it a different way. Rendering twice from one run is what keeps the summary and the HTML
    // describing the same execution.
    let mut run: Vec<&OsStr> = vec![
        OsStr::new("--no-report"),
        OsStr::new("--workspace"),
        OsStr::new("--locked"),
    ];
    if !host_only {
        // Serial for the same reason `ci-privileged` is: these boot real microVMs and assert on
        // host-global state (no leaked scratch dirs, taps, or VMM processes), so one test's live
        // scratch dir would trip another's leak check.
        run.extend([
            OsStr::new("--"),
            OsStr::new("--include-ignored"),
            OsStr::new("--test-threads=1"),
        ]);
    }
    llvm_cov_run(&llvm_cov, &run)?;

    llvm_cov_run(
        &llvm_cov,
        &[
            OsStr::new("report"),
            OsStr::new("--summary-only"),
            OsStr::new("--ignore-filename-regex"),
            OsStr::new(NOT_SHIPPED),
        ],
    )?;
    llvm_cov_run(
        &llvm_cov,
        &[
            OsStr::new("report"),
            OsStr::new("--html"),
            OsStr::new("--ignore-filename-regex"),
            OsStr::new(NOT_SHIPPED),
            // `--output-dir` is where llvm-cov *creates* its `html/` dir, not the dir itself.
            OsStr::new("--output-dir"),
            report_dir.as_os_str(),
        ],
    )?;

    let scope = if host_only {
        "host-safe tests only (partial)"
    } else {
        "host-safe + privileged tests"
    };
    println!("\n✓ coverage measured: {scope}, over the shipped crates (xtask/ and crates/test-support/ are excluded)");
    println!(
        "  the per-file uncovered regions are the point, not the percentage: {}",
        html_dir.join("index.html").display()
    );
    Ok(())
}

/// One `cargo-llvm-cov` invocation, echoed like the other runners. Called as
/// `cargo-llvm-cov llvm-cov <args>` (the cargo-subcommand argv shape) rather than
/// `cargo llvm-cov`: this command runs under `sudo`, where `~/.cargo/bin` is off root's `PATH` and
/// cargo would report the subcommand as missing even though it is installed.
fn llvm_cov_run(llvm_cov: &Path, args: &[&OsStr]) -> Result<()> {
    println!(
        "$ cargo llvm-cov {}",
        args.iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let status = std::process::Command::new(llvm_cov)
        .arg("llvm-cov")
        .args(args)
        .current_dir(workspace_root())
        // `CARGO_TARGET_DIR` is deliberately **inherited**, never overridden: cargo-llvm-cov
        // already isolates its instrumented build in `<CARGO_TARGET_DIR>/llvm-cov-target/`, and the
        // tests resolve preflight-built fixtures (the static guest example) through this variable
        // at runtime, so a coverage-private target dir sends them looking where nothing was built.
        // cargo-llvm-cov shells out to `cargo`, which `sudo` may also have dropped from `PATH`;
        // hand it the one that built this binary rather than hope for a lookup.
        .env("CARGO", env!("CARGO"))
        .status()
        .context("running cargo-llvm-cov")?;
    if !status.success() {
        bail!("cargo llvm-cov failed ({status})");
    }
    Ok(())
}

/// The `cargo-llvm-cov` binary, resolved the sudo-aware way ([`dev_tool_path`]) because this command
/// is normally run under `sudo` and `cargo install` puts it in the *invoking* user's `~/.cargo/bin`.
fn require_cargo_llvm_cov() -> Result<PathBuf> {
    dev_tool_path("cargo-llvm-cov").ok_or_else(|| {
        anyhow::anyhow!(
            "cargo-llvm-cov not installed — `cargo xtask coverage` needs it: \
             `cargo install cargo-llvm-cov --locked`. See docs/contributing-testing.md."
        )
    })
}

/// `llvm-tools-preview` on the **pinned stable** toolchain, which is what instruments and merges the
/// profile. The sibling of `require_llvm_tools` (that one guards `cargo fuzz coverage` on the pinned
/// *nightly*); both check up front and bail with the one-line fix rather than letting the run die
/// cryptically at the merge step.
///
/// Deliberately not added to `rust-toolchain.toml`'s `components`: that would push the download onto
/// every dev and every CI job for a command almost none of them run.
fn require_llvm_tools_stable() -> Result<()> {
    let toolchain = std::fs::read_to_string(workspace_root().join("rust-toolchain.toml"))
        .context("reading rust-toolchain.toml")?;
    let channel = toolchain_channel(&toolchain)
        .context("rust-toolchain.toml does not declare a [toolchain] channel")?;
    let installed = std::process::Command::new("rustup")
        .args(["component", "list", "--toolchain", channel, "--installed"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("llvm-tools"))
        .unwrap_or(false);
    if installed {
        return Ok(());
    }
    bail!(
        "llvm-tools not installed on {channel} — coverage instrumentation needs it: \
         `rustup component add llvm-tools-preview --toolchain {channel}`. See docs/contributing-testing.md."
    )
}
