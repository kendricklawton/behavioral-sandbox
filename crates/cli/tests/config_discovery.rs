//! The harness property every other e2e file depends on: a spawned `bsx` must read the config this
//! test wrote and nothing else.
//!
//! - **Two coordinates, not one.** `$HOME` selects the user file; the *working directory* selects
//!   the project file, by walking up. Pinning one and inheriting the other leaves discovery reading
//!   whatever is above the checkout.
//! - **Unprivileged on purpose.** `bsx run` refuses a bad config before it opens `/dev/kvm`, so the
//!   refusal these tests are about is reachable on any host.
// A test binary: `panic!` on spawn failure is the idiomatic assertion, which the workspace's
// `clippy::panic` deny does not auto-exempt outside a `#[test]` fn.
#![allow(clippy::panic)]

use std::path::Path;
use std::process::Command;

use bsx_test_support::{ScratchDir, seal_config_discovery};

/// `bsx run … -- true` from `cwd`, with `$HOME` at `home` and nothing else touched. Returns stderr,
/// which is where a config refusal lands.
fn run_from(cwd: &Path, home: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_bsx"))
        .args(["run", "--unjailed", "--", "true"])
        .current_dir(cwd)
        .env("HOME", home)
        .env("BSX_LOG", "warn")
        .output()
        .unwrap_or_else(|e| panic!("spawn bsx: {e}"));
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The failure this seal exists for, reproduced against the real binary: an ancestor of the working
/// directory holds a `.bsx.toml` naming user-only keys, `$HOME` points elsewhere, and the run dies
/// in preflight. On a configured host that ancestor is the operator's own home, holding the file
/// `install.sh` writes.
#[test]
fn an_unsealed_spawn_reads_a_config_from_above_the_working_directory() {
    let tree = ScratchDir::created("cfg-unsealed");
    std::fs::write(
        tree.path().join(".bsx.toml"),
        "kernel = \"/not/a/kernel\"\n",
    )
    .expect("plant the ancestor config");
    let work = tree.path().join("checkout/crates/cli");
    std::fs::create_dir_all(&work).expect("mkdirs");
    let empty_home = ScratchDir::created("cfg-unsealed-home");

    let stderr = run_from(&work, empty_home.path());
    assert!(
        stderr.contains("not from a file found above the working directory"),
        "the ancestor's user-only key must reach the run and refuse it: {stderr}"
    );
    assert!(
        stderr.contains(&tree.path().join(".bsx.toml").display().to_string()),
        "and the refusal names the planted file: {stderr}"
    );
}

/// The seal against the shape the harnesses actually present: a caller that has already chosen a
/// working directory it does not control, with a poisoned config above it. This is `trace_e2e`'s
/// `current_dir(&root)`, where `root` is a checkout that may sit under the operator's home.
///
/// The seal has to override that choice, not merely add to it. Sealing that only pinned `$HOME`
/// would leave the walk climbing out of the caller's directory, which is the bug.
#[test]
fn a_sealed_spawn_overrides_a_working_directory_it_does_not_control() {
    let tree = ScratchDir::created("cfg-sealed");
    std::fs::write(
        tree.path().join(".bsx.toml"),
        "kernel = \"/not/a/kernel\"\n",
    )
    .expect("plant the ancestor config");
    // The caller's own choice: inside the poisoned tree, with no sentinel of its own.
    let caller_cwd = tree.path().join("checkout/crates/cli");
    std::fs::create_dir_all(&caller_cwd).expect("mkdirs");
    let sealed = ScratchDir::created("cfg-sealed-home");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bsx"));
    cmd.args(["run", "--unjailed", "--", "true"])
        .env("BSX_LOG", "warn")
        .current_dir(&caller_cwd);
    seal_config_discovery(&mut cmd, sealed.path());
    let out = cmd.output().unwrap_or_else(|e| panic!("spawn bsx: {e}"));
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("not from a file found above the working directory"),
        "the planted ancestor must never be reached: {stderr}"
    );
    assert!(
        !stderr.contains(&tree.path().join(".bsx.toml").display().to_string()),
        "and it must not be named at all: {stderr}"
    );
    // Positive control: the run must actually get *past* config to something else, or this test
    // would pass on a binary that failed before discovery ever ran.
    assert!(
        stderr.contains("missing artifact"),
        "the run should reach the artifact check, past config: {stderr}"
    );
}

/// The sentinel is what stops the walk, so it has to actually be written where the seal claims.
#[test]
fn sealing_writes_the_sentinel_and_pins_both_coordinates() {
    let dir = ScratchDir::created("cfg-sentinel");
    let mut cmd = Command::new("true");
    seal_config_discovery(&mut cmd, dir.path());
    assert!(
        dir.path().join(".bsx.toml").is_file(),
        "an empty .bsx.toml must exist for the walk to stop on"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".bsx.toml")).expect("read"),
        "",
        "the sentinel sets nothing; it only ends the search"
    );
}
