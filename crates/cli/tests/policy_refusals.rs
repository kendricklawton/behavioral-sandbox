//! The pre-boot refusals (operator policy, config), host-safe: every check here fires **before any
//! boot**, so these tests spawn the real `bsx` binary with `BSX_FIRECRACKER` pointed at a path
//! that does not exist. A run the gate admits then fails on the missing VMM (a distinct message),
//! and a run it refuses never reaches it, which is what lets the assertions tell the two apart
//! without KVM, a rootfs, or root, on any host the host-safe gate runs on.
// A test binary: `panic!`/`expect` is the idiomatic assertion, which the workspace's
// `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use bsx_test_support::ScratchDir;

/// A scratch cwd holding the test's project `.bsx.toml`, plus an empty `$HOME` for the spawned
/// process, removed on drop. Its own `.bsx.toml` is the nearest one, and the pinned `HOME` has none,
/// so neither layer of discovery reaches a stray file (including the developer's real
/// `~/.bsx.toml`, which would otherwise supply artifact paths to every one of these runs).
struct PolicyDir(ScratchDir);

impl PolicyDir {
    fn with_toml(name: &str, toml: &str) -> Self {
        let dir = ScratchDir::created(&format!("policy-{name}"));
        std::fs::create_dir_all(dir.path().join("home"))
            .unwrap_or_else(|e| panic!("create home: {e}"));
        std::fs::write(dir.path().join(".bsx.toml"), toml)
            .unwrap_or_else(|e| panic!("write .bsx.toml: {e}"));
        Self(dir)
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    /// The empty `$HOME` handed to the spawned `bsx`.
    fn home(&self) -> PathBuf {
        self.path().join("home")
    }
}

/// Run `bsx run <args> -- true` in `dir`, returning `(exit_code, stderr)`. The VMM path is bogus
/// on purpose: reaching it at all means the policy gate admitted the run.
fn run_in(dir: &PolicyDir, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bsx"))
        .arg("run")
        .args(args)
        .arg("--unjailed") // never ask for root; the run must die before the VMM either way
        .arg("--")
        .arg("true")
        .current_dir(dir.path())
        .env("HOME", dir.home())
        .env("BSX_FIRECRACKER", "/nonexistent/firecracker-for-this-test")
        .env("BSX_SIGNING_KEY", dir.path().join("signing.key"))
        .output()
        .unwrap_or_else(|e| panic!("spawn bsx: {e}"));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn require_record_refuses_a_run_that_would_leave_no_audit_record() {
    // The posture's contract (docs/cli-config.md): "Refuses any run that would leave no audit
    // record." Three shapes, one gate:
    let dir = PolicyDir::with_toml("bare", "require_record = true\n");

    // A bare run leaves nothing: refused, by the policy, before any VMM is looked for.
    let (code, stderr) = run_in(&dir, &[]);
    assert_eq!(code, Some(2), "a policy refusal exits 2: {stderr}");
    assert!(
        stderr.contains("audit record") && stderr.contains("operator policy"),
        "the refusal names the posture, not a boot failure: {stderr}"
    );

    // A `--record-summary`-only run leaves a summary, which is an unsigned *projection* of the
    // record, not the record: still refused. Accepting it would let a require_record host serve
    // runs whose only trace is unverifiable.
    let (code, stderr) = run_in(&dir, &["--record-summary", "s.json"]);
    assert_eq!(code, Some(2), "summary-only must be a refusal: {stderr}");
    assert!(
        stderr.contains("audit record") && stderr.contains("operator policy"),
        "summary-only is refused by the policy, not admitted through to a boot: {stderr}"
    );

    // `--record` satisfies the gate: the run is admitted and dies later, on the deliberately
    // missing VMM, which is the proof the refusal above was the policy and not the environment.
    let (code, stderr) = run_in(&dir, &["--record", "r.json"]);
    assert_eq!(code, Some(2), "the admitted run still fails, on the VMM");
    assert!(
        !stderr.contains("operator policy"),
        "--record must pass the record gate; this failure should be the missing VMM: {stderr}"
    );
}

#[test]
fn an_invalid_log_filter_is_a_loud_refusal_not_a_silent_warn() {
    // The config posture is "a typo must not silently no-op" (`deny_unknown_fields` on the file's
    // *keys*); a filter *value* `tracing` cannot parse deserves the same loudness, in both entry
    // points, instead of a silent fall-back that runs with logging the operator did not choose.
    // (A bare unknown ident like `debgu` is not this case: EnvFilter grammar reads it as a target
    // name, so it parses; what is policed here is what the parser itself rejects.)
    let dir = PolicyDir::with_toml("badlog", "");

    // The CLI: refused before anything else happens.
    let out = Command::new(env!("CARGO_BIN_EXE_bsx"))
        .args(["--log", "bsx=notalevel", "run", "--unjailed", "--", "true"])
        .current_dir(dir.path())
        .env("BSX_FIRECRACKER", "/nonexistent/firecracker-for-this-test")
        .output()
        .unwrap_or_else(|e| panic!("spawn bsx run: {e}"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "a bad filter exits 2: {stderr}");
    assert!(
        stderr.contains("log filter") && stderr.contains("bsx=notalevel"),
        "the refusal names the filter it could not parse: {stderr}"
    );

    // The daemon: refuses to start, same loudness (it would otherwise serve with logging the
    // operator did not choose).
    let out = Command::new(env!("CARGO_BIN_EXE_bsx"))
        .args(["serve", "--log", "bsx=notalevel", "--socket"])
        .arg(dir.path().join("never-bound.sock"))
        .current_dir(dir.path())
        .output()
        .unwrap_or_else(|e| panic!("spawn bsx serve: {e}"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the daemon refuses to start: {stderr}"
    );
    assert!(
        stderr.contains("log filter") && stderr.contains("bsx=notalevel"),
        "the daemon's refusal names the filter too: {stderr}"
    );
    assert!(
        !dir.path().join("never-bound.sock").exists(),
        "a daemon refused at startup must not have bound its socket"
    );
}

#[test]
fn records_dir_satisfies_require_record_on_its_own() {
    // The book's sentence, pinned: "Satisfied on its own by records_dir." An operator who records
    // every run by default owes their callers no flag.
    //
    // `records_dir` names a directory this host writes into, so it is read from the user file. The
    // posture that needs it, `require_record`, can come from either.
    let dir = PolicyDir::with_toml("recdir", "require_record = true\n");
    std::fs::write(dir.home().join(".bsx.toml"), "records_dir = \"records\"\n")
        .expect("write the user file");
    let (code, stderr) = run_in(&dir, &[]);
    assert_eq!(code, Some(2), "admitted, then fails on the missing VMM");
    assert!(
        !stderr.contains("operator policy"),
        "records_dir alone must satisfy require_record: {stderr}"
    );
}

#[test]
fn a_project_file_naming_a_user_only_key_is_refused_before_any_boot() {
    // A `.bsx.toml` can arrive with the code it configures, so the keys that name a host binary are
    // not read from one found above the working directory.
    let dir = PolicyDir::with_toml("useronly", "firecracker = \"/tmp/planted-firecracker\"\n");
    let (code, stderr) = run_in(&dir, &[]);
    assert_eq!(code, Some(2), "refused, and before any boot");
    assert!(
        stderr.contains("`firecracker`") && stderr.contains(".bsx.toml"),
        "names the key and the file: {stderr}"
    );
    assert!(
        !stderr.contains("planted-firecracker"),
        "and never reaches the planted path: {stderr}"
    );
}
