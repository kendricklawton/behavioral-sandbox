//! `bsx export`: a record store to a tar file, with no guest booted. The suite plants a record
//! with `bsx-record` and runs the built binary against a scratch `$BSX_RUNS_DIR`.

// A test binary: `expect` is the idiomatic assertion in helpers outside `#[test]`.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

use bsx_test_support::ScratchDir;

fn bsx(runs: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bsx"));
    cmd.env("BSX_RUNS_DIR", runs);
    cmd
}

/// A run to export: a record with one captured output file.
fn planted(runs: &Path) -> bsx_record::Record {
    let store = bsx_record::Store::at(runs.to_path_buf()).expect("a store");
    let mut record = bsx_record::Record::begin(
        "exportee",
        bsx_record::Verb::Run,
        vec!["true".into()],
        bsx_record::Posture::new("/img".into(), 1, 512),
    );
    record.id = "1756860007123-exportee".to_string();
    let run = store.create(&record).expect("created");
    std::fs::write(run.stdout(), b"captured\n").expect("stdout");
    record
}

/// The verb writes the archive where asked (by id or name, `--to` or the cwd), prints only the
/// path, a stock `tar` lists the entries, and an unknown key leaves stdout empty.
#[test]
fn export_writes_a_tar_where_asked_and_prints_only_the_path() {
    let scratch = ScratchDir::created("cli-export");
    let runs = scratch.path().join("runs");
    let record = planted(&runs);
    let dest = scratch.path().join("dest");
    std::fs::create_dir(&dest).expect("a dest dir");

    let out = bsx(&runs)
        .args(["export", &record.id, "--to"])
        .arg(&dest)
        .output()
        .expect("bsx ran");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let expected = dest.join(format!("bsx-{}.tar", record.id));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("{}\n", expected.display()),
        "stdout is the written path and nothing else"
    );
    assert!(expected.is_file());

    let listing = Command::new("tar")
        .arg("-tf")
        .arg(&expected)
        .output()
        .expect("the system tar ran");
    assert!(
        listing.status.success(),
        "{}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let names = String::from_utf8_lossy(&listing.stdout);
    assert!(names.contains("1756860007123-exportee/record"), "{names}");
    assert!(names.contains("1756860007123-exportee/stdout"), "{names}");

    let cwd = scratch.path().join("cwd");
    std::fs::create_dir(&cwd).expect("a cwd");
    let out = bsx(&runs)
        .args(["export", "exportee"])
        .current_dir(&cwd)
        .output()
        .expect("bsx ran");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        cwd.join(format!("bsx-{}.tar", record.id)).is_file(),
        "by name, into the current directory"
    );

    let out = bsx(&runs).args(["export", "nobody"]).output().expect("ran");
    assert_eq!(out.status.code(), Some(2), "an operational refusal");
    assert!(out.stdout.is_empty(), "stdout stays pipe-clean");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no run named or numbered"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
