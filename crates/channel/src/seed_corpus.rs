//! The libFuzzer seed corpus under `fuzz/seeds/`, generated from this crate's own encoders.
//!
//! - **Generated, never hand-rolled.** Every seed is what `write_request`, `write_response`,
//!   `write_frame` or `write_handshake` emits, and
//!   `the_committed_seeds_are_what_the_encoders_produce` fails when the tree stops matching them.
//! - **Two shapes per message**, because every target calls two entry points: the whole frame for
//!   the raw decoder, and the `tag · body` twin (`.body`) for the `_wellformed` one, which supplies
//!   a header of its own.
//! - **A comparison, not a build step.** The test below rewrites the tree only under
//!   `BSX_UPDATE_FUZZ_SEEDS`; otherwise it compares, and an orphaned directory is an extra key.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use crate::{
    ChannelError, FRAME_HEADER, MAGIC, Request, Response, Tag, read_frame, read_handshake,
    read_request, read_response, reframe, write_frame, write_handshake, write_request,
    write_response,
};

/// Turns the comparison into a rewrite, for the commit that follows a wire change.
const UPDATE: &str = "BSX_UPDATE_FUZZ_SEEDS";

/// The bytes an encoder writes, for a fixture the encoder must accept.
fn encoded(write: impl FnOnce(&mut Vec<u8>) -> Result<(), ChannelError>) -> Vec<u8> {
    let mut buf = Vec::new();
    write(&mut buf).expect("an encoder accepts its own fixture");
    buf
}

/// One valid frame per `Request` the host sends, `Exec` twice for its optional timeout.
fn requests() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "put_file",
            encoded(|w| {
                write_request(
                    w,
                    &Request::PutFile {
                        path: "in.txt".into(),
                        data: b"hello".to_vec(),
                    },
                )
            }),
        ),
        (
            "exec",
            encoded(|w| {
                write_request(
                    w,
                    &Request::Exec {
                        argv: vec!["echo".into(), "hi".into()],
                        stdin: b"input".to_vec(),
                        env: vec![("PATH".into(), "/usr/bin".into())],
                        artifacts: vec!["out.txt".into()],
                        timeout_ms: NonZeroU32::new(1_000),
                    },
                )
            }),
        ),
        (
            "exec_untimed",
            encoded(|w| {
                write_request(
                    w,
                    &Request::Exec {
                        argv: vec!["sh".into()],
                        stdin: Vec::new(),
                        env: Vec::new(),
                        artifacts: Vec::new(),
                        timeout_ms: None,
                    },
                )
            }),
        ),
        (
            "exec_pty",
            encoded(|w| {
                write_request(
                    w,
                    &Request::ExecPty {
                        argv: vec!["/bin/sh".into()],
                        env: vec![("TERM".into(), "xterm-256color".into())],
                        cols: 120,
                        rows: 40,
                    },
                )
            }),
        ),
        (
            "stdin",
            encoded(|w| write_request(w, &Request::Stdin(b"ls -la\r".to_vec()))),
        ),
        (
            "resize",
            encoded(|w| write_request(w, &Request::Resize { cols: 80, rows: 24 })),
        ),
    ]
}

/// One valid frame per `Response` the guest sends, `Exit` twice because the code is signed.
fn responses() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "stdout",
            encoded(|w| write_response(w, &Response::Stdout(b"hello\n".to_vec()))),
        ),
        (
            "stderr",
            encoded(|w| write_response(w, &Response::Stderr(b"warning\n".to_vec()))),
        ),
        (
            "file",
            encoded(|w| {
                write_response(
                    w,
                    &Response::File {
                        path: "out.txt".into(),
                        data: b"result".to_vec(),
                    },
                )
            }),
        ),
        (
            "exit",
            encoded(|w| write_response(w, &Response::Exit { code: 0 })),
        ),
        (
            "exit_negative",
            encoded(|w| write_response(w, &Response::Exit { code: -9 })),
        ),
        (
            "timed_out",
            encoded(|w| write_response(w, &Response::TimedOut { elapsed_ms: 30_000 })),
        ),
        (
            "error",
            encoded(|w| write_response(w, &Response::Error("boom".into()))),
        ),
    ]
}

/// Frames chosen for the codec's shape rather than any message's meaning: the length field at its
/// edges, and a tag no [`Tag`] names, which the frame reader passes through for a caller to reject.
fn frames() -> Vec<(&'static str, Vec<u8>)> {
    let stdout = Tag::Stdout.as_u8();
    vec![
        ("empty", encoded(|w| write_frame(w, stdout, &[]))),
        ("one_byte", encoded(|w| write_frame(w, stdout, b"x"))),
        (
            "kibibyte",
            encoded(|w| write_frame(w, stdout, &[b'a'; 1024])),
        ),
        (
            "unknown_tag",
            encoded(|w| write_frame(w, 0xFF, b"\x00\x01\x02\x03")),
        ),
    ]
}

/// Every seed file, keyed by its path under `fuzz/seeds/`.
fn corpus() -> BTreeMap<String, Vec<u8>> {
    let mut seeds = BTreeMap::new();
    for (target, frames) in [
        ("channel_request", requests()),
        ("channel_response", responses()),
        ("channel_frame", frames()),
    ] {
        for (name, frame) in frames {
            let mut body = frame[..1].to_vec();
            body.extend_from_slice(&frame[FRAME_HEADER..]);
            seeds.insert(format!("{target}/{name}.body"), body);
            seeds.insert(format!("{target}/{name}"), frame);
        }
    }
    // The handshake is not framed, so its twin drops the magic instead of the `tag · len` header.
    let hello = encoded(write_handshake);
    seeds.insert(
        "channel_handshake/hello.after_magic".into(),
        hello[MAGIC.len()..].to_vec(),
    );
    seeds.insert("channel_handshake/hello".into(), hello);
    seeds
}

/// `fuzz/seeds/`, from this crate's manifest rather than the cwd, which a test runner chooses.
fn seeds_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/seeds")
        .canonicalize()
        .expect("fuzz/seeds/ is committed")
}

/// Every file under `root`, keyed as `<dir>/<file>`, so a directory naming no target reads as an
/// extra key rather than going unnoticed.
fn on_disk(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut found = BTreeMap::new();
    for dir in std::fs::read_dir(root).expect("fuzz/seeds/").flatten() {
        if !dir.path().is_dir() {
            continue;
        }
        let target = dir.file_name().to_string_lossy().into_owned();
        for file in std::fs::read_dir(dir.path()).expect("a seed dir").flatten() {
            if file.path().is_file() {
                let name = file.file_name().to_string_lossy().into_owned();
                let bytes = std::fs::read(file.path()).expect("a seed file");
                found.insert(format!("{target}/{name}"), bytes);
            }
        }
    }
    found
}

/// Makes `root` hold exactly `want`: stale files go first, so a renamed seed leaves nothing behind.
fn rewrite(root: &Path, want: &BTreeMap<String, Vec<u8>>) {
    for stale in on_disk(root).keys().filter(|k| !want.contains_key(*k)) {
        std::fs::remove_file(root.join(stale)).expect("remove a stale seed");
    }
    for dir in std::fs::read_dir(root).expect("fuzz/seeds/").flatten() {
        let empty = std::fs::read_dir(dir.path()).map_or(0, Iterator::count) == 0;
        if dir.path().is_dir() && empty {
            std::fs::remove_dir(dir.path()).expect("remove an emptied seed dir");
        }
    }
    for (path, bytes) in want {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().expect("a target dir")).expect("create a seed dir");
        std::fs::write(&path, bytes).expect("write a seed");
    }
    println!(
        "seeds: rewrote {} file(s) under {}",
        want.len(),
        root.display()
    );
}

/// The committed seeds are the encoders' current output, or `cargo xtask fuzz` starts a run from
/// frames the decoder rejects at its first branch, which is indistinguishable from no seeds at all.
#[test]
fn the_committed_seeds_are_what_the_encoders_produce() {
    let root = seeds_root();
    let want = corpus();
    if std::env::var_os(UPDATE).is_some() {
        rewrite(&root, &want);
        return;
    }
    let have = on_disk(&root);
    let fix = format!("re-generate them with `{UPDATE}=1 cargo test -p bsx-channel`");

    let missing: Vec<&String> = want.keys().filter(|k| !have.contains_key(*k)).collect();
    assert!(
        missing.is_empty(),
        "seeds missing from fuzz/seeds/: {missing:?} — {fix}"
    );
    let extra: Vec<&String> = have.keys().filter(|k| !want.contains_key(*k)).collect();
    assert!(
        extra.is_empty(),
        "fuzz/seeds/ holds files no target is seeded from: {extra:?} — {fix}"
    );
    for (path, bytes) in &want {
        assert_eq!(
            have.get(path),
            Some(bytes),
            "fuzz/seeds/{path} is not what the encoder writes today — {fix}"
        );
    }
}

/// Every tag the wire knows is carried by a request or response seed. A tag added without one is a
/// message shape the fuzzer reaches only by guessing its first byte, which is the gap seeds close.
#[test]
fn every_wire_tag_is_carried_by_a_seed() {
    // Derived from the decoder\u{2019}s own match rather than a list beside it, which would drift.
    let known = (0..=u8::MAX).filter(|t| Tag::from_u8(*t).is_some());
    let seeded: Vec<u8> = corpus()
        .iter()
        .filter(|(path, _)| {
            !path.ends_with(".body")
                && (path.starts_with("channel_request") || path.starts_with("channel_response"))
        })
        .filter_map(|(_, bytes)| bytes.first().copied())
        .collect();
    for tag in known {
        assert!(
            seeded.contains(&tag),
            "wire tag {tag} ({:?}) has no seed, so it is fuzzed only by chance",
            Tag::from_u8(tag)
        );
    }
}

/// A seed is only worth committing if it decodes: one that does not is a file the fuzzer spends
/// its first mutations discarding. The twins go through [`reframe`], the same call their
/// `_wellformed` entry point makes, so a twin built the wrong way round fails here.
#[test]
fn every_seed_decodes_through_the_entry_point_it_seeds() {
    for (path, bytes) in corpus() {
        let (target, name) = path.split_once('/').expect("<target>/<file>");
        let frame = match name.rsplit_once('.') {
            Some((_, "body")) => reframe(&bytes).expect("a twin is a `tag \u{b7} body`"),
            Some((_, "after_magic")) => [&MAGIC[..], &bytes].concat(),
            _ => bytes,
        };
        let decoded = match target {
            "channel_request" => Some(read_request(&mut &frame[..]).map(drop)),
            "channel_response" => Some(read_response(&mut &frame[..]).map(drop)),
            "channel_frame" => Some(read_frame(&mut &frame[..]).map(drop)),
            "channel_handshake" => Some(read_handshake(&mut &frame[..])),
            _ => None,
        }
        .expect("every seed directory names a target with a decoder");
        assert!(
            decoded.is_ok(),
            "fuzz/seeds/{path} does not decode: {:?}",
            decoded.err()
        );
    }
}
