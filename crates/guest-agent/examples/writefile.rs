//! A P3.9 runtime-agnostic **fixture** — *not* a usage example of the agent.
//!
//! A minimal, **statically linked** native binary (musl, no dynamic libc, no interpreter, no
//! `PT_INTERP`) that the driver injects into a microVM read-only and executes, to prove the engine
//! runs an *arbitrary* Linux ELF handed to it at runtime — not just the baked-in Python/Node
//! interpreters. Built static by `cargo xtask build-guest-example`; the privileged test
//! `runs_a_static_native_binary_and_captures_its_artifact` injects it via a block device and runs it.
//!
//! It writes a known payload to the path in `argv[1]` (the guest's writable `/output`) and prints a
//! marker line — the same inject → run → capture loop the interpreter tests exercise, but with a
//! native binary that carries no runtime of its own.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(out_path) = std::env::args().nth(1) else {
        eprintln!("usage: writefile <output-path>");
        return ExitCode::from(2);
    };
    if let Err(e) = std::fs::write(&out_path, b"written by a static native ELF: 6*7=42\n") {
        eprintln!("writefile: {out_path}: {e}");
        return ExitCode::FAILURE;
    }
    // A stdout marker, so the exec round trip is observable even without reading the file back.
    let _ = writeln!(std::io::stdout(), "writefile ok -> {out_path}");
    ExitCode::SUCCESS
}
