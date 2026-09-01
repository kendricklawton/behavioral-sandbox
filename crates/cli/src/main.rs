//! The `bsx` CLI.
//!
//! **This binary drives nothing at present.** The Firecracker engine it used to call was deleted
//! when the project moved to libkrun, and the supervisor that replaces it is not written yet:
//! `scratch/ROADMAP.md` phase 2 builds it, phase 3 gives this binary its verbs back. Until then
//! `bsx` parses its arguments, says so, and exits non-zero, so a caller cannot mistake it for a
//! sandbox that ran their command.
//!
//! `tracing` logs to **stderr** and **stdout** stays reserved for a run's result, so the pipe
//! contract survives the rebuild.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

/// Exit code for an operational failure, as opposed to a guest command's own exit code:
/// conventional "2", the same convention (and name) as the guest agent's.
const EXIT_OPERATIONAL: u8 = 2;

#[derive(Parser)]
#[command(
    name = "bsx",
    version,
    about = "Run untrusted code in a hardware-isolated sandbox.",
    long_about = "Run untrusted code in a hardware-isolated sandbox.\n\n\
                  No subcommand works right now: the engine was removed in the move to libkrun and \
                  its replacement is still being written."
)]
struct Cli;

fn main() -> ExitCode {
    Cli::parse();
    eprintln!(
        "bsx: no sandbox to drive. The Firecracker engine was removed in the move to libkrun and \
         the supervisor that replaces it is not written yet."
    );
    ExitCode::from(EXIT_OPERATIONAL)
}
