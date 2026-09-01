//! The `bsx` CLI, and the hidden helper subcommand that becomes a virtual machine.
//!
//! **No user-facing verb works yet.** The Firecracker engine this binary used to drive was deleted
//! when the project moved to libkrun, and the supervisor that replaces it is being written:
//! `scratch/ROADMAP.md` phase 2 builds it, phase 3 gives this binary `run` and `shell` back. What
//! does work is `__vmm`, which is not a verb anyone types: it is how a VM comes into existence, and
//! [`vmm`] explains why that has to be a whole process.
//!
//! `tracing` logs to **stderr** and **stdout** stays reserved for a run's result, so the pipe
//! contract survives the rebuild.
#![forbid(unsafe_code)]

mod vmm;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Become a virtual machine. Not a verb: the supervisor re-executes this binary with it.
    ///
    /// Hidden rather than removed from the parser, so a boot that fails can be reproduced by hand
    /// with the exact arguments the supervisor used.
    #[command(name = vmm::HELPER_SUBCOMMAND, hide = true)]
    Vmm(vmm::VmmArgs),
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Some(Cmd::Vmm(args)) => vmm::run(&args),
        None => {
            eprintln!(
                "bsx: no sandbox to drive. The Firecracker engine was removed in the move to \
                 libkrun and the supervisor that replaces it is not written yet."
            );
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}
