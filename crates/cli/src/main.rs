//! The `bsx` CLI, and the hidden helper subcommand that becomes a virtual machine.
//!
//! `bsx run` boots a sandbox, runs one command, and exits with its status ([`run`]). Beside it
//! sits `__vmm`, which is not a verb anyone types: it is how a VM comes into existence, and
//! [`vmm`] explains why that has to be a whole process. The rest of the verbs arrive with
//! `scratch/ROADMAP.md` phase 3.
//!
//! stdout stays reserved for the guest's own output, so the pipe contract holds: what the command
//! in the sandbox writes is what `bsx run` writes.
#![forbid(unsafe_code)]

mod run;
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
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one command in a fresh sandbox and exit with its status.
    Run(run::RunArgs),
    /// Become a virtual machine. Not a verb: the supervisor re-executes this binary with it.
    ///
    /// Hidden rather than removed from the parser, so a boot that fails can be reproduced by hand
    /// with the exact arguments the supervisor used.
    #[command(name = vmm::HELPER_SUBCOMMAND, hide = true)]
    Vmm(vmm::VmmArgs),
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Run(args) => run::run(&args),
        Cmd::Vmm(args) => vmm::run(&args),
    }
}
