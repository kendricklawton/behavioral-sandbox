//! The `guest-agent` binary: listens for connections and serves one command each.
//!
//! - **Two transports.** In a real guest the agent listens on **vsock** (`vsock:<port>`), the channel
//!   the host reaches through libkrun's vsock mapping. For host-side development it also listens on
//!   a **unix socket** (`unix:<path>`), which makes the whole exec path runnable with no VM. Only the
//!   listener differs, since `serve` takes any `Read`+`Write`.
//! - **Streams.** `tracing` goes to stderr. Exactly one line goes to **stdout**, the readiness
//!   sentinel ([`GUEST_READY_MARKER`](bsx_channel::GUEST_READY_MARKER)) emitted once the vsock
//!   listener is bound, because the guest's stdout is the serial console the host scans.
//! - **One session per process.** Every connection serves from the same working directory, so
//!   repeated execs against one VM compose into a **stateful session**.
#![forbid(unsafe_code)]

use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod listen;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    listen::main()
}

/// The agent serves a Linux guest and `bsx-guest-agent` compiles to nothing off Linux, so the
/// binary a host build produces there exists to say so rather than to be run.
#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("guest-agent runs inside a Linux guest; a host build of it does nothing");
    ExitCode::from(2)
}
