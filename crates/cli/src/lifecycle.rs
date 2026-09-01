//! `bsx ls`, `bsx exec` and `bsx stop`: the verbs for a VM this process did not start.
//!
//! **There is no daemon.** A VM exists because its helper is listening on a control socket in the
//! runtime directory, and it stops existing when that helper does, so these verbs are a directory
//! scan plus a one-shot exchange with each VM's own process. That is what lets a VM started by the
//! GUI be listed and stopped by the CLI, with neither knowing about the other.
//!
//! - **`ls` is a point-in-time answer.** A VM can end between the scan and the print, which no
//!   design without a supervising daemon avoids, and which a caller has to handle anyway because
//!   it is equally true of a VM it started itself.
//! - **`stop` is a power cut**, the same one [`Vm::stop`](bsx_supervisor::Vm::stop) is: libkrun's
//!   only graceful surface is efi-only and returns `-ENOTSUP`, so there is nothing gentler to ask
//!   for. The VM ends itself, rather than being signalled by pid, so there is no window in which
//!   the number could name somebody else.
//! - **`exec` needs an agent**, which means a VM started by `bsx up`. A VM booted straight into a
//!   workload has nothing listening to ask.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Args;

use bsx_channel::Response;
use bsx_supervisor::control::{self, Channel, Info};
use bsx_supervisor::{discover, socket};

use crate::EXIT_OPERATIONAL;

/// How long `stop` waits for a stopped VM to actually be gone before reporting it as still there.
/// The VM kills itself the moment it has answered, so this is slack for scheduling, not for work.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Between checks that a stopping VM has gone.
const STOP_POLL: Duration = Duration::from_millis(20);

/// List the sandboxes running on this machine.
#[derive(Args, Debug)]
pub(crate) struct LsArgs {
    /// Also remove the socket files left behind by VMs that have ended. Off by default: a caller
    /// asking what is running should not quietly modify the directory.
    #[arg(long)]
    pub(crate) reap: bool,
}

/// Run a command in a sandbox that is already up.
#[derive(Args, Debug)]
pub(crate) struct ExecArgs {
    /// The VM's name, as `bsx ls` lists it.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
    /// A `KEY=VALUE` entry for the command's environment. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// The command, after `--`. Resolved by the guest, against the guest's `PATH`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub(crate) command: Vec<String>,
}

/// Stop a running sandbox.
#[derive(Args, Debug)]
pub(crate) struct StopArgs {
    /// The VM's name, as `bsx ls` lists it.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
}

pub(crate) fn ls(args: &LsArgs) -> ExitCode {
    match list(args, &mut std::io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("bsx ls: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

pub(crate) fn exec(args: &ExecArgs) -> ExitCode {
    match run_in(args) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("bsx exec: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

pub(crate) fn stop(args: &StopArgs) -> ExitCode {
    match end(&args.name) {
        Ok(name) => {
            println!("{name}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("bsx stop: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// The columns, in order. One definition, so the header and every row are laid out from the same
/// widths and cannot drift into a table whose header names the wrong column.
const COLUMNS: [(&str, usize); 7] = [
    ("NAME", 16),
    ("PID", 8),
    ("VCPUS", 6),
    ("MEM", 8),
    ("NET", 6),
    ("ROOTFS", 10),
    ("CHANNEL", 7),
];

/// What a cell says when the VM did not answer. A VM can end between the scan and the ask, and
/// filling the row with plausible numbers would be inventing a machine.
const UNKNOWN: &str = "-";

fn list(args: &LsArgs, out: &mut impl Write) -> Result<(), String> {
    if args.reap {
        let removed = discover::reap_stale().map_err(|e| e.to_string())?;
        if removed > 0 {
            eprintln!("bsx ls: removed {removed} socket(s) left by VMs that had ended");
        }
    }
    let found = discover::live().map_err(|e| e.to_string())?;
    let mut row = String::new();
    for (title, width) in COLUMNS {
        row.push_str(&format!("{title:<width$}  "));
    }
    writeln!(out, "{}", row.trim_end()).map_err(|e| e.to_string())?;

    for vm in found {
        // Asked one VM at a time, because each answer comes from that VM's own process: there is
        // nothing that knows about all of them to ask instead.
        let cells = match control::info(&vm.socket) {
            Ok(info) => cells_of(&info),
            Err(e) => {
                eprintln!("bsx ls: {}: {e}", vm.name);
                [const { String::new() }; 6].map(|_| UNKNOWN.to_string())
            }
        };
        let mut row = format!("{:<width$}  ", vm.name, width = COLUMNS[0].1);
        for (cell, (_, width)) in cells.iter().zip(COLUMNS.iter().skip(1)) {
            row.push_str(&format!("{cell:<width$}  "));
        }
        writeln!(out, "{}", row.trim_end()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// One VM's cells, in [`COLUMNS`] order after the name.
fn cells_of(info: &Info) -> [String; 6] {
    [
        info.pid.to_string(),
        info.vcpus.to_string(),
        info.mem_mib.to_string(),
        info.net.as_flag().to_string(),
        info.rootfs.as_flag().to_string(),
        info.channel.as_word().to_string(),
    ]
}

/// The control socket of the live VM called `name`, or why there is no such thing.
fn live_socket(name: &str) -> Result<std::path::PathBuf, String> {
    let path = socket::path_for(name).map_err(|e| e.to_string())?;
    if !socket::is_live(&path) {
        return Err(format!(
            "no VM named {name:?} is running (`bsx ls` lists the ones that are)"
        ));
    }
    Ok(path)
}

fn run_in(args: &ExecArgs) -> Result<u8, String> {
    let control_sock = live_socket(&args.name)?;
    let info = control::info(&control_sock).map_err(|e| e.to_string())?;
    if info.channel != Channel::Present {
        return Err(format!(
            "the VM {:?} has no agent channel, so there is nothing in it to ask; \
             `bsx up` starts one that has",
            args.name
        ));
    }
    let mut env = Vec::with_capacity(args.env.len());
    for entry in &args.env {
        let Some((key, value)) = entry.split_once('=').filter(|(k, _)| !k.is_empty()) else {
            return Err(format!("--env {entry:?} is not KEY=VALUE"));
        };
        env.push((key.to_string(), value.to_string()));
    }

    let channel_sock = socket::agent_path_for(&args.name).map_err(|e| e.to_string())?;
    let (mut conn, _stream) = crate::agent::connect(&channel_sock).map_err(|e| e.to_string())?;
    conn.send_exec(&args.command, &read_stdin()?, &env, &[] as &[&str], None)
        .map_err(|e| format!("start the command: {e}"))?;

    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    loop {
        match conn.recv_response() {
            Ok(Response::Stdout(bytes)) => {
                stdout.write_all(&bytes).map_err(|e| e.to_string())?;
                stdout.flush().map_err(|e| e.to_string())?;
            }
            Ok(Response::Stderr(bytes)) => {
                stderr.write_all(&bytes).map_err(|e| e.to_string())?;
            }
            Ok(Response::Exit { code }) => return Ok(crate::run::guest_code(code)),
            Ok(Response::TimedOut { elapsed_ms }) => {
                return Err(format!("the command was killed after {elapsed_ms} ms"));
            }
            Ok(Response::Error(msg)) => return Err(format!("the agent refused: {msg}")),
            Ok(_) => {}
            Err(e) => return Err(format!("the command ended abnormally: {e}")),
        }
    }
}

/// This process's stdin for the guest command, or nothing when there is a terminal on it.
///
/// The agent's exec request carries stdin as one payload rather than a stream, so it has to be
/// read to EOF before the command starts, and a terminal has no EOF to read to: waiting for one
/// would hang on every interactive invocation. A capability probe, not a guess about how it was
/// run.
///
/// **An inherited stdin can be non-blocking, and that is not an error.** `O_NONBLOCK` belongs to
/// the open file description, which a caller shares with whoever handed it over, so a read can
/// return `EAGAIN` meaning "nothing yet" where this wants "nothing ever". Reported as a failure,
/// that made `bsx exec` refuse to run anything at all under a harness whose stdin was
/// non-blocking (watched happen). Waiting for readability and retrying is what a blocking read
/// would have done, without setting a flag back on an fd this process does not own.
fn read_stdin() -> Result<Vec<u8>, String> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Ok(Vec::new());
    }
    let mut reader = stdin
        .lock()
        .take(u64::try_from(bsx_channel::MAX_PAYLOAD).unwrap_or(u64::MAX));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => wait_readable()?,
            Err(e) => return Err(format!("read stdin: {e}")),
        }
    }
}

/// Blocks until stdin has something to read or has ended. The wait a blocking read would have
/// done, for a description whose owner made it non-blocking.
fn wait_readable() -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut fds = [rustix::event::PollFd::new(
        &stdin,
        rustix::event::PollFlags::IN,
    )];
    // No timeout: a pipe nobody writes to and nobody closes is exactly what a blocking read waits
    // on too, so this adds no way to hang that reading normally did not have.
    rustix::event::poll(&mut fds, None).map_err(|e| format!("wait on stdin: {e}"))?;
    Ok(())
}

fn end(name: &str) -> Result<String, String> {
    let control_sock = live_socket(name)?;
    control::stop(&control_sock).map_err(|e| e.to_string())?;
    // The VM answers and then ends itself, so the socket going dead is what says it is gone. The
    // process is not this one's child, so there is no `wait` to do instead.
    let deadline = Instant::now() + STOP_GRACE;
    while socket::is_live(&control_sock) {
        if Instant::now() >= deadline {
            return Err(format!(
                "the VM {name:?} accepted the stop but is still answering after {STOP_GRACE:?}"
            ));
        }
        std::thread::sleep(STOP_POLL);
    }
    // Its sockets are leftovers now, and this caller is the one that ended it, so it is the one
    // entitled to the name.
    tidy(&control_sock);
    if let Ok(channel) = socket::agent_path_for(name) {
        tidy(&channel);
    }
    if let Ok(log) = socket::log_path_for(name) {
        let _ = std::fs::remove_file(log);
    }
    Ok(name.to_string())
}

/// Removes a socket file nobody is listening on. Failures are dropped: the VM is stopped either
/// way, and a leftover is what the stale check exists for.
fn tidy(path: &Path) {
    let _ = socket::clear_if_stale(path);
}
