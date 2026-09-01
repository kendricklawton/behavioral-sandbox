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

use std::io::{Read, Write};
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
    /// Send this process's stdin to the command, read to end of input before it starts.
    #[arg(long = "stdin", short = 'i')]
    pub(crate) stdin: bool,
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

/// The columns, in order, with the width each is padded to. One definition, so the header and
/// every row are laid out from the same widths and cannot drift into a table whose header names
/// the wrong column. A name longer than its width pushes the row out rather than being
/// truncated, since a truncated name is not one `bsx exec` would take back.
const COLUMNS: [(&str, usize); CELLS + 1] = [
    ("NAME", 16),
    ("PID", 8),
    ("VCPUS", 6),
    ("MEM", 8),
    ("NET", 6),
    ("ROOTFS", 10),
    ("CHANNEL", 7),
];

/// Cells a VM answers with, after the name it was already listed under.
const CELLS: usize = 6;

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
    let titles = COLUMNS.map(|(title, _)| title.to_string());
    writeln!(out, "{}", row(&titles)).map_err(|e| e.to_string())?;

    for vm in found {
        // Asked one VM at a time, because each answer comes from that VM's own process: there is
        // nothing that knows about all of them to ask instead.
        let cells = match control::info(&vm.socket) {
            Ok(info) => cells_of(&info),
            Err(e) => {
                eprintln!("bsx ls: {}: {e}", vm.name);
                [UNKNOWN; CELLS].map(str::to_string)
            }
        };
        let mut fields = [const { String::new() }; CELLS + 1];
        fields[0] = vm.name;
        fields[1..].clone_from_slice(&cells);
        writeln!(out, "{}", row(&fields)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// One line of the table: each field padded to its column's width, trailing space trimmed. The
/// header and every VM go through this, so a column added to [`COLUMNS`] cannot reach one and
/// miss the other.
fn row(fields: &[String; CELLS + 1]) -> String {
    let mut line = String::new();
    for (field, (_, width)) in fields.iter().zip(COLUMNS) {
        line.push_str(&format!("{field:<width$}  "));
    }
    line.trim_end().to_string()
}

/// One VM's cells, in [`COLUMNS`] order after the name.
fn cells_of(info: &Info) -> [String; CELLS] {
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

    // Read before the dial, because this can wait on whatever is feeding stdin and there is no
    // reason to hold a connection into the guest open while it does.
    let stdin = if args.stdin {
        read_stdin()?
    } else {
        Vec::new()
    };

    let channel_sock = socket::agent_path_for(&args.name).map_err(|e| e.to_string())?;
    let (mut conn, _stream) =
        crate::agent::connect(&channel_sock, &control_sock).map_err(|e| e.to_string())?;
    conn.send_exec(&args.command, &stdin, &env, &[] as &[&str], None)
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
            // A channel that ends mid-command is most often the VM ending under it, which the
            // control socket can be *asked* rather than guessed at: "failed to fill whole buffer"
            // is true and tells the caller nothing about what happened to their sandbox.
            Err(e) if !socket::is_live(&control_sock) => {
                return Err(format!(
                    "the VM {:?} ended while the command was running ({e})",
                    args.name
                ));
            }
            Err(e) => return Err(format!("the command ended abnormally: {e}")),
        }
    }
}

/// This process's stdin, read to end of input, for a caller that asked for it with `--stdin`.
///
/// **Only when asked.** The agent's exec request carries stdin as one payload rather than a
/// stream, so it has to be read to EOF before the command starts, and plenty of things hand a
/// program an stdin that never reaches one: a job runner's idle pipe, a CI harness, an
/// interactive terminal. Reading whenever stdin was not a terminal made `bsx exec vm -- echo hi`
/// hang forever with no output under exactly such a pipe (watched, twice). So the flag, which is
/// also the spelling every comparable tool uses.
///
/// **An inherited stdin can be non-blocking, and that is not an error.** `O_NONBLOCK` belongs to
/// the open file description, which a caller shares with whoever handed it over, so a read can
/// return `EAGAIN` meaning "nothing yet" where this wants "nothing ever". Reported as a failure,
/// that made `bsx exec` refuse to run anything at all under a harness whose stdin was
/// non-blocking (watched happen). Waiting for readability and retrying is what a blocking read
/// would have done, without setting a flag back on a description this process does not own.
fn read_stdin() -> Result<Vec<u8>, String> {
    let mut reader = std::io::stdin()
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use std::num::{NonZeroU8, NonZeroU32};

    use bsx_supervisor::{Net, RootFs};

    use super::{CELLS, COLUMNS, Channel, Info, UNKNOWN, cells_of, row};

    /// A VM's row lines up with the header it is printed under, and a VM that did not answer
    /// still occupies every column: a short row would silently shift the reader's eye onto the
    /// wrong heading.
    #[test]
    fn every_row_carries_one_field_for_every_column() {
        let info = Info::new(
            4242,
            NonZeroU8::MIN,
            NonZeroU32::new(512).expect("512 is not zero"),
            Net::Tsi,
            RootFs::Writable,
            Channel::Present,
        );
        let header = row(&COLUMNS.map(|(title, _)| title.to_string()));
        let count = |line: &str| line.split_whitespace().count();
        assert_eq!(count(&header), CELLS + 1);

        for cells in [cells_of(&info), [UNKNOWN; CELLS].map(str::to_string)] {
            let mut fields = [const { String::new() }; CELLS + 1];
            fields[0] = "vm-under-test".to_string();
            fields[1..].clone_from_slice(&cells);
            assert_eq!(count(&row(&fields)), CELLS + 1, "{fields:?}");
        }
    }

    /// The cells are the postures the VM answered with, in the order the header names them, and
    /// each is the shared spelling rather than a second one written here.
    #[test]
    fn the_cells_are_the_postures_in_the_order_the_header_names() {
        let info = Info::new(
            7,
            NonZeroU8::MIN,
            NonZeroU32::new(256).expect("256 is not zero"),
            Net::Tsi,
            RootFs::Writable,
            Channel::Present,
        );
        assert_eq!(
            cells_of(&info),
            [
                "7".to_string(),
                "1".to_string(),
                "256".to_string(),
                Net::Tsi.as_flag().to_string(),
                RootFs::Writable.as_flag().to_string(),
                Channel::Present.as_word().to_string(),
            ]
        );
        assert_eq!(
            COLUMNS.map(|(title, _)| title),
            ["NAME", "PID", "VCPUS", "MEM", "NET", "ROOTFS", "CHANNEL"]
        );
    }
}
