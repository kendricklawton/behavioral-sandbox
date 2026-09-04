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
//! - **The record is kept in step here.** `exec` appends what it printed to the sandbox's
//!   record, `stop` writes the end, and `ls --all` marks a run whose socket is dead and whose
//!   record has no end as gone, which is the one bookkeeping a listing does.

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Args;

use bsx_channel::Response;
use bsx_record::{End, Store};
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
    /// Also list the runs that have ended, from the notebook's records, newest first.
    #[arg(long)]
    pub(crate) all: bool,
}

/// Show one run's record: by id, or the newest by name.
#[derive(Args, Debug)]
pub(crate) struct ShowArgs {
    /// The run's id, or a VM name.
    #[arg(value_name = "ID|NAME")]
    pub(crate) key: String,
}

/// Remove one run's record and everything it captured.
#[derive(Args, Debug)]
pub(crate) struct RmArgs {
    /// The run's id, or a VM name.
    #[arg(value_name = "ID|NAME")]
    pub(crate) key: String,
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
    /// Run the command on a pty in the guest with this terminal attached, as `bsx shell` does
    /// on a fresh sandbox: keystrokes and the terminal's size go in until the command exits.
    #[arg(long = "tty", short = 't', conflicts_with = "stdin")]
    pub(crate) tty: bool,
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

pub(crate) fn show(args: &ShowArgs) -> ExitCode {
    match describe(&args.key, &mut std::io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("bsx show: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

pub(crate) fn rm(args: &RmArgs) -> ExitCode {
    match forget(&args.key) {
        Ok(id) => {
            println!("{id}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("bsx rm: {msg}");
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
    if args.all {
        list_past(out)?;
    }
    Ok(())
}

/// The runs that have ended, newest first, after marking as gone the open ones whose VM no
/// longer answers.
fn list_past(out: &mut impl Write) -> Result<(), String> {
    let store = Store::open().map_err(|e| e.to_string())?;
    let ended = settle_gone(&store)?;
    writeln!(out).map_err(|e| e.to_string())?;
    writeln!(
        out,
        "{:<16}  {:<10}  {:<20}  {:<8}  ID",
        "NAME", "END", "STARTED", "TOOK"
    )
    .map_err(|e| e.to_string())?;
    for record in ended {
        let took = record
            .ended_ms
            .map(|e| bsx_record::format_duration(e.saturating_sub(record.started_ms)))
            .unwrap_or_default();
        writeln!(
            out,
            "{:<16}  {:<10}  {:<20}  {:<8}  {}",
            record.name,
            record.end.map(|e| e.to_string()).unwrap_or_default(),
            bsx_record::format_time(record.started_ms),
            took,
            record.id
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Marks every open record whose VM is not answering as gone, and returns the ended records,
/// newest first.
pub(crate) fn settle_gone(store: &Store) -> Result<Vec<bsx_record::Record>, String> {
    let mut ended = Vec::new();
    for mut record in store.list().map_err(|e| e.to_string())? {
        if record.is_open() {
            let live = socket::path_for(&record.name).is_ok_and(|p| socket::is_live(&p));
            if live {
                continue;
            }
            record.finish(End::Gone);
            let _ = store.save(&record);
        }
        ended.push(record);
    }
    Ok(ended)
}

fn describe(key: &str, out: &mut impl Write) -> Result<(), String> {
    let store = Store::open().map_err(|e| e.to_string())?;
    let record = store
        .find(key)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no run named or numbered {key:?} (`bsx ls --all` lists them)"))?;
    let dir = store.dir_of(&record.id);
    write!(out, "{}", record.to_text()).map_err(|e| e.to_string())?;
    writeln!(out, "dir {}", dir.path().display()).map_err(|e| e.to_string())?;
    for (label, path) in [
        ("stdout", dir.stdout()),
        ("stderr", dir.stderr()),
        ("shell.log", dir.shell_log()),
        ("exec.log", dir.exec_log()),
    ] {
        if let Ok(meta) = std::fs::metadata(&path) {
            let cut = if path.with_extension("truncated").exists() {
                " (capped)"
            } else {
                ""
            };
            writeln!(out, "output {label} {} bytes{cut}", meta.len()).map_err(|e| e.to_string())?;
        }
    }
    for (file, size) in dir.result_files().map_err(|e| e.to_string())? {
        writeln!(out, "result {} {size} bytes", file.display()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn forget(key: &str) -> Result<String, String> {
    let store = Store::open().map_err(|e| e.to_string())?;
    let record = store
        .find(key)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no run named or numbered {key:?} (`bsx ls --all` lists them)"))?;
    if record.is_open() && socket::path_for(&record.name).is_ok_and(|p| socket::is_live(&p)) {
        return Err(format!(
            "the run {} is still running; `bsx stop {}` ends it first",
            record.id, record.name
        ));
    }
    store.remove(&record.id).map_err(|e| e.to_string())?;
    Ok(record.id)
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
    let (mut conn, stream) =
        crate::agent::connect(&channel_sock, &control_sock).map_err(|e| e.to_string())?;
    // The sandbox's record, when it has one: each exec's output is appended under a line naming
    // the command, so the notebook shows what was run in it and what came back.
    let mut log = Store::open()
        .ok()
        .and_then(|store| {
            store
                .open_run(&args.name)
                .ok()
                .flatten()
                .map(|r| (store, r))
        })
        .and_then(|(store, record)| {
            let dir = store.dir_of(&record.id);
            dir.append(&dir.exec_log()).ok()
        });
    if let Some(log) = &mut log {
        let _ = writeln!(log, "# {} {}", bsx_record::now_ms(), args.command.join(" "));
    }
    if args.tty {
        let mut sink = std::io::sink();
        let log: &mut dyn Write = match &mut log {
            Some(log) => log,
            None => &mut sink,
        };
        return crate::pty::session(conn, stream, args.command.clone(), env, log);
    }
    conn.send_exec(&args.command, &stdin, &env, &[] as &[&str], None)
        .map_err(|e| format!("start the command: {e}"))?;

    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    loop {
        match conn.recv_response() {
            Ok(Response::Stdout(bytes)) => {
                if let Some(log) = &mut log {
                    let _ = log.write_all(&bytes);
                }
                stdout.write_all(&bytes).map_err(|e| e.to_string())?;
                stdout.flush().map_err(|e| e.to_string())?;
            }
            Ok(Response::Stderr(bytes)) => {
                if let Some(log) = &mut log {
                    let _ = log.write_all(&bytes);
                }
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

/// This process's stdin, read to end of input, for a caller that asked with `--stdin`.
///
/// **Only when asked**, since the request carries stdin as one payload and an idle pipe has no
/// end. **`EAGAIN` is not an error** on an inherited non-blocking description: waited for, not
/// reported.
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
    // The record's end: this caller ended the run, so it is the one that knows how.
    if let Ok(store) = Store::open()
        && let Ok(Some(mut record)) = store.open_run(name)
    {
        record.finish(End::Stopped);
        let _ = store.save(&record);
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
