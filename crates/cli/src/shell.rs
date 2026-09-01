//! `bsx shell`: an interactive shell (or any command) on a pseudo-terminal inside a fresh sandbox.
//!
//! The console cannot do this: libkrun wires the workload's stdio through pipes, so a guest
//! command never sees a tty there no matter what the host side is (measured, `scratch/ROADMAP.md`
//! 3.1). The pty therefore lives **in the guest**, allocated by the agent, and this verb is the
//! host half of that session:
//!
//! - Boot a VM whose workload *is* the agent, listening on vsock; reach it through the unix
//!   socket the helper maps (`--vsock`), and ask for a [`Request::ExecPty`].
//! - Put the host terminal in **raw mode** for the session, so every byte (including `^C`, which
//!   must reach the guest's foreground job, not this process) passes through; the guest pty's
//!   line discipline is the one that interprets them. Restored on every exit path by a drop guard.
//! - Follow the host terminal's size: polled, and a change becomes a [`Request::Resize`]. Polling
//!   rather than `SIGWINCH` keeps signal handling (and its `unsafe`) out of the crate for the
//!   price of a 250 ms lag on a resize.
//! - The guest console is detached ([`Console::Detached`]): an attached one *reads this
//!   process's stdin into the guest console*, stealing the session's keystrokes (watched happen),
//!   and its output would interleave boot noise into a raw terminal.
use std::io::{IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Args;

use bsx_channel::{ClientConnection, GUEST_AGENT_PATH, Request, Response, VSOCK_PORT};
use bsx_supervisor::{Console, Vm, VmConfig};

use crate::EXIT_OPERATIONAL;

/// How long the agent is given to answer on the channel before the boot is called failed. Cold
/// boot is ~300 ms on the development laptop; this is headroom, not a tuned value.
const DIAL_GRACE: Duration = Duration::from_secs(10);

/// How often the host terminal's size is polled. The lag a resize can see, and the price of
/// keeping signal handling out of the crate.
const WINSIZE_POLL: Duration = Duration::from_millis(250);

/// Open an interactive shell in a fresh sandbox.
#[derive(Args, Debug)]
pub(crate) struct ShellArgs {
    /// The guest root directory. Falls back like `bsx run`'s.
    #[arg(long, value_name = "DIR")]
    pub(crate) root: Option<PathBuf>,
    /// vCPUs for this sandbox.
    #[arg(long, value_name = "N")]
    pub(crate) vcpus: Option<std::num::NonZeroU8>,
    /// Guest RAM in MiB.
    #[arg(long, value_name = "MIB")]
    pub(crate) mem: Option<std::num::NonZeroU32>,
    /// A host directory made read-write at a guest path, as `GUESTDIR=HOSTDIR`: the project
    /// case, where edits land on the host. Repeatable.
    #[arg(long = "mount", value_name = "GUESTDIR=HOSTDIR")]
    pub(crate) mounts: Vec<String>,
    /// An extra virtiofs device, as `TAG=HOSTPATH`, for a guest that mounts by tag itself.
    /// Repeatable; `--mount` is the one that also mounts.
    #[arg(long = "share", value_name = "TAG=HOSTPATH")]
    pub(crate) shares: Vec<String>,
    /// A `KEY=VALUE` entry for the shell's guest environment. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// The VM's name while it runs. Defaults to `shell-<pid>`.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// The command to run on the pty, after `--`. Defaults to `/bin/sh`.
    #[arg(last = true, value_name = "COMMAND")]
    pub(crate) command: Vec<String>,
}

pub(crate) fn run(args: &ShellArgs) -> ExitCode {
    match session(args) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("bsx shell: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn session(args: &ShellArgs) -> Result<u8, String> {
    let root = crate::run::resolve_root(args.root.as_deref())?;
    for entry in &args.env {
        if !crate::vmm::well_formed_env(entry) {
            return Err(format!("--env {entry:?} is not KEY=VALUE"));
        }
    }

    // A private directory for the channel socket, owned (and removed) by this process: unlike a
    // VM's control socket, this one's lifetime is exactly this session's.
    let dir = SessionDir::create()?;
    let channel_sock = dir.path.join("agent.sock");

    let mut cfg = VmConfig::new(root, GUEST_AGENT_PATH);
    cfg.args = vec![format!("vsock:{VSOCK_PORT}").into()];
    // The agent's stderr is the guest console; at `info` it narrates every session into the
    // operator's terminal.
    cfg.env = vec!["BSX_LOG=warn".into()];
    cfg.vsock = Some((VSOCK_PORT, channel_sock.clone()));
    cfg.console = Console::Detached;
    if let Some(v) = args.vcpus {
        cfg.vcpus = v;
    }
    if let Some(m) = args.mem {
        cfg.mem_mib = m;
    }
    for spec in &args.shares {
        let Some((tag, path)) = crate::vmm::split_share(spec) else {
            return Err(format!("--share {spec:?} is not TAG=HOSTPATH"));
        };
        cfg.shares.push((tag.to_string(), path.to_path_buf()));
    }
    for spec in &args.mounts {
        let Some((guest, host)) = crate::vmm::split_mount(spec) else {
            return Err(format!(
                "--mount {spec:?} is not GUESTDIR=HOSTDIR with an absolute guest path"
            ));
        };
        cfg.mounts.push((guest.to_path_buf(), host.to_path_buf()));
    }
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("shell-{}", std::process::id()));

    let mut vm = Vm::spawn(name, &cfg).map_err(|e| e.to_string())?;
    let (mut reader, stream) = dial(&channel_sock, &mut vm)?;

    // Sized before raw mode, engaged before the request: output starts the moment the agent has
    // the command, and a cooked terminal would re-interpret it.
    let tty = std::io::stdin().is_terminal();
    let (cols, rows) = terminal_size().unwrap_or((80, 24));
    let _raw = tty.then(RawGuard::engage).flatten();

    let sender = Arc::new(Mutex::new(ClientConnection::resume(stream)));

    let mut command: Vec<String> = args.command.clone();
    if command.is_empty() {
        command = vec!["/bin/sh".to_string()];
    }
    let mut env: Vec<(String, String)> = args
        .env
        .iter()
        .filter_map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    if let Ok(term) = std::env::var("TERM") {
        env.push(("TERM".to_string(), term));
    }
    sender
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .send_request(&Request::ExecPty {
            argv: command,
            env,
            cols,
            rows,
        })
        .map_err(|e| format!("start the session: {e}"))?;

    // Keystrokes up, on their own thread, because reads of both stdin and the channel block.
    let stdin_sender = Arc::clone(&sender);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 {
                break;
            }
            let sent = stdin_sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .send_request(&Request::Stdin(buf[..n].to_vec()));
            if sent.is_err() {
                break;
            }
        }
    });
    // Size changes up. Only when this is a terminal: a pipe has no size to follow.
    if tty {
        let resize_sender = Arc::clone(&sender);
        let mut last = (cols, rows);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(WINSIZE_POLL);
                let Some(now) = terminal_size() else { continue };
                if now != last {
                    last = now;
                    let sent = resize_sender
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .send_request(&Request::Resize {
                            cols: now.0,
                            rows: now.1,
                        });
                    if sent.is_err() {
                        break;
                    }
                }
            }
        });
    }

    // The terminal's bytes down, on this thread, until the command exits.
    let mut stdout = std::io::stdout();
    loop {
        match reader.recv_response() {
            Ok(Response::Stdout(bytes)) => {
                stdout.write_all(&bytes).map_err(|e| e.to_string())?;
                stdout.flush().map_err(|e| e.to_string())?;
            }
            Ok(Response::Exit { code }) => return Ok(crate::run::guest_code(code)),
            Ok(Response::Error(msg)) => return Err(format!("the agent refused: {msg}")),
            Ok(_) => {}
            Err(e) => return Err(format!("the session ended abnormally: {e}")),
        }
    }
}

/// Dials the agent: connects to the channel socket and completes the protocol handshake,
/// retrying until it succeeds or the grace runs out. A completed `connect` alone proves nothing,
/// because libkrun accepts on the unix socket before the guest is listening on the vsock port
/// inside and resets when the forward fails (watched happen); **the handshake is the readiness
/// probe**. A helper that has already died fails fast with its exit, not a timeout.
///
/// Returns the handshaken connection (the session's read half) plus the raw stream for the send
/// half, with the read deadline used against a wedged boot taken back off.
fn dial(
    sock: &std::path::Path,
    vm: &mut Vm,
) -> Result<(ClientConnection<UnixStream>, UnixStream), String> {
    let deadline = Instant::now() + DIAL_GRACE;
    loop {
        if let Ok(Some(exit)) = vm.try_wait() {
            return Err(format!(
                "the VM ended ({exit:?}) before the agent answered: is the guest image one with \
                 the agent baked in? (`cargo xtask build-rootfs`)"
            ));
        }
        let failed = match try_dial(sock) {
            Ok(pair) => return Ok(pair),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "the agent never answered on {} within {DIAL_GRACE:?} (last attempt: {failed})",
                sock.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// One dial attempt: connect, bound the handshake by a deadline so a wedged guest cannot hang the
/// dial loop past its grace, and hand back both halves with the deadline cleared.
fn try_dial(sock: &std::path::Path) -> Result<(ClientConnection<UnixStream>, UnixStream), String> {
    let stream = UnixStream::connect(sock).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let conn = ClientConnection::connect(stream.try_clone().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    // Interactive sessions idle indefinitely; the deadline was for the handshake only.
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok((conn, stream))
}

/// The host terminal's `(cols, rows)`, read from stdin: the fd the raw-mode guard owns, so the
/// size follows the same terminal the keystrokes come from even when stdout is a pipe.
fn terminal_size() -> Option<(u16, u16)> {
    let ws = rustix::termios::tcgetwinsize(std::io::stdin()).ok()?;
    if ws.ws_col == 0 || ws.ws_row == 0 {
        return None;
    }
    Some((ws.ws_col, ws.ws_row))
}

/// Raw mode on the host terminal, restored on drop, so a panic or an early `?` cannot leave the
/// operator's terminal eating its own line feeds.
struct RawGuard {
    saved: rustix::termios::Termios,
}

impl RawGuard {
    fn engage() -> Option<Self> {
        let stdin = std::io::stdin();
        let saved = rustix::termios::tcgetattr(&stdin).ok()?;
        let mut raw = saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(&stdin, rustix::termios::OptionalActions::Now, &raw).ok()?;
        Some(Self { saved })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Now,
            &self.saved,
        );
    }
}

/// A private 0700 directory for this session's channel socket, removed on drop.
struct SessionDir {
    path: PathBuf,
}

impl SessionDir {
    fn create() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("bsx-shell-{}", std::process::id()));
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(&path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for SessionDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use clap::Parser;

    use crate::{Cli, Cmd};

    /// No command means `/bin/sh`, and a command after `--` arrives verbatim, hyphens and all.
    #[test]
    fn the_shell_command_defaults_to_sh_and_passes_verbatim() {
        let cli = Cli::parse_from(["bsx", "shell"]);
        let Cmd::Shell(args) = cli.cmd else {
            panic!("shell must parse");
        };
        assert!(args.command.is_empty(), "empty means the default shell");

        let cli = Cli::parse_from(["bsx", "shell", "--", "top", "-d", "1"]);
        let Cmd::Shell(args) = cli.cmd else {
            panic!("shell must parse");
        };
        assert_eq!(args.command, ["top", "-d", "1"]);
    }
}
