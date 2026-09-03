//! A pty session on the host terminal: keystrokes and the terminal's size up, the terminal's
//! bytes down, until the command in the guest exits. `bsx shell` runs it on a fresh sandbox and
//! `bsx exec --tty` on a live one.
//!
//! - **Raw mode for exactly the session.** Engaged before the request and restored on drop, so
//!   a panic or an early `?` cannot leave the operator's terminal eating its own line feeds.
//! - **The record keeps what the terminal showed.** Every byte down goes to `log` too; typed
//!   text appears only where the guest echoed it.

use std::io::{IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bsx_channel::{ClientConnection, Request, Response};

/// How often the host terminal's size is polled for a change to forward.
const WINSIZE_POLL: Duration = Duration::from_millis(250);

/// Runs `command` on a pty in the guest behind `reader` and `stream`, with `env` added to its
/// environment and the host's `TERM`, and returns the command's exit code.
pub(crate) fn session(
    mut reader: ClientConnection<UnixStream>,
    stream: UnixStream,
    command: Vec<String>,
    mut env: Vec<(String, String)>,
    log: &mut dyn Write,
) -> Result<u8, String> {
    // Sized before raw mode, engaged before the request: output starts the moment the agent has
    // the command, and a cooked terminal would re-interpret it.
    let tty = std::io::stdin().is_terminal();
    let (cols, rows) = terminal_size().unwrap_or((80, 24));
    let _raw = tty.then(RawGuard::engage).flatten();

    let sender = Arc::new(Mutex::new(ClientConnection::resume(stream)));

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

    // The terminal's bytes down, on this thread, until the command exits. What the terminal
    // shows is what the record keeps: typed text only where the guest echoed it.
    let mut stdout = std::io::stdout();
    loop {
        match reader.recv_response() {
            Ok(Response::Stdout(bytes)) => {
                let _ = log.write_all(&bytes);
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
