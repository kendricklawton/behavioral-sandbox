//! The winit side of the guest's input, and the two feeders the helper runs. The devices, the
//! reports and the line grammar are `bsx_input`'s; this is what the helper adds to them.
//!
//! - **`BSX_INPUT_REPLAY`** names a file or FIFO of lines the helper feeds to the devices as a
//!   window would: the end-to-end test's way in on a runner with no display server.
//! - **An `input` session is a thread.** The control thread answers `ok` and hands the
//!   connection to a thread that feeds its lines until the client goes, so a slow or silent
//!   client parks nothing that answers for this VM, and the release of what it left down is
//!   `feed`'s.

use std::io::{self, BufReader};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use bsx_input::{Button, Target, feed};
use bsx_krun::{InputEvent, InputSender};
use winit::event::MouseButton;

/// The environment variable naming the replay source.
pub(crate) const REPLAY_ENV: &str = "BSX_INPUT_REPLAY";

/// The senders of both devices, as the window and the feeders hold them.
#[derive(Debug, Clone)]
pub(crate) struct Inputs {
    pub(crate) keyboard: InputSender,
    pub(crate) pointer: InputSender,
}

impl Inputs {
    /// Queues `events` on `target`'s device; a full queue drops the report, as the window does.
    pub(crate) fn send(&self, target: Target, events: &[InputEvent]) {
        let sender = match target {
            Target::Keyboard => &self.keyboard,
            Target::Pointer => &self.pointer,
        };
        let _ = sender.send(events);
    }
}

/// The evdev code of a mouse button, or `None` for one the pointer does not emit.
pub(crate) fn button_code(button: MouseButton) -> Option<u16> {
    Some(bsx_input::button_code(match button {
        MouseButton::Left => Button::Left,
        MouseButton::Right => Button::Right,
        MouseButton::Middle => Button::Middle,
        MouseButton::Back => Button::Back,
        MouseButton::Forward => Button::Forward,
        MouseButton::Other(_) => return None,
    }))
}

/// Feeds the lines of `path` to the devices from a thread of its own, one event per line, until
/// the file ends. A FIFO blocks the open until its writer arrives, which is how a test waits for
/// the guest to be listening before it types.
pub(crate) fn replay(path: PathBuf, inputs: Inputs) -> io::Result<()> {
    std::thread::Builder::new()
        .name("bsx-input-replay".to_string())
        .spawn(move || {
            let Ok(file) = std::fs::File::open(&path) else {
                eprintln!(
                    "bsx __vmm: warning: {REPLAY_ENV}={} could not be opened; no input replayed",
                    path.display()
                );
                return;
            };
            feed(
                BufReader::new(file),
                |target, events| inputs.send(target, events),
                |line| eprintln!("bsx __vmm: warning: replay line ignored: {line:?}"),
            );
        })
        .map(drop)
}

/// Feeds the lines of an `input` session to the devices from a thread of its own until the
/// client hangs up.
pub(crate) fn serve(stream: UnixStream, inputs: Inputs) -> io::Result<()> {
    std::thread::Builder::new()
        .name("bsx-input-session".to_string())
        .spawn(move || {
            feed(
                BufReader::new(stream),
                |target, events| inputs.send(target, events),
                |line| eprintln!("bsx __vmm: warning: input line ignored: {line:?}"),
            );
        })
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// winit's buttons map to the codes the device advertises, and one it has no code for is
    /// no report.
    #[test]
    fn winit_buttons_map_to_the_devices_codes() {
        assert_eq!(button_code(MouseButton::Left), Some(bsx_input::BTN_LEFT));
        assert_eq!(button_code(MouseButton::Right), Some(bsx_input::BTN_RIGHT));
        assert_eq!(
            button_code(MouseButton::Middle),
            Some(bsx_input::BTN_MIDDLE)
        );
        assert_eq!(button_code(MouseButton::Back), Some(bsx_input::BTN_SIDE));
        assert_eq!(
            button_code(MouseButton::Forward),
            Some(bsx_input::BTN_EXTRA)
        );
        assert_eq!(button_code(MouseButton::Other(9)), None);
    }
}
