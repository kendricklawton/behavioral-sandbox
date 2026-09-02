//! Keyboard and pointer into the guest: the two virtio-input devices a display comes with, and
//! the translation from what winit reports to the evdev events they carry.
//!
//! - **Two devices of fixed shape.** A keyboard that emits every code a physical keyboard has,
//!   and an absolute pointer (a tablet, in evdev's terms) whose axes run `0..=ABS_MAX` whatever
//!   the window or the scanout measures, so a resize changes the scale and not the device.
//! - **Scancodes, not symbols.** winit reports the physical key, and on X11 and Wayland that is
//!   the evdev code; the guest applies its own keymap to it, as it would to a real keyboard.
//! - **Losing focus releases everything held.** The release of a key held across a focus change
//!   goes to another window, and a modifier the guest still thinks is down is the classic
//!   guest-input defect.
//! - **`BSX_INPUT_REPLAY`** names a file or FIFO of `kbd|ptr TYPE CODE VALUE` lines the helper
//!   feeds to the devices as a window would. It is the end-to-end test's way in on a runner with
//!   no display server, and the one way to drive the guest's input without one.

use std::collections::BTreeSet;
use std::io::{self, BufRead};
use std::path::PathBuf;

use bsx_krun::{AbsInfo, EV_ABS, EV_KEY, EV_REL, InputDevice, InputEvent, InputSender};
use winit::event::MouseButton;

use crate::window::Placement;

/// `BTN_LEFT`, and the four beside it.
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const BTN_SIDE: u16 = 0x113;
const BTN_EXTRA: u16 = 0x114;
/// `ABS_X` and `ABS_Y`.
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;
/// `REL_HWHEEL` and `REL_WHEEL`.
const REL_HWHEEL: u16 = 6;
const REL_WHEEL: u16 = 8;
/// `BUS_VIRTUAL`, the bus type of a device no wire carries.
const BUS_VIRTUAL: u16 = 6;
/// The vendor id the devices report: `bs`.
const VENDOR: u16 = 0x6273;
/// The largest key code the keyboard emits: the keyboard block of `linux/input-event-codes.h`,
/// below the button codes a pointer owns.
const KEY_LAST: u16 = 0xff;
/// The far end of each pointer axis. Every guest driver scales it to the screen, so no size of
/// window or scanout has to be known when the device is made.
pub(crate) const ABS_MAX: u32 = 32767;
/// The environment variable naming the replay source.
pub(crate) const REPLAY_ENV: &str = "BSX_INPUT_REPLAY";

/// The keyboard the guest sees.
pub(crate) fn keyboard() -> InputDevice {
    InputDevice::new("bsx keyboard")
        .serial("bsx-kbd")
        .ids(BUS_VIRTUAL, VENDOR, 1, 1)
        .keys(1..=KEY_LAST)
}

/// The pointer the guest sees: absolute position, five buttons, two wheels.
pub(crate) fn pointer() -> InputDevice {
    InputDevice::new("bsx pointer")
        .serial("bsx-ptr")
        .ids(BUS_VIRTUAL, VENDOR, 2, 1)
        .keys([BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA])
        .absolute_axis(ABS_X, AbsInfo::range(0, ABS_MAX))
        .absolute_axis(ABS_Y, AbsInfo::range(0, ABS_MAX))
        .relative_axes([REL_WHEEL, REL_HWHEEL])
}

/// The senders of both devices, as the window and the replay hold them.
#[derive(Debug, Clone)]
pub(crate) struct Inputs {
    pub(crate) keyboard: InputSender,
    pub(crate) pointer: InputSender,
}

/// A key report: press, release, or repeat of the key at evdev `scancode`, or `None` for a code
/// the keyboard does not emit.
pub(crate) fn key(scancode: u32, pressed: bool, repeat: bool) -> Option<[InputEvent; 2]> {
    let code = u16::try_from(scancode)
        .ok()
        .filter(|c| (1..=KEY_LAST).contains(c))?;
    let value = match (pressed, repeat) {
        (false, _) => 0,
        (true, false) => 1,
        (true, true) => 2,
    };
    Some([
        InputEvent::new(EV_KEY, code, value),
        InputEvent::syn_report(),
    ])
}

/// The evdev code of a mouse button, or `None` for one the pointer does not emit.
pub(crate) fn button_code(button: MouseButton) -> Option<u16> {
    Some(match button {
        MouseButton::Left => BTN_LEFT,
        MouseButton::Right => BTN_RIGHT,
        MouseButton::Middle => BTN_MIDDLE,
        MouseButton::Back => BTN_SIDE,
        MouseButton::Forward => BTN_EXTRA,
        MouseButton::Other(_) => return None,
    })
}

/// A button report.
pub(crate) fn button(code: u16, pressed: bool) -> [InputEvent; 2] {
    [
        InputEvent::new(EV_KEY, code, i32::from(pressed)),
        InputEvent::syn_report(),
    ]
}

/// A position report for the window pixel `(x, y)`, measured against where the frame sits:
/// the frame's left edge is `0`, its right edge `ABS_MAX`, and a pixel outside it is clamped to
/// the nearest edge rather than dropped, so a drag that leaves the frame keeps its button down
/// somewhere sensible.
pub(crate) fn position(x: f64, y: f64, place: Placement) -> [InputEvent; 3] {
    let axis = |v: f64, origin: u32, extent: u32| -> i32 {
        if extent < 2 {
            return 0;
        }
        let along = (v - f64::from(origin)) / f64::from(extent - 1) * f64::from(ABS_MAX);
        // Clamped first, so the cast has nothing to truncate.
        along.round().clamp(0.0, f64::from(ABS_MAX)) as i32
    };
    [
        InputEvent::new(EV_ABS, ABS_X, axis(x, place.x, place.width)),
        InputEvent::new(EV_ABS, ABS_Y, axis(y, place.y, place.height)),
        InputEvent::syn_report(),
    ]
}

/// A wheel report for `dx` and `dy` lines, or nothing when both round to zero.
pub(crate) fn wheel(dx: f32, dy: f32) -> Vec<InputEvent> {
    let mut report = Vec::with_capacity(3);
    // Clamped first, so the cast has nothing to truncate.
    let lines = |v: f32| v.round().clamp(-1000.0, 1000.0) as i32;
    if lines(dy) != 0 {
        report.push(InputEvent::new(EV_REL, REL_WHEEL, lines(dy)));
    }
    if lines(dx) != 0 {
        report.push(InputEvent::new(EV_REL, REL_HWHEEL, lines(dx)));
    }
    if !report.is_empty() {
        report.push(InputEvent::syn_report());
    }
    report
}

/// What the guest thinks is down, so a focus change can release it.
#[derive(Debug, Default)]
pub(crate) struct Held {
    keys: BTreeSet<u16>,
    buttons: BTreeSet<u16>,
}

impl Held {
    /// Records a key going down or up.
    pub(crate) fn key(&mut self, code: u16, pressed: bool) {
        if pressed {
            self.keys.insert(code);
        } else {
            self.keys.remove(&code);
        }
    }

    /// Records a button going down or up.
    pub(crate) fn button(&mut self, code: u16, pressed: bool) {
        if pressed {
            self.buttons.insert(code);
        } else {
            self.buttons.remove(&code);
        }
    }

    /// Releases everything held: the keyboard's report and the pointer's, each empty when
    /// nothing of its was down.
    pub(crate) fn release_all(&mut self) -> (Vec<InputEvent>, Vec<InputEvent>) {
        let release = |codes: &mut BTreeSet<u16>| -> Vec<InputEvent> {
            if codes.is_empty() {
                return Vec::new();
            }
            let mut report: Vec<InputEvent> = std::mem::take(codes)
                .into_iter()
                .map(|code| InputEvent::new(EV_KEY, code, 0))
                .collect();
            report.push(InputEvent::syn_report());
            report
        };
        (release(&mut self.keys), release(&mut self.buttons))
    }
}

/// Which device a replay line is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Keyboard,
    Pointer,
}

/// A replay line, `kbd|ptr TYPE CODE VALUE` in decimal, or `None` for anything else.
pub(crate) fn parse_replay_line(line: &str) -> Option<(Target, InputEvent)> {
    let mut words = line.split_whitespace();
    let target = match words.next()? {
        "kbd" => Target::Keyboard,
        "ptr" => Target::Pointer,
        _ => return None,
    };
    let type_ = words.next()?.parse().ok()?;
    let code = words.next()?.parse().ok()?;
    let value = words.next()?.parse().ok()?;
    if words.next().is_some() {
        return None;
    }
    Some((target, InputEvent::new(type_, code, value)))
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
            for line in io::BufReader::new(file).lines().map_while(Result::ok) {
                match parse_replay_line(&line) {
                    Some((Target::Keyboard, event)) => {
                        let _ = inputs.keyboard.send(&[event]);
                    }
                    Some((Target::Pointer, event)) => {
                        let _ = inputs.pointer.send(&[event]);
                    }
                    None if line.trim().is_empty() => {}
                    None => eprintln!("bsx __vmm: warning: replay line ignored: {line:?}"),
                }
            }
        })
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsx_krun::EV_SYN;

    fn place(x: u32, y: u32, width: u32, height: u32) -> Placement {
        Placement {
            x,
            y,
            width,
            height,
        }
    }

    /// A key report carries the scancode as the code, press as 1, repeat as 2, release as 0,
    /// and ends with a `SYN_REPORT`; a code outside the keyboard's block makes no report.
    #[test]
    fn a_key_report_is_the_scancode_and_a_syn() {
        let [k, syn] = key(30, true, false).expect("KEY_A");
        assert_eq!((k.type_, k.code, k.value), (EV_KEY, 30, 1));
        assert_eq!((syn.type_, syn.code, syn.value), (EV_SYN, 0, 0));
        assert_eq!(key(30, true, true).expect("repeat")[0].value, 2);
        assert_eq!(key(30, false, true).expect("release")[0].value, 0);
        assert_eq!(key(0, true, false), None, "KEY_RESERVED");
        assert_eq!(key(0x100, true, false), None, "a button code");
        assert_eq!(key(u32::MAX, true, false), None);
    }

    /// The pointer maps the frame's corners to the axis ends, the middle to the middle, and a
    /// pixel outside the frame to the nearest edge.
    #[test]
    fn a_position_is_measured_against_where_the_frame_sits() {
        let p = place(10, 20, 101, 51);
        let at = |x: f64, y: f64| {
            let [ax, ay, syn] = position(x, y, p);
            assert_eq!(
                (ax.type_, ax.code, ay.type_, ay.code),
                (EV_ABS, 0, EV_ABS, 1)
            );
            assert_eq!(syn.type_, EV_SYN);
            (ax.value, ay.value)
        };
        assert_eq!(at(10.0, 20.0), (0, 0), "top-left");
        assert_eq!(at(110.0, 70.0), (32767, 32767), "bottom-right");
        assert_eq!(at(60.0, 45.0), (16384, 16384), "middle, rounded");
        assert_eq!(at(0.0, 0.0), (0, 0), "left of and above the frame");
        assert_eq!(at(500.0, 500.0), (32767, 32767), "past the frame");
        assert_eq!(
            position(5.0, 5.0, place(0, 0, 0, 0))[0].value,
            0,
            "no frame is the origin, not a division by zero"
        );
        assert_eq!(position(5.0, 5.0, place(0, 0, 1, 1))[0].value, 0);
    }

    /// Buttons map to the `BTN_*` codes the device advertises, and a report is code and syn.
    #[test]
    fn buttons_map_to_the_codes_the_device_advertises() {
        assert_eq!(button_code(MouseButton::Left), Some(BTN_LEFT));
        assert_eq!(button_code(MouseButton::Right), Some(BTN_RIGHT));
        assert_eq!(button_code(MouseButton::Middle), Some(BTN_MIDDLE));
        assert_eq!(button_code(MouseButton::Back), Some(BTN_SIDE));
        assert_eq!(button_code(MouseButton::Forward), Some(BTN_EXTRA));
        assert_eq!(button_code(MouseButton::Other(9)), None);
        let [b, syn] = button(BTN_LEFT, true);
        assert_eq!(
            (b.type_, b.code, b.value, syn.type_),
            (EV_KEY, BTN_LEFT, 1, EV_SYN)
        );
        assert_eq!(button(BTN_LEFT, false)[0].value, 0);
    }

    /// A wheel report carries whole lines on the axes that moved and nothing when none did.
    #[test]
    fn a_wheel_report_carries_whole_lines_and_nothing_for_none() {
        assert!(wheel(0.0, 0.0).is_empty());
        assert!(wheel(0.2, -0.3).is_empty(), "less than a line is nothing");
        let up = wheel(0.0, 1.0);
        assert_eq!(up.len(), 2);
        assert_eq!(
            (up[0].type_, up[0].code, up[0].value),
            (EV_REL, REL_WHEEL, 1)
        );
        assert_eq!(up[1].type_, EV_SYN);
        let both = wheel(-2.0, 3.0);
        assert_eq!(both.len(), 3);
        assert_eq!((both[0].code, both[0].value), (REL_WHEEL, 3));
        assert_eq!((both[1].code, both[1].value), (REL_HWHEEL, -2));
    }

    /// Releasing everything held reports each key and button once, up, then holds nothing.
    #[test]
    fn a_focus_loss_releases_what_is_held_and_forgets_it() {
        let mut held = Held::default();
        assert_eq!(held.release_all(), (Vec::new(), Vec::new()));
        held.key(30, true);
        held.key(42, true);
        held.key(30, false);
        held.button(BTN_LEFT, true);
        let (keys, buttons) = held.release_all();
        assert_eq!(
            keys,
            [InputEvent::new(EV_KEY, 42, 0), InputEvent::syn_report()]
        );
        assert_eq!(
            buttons,
            [
                InputEvent::new(EV_KEY, BTN_LEFT, 0),
                InputEvent::syn_report()
            ]
        );
        assert_eq!(
            held.release_all(),
            (Vec::new(), Vec::new()),
            "nothing held now"
        );
    }

    /// A replay line is a device word and three decimal numbers, nothing more or less.
    #[test]
    fn a_replay_line_is_a_device_and_three_numbers() {
        assert_eq!(
            parse_replay_line("kbd 1 30 1"),
            Some((Target::Keyboard, InputEvent::new(EV_KEY, 30, 1)))
        );
        assert_eq!(
            parse_replay_line("  ptr 2 8 -1 "),
            Some((Target::Pointer, InputEvent::new(EV_REL, 8, -1)))
        );
        for bad in [
            "",
            "kbd",
            "kbd 1 30",
            "kbd 1 30 1 0",
            "mouse 1 30 1",
            "kbd a b c",
        ] {
            assert_eq!(parse_replay_line(bad), None, "{bad:?}");
        }
    }
}
