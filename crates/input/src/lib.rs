//! Keyboard and pointer into the guest: the two virtio-input devices a display comes with, the
//! reports they carry, and the line grammar those reports travel as between processes.
//!
//! - **Two devices of fixed shape.** A keyboard that emits every code a physical keyboard has,
//!   and an absolute pointer (a tablet, in evdev's terms) whose axes run `0..=ABS_MAX` whatever
//!   the window or the scanout measures, so a resize changes the scale and not the device.
//! - **Codes, not symbols.** A key is its evdev code. A toolkit that names the physical key by
//!   its UI Events `code` ("KeyA") gets the evdev code from [`key_code`]; the guest applies its
//!   own keymap to it, as it would to a real keyboard.
//! - **A feeder that ends releases everything it held.** The release of a key held across a
//!   focus change goes to another window, and a client that dies mid-drag never sends one; a
//!   modifier the guest still thinks is down is the classic guest-input defect. [`Held`] is the
//!   record and [`feed`] applies it when a stream of lines ends.
//! - **One grammar for every feeder.** `kbd|ptr TYPE CODE VALUE` lines, one event each, decimal:
//!   the replay file the helper reads and the `input` request on the control socket are the
//!   same lines into [`feed`].

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io::BufRead;

use bsx_krun::{AbsInfo, InputDevice};
pub use bsx_krun::{EV_ABS, EV_KEY, EV_REL, EV_SYN, InputEvent};

/// `BTN_LEFT`, and the four beside it.
pub const BTN_LEFT: u16 = 0x110;
/// `BTN_RIGHT`.
pub const BTN_RIGHT: u16 = 0x111;
/// `BTN_MIDDLE`.
pub const BTN_MIDDLE: u16 = 0x112;
/// `BTN_SIDE`, the back button.
pub const BTN_SIDE: u16 = 0x113;
/// `BTN_EXTRA`, the forward button.
pub const BTN_EXTRA: u16 = 0x114;
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
pub const ABS_MAX: u32 = 32767;
/// How many window pixels of scroll count as one wheel line, for a toolkit that reports pixels.
pub const WHEEL_LINE_PIXELS: f64 = 20.0;

/// The keyboard the guest sees.
#[must_use]
pub fn keyboard() -> InputDevice {
    InputDevice::new("bsx keyboard")
        .serial("bsx-kbd")
        .ids(BUS_VIRTUAL, VENDOR, 1, 1)
        .keys(1..=KEY_LAST)
}

/// The pointer the guest sees: absolute position, five buttons, two wheels.
#[must_use]
pub fn pointer() -> InputDevice {
    InputDevice::new("bsx pointer")
        .serial("bsx-ptr")
        .ids(BUS_VIRTUAL, VENDOR, 2, 1)
        .keys([BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA])
        .absolute_axis(ABS_X, AbsInfo::range(0, ABS_MAX))
        .absolute_axis(ABS_Y, AbsInfo::range(0, ABS_MAX))
        .relative_axes([REL_WHEEL, REL_HWHEEL])
}

/// The buttons the pointer has, as a toolkit names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Button {
    /// The primary button.
    Left,
    /// The secondary button.
    Right,
    /// The wheel button.
    Middle,
    /// The back thumb button.
    Back,
    /// The forward thumb button.
    Forward,
}

/// The evdev code of a button.
#[must_use]
pub fn button_code(button: Button) -> u16 {
    match button {
        Button::Left => BTN_LEFT,
        Button::Right => BTN_RIGHT,
        Button::Middle => BTN_MIDDLE,
        Button::Back => BTN_SIDE,
        Button::Forward => BTN_EXTRA,
    }
}

/// A key report: press, release, or repeat of the key at evdev `scancode`, or `None` for a code
/// the keyboard does not emit.
#[must_use]
pub fn key(scancode: u32, pressed: bool, repeat: bool) -> Option<[InputEvent; 2]> {
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

/// A button report.
#[must_use]
pub fn button(code: u16, pressed: bool) -> [InputEvent; 2] {
    [
        InputEvent::new(EV_KEY, code, i32::from(pressed)),
        InputEvent::syn_report(),
    ]
}

/// Where the frame sits in the window, in the window's own units: what a pointer position is
/// measured against.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Area {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

impl Area {
    /// An area at `(x, y)` of `width` by `height`.
    #[must_use]
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

/// A position report for the window point `(x, y)`, measured against where the frame sits: its
/// left edge is `0`, its right `ABS_MAX`, and a point outside is clamped to the nearest edge.
#[must_use]
pub fn position(x: f64, y: f64, area: Area) -> [InputEvent; 3] {
    let axis = |v: f64, origin: f64, extent: f64| -> i32 {
        if extent < 2.0 {
            return 0;
        }
        let along = (v - origin) / (extent - 1.0) * f64::from(ABS_MAX);
        // Clamped first, so the cast has nothing to truncate.
        along.round().clamp(0.0, f64::from(ABS_MAX)) as i32
    };
    [
        InputEvent::new(EV_ABS, ABS_X, axis(x, area.x, area.width)),
        InputEvent::new(EV_ABS, ABS_Y, axis(y, area.y, area.height)),
        InputEvent::syn_report(),
    ]
}

/// A wheel report for `dx` and `dy` lines, or nothing when both round to zero.
#[must_use]
pub fn wheel(dx: f32, dy: f32) -> Vec<InputEvent> {
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

/// What the guest thinks is down, so a focus change or a feeder's end can release it.
#[derive(Debug, Default)]
pub struct Held {
    keys: BTreeSet<u16>,
    buttons: BTreeSet<u16>,
}

impl Held {
    /// Records a key going down or up.
    pub fn key(&mut self, code: u16, pressed: bool) {
        if pressed {
            self.keys.insert(code);
        } else {
            self.keys.remove(&code);
        }
    }

    /// Records a button going down or up.
    pub fn button(&mut self, code: u16, pressed: bool) {
        if pressed {
            self.buttons.insert(code);
        } else {
            self.buttons.remove(&code);
        }
    }

    /// Records what a report says, on `target`'s device.
    pub fn note(&mut self, target: Target, event: &InputEvent) {
        if event.type_ != EV_KEY {
            return;
        }
        match target {
            Target::Keyboard => self.key(event.code, event.value != 0),
            Target::Pointer => self.button(event.code, event.value != 0),
        }
    }

    /// Releases everything held: the keyboard's report and the pointer's, each empty when
    /// nothing of its was down.
    pub fn release_all(&mut self) -> (Vec<InputEvent>, Vec<InputEvent>) {
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

/// Which device a line is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The keyboard.
    Keyboard,
    /// The pointer.
    Pointer,
}

impl Target {
    /// The word a line names this device by.
    #[must_use]
    pub fn as_word(self) -> &'static str {
        match self {
            Self::Keyboard => "kbd",
            Self::Pointer => "ptr",
        }
    }
}

/// A line, `kbd|ptr TYPE CODE VALUE` in decimal, or `None` for anything else.
#[must_use]
pub fn parse_line(line: &str) -> Option<(Target, InputEvent)> {
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

/// The line that carries `event` to `target`, without its newline.
#[must_use]
pub fn format_line(target: Target, event: &InputEvent) -> String {
    format!(
        "{} {} {} {}",
        target.as_word(),
        event.type_,
        event.code,
        event.value
    )
}

/// Feeds `lines` to `sink` until they end, one event per line, then releases whatever they left
/// held, so a feeder that dies mid-drag leaves no button down in the guest. `ignored` is told
/// each non-blank line that is not a report.
pub fn feed(
    lines: impl BufRead,
    mut sink: impl FnMut(Target, &[InputEvent]),
    mut ignored: impl FnMut(&str),
) {
    let mut held = Held::default();
    for line in lines.lines().map_while(Result::ok) {
        match parse_line(&line) {
            Some((target, event)) => {
                held.note(target, &event);
                sink(target, &[event]);
            }
            None if line.trim().is_empty() => {}
            None => ignored(&line),
        }
    }
    let (keys, buttons) = held.release_all();
    if !keys.is_empty() {
        sink(Target::Keyboard, &keys);
    }
    if !buttons.is_empty() {
        sink(Target::Pointer, &buttons);
    }
}

/// The evdev code of the physical key a UI Events `code` names (`"KeyA"`, `"Digit1"`,
/// `"Enter"`), the same name winit and iced give the variant, or `None` for a key the table has
/// no code for. The table is the Linux one winit applies under X11 and Wayland.
#[must_use]
pub fn key_code(name: &str) -> Option<u16> {
    Some(match name {
        "Escape" => 1,
        "Digit1" => 2,
        "Digit2" => 3,
        "Digit3" => 4,
        "Digit4" => 5,
        "Digit5" => 6,
        "Digit6" => 7,
        "Digit7" => 8,
        "Digit8" => 9,
        "Digit9" => 10,
        "Digit0" => 11,
        "Minus" => 12,
        "Equal" => 13,
        "Backspace" => 14,
        "Tab" => 15,
        "KeyQ" => 16,
        "KeyW" => 17,
        "KeyE" => 18,
        "KeyR" => 19,
        "KeyT" => 20,
        "KeyY" => 21,
        "KeyU" => 22,
        "KeyI" => 23,
        "KeyO" => 24,
        "KeyP" => 25,
        "BracketLeft" => 26,
        "BracketRight" => 27,
        "Enter" => 28,
        "ControlLeft" => 29,
        "KeyA" => 30,
        "KeyS" => 31,
        "KeyD" => 32,
        "KeyF" => 33,
        "KeyG" => 34,
        "KeyH" => 35,
        "KeyJ" => 36,
        "KeyK" => 37,
        "KeyL" => 38,
        "Semicolon" => 39,
        "Quote" => 40,
        "Backquote" => 41,
        "ShiftLeft" => 42,
        "Backslash" => 43,
        "KeyZ" => 44,
        "KeyX" => 45,
        "KeyC" => 46,
        "KeyV" => 47,
        "KeyB" => 48,
        "KeyN" => 49,
        "KeyM" => 50,
        "Comma" => 51,
        "Period" => 52,
        "Slash" => 53,
        "ShiftRight" => 54,
        "NumpadMultiply" => 55,
        "AltLeft" => 56,
        "Space" => 57,
        "CapsLock" => 58,
        "F1" => 59,
        "F2" => 60,
        "F3" => 61,
        "F4" => 62,
        "F5" => 63,
        "F6" => 64,
        "F7" => 65,
        "F8" => 66,
        "F9" => 67,
        "F10" => 68,
        "NumLock" => 69,
        "ScrollLock" => 70,
        "Numpad7" => 71,
        "Numpad8" => 72,
        "Numpad9" => 73,
        "NumpadSubtract" => 74,
        "Numpad4" => 75,
        "Numpad5" => 76,
        "Numpad6" => 77,
        "NumpadAdd" => 78,
        "Numpad1" => 79,
        "Numpad2" => 80,
        "Numpad3" => 81,
        "Numpad0" => 82,
        "NumpadDecimal" => 83,
        "Lang5" => 85,
        "IntlBackslash" => 86,
        "F11" => 87,
        "F12" => 88,
        "IntlRo" => 89,
        "Lang3" => 90,
        "Lang4" => 91,
        "Convert" => 92,
        "KanaMode" => 93,
        "NonConvert" => 94,
        "NumpadEnter" => 96,
        "ControlRight" => 97,
        "NumpadDivide" => 98,
        "PrintScreen" => 99,
        "AltRight" => 100,
        "Home" => 102,
        "ArrowUp" => 103,
        "PageUp" => 104,
        "ArrowLeft" => 105,
        "ArrowRight" => 106,
        "End" => 107,
        "ArrowDown" => 108,
        "PageDown" => 109,
        "Insert" => 110,
        "Delete" => 111,
        "AudioVolumeMute" => 113,
        "AudioVolumeDown" => 114,
        "AudioVolumeUp" => 115,
        "NumpadEqual" => 117,
        "Pause" => 119,
        "NumpadComma" => 121,
        "Lang1" => 122,
        "Lang2" => 123,
        "IntlYen" => 124,
        "SuperLeft" => 125,
        "SuperRight" => 126,
        "ContextMenu" => 127,
        "MediaTrackNext" => 163,
        "MediaPlayPause" => 164,
        "MediaTrackPrevious" => 165,
        "MediaStop" => 166,
        "F13" => 183,
        "F14" => 184,
        "F15" => 185,
        "F16" => 186,
        "F17" => 187,
        "F18" => 188,
        "F19" => 189,
        "F20" => 190,
        "F21" => 191,
        "F22" => 192,
        "F23" => 193,
        "F24" => 194,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// point outside the frame to the nearest edge.
    #[test]
    fn a_position_is_measured_against_where_the_frame_sits() {
        let a = Area::new(10.0, 20.0, 101.0, 51.0);
        let at = |x: f64, y: f64| {
            let [ax, ay, syn] = position(x, y, a);
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
            position(5.0, 5.0, Area::new(0.0, 0.0, 0.0, 0.0))[0].value,
            0,
            "no frame is the origin, not a division by zero"
        );
        assert_eq!(
            position(5.0, 5.0, Area::new(0.0, 0.0, 1.0, 1.0))[0].value,
            0
        );
    }

    /// Buttons map to the `BTN_*` codes the device advertises, and a report is code and syn.
    #[test]
    fn buttons_map_to_the_codes_the_device_advertises() {
        assert_eq!(button_code(Button::Left), BTN_LEFT);
        assert_eq!(button_code(Button::Right), BTN_RIGHT);
        assert_eq!(button_code(Button::Middle), BTN_MIDDLE);
        assert_eq!(button_code(Button::Back), BTN_SIDE);
        assert_eq!(button_code(Button::Forward), BTN_EXTRA);
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

    /// A line is a device word and three decimal numbers, nothing more or less, and a formatted
    /// line parses back to what it carried.
    #[test]
    fn a_line_is_a_device_and_three_numbers() {
        assert_eq!(
            parse_line("kbd 1 30 1"),
            Some((Target::Keyboard, InputEvent::new(EV_KEY, 30, 1)))
        );
        assert_eq!(
            parse_line("  ptr 2 8 -1 "),
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
            assert_eq!(parse_line(bad), None, "{bad:?}");
        }
        let event = InputEvent::new(EV_REL, REL_WHEEL, -3);
        assert_eq!(format_line(Target::Pointer, &event), "ptr 2 8 -3");
        assert_eq!(
            parse_line(&format_line(Target::Keyboard, &event)),
            Some((Target::Keyboard, event))
        );
    }

    /// The lines reach the sink one event each on the device they name; a bad line is reported
    /// and skipped; and when the lines end, whatever they left down is released.
    #[test]
    fn a_feed_ends_by_releasing_what_its_lines_left_down() {
        let lines = "kbd 1 30 1\nkbd 0 0 0\nptr 1 272 1\nptr 0 0 0\n\nnonsense here\nkbd 1 30 0\nkbd 0 0 0\n";
        let mut sunk = Vec::new();
        let mut bad = Vec::new();
        feed(
            lines.as_bytes(),
            |target, events| sunk.push((target, events.to_vec())),
            |line| bad.push(line.to_string()),
        );
        assert_eq!(bad, ["nonsense here"]);
        assert_eq!(sunk.len(), 7, "six lines, then the release: {sunk:?}");
        assert_eq!(
            sunk[6],
            (
                Target::Pointer,
                vec![
                    InputEvent::new(EV_KEY, BTN_LEFT, 0),
                    InputEvent::syn_report()
                ]
            ),
            "the button the lines left down is released; the key they released is not"
        );
    }

    /// The table names keys by their UI Events code and answers with the Linux evdev code.
    #[test]
    fn a_key_name_is_its_evdev_code() {
        assert_eq!(key_code("KeyA"), Some(30));
        assert_eq!(key_code("Enter"), Some(28));
        assert_eq!(key_code("Space"), Some(57));
        assert_eq!(key_code("F24"), Some(194));
        assert_eq!(key_code("Hyper"), None, "no Linux code");
        assert_eq!(key_code(""), None);
    }
}
