//! `Boxdesk`: the notebook. Runs on this machine, live and past, one row each; a run opens to
//! its record, and a live one to its display with the keyboard and pointer going in.
//!
//! - **Everything here the CLI can do.** The records are `boxdesk-record`'s, read straight from the
//!   runs directory; starting, stopping and a shell go through the `boxdesk` binary beside this one,
//!   so the app grows no verb the CLI lacks and an agent driving the CLI and a person at this
//!   window see one notebook.
//! - **Nothing leaves the machine.** The runs directory is local, the sockets are local, and the
//!   only processes started are `boxdesk` and, for a shell, the operator's terminal.
//! - **Bounded.** The list is what retention keeps, the output pane shows the tail of a file up
//!   to a fixed size, the frame history is capped, and a display lease is shut down when its run
//!   is left, so nothing grows with time in the window.
//! - **The frame logs are the measurement.** `--log`, `--drawn-log` and `--input-log` record the
//!   display path on the host's monotonic clock, as `cargo xtask bench-frames --app` reads them.
#![deny(unsafe_code)]

mod chrome;
mod cli;
mod fonts;
mod frame;
mod icons;
mod lease;
mod screens;
mod state;
mod theme;
mod timer;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use iced::animation::Easing;
use iced::{Animation, Element, Size, Subscription, Task};

use boxdesk_krun::SharedFrames;
use boxdesk_record::{Record, Store};
use boxdesk_supervisor::control::Damage;

/// Exit code for an operational failure, the CLI's convention.
const EXIT_OPERATIONAL: u8 = 2;

/// Presents the app remembers the damage of, so an upload after a run of missed redraws covers
/// exactly what changed since the frame it last uploaded.
const HISTORY: usize = 64;

/// The display a form offers before anyone changes it, and what a record without one falls back
/// to when it is re-run.
const DEFAULT_DISPLAY: &str = "640x480";

/// The limits a form offers before anyone changes it, and what a field nobody typed a number in
/// falls back to. Non-zero by type, as the record's own limits are.
pub(crate) const DEFAULT_VCPUS: std::num::NonZeroU8 = std::num::NonZeroU8::MIN;
pub(crate) const DEFAULT_MEM_MIB: std::num::NonZeroU32 = match std::num::NonZeroU32::new(512) {
    Some(mib) => mib,
    None => std::num::NonZeroU32::MIN,
};

/// Bytes of an output file the pane shows, from its end.
const OUTPUT_TAIL: u64 = 256 * 1024;

/// The shortest gap between two presents a thumbnail in the list is redrawn for. A thumbnail is
/// a glance, not a screen, and every present it takes is a whole window rebuild.
const THUMBNAIL_EVERY: std::time::Duration = std::time::Duration::from_millis(100);

/// The most live displays the list leases at once, newest first. Each costs a thread, a socket
/// and a scanout mapping.
const MAX_THUMBNAILS: usize = 12;

/// The grid's leases plus the open run must each have a texture to upload into, or the cache
/// thrashes. The compiler holds the two constants in step, so neither can be raised alone.
const _: () = assert!(MAX_THUMBNAILS < frame::MAX_TEXTURES);

/// What the platform calls this application: the name the packaged executable carries, which
/// macOS reads for the menu bar and the Dock and a desktop entry names in `Exec`.
///
/// Not `CARGO_BIN_NAME`. Cargo writes every binary of a workspace into one directory, and the
/// default macOS filesystem is case-insensitive, so a `Boxdesk` built beside `boxdesk` would be
/// the same file; the build keeps them apart and `cargo xtask dist` renames this one.
pub(crate) const NAME: &str = "Boxdesk";

/// The identifier the application registers under. The Linux window carries it, which is what
/// pairs the window with its desktop entry; xtask's bundle carries the same word as
/// `CFBundleIdentifier` and holds the two equal by reading this line.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const APP_ID: &str = "ai.boxdesk.app";

#[derive(Parser)]
#[command(
    name = NAME,
    version,
    about = "The notebook: sandboxes on this machine, live and past, and their displays."
)]
struct Cli {
    /// Open straight onto this run, by id or by name (the newest of that name), instead of the
    /// list.
    name: Option<String>,
    /// Append one `frame_id<TAB>nanoseconds` line here per present record read.
    #[arg(long, value_name = "PATH")]
    log: Option<PathBuf>,
    /// Append one `frame_id<TAB>nanoseconds` line here per frame uploaded to the GPU.
    #[arg(long, value_name = "PATH")]
    drawn_log: Option<PathBuf>,
    /// Append each input line sent to the guest here, as it went down the session.
    #[arg(long, value_name = "PATH")]
    input_log: Option<PathBuf>,
    /// Exit when the opened run's lease ends, as a measurement run wants; the default keeps the
    /// notebook open.
    #[arg(long)]
    exit_with_lease: bool,
    /// The mode to draw in: `light`, `dark`, or `system`, which follows the desktop. Case is
    /// ignored. Falls back to `$BOXDESK_THEME`, then to the pick in Settings, then to `system`. An
    /// unknown name is refused with the three.
    #[arg(long, value_name = "NAME")]
    theme: Option<String>,
    /// Open on this screen instead of the menu.
    #[arg(long, value_name = "SCREEN", conflicts_with = "name")]
    open: Option<OpenScreen>,
}

/// The screens the command line can open on: every one that needs no run to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OpenScreen {
    List,
    New,
    Settings,
}

impl OpenScreen {
    /// The [`Screen`] this asks for: the one place the two enums meet.
    fn screen(self) -> Screen {
        match self {
            Self::List => Screen::List,
            Self::New => Screen::New,
            // There is no settings screen to land on: `--open settings` opens the notebook with
            // the sheet over it, which `App::new` puts up.
            Self::Settings => Screen::List,
        }
    }

    /// The screen a saved `open` line names, through the flag's own parser.
    fn from_name(name: &str) -> Option<Self> {
        <Self as clap::ValueEnum>::from_str(name, true).ok()
    }
}

/// The flag's spelling, so the state file and `--open` share one grammar.
impl std::fmt::Display for OpenScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::List => "list",
            Self::New => "new",
            Self::Settings => "settings",
        })
    }
}

/// What the notebook's list is doing.
///
/// The selected ids live in the mode rather than beside it, so there is no selection to leave
/// behind when the list goes back to being read, and no third state where a stale set and a
/// cleared flag disagree. Only ended runs are ever in it: a live one is refused a delete anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListMode {
    /// Reading the list; pressing a row opens its run.
    Browsing,
    /// Selecting records to remove; pressing a row adds or removes it instead of opening it.
    Selecting(BTreeSet<String>),
}

/// One thing the window told the operator, and when it said it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    /// When it was said, milliseconds since the Unix epoch.
    pub(crate) at_ms: u64,
    /// What was said, in the words the status line used.
    pub(crate) text: String,
}

/// How many notices are kept. **A window that ran all week is not a log file**, and the ones worth
/// reading are the recent ones; the oldest go first when this is reached.
const NOTICES: usize = 200;

/// Where a problem is reported. The repository this build came from, which is the only address
/// this project has.
const ISSUES: &str = "https://github.com/kendricklawton/boxdesk/issues";

/// The settings a sheet edits, together, so a draft can be compared with what was there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Picks {
    pub(crate) mode: theme::Mode,
    pub(crate) scale: u16,
    pub(crate) opens_on: OpenScreen,
}

/// The settings sheet, and the picks the window had when it opened.
///
/// **A pick previews at once and is written down on Apply.** Trying a theme should show you the
/// theme, so every control here takes effect the moment it is pressed; what `Close` does is put
/// back what was there, which is what makes trying one free. Nothing reaches the state file until
/// `Apply`.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// What to put back if this sheet is closed rather than applied.
    was: Picks,
}

impl Settings {
    /// Whether anything has been changed since the sheet opened, which is what `Apply` is for.
    pub(crate) fn changed(&self, now: Picks) -> bool {
        self.was != now
    }
}

/// What a destructive press is waiting on, and the only thing that draws the modal.
///
/// **Nothing is removed until [`Message::DeleteConfirmed`] answers one of these.** One value for
/// both paths, so a window cannot end up asking two questions at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Confirm {
    /// One run, pressed on its own pane or in its row.
    One(RunId),
    /// The list's selection, which a cancel leaves selected.
    Selected(BTreeSet<String>),
    /// One volume, and everything in it. **A volume is the thing that was not ephemeral**, so
    /// this is the one question in the window whose answer destroys something a run had kept.
    Volume(String),
    /// Every ended run, with the count so the question can say how many.
    Swept(usize),
    /// Every store this project keeps. The largest answer in the window.
    Everything,
}

impl Confirm {
    /// How many records answering yes would remove.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::One(_) | Self::Volume(_) | Self::Everything => 1,
            Self::Selected(ids) => ids.len(),
            Self::Swept(n) => *n,
        }
    }
}

impl ListMode {
    /// The ids selected so far, empty while browsing.
    pub(crate) fn selected(&self) -> &BTreeSet<String> {
        match self {
            Self::Browsing => {
                static NONE: std::sync::LazyLock<BTreeSet<String>> =
                    std::sync::LazyLock::new(BTreeSet::new);
                &NONE
            }
            Self::Selecting(ids) => ids,
        }
    }

    /// Whether a row should answer a press by being selected rather than opened.
    pub(crate) fn is_selecting(&self) -> bool {
        matches!(self, Self::Selecting(_))
    }
}

/// An interface scale Settings offers, in percent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scale(pub(crate) u16);

impl std::fmt::Display for Scale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}%", self.0)
    }
}

/// The scales Settings offers.
pub(crate) const SCALES: [Scale; 4] = [Scale(90), Scale(100), Scale(110), Scale(125)];

/// The window as a source-list app opens one: on macOS the title is hidden and the titlebar is
/// transparent over the content, so the sidebar runs to the top with the traffic lights on it.
fn window_settings() -> iced::window::Settings {
    #[cfg(target_os = "macos")]
    let platform_specific = iced::window::settings::PlatformSpecific {
        title_hidden: true,
        titlebar_transparent: true,
        fullsize_content_view: true,
    };
    #[cfg(target_os = "linux")]
    let platform_specific = iced::window::settings::PlatformSpecific {
        application_id: APP_ID.to_string(),
        ..iced::window::settings::PlatformSpecific::default()
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let platform_specific = iced::window::settings::PlatformSpecific::default();
    iced::window::Settings {
        size: Size::new(1360.0, 860.0),
        min_size: Some(WINDOW_MIN),
        platform_specific,
        ..iced::window::Settings::default()
    }
}

/// The narrowest page this window is meant to draw: a card and the two gutters beside it. Below
/// this a line of prose is two words wide, which is not a layout but a failure of one.
const PAGE_MIN: f32 = 360.0;

/// The window will not be dragged narrower than the rail **and** a page beside it, nor shorter
/// than a card under a head. The rail is never folded for the person: a window that cannot hold
/// both is one this refuses to become, which is a floor rather than a layout that moves under
/// them.
const WINDOW_MIN: Size = Size::new(screens::SIDEBAR + PAGE_MIN + 2.0 * screens::GUTTER, 420.0);

/// Where a plain launch lands: the `--open` flag, else the saved pick, else the notebook.
fn landing(flag: Option<OpenScreen>, saved: Option<OpenScreen>) -> OpenScreen {
    flag.or(saved).unwrap_or(OpenScreen::List)
}

fn main() -> ExitCode {
    chrome::name_the_application();
    let cli = Cli::parse();
    // Before the adapter probe: a name this cannot resolve is a typo in an argument, and
    // answering it should not cost a GPU handle first.
    let asked = theme::asked_for(cli.theme.as_deref(), theme::from_env());
    let theme_overridden = asked.is_some();
    let saved = state::load();
    let (mode, theme_note) = match theme::startup(asked.as_deref(), saved.theme.as_deref()) {
        Ok(pair) => pair,
        Err(why) => {
            eprintln!("{NAME}: {why}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    frame::report_adapter();
    let sinks = match frame::Sinks::open(cli.drawn_log.as_deref(), cli.input_log.as_deref()) {
        Ok(sinks) => Arc::new(sinks),
        Err(e) => {
            eprintln!("{NAME}: opening a log: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let store = match Store::open() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("{NAME}: the runs directory: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let opening = cli.name.clone();
    let log = cli.log.clone();
    let exit_with_lease = cli.exit_with_lease;
    let open = cli.open;
    let scale = saved.scale.unwrap_or(100);
    let opens_on = saved.open.as_deref().and_then(OpenScreen::from_name);
    let panel = saved.panel;
    let boot = move || {
        let mut app = App::new(
            store.clone(),
            opening.clone(),
            log.clone(),
            Arc::clone(&sinks),
            exit_with_lease,
        );
        app.mode = mode;
        app.theme_overridden = theme_overridden;
        app.scale = scale;
        app.opens_on = opens_on.unwrap_or(OpenScreen::List);
        if let Some(panel) = panel {
            app.panel = screens::panel_within(panel);
        }
        if app.status.is_none() {
            app.status = theme_note.clone();
        }
        if opening.is_none() {
            app.set_screen(landing(open, opens_on).screen());
        }
        // Asked once here and followed by subscription after, so `System` is right from the
        // first frame rather than from the first change.
        (
            app,
            Task::batch([
                iced::system::theme().map(Message::DesktopTheme),
                // Both, because a window already open when this runs sends no `Opened` and one
                // opened after it is not `latest` yet.
                iced::window::latest()
                    .then(|id| id.map_or_else(Task::none, chrome::unify_titlebar)),
            ]),
        )
    };
    let ran = iced::application(boot, App::update, App::view)
        .subscription(App::subscription)
        .title(|app: &App| app.title())
        .theme(|app: &App| theme::theme(app.mode, app.desktop))
        // Before `.font`: `settings` replaces the whole set, fonts included.
        .settings(iced::Settings {
            default_text_size: iced::Pixels(screens::BODY),
            default_font: fonts::SANS,
            ..iced::Settings::default()
        })
        .font(icons::BYTES)
        .font(fonts::FACES[0])
        .font(fonts::FACES[1])
        .font(fonts::FACES[2])
        .font(fonts::FACES[3])
        .scale_factor(|app: &App| f32::from(app.scale) / 100.0)
        .window(window_settings())
        .run();
    match ran {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{NAME}: {e}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// A run's id: `<started_ms>-<name>`, which is also its directory under the runs directory.
///
/// Distinct from [`RunName`] by type because the id *contains* the name, so the two are freely
/// confusable as `String` and a mix-up is a silent lookup miss: a dead button, or a display that
/// never arrives. The record is the only place either is minted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RunId(String);

impl RunId {
    /// The id of `record`.
    pub(crate) fn of(record: &Record) -> Self {
        Self(record.id.clone())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A run's name: what its VM answers to on the control socket, and what a lease asks for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RunName(String);

impl RunName {
    /// The name of `record`.
    pub(crate) fn of(record: &Record) -> Self {
        Self(record.name.clone())
    }

    /// The name a started run reported, which is the only name minted outside a record.
    pub(crate) fn started(name: String) -> Self {
        Self(name)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RunName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which screen the window shows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Screen {
    /// The notebook: every run, newest first.
    List,
    /// One run's record, by id.
    Run(RunId),
    /// The form for a new run.
    New,
    /// The sandboxes worth making again, by name.
    Snapshots,
    /// Where images come from, and who this machine is when it asks.
    Registries,
    /// The form for a new registry.
    NewRegistry,
    /// Directories with lives of their own.
    Volumes,
    /// The form for a new volume.
    NewVolume,
}

/// Which captured file the output pane shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
    Shell,
    Exec,
}

impl Stream {
    /// The file this stream is in a run's directory.
    fn path(self, dir: &boxdesk_record::RunDir) -> PathBuf {
        match self {
            Self::Stdout => dir.stdout(),
            Self::Stderr => dir.stderr(),
            Self::Shell => dir.shell_log(),
            Self::Exec => dir.exec_log(),
        }
    }

    /// The streams a run of `verb` has.
    pub(crate) fn of(verb: boxdesk_record::Verb) -> &'static [Self] {
        match verb {
            boxdesk_record::Verb::Run => &[Self::Stdout, Self::Stderr],
            boxdesk_record::Verb::Shell => &[Self::Shell],
            boxdesk_record::Verb::Up => &[Self::Exec],
            _ => &[],
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Shell => "terminal",
            Self::Exec => "exec",
        }
    }
}

/// The tail of a captured file, as the pane shows it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Output {
    pub(crate) stream: Option<Stream>,
    pub(crate) text: String,
    /// Bytes the file holds in all.
    pub(crate) size: u64,
    /// Whether the record capped it.
    pub(crate) capped: bool,
}

/// The form for a new run, as text fields until it is started.
#[derive(Debug, Clone, Default)]
pub(crate) struct Form {
    pub(crate) name: String,
    pub(crate) root: String,
    pub(crate) writable_root: bool,
    pub(crate) command: String,
    pub(crate) mounts: String,
    pub(crate) shares: String,
    pub(crate) network: bool,
    pub(crate) display: bool,
    pub(crate) display_size: String,
    pub(crate) sound: bool,
    pub(crate) gpu: bool,
    pub(crate) results: bool,
    pub(crate) vcpus: String,
    pub(crate) mem_mib: String,
}

impl Form {
    fn blank() -> Self {
        Self {
            root: cli::default_root()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            display_size: DEFAULT_DISPLAY.to_string(),
            results: true,
            vcpus: DEFAULT_VCPUS.to_string(),
            mem_mib: DEFAULT_MEM_MIB.to_string(),
            ..Self::default()
        }
    }

    /// The form filled from a record, for a re-run: its command and posture again.
    fn from_record(record: &Record) -> Self {
        Self::from_posture(&record.posture, &record.command, String::new())
    }

    /// The form filled from a snapshot, which is what pressing one does: its posture, its command
    /// and its name, ready to be started or edited first.
    ///
    /// Through the same filler as [`from_record`](Self::from_record), because a snapshot and a
    /// record carry the same posture: two fillers would be two answers to one question, and the
    /// second is the one a new posture field gets missed in.
    fn from_snapshot(snapshot: &boxdesk_record::Snapshot) -> Self {
        Self::from_posture(&snapshot.posture, &snapshot.command, snapshot.name.clone())
    }

    /// The form a posture and a command describe, under `name`.
    fn from_posture(p: &boxdesk_record::Posture, command: &[String], name: String) -> Self {
        Self {
            name,
            root: p.root.display().to_string(),
            writable_root: p.rootfs == boxdesk_record::Rootfs::Writable,
            command: command.join(" "),
            mounts: p
                .mounts
                .iter()
                .map(|m| format!("{}={}", m.guest.display(), m.host.display()))
                .collect::<Vec<_>>()
                .join(" "),
            shares: p
                .shares
                .iter()
                .map(|s| format!("{}={}", s.tag, s.host.display()))
                .collect::<Vec<_>>()
                .join(" "),
            network: p.network == boxdesk_record::Network::Tsi,
            display: p.display.is_some(),
            display_size: p
                .display
                .map_or_else(|| DEFAULT_DISPLAY.to_string(), |d| d.as_spec()),
            sound: p.sound,
            gpu: p.gpu,
            results: p.results,
            vcpus: p.vcpus.to_string(),
            mem_mib: p.mem_mib.to_string(),
        }
    }
}

/// The fields of the add-a-registry form. Four boxes, because a registry record is four things
/// and a password is not one of them.
#[derive(Debug, Clone, Default)]
pub(crate) struct RegistryForm {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) project: String,
    pub(crate) username: String,
}

/// The boxes of the make-a-volume form. Two, because a volume is a name and a line about it; the
/// directory is made here and the contents arrive from a guest.
#[derive(Debug, Clone, Default)]
pub(crate) struct VolumeForm {
    pub(crate) name: String,
    pub(crate) about: String,
}

/// Which box of [`VolumeForm`] a keystroke went into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VolumeField {
    Name,
    About,
}

/// Which box of [`RegistryForm`] a keystroke went into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryField {
    Name,
    Url,
    Project,
    Username,
}

impl RegistryForm {
    /// The registry these boxes describe, or what is wrong with them.
    ///
    /// **Refused here rather than by the store**, so the message names the box to go back to: a
    /// name that is not a file name and a host that is empty are the two ways this goes wrong.
    fn registry(&self) -> Result<boxdesk_record::Registry, String> {
        let name = self.name.trim();
        let url = self.url.trim();
        if name.is_empty() {
            return Err("a registry needs a name to be listed under".to_string());
        }
        if !boxdesk_record::valid_id(name) {
            return Err(format!(
                "{name:?} is not a usable name: letters, digits, `-` and `_`"
            ));
        }
        if url.is_empty() {
            return Err("a registry needs a host, as it appears in an image reference".to_string());
        }
        Ok(boxdesk_record::Registry::new(name, url)
            .signed_in_as(self.project.trim(), self.username.trim()))
    }
}

/// A field of the form, for one message that carries any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    Name,
    Root,
    Command,
    Mounts,
    Shares,
    DisplaySize,
    Vcpus,
    Mem,
}

/// A switch of the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Switch {
    WritableRoot,
    Network,
    Display,
    Sound,
    Gpu,
    Results,
}

/// What the window reacts to.
#[derive(Debug, Clone)]
pub(crate) enum Message {
    /// A second passed: reread the notebook and the open run's output.
    Tick,
    /// A frame went up at this instant: the clock the sidebar's motion is read against.
    Drawn(std::time::Instant),
    /// A window is on screen: what its own chrome is settled on.
    Opened(iced::window::Id),
    /// The window changed size, which is also how it enters and leaves full screen.
    Resized(iced::window::Id),
    /// The head's own line was double-clicked, which is how a macOS window is zoomed.
    ZoomWindow,
    /// The head's quit control was pressed, where the platform draws no close button of its own.
    Quit,
    /// Whether the window is full screen, answered after a resize: the one thing that takes the
    /// platform's own buttons off the head's line while still drawing them elsewhere.
    Fullscreen(bool),
    Open(RunId),
    Back,
    List,
    Settings,
    /// A keyboard event every widget ignored: what the window's own chords read.
    Keyboard(iced::keyboard::Event),
    /// Draw in this mode from now on, and remember it.
    SetTheme(theme::Mode),
    /// The toolkit's report of what the desktop is showing, at start and on every change.
    DesktopTheme(iced::theme::Mode),
    /// Open the troubleshoot sheet, or close it.
    Troubleshoot,
    /// Put what this machine has on the clipboard, for pasting into a report.
    CopyDiagnostics,
    /// Show the directory everything is kept in.
    RevealData,
    /// Open where a problem is reported.
    ReportProblem,
    /// Ask before removing every ended run.
    SweepEnded,
    /// Ask before removing every store this project keeps.
    ResetEverything,
    /// Open the notifications panel, or close it.
    Notifications,
    /// Forget everything the window has said.
    ClearNotices,
    /// The panel's edge was taken hold of.
    PanelGrabbed,
    /// The pointer moved while the edge was held.
    PanelDragged(iced::Point),
    /// The edge was let go, or the pointer left the window still holding it.
    PanelDropped,
    /// Put back what the settings were when the sheet opened, and take it down.
    SettingsClosed,
    /// Write the settings down, and take the sheet down.
    SettingsApplied,
    /// Draw at this scale from now on, and remember it.
    SetScale(Scale),
    /// Open the next plain launch on this screen, and remember it.
    SetOpensOn(OpenScreen),
    /// Every setting back to what a fresh install has, and remembered so.
    ResetSettings,
    /// Fold the sidebar away, or bring it back.
    ToggleSidebar,
    /// The band's field was typed in: narrow the list to this.
    Search(String),
    /// Put the cursor in the band's field, which is what the chord it advertises does.
    FocusSearch,
    /// The pointer arrived on the fold, or left it: whether to draw the control there.
    HoverDivider(bool),
    NewRun,
    /// Open the snapshots.
    Snapshots,
    /// Open the registries.
    Registries,
    /// Take a registry away. The images already pulled from it are untouched.
    ForgetRegistry(String),
    /// Open the form for a new registry.
    NewRegistry,
    /// A box of that form was typed in.
    RegistryField(RegistryField, String),
    /// Write the form as a registry.
    AddRegistry,
    /// Open the volumes.
    Volumes,
    /// Open the form for a new volume.
    NewVolume,
    /// A box of that form was typed in.
    VolumeField(VolumeField, String),
    /// Make the volume the form describes.
    AddVolume,
    /// Ask before taking a volume and everything in it away.
    ForgetVolume(String),
    /// Fill the start form from a snapshot and show it, rather than starting it.
    UseSnapshot(String),
    /// Write the start form as a snapshot, under the name the form carries.
    SaveSnapshot,
    /// Take a snapshot away. The sandboxes already made from it are untouched.
    ForgetSnapshot(String),
    Field(Field, String),
    Switch(Switch, bool),
    Start,
    Started(Result<RunName, String>),
    Stop(RunName),
    Acted(Result<String, String>),
    Shell(RunName),
    Rerun(RunId),
    Delete(RunId),
    /// Start selecting records to remove.
    Select,
    /// Add or remove one record from the selection.
    SelectToggle(RunId),
    /// Select every ended run, or none of them.
    SelectAll(bool),
    /// Stop selecting and keep everything.
    SelectCancelled,
    /// Ask before removing what was selected.
    RemoveSelected,
    /// Remove what the modal is asking about.
    DeleteConfirmed,
    /// Put the modal away and remove nothing.
    DeleteCancelled,
    /// Write the run's directory as a tar file where a person can pick it up.
    Export(RunId),
    Show(Stream),
    /// A run's lease landed and its memfd is mapped.
    Mapped(RunName, Arc<SharedFrames>),
    /// A run presented a frame into `slot`.
    Presented {
        name: RunName,
        frame_id: u32,
        slot: u32,
        damage: Damage,
    },
    /// A run's input session is open: these are the lines its keyboard and pointer become.
    Input(
        RunName,
        iced::futures::channel::mpsc::UnboundedSender<String>,
    ),
    /// Something the operator should see in the window rather than on a stderr they may not have.
    Note(String),
    /// A run's lease ended, with why; the sandbox stopping is the ordinary case.
    Ended(RunName, String),
}

pub(crate) struct App {
    store: Store,
    /// Where the snapshots are, or `None` on a machine with nowhere to put them. The window still
    /// opens without one: a notebook that refused to start because a directory could not be named
    /// would be a notebook nobody could read their runs in.
    snapshots_store: Option<boxdesk_record::SnapshotStore>,
    /// Every snapshot, by name, as of the last tick.
    snapshots: Vec<boxdesk_record::Snapshot>,
    /// Where the registries are, `None` on a machine with nowhere to keep them.
    registries_store: Option<boxdesk_record::RegistryStore>,
    /// Every registry, by name, as of the last tick.
    registries: Vec<boxdesk_record::Registry>,
    /// Where the volumes are, `None` on a machine with nowhere to keep them.
    volumes_store: Option<boxdesk_record::VolumeStore>,
    /// Every volume, by name, with what it holds, as of the last tick.
    volumes: Vec<(boxdesk_record::Volume, u64)>,
    screen: Screen,
    /// Every run, newest first, as of the last tick.
    runs: Vec<Record>,
    /// The names answering on their control sockets as of the last tick.
    live: BTreeSet<RunName>,
    /// Where `boxdesk` and the guest root are, as of the last tick: what the menu reports.
    platform: cli::Platform,
    form: Form,
    /// The boxes of the add-a-registry form.
    registry_form: RegistryForm,
    /// The boxes of the make-a-volume form.
    volume_form: VolumeForm,
    /// The last thing worth telling the operator: an error, or what just happened.
    status: Option<String>,
    output: Output,
    /// The shown run's result files, as of the last tick. Held here rather than read in `view`,
    /// which iced rebuilds once per message: with a guest presenting frames that is a directory
    /// walk per frame.
    results: Vec<(PathBuf, u64)>,
    log: Option<PathBuf>,
    sinks: Arc<frame::Sinks>,
    /// The display of every run this window is leasing, by name: the one on screen, and every
    /// live run with a display when the list is showing its grid.
    displays: BTreeMap<RunName, Display>,
    exit_with_lease: bool,
    /// The mode every view draws in; Settings changes it live.
    mode: theme::Mode,
    /// What the desktop is showing, as the toolkit last reported it: what `System` follows.
    desktop: iced::theme::Mode,
    /// Whether --theme or $BOXDESK_THEME set it, which outranks a pick at the next launch.
    theme_overridden: bool,
    /// The interface scale in percent; Settings changes it live.
    scale: u16,
    /// The screen a plain launch opens on: the saved pick Settings shows and writes.
    opens_on: OpenScreen,
    /// Whether the list is asking "really clear the history?". Leaving the list disarms it.
    list: ListMode,
    /// The question a destructive press is waiting on. `None` is a window with nothing to answer,
    /// and is the only state in which anything can be removed.
    confirm: Option<Confirm>,
    /// The settings sheet, while one is up. A sheet rather than a screen, so what it is changing
    /// stays visible behind it.
    settings: Option<Settings>,
    /// Everything the window has said, newest first. **The status line holds one thing and the
    /// next thing destroys it**; this is where the one before went.
    notices: Vec<Notice>,
    /// How many have arrived since the panel was last opened.
    unread: usize,
    /// Whether the notifications panel is open.
    notices_open: bool,
    /// Whether the troubleshoot sheet is open.
    trouble_open: bool,
    /// How wide that panel is, in logical pixels, which the divider beside it drags.
    panel: f32,
    /// Where the pointer was at the last move of a divider drag, or `None` when none is under
    /// way. A drag is tracked as a delta, so it needs no knowledge of how wide the window is.
    dragging: Option<f32>,
    /// Whether the sidebar is out, and where it stands while that is changing.
    sidebar: Animation<bool>,
    /// The instant the last frame was drawn at, which every animation is read at.
    now: std::time::Instant,
    /// The window this is drawing in, once it is open: what a zoom is asked of.
    window: Option<iced::window::Id>,
    /// What the band's field holds: the words the list is narrowed by. Not saved, because a
    /// filter is what is being looked at now rather than how this window is set up.
    search: String,
    /// Whether the pointer is on the fold, which is the only thing that draws the control there.
    divider_hovered: bool,
    /// Whether the window is full screen. Only macOS moves its buttons off the head's line for
    /// it, but the field is not `cfg`-gated: a screen asks [`lights`](Self::lights), and one
    /// answer for every platform is one layout to reason about.
    fullscreen: bool,
}

/// One leased display: what was mapped for it, the presents it has reported, and where its input
/// goes.
struct Display {
    frames: Arc<SharedFrames>,
    history: Arc<std::collections::VecDeque<frame::Present>>,
    input: Option<iced::futures::channel::mpsc::UnboundedSender<String>>,
    read: u64,
}

impl App {
    fn new(
        store: Store,
        opening: Option<String>,
        log: Option<PathBuf>,
        sinks: Arc<frame::Sinks>,
        exit_with_lease: bool,
    ) -> Self {
        let mut app = Self {
            store,
            snapshots_store: boxdesk_record::SnapshotStore::open().ok(),
            snapshots: Vec::new(),
            registries_store: boxdesk_record::RegistryStore::open().ok(),
            registries: Vec::new(),
            volumes_store: boxdesk_record::VolumeStore::open().ok(),
            volumes: Vec::new(),
            screen: Screen::List,
            runs: Vec::new(),
            live: BTreeSet::new(),
            platform: cli::Platform::default(),
            form: Form::blank(),
            registry_form: RegistryForm::default(),
            volume_form: VolumeForm::default(),
            status: None,
            output: Output::default(),
            results: Vec::new(),
            log,
            sinks,
            displays: BTreeMap::new(),
            exit_with_lease,
            mode: theme::Mode::default(),
            desktop: iced::theme::Mode::None,
            theme_overridden: false,
            scale: 100,
            opens_on: OpenScreen::List,
            list: ListMode::Browsing,
            confirm: None,
            settings: None,
            notices: Vec::new(),
            unread: 0,
            notices_open: false,
            trouble_open: false,
            panel: screens::PANEL_DEFAULT,
            dragging: None,
            sidebar: Animation::new(true).quick().easing(Easing::EaseInOut),
            now: std::time::Instant::now(),
            window: None,
            // A window opens windowed; the first resize answers for the rest.
            search: String::new(),
            divider_hovered: false,
            fullscreen: false,
        };
        app.refresh();
        if let Some(key) = opening {
            let found = app
                .runs
                .iter()
                .find(|r| r.id == key)
                .or_else(|| app.runs.iter().find(|r| r.name == key))
                .map(RunId::of);
            match found {
                Some(id) => app.open(id),
                None => app.status = Some(format!("no run named or numbered {key:?}")),
            }
        }
        app
    }

    fn title(&self) -> String {
        match &self.screen {
            Screen::List => format!("{NAME} › sandboxes"),
            Screen::New => format!("{NAME} › new run"),
            Screen::Snapshots => format!("{NAME} › snapshots"),
            Screen::Registries => format!("{NAME} › registries"),
            Screen::NewRegistry => format!("{NAME} › new registry"),
            Screen::Volumes => format!("{NAME} › volumes"),
            Screen::NewVolume => format!("{NAME} › new volume"),
            Screen::Run(id) => format!(
                "{NAME} › {}",
                self.record(id).map_or(id.as_str(), |r| r.name.as_str())
            ),
        }
    }

    /// The room the window's own buttons take on the head's line, right now: none in full
    /// screen, where macOS hides the titlebar carrying them, and none where the platform never
    /// drew them on that line.
    pub(crate) fn lights(&self) -> f32 {
        if self.fullscreen {
            0.0
        } else {
            chrome::LIGHTS / self.scale_factor()
        }
    }

    /// What every layout length is multiplied by before it is drawn, which is what Settings'
    /// scale sets.
    ///
    /// **Anything that has to line up with the platform's own chrome is divided by this.** The
    /// window's buttons are drawn by macOS in the window's own points and do not scale with the
    /// app's; a length handed to the toolkit is in points the toolkit then scales. So 91 of room
    /// asked for at 125% reserved 114 of window for buttons that still took 91, and the band's
    /// own height stretched past the line the buttons sit on. Dividing turns a measurement of the
    /// platform's chrome into the length that draws as that measurement.
    pub(crate) fn scale_factor(&self) -> f32 {
        f32::from(self.scale) / 100.0
    }

    /// What the band's field holds, for the field to draw.
    pub(crate) fn search(&self) -> &str {
        &self.search
    }

    /// Whether the fold is showing the control that works it.
    pub(crate) fn divider_hovered(&self) -> bool {
        self.divider_hovered
    }

    /// The mode the band's sun-and-moon steps to: the next of [`theme::MODES`], wrapping, so one
    /// glyph walks the three rather than the band carrying a picker Settings already has.
    pub(crate) fn next_mode(&self) -> theme::Mode {
        let modes = theme::MODES;
        let at = modes.iter().position(|m| *m == self.mode).unwrap_or(0);
        modes[(at + 1) % modes.len()]
    }

    /// Whether `record` is one of what the band's field is asking for: its name or the command it
    /// ran holding the words typed, folded to one case so a name is found however it is spelled.
    ///
    /// An empty field asks for everything, which is what makes the field's absence and its being
    /// empty the same list.
    /// Every snapshot, by name, as of the last tick.
    pub(crate) fn snapshots(&self) -> &[boxdesk_record::Snapshot] {
        &self.snapshots
    }

    /// The boxes of the add-a-registry form, as they stand.
    pub(crate) fn registry_form(&self) -> &RegistryForm {
        &self.registry_form
    }

    /// Every registry, by name, as of the last tick.
    pub(crate) fn registries(&self) -> &[boxdesk_record::Registry] {
        &self.registries
    }

    /// Every volume, by name, with what it holds, as of the last tick.
    pub(crate) fn volumes(&self) -> &[(boxdesk_record::Volume, u64)] {
        &self.volumes
    }

    /// The boxes of the make-a-volume form, as they stand.
    pub(crate) fn volume_form(&self) -> &VolumeForm {
        &self.volume_form
    }

    /// Whether a volume answers the band's field: its name and the line beside it.
    pub(crate) fn matches_volume(&self, volume: &boxdesk_record::Volume) -> bool {
        asked_for(&self.search, &format!("{} {}", volume.name, volume.about))
    }

    /// Whether a registry answers the band's field: its name, its host and its project.
    pub(crate) fn matches_registry(&self, registry: &boxdesk_record::Registry) -> bool {
        asked_for(
            &self.search,
            &format!(
                "{} {} {} {}",
                registry.name, registry.url, registry.project, registry.username
            ),
        )
    }

    /// Whether a snapshot answers the band's field, by the same rule a run does: its name and the
    /// words beside it, every word of the search present somewhere.
    pub(crate) fn matches_snapshot(&self, snapshot: &boxdesk_record::Snapshot) -> bool {
        asked_for(
            &self.search,
            &format!("{} {}", snapshot.name, snapshot.about),
        )
    }

    pub(crate) fn matches_search(&self, record: &Record) -> bool {
        asked_for(
            &self.search,
            &format!("{} {}", record.name, record.command.join(" ")),
        )
    }

    /// The ids a selection may hold: every run that has ended. A live run is refused a delete, so
    /// offering it would be offering something the press cannot do.
    pub(crate) fn removable(&self) -> impl Iterator<Item = String> + '_ {
        self.runs
            .iter()
            .filter(|r| !self.is_live(r))
            .map(|r| r.id.clone())
    }

    /// How far the sidebar is out: 0 folded away, 1 all the way, and between while it moves.
    pub(crate) fn sidebar_out(&self) -> f32 {
        self.sidebar.interpolate(0.0, 1.0, self.now)
    }

    /// The record with `id`, from the last tick.
    pub(crate) fn record(&self, id: &RunId) -> Option<&Record> {
        self.runs.iter().find(|r| r.id == id.as_str())
    }

    /// Whether the run with `id` is answering now.
    pub(crate) fn is_live(&self, record: &Record) -> bool {
        record.is_open() && self.live.contains(&RunName::of(record))
    }

    /// Rereads the notebook: the records, which names answer, and marks the open records whose
    /// VM does not answer as gone (the one bookkeeping a listing does, as `boxdesk ls --all`).
    fn refresh(&mut self) {
        self.platform = cli::probe();
        self.live = boxdesk_supervisor::discover::live()
            .map(|found| {
                found
                    .into_iter()
                    .map(|f| RunName::started(f.name))
                    .collect()
            })
            .unwrap_or_default();
        self.snapshots = self
            .snapshots_store
            .as_ref()
            .map(boxdesk_record::SnapshotStore::list)
            .unwrap_or_default();
        self.registries = self
            .registries_store
            .as_ref()
            .map(boxdesk_record::RegistryStore::list)
            .unwrap_or_default();
        // The size is walked here, once a tick, rather than in `view`, which iced rebuilds on
        // every message: a directory walk per frame is what that would be.
        self.volumes = self
            .volumes_store
            .as_ref()
            .map(|store| {
                store
                    .list()
                    .into_iter()
                    .map(|v| {
                        let held = store.size_of(&v.name);
                        (v, held)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut runs = self.store.list().unwrap_or_default();
        settle_gone(&self.store, &mut runs, &self.live);
        runs.sort_by(|a, b| b.started_ms.cmp(&a.started_ms).then(b.id.cmp(&a.id)));
        self.runs = runs;
        if let Screen::Run(id) = &self.screen {
            let id = id.clone();
            self.reload_output(&id);
        }
        self.forget_unwatched();
    }

    /// Rereads the tail of the shown stream of run `id`, and the results the guest has written.
    fn reload_output(&mut self, id: &RunId) {
        let Some(record) = self.record(id) else {
            self.output = Output::default();
            self.results = Vec::new();
            return;
        };
        let streams = Stream::of(record.verb);
        let stream = match self.output.stream {
            Some(s) if streams.contains(&s) => Some(s),
            _ => streams.first().copied(),
        };
        let dir = self.store.dir_of(id.as_str());
        self.results = dir.result_files().unwrap_or_default();
        self.output = match stream {
            Some(stream) => {
                let path = stream.path(&dir);
                let (text, size) = tail_of(&path, OUTPUT_TAIL);
                Output {
                    stream: Some(stream),
                    text,
                    size,
                    capped: path.with_extension("truncated").exists(),
                }
            }
            None => Output::default(),
        };
    }

    /// Opens run `id`: the record, its output, and its display if it is live and has one.
    fn open(&mut self, id: RunId) {
        self.leave();
        self.set_screen(Screen::Run(id.clone()));
        self.output.stream = None;
        self.reload_output(&id);
    }

    /// Leaves whatever run is shown. The leases the next screen does not want end with their
    /// subscriptions, and [`Self::forget_unwatched`] drops what was mapped for them.
    fn leave(&mut self) {
        self.results = Vec::new();
    }

    /// Every live run with a display, newest first: what the list's grid shows a frame for.
    fn showing_displays(&self) -> Vec<&Record> {
        self.runs
            .iter()
            .filter(|r| self.is_live(r) && r.posture.display.is_some())
            .collect()
    }

    /// The runs to lease and how often each wants a present: the open run at the guest's pace,
    /// every other live display at [`THUMBNAIL_EVERY`].
    fn watches(&self) -> Vec<lease::Watch> {
        let open = match &self.screen {
            Screen::Run(id) => self.record(id).map(RunName::of),
            Screen::Snapshots
            | Screen::Registries
            | Screen::NewRegistry
            | Screen::Volumes
            | Screen::NewVolume => {
                return Vec::new();
            }
            Screen::List | Screen::New => None,
        };
        let mut watches = Vec::new();
        if let Some(name) = &open {
            if self
                .record_by_name(name)
                .is_some_and(|r| self.is_live(r) && r.posture.display.is_some())
            {
                watches.push(lease::Watch {
                    name: name.clone(),
                    log: self.log.clone(),
                    every: std::time::Duration::ZERO,
                });
            }
            return watches;
        }
        for record in self.showing_displays().into_iter().take(MAX_THUMBNAILS) {
            watches.push(lease::Watch {
                name: RunName::of(record),
                log: None,
                every: THUMBNAIL_EVERY,
            });
        }
        watches
    }

    /// Moves to `screen` and settles what is leased for it.
    fn set_screen(&mut self, screen: Screen) {
        self.list = ListMode::Browsing;
        self.screen = screen;
        self.forget_unwatched();
    }

    /// What Settings persists, gathered whole so every save writes every knob.
    /// The settings as they stand, which is what a sheet drafts against.
    pub(crate) fn picks(&self) -> Picks {
        Picks {
            mode: self.mode,
            scale: self.scale,
            opens_on: self.opens_on,
        }
    }

    /// Puts `picks` back, without writing anything down: what closing a sheet does.
    fn restore(&mut self, picks: Picks) {
        self.mode = picks.mode;
        self.scale = picks.scale;
        self.opens_on = picks.opens_on;
    }

    /// The settings sheet, while one is up.
    pub(crate) fn settings_sheet(&self) -> Option<&Settings> {
        self.settings.as_ref()
    }

    /// Whether the troubleshoot sheet is open.
    pub(crate) fn trouble_open(&self) -> bool {
        self.trouble_open
    }

    /// Every directory this project keeps something in, by the name it is known by.
    ///
    /// **One list, because two would be a reset that missed one.** The page that says where
    /// things are and the act that removes them read the same list, so a store added to the
    /// project and forgotten here would be visibly missing from both rather than quietly
    /// surviving a wipe.
    pub(crate) fn data_dirs(&self) -> Vec<(&'static str, PathBuf)> {
        let each: [(&str, std::io::Result<PathBuf>); 5] = [
            ("runs", boxdesk_record::runs_dir()),
            ("snapshots", boxdesk_record::snapshots_dir()),
            ("registries", boxdesk_record::registries_dir()),
            ("volumes", boxdesk_record::volumes_dir()),
            ("images", boxdesk_record::images_dir()),
        ];
        each.into_iter()
            .filter_map(|(name, dir)| dir.ok().map(|dir| (name, dir)))
            .collect()
    }

    /// What this machine has, as the text somebody pastes into a report.
    ///
    /// **Paths and counts, never contents.** A run's command, a registry's username and what a
    /// guest wrote are this person's business; what a report needs is which build, which host,
    /// and how much of what is where.
    pub(crate) fn diagnostics(&self) -> String {
        let mut out = format!(
            "boxdesk {}\nhost {} {}\n",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        );
        out.push_str(&format!(
            "cli {}\n",
            self.platform
                .boxdesk
                .as_ref()
                .map_or_else(|| "not found".to_string(), |p| p.display().to_string())
        ));
        out.push_str(&format!("guest root {}\n", self.platform.root.spelled()));
        out.push_str(&format!(
            "runs {} ({} live)\nsnapshots {}\nregistries {}\nvolumes {}\n",
            self.runs.len(),
            self.live.len(),
            self.snapshots.len(),
            self.registries.len(),
            self.volumes.len(),
        ));
        for (name, dir) in self.data_dirs() {
            out.push_str(&format!("{name} dir {}\n", dir.display()));
        }
        out
    }

    /// Removes every store this project keeps, and reports what went.
    ///
    /// **Each directory by name, never a computed parent.** `$BOXDESK_RUNS_DIR` can point
    /// anywhere, so reaching for its parent and handing that to `remove_dir_all` would be a reset
    /// that removed whatever happened to be beside it.
    fn wipe(&mut self) -> String {
        let mut gone = Vec::new();
        let mut failed: Option<String> = None;
        for (name, dir) in self.data_dirs() {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => gone.push(name),
                // One that was never there is one already in the state being asked for.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => gone.push(name),
                Err(e) => {
                    failed.get_or_insert_with(|| format!("{name}: {e}"));
                }
            }
        }
        self.mode = theme::Mode::default();
        self.scale = 100;
        self.opens_on = OpenScreen::List;
        self.panel = screens::PANEL_DEFAULT;
        let _ = state::save(&self.saved());
        self.refresh();
        match failed {
            Some(why) => format!("removed {}, then {why}", gone.join(", ")),
            None => format!("removed {}, and put the settings back", gone.join(", ")),
        }
    }

    /// Everything the window has said, newest first.
    pub(crate) fn notices(&self) -> &[Notice] {
        &self.notices
    }

    /// How many have arrived since the panel was last opened.
    pub(crate) fn unread(&self) -> usize {
        self.unread
    }

    /// Whether the notifications panel is open.
    pub(crate) fn notices_open(&self) -> bool {
        self.notices_open
    }

    /// How wide that panel is.
    pub(crate) fn panel(&self) -> f32 {
        self.panel
    }

    /// Whether the panel's edge is being dragged.
    pub(crate) fn dragging(&self) -> bool {
        self.dragging.is_some()
    }

    /// Keeps `text` as a notice, newest first, dropping the oldest past [`NOTICES`].
    fn note(&mut self, text: String) {
        self.notices.insert(
            0,
            Notice {
                at_ms: boxdesk_record::now_ms(),
                text,
            },
        );
        self.notices.truncate(NOTICES);
        // Read as it arrives when the panel is open, so the bell is not marked for something the
        // reader is already looking at.
        if !self.notices_open {
            self.unread += 1;
        }
    }

    /// Sets the status line and keeps `text` as a notice.
    fn notify(&mut self, text: String) {
        self.status = Some(text.clone());
        self.note(text);
    }

    /// What a pick does: previewed while a sheet is up, written down at once when one is not.
    ///
    /// **The band's theme toggle is the reason for the second half.** It is not part of the sheet,
    /// so pressing it is a decision rather than a draft, and it should survive the next launch
    /// without anybody pressing Apply.
    fn picked(&mut self, said: String) {
        if self.settings.is_some() {
            self.status = None;
            return;
        }
        match state::save(&self.saved()) {
            Ok(()) => self.status = Some(said),
            Err(e) => self.notify(format!("{said} for this window; not saved: {e}")),
        }
    }

    fn saved(&self) -> state::Saved {
        state::Saved {
            theme: Some(self.mode.to_string()),
            scale: Some(self.scale),
            open: Some(self.opens_on.to_string()),
            panel: Some(self.panel),
        }
    }

    /// Whether this run happened somewhere else, so the buttons that reach a control socket are
    /// not offered for it.
    ///
    /// A remote run can be read, exported and re-run here; it cannot be stopped, shelled into or
    fn forget_unwatched(&mut self) {
        let wanted: BTreeSet<RunName> = self.watches().into_iter().map(|w| w.name).collect();
        self.displays.retain(|name, _| wanted.contains(name));
    }

    /// The record with `name`, from the last tick.
    fn record_by_name(&self, name: &RunName) -> Option<&Record> {
        self.runs.iter().find(|r| r.name == name.as_str())
    }

    /// Runs `message`.
    fn update(&mut self, message: Message) -> Task<Message> {
        self.act(message)
    }

    fn act(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                self.refresh();
                Task::none()
            }
            Message::Open(id) => {
                self.open(id);
                self.status = None;
                Task::none()
            }
            Message::Back | Message::List => {
                self.leave();
                self.set_screen(Screen::List);
                self.status = None;
                Task::none()
            }
            Message::Settings => {
                // A sheet over whatever is showing, not a screen instead of it: what the scale
                // and the theme are changing stays visible behind the card while they change.
                self.settings = Some(Settings { was: self.picks() });
                self.status = None;
                Task::none()
            }
            Message::Troubleshoot => {
                self.trouble_open = !self.trouble_open;
                Task::none()
            }
            Message::CopyDiagnostics => {
                self.status = Some("what this machine has is on the clipboard".to_string());
                iced::clipboard::write(self.diagnostics())
            }
            Message::RevealData => {
                match cli::reveal(&self.data_dirs()) {
                    Ok(()) => self.status = Some("showed where everything is kept".to_string()),
                    Err(e) => self.notify(e),
                }
                Task::none()
            }
            Message::ReportProblem => {
                match cli::browse(ISSUES) {
                    Ok(()) => self.status = Some(format!("opened {ISSUES}")),
                    Err(e) => self.notify(e),
                }
                Task::none()
            }
            Message::SweepEnded => {
                let ended = self.runs.iter().filter(|r| !self.is_live(r)).count();
                if ended == 0 {
                    self.status = Some("there are no ended runs to sweep".to_string());
                    return Task::none();
                }
                self.confirm = Some(Confirm::Swept(ended));
                Task::none()
            }
            Message::ResetEverything => {
                self.confirm = Some(Confirm::Everything);
                Task::none()
            }
            Message::Notifications => {
                self.notices_open = !self.notices_open;
                if self.notices_open {
                    self.unread = 0;
                }
                Task::none()
            }
            Message::ClearNotices => {
                self.notices.clear();
                self.unread = 0;
                Task::none()
            }
            Message::PanelGrabbed => {
                // `None` until the first move: a press says a drag has begun, and the move after
                // it is what says where from.
                self.dragging = Some(f32::NAN);
                Task::none()
            }
            Message::PanelDragged(at) => {
                if let Some(last) = self.dragging {
                    if last.is_finite() {
                        // The edge is on the panel's left, so the pointer moving left widens it.
                        self.panel = screens::panel_within(self.panel + (last - at.x));
                    }
                    self.dragging = Some(at.x);
                }
                Task::none()
            }
            Message::PanelDropped => {
                if self.dragging.take().is_some() {
                    // Written down on release rather than on every move: a drag is one decision,
                    // not sixty.
                    if let Err(e) = state::save(&self.saved()) {
                        self.notify(format!("the panel's width was not saved: {e}"));
                    }
                }
                Task::none()
            }
            Message::SettingsClosed => {
                if let Some(sheet) = self.settings.take() {
                    // Put back what was here. Every pick took effect the moment it was pressed, so
                    // this is the only thing that makes trying one free.
                    self.restore(sheet.was);
                    self.status = None;
                }
                Task::none()
            }
            Message::SettingsApplied => {
                if self.settings.take().is_some() {
                    match state::save(&self.saved()) {
                        Ok(()) => self.status = Some("settings applied".to_string()),
                        Err(e) => {
                            self.notify(format!("applied for this window; not saved: {e}"));
                        }
                    }
                }
                Task::none()
            }
            Message::Keyboard(event) => {
                if let iced::keyboard::Event::KeyPressed { key, modifiers, .. } = event
                    && let Some(chord) = hotkey(&key, modifiers)
                {
                    return self.update(chord);
                }
                Task::none()
            }
            Message::Search(words) => {
                self.search = words;
                Task::none()
            }
            Message::HoverDivider(on) => {
                self.divider_hovered = on;
                Task::none()
            }
            Message::FocusSearch => {
                // The field narrows the list, so the chord shows the list it narrows: focusing it
                // from the form or a run's pane would filter a screen the reader cannot see.
                self.leave();
                iced::widget::operation::focus(iced::widget::Id::new(screens::SEARCH_ID))
            }
            Message::SetTheme(mode) => {
                self.mode = mode;
                self.picked(format!("drawing in {mode}"));
                Task::none()
            }
            Message::ToggleSidebar => {
                // From the clock rather than the last frame: an idle window draws none, and a
                // motion begun in the past is over before it is seen.
                self.now = std::time::Instant::now();
                let out = self.sidebar.value();
                self.sidebar.go_mut(!out, self.now);
                Task::none()
            }
            Message::Drawn(at) => {
                self.now = at;
                Task::none()
            }
            Message::Opened(id) => {
                self.window = Some(id);
                chrome::unify_titlebar(id)
            }
            Message::Resized(id) => chrome::fit_fullscreen(id).map(Message::Fullscreen),
            Message::Fullscreen(full) => {
                self.fullscreen = full;
                Task::none()
            }
            Message::ZoomWindow => self
                .window
                .map_or_else(Task::none, iced::window::toggle_maximize),
            // The running sandboxes are helper processes of their own and keep running; what
            // this ends is the notebook looking at them.
            Message::Quit => iced::exit(),
            Message::ResetSettings => {
                self.mode = theme::Mode::default();
                self.scale = 100;
                self.opens_on = OpenScreen::List;
                self.picked("settings reset".to_string());
                Task::none()
            }
            Message::DesktopTheme(desktop) => {
                self.desktop = desktop;
                Task::none()
            }
            Message::SetScale(Scale(pct)) => {
                self.scale = pct;
                self.picked(format!("drawn at {}", Scale(pct)));
                Task::none()
            }
            Message::SetOpensOn(open) => {
                self.opens_on = open;
                self.picked(format!("a plain launch now opens on the {open} screen"));
                Task::none()
            }
            Message::NewRun => {
                self.leave();
                self.form = Form::blank();
                self.set_screen(Screen::New);
                self.status = None;
                Task::none()
            }
            Message::Field(field, value) => {
                match field {
                    Field::Name => self.form.name = value,
                    Field::Root => self.form.root = value,
                    Field::Command => self.form.command = value,
                    Field::Mounts => self.form.mounts = value,
                    Field::Shares => self.form.shares = value,
                    Field::DisplaySize => self.form.display_size = value,
                    Field::Vcpus => self.form.vcpus = value,
                    Field::Mem => self.form.mem_mib = value,
                }
                Task::none()
            }
            Message::Switch(switch, on) => {
                match switch {
                    Switch::WritableRoot => self.form.writable_root = on,
                    Switch::Network => self.form.network = on,
                    Switch::Display => self.form.display = on,
                    Switch::Sound => self.form.sound = on,
                    Switch::Gpu => self.form.gpu = on,
                    Switch::Results => self.form.results = on,
                }
                Task::none()
            }
            Message::Snapshots => {
                self.set_screen(Screen::Snapshots);
                Task::none()
            }
            Message::Registries => {
                self.set_screen(Screen::Registries);
                Task::none()
            }
            Message::NewRegistry => {
                self.registry_form = RegistryForm::default();
                self.set_screen(Screen::NewRegistry);
                Task::none()
            }
            Message::RegistryField(which, value) => {
                let form = &mut self.registry_form;
                match which {
                    RegistryField::Name => form.name = value,
                    RegistryField::Url => form.url = value,
                    RegistryField::Project => form.project = value,
                    RegistryField::Username => form.username = value,
                }
                Task::none()
            }
            Message::AddRegistry => {
                match self.registry_form.registry() {
                    Ok(registry) => {
                        let saved = self
                            .registries_store
                            .as_ref()
                            .ok_or_else(|| "there is nowhere to keep registries".to_string())
                            .and_then(|store| store.save(&registry).map_err(|e| e.to_string()));
                        match saved {
                            Ok(()) => {
                                self.notify(format!("added the registry {}", registry.name));
                                self.refresh();
                                self.set_screen(Screen::Registries);
                            }
                            Err(said) => self.notify(said),
                        }
                    }
                    Err(said) => self.status = Some(said),
                }
                Task::none()
            }
            Message::Volumes => {
                self.set_screen(Screen::Volumes);
                Task::none()
            }
            Message::NewVolume => {
                self.volume_form = VolumeForm::default();
                self.set_screen(Screen::NewVolume);
                Task::none()
            }
            Message::VolumeField(which, value) => {
                match which {
                    VolumeField::Name => self.volume_form.name = value,
                    VolumeField::About => self.volume_form.about = value,
                }
                Task::none()
            }
            Message::AddVolume => {
                let name = self.volume_form.name.trim().to_string();
                let made = if name.is_empty() {
                    Err("a volume needs a name to be mounted by".to_string())
                } else if !boxdesk_record::valid_id(&name) {
                    Err(format!(
                        "{name:?} is not a usable name: letters, digits, `-` and `_`"
                    ))
                } else {
                    match self.volumes_store.as_ref() {
                        None => Err("there is nowhere to keep volumes".to_string()),
                        Some(store) if store.holds(&name) => {
                            Err(format!("a volume named {name:?} is already here"))
                        }
                        Some(store) => {
                            let volume = boxdesk_record::Volume::new(&name)
                                .about(self.volume_form.about.trim());
                            store.create(&volume).map(|_| ()).map_err(|e| e.to_string())
                        }
                    }
                };
                match made {
                    Ok(()) => {
                        self.notify(format!("made the volume {name}"));
                        self.refresh();
                        self.set_screen(Screen::Volumes);
                    }
                    Err(said) => self.status = Some(said),
                }
                Task::none()
            }
            // Through the same question every other destructive press goes through, because this
            // is the one that takes away what a run had deliberately kept.
            Message::ForgetVolume(name) => {
                self.confirm = Some(Confirm::Volume(name));
                Task::none()
            }
            Message::ForgetRegistry(name) => {
                let said = match self.registries_store.as_ref().map(|s| s.remove(&name)) {
                    Some(Ok(())) => format!("removed the registry {name}"),
                    Some(Err(e)) => e.to_string(),
                    None => "there is nowhere to keep registries".to_string(),
                };
                self.notify(said);
                self.refresh();
                Task::none()
            }
            Message::UseSnapshot(name) => {
                match self.snapshots.iter().find(|s| s.name == name) {
                    Some(snapshot) => {
                        self.form = Form::from_snapshot(snapshot);
                        self.set_screen(Screen::New);
                    }
                    // The list is a tick old, so a snapshot removed at a terminal since then is
                    // gone rather than broken: say so and show what is actually there.
                    None => {
                        self.notify(format!("the snapshot {name} is no longer here"));
                        self.refresh();
                    }
                }
                Task::none()
            }
            Message::SaveSnapshot => {
                let name = self.form.name.trim().to_string();
                if name.is_empty() {
                    self.status =
                        Some("a snapshot needs a name: fill the sandbox's name in".to_string());
                    return Task::none();
                }
                match cli::save_snapshot(&cli::boxdesk_path(), &self.form, &name) {
                    Ok(said) => {
                        self.notify(said);
                        self.refresh();
                    }
                    Err(said) => self.notify(said),
                }
                Task::none()
            }
            Message::ForgetSnapshot(name) => {
                let said = match self.snapshots_store.as_ref().map(|s| s.remove(&name)) {
                    Some(Ok(())) => format!("removed the snapshot {name}"),
                    Some(Err(e)) => e.to_string(),
                    None => "there is nowhere to keep snapshots".to_string(),
                };
                self.notify(said);
                self.refresh();
                Task::none()
            }
            Message::Start => {
                let form = self.form.clone();
                Task::perform(
                    async move { cli::start(&cli::boxdesk_path(), &form) },
                    Message::Started,
                )
            }
            Message::Started(Ok(name)) => {
                self.notify(format!("started {name}"));
                self.refresh();
                match self.runs.iter().find(|r| r.name == name.as_str()) {
                    Some(record) => {
                        let id = RunId::of(record);
                        self.open(id);
                    }
                    None => self.set_screen(Screen::List),
                }
                Task::none()
            }
            Message::Started(Err(why)) | Message::Acted(Err(why)) => {
                self.notify(why);
                Task::none()
            }
            Message::Acted(Ok(what)) => {
                self.notify(what);
                self.refresh();
                Task::none()
            }
            Message::Stop(name) => Task::perform(
                async move { cli::stop(&cli::boxdesk_path(), name.as_str()) },
                Message::Acted,
            ),
            Message::Shell(name) => Task::perform(
                async move { cli::open_shell(&cli::boxdesk_path(), name.as_str()) },
                Message::Acted,
            ),
            Message::Rerun(id) => {
                if let Some(record) = self.record(&id) {
                    self.form = Form::from_record(record);
                    self.leave();
                    self.set_screen(Screen::New);
                }
                Task::none()
            }
            Message::Delete(id) => {
                if self.record(&id).is_some_and(|r| self.is_live(r)) {
                    self.status = Some("stop the run before deleting its record".to_string());
                    return Task::none();
                }
                self.confirm = Some(Confirm::One(id));
                Task::none()
            }
            Message::Select => {
                self.list = ListMode::Selecting(BTreeSet::new());
                Task::none()
            }
            Message::SelectToggle(id) => {
                if let ListMode::Selecting(ids) = &mut self.list
                    && !ids.remove(id.as_str())
                {
                    ids.insert(id.as_str().to_string());
                }
                Task::none()
            }
            Message::SelectAll(all) => {
                let every: BTreeSet<String> = self.removable().collect();
                if let ListMode::Selecting(ids) = &mut self.list {
                    *ids = if all { every } else { BTreeSet::new() };
                }
                Task::none()
            }
            Message::SelectCancelled => {
                self.list = ListMode::Browsing;
                Task::none()
            }
            Message::RemoveSelected => {
                if let ListMode::Selecting(ids) = &self.list
                    && !ids.is_empty()
                {
                    self.confirm = Some(Confirm::Selected(ids.clone()));
                }
                Task::none()
            }
            // Escape lands here, so it is the one way out of whichever card is up. A question
            // outranks the sheet: it is the one drawn over it.
            Message::DeleteCancelled => {
                if self.confirm.take().is_none() {
                    return self.act(Message::SettingsClosed);
                }
                Task::none()
            }
            Message::DeleteConfirmed => {
                match self.confirm.take() {
                    None => return Task::none(),
                    Some(Confirm::One(id)) => {
                        self.leave();
                        let said = match self.store.remove(id.as_str()) {
                            Ok(()) => format!("removed {id}"),
                            Err(e) => format!("removing {id}: {e}"),
                        };
                        self.notify(said);
                        self.set_screen(Screen::List);
                    }
                    // `force`, because the question has already been asked: the card said what
                    // would go, and this is the answer.
                    Some(Confirm::Volume(name)) => {
                        let said = match self.volumes_store.as_ref() {
                            None => "there is nowhere to keep volumes".to_string(),
                            Some(store) => match store.remove(&name, true) {
                                Ok(()) => format!("removed the volume {name}"),
                                Err(e) => format!("removing {name}: {e}"),
                            },
                        };
                        self.notify(said);
                        self.set_screen(Screen::Volumes);
                    }
                    Some(Confirm::Swept(_)) => {
                        self.leave();
                        let ended: Vec<String> = self
                            .runs
                            .iter()
                            .filter(|r| !self.is_live(r))
                            .map(|r| r.id.clone())
                            .collect();
                        let mut gone = 0usize;
                        for id in &ended {
                            if self.store.remove(id).is_ok() {
                                gone += 1;
                            }
                        }
                        self.notify(format!("swept {}", ended_runs(gone)));
                        self.set_screen(Screen::List);
                    }
                    Some(Confirm::Everything) => {
                        self.leave();
                        let said = self.wipe();
                        self.notify(said);
                        self.set_screen(Screen::List);
                    }
                    Some(Confirm::Selected(ids)) => {
                        self.list = ListMode::Browsing;
                        let mut removed = 0usize;
                        let mut failed: Option<String> = None;
                        for id in &ids {
                            match self.store.remove(id) {
                                Ok(()) => removed += 1,
                                // The first failure is the one reported, and the rest of the
                                // selection is still attempted: one unreadable record does not
                                // strand the others.
                                Err(e) => {
                                    failed.get_or_insert_with(|| format!("removing {id}: {e}"));
                                }
                            }
                        }
                        let said = match failed {
                            Some(why) => format!("removed {}, then {why}", ended_runs(removed)),
                            None => format!("removed {}", ended_runs(removed)),
                        };
                        self.notify(said);
                    }
                }
                self.refresh();
                Task::none()
            }
            Message::Export(id) => {
                let store = self.store.clone();
                Task::perform(
                    async move {
                        let home = std::env::var_os("HOME").map(PathBuf::from);
                        let dest = export_destination(home, &store);
                        store
                            .export(id.as_str(), &dest)
                            .map(|path| format!("exported to {}", path.display()))
                            .map_err(|e| format!("exporting {id}: {e}"))
                    },
                    Message::Acted,
                )
            }
            Message::Show(stream) => {
                self.output.stream = Some(stream);
                if let Screen::Run(id) = &self.screen {
                    let id = id.clone();
                    self.reload_output(&id);
                }
                Task::none()
            }
            Message::Mapped(name, frames) => {
                let layout = frames.layout();
                eprintln!(
                    "{NAME}: mapped {name} {}x{} {:?}, stride {}, {} slots",
                    layout.width, layout.height, layout.format, layout.stride, layout.slots
                );
                // A new scanout, so the history starts again; a reconfigure leaves input open.
                let input = self.displays.remove(&name).and_then(|d| d.input);
                self.displays.insert(
                    name,
                    Display {
                        frames,
                        history: Arc::new(std::collections::VecDeque::with_capacity(HISTORY)),
                        input,
                        read: 0,
                    },
                );
                Task::none()
            }
            Message::Presented {
                name,
                frame_id,
                slot,
                damage,
            } => {
                // A present for a run this window has stopped leasing is dropped: its lease and
                // its mapping are already gone.
                let Some(display) = self.displays.get_mut(&name) else {
                    return Task::none();
                };
                display.read += 1;
                // `make_mut` copies only while the widget holds this for a draw.
                let history = Arc::make_mut(&mut display.history);
                if history.len() >= HISTORY {
                    history.pop_front();
                }
                history.push_back(frame::Present {
                    frame_id,
                    slot,
                    damage,
                });
                Task::none()
            }
            Message::Input(name, lines) => {
                if let Some(display) = self.displays.get_mut(&name) {
                    display.input = Some(lines);
                    eprintln!("{NAME}: the keyboard and pointer reach {name}");
                }
                Task::none()
            }
            Message::Note(what) => {
                self.notify(what);
                Task::none()
            }
            Message::Ended(name, why) => {
                let read = self.displays.get(&name).map_or(0, |d| d.read);
                eprintln!(
                    "{NAME}: {name}: {why}; read {read} presents, uploaded {} frames",
                    self.sinks.uploaded()
                );
                self.displays.remove(&name);
                if self.exit_with_lease {
                    return iced::exit();
                }
                self.refresh();
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let content = match &self.screen {
            Screen::List => screens::list(self),
            Screen::New => screens::new_run(self, &self.form),
            Screen::Snapshots => screens::snapshots(self),
            Screen::Registries => screens::registries(self),
            Screen::NewRegistry => screens::new_registry(self),
            Screen::Volumes => screens::volumes(self),
            Screen::NewVolume => screens::new_volume(self),
            Screen::Run(id) => screens::run(self, id),
        };
        screens::chrome(self, content)
    }

    fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![timer::every_second()];
        subs.push(iced::keyboard::listen().map(Message::Keyboard));
        subs.push(iced::system::theme_changes().map(Message::DesktopTheme));
        subs.push(iced::window::open_events().map(Message::Opened));
        subs.push(iced::window::resize_events().map(|(id, _)| Message::Resized(id)));
        // Only while something is moving: a frame subscription redraws the window on every
        // frame for as long as it is held.
        if self.sidebar.is_animating(self.now) {
            subs.push(iced::window::frames().map(Message::Drawn));
        }
        // Dropping a run's subscription cancels its lease and ends its thread.
        subs.extend(
            self.watches()
                .into_iter()
                .map(|watch| Subscription::run_with(watch, lease::stream)),
        );
        Subscription::batch(subs)
    }
}

/// Where an export goes: `$HOME/Downloads` when it exists, else home, else beside the runs
/// directory, which exists because the store opened.
fn export_destination(home: Option<PathBuf>, store: &Store) -> PathBuf {
    if let Some(home) = home {
        let downloads = home.join("Downloads");
        if downloads.is_dir() {
            return downloads;
        }
        if home.is_dir() {
            return home;
        }
    }
    store
        .dir()
        .parent()
        .map_or_else(|| store.dir().to_path_buf(), Path::to_path_buf)
}

/// The chords the window answers anywhere: the platform's command with `,` opens Settings.
fn hotkey(key: &iced::keyboard::Key, modifiers: iced::keyboard::Modifiers) -> Option<Message> {
    match key {
        iced::keyboard::Key::Character(c) if c == "," && modifiers.command() => {
            Some(Message::Settings)
        }
        iced::keyboard::Key::Character(c) if c == "k" && modifiers.command() => {
            Some(Message::FocusSearch)
        }
        // The sidebar names features, not verbs, so starting a run is a chord and a button on the
        // notebook rather than a fifth tab.
        iced::keyboard::Key::Character(c) if c == "n" && modifiers.command() => {
            Some(Message::NewRun)
        }
        iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape) => {
            Some(Message::DeleteCancelled)
        }
        _ => None,
    }
}

/// Marks as gone, in `runs` and in the store, every open record that no VM in `live` belongs to.
///
/// **A name is reusable**, and `live` says only that *some* VM answers under one, so the newest
/// open run of a name is the one that VM is: the rule `boxdesk ls --all` settles a name by, and the
/// one [`boxdesk_record::Store::open_run`] reads a name by. `runs` is newest first, as
/// [`boxdesk_record::Store::list`] returns it, which is what makes the first claim on a name the
/// newest rather than an arbitrary one.
fn settle_gone(store: &Store, runs: &mut [Record], live: &BTreeSet<RunName>) {
    let mut claimed = BTreeSet::new();
    for record in runs.iter_mut().filter(|r| r.is_open()) {
        let name = RunName::of(record);
        if claimed.insert(name.clone()) && live.contains(&name) {
            continue;
        }
        record.finish(boxdesk_record::End::Gone);
        let _ = store.save(record);
    }
}

/// `n` runs, spelled with its plural. What a header asks about, where "ended" is already
/// implied: only an ended run can be selected.
pub(crate) fn runs(n: usize) -> String {
    format!("{n} run{}", if n == 1 { "" } else { "s" })
}

/// `n` ended runs, spelled with its plural: the status line says which kind went.
pub(crate) fn ended_runs(n: usize) -> String {
    format!("{n} ended run{}", if n == 1 { "" } else { "s" })
}

/// The last `max` bytes of `path` as text, and the file's whole size.
fn tail_of(path: &std::path::Path, max: u64) -> (String, u64) {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return (String::new(), 0);
    };
    let size = file.metadata().map_or(0, |m| m.len());
    let start = size.saturating_sub(max);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return (String::new(), size);
    }
    let mut bytes = Vec::new();
    let _ = file.take(max).read_to_end(&mut bytes);
    (String::from_utf8_lossy(&bytes).into_owned(), size)
}

/// Where a run's frames, history, sinks and input go: the shader widget's program, or `None`
/// when this window holds no display for it yet.
pub(crate) fn frame_program(app: &App, name: &RunName) -> Option<frame::Program> {
    let display = app.displays.get(name)?;
    Some(frame::Program {
        run: Arc::from(name.as_str()),
        frames: Arc::clone(&display.frames),
        history: Arc::clone(&display.history),
        sinks: Arc::clone(&app.sinks),
        input: display.input.clone(),
    })
}

/// Whether `haystack` is what `wanted` asks for: every word of it somewhere in the text, folded
/// to one case.
///
/// **Every word, not the whole string**, so `py 3` finds a run named `py-sandbox` that ran
/// `python3`; typing more narrows rather than having to be typed in the order the row happens to
/// read. An empty ask matches everything, which is what makes an empty field and no field the
/// same list.
fn asked_for(wanted: &str, haystack: &str) -> bool {
    let wanted = wanted.trim().to_lowercase();
    if wanted.is_empty() {
        return true;
    }
    let haystack = haystack.to_lowercase();
    wanted
        .split_whitespace()
        .all(|word| haystack.contains(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The band's field narrows by every word it holds, in any order and in any case, and an
    /// empty one narrows nothing. A field that matched the whole string would find nothing the
    /// moment a second word was typed, which is the point at which a person is narrowing.
    #[test]
    fn the_bands_field_asks_for_every_word_it_holds() {
        let row = "py-sandbox python3 -c print(6*7)";
        assert!(asked_for("", row), "an empty field asks for everything");
        assert!(asked_for("   ", row), "and so does one holding only spaces");
        assert!(asked_for("py", row), "one word");
        assert!(asked_for("PY-SANDBOX", row), "however it is cased");
        assert!(asked_for("py 3", row), "two words, in the order they read");
        assert!(asked_for("3 py", row), "and in the other order");
        assert!(
            !asked_for("py rust", row),
            "a word that is not there refuses"
        );
        assert!(!asked_for("java", row), "and so does one on its own");
    }

    /// The platform's command with `,` opens Settings; the pieces alone open nothing.
    #[test]
    fn the_platforms_command_and_comma_open_settings() {
        use iced::keyboard::{Key, Modifiers};
        let comma = Key::Character(",".into());
        assert!(matches!(
            hotkey(&comma, Modifiers::COMMAND),
            Some(Message::Settings)
        ));
        assert!(
            hotkey(&comma, Modifiers::empty()).is_none(),
            "bare comma types"
        );
        assert!(
            hotkey(&Key::Character("q".into()), Modifiers::COMMAND).is_none(),
            "no other chord is taken"
        );
    }

    /// Starting a run left the sidebar when the sidebar became four features, so the chord is
    /// now one of its two doors and is checked rather than assumed.
    #[test]
    fn the_platforms_command_and_n_start_a_run() {
        use iced::keyboard::{Key, Modifiers};
        let n = Key::Character("n".into());
        assert!(matches!(
            hotkey(&n, Modifiers::COMMAND),
            Some(Message::NewRun)
        ));
        assert!(hotkey(&n, Modifiers::empty()).is_none(), "bare n types");
    }

    /// Every tab in the rail opens its own page and never another.
    ///
    /// **This is the test that earned its keep.** `Registries` used to be wired to a placeholder:
    /// a tab named after one thing opening a working screen about another. All four are real
    /// features now, so the check is that each one still goes where its word says.
    #[test]
    fn every_sidebar_tab_opens_its_own_page_and_never_another() {
        let mut app = app_with(Vec::new(), &[]);
        let tabs: [(Message, Screen); 4] = [
            (Message::Snapshots, Screen::Snapshots),
            (Message::Registries, Screen::Registries),
            (Message::Volumes, Screen::Volumes),
            (Message::List, Screen::List),
        ];
        for (press, page) in tabs {
            let asked = format!("{press:?}");
            let _ = app.update(press);
            assert_eq!(app.screen, page, "{asked} opened something else");
        }
    }

    /// **A volume is the thing that was not ephemeral**, so the press that removes one asks
    /// first, like every other destructive press in the window. Nothing goes until the question
    /// is answered.
    #[test]
    fn a_volume_is_never_removed_without_the_question() {
        let dir = boxdesk_test_support::ScratchDir::created("app-volume-confirm");
        let store = boxdesk_record::VolumeStore::at(dir.path().join("volumes")).expect("a store");
        let data = store
            .create(&boxdesk_record::Volume::new("datasets"))
            .expect("created");
        std::fs::write(data.join("corpus.bin"), b"keep me").expect("wrote");

        let mut app = app_with(Vec::new(), &[]);
        app.volumes_store = Some(store.clone());
        let _ = app.update(Message::ForgetVolume("datasets".to_string()));
        assert_eq!(
            app.confirm,
            Some(Confirm::Volume("datasets".to_string())),
            "the press should raise the question"
        );
        assert!(store.holds("datasets"), "and take nothing away yet");

        let _ = app.update(Message::DeleteConfirmed);
        assert!(
            !store.holds("datasets"),
            "answering yes takes it and what was in it"
        );
        std::mem::forget(dir);
    }

    /// One run is not "1 runs": both places that count them spell it through one helper.
    #[test]
    fn a_count_of_ended_runs_is_spelled_with_its_plural() {
        assert_eq!(ended_runs(1), "1 ended run");
        assert_eq!(ended_runs(2), "2 ended runs");
    }

    /// The archive goes where a person looks first: Downloads, else home, else beside
    /// the store.
    #[test]
    fn an_export_lands_in_downloads_then_home_then_beside_the_store() {
        let dir = boxdesk_test_support::ScratchDir::created("app-export-dest");
        let store = Store::at(dir.path().join("data/runs")).expect("a store");
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("Downloads")).expect("a downloads dir");
        assert_eq!(
            export_destination(Some(home.clone()), &store),
            home.join("Downloads")
        );
        std::fs::remove_dir(home.join("Downloads")).expect("removed");
        assert_eq!(export_destination(Some(home.clone()), &store), home);
        assert_eq!(export_destination(None, &store), dir.path().join("data"));
    }

    /// The pane shows the tail of a file and its whole size, and an absent file is empty.
    #[test]
    fn the_output_pane_shows_the_tail() {
        let dir = std::env::temp_dir().join(format!("boxdesk-app-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a dir");
        let path = dir.join("stdout");
        std::fs::write(&path, "0123456789").expect("written");
        assert_eq!(tail_of(&path, 4), ("6789".to_string(), 10));
        assert_eq!(tail_of(&path, 100), ("0123456789".to_string(), 10));
        assert_eq!(tail_of(&dir.join("none"), 4), (String::new(), 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run with a display, live or not, for the watch-set tests.
    fn displayed(name: &str, with_display: bool) -> Record {
        let mut p = boxdesk_record::Posture::new(
            PathBuf::from("/img"),
            std::num::NonZeroU8::MIN,
            std::num::NonZeroU32::new(512).expect("non-zero"),
        );
        p.display = with_display
            .then(|| boxdesk_record::DisplayMode::parse("640x480"))
            .flatten();
        Record::begin(name, boxdesk_record::Verb::Run, vec!["true".into()], p)
    }

    /// A record for a run that has ended, and one for a run that is still up.
    fn ended(name: &str) -> Record {
        let mut record = displayed(name, false);
        record.finish(boxdesk_record::End::Exit(0));
        record
    }

    fn open_run(name: &str) -> Record {
        displayed(name, false)
    }

    fn app_with(runs: Vec<Record>, live: &[&str]) -> App {
        let dir = boxdesk_test_support::ScratchDir::created("app-watches");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let sinks = Arc::new(frame::Sinks::open(None, None).expect("sinks"));
        let mut app = App::new(store, None, None, sinks, false);
        app.runs = runs;
        app.live = live
            .iter()
            .map(|n| RunName::started((*n).to_string()))
            .collect();
        // The scratch dir is dropped at the end of the test; nothing here touches it again.
        std::mem::forget(dir);
        app
    }

    /// Only the newest open run of a name is the one a VM answering under it belongs to. An
    /// older one is an abandoned run whose name a later sandbox took: shown as running, and
    /// leased for a display it does not have, until it is written back as gone.
    #[test]
    fn an_open_run_whose_name_was_taken_again_is_not_shown_as_live() {
        let dir = boxdesk_test_support::ScratchDir::created("app-settle-gone");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let mut abandoned = displayed("web", true);
        abandoned.started_ms -= 10;
        abandoned.id = format!("{}-web", abandoned.started_ms);
        let current = displayed("web", true);
        let orphan = displayed("solo", true);
        let mut runs = vec![current.clone(), abandoned.clone(), orphan.clone()];
        for record in &runs {
            store.create(record).expect("created");
        }

        let live: BTreeSet<RunName> = [RunName::started("web".to_string())].into_iter().collect();
        settle_gone(&store, &mut runs, &live);

        assert!(runs[0].is_open(), "the newest `web` is the VM answering");
        assert_eq!(
            (runs[1].end, runs[2].end),
            (
                Some(boxdesk_record::End::Gone),
                Some(boxdesk_record::End::Gone)
            ),
            "the older `web` and the unanswered `solo` are gone"
        );
        assert_eq!(
            store.read(&abandoned.id).expect("read").end,
            Some(boxdesk_record::End::Gone),
            "and written back, so the notebook says so next time too"
        );

        // The point of the bookkeeping: the list neither shows nor leases the abandoned run.
        let mut app = app_with(runs, &["web"]);
        app.screen = Screen::List;
        assert_eq!(
            app.runs.iter().filter(|r| app.is_live(r)).count(),
            1,
            "one sandbox is running, not two"
        );
        assert_eq!(
            app.watches().len(),
            1,
            "and one display is leased, not two under one name"
        );
    }

    /// The list leases every live display, each at the thumbnail rate; opening one run leases
    /// that one alone, at the guest's own pace. A run without a display is never leased, and
    /// neither is one that has ended.
    #[test]
    fn the_list_watches_every_live_display_and_a_run_screen_watches_one() {
        let runs = vec![
            displayed("alpha", true),
            displayed("beta", true),
            displayed("nodisplay", false),
            displayed("ended", true),
        ];
        let open_id = RunId::of(&runs[0]);
        let mut app = app_with(runs, &["alpha", "beta", "nodisplay"]);
        app.screen = Screen::List;

        let mut watched: Vec<(RunName, std::time::Duration)> = app
            .watches()
            .into_iter()
            .map(|w| (w.name, w.every))
            .collect();
        watched.sort();
        assert_eq!(
            watched,
            [
                (RunName::started("alpha".to_string()), THUMBNAIL_EVERY),
                (RunName::started("beta".to_string()), THUMBNAIL_EVERY),
            ],
            "the list watches both live displays, and only those, at the thumbnail rate"
        );

        app.screen = Screen::Run(open_id);
        let watched: Vec<(RunName, std::time::Duration)> = app
            .watches()
            .into_iter()
            .map(|w| (w.name, w.every))
            .collect();
        assert_eq!(
            watched,
            [(
                RunName::started("alpha".to_string()),
                std::time::Duration::ZERO
            )],
            "an open run is the only lease, and it takes every present"
        );
    }

    /// A display this window has stopped watching is dropped, so its mapping, its history and
    /// its input session go with the lease rather than outliving it.
    #[test]
    fn a_display_no_longer_watched_is_forgotten() {
        let runs = vec![displayed("alpha", true), displayed("beta", true)];
        let mut app = app_with(runs, &["alpha", "beta"]);
        app.screen = Screen::List;
        // A real mapping, so what is dropped is the memfd and the region, not a stand-in.
        let frames = {
            use boxdesk_krun::DisplayBackend as _;
            let mut fb = boxdesk_krun::MemoryFramebuffer::shared();
            fb.configure_scanout(0, 64, 32, 64, 32, boxdesk_krun::PixelFormat::B8G8R8X8Unorm)
                .expect("a scanout");
            let (fd, layout) = fb.share(0).expect("shareable").expect("a scanout");
            Arc::new(boxdesk_krun::SharedFrames::map(fd, layout).expect("mapped"))
        };
        for name in ["alpha", "beta"] {
            app.displays.insert(
                RunName::started(name.to_string()),
                Display {
                    frames: Arc::clone(&frames),
                    history: Arc::new(std::collections::VecDeque::new()),
                    input: None,
                    read: 0,
                },
            );
        }
        app.live.remove(&RunName::started("beta".to_string()));
        app.forget_unwatched();
        assert_eq!(
            app.displays.keys().collect::<Vec<_>>(),
            [&RunName::started("alpha".to_string())],
            "the run that stopped answering is no longer held"
        );
    }

    /// The window opens on the menu; naming a run on the command line skips straight to it.
    #[test]
    fn the_window_opens_on_the_notebook_and_a_deep_link_skips_it() {
        let dir = boxdesk_test_support::ScratchDir::created("app-boot");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = displayed("opened", false);
        store.create(&record).expect("created");
        let sinks = Arc::new(frame::Sinks::open(None, None).expect("sinks"));
        let app = App::new(store.clone(), None, None, Arc::clone(&sinks), false);
        assert_eq!(app.screen, Screen::List, "nothing asked, so the notebook");
        let app = App::new(store, Some("opened".to_string()), None, sinks, false);
        assert_eq!(app.screen, Screen::Run(RunId::of(&record)));
    }

    /// A saved `open` line is spelled exactly as the flag spells it, and parses back through the
    /// flag's own parser, so the state file and `--open` share one grammar.
    #[test]
    fn the_open_names_share_the_flag_grammar() {
        for open in [OpenScreen::List, OpenScreen::New, OpenScreen::Settings] {
            let flag = clap::ValueEnum::to_possible_value(&open).expect("every screen is a value");
            assert_eq!(open.to_string(), flag.get_name(), "one spelling");
            assert_eq!(OpenScreen::from_name(&open.to_string()), Some(open));
        }
        assert_eq!(OpenScreen::from_name("nowhere"), None);
    }

    #[test]
    fn a_scale_is_spelled_in_percent() {
        assert_eq!(Scale(110).to_string(), "110%");
    }

    #[test]
    fn a_plain_launch_lands_on_the_flag_then_the_saved_pick() {
        assert_eq!(
            landing(Some(OpenScreen::List), Some(OpenScreen::New)),
            OpenScreen::List,
            "the flag wins"
        );
        assert_eq!(
            landing(None, Some(OpenScreen::New)),
            OpenScreen::New,
            "else the saved pick"
        );
        assert_eq!(landing(None, None), OpenScreen::List);
    }

    /// Every screen the flag can name maps to one, so `--open list` is the list.
    ///
    /// **`--open settings` lands on the notebook**, because settings stopped being a screen: it
    /// is a sheet over whatever is showing, and the flag opens the notebook with it up.
    #[test]
    fn the_open_flag_maps_to_its_screens() {
        assert_eq!(OpenScreen::List.screen(), Screen::List);
        assert_eq!(OpenScreen::New.screen(), Screen::New);
        assert_eq!(OpenScreen::Settings.screen(), Screen::List);
    }

    /// **One list, because two would be a reset that missed one.** The page that says where
    /// things are kept and the act that removes them read the same list, so a store added to the
    /// project and forgotten would be visibly missing from the page rather than quietly surviving
    /// a wipe.
    #[test]
    fn what_is_shown_as_kept_is_exactly_what_a_reset_removes() {
        let app = app_with(Vec::new(), &[]);
        let named: Vec<&str> = app.data_dirs().iter().map(|(name, _)| *name).collect();
        assert_eq!(
            named,
            vec!["runs", "snapshots", "registries", "volumes", "images"],
            "every store this project keeps has to be in the one list"
        );
        let said = app.diagnostics();
        for name in named {
            assert!(
                said.contains(&format!("{name} dir ")),
                "the diagnostics say nothing about where {name} is:\n{said}"
            );
        }
    }

    /// **Paths and counts, never contents.** A run's command, a registry's username and what a
    /// guest wrote are this person's business; what a report needs is which build, which host and
    /// how much of what is where.
    #[test]
    fn the_diagnostics_carry_no_contents() {
        let mut app = app_with(vec![ended("secret-project")], &[]);
        app.registries =
            vec![boxdesk_record::Registry::new("work", "ghcr.io").signed_in_as("acme", "buildbot")];
        app.snapshots = vec![boxdesk_record::Snapshot::new(
            "devbox",
            boxdesk_record::Posture::default(),
            vec!["curl".to_string(), "https://example.invalid".to_string()],
        )];

        let said = app.diagnostics();
        for private in [
            "secret-project",
            "buildbot",
            "ghcr.io",
            "example.invalid",
            "devbox",
        ] {
            assert!(
                !said.contains(private),
                "{private:?} is this person's business, not a report's:\n{said}"
            );
        }
        assert!(said.contains("runs 1"), "counts are the point: {said}");
        assert!(said.contains("registries 1"), "{said}");
        assert!(said.contains(env!("CARGO_PKG_VERSION")), "{said}");
    }

    /// Sweeping takes every ended run and leaves a live one where it is, and it asks first.
    #[test]
    fn sweeping_asks_first_and_never_takes_a_live_run() {
        let mut app = app_with(vec![ended("gone"), open_run("alive")], &["alive"]);
        // Into the store as well, because sweeping removes from the store and the assertion has
        // to be about what is on disk rather than about a list a refresh rebuilds.
        for record in &app.runs {
            app.store.create(record).expect("filed");
        }

        let _ = app.update(Message::SweepEnded);
        assert_eq!(
            app.confirm,
            Some(Confirm::Swept(1)),
            "the question should name how many"
        );

        let _ = app.update(Message::DeleteConfirmed);
        let left: Vec<String> = app
            .store
            .list()
            .expect("read back")
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(left, vec!["alive"], "the live one stayed");
    }

    /// Nothing to sweep is refused rather than asked about: a question whose answer removes
    /// nothing is a question nobody should be made to read.
    #[test]
    fn sweeping_nothing_asks_nothing() {
        let mut app = app_with(vec![open_run("alive")], &["alive"]);
        let _ = app.update(Message::SweepEnded);
        assert!(app.confirm.is_none(), "no question was raised");
        assert!(
            app.status
                .as_deref()
                .is_some_and(|s| s.contains("no ended runs")),
            "and it says why: {:?}",
            app.status
        );
    }

    /// **The largest answer in the window asks first, like every other one.** Pressing it raises
    /// the question and removes nothing.
    #[test]
    fn removing_everything_asks_before_it_removes_anything() {
        let mut app = app_with(vec![ended("kept")], &[]);
        let _ = app.update(Message::ResetEverything);
        assert_eq!(app.confirm, Some(Confirm::Everything));
        assert_eq!(app.runs.len(), 1, "nothing went on the press");
    }

    /// Theme and local UI changes only update the status line; they are not kept as notices.
    #[test]
    fn theme_changes_are_not_recorded_as_notices() {
        let mut app = app_with(Vec::new(), &[]);
        let _ = app.update(Message::SetTheme(theme::Mode::Dark));
        let _ = app.update(Message::SetScale(Scale(125)));
        let _ = app.update(Message::CopyDiagnostics);
        assert!(
            app.notices().is_empty(),
            "local UI preferences are not notices"
        );
        assert_eq!(app.unread(), 0, "local UI preferences do not mark the bell");

        let _ = app.update(Message::Started(Ok(RunName::started("demo".to_string()))));
        assert_eq!(app.notices().len(), 1, "sandbox start is kept as a notice");
        assert_eq!(app.notices()[0].text, "started demo");
        assert_eq!(app.unread(), 1, "and marks the bell");
    }

    /// Every notice is kept, newest first, and opening the panel marks them read.
    #[test]
    fn notices_are_kept_newest_first() {
        let mut app = app_with(Vec::new(), &[]);
        let _ = app.update(Message::Note("first notice".to_string()));
        let _ = app.update(Message::Note("second notice".to_string()));

        assert_eq!(app.notices().len(), 2, "both were kept");
        assert_eq!(app.notices()[0].text, "second notice", "newest first");
        assert_eq!(app.unread(), 2, "and the bell says so");

        // Opening the panel reads them; the count does not come back.
        let _ = app.update(Message::Notifications);
        assert!(app.notices_open());
        assert_eq!(app.unread(), 0);
        let _ = app.update(Message::Note("third notice".to_string()));
        assert_eq!(
            app.unread(),
            0,
            "what arrives while the panel is open is already read"
        );

        let _ = app.update(Message::ClearNotices);
        assert!(app.notices().is_empty());
    }

    /// A window left running is not a log file: the oldest go once the cap is reached, and the
    /// newest are the ones kept.
    #[test]
    fn the_notices_are_capped_and_the_oldest_go_first() {
        let mut app = app_with(Vec::new(), &[]);
        for n in 0..NOTICES + 10 {
            app.note(format!("notice {n}"));
        }
        assert_eq!(app.notices().len(), NOTICES);
        assert_eq!(
            app.notices()[0].text,
            format!("notice {}", NOTICES + 9),
            "the newest is at the front"
        );
        assert!(
            !app.notices().iter().any(|n| n.text == "notice 0"),
            "and the oldest went"
        );
    }

    /// **The drag is a delta**, so nothing about it has to know how wide the window is, and the
    /// edge is on the panel's left: a pointer moving left widens it.
    #[test]
    fn dragging_the_panels_edge_widens_it_towards_the_pointer() {
        let mut app = app_with(Vec::new(), &[]);
        let at = |x: f32| iced::Point::new(x, 0.0);
        let start = app.panel();

        let _ = app.update(Message::PanelGrabbed);
        assert!(app.dragging(), "a press begins the drag");
        // The first move only says where from: an edge that jumped on the press would jump to
        // wherever the pointer happened to be.
        let _ = app.update(Message::PanelDragged(at(900.0)));
        assert_eq!(app.panel(), start, "the first move moves nothing");

        let _ = app.update(Message::PanelDragged(at(860.0)));
        assert_eq!(app.panel(), start + 40.0, "leftwards is wider");
        let _ = app.update(Message::PanelDragged(at(900.0)));
        assert_eq!(app.panel(), start, "and rightwards is narrower again");

        let _ = app.update(Message::PanelDropped);
        assert!(!app.dragging(), "letting go ends it");
    }

    /// A drag cannot make the panel unreadable or make the page beside it the narrower of the
    /// two, however far the pointer goes.
    #[test]
    fn a_drag_cannot_take_the_panel_outside_its_bounds() {
        let mut app = app_with(Vec::new(), &[]);
        let at = |x: f32| iced::Point::new(x, 0.0);

        let _ = app.update(Message::PanelGrabbed);
        let _ = app.update(Message::PanelDragged(at(1000.0)));
        let _ = app.update(Message::PanelDragged(at(-9000.0)));
        let wide = app.panel();
        assert_eq!(
            wide,
            screens::panel_within(f32::INFINITY),
            "held at the ceiling"
        );

        let _ = app.update(Message::PanelDragged(at(9000.0)));
        assert_eq!(
            app.panel(),
            screens::panel_within(f32::NEG_INFINITY),
            "and at the floor"
        );
        assert!(app.panel() < wide, "the two bounds are not the same number");
    }

    /// **A pick previews at once and is written down on Apply.** Closing puts back what was here,
    /// which is the whole of what makes trying a theme free — and the only thing standing between
    /// a look at a palette and living with it.
    #[test]
    fn closing_the_settings_sheet_puts_back_what_it_opened_with() {
        let mut app = app_with(Vec::new(), &[]);
        let before = app.picks();

        let _ = app.update(Message::Settings);
        assert!(app.settings_sheet().is_some(), "the press opens the sheet");

        let _ = app.update(Message::SetScale(Scale(125)));
        assert_eq!(app.scale, 125, "a pick takes effect while the sheet is up");
        assert!(
            app.settings_sheet().is_some_and(|s| s.changed(app.picks())),
            "and Apply should have something to do"
        );

        let _ = app.update(Message::SettingsClosed);
        assert!(app.settings_sheet().is_none(), "the sheet goes");
        assert_eq!(app.picks(), before, "and takes the change with it");
    }

    /// Apply keeps what was drafted and takes the sheet down; Escape after that has nothing to
    /// put back.
    #[test]
    fn applying_the_settings_sheet_keeps_what_was_drafted() {
        let mut app = app_with(Vec::new(), &[]);
        let _ = app.update(Message::Settings);
        let _ = app.update(Message::SetScale(Scale(125)));
        let _ = app.update(Message::SettingsApplied);

        assert!(app.settings_sheet().is_none(), "the sheet goes");
        assert_eq!(app.scale, 125, "and the pick stays");

        let _ = app.update(Message::DeleteCancelled);
        assert_eq!(app.scale, 125, "escape with no sheet up puts nothing back");
    }

    /// **A question outranks the sheet.** Escape answers whichever card is on top, and the
    /// confirm is the one drawn over the sheet, so it is the one that goes first.
    #[test]
    fn escape_answers_the_card_on_top_first() {
        let mut app = app_with(Vec::new(), &[]);
        let _ = app.update(Message::Settings);
        app.confirm = Some(Confirm::Volume("datasets".to_string()));

        let _ = app.update(Message::DeleteCancelled);
        assert!(app.confirm.is_none(), "the question goes first");
        assert!(app.settings_sheet().is_some(), "and the sheet is still up");

        let _ = app.update(Message::DeleteCancelled);
        assert!(app.settings_sheet().is_none(), "then the sheet");
    }

    /// The band's theme toggle is not part of the sheet, so pressing it is a decision rather than
    /// a draft: it should survive the next launch without anybody pressing Apply.
    #[test]
    fn a_pick_made_outside_the_sheet_is_written_down_at_once() {
        let mut app = app_with(Vec::new(), &[]);
        assert!(app.settings_sheet().is_none(), "no sheet is up");
        let _ = app.update(Message::SetTheme(theme::Mode::Dark));
        assert!(
            app.status.is_some(),
            "a pick with no sheet up reports what it wrote, or why it could not"
        );
    }

    /// One run's Delete asks too, and a live run is never asked about: pressing it reports why
    /// instead of raising a question whose only honest answer is no.
    #[test]
    fn deleting_one_run_asks_first_and_never_asks_about_a_live_one() {
        let dir = boxdesk_test_support::ScratchDir::created("app-delete-one");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let name = format!("delete-live-{}", std::process::id());
        let sock = boxdesk_supervisor::socket::path_for(&name).expect("a socket path");
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("a live socket");

        let mut ended = displayed("ended", false);
        ended.finish(boxdesk_record::End::Exit(0));
        let live = displayed(&name, false);
        for r in [&ended, &live] {
            store.create(r).expect("created");
        }

        let sinks = Arc::new(frame::Sinks::open(None, None).expect("sinks"));
        let mut app = App::new(store.clone(), None, None, sinks, false);

        // A live run is refused at the press, so no question is ever raised about it.
        let _ = app.update(Message::Delete(RunId(live.id.clone())));
        assert!(app.confirm.is_none(), "a live run raises no question");
        assert_eq!(
            app.status.as_deref(),
            Some("stop the run before deleting its record")
        );

        // An ended one asks, and asking alone removes nothing.
        let _ = app.update(Message::Delete(RunId(ended.id.clone())));
        assert_eq!(
            app.confirm,
            Some(Confirm::One(RunId(ended.id.clone()))),
            "the press asks rather than removes"
        );
        assert_eq!(
            store.list().expect("listed").len(),
            2,
            "asking removes none"
        );

        // Escape is the same answer as Cancel, and it keeps the record.
        let _ = app.update(Message::Keyboard(iced::keyboard::Event::KeyPressed {
            key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
            modified_key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
            physical_key: iced::keyboard::key::Physical::Code(iced::keyboard::key::Code::Escape),
            location: iced::keyboard::Location::Standard,
            modifiers: iced::keyboard::Modifiers::empty(),
            text: None,
            repeat: false,
        }));
        assert!(app.confirm.is_none(), "escape puts the question away");
        assert_eq!(store.list().expect("listed").len(), 2, "and keeps the run");

        // Answering it is the only thing that removes.
        let _ = app.update(Message::Delete(RunId(ended.id.clone())));
        let _ = app.update(Message::DeleteConfirmed);
        let left: Vec<String> = store
            .list()
            .expect("listed")
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(left, vec![live.name.clone()], "only the answered one went");
        assert!(app.confirm.is_none(), "the question goes with it");
        drop(listener);
        let _ = std::fs::remove_file(&sock);
    }

    /// A selection removes exactly what was selected, only behind the confirm, and never a live run;
    /// a second press unselects, and leaving the list drops the selection.
    #[test]
    fn a_selection_removes_what_was_selected_and_only_behind_the_confirm() {
        let dir = boxdesk_test_support::ScratchDir::created("app-clear");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let name = format!("clear-live-{}", std::process::id());
        let sock = boxdesk_supervisor::socket::path_for(&name).expect("a socket path");
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("a live socket");

        let mut gone = displayed("gone", false);
        gone.finish(boxdesk_record::End::Exit(0));
        let mut failed = displayed("failed", false);
        failed.finish(boxdesk_record::End::Failed);
        let live = displayed(&name, false);
        for r in [&gone, &failed, &live] {
            store.create(r).expect("created");
        }

        let sinks = Arc::new(frame::Sinks::open(None, None).expect("sinks"));
        let mut app = App::new(store.clone(), None, None, sinks, false);
        // A selection offers only what a delete would accept: the live run is not in it.
        let _ = app.update(Message::Select);
        let _ = app.update(Message::SelectAll(true));
        assert_eq!(
            app.list.selected().len(),
            2,
            "the live run is not selectable"
        );
        assert_eq!(
            store.list().expect("listed").len(),
            3,
            "selecting removes nothing"
        );
        let _ = app.update(Message::SelectCancelled);
        assert_eq!(app.list, ListMode::Browsing);
        assert_eq!(
            store.list().expect("listed").len(),
            3,
            "neither does cancelling"
        );

        // One of the two, which is the whole point: not all, and not one at a time.
        let one = gone.id.clone();
        let _ = app.update(Message::Select);
        let _ = app.update(Message::SelectToggle(RunId(one.clone())));
        assert_eq!(app.list.selected().len(), 1);
        let _ = app.update(Message::RemoveSelected);
        assert!(
            matches!(app.confirm, Some(Confirm::Selected(_))),
            "asking before removing"
        );
        assert_eq!(
            store.list().expect("listed").len(),
            3,
            "asking removes nothing"
        );
        // Cancelling gives the selection back rather than dropping it: the way out of the question
        // is not the way out of the selection that raised it.
        let _ = app.update(Message::DeleteCancelled);
        assert!(app.confirm.is_none(), "cancelling puts the question away");
        assert_eq!(
            app.list.selected().len(),
            1,
            "cancelling keeps what was selected"
        );
        assert_eq!(
            store.list().expect("listed").len(),
            3,
            "neither does cancelling the question"
        );
        let _ = app.update(Message::RemoveSelected);
        let _ = app.update(Message::DeleteConfirmed);
        assert_eq!(app.list, ListMode::Browsing);
        let left: Vec<String> = store
            .list()
            .expect("listed")
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(left.len(), 2, "one went, the other two stayed");
        assert!(!left.contains(&gone.name), "the selected one went");
        assert!(left.contains(&failed.name), "the unselected one stayed");
        assert_eq!(app.status.as_deref(), Some("removed 1 ended run"));

        // Pressing the same row twice takes it back out.
        let _ = app.update(Message::Select);
        let two = failed.id.clone();
        let _ = app.update(Message::SelectToggle(RunId(two.clone())));
        let _ = app.update(Message::SelectToggle(RunId(two)));
        assert!(app.list.selected().is_empty(), "a second press unselects");

        app.set_screen(Screen::New);
        assert_eq!(app.list, ListMode::Browsing, "leaving the list disarms");
        drop(listener);
        let _ = std::fs::remove_file(&sock);
    }

    /// A re-run's form is the record's command and posture again.
    #[test]
    fn a_rerun_form_is_the_records_posture_again() {
        let mut p = boxdesk_record::Posture::new(
            PathBuf::from("/img"),
            std::num::NonZeroU8::new(2).expect("non-zero"),
            std::num::NonZeroU32::new(768).expect("non-zero"),
        );
        p.rootfs = boxdesk_record::Rootfs::Writable;
        p.mounts.push(boxdesk_record::Mount::new(
            PathBuf::from("/mnt"),
            PathBuf::from("/home/x/out"),
        ));
        p.network = boxdesk_record::Network::Tsi;
        p.display = boxdesk_record::DisplayMode::parse("800x600");
        p.results = false;
        let record = boxdesk_record::Record::begin(
            "r",
            boxdesk_record::Verb::Run,
            vec!["python3".into(), "x.py".into()],
            p,
        );
        let form = Form::from_record(&record);
        assert_eq!(form.command, "python3 x.py");
        assert!(form.writable_root && form.network && form.display && !form.results);
        assert_eq!(form.mounts, "/mnt=/home/x/out");
        assert_eq!(
            (
                form.vcpus.as_str(),
                form.mem_mib.as_str(),
                form.display_size.as_str()
            ),
            ("2", "768", "800x600")
        );
    }
}
