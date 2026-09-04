//! `bsx-app`: the notebook. Runs on this machine, live and past, one row each; a run opens to
//! its record, and a live one to its display with the keyboard and pointer going in.
//!
//! - **Everything here the CLI can do.** The records are `bsx-record`'s, read straight from the
//!   runs directory; starting, stopping and a shell go through the `bsx` binary beside this one,
//!   so the app grows no verb the CLI lacks and an agent driving the CLI and a person at this
//!   window see one notebook.
//! - **Nothing leaves the machine.** The runs directory is local, the sockets are local, and the
//!   only processes started are `bsx` and, for a shell, the operator's terminal.
//! - **Bounded.** The list is what retention keeps, the output pane shows the tail of a file up
//!   to a fixed size, the frame history is capped, and a display lease is shut down when its run
//!   is left, so nothing grows with time in the window.
//! - **The frame logs are the measurement.** `--log`, `--drawn-log` and `--input-log` record the
//!   display path on the host's monotonic clock, as `cargo xtask bench-frames --app` reads them.
#![forbid(unsafe_code)]

mod cli;
mod frame;
mod lease;
mod screens;
mod timer;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use iced::{Element, Size, Subscription, Task};

use bsx_krun::SharedFrames;
use bsx_record::{Record, Store};
use bsx_supervisor::control::Damage;

/// Exit code for an operational failure, the CLI's convention.
const EXIT_OPERATIONAL: u8 = 2;

/// Presents the app remembers the damage of, so an upload after a run of missed redraws covers
/// exactly what changed since the frame it last uploaded.
const HISTORY: usize = 64;

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

#[derive(Parser)]
#[command(
    name = "bsx-app",
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
    /// Open on the form for a new run.
    #[arg(long, conflicts_with = "name")]
    new: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    frame::report_adapter();
    let sinks = match frame::Sinks::open(cli.drawn_log.as_deref(), cli.input_log.as_deref()) {
        Ok(sinks) => Arc::new(sinks),
        Err(e) => {
            eprintln!("bsx-app: opening a log: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let store = match Store::open() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("bsx-app: the runs directory: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let opening = cli.name.clone();
    let log = cli.log.clone();
    let exit_with_lease = cli.exit_with_lease;
    let new = cli.new;
    let boot = move || {
        let mut app = App::new(
            store.clone(),
            opening.clone(),
            log.clone(),
            Arc::clone(&sinks),
            exit_with_lease,
        );
        if new {
            app.screen = Screen::New;
        }
        app
    };
    let ran = iced::application(boot, App::update, App::view)
        .subscription(App::subscription)
        .title(|app: &App| app.title())
        .theme(|_: &App| iced::Theme::TokyoNightStorm)
        .window_size(Size::new(1100.0, 720.0))
        .run();
    match ran {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bsx-app: {e}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// Which screen the window shows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Screen {
    /// The notebook: every run, newest first.
    List,
    /// One run's record, by id.
    Run(String),
    /// The form for a new run.
    New,
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
    fn path(self, dir: &bsx_record::RunDir) -> PathBuf {
        match self {
            Self::Stdout => dir.stdout(),
            Self::Stderr => dir.stderr(),
            Self::Shell => dir.shell_log(),
            Self::Exec => dir.exec_log(),
        }
    }

    /// The streams a run of `verb` has.
    pub(crate) fn of(verb: bsx_record::Verb) -> &'static [Self] {
        match verb {
            bsx_record::Verb::Run => &[Self::Stdout, Self::Stderr],
            bsx_record::Verb::Shell => &[Self::Shell],
            bsx_record::Verb::Up => &[Self::Exec],
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
            display_size: "640x480".to_string(),
            results: true,
            vcpus: "1".to_string(),
            mem_mib: "512".to_string(),
            ..Self::default()
        }
    }

    /// The form filled from a record, for a re-run: its command and posture again.
    fn from_record(record: &Record) -> Self {
        let p = &record.posture;
        Self {
            name: String::new(),
            root: p.root.display().to_string(),
            writable_root: p.rootfs == "writable",
            command: record.command.join(" "),
            mounts: p
                .mounts
                .iter()
                .map(|(g, h)| format!("{}={}", g.display(), h.display()))
                .collect::<Vec<_>>()
                .join(" "),
            shares: p
                .shares
                .iter()
                .map(|(t, h)| format!("{t}={}", h.display()))
                .collect::<Vec<_>>()
                .join(" "),
            network: p.network == "tsi",
            display: p.display.is_some(),
            display_size: p.display.clone().unwrap_or_else(|| "640x480".to_string()),
            sound: p.sound,
            results: p.results,
            vcpus: p.vcpus.to_string(),
            mem_mib: p.mem_mib.to_string(),
        }
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
    Results,
}

/// What the window reacts to.
#[derive(Debug, Clone)]
pub(crate) enum Message {
    /// A second passed: reread the notebook and the open run's output.
    Tick,
    Open(String),
    Back,
    NewRun,
    Field(Field, String),
    Switch(Switch, bool),
    Start,
    Started(Result<String, String>),
    Stop(String),
    Acted(Result<String, String>),
    Shell(String),
    Rerun(String),
    Delete(String),
    Show(Stream),
    /// A run's lease landed and its memfd is mapped.
    Mapped(String, Arc<SharedFrames>),
    /// A run presented a frame into `slot`.
    Presented {
        name: String,
        frame_id: u32,
        slot: u32,
        damage: Damage,
    },
    /// A run's input session is open: these are the lines its keyboard and pointer become.
    Input(
        String,
        iced::futures::channel::mpsc::UnboundedSender<String>,
    ),
    /// Something the operator should see in the window rather than on a stderr they may not have.
    Note(String),
    /// A run's lease ended, with why; the sandbox stopping is the ordinary case.
    Ended(String, String),
}

pub(crate) struct App {
    store: Store,
    screen: Screen,
    /// Every run, newest first, as of the last tick.
    runs: Vec<Record>,
    /// The names answering on their control sockets as of the last tick.
    live: BTreeSet<String>,
    form: Form,
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
    displays: BTreeMap<String, Display>,
    exit_with_lease: bool,
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
            screen: Screen::List,
            runs: Vec::new(),
            live: BTreeSet::new(),
            form: Form::blank(),
            status: None,
            output: Output::default(),
            results: Vec::new(),
            log,
            sinks,
            displays: BTreeMap::new(),
            exit_with_lease,
        };
        app.refresh();
        if let Some(key) = opening {
            let found = app
                .runs
                .iter()
                .find(|r| r.id == key)
                .or_else(|| app.runs.iter().find(|r| r.name == key))
                .map(|r| r.id.clone());
            match found {
                Some(id) => app.open(id),
                None => app.status = Some(format!("no run named or numbered {key:?}")),
            }
        }
        app
    }

    fn title(&self) -> String {
        match &self.screen {
            Screen::List => "bsx".to_string(),
            Screen::New => "bsx › new run".to_string(),
            Screen::Run(id) => format!(
                "bsx › {}",
                self.record(id).map_or(id.as_str(), |r| r.name.as_str())
            ),
        }
    }

    /// The record with `id`, from the last tick.
    pub(crate) fn record(&self, id: &str) -> Option<&Record> {
        self.runs.iter().find(|r| r.id == id)
    }

    /// Whether the run with `id` is answering now.
    pub(crate) fn is_live(&self, record: &Record) -> bool {
        record.is_open() && self.live.contains(&record.name)
    }

    /// Rereads the notebook: the records, which names answer, and marks the open records whose
    /// VM does not answer as gone (the one bookkeeping a listing does, as `bsx ls --all`).
    fn refresh(&mut self) {
        self.live = bsx_supervisor::discover::live()
            .map(|found| found.into_iter().map(|f| f.name).collect())
            .unwrap_or_default();
        let mut runs = self.store.list().unwrap_or_default();
        for record in &mut runs {
            if record.is_open() && !self.live.contains(&record.name) {
                record.finish(bsx_record::End::Gone);
                let _ = self.store.save(record);
            }
        }
        self.runs = runs;
        if let Screen::Run(id) = &self.screen {
            let id = id.clone();
            self.reload_output(&id);
        }
        self.forget_unwatched();
    }

    /// Rereads the tail of the shown stream of run `id`, and the results the guest has written.
    fn reload_output(&mut self, id: &str) {
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
        let dir = self.store.dir_of(id);
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
    fn open(&mut self, id: String) {
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
            Screen::Run(id) => self.record(id).map(|r| r.name.clone()),
            _ => None,
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
                name: record.name.clone(),
                log: None,
                every: THUMBNAIL_EVERY,
            });
        }
        watches
    }

    /// Moves to `screen` and settles what is leased for it.
    fn set_screen(&mut self, screen: Screen) {
        self.screen = screen;
        self.forget_unwatched();
    }

    /// Drops what was mapped for a run this window no longer leases, so a display left behind
    /// does not keep its memfd, its input session or its history alive.
    fn forget_unwatched(&mut self) {
        let wanted: BTreeSet<String> = self.watches().into_iter().map(|w| w.name).collect();
        self.displays.retain(|name, _| wanted.contains(name));
    }

    /// The record with `name`, from the last tick.
    fn record_by_name(&self, name: &str) -> Option<&Record> {
        self.runs.iter().find(|r| r.name == name)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
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
            Message::Back => {
                self.leave();
                self.set_screen(Screen::List);
                self.status = None;
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
                    Switch::Results => self.form.results = on,
                }
                Task::none()
            }
            Message::Start => {
                let form = self.form.clone();
                Task::perform(
                    async move { cli::start(&cli::bsx_path(), &form) },
                    Message::Started,
                )
            }
            Message::Started(Ok(name)) => {
                self.status = Some(format!("started {name}"));
                self.refresh();
                match self.runs.iter().find(|r| r.name == name) {
                    Some(record) => {
                        let id = record.id.clone();
                        self.open(id);
                    }
                    None => self.set_screen(Screen::List),
                }
                Task::none()
            }
            Message::Started(Err(why)) | Message::Acted(Err(why)) => {
                self.status = Some(why);
                Task::none()
            }
            Message::Acted(Ok(what)) => {
                self.status = Some(what);
                self.refresh();
                Task::none()
            }
            Message::Stop(name) => Task::perform(
                async move { cli::stop(&cli::bsx_path(), &name) },
                Message::Acted,
            ),
            Message::Shell(name) => Task::perform(
                async move { cli::open_shell(&cli::bsx_path(), &name) },
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
                self.leave();
                self.status = match self.store.remove(&id) {
                    Ok(()) => Some(format!("removed {id}")),
                    Err(e) => Some(format!("removing {id}: {e}")),
                };
                self.set_screen(Screen::List);
                self.refresh();
                Task::none()
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
                    "bsx-app: mapped {name} {}x{} {:?}, stride {}, {} slots",
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
                    eprintln!("bsx-app: the keyboard and pointer reach {name}");
                }
                Task::none()
            }
            Message::Note(what) => {
                self.status = Some(what);
                Task::none()
            }
            Message::Ended(name, why) => {
                let read = self.displays.get(&name).map_or(0, |d| d.read);
                eprintln!(
                    "bsx-app: {name}: {why}; read {read} presents, uploaded {} frames",
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
        match &self.screen {
            Screen::List => screens::list(self),
            Screen::New => screens::new_run(self, &self.form),
            Screen::Run(id) => screens::run(self, id),
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![timer::every_second()];
        // Dropping a run's subscription cancels its lease and ends its thread.
        subs.extend(
            self.watches()
                .into_iter()
                .map(|watch| Subscription::run_with(watch, lease::stream)),
        );
        Subscription::batch(subs)
    }
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
pub(crate) fn frame_program(app: &App, name: &str) -> Option<frame::Program> {
    let display = app.displays.get(name)?;
    Some(frame::Program {
        run: Arc::from(name),
        frames: Arc::clone(&display.frames),
        history: Arc::clone(&display.history),
        sinks: Arc::clone(&app.sinks),
        input: display.input.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pane shows the tail of a file and its whole size, and an absent file is empty.
    #[test]
    fn the_output_pane_shows_the_tail() {
        let dir = std::env::temp_dir().join(format!("bsx-app-tail-{}", std::process::id()));
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
        let mut p = bsx_record::Posture::new(PathBuf::from("/img"), 1, 512);
        p.display = with_display.then(|| "640x480".to_string());
        Record::begin(name, bsx_record::Verb::Run, vec!["true".into()], p)
    }

    fn app_with(runs: Vec<Record>, live: &[&str]) -> App {
        let dir = bsx_test_support::ScratchDir::created("app-watches");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let sinks = Arc::new(frame::Sinks::open(None, None).expect("sinks"));
        let mut app = App::new(store, None, None, sinks, false);
        app.runs = runs;
        app.live = live.iter().map(|n| (*n).to_string()).collect();
        // The scratch dir is dropped at the end of the test; nothing here touches it again.
        std::mem::forget(dir);
        app
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
        let open_id = runs[0].id.clone();
        let mut app = app_with(runs, &["alpha", "beta", "nodisplay"]);

        let mut watched: Vec<(String, std::time::Duration)> = app
            .watches()
            .into_iter()
            .map(|w| (w.name, w.every))
            .collect();
        watched.sort();
        assert_eq!(
            watched,
            [
                ("alpha".to_string(), THUMBNAIL_EVERY),
                ("beta".to_string(), THUMBNAIL_EVERY),
            ],
            "the list watches both live displays, and only those, at the thumbnail rate"
        );

        app.screen = Screen::Run(open_id);
        let watched: Vec<(String, std::time::Duration)> = app
            .watches()
            .into_iter()
            .map(|w| (w.name, w.every))
            .collect();
        assert_eq!(
            watched,
            [("alpha".to_string(), std::time::Duration::ZERO)],
            "an open run is the only lease, and it takes every present"
        );
    }

    /// A display this window has stopped watching is dropped, so its mapping, its history and
    /// its input session go with the lease rather than outliving it.
    #[test]
    fn a_display_no_longer_watched_is_forgotten() {
        let runs = vec![displayed("alpha", true), displayed("beta", true)];
        let mut app = app_with(runs, &["alpha", "beta"]);
        // A real mapping, so what is dropped is the memfd and the region, not a stand-in.
        let frames = {
            use bsx_krun::DisplayBackend as _;
            let mut fb = bsx_krun::MemoryFramebuffer::shared();
            fb.configure_scanout(0, 64, 32, 64, 32, bsx_krun::PixelFormat::B8G8R8X8Unorm)
                .expect("a scanout");
            let (fd, layout) = fb.share(0).expect("shareable").expect("a scanout");
            Arc::new(bsx_krun::SharedFrames::map(fd, layout).expect("mapped"))
        };
        for name in ["alpha", "beta"] {
            app.displays.insert(
                name.to_string(),
                Display {
                    frames: Arc::clone(&frames),
                    history: Arc::new(std::collections::VecDeque::new()),
                    input: None,
                    read: 0,
                },
            );
        }
        app.live.remove("beta");
        app.forget_unwatched();
        assert_eq!(
            app.displays.keys().collect::<Vec<_>>(),
            ["alpha"],
            "the run that stopped answering is no longer held"
        );
    }

    /// A re-run's form is the record's command and posture again.
    #[test]
    fn a_rerun_form_is_the_records_posture_again() {
        let mut p = bsx_record::Posture::new(PathBuf::from("/img"), 2, 768);
        p.rootfs = "writable".to_string();
        p.mounts
            .push((PathBuf::from("/mnt"), PathBuf::from("/home/x/out")));
        p.network = "tsi".to_string();
        p.display = Some("800x600".to_string());
        p.results = false;
        let record = bsx_record::Record::begin(
            "r",
            bsx_record::Verb::Run,
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
