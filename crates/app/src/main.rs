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

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::Parser;
use iced::{Element, Size, Subscription, Task};

use bsx_krun::SharedFrames;
use bsx_record::{Record, Store};
use bsx_supervisor::control::{Damage, InputSession};

/// Exit code for an operational failure, the CLI's convention.
const EXIT_OPERATIONAL: u8 = 2;

/// Presents the app remembers the damage of, so an upload after a run of missed redraws covers
/// exactly what changed since the frame it last uploaded.
const HISTORY: usize = 64;

/// Bytes of an output file the pane shows, from its end.
const OUTPUT_TAIL: u64 = 256 * 1024;

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
        .theme(|_: &App| iced::Theme::Dark)
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
    /// The lease landed and its memfd is mapped.
    Mapped(Arc<SharedFrames>),
    /// A frame was presented into `slot`.
    Presented {
        frame_id: u32,
        slot: u32,
        damage: Damage,
    },
    /// The input session is open: the window's keyboard and pointer reach the guest.
    Input(Arc<Mutex<Option<InputSession>>>),
    /// The lease ended, with why; the sandbox stopping is the ordinary case.
    Ended(String),
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
    log: Option<PathBuf>,
    sinks: Arc<frame::Sinks>,
    /// The display path of the run being viewed, when it is live and has one.
    frames: Option<Arc<SharedFrames>>,
    history: Arc<Vec<frame::Present>>,
    input: Arc<Mutex<Option<InputSession>>>,
    read: u64,
    exit_with_lease: bool,
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
            log,
            sinks,
            frames: None,
            history: Arc::new(Vec::new()),
            input: Arc::new(Mutex::new(None)),
            read: 0,
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
    }

    /// Rereads the tail of the shown stream of run `id`.
    fn reload_output(&mut self, id: &str) {
        let Some(record) = self.record(id) else {
            self.output = Output::default();
            return;
        };
        let streams = Stream::of(record.verb);
        let stream = match self.output.stream {
            Some(s) if streams.contains(&s) => Some(s),
            _ => streams.first().copied(),
        };
        let dir = self.store.dir_of(id);
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
        self.screen = Screen::Run(id.clone());
        self.output.stream = None;
        self.reload_output(&id);
    }

    /// Leaves whatever run is shown: the display lease ends with its subscription, and what was
    /// mapped for it is dropped here.
    fn leave(&mut self) {
        self.frames = None;
        self.history = Arc::new(Vec::new());
        *self
            .input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.read = 0;
    }

    /// The live run whose display the window is leasing, if the shown run is one.
    fn leased(&self) -> Option<&Record> {
        let Screen::Run(id) = &self.screen else {
            return None;
        };
        let record = self.record(id)?;
        (self.is_live(record) && record.posture.display.is_some()).then_some(record)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                self.refresh();
                Task::none()
            }
            Message::Open(id) => {
                self.open(id);
                Task::none()
            }
            Message::Back => {
                self.leave();
                self.screen = Screen::List;
                self.status = None;
                Task::none()
            }
            Message::NewRun => {
                self.leave();
                self.form = Form::blank();
                self.screen = Screen::New;
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
                    None => self.screen = Screen::List,
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
                    self.screen = Screen::New;
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
                self.screen = Screen::List;
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
            Message::Mapped(frames) => {
                let layout = frames.layout();
                eprintln!(
                    "bsx-app: mapped {}x{} {:?}, stride {}, {} slots",
                    layout.width, layout.height, layout.format, layout.stride, layout.slots
                );
                // A new mapping is a new scanout: the history's frame ids and slots were the
                // old one's.
                self.frames = Some(frames);
                self.history = Arc::new(Vec::new());
                Task::none()
            }
            Message::Presented {
                frame_id,
                slot,
                damage,
            } => {
                self.read += 1;
                let history = Arc::make_mut(&mut self.history);
                if history.len() >= HISTORY {
                    history.remove(0);
                }
                history.push(frame::Present {
                    frame_id,
                    slot,
                    damage,
                });
                Task::none()
            }
            Message::Input(session) => {
                self.input = session;
                eprintln!("bsx-app: the keyboard and pointer reach the guest");
                Task::none()
            }
            Message::Ended(why) => {
                eprintln!(
                    "bsx-app: {why}; read {} presents, uploaded {} frames",
                    self.read,
                    self.sinks.uploaded()
                );
                self.leave();
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
        if let Some(record) = self.leased() {
            subs.push(Subscription::run_with(
                (record.name.clone(), self.log.clone()),
                lease::stream,
            ));
        }
        Subscription::batch(subs)
    }
}

/// The last `max` bytes of `path` as text, and the file's whole size.
fn tail_of(path: &std::path::Path, max: u64) -> (String, u64) {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return (String::new(), 0);
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = size.saturating_sub(max);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return (String::new(), size);
    }
    let mut bytes = Vec::new();
    let _ = file.take(max).read_to_end(&mut bytes);
    (String::from_utf8_lossy(&bytes).into_owned(), size)
}

/// Where the shown run's frames, history, sinks and input go: the shader widget's program.
pub(crate) fn frame_program(app: &App) -> Option<frame::Program> {
    let frames = app.frames.as_ref()?;
    Some(frame::Program {
        frames: Arc::clone(frames),
        history: Arc::clone(&app.history),
        sinks: Arc::clone(&app.sinks),
        input: Arc::clone(&app.input),
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
