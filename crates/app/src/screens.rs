//! The screens: the menu at the door, the notebook's list, one run, and the form for a new one.
//!
//! - **The posture is the layout.** A row shows what a run could touch before its name is read
//!   twice; a run's pane spells it out; the form's sentence is the same words the CLI prints,
//!   generated from the fields, so starting is confirming it (rule 3 as a screen).
//! - **Nothing here is a verb.** Every button becomes a `bsx` call or a file read; the CLI does
//!   the same thing with the same words.

use iced::widget::{
    button, checkbox, column, container, mouse_area, pick_list, row, rule, scrollable, shader,
    space, text, text_input,
};
use iced::{Element, Fill, Font, Length};

use bsx_record::{Record, Verb};

use crate::{App, Field, Form, Message, Stream, Switch};

/// Identifiers, and only identifiers: a name, a command, a path, an id. Prose is the system's
/// own sans, so a row reads as a sentence rather than a terminal dump.
const MONO: Font = Font::MONOSPACE;

/// The name of a run: the one thing a reader is scanning for down a column.
const NAME: Font = Font {
    weight: iced::font::Weight::Semibold,
    ..Font::MONOSPACE
};

/// The type scale. Three sizes, so a card has a first, second and third thing to read.
const TITLE: f32 = 15.0;
const BODY: f32 = 13.0;
const SMALL: f32 = 12.0;

/// How a run ended, as a colour: running, ended cleanly, or ended badly. The dot and the state
/// share it, so the two cannot disagree.
fn status_colour(theme: &iced::Theme, record: &Record, live: bool) -> iced::Color {
    let palette = theme.extended_palette();
    if live {
        return palette.success.base.color;
    }
    match record.end {
        Some(bsx_record::End::Exit(0)) => palette.background.strong.text,
        Some(bsx_record::End::Exit(_) | bsx_record::End::Signal(_) | bsx_record::End::Failed) => {
            palette.danger.base.color
        }
        _ => palette.background.strong.text,
    }
}

/// Muted text: everything that is not the name or the command.
fn muted(theme: &iced::Theme) -> iced::Color {
    theme.extended_palette().background.strong.text
}

/// The door: what to do next, and whether this machine is set up to do it.
pub(crate) fn menu(app: &App) -> Element<'_, Message> {
    let running = app.runs.iter().filter(|r| app.is_live(r)).count();
    let past = app.runs.len() - running;
    let actions = column![
        button(text("New run").size(TITLE))
            .style(button::primary)
            .width(Fill)
            .on_press(Message::NewRun),
        button(text(format!("Sandboxes · {running} running · {past} past")).size(TITLE))
            .width(Fill)
            .on_press(Message::List),
        button(text("Settings").size(TITLE))
            .width(Fill)
            .on_press(Message::Settings),
    ]
    .spacing(10)
    .width(Length::Fixed(300.0));
    let mut page = column![
        text("bsx").font(NAME).size(28),
        muted_line("sandboxes on this machine".to_string(), BODY),
        space().height(16),
        actions,
        space().height(16),
        muted_line(bsx_line(app), SMALL),
        muted_line(root_line(app), SMALL),
    ]
    .spacing(6)
    .align_x(iced::alignment::Horizontal::Center);
    if let Some(status) = &app.status {
        page = page.push(space().height(10));
        page = page.push(text(status).size(BODY));
    }
    container(page).center(Fill).into()
}

/// One muted line of prose, the menu's quiet register.
fn muted_line<'a>(line: String, size: f32) -> Element<'a, Message> {
    text(line)
        .size(size)
        .style(|t| text::Style {
            color: Some(muted(t)),
        })
        .into()
}

/// Where the `bsx` this window would spawn is, or what to set when it is nowhere.
fn bsx_line(app: &App) -> String {
    match &app.platform.bsx {
        Some(path) => format!("bsx: {}", path.display()),
        None => "bsx: not found (set $BSX_CLI, or put bsx beside bsx-app or on PATH)".to_string(),
    }
}

/// Where the default guest root is, and whether anything is there yet.
fn root_line(app: &App) -> String {
    match (&app.platform.root, app.platform.root_present) {
        (Some(path), true) => format!("guest root: {}", path.display()),
        (Some(path), false) => format!("guest root: {} (absent)", path.display()),
        (None, _) => "guest root: none (set $BSX_GUEST_ROOT)".to_string(),
    }
}

/// The notebook's own knobs. One section today; a later knob is a later heading block.
pub(crate) fn settings(app: &App) -> Element<'_, Message> {
    let bar = row![
        button(text("← menu")).on_press(Message::Menu),
        text("Settings").size(18),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center);
    let mut appearance = column![
        heading("APPEARANCE"),
        row![
            text("theme").size(BODY).width(LABEL),
            pick_list(iced::Theme::ALL, Some(app.theme.clone()), Message::SetTheme)
                .text_size(BODY)
                .width(Length::Fixed(240.0)),
        ]
        .spacing(10)
        .align_y(iced::alignment::Vertical::Center),
    ]
    .spacing(8);
    if app.theme_overridden {
        appearance = appearance.push(muted_line(
            "started with --theme or $BSX_THEME, which outranks this choice at the next launch"
                .to_string(),
            SMALL,
        ));
    }
    let mut page = column![
        bar,
        container(appearance)
            .style(container::rounded_box)
            .padding(14)
            .width(Fill),
    ]
    .spacing(14)
    .padding(18);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(BODY));
    }
    container(page.max_width(PAGE))
        .width(Fill)
        .center_x(Fill)
        .into()
}

/// The notebook: what is running, then what has run.
pub(crate) fn list(app: &App) -> Element<'_, Message> {
    let live: Vec<&Record> = app.runs.iter().filter(|r| app.is_live(r)).collect();
    let past: Vec<&Record> = app.runs.iter().filter(|r| !app.is_live(r)).collect();
    let start = row![
        button(text("← menu")).on_press(Message::Menu),
        text("Sandboxes").size(18),
        space().width(Fill),
    ];
    let header = if app.confirm_clear {
        start.push(
            row![
                text(format!("remove {} ended runs?", past.len())).size(BODY),
                button(text("Remove"))
                    .style(button::danger)
                    .on_press(Message::ClearConfirmed),
                button(text("Keep")).on_press(Message::ClearCancelled),
            ]
            .spacing(12)
            .align_y(iced::alignment::Vertical::Center),
        )
    } else {
        let mut ordinary = start;
        if !past.is_empty() {
            ordinary = ordinary.push(button(text("Clear history")).on_press(Message::ClearHistory));
        }
        ordinary.push(button(text("New run")).on_press(Message::NewRun))
    }
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center);

    let mut rows = column![].spacing(8);
    if !live.is_empty() {
        rows = rows.push(section("RUNNING", live.len()));
        for record in &live {
            rows = rows.push(run_row(app, record));
        }
    }
    if !past.is_empty() {
        rows = rows.push(section("HISTORY", past.len()));
        for record in &past {
            rows = rows.push(run_row(app, record));
        }
    }
    if app.runs.is_empty() {
        rows = rows.push(
            text("No runs yet. Start one here, or with `bsx run`, `bsx shell` or `bsx up`.")
                .size(BODY)
                .style(|t| text::Style {
                    color: Some(muted(t)),
                }),
        );
    }
    let mut page = column![header, scrollable(rows).height(Fill)]
        .spacing(14)
        .padding(18);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(BODY));
    }
    // A card is read left to right, so it stops where reading does: a row stretched across a wide
    // window puts its two halves too far apart to take in at once.
    container(page.max_width(PAGE))
        .width(Fill)
        .center_x(Fill)
        .into()
}

/// The width a page of cards stops at, in logical pixels.
const PAGE: f32 = 1000.0;

/// The one heading style: small, muted and set apart, on a pane and on a section alike.
fn heading(title: &str) -> Element<'_, Message> {
    text(title)
        .size(SMALL)
        .font(NAME)
        .style(|t| text::Style {
            color: Some(muted(t)),
        })
        .into()
}

/// A section heading with how many are under it.
fn section(title: &'static str, count: usize) -> Element<'static, Message> {
    row![
        heading(title),
        text(format!("{count}")).size(SMALL).style(|t| text::Style {
            color: Some(muted(t))
        }),
        space().width(Fill),
    ]
    .spacing(8)
    .padding([10, 2])
    .into()
}

/// One card: the name and how it went on the first line, the command on the second, what it
/// could touch on the third, and a live frame beside them when there is one.
fn run_row<'a>(app: &'a App, record: &'a Record) -> Element<'a, Message> {
    let live = app.is_live(record);
    let command = if record.command.is_empty() {
        match record.verb {
            Verb::Up => "a sandbox to exec into".to_string(),
            _ => String::new(),
        }
    } else {
        record.command.join(" ")
    };
    // How it went and how long. No wall clock: that is on the run's own screen, and a row has
    // room for one of the two.
    let state = if live {
        format!(
            "running {}",
            bsx_record::format_duration(bsx_record::now_ms().saturating_sub(record.started_ms))
        )
    } else {
        let end = record.end.map(|e| e.to_string()).unwrap_or_default();
        match record.ended_ms {
            Some(ended) => format!(
                "{end} · {}",
                bsx_record::format_duration(ended.saturating_sub(record.started_ms))
            ),
            None => end,
        }
    };
    let dot = record.clone();
    let title = row![
        text("●").size(SMALL).style(move |t| text::Style {
            color: Some(status_colour(t, &dot, live))
        }),
        text(&record.name).font(NAME).size(TITLE),
        space().width(Fill),
        text(state)
            .size(SMALL)
            .wrapping(text::Wrapping::None)
            .style(move |t| text::Style {
                color: Some(muted(t))
            }),
    ]
    .spacing(8)
    .align_y(iced::alignment::Vertical::Center);
    // The command is one line and clipped, never wrapped: a long one reflowing a card pushes
    // every card below it out of place. The whole of it is on the run's own screen.
    let command = text(command)
        .font(MONO)
        .size(BODY)
        .wrapping(text::Wrapping::None)
        .style(|t| text::Style {
            color: Some(muted(t)),
        });
    // What it could touch, spelled rather than abbreviated: this is the line that says whether a
    // sandbox could reach the network or a directory, and it is worth the words.
    let posture = text(posture_tags(record))
        .size(SMALL)
        .wrapping(text::Wrapping::None)
        .style(|t| text::Style {
            color: Some(muted(t)),
        });
    let text_side = column![title, command, posture].spacing(4);
    // A running sandbox with a display shows it, so the list says what each one is doing rather
    // than only what it was asked to do.
    let body: Element<'_, Message> = match crate::frame_program(app, &crate::RunName::of(record)) {
        Some(program) if live => row![
            container(shader(program).width(Fill).height(Fill))
                .width(Length::Fixed(THUMBNAIL.0))
                .height(Length::Fixed(THUMBNAIL.1))
                .style(container::dark),
            text_side.width(Fill),
        ]
        .spacing(14)
        .align_y(iced::alignment::Vertical::Center)
        .into(),
        _ => text_side.width(Fill).into(),
    };
    mouse_area(
        container(body)
            .width(Fill)
            .padding(12)
            .style(container::rounded_box),
    )
    .on_press(Message::Open(crate::RunId::of(record)))
    .into()
}

/// How big a live sandbox's frame is in the list, in logical pixels. Wide enough to tell two
/// desktops apart at a glance, small enough that a screen of them is still a list.
const THUMBNAIL: (f32, f32) = (160.0, 120.0);

/// The posture in a glance, in words: the display, the network, and what of the host it can
/// reach. Abbreviations save a few characters and cost the reader the sentence, and this is the
/// line that says whether a sandbox could touch the network or a directory.
fn posture_tags(record: &Record) -> String {
    let p = &record.posture;
    let mut parts = Vec::new();
    if let Some(display) = p.display {
        parts.push(display.as_spec().replace('x', "\u{d7}"));
    }
    parts.push(
        if p.network == bsx_record::Network::Tsi {
            "network via host"
        } else {
            "no network"
        }
        .to_string(),
    );
    if p.rootfs == bsx_record::Rootfs::Writable {
        parts.push("writable root".to_string());
    }
    // One share is worth naming; several are worth counting, or the line outgrows the card.
    match (p.mounts.len(), p.shares.len()) {
        (0, 0) => parts.push("no host directories".to_string()),
        (1, 0) => {
            let (guest, host) = &p.mounts[0];
            parts.push(format!("{} \u{2190} {}", guest.display(), host.display()));
        }
        (0, 1) => {
            let (tag, host) = &p.shares[0];
            parts.push(format!("{tag} \u{2190} {}", host.display()));
        }
        (m, sh) => parts.push(format!("{} host directories", m + sh)),
    }
    if p.results {
        parts.push(bsx_record::RESULTS_GUEST_PATH.to_string());
    }
    if p.sound {
        parts.push("sound".to_string());
    }
    parts.join(" \u{b7} ")
}

/// One run: its record on the left, its display and output on the right.
pub(crate) fn run<'a>(app: &'a App, id: &crate::RunId) -> Element<'a, Message> {
    let Some(record) = app.record(id) else {
        return column![
            button(text("← runs")).on_press(Message::Back),
            text(format!("the run {id} is no longer in the notebook")),
        ]
        .spacing(10)
        .padding(14)
        .into();
    };
    let live = app.is_live(record);
    let mut bar = row![
        button(text("← runs")).on_press(Message::Back),
        text(&record.name).font(MONO).size(18),
        space().width(Fill),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center);
    bar = bar.push(button(text("Export")).on_press(Message::Export(crate::RunId::of(record))));
    if live {
        if record.verb == Verb::Up {
            bar = bar
                .push(button(text("Shell")).on_press(Message::Shell(crate::RunName::of(record))));
        }
        bar = bar.push(
            button(text("Stop"))
                .style(button::danger)
                .on_press(Message::Stop(crate::RunName::of(record))),
        );
    } else {
        bar = bar.push(button(text("Re-run")).on_press(Message::Rerun(crate::RunId::of(record))));
        bar = bar.push(
            button(text("Delete"))
                .style(button::danger)
                .on_press(Message::Delete(crate::RunId::of(record))),
        );
    }

    let left = scrollable(
        column![
            pane("POSTURE", posture_lines(record)),
            pane("RUN", run_lines(record, live)),
            pane("RESULTS", results_lines(app, record)),
        ]
        .spacing(12),
    )
    // A share of the window rather than a fixed width: the panes hold paths, and 340 logical
    // pixels of monospace broke a guest root across two lines on a narrow window.
    .width(Length::FillPortion(2));

    let mut right = column![].spacing(10);
    if live && record.posture.display.is_some() {
        let display: Element<'_, Message> =
            match crate::frame_program(app, &crate::RunName::of(record)) {
                Some(program) => shader(program).width(Fill).height(Fill).into(),
                None => container(text("leasing the display…").size(14))
                    .center(Fill)
                    .into(),
            };
        right = right.push(
            container(display)
                .width(Fill)
                .height(Length::FillPortion(3))
                .style(container::dark),
        );
    }
    right = right.push(output_pane(app, record).height(Length::FillPortion(2)));

    let mut page = column![
        bar,
        rule::horizontal(1),
        row![left, rule::vertical(1), right.width(Length::FillPortion(3))]
            .spacing(12)
            .height(Fill),
    ]
    .spacing(10)
    .padding(14);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(13));
    }
    page.into()
}

/// The width the label column of a pane takes, in logical pixels: the longest label plus a gap.
const LABEL: f32 = 74.0;

/// A titled box of `label`, `value` rows, as two widgets so a long value wraps in its column.
fn pane<'a>(title: &'a str, rows: Vec<(String, String)>) -> Element<'a, Message> {
    let mut body = column![heading(title)].spacing(3);
    for (label, value) in rows {
        body = body.push(
            row![
                text(label).font(MONO).size(13).width(Length::Fixed(LABEL)),
                text(value).font(MONO).size(13).width(Fill),
            ]
            .spacing(4),
        );
    }
    container(body.padding(10))
        .width(Fill)
        .style(container::rounded_box)
        .into()
}

fn posture_lines(record: &Record) -> Vec<(String, String)> {
    let p = &record.posture;
    let mut lines = vec![(
        "root".to_string(),
        format!("{}, {}", p.root.display(), p.rootfs.as_word()),
    )];
    for (guest, host) in &p.mounts {
        lines.push((
            "mount".to_string(),
            format!("{} = {}", guest.display(), host.display()),
        ));
    }
    for (tag, host) in &p.shares {
        lines.push(("share".to_string(), format!("{tag} = {}", host.display())));
    }
    if p.mounts.is_empty() && p.shares.is_empty() {
        lines.push(("share".to_string(), "none".to_string()));
    }
    lines.push(("network".to_string(), p.network.as_word().to_string()));
    lines.push((
        "display".to_string(),
        p.display
            .map_or_else(|| "none".to_string(), |d| d.as_spec()),
    ));
    lines.push((
        "sound".to_string(),
        if p.sound { "on" } else { "off" }.to_string(),
    ));
    lines.push((
        "results".to_string(),
        if p.results {
            bsx_record::RESULTS_GUEST_PATH
        } else {
            "off"
        }
        .to_string(),
    ));
    lines.push((
        "limits".to_string(),
        format!("{} vcpu, {} MiB", p.vcpus, p.mem_mib),
    ));
    lines.push((
        "agent".to_string(),
        if record.verb == Verb::Up {
            "present"
        } else {
            "none"
        }
        .to_string(),
    ));
    lines
}

fn run_lines(record: &Record, live: bool) -> Vec<(String, String)> {
    let mut lines = vec![
        ("verb".to_string(), record.verb.as_word().to_string()),
        (
            "started".to_string(),
            bsx_record::format_time(record.started_ms),
        ),
    ];
    if !record.command.is_empty() {
        lines.push(("command".to_string(), record.command.join(" ")));
    }
    if let Some(pid) = record.pid {
        lines.push(("pid".to_string(), pid.to_string()));
    }
    match (live, record.end, record.ended_ms) {
        (true, _, _) => lines.push(("state".to_string(), "running".to_string())),
        (false, Some(end), Some(ended)) => {
            lines.push(("ended".to_string(), bsx_record::format_time(ended)));
            lines.push(("end".to_string(), end.to_string()));
        }
        (false, Some(end), None) => lines.push(("end".to_string(), end.to_string())),
        (false, None, _) => lines.push(("state".to_string(), "not answering".to_string())),
    }
    lines.push(("id".to_string(), record.id.clone()));
    lines
}

fn results_lines(app: &App, record: &Record) -> Vec<(String, String)> {
    if app.results.is_empty() {
        let dir = app.store.dir_of(&record.id);
        return vec![(
            "(none)".to_string(),
            format!("in {}", dir.results().display()),
        )];
    }
    // The file is the value here, not the label: a result's path is the long half, so it gets the
    // column that wraps.
    app.results
        .iter()
        .map(|(file, size)| (bytes(*size), file.display().to_string()))
        .collect()
}

/// The captured output: one button per stream, and the tail of the chosen one.
fn output_pane<'a>(app: &'a App, record: &'a Record) -> iced::widget::Container<'a, Message> {
    let mut head = row![heading("OUTPUT"), space().width(Fill)].spacing(8);
    for stream in Stream::of(record.verb) {
        let label = if app.output.stream == Some(*stream) {
            format!("[{}]", stream.label())
        } else {
            stream.label().to_string()
        };
        head = head.push(
            button(text(label).size(13))
                .style(button::text)
                .on_press(Message::Show(*stream)),
        );
    }
    let note = match (app.output.size, app.output.capped) {
        (0, _) => "(nothing yet)".to_string(),
        (size, true) => format!(
            "{} shown of {} (the record capped it)",
            bytes(size.min(crate::OUTPUT_TAIL)),
            bytes(size)
        ),
        (size, false) if size > crate::OUTPUT_TAIL => {
            format!("the last {} of {}", bytes(crate::OUTPUT_TAIL), bytes(size))
        }
        (size, false) => bytes(size),
    };
    let body = column![
        head,
        text(note).size(12),
        scrollable(text(&app.output.text).font(MONO).size(13)).height(Fill),
    ]
    .spacing(6)
    .padding(10);
    container(body).width(Fill).style(container::rounded_box)
}

/// The form for a new run, with the posture sentence above the buttons.
pub(crate) fn new_run<'a>(app: &'a App, form: &'a Form) -> Element<'a, Message> {
    let field = |label: &'static str, value: &'a str, which: Field| {
        row![
            text(label).width(Length::Fixed(90.0)),
            text_input("", value)
                .on_input(move |v| Message::Field(which, v))
                .font(MONO)
                .width(Fill),
        ]
        .spacing(8)
        .align_y(iced::alignment::Vertical::Center)
    };
    let switch = |label: &'static str, on: bool, which: Switch| {
        checkbox(on)
            .label(label)
            .on_toggle(move |v| Message::Switch(which, v))
    };
    let mut posture = bsx_record::Posture::new(
        std::path::PathBuf::from(form.root.trim()),
        form.vcpus.trim().parse().unwrap_or(1),
        form.mem_mib.trim().parse().unwrap_or(512),
    );
    posture.rootfs = if form.writable_root {
        bsx_record::Rootfs::Writable
    } else {
        bsx_record::Rootfs::ReadOnly
    };
    posture.network = if form.network {
        bsx_record::Network::Tsi
    } else {
        bsx_record::Network::None
    };
    posture.mounts = form
        .mounts
        .split_whitespace()
        .filter_map(|m| m.split_once('='))
        .map(|(g, h)| (g.into(), h.into()))
        .collect();
    posture.shares = form
        .shares
        .split_whitespace()
        .filter_map(|m| m.split_once('='))
        .map(|(t, h)| (t.to_string(), h.into()))
        .collect();
    posture.display = form
        .display
        .then(|| bsx_record::DisplayMode::parse(form.display_size.trim()))
        .flatten();
    posture.sound = form.sound;
    posture.results = form.results;

    let mut page = column![
        text("New run").size(18),
        field("name", &form.name, Field::Name),
        field("root", &form.root, Field::Root),
        switch(
            "the guest may write its root",
            form.writable_root,
            Switch::WritableRoot
        ),
        field("command", &form.command, Field::Command),
        text("words split on spaces; empty starts a sandbox to exec into").size(12),
        field("mounts", &form.mounts, Field::Mounts),
        text("GUESTDIR=HOSTDIR, space-separated, read-write").size(12),
        field("shares", &form.shares, Field::Shares),
        switch(
            "network through the host (tsi)",
            form.network,
            Switch::Network
        ),
        row![
            switch("display", form.display, Switch::Display),
            text_input("640x480", &form.display_size)
                .on_input(|v| Message::Field(Field::DisplaySize, v))
                .font(MONO)
                .width(Length::Fixed(140.0)),
            switch("sound", form.sound, Switch::Sound),
        ]
        .spacing(16)
        .align_y(iced::alignment::Vertical::Center),
        switch(
            "keep what the guest writes to /results in the record",
            form.results,
            Switch::Results
        ),
        row![
            field("vcpus", &form.vcpus, Field::Vcpus),
            field("mem MiB", &form.mem_mib, Field::Mem),
        ]
        .spacing(16),
        rule::horizontal(1),
        text(posture.sentence()).size(14),
        row![
            space().width(Fill),
            button(text("Cancel")).on_press(Message::Back),
            button(text("Start sandbox"))
                .style(button::primary)
                .on_press(Message::Start),
        ]
        .spacing(12),
    ]
    .spacing(10)
    .padding(14)
    .max_width(820.0);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(13));
    }
    scrollable(page).into()
}

/// `n` bytes as a reader wants them.
fn bytes(n: u64) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
