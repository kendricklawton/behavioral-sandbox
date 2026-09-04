//! The three screens: the notebook's list, one run, and the form for a new one.
//!
//! - **The posture is the layout.** A row shows what a run could touch before its name is read
//!   twice; a run's pane spells it out; the form's sentence is the same words the CLI prints,
//!   generated from the fields, so starting is confirming it (rule 3 as a screen).
//! - **Nothing here is a verb.** Every button becomes a `bsx` call or a file read; the CLI does
//!   the same thing with the same words.

use iced::widget::{
    button, checkbox, column, container, mouse_area, row, rule, scrollable, shader, space, text,
    text_input,
};
use iced::{Element, Fill, Font, Length};

use bsx_record::{Record, Verb};

use crate::{App, Field, Form, Message, Stream, Switch};

const MONO: Font = Font::MONOSPACE;

/// The notebook: every run, newest first, live ones above the rule.
pub(crate) fn list(app: &App) -> Element<'_, Message> {
    let live: Vec<&Record> = app.runs.iter().filter(|r| app.is_live(r)).collect();
    let past: Vec<&Record> = app.runs.iter().filter(|r| !app.is_live(r)).collect();
    let header = row![
        button(text("New run")).on_press(Message::NewRun),
        space().width(Fill),
        text(format!("runs: {} live, {} past", live.len(), past.len())).size(14),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center);
    // Clear of the scrollbar, so the posture tags at the right of a row are not drawn under it.
    let mut rows = column![].spacing(4).padding(iced::Padding::ZERO.right(12));
    for record in &live {
        rows = rows.push(run_row(app, record));
    }
    if !live.is_empty() && !past.is_empty() {
        rows = rows.push(rule::horizontal(1));
    }
    for record in &past {
        rows = rows.push(run_row(app, record));
    }
    if app.runs.is_empty() {
        rows = rows.push(
            text("No runs yet. Start one here, or with `bsx run`, `bsx shell` or `bsx up`.")
                .size(14),
        );
    }
    let mut page = column![header, rule::horizontal(1), scrollable(rows).height(Fill)]
        .spacing(10)
        .padding(14);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(13));
    }
    page.into()
}

/// One row of the list: the bullet, the name, the command, the posture, and the state.
fn run_row<'a>(app: &'a App, record: &'a Record) -> Element<'a, Message> {
    let live = app.is_live(record);
    let bullet = if live { "●" } else { "○" };
    let command = if record.command.is_empty() {
        match record.verb {
            Verb::Up => "(sandbox, exec into it)".to_string(),
            _ => String::new(),
        }
    } else {
        record.command.join(" ")
    };
    // How it went and how long, and no clock: a row has room for one of the two, and the wall
    // time is on the run's own screen. `Wrapping::None` draws past its box rather than clipping
    // to it, so what is here has to fit rather than be trimmed by the layout.
    let state = if live {
        format!(
            "running {}",
            bsx_record::format_duration(bsx_record::now_ms().saturating_sub(record.started_ms))
        )
    } else {
        let end = record.end.map(|e| e.to_string()).unwrap_or_default();
        match record.ended_ms {
            Some(ended) => format!(
                "{end} in {}",
                bsx_record::format_duration(ended.saturating_sub(record.started_ms))
            ),
            None => end,
        }
    };
    // The command is one line and clipped, never wrapped: a row is a glance down a column of
    // names, and a long command reflowing it pushes every row below out of place. The whole of it
    // is on the run's own screen.
    let first = row![
        text(bullet).width(Length::Fixed(18.0)),
        text(&record.name).font(MONO).width(Length::Fixed(140.0)),
        text(command)
            .font(MONO)
            .wrapping(text::Wrapping::None)
            .width(Fill),
    ]
    .spacing(8);
    // The posture sits under the command with the state, where it has the width to finish; on the
    // first line it was the element that ran off the edge.
    // The posture keeps its natural width and the state is the half that gives: a row that runs
    // out of width should lose the end of a timestamp, not which directories the sandbox can
    // reach. `Fill` on the state is what makes it the one squeezed.
    let second = row![
        space().width(Length::Fixed(18.0)),
        text(state)
            .size(13)
            .wrapping(text::Wrapping::None)
            .width(Fill),
        text(posture_tags(record))
            .size(13)
            .wrapping(text::Wrapping::None),
    ]
    .spacing(8);
    let text_side = column![first, second].spacing(2).padding([6, 8]);
    // A running sandbox with a display shows it, so the list says what each one is doing rather
    // than only what it was asked to do.
    let body: Element<'_, Message> = match crate::frame_program(app, &record.name) {
        Some(program) if live => row![
            container(shader(program).width(Fill).height(Fill))
                .width(Length::Fixed(THUMBNAIL.0))
                .height(Length::Fixed(THUMBNAIL.1))
                .style(container::dark),
            text_side.width(Fill),
        ]
        .spacing(10)
        .align_y(iced::alignment::Vertical::Center)
        .into(),
        _ => text_side.width(Fill).into(),
    };
    mouse_area(container(body).width(Fill).style(container::rounded_box))
        .on_press(Message::Open(record.id.clone()))
        .into()
}

/// How big a live sandbox's frame is in the list, in logical pixels. Wide enough to tell two
/// desktops apart at a glance, small enough that a screen of them is still a list.
const THUMBNAIL: (f32, f32) = (160.0, 120.0);

/// The posture in a glance: network, mounts, display, sound.
fn posture_tags(record: &Record) -> String {
    let p = &record.posture;
    let mut tags = vec![format!("net:{}", p.network)];
    if !p.mounts.is_empty() {
        tags.push(format!("mnt:{}", p.mounts.len()));
    }
    if p.rootfs == "writable" {
        tags.push("root:rw".to_string());
    }
    if p.display.is_some() {
        tags.push("display".to_string());
    }
    if p.sound {
        tags.push("sound".to_string());
    }
    tags.join("  ")
}

/// One run: its record on the left, its display and output on the right.
pub(crate) fn run<'a>(app: &'a App, id: &str) -> Element<'a, Message> {
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
    if live {
        if record.verb == Verb::Up {
            bar = bar.push(button(text("Shell")).on_press(Message::Shell(record.name.clone())));
        }
        bar = bar.push(
            button(text("Stop"))
                .style(button::danger)
                .on_press(Message::Stop(record.name.clone())),
        );
    } else {
        bar = bar.push(button(text("Re-run")).on_press(Message::Rerun(record.id.clone())));
        bar = bar.push(
            button(text("Delete"))
                .style(button::danger)
                .on_press(Message::Delete(record.id.clone())),
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
        let display: Element<'_, Message> = match crate::frame_program(app, &record.name) {
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

/// A titled box of `label`, `value` rows.
///
/// The two are separate widgets rather than one padded string, so a value too long for the pane
/// wraps under itself and stays in its column. Padding a monospace line only lines up while
/// nothing wraps, and a guest root is a path with no length limit.
fn pane<'a>(title: &'a str, rows: Vec<(String, String)>) -> Element<'a, Message> {
    let mut body = column![text(title).size(13)].spacing(3);
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
        format!("{}, {}", p.root.display(), p.rootfs),
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
    lines.push(("network".to_string(), p.network.clone()));
    lines.push((
        "display".to_string(),
        p.display.clone().unwrap_or_else(|| "none".to_string()),
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
    let mut head = row![text("OUTPUT").size(13), space().width(Fill)].spacing(8);
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
        "writable"
    } else {
        "read-only"
    }
    .to_string();
    posture.network = if form.network { "tsi" } else { "none" }.to_string();
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
    posture.display = form.display.then(|| form.display_size.trim().to_string());
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
