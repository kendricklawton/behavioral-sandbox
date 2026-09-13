//! The screens: the menu at the door, the notebook's list, one run, and the form for a new one.
//!
//! - **The posture is the layout.** A row shows what a run could touch before its name is read
//!   twice; a run's pane spells it out; the form's sentence is `Posture::sentence`, generated
//!   from the fields, so starting is confirming what the record will say (rule 2 as a screen).
//! - **Nothing here is a verb.** Every button becomes a `boxdesk` call or a file read; the CLI does
//!   the same thing with the same words.

use iced::widget::{
    button, checkbox, column, container, mouse_area, row, rule, scrollable, shader, slider, space,
    text, text_input, toggler,
};
use iced::{Element, Fill, Font, Length};

use boxdesk_record::{Record, Verb};

use crate::{App, Field, Form, Message, Stream, Switch, cli, icons};

/// Identifiers, and only identifiers: a name, a command, a path, an id. Prose is the sans, so a
/// row reads as a sentence rather than a terminal dump.
const MONO: Font = crate::fonts::MONO;

/// The name of a run: the one thing a reader is scanning for down a column.
const NAME: Font = Font {
    weight: iced::font::Weight::Semibold,
    ..crate::fonts::MONO
};

/// A pane's own name, at the head of the screen the sidebar opened.
const HEAD: f32 = 17.0;

/// The system's sans in the weight a name is set in.
const HEADING: Font = Font {
    weight: iced::font::Weight::Semibold,
    ..crate::fonts::SANS
};

/// The type scale. Three sizes, so a card has a first, second and third thing to read.
const TITLE: f32 = 15.0;
pub(crate) const BODY: f32 = 13.0;
const SMALL: f32 = 12.0;

/// How a run ended, as a colour: running, ended cleanly, or ended badly. The dot and the state
/// share it, so the two cannot disagree.
fn status_colour(theme: &iced::Theme, record: &Record, live: bool) -> iced::Color {
    let palette = theme.extended_palette();
    if live {
        return palette.success.base.color;
    }
    match record.end {
        Some(boxdesk_record::End::Exit(0)) => palette.background.strong.text,
        Some(
            boxdesk_record::End::Exit(_)
            | boxdesk_record::End::Signal(_)
            | boxdesk_record::End::Failed,
        ) => palette.danger.base.color,
        _ => palette.background.strong.text,
    }
}

/// Muted text: everything that is not the name or the command.
fn muted(theme: &iced::Theme) -> iced::Color {
    theme.extended_palette().background.strong.text
}

/// The scroll rail as macOS draws it: no rail, a translucent pill in a lane of its own.
fn scroll(theme: &iced::Theme, status: scrollable::Status) -> scrollable::Style {
    let mut style = scrollable::default(theme, status);
    let pill = theme
        .extended_palette()
        .background
        .base
        .text
        .scale_alpha(0.25);
    for rail in [&mut style.vertical_rail, &mut style.horizontal_rail] {
        rail.background = None;
        rail.border = iced::Border::default();
        rail.scroller.background = iced::Background::Color(pill);
        rail.scroller.border = iced::Border {
            radius: CORNER.into(),
            ..iced::Border::default()
        };
    }
    style
}

/// A scrollbar embedded beside the content, so it can never sit over what it scrolls.
fn lane() -> scrollable::Direction {
    scrollable::Direction::Vertical(
        scrollable::Scrollbar::new()
            .width(6)
            .scroller_width(6)
            .spacing(12),
    )
}

/// The window's own furniture: the sidebar on the left, the open screen beside it.
pub(crate) fn chrome<'a>(app: &'a App, content: Element<'a, Message>) -> Element<'a, Message> {
    let out = app.sidebar_out();
    // Folded is a rail of icons, not an absence: Docker Desktop keeps its column of glyphs and
    // drops only the words beside them, so the way back is the same column that was there before
    // and nothing has to be found again. The sidebar is therefore always drawn.
    let panes = row![
        sidebar(app, rail_width(out)),
        rule::vertical(RULE).style(divider),
    ];
    // The header is a band across the whole window rather than a head inside the content pane,
    // which is the shape Docker Desktop's is: the sidebar starts under it, not beside it, so the
    // band is the one line that crosses the window and the fold happens below it. That is also
    // what takes the window's own buttons off the panes' line and puts them on the band.
    let mut body = panes.push(content);
    if app.notices_open() {
        body = body.push(panel_grip()).push(notices(app));
    }
    let mut window = iced::widget::stack![column![header(app), body], divider_reach(app),];
    // Over every layer, including the band: while a question is up it is the only thing that
    // answers a press.
    if let Some(open) = app.settings_sheet() {
        window = window.push(settings(app, open));
    }
    if app.trouble_open() {
        window = window.push(troubleshoot(app));
    }
    // Over every layer, including the sheet: a question asked from the sheet is answered before
    // the sheet is.
    if let Some(confirm) = &app.confirm {
        window = window.push(asking(app, confirm));
    }
    // **Only while a drag is under way**, because these fire on every pointer move: a window that
    // published one per move at rest would redraw itself for nothing. The whole window is the
    // area, so the pointer can leave the strip it grabbed and the edge still follows it.
    if app.dragging() {
        return mouse_area(window)
            .interaction(iced::mouse::Interaction::ResizingHorizontally)
            .on_move(Message::PanelDragged)
            .on_release(Message::PanelDropped)
            .on_exit(Message::PanelDropped)
            .into();
    }
    window.into()
}

/// How wide the notifications panel is when nobody has dragged it, and the bounds a drag holds
/// it to.
///
/// **The floor is what a line of it needs to be readable**, and the ceiling keeps the page it is
/// beside from becoming the narrower of the two: a panel is something you glance at.
pub(crate) const PANEL_DEFAULT: f32 = 320.0;
const PANEL_MIN: f32 = 240.0;
const PANEL_MAX: f32 = 560.0;

const _: () = assert!(
    PANEL_MIN <= PANEL_DEFAULT && PANEL_DEFAULT <= PANEL_MAX,
    "the width nobody chose has to be one a drag could have chosen"
);

/// A panel width held inside its bounds, which is what a drag and a state file both go through.
pub(crate) fn panel_within(width: f32) -> f32 {
    width.clamp(PANEL_MIN, PANEL_MAX)
}

/// How wide the strip that drags the panel's edge is. Wider than the line it draws, because a
/// one-pixel target is one nobody can hit; the same bargain [`DIVIDER_REACH`] makes on the fold.
const GRIP: f32 = 9.0;

/// The panel's edge: a hairline with a strip of pointer either side of it.
///
/// **The drag is a delta, not a position.** Each move moves the edge by however far the pointer
/// moved since the last one, so nothing here has to know how wide the window is — which is the
/// one thing a widget in this position cannot ask.
fn panel_grip<'a>() -> Element<'a, Message> {
    mouse_area(
        container(rule::vertical(RULE).style(divider))
            .width(GRIP)
            .height(Fill)
            .align_x(iced::alignment::Horizontal::Center)
            // Wider than its line, so without the panes' own surface the reach either side of it
            // shows as a band of the page colour between them.
            .style(|theme: &iced::Theme| container::Style {
                background: Some(crate::theme::raised(theme).into()),
                ..container::Style::default()
            }),
    )
    .interaction(iced::mouse::Interaction::ResizingHorizontally)
    .on_press(Message::PanelGrabbed)
    .into()
}

/// The notifications panel: everything the window has said, newest first.
///
/// **The status line holds one thing and the next thing destroys it.** This is where the one
/// before went, which is the whole reason the panel is worth having: a run that ended while you
/// were reading another page used to be a sentence you missed.
pub(crate) fn notices(app: &App) -> Element<'_, Message> {
    let head = container(
        row![
            text("Notifications")
                .size(TAB)
                .font(HEADING)
                .line_height(1.0)
                .width(Fill),
            icon_action(icons::CLOSE, "Close", Some(Message::Notifications)),
        ]
        .align_y(iced::alignment::Vertical::Center),
    )
    .height(HEAD_BAR)
    .align_y(iced::alignment::Vertical::Center)
    .padding(iced::Padding {
        top: 0.0,
        right: GUTTER,
        bottom: 0.0,
        left: GUTTER,
    })
    .width(Fill);

    let mut body = column![].spacing(8);
    if app.notices().is_empty() {
        body = body.push(
            iced::widget::center(
                column![
                    icons::glyph_at(icons::BELL, 28.0).center().width(Fill),
                    text("No new notifications")
                        .size(BODY)
                        .style(|t| text::Style {
                            color: Some(muted(t)),
                        }),
                ]
                .spacing(12)
                .align_x(iced::alignment::Horizontal::Center),
            )
            .height(Fill),
        );
    } else {
        for notice in app.notices() {
            body = body.push(
                column![
                    text(boxdesk_record::format_time(notice.at_ms))
                        .size(SMALL)
                        .style(|t| text::Style {
                            color: Some(muted(t)),
                        }),
                    text(notice.text.clone()).size(BODY),
                ]
                .spacing(4)
                .padding(10)
                .width(Fill),
            );
            body = body.push(rule::horizontal(RULE).style(divider));
        }
    }

    let mut content = column![
        rule::horizontal(RULE).style(divider),
        scrollable(body)
            .direction(lane())
            .style(scroll)
            .height(Fill),
    ]
    .spacing(12);
    if !app.notices().is_empty() {
        content = content.push(
            row![
                space().width(Fill),
                small_button("Clear", push).on_press(Message::ClearNotices),
            ]
            .align_y(iced::alignment::Vertical::Center),
        );
    }

    let panel = column![
        head,
        container(content)
            .width(Fill)
            .height(Fill)
            .padding(iced::Padding {
                top: 0.0,
                right: GUTTER,
                bottom: GUTTER,
                left: GUTTER,
            }),
    ];

    container(panel)
        .width(Length::Fixed(app.panel()))
        .height(Fill)
        .style(|theme: &iced::Theme| container::Style {
            background: Some(crate::theme::raised(theme).into()),
            ..container::Style::default()
        })
        .into()
}

/// The band across the top of the window: what the product is called, what it can be asked, and
/// the handful of things that are reachable from anywhere.
///
/// - **The window's own buttons ride on it.** [`crate::chrome::LIGHTS`] is their room, kept as
///   the first thing in the row, so nothing is drawn under them; full screen takes them off the
///   line and the room closes with them.
/// - **Only what boxdesk can actually do stands here.** Docker's band carries help, notifications,
///   extensions and a sign-in; this machine signs in to nothing and has no inbox, so the right of
///   the band is the two settings a person changes most and the quit control on the platforms
///   that draw no close button of their own.
/// - **It is one of the page's own surfaces, parted by a rule.** Docker's band is a blue of its
///   own in both appearances; this one is [`crate::theme::raised`] with a hairline under it, so
///   the window is light in light and dark in dark all the way up, and the band is told from the
///   panes by the same line that parts the panes from each other.
/// - **A double click on the band zooms the window**, as it does on any titlebar, since the band
///   is drawn where the titlebar would be. The controls on it answer a press first, so only the
///   surface between them reaches this.
fn header(app: &App) -> Element<'_, Message> {
    let bar = row![
        wordmark(),
        badge("LOCAL"),
        space().width(Fill),
        search_field(app),
        space().width(Fill),
        // The troubleshoot door, beside the other two things that are settings rather than features.
        header_icon(icons::LIFE_BUOY, Message::Troubleshoot),
        // Two glyphs, not a number: a count on a bell this small is a smudge, and what a reader
        // needs to know is whether there is anything at all.
        header_icon(
            if app.unread() > 0 {
                icons::BELL_DOT
            } else {
                icons::BELL
            },
            Message::Notifications,
        ),
        header_icon(icons::SUN_MOON, Message::SetTheme(app.next_mode())),
        header_icon(icons::SETTINGS, Message::Settings),
    ]
    .align_y(iced::alignment::Vertical::Center)
    .spacing(HEADER_GAP);
    let bar = if crate::chrome::DRAWS_ITS_OWN_QUIT {
        bar.push(header_icon(icons::CLOSE, Message::Quit))
    } else {
        bar
    };
    mouse_area(column![
        container(bar)
            .height(band_height(app.scale_factor()))
            .width(Fill)
            .align_y(iced::alignment::Vertical::Center)
            .padding(iced::Padding {
                top: 0.0,
                right: GUTTER,
                bottom: 0.0,
                left: band_starts_at(app.lights()),
            })
            .style(|theme: &iced::Theme| container::Style {
                background: Some(crate::theme::raised(theme).into()),
                ..container::Style::default()
            }),
        rule::horizontal(RULE).style(divider),
    ])
    .on_double_click(Message::ZoomWindow)
    .into()
}

/// The product's own name on the band, in the weight a wordmark is set in.
fn wordmark<'a>() -> Element<'a, Message> {
    row![
        icons::glyph(icons::SQUARE),
        text(crate::NAME)
            .size(HEAD)
            .font(HEADING)
            .line_height(1.0)
            .wrapping(text::Wrapping::None),
    ]
    .align_y(iced::alignment::Vertical::Center)
    .spacing(8)
    .into()
}

/// The word set into the band beside the name, where Docker's says which account is signed in.
/// This one says the thing that is true of every boxdesk: the runs are on this machine and
/// nowhere else. A label, not a control — there is nothing to press it for.
fn badge<'a>(word: &'a str) -> Element<'a, Message> {
    container(
        text(word)
            .size(BADGE)
            .font(HEADING)
            .line_height(1.0)
            .style(|theme: &iced::Theme| text::Style {
                color: Some(muted(theme)),
            }),
    )
    .padding(BADGE_PAD)
    .style(|theme: &iced::Theme| container::Style {
        background: Some(crate::theme::selected(theme).into()),
        border: iced::Border {
            radius: CORNER.into(),
            ..iced::Border::default()
        },
        ..container::Style::default()
    })
    .into()
}

/// One glyph on the band: a lone icon, wearing the mark every lone icon in the window wears,
/// since the band is a surface of the page rather than a colour of its own.
fn header_icon<'a>(icon: icons::Icon, press: Message) -> Element<'a, Message> {
    button(icons::glyph(icon).center().width(HALO))
        .style(halo)
        .padding(0)
        .height(HALO)
        .on_press(press)
        .into()
}

/// The field on the band: what the notebook's list is narrowed by.
///
/// **It filters rather than decorates.** A band that carried a field which did nothing would be
/// the same promise Docker's makes and this one would not keep, so the text here is what
/// [`crate::App::matches_search`] reads and the list below is what it leaves.
fn search_field(app: &App) -> Element<'_, Message> {
    container(
        row![
            icons::glyph(icons::SEARCH),
            text_input("Search sandboxes", app.search())
                .id(SEARCH_ID)
                .on_input(Message::Search)
                .size(BODY)
                .padding(0)
                .style(|theme: &iced::Theme, status| {
                    let mut style = entry(theme, status);
                    // The well around it is what is drawn; the field only sets ink.
                    style.background = iced::Color::TRANSPARENT.into();
                    style.border = iced::Border::default();
                    style
                }),
        ]
        .align_y(iced::alignment::Vertical::Center)
        .spacing(8),
    )
    .width(Length::Fixed(SEARCH_WIDTH))
    .padding(SEARCH_PAD)
    .style(|theme: &iced::Theme| container::Style {
        background: Some(crate::theme::selected(theme).into()),
        border: iced::Border {
            radius: CORNER.into(),
            ..iced::Border::default()
        },
        ..container::Style::default()
    })
    .into()
}

/// The field's own id, so a chord can put the cursor in it without the band holding focus state.
pub(crate) const SEARCH_ID: &str = "header-search";

/// How wide the field is: room for a run's name and its image, which is what is being scanned
/// for, and not so wide that the band is a field with a name beside it.
const SEARCH_WIDTH: f32 = 380.0;
const SEARCH_PAD: [f32; 2] = [7.0, 10.0];

/// The room around the badge's word, and the size it is set at: a step under body text, as a
/// badge is set beside a name rather than beneath it.
const BADGE: f32 = 10.0;
const BADGE_PAD: [f32; 2] = [4.0, 7.0];

/// The gap between what stands on the band, and the room kept at its own left edge before the
/// first of them.
const HEADER_GAP: f32 = 10.0;
const HEADER_EDGE: f32 = 12.0;

/// Where the first control on the band stands, given the room `lights` the window's own buttons
/// take: the band's own edge, out past them.
///
/// **Full screen closes their room and the controls come back with it.** macOS auto-hides the
/// titlebar carrying the buttons there, so [`crate::App::lights`] answers zero and the toggle
/// returns to the edge rather than standing 91 in past a band holding nothing — which is the
/// mistake the head's own line made until 2026-09-10, in the layout this one replaced.
fn band_starts_at(lights: f32) -> f32 {
    HEADER_EDGE + lights
}

/// The question a destructive press waits behind: what would go, and the two ways out.
///
/// **The scrim is `opaque`, so nothing under it answers a press.** A press on it cancels, as does
/// Escape, which is the way out a person reaches for first.
fn asking<'a>(app: &'a App, confirm: &'a crate::Confirm) -> Element<'a, Message> {
    let subject = match confirm {
        crate::Confirm::One(id) => app
            .record(id)
            .map_or_else(|| "this run".to_string(), |record| record.name.clone()),
        crate::Confirm::Selected(_) => crate::runs(confirm.len()),
        crate::Confirm::Volume(name) => format!("the volume {name}"),
        crate::Confirm::Swept(n) => crate::ended_runs(*n),
        crate::Confirm::Everything => "everything Boxdesk keeps".to_string(),
    };
    let card = container(
        column![
            text(format!("Delete {subject}?")).size(TITLE).font(HEADING),
            // What a delete does, not what it costs: the directory is the mechanism, and naming it
            // is the whole warning.
            text(match confirm {
                // A volume is the thing that was **not** ephemeral, so the warning is about its
                // contents rather than about a record.
                crate::Confirm::Volume(_) =>
                    "Everything in it goes with it. Nothing else keeps a copy.",
                crate::Confirm::One(_) =>
                    "Its record, captured output and results are removed from the runs directory.",
                crate::Confirm::Selected(_) | crate::Confirm::Swept(_) =>
                    "Their records, captured output and results are removed from the runs directory.",
                // The largest answer in the window, so it names what is easiest to forget is in
                // there: the volumes, which exist because their contents were worth keeping.
                crate::Confirm::Everything =>
                    "Every run, snapshot, registry, volume and image goes, and the settings with \
                     them. What is in a volume goes too, and nothing else has a copy.",
            })
            .size(BODY),
            row![
                space().width(Fill),
                small_button("Cancel", push).on_press(Message::DeleteCancelled),
                small_button("Delete", destructive).on_press(Message::DeleteConfirmed),
            ]
            .spacing(8),
        ]
        .spacing(14),
    )
    .padding(20)
    .width(Length::Fixed(340.0))
    .style(card);

    iced::widget::opaque(
        mouse_area(iced::widget::center(iced::widget::opaque(card)).style(scrim))
            .on_press(Message::DeleteCancelled),
    )
}

/// The wash over the window while a question is up: dark enough to put the page behind it, sheer
/// enough to leave the run being deleted readable under it.
fn scrim(_theme: &iced::Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(iced::Color::from_rgba(
            0.0, 0.0, 0.0, 0.45,
        ))),
        ..container::Style::default()
    }
}

/// The sidebar at `width`: where this machine's sandboxes are reached, clipped to what the fold
/// has left it rather than laid out again at every width.
fn sidebar(app: &App, width: f32) -> Element<'_, Message> {
    let running = app.runs.iter().filter(|r| app.is_live(r)).count();
    let on_list = matches!(app.screen, crate::Screen::List | crate::Screen::Run(_));
    // Four features and no verbs. Starting a run is a button on the notebook and ⌘N; settings and
    // troubleshoot are icons in the band. Three of the four are not built, and each opens a page
    // that says so rather than borrowing a screen that works.
    let mut nav = column![tab(
        icons::CONTAINER,
        "Sandboxes",
        (running > 0).then(|| running.to_string()),
        on_list,
        Message::List,
    )]
    .spacing(3);
    nav = nav.push(tab(
        icons::BOX,
        "Snapshots",
        (!app.snapshots().is_empty()).then(|| app.snapshots().len().to_string()),
        app.screen == crate::Screen::Snapshots,
        Message::Snapshots,
    ));
    nav = nav.push(tab(
        icons::PACKAGE_OPEN,
        "Registries",
        (!app.registries().is_empty()).then(|| app.registries().len().to_string()),
        app.screen == crate::Screen::Registries,
        Message::Registries,
    ));
    nav = nav.push(tab(
        icons::HARD_DRIVE,
        "Volumes",
        (!app.volumes().is_empty()).then(|| app.volumes().len().to_string()),
        app.screen == crate::Screen::Volumes,
        Message::Volumes,
    ));
    container(nav)
        .style(rail)
        .width(Length::Fixed(width))
        .height(Fill)
        .clip(true)
        .padding(iced::Padding {
            top: NAV_TOP,
            right: RAIL_PAD,
            bottom: 12.0,
            left: RAIL_PAD,
        })
        .into()
}

/// The button that folds the sidebar and brings it back, wearing the glyph macOS gives it.
fn sidebar_toggle<'a>() -> Element<'a, Message> {
    button(
        icons::glyph_at(icons::PANEL_LEFT, DIVIDER_GLYPH)
            .center()
            .width(DIVIDER_TOGGLE)
            .style(|theme: &iced::Theme| text::Style {
                color: Some(theme.extended_palette().primary.base.color),
            }),
    )
    .style(divider_toggle)
    .padding(0)
    .height(DIVIDER_TOGGLE)
    .on_press(Message::ToggleSidebar)
    .into()
}

/// The strip of window the fold answers to, and the control it shows there.
///
/// **The line is the target, not a button parked beside it.** Docker Desktop puts nothing on the
/// boundary until the pointer is near it, and then a circle on the line itself; a control that
/// were always drawn would be one more thing on a band that already carries four. So this layer
/// is a strip [`DIVIDER_REACH`] wide down the fold, and the circle is what it shows while the
/// pointer is inside it.
///
/// **Nothing here takes a press that was not for it.** The strip is a `mouse_area` with only
/// `on_enter` and `on_exit`, which iced does not let capture a click, so the sidebar row and the
/// page column under the strip answer presses as though it were not there. Only the circle, a
/// button in its own bounds, takes one.
fn divider_reach(app: &App) -> Element<'_, Message> {
    let fold = rail_width(app.sidebar_out());
    let shown: Element<'_, Message> = if app.divider_hovered() {
        sidebar_toggle()
    } else {
        space().width(DIVIDER_TOGGLE).height(DIVIDER_TOGGLE).into()
    };
    container(
        mouse_area(
            container(shown)
                .width(DIVIDER_REACH)
                .height(Fill)
                .align_x(iced::alignment::Horizontal::Center)
                .padding(iced::Padding {
                    top: (HEAD_BAR - DIVIDER_TOGGLE) / 2.0,
                    right: 0.0,
                    bottom: 0.0,
                    left: 0.0,
                }),
        )
        .on_enter(Message::HoverDivider(true))
        .on_exit(Message::HoverDivider(false)),
    )
    // The layer is the whole window, so the strip inside it has a window's height to fill; a
    // container left to shrink would be as tall as the circle and the fold would answer the
    // pointer on one line of itself.
    .width(Fill)
    .height(Fill)
    .padding(iced::Padding {
        top: band_height(app.scale_factor()),
        right: 0.0,
        bottom: 0.0,
        left: reach_at(fold),
    })
    .into()
}

/// Where the strip's own left edge falls, given how far `fold` the sidebar is out: centred on the
/// boundary, and never past the window's edge, so a folded sidebar still has a whole circle to be
/// brought back by rather than half of one cut off at zero.
fn reach_at(fold: f32) -> f32 {
    (fold - DIVIDER_REACH / 2.0).max(0.0)
}

/// How far the circle reaches into the pane beside it, which it does at every fold, since it is
/// centred on a boundary that is always there now.
///
/// A head begins a [`GUTTER`] into that pane, and this is less, so the two never meet and the
/// head's inset is the gutter at every width — which it was not while the fold ran to nothing and
/// the circle stood on the page itself, drawn through the first letter of the head's own name.
/// `the_circle_never_reaches_a_head` is what keeps that from coming back.
const CIRCLE_INTO_PANE: f32 = DIVIDER_TOGGLE / 2.0 - RULE;
const _: () = assert!(
    CIRCLE_INTO_PANE < GUTTER,
    "the circle would reach past where a head's name starts, and be drawn through its first \
     letter, as it was while the fold ran to nothing"
);

/// The circle the fold is worked by, and the strip of window that shows it. The circle is Docker's
/// size; the strip is wider than the circle so the pointer that brought it out is still inside
/// the strip once it is on the circle, which is what stops it flickering away under its own
/// arrival.
const DIVIDER_TOGGLE: f32 = 30.0;
const DIVIDER_REACH: f32 = 42.0;
const _: () = assert!(
    DIVIDER_REACH > DIVIDER_TOGGLE,
    "the strip must outreach the circle, or the pointer leaves the strip by arriving on the \
     circle it brought out and the circle goes with it"
);

/// The glyph inside the circle, which is smaller than [`icons::SIZE`] on purpose.
///
/// **An icon in a ring is not an icon in a row.** The set's own size fills a 30-pt circle to
/// within 5 pt of its edge, and a glyph that close reads as touching the ring rather than sitting
/// inside it. [`DIVIDER_CLEARANCE`] is the room this leaves instead, and is held to a floor
/// below, because the two sizes drifting together is exactly how that crowding came back.
const DIVIDER_GLYPH: f32 = 15.0;

/// The room between the glyph's ink and the ring around it, on every side.
const DIVIDER_CLEARANCE: f32 = (DIVIDER_TOGGLE - DIVIDER_GLYPH) / 2.0;
const _: () = assert!(
    DIVIDER_CLEARANCE >= 7.0,
    "the glyph in the fold's circle wants air around it, or it reads as touching the ring"
);

/// The circle on the fold: a raised surface on the line, held by the same hairline as the rule it
/// covers and lifted off it by the shadow a card takes.
///
/// **The one control that is not [`CORNER`]**, and named as one in
/// `every_control_takes_the_windows_own_corner`. It is drawn on a line rather than on a surface,
/// and a square on a rule reads as a break in the rule; a circle reads as something sitting on
/// it. Docker draws the same thing the same way.
fn divider_toggle(theme: &iced::Theme, status: button::Status) -> button::Style {
    let surface = match status {
        button::Status::Hovered | button::Status::Pressed => crate::theme::raised_hovered(theme),
        button::Status::Active | button::Status::Disabled => crate::theme::raised(theme),
    };
    button::Style {
        background: Some(surface.into()),
        text_color: theme.extended_palette().primary.base.color,
        border: iced::Border {
            color: hairline(theme),
            width: 1.0,
            radius: (DIVIDER_TOGGLE / 2.0).into(),
        },
        shadow: RAISE,
        ..button::Style::default()
    }
}

/// The mark a lone glyph wears under the pointer, wider than the glyph, as a toolbar icon's halo
/// is.
const HALO: f32 = 36.0;

/// An icon on its own: nothing until the pointer finds it, then the mark a toolbar icon wears,
/// a step past a row's hover so it reads on the rail as well as on the page.
///
/// Its corner is [`CORNER`], the one every other control takes, so the window has one corner and
/// not two. `the_icons_mark_takes_the_windows_own_corner` holds it there.
fn halo(theme: &iced::Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();
    let surface = match status {
        button::Status::Hovered | button::Status::Pressed => crate::theme::selected(theme),
        button::Status::Active | button::Status::Disabled => iced::Color::TRANSPARENT,
    };
    let mut style = role(surface, palette.background.base.text, None, status);
    style.border.radius = CORNER.into();
    style
}

/// A head's height, as a toolbar window has one: 19.5 of room over its content, which is what a
/// window whose titlebar carries a toolbar leaves over the traffic lights in it.
///
/// **In the window's own points, not the toolkit's.** This is a measurement of the platform's
/// titlebar, and the window's buttons sit on its middle; see [`band_height`], which is what the
/// band is actually laid out to.
const HEAD_BAR: f32 = 52.0;

/// The band's height at this scale: [`HEAD_BAR`] of window, whatever Settings is drawing at.
///
/// **The band is chrome, so it does not zoom with the content.** The buttons macOS draws on it
/// are a fixed size at a fixed place, so a band that grew with the app's scale left them above
/// its middle while everything the app drew stayed centred — the two lines of the same bar
/// disagreeing, at every scale but one. What zooms is what stands on the band; the band itself
/// is the platform's line.
fn band_height(scale: f32) -> f32 {
    HEAD_BAR / scale
}

/// Where the sidebar's first tab starts, under the band: the rail's own padding and no more,
/// since the toggle that used to stand on this line has moved onto the band above it.
const NAV_TOP: f32 = 12.0;

/// The room the sidebar keeps at its own edges, and so how far a tab's pill stops short of the
/// boundary.
///
/// **Wider than the circle reaches back over the rail.** The control on the fold is centred on
/// the boundary, so it hangs [`DIVIDER_TOGGLE`] / 2 back over the rail's own last column; a pill
/// that ran to within less than that was drawn under it, and the circle sat on the corner of the
/// open tab's mark. The relation holds at every fold, since the pill's edge and the circle's are
/// both measured back from the same boundary.
const RAIL_PAD: f32 = 20.0;
const _: () = assert!(
    RAIL_PAD >= DIVIDER_TOGGLE / 2.0 + 4.0,
    "a tab's pill would run under the circle on the boundary"
);

/// The room inside a sidebar row, around its icon and label.
const TAB_PAD: [f32; 2] = [9.0, 12.0];

/// One sidebar tab: its name, an optional count, and the pill it wears while its screen is open.
fn tab<'a>(
    icon: icons::Icon,
    label: &'a str,
    count: Option<String>,
    open: bool,
    message: Message,
) -> Element<'a, Message> {
    // The glyph is fixed and the word takes what is left, rather than the word asking for its
    // own width and the glyph taking what remains: folded, what is left is nothing, so the word
    // clips to nothing and the icon still stands in its column. Asking the other way round gave
    // the row more children than it had room for and iced drew none of them.
    let mut line = row![
        icons::glyph(icon),
        container(
            // One line whatever room is left: a label that rewrapped would step down the rail on
            // every frame of a fold.
            text(label).size(TAB).wrapping(text::Wrapping::None)
        )
        .width(Fill)
        .padding(iced::Padding {
            top: 0.0,
            right: 0.0,
            bottom: 0.0,
            left: LABEL_GAP,
        })
        .clip(true),
    ];
    if let Some(count) = count {
        line = line.push(text(count).size(SMALL).style(|t| text::Style {
            color: Some(muted(t)),
        }));
    }
    button(line.align_y(iced::alignment::Vertical::Center))
        .style(move |t, s| if open { selected_tab(t) } else { ghost(t, s) })
        .width(Fill)
        .padding(TAB_PAD)
        .on_press(message)
        .into()
}

/// The pill under the open screen's tab: the rail a step darker, flat, as a source list marks
/// its row.
fn selected_tab(theme: &iced::Theme) -> button::Style {
    let palette = theme.extended_palette();
    role(
        crate::theme::selected(theme),
        palette.background.base.text,
        None,
        button::Status::Active,
    )
}

/// The sidebar's surface: the page tinted one step, which the rule beside it parts from the page.
fn rail(theme: &iced::Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(crate::theme::recessed(theme))),
        ..container::Style::default()
    }
}

/// One muted line of prose, the quiet register. Takes what `text` takes, so a fixed line
/// borrows rather than allocating on every redraw.
fn muted_line<'a>(line: impl text::IntoFragment<'a>, size: f32) -> Element<'a, Message> {
    text(line)
        .size(size)
        .style(|t| text::Style {
            color: Some(muted(t)),
        })
        .into()
}

/// Where the `boxdesk` this window would spawn is, or what to set when it is nowhere.
fn boxdesk_line(app: &App) -> String {
    let home = std::env::var("HOME").ok();
    match &app.platform.boxdesk {
        Some(path) => tilde(home.as_deref(), path),
        None => {
            "Not found: set $BOXDESK_CLI, or put boxdesk beside Boxdesk, in the bundle\'s Resources, or on PATH.".to_string()
        }
    }
}

/// Where the default guest root is, and whether anything is there yet.
fn root_line(app: &App) -> String {
    let home = std::env::var("HOME").ok();
    match &app.platform.root {
        cli::GuestRoot::Present(path) => tilde(home.as_deref(), path),
        cli::GuestRoot::Absent(path) => {
            format!("{} (nothing there yet)", tilde(home.as_deref(), path))
        }
        cli::GuestRoot::Unset => "None: set $BOXDESK_GUEST_ROOT.".to_string(),
    }
}

/// A path spelled the way a person says it: `home` contracted to `~`.
fn tilde(home: Option<&str>, path: &std::path::Path) -> String {
    let spelled = path.display().to_string();
    match home {
        Some(home) if !home.is_empty() && spelled.starts_with(home) => {
            format!("~{}", &spelled[home.len()..])
        }
        _ => spelled,
    }
}

/// The notebook's own knobs, one heading block per area; a later knob joins its block.
pub(crate) fn settings<'a>(app: &'a App, sheet_of: &'a crate::Settings) -> Element<'a, Message> {
    let modes = row(crate::theme::MODES.iter().map(|mode| {
        let on = *mode == app.mode;
        button(text(mode.to_string()).size(BODY))
            .style(move |t, s| if on { segment(t) } else { push(t, s) })
            .padding(PAGE_PAD)
            .on_press(Message::SetTheme(*mode))
            .into()
    }))
    .spacing(6);
    let theme_note = if app.theme_overridden {
        "Started with --theme or $BOXDESK_THEME, which outranks this pick at the next launch."
    } else {
        "Light, dark, or whichever the desktop is showing."
    };
    let at = crate::SCALES
        .iter()
        .position(|s| s.0 == app.scale)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(1);
    let steps = u8::try_from(crate::SCALES.len() - 1).unwrap_or(3);
    let scale = column![
        slider(0..=steps, at, |i| Message::SetScale(
            crate::SCALES[usize::from(i)]
        ))
        .style(rail_of)
        .width(Fill),
        ticks(crate::SCALES.iter().map(ToString::to_string).collect()),
    ]
    .spacing(6);
    let mut body = column![
        setting(
            None,
            "Boxdesk",
            format!("version {}", env!("CARGO_PKG_VERSION")),
            space().width(0)
        ),
        setting(Some(icons::SUN_MOON), "Theme", theme_note, modes),
        stacked(
            Some(icons::SCALING),
            "Scale",
            "How large the notebook draws everything.",
            scale
        ),
        setting(
            Some(icons::ROCKET),
            "Open on a new run",
            "A plain launch shows the form instead of the notebook; --open and a named run \
             outrank it.",
            toggler(app.opens_on == crate::OpenScreen::New)
                .size(22)
                .style(switch)
                .on_toggle(|on| Message::SetOpensOn(if on {
                    crate::OpenScreen::New
                } else {
                    crate::OpenScreen::List
                })),
        ),
        setting(
            Some(icons::TERMINAL),
            "Command line",
            boxdesk_line(app),
            space().width(0)
        ),
        setting(
            Some(icons::FOLDER),
            "Guest root",
            root_line(app),
            space().width(0)
        ),
        row![
            space().width(Fill),
            page_button("Reset to defaults", push).on_press(Message::ResetSettings),
        ],
    ]
    .spacing(28)
    .width(Fill);
    if let Some(status) = &app.status {
        body = body.push(text(status).size(BODY));
    }

    // The foot carries the two answers; the head's way out is the shell's.
    let foot = row![
        space().width(Fill),
        page_button("Close", push).on_press(Message::SettingsClosed),
        // **Nothing to apply is a button that does nothing**, and the toolkit draws a button with
        // no message as the refused one it is. `Apply` lights up when a pick differs from what the
        // sheet opened with, and not before.
        page_button("Apply", primary).on_press_maybe(
            sheet_of
                .changed(app.picks())
                .then_some(Message::SettingsApplied)
        ),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center);

    sheet(
        app,
        "Settings",
        Message::SettingsClosed,
        body,
        Some(foot.into()),
    )
}

/// The card a sheet is drawn in: a head with its name and its way out, a body that scrolls
/// between two rules, and a foot where there is one.
///
/// Shared by both sheets, so the settings and the troubleshoot pages cannot come to be two shapes
/// of the same thing.
fn sheet<'a>(
    app: &'a App,
    title: &'a str,
    close: Message,
    body: iced::widget::Column<'a, Message>,
    foot: Option<Element<'a, Message>>,
) -> Element<'a, Message> {
    let mut body = body;
    if let Some(status) = &app.status {
        body = body.push(text(status).size(BODY));
    }
    let mut inside = column![
        row![
            text(title).size(HEAD).font(HEADING).width(Fill),
            icon_action(icons::CLOSE, "Close", Some(close.clone())),
        ]
        .align_y(iced::alignment::Vertical::Center),
        rule::horizontal(RULE).style(divider),
        container(scrollable(body).direction(lane()).style(scroll))
            .height(Fill)
            .padding(iced::Padding {
                top: SHEET_PAD,
                right: 0.0,
                bottom: SHEET_PAD,
                left: 0.0,
            }),
    ]
    .spacing(SHEET_PAD);
    if let Some(foot) = foot {
        inside = inside
            .push(rule::horizontal(RULE).style(divider))
            .push(foot);
    }

    let shown = container(inside)
        .padding(SHEET_PAD)
        .width(Length::Fixed(SHEET.0))
        .max_height(SHEET.1)
        .style(card);

    // Over everything, and `opaque`, so nothing behind the sheet answers a press while it is up.
    // A press on the wash closes it, as Escape does.
    iced::widget::opaque(
        mouse_area(iced::widget::center(iced::widget::opaque(shown)).style(scrim)).on_press(close),
    )
}

/// The troubleshoot sheet: what this machine has, and the handful of things that put it back.
///
/// **The read-only half comes first.** Every act below it either cannot be undone or opens
/// something outside the window, and the most useful thing this page does is let somebody say
/// what their machine looks like without having to know where any of it is.
pub(crate) fn troubleshoot(app: &App) -> Element<'_, Message> {
    let ended = app.runs.iter().filter(|r| !app.is_live(r)).count();
    let body = column![
        stacked(
            Some(icons::LIFE_BUOY),
            "What this machine has",
            "Paths and counts, never contents: the build, the host, and how much of what is \
             where. This is what a report needs.",
            column![
                container(
                    text(app.diagnostics())
                        .font(MONO)
                        .size(SMALL)
                        .style(|t| text::Style {
                            color: Some(muted(t)),
                        })
                )
                .width(Fill)
                .padding(12)
                .style(|theme: &iced::Theme| container::Style {
                    background: Some(crate::theme::recessed(theme).into()),
                    border: iced::Border {
                        radius: CORNER.into(),
                        ..iced::Border::default()
                    },
                    ..container::Style::default()
                }),
                row![
                    space().width(Fill),
                    small_button("Copy", push).on_press(Message::CopyDiagnostics),
                ],
            ]
            .spacing(10),
        ),
        setting(
            Some(icons::FOLDER_OPEN),
            "Where everything is kept",
            "Runs, snapshots, registries, volumes and images, in one place on this machine.",
            small_button("Show", push).on_press(Message::RevealData),
        ),
        setting(
            Some(icons::EXTERNAL_LINK),
            "Report a problem",
            "Opens the issue tracker. Paste what is above into it.",
            small_button("Open", push).on_press(Message::ReportProblem),
        ),
        rule::horizontal(RULE).style(divider),
        setting(
            Some(icons::TRASH),
            "Sweep the ended runs",
            "Every ended run's record, captured output and results go. A running sandbox is not \
             touched.",
            // Nothing to sweep is a button that does nothing, and the toolkit draws one with no
            // message as the refused one it is.
            small_button("Sweep", destructive)
                .on_press_maybe((ended > 0).then_some(Message::SweepEnded)),
        ),
        setting(
            Some(icons::TRASH),
            "Remove everything Boxdesk keeps",
            "Every store, and the settings with them. Volumes included \u{2014} what is in them \
             goes too, and nothing else has a copy.",
            small_button("Remove everything", destructive).on_press(Message::ResetEverything),
        ),
    ]
    .spacing(28)
    .width(Fill);

    sheet(app, "Troubleshoot", Message::Troubleshoot, body, None)
}

/// How big the settings sheet is: wide enough for a setting's name, its line and its control on
/// one row, and short enough that the page it is over is still visible around it.
const SHEET: (f32, f32) = (620.0, 640.0);

/// The room inside the sheet's edge, and between its head, its body and its foot.
const SHEET_PAD: f32 = 18.0;

/// One setting as a source-list app lays one out: its name over a grey line of what it does,
/// and the control at the row's right edge.
fn setting<'a>(
    icon: Option<icons::Icon>,
    title: &'a str,
    what: impl text::IntoFragment<'a>,
    control: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    row![labelled(icon, title, what).width(Fill), control.into()]
        .spacing(16)
        .align_y(iced::alignment::Vertical::Center)
        .into()
}

/// A setting's name over its line, with its icon at the left where there is one.
fn labelled<'a>(
    icon: Option<icons::Icon>,
    title: &'a str,
    what: impl text::IntoFragment<'a>,
) -> iced::widget::Row<'a, Message> {
    let mut line = row![].spacing(12);
    if let Some(icon) = icon {
        line = line.push(icons::glyph(icon));
    }
    line.push(
        column![text(title).size(TAB), muted_line(what, BODY)]
            .spacing(4)
            .width(Fill),
    )
}

/// A setting whose control wants the row's whole width, so it sits under the line instead.
fn stacked<'a>(
    icon: Option<icons::Icon>,
    title: &'a str,
    what: impl text::IntoFragment<'a>,
    control: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    column![labelled(icon, title, what), control.into()]
        .spacing(6)
        .into()
}

/// The labels under a stepped slider, one per step, the first flush left and the last flush
/// right so each sits under its notch.
fn ticks<'a>(labels: Vec<String>) -> Element<'a, Message> {
    let mut line = row![].width(Fill);
    let last = labels.len().saturating_sub(1);
    for (i, label) in labels.into_iter().enumerate() {
        line = line.push(muted_line(label, SMALL));
        if i < last {
            line = line.push(space().width(Fill));
        }
    }
    line.into()
}

/// The segment that is picked: the same bordered shape as [`push`], a step of grey darker.
fn segment(theme: &iced::Theme) -> button::Style {
    let palette = theme.extended_palette();
    let mut style = role(
        crate::theme::selected(theme),
        palette.background.base.text,
        Some(hairline(theme)),
        button::Status::Active,
    );
    style.shadow = RAISE;
    style
}

/// How wide the slider's handle is drawn, which is the diameter the round one had.
const HANDLE: u16 = 18;

/// A slider as macOS draws one on a settings page: a grey rail, a white handle held by a hairline.
fn rail_of(theme: &iced::Theme, status: slider::Status) -> slider::Style {
    let palette = theme.extended_palette();
    let mut style = slider::default(theme, status);
    let rail = iced::Background::Color(crate::theme::selected(theme));
    style.rail.backgrounds = (rail, rail);
    style.rail.width = 4.0;
    style.handle = slider::Handle {
        shape: slider::HandleShape::Rectangle {
            width: HANDLE,
            border_radius: CORNER.into(),
        },
        background: iced::Background::Color(palette.background.base.color),
        border_width: 1.0,
        border_color: hairline(theme),
    };
    style
}

/// A switch as macOS draws one: grey when off, the accent when on, a white knob either way.
fn switch(theme: &iced::Theme, status: toggler::Status) -> toggler::Style {
    let palette = theme.extended_palette();
    let mut style = toggler::default(theme, status);
    let on = matches!(
        status,
        toggler::Status::Active { is_toggled: true }
            | toggler::Status::Hovered { is_toggled: true }
    );
    style.background = iced::Background::Color(if on {
        palette.primary.base.color
    } else {
        crate::theme::selected(theme)
    });
    style.foreground = iced::Background::Color(iced::Color::WHITE);
    // `None` here is a switch drawn as two circles, which is the one shape [`CORNER`] would not
    // otherwise reach.
    style.border_radius = Some(CORNER.into());
    style
}

/// The corner every control takes: a button, a card, a field, the mark under a lone icon, the
/// switch and the slider's handle.
///
/// **One value, so the window cannot end up with two corners.** Square as of 2026-09-09; one
/// number here is what rounds the whole window again.
/// `every_control_takes_the_windows_own_corner` holds each of them to it.
const CORNER: f32 = 0.0;

/// The hairline every surface is held by: a subtle edge scaled against the palette's text.
fn hairline(theme: &iced::Theme) -> iced::Color {
    theme
        .extended_palette()
        .background
        .base
        .text
        .scale_alpha(if theme.extended_palette().is_dark {
            0.18
        } else {
            0.20
        })
}

/// A rule between two panes, or across a form: a visible divider line.
fn divider(theme: &iced::Theme) -> rule::Style {
    let alpha = if theme.extended_palette().is_dark {
        0.20
    } else {
        0.25
    };
    rule::Style {
        color: theme
            .extended_palette()
            .background
            .base
            .text
            .scale_alpha(alpha),
        radius: 0.0.into(),
        fill_mode: rule::FillMode::Full,
        snap: true,
    }
}

/// The faint shadow under a push button's edge, as macOS sets one on the page.
const RAISE: iced::Shadow = iced::Shadow {
    color: iced::Color {
        a: 0.08,
        ..iced::Color::BLACK
    },
    offset: iced::Vector::new(0.0, 1.0),
    blur_radius: 2.0,
};

/// A push button as macOS draws one: the page's own surface inside a hairline, no colour of its
/// own, a step of grey under the pointer. Every action here is one of these.
fn push(theme: &iced::Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();
    bordered(theme, palette.background.base.text, status)
}

/// The default action, as macOS fills one: the accent under the label it carries, a step darker
/// under the pointer. One to a screen, or none of them reads as the way out.
fn primary(theme: &iced::Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();
    let surface = match status {
        button::Status::Hovered | button::Status::Pressed => palette.primary.strong.color,
        button::Status::Active | button::Status::Disabled => palette.primary.base.color,
    };
    let mut style = role(surface, palette.primary.base.text, None, status);
    style.shadow = RAISE;
    style
}

/// The destructive act: the same push button, its label in the palette's danger.
fn destructive(theme: &iced::Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();
    bordered(theme, palette.danger.base.color, status)
}

/// Navigation that stays quiet until the pointer finds it: no edge, the same grey under it.
fn ghost(theme: &iced::Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();
    let surface = match status {
        button::Status::Hovered | button::Status::Pressed => crate::theme::hovered(theme),
        button::Status::Active | button::Status::Disabled => iced::Color::TRANSPARENT,
    };
    role(surface, palette.background.base.text, None, status)
}

/// The shape [`push`] and [`destructive`] share, differing only in what colour the label is.
fn bordered(theme: &iced::Theme, text: iced::Color, status: button::Status) -> button::Style {
    let surface = match status {
        button::Status::Hovered | button::Status::Pressed => crate::theme::hovered(theme),
        button::Status::Active | button::Status::Disabled => crate::theme::raised(theme),
    };
    let mut style = role(surface, text, Some(hairline(theme)), status);
    style.shadow = RAISE;
    style
}

/// One shape for every role: a fill on the corner, an optional hairline, and the whole control
/// fading when disabled, the way a macOS dialog draws its buttons.
fn role(
    surface: iced::Color,
    text: iced::Color,
    edge: Option<iced::Color>,
    status: button::Status,
) -> button::Style {
    let faded = matches!(status, button::Status::Disabled);
    let dim = |color: iced::Color| if faded { color.scale_alpha(0.5) } else { color };
    button::Style {
        background: Some(iced::Background::Color(dim(surface))),
        text_color: dim(text),
        border: iced::Border {
            color: edge.map_or(iced::Color::TRANSPARENT, dim),
            width: f32::from(u8::from(edge.is_some())),
            radius: CORNER.into(),
        },
        ..button::Style::default()
    }
}

/// A card: the page's own surface a shade lifted, held by a hairline border.
fn card(theme: &iced::Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(crate::theme::raised(theme))),
        border: iced::Border {
            color: hairline(theme),
            width: 1.0,
            radius: CORNER.into(),
        },
        ..container::Style::default()
    }
}

/// The snapshots: sandboxes worth making again, by name.
///
/// A row is a template, not a run. Pressing one fills the start form from it — the same form a
/// re-run fills — so what a snapshot does is put you one press from a sandbox with that posture,
/// with every knob still open before it boots.
pub(crate) fn snapshots(app: &App) -> Element<'_, Message> {
    let head: Element<'_, Message> = row![
        head_title("Snapshots"),
        small_button("Create Snapshot", primary).on_press(Message::NewRun),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center)
    .into();

    // The band's field narrows this list too: one search, whichever page is showing.
    let shown: Vec<&boxdesk_record::Snapshot> = app
        .snapshots()
        .iter()
        .filter(|s| app.matches_snapshot(s))
        .collect();

    let mut rows = column![].spacing(8);
    if app.snapshots().is_empty() {
        rows = rows.push(
            column![
                muted_line(
                    "No snapshots yet. A snapshot is a sandbox worth making again: fill the \
                     start form, name it, and save it there — or write one with `boxdesk \
                     snapshot new`.",
                    BODY,
                ),
                small_button("Create Sandbox", push).on_press(Message::NewRun),
            ]
            .spacing(12),
        );
    } else if shown.is_empty() {
        rows = rows.push(
            text(format!(
                "No snapshot matches \u{201c}{}\u{201d}.",
                app.search().trim()
            ))
            .size(BODY)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
        );
    } else {
        rows = rows.push(section("SNAPSHOTS", shown.len()));
        for snapshot in &shown {
            rows = rows.push(snapshot_row(snapshot));
        }
    }

    framed(
        head,
        column![
            scrollable(rows)
                .direction(lane())
                .style(scroll)
                .height(Fill)
        ]
        .spacing(14),
    )
}

/// One snapshot's card: its name, what it is for, and the posture a sandbox from it would get.
///
/// **The same three lines a run's row shows**, in the same places, because it is the same posture
/// read a moment earlier: a reader who has learned one row has learned both.
fn snapshot_row(snapshot: &boxdesk_record::Snapshot) -> Element<'static, Message> {
    let name = snapshot.name.clone();
    // What it is for, in the words whoever wrote it chose — or failing that, the command it
    // would run, which is the next most useful thing to say about a template.
    let about = if !snapshot.about.is_empty() {
        snapshot.about.clone()
    } else if snapshot.command.is_empty() {
        "a sandbox to exec into".to_string()
    } else {
        snapshot.command.join(" ")
    };
    let title = row![
        icons::glyph(icons::BOX),
        text(snapshot.name.clone()).font(NAME).size(TITLE),
        space().width(Fill),
    ]
    .spacing(8)
    .align_y(iced::alignment::Vertical::Center);
    let lines = column![
        title,
        text(about)
            .font(MONO)
            .size(BODY)
            .wrapping(text::Wrapping::None)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
        text(posture_tags_of(&snapshot.posture))
            .size(SMALL)
            .wrapping(text::Wrapping::None)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
    ]
    .spacing(4);
    // Two acts, not the run row's four: a template has nothing to stop and nothing to export.
    let acts = row![
        icon_action(
            icons::PLAY,
            "Create Sandbox",
            Some(Message::UseSnapshot(name.clone())),
        ),
        icon_action(
            icons::TRASH,
            "Delete",
            Some(Message::ForgetSnapshot(name.clone())),
        ),
    ]
    .spacing(2)
    .align_y(iced::alignment::Vertical::Center);
    button(
        row![container(lines).width(Fill).clip(true), acts]
            .spacing(12)
            .align_y(iced::alignment::Vertical::Center),
    )
    .width(Fill)
    .padding(12)
    .style(row_card)
    .on_press(Message::UseSnapshot(name))
    .into()
}

/// The registries: where images come from, and who this machine is when it asks.
///
/// **A row is an address, never a secret.** The store holds a host, a project and a username and
/// no password at all — one is read from `$BOXDESK_REGISTRY_PASSWORD` at the moment a pull needs
/// it. This page says so rather than leaving a reader to wonder where the password went.
pub(crate) fn registries(app: &App) -> Element<'_, Message> {
    let head = row![
        head_title("Registries"),
        small_button("Add Registry", primary).on_press(Message::NewRegistry),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center)
    .into();

    let shown: Vec<&boxdesk_record::Registry> = app
        .registries()
        .iter()
        .filter(|r| app.matches_registry(r))
        .collect();

    let mut rows = column![].spacing(8);
    if app.registries().is_empty() {
        rows = rows.push(
            column![
                muted_line(
                    "No registries yet. A public image needs none — `boxdesk pull alpine:3.20` \
                     works as it stands. Add one to say who this machine is when it asks a \
                     registry that wants to know: `boxdesk registry add work ghcr.io --username \
                     you`.",
                    BODY,
                ),
                muted_line(
                    "The password is never kept here. It is read from \
                     $BOXDESK_REGISTRY_PASSWORD at the moment a pull needs it.",
                    SMALL,
                ),
            ]
            .spacing(12),
        );
    } else if shown.is_empty() {
        rows = rows.push(
            text(format!(
                "No registry matches \u{201c}{}\u{201d}.",
                app.search().trim()
            ))
            .size(BODY)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
        );
    } else {
        rows = rows.push(section("REGISTRIES", shown.len()));
        for registry in &shown {
            rows = rows.push(registry_row(registry));
        }
    }

    framed(
        head,
        column![
            scrollable(rows)
                .direction(lane())
                .style(scroll)
                .height(Fill)
        ]
        .spacing(14),
    )
}

/// The form for a new registry: four boxes, and a line saying where the password is not.
pub(crate) fn new_registry(app: &App) -> Element<'_, Message> {
    let form = app.registry_form();
    let field =
        |label: &'static str, value: &str, which: crate::RegistryField, hint: &'static str| {
            column![
                row![
                    text(label).width(Length::Fixed(FORM_LABEL)),
                    text_input("", value)
                        .style(entry)
                        .on_input(move |v| Message::RegistryField(which, v))
                        .font(MONO)
                        .width(Fill),
                ]
                .spacing(8)
                .align_y(iced::alignment::Vertical::Center),
                row![
                    space().width(Length::Fixed(FORM_LABEL)),
                    muted_line(hint, SMALL),
                ]
                .spacing(8),
            ]
            .spacing(4)
        };
    let mut page = column![
        field(
            "Name",
            &form.name,
            crate::RegistryField::Name,
            "what this is listed under here; letters, digits, - and _",
        ),
        field(
            "Host",
            &form.url,
            crate::RegistryField::Url,
            "as it appears in an image reference: ghcr.io, docker.io",
        ),
        field(
            "Project",
            &form.project,
            crate::RegistryField::Project,
            "the namespace or organisation images sit under, if there is one",
        ),
        field(
            "Username",
            &form.username,
            crate::RegistryField::Username,
            "who this machine signs in as; leave it empty for public images",
        ),
        rule::horizontal(1).style(divider),
        // Said on the form, where somebody is looking for the box to type it in.
        muted_line(
            "There is no password box. A registry file is a file that gets copied and \
             backed up, so nothing here keeps one: set $BOXDESK_REGISTRY_PASSWORD and a pull \
             reads it at the moment it needs it.",
            BODY,
        ),
        row![
            space().width(Fill),
            page_button("Cancel", push).on_press(Message::Registries),
            page_button("Add registry", primary).on_press(Message::AddRegistry),
        ]
        .spacing(12),
    ]
    .spacing(10)
    .width(Fill);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(BODY));
    }
    framed(
        head_title("New registry"),
        column![scrollable(page).direction(lane()).style(scroll)].width(Fill),
    )
}

/// One registry's card: its handle, where it is, and who this machine is there.
fn registry_row(registry: &boxdesk_record::Registry) -> Element<'static, Message> {
    let name = registry.name.clone();
    let where_it_is = if registry.project.is_empty() {
        registry.url.clone()
    } else {
        format!("{}/{}", registry.url, registry.project)
    };
    // Said on every row, because "who am I here" is the question a registry list exists to answer,
    // and a blank would read as a field nobody filled rather than as a deliberate anonymous pull.
    let who = if registry.username.is_empty() {
        "anonymous \u{2014} public images only".to_string()
    } else {
        format!("as {}", registry.username)
    };
    let title = row![
        icons::glyph(icons::PACKAGE_OPEN),
        text(registry.name.clone()).font(NAME).size(TITLE),
        space().width(Fill),
    ]
    .spacing(8)
    .align_y(iced::alignment::Vertical::Center);
    let lines = column![
        title,
        text(where_it_is)
            .font(MONO)
            .size(BODY)
            .wrapping(text::Wrapping::None)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
        text(who)
            .size(SMALL)
            .wrapping(text::Wrapping::None)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
    ]
    .spacing(4);
    let acts = row![icon_action(
        icons::TRASH,
        "Delete",
        Some(Message::ForgetRegistry(name)),
    )]
    .align_y(iced::alignment::Vertical::Center);
    container(
        row![container(lines).width(Fill).clip(true), acts]
            .spacing(12)
            .align_y(iced::alignment::Vertical::Center),
    )
    .width(Fill)
    .padding(12)
    .style(card)
    .into()
}

/// The volumes: directories with lives of their own, mounted into sandboxes by name.
///
/// **What a row says that a run's row cannot is how much is in it.** A volume exists because its
/// contents outlived the run that wrote them, so the size is the fact somebody scanning this page
/// is actually after.
pub(crate) fn volumes(app: &App) -> Element<'_, Message> {
    let head: Element<'_, Message> = row![
        head_title("Volumes"),
        small_button("Create Volume", primary).on_press(Message::NewVolume),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center)
    .into();

    let shown: Vec<&(boxdesk_record::Volume, u64)> = app
        .volumes()
        .iter()
        .filter(|(v, _)| app.matches_volume(v))
        .collect();

    let mut rows = column![].spacing(8);
    if app.volumes().is_empty() {
        rows = rows.push(
            column![
                muted_line(
                    "No volumes yet. A volume is a directory that outlives the sandbox that \
                     wrote it: make one here, mount it with `boxdesk run --volume NAME:/work`, \
                     and what a guest leaves in it is still there for the next one.",
                    BODY,
                ),
                // Said plainly, because the page this is modelled on says the opposite and
                // somebody arriving from it will be looking for the bucket.
                muted_line(
                    "Local only \u{2014} a directory on this machine, not an object store and \
                     not shared between machines.",
                    SMALL,
                ),
                small_button("Create Volume", push).on_press(Message::NewVolume),
            ]
            .spacing(12),
        );
    } else if shown.is_empty() {
        rows = rows.push(
            text(format!(
                "No volume matches \u{201c}{}\u{201d}.",
                app.search().trim()
            ))
            .size(BODY)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
        );
    } else {
        rows = rows.push(section("VOLUMES", shown.len()));
        for (volume, held) in &shown {
            rows = rows.push(volume_row(volume, *held));
        }
    }

    framed(
        head,
        column![
            scrollable(rows)
                .direction(lane())
                .style(scroll)
                .height(Fill)
        ]
        .spacing(14),
    )
}

/// One volume's card: its name, what is in it, and how it is mounted.
fn volume_row(volume: &boxdesk_record::Volume, held: u64) -> Element<'static, Message> {
    let name = volume.name.clone();
    let about = if volume.about.is_empty() {
        format!("--volume {name}:/work")
    } else {
        volume.about.clone()
    };
    let title = row![
        icons::glyph(icons::HARD_DRIVE),
        text(volume.name.clone()).font(NAME).size(TITLE),
        space().width(Fill),
        text(held_as_words(held))
            .size(SMALL)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
    ]
    .spacing(8)
    .align_y(iced::alignment::Vertical::Center);
    let lines = column![
        title,
        text(about)
            .font(MONO)
            .size(BODY)
            .wrapping(text::Wrapping::None)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
    ]
    .spacing(4);
    let acts = row![icon_action(
        icons::TRASH,
        "Delete",
        Some(Message::ForgetVolume(name)),
    )]
    .align_y(iced::alignment::Vertical::Center);
    container(
        row![container(lines).width(Fill).clip(true), acts]
            .spacing(12)
            .align_y(iced::alignment::Vertical::Center),
    )
    .width(Fill)
    .padding(12)
    .style(card)
    .into()
}

/// A byte count in the units a directory listing uses. The CLI spells it the same way; this is the
/// window's copy because the two crates share no formatting.
fn held_as_words(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[expect(
        clippy::cast_precision_loss,
        reason = "a size shown to a person, where the last significant figure is not one"
    )]
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// The form for a new volume: a name, and a line about what will be in it.
pub(crate) fn new_volume(app: &App) -> Element<'_, Message> {
    let form = app.volume_form();
    let field =
        |label: &'static str, value: &str, which: crate::VolumeField, hint: &'static str| {
            column![
                row![
                    text(label).width(Length::Fixed(FORM_LABEL)),
                    text_input("", value)
                        .style(entry)
                        .on_input(move |v| Message::VolumeField(which, v))
                        .font(MONO)
                        .width(Fill),
                ]
                .spacing(8)
                .align_y(iced::alignment::Vertical::Center),
                row![
                    space().width(Length::Fixed(FORM_LABEL)),
                    muted_line(hint, SMALL),
                ]
                .spacing(8),
            ]
            .spacing(4)
        };
    let mut page = column![
        field(
            "Name",
            &form.name,
            crate::VolumeField::Name,
            "what sandboxes mount it by; letters, digits, - and _",
        ),
        field(
            "About",
            &form.about,
            crate::VolumeField::About,
            "one line saying what will be in it",
        ),
        rule::horizontal(1).style(divider),
        muted_line(
            "It starts empty. Mount it with `boxdesk run --volume NAME:/work`, and the guest \
             path has to be a directory the image already has \u{2014} the same rule `--mount` \
             keeps.",
            BODY,
        ),
        row![
            space().width(Fill),
            page_button("Cancel", push).on_press(Message::Volumes),
            page_button("Create volume", primary).on_press(Message::AddVolume),
        ]
        .spacing(12),
    ]
    .spacing(10)
    .width(Fill);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(BODY));
    }
    framed(
        head_title("New volume"),
        column![scrollable(page).direction(lane()).style(scroll)].width(Fill),
    )
}

/// A tick box on the window's own corner. Like the switch and the slider's handle, the toolkit
/// rounds its own unless a style says not to.
fn check(theme: &iced::Theme, status: checkbox::Status) -> checkbox::Style {
    let mut style = checkbox::primary(theme, status);
    style.border.radius = CORNER.into();
    style
}

/// A text entry as macOS draws one: the default look on a rounded corner.
fn entry(theme: &iced::Theme, status: text_input::Status) -> text_input::Style {
    let mut style = text_input::default(theme, status);
    style.background = iced::Background::Color(crate::theme::raised(theme));
    style.border.radius = CORNER.into();
    style
}

/// The notebook: what is running, then what has run.
pub(crate) fn list(app: &App) -> Element<'_, Message> {
    // The band's field narrows both sections, so a search is one list of what matched rather
    // than a running section that ignored it and a history that did not.
    let shown: Vec<&Record> = app.runs.iter().filter(|r| app.matches_search(r)).collect();
    let live: Vec<&Record> = shown.iter().copied().filter(|r| app.is_live(r)).collect();
    let past: Vec<&Record> = shown.iter().copied().filter(|r| !app.is_live(r)).collect();
    let start = row![head_title("Sandboxes")];
    let header = match &app.list {
        crate::ListMode::Selecting(ids) => {
            let every = past.len();
            let all = ids.len() == every && every > 0;
            row![
                head_title(format!("{} of {every} selected", ids.len())),
                small_button(if all { "None" } else { "All" }, push)
                    .on_press(Message::SelectAll(!all)),
                // Nothing selected is nothing to remove, and iced draws a button with no message as
                // the disabled one it is.
                small_button("Remove", destructive)
                    .on_press_maybe((!ids.is_empty()).then_some(Message::RemoveSelected)),
                small_button("Done", push).on_press(Message::SelectCancelled),
            ]
        }
        crate::ListMode::Browsing => {
            let mut ordinary = start;
            if !past.is_empty() {
                ordinary = ordinary.push(small_button("Select", push).on_press(Message::Select));
            }
            // The page's one filled button, at the end of its own head: the sidebar names features
            // and this is where the verb for this one lives.
            ordinary.push(small_button("Create Sandbox", primary).on_press(Message::NewRun))
        }
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
    if shown.is_empty() && !app.runs.is_empty() {
        rows = rows.push(
            text(format!(
                "No sandbox matches \u{201c}{}\u{201d}.",
                app.search().trim()
            ))
            .size(BODY)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
        );
    }
    if app.runs.is_empty() {
        rows = rows.push(
            text(
                "No sandboxes yet. Create one here, or with `boxdesk run`, `boxdesk shell` \
                 or `boxdesk up`.",
            )
            .size(BODY)
            .style(|t| text::Style {
                color: Some(muted(t)),
            }),
        );
    }
    // A card is read left to right, so it stops where reading does: a row stretched across a wide
    // window puts its two halves too far apart to take in at once.
    let mut body = column![
        scrollable(rows)
            .direction(lane())
            .style(scroll)
            .height(Fill)
    ]
    .spacing(14)
    .width(Fill);
    if let Some(status) = &app.status {
        body = body.push(text(status).size(BODY));
    }
    framed(header.into(), body)
}

/// The width a page of cards stops at, in logical pixels.
const PAGE: f32 = 1000.0;

/// The inset a pane's own name and its actions sit at, off the sidebar and the window's edge.
pub(crate) const GUTTER: f32 = 24.0;

/// Where the page begins, from the window's own top edge rather than from the head above it, so
/// that the room a reader sees does not follow the head's height.
const PAGE_TOP: f32 = 82.0;

/// A screen the sidebar opened: its name at the pane's own edge, its content centred under it at
/// the width a row is still taken in at one glance, on the surface the band and the panel share.
fn framed<'a>(
    head: Element<'a, Message>,
    body: iced::widget::Column<'a, Message>,
) -> Element<'a, Message> {
    container(column![
        head_bar(head),
        container(body.max_width(PAGE))
            .width(Fill)
            .height(Fill)
            .padding(iced::Padding {
                top: PAGE_TOP - HEAD_BAR,
                right: GUTTER,
                bottom: GUTTER,
                left: GUTTER,
            }),
    ])
    .width(Fill)
    .height(Fill)
    .style(|theme: &iced::Theme| container::Style {
        background: Some(crate::theme::raised(theme).into()),
        ..container::Style::default()
    })
    .into()
}

/// A pane's own name on a head's line, centred by its own line box.
///
/// No cap-height correction: the toggle beside it is a glyph in a font, so centring both by the
/// line box is one rule for both, where a constant would be a guess at one font's cap metrics.
fn head_title<'a>(name: impl text::IntoFragment<'a>) -> Element<'a, Message> {
    container(
        text(name)
            .size(HEAD)
            .font(HEADING)
            .line_height(1.0)
            .wrapping(text::Wrapping::None),
    )
    // The title takes the free space and gives it back first. A row hands its fixed children
    // their width before a `Fill` one, so the buttons keep theirs and the name is what clips;
    // without this the name held its whole width and pushed `New run` off the window.
    .width(Fill)
    .clip(true)
    .into()
}

/// A control that has to fit a line rather than a page: a head's, whose room the traffic lights
/// set, or the end of a row in the notebook.
fn small_button<'a>(
    label: &'a str,
    style: fn(&iced::Theme, button::Status) -> button::Style,
) -> iced::widget::Button<'a, Message> {
    button(text(label).size(BODY).wrapping(text::Wrapping::None))
        .style(style)
        .padding(SMALL_PAD)
}

/// The room around a control that fits a line, and around a page's action.
const SMALL_PAD: [f32; 2] = [4.0, 10.0];
const PAGE_PAD: [f32; 2] = [6.0, 14.0];

/// A page's committing action, at the end of a form: the notebook's own type on the room macOS
/// gives a dialog's push button, which is more than a control on a line gets.
fn page_button<'a>(
    label: &'a str,
    style: fn(&iced::Theme, button::Status) -> button::Style,
) -> iced::widget::Button<'a, Message> {
    button(text(label).size(BODY))
        .style(style)
        .padding(PAGE_PAD)
}

/// The control that closes the window, at the end of every head where the platform draws no
/// close button of its own. The sandboxes are their own processes and outlive this window, so
/// there is nothing to confirm: quitting puts the notebook away, it does not stop a run.
fn quit_button<'a>() -> Element<'a, Message> {
    button(icons::glyph(icons::CLOSE).center().width(HALO))
        .style(halo)
        .padding(0)
        .height(HALO)
        .on_press(Message::Quit)
        .into()
}

/// A window's head: one row centred on the line the traffic lights sit on, and clear of them.
///
/// The head fills the line, so whatever it puts at its own right edge stays there and the quit
/// control sits outside it: on the notebook that puts the quit beyond `New run`.
fn head_bar<'a>(head: Element<'a, Message>) -> Element<'a, Message> {
    let line: Element<'a, Message> = if crate::chrome::DRAWS_ITS_OWN_QUIT {
        row![container(head).width(Fill), quit_button()]
            .align_y(iced::alignment::Vertical::Center)
            .spacing(12)
            .into()
    } else {
        head
    };
    container(line)
        .height(HEAD_BAR)
        .align_y(iced::alignment::Vertical::Center)
        .padding(iced::Padding {
            top: 0.0,
            right: GUTTER,
            bottom: 0.0,
            left: GUTTER,
        })
        .width(Fill)
        .into()
}

/// The sidebar's width: the nav labels plus their counts, and no more.
pub(crate) const SIDEBAR: f32 = 200.0;

/// The width it folds to: a rail of icons with the words gone.
///
/// **Derived, not chosen**, and that is what centres the column. A tab is padded [`TAB_PAD`] on
/// each side of the icon it starts with, inside a rail padded [`RAIL_PAD`] on each side of the
/// pill; adding those to the icon is the width at which the icon is exactly centred in its own
/// pill. So the glyphs do not shift sideways as the labels go — the column stands still and the
/// words leave it.
const RAIL_FOLDED: f32 = RAIL_PAD * 2.0 + TAB_PAD[1] * 2.0 + icons::SIZE;

/// The rule between the two panes.
const RULE: f32 = 1.0;

/// How wide the sidebar stands, at this much of the fold.
fn rail_width(out: f32) -> f32 {
    RAIL_FOLDED + (SIDEBAR - RAIL_FOLDED) * out
}

/// A sidebar row's label, a step up from body text, as a source list sets one.
const TAB: f32 = 14.0;

/// The gap between a tab's icon and its word.
///
/// **Inside the label's own box, not spacing on the row.** Spacing is added between children
/// whether or not there is room for it, so folded — where what is left for the label is nothing —
/// a row of icon, spacing and label came to 12 more than the cell it had, overflowed, and drew
/// its glyph off the centre it was supposed to hold. Padding lives inside the label's width, so
/// when that width is nothing the gap goes with it and the row is exactly its icon.
const LABEL_GAP: f32 = 12.0;

/// The one heading style: small, muted and set apart, on a pane and on a section alike.
fn heading(title: &str) -> Element<'_, Message> {
    text(title)
        .size(SMALL)
        .font(HEADING)
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
            boxdesk_record::format_duration(
                boxdesk_record::now_ms().saturating_sub(record.started_ms)
            )
        )
    } else {
        let end = record.end.map(|e| e.to_string()).unwrap_or_default();
        match record.ended_ms {
            Some(ended) => format!(
                "{end} · {}",
                boxdesk_record::format_duration(ended.saturating_sub(record.started_ms))
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
    ]
    .spacing(8)
    .align_y(iced::alignment::Vertical::Center);
    let title = title.push(space().width(Fill));
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
    // Clipped to the room the row leaves it: each line is unwrapped, so a long command draws its
    // whole width and would otherwise run across the state and the actions beside it.
    let text_side = container(column![title, command, posture].spacing(4)).clip(true);
    // A running sandbox with a display shows it, so the list says what each one is doing rather
    // than only what it was asked to do.
    let told: Element<'_, Message> = match crate::frame_program(app, &crate::RunName::of(record)) {
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
    let state_text = text(state)
        .size(SMALL)
        .wrapping(text::Wrapping::None)
        .style(move |t| text::Style {
            color: Some(muted(t)),
        });
    // While a selection is being made every row reads the same way: a box says whether it is in, and
    // the row's own actions step aside so the only destructive press is the header's.
    let selecting = app.list.is_selecting();
    let selected = app.list.selected().contains(record.id.as_str());
    let mut body = row![];
    if selecting {
        // A live run is refused a delete, so it is shown as something that cannot be selected
        // rather than offered a box that would not answer.
        let box_icon = if live {
            icons::glyph(icons::SQUARE).style(|t| text::Style {
                color: Some(muted(t).scale_alpha(0.4)),
            })
        } else if selected {
            icons::glyph(icons::SQUARE_CHECK)
        } else {
            icons::glyph(icons::SQUARE)
        };
        body = body.push(box_icon);
    }
    body = body.push(told).push(state_text);
    if !selecting {
        // What this row can be told to do, at its own end: a sandbox is stopped where it is
        // listed rather than only on its own screen. There is no pause, because libkrun has no
        // suspend.
        body = body.push(row_actions(record, live));
    }
    let body = body.spacing(12).align_y(iced::alignment::Vertical::Center);
    // A button rather than a container under a `mouse_area`: the row is a thing you click, so it
    // answers the pointer with the step of grey a source list gives a row under one. A nested
    // checkbox would never see the press, which is why the whole row is the target.
    let press = match (selecting, live) {
        (true, true) => None,
        (true, false) => Some(Message::SelectToggle(crate::RunId::of(record))),
        (false, _) => Some(Message::Open(crate::RunId::of(record))),
    };
    button(body)
        .width(Fill)
        .padding(12)
        .style(row_card)
        .on_press_maybe(press)
        .into()
}

/// A card that is a row you click: the raised surface, a step under the pointer, a hairline edge.
fn row_card(theme: &iced::Theme, status: button::Status) -> button::Style {
    let surface = match status {
        button::Status::Hovered | button::Status::Pressed => crate::theme::raised_hovered(theme),
        button::Status::Active | button::Status::Disabled => crate::theme::raised(theme),
    };
    let mut style = role(
        surface,
        theme.extended_palette().background.base.text,
        Some(hairline(theme)),
        status,
    );
    style.border.radius = CORNER.into();
    style
}

/// What a row can be told to do, as four icons standing in the same four places on every row.
///
/// **A column holds whether or not the row can use it.** An act a row cannot do is drawn faded
/// rather than dropped: an icon that moves between rows is an icon the pointer has to hunt for,
/// and a faded one says *stop it first* where a missing one says nothing. Every glyph carries its
/// word under the pointer, because an icon alone is a guess until you press it.
///
/// **No overflow behind a `\u{2026}`.** Four acts fit four columns; a menu is what a row grows when
/// it has more to offer than it has room for, and this one does not.
///
/// **`Delete` is never live.** That is the same rule the confirm keeps, said a step earlier.
fn row_actions<'a>(record: &Record, live: bool) -> iced::widget::Row<'a, Message> {
    let mut acts = row![].spacing(2);
    for (icon, word, press) in row_acts(record, live) {
        acts = acts.push(icon_action(icon, word, press));
    }
    acts.align_y(iced::alignment::Vertical::Center)
}

/// The four columns of [`row_actions`], in the order they stand, each with the glyph it wears, the
/// word it answers to, and what pressing it says — or `None` where this record cannot be told to
/// do it.
///
/// Split out from the drawing so the rule about which acts a record offers is a thing a test can
/// read. An `Element` is not.
fn row_acts(record: &Record, live: bool) -> [(icons::Icon, &'static str, Option<Message>); 4] {
    let id = crate::RunId::of(record);
    let name = crate::RunName::of(record);
    let verb = if live {
        (
            icons::CIRCLE_STOP,
            "Stop",
            Some(Message::Stop(name.clone())),
        )
    } else {
        (icons::PLAY, "Re-run", Some(Message::Rerun(id.clone())))
    };
    // Only an `up` sandbox has a guest left waiting to be entered: a `run` ends with its command,
    // and an ended record has nothing to attach to at all.
    let shell = (live && record.verb == Verb::Up).then(|| Message::Shell(name));
    [
        verb,
        (icons::SQUARE_TERMINAL, "Shell", shell),
        (icons::DOWNLOAD, "Export", Some(Message::Export(id.clone()))),
        (icons::TRASH, "Delete", (!live).then(|| Message::Delete(id))),
    ]
}

/// One of a row's icons: the glyph in a square the size the band's icons wear, and its word under
/// the pointer.
///
/// **The glyph is dimmed here rather than by the button.** A button fades a disabled label through
/// its `text_color`, and [`icons::glyph`] sets a colour of its own, so an icon button left to the
/// toolkit looks pressable when it is not.
fn icon_action<'a>(
    icon: icons::Icon,
    word: &'a str,
    press: Option<Message>,
) -> Element<'a, Message> {
    let offered = press.is_some();
    let glyph = icons::glyph(icon)
        .center()
        .width(HALO)
        .style(move |theme: &iced::Theme| text::Style {
            color: Some(if offered {
                crate::theme::icon(theme)
            } else {
                crate::theme::icon(theme).scale_alpha(0.35)
            }),
        });
    iced::widget::tooltip(
        button(glyph)
            .style(halo)
            .padding(0)
            .height(HALO)
            .on_press_maybe(press),
        container(text(word).size(SMALL).wrapping(text::Wrapping::None))
            .padding(SMALL_PAD)
            .style(|theme: &iced::Theme| container::Style {
                background: Some(crate::theme::raised(theme).into()),
                border: iced::Border {
                    color: hairline(theme),
                    width: 1.0,
                    radius: CORNER.into(),
                },
                shadow: RAISE,
                ..container::Style::default()
            }),
        iced::widget::tooltip::Position::Top,
    )
    .into()
}

/// How big a live sandbox's frame is in the list, in logical pixels. Wide enough to tell two
/// desktops apart at a glance, small enough that a screen of them is still a list.
const THUMBNAIL: (f32, f32) = (160.0, 120.0);

/// The posture in a glance, in words: the display, the network, and what of the host it can
/// reach. Abbreviations save a few characters and cost the reader the sentence, and this is the
/// line that says whether a sandbox could touch the network or a directory.
fn posture_tags(record: &Record) -> String {
    posture_tags_of(&record.posture)
}

/// The same, of a posture that is not a record's: what a snapshot promises a sandbox from it.
fn posture_tags_of(p: &boxdesk_record::Posture) -> String {
    let mut parts = Vec::new();
    if let Some(display) = p.display {
        parts.push(display.as_spec().replace('x', "\u{d7}"));
    }
    parts.push(
        if p.network == boxdesk_record::Network::Tsi {
            "network via host"
        } else {
            "no network"
        }
        .to_string(),
    );
    if p.rootfs == boxdesk_record::Rootfs::Writable {
        parts.push("writable root".to_string());
    }
    // One share is worth naming; several are worth counting, or the line outgrows the card.
    match (p.mounts.len(), p.shares.len()) {
        (0, 0) => parts.push("no host directories".to_string()),
        (1, 0) => {
            let m = &p.mounts[0];
            parts.push(format!(
                "{} \u{2190} {}",
                m.guest.display(),
                m.host.display()
            ));
        }
        (0, 1) => {
            let s = &p.shares[0];
            parts.push(format!("{} \u{2190} {}", s.tag, s.host.display()));
        }
        (m, sh) => parts.push(format!("{} host directories", m + sh)),
    }
    if p.results {
        parts.push(boxdesk_record::RESULTS_GUEST_PATH.to_string());
    }
    if p.sound {
        parts.push("sound".to_string());
    }
    if p.gpu {
        parts.push("gpu".to_string());
    }
    parts.join(" \u{b7} ")
}

/// One run: its record on the left, its display and output on the right.
pub(crate) fn run<'a>(app: &'a App, id: &crate::RunId) -> Element<'a, Message> {
    let Some(record) = app.record(id) else {
        return framed(
            small_button("← runs", ghost).on_press(Message::Back).into(),
            column![text(format!("the run {id} is no longer in the notebook")).size(BODY)],
        );
    };
    let live = app.is_live(record);
    let mut bar = row![
        small_button("← runs", ghost).on_press(Message::Back),
        // The name yields before the buttons do, as a head's title does: a run's own controls are
        // the only way to act on it, and a clipped name still says which run it is.
        container(
            text(&record.name)
                .font(MONO)
                .size(TITLE)
                .line_height(1.0)
                .wrapping(text::Wrapping::None)
        )
        .width(Fill)
        .clip(true),
    ]
    .spacing(12)
    .align_y(iced::alignment::Vertical::Center);
    bar =
        bar.push(small_button("Export", push).on_press(Message::Export(crate::RunId::of(record))));
    if live {
        if record.verb == Verb::Up {
            bar = bar.push(
                small_button("Shell", push).on_press(Message::Shell(crate::RunName::of(record))),
            );
        }
        bar = bar.push(
            small_button("Stop", destructive).on_press(Message::Stop(crate::RunName::of(record))),
        );
    } else {
        bar = bar
            .push(small_button("Re-run", push).on_press(Message::Rerun(crate::RunId::of(record))));
        bar = bar.push(
            small_button("Delete", destructive).on_press(Message::Delete(crate::RunId::of(record))),
        );
    }

    let home = std::env::var("HOME").ok();
    let left = scrollable(
        column![
            // Spelled as Settings spells the same paths: a guest root under home is most of this
            // column, and every character of that is `/Users/<you>`.
            pane("POSTURE", posture_lines(record, home.as_deref())),
            pane("RUN", run_lines(record, live)),
            pane("RESULTS", results_lines(app, record)),
        ]
        .spacing(12),
    )
    .direction(lane())
    .style(scroll)
    // A share of the window rather than a fixed width: the panes hold paths, and 340 logical
    // pixels of monospace broke a guest root across two lines on a narrow window.
    .width(Length::FillPortion(2));

    let mut right = column![].spacing(10);
    if live && record.posture.display.is_some() {
        let display: Element<'_, Message> =
            match crate::frame_program(app, &crate::RunName::of(record)) {
                Some(program) => shader(program).width(Fill).height(Fill).into(),
                None => container(text("leasing the display…").size(BODY))
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

    let body = row![
        left,
        rule::vertical(1).style(divider),
        right.width(Length::FillPortion(3))
    ]
    .spacing(12)
    .height(Fill);
    let mut page = column![
        head_bar(bar.into()),
        container(body).height(Fill).padding(iced::Padding {
            top: 0.0,
            right: GUTTER,
            bottom: GUTTER,
            left: GUTTER,
        }),
    ];
    if let Some(status) = &app.status {
        page = page.push(container(text(status).size(BODY)).padding([0.0, GUTTER]));
    }
    page.into()
}

/// The width a form's label column takes: the longest of them, so every field starts on one line.
const FORM_LABEL: f32 = 100.0;

/// The width a field holding a number takes, sized to the number rather than to the row.
const FORM_NUMBER: f32 = 96.0;

/// The width the label column of a pane takes, in logical pixels: the longest label plus a gap.
const LABEL: f32 = 74.0;

/// How many characters a pane's value column holds before [`elide`] cuts it.
///
/// **Measured, not chosen**: the value column is what is left of a [`FillPortion`](Length) of the
/// default window after the sidebar, the gutters, the card's padding and [`LABEL`], which is about
/// 342 logical pixels, and [`MONO`] at [`BODY`] advances about 7.8 of them. A narrower window
/// clips what is left, as a fixed column does; this only bounds the line.
const VALUE_CHARS: usize = 44;

/// `text` with its middle replaced by an ellipsis when it is longer than `max` characters.
///
/// **Both ends survive**, because a path's tail is the half that says which path it is: cutting
/// only the end leaves every guest root reading the same. Counts characters, not bytes, so a
/// multi-byte path is cut on a boundary.
fn elide(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max || max == 0 {
        return text.to_string();
    }
    // One character goes to the ellipsis, and the head keeps the smaller share: a run's own name
    // sits at the end of a path, and the directories above it repeat across every run.
    let keep = max - 1;
    let head = keep / 3;
    let tail = keep - head;
    let mut out: String = text.chars().take(head).collect();
    out.push('…');
    out.extend(text.chars().skip(count - tail));
    out
}

/// A checkbox's box, at the side macOS draws one beside body text.
const CHECK: f32 = 14.0;

/// A titled box of `label`, `value` rows, as two widgets so a long value wraps in its column.
fn pane<'a>(title: &'a str, rows: Vec<(String, String)>) -> Element<'a, Message> {
    let mut body = column![heading(title)].spacing(3);
    for (label, value) in rows {
        body = body.push(
            row![
                text(label)
                    .font(MONO)
                    .size(BODY)
                    .width(Length::Fixed(LABEL)),
                text(elide(&value, VALUE_CHARS))
                    .font(MONO)
                    .size(BODY)
                    .wrapping(text::Wrapping::None)
                    .width(Fill),
            ]
            .spacing(4),
        );
    }
    container(body.padding(10)).width(Fill).style(card).into()
}

fn posture_lines(record: &Record, home: Option<&str>) -> Vec<(String, String)> {
    let p = &record.posture;
    let mut lines = vec![(
        "root".to_string(),
        format!("{}, {}", tilde(home, &p.root), p.rootfs.as_word()),
    )];
    for m in &p.mounts {
        lines.push((
            "mount".to_string(),
            format!("{} = {}", m.guest.display(), tilde(home, &m.host)),
        ));
    }
    for s in &p.shares {
        lines.push((
            "share".to_string(),
            format!("{} = {}", s.tag, tilde(home, &s.host)),
        ));
    }
    if p.mounts.is_empty() && p.shares.is_empty() {
        lines.push(("share".to_string(), "none".to_string()));
    }
    // The names the record kept; a value was never written, so there is none to show.
    if !p.env.is_empty() {
        lines.push(("env".to_string(), p.env.join(", ")));
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
        "gpu".to_string(),
        if p.gpu { "on" } else { "off" }.to_string(),
    ));
    lines.push((
        "results".to_string(),
        if p.results {
            boxdesk_record::RESULTS_GUEST_PATH
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
            boxdesk_record::format_time(record.started_ms),
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
            lines.push(("ended".to_string(), boxdesk_record::format_time(ended)));
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
        let home = std::env::var("HOME").ok();
        return vec![(
            "(none)".to_string(),
            format!("in {}", tilde(home.as_deref(), &dir.results())),
        )];
    }
    // The file is the value here, not the label: a result's path is the long half, so it gets the
    // column that wraps.
    app.results
        .iter()
        .map(|(file, size)| (bytes(*size), file.display().to_string()))
        .collect()
}

/// The captured output: one button per stream, and the tail of the selected one.
fn output_pane<'a>(app: &'a App, record: &'a Record) -> iced::widget::Container<'a, Message> {
    let mut head = row![heading("OUTPUT"), space().width(Fill)].spacing(8);
    for stream in Stream::of(record.verb) {
        let on = app.output.stream == Some(*stream);
        head = head.push(
            button(text(stream.label()).size(BODY))
                .style(move |t, s| if on { segment(t) } else { push(t, s) })
                .padding(SMALL_PAD)
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
        text(note).size(SMALL),
        scrollable(text(&app.output.text).font(MONO).size(BODY))
            .direction(lane())
            .style(scroll)
            .height(Fill),
    ]
    .spacing(6)
    .padding(10);
    container(body).width(Fill).style(card)
}

/// A field's aside, indented into the value column so the left edge stays the labels'.
fn caption(line: &'static str) -> Element<'static, Message> {
    row![
        space().width(Length::Fixed(FORM_LABEL + 8.0)),
        text(line).size(SMALL).style(|t| text::Style {
            color: Some(muted(t)),
        }),
    ]
    .into()
}

/// The form for a new run, with the posture sentence above the buttons.
pub(crate) fn new_run<'a>(app: &'a App, form: &'a Form) -> Element<'a, Message> {
    let field = |label: &'static str, value: &'a str, which: Field, width: Length| {
        row![
            text(label).width(Length::Fixed(FORM_LABEL)),
            text_input("", value)
                .style(entry)
                .on_input(move |v| Message::Field(which, v))
                .font(MONO)
                .width(width),
        ]
        .spacing(8)
        .align_y(iced::alignment::Vertical::Center)
    };
    let switch = |label: &'static str, on: bool, which: Switch| {
        checkbox(on)
            .label(label)
            .size(CHECK)
            .style(check)
            .on_toggle(move |v| Message::Switch(which, v))
    };
    let mut posture = boxdesk_record::Posture::new(
        std::path::PathBuf::from(form.root.trim()),
        form.vcpus.trim().parse().unwrap_or(crate::DEFAULT_VCPUS),
        form.mem_mib
            .trim()
            .parse()
            .unwrap_or(crate::DEFAULT_MEM_MIB),
    );
    posture.rootfs = if form.writable_root {
        boxdesk_record::Rootfs::Writable
    } else {
        boxdesk_record::Rootfs::ReadOnly
    };
    posture.network = if form.network {
        boxdesk_record::Network::Tsi
    } else {
        boxdesk_record::Network::None
    };
    posture.mounts = form
        .mounts
        .split_whitespace()
        .filter_map(|m| m.split_once('='))
        .map(|(guest, host)| boxdesk_record::Mount::new(guest.into(), host.into()))
        .collect();
    posture.shares = form
        .shares
        .split_whitespace()
        .filter_map(|m| m.split_once('='))
        .map(|(tag, host)| boxdesk_record::Share::new(tag.to_string(), host.into()))
        .collect();
    posture.display = form
        .display
        .then(|| boxdesk_record::DisplayMode::parse(form.display_size.trim()))
        .flatten();
    posture.sound = form.sound;
    posture.gpu = form.gpu;
    posture.results = form.results;

    let mut page = column![
        field("Name", &form.name, Field::Name, Fill),
        field("Root", &form.root, Field::Root, Fill),
        switch(
            "The guest may write its root",
            form.writable_root,
            Switch::WritableRoot
        ),
        field("Command", &form.command, Field::Command, Fill),
        caption("words split on spaces; empty starts a sandbox to exec into"),
        field("Mounts", &form.mounts, Field::Mounts, Fill),
        caption("GUESTDIR=HOSTDIR, space-separated, read-write"),
        field("Shares", &form.shares, Field::Shares, Fill),
        switch(
            "Network through the host (TSI)",
            form.network,
            Switch::Network
        ),
        row![
            switch("Display", form.display, Switch::Display),
            text_input("640x480", &form.display_size)
                .style(entry)
                .on_input(|v| Message::Field(Field::DisplaySize, v))
                .font(MONO)
                .width(Length::Fixed(140.0)),
            switch("Sound", form.sound, Switch::Sound),
            switch("GPU", form.gpu, Switch::Gpu),
        ]
        .spacing(16)
        .align_y(iced::alignment::Vertical::Center),
        switch(
            "Keep what the guest writes to /results in the record",
            form.results,
            Switch::Results
        ),
        row![
            field(
                "vCPUs",
                &form.vcpus,
                Field::Vcpus,
                Length::Fixed(FORM_NUMBER)
            ),
            field(
                "Memory MiB",
                &form.mem_mib,
                Field::Mem,
                Length::Fixed(FORM_NUMBER)
            ),
        ]
        .spacing(16),
        rule::horizontal(1).style(divider),
        text(posture.sentence()).size(BODY),
        row![
            space().width(Fill),
            page_button("Cancel", push).on_press(Message::Back),
            // The posture on this form is the thing a snapshot keeps, so this is where one is
            // written: a snapshot is this sandbox, named and put by, rather than a second form
            // asking the same questions again. It needs the name, so it is refused without one.
            page_button("Save as snapshot", push)
                .on_press_maybe((!form.name.trim().is_empty()).then_some(Message::SaveSnapshot)),
            page_button("Start sandbox", primary).on_press(Message::Start),
        ]
        .spacing(12),
    ]
    .spacing(10)
    .width(Fill);
    if let Some(status) = &app.status {
        page = page.push(text(status).size(BODY));
    }
    framed(
        head_title("New sandbox"),
        column![scrollable(page).direction(lane()).style(scroll)].width(Fill),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A record for a run of `verb`, which is all these need: the acts a row offers turn on the
    /// verb and on whether the run is still up, and on nothing else.
    fn ran(verb: Verb) -> Record {
        Record::begin(
            "sample",
            verb,
            vec!["true".to_string()],
            boxdesk_record::Posture::default(),
        )
    }

    /// The four columns hold on every row, whatever the row can and cannot do. A column that
    /// vanished on some rows would move the three beside it, and the pointer would have to read
    /// each row before it could aim at one.
    #[test]
    fn every_row_offers_the_same_four_columns_in_the_same_order() {
        for verb in [Verb::Run, Verb::Up] {
            for live in [true, false] {
                let record = ran(verb);
                let words: Vec<&str> = row_acts(&record, live)
                    .iter()
                    .map(|(_, word, _)| *word)
                    .collect();
                assert_eq!(
                    words,
                    vec![
                        if live { "Stop" } else { "Re-run" },
                        "Shell",
                        "Export",
                        "Delete"
                    ],
                    "a {verb:?} row, live={live}, stands its acts somewhere else"
                );
            }
        }
    }

    /// **A live run is never offered a delete**, which is the rule the confirm keeps, said a step
    /// earlier so the press never happens. An ended one is never offered a stop, for the same
    /// reason from the other side.
    #[test]
    fn a_live_row_offers_no_delete_and_an_ended_one_offers_no_stop() {
        let record = ran(Verb::Up);
        let offered = |live: bool, word: &str| {
            row_acts(&record, live)
                .into_iter()
                .any(|(_, w, press)| w == word && press.is_some())
        };
        assert!(
            !offered(true, "Delete"),
            "a running sandbox was offered a delete"
        );
        assert!(offered(false, "Delete"), "an ended one should be");
        assert!(
            offered(true, "Stop"),
            "a running sandbox should be stoppable"
        );
        assert!(
            offered(false, "Re-run"),
            "an ended one should be runnable again"
        );
    }

    /// `Shell` is offered only where there is a guest left to enter: an `up` sandbox that is still
    /// running. Its column is still drawn on every other row, faded, which is why the rule lives
    /// here rather than in whether the icon exists.
    #[test]
    fn only_a_live_up_sandbox_can_be_shelled_into() {
        let shellable = |verb: Verb, live: bool| {
            row_acts(&ran(verb), live)
                .into_iter()
                .any(|(_, w, press)| w == "Shell" && press.is_some())
        };
        assert!(shellable(Verb::Up, true), "a live `up` is the one case");
        assert!(
            !shellable(Verb::Up, false),
            "an ended `up` has no guest left"
        );
        assert!(!shellable(Verb::Run, true), "a `run` ends with its command");
    }

    /// Every room the window's own buttons can take: none, and the 91 macOS gives them. The
    /// geometry takes the room as an argument, so this covers the other platform's layout too
    /// rather than only the one this build compiles.
    const ROOMS: [f32; 2] = [0.0, 91.0];

    /// The band keeps the window's own buttons their room and starts its first control past it,
    /// and closes that room when full screen takes the buttons off the line. The band is drawn
    /// where the titlebar would be, so a control that ignored this would be under them.
    #[test]
    fn the_band_keeps_the_windows_buttons_their_room() {
        for lights in ROOMS {
            let first = band_starts_at(lights);
            assert!(
                first >= lights + HEADER_EDGE,
                "with {lights} of lights the first control starts at {first}, on top of them"
            );
        }
        assert!(
            band_starts_at(0.0) < band_starts_at(91.0),
            "the two layouts are the same function of the room, not one layout"
        );
        assert_eq!(
            band_starts_at(0.0),
            HEADER_EDGE,
            "full screen should bring the band's contents back to its own edge"
        );
    }

    /// Nothing standing on the band is taller than the band, at any scale Settings offers.
    ///
    /// **The largest scale is the tight one.** The band holds [`HEAD_BAR`] of window however the
    /// app is zoomed, so in the lengths a layout is written in it *shrinks* as the scale grows,
    /// while everything standing on it keeps its number and is drawn larger. 125% is therefore
    /// where a control runs out of band, and each of these is padded from its own text rather
    /// than given a height, so one growing would be clipped by the band rather than reported.
    #[test]
    fn everything_standing_on_the_band_fits_it_at_every_scale() {
        let tightest = crate::SCALES
            .iter()
            .map(|s| f32::from(s.0) / 100.0)
            .fold(f32::MIN, f32::max);
        let band = band_height(tightest);
        let tall = [
            ("a glyph's halo", HALO),
            ("the search field", BODY + SEARCH_PAD[0] * 2.0),
            ("the badge", BADGE + BADGE_PAD[0] * 2.0),
            ("the wordmark", HEAD),
        ];
        for (what, height) in tall {
            assert!(
                height <= band,
                "{what} is {height} on a band {band} tall at {tightest}x"
            );
        }
    }

    /// The band is the same amount of window at every scale, which is what keeps the buttons
    /// macOS draws on it in its middle. They do not zoom, so neither does it.
    #[test]
    fn the_band_is_the_same_window_at_every_scale() {
        for scale in crate::SCALES.iter().map(|s| f32::from(s.0) / 100.0) {
            let drawn = band_height(scale) * scale;
            assert!(
                (drawn - HEAD_BAR).abs() < 0.01,
                "at {scale}x the band draws as {drawn} of window, not {HEAD_BAR}"
            );
        }
    }

    /// Every control takes [`CORNER`], so the window has one corner and not a handful that drift
    /// apart. The tick box, the switch and the slider's handle are here because each would
    /// otherwise round itself: the toolkit's own default, a `None` radius and a `Circle` handle.
    #[test]
    fn every_control_takes_the_windows_own_corner() {
        let theme = crate::theme::theme(crate::theme::Mode::Light, iced::theme::Mode::Light);
        let corner: iced::border::Radius = CORNER.into();
        for (what, style) in [
            ("a push button", push(&theme, button::Status::Active)),
            (
                "the default action",
                primary(&theme, button::Status::Active),
            ),
            ("a lone icon's mark", halo(&theme, button::Status::Hovered)),
            ("a picked segment", segment(&theme)),
        ] {
            assert_eq!(style.border.radius, corner, "{what}");
        }
        assert_eq!(
            entry(&theme, text_input::Status::Active).border.radius,
            corner,
            "a field"
        );
        assert_eq!(card(&theme).border.radius, corner, "a card");
        assert_eq!(
            check(&theme, checkbox::Status::Active { is_checked: true })
                .border
                .radius,
            corner,
            "a tick box, which the toolkit draws round by default"
        );
        assert_eq!(
            switch(&theme, toggler::Status::Active { is_toggled: true }).border_radius,
            Some(corner),
            "the switch, which the toolkit draws round when this is None"
        );
        let handle = rail_of(&theme, slider::Status::Active).handle.shape;
        assert!(
            matches!(
                handle,
                slider::HandleShape::Rectangle { border_radius, .. } if border_radius == corner
            ),
            "the slider's handle, which the toolkit draws round as a Circle: {handle:?}"
        );
        // The one exception, named rather than hidden: the fold's control is drawn on a rule
        // rather than on a surface, where a square reads as a break in the line and a circle reads
        // as something set on it.
        assert_eq!(
            divider_toggle(&theme, button::Status::Active).border.radius,
            (DIVIDER_TOGGLE / 2.0).into(),
            "the fold's circle is the window's one round control"
        );
    }

    /// The circle rides a boundary that is always there, and never reaches far enough into the
    /// pane beside it to touch a head. While the fold ran to nothing the circle stood on the page
    /// itself and `Sandboxes` was drawn with it through the `S`; a rail that keeps its icons is
    /// what took that case away, and this is what holds it away.
    #[test]
    fn the_circle_never_reaches_a_head() {
        assert!(
            rail_width(0.0) > DIVIDER_TOGGLE / 2.0,
            "folded, the rail must be wider than the circle's own reach back over it"
        );
    }

    /// The fold's strip stays centred on the boundary across the whole fold, and the boundary
    /// never leaves the window, so there is always a whole circle to work the rail by.
    #[test]
    fn the_folds_strip_follows_the_boundary() {
        for step in 0u8..=100 {
            let out = f32::from(step) / 100.0;
            let fold = rail_width(out);
            let left = reach_at(fold);
            assert!(left >= 0.0, "at {out} out the strip starts at {left}");
            assert!(
                left + DIVIDER_REACH >= fold,
                "at {out} out the strip ends at {} and misses the boundary at {fold}",
                left + DIVIDER_REACH
            );
        }
        assert!(
            rail_width(0.0) < rail_width(1.0),
            "the rail must widen as the sidebar comes out"
        );
    }

    /// A tab's pill stops short of the circle on the boundary, at every fold. Both edges are
    /// measured back from the same boundary, so one check covers the whole fold: until this, the
    /// circle was drawn over the corner of the open tab's own mark.
    #[test]
    fn a_pill_never_runs_under_the_circle() {
        for step in 0u8..=100 {
            let out = f32::from(step) / 100.0;
            let rail = rail_width(out);
            let pill_right = rail - RAIL_PAD;
            let circle_left = rail - DIVIDER_TOGGLE / 2.0;
            assert!(
                pill_right < circle_left,
                "at {out} out the pill ends at {pill_right} and the circle starts at {circle_left}"
            );
        }
    }

    /// Folded, the rail is exactly wide enough to centre the icon each tab starts with, so the
    /// column of glyphs stands still and only the words leave it.
    #[test]
    fn the_folded_rail_centres_its_icons() {
        let pill = rail_width(0.0) - RAIL_PAD * 2.0;
        let left = TAB_PAD[1];
        let right = pill - TAB_PAD[1] - icons::SIZE;
        assert!(
            (left - right).abs() < 0.01,
            "the icon sits {left} from one edge of the pill and {right} from the other"
        );
    }

    /// A value longer than its column keeps both ends, because a guest root's tail is the half
    /// that says which root it is: `~/.local/share/boxdesk/rootfs` and `~/.local/share/other/tree`
    /// differ only past the point an end-truncation would cut.
    #[test]
    fn a_long_value_is_cut_in_the_middle_and_keeps_both_ends() {
        let root = "~/.local/share/boxdesk/rootfs, read-only";
        let cut = elide(root, 30);
        assert_eq!(cut.chars().count(), 30, "{cut}");
        assert!(cut.starts_with("~/.local"), "the head is gone: {cut}");
        assert!(cut.ends_with("read-only"), "the tail is gone: {cut}");
        assert!(cut.contains('…'), "nothing says it was cut: {cut}");

        // Two roots differing only in their tail stay different, which end-truncation would not.
        let a = elide("~/.local/share/boxdesk/rootfs", 20);
        let b = elide("~/.local/share/boxdesk/other", 20);
        assert_ne!(a, b, "both cut to the same string: {a}");
    }

    /// Short enough is left exactly alone: an ellipsis on a value that fits is a lie about it.
    #[test]
    fn a_value_that_fits_is_left_alone() {
        for value in ["none", "1 vcpu, 512 MiB", "read-only"] {
            assert_eq!(elide(value, VALUE_CHARS), value);
        }
        // At the budget exactly, and one past it.
        let exact: String = "x".repeat(VALUE_CHARS);
        assert_eq!(elide(&exact, VALUE_CHARS), exact);
        let over: String = "x".repeat(VALUE_CHARS + 1);
        assert_eq!(elide(&over, VALUE_CHARS).chars().count(), VALUE_CHARS);
    }

    /// The cut lands on a character boundary, not inside one: a path may carry any character, and
    /// slicing bytes panics the moment a cut point falls inside a multi-byte one.
    ///
    /// Both values below are chosen so that a byte-slicing `elide` *would* panic: at these
    /// budgets each cut point sits on a continuation byte.
    #[test]
    fn a_multibyte_value_is_cut_on_a_boundary() {
        for (value, max) in [
            ("~/Dökümënté/ünïcødé-påth/rëßültß/rootfs", 24),
            ("é".repeat(60).as_str(), 30),
        ] {
            let cut = elide(value, max);
            assert_eq!(cut.chars().count(), max, "{cut}");
            let (head, tail) = cut.split_once('…').expect("an ellipsis");
            assert!(value.starts_with(head), "{cut}: head is not the value's");
            assert!(value.ends_with(tail), "{cut}: tail is not the value's");
        }
    }

    /// The posture pane spells a path the way Settings spells the same one. Before this the run
    /// screen printed `/Users/<you>/.local/...` in a column two thirds of it wide.
    #[test]
    fn the_posture_pane_spells_a_path_the_way_settings_does() {
        let mut posture = boxdesk_record::Posture::new(
            std::path::PathBuf::from("/Users/x/.local/share/boxdesk/rootfs"),
            std::num::NonZeroU8::MIN,
            std::num::NonZeroU32::new(512).expect("non-zero"),
        );
        posture.shares.push(boxdesk_record::Share::new(
            "work".to_string(),
            std::path::PathBuf::from("/Users/x/projects"),
        ));
        let record = Record::begin("r", Verb::Run, vec!["true".into()], posture);

        let lines = posture_lines(&record, Some("/Users/x"));
        let root = &lines.iter().find(|(l, _)| l == "root").expect("a root").1;
        assert!(root.starts_with("~/.local"), "{root}");
        let share = &lines.iter().find(|(l, _)| l == "share").expect("a share").1;
        assert!(share.ends_with("~/projects"), "{share}");

        // A path outside home is left whole: `~` there would name the wrong directory.
        let elsewhere = posture_lines(&record, Some("/Users/someone-else"));
        let root = &elsewhere
            .iter()
            .find(|(l, _)| l == "root")
            .expect("a root")
            .1;
        assert!(root.starts_with("/Users/x/"), "{root}");
    }

    /// A path under home is spelled with `~`; anything else is left whole.
    #[test]
    fn a_path_under_home_is_spelled_with_a_tilde() {
        let path = std::path::Path::new("/Users/x/Desktop/tree");
        assert_eq!(tilde(Some("/Users/x"), path), "~/Desktop/tree");
        assert_eq!(tilde(Some("/Users/y"), path), "/Users/x/Desktop/tree");
        assert_eq!(tilde(None, path), "/Users/x/Desktop/tree");
        assert_eq!(tilde(Some(""), path), "/Users/x/Desktop/tree");
    }

    /// Dividers have sufficient opacity to be clearly visible against adjacent surfaces.
    #[test]
    fn dividers_have_visible_contrast() {
        let light = crate::theme::theme(crate::theme::Mode::Light, iced::theme::Mode::Light);
        let dark = crate::theme::theme(crate::theme::Mode::Dark, iced::theme::Mode::Dark);
        assert!(
            divider(&light).color.a >= 0.20,
            "light divider alpha: {}",
            divider(&light).color.a
        );
        assert!(
            divider(&dark).color.a >= 0.20,
            "dark divider alpha: {}",
            divider(&dark).color.a
        );
    }
}
