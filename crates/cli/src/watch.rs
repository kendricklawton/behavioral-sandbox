//! The live view (`agent run --watch`): a full-screen terminal UI over one running sandbox,
//! its network flows and denials, its resources, the VMM's host-syscall footprint, and a running
//! timeline of what changed. Drawn on **stderr** (stdout stays reserved for the run's result, the
//! pipe-clean convention), redrawn from non-destructive [`LiveSnapshot`] polls, so watching never
//! disturbs the record that [`collect`](agent_probes_loader::SandboxProbes::collect) finalizes.
//!
//! The guest command runs on a worker thread the whole time; this view is a *reader*. `q`/`Esc`
//! closes the view (the run continues headless), it never cancels the run.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use agent_probes_loader::LiveSnapshot;
use agent_vmm::VmmError;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};

use crate::trace::{human_bytes, human_duration, proto_name, syscall_name};
use agent_cli::audit::RunProbes;

/// What the header identifies the run by, plain values captured before the sandbox moves to the
/// exec worker thread.
pub struct WatchMeta {
    pub vmm_pid: u32,
    pub boot: Duration,
    pub command: String,
}

/// How often the view polls the probes and the keyboard.
const TICK: Duration = Duration::from_millis(120);
/// Timeline memory: enough to scroll history off-screen without growing unbounded.
const MAX_TIMELINE: usize = 256;

/// The run's event timeline, derived by **diffing successive snapshots**, a new flow, a denial
/// count moving, a new distinct notable syscall each become one timestamped entry. Pure (no
/// terminal, no probes), so the diffing is unit-tested host-safe.
pub struct Timeline {
    seen_flows: BTreeSet<(u32, u16, u8, u32, u16)>,
    denial_counts: BTreeMap<(u32, u16, u8), u64>,
    seen_notable: BTreeSet<(u32, String)>,
    events: Vec<(Duration, String)>,
}

impl Timeline {
    pub fn new() -> Self {
        Self {
            seen_flows: BTreeSet::new(),
            denial_counts: BTreeMap::new(),
            seen_notable: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    /// Append a lifecycle entry (boot, finish, detach) outside the snapshot diff.
    pub fn push(&mut self, at: Duration, text: String) {
        self.events.push((at, text));
        if self.events.len() > MAX_TIMELINE {
            let excess = self.events.len() - MAX_TIMELINE;
            self.events.drain(..excess);
        }
    }

    /// Fold one snapshot in, emitting an entry per *change* since the last one.
    pub fn observe(&mut self, at: Duration, snap: &LiveSnapshot) {
        if let Some(net) = &snap.network {
            for flow in &net.flows {
                let k = &flow.key;
                let id = (k.dst_addr, k.dst_port, k.proto, k.src_addr, k.src_port);
                if self.seen_flows.insert(id) {
                    self.push(at, format!("flow    {k}"));
                }
            }
            for denial in &net.denials {
                let id = (denial.dst_addr, denial.dst_port, denial.proto);
                let before = self.denial_counts.get(&id).copied().unwrap_or(0);
                if denial.count > before {
                    let d = denial.dst_addr.to_be_bytes();
                    self.push(
                        at,
                        format!(
                            "denied  {}.{}.{}.{}:{} {} (+{})",
                            d[0],
                            d[1],
                            d[2],
                            d[3],
                            denial.dst_port,
                            proto_name(denial.proto),
                            denial.count - before
                        ),
                    );
                    self.denial_counts.insert(id, denial.count);
                }
            }
        }
        if let Some(footprint) = &snap.host_syscalls {
            for n in &footprint.notable {
                let id = (n.kind as u32, n.detail.clone());
                if !self.seen_notable.contains(&id) {
                    self.push(
                        at,
                        format!("{} {} ({})", syscall_name(n.kind), n.detail, n.comm),
                    );
                    self.seen_notable.insert(id);
                }
            }
        }
    }

    /// The most recent `n` entries, oldest first (what the bottom panel shows).
    fn tail(&self, n: usize) -> &[(Duration, String)] {
        let start = self.events.len().saturating_sub(n);
        &self.events[start..]
    }
}

/// Raw-mode + alternate-screen guard: however the view exits (return, error, panic-unwind), the
/// terminal is restored, a wrecked terminal would violate the "no host wreckage" spirit of the
/// no-panic path.
struct Term {
    terminal: Terminal<ratatui::backend::CrosstermBackend<std::io::Stderr>>,
}

impl Term {
    fn new() -> Result<Self, VmmError> {
        enable_raw_mode().map_err(|e| VmmError::Vmm(format!("enter raw mode: {e}")))?;
        if let Err(e) = execute!(std::io::stderr(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(VmmError::Vmm(format!("enter alternate screen: {e}")));
        }
        match Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stderr())) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(e) => {
                let _ = execute!(std::io::stderr(), LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(VmmError::Vmm(format!("initialize terminal: {e}")))
            }
        }
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stderr(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

/// Run the live view until the command finishes (then one keypress closes it) or the user detaches
/// early with `q`/`Esc`/`Ctrl-C`, the run itself continues either way; this is a reader.
///
/// # Errors
/// [`VmmError::Vmm`] if the terminal can't be entered or drawn, the caller logs and lets the run
/// finish headless (a broken TUI must not fail a working run).
pub fn live(probes: &RunProbes, meta: &WatchMeta, done: &AtomicBool) -> Result<(), VmmError> {
    let mut term = Term::new()?;
    let start = Instant::now();
    let mut timeline = Timeline::new();
    timeline.push(
        Duration::ZERO,
        format!(
            "microVM up (boot {}) · running: {}",
            human_duration(meta.boot),
            meta.command
        ),
    );
    // Last good reading per axis: a transient `None` (a snapshot racing teardown, a busy lock)
    // keeps the previous view rather than blanking a panel.
    let mut last = LiveSnapshot::default();
    let mut finished_noted = false;
    loop {
        let finished = done.load(Ordering::Acquire);
        let snap = probes.snapshot();
        if snap.network.is_some() {
            last.network = snap.network;
        }
        if snap.resources.is_some() {
            last.resources = snap.resources;
        }
        if snap.host_syscalls.is_some() {
            last.host_syscalls = snap.host_syscalls;
        }
        timeline.observe(start.elapsed(), &last);
        if finished && !finished_noted {
            finished_noted = true;
            timeline.push(
                start.elapsed(),
                "command finished · press q to close".to_string(),
            );
        }
        term.terminal
            .draw(|f| ui(f, meta, start.elapsed(), finished, &last, &timeline))
            .map_err(|e| VmmError::Vmm(format!("draw live view: {e}")))?;
        // Keyboard: q/Esc/Ctrl-C closes the view (never the run). Poll errors are treated as
        // "no input", input trouble must not kill a healthy run.
        if event::poll(TICK).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                let quit = key.kind == KeyEventKind::Press
                    && (key.code == KeyCode::Char('q')
                        || key.code == KeyCode::Esc
                        || (key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL)));
                if quit {
                    return Ok(());
                }
            }
        }
    }
}

/// One frame: header · (network+resources | syscalls) · timeline.
fn ui(
    f: &mut Frame,
    meta: &WatchMeta,
    elapsed: Duration,
    finished: bool,
    snap: &LiveSnapshot,
    timeline: &Timeline,
) {
    let [header, middle, bottom] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(8),
        Constraint::Length(10),
    ])
    .areas(f.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(middle);
    let [net_area, res_area] =
        Layout::vertical([Constraint::Min(6), Constraint::Length(5)]).areas(left);

    draw_header(f, header, meta, elapsed, finished);
    draw_network(f, net_area, snap);
    draw_resources(f, res_area, snap);
    draw_syscalls(f, right, snap);
    draw_timeline(f, bottom, timeline);
}

fn titled(title: &str) -> Block<'_> {
    Block::default().borders(Borders::ALL).title(Span::styled(
        format!(" {title} "),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn draw_header(f: &mut Frame, area: Rect, meta: &WatchMeta, elapsed: Duration, finished: bool) {
    let state = if finished {
        Span::styled("finished", Style::default().fg(Color::Green))
    } else {
        Span::styled("running", Style::default().fg(Color::Yellow))
    };
    let lines = vec![
        Line::from(vec![
            Span::raw(format!(
                "sandbox pid {} · boot {} · elapsed {} · ",
                meta.vmm_pid,
                human_duration(meta.boot),
                human_duration(elapsed)
            )),
            state,
        ]),
        Line::from(Span::styled(
            format!(
                "$ {}   (q closes the view; the run continues)",
                meta.command
            ),
            Style::default().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).block(titled("agent watch · hardware-isolated run")),
        area,
    );
}

fn draw_network(f: &mut Frame, area: Rect, snap: &LiveSnapshot) {
    let mut lines: Vec<Line> = Vec::new();
    match &snap.network {
        None => lines.push(Line::from(Span::styled(
            "no NIC (boot with --net) or tap not attached",
            Style::default().fg(Color::DarkGray),
        ))),
        Some(net) => {
            lines.push(Line::from(format!(
                "guest sent {} pkts / {} · received {} pkts / {}",
                net.totals.ingress_packets,
                human_bytes(net.totals.ingress_bytes),
                net.totals.egress_packets,
                human_bytes(net.totals.egress_bytes)
            )));
            let room = usize::from(area.height.saturating_sub(3));
            for flow in net
                .flows
                .iter()
                .take(room.saturating_sub(net.denials.len()))
            {
                // Same vocabulary as the `--trace` trail: tap ingress is what the guest sent.
                lines.push(Line::from(format!(
                    "  {} · sent {}/{} · recv {}/{}",
                    flow.key,
                    flow.counts.ingress_packets,
                    human_bytes(flow.counts.ingress_bytes),
                    flow.counts.egress_packets,
                    human_bytes(flow.counts.egress_bytes)
                )));
            }
            for denial in &net.denials {
                let d = denial.dst_addr.to_be_bytes();
                lines.push(Line::from(Span::styled(
                    format!(
                        "  denied {}.{}.{}.{}:{} {} · {} pkt(s)",
                        d[0],
                        d[1],
                        d[2],
                        d[3],
                        denial.dst_port,
                        proto_name(denial.proto),
                        denial.count
                    ),
                    Style::default().fg(Color::Red),
                )));
            }
        }
    }
    f.render_widget(Paragraph::new(lines).block(titled("network (tap)")), area);
}

fn draw_resources(f: &mut Frame, area: Rect, snap: &LiveSnapshot) {
    let lines: Vec<Line> = match &snap.resources {
        None => vec![Line::from(Span::styled(
            "meter unavailable",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(res) => vec![
            Line::from(format!("cpu  {}", human_duration(res.cpu_time))),
            Line::from(format!(
                "mem  {} (peak {})",
                res.cgroup
                    .memory_current
                    .map_or_else(|| "n/a".into(), human_bytes),
                res.cgroup
                    .memory_peak
                    .map_or_else(|| "n/a".into(), human_bytes)
            )),
            Line::from(format!(
                "io   read {} / written {}",
                res.cgroup
                    .io_rbytes
                    .map_or_else(|| "n/a".into(), human_bytes),
                res.cgroup
                    .io_wbytes
                    .map_or_else(|| "n/a".into(), human_bytes)
            )),
        ],
    };
    f.render_widget(Paragraph::new(lines).block(titled("resources")), area);
}

fn draw_syscalls(f: &mut Frame, area: Rect, snap: &LiveSnapshot) {
    let mut lines: Vec<Line> = Vec::new();
    match &snap.host_syscalls {
        None => lines.push(Line::from(Span::styled(
            "tracer unavailable",
            Style::default().fg(Color::DarkGray),
        ))),
        Some(sys) => {
            lines.push(Line::from(format!(
                "{} total · execve {} · openat {} · connect {}",
                sys.total, sys.by_kind.execve, sys.by_kind.openat, sys.by_kind.connect
            )));
            let mut notable: Vec<_> = sys.notable.iter().collect();
            notable.sort_by_key(|n| std::cmp::Reverse(n.hits));
            let room = usize::from(area.height.saturating_sub(3));
            for n in notable.iter().take(room) {
                lines.push(Line::from(format!(
                    "  {:<8} {} x{}",
                    syscall_name(n.kind),
                    n.detail,
                    n.hits
                )));
            }
        }
    }
    f.render_widget(
        Paragraph::new(lines).block(titled("host syscalls (the VMM's, not the guest's)")),
        area,
    );
}

fn draw_timeline(f: &mut Frame, area: Rect, timeline: &Timeline) {
    let room = usize::from(area.height.saturating_sub(2));
    let lines: Vec<Line> = timeline
        .tail(room)
        .iter()
        .map(|(at, text)| {
            Line::from(vec![
                Span::styled(
                    format!("+{:>8} ", human_duration(*at)),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(text.clone()),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(titled("timeline")), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_probes_loader::{
        FlowCounts, FlowKey, NetSection, NetStats, SyscallFootprint, DETAIL_CAP,
    };

    fn net(flows: Vec<(FlowKey, FlowCounts)>, denials: Vec<(FlowKey, u64)>) -> NetSection {
        NetSection::from_tap(flows, NetStats::default(), denials)
    }

    fn key(dst: [u8; 4], dport: u16) -> FlowKey {
        FlowKey::new(
            u32::from_be_bytes([10, 200, 0, 2]),
            u32::from_be_bytes(dst),
            40000,
            dport,
            17,
        )
    }

    #[test]
    fn timeline_emits_once_per_new_flow_and_tracks_denial_deltas() {
        let mut tl = Timeline::new();
        let snap1 = LiveSnapshot {
            network: Some(net(
                vec![(key([1, 1, 1, 1], 53), FlowCounts::default())],
                vec![(key([9, 9, 9, 9], 443), 2)],
            )),
            resources: None,
            host_syscalls: None,
        };
        tl.observe(Duration::from_millis(100), &snap1);
        assert_eq!(tl.events.len(), 2, "one flow + one denial entry");
        // The same snapshot again: nothing new, nothing emitted.
        tl.observe(Duration::from_millis(200), &snap1);
        assert_eq!(tl.events.len(), 2, "unchanged state emits nothing");
        // The denial count grows and a second flow appears: one entry each.
        let snap2 = LiveSnapshot {
            network: Some(net(
                vec![
                    (key([1, 1, 1, 1], 53), FlowCounts::default()),
                    (key([8, 8, 8, 8], 443), FlowCounts::default()),
                ],
                vec![(key([9, 9, 9, 9], 443), 5)],
            )),
            resources: None,
            host_syscalls: None,
        };
        tl.observe(Duration::from_millis(300), &snap2);
        assert_eq!(tl.events.len(), 4);
        let texts: Vec<&str> = tl.events.iter().map(|(_, t)| t.as_str()).collect();
        assert!(
            texts[3].contains("(+3)"),
            "the delta, not the total: {texts:?}"
        );
    }

    #[test]
    fn timeline_emits_new_notable_syscalls_once() {
        use agent_probes_loader::{Syscall, SyscallEvent};
        let mk = |detail: &[u8]| {
            let mut d = [0u8; DETAIL_CAP];
            d[..detail.len()].copy_from_slice(detail);
            SyscallEvent {
                cgroup_id: 1,
                pid: 1,
                tid: 1,
                syscall: Syscall::Openat as u32,
                detail_len: detail.len() as u32,
                comm: [0; agent_probes_loader::COMM_CAP],
                detail: d,
            }
        };
        let mut tl = Timeline::new();
        let snap = LiveSnapshot {
            network: None,
            resources: None,
            host_syscalls: Some(SyscallFootprint::from_events(1, &[mk(b"/etc/hosts")])),
        };
        tl.observe(Duration::ZERO, &snap);
        tl.observe(Duration::from_millis(50), &snap);
        assert_eq!(tl.events.len(), 1, "a distinct syscall lands once");
        assert!(tl.events[0].1.contains("openat"));
    }

    #[test]
    fn timeline_is_bounded() {
        let mut tl = Timeline::new();
        for i in 0..(MAX_TIMELINE + 40) {
            tl.push(Duration::from_millis(i as u64), format!("event {i}"));
        }
        assert_eq!(tl.events.len(), MAX_TIMELINE);
        assert!(tl.events[0].1.contains("event 40"), "oldest were dropped");
    }
}
