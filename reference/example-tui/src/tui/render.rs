//! All drawing for the chat TUI, plus the click-target map (`Hits`) the event
//! loop consults to make every control mouse-drivable.
//!
//! Nothing here owns state: [`draw`] reads the [`App`], paints a frame, and
//! records where it put each clickable thing. The transcript computes its own
//! wrapped line list so it can pin the current turn's user message to the top
//! (the "sticky messages" behaviour) and drive its own scrollbar.

use std::time::{SystemTime, UNIX_EPOCH};

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, HighlightSpacing, List, ListItem, ListState, Paragraph,
    Scrollbar, ScrollbarOrientation, ScrollbarState,
};

use super::App;
use super::command;
use super::model::{
    AGENTS, DiffLine, Effort, FileDiff, MODELS, Message, Permissions, QueueMode, Role, Sandbox,
    Segment, Session, TurnStats, models_for, peak_mode, providers,
};
use super::palette::{
    BRASS, DISABLED, FOG, GREEN, HOVER_BG, INK, NIGHT, PLACEHOLDER, RED, SURFACE, TEAL, YELLOW,
};
use super::widgets::{hot, truncate, wrap};

/// The pickers the composer can raise over itself. The model picker is two
/// levels: first a provider, then a model within it.
#[derive(Debug, Clone, Copy)]
pub enum Overlay {
    /// The provider list — the first level of the model picker.
    Provider {
        cursor: usize,
    },
    /// The models offered by `provider` (an index into [`model::providers`]).
    Model {
        provider: usize,
        cursor: usize,
    },
    Effort {
        cursor: usize,
    },
    Agent {
        cursor: usize,
    },
    Sandbox {
        cursor: usize,
    },
    Permissions {
        cursor: usize,
    },
    Subagents {
        cursor: usize,
        count: usize,
    },
    Background {
        cursor: usize,
        count: usize,
    },
    Timers {
        cursor: usize,
        count: usize,
    },
    Tools {
        cursor: usize,
        count: usize,
    },
    Skills {
        cursor: usize,
        count: usize,
    },
    /// Trash on a sidebar session: Cancel (0) or Delete (1).
    ConfirmDelete {
        session: usize,
        cursor: usize,
    },
}

impl Overlay {
    pub fn cursor(&self) -> usize {
        match self {
            Overlay::Provider { cursor }
            | Overlay::Model { cursor, .. }
            | Overlay::Effort { cursor }
            | Overlay::Agent { cursor }
            | Overlay::Sandbox { cursor }
            | Overlay::Permissions { cursor }
            | Overlay::Subagents { cursor, .. }
            | Overlay::Background { cursor, .. }
            | Overlay::Timers { cursor, .. }
            | Overlay::Tools { cursor, .. }
            | Overlay::Skills { cursor, .. }
            | Overlay::ConfirmDelete { cursor, .. } => *cursor,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Overlay::Provider { .. } => providers().len(),
            Overlay::Model { provider, .. } => providers()
                .get(*provider)
                .map(|p| models_for(p).len())
                .unwrap_or(0),
            Overlay::Effort { .. } => Effort::ORDER.len(),
            Overlay::Agent { .. } => AGENTS.len(),
            Overlay::Sandbox { .. } => Sandbox::ORDER.len(),
            Overlay::Permissions { .. } => Permissions::ORDER.len(),
            Overlay::Subagents { count, .. }
            | Overlay::Background { count, .. }
            | Overlay::Timers { count, .. }
            | Overlay::Tools { count, .. }
            | Overlay::Skills { count, .. } => *count,
            Overlay::ConfirmDelete { .. } => 2,
        }
    }

    pub fn set_cursor(&mut self, value: usize) {
        match self {
            Overlay::Provider { cursor }
            | Overlay::Model { cursor, .. }
            | Overlay::Effort { cursor }
            | Overlay::Agent { cursor }
            | Overlay::Sandbox { cursor }
            | Overlay::Permissions { cursor }
            | Overlay::Subagents { cursor, .. }
            | Overlay::Background { cursor, .. }
            | Overlay::Timers { cursor, .. }
            | Overlay::Tools { cursor, .. }
            | Overlay::Skills { cursor, .. }
            | Overlay::ConfirmDelete { cursor, .. } => *cursor = value,
        }
    }

    /// Activity-bar menus drop from their header pill; composer pickers rise
    /// from the input footer. Header menus pan their viewport on the wheel;
    /// composer pickers still move the highlighted row.
    pub fn opens_from_header(self) -> bool {
        matches!(
            self,
            Overlay::Subagents { .. }
                | Overlay::Background { .. }
                | Overlay::Timers { .. }
                | Overlay::Tools { .. }
                | Overlay::Skills { .. }
        )
    }
}

/// Every rectangle the last frame made clickable, rebuilt on each [`draw`].
#[derive(Default)]
pub struct Hits {
    pub sidebar_toggle: Rect,
    pub new_session: Rect,
    /// `(session index, row rect)` for each sidebar entry.
    pub sessions: Vec<(usize, Rect)>,
    /// The session list (and its scrollbar), so the wheel can scroll it.
    pub sidebar_list: Rect,
    /// `(session index, [Archive] rect)` — only while that row is hovered.
    pub archive: Vec<(usize, Rect)>,
    /// `(session index, trash rect)` — only while that row is hovered.
    pub delete: Vec<(usize, Rect)>,
    /// `(session index, [Pin]/[Unpin] rect)` — only while that row is hovered.
    pub session_pin: Vec<(usize, Rect)>,
    pub agent_pill: Rect,
    pub model_pill: Rect,
    pub effort_pill: Rect,
    pub permissions_pill: Rect,
    pub sandbox_pill: Rect,
    /// Breadcrumb segments: `(focus path, rect)`. An empty path is the root.
    pub crumbs: Vec<(Vec<usize>, Rect)>,
    pub subagents_pill: Rect,
    pub tasks_pill: Rect,
    pub timers_pill: Rect,
    pub tools_pill: Rect,
    pub skills_pill: Rect,
    /// `(path, interactive, transcript line)` for inlined subagent cards.
    pub subagent_lines: Vec<(Vec<usize>, bool, usize)>,
    /// Visible inlined subagent cards: `(path, interactive, rect)`.
    pub subagent_blocks: Vec<(Vec<usize>, bool, Rect)>,
    /// Transcript scrollbar track, when the chat overflows.
    pub transcript_sb: Rect,
    /// Sidebar scrollbar track, when the session list overflows.
    pub sidebar_sb: Rect,
    pub send: Rect,
    /// `(suggestion index, chip rect)`.
    pub suggestions: Vec<(usize, Rect)>,
    pub transcript: Rect,
    /// The "jump to latest" chip, shown while the transcript isn't following.
    pub jump_latest: Rect,
    /// The sticky (pinned) user-message header row.
    pub sticky: Rect,
    /// Where clicking the sticky header should scroll to — just above the
    /// current turn, so the previous turn becomes the sticky one.
    pub sticky_target: usize,
    /// `(message index, [Pin]/[Unpin] rect)` for each visible user/agent header.
    pub pin: Vec<(usize, Rect)>,
    /// `(message index, [Fork] rect)` for each visible user/agent header.
    pub fork: Vec<(usize, Rect)>,
    /// `(message index, Thinking / Thought header rect)` for agent reasoning.
    pub thinking: Vec<(usize, Rect)>,
    /// `(message index, role-name rect)` — click to show TTFT / TPS / cache.
    pub agent_name: Vec<(usize, Rect)>,
    /// `(message index, [show|hide summary] rect)` for compaction boundaries.
    pub summaries: Vec<(usize, Rect)>,
    /// `(queue item index, [turn, boundary, interrupt] chip rects)`.
    pub queue_modes: Vec<(usize, [Rect; 3])>,
    /// Group [Edit] / [Edit all] on the queue header.
    pub queue_edit: Rect,
    /// `(queue item index, remove rect)`.
    pub queue_remove: Vec<(usize, Rect)>,
    /// Overlay list rows: `(option index, rect)`.
    pub overlay_rows: Vec<(usize, Rect)>,
    /// The overlay popup's outer rect, so the wheel can scroll it when hovered.
    pub overlay_box: Rect,
    /// Overlay scrollbar track, when a header menu overflows.
    pub overlay_sb: Rect,
    /// `(command name, row rect)` for each visible slash-palette entry.
    pub slash_rows: Vec<(&'static str, Rect)>,
}

const SIDEBAR_WIDTH: u16 = 30;
/// The composer grows to at most this many text rows before scrolling inside.
const MAX_INPUT_ROWS: usize = 8;

/// Paint the whole app and return where the text caret should sit (composer
/// input), or `None` when a picker is open.
pub fn draw(app: &mut App, frame: &mut Frame) -> Option<Position> {
    let mut hits = Hits::default();
    let area = frame.area();

    let (sidebar_area, main_area) = if app.sidebar_open {
        let [side, main] = area.layout(&Layout::horizontal([
            Constraint::Length(SIDEBAR_WIDTH),
            Constraint::Min(0),
        ]));
        (side, main)
    } else {
        (Rect::default(), area)
    };

    if app.sidebar_open {
        render_sidebar(app, frame, sidebar_area, &mut hits);
    }
    let caret = render_main(app, frame, main_area, &mut hits);

    let overlay = app.overlay;
    if let Some(overlay) = overlay {
        render_overlay(app, frame, overlay, &mut hits);
    }

    app.hits = hits;
    if app.overlay.is_some() { None } else { caret }
}

/* -------------------------------- sidebar --------------------------------- */

fn render_sidebar(app: &mut App, frame: &mut Frame, area: Rect, hits: &mut Hits) {
    fill_bg(frame, area, SURFACE);
    let block = Block::new().style(Style::new().bg(SURFACE));
    frame.render_widget(&block, area);

    let inner = area.inner(Margin::new(1, 1));
    let [head, _, new, _, label, list, legend] = inner.layout(&Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(2),
    ]));

    let hide_w = HIDE_LABEL.chars().count() as u16 + 1;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("◆ ", Style::new().fg(BRASS)),
            Span::styled(
                "Cockpit Code",
                Style::new().fg(INK).add_modifier(Modifier::BOLD),
            ),
        ])),
        Rect {
            width: head.width.saturating_sub(hide_w),
            ..head
        },
    );
    paint_sidebar_toggle(frame, head, HIDE_LABEL, app.mouse, hits);

    let new_label = " + New session ";
    hits.new_session = Rect {
        x: new.x,
        y: new.y,
        width: (new_label.chars().count() as u16).min(new.width),
        height: 1,
    };
    paint_chip(
        frame,
        hits.new_session,
        new_label,
        Style::new().fg(BRASS),
        hot(hits.new_session, app.mouse),
    );

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "SESSIONS",
            Style::new().fg(FOG).add_modifier(Modifier::BOLD),
        ))),
        label,
    );

    // Visible (non-archived) sessions, each a two-line `ListItem`: title with
    // its status dot, then last-activity datetime. We window the list ourselves
    // so the sidebar can scroll independently of which session is active.
    let visible = super::model::Session::visible_indices(&app.sessions);
    let capacity = (usize::from(list.height) / 2).max(1);
    let max_scroll = visible.len().saturating_sub(capacity);
    app.sidebar_view = capacity;
    app.sidebar_scroll = app.sidebar_scroll.min(max_scroll);
    let scroll = app.sidebar_scroll;
    hits.sidebar_list = list;

    let overflowing = visible.len() > capacity;
    let text_list = if overflowing {
        Rect {
            width: list.width.saturating_sub(1),
            ..list
        }
    } else {
        list
    };

    let window = &visible[scroll..(scroll + capacity).min(visible.len())];
    let selected = window.iter().position(|&index| index == app.active);
    let width = usize::from(text_list.width).saturating_sub(2);
    let items: Vec<ListItem> = window
        .iter()
        .map(|&index| {
            let session = &app.sessions[index];
            let mut title = vec![Span::styled("● ", Style::new().fg(session.status().dot()))];
            let title_w = if session.starred {
                title.push(Span::styled("★ ", Style::new().fg(YELLOW)));
                width.saturating_sub(2)
            } else {
                width
            };
            title.push(Span::styled(
                truncate(&session.title, title_w),
                Style::new().fg(INK),
            ));
            let title = Line::from(title);
            let when = Line::from(Span::styled(
                datetime_label(session.last_active),
                Style::new().fg(FOG),
            ));
            ListItem::new(Text::from(vec![title, when]))
        })
        .collect();

    let mut state = ListState::default().with_selected(selected);
    let sessions = List::new(items)
        .style(Style::new().bg(SURFACE))
        .highlight_style(
            Style::new()
                .bg(HOVER_BG)
                .fg(BRASS)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▌")
        .repeat_highlight_symbol(true)
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(sessions, text_list, &mut state);

    if overflowing {
        let mut sb_state = ScrollbarState::new(max_scroll + 1)
            .position(scroll)
            .viewport_content_length(capacity);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .thumb_symbol("█")
            .track_style(Style::new().fg(NIGHT))
            .thumb_style(Style::new().fg(BRASS));
        frame.render_stateful_widget(scrollbar, list, &mut sb_state);
        hits.sidebar_sb = scrollbar_track(list);
    }

    for (k, &index) in window.iter().enumerate() {
        let row = Rect {
            x: text_list.x,
            y: text_list.y + (k * 2) as u16,
            width: text_list.width,
            height: 2,
        };
        hits.sessions.push((index, row));
        if hot(row, app.mouse) {
            paint_session_actions(
                frame,
                row,
                index == app.active,
                index,
                app.sessions[index].starred,
                app.mouse,
                hits,
            );
        }
    }

    // Legend, so the dot colours are self-explanatory.
    let legend_line = Line::from(vec![
        Span::styled("● ", Style::new().fg(YELLOW)),
        Span::styled("working  ", Style::new().fg(FOG)),
        Span::styled("● ", Style::new().fg(RED)),
        Span::styled("waiting  ", Style::new().fg(FOG)),
        Span::styled("● ", Style::new().fg(GREEN)),
        Span::styled("done", Style::new().fg(FOG)),
    ]);
    frame.render_widget(Paragraph::new(legend_line), legend);
}

const ARCHIVE_LABEL: &str = "[Archive]";
const PIN_SESSION_LABEL: &str = "[Pin]";
const UNPIN_SESSION_LABEL: &str = "[Unpin]";
/// Single-column delete mark — emoji wastebaskets are two cells and shove
/// the neighbouring chips off the datetime row.
const TRASH_LABEL: &str = "[×]";
const HIDE_LABEL: &str = "[Hide]";
const SHOW_LABEL: &str = "[Show]";

/// `[Hide]` / `[Show]` flush to the right of `row` (sidebar header) or the
/// left of `row` (terminal top-left when the sidebar is closed).
fn paint_sidebar_toggle(
    frame: &mut Frame,
    row: Rect,
    label: &str,
    mouse: Option<Position>,
    hits: &mut Hits,
) {
    let w = label.chars().count() as u16;
    if row.width < w {
        return;
    }
    let rect = if label == HIDE_LABEL {
        Rect {
            x: row.right().saturating_sub(w),
            y: row.y,
            width: w,
            height: 1,
        }
    } else {
        Rect {
            x: row.x,
            y: row.y,
            width: w,
            height: 1,
        }
    };
    paint_chip(frame, rect, label, Style::new().fg(FOG), hot(rect, mouse));
    hits.sidebar_toggle = rect;
}

/// Replace a hovered session's datetime row with `[Pin]`/`[Unpin]`,
/// `[Archive]`, and a wastebasket chip.
fn paint_session_actions(
    frame: &mut Frame,
    row: Rect,
    selected: bool,
    index: usize,
    starred: bool,
    mouse: Option<Position>,
    hits: &mut Hits,
) {
    let line = Rect {
        x: row.x,
        y: row.y + 1,
        width: row.width,
        height: 1,
    };
    if line.width == 0 {
        return;
    }
    // Wipe the datetime glyphs, not just the background — otherwise the
    // minute digits show through the one-column gaps between chips.
    clear_cells(frame, line, if selected { HOVER_BG } else { SURFACE });
    let pin = if starred {
        UNPIN_SESSION_LABEL
    } else {
        PIN_SESSION_LABEL
    };
    let pin_w = cols(pin);
    let archive_w = cols(ARCHIVE_LABEL);
    let trash_w = cols(TRASH_LABEL);
    let gap = 1u16;
    let total = pin_w + gap + archive_w + gap + trash_w;
    if line.width < total {
        return;
    }
    let start = line.right().saturating_sub(total + 1);
    let pin_rect = Rect {
        x: start,
        y: line.y,
        width: pin_w,
        height: 1,
    };
    let archive = Rect {
        x: start + pin_w + gap,
        y: line.y,
        width: archive_w,
        height: 1,
    };
    let delete = Rect {
        x: start + pin_w + gap + archive_w + gap,
        y: line.y,
        width: trash_w,
        height: 1,
    };
    paint_chip(
        frame,
        pin_rect,
        pin,
        if starred {
            Style::new().fg(YELLOW)
        } else {
            Style::new().fg(FOG)
        },
        hot(pin_rect, mouse),
    );
    paint_chip(
        frame,
        archive,
        ARCHIVE_LABEL,
        Style::new().fg(FOG),
        hot(archive, mouse),
    );
    paint_chip(
        frame,
        delete,
        TRASH_LABEL,
        Style::new().fg(RED),
        hot(delete, mouse),
    );
    hits.session_pin.push((index, pin_rect));
    hits.archive.push((index, archive));
    hits.delete.push((index, delete));
}

fn cols(text: &str) -> u16 {
    Line::from(text).width() as u16
}

/// The rightmost column of `area` — the only place a vertical scrollbar
/// should accept a click-drag.
fn scrollbar_track(area: Rect) -> Rect {
    Rect {
        x: area.right().saturating_sub(1),
        y: area.y,
        width: 1,
        height: area.height,
    }
}

/* ---------------------------------- main ---------------------------------- */

fn render_main(app: &mut App, frame: &mut Frame, area: Rect, hits: &mut Hits) -> Option<Position> {
    let session_status = app.sessions[app.active].status();

    // Work out the composer's height so the transcript can claim the rest.
    let (queue_h, sugg_h) = {
        let session = &app.sessions[app.active];
        let queue_h = if session.queue.is_empty() {
            0
        } else {
            let hint = if peak_mode(&session.queue) == Some(QueueMode::Interrupt) {
                0
            } else {
                1
            };
            1 + session.queue.len().min(5) as u16 + hint
        };
        let show_sugg =
            !session.is_working() && session.queue.is_empty() && !session.suggestions.is_empty();
        (queue_h, if show_sugg { 1 } else { 0 })
    };
    // The input box grows with its content: one row per wrapped line (capped),
    // plus the top and bottom borders. Its bottom border carries the pills.
    let input_text_width = usize::from(area.width.saturating_sub(2)).max(1);
    let input_rows = app
        .input
        .line_count(input_text_width)
        .clamp(1, MAX_INPUT_ROWS) as u16;
    let input_box_h = input_rows + 2;
    let composer_h = queue_h + sugg_h + input_box_h;

    let [header, body, composer] = area.layout(&Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(composer_h),
    ]));

    // The input box's top row (the slash palette floats just above it) and its
    // bottom border row (where the pickers open from).
    let input_top = composer.y + queue_h + sugg_h;
    app.overlay_anchor = Rect {
        x: composer.x,
        y: input_top + input_rows + 1,
        width: composer.width,
        height: 1,
    };

    render_header(app, frame, header, session_status, hits);
    render_transcript(app, frame, body, hits);
    let caret = render_composer(app, frame, composer, queue_h, sugg_h, input_box_h, hits);
    if app.slash_active() {
        render_slash(app, frame, input_top, hits);
    }
    caret
}

fn render_header(
    app: &App,
    frame: &mut Frame,
    area: Rect,
    status: super::model::Status,
    hits: &mut Hits,
) {
    let session = &app.sessions[app.active];
    if area.height == 0 {
        return;
    }
    let row = |offset: u16| Rect {
        y: area.y + offset,
        height: 1,
        ..area
    };
    let title_row = row(0);
    let meta_row = (area.height >= 3).then(|| row(1));
    let rule_row = match area.height {
        1 => None,
        2 => Some(row(1)),
        _ => Some(row(2)),
    };

    // When the sidebar is closed, [Show] sits in the terminal's top-left
    // corner — the first cell of this header row.
    let show_w = if app.sidebar_open {
        0
    } else {
        paint_sidebar_toggle(frame, title_row, SHOW_LABEL, app.mouse, hits);
        SHOW_LABEL.chars().count() as u16 + 1
    };

    let badge = format!("● {}", status.short());
    let badge_w = badge.chars().count() as u16;
    let stack = routing_status(app);
    let stack_w = stack.as_deref().map(|label| cols(label) + 2).unwrap_or(0);
    let title = truncate(
        &session.title,
        usize::from(
            title_row
                .width
                .saturating_sub(badge_w + 2 + show_w + stack_w),
        ),
    );
    let title_area = Rect {
        x: title_row.x + show_w,
        y: title_row.y,
        width: title_row.width.saturating_sub(show_w),
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            title,
            Style::new().fg(INK).add_modifier(Modifier::BOLD),
        ))),
        title_area,
    );
    let mut badge_style = Style::new().fg(status.dot());
    if status.pulses() {
        badge_style = badge_style.add_modifier(Modifier::BOLD);
    }
    if let Some(stack) = stack.as_deref() {
        let stack_area = Rect {
            x: title_row.x,
            y: title_row.y,
            width: title_row.width.saturating_sub(badge_w + 1),
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                stack.to_string(),
                Style::new().fg(DISABLED),
            )))
            .right_aligned(),
            stack_area,
        );
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(badge, badge_style))).right_aligned(),
        title_row,
    );
    if let Some(meta_row) = meta_row {
        render_path_and_pills(app, frame, meta_row, hits);
    }

    if let Some(rule_row) = rule_row {
        let rule = "─".repeat(usize::from(rule_row.width));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(rule, Style::new().fg(NIGHT)))),
            rule_row,
        );
    }
}

/// Repo path and git on the left, activity pills on the right.
/// Compact pills first; only then elide leading path directories.
fn render_path_and_pills(app: &App, frame: &mut Frame, area: Rect, hits: &mut Hits) {
    if area.width == 0 {
        return;
    }
    let session = &app.sessions[app.active];
    let tasks = session.layer_tasks().len();
    let timers = session.layer_timers().len();
    let tools = session.layer_tools().len();
    let skills = session.layer_skills().len();
    let repo = session.repo.clone();
    let full = [
        "[subagents]".to_string(),
        format!("[background tasks: {tasks}]"),
        format!("[timers: {timers}]"),
        format!("[tools: {tools}]"),
        format!("[skills: {skills}]"),
    ];
    let compact = [
        "[subs]".to_string(),
        format!("[bg: {tasks}]"),
        format!("[timers: {timers}]"),
        format!("[tools: {tools}]"),
        format!("[skills: {skills}]"),
    ];

    let git = git_suffix(app);
    let full_path = format!("⎇ {repo}");
    let full_left = format!("{full_path}{git}");

    let labels = if cluster_width(&full) + 2 + cols(&full_left) <= area.width {
        &full
    } else {
        &compact
    };
    let pills_w = cluster_width(labels);
    let left_budget = area
        .width
        .saturating_sub(if pills_w == 0 { 0 } else { pills_w + 2 });

    render_repo_path(app, frame, area, left_budget, &full_path);
    paint_activity_pills(app, frame, area, labels, pills_w, hits);
}

/// Who the next message is for — status, not a place you can navigate to.
fn routing_status(app: &App) -> Option<String> {
    let session = &app.sessions[app.active];
    session
        .locked_in_interactive()
        .then(|| session.focused_name().map(str::to_string))
        .flatten()
}

/// `(branch, " ● N changes" | " ✓ clean")` when the working tree is a repo.
fn git_parts(app: &App) -> Option<(String, String)> {
    let git = &app.git;
    let branch = git.is_repo.then_some(git.branch.clone()).flatten()?;
    let status = if git.dirty() {
        let plural = if git.changes == 1 { "" } else { "s" };
        format!(" ● {} change{plural}", git.changes)
    } else {
        " ✓ clean".to_string()
    };
    Some((branch, status))
}

fn git_suffix(app: &App) -> String {
    git_parts(app)
        .map(|(branch, status)| format!("   {branch}{status}"))
        .unwrap_or_default()
}

fn render_repo_path(app: &App, frame: &mut Frame, area: Rect, left_budget: u16, full_path: &str) {
    let parts = git_parts(app);
    let (pad, git_w) = match &parts {
        Some((branch, status)) => {
            let comfortable = cols("   ") + cols(branch) + cols(status);
            let tight = cols(branch) + cols(status);
            if comfortable <= left_budget {
                ("   ", comfortable)
            } else {
                ("", tight)
            }
        }
        None => ("", 0),
    };
    // Keep branch/dirty visible whenever they fit; elide the path to make room.
    let show_git = parts.is_some() && git_w <= left_budget;
    let path_budget = if show_git {
        left_budget.saturating_sub(git_w)
    } else {
        left_budget
    };
    let prefix = "⎇ ";
    let prefix_w = cols(prefix);
    let path = if cols(full_path) <= path_budget {
        full_path.to_string()
    } else if path_budget == 0 {
        String::new()
    } else if path_budget < prefix_w {
        truncate("…", usize::from(path_budget))
    } else {
        let room = usize::from(path_budget.saturating_sub(prefix_w));
        format!(
            "{prefix}{}",
            elide_path(&app.sessions[app.active].repo, room)
        )
    };
    let show_git = show_git && cols(&path) + git_w <= left_budget;

    let mut spans = vec![Span::styled(path, Style::new().fg(FOG))];
    if show_git && let Some((branch, status)) = parts {
        if !pad.is_empty() {
            spans.push(Span::styled(pad, Style::new().fg(FOG)));
        }
        spans.push(Span::styled(
            branch,
            Style::new().fg(BRASS).add_modifier(Modifier::BOLD),
        ));
        let dirty = app.git.dirty();
        spans.push(Span::styled(
            status,
            Style::new().fg(if dirty { YELLOW } else { GREEN }),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            width: left_budget,
            ..area
        },
    );
}

fn paint_activity_pills(
    app: &App,
    frame: &mut Frame,
    area: Rect,
    labels: &[String],
    pills_w: u16,
    hits: &mut Hits,
) {
    let mut px = area.right().saturating_sub(pills_w);
    let pill_hits = [
        &mut hits.subagents_pill,
        &mut hits.tasks_pill,
        &mut hits.timers_pill,
        &mut hits.tools_pill,
        &mut hits.skills_pill,
    ];
    for (label, hit_rect) in labels.iter().zip(pill_hits) {
        let w = cols(label);
        if px + w > area.right() {
            break;
        }
        *hit_rect = Rect {
            x: px,
            y: area.y,
            width: w,
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                label.clone(),
                chip_style(Style::new().fg(FOG), hot(*hit_rect, app.mouse)),
            ))),
            *hit_rect,
        );
        px += w + 1;
    }
}

/// Keep the longest trailing `/`-separated tail that fits in `max` columns,
/// prefixed with `…/`. The full path is returned when it already fits.
pub fn elide_path(path: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if path.chars().count() <= max {
        return path.to_string();
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return truncate(path, max);
    }
    let mut best = String::from("…");
    for n in 1..=parts.len() {
        let tail = parts[parts.len() - n..].join("/");
        let candidate = format!("…/{tail}");
        if candidate.chars().count() <= max {
            best = candidate;
        } else {
            break;
        }
    }
    if best != "…" {
        return best;
    }
    let last = parts[parts.len() - 1];
    let prefix = "…/";
    let room = max.saturating_sub(prefix.chars().count());
    if room == 0 {
        return "…".to_string();
    }
    format!("{prefix}{}", truncate(last, room))
}

/* ------------------------------- transcript ------------------------------- */

/// A wrapped transcript line, tagged with the turn it belongs to and whether
/// it's part of the turn's (stickable) user message.
struct RenderLine {
    turn: usize,
    header: bool,
    line: Line<'static>,
}

struct TranscriptLayout {
    lines: Vec<RenderLine>,
    turn_user: Vec<Option<String>>,
    turn_accent: Vec<Color>,
    actions: Vec<HeaderAction>,
    thinking: Vec<(usize, usize)>,
    names: Vec<NameAction>,
    summaries: Vec<(usize, usize)>,
    subagents: Vec<(Vec<usize>, bool, usize)>,
}

struct NameAction {
    message: usize,
    line: usize,
    col: u16,
    width: u16,
}

fn transcript_has_content(session: &Session) -> bool {
    !session.messages.is_empty()
}

fn render_transcript(app: &mut App, frame: &mut Frame, area: Rect, hits: &mut Hits) {
    hits.transcript = area;
    let active = app.active;

    if !transcript_has_content(&app.sessions[active]) {
        render_empty_state(frame, area);
        app.transcript_total = 0;
        app.transcript_view = usize::from(area.height);
        return;
    }

    // Reserve the rightmost column for the scrollbar so text never reflows as
    // it appears and disappears.
    let text_area = Rect {
        width: area.width.saturating_sub(1),
        ..area
    };
    let width = usize::from(text_area.width);
    let layout = build_lines(&app.sessions[active], width);
    let lines = layout.lines;
    let turn_user = layout.turn_user;
    let turn_accent = layout.turn_accent;
    let header_actions = layout.actions;
    let thinking_actions = layout.thinking;
    let name_actions = layout.names;
    let summary_actions = layout.summaries;
    let subagent_lines = layout.subagents;
    let total = lines.len();
    let view_h = usize::from(text_area.height);

    let session = &mut app.sessions[active];
    let max_scroll = total.saturating_sub(view_h);
    if session.pinned {
        session.scroll = max_scroll;
    }
    session.scroll = session.scroll.min(max_scroll);
    let scroll = session.scroll;
    let pinned = session.pinned;
    app.transcript_total = total;
    app.transcript_view = view_h;

    // The whole visible window is one `Paragraph` over a `Text`; our own
    // wrapping already produced screen-ready lines, so no `Wrap` is needed.
    let end = (scroll + view_h).min(total);
    let visible: Vec<Line> = lines[scroll..end].iter().map(|l| l.line.clone()).collect();
    frame.render_widget(Paragraph::new(Text::from(visible)), text_area);

    if total > view_h {
        // The scrollbar's content length is the number of *scroll positions*
        // (`max_scroll + 1`), not the line count: ratatui maps its bottom to
        // `content_length - 1`, so using the line count would leave the thumb
        // short of the bottom when scrolled all the way down.
        let mut sb_state = ScrollbarState::new(max_scroll + 1)
            .position(scroll)
            .viewport_content_length(view_h);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .thumb_symbol("█")
            .track_style(Style::new().fg(NIGHT))
            .thumb_style(Style::new().fg(BRASS));
        frame.render_stateful_widget(scrollbar, area, &mut sb_state);
        hits.transcript_sb = scrollbar_track(area);
    }

    // Sticky user message: when the top visible line belongs to a turn whose
    // user message has scrolled above the fold, pin a condensed version of it
    // to the first row. Always on — it's the default reading behaviour.
    if scroll > 0 {
        let top_turn = lines[scroll].turn;
        let header_start = lines.iter().position(|l| l.turn == top_turn && l.header);
        if let Some(start) = header_start
            && start < scroll
            && let Some(Some(text)) = turn_user.get(top_turn)
        {
            let bar = Rect {
                x: text_area.x,
                y: text_area.y,
                width: text_area.width,
                height: 1,
            };
            fill_bg(frame, bar, SURFACE);
            let condensed = truncate(
                &text.replace('\n', " "),
                usize::from(text_area.width).saturating_sub(2),
            );
            let accent = turn_accent.get(top_turn).copied().unwrap_or(BRASS);
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("▌", Style::new().fg(accent)),
                    Span::styled(condensed, Style::new().fg(INK).add_modifier(Modifier::BOLD)),
                ])),
                bar,
            );
            // Clicking the sticky steps back one turn: scroll just above the
            // current turn's header so the previous turn becomes the sticky one.
            hits.sticky = bar;
            hits.sticky_target = start.saturating_sub(1);
        }
    }

    // Pin / fork hit targets for headers still in the visible window.
    hits.subagent_lines = subagent_lines;
    for (path, interactive, line) in &hits.subagent_lines {
        if *line < scroll || *line >= scroll + view_h {
            continue;
        }
        hits.subagent_blocks.push((
            path.clone(),
            *interactive,
            Rect {
                x: text_area.x,
                y: text_area.y + (*line - scroll) as u16,
                width: text_area.width,
                height: 1,
            },
        ));
    }

    for action in header_actions {
        if action.line < scroll || action.line >= scroll + view_h {
            continue;
        }
        let y = text_area.y + (action.line - scroll) as u16;
        hits.pin.push((
            action.message,
            Rect {
                x: text_area.x + action.buttons.pin_col,
                y,
                width: action.buttons.pin_w,
                height: 1,
            },
        ));
        hits.fork.push((
            action.message,
            Rect {
                x: text_area.x + action.buttons.fork_col,
                y,
                width: action.buttons.fork_w,
                height: 1,
            },
        ));
    }

    for (message, line) in thinking_actions {
        if line < scroll || line >= scroll + view_h {
            continue;
        }
        let y = text_area.y + (line - scroll) as u16;
        hits.thinking.push((
            message,
            Rect {
                x: text_area.x + 2,
                y,
                width: cols(THOUGHT_OPEN).max(cols(THINKING_LIVE)),
                height: 1,
            },
        ));
    }

    for action in name_actions {
        if action.line < scroll || action.line >= scroll + view_h {
            continue;
        }
        hits.agent_name.push((
            action.message,
            Rect {
                x: text_area.x + action.col,
                y: text_area.y + (action.line - scroll) as u16,
                width: action.width,
                height: 1,
            },
        ));
    }

    for (message, line) in summary_actions {
        if line < scroll || line >= scroll + view_h {
            continue;
        }
        hits.summaries.push((
            message,
            Rect {
                x: text_area.x + 2,
                y: text_area.y + (line - scroll) as u16,
                width: cols(SHOW_SUMMARY),
                height: 1,
            },
        ));
    }

    for (idx, rect) in &hits.pin {
        let pinned = app
            .sessions
            .get(active)
            .and_then(|s| s.focused_messages().get(*idx))
            .is_some_and(|m| m.pinned);
        let label = if pinned { UNPIN_LABEL } else { PIN_LABEL };
        if hot(*rect, app.mouse) {
            paint_chip(frame, *rect, label, Style::new().fg(FOG), true);
        }
    }
    for (_, rect) in &hits.fork {
        if hot(*rect, app.mouse) {
            paint_chip(frame, *rect, FORK_LABEL, Style::new().fg(FOG), true);
        }
    }
    for (idx, rect) in &hits.thinking {
        if !hot(*rect, app.mouse) {
            continue;
        }
        let message = app
            .sessions
            .get(active)
            .and_then(|session| session.focused_messages().get(*idx));
        let live = message.is_some_and(|message| {
            message.streaming && matches!(message.segments.last(), Some(Segment::Reasoning(_)))
        });
        let open = message
            .zip(app.sessions.get(active))
            .is_some_and(|(message, session)| session.thinking_visible(message));
        paint_chip(
            frame,
            *rect,
            thinking_header(live, open),
            Style::new().fg(FOG),
            true,
        );
    }
    for (idx, rect) in &hits.summaries {
        if !hot(*rect, app.mouse) {
            continue;
        }
        let open = app
            .sessions
            .get(active)
            .and_then(|session| session.focused_messages().get(*idx))
            .is_some_and(|message| message.summary_open);
        let label = if open { HIDE_SUMMARY } else { SHOW_SUMMARY };
        paint_chip(frame, *rect, label, Style::new().fg(FOG), true);
    }
    for (idx, rect) in &hits.agent_name {
        let session = app.sessions.get(active);
        let open = session
            .and_then(|session| session.focused_messages().get(*idx))
            .is_some_and(|message| message.stats_open);
        if !open && !hot(*rect, app.mouse) {
            continue;
        }
        let accent = if session.is_some_and(|session| session.locked_in_interactive()) {
            TEAL
        } else {
            BRASS
        };
        paint_chip(
            frame,
            *rect,
            "Agent",
            Style::new().fg(accent).add_modifier(Modifier::BOLD),
            true,
        );
    }

    // Jump-to-latest: while the transcript isn't following the tail and there's
    // content below, float a chip in the bottom-right. Clicking it re-pins.
    if !pinned && scroll < max_scroll {
        let label = " ↓ Latest ";
        let w = (label.chars().count() as u16).min(text_area.width);
        let rect = Rect {
            x: text_area.right().saturating_sub(w),
            y: text_area.bottom().saturating_sub(1),
            width: w,
            height: 1,
        };
        fill_bg(frame, rect, HOVER_BG);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                label,
                Style::new().fg(BRASS).add_modifier(Modifier::BOLD),
            ))),
            rect,
        );
        hits.jump_latest = rect;
    }
}

/// Turn the active session's messages into wrapped, tagged render lines, plus
/// each turn's raw user text (indexed by turn number) for the sticky header,
/// plus pin/fork hit layouts for every user/agent header.
fn build_lines(session: &Session, width: usize) -> TranscriptLayout {
    let mut layout = TranscriptLayout {
        lines: Vec::new(),
        turn_user: vec![None],
        turn_accent: vec![BRASS],
        actions: Vec::new(),
        thinking: Vec::new(),
        names: Vec::new(),
        summaries: Vec::new(),
        subagents: Vec::new(),
    };
    let mut turn = 0usize;
    paint_messages(
        &mut layout,
        &session.messages,
        width,
        session,
        &mut turn,
        &[],
        BRASS,
    );
    layout
}

fn paint_messages(
    layout: &mut TranscriptLayout,
    messages: &[Message],
    width: usize,
    session: &Session,
    turn: &mut usize,
    layer: &[usize],
    accent: Color,
) {
    let record_hits = layer == session.focus.as_slice();
    for (message_idx, message) in messages.iter().enumerate() {
        match message.role {
            Role::User => {
                *turn += 1;
                layout.turn_user.push(Some(message.plain()));
                if layout.turn_accent.len() <= *turn {
                    layout.turn_accent.resize(*turn + 1, BRASS);
                }
                layout.turn_accent[*turn] = accent;
                push_user(
                    &mut layout.lines,
                    &mut layout.actions,
                    *turn,
                    message_idx,
                    message,
                    width,
                    accent,
                    record_hits,
                );
            }
            Role::Agent => push_agent(
                layout,
                turn,
                message_idx,
                message,
                width,
                session,
                layer,
                accent,
            ),
            Role::System => {
                if let Some(Segment::Injection { from, body }) = message.segments.first() {
                    push_injection(&mut layout.lines, *turn, from, body, width);
                } else if let Some(Segment::Compaction { notice, summary }) =
                    message.segments.first()
                {
                    push_compaction(
                        layout,
                        *turn,
                        message_idx,
                        notice,
                        summary,
                        message.summary_open,
                        width,
                        record_hits,
                    );
                } else {
                    push_system(&mut layout.lines, *turn, message, width);
                }
            }
        }
        layout.lines.push(RenderLine {
            turn: *turn,
            header: false,
            line: Line::default(),
        });
    }
}

fn push_stats(
    layout: &mut TranscriptLayout,
    turn: usize,
    stats: &TurnStats,
    streaming: bool,
    width: usize,
) {
    let rows = [
        ("Model", stats.model_text()),
        ("TTFT", stats.ttft_text(streaming)),
        ("TPS", stats.tps_text(streaming)),
        ("Cache", stats.cache_text()),
    ];
    for (label, value) in rows {
        let line = format!("  {label:<5}  {value}");
        for wrapped in wrap(&line, width) {
            layout.lines.push(RenderLine {
                turn,
                header: false,
                line: Line::from(Span::styled(wrapped, Style::new().fg(FOG))),
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_user(
    lines: &mut Vec<RenderLine>,
    actions: &mut Vec<HeaderAction>,
    turn: usize,
    message_idx: usize,
    message: &Message,
    width: usize,
    accent: Color,
    record_hits: bool,
) {
    let line_idx = lines.len();
    let (line, buttons) = header_with_actions(
        vec![
            Span::styled("▌ ", Style::new().fg(accent)),
            Span::styled("You", Style::new().fg(INK).add_modifier(Modifier::BOLD)),
        ],
        message.pinned,
        message.at,
        width,
        record_hits,
    );
    lines.push(RenderLine {
        turn,
        header: true,
        line,
    });
    if record_hits && let Some(buttons) = buttons {
        actions.push(HeaderAction {
            message: message_idx,
            line: line_idx,
            buttons,
        });
    }
    for wrapped in wrap(&message.plain(), width.saturating_sub(2)) {
        lines.push(RenderLine {
            turn,
            header: true,
            line: Line::from(vec![
                Span::styled("▌ ", Style::new().fg(accent)),
                Span::styled(wrapped, Style::new().fg(INK)),
            ]),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn push_agent(
    layout: &mut TranscriptLayout,
    turn: &mut usize,
    message_idx: usize,
    message: &Message,
    width: usize,
    session: &Session,
    layer: &[usize],
    accent: Color,
) {
    let record_hits = layer == session.focus.as_slice();
    let show_thinking = session.thinking_visible(message);
    let line_idx = layout.lines.len();
    let (line, buttons) = header_with_actions(
        vec![
            Span::styled("▌ ", Style::new().fg(accent)),
            Span::styled(
                "Agent".to_string(),
                Style::new().fg(accent).add_modifier(Modifier::BOLD),
            ),
        ],
        message.pinned,
        message.at,
        width,
        record_hits,
    );
    layout.lines.push(RenderLine {
        turn: *turn,
        header: false,
        line,
    });
    if record_hits && let Some(buttons) = buttons {
        layout.actions.push(HeaderAction {
            message: message_idx,
            line: line_idx,
            buttons,
        });
    }
    if record_hits && message.stats.is_some() {
        layout.names.push(NameAction {
            message: message_idx,
            line: line_idx,
            col: 2,
            width: cols("Agent"),
        });
    }

    if message.stats_open
        && let Some(stats) = &message.stats
    {
        push_stats(layout, *turn, stats, message.streaming, width);
    }

    if message.segments.is_empty() && message.streaming {
        layout.lines.push(RenderLine {
            turn: *turn,
            header: false,
            line: Line::from(Span::styled("  · · ·", Style::new().fg(FOG))),
        });
    }

    // A blank row separates agent prose from a tool call (a diff) in either
    // direction, so file changes read as their own block.
    let mut prev_diff: Option<bool> = None;
    let last_idx = message.segments.len().saturating_sub(1);
    for (seg_i, segment) in message.segments.iter().enumerate() {
        let is_diff = matches!(segment, Segment::Diff(_));
        let is_block = matches!(
            segment,
            Segment::Subagent { .. }
                | Segment::Tool { .. }
                | Segment::Injection { .. }
                | Segment::Compaction { .. }
        );
        let is_live_think =
            matches!(segment, Segment::Reasoning(_)) && message.streaming && seg_i == last_idx;
        if !is_diff && !is_block && !is_live_think && segment.text().is_empty() {
            continue;
        }
        if prev_diff.is_some_and(|was| was != is_diff) {
            layout.lines.push(RenderLine {
                turn: *turn,
                header: false,
                line: Line::default(),
            });
        }
        if let Segment::Diff(file) = segment {
            push_diff(&mut layout.lines, *turn, file, width);
        } else if let Segment::Subagent {
            name,
            interactive,
            summary,
            path,
        } = segment
        {
            let header_line = layout.lines.len();
            if *interactive {
                push_expand_rule(&mut layout.lines, *turn, name, width);
                layout.subagents.push((path.clone(), true, header_line));
                if let Some(node) = session.node_at(path) {
                    paint_messages(
                        layout,
                        &node.messages,
                        width,
                        session,
                        turn,
                        path.as_slice(),
                        TEAL,
                    );
                }
            } else {
                push_subagent(&mut layout.lines, *turn, name, *interactive, summary, width);
                layout
                    .subagents
                    .push((path.clone(), *interactive, header_line));
            }
        } else if let Segment::Tool { name, hint } = segment {
            push_tool(&mut layout.lines, *turn, name, hint, width);
        } else if let Segment::Injection { from, body } = segment {
            push_injection(&mut layout.lines, *turn, from, body, width);
        } else if let Segment::Reasoning(text) = segment {
            push_thinking(
                layout,
                *turn,
                message_idx,
                text,
                is_live_think,
                show_thinking,
                width,
                record_hits,
            );
        } else {
            let (style, prefix) = (Style::new().fg(INK), "  ");
            for wrapped in wrap(segment.text(), width.saturating_sub(2)) {
                layout.lines.push(RenderLine {
                    turn: *turn,
                    header: false,
                    line: Line::from(Span::styled(format!("{prefix}{wrapped}"), style)),
                });
            }
        }
        prev_diff = Some(is_diff || is_block);
    }

    // A streaming caret on the last rendered line — but not on a diff, which
    // lands whole rather than streaming character by character.
    if message.streaming
        && !matches!(
            message.segments.last(),
            Some(
                Segment::Diff(_)
                    | Segment::Subagent { .. }
                    | Segment::Tool { .. }
                    | Segment::Injection { .. }
                    | Segment::Compaction { .. }
            )
        )
        && !message.segments.is_empty()
        && let Some(last) = layout.lines.last_mut()
    {
        last.line
            .spans
            .push(Span::styled("▌", Style::new().fg(accent)));
    }

    if message.interrupted {
        layout.lines.push(RenderLine {
            turn: *turn,
            header: false,
            line: Line::from(vec![
                Span::styled("  ⎯ ", Style::new().fg(YELLOW)),
                Span::styled("Stopped — you sent a message", Style::new().fg(FOG)),
            ]),
        });
    }
}

fn thinking_header(live: bool, open: bool) -> &'static str {
    if live {
        THINKING_LIVE
    } else if open {
        THOUGHT_OPEN
    } else {
        THOUGHT_CLOSED
    }
}

#[allow(clippy::too_many_arguments)]
fn push_thinking(
    layout: &mut TranscriptLayout,
    turn: usize,
    message_idx: usize,
    text: &str,
    live: bool,
    open: bool,
    width: usize,
    record_hits: bool,
) {
    let label = thinking_header(live, open);
    let chip_line = layout.lines.len();
    let mut header_style = Style::new().fg(FOG);
    if live {
        header_style = header_style.add_modifier(Modifier::ITALIC);
    }
    layout.lines.push(RenderLine {
        turn,
        header: false,
        line: Line::from(Span::styled(format!("  {label}"), header_style)),
    });
    if record_hits {
        layout.thinking.push((message_idx, chip_line));
    }
    if !live && !open {
        return;
    }
    if text.is_empty() {
        layout.lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled("  · · ·", Style::new().fg(FOG))),
        });
        return;
    }
    for wrapped in wrap(text, width.saturating_sub(2)) {
        layout.lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled(
                format!("  {wrapped}"),
                Style::new().fg(DISABLED).add_modifier(Modifier::ITALIC),
            )),
        });
    }
}

fn push_expand_rule(lines: &mut Vec<RenderLine>, turn: usize, name: &str, width: usize) {
    let label = format!("─ {name}");
    for wrapped in wrap(&label, width.saturating_sub(2)) {
        lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled(
                format!("  {wrapped}"),
                Style::new().fg(DISABLED),
            )),
        });
    }
}

fn push_subagent(
    lines: &mut Vec<RenderLine>,
    turn: usize,
    name: &str,
    interactive: bool,
    summary: &str,
    width: usize,
) {
    let bar = if interactive { TEAL } else { FOG };
    lines.push(RenderLine {
        turn,
        header: false,
        line: Line::from(vec![
            Span::styled("▌ ", Style::new().fg(bar)),
            Span::styled(
                name.to_string(),
                Style::new().fg(INK).add_modifier(Modifier::BOLD),
            ),
        ]),
    });
    for wrapped in wrap(summary, width.saturating_sub(2)) {
        lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(vec![
                Span::styled("▌ ", Style::new().fg(bar)),
                Span::styled(wrapped, Style::new().fg(FOG)),
            ]),
        });
    }
}

fn push_tool(lines: &mut Vec<RenderLine>, turn: usize, name: &str, hint: &str, width: usize) {
    let label = if hint.is_empty() {
        format!("▸ {name}")
    } else {
        format!("▸ {name}  {hint}")
    };
    for (i, wrapped) in wrap(&label, width.saturating_sub(2))
        .into_iter()
        .enumerate()
    {
        let prefix = if i == 0 { "  " } else { "    " };
        lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled(
                format!("{prefix}{wrapped}"),
                Style::new().fg(FOG),
            )),
        });
    }
}

fn push_injection(lines: &mut Vec<RenderLine>, turn: usize, from: &str, body: &str, width: usize) {
    let label = format!("▸ {from}");
    for (i, wrapped) in wrap(&label, width.saturating_sub(2))
        .into_iter()
        .enumerate()
    {
        let prefix = if i == 0 { "  " } else { "    " };
        lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled(
                format!("{prefix}{wrapped}"),
                Style::new().fg(FOG),
            )),
        });
    }
    for wrapped in wrap(body, width.saturating_sub(2)) {
        lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled(format!("  {wrapped}"), Style::new().fg(FOG))),
        });
    }
}

/// Render a file change as a diff: a header naming the file and its ±counts,
/// then a left-guttered body where additions are green, removals red, and
/// context dim. Long lines wrap under a blank sign so the columns stay aligned.
fn push_diff(lines: &mut Vec<RenderLine>, turn: usize, file: &FileDiff, width: usize) {
    let (added, removed) = file.counts();
    let mut header = vec![
        Span::styled("  ◇ ", Style::new().fg(BRASS)),
        Span::styled(format!("{} ", file.verb()), Style::new().fg(FOG)),
        Span::styled(
            file.path.clone(),
            Style::new().fg(INK).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("  +{added}"), Style::new().fg(GREEN)),
    ];
    if removed > 0 {
        header.push(Span::styled(format!(" -{removed}"), Style::new().fg(RED)));
    }
    lines.push(RenderLine {
        turn,
        header: false,
        line: Line::from(header),
    });

    // Indent (2) + gutter "│ " (2) + sign "± " (2) = 6 columns of chrome.
    let content_w = width.saturating_sub(6).max(1);
    for diff_line in &file.lines {
        let (sign, content, color) = match diff_line {
            DiffLine::Added(text) => ('+', text, GREEN),
            DiffLine::Removed(text) => ('-', text, RED),
            DiffLine::Context(text) => (' ', text, FOG),
        };
        let wrapped = if content.is_empty() {
            vec![String::new()]
        } else {
            wrap(content, content_w)
        };
        for (i, piece) in wrapped.iter().enumerate() {
            let sign_span = if i == 0 {
                Span::styled(format!("{sign} "), Style::new().fg(color))
            } else {
                Span::raw("  ")
            };
            lines.push(RenderLine {
                turn,
                header: false,
                line: Line::from(vec![
                    Span::raw("  "),
                    Span::styled("│ ", Style::new().fg(NIGHT)),
                    sign_span,
                    Span::styled(piece.clone(), Style::new().fg(color)),
                ]),
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_compaction(
    layout: &mut TranscriptLayout,
    turn: usize,
    message_idx: usize,
    notice: &str,
    summary: &str,
    open: bool,
    width: usize,
    record_hits: bool,
) {
    for wrapped in wrap(notice, width.saturating_sub(6)) {
        layout.lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled(
                format!("⋯ {wrapped} ⋯"),
                Style::new().fg(DISABLED).add_modifier(Modifier::ITALIC),
            ))
            .centered(),
        });
    }
    let label = if open { HIDE_SUMMARY } else { SHOW_SUMMARY };
    let chip_line = layout.lines.len();
    layout.lines.push(RenderLine {
        turn,
        header: false,
        line: Line::from(Span::styled(format!("  {label}"), Style::new().fg(FOG))),
    });
    if record_hits {
        layout.summaries.push((message_idx, chip_line));
    }
    if open {
        for wrapped in wrap(summary, width.saturating_sub(2)) {
            layout.lines.push(RenderLine {
                turn,
                header: false,
                line: Line::from(Span::styled(
                    if wrapped.is_empty() {
                        String::new()
                    } else {
                        format!("  {wrapped}")
                    },
                    Style::new().fg(INK),
                )),
            });
        }
    }
}

/// A slash-command note: a dim, centered `⋯ text ⋯` divider.
fn push_system(lines: &mut Vec<RenderLine>, turn: usize, message: &Message, width: usize) {
    for wrapped in wrap(&message.plain(), width.saturating_sub(6)) {
        lines.push(RenderLine {
            turn,
            header: false,
            line: Line::from(Span::styled(
                format!("⋯ {wrapped} ⋯"),
                Style::new().fg(DISABLED).add_modifier(Modifier::ITALIC),
            ))
            .centered(),
        });
    }
}

fn render_empty_state(frame: &mut Frame, area: Rect) {
    let mut lines = Vec::new();
    let wide_enough = usize::from(area.width) >= super::banner::RENDERED_WIDTH;
    let tall_enough = usize::from(area.height) >= super::banner::RENDERED_HEIGHT + 2;
    if wide_enough && tall_enough {
        lines.extend(super::banner::p51_lines());
        lines.push(Line::default());
    }
    lines.push(
        Line::from(vec![
            Span::styled("cockpit", Style::new().fg(INK).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::styled(
                format!("v{}", env!("CARGO_PKG_VERSION")),
                Style::new().fg(FOG),
            ),
        ])
        .centered(),
    );
    let block_h = lines.len() as u16;
    let y = area.y + area.height.saturating_sub(block_h) / 2;
    let inner = Rect {
        x: area.x,
        y,
        width: area.width,
        height: block_h.min(area.height),
    };
    frame.render_widget(Paragraph::new(lines).centered(), inner);
}

/* -------------------------------- composer -------------------------------- */

fn render_composer(
    app: &App,
    frame: &mut Frame,
    area: Rect,
    queue_h: u16,
    sugg_h: u16,
    input_box_h: u16,
    hits: &mut Hits,
) -> Option<Position> {
    let session = &app.sessions[app.active];
    let [queue_area, sugg_area, input_area] = area.layout(&Layout::vertical([
        Constraint::Length(queue_h),
        Constraint::Length(sugg_h),
        Constraint::Length(input_box_h),
    ]));

    if queue_h > 0 {
        render_queue(session, frame, queue_area, app.mouse, hits);
    }
    if sugg_h > 0 {
        render_suggestions(session, frame, sugg_area, hits);
    }

    render_input(app, frame, input_area, hits)
}

fn render_queue(
    session: &Session,
    frame: &mut Frame,
    area: Rect,
    mouse: Option<Position>,
    hits: &mut Hits,
) {
    let peak = peak_mode(&session.queue).unwrap_or(QueueMode::Turn);
    let [label_row, items_area, hint_row] = area.layout(&Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(session.queue.len().min(5) as u16),
        Constraint::Min(0),
    ]));

    let edit_label = if session.queue.len() == 1 {
        "[Edit]"
    } else {
        "[Edit all]"
    };
    let edit_w = cols(edit_label);
    let edit_rect = Rect {
        x: label_row.right().saturating_sub(edit_w),
        y: label_row.y,
        width: edit_w,
        height: 1,
    };
    let summary_w = label_row.width.saturating_sub(edit_w + 1);
    let count = session.queue.len();
    let plural = if count == 1 { "" } else { "s" };
    let rest = format!("· {count} message{plural}  {}", peak.detail());
    let label_w = peak.label().chars().count() + 1;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{} ", peak.label()),
                Style::new().fg(peak.color()).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                truncate(&rest, usize::from(summary_w).saturating_sub(label_w)),
                Style::new().fg(FOG),
            ),
        ])),
        Rect {
            width: summary_w,
            ..label_row
        },
    );
    paint_chip(
        frame,
        edit_rect,
        edit_label,
        Style::new().fg(BRASS),
        hot(edit_rect, mouse),
    );
    hits.queue_edit = edit_rect;

    for (row, item) in session.queue.iter().take(5).enumerate() {
        let rect = Rect {
            x: items_area.x,
            y: items_area.y + row as u16,
            width: items_area.width,
            height: 1,
        };
        // Schedule chips + remove, right-aligned: [Queued] [Boundary] [Interrupt] [x]
        let chips: [(&str, QueueMode); 3] = [
            (QueueMode::Turn.chip(), QueueMode::Turn),
            (QueueMode::Boundary.chip(), QueueMode::Boundary),
            (QueueMode::Interrupt.chip(), QueueMode::Interrupt),
        ];
        const REMOVE: &str = "[x]";
        let chips_w: u16 = chips
            .iter()
            .map(|(label, _)| label.chars().count() as u16 + 1)
            .sum::<u16>()
            + REMOVE.chars().count() as u16;
        let text_w = usize::from(rect.width.saturating_sub(chips_w + 1));
        let text = truncate(&item.text, text_w);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(text, Style::new().fg(INK)))),
            rect,
        );

        let mut x = rect.right().saturating_sub(chips_w);
        let mut mode_rects = [Rect::default(); 3];
        for (i, (label, mode)) in chips.iter().enumerate() {
            let w = label.chars().count() as u16;
            let selected = item.mode == *mode;
            let style = if selected {
                Style::new().fg(mode.color()).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(DISABLED)
            };
            let r = Rect {
                x,
                y: rect.y,
                width: w,
                height: 1,
            };
            paint_chip(frame, r, label, style, hot(r, mouse));
            mode_rects[i] = r;
            x += w + 1;
        }
        let remove_w = REMOVE.chars().count() as u16;
        let remove_rect = Rect {
            x,
            y: rect.y,
            width: remove_w,
            height: 1,
        };
        paint_chip(
            frame,
            remove_rect,
            REMOVE,
            Style::new().fg(FOG),
            hot(remove_rect, mouse),
        );
        hits.queue_modes.push((row, mode_rects));
        hits.queue_remove.push((row, remove_rect));
    }

    if !peak.next_hint().is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("↵ ", Style::new().fg(BRASS)),
                Span::styled(peak.next_hint(), Style::new().fg(FOG)),
            ])),
            hint_row,
        );
    }
}

fn render_suggestions(session: &Session, frame: &mut Frame, area: Rect, hits: &mut Hits) {
    let mut x = area.x;
    for (i, suggestion) in session.suggestions.iter().enumerate() {
        let chip = format!("‹ {} ›", truncate(suggestion, 40));
        let w = chip.chars().count() as u16;
        if x + w > area.right() {
            break;
        }
        let rect = Rect {
            x,
            y: area.y,
            width: w,
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(chip, Style::new().fg(FOG)))),
            rect,
        );
        hits.suggestions.push((i, rect));
        x += w + 1;
    }
}

/// The composer input: a rounded box whose *bottom border* carries the model
/// and effort pills on the left and the send action on the right, e.g.
/// `╰ ⚙ GPT-5 Codex ▾ · Effort: High ▾ ──────── [ Send ↵ ] ╯`.
fn render_input(app: &App, frame: &mut Frame, area: Rect, hits: &mut Hits) -> Option<Position> {
    let session = &app.sessions[app.active];
    let focused = app.overlay.is_none();
    let border = if focused { BRASS } else { NIGHT };

    // Box with a top and sides only; we draw the bottom border by hand so the
    // controls can live on it.
    let block = Block::new()
        .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(border));
    frame.render_widget(&block, area);

    // The text rows between the borders. The box grows with content, so this
    // can be several rows tall; the input wraps to fill them.
    let text_rows = area.height.saturating_sub(2).max(1);
    let text = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: text_rows,
    };
    let caret = if app.input.text().is_empty() {
        let placeholder = if session.is_working() {
            if session.queue.is_empty() {
                "The agent is working — type to queue a message…".to_string()
            } else {
                "Press Enter again to send sooner…".to_string()
            }
        } else {
            "Ask anything, ⇧↵ for a newline, or / for commands…".to_string()
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate(&placeholder, usize::from(text.width)),
                Style::new().fg(PLACEHOLDER).add_modifier(Modifier::ITALIC),
            ))),
            text,
        );
        focused.then(|| Position::new(text.x, text.y))
    } else {
        let (rows, caret_row, caret_col) = app
            .input
            .layout(usize::from(text.width), usize::from(text_rows));
        let body: Vec<Line> = rows
            .into_iter()
            .map(|row| Line::from(Span::styled(row, Style::new().fg(INK))))
            .collect();
        frame.render_widget(Paragraph::new(Text::from(body)), text);
        focused.then(|| Position::new(text.x + caret_col, text.y + caret_row))
    };

    render_input_footer(app, frame, area, border, hits);
    caret
}

/// Paint the input box's bottom border: rounded corners, the agent / model /
/// effort / sandbox pills, the send action, and dashes filling the gaps.
/// Uses the long labels when they fit, otherwise the compact ones.
fn render_input_footer(app: &App, frame: &mut Frame, area: Rect, border: Color, hits: &mut Hits) {
    if area.width < 2 {
        return;
    }
    let session = &app.sessions[app.active];
    let border_style = Style::new().fg(border);
    let label_style = Style::new().fg(FOG);
    let send_style = Style::new().fg(BRASS).add_modifier(Modifier::BOLD);

    let locked = session.locked_in_interactive();
    let agent_name = AGENTS[app.agent].name;
    let model_name = if locked {
        session.focused_model().unwrap_or(MODELS[app.model].display)
    } else {
        MODELS[app.model].display
    };
    let effort_name = app.effort.label();
    let permissions_name = app.permissions.label();
    let sandbox_name = app.sandbox.label();
    let full = [
        format!("[{agent_name}]"),
        format!("[{model_name}]"),
        format!("[{effort_name}]"),
        format!("[permissions: {permissions_name}]"),
        format!("[sandbox: {sandbox_name}]"),
    ];
    let compact = [
        format!("[{agent_name}]"),
        format!("[{model_name}]"),
        format!("[{effort_name}]"),
        format!("[{permissions_name}]"),
        format!("[{sandbox_name}]"),
    ];
    let send_label = if session.is_working() {
        "[Queue]"
    } else {
        "[Send]"
    };
    let send_w = cols(send_label);

    let y = area.bottom() - 1;
    let right = area.right();

    // Base: rounded corners with a dashed rule between.
    let dashes = "─".repeat(usize::from(area.width) - 2);
    let buf = frame.buffer_mut();
    buf.set_string(area.x, y, format!("╰{dashes}"), border_style);
    buf.set_string(right - 1, y, "╯", border_style);

    // Budget: opening corner, one dash before send, send, closing corner.
    let budget = area.width.saturating_sub(2 + send_w + 1);
    let labels = if cluster_width(&full) <= budget {
        &full
    } else {
        &compact
    };
    if cluster_width(labels) > budget && area.width < 2 + send_w {
        return;
    }

    let send_x = right - 1 - send_w;
    hits.send = Rect {
        x: send_x,
        y,
        width: send_w,
        height: 1,
    };
    buf.set_string(
        send_x,
        y,
        send_label,
        chip_style(send_style, hot(hits.send, app.mouse)),
    );

    let mut x = area.x + 1;
    let end = send_x.saturating_sub(1);
    let pill_hits = [
        &mut hits.agent_pill,
        &mut hits.model_pill,
        &mut hits.effort_pill,
        &mut hits.permissions_pill,
        &mut hits.sandbox_pill,
    ];
    for (i, (label, hit_rect)) in labels.iter().zip(pill_hits).enumerate() {
        let w = cols(label);
        if x + w > end {
            break;
        }
        let clickable = !locked || i > 1;
        *hit_rect = Rect {
            x,
            y,
            width: w,
            height: 1,
        };
        buf.set_string(
            x,
            y,
            label,
            chip_style(label_style, clickable && hot(*hit_rect, app.mouse)),
        );
        x += w + 1;
    }
}

fn cluster_width(labels: &[String]) -> u16 {
    if labels.is_empty() {
        return 0;
    }
    labels.iter().map(|label| cols(label)).sum::<u16>() + (labels.len() as u16 - 1)
}

/// The slash-command palette, floating just above the input box. Mirrors the
/// web console's menu: `/name` plus a one-line hint, keyboard- and
/// mouse-drivable, ranked prefix-first.
fn render_slash(app: &App, frame: &mut Frame, input_top: u16, hits: &mut Hits) {
    let Some(query) = app.slash_query() else {
        return;
    };
    let matches = command::matches(query);
    if matches.is_empty() {
        return;
    }
    let cursor = app.slash_cursor().min(matches.len() - 1);
    let anchor = app.overlay_anchor;

    let visible = matches.len().min(6) as u16;
    let height = visible + 2;
    let width = anchor.width.clamp(24, 56).min(anchor.width.max(1));
    let rect = Rect {
        x: anchor.x,
        y: input_top.saturating_sub(height),
        width,
        height,
    };

    frame.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(BRASS))
        .title(Span::styled(" Commands ", Style::new().fg(BRASS)));
    let inner = block.inner(rect);

    let hint_w = usize::from(inner.width).saturating_sub(14);
    let items: Vec<ListItem> = matches
        .iter()
        .map(|command| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("/{}", command.name),
                    Style::new().fg(INK).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  {}", truncate(command.hint, hint_w)),
                    Style::new().fg(FOG),
                ),
            ]))
        })
        .collect();

    let mut state = ListState::default().with_selected(Some(cursor));
    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::new()
                .bg(HOVER_BG)
                .fg(BRASS)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(list, rect, &mut state);

    // Click targets, aligned to the offset `List` settled on.
    let offset = state.offset();
    for (row, command) in matches.iter().enumerate().skip(offset) {
        let y = inner.y + (row - offset) as u16;
        if y >= inner.bottom() {
            break;
        }
        hits.slash_rows.push((
            command.name,
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            },
        ));
    }
}

/* --------------------------------- overlay -------------------------------- */

fn render_overlay(app: &mut App, frame: &mut Frame, overlay: Overlay, hits: &mut Hits) {
    let anchor = app.overlay_anchor;
    let confirm_title = match overlay {
        Overlay::ConfirmDelete { session, .. } => app
            .sessions
            .get(session)
            .map(|s| s.title.clone())
            .unwrap_or_else(|| "session".into()),
        _ => String::new(),
    };
    let session = &app.sessions[app.active];
    let (title, rows): (String, Vec<(String, String)>) = match overlay {
        Overlay::Provider { .. } => (
            "Select provider".to_string(),
            providers()
                .iter()
                .map(|p| {
                    let count = models_for(p).len();
                    let plural = if count == 1 { "" } else { "s" };
                    (p.to_string(), format!("{count} model{plural}  ›"))
                })
                .collect(),
        ),
        Overlay::Model { provider, .. } => {
            let name = providers().get(provider).copied().unwrap_or("");
            (
                format!("{name} models"),
                models_for(name)
                    .iter()
                    .map(|&i| (MODELS[i].display.to_string(), String::new()))
                    .collect(),
            )
        }
        Overlay::Effort { .. } => (
            "Reasoning effort".to_string(),
            Effort::ORDER
                .iter()
                .map(|e| (e.label().to_string(), e.hint().to_string()))
                .collect(),
        ),
        Overlay::Agent { .. } => (
            "Select agent".to_string(),
            AGENTS
                .iter()
                .map(|a| (a.name.to_string(), a.hint.to_string()))
                .collect(),
        ),
        Overlay::Sandbox { .. } => (
            "Sandbox".to_string(),
            Sandbox::ORDER
                .iter()
                .map(|mode| (mode.label().to_string(), mode.hint().to_string()))
                .collect(),
        ),
        Overlay::Permissions { .. } => (
            "Permissions".to_string(),
            Permissions::ORDER
                .iter()
                .map(|mode| (mode.label().to_string(), mode.hint().to_string()))
                .collect(),
        ),
        Overlay::Subagents { .. } => {
            let kids = session.background_workers();
            (
                "Active subagents".to_string(),
                if kids.is_empty() {
                    vec![("No active subagents".to_string(), String::new())]
                } else {
                    kids.iter()
                        .map(|(_, node)| (node.name.clone(), node.status.short().to_string()))
                        .collect()
                },
            )
        }
        Overlay::Background { .. } => {
            let tasks = session.layer_tasks();
            (
                "Background tasks".to_string(),
                if tasks.is_empty() {
                    vec![("No background tasks".to_string(), String::new())]
                } else {
                    tasks
                        .iter()
                        .map(|task| (task.name.clone(), task.status.short().to_string()))
                        .collect()
                },
            )
        }
        Overlay::Timers { .. } => {
            let timers = session.layer_timers();
            (
                "Timers".to_string(),
                if timers.is_empty() {
                    vec![("No timers".to_string(), String::new())]
                } else {
                    timers
                        .iter()
                        .map(|timer| (timer.name.clone(), timer.remaining.clone()))
                        .collect()
                },
            )
        }
        Overlay::Tools { .. } => {
            let tools = session.layer_tools();
            (
                "Tools".to_string(),
                if tools.is_empty() {
                    vec![("No tools".to_string(), String::new())]
                } else {
                    tools
                        .iter()
                        .map(|tool| {
                            (
                                tool.name.clone(),
                                format!("{} · {}", tool.tier.label(), tool.hint),
                            )
                        })
                        .collect()
                },
            )
        }
        Overlay::Skills { .. } => {
            let skills = session.layer_skills();
            (
                "Skills".to_string(),
                if skills.is_empty() {
                    vec![("No skills".to_string(), String::new())]
                } else {
                    skills
                        .iter()
                        .map(|skill| (skill.name.clone(), skill.hint.clone()))
                        .collect()
                },
            )
        }
        Overlay::ConfirmDelete { .. } => (
            "Confirm delete".to_string(),
            vec![
                ("Cancel".to_string(), "Keep this session".to_string()),
                (
                    "Delete".to_string(),
                    format!("Remove \"{}\"", truncate(&confirm_title, 28)),
                ),
            ],
        ),
    };
    let cursor = overlay.cursor().min(rows.len().saturating_sub(1));

    let header_anchor = match overlay {
        Overlay::Subagents { .. } => hits.subagents_pill,
        Overlay::Background { .. } => hits.tasks_pill,
        Overlay::Timers { .. } => hits.timers_pill,
        Overlay::Tools { .. } => hits.tools_pill,
        Overlay::Skills { .. } => hits.skills_pill,
        _ => Rect::default(),
    };
    let from_header = overlay.opens_from_header() && header_anchor.width > 0;
    let centered = matches!(overlay, Overlay::ConfirmDelete { .. });
    let anchor = if from_header { header_anchor } else { anchor };
    let screen = frame.area();
    let width = if from_header || centered {
        46u16.min(screen.width.saturating_sub(2)).max(20)
    } else {
        46u16.min(anchor.width.max(20))
    };
    let max_h = if centered {
        screen.height.max(3)
    } else if from_header {
        screen
            .bottom()
            .saturating_sub(anchor.bottom())
            .max(anchor.y.saturating_sub(screen.y))
            .max(3)
    } else {
        anchor.y.saturating_sub(screen.y).max(3)
    };
    let warn = matches!(overlay, Overlay::Tools { .. }) && app.tool_cache_warn;
    let height = (rows.len() as u16 + 2 + u16::from(warn))
        .min(max_h)
        .min(16 + u16::from(warn));
    let side = if centered {
        PopoverSide::Center
    } else if from_header {
        PopoverSide::Below
    } else {
        PopoverSide::Above
    };
    let rect = place_popover(anchor, width, height, screen, side);

    hits.overlay_box = rect;
    frame.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(BRASS))
        .title(Span::styled(format!(" {title} "), Style::new().fg(BRASS)));
    let inner = block.inner(rect);
    frame.render_widget(&block, rect);

    if overlay.opens_from_header() {
        render_panning_overlay_list(app, frame, inner, &rows, cursor, hits);
        return;
    }

    let avail = usize::from(inner.width).saturating_sub(2);
    let items: Vec<ListItem> = rows
        .iter()
        .map(|(label, hint)| {
            let label_w = label.chars().count();
            let hint_text = truncate(hint, avail.saturating_sub(label_w + 2));
            ListItem::new(Line::from(vec![
                Span::styled(label.clone(), Style::new().fg(INK)),
                Span::styled(format!("  {hint_text}"), Style::new().fg(FOG)),
            ]))
        })
        .collect();

    let mut state = ListState::default().with_selected(Some(cursor));
    let list = List::new(items)
        .highlight_style(
            Style::new()
                .bg(HOVER_BG)
                .fg(BRASS)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ")
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_stateful_widget(list, inner, &mut state);

    let offset = state.offset();
    for (i, _) in rows.iter().enumerate().skip(offset) {
        let y = inner.y + (i - offset) as u16;
        if y >= inner.bottom() {
            break;
        }
        hits.overlay_rows.push((
            i,
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            },
        ));
    }
}

fn render_panning_overlay_list(
    app: &mut App,
    frame: &mut Frame,
    inner: Rect,
    rows: &[(String, String)],
    cursor: usize,
    hits: &mut Hits,
) {
    let warn = matches!(app.overlay, Some(Overlay::Tools { .. })) && app.tool_cache_warn;
    let footer = u16::from(warn);
    let list_h = inner.height.saturating_sub(footer);
    let view = usize::from(list_h).max(1);
    app.overlay_view = view;
    let max_scroll = rows.len().saturating_sub(view);
    app.overlay_scroll = app.overlay_scroll.min(max_scroll);
    let scroll = app.overlay_scroll;
    let overflow = rows.len() > view;
    let text_area = if overflow && inner.width >= 2 {
        Rect {
            width: inner.width.saturating_sub(1),
            height: list_h,
            ..inner
        }
    } else {
        Rect {
            height: list_h,
            ..inner
        }
    };
    let avail = usize::from(text_area.width).saturating_sub(2);
    for (row, (label, hint)) in rows.iter().enumerate().skip(scroll).take(view) {
        let y = text_area.y + (row - scroll) as u16;
        let rect = Rect {
            x: text_area.x,
            y,
            width: text_area.width,
            height: 1,
        };
        hits.overlay_rows.push((row, rect));
        let selected = row == cursor;
        let label_w = label.chars().count();
        let hint_text = truncate(hint, avail.saturating_sub(label_w + 2));
        let style = if selected {
            Style::new()
                .bg(HOVER_BG)
                .fg(BRASS)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(INK)
        };
        let hint_style = if selected {
            Style::new().bg(HOVER_BG).fg(FOG)
        } else {
            Style::new().fg(FOG)
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(if selected { "› " } else { "  " }.to_string(), style),
                Span::styled(label.clone(), style),
                Span::styled(format!("  {hint_text}"), hint_style),
            ])),
            rect,
        );
    }
    if overflow {
        let track = Rect {
            x: inner.right().saturating_sub(1),
            y: inner.y,
            width: 1,
            height: list_h,
        };
        let mut sb_state = ScrollbarState::new(max_scroll + 1)
            .position(scroll)
            .viewport_content_length(view);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .thumb_symbol("█")
            .track_style(Style::new().fg(NIGHT))
            .thumb_style(Style::new().fg(BRASS));
        frame.render_stateful_widget(scrollbar, track, &mut sb_state);
        hits.overlay_sb = track;
    }
    if warn {
        let rect = Rect {
            x: inner.x,
            y: inner.bottom().saturating_sub(1),
            width: inner.width,
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " Enabling/disabling busts the prompt cache.",
                Style::new().fg(YELLOW),
            ))),
            rect,
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PopoverSide {
    Above,
    Below,
    Center,
}

/// Sit a popup on `anchor`: composer pickers open upward and left-align;
/// activity-bar menus open downward and right-align to the pill, then clamp
/// to `screen` so a right-edge pill does not clip.
fn place_popover(anchor: Rect, width: u16, height: u16, screen: Rect, side: PopoverSide) -> Rect {
    let width = width.min(screen.width).max(1);
    let height = height.min(screen.height).max(1);
    let mut x = match side {
        PopoverSide::Above => anchor.x,
        PopoverSide::Below => anchor.right().saturating_sub(width),
        PopoverSide::Center => screen.x + screen.width.saturating_sub(width) / 2,
    };
    x = x.max(screen.x);
    if x + width > screen.right() {
        x = screen.right().saturating_sub(width);
    }

    let mut y = match side {
        PopoverSide::Above => anchor.y.saturating_sub(height),
        PopoverSide::Below => anchor.bottom(),
        PopoverSide::Center => screen.y + screen.height.saturating_sub(height) / 2,
    };
    if side == PopoverSide::Below && y + height > screen.bottom() {
        y = anchor.y.saturating_sub(height);
    }
    if side == PopoverSide::Above && y < screen.y {
        y = anchor.bottom();
    }
    y = y.max(screen.y);
    if y + height > screen.bottom() {
        y = screen.bottom().saturating_sub(height);
    }

    Rect {
        x,
        y,
        width,
        height,
    }
}

/* --------------------------------- helpers -------------------------------- */

/// Trailing columns kept clear between the timestamp and the scrollbar.
const TIME_RIGHT_PAD: usize = 2;
const PIN_LABEL: &str = "[Pin]";
const UNPIN_LABEL: &str = "[Unpin]";
const FORK_LABEL: &str = "[Fork]";
const THINKING_LIVE: &str = "Thinking";
const THOUGHT_OPEN: &str = "▾ Thought";
const THOUGHT_CLOSED: &str = "▸ Thought";
const SHOW_SUMMARY: &str = "[show summary]";
const HIDE_SUMMARY: &str = "[hide summary]";

/// Clickable `[Pin]` / `[Fork]` slots on a user or agent header, in columns
/// relative to the transcript's text origin.
struct HeaderButtons {
    pin_col: u16,
    pin_w: u16,
    fork_col: u16,
    fork_w: u16,
}

/// One header's pin/fork buttons, tagged with the message and the line index
/// in the wrapped transcript so we can turn them into screen hits after scroll.
struct HeaderAction {
    message: usize,
    line: usize,
    buttons: HeaderButtons,
}

/// Build a message header: leading role, then `[Pin]`/`[Unpin]` and `[Fork]`,
/// then a dim `HH:MM` stamp. The stamp and the buttons drop independently when
/// the row is too narrow. [`TIME_RIGHT_PAD`] columns stay clear of the scrollbar.
fn header_with_actions(
    mut spans: Vec<Span<'static>>,
    pinned: bool,
    at: SystemTime,
    width: usize,
    show_actions: bool,
) -> (Line<'static>, Option<HeaderButtons>) {
    let pin = if pinned { UNPIN_LABEL } else { PIN_LABEL };
    let time = clock_label(at);
    let left: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let pin_w = pin.chars().count();
    let fork_w = FORK_LABEL.chars().count();
    let time_w = time.chars().count();
    let actions_w = pin_w + 1 + fork_w;
    let time_block = 2 + time_w + TIME_RIGHT_PAD;

    let show_actions = show_actions && width >= left + 1 + actions_w + TIME_RIGHT_PAD;
    let show_time = if show_actions {
        width >= left + 1 + actions_w + time_block
    } else {
        width >= left + 1 + time_w + TIME_RIGHT_PAD
    };

    let mut buttons = None;
    if show_actions {
        let right = actions_w
            + if show_time {
                time_block
            } else {
                TIME_RIGHT_PAD
            };
        let gap = width.saturating_sub(left + right);
        spans.push(Span::raw(" ".repeat(gap)));
        let pin_col = (left + gap) as u16;
        let pin_style = if pinned {
            Style::new().fg(YELLOW).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(FOG)
        };
        spans.push(Span::styled(pin.to_string(), pin_style));
        spans.push(Span::raw(" "));
        let fork_col = pin_col + pin_w as u16 + 1;
        spans.push(Span::styled(FORK_LABEL.to_string(), Style::new().fg(FOG)));
        if show_time {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(time, Style::new().fg(DISABLED)));
        }
        buttons = Some(HeaderButtons {
            pin_col,
            pin_w: pin_w as u16,
            fork_col,
            fork_w: fork_w as u16,
        });
    } else if show_time {
        spans.push(Span::raw(
            " ".repeat(width - left - time_w - TIME_RIGHT_PAD),
        ));
        spans.push(Span::styled(time, Style::new().fg(DISABLED)));
    }
    (Line::from(spans), buttons)
}

/// Format a wall-clock instant as local `HH:MM`.
fn clock_label(at: SystemTime) -> String {
    let tm = local_tm(at);
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

/// Compact local datetime for the sidebar, e.g. `Sep 5, 21:48`.
pub(super) fn datetime_label(at: SystemTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let tm = local_tm(at);
    let month = MONTHS.get(tm.tm_mon as usize).copied().unwrap_or("???");
    format!("{month} {}, {:02}:{:02}", tm.tm_mday, tm.tm_hour, tm.tm_min)
}

fn local_tm(at: SystemTime) -> libc::tm {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `localtime_r` writes into our owned `tm`; `secs` is a valid time_t
    // and the two pointers are non-null and distinct.
    unsafe {
        libc::localtime_r(&secs, &mut tm);
    }
    tm
}

fn chip_style(base: Style, hovered: bool) -> Style {
    if hovered {
        base.bg(HOVER_BG).fg(BRASS).add_modifier(Modifier::BOLD)
    } else {
        base
    }
}

fn paint_chip(frame: &mut Frame, rect: Rect, label: &str, base: Style, hovered: bool) {
    if rect.width == 0 || rect.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate(label, usize::from(rect.width)),
            chip_style(base, hovered),
        ))),
        rect,
    );
}

/// Replace every cell in `rect` with a space on `color`, so prior glyphs
/// (e.g. a datetime under session actions) cannot leak through the gaps.
fn clear_cells(frame: &mut Frame, rect: Rect, color: ratatui::style::Color) {
    let buf = frame.buffer_mut();
    for y in rect.y..rect.bottom() {
        for x in rect.x..rect.right() {
            let cell = &mut buf[(x, y)];
            cell.set_symbol(" ");
            cell.set_fg(color);
            cell.set_bg(color);
        }
    }
}

/// Wash `rect` with a solid background colour, leaving the glyphs to whatever
/// is painted on top.
fn fill_bg(frame: &mut Frame, rect: Rect, color: ratatui::style::Color) {
    let buf = frame.buffer_mut();
    for y in rect.y..rect.bottom() {
        for x in rect.x..rect.right() {
            buf[(x, y)].set_bg(color);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Render just the transcript's scrollbar at `scroll` and return the glyph
    /// in its bottom row, using the same state the transcript builds.
    fn scrollbar_bottom_glyph(content_length: usize, view_h: u16, scroll: usize) -> String {
        let mut terminal = Terminal::new(TestBackend::new(1, view_h)).unwrap();
        terminal
            .draw(|frame| {
                let mut state = ScrollbarState::new(content_length)
                    .position(scroll)
                    .viewport_content_length(usize::from(view_h));
                let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None)
                    .track_symbol(Some("│"))
                    .thumb_symbol("█");
                frame.render_stateful_widget(scrollbar, frame.area(), &mut state);
            })
            .unwrap();
        terminal.backend().buffer()[(0, view_h - 1)]
            .symbol()
            .to_string()
    }

    #[test]
    fn the_scrollbar_thumb_reaches_the_bottom_at_max_scroll() {
        let total = 20usize;
        let view_h = 5u16;
        let max_scroll = total - usize::from(view_h);
        // Our fix: content length is the number of scroll positions.
        assert_eq!(
            scrollbar_bottom_glyph(max_scroll + 1, view_h, max_scroll),
            "█",
            "the thumb must fill the bottom row when scrolled all the way down"
        );
        // Regression guard: the old line-count content length left a gap.
        assert_eq!(
            scrollbar_bottom_glyph(total, view_h, max_scroll),
            "│",
            "line-count content length was the bug — thumb fell short"
        );
    }

    #[test]
    fn datetime_label_includes_a_month_and_a_clock() {
        let label = datetime_label(SystemTime::now());
        assert!(
            label.contains(':'),
            "sidebar stamps look like `Sep 5, 21:48`, got {label}"
        );
        assert!(label.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn clock_label_is_a_zero_padded_hh_mm() {
        let label = clock_label(SystemTime::now());
        let bytes = label.as_bytes();
        assert_eq!(label.len(), 5, "HH:MM is five columns");
        assert_eq!(bytes[2], b':');
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(i, b)| i == 2 || b.is_ascii_digit())
        );
    }

    #[test]
    fn a_header_carries_actions_and_a_right_aligned_stamp() {
        let at = SystemTime::now();
        let (line, buttons) = header_with_actions(vec![Span::raw("◆ Agent")], false, at, 50, true);
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(rendered.starts_with("◆ Agent"));
        assert!(rendered.contains("[Pin]"));
        assert!(rendered.contains("[Fork]"));
        assert!(rendered.ends_with(&clock_label(at)));
        assert_eq!(rendered.chars().count(), 50 - TIME_RIGHT_PAD);
        assert!(buttons.is_some());
    }

    #[test]
    fn a_pinned_header_shows_unpin() {
        let (line, _) = header_with_actions(
            vec![Span::raw("◆ Agent")],
            true,
            SystemTime::now(),
            50,
            true,
        );
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(rendered.contains("[Unpin]"));
        assert!(!rendered.contains("[Pin]"));
    }

    #[test]
    fn a_narrow_header_drops_the_stamp_and_the_actions() {
        let (line, buttons) = header_with_actions(
            vec![Span::raw("◆ Agent")],
            false,
            SystemTime::now(),
            8,
            true,
        );
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(rendered, "◆ Agent");
        assert!(buttons.is_none());
    }

    #[test]
    fn elide_path_keeps_the_longest_trailing_tail() {
        assert_eq!(elide_path("acme/api-gateway", 20), "acme/api-gateway");
        assert_eq!(elide_path("acme/api-gateway", 14), "…/api-gateway");
        assert_eq!(elide_path("one/two/three/four", 16), "…/two/three/four");
        assert_eq!(elide_path("one/two/three/four", 15), "…/three/four");
        assert!(elide_path("verylongname", 6).starts_with('…'));
    }
}
