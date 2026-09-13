use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};

use super::{
    ActionHit, CardAction, CardHit, ColumnFocus, ConfirmChoice, LIST_LIMIT, PREVIEW_PAGE,
    RailLayoutMode, SKELETON_CARDS, Scope, SessionRail, Step, card_description,
};
use crate::tui::message_block::MessageBlockRole;
use crate::tui::pane_shared::{boxed_row, short_id};
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};
use cockpit_proto::SessionSummary;

impl SessionRail {
    /// Split the chat body into `(persistent_rail, remaining_chat)`. The
    /// overlay-sized focused rail is drawn later over `remaining_chat`.
    pub fn split_body(&self, body: Rect, frame_width: u16) -> (Option<Rect>, Rect) {
        let mode = RailLayoutMode::from_width(frame_width);
        let persistent = mode.persistent_width(self.focused);
        if persistent == 0 || persistent >= body.width {
            return (None, body);
        }
        let rail = Rect {
            x: body.x,
            y: body.y,
            width: persistent,
            height: body.height,
        };
        let chat = Rect {
            x: body.x.saturating_add(persistent),
            y: body.y,
            width: body.width.saturating_sub(persistent),
            height: body.height,
        };
        (Some(rail), chat)
    }

    pub fn overlay_rail_rect(&self, body: Rect, frame_width: u16) -> Option<Rect> {
        let mode = RailLayoutMode::from_width(frame_width);
        if mode.shows_persistent_cards() || !self.focused {
            return None;
        }
        let width = mode.focused_overlay_width(frame_width).min(body.width);
        Some(Rect {
            x: body.x,
            y: body.y,
            width,
            height: body.height,
        })
    }

    pub(crate) fn render(
        &mut self,
        frame: &mut Frame,
        persistent: Option<Rect>,
        overlay: Option<Rect>,
        extra: Option<&mut crate::tui::button::ButtonRegistry>,
        frame_width: u16,
    ) {
        self.last_frame_width = frame_width;
        self.card_hits.clear();
        self.action_hits.clear();
        self.list_area = None;
        self.preview_area = None;
        self.search_area = None;
        self.compact_area = None;
        self.rail_area = None;
        self.confirm_buttons.begin_frame(self.pointer_capture, 1);

        let mode = RailLayoutMode::from_width(frame_width);
        if let Some(area) = overlay {
            self.render_wide(frame, area, extra);
        } else if let Some(area) = persistent {
            match mode {
                RailLayoutMode::Wide { .. } => self.render_wide(frame, area, extra),
                RailLayoutMode::Compact => self.render_compact_affordance(frame, area),
                RailLayoutMode::HiddenUntilFocused => {}
            }
        }
    }

    fn render_compact_affordance(&mut self, frame: &mut Frame, area: Rect) {
        self.compact_area = Some(area);
        self.rail_area = Some(area);
        let focused = self.focused;
        let style = if focused {
            Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX))
        } else {
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX))
        };
        let label = if self.search.is_empty() { "S" } else { "/" };
        let block = Block::default()
            .borders(Borders::RIGHT)
            .border_style(style)
            .title(label);
        frame.render_widget(block, area);
    }

    fn render_wide(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        extra: Option<&mut crate::tui::button::ButtonRegistry>,
    ) {
        self.rail_area = Some(area);
        let focused = self.focused;
        let border = if focused {
            Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX))
        } else {
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX))
        };
        let title = self.title();
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border)
            .title(title);
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let [search, body, help] = inner.layout(&Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ]));
        self.search_area = Some(search);
        self.render_search(frame, search);
        self.render_cards(frame, body);
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(Paragraph::new(self.help_line()).style(muted), help);

        if let Step::Confirm { .. } = &self.step {
            self.render_confirm(frame, inner, extra);
        } else {
            self.confirm_buttons.end_frame();
        }
    }

    fn render_search(&self, frame: &mut Frame, area: Rect) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let focused = self.column_focus == ColumnFocus::Search && self.focused;
        let prefix = if focused { "/" } else { " " };
        let query = if self.search.is_empty() && !focused {
            "search"
        } else {
            &self.search
        };
        let style = if focused {
            Style::default().fg(Color::White)
        } else {
            muted
        };
        let disabled = self.loading && self.current().cards.is_empty();
        let line = if disabled {
            Line::from(Span::styled(" search disabled", muted))
        } else {
            Line::from(vec![
                Span::styled(prefix.to_string(), style),
                Span::styled(query.to_string(), style),
            ])
        };
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_cards(&mut self, frame: &mut Frame, body: Rect) {
        self.list_area = Some(body);
        if self.loading && self.current().cards.is_empty() {
            self.render_skeleton(frame, body);
            return;
        }
        if let Some(error) = &self.error
            && self.current().cards.is_empty()
        {
            let lines = vec![
                Line::from(Span::styled(error.clone(), Style::default().fg(Color::Red))),
                Line::from(Span::styled(
                    "press r to retry",
                    Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
                )),
            ];
            frame.render_widget(Paragraph::new(lines), body);
            return;
        }
        let cards = self.filtered_cards();
        if cards.is_empty() {
            frame.render_widget(Paragraph::new(self.empty_line()), body);
            return;
        }

        let width = body.width as usize;
        let mut lines: Vec<Line<'static>> = Vec::new();
        if self.stale {
            lines.push(Line::from(Span::styled(
                "stale — reconnecting".to_string(),
                Style::default().fg(Color::Yellow),
            )));
        }
        let selected_id = self.selected_id();
        let show_project = matches!(self.scope, Scope::All) || self.levels.len() > 1;
        let mut selected_span = None;
        let mut spans: Vec<(usize, usize, usize)> = Vec::new();
        for (index, (summary, tier)) in cards.iter().enumerate() {
            let start = lines.len();
            let selected = Some(summary.session_id) == selected_id;
            let card = card_lines(
                summary,
                *tier,
                selected,
                show_project,
                width,
                self.use_emojis,
            );
            let end = start + card.len();
            if selected {
                selected_span = Some((start, end));
            }
            spans.push((index, start, end));
            lines.extend(card);
        }
        if let Some(preview) = &self.preview {
            let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
            let preview_line = if let Some(error) = &preview.error {
                Line::from(Span::styled(
                    format!("preview unavailable: {error}"),
                    Style::default().fg(Color::Red),
                ))
            } else if preview.loading && preview.messages.is_empty() {
                Line::from(Span::styled("preview loading…".to_string(), muted))
            } else if preview.messages.is_empty() {
                Line::from(Span::styled("no text messages".to_string(), muted))
            } else {
                let last = preview.messages.last();
                let role = last.map(|message| match message.role {
                    cockpit_proto::MessageRole::User => MessageBlockRole {
                        label: crate::tui::history::user_display_label().to_string(),
                        style: Style::default().fg(crate::tui::history::user_message_color()),
                    },
                    cockpit_proto::MessageRole::Agent => MessageBlockRole {
                        label: "agent".to_string(),
                        style: muted,
                    },
                });
                let label = role
                    .as_ref()
                    .map(|role| role.label.as_str())
                    .unwrap_or("preview");
                let body = last.map(|m| m.text.as_str()).unwrap_or("");
                Line::from(Span::styled(
                    format!("{label} · {} msgs · {body}", preview.messages.len()),
                    muted,
                ))
            };
            self.last_preview_rows = 1;
            self.last_preview_height = 1;
            lines.push(preview_line);
        }
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        let mut scroll = self
            .current()
            .row_offset
            .min(self.last_content_rows.saturating_sub(self.last_body_height));
        if let Some((start, end)) = selected_span {
            scroll = crate::tui::pane_shared::clamp_scroll_to_visible_span(
                scroll,
                self.last_body_height,
                self.last_content_rows,
                start,
                end,
            );
        }
        if let Some(level) = self.levels.last_mut() {
            level.row_offset = scroll;
        }
        self.record_card_hits(body, scroll, &spans, &cards);
        frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), body);
        if self.last_content_rows > self.last_body_height && body.width > 1 && body.height > 0 {
            let scrollbar_area = Rect::new(body.right().saturating_sub(1), body.y, 1, body.height);
            let mut state = ScrollbarState::new(self.last_content_rows)
                .position(scroll)
                .viewport_content_length(self.last_body_height);
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_style(Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)))
                .thumb_style(Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX)));
            frame.render_stateful_widget(scrollbar, scrollbar_area, &mut state);
        }
        let _ = (LIST_LIMIT, PREVIEW_PAGE);
    }

    fn record_card_hits(
        &mut self,
        body: Rect,
        scroll: usize,
        spans: &[(usize, usize, usize)],
        cards: &[(SessionSummary, super::Tier)],
    ) {
        let mut hits = Vec::new();
        let mut actions = Vec::new();
        let selected_id = self.selected_id();
        for (index, start, end) in spans.iter().copied() {
            let visible_start = start.max(scroll);
            let visible_end = end.min(scroll + body.height as usize);
            if visible_start >= visible_end {
                continue;
            }
            let rect = Rect {
                x: body.x,
                y: body.y + (visible_start - scroll) as u16,
                width: body.width,
                height: (visible_end - visible_start) as u16,
            };
            hits.push(CardHit { index, rect });
            let selected = Some(cards[index].0.session_id) == selected_id;
            // Action labels are painted only on the selected card, on the
            // second-to-last content line (above the bottom border). Hits
            // exist only on that painted row.
            let action_line = end.saturating_sub(2);
            if selected
                && rect.width >= 12
                && action_line >= visible_start
                && action_line < visible_end
            {
                let action_y = body.y + (action_line - scroll) as u16;
                let mut x = rect.x.saturating_add(2);
                for (label, action) in action_labels(&cards[index].0) {
                    let width = (label.len() as u16).saturating_add(2).min(rect.width);
                    if x.saturating_add(width) > rect.right() {
                        break;
                    }
                    actions.push(ActionHit {
                        index,
                        action,
                        rect: Rect {
                            x,
                            y: action_y,
                            width,
                            height: 1,
                        },
                    });
                    x = x.saturating_add(width).saturating_add(1);
                }
            }
        }
        self.card_hits = hits;
        self.action_hits = actions;
    }

    fn render_skeleton(&self, frame: &mut Frame, body: Rect) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let inner_w = (body.width as usize).saturating_sub(2).max(4);
        let mut lines = Vec::new();
        for _ in 0..SKELETON_CARDS {
            lines.push(Line::from(Span::styled(
                format!("╭{}╮", "─".repeat(inner_w)),
                muted,
            )));
            lines.push(Line::from(Span::styled(
                format!("│{}│", " ".repeat(inner_w)),
                muted,
            )));
            lines.push(Line::from(Span::styled(
                format!("│{}│", " ".repeat(inner_w)),
                muted,
            )));
            lines.push(Line::from(Span::styled(
                format!("╰{}╯", "─".repeat(inner_w)),
                muted,
            )));
        }
        frame.render_widget(Paragraph::new(lines), body);
    }

    fn empty_line(&self) -> Line<'static> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let scope = match self.scope {
            Scope::Project => "this project",
            Scope::All => "all projects",
        };
        let archived = if self.show_archived {
            "archived"
        } else {
            "active"
        };
        let text = if !self.search.is_empty() {
            format!(
                "no {archived} sessions in {scope} matching “{}”",
                self.search
            )
        } else {
            format!("no {archived} sessions in {scope}")
        };
        Line::from(Span::styled(text, muted))
    }

    fn title(&self) -> Line<'static> {
        let scope_label = match self.scope {
            Scope::Project => "project",
            Scope::All => "all",
        };
        let mut spans = vec![
            Span::raw(" sessions "),
            Span::styled(
                format!("{scope_label} "),
                Style::default().fg(Color::Yellow),
            ),
        ];
        if self.show_archived {
            spans.push(Span::styled(
                "archived ",
                Style::default().fg(Color::Magenta),
            ));
        }
        if self.stale {
            spans.push(Span::styled("stale ", Style::default().fg(Color::Yellow)));
        }
        Line::from(spans)
    }

    fn help_line(&self) -> Line<'static> {
        if self.daemon_connected {
            Line::from("↑/↓  ⏎ open  / search  f ★  a archived  Esc composer")
        } else {
            Line::from("browse only — no daemon")
        }
    }

    fn render_confirm(
        &mut self,
        frame: &mut Frame,
        body: Rect,
        extra: Option<&mut crate::tui::button::ButtonRegistry>,
    ) {
        let Step::Confirm {
            label,
            descendants,
            live,
            choice,
            ..
        } = &self.step
        else {
            return;
        };
        let h = 7u16.min(body.height);
        let rect = Rect {
            x: body.x,
            y: body.y + body.height.saturating_sub(h),
            width: body.width,
            height: h,
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX)))
            .title(" archive / delete ");
        let inner = block.inner(rect);
        frame.render_widget(Clear, rect);
        frame.render_widget(block, rect);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(label.clone()));
        let cascade = if *descendants > 0 {
            format!("Cascades to {descendants} fork(s) and their descendants.")
        } else {
            "No forks affected.".to_string()
        };
        lines.push(Line::from(Span::styled(cascade, muted)));
        if *live {
            lines.push(Line::from(Span::styled(
                "Session is live — it will be interrupted first.".to_string(),
                Style::default().fg(Color::Yellow),
            )));
        }
        let button_y = inner.y.saturating_add(lines.len() as u16);
        let choice = *choice;
        frame.render_widget(Paragraph::new(lines), inner);
        paint_confirm_buttons_into(&mut self.confirm_buttons, frame, inner, button_y, choice);
        self.confirm_buttons.end_frame();
        if let Some(extra) = extra {
            paint_confirm_buttons_into(extra, frame, inner, button_y, choice);
        }
    }
}

fn action_labels(summary: &SessionSummary) -> Vec<(&'static str, CardAction)> {
    let mut out = vec![
        ("Open", CardAction::Open),
        ("Prev", CardAction::Preview),
        (
            if summary.favorite { "Un★" } else { "★" },
            CardAction::Favorite,
        ),
    ];
    if summary.archived_at_unix_ms.is_some() {
        out.push(("Unarch", CardAction::Unarchive));
    } else {
        out.push(("Arch", CardAction::Archive));
    }
    out.push(("Del", CardAction::Delete));
    out
}

fn paint_confirm_buttons_into(
    buttons: &mut crate::tui::button::ButtonRegistry,
    frame: &mut Frame,
    inner: Rect,
    y: u16,
    choice: ConfirmChoice,
) {
    if y >= inner.bottom() {
        return;
    }
    let mut x = inner.x;
    for (label, this) in [
        ("Archive", ConfirmChoice::Archive),
        ("Delete", ConfirmChoice::Delete),
        ("Cancel", ConfirmChoice::Cancel),
    ] {
        let kind = if this == ConfirmChoice::Delete {
            crate::tui::button::ButtonKind::Destructive
        } else {
            crate::tui::button::ButtonKind::Default
        };
        let spec = crate::tui::button::ButtonSpec::new(
            match this {
                ConfirmChoice::Archive => crate::tui::button::ButtonId::SessionsConfirmArchive,
                ConfirmChoice::Delete => crate::tui::button::ButtonId::SessionsConfirmDelete,
                ConfirmChoice::Cancel => crate::tui::button::ButtonId::SessionsConfirmCancel,
            },
            label,
            match this {
                ConfirmChoice::Archive => {
                    crate::tui::button::ButtonDispatch::SessionsConfirmArchive
                }
                ConfirmChoice::Delete => crate::tui::button::ButtonDispatch::SessionsConfirmDelete,
                ConfirmChoice::Cancel => crate::tui::button::ButtonDispatch::SessionsConfirmCancel,
            },
        )
        .focused(this == choice)
        .kind(kind);
        let max_width = inner.right().saturating_sub(x);
        if let Some(rect) = buttons.paint(frame, x, y, max_width, spec) {
            x = rect.right().saturating_add(1);
        }
    }
}

pub fn card_lines(
    s: &SessionSummary,
    tier: super::Tier,
    selected: bool,
    show_project: bool,
    width: usize,
    use_emojis: bool,
) -> Vec<Line<'static>> {
    let inner_w = width.saturating_sub(2).max(8);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let border_style = if selected {
        Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX))
    } else {
        muted
    };

    let mut out: Vec<Line<'static>> = Vec::new();
    out.push(Line::from(Span::styled(
        format!("╭{}╮", "─".repeat(inner_w)),
        border_style,
    )));

    let star = if s.favorite { "★ " } else { "" };
    let desc = format!("{star}{}", card_description(s));
    let status = Span::styled(tier.label_for(s), Style::default().fg(tier.color()));
    out.push(boxed_row(
        vec![
            Span::styled(
                desc,
                if selected {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                },
            ),
            Span::raw("  "),
            status,
        ],
        inner_w,
        border_style,
    ));

    let mut meta: Vec<Span<'static>> = vec![Span::styled(
        fmt_time_with_relative(s.last_active_at_unix_ms),
        muted,
    )];
    if show_project {
        meta.push(Span::raw("  "));
        meta.push(Span::styled(
            format!("[{}]", project_label(&s.project_root)),
            muted,
        ));
    }
    if s.archived_at_unix_ms.is_some() {
        meta.push(Span::raw("  "));
        meta.push(Span::styled(
            "archived".to_string(),
            Style::default().fg(Color::Magenta),
        ));
    }
    if s.pin_count > 0 {
        meta.push(Span::raw("  "));
        let pin = if use_emojis {
            format!("📌 {}", s.pin_count)
        } else {
            format!("pin {}", s.pin_count)
        };
        meta.push(Span::styled(pin, Style::default().fg(Color::Yellow)));
    }
    if s.assistant_inbox_unread > 0 {
        meta.push(Span::raw("  "));
        let source = s
            .assistant_inbox_latest_source_session_id
            .map(|id| short_id(&id.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        meta.push(Span::styled(
            format!("inbox {} ← {source}", s.assistant_inbox_unread),
            Style::default().fg(Color::Cyan),
        ));
    }
    if s.fork_count > 0 {
        meta.push(Span::raw("  "));
        meta.push(Span::styled(
            format!("{} forks", s.fork_count),
            Style::default().fg(Color::Cyan),
        ));
    }
    if s.lineage_window_count > 1 {
        meta.push(Span::raw("  "));
        meta.push(Span::styled(
            format!("{} windows", s.lineage_window_count),
            Style::default().fg(Color::Cyan),
        ));
    }
    out.push(boxed_row(meta, inner_w, border_style));

    if selected {
        let actions = action_labels(s)
            .into_iter()
            .map(|(label, _)| format!("[{label}]"))
            .collect::<Vec<_>>()
            .join(" ");
        out.push(boxed_row(
            vec![Span::styled(
                actions,
                Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX)),
            )],
            inner_w,
            border_style,
        ));
    }

    out.push(Line::from(Span::styled(
        format!("╰{}╯", "─".repeat(inner_w)),
        border_style,
    )));
    out
}

fn fmt_time(epoch_unix_ms: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(epoch_unix_ms).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => "—".to_string(),
    }
}

fn fmt_time_with_relative(epoch_unix_ms: i64) -> String {
    let elapsed_ms = chrono::Utc::now()
        .timestamp_millis()
        .saturating_sub(epoch_unix_ms);
    format!(
        "{} · {}",
        relative_time(elapsed_ms / 1_000),
        fmt_time(epoch_unix_ms)
    )
}

fn relative_time(elapsed_secs: i64) -> String {
    fn unit(n: i64, singular: &str) -> String {
        if n == 1 {
            format!("1 {singular} ago")
        } else {
            format!("{n} {singular}s ago")
        }
    }
    if elapsed_secs < 60 {
        return "just now".to_string();
    }
    let minutes = elapsed_secs / 60;
    if minutes < 60 {
        return unit(minutes, "minute");
    }
    let hours = elapsed_secs / 3_600;
    if hours < 48 {
        return unit(hours, "hour");
    }
    let days = elapsed_secs / 86_400;
    if days < 30 {
        return unit(days, "day");
    }
    if days < 365 {
        return unit(days / 30, "month");
    }
    unit(days / 365, "year")
}

fn project_label(root: &str) -> String {
    std::path::Path::new(root)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.to_string())
}
