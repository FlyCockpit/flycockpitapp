use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::{
    ActionHit, CardAction, CardHit, ConfirmChoice, LIST_LIMIT, PREVIEW_PAGE, RailLayoutMode,
    SKELETON_CARDS, Scope, SessionRail, Step, card_description, point_in_rect,
};
use crate::tui::chrome::{clear_cells, fill_bg, paint_chip, scrollbar};
use crate::tui::message_block::MessageBlockRole;
use crate::tui::pane_shared::short_id;
use crate::tui::theme::{
    ACCENT_BLUE_INDEX, BRASS, BRASS_INDEX, GOOD, GOOD_INDEX, HOVER_BG, HOVER_BG_INDEX, INK,
    INK_INDEX, MUTED_COLOR_INDEX, RED, RED_INDEX, SURFACE, SURFACE_INDEX, YELLOW, YELLOW_INDEX,
    resolve_color,
};
use cockpit_proto::SessionSummary;

impl SessionRail {
    /// Split the chat body into `(persistent_rail, remaining_chat)`. The
    /// overlay-sized focused rail is drawn later over `remaining_chat`.
    pub fn split_body(&self, body: Rect, frame_width: u16) -> (Option<Rect>, Rect) {
        let mode = self.layout_mode(frame_width);
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
        let mode = self.layout_mode(frame_width);
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
        self.begin_frame();

        let mode = self.layout_mode(frame_width);
        if matches!(mode, RailLayoutMode::HiddenByPreference) {
            self.render_show_toggle(frame);
            return;
        }
        if let Some(area) = overlay {
            self.render_wide(frame, area, extra);
        } else if let Some(area) = persistent {
            match mode {
                RailLayoutMode::Wide { .. } => self.render_wide(frame, area, extra),
                RailLayoutMode::Compact => self.render_compact_affordance(frame, area),
                RailLayoutMode::HiddenByPreference | RailLayoutMode::HiddenUntilFocused => {}
            }
        }
    }

    fn render_show_toggle(&mut self, frame: &mut Frame) {
        let area = Rect::new(frame.area().x, frame.area().y, 6.min(frame.area().width), 1);
        self.rail_area = Some(area);
        self.toggle_area = Some(area);
        paint_chip(
            frame,
            area,
            "[Show]",
            Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX)),
            self.pointer_position
                .is_some_and(|(x, y)| point_in_rect(area, x, y)),
        );
    }

    fn render_compact_affordance(&mut self, frame: &mut Frame, area: Rect) {
        self.compact_area = Some(area);
        self.rail_area = Some(area);
        let focused = self.focused;
        let style = if focused {
            Style::default().fg(crate::tui::theme::indexed_color(ACCENT_BLUE_INDEX))
        } else {
            Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX))
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
        let surface = resolve_color(SURFACE, SURFACE_INDEX);
        fill_bg(frame, area, surface);
        frame.render_widget(Block::default().style(Style::default().bg(surface)), area);
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        if inner.width == 0 || inner.height == 0 {
            return;
        }
        let [header, _, new_session, _, label, body, legend] = inner.layout(&Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
        ]));

        let toggle_width = 6.min(header.width);
        let title_area = Rect {
            width: header.width.saturating_sub(toggle_width + 1),
            ..header
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("◆ ", Style::default().fg(resolve_color(BRASS, BRASS_INDEX))),
                Span::styled(
                    "Cockpit",
                    Style::default()
                        .fg(resolve_color(INK, INK_INDEX))
                        .add_modifier(Modifier::BOLD),
                ),
            ])),
            title_area,
        );
        let toggle = Rect::new(
            header.right().saturating_sub(toggle_width),
            header.y,
            toggle_width,
            1,
        );
        self.toggle_area = Some(toggle);
        paint_chip(
            frame,
            toggle,
            "[Hide]",
            Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX)),
            self.pointer_position
                .is_some_and(|(x, y)| point_in_rect(toggle, x, y)),
        );
        let new_width = 15.min(new_session.width);
        let new_area = Rect::new(new_session.x, new_session.y, new_width, 1);
        self.new_session_area = Some(new_area);
        paint_chip(
            frame,
            new_area,
            " + New session ",
            Style::default().fg(resolve_color(BRASS, BRASS_INDEX)),
            self.pointer_position
                .is_some_and(|(x, y)| point_in_rect(new_area, x, y)),
        );
        let label_text = if self.search.is_empty() {
            "SESSIONS".to_string()
        } else {
            format!("SESSIONS /{}", self.search)
        };
        self.search_area = Some(label);
        frame.render_widget(
            Paragraph::new(Span::styled(
                label_text,
                Style::default()
                    .fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX))
                    .add_modifier(Modifier::BOLD),
            )),
            label,
        );
        self.render_cards(frame, body);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    "● ",
                    Style::default().fg(resolve_color(YELLOW, YELLOW_INDEX)),
                ),
                Span::styled(
                    "working  ",
                    Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX)),
                ),
                Span::styled("● ", Style::default().fg(resolve_color(RED, RED_INDEX))),
                Span::styled(
                    "waiting  ",
                    Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX)),
                ),
                Span::styled("● ", Style::default().fg(resolve_color(GOOD, GOOD_INDEX))),
                Span::styled(
                    "done",
                    Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX)),
                ),
            ])),
            legend,
        );

        if let Step::Confirm { .. } = &self.step {
            self.render_confirm(frame, inner, extra);
        } else {
            self.confirm_buttons.end_frame();
        }
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
                    Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX)),
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
            spans.push((index, start, end));
            lines.extend(card);
        }
        if let Some(preview) = &self.preview {
            let muted = Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX));
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
        let stale_rows = if self.stale { 1 } else { 0 };
        self.last_session_view = (self.last_body_height.saturating_sub(stale_rows) / 2).max(1);
        let card_count = cards.len();
        let max_session_scroll = card_count.saturating_sub(self.last_session_view);
        if let Some(level) = self.levels.last_mut() {
            level.session_scroll = level.session_scroll.min(max_session_scroll);
        }
        let scroll = spans
            .get(self.current().session_scroll)
            .map(|(_, start, _)| *start)
            .unwrap_or(stale_rows);
        let session_overflowing = card_count > self.last_session_view;
        let overflowing = session_overflowing || self.last_content_rows > self.last_body_height;
        let content_body = if overflowing && body.width > 1 {
            Rect {
                width: body.width - 1,
                ..body
            }
        } else {
            body
        };
        self.record_card_hits(content_body, scroll, &spans);
        frame.render_widget(
            Paragraph::new(lines).scroll((scroll as u16, 0)),
            content_body,
        );
        if session_overflowing && body.width > 1 && body.height > 0 {
            scrollbar(
                frame,
                body,
                card_count,
                self.last_session_view,
                self.current().session_scroll,
            );
        }
        self.paint_hover_actions(frame, content_body, scroll, &spans, &cards);
        let _ = (LIST_LIMIT, PREVIEW_PAGE);
    }

    fn record_card_hits(&mut self, body: Rect, scroll: usize, spans: &[(usize, usize, usize)]) {
        let mut hits = Vec::new();
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
        }
        self.card_hits = hits;
        self.action_hits.clear();
    }

    /// excoc hover replacement: clear the datetime cells and right-align the
    /// three pointer-only actions. Open/preview/forks/windows remain keyboard
    /// operations and are intentionally absent from this row.
    fn paint_hover_actions(
        &mut self,
        frame: &mut Frame,
        body: Rect,
        scroll: usize,
        spans: &[(usize, usize, usize)],
        cards: &[(SessionSummary, super::Tier)],
    ) {
        let Some(index) = self.hovered_card else {
            return;
        };
        let Some((_, start, end)) = spans.iter().copied().find(|(i, _, _)| *i == index) else {
            return;
        };
        let action_line = start + 1;
        if action_line < scroll
            || action_line >= scroll + body.height as usize
            || action_line >= end
        {
            return;
        }
        let y = body.y + (action_line - scroll) as u16;
        let selected = Some(cards[index].0.session_id) == self.selected_id();
        let background = if selected {
            resolve_color(HOVER_BG, HOVER_BG_INDEX)
        } else {
            resolve_color(SURFACE, SURFACE_INDEX)
        };
        let line = Rect::new(body.x, y, body.width, 1);
        clear_cells(frame, line, background);
        let labels = [
            (
                if cards[index].0.favorite {
                    "[Unpin]"
                } else {
                    "[Pin]"
                },
                CardAction::Favorite,
            ),
            ("[Archive]", CardAction::Archive),
            ("[×]", CardAction::Delete),
        ];
        let total = labels
            .iter()
            .map(|(label, _)| label.chars().count() as u16)
            .sum::<u16>()
            + 2;
        if total + 1 > line.width {
            return;
        }
        let mut x = line.right().saturating_sub(total + 1);
        for (position, (label, action)) in labels.into_iter().enumerate() {
            let width = label.chars().count() as u16;
            let rect = Rect::new(x, y, width, 1);
            let base = match action {
                CardAction::Favorite if cards[index].0.favorite => {
                    Style::default().fg(resolve_color(YELLOW, YELLOW_INDEX))
                }
                CardAction::Delete => Style::default().fg(resolve_color(RED, RED_INDEX)),
                _ => Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX)),
            };
            let hovered = self
                .pointer_position
                .is_some_and(|(pointer_x, pointer_y)| point_in_rect(rect, pointer_x, pointer_y));
            paint_chip(frame, rect, label, base.bg(background), hovered);
            self.action_hits.push(ActionHit {
                index,
                action,
                rect,
            });
            x = x.saturating_add(width);
            if position < 2 {
                x = x.saturating_add(1);
            }
        }
    }

    fn render_skeleton(&self, frame: &mut Frame, body: Rect) {
        let muted = Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX));
        let mut lines = Vec::new();
        for _ in 0..SKELETON_CARDS {
            lines.push(Line::from(Span::styled("  ••• loading".to_string(), muted)));
            lines.push(Line::from(Span::styled("  —".to_string(), muted)));
        }
        frame.render_widget(Paragraph::new(lines), body);
    }

    fn empty_line(&self) -> Line<'static> {
        let muted = Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX));
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
        let rect = crate::tui::chrome::place_popover(
            body,
            body.width.min(46),
            body.height.min(7),
            body,
            crate::tui::chrome::PopoverSide::Center,
        );
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(crate::tui::chrome::rounded_border_type())
            .border_style(Style::default().fg(crate::tui::theme::indexed_color(ACCENT_BLUE_INDEX)))
            .title(" archive / delete ");
        let inner = block.inner(rect);
        frame.render_widget(Clear, rect);
        frame.render_widget(block, rect);

        let muted = Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX));
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
    let muted = Style::default().fg(crate::tui::theme::indexed_color(MUTED_COLOR_INDEX));
    let row_style = if selected {
        Style::default()
            .bg(resolve_color(HOVER_BG, HOVER_BG_INDEX))
            .fg(resolve_color(BRASS, BRASS_INDEX))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().bg(resolve_color(SURFACE, SURFACE_INDEX))
    };
    let prefix = if selected { "▌" } else { " " };
    let star = if s.favorite { "★ " } else { "" };
    let title_budget = width.saturating_sub(3 + text_width(star));
    let title = truncate_text(&card_description(s), title_budget);
    let used = 3 + text_width(star) + text_width(&title);
    let padding = " ".repeat(width.saturating_sub(used));
    let title_line = Line::from(vec![
        Span::styled(prefix, row_style),
        Span::styled(
            "● ",
            if selected {
                row_style
            } else {
                row_style.fg(tier.color())
            },
        ),
        Span::styled(
            star.to_string(),
            if selected {
                row_style
            } else {
                row_style.fg(resolve_color(YELLOW, YELLOW_INDEX))
            },
        ),
        Span::styled(
            title,
            if selected {
                row_style
            } else {
                row_style.fg(resolve_color(INK, INK_INDEX))
            },
        ),
        Span::styled(padding, row_style),
    ]);

    let when = fmt_time(s.last_active_at_unix_ms);
    let when_text = format!("{prefix}{when}");
    let when_padding = " ".repeat(width.saturating_sub(text_width(&when_text)));
    let when_line = Line::from(vec![
        Span::styled(prefix, row_style),
        Span::styled(
            when,
            if selected {
                row_style
            } else {
                row_style.patch(muted)
            },
        ),
        Span::styled(when_padding, row_style),
    ]);

    let mut out = vec![title_line, when_line];
    if !selected {
        return out;
    }

    // Bounded Cockpit product extension: only the selected row gets one
    // additional line for its eight-tier label and durable product metadata.
    // Every unselected row remains the reference's fixed two-line shape.
    let mut meta = tier.label_for(s);
    if show_project {
        meta.push_str(&format!("  [{}]", project_label(&s.project_root)));
    }
    if s.archived_at_unix_ms.is_some() {
        meta.push_str("  archived");
    }
    if s.pin_count > 0 {
        let pin = if use_emojis {
            format!("📌 {}", s.pin_count)
        } else {
            format!("pin {}", s.pin_count)
        };
        meta.push_str(&format!("  {pin}"));
    }
    if s.assistant_inbox_unread > 0 {
        let source = s
            .assistant_inbox_latest_source_session_id
            .map(|id| short_id(&id.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        meta.push_str(&format!("  inbox {} ← {source}", s.assistant_inbox_unread));
    }
    if s.fork_count > 0 {
        meta.push_str(&format!("  {} forks", s.fork_count));
    }
    if s.lineage_window_count > 1 {
        meta.push_str(&format!("  {} windows", s.lineage_window_count));
    }
    let meta = truncate_text(&meta, width.saturating_sub(3));
    let meta_text = format!("{prefix}{meta}");
    let padding = " ".repeat(width.saturating_sub(text_width(&meta_text)));
    out.push(Line::from(vec![
        Span::styled(prefix, row_style),
        Span::styled(meta, row_style),
        Span::styled(padding, row_style),
    ]));
    out
}

fn truncate_text(text: &str, width: usize) -> String {
    if text_width(text) <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let content_width = width.saturating_sub(1);
    let mut used = 0;
    let mut out = String::new();
    for ch in text.chars() {
        let char_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + char_width > content_width {
            break;
        }
        out.push(ch);
        used += char_width;
    }
    out.push('…');
    out
}

fn text_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn fmt_time(epoch_unix_ms: i64) -> String {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(pinned) = crate::tui::golden::pinned_datetime() {
        return pinned.to_string();
    }
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(epoch_unix_ms).single() {
        Some(dt) => dt.format("%b %-d, %H:%M").to_string(),
        None => "—".to_string(),
    }
}

fn project_label(root: &str) -> String {
    std::path::Path::new(root)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.to_string())
}
