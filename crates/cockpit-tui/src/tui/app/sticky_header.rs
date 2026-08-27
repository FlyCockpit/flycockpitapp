//! Sticky previous-user-message header for the chat viewport.
//!
//! The header is carved out of the chat pane *before* `render_history`
//! so `chat_visible_lines`, the six scroll clamps, `chat_row_meta`,
//! live buttons, and the selection grid all see the remaining height.
//! Height is 0 or [`STICKY_USER_HEADER_HEIGHT`] per frame, derived from
//! the uncarved pane size so a mid-frame flip cannot oscillate the
//! scroll-anchor round-trip.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::render::chat_visible_top;
use super::{App, MouseGestureInvalidation};
use crate::tui::history::HistoryEntry;
use crate::tui::pins_overlay::{PIN_YELLOW, preview_text_rows};
use crate::tui::theme::{MUTED_COLOR_INDEX, TRANSCRIPT_HOVER_BG};

/// Two content lines. Stable: never 1, never a mid-frame change.
pub(super) const STICKY_USER_HEADER_HEIGHT: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StickyUserTarget {
    pub history_index: usize,
}

impl App {
    /// Render the chat pane, carving a sticky header rect out of the top
    /// when the previous user message has scrolled out of view.
    pub(super) fn render_chat_history_pane(&mut self, frame: &mut Frame, pane: Rect) {
        let header_h = self.sticky_user_header_height(pane);
        let was_visible = self.sticky_header_area.is_some();
        let now_visible = header_h > 0;
        if was_visible != now_visible {
            self.invalidate_mouse_gesture(
                MouseGestureInvalidation::ViewChange,
                self.event_loop_monotonic_now,
            );
            // Keep offset-from-bottom; recapture the anchor against the
            // new (carved or full) height inside `render_history`.
            self.chat_scroll_anchor = None;
        }

        if now_visible {
            let header = Rect {
                x: pane.x,
                y: pane.y,
                width: pane.width,
                height: header_h,
            };
            let history = Rect {
                x: pane.x,
                y: pane.y.saturating_add(header_h),
                width: pane.width,
                height: pane.height.saturating_sub(header_h),
            };
            self.sticky_header_area = Some(header);
            if let Some(target) = self.sticky_user_target(pane.height as usize) {
                self.sticky_header_history_index = Some(target.history_index);
            }
            self.render_sticky_user_header(frame, header);
            self.render_history(frame, history);
        } else {
            self.sticky_header_area = None;
            self.sticky_header_history_index = None;
            self.render_history(frame, pane);
        }
    }

    /// 0 or [`STICKY_USER_HEADER_HEIGHT`], derived from the *uncarved*
    /// pane height so the decision does not depend on whether the header
    /// is currently shown.
    pub(super) fn sticky_user_header_height(&self, pane: Rect) -> u16 {
        if !self.sticky_user_message {
            return 0;
        }
        if pane.height <= STICKY_USER_HEADER_HEIGHT {
            return 0;
        }
        if self.sticky_user_target(pane.height as usize).is_none() {
            return 0;
        }
        STICKY_USER_HEADER_HEIGHT
    }

    /// Last `HistoryEntry::User` whose last display row sits strictly
    /// above the uncarved viewport top. `None` when that message is
    /// already visible, when the view is at the tail with nothing above,
    /// or when the in-scroll banner still occupies the top.
    pub(super) fn sticky_user_target(&self, uncarved_visible: usize) -> Option<StickyUserTarget> {
        let visible = uncarved_visible.max(1);
        let total = self.chat_total_lines;
        if total == 0 {
            return None;
        }
        let visible_top = chat_visible_top(total, visible, self.chat_scroll_offset);
        if self.chat_banner_lines > 0 && visible_top < self.chat_banner_lines {
            return None;
        }

        let geometry = &self.chat_geometry;
        let entry_count = geometry.entry_count().min(self.history.len());
        if entry_count == 0 {
            return None;
        }
        let prefix = self.history_prefix_rows_len();
        let banner = self.chat_banner_lines;
        let mut found = None;
        for idx in 0..entry_count {
            if !matches!(self.history.get(idx), Some(HistoryEntry::User { .. })) {
                continue;
            }
            let last_row = banner
                + prefix
                + geometry.entry_start_row(idx)
                + geometry.entry_height(idx).saturating_sub(1);
            if last_row < visible_top {
                found = Some(StickyUserTarget { history_index: idx });
            }
        }
        found
    }

    fn render_sticky_user_header(&self, frame: &mut Frame, area: Rect) {
        let raw = self
            .sticky_header_history_index
            .and_then(|idx| self.history.get(idx))
            .and_then(user_raw_text)
            .unwrap_or("");
        let label = " you ";
        let indent = "     ";
        let show_label = area.width as usize > label.len() + 1;
        let preview_width = if show_label {
            (area.width as usize).saturating_sub(label.len())
        } else {
            area.width as usize
        }
        .max(1);
        let mut rows = preview_text_rows(raw, preview_width, STICKY_USER_HEADER_HEIGHT as usize);
        rows.resize(STICKY_USER_HEADER_HEIGHT as usize, String::new());

        let bg = Style::default().bg(TRANSCRIPT_HOVER_BG);
        let label_style = Style::default()
            .fg(PIN_YELLOW)
            .bg(TRANSCRIPT_HOVER_BG)
            .add_modifier(Modifier::BOLD);
        let body_style = Style::default()
            .fg(ratatui::style::Color::Indexed(MUTED_COLOR_INDEX))
            .bg(TRANSCRIPT_HOVER_BG);

        let lines = if show_label {
            vec![
                Line::from(vec![
                    Span::styled(label, label_style),
                    Span::styled(rows[0].clone(), body_style),
                ]),
                Line::from(vec![
                    Span::styled(indent, bg),
                    Span::styled(rows[1].clone(), body_style),
                ]),
            ]
        } else {
            vec![
                Line::from(vec![Span::styled(rows[0].clone(), body_style)]),
                Line::from(vec![Span::styled(rows[1].clone(), body_style)]),
            ]
        };
        frame.render_widget(Paragraph::new(lines).style(bg), area);
    }

    pub(super) fn jump_to_sticky_user_header(&mut self) {
        let Some(idx) = self.sticky_header_history_index else {
            return;
        };
        let Some(&rel) = self.msg_abs_line.get(&idx) else {
            return;
        };
        let abs = self.chat_banner_lines + rel;
        self.scroll_abs_line_into_view(abs);
    }

    pub(super) fn mouse_in_sticky_header(&self, col: u16, row: u16) -> bool {
        self.sticky_header_area
            .is_some_and(|area| super::mouse::point_in(area, col, row))
    }
}

fn user_raw_text(entry: &HistoryEntry) -> Option<&str> {
    match entry {
        HistoryEntry::User { text, .. } => Some(text.as_str()),
        _ => None,
    }
}
