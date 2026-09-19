//! Sticky previous-user-message header for the chat viewport.
//!
//! The header is carved out of the chat pane *before* `render_history`
//! so `chat_visible_lines`, the six scroll clamps, `chat_row_meta`,
//! live buttons, and the selection grid all see the remaining height.
//! Height is 0 or [`STICKY_USER_HEADER_HEIGHT`] per frame. A stale layout
//! decision is settled within the same frame after geometry refresh.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::render::chat_visible_top;
use super::{App, HistoryEntryId, MouseGestureInvalidation};
use crate::tui::chrome::fill_bg;
use crate::tui::history::HistoryEntry;
use crate::tui::pins_overlay::preview_text;
use crate::tui::theme::{
    BRASS, BRASS_INDEX, INK, INK_INDEX, SURFACE, SURFACE_INDEX, TEAL, TEAL_INDEX, resolve_color,
};

/// The always-on sticky turn header occupies exactly one row.
pub(super) const STICKY_USER_HEADER_HEIGHT: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StickyUserTarget {
    pub history_index: usize,
    pub id: HistoryEntryId,
}

impl App {
    /// Render the chat pane, carving a sticky header rect out of the top
    /// when the previous user message has scrolled out of view.
    pub(super) fn render_chat_history_pane(&mut self, frame: &mut Frame, pane: Rect) {
        let mut target = self.sticky_user_target_for_pane(pane);
        self.apply_sticky_visibility(pane, target.is_some());
        self.render_history(frame, history_rect(pane, target.is_some()));

        // The first render after startup, a resize, or a history mutation refreshes
        // wrapping and total-row state. Settle once against that current geometry so
        // an idle event loop never leaves a previous-frame header decision onscreen.
        let refreshed = self.sticky_user_target_for_pane(pane);
        if refreshed.is_some() != target.is_some() {
            target = refreshed;
            self.apply_sticky_visibility(pane, target.is_some());
            self.chat_find_lines_dirty = true;
            self.render_history(frame, history_rect(pane, target.is_some()));
            target = self.sticky_user_target_for_pane(pane);
        } else {
            // Visibility may be unchanged while front trimming or rewrapping selects
            // a different last-hidden user message.
            target = refreshed;
        }

        self.sticky_header_target = target.map(|target| target.id);
        if let Some(header) = self.sticky_header_area {
            self.render_sticky_user_header(frame, header);
        }
    }

    fn sticky_user_target_for_pane(&self, pane: Rect) -> Option<StickyUserTarget> {
        if pane.height <= STICKY_USER_HEADER_HEIGHT {
            return None;
        }
        // The message must leave the existing viewport before it becomes sticky;
        // carving the header must not itself turn a visible message into a target.
        self.sticky_user_target(pane.height as usize)
    }

    fn apply_sticky_visibility(&mut self, pane: Rect, visible: bool) {
        let was_visible = self.sticky_header_area.is_some();
        if was_visible != visible {
            // A completed selection belongs to transcript content, not to a
            // particular viewport origin. Keep it attached to that content
            // while the sticky header carves (or restores) its row.
            // An in-progress drag must still be cancelled: its pointer
            // coordinates can no longer describe a valid gesture.
            let completed_selection = self.selection.filter(|selection| !selection.active);
            let completed_spans = completed_selection.and_then(|_| self.selection_spans.clone());
            self.invalidate_mouse_gesture(
                MouseGestureInvalidation::ViewChange,
                self.event_loop_monotonic_now,
            );
            if let Some(mut selection) = completed_selection {
                let shift = STICKY_USER_HEADER_HEIGHT;
                if visible {
                    selection.anchor.1 = selection.anchor.1.saturating_add(shift);
                    selection.focus.1 = selection.focus.1.saturating_add(shift);
                } else {
                    selection.anchor.1 = selection.anchor.1.saturating_sub(shift);
                    selection.focus.1 = selection.focus.1.saturating_sub(shift);
                }
                self.selection = Some(selection);
                self.selection_spans = completed_spans.map(|spans| {
                    spans
                        .into_iter()
                        .map(|mut span| {
                            span.row = if visible {
                                span.row.saturating_add(shift)
                            } else {
                                span.row.saturating_sub(shift)
                            };
                            span
                        })
                        .collect()
                });
            }
            self.chat_scroll_anchor = None;
        }
        self.sticky_header_area = visible.then(|| Rect {
            x: pane.x,
            y: pane.y,
            width: pane.width,
            height: STICKY_USER_HEADER_HEIGHT,
        });
        if !visible {
            self.sticky_header_target = None;
        }
    }

    /// Last `HistoryEntry::User` whose last display row sits strictly
    /// above the history viewport top. `None` when that message is
    /// already visible, when the view is at the tail with nothing above,
    /// or when the in-scroll banner still occupies the top.
    pub(super) fn sticky_user_target(&self, visible_lines: usize) -> Option<StickyUserTarget> {
        let visible = visible_lines.max(1);
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
            let rendered_rows = self.cached_history_entry_rows_at(idx);
            if rendered_rows == 0 {
                continue;
            }
            let last_row =
                banner + prefix + geometry.entry_start_row(idx) + rendered_rows.saturating_sub(1);
            if last_row < visible_top {
                let id = self.history.id_at(idx)?;
                found = Some(StickyUserTarget {
                    history_index: idx,
                    id,
                });
            }
        }
        found
    }

    fn render_sticky_user_header(&self, frame: &mut Frame, area: Rect) {
        let raw = self
            .sticky_header_target
            .and_then(|id| self.history_position_for_id(id))
            .and_then(|idx| self.history.get(idx))
            .and_then(user_raw_text)
            .unwrap_or("");
        let surface = resolve_color(SURFACE, SURFACE_INDEX);
        fill_bg(frame, area, surface);
        let accent = if self.active_subagent_view().is_some() {
            resolve_color(TEAL, TEAL_INDEX)
        } else {
            resolve_color(BRASS, BRASS_INDEX)
        };
        let condensed = preview_text(
            &raw.replace('\n', " "),
            usize::from(area.width).saturating_sub(2),
        );
        // The sticky accent is the bare `▌` bar (no trailing space — the
        // user-message body keeps `▌ `), followed directly by the condensed
        // INK-bold preview, matching the reference sticky row.
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("▌", Style::default().fg(accent).bg(surface)),
                Span::styled(
                    condensed,
                    Style::default()
                        .fg(resolve_color(INK, INK_INDEX))
                        .bg(surface)
                        .add_modifier(Modifier::BOLD),
                ),
            ])),
            area,
        );
    }

    pub(super) fn jump_to_sticky_user_header(&mut self) {
        let Some(id) = self.sticky_header_target else {
            return;
        };
        let Some(idx) = self.history_position_for_id(id) else {
            return;
        };
        let rel = self.msg_abs_line.get(&idx).copied().unwrap_or_else(|| {
            self.history_prefix_rows_len() + self.chat_geometry.entry_start_row(idx)
        });
        let abs = self.chat_banner_lines + rel;
        self.scroll_abs_line_into_view(abs);
        if self.chat_scroll_offset == 0 {
            let visible = self.chat_visible_lines.max(1);
            let total = self.chat_total_lines;
            if total > visible {
                self.set_chat_scroll_offset_from_interaction(total - visible);
            }
        }
    }

    pub(super) fn mouse_in_sticky_header(&self, col: u16, row: u16) -> bool {
        self.sticky_header_area
            .is_some_and(|area| super::mouse::point_in(area, col, row))
    }
}

fn history_rect(pane: Rect, visible: bool) -> Rect {
    if !visible {
        return pane;
    }
    Rect {
        x: pane.x,
        y: pane.y.saturating_add(STICKY_USER_HEADER_HEIGHT),
        width: pane.width,
        height: pane.height.saturating_sub(STICKY_USER_HEADER_HEIGHT),
    }
}

fn user_raw_text(entry: &HistoryEntry) -> Option<&str> {
    match entry {
        HistoryEntry::User { text, .. } => Some(text.as_str()),
        _ => None,
    }
}
