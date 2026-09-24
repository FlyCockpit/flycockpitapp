//! Shared chrome for onboarding screens: the warm instrument-panel palette
//! helpers, the header/help/column layout, a bordered single-line field, a
//! hand-drawn scrollbar, and a small [`ListNav`] cursor so every list screen
//! scrolls and pages the same way.

use ratatui::Frame;
use ratatui::layout::{Constraint, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

pub(super) use crate::tui::chrome::{
    RADIO_OFF, RADIO_ON, check_mark, radio_mark, render_field, render_field_masked,
};
use crate::tui::theme::{BRASS, FOG, INK, NIGHT};
#[allow(dead_code)] // starred default-model rows land in #430.
pub(super) const STAR: &str = "\u{2605}"; // ★
pub(super) const SCROLL_TRACK: &str = "\u{2502}"; // │
pub(super) const SCROLL_THUMB: &str = "\u{2588}"; // █

/// Centre a readable column, matching the other onboarding steps.
pub(super) fn column(area: Rect) -> Rect {
    area.inner(Margin::new(2, 1))
        .centered(Constraint::Max(86), Constraint::Fill(1))
}

pub(super) fn render_header_colored(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    subtitle: &str,
    title_fg: Color,
) {
    let lines = vec![
        Line::from(Span::styled(
            title.to_string(),
            Style::new().fg(title_fg).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(subtitle.to_string(), Style::new().fg(FOG))),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

/// The rule that closes the header block (below the progress row). It spans
/// the readable column so it separates the chrome from the content rather
/// than underlining any single line.
pub(super) fn render_rule(frame: &mut Frame, area: Rect) {
    let rule = "\u{2500}".repeat(usize::from(area.width));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(rule, Style::new().fg(NIGHT)))),
        area,
    );
}

pub(super) fn render_help(frame: &mut Frame, area: Rect, text: &str) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text.to_string(),
            Style::new().fg(FOG),
        ))),
        area,
    );
}

/// Hand-drawn scrollbar thumb, sized to the visible fraction of the list.
pub(super) fn render_scrollbar(
    frame: &mut Frame,
    area: Rect,
    total: usize,
    view_h: usize,
    offset: usize,
    dragging: bool,
) {
    let track = usize::from(area.height);
    if track == 0 {
        return;
    }
    let (start, len) = if total <= view_h {
        (0, track)
    } else {
        let len = ((track * view_h + total / 2) / total).clamp(1, track.saturating_sub(1).max(1));
        let travel = track - len;
        let max_offset = total - view_h;
        (offset.min(max_offset) * travel / max_offset, len)
    };
    let buf = frame.buffer_mut();
    for row in 0..track {
        let (symbol, style) = if (start..start + len).contains(&row) {
            (
                SCROLL_THUMB,
                Style::new().fg(if dragging { INK } else { BRASS }),
            )
        } else {
            (SCROLL_TRACK, Style::new().fg(NIGHT))
        };
        buf.set_string(area.x, area.y + row as u16, symbol, style);
    }
}

/// Selection cursor plus viewport offset for a scrollable list of `n` rows.
/// `cursor` wraps on arrow moves (matching the provider picker); the offset is
/// nudged just enough to keep the cursor visible.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)] // list screens in #428–#433 own a ListNav.
pub(super) struct ListNav {
    pub cursor: usize,
    pub offset: usize,
    pub view_h: usize,
}

impl ListNav {
    pub(super) fn new() -> Self {
        Self {
            cursor: 0,
            offset: 0,
            view_h: 1,
        }
    }

    pub(super) fn set_view_h(&mut self, h: usize) {
        self.view_h = h.max(1);
    }

    pub(super) fn clamp(&mut self, n: usize) {
        if n == 0 {
            self.cursor = 0;
            self.offset = 0;
            return;
        }
        if self.cursor >= n {
            self.cursor = n - 1;
        }
        self.ensure_visible(n);
    }

    pub(super) fn move_by(&mut self, delta: isize, n: usize) {
        if n == 0 {
            return;
        }
        self.cursor = (self.cursor as isize + delta).rem_euclid(n as isize) as usize;
        self.ensure_visible(n);
    }

    pub(super) fn page(&mut self, down: bool, n: usize) {
        if n == 0 {
            return;
        }
        let step = self.view_h as isize;
        let delta = if down { step } else { -step };
        self.cursor = (self.cursor as isize + delta).clamp(0, n as isize - 1) as usize;
        self.ensure_visible(n);
    }

    pub(super) fn ensure_visible(&mut self, n: usize) {
        let max_offset = n.saturating_sub(self.view_h);
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else if self.cursor >= self.offset + self.view_h {
            self.offset = self.cursor + 1 - self.view_h;
        }
        if self.offset > max_offset {
            self.offset = max_offset;
        }
    }

    #[allow(dead_code)] // wheel-on-list offset without moving the cursor; used by #428+.
    pub(super) fn scroll_by(&mut self, delta: isize, n: usize) {
        let max_offset = n.saturating_sub(self.view_h) as isize;
        self.offset = (self.offset as isize + delta).clamp(0, max_offset.max(0)) as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listnav_wraps_and_keeps_cursor_visible() {
        let mut nav = ListNav::new();
        nav.set_view_h(3);
        nav.clamp(10);
        nav.move_by(-1, 10); // wrap to last
        assert_eq!(nav.cursor, 9);
        assert!(nav.offset <= 9 && nav.offset + nav.view_h > 9);
        nav.move_by(1, 10); // wrap to first
        assert_eq!(nav.cursor, 0);
        assert_eq!(nav.offset, 0);
    }

    #[test]
    fn listnav_paging_clamps_within_bounds() {
        let mut nav = ListNav::new();
        nav.set_view_h(4);
        nav.clamp(20);
        nav.page(true, 20);
        assert_eq!(nav.cursor, 4);
        nav.page(false, 20);
        assert_eq!(nav.cursor, 0);
    }
}
