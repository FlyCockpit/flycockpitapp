//! Shared pane contracts and selectable-list scroll state.

use crossterm::event::KeyEvent;
use ratatui::Frame;
use ratatui::layout::Rect;

/// Common shape for TUI panes routed by the app.
#[allow(dead_code)]
pub(crate) trait Pane {
    type Outcome;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome;

    fn render(&mut self, frame: &mut Frame, area: Rect);
}

/// Cursor plus scroll state for selectable lists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScrollList {
    cursor: usize,
    scroll: usize,
}

impl ScrollList {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn at(cursor: usize, scroll: usize) -> Self {
        Self { cursor, scroll }
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
    }

    pub(crate) fn set_scroll(&mut self, scroll: usize) {
        self.scroll = scroll;
    }

    pub(crate) fn reset(&mut self) {
        self.cursor = 0;
        self.scroll = 0;
    }

    pub(crate) fn clamp_cursor(&mut self, len: usize) {
        self.cursor = self.cursor.min(len.saturating_sub(1));
    }

    pub(crate) fn move_by(&mut self, delta: isize, len: usize) {
        if delta == 0 {
            return;
        }
        let steps = delta.unsigned_abs();
        for _ in 0..steps {
            self.cursor = if delta < 0 {
                crate::tui::nav::wrap_prev(self.cursor, len)
            } else {
                crate::tui::nav::wrap_next(self.cursor, len)
            };
        }
    }

    pub(crate) fn move_clamped(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.cursor = 0;
            return;
        }
        let next = self.cursor as isize + delta;
        self.cursor = next.clamp(0, len as isize - 1) as usize;
    }

    pub(crate) fn clamp_windowed(&mut self, len: usize, viewport: usize) {
        self.scroll = crate::tui::nav::windowed_scroll(self.cursor, self.scroll, len, viewport);
    }

    pub(crate) fn clamp_visible_span(
        &mut self,
        viewport_rows: usize,
        content_rows: usize,
        selected_start: usize,
        selected_end: usize,
    ) {
        self.scroll = crate::tui::pane_shared::clamp_scroll_to_visible_span(
            self.scroll,
            viewport_rows,
            content_rows,
            selected_start,
            selected_end,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_list_wraps_and_clamps() {
        let mut list = ScrollList::new();

        list.move_by(-1, 0);
        assert_eq!(list.cursor(), 0);
        list.move_by(1, 0);
        assert_eq!(list.cursor(), 0);

        list.move_by(1, 1);
        assert_eq!(list.cursor(), 0);
        list.move_by(-1, 1);
        assert_eq!(list.cursor(), 0);

        list.move_by(-1, 3);
        assert_eq!(list.cursor(), 2);
        list.move_by(1, 3);
        assert_eq!(list.cursor(), 0);

        list = ScrollList::at(5, 0);
        list.clamp_windowed(10, 5);
        assert_eq!(list.scroll(), 2);

        list = ScrollList::at(0, 0);
        list.clamp_visible_span(3, 10, 5, 6);
        assert_eq!(list.scroll(), 3);
    }
}
