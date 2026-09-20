//! Pane geometry — one place to compute section heights and split a frame.
//!
//! The TUI viewport is a fixed-height pane anchored to the bottom of the
//! terminal. Its layout is one of:
//!
//! - chat:   `[ body (history) | queue/slash | input ]`
//! - dialog: `[ body (dialog)                         ]`
//!
//! `PaneGeometry::compute` produces the section heights for a given app
//! state; `layout` then carves a `Rect` into the named sub-rects.

use ratatui::layout::{Constraint, Layout, Rect};

pub const MIN_HISTORY_HEIGHT: u16 = 1;
pub const MIN_INPUT_CONTENT: u16 = 1;
pub const MAX_INPUT_CONTENT: u16 = 8;
pub const INPUT_BORDER: u16 = 2;

#[derive(Debug, Clone, Copy)]
pub struct PaneGeometry {
    /// Input box height (content + border). Zero when a dialog is open.
    pub input: u16,
    /// Queued-messages strip above the input. Zero when nothing is
    /// queued, or while suggestions occupy the same connected strip slot.
    /// Includes its top border and its bottom border. When the input is
    /// present, the strip's last row overlaps the input's top border row.
    pub queue: u16,
    /// Suggestion/vim-hint strip above the input. Zero when there are no
    /// active suggestions and no vim hint, or a dialog is open. Occupies
    /// the same connected strip slot as the queue and takes precedence.
    pub suggestions: u16,
    /// Dialog height. Zero when no dialog is open.
    pub dialog: u16,
    /// Compact bottom-anchored overlay height (the answering/question
    /// dialog, GOALS §3b). Unlike `dialog` (a fullscreen modal that hides
    /// history), this sits at the bottom above the status row and lets
    /// history show above it. Zero when no compact overlay is open.
    pub compact: u16,
    /// History rows wanted by the current scrollback. The pane will grow
    /// to fit up to the terminal height; beyond that, old entries spill
    /// into terminal scrollback.
    // Read by the not-yet-wired `desired_pane_height` grow policy.
    #[allow(dead_code)]
    pub history: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct PaneRects {
    /// Where history renders (chat mode) or the dialog overlays
    /// (dialog mode).
    pub body: Rect,
    /// Queued-messages strip above the input. Zero-area when the queue
    /// is empty, suggestions are visible, or a dialog is open.
    pub queue: Rect,
    /// Suggestion/vim-hint strip above the input. Zero-area when no
    /// suggestion box is visible or a dialog is open.
    pub suggestions: Rect,
    /// Input box rect. Zero-area when a dialog is open.
    pub input: Rect,
    /// Compact bottom-anchored overlay rect (answering dialog). Zero-area
    /// unless a compact overlay is open. Sits below `body` (history) and
    /// below `body`.
    pub compact: Rect,
}

impl PaneGeometry {
    /// Stable launch-banner reference height: the frame minus only the
    /// permanent chrome — the minimum bordered input box,
    /// and the three-row chat header that sits above the history pane
    /// whenever the body is tall enough to host it.
    pub const fn baseline_body_height(frame_height: u16) -> u16 {
        let body = frame_height.saturating_sub(MIN_INPUT_CONTENT + INPUT_BORDER);
        // The header renders only when the body is taller than it; the
        // baseline must match the pane the banner actually centers in.
        if body > crate::tui::chat_header::CHAT_HEADER_HEIGHT {
            body - crate::tui::chat_header::CHAT_HEADER_HEIGHT
        } else {
            body
        }
    }
    /// Build the geometry for an app frame.
    ///
    /// `input_height` and `suggestions_height` are passed in (rather than
    /// computed here) so the only inputs this module needs are integers —
    /// no dependency on the App or Composer types.
    pub fn compute(
        input_height: u16,
        queue_height: u16,
        suggestions_height: u16,
        history_lines: u16,
        dialog_height: u16,
        compact_height: u16,
    ) -> Self {
        // Required-decision overlays take precedence over optional dialogs
        // (settings/model picker/etc.) while keeping history visible above
        // the compact bottom-anchored pane.
        if compact_height > 0 {
            return Self {
                input: 0,
                queue: 0,
                suggestions: 0,
                dialog: 0,
                compact: compact_height,
                history: history_lines.max(MIN_HISTORY_HEIGHT),
            };
        }
        if dialog_height > 0 {
            Self {
                input: 0,
                queue: 0,
                suggestions: 0,
                dialog: dialog_height,
                compact: 0,
                history: history_lines.max(MIN_HISTORY_HEIGHT),
            }
        } else {
            // Queue/suggestions and input are both full bordered rects.
            // Suggestions take the queue slot while visible — the two
            // never stack; a visible suggestion box hides the queue
            // strip for that frame. The active strip's bottom border
            // overlaps the input's top border; aggregate height
            // accounting subtracts that overlap instead of shrinking
            // either rect.
            let input = input_height;
            let suggestions = suggestions_height;
            let queue = if suggestions > 0 { 0 } else { queue_height };
            Self {
                input,
                queue,
                suggestions,
                dialog: 0,
                compact: 0,
                history: history_lines.max(MIN_HISTORY_HEIGHT),
            }
        }
    }

    /// Pane height the current state would prefer if we weren't constrained
    /// by the terminal or by the monotonic-grow policy. Sum of all sections
    /// + however much history wants to show.
    // Retained for the not-yet-wired monotonic-grow / spill geometry.
    #[allow(dead_code)]
    pub fn desired_pane_height(&self) -> u16 {
        if self.dialog > 0 {
            self.dialog
        } else {
            self.history
                + self.active_strip()
                + self.input.saturating_sub(self.strip_input_overlap())
                + self.compact
        }
    }

    fn active_strip(&self) -> u16 {
        self.suggestions.max(self.queue)
    }

    fn strip_input_overlap(&self) -> u16 {
        u16::from(self.active_strip() > 0 && self.input > 0)
    }

    /// Sum of every section above `body`. Used by `maybe_spill_history` to
    /// figure out how many rows are available for history.
    // Retained for the not-yet-wired `maybe_spill_history` row math.
    #[allow(dead_code)]
    pub fn chrome_height(&self) -> u16 {
        if self.dialog > 0 {
            0
        } else {
            self.active_strip()
                + self.input.saturating_sub(self.strip_input_overlap())
                + self.compact
        }
    }

    /// Split `area` into the named sub-rects.
    ///
    /// `body` is deliberately stable in dialog mode: callers split persistent
    /// navigation (the session rail) from it before choosing the dialog or
    /// overlay renderer. Dialog mode suppresses composer chrome, but never
    /// substitutes a separate fullscreen geometry that can erase that split.
    /// This ordering is the public seam used by subsequent popover work.
    pub fn layout(&self, area: Rect) -> PaneRects {
        let dialog_mode = self.dialog > 0;
        let strip_input_overlap = if dialog_mode {
            0
        } else {
            self.strip_input_overlap()
        };
        let input_slot = if dialog_mode {
            0
        } else {
            self.input.saturating_sub(strip_input_overlap)
        };
        let visible = |height| if dialog_mode { 0 } else { height };
        let parts = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(visible(self.active_strip())),
            Constraint::Length(input_slot),
            Constraint::Length(visible(self.compact)),
        ])
        .split(area);
        let input = if strip_input_overlap > 0 {
            Rect::new(
                parts[2].x,
                parts[2].y.saturating_sub(strip_input_overlap),
                parts[2].width,
                self.input,
            )
        } else {
            parts[2]
        };
        let queue = if self.suggestions > 0 {
            Rect::new(0, 0, 0, 0)
        } else {
            parts[1]
        };
        let suggestions = if self.suggestions > 0 {
            parts[1]
        } else {
            Rect::new(0, 0, 0, 0)
        };
        PaneRects {
            body: parts[0],
            queue,
            suggestions,
            input,
            compact: parts[3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_body_height_subtracts_only_permanent_chrome() {
        // Minimum bordered input + the permanent three-row
        // chat header (subtracted only while the body can host the header).
        assert_eq!(PaneGeometry::baseline_body_height(24), 18);
        assert_eq!(PaneGeometry::baseline_body_height(40), 34);
        // Bodies no taller than the header keep every row: the header is
        // skipped, so nothing is carved.
        assert_eq!(PaneGeometry::baseline_body_height(7), 1);
        assert_eq!(PaneGeometry::baseline_body_height(4), 1);
        assert_eq!(PaneGeometry::baseline_body_height(2), 0);

        let transient_heights = [0, 1, 3, 6, 8, u16::MAX];
        for _transient in transient_heights {
            assert_eq!(PaneGeometry::baseline_body_height(40), 34);
        }
    }

    #[test]
    fn dialog_layout_keeps_a_stable_body_for_pre_overlay_navigation_split() {
        let geometry = PaneGeometry::compute(3, 2, 0, 20, 12, 0);
        let rects = geometry.layout(Rect::new(0, 0, 120, 40));
        assert_eq!(rects.body, Rect::new(0, 0, 120, 40));
        assert!(rects.input.is_empty());
        assert!(rects.queue.is_empty());
    }

    #[test]
    fn queue_and_input_rects_overlap_on_one_border_row() {
        let geom = PaneGeometry::compute(3, 3, 0, 1, 0, 0);

        assert_eq!(geom.input, 3);
        assert_eq!(geom.queue, 3);
        assert_eq!(geom.chrome_height(), 5);

        let rects = geom.layout(Rect::new(0, 0, 20, 8));
        assert_eq!(rects.queue.y + rects.queue.height - 1, rects.input.y);
        assert_eq!(rects.input.height, 3);
    }

    #[test]
    fn suggestions_replace_queue_and_overlap_input() {
        // Documented slot conflict: a visible suggestion box occupies the
        // same connected strip as the queue and wins, so queue height is
        // zero even when messages are queued.
        let geom = PaneGeometry::compute(3, 3, 4, 1, 0, 0);

        assert_eq!(geom.queue, 0);
        assert_eq!(geom.suggestions, 4);
        assert_eq!(geom.chrome_height(), 6);

        let rects = geom.layout(Rect::new(0, 0, 20, 11));
        assert_eq!(rects.queue.height, 0);
        assert_eq!(
            rects.suggestions.y + rects.suggestions.height - 1,
            rects.input.y
        );
    }
}
