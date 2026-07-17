//! Pane geometry — one place to compute section heights and split a frame.
//!
//! The TUI viewport is a fixed-height pane anchored to the bottom of the
//! terminal. Its layout is one of:
//!
//! - chat:   `[ body (history)  |  strip  |  input  |  status ]`
//! - dialog: `[ body (dialog)                                  |  status ]`
//!
//! `PaneGeometry::compute` produces the section heights for a given app
//! state; `layout` then carves a `Rect` into the named sub-rects.

use ratatui::layout::{Constraint, Layout, Rect};

pub const STATUS_HEIGHT: u16 = 1;
pub const MIN_HISTORY_HEIGHT: u16 = 1;
pub const MIN_INPUT_CONTENT: u16 = 1;
pub const MAX_INPUT_CONTENT: u16 = 6;
pub const INPUT_BORDER: u16 = 2;

#[derive(Debug, Clone, Copy)]
pub struct PaneGeometry {
    /// Input box height (content + border). Zero when a dialog is open.
    pub input: u16,
    /// "Agent is working" status indicator row above the queue strip.
    /// Zero unless the agent is busy past the startup grace. One row
    /// when shown.
    pub indicator: u16,
    /// Queued-messages strip above the input. Zero when nothing is
    /// queued, or while suggestions occupy the same connected strip slot.
    /// Includes its top border and its bottom border. When the input is
    /// present, the strip's last row overlaps the input's top border row.
    pub queue: u16,
    /// Suggestion/vim-hint strip above the input. Zero when there are no
    /// active suggestions and no vim hint, or a dialog is open. Occupies
    /// the same connected strip slot as the queue and takes precedence.
    pub suggestions: u16,
    /// Pinned-message count indicator row below the input
    /// (`pinned-messages`). One row when the session has ≥1 pin and no
    /// dialog is open; zero otherwise.
    pub pins: u16,
    /// Persistent sandbox-down notice rows below the input
    /// (`implementation notes` §6.5). Non-zero (its wrapped row count) while the
    /// shell sandbox can't initialize and no dialog is open; zero otherwise.
    /// Persistent — never times out like a toast.
    pub sandbox_notice: u16,
    /// Status row height. Always `STATUS_HEIGHT`; named so that callers
    /// don't need to reach for the constant separately.
    pub status: u16,
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
    /// Status-indicator row above the queue strip. Zero-area unless the
    /// working indicator is showing.
    pub indicator: Rect,
    /// Queued-messages strip above the input. Zero-area when the queue
    /// is empty, suggestions are visible, or a dialog is open.
    pub queue: Rect,
    /// Suggestion/vim-hint strip above the input. Zero-area when no
    /// suggestion box is visible or a dialog is open.
    pub suggestions: Rect,
    /// Input box rect. Zero-area when a dialog is open.
    pub input: Rect,
    /// Pinned-message count indicator rect, below the input
    /// (`pinned-messages`). Zero-area when the session has no pins or a
    /// dialog is open.
    pub pins: Rect,
    /// Persistent sandbox-down notice rect, below the input
    /// (`implementation notes` §6.5). Zero-area when the sandbox is fine or a
    /// dialog/popup occupies the space.
    pub sandbox_notice: Rect,
    /// Compact bottom-anchored overlay rect (answering dialog). Zero-area
    /// unless a compact overlay is open. Sits below `body` (history) and
    /// above `status`.
    pub compact: Rect,
    /// Status row — always rendered, including under a dialog.
    pub status: Rect,
}

impl PaneGeometry {
    /// Stable launch-banner reference height: the frame minus only the
    /// permanent status row and the minimum bordered input box.
    pub const fn baseline_body_height(frame_height: u16) -> u16 {
        frame_height.saturating_sub(STATUS_HEIGHT + MIN_INPUT_CONTENT + INPUT_BORDER)
    }
    /// Build the geometry for an app frame.
    ///
    /// `input_height` and `suggestions_height` are passed in (rather than
    /// computed here) so the only inputs this module needs are integers —
    /// no dependency on the App or Composer types.
    // Each arg is one below-input slot height; grouping them into a struct
    // would only move the same integer list behind a constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn compute(
        input_height: u16,
        indicator_height: u16,
        queue_height: u16,
        suggestions_height: u16,
        pins_height: u16,
        sandbox_notice_height: u16,
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
                indicator: 0,
                queue: 0,
                suggestions: 0,
                pins: 0,
                sandbox_notice: 0,
                status: STATUS_HEIGHT,
                dialog: 0,
                compact: compact_height,
                history: history_lines.max(MIN_HISTORY_HEIGHT),
            };
        }
        if dialog_height > 0 {
            Self {
                input: 0,
                indicator: 0,
                queue: 0,
                suggestions: 0,
                pins: 0,
                sandbox_notice: 0,
                status: STATUS_HEIGHT,
                dialog: dialog_height,
                compact: 0,
                history: history_lines.max(MIN_HISTORY_HEIGHT),
            }
        } else {
            // Queue/suggestions and input are both full bordered rects.
            // Suggestions take the queue slot while visible. The active
            // strip's bottom border overlaps the input's top border;
            // aggregate height accounting subtracts that overlap instead of
            // shrinking either rect.
            let input = input_height;
            let suggestions = suggestions_height;
            let queue = if suggestions > 0 { 0 } else { queue_height };
            Self {
                input,
                indicator: indicator_height,
                queue,
                suggestions,
                pins: pins_height,
                sandbox_notice: sandbox_notice_height,
                status: STATUS_HEIGHT,
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
            self.dialog + self.status
        } else {
            self.history
                + self.indicator
                + self.active_strip()
                + self.input.saturating_sub(self.strip_input_overlap())
                + self.pins
                + self.sandbox_notice
                + self.compact
                + self.status
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
            self.status
        } else {
            self.indicator
                + self.active_strip()
                + self.input.saturating_sub(self.strip_input_overlap())
                + self.pins
                + self.sandbox_notice
                + self.compact
                + self.status
        }
    }

    /// Split `area` into the named sub-rects.
    pub fn layout(&self, area: Rect) -> PaneRects {
        if self.dialog > 0 {
            let parts =
                Layout::vertical([Constraint::Min(0), Constraint::Length(self.status)]).split(area);
            PaneRects {
                body: parts[0],
                indicator: Rect::new(0, 0, 0, 0),
                queue: Rect::new(0, 0, 0, 0),
                suggestions: Rect::new(0, 0, 0, 0),
                input: Rect::new(0, 0, 0, 0),
                pins: Rect::new(0, 0, 0, 0),
                sandbox_notice: Rect::new(0, 0, 0, 0),
                compact: Rect::new(0, 0, 0, 0),
                status: parts[1],
            }
        } else {
            let strip_input_overlap = self.strip_input_overlap();
            let input_slot = self.input.saturating_sub(strip_input_overlap);
            let parts = Layout::vertical([
                Constraint::Min(0),
                Constraint::Length(self.indicator),
                Constraint::Length(self.active_strip()),
                Constraint::Length(input_slot),
                Constraint::Length(self.pins),
                Constraint::Length(self.sandbox_notice),
                Constraint::Length(self.compact),
                Constraint::Length(self.status),
            ])
            .split(area);
            let input = if strip_input_overlap > 0 {
                Rect::new(
                    parts[3].x,
                    parts[3].y.saturating_sub(strip_input_overlap),
                    parts[3].width,
                    self.input,
                )
            } else {
                parts[3]
            };
            let queue = if self.suggestions > 0 {
                Rect::new(0, 0, 0, 0)
            } else {
                parts[2]
            };
            let suggestions = if self.suggestions > 0 {
                parts[2]
            } else {
                Rect::new(0, 0, 0, 0)
            };
            PaneRects {
                body: parts[0],
                indicator: parts[1],
                queue,
                suggestions,
                input,
                pins: parts[4],
                sandbox_notice: parts[5],
                compact: parts[6],
                status: parts[7],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_body_height_subtracts_only_permanent_chrome() {
        assert_eq!(PaneGeometry::baseline_body_height(24), 20);
        assert_eq!(PaneGeometry::baseline_body_height(4), 0);
        assert_eq!(PaneGeometry::baseline_body_height(2), 0);

        let transient_heights = [0, 1, 3, 6, 8, u16::MAX];
        for _transient in transient_heights {
            assert_eq!(PaneGeometry::baseline_body_height(40), 36);
        }
    }

    #[test]
    fn queue_and_input_rects_overlap_on_one_border_row() {
        let geom = PaneGeometry::compute(3, 0, 3, 0, 0, 0, 1, 0, 0);

        assert_eq!(geom.input, 3);
        assert_eq!(geom.queue, 3);
        assert_eq!(geom.chrome_height(), 6);

        let rects = geom.layout(Rect::new(0, 0, 20, 8));
        assert_eq!(rects.queue.y + rects.queue.height - 1, rects.input.y);
        assert_eq!(rects.input.height, 3);
        assert_eq!(rects.status.y, 7);
    }

    #[test]
    fn suggestions_replace_queue_and_overlap_input() {
        let geom = PaneGeometry::compute(3, 0, 3, 4, 1, 1, 1, 0, 0);

        assert_eq!(geom.queue, 0);
        assert_eq!(geom.suggestions, 4);
        assert_eq!(geom.chrome_height(), 9);

        let rects = geom.layout(Rect::new(0, 0, 20, 11));
        assert_eq!(rects.queue.height, 0);
        assert_eq!(
            rects.suggestions.y + rects.suggestions.height - 1,
            rects.input.y
        );
        assert_eq!(rects.pins.height, 1);
        assert_eq!(rects.sandbox_notice.height, 1);
    }
}
