//! `/pin` pick-a-message mode + `/pins` review mode (`pinned-messages`).
//!
//! Both are lightweight client-side navigation modes over the session's
//! pinnable messages. The state here is pure + unit-testable; the `App`
//! owns the DB writes (pin/unpin) and the transcript scroll, and routes
//! keys/mouse into these state machines (see `app/input.rs`,
//! `app/render.rs`).
//!
//! Pins are TUI/DB state only — nothing here ever enters the outbound
//! model prompt (token economy, priority #2).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use cockpit_proto::PinnedMessage;

use crate::tui::composer::display_width;

/// Grey for the `pin` half of the mouse control + muted chrome.
pub const PIN_GREY: Color = Color::Indexed(244);
/// Yellow for the `unpin` half of the mouse control + the pick arrow.
pub const PIN_YELLOW: Color = Color::Yellow;

/// The left-margin arrow `/pin` pick-mode draws next to the selected
/// message. One glyph wide; the transcript text is inset to leave room.
pub const PICK_ARROW: &str = "▶";

/// Column width of the single mouse control actually shown for a row:
/// `[unpin]` (7) when `pinned`, `[pin]` (5) when not. The mouse handler
/// hit-tests exactly this many leftmost columns so a click lands only on
/// the visible control.
pub fn pin_control_width(pinned: bool) -> u16 {
    if pinned { 7 } else { 5 }
}

pub fn fork_control_width() -> u16 {
    6
}

/// `/pin` pick-a-message mode. Holds the ordered list of pinnable message
/// history indices (oldest→newest) and a cursor into it. Selection starts
/// at the most recently completed message (the last entry) and navigates
/// outward (up = older, down = newer), per the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinPick {
    /// History indices of pinnable (User/Agent) entries, in transcript
    /// order. Empty only when there is nothing to pin.
    pub pinnable: Vec<usize>,
    /// Cursor into `pinnable`. Always in range when `pinnable` is
    /// non-empty.
    pub cursor: usize,
}

/// `/fork` pick-a-message mode. Same cursor semantics as [`PinPick`], but
/// confirmation branches the session instead of pinning the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkPick {
    pub pinnable: Vec<usize>,
    pub cursor: usize,
}

/// Keyboard copy-pick mode. Navigation matches [`PinPick`], with an
/// additional target cursor for whole-message vs fenced code blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPick {
    pub pinnable: Vec<usize>,
    pub cursor: usize,
    pub block_target: usize,
}

impl CopyPick {
    pub fn enter(pinnable: Vec<usize>) -> Option<Self> {
        if pinnable.is_empty() {
            return None;
        }
        let cursor = pinnable.len() - 1;
        Some(Self {
            pinnable,
            cursor,
            block_target: 0,
        })
    }

    pub fn up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
        self.block_target = 0;
    }

    pub fn down(&mut self) {
        if self.cursor + 1 < self.pinnable.len() {
            self.cursor += 1;
        }
        self.block_target = 0;
    }

    pub fn cycle_block_target(&mut self, delta: i32, block_count: usize) {
        if block_count == 0 {
            self.block_target = 0;
            return;
        }
        let len = block_count + 1;
        self.block_target = match delta.cmp(&0) {
            std::cmp::Ordering::Less => crate::tui::nav::wrap_prev(self.block_target, len),
            std::cmp::Ordering::Greater => crate::tui::nav::wrap_next(self.block_target, len),
            std::cmp::Ordering::Equal => self.block_target,
        };
    }

    pub fn selected_history_index(&self) -> usize {
        self.pinnable[self.cursor]
    }
}

impl PinPick {
    /// Enter pick mode over `pinnable` (transcript-ordered history
    /// indices). Returns `None` when there is nothing pinnable. The cursor
    /// starts at the **most recently completed** message (the last index).
    pub fn enter(pinnable: Vec<usize>) -> Option<Self> {
        if pinnable.is_empty() {
            return None;
        }
        let cursor = pinnable.len() - 1;
        Some(Self { pinnable, cursor })
    }

    /// Move the arrow toward older messages (clamped at the top).
    pub fn up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move the arrow toward newer messages (clamped at the bottom).
    pub fn down(&mut self) {
        if self.cursor + 1 < self.pinnable.len() {
            self.cursor += 1;
        }
    }

    /// The currently selected message's history index.
    pub fn selected_history_index(&self) -> usize {
        self.pinnable[self.cursor]
    }
}

impl ForkPick {
    pub fn enter(pinnable: Vec<usize>) -> Option<Self> {
        if pinnable.is_empty() {
            return None;
        }
        let cursor = pinnable.len() - 1;
        Some(Self { pinnable, cursor })
    }

    pub fn up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn down(&mut self) {
        if self.cursor + 1 < self.pinnable.len() {
            self.cursor += 1;
        }
    }

    pub fn selected_history_index(&self) -> usize {
        self.pinnable[self.cursor]
    }
}

/// `/pins` review mode — a checklist over the session's pinned messages
/// with jump navigation. Holds the resolved pins (each carries its durable
/// original text, so it renders correctly after `/prune` + `/compact`) and
/// a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinsReview {
    /// Pinned messages in pin order, each with its `seq`, role, and
    /// durable original text.
    pub pins: Vec<PinnedMessage>,
    /// Cursor into `pins`. Clamped to a valid index while `pins` is
    /// non-empty.
    pub cursor: usize,
}

impl PinsReview {
    /// Enter review mode over `pins`. Returns `None` when there are no
    /// pins (the `/pins` command then just reports "no pins").
    pub fn enter(pins: Vec<PinnedMessage>) -> Option<Self> {
        if pins.is_empty() {
            return None;
        }
        Some(Self { pins, cursor: 0 })
    }

    pub fn up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn down(&mut self) {
        if self.cursor + 1 < self.pins.len() {
            self.cursor += 1;
        }
    }

    /// The currently highlighted pin, or `None` when the list is empty.
    pub fn selected(&self) -> Option<&PinnedMessage> {
        self.pins.get(self.cursor)
    }

    /// Remove the pin at `seq` from the in-memory list (after the DB unpin
    /// succeeds) and re-clamp the cursor. Returns `true` when the list is
    /// now empty (the caller closes the mode). Both `d` and checking an
    /// item route here — there is no separate "done but still pinned"
    /// state (checklist semantics: checking unpins).
    pub fn remove_seq(&mut self, seq: i64) -> bool {
        self.pins.retain(|p| p.seq != seq);
        if self.pins.is_empty() {
            return true;
        }
        if self.cursor >= self.pins.len() {
            self.cursor = self.pins.len() - 1;
        }
        false
    }

    /// Remove `seq` from the list only if it's present, re-clamping the
    /// cursor. Returns `true` when the removal emptied the list (caller
    /// closes the mode). Used to keep an open review in sync when a pin is
    /// toggled off via the mouse control elsewhere. A `seq` not in the list
    /// is a no-op returning `false`.
    pub fn remove_seq_if_present(&mut self, seq: i64) -> bool {
        if !self.pins.iter().any(|p| p.seq == seq) {
            return false;
        }
        self.remove_seq(seq)
    }

    /// Render the checklist as overlay lines. Each row is an unchecked box
    /// `[ ]` (checking unpins, so a pinned item is never shown checked),
    /// the message role, and a one-line preview of its original text. The
    /// highlighted row is bold + reversed.
    pub fn render_lines(&self, width: u16) -> Vec<Line<'static>> {
        let mut out: Vec<Line<'static>> = Vec::new();
        out.push(Line::from(vec![Span::styled(
            format!(
                " Pinned messages ({}) — ↑/↓ jump · d/space unpin · esc close ",
                self.pins.len()
            ),
            Style::default().fg(PIN_YELLOW).add_modifier(Modifier::BOLD),
        )]));
        for (i, pin) in self.pins.iter().enumerate() {
            let role = if pin.is_assistant { "agent" } else { "you" };
            let preview = preview_text(&pin.text, width.saturating_sub(12) as usize);
            let label = format!("[ ] {role}: {preview}");
            let style = if i == self.cursor {
                Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                Style::default().fg(PIN_GREY)
            };
            out.push(Line::from(vec![Span::styled(label, style)]));
        }
        out
    }
}

/// First non-empty line of `text`, hard-truncated to `max` columns with an
/// ellipsis. Newlines collapse so a multi-line message previews on one row.
pub fn preview_text(text: &str, max: usize) -> String {
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let max = max.max(8);
    truncate_preview_line(first, max)
}

/// Width-fitted preview of the raw message: up to `max_rows` visual lines
/// taken from the source text (never from a render cache), with an
/// ellipsis on the last row when more content remains. Each row is
/// truncated through [`preview_text`]'s ellipsis rule.
pub fn preview_text_rows(text: &str, width: usize, max_rows: usize) -> Vec<String> {
    if max_rows == 0 {
        return Vec::new();
    }
    let width = width.max(1);
    let source: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let mut rows = Vec::new();
    for (i, line) in source.iter().copied().enumerate() {
        let mut rest = line;
        while !rest.is_empty() {
            let last_slot = rows.len() + 1 >= max_rows;
            if last_slot {
                let later_lines = i + 1 < source.len();
                let rest_overflows = display_width(rest) > width;
                rows.push(ellipsize_display_width(
                    rest,
                    width,
                    later_lines || rest_overflows,
                ));
                return rows;
            }
            let (head, tail) = split_preview_line(rest, width);
            rows.push(head);
            rest = tail;
        }
    }
    rows
}

fn truncate_preview_line(first: &str, max: usize) -> String {
    if first.chars().count() <= max {
        first.to_string()
    } else {
        let head: String = first.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn split_preview_line(line: &str, width: usize) -> (String, &str) {
    if display_width(line) <= width {
        return (line.to_string(), "");
    }
    let mut split = 0usize;
    let mut used = 0usize;
    for grapheme in crate::tui::markdown::semantic_graphemes(line) {
        let grapheme_width = display_width(&grapheme);
        if used.saturating_add(grapheme_width) > width {
            break;
        }
        used = used.saturating_add(grapheme_width);
        split = split.saturating_add(grapheme.len());
    }
    // A grapheme wider than the whole row cannot be displayed there. Consume it
    // so callers always make progress while keeping the returned row width-safe.
    if split == 0 {
        split = crate::tui::markdown::semantic_graphemes(line)
            .first()
            .map_or(line.len(), String::len);
        return (String::new(), &line[split..]);
    }
    (line[..split].to_string(), &line[split..])
}

fn ellipsize_display_width(text: &str, width: usize, truncated: bool) -> String {
    if !truncated && display_width(text) <= width {
        return text.to_string();
    }
    let ellipsis = "…";
    let budget = width.saturating_sub(display_width(ellipsis));
    let (mut prefix, _) = split_preview_line(text, budget);
    while display_width(&prefix) > budget {
        prefix.pop();
    }
    if display_width(ellipsis) <= width {
        prefix.push('…');
    }
    prefix
}

/// The fork mouse control: grey `[fork]`, rendered unemphasized. It is drawn
/// immediately left of the state-appropriate pin control when both fit.
pub fn fork_control_spans() -> Vec<Span<'static>> {
    vec![Span::styled("[fork]", Style::default().fg(PIN_GREY))]
}

/// The single state-appropriate pin mouse control: yellow `[unpin]` when
/// `pinned`, grey `[pin]` when not. Only one pin action is ever shown (no `|`
/// separator), rendered unemphasized — clicking it toggles the pin state.
pub fn pin_control_spans(pinned: bool) -> Vec<Span<'static>> {
    if pinned {
        vec![Span::styled("[unpin]", Style::default().fg(PIN_YELLOW))]
    } else {
        vec![Span::styled("[pin]", Style::default().fg(PIN_GREY))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(seq: i64, is_assistant: bool, text: &str) -> PinnedMessage {
        PinnedMessage {
            seq,
            is_assistant,
            text: text.to_string(),
        }
    }

    #[test]
    fn pick_starts_at_most_recent_and_navigates_outward() {
        // Pinnable history indices in transcript order.
        let mut pick = PinPick::enter(vec![2, 4, 6, 8]).unwrap();
        // Starts at the most recently completed message (the last one).
        assert_eq!(pick.selected_history_index(), 8);
        // Up walks toward older messages.
        pick.up();
        assert_eq!(pick.selected_history_index(), 6);
        pick.up();
        pick.up();
        assert_eq!(pick.selected_history_index(), 2);
        // Clamped at the top.
        pick.up();
        assert_eq!(pick.selected_history_index(), 2);
        // Down walks back toward newer messages, clamped at the bottom.
        pick.down();
        assert_eq!(pick.selected_history_index(), 4);
        for _ in 0..10 {
            pick.down();
        }
        assert_eq!(pick.selected_history_index(), 8);
    }

    #[test]
    fn fork_pick_starts_at_most_recent_and_navigates_outward() {
        let mut pick = ForkPick::enter(vec![2, 4, 6, 8]).unwrap();
        assert_eq!(pick.selected_history_index(), 8);
        pick.up();
        assert_eq!(pick.selected_history_index(), 6);
        pick.up();
        pick.up();
        assert_eq!(pick.selected_history_index(), 2);
        pick.up();
        assert_eq!(pick.selected_history_index(), 2);
        pick.down();
        assert_eq!(pick.selected_history_index(), 4);
        pick.down();
        pick.down();
        assert_eq!(pick.selected_history_index(), 8);
        pick.down();
        assert_eq!(pick.selected_history_index(), 8);
    }

    #[test]
    fn fork_pick_enter_none_when_nothing_pinnable() {
        assert!(ForkPick::enter(Vec::new()).is_none());
    }

    #[test]
    fn pick_enter_none_when_nothing_pinnable() {
        assert!(PinPick::enter(vec![]).is_none());
    }

    #[test]
    fn copy_pick_starts_at_most_recent_and_navigates_outward() {
        let mut pick = CopyPick::enter(vec![2, 4, 6, 8]).unwrap();
        assert_eq!(pick.selected_history_index(), 8);
        pick.up();
        assert_eq!(pick.selected_history_index(), 6);
        pick.up();
        pick.up();
        assert_eq!(pick.selected_history_index(), 2);
        pick.up();
        assert_eq!(pick.selected_history_index(), 2);
        pick.down();
        assert_eq!(pick.selected_history_index(), 4);
        for _ in 0..10 {
            pick.down();
        }
        assert_eq!(pick.selected_history_index(), 8);
    }

    #[test]
    fn copy_pick_enter_none_when_nothing_copyable() {
        assert!(CopyPick::enter(vec![]).is_none());
    }

    #[test]
    fn copy_pick_block_target_resets_on_message_move() {
        let mut pick = CopyPick::enter(vec![2, 4, 6]).unwrap();
        pick.block_target = 2;
        pick.up();
        assert_eq!(pick.block_target, 0);
        pick.block_target = 2;
        pick.down();
        assert_eq!(pick.block_target, 0);
    }

    #[test]
    fn copy_pick_block_cycle_wraps_over_whole_message_and_blocks() {
        let mut pick = CopyPick::enter(vec![2]).unwrap();
        pick.cycle_block_target(1, 3);
        assert_eq!(pick.block_target, 1);
        pick.cycle_block_target(1, 3);
        assert_eq!(pick.block_target, 2);
        pick.cycle_block_target(1, 3);
        assert_eq!(pick.block_target, 3);
        pick.cycle_block_target(1, 3);
        assert_eq!(pick.block_target, 0);
        pick.cycle_block_target(-1, 3);
        assert_eq!(pick.block_target, 3);
    }

    #[test]
    fn review_check_and_d_both_unpin_via_remove_seq() {
        let mut review = PinsReview::enter(vec![
            pin(10, false, "first"),
            pin(20, true, "second"),
            pin(30, false, "third"),
        ])
        .unwrap();
        assert_eq!(review.selected().unwrap().seq, 10);

        // `d` on the highlighted pin (seq 10) removes it; cursor stays in
        // range, now pointing at the next pin.
        let emptied = review.remove_seq(10);
        assert!(!emptied);
        assert_eq!(review.pins.len(), 2);
        assert_eq!(review.selected().unwrap().seq, 20);

        // Checking an item (same code path) removes it too — no separate
        // "done but pinned" state.
        review.down();
        assert_eq!(review.selected().unwrap().seq, 30);
        let emptied = review.remove_seq(30);
        assert!(!emptied);
        // Cursor re-clamped to the last remaining pin.
        assert_eq!(review.selected().unwrap().seq, 20);

        // Removing the last pin empties the list (caller closes the mode).
        let emptied = review.remove_seq(20);
        assert!(emptied);
        assert!(review.selected().is_none());
    }

    #[test]
    fn review_enter_none_when_no_pins() {
        assert!(PinsReview::enter(vec![]).is_none());
    }

    #[test]
    fn review_navigation_clamps() {
        let mut review = PinsReview::enter(vec![pin(1, false, "a"), pin(2, true, "b")]).unwrap();
        assert_eq!(review.cursor, 0);
        review.up();
        assert_eq!(review.cursor, 0, "clamped at top");
        review.down();
        assert_eq!(review.cursor, 1);
        review.down();
        assert_eq!(review.cursor, 1, "clamped at bottom");
    }

    #[test]
    fn preview_collapses_and_truncates() {
        assert_eq!(preview_text("\n\n  hello world  \n", 100), "hello world");
        let long = "x".repeat(50);
        let p = preview_text(&long, 10);
        assert!(p.ends_with('…'));
        assert_eq!(p.chars().count(), 10);
    }

    #[test]
    fn preview_text_rows_takes_two_source_lines_and_ellipsizes() {
        let rows = preview_text_rows("alpha\nbeta\ngamma", 20, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], "alpha");
        assert!(rows[1].contains("beta"), "{rows:?}");
        assert!(rows[1].contains('…'), "{rows:?}");
    }

    #[test]
    fn preview_text_rows_wraps_a_long_single_line() {
        let rows = preview_text_rows(&"x".repeat(30), 10, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].chars().count(), 10);
        assert!(rows[1].ends_with('…'), "{rows:?}");
        assert_eq!(rows[1].chars().count(), 10);
    }

    #[test]
    fn preview_text_rows_fits_wide_graphemes_by_display_width() {
        let rows = preview_text_rows("界界界界界界", 6, 2);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| display_width(row) <= 6), "{rows:?}");
        assert!(rows[1].ends_with('…'), "{rows:?}");
    }

    #[test]
    fn pin_control_shows_single_state_action() {
        // Unpinned → lone grey `[pin]`, no separator, no second action.
        let spans = pin_control_spans(false);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content, "[pin]");
        assert_eq!(spans[0].style.fg, Some(PIN_GREY));
        assert!(!spans[0].style.add_modifier.contains(Modifier::BOLD));

        // Pinned → lone yellow `[unpin]`, no separator, no second action.
        let spans = pin_control_spans(true);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content, "[unpin]");
        assert_eq!(spans[0].style.fg, Some(PIN_YELLOW));
        assert!(!spans[0].style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn pin_control_width_matches_shown_action() {
        // Width is the width of the single control actually shown.
        assert_eq!(pin_control_width(false), 5, "[pin] is 5 columns");
        assert_eq!(pin_control_width(true), 7, "[unpin] is 7 columns");
        assert_eq!(fork_control_width(), 6, "[fork] is 6 columns");

        // The hit-test width equals the rendered span's column width.
        assert_eq!(
            pin_control_width(false) as usize,
            pin_control_spans(false)[0].content.chars().count()
        );
        assert_eq!(
            pin_control_width(true) as usize,
            pin_control_spans(true)[0].content.chars().count()
        );
        assert_eq!(
            fork_control_width() as usize,
            fork_control_spans()[0].content.chars().count()
        );

        // A click at column 6 (past `[pin]`) does NOT register on an
        // unpinned control — only columns 0..5 are live.
        assert!(6 >= pin_control_width(false));
    }
}
