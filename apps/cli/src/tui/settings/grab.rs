//! Shared grab/reorder-mode visuals for the `/settings` lists
//! (implementation note).
//!
//! Four sub-pages — Skills, the generic string-lists, Instructions, and the
//! Environment-File-Patterns (redact) page — let the user "grab" a row, drop
//! it with `Enter` (which saves), or cancel with `Esc`. The string-lists,
//! Instructions, and redact page also reorder the held row with `↑`/`↓`;
//! Skills grab is edit-only (no reorder), so it gets the [`GRAB_HINT_EDIT`]
//! variant while the other three get [`GRAB_HINT`]. This module is the single
//! source of truth for how the mode looks so the four sites stay in sync: the
//! held-row marker + style and both footer-hint variants live here, nowhere
//! else.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::MUTED_COLOR_INDEX;

use super::shell::clamp_to_char_boundary;

/// Marker prefixing the currently-grabbed (held) row. Distinct from the
/// browse cursor (`▸ `) so a held row reads as "picked up, moving".
pub(super) const GRAB_MARKER: &str = "✥ ";

/// Marker prefixing the (non-grabbed) browse cursor row.
pub(super) const CURSOR_MARKER: &str = "▸ ";

/// Marker prefixing a non-selected row.
pub(super) const IDLE_MARKER: &str = "  ";

/// Trailing caret drawn after a grabbed row's live text buffer.
const GRAB_CARET: &str = "▎";

/// Footer hint shown ONLY while a row is grabbed, for the three sites that
/// reorder the held row with `↑`/`↓` (string-lists, Instructions, redact).
pub(super) const GRAB_HINT: &str = "grabbed — ↑/↓ reorder · enter: drop & save · esc: cancel";

/// Footer hint for the Skills page, whose grab is edit-only (no reorder) —
/// the held row is an editable text field, so the hint omits the `↑`/`↓`
/// reorder claim that would be false there.
pub(super) const GRAB_HINT_EDIT: &str = "grabbed — type to edit · enter: drop & save · esc: cancel";

/// Style of a grabbed row's text (held rows read cyan-bold; the browse
/// cursor is yellow-bold, idle rows white).
pub(super) fn grabbed_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

/// Build the spans for the grabbed row: marker + live buffer text + caret,
/// plus the placeholder `empty_hint` when the buffer is empty.
pub(super) fn grabbed_row_spans(
    buf_text: &str,
    cursor: usize,
    empty_hint: &str,
) -> Vec<Span<'static>> {
    let cyan = Style::default().fg(Color::Cyan);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let cursor = clamp_to_char_boundary(buf_text, cursor);
    let (before, after) = buf_text.split_at(cursor);
    let mut spans = vec![
        Span::raw(GRAB_MARKER),
        Span::styled(before.to_string(), grabbed_style()),
        Span::styled(GRAB_CARET.to_string(), cyan),
    ];
    if buf_text.is_empty() {
        spans.push(Span::styled(empty_hint.to_string(), muted));
    } else {
        spans.push(Span::styled(after.to_string(), grabbed_style()));
    }
    spans
}

/// The while-grabbed footer hint line (cyan, to match the held row), built
/// from the given hint text ([`GRAB_HINT`] for reorder sites, [`GRAB_HINT_EDIT`]
/// for Skills). Append it to the rendered page only while a row is grabbed.
pub(super) fn grab_hint_line(hint: &str) -> Line<'static> {
    Line::from(Span::styled(hint.to_string(), grabbed_style()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(spans: Vec<Span<'static>>) -> String {
        spans
            .into_iter()
            .map(|span| span.content.to_string())
            .collect()
    }

    #[test]
    fn grabbed_row_spans_render_caret_at_logical_cursor() {
        assert_eq!(text(grabbed_row_spans("alpha", 2, "empty")), "✥ al▎pha");
    }
}
