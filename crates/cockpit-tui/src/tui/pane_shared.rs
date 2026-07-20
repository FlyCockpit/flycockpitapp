//! Small pure helpers shared by the `/sessions`, `/plans`, and `/stats`
//! panes. Hoisted here so the three panes keep one copy each rather than
//! drifting independently.

use std::path::Path;

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Wrap a row's spans in vertical bars, padding to `inner_w` (truncating
/// when the content overruns the card width).
pub(crate) fn boxed_row(
    content: Vec<Span<'static>>,
    inner_w: usize,
    border: Style,
) -> Line<'static> {
    let available = inner_w.saturating_sub(1);
    let content = truncate_spans_to_width(content, available);
    let used = spans_width(&content);
    let pad = available.saturating_sub(used);
    let mut spans = vec![Span::styled("│".to_string(), border)];
    if inner_w > 0 {
        spans.push(Span::raw(" "));
        spans.extend(content);
        spans.push(Span::raw(" ".repeat(pad)));
    }
    spans.push(Span::styled("│".to_string(), border));
    Line::from(spans)
}

fn spans_width(spans: &[Span<'static>]) -> usize {
    spans
        .iter()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .sum()
}

fn truncate_spans_to_width(spans: Vec<Span<'static>>, max_width: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut used = 0;
    for span in spans {
        if used >= max_width {
            break;
        }
        let mut text = String::new();
        for ch in span.content.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(0);
            if used + w > max_width {
                break;
            }
            text.push(ch);
            used += w;
        }
        if !text.is_empty() {
            out.push(Span::styled(text, span.style));
        }
    }
    out
}

/// Resolve the cwd to a `project_id` the same way session creation and
/// the CLI mirror do (GOALS §15b): prefer the git worktree root for
/// stability, else the cwd. `None` when the cwd can't be read.
pub(crate) fn resolve_project_id(cwd: &Path) -> Option<String> {
    let root = crate::git::find_worktree_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    Some(crate::session::project_id_for(&root))
}

/// Short prefix of a `project_id` hash for the title chip — the full
/// hash is long and the title only needs to be recognizable.
pub(crate) fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Clamp a scroll offset so the selected rendered row span stays visible.
///
/// `selected_end` is exclusive. If the selected item is taller than the
/// viewport, keep its top row visible; otherwise keep the full span visible
/// whenever possible.
pub(crate) fn clamp_scroll_to_visible_span(
    scroll: usize,
    viewport_rows: usize,
    content_rows: usize,
    selected_start: usize,
    selected_end: usize,
) -> usize {
    let max_scroll = content_rows.saturating_sub(viewport_rows);
    let scroll = scroll.min(max_scroll);
    if viewport_rows == 0 || selected_start >= selected_end {
        return scroll;
    }

    let selected_rows = selected_end - selected_start;
    if selected_rows > viewport_rows {
        return selected_start.min(max_scroll);
    }

    if selected_start < scroll {
        selected_start
    } else if selected_end > scroll + viewport_rows {
        selected_end.saturating_sub(viewport_rows).min(max_scroll)
    } else {
        scroll
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn line_width(line: &Line<'static>) -> usize {
        UnicodeWidthStr::width(plain(line).as_str())
    }

    fn right_border_col(line: &Line<'static>) -> usize {
        let before_right: String = line.spans[..line.spans.len().saturating_sub(1)]
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        UnicodeWidthStr::width(before_right.as_str())
    }

    #[test]
    fn clamp_scroll_keeps_full_span_visible_when_it_fits() {
        assert_eq!(clamp_scroll_to_visible_span(0, 5, 20, 7, 10), 5);
        assert_eq!(clamp_scroll_to_visible_span(8, 5, 20, 2, 5), 2);
        assert_eq!(clamp_scroll_to_visible_span(4, 5, 20, 5, 8), 4);
    }

    #[test]
    fn clamp_scroll_keeps_top_visible_when_span_is_taller_than_viewport() {
        assert_eq!(clamp_scroll_to_visible_span(0, 3, 20, 6, 12), 6);
    }

    #[test]
    fn clamp_scroll_stays_within_content_bounds() {
        assert_eq!(clamp_scroll_to_visible_span(99, 5, 12, 10, 12), 7);
        assert_eq!(clamp_scroll_to_visible_span(0, 20, 12, 10, 12), 0);
    }

    #[test]
    fn boxed_row_ascii_width_places_right_border() {
        let line = boxed_row(vec![Span::raw("abc")], 8, Style::default());
        assert_eq!(line_width(&line), 10);
        assert_eq!(right_border_col(&line), 9);
        assert_eq!(plain(&line), "│ abc    │");
    }

    #[test]
    fn boxed_row_cjk_width_places_right_border() {
        let line = boxed_row(vec![Span::raw("界")], 4, Style::default());
        assert_eq!(line_width(&line), 6);
        assert_eq!(right_border_col(&line), 5);
    }

    #[test]
    fn boxed_row_emoji_width_places_right_border() {
        let line = boxed_row(vec![Span::raw("📌 3")], 6, Style::default());
        assert_eq!(line_width(&line), 8);
        assert_eq!(right_border_col(&line), 7);
    }

    #[test]
    fn boxed_row_overlong_content_is_truncated_to_inner_width() {
        let line = boxed_row(vec![Span::raw("abcdef")], 4, Style::default());
        assert_eq!(line_width(&line), 6);
        assert_eq!(right_border_col(&line), 5);
        assert_eq!(plain(&line), "│ abc│");
    }
}
