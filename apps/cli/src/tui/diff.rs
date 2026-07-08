//! Diff rendering for `edit` / `editunlock` tool calls.
//!
//! Three modes (config `tui.diff_style`):
//!
//! - [`DiffStyle::SideBySide`] — old on the left, new on the right.
//!   Degrades to [`DiffStyle::Inline`] when the terminal is narrower
//!   than [`SIDE_BY_SIDE_MIN_WIDTH`].
//! - [`DiffStyle::Inline`] — unified diff. Removed lines prefixed
//!   `-` in red; added lines prefixed `+` in green; context lines
//!   prefixed ` `.
//! - [`DiffStyle::Hidden`] — one-line summary
//!   (`edited <path> (+N −M)`).
//!
//! Diffing is line-granular via [`similar::TextDiff::from_lines`].
//! Context lines outside hunks are emitted with a `…` separator so
//! large unchanged regions don't drown out the meaningful changes
//! (the limit is [`CONTEXT_LINES`]).
//!
//! `write` / `writeunlock` diffs are deferred — the tool doesn't
//! currently surface the pre-write file content to the TUI.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use similar::{ChangeTag, TextDiff};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::config::extended::DiffStyle;

/// Minimum terminal width (in columns) for [`DiffStyle::SideBySide`].
/// Below this, [`render_diff`] falls back to [`DiffStyle::Inline`].
pub const SIDE_BY_SIDE_MIN_WIDTH: u16 = 80;

/// Context lines kept on either side of an edit hunk (matches the
/// default for `git diff -U`). Anything past that is collapsed into a
/// single `…` separator line.
const CONTEXT_LINES: usize = 3;

const COL_REMOVED: Color = Color::Rgb(255, 190, 190);
const COL_ADDED: Color = Color::Rgb(178, 235, 190);
const BG_REMOVED: Color = Color::Rgb(92, 28, 36);
const BG_ADDED: Color = Color::Rgb(24, 84, 48);
const COL_HEADER: Color = Color::Cyan;
const COL_SEP: Color = Color::Indexed(244);
const COL_ELLIPSIS: Color = Color::Indexed(244);

/// Inline render mode prefixes (one column per character).
const PREFIX_REM: &str = "- ";
const PREFIX_ADD: &str = "+ ";
const PREFIX_CTX: &str = "  ";
/// Side-by-side separator. Spaces on either side absorb the column
/// gap so individual lines line up cleanly.
const COL_SEPARATOR: &str = " │ ";
/// Left indent applied to every diff line, matching the tool-output
/// indent the existing `Plain` history entries use.
const LEFT_INDENT: &str = "  ";

/// Render an `edit` / `editunlock` tool call as a diff.
///
/// `width` is the chat-pane width in terminal columns; the side-by-side
/// renderer uses it to size the two columns. `path` is the edited
/// file's path (displayed in the header).
pub fn render_diff(
    tool: &str,
    path: &str,
    old: &str,
    new: &str,
    style: DiffStyle,
    width: u16,
    emojis: bool,
) -> Vec<Line<'static>> {
    let diff = TextDiff::from_lines(old, new);
    let (added, removed) = count_changes(&diff);
    let style = effective_style(tool, style);

    let mut out = vec![header_line(tool, path, added, removed, emojis)];
    match style {
        DiffStyle::Hidden => {}
        DiffStyle::Inline => {
            out.extend(render_inline(&diff, width));
        }
        DiffStyle::SideBySide if width >= SIDE_BY_SIDE_MIN_WIDTH => {
            out.extend(render_side_by_side(&diff, width));
        }
        DiffStyle::SideBySide => {
            // Degrade to inline at narrow widths. Two-column layout
            // with anything less than ~30 cells per side is unreadable.
            out.extend(render_inline(&diff, width));
        }
    }
    out
}

fn effective_style(tool: &str, style: DiffStyle) -> DiffStyle {
    if matches!(tool, "write" | "writeunlock") && matches!(style, DiffStyle::SideBySide) {
        DiffStyle::Inline
    } else {
        style
    }
}

/// Diff header: `[glyph] label: path (+N −M)`. The glyph + label come
/// from the shared tool-line helper so diffs match the tool-box styling
/// and honor the emoji setting.
fn header_line(
    tool: &str,
    path: &str,
    added: usize,
    removed: usize,
    emojis: bool,
) -> Line<'static> {
    let (glyph, label) = crate::tui::history::tool_glyph_label(tool, emojis);
    let mut spans = vec![Span::raw(LEFT_INDENT.to_string())];
    if !glyph.is_empty() {
        spans.push(Span::raw(glyph));
    }
    spans.push(Span::styled(
        format!("{label}: "),
        Style::default().fg(COL_HEADER),
    ));
    spans.push(Span::raw(path.to_string()));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        format!("(+{added} −{removed})"),
        Style::default().fg(COL_SEP),
    ));
    Line::from(spans)
}

fn count_changes<'a>(diff: &TextDiff<'a, 'a, str>) -> (usize, usize) {
    let mut added = 0usize;
    let mut removed = 0usize;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
    }
    (added, removed)
}

// ---- inline ---------------------------------------------------------------

fn render_inline<'a>(diff: &TextDiff<'a, 'a, str>, width: u16) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let gutter_width = line_number_width(diff);
    let row_width = inline_row_width(width, gutter_width);
    for group in diff.grouped_ops(CONTEXT_LINES) {
        if !out.is_empty() {
            out.push(ellipsis_line(gutter_width, false));
        }
        for op in group {
            for change in diff.iter_changes(&op) {
                let value = strip_trailing_newline(change.value());
                let old_ln = change.old_index().map(|i| i + 1);
                let new_ln = change.new_index().map(|i| i + 1);
                let (prefix, style) = match change.tag() {
                    ChangeTag::Delete => (PREFIX_REM, removed_style()),
                    ChangeTag::Insert => (PREFIX_ADD, added_style()),
                    ChangeTag::Equal => (PREFIX_CTX, Style::default()),
                };
                let text = pad_to_width(value, row_width);
                out.push(Line::from(vec![
                    Span::raw(LEFT_INDENT.to_string()),
                    Span::styled(line_no(old_ln, gutter_width), Style::default().fg(COL_SEP)),
                    Span::styled(" ".to_string(), Style::default().fg(COL_SEP)),
                    Span::styled(line_no(new_ln, gutter_width), Style::default().fg(COL_SEP)),
                    Span::styled(" ".to_string(), Style::default().fg(COL_SEP)),
                    Span::styled(prefix.to_string(), style),
                    Span::styled(text, style),
                ]));
            }
        }
    }
    out
}

// ---- side-by-side ---------------------------------------------------------

fn render_side_by_side<'a>(diff: &TextDiff<'a, 'a, str>, width: u16) -> Vec<Line<'static>> {
    let gutter_width = line_number_width(diff);
    let col_width = side_by_side_column_width(width, gutter_width);
    let mut out = Vec::new();

    for group in diff.grouped_ops(CONTEXT_LINES) {
        if !out.is_empty() {
            out.push(ellipsis_line(gutter_width, true));
        }
        // Within each group we re-pair removed/added lines: a 3-line
        // delete followed by a 3-line insert renders as three rows of
        // (red, green) instead of three rows of (red, blank) then
        // three rows of (blank, green). That's what `git diff
        // --color-words`'s line variant would do, and it matches what
        // people expect "side by side" to mean.
        let mut left_pending: Vec<(usize, String)> = Vec::new();
        let mut right_pending: Vec<(usize, String)> = Vec::new();
        for op in group {
            for change in diff.iter_changes(&op) {
                let value = strip_trailing_newline(change.value()).to_string();
                match change.tag() {
                    ChangeTag::Delete => {
                        if let Some(i) = change.old_index() {
                            left_pending.push((i + 1, value));
                        }
                    }
                    ChangeTag::Insert => {
                        if let Some(i) = change.new_index() {
                            right_pending.push((i + 1, value));
                        }
                    }
                    ChangeTag::Equal => {
                        flush_pair(
                            &mut left_pending,
                            &mut right_pending,
                            col_width,
                            gutter_width,
                            &mut out,
                        );
                        // Equal lines mirror across both columns.
                        let l = pad_to_width(&value, col_width);
                        let r = pad_to_width(&value, col_width);
                        let old_ln = change.old_index().map(|i| i + 1);
                        let new_ln = change.new_index().map(|i| i + 1);
                        out.push(side_by_side_row(
                            old_ln,
                            l,
                            None,
                            new_ln,
                            r,
                            None,
                            gutter_width,
                        ));
                    }
                }
            }
        }
        flush_pair(
            &mut left_pending,
            &mut right_pending,
            col_width,
            gutter_width,
            &mut out,
        );
    }
    out
}

fn flush_pair(
    left: &mut Vec<(usize, String)>,
    right: &mut Vec<(usize, String)>,
    col_width: usize,
    gutter_width: usize,
    out: &mut Vec<Line<'static>>,
) {
    let n = left.len().max(right.len());
    for i in 0..n {
        let (left_ln, l) = left
            .get(i)
            .map(|(ln, text)| (Some(*ln), text.clone()))
            .unwrap_or((None, String::new()));
        let (right_ln, r) = right
            .get(i)
            .map(|(ln, text)| (Some(*ln), text.clone()))
            .unwrap_or((None, String::new()));
        let l_text = pad_to_width(&l, col_width);
        let r_text = pad_to_width(&r, col_width);
        let l_style = if left.get(i).is_some() {
            Some(removed_style())
        } else {
            None
        };
        let r_style = if right.get(i).is_some() {
            Some(added_style())
        } else {
            None
        };
        out.push(side_by_side_row(
            left_ln,
            l_text,
            l_style,
            right_ln,
            r_text,
            r_style,
            gutter_width,
        ));
    }
    left.clear();
    right.clear();
}

fn side_by_side_row(
    left_ln: Option<usize>,
    left: String,
    left_style: Option<Style>,
    right_ln: Option<usize>,
    right: String,
    right_style: Option<Style>,
    gutter_width: usize,
) -> Line<'static> {
    Line::from(vec![
        Span::raw(LEFT_INDENT.to_string()),
        Span::styled(line_no(left_ln, gutter_width), Style::default().fg(COL_SEP)),
        Span::raw(" "),
        Span::styled(left, left_style.unwrap_or_default()),
        Span::styled(COL_SEPARATOR.to_string(), Style::default().fg(COL_SEP)),
        Span::styled(
            line_no(right_ln, gutter_width),
            Style::default().fg(COL_SEP),
        ),
        Span::raw(" "),
        Span::styled(right, right_style.unwrap_or_default()),
    ])
}

/// How many cells of usable text fit in each diff column. Subtract:
/// LEFT_INDENT (2), the COL_SEPARATOR (3), and floor-divide the rest
/// by 2. Falls back to a tiny minimum so an absurdly narrow terminal
/// still produces *something* instead of a panic.
fn side_by_side_column_width(width: u16, gutter_width: usize) -> usize {
    let usable = (width as usize)
        .saturating_sub(LEFT_INDENT.chars().count())
        .saturating_sub(COL_SEPARATOR.chars().count())
        .saturating_sub((gutter_width + 1) * 2);
    (usable / 2).max(4)
}

fn inline_row_width(width: u16, gutter_width: usize) -> usize {
    (width as usize)
        .saturating_sub(LEFT_INDENT.chars().count())
        .saturating_sub((gutter_width + 1) * 2)
        .saturating_sub(PREFIX_REM.chars().count())
        .max(1)
}

fn pad_to_width(s: &str, width: usize) -> String {
    let display = UnicodeWidthStr::width(s);
    if display > width {
        let target = width.saturating_sub(1);
        let mut out = String::new();
        let mut used = 0usize;
        for ch in s.chars() {
            let w = UnicodeWidthChar::width(ch).unwrap_or(0);
            if used + w > target {
                break;
            }
            out.push(ch);
            used += w;
        }
        out.push('…');
        out
    } else {
        let mut out = s.to_string();
        for _ in 0..(width - display) {
            out.push(' ');
        }
        out
    }
}

fn line_number_width<'a>(diff: &TextDiff<'a, 'a, str>) -> usize {
    let max_ln = diff
        .iter_all_changes()
        .filter_map(|c| c.old_index().or(c.new_index()))
        .max()
        .map(|i| i + 1)
        .unwrap_or(0);
    max_ln.to_string().len().max(2)
}

fn line_no(n: Option<usize>, width: usize) -> String {
    match n {
        Some(n) => format!("{n:>width$}"),
        None => " ".repeat(width),
    }
}

fn removed_style() -> Style {
    Style::default().fg(COL_REMOVED).bg(BG_REMOVED)
}

fn added_style() -> Style {
    Style::default().fg(COL_ADDED).bg(BG_ADDED)
}

fn ellipsis_line(gutter_width: usize, side_by_side: bool) -> Line<'static> {
    let gutter = if side_by_side {
        format!(
            "{} {}{}{} ",
            " ".repeat(gutter_width),
            "…",
            COL_SEPARATOR,
            " ".repeat(gutter_width)
        )
    } else {
        format!("{} {} ", " ".repeat(gutter_width), " ".repeat(gutter_width))
    };
    Line::from(vec![
        Span::raw(LEFT_INDENT.to_string()),
        Span::raw(gutter),
        Span::styled(
            "…",
            Style::default()
                .fg(COL_ELLIPSIS)
                .add_modifier(Modifier::DIM),
        ),
    ])
}

fn strip_trailing_newline(s: &str) -> &str {
    s.strip_suffix('\n').unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines_to_strings(lines: &[Line<'static>]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn hidden_returns_one_line() {
        let lines = render_diff(
            "edit",
            "src/foo.rs",
            "a\nb\nc\n",
            "a\nB\nc\n",
            DiffStyle::Hidden,
            120,
            false,
        );
        assert_eq!(lines.len(), 1);
        let s = &lines_to_strings(&lines)[0];
        assert!(s.contains("src/foo.rs"), "{s:?}");
        assert!(s.contains("(+1 −1)"), "{s:?}");
    }

    #[test]
    fn inline_renders_with_plus_minus_prefixes() {
        let lines = render_diff(
            "edit",
            "src/foo.rs",
            "alpha\nbeta\ngamma\n",
            "alpha\nBETA\ngamma\n",
            DiffStyle::Inline,
            120,
            false,
        );
        let rendered = lines_to_strings(&lines);
        assert!(rendered[0].contains("(+1 −1)"));
        let body = rendered[1..].join("\n");
        assert!(body.contains("- beta"));
        assert!(body.contains("+ BETA"));
        assert!(body.contains("  1  1   alpha"));
    }

    #[test]
    fn inline_renders_line_numbers_and_full_changed_band_style() {
        let lines = render_diff(
            "edit",
            "src/foo.rs",
            "alpha\nbeta\ngamma\n",
            "alpha\nBETA\ngamma\n",
            DiffStyle::Inline,
            40,
            false,
        );
        let rendered = lines_to_strings(&lines);
        assert!(
            rendered.iter().any(|line| line.contains(" 2    - beta")),
            "{rendered:?}"
        );
        assert!(
            rendered.iter().any(|line| line.contains("    2 + BETA")),
            "{rendered:?}"
        );
        let removed = lines
            .iter()
            .find(|line| {
                line.spans
                    .iter()
                    .any(|span| span.content.as_ref().contains("beta"))
            })
            .expect("removed line");
        assert!(
            removed
                .spans
                .iter()
                .any(|span| span.style.fg == Some(COL_REMOVED)
                    && span.style.bg == Some(BG_REMOVED)
                    && span.content.ends_with(' '))
        );
        let added = lines
            .iter()
            .find(|line| {
                line.spans
                    .iter()
                    .any(|span| span.content.as_ref().contains("BETA"))
            })
            .expect("added line");
        assert!(
            added
                .spans
                .iter()
                .any(|span| span.style.fg == Some(COL_ADDED)
                    && span.style.bg == Some(BG_ADDED)
                    && span.content.ends_with(' '))
        );
    }

    #[test]
    fn side_by_side_falls_back_to_inline_when_narrow() {
        let narrow = render_diff(
            "edit",
            "x.rs",
            "a\nb\n",
            "a\nB\n",
            DiffStyle::SideBySide,
            40,
            false,
        );
        // Narrow mode should look like the inline render (uses `- ` /
        // `+ ` prefixes rather than the side-by-side `│` separator).
        let rendered = lines_to_strings(&narrow).join("\n");
        assert!(rendered.contains("- b"));
        assert!(rendered.contains("+ B"));
        assert!(!rendered.contains(COL_SEPARATOR));
    }

    #[test]
    fn side_by_side_uses_separator_when_wide() {
        let wide = render_diff(
            "edit",
            "x.rs",
            "alpha\nbeta\n",
            "alpha\nBETA\n",
            DiffStyle::SideBySide,
            120,
            false,
        );
        let rendered = lines_to_strings(&wide).join("\n");
        // Header doesn't carry the column separator; body rows do.
        assert!(rendered.contains(COL_SEPARATOR));
        assert!(rendered.contains(" 1 alpha"));
        assert!(rendered.contains(" 2 BETA"));
    }

    #[test]
    fn write_tools_force_inline_even_when_side_by_side_is_enabled() {
        for tool in ["write", "writeunlock"] {
            let lines = render_diff(
                tool,
                "x.rs",
                "",
                "alpha\nbeta\n",
                DiffStyle::SideBySide,
                120,
                false,
            );
            let rendered = lines_to_strings(&lines).join("\n");
            assert!(rendered.contains("+ alpha"), "{tool}: {rendered}");
            assert!(rendered.contains("+ beta"), "{tool}: {rendered}");
            assert!(!rendered.contains(COL_SEPARATOR), "{tool}: {rendered}");
        }
    }

    #[test]
    fn pad_to_width_truncates_with_ellipsis() {
        assert_eq!(pad_to_width("abcdef", 4), "abc…");
    }

    #[test]
    fn pad_to_width_pads_short_strings() {
        assert_eq!(pad_to_width("ab", 5), "ab   ");
    }

    #[test]
    fn pad_to_width_uses_display_columns_for_wide_text() {
        assert_eq!(pad_to_width("中", 4), "中  ");
        assert_eq!(pad_to_width("中abc", 4), "中a…");
    }

    #[test]
    fn count_changes_matches_visible_summary() {
        let diff = TextDiff::from_lines("a\nb\nc\n", "a\nB\nC\n");
        let (added, removed) = count_changes(&diff);
        assert_eq!(added, 2);
        assert_eq!(removed, 2);
    }
}
