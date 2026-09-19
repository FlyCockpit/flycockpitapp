//! Diff rendering for `edit` and `write` tool calls.
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
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use similar::{ChangeTag, TextDiff};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use cockpit_config::extended::DiffStyle;

use crate::tui::history::DiffVerb;

/// Minimum terminal width (in columns) for [`DiffStyle::SideBySide`].
/// Below this, [`render_diff`] falls back to [`DiffStyle::Inline`].
pub const SIDE_BY_SIDE_MIN_WIDTH: u16 = 80;

/// Context lines kept on either side of an edit hunk (matches the
/// default for `git diff -U`). Anything past that is collapsed into a
/// single `…` separator line.
const CONTEXT_LINES: usize = 3;

const COL_REMOVED: Color = crate::tui::theme::RED;
const COL_ADDED: Color = crate::tui::theme::GREEN;
const COL_SEP: Color = crate::tui::theme::NIGHT;
const COL_ELLIPSIS: Color = crate::tui::theme::FOG;

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

/// Render a file diff for the transcript.
///
/// `width` is the chat-pane width in terminal columns; the side-by-side
/// renderer uses it to size the two columns. `path` is the edited
/// file's path (displayed in the header).
pub fn render_diff(
    verb: DiffVerb,
    path: &str,
    old: &str,
    new: &str,
    style: DiffStyle,
    width: u16,
    emojis: bool,
    file_icons: bool,
) -> Vec<Line<'static>> {
    let diff = TextDiff::from_lines(old, new);
    let (added, removed) = count_changes(&diff);

    let mut out = vec![header_line(verb, path, added, removed, emojis, file_icons)];
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

/// Diff header matching the transcript reference chrome.
fn header_line(
    verb: DiffVerb,
    path: &str,
    added: usize,
    removed: usize,
    _emojis: bool,
    _file_icons: bool,
) -> Line<'static> {
    let label = match verb {
        DiffVerb::Created => "Created",
        DiffVerb::Edited => "Edited",
    };
    let mut spans = vec![Span::styled(
        "  ◇ ",
        Style::default().fg(crate::tui::theme::BRASS),
    )];
    spans.push(Span::styled(
        format!("{label} "),
        Style::default().fg(crate::tui::theme::FOG),
    ));
    spans.push(Span::styled(
        path.to_string(),
        Style::default()
            .fg(crate::tui::theme::INK)
            .add_modifier(Modifier::BOLD),
    ));
    if added > 0 {
        spans.push(Span::styled(
            format!("  +{added}"),
            Style::default().fg(COL_ADDED),
        ));
    }
    if removed > 0 {
        spans.push(Span::styled(
            format!(" -{removed}"),
            Style::default().fg(COL_REMOVED),
        ));
    }
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
    let row_width = usize::from(width).saturating_sub(6).max(1);
    for group in diff.grouped_ops(CONTEXT_LINES) {
        if !out.is_empty() {
            out.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("│ ", Style::default().fg(COL_SEP)),
                Span::styled("  …", Style::default().fg(COL_ELLIPSIS)),
            ]));
        }
        for op in group {
            for change in diff.iter_changes(&op) {
                let value = strip_trailing_newline(change.value());
                let (prefix, style) = match change.tag() {
                    ChangeTag::Delete => (PREFIX_REM, removed_style()),
                    ChangeTag::Insert => (PREFIX_ADD, added_style()),
                    ChangeTag::Equal => (PREFIX_CTX, Style::default().fg(COL_ELLIPSIS)),
                };
                let (wrapped, _) = crate::tui::message_block::wrap_lines_to_width(
                    vec![Line::from(Span::styled(value.to_string(), style))],
                    row_width,
                );
                for (index, piece) in wrapped.into_iter().enumerate() {
                    let mut spans = vec![
                        Span::raw(LEFT_INDENT.to_string()),
                        Span::styled("│ ", Style::default().fg(COL_SEP)),
                        if index == 0 {
                            Span::styled(prefix.to_string(), style)
                        } else {
                            Span::raw("  ")
                        },
                    ];
                    spans.extend(piece.spans);
                    out.push(Line::from(spans));
                }
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
    Style::default().fg(COL_REMOVED)
}

fn added_style() -> Style {
    Style::default().fg(COL_ADDED)
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
    use crate::tui::history::DiffVerb;

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
            DiffVerb::Edited,
            "src/foo.rs",
            "a\nb\nc\n",
            "a\nB\nc\n",
            DiffStyle::Hidden,
            120,
            false,
            false,
        );
        assert_eq!(lines.len(), 1);
        let s = &lines_to_strings(&lines)[0];
        assert_eq!(s, "  ◇ Edited src/foo.rs  +1 -1");
    }

    #[test]
    fn inline_renders_with_plus_minus_prefixes() {
        let lines = render_diff(
            DiffVerb::Edited,
            "src/foo.rs",
            "alpha\nbeta\ngamma\n",
            "alpha\nBETA\ngamma\n",
            DiffStyle::Inline,
            120,
            false,
            false,
        );
        let rendered = lines_to_strings(&lines);
        assert_eq!(rendered[0], "  ◇ Edited src/foo.rs  +1 -1");
        assert_eq!(
            rendered[1..],
            ["  │   alpha", "  │ - beta", "  │ + BETA", "  │   gamma"]
        );
    }

    #[test]
    fn inline_uses_exact_six_column_chrome_and_semantic_colors() {
        let lines = render_diff(
            DiffVerb::Edited,
            "src/foo.rs",
            "alpha\nbeta\ngamma\n",
            "alpha\nBETA\ngamma\n",
            DiffStyle::Inline,
            40,
            false,
            false,
        );
        let rendered = lines_to_strings(&lines);
        assert!(rendered.iter().any(|line| line == "  │ - beta"));
        assert!(rendered.iter().any(|line| line == "  │ + BETA"));
        let removed = lines
            .iter()
            .find(|line| {
                line.spans
                    .iter()
                    .any(|span| span.content.as_ref().contains("beta"))
            })
            .expect("removed line");
        assert!(removed.spans.iter().any(|span| {
            span.style.fg == Some(COL_REMOVED) && span.style.bg.is_none() && span.content == "beta"
        }));
        let added = lines
            .iter()
            .find(|line| {
                line.spans
                    .iter()
                    .any(|span| span.content.as_ref().contains("BETA"))
            })
            .expect("added line");
        assert!(added.spans.iter().any(|span| {
            span.style.fg == Some(COL_ADDED) && span.style.bg.is_none() && span.content == "BETA"
        }));
    }

    #[test]
    fn side_by_side_falls_back_to_inline_when_narrow() {
        let narrow = render_diff(
            DiffVerb::Edited,
            "x.rs",
            "a\nb\n",
            "a\nB\n",
            DiffStyle::SideBySide,
            40,
            false,
            false,
        );
        let rendered = lines_to_strings(&narrow);
        assert!(rendered.iter().any(|line| line == "  │ - b"));
        assert!(rendered.iter().any(|line| line == "  │ + B"));
    }

    #[test]
    fn side_by_side_uses_separator_when_wide() {
        let wide = render_diff(
            DiffVerb::Edited,
            "x.rs",
            "alpha\nbeta\n",
            "alpha\nBETA\n",
            DiffStyle::SideBySide,
            120,
            false,
            false,
        );
        let rendered = lines_to_strings(&wide).join("\n");
        // Header doesn't carry the column separator; body rows do.
        assert!(rendered.contains(COL_SEPARATOR));
        assert!(rendered.contains(" 1 alpha"));
        assert!(rendered.contains(" 2 BETA"));
    }

    #[test]
    fn write_created_side_by_side_places_additions_in_right_column() {
        let rendered = lines_to_strings(&render_diff(
            DiffVerb::Created,
            "new.txt",
            "",
            "alpha\nbeta\n",
            DiffStyle::SideBySide,
            120,
            false,
            false,
        ));
        assert_eq!(rendered[0], "  ◇ Created new.txt  +2");
        let first = rendered[1].split_once(COL_SEPARATOR).unwrap();
        let second = rendered[2].split_once(COL_SEPARATOR).unwrap();
        assert_eq!(first.0.trim(), "");
        assert_eq!(first.1.trim(), "1 alpha");
        assert_eq!(second.0.trim(), "");
        assert_eq!(second.1.trim(), "2 beta");
    }

    #[test]
    fn write_created_renders_all_additions() {
        let lines = render_diff(
            DiffVerb::Created,
            "fixtures/new.txt",
            "",
            "alpha\nbeta\n",
            DiffStyle::Inline,
            120,
            false,
            false,
        );
        let rendered = lines_to_strings(&lines);
        assert_eq!(rendered[0], "  ◇ Created fixtures/new.txt  +2");
        assert!(rendered.iter().any(|line| line.contains("+ alpha")));
        assert!(rendered.iter().any(|line| line.contains("+ beta")));
    }

    #[test]
    fn write_edited_renders_correct_plus_minus_counts() {
        let lines = render_diff(
            DiffVerb::Edited,
            "fixtures/existing.txt",
            "keep\nold line\n",
            "keep\nnew line\n",
            DiffStyle::Inline,
            120,
            false,
            false,
        );
        let rendered = lines_to_strings(&lines);
        assert_eq!(rendered[0], "  ◇ Edited fixtures/existing.txt  +1 -1");
        assert!(rendered.iter().any(|line| line == "  │ - old line"));
        assert!(rendered.iter().any(|line| line == "  │ + new line"));
    }

    #[test]
    fn write_created_hidden_mode_is_summary_only() {
        let lines = render_diff(
            DiffVerb::Created,
            "x.rs",
            "",
            "line\n",
            DiffStyle::Hidden,
            120,
            false,
            false,
        );
        assert_eq!(lines.len(), 1);
        assert_eq!(lines_to_strings(&lines)[0], "  ◇ Created x.rs  +1");
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
