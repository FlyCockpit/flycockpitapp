//! Shared static message-body and message-block layout.
//!
//! The main transcript composes the body result with its live-only chrome
//! (streaming, pin controls, reasoning, hover), while compact read-only views
//! such as `/sessions` add a role/timestamp header. Markdown parsing and
//! word-aware styled wrapping live here so those surfaces cannot drift.

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use std::rc::Rc;
use unicode_width::UnicodeWidthStr;

use crate::tui::markdown;

#[derive(Debug, Clone)]
pub(crate) struct MessageBlock {
    pub(crate) lines: Vec<Line<'static>>,
    pub(crate) continuations: Vec<bool>,
    pub(crate) copy_cells: Vec<Vec<Option<u32>>>,
    pub(crate) copy_newlines_before: Vec<usize>,
    pub(crate) copy_incomplete: Vec<bool>,
    pub(crate) copy_fragments: Rc<Vec<markdown::CopyFragment>>,
}

struct WrappedMarkdown {
    lines: Vec<Line<'static>>,
    continuations: Vec<bool>,
    copy_cells: Vec<Vec<Option<u32>>>,
    copy_newlines_before: Vec<usize>,
    copy_incomplete: Vec<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct MessageBlockRole {
    pub(crate) label: String,
    pub(crate) style: Style,
}

/// Build one static Markdown message block. This is the single shared
/// Markdown-message assembly site consumed by both the transcript and compact
/// read-only surfaces. Callers may compose their own live chrome around the
/// returned block, or add the compact role/timestamp header with
/// [`MessageBlock::with_header`].
pub(crate) fn render_markdown_message_block(
    text: &str,
    max_width: usize,
    reserve_first: usize,
    indent: usize,
    body_style: Style,
) -> MessageBlock {
    let logical = markdown::render_with_provenance(text, max_width.max(1));
    layout_rendered_markdown_message(logical, max_width, reserve_first, indent, body_style)
}

pub(crate) fn layout_rendered_markdown_message(
    rendered: markdown::RenderedMarkdown,
    max_width: usize,
    reserve_first: usize,
    indent: usize,
    body_style: Style,
) -> MessageBlock {
    let mut wrapped = wrap_rendered_markdown(
        rendered.lines,
        rendered.copy_cells,
        rendered.copy_newlines_before,
        rendered.copy_incomplete,
        max_width,
        reserve_first,
    );
    wrapped.lines = indent_lines(wrapped.lines, indent);
    if indent > 0 {
        for cells in &mut wrapped.copy_cells {
            cells.splice(0..0, std::iter::repeat_n(None, indent));
        }
    }
    for line in &mut wrapped.lines {
        line.style = body_style;
    }
    MessageBlock {
        lines: wrapped.lines,
        continuations: wrapped.continuations,
        copy_cells: wrapped.copy_cells,
        copy_newlines_before: wrapped.copy_newlines_before,
        copy_incomplete: wrapped.copy_incomplete,
        copy_fragments: rendered.copy_fragments,
    }
}

/// Lay out already-parsed Markdown. The pending transcript renderer uses this
/// after incrementally reusing stable parsed paragraphs.
pub(crate) fn layout_markdown_message_lines(
    lines: Vec<Line<'static>>,
    max_width: usize,
    reserve_first: usize,
    indent: usize,
    body_style: Style,
) -> MessageBlock {
    let (mut lines, continuations) =
        wrap_lines_to_width_reserving_first(lines, max_width, reserve_first);
    lines = indent_lines(lines, indent);
    for line in &mut lines {
        line.style = body_style;
    }
    MessageBlock {
        lines,
        continuations,
        copy_cells: Vec::new(),
        copy_newlines_before: Vec::new(),
        copy_incomplete: Vec::new(),
        copy_fragments: Rc::new(Vec::new()),
    }
}

fn wrap_rendered_markdown(
    lines: Vec<Line<'static>>,
    cells: Vec<Vec<Option<u32>>>,
    newlines: Vec<usize>,
    incomplete: Vec<bool>,
    max_width: usize,
    reserve_first: usize,
) -> WrappedMarkdown {
    let mut out_lines = Vec::new();
    let mut out_continuations = Vec::new();
    let mut out_cells = Vec::new();
    let mut out_newlines = Vec::new();
    let mut out_incomplete = Vec::new();
    let mut first_overall = true;
    for (index, line) in lines.into_iter().enumerate() {
        let mut remaining = line.spans;
        let mut remaining_cells = cells.get(index).cloned().unwrap_or_default();
        let mut first = true;
        loop {
            let width = if first_overall {
                max_width.saturating_sub(reserve_first).max(1)
            } else {
                max_width
            };
            let (head, tail) = slice_spans_at_width(remaining, width);
            let head_width = head.iter().map(|span| span.content.width()).sum::<usize>();
            let split = head_width.min(remaining_cells.len());
            let tail_cells = remaining_cells.split_off(split);
            out_lines.push(Line::from(head));
            out_cells.push(remaining_cells);
            out_continuations.push(!first);
            out_newlines.push(if first {
                newlines.get(index).copied().unwrap_or(0)
            } else {
                0
            });
            out_incomplete.push(incomplete.get(index).copied().unwrap_or(false));
            first = false;
            first_overall = false;
            match tail {
                Some(tail) => {
                    remaining = tail;
                    remaining_cells = tail_cells;
                }
                None => break,
            }
        }
    }
    WrappedMarkdown {
        lines: out_lines,
        continuations: out_continuations,
        copy_cells: out_cells,
        copy_newlines_before: out_newlines,
        copy_incomplete: out_incomplete,
    }
}

impl MessageBlock {
    /// Add the compact header used by preview surfaces. Keeping this on the
    /// shared block prevents compact views from growing a parallel Markdown
    /// assembly path while letting the transcript retain its live chrome.
    pub(crate) fn with_header(
        self,
        role: MessageBlockRole,
        timestamp: String,
    ) -> Vec<Line<'static>> {
        let header_style = role.style.add_modifier(ratatui::style::Modifier::BOLD);
        let mut lines = Vec::with_capacity(self.lines.len() + 1);
        lines.push(Line::from(vec![
            Span::styled(role.label, header_style),
            Span::styled(format!(" · {timestamp}"), header_style),
        ]));
        lines.extend(self.lines);
        lines
    }
}

/// Re-wrap styled lines at whitespace boundaries, hard-cutting only a token
/// that is itself wider than the available width.
pub(crate) fn wrap_lines_to_width(
    lines: Vec<Line<'static>>,
    max_width: usize,
) -> (Vec<Line<'static>>, Vec<bool>) {
    wrap_lines_to_width_reserving_first(lines, max_width, 0)
}

pub(crate) fn wrap_lines_to_width_reserving_first(
    lines: Vec<Line<'static>>,
    max_width: usize,
    reserve_first: usize,
) -> (Vec<Line<'static>>, Vec<bool>) {
    if max_width == 0 {
        let conts = vec![false; lines.len()];
        return (lines, conts);
    }
    let mut out = Vec::with_capacity(lines.len());
    let mut conts = Vec::with_capacity(lines.len());
    let mut first_row_overall = true;
    for line in lines {
        let mut remaining = line.spans;
        let mut first = true;
        loop {
            let width = if first_row_overall {
                max_width.saturating_sub(reserve_first).max(1)
            } else {
                max_width
            };
            let (head, tail) = slice_spans_at_width(remaining, width);
            out.push(Line::from(head));
            conts.push(!first);
            first = false;
            first_row_overall = false;
            match tail {
                Some(tail) => remaining = tail,
                None => break,
            }
        }
    }
    (out, conts)
}

pub(crate) fn indent_lines(lines: Vec<Line<'static>>, n: usize) -> Vec<Line<'static>> {
    if n == 0 {
        return lines;
    }
    let prefix = " ".repeat(n);
    lines
        .into_iter()
        .map(|mut line| {
            let mut spans = vec![Span::raw(prefix.clone())];
            spans.append(&mut line.spans);
            Line::from(spans)
        })
        .collect()
}

pub(crate) fn slice_spans_at_width(
    spans: Vec<Span<'static>>,
    max_width: usize,
) -> (Vec<Span<'static>>, Option<Vec<Span<'static>>>) {
    let total: usize = spans.iter().map(|span| span.content.width()).sum();
    if total <= max_width || max_width == 0 {
        return (spans, None);
    }
    let text = spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    let scalars = spans
        .iter()
        .flat_map(|span| span.content.chars().map(move |ch| (ch, span.style)))
        .collect::<Vec<_>>();
    let mut scalar_offset = 0usize;
    let flat = markdown::semantic_graphemes(&text)
        .into_iter()
        .map(|grapheme| {
            let end = scalar_offset + grapheme.chars().count();
            let styled_scalars = scalars.get(scalar_offset..end).unwrap_or_default().to_vec();
            scalar_offset = end;
            (grapheme, styled_scalars)
        })
        .collect::<Vec<_>>();
    let mut used = 0usize;
    let mut hard_split = flat.len();
    let mut whitespace_split = None;
    for (index, (grapheme, _)) in flat.iter().enumerate() {
        let width = grapheme.width();
        if index > 0 && used + width > max_width {
            hard_split = index;
            break;
        }
        used += width;
        if used > max_width {
            hard_split = index + 1;
            break;
        }
        if grapheme.chars().all(char::is_whitespace) {
            whitespace_split = Some(index + 1);
        }
    }
    let split_at = whitespace_split.unwrap_or(hard_split);
    let head = group_into_spans(&flat[..split_at]);
    let tail = group_into_spans(&flat[split_at..]);
    let tail = (!tail.is_empty()).then_some(tail);
    (head, tail)
}

fn group_into_spans(graphemes: &[(String, Vec<(char, Style)>)]) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut current_style = None;
    let mut current_text = String::new();
    for (_, styled_scalars) in graphemes {
        for &(ch, style) in styled_scalars {
            match current_style {
                Some(current) if current == style => current_text.push(ch),
                _ => {
                    if let Some(current) = current_style.take() {
                        out.push(Span::styled(std::mem::take(&mut current_text), current));
                    }
                    current_style = Some(style);
                    current_text.push(ch);
                }
            }
        }
    }
    if let Some(style) = current_style
        && !current_text.is_empty()
    {
        out.push(Span::styled(current_text, style));
    }
    out
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    use ratatui::style::Color;

    #[test]
    fn markdown_provenance_wraps_and_indents_with_the_rendered_cells() {
        let block = render_markdown_message_block("**alpha** beta", 6, 0, 2, Style::default());
        assert_eq!(block.lines.len(), block.copy_cells.len());
        assert_eq!(block.lines.len(), block.copy_newlines_before.len());
        assert!(
            block
                .copy_cells
                .iter()
                .all(|row| row.starts_with(&[None, None]))
        );
        assert_eq!(
            block.copy_newlines_before[1], 0,
            "soft wrapping is not a semantic newline"
        );
        assert!(!block.copy_fragments.is_empty());
    }

    #[test]
    fn markdown_provenance_wrap_boundary_keeps_graphemes_mapped() {
        let block =
            render_markdown_message_block("ab👩\u{200d}💻e\u{301}z", 2, 0, 0, Style::default());
        assert!(block.lines.len() >= 3);
        let emoji_row = block
            .copy_cells
            .iter()
            .find(|row| row.iter().flatten().count() == 2)
            .expect("wide emoji occupies a wrapped row");
        let ids = emoji_row.iter().flatten().copied().collect::<Vec<_>>();
        assert_eq!(ids[0], ids[1], "wide grapheme keeps one fragment identity");
        let copied = block
            .copy_cells
            .iter()
            .flat_map(|row| row.iter().flatten().copied())
            .fold((None, String::new()), |(last, mut text), id| {
                if last != Some(id) {
                    text.push_str(&block.copy_fragments[id as usize].text);
                }
                (Some(id), text)
            })
            .1;
        assert_eq!(copied, "ab👩\u{200d}💻e\u{301}z");
        assert!(block.copy_newlines_before.iter().all(|count| *count == 0));
    }

    #[test]
    fn grapheme_wrap_preserves_styles_inside_atomic_cluster() {
        let red = Style::default().fg(Color::Red);
        let blue = Style::default().fg(Color::Blue);
        let spans = vec![
            Span::raw("ab"),
            Span::styled("e", red),
            Span::styled("\u{301}", blue),
            Span::styled("👩\u{200d}", red),
            Span::styled("💻", blue),
        ];
        let (head, tail) = slice_spans_at_width(spans, 2);
        assert_eq!(
            head.iter()
                .map(|span| span.content.as_ref())
                .collect::<String>(),
            "ab"
        );
        let tail = tail.expect("clusters continue after the first row");
        assert_eq!(tail[0].content.as_ref(), "e");
        assert_eq!(tail[0].style, red);
        assert_eq!(tail[1].content.as_ref(), "\u{301}");
        assert_eq!(tail[1].style, blue);
        assert_eq!(tail[2].content.as_ref(), "👩\u{200d}");
        assert_eq!(tail[2].style, red);
        assert_eq!(tail[3].content.as_ref(), "💻");
        assert_eq!(tail[3].style, blue);
    }
}
