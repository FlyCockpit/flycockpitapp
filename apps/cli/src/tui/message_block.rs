//! Shared static message-body and message-block layout.
//!
//! The main transcript composes the body result with its live-only chrome
//! (streaming, pin controls, reasoning, hover), while compact read-only views
//! such as `/sessions` add a role/timestamp header. Markdown parsing and
//! word-aware styled wrapping live here so those surfaces cannot drift.

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::tui::markdown;

#[derive(Debug, Clone)]
pub(crate) struct MessageBlock {
    pub(crate) lines: Vec<Line<'static>>,
    pub(crate) continuations: Vec<bool>,
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
    let logical = markdown::render_with_width(text, max_width.max(1));
    layout_markdown_message_lines(logical, max_width, reserve_first, indent, body_style)
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
    let flat: Vec<(char, Style)> = spans
        .iter()
        .flat_map(|span| span.content.chars().map(move |ch| (ch, span.style)))
        .collect();
    let mut used = 0usize;
    let mut hard_split = flat.len();
    let mut whitespace_split = None;
    for (index, (ch, _)) in flat.iter().enumerate() {
        let width = UnicodeWidthChar::width(*ch).unwrap_or(0);
        if index > 0 && used + width > max_width {
            hard_split = index;
            break;
        }
        used += width;
        if used > max_width {
            hard_split = index + 1;
            break;
        }
        if ch.is_whitespace() {
            whitespace_split = Some(index + 1);
        }
    }
    let split_at = whitespace_split.unwrap_or(hard_split);
    let head = group_into_spans(&flat[..split_at]);
    let tail = group_into_spans(&flat[split_at..]);
    let tail = (!tail.is_empty()).then_some(tail);
    (head, tail)
}

fn group_into_spans(chars: &[(char, Style)]) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut current_style = None;
    let mut current_text = String::new();
    for &(ch, style) in chars {
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
    if let Some(style) = current_style
        && !current_text.is_empty()
    {
        out.push(Span::styled(current_text, style));
    }
    out
}
