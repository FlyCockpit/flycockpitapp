//! Markdown → `Vec<Line<'static>>` emitter for the chat pane.
//!
//! Uses `pulldown-cmark` for parsing and walks the event stream to
//! build styled ratatui spans. Scope is deliberately narrow — we
//! support what LLMs actually emit in chat: bold, italic, inline code,
//! fenced code blocks, headings (h1–h3), bullet + ordered lists, block
//! quotes, and GitHub-style tables rendered as boxed text lines. No
//! images, no link rendering beyond showing the label (we keep the
//! `[text](url)` URL inline in muted grey so the user can still copy it).
//!
//! Soft wrapping is the *caller's* job — the chrome already runs lines
//! through `wrap_with_reserved_first_line` so the output here is
//! emitted at logical line boundaries only.

use super::math_render;
use pulldown_cmark::{Alignment, CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::rc::Rc;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Copy provenance emitted from the Markdown event stream.  `text` is exactly
/// what the renderer makes semantic (never a delimiter); source offsets are
/// diagnostic only and are never used to reconstruct clipboard text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CopyFragment {
    pub(crate) id: usize,
    pub(crate) text: String,
    #[allow(dead_code)]
    pub(crate) source: Option<std::ops::Range<usize>>,
    pub(crate) logical_line: usize,
    pub(crate) table_cell: Option<(usize, usize)>,
}

/// Markdown presentation and semantic-copy data produced by one parser pass.
#[derive(Debug, Clone)]
pub(crate) struct RenderedMarkdown {
    pub(crate) lines: Vec<Line<'static>>,
    pub(crate) copy_cells: Vec<Vec<Option<u32>>>,
    pub(crate) copy_newlines_before: Vec<usize>,
    pub(crate) copy_incomplete: Vec<bool>,
    pub(crate) copy_fragments: Rc<Vec<CopyFragment>>,
}

/// Dependency-free terminal grapheme clustering. In addition to zero-width
/// combining/variation/modifier characters and ZWJ-linked emoji, keep the
/// stateful clusters whose scalar widths alone do not describe their terminal
/// identity: regional-indicator pairs, Hangul Jamo syllables, and Indic virama
/// conjuncts.
pub(crate) fn semantic_graphemes(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut join_next = false;
    let mut regional_in_last = false;
    let mut hangul_state = None;
    let mut after_virama = false;
    for ch in text.chars() {
        let cp = ch as u32;
        let combining = !ch.is_control() && ch.width().unwrap_or(0) == 0
            || (0xFE00..=0xFE0F).contains(&cp)
            || (0x1F3FB..=0x1F3FF).contains(&cp)
            || (0xE0100..=0xE01EF).contains(&cp);
        let regional = (0x1F1E6..=0x1F1FF).contains(&cp);
        let hangul = hangul_jamo_class(cp);
        let joins_hangul = matches!(
            (hangul_state, hangul),
            (Some(HangulJamo::L), Some(HangulJamo::L | HangulJamo::V))
                | (Some(HangulJamo::V), Some(HangulJamo::V | HangulJamo::T))
                | (Some(HangulJamo::T), Some(HangulJamo::T))
        );
        if combining || join_next || after_virama || joins_hangul || (regional && regional_in_last)
        {
            if let Some(last) = out.last_mut() {
                last.push(ch);
            } else {
                out.push(ch.to_string());
            }
        } else {
            out.push(ch.to_string());
        }
        join_next = ch == '\u{200d}';
        after_virama = is_virama(cp);
        hangul_state = hangul;
        regional_in_last = regional && !regional_in_last;
        if !regional {
            regional_in_last = false;
        }
    }
    out
}

#[derive(Clone, Copy)]
enum HangulJamo {
    L,
    V,
    T,
}

fn hangul_jamo_class(cp: u32) -> Option<HangulJamo> {
    match cp {
        0x1100..=0x115f | 0xa960..=0xa97c => Some(HangulJamo::L),
        0x1160..=0x11a7 | 0xd7b0..=0xd7c6 => Some(HangulJamo::V),
        0x11a8..=0x11ff | 0xd7cb..=0xd7fb => Some(HangulJamo::T),
        _ => None,
    }
}

fn is_virama(cp: u32) -> bool {
    matches!(
        cp,
        0x094d
            | 0x09cd
            | 0x0a4d
            | 0x0acd
            | 0x0b4d
            | 0x0bcd
            | 0x0c4d
            | 0x0ccd
            | 0x0d3b
            | 0x0d3c
            | 0x0d4d
            | 0x0dca
            | 0x0e3a
            | 0x0f84
            | 0x1039
            | 0x103a
            | 0x1714
            | 0x1734
            | 0x17d2
            | 0x1a60
            | 0x1b44
            | 0x1baa
            | 0x1bab
            | 0xa806
            | 0xa8c4
            | 0xa953
            | 0xa9c0
            | 0xaaf6
            | 0xabed
            | 0x10a3f
            | 0x11046
            | 0x11070
            | 0x11133
            | 0x11134
            | 0x111c0
            | 0x11235
            | 0x112ea
            | 0x1134d
            | 0x11442
            | 0x114c2
            | 0x115bf
            | 0x1163f
            | 0x116b6
            | 0x1172b
            | 0x11839
            | 0x1193d
            | 0x1193e
            | 0x119e0
            | 0x11a34
            | 0x11a47
            | 0x11a99
            | 0x11c3f
            | 0x11d44
            | 0x11d45
            | 0x11d97
            | 0x11f41
            | 0x11f42
    )
}

#[cfg(test)]
thread_local! {
    static RENDER_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RENDER_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_render_counters() {
    RENDER_BYTES.with(|bytes| bytes.set(0));
    RENDER_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn render_byte_count() -> usize {
    RENDER_BYTES.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn render_call_count() -> usize {
    RENDER_CALLS.with(std::cell::Cell::get)
}

const CODE_FG: Color = Color::Indexed(229); // soft yellow
const CODE_BG: Color = Color::Indexed(236); // near-black grey
const HEADING_FG: Color = Color::Indexed(81); // light cyan
const QUOTE_FG: Color = Color::Indexed(244); // mid grey
const LINK_FG: Color = Color::Indexed(75); // sky blue
const MATH_FG: Color = Color::Indexed(151); // soft green
pub(crate) const TAB_STOP: usize = 4;

fn expand_tabs(text: &str, start_col: usize) -> String {
    let mut out = String::with_capacity(text.len());
    let mut col = start_col;
    for ch in text.chars() {
        if ch == '\t' {
            let spaces = TAB_STOP - col % TAB_STOP;
            out.push_str(&" ".repeat(spaces));
            col += spaces;
        } else {
            out.push(ch);
            col += ch.width().unwrap_or(0);
        }
    }
    out
}

/// Parse `src` as Markdown and return one ratatui line per logical
/// rendered row. Empty input renders as a single empty line so the
/// caller's render path stays predictable. `width` is the available
/// content width in columns: a display-math block laid out wider than
/// `width` falls back to its raw source rather than producing broken/
/// wrapped typesetting.
pub fn render_with_width(src: &str, width: usize) -> Vec<Line<'static>> {
    render_with_provenance(src, width).lines
}

pub(crate) fn render_with_provenance(src: &str, width: usize) -> RenderedMarkdown {
    #[cfg(test)]
    {
        RENDER_BYTES.with(|bytes| bytes.set(bytes.get() + src.len()));
        RENDER_CALLS.with(|calls| calls.set(calls.get() + 1));
    }
    if src.is_empty() {
        return RenderedMarkdown {
            lines: vec![Line::default()],
            copy_cells: vec![Vec::new()],
            copy_newlines_before: vec![0],
            copy_incomplete: vec![false],
            copy_fragments: Rc::new(Vec::new()),
        };
    }
    // pulldown-cmark's math extension handles `$…$`/`$$…$$` but not the
    // backslash-delimiter forms `\(…\)`/`\[…\]`. Normalize *closed*
    // backslash delimiters into the `$` forms before parsing; unclosed
    // ones are left verbatim so a mid-stream span stays raw until its
    // closer arrives (streaming correctness).
    let normalized = normalize_backslash_math(src);
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_MATH);
    opts.insert(Options::ENABLE_TABLES);
    let source_unchanged = normalized == src;
    let parser = Parser::new_ext(&normalized, opts).into_offset_iter();
    let mut emitter = Emitter {
        math_width: width,
        ..Emitter::default()
    };
    for (event, range) in parser {
        emitter.handle(event, source_unchanged.then_some(range));
    }
    emitter.finish()
}

/// Rewrite *closed* `\(…\)` → `$…$` and `\[…\]` → `$$…$$` so the
/// pulldown-cmark math extension emits math events for all four delimiter
/// forms. Content inside inline-code backtick runs and fenced code blocks
/// is left untouched (math delimiters there are literal). An *unclosed*
/// `\(`/`\[` is left verbatim — important for streaming, where the closer
/// has not yet arrived and the span must render as raw text, not math.
fn normalize_backslash_math(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    // Track fenced-code state by counting ``` / ~~~ fences at line starts.
    let mut in_fence: Option<char> = None;
    let mut at_line_start = true;
    while i < chars.len() {
        let c = chars[i];
        // Fenced code block detection (``` or ~~~ at line start).
        if at_line_start && (c == '`' || c == '~') {
            let mut run = 0;
            while i + run < chars.len() && chars[i + run] == c {
                run += 1;
            }
            if run >= 3 {
                match in_fence {
                    Some(fc) if fc == c => in_fence = None,
                    None => in_fence = Some(c),
                    _ => {}
                }
                for _ in 0..run {
                    out.push(c);
                }
                i += run;
                at_line_start = false;
                continue;
            }
        }
        if in_fence.is_some() {
            out.push(c);
            at_line_start = c == '\n';
            i += 1;
            continue;
        }
        match c {
            '\n' => {
                out.push(c);
                at_line_start = true;
                i += 1;
            }
            '`' => {
                // Inline code span: copy the opening run, then everything
                // up to a matching-length closing run, verbatim.
                let mut run = 0;
                while i + run < chars.len() && chars[i + run] == '`' {
                    run += 1;
                }
                for _ in 0..run {
                    out.push('`');
                }
                i += run;
                at_line_start = false;
                // Find a closing run of exactly `run` backticks.
                let mut j = i;
                while j < chars.len() {
                    if chars[j] == '`' {
                        let mut close = 0;
                        while j + close < chars.len() && chars[j + close] == '`' {
                            close += 1;
                        }
                        if close == run {
                            for ch in &chars[i..j + close] {
                                out.push(*ch);
                            }
                            i = j + close;
                            break;
                        }
                        j += close;
                    } else {
                        j += 1;
                    }
                }
                if j >= chars.len() {
                    // No closer: copy remainder verbatim.
                    for ch in &chars[i..] {
                        out.push(*ch);
                    }
                    i = chars.len();
                }
            }
            '\\' if i + 1 < chars.len() => {
                at_line_start = false;
                let next = chars[i + 1];
                if next == '(' || next == '[' {
                    let (close_open, close_close, dollars) = if next == '(' {
                        ('\\', ')', "$")
                    } else {
                        ('\\', ']', "$$")
                    };
                    if let Some(end) = find_backslash_close(&chars, i + 2, close_open, close_close)
                    {
                        let inner: String = chars[i + 2..end].iter().collect();
                        // Refuse if the inner content contains a `$` — it
                        // would confuse the math lexer. Leave verbatim.
                        if inner.contains('$') {
                            out.push('\\');
                            out.push(next);
                            i += 2;
                        } else {
                            out.push_str(dollars);
                            out.push_str(&inner);
                            out.push_str(dollars);
                            i = end + 2; // skip the `\)` / `\]`
                        }
                    } else {
                        // Unclosed → leave verbatim (streaming: stays raw).
                        out.push('\\');
                        out.push(next);
                        i += 2;
                    }
                } else {
                    // Other escape (`\$`, `\\`, …): copy both chars so the
                    // backslash keeps its escaping role.
                    out.push('\\');
                    out.push(next);
                    i += 2;
                }
            }
            _ => {
                out.push(c);
                at_line_start = false;
                i += 1;
            }
        }
    }
    out
}

/// Find the index of the opening backslash of a closing `\)` / `\]`
/// starting the search at `from`. Returns the index of the `\`.
fn find_backslash_close(chars: &[char], from: usize, bs: char, closer: char) -> Option<usize> {
    let mut k = from;
    while k + 1 < chars.len() {
        if chars[k] == bs && chars[k + 1] == closer {
            return Some(k);
        }
        // A blank line / paragraph break can't be crossed by a math span;
        // bail so an unterminated opener doesn't swallow the rest of the
        // document.
        if chars[k] == '\n' && k + 1 < chars.len() && chars[k + 1] == '\n' {
            return None;
        }
        k += 1;
    }
    None
}

#[derive(Default)]
struct Emitter {
    /// Available content width in columns; a display-math block wider than
    /// this degrades to raw source.
    math_width: usize,
    lines: Vec<Line<'static>>,
    /// Spans accumulating into the current logical row.
    current: Vec<Span<'static>>,
    current_copy: Vec<Option<u32>>,
    copy_cells: Vec<Vec<Option<u32>>>,
    copy_newlines_before: Vec<usize>,
    copy_fragments: Vec<CopyFragment>,
    next_fragment_id: usize,
    logical_line: usize,
    pending_copy_newlines: usize,
    event_source: Option<std::ops::Range<usize>>,
    /// Stack of style modifiers from open inline tags (bold/italic/etc).
    style_stack: Vec<Style>,
    /// True while inside a fenced/indented code block.
    in_code_block: bool,
    /// True while inside a block quote — we'll prefix each emitted line
    /// with a quote bar.
    in_block_quote: bool,
    /// List nesting state. For each open list, hold the (kind, next-index)
    /// where `kind` is None for bullets and `Some(n)` for ordered lists.
    list_stack: Vec<ListState>,
    table: Option<TableState>,
}

#[derive(Clone, Copy)]
struct ListState {
    ordered_index: Option<u64>,
}

#[derive(Default)]
struct TableState {
    alignments: Vec<Alignment>,
    rows: Vec<TableRow>,
    current_row: Option<TableRow>,
    current_cell: Option<TableCell>,
    in_head: bool,
}

struct TableRow {
    cells: Vec<TableCell>,
    is_header: bool,
}

#[derive(Clone)]
struct TableCell {
    spans: Vec<Span<'static>>,
    copy_cells: Vec<Option<u32>>,
}

impl Emitter {
    fn handle(&mut self, event: Event, source: Option<std::ops::Range<usize>>) {
        self.event_source = source;
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(s) => self.text(s.into_string()),
            Event::Code(s) => self.inline_code(s.into_string()),
            Event::SoftBreak => self.text(" ".to_string()),
            Event::HardBreak => self.flush_line(),
            Event::Rule => self.horizontal_rule(),
            Event::Html(s) | Event::InlineHtml(s) => self.text(s.into_string()),
            Event::InlineMath(s) => self.inline_math(s.into_string()),
            Event::DisplayMath(s) => self.display_math(s.into_string()),
            Event::FootnoteReference(_) | Event::TaskListMarker(_) => {}
        }
    }

    /// Render an inline math span. Falls back to the raw `$…$` source if
    /// the renderer can't typeset it on a single line.
    fn inline_math(&mut self, latex: String) {
        match math_render::render_inline(&latex) {
            Some(typeset) => {
                self.push_semantic_text(typeset, Style::default().fg(MATH_FG));
            }
            None => {
                // Verbatim raw source, delimiters included, in the normal
                // text style so nothing is dropped.
                let style = self.current_style();
                self.push_semantic_text(format!("${latex}$"), style);
            }
        }
    }

    /// Render a display math span as a multi-line block. Falls back to the
    /// raw `$$…$$` source if unsupported or wider than the viewport.
    fn display_math(&mut self, latex: String) {
        if self.table.is_some() {
            let visible =
                math_render::render_inline(&latex).unwrap_or_else(|| format!("$${latex}$$"));
            self.push_semantic_text(visible, Style::default().fg(MATH_FG));
            return;
        }
        self.flush_line();
        match math_render::render_display(&latex, self.math_width) {
            Some(block) => {
                for row in block {
                    let (fragments, cells) = make_copy_fragments(
                        &row,
                        &mut self.next_fragment_id,
                        self.logical_line,
                        None,
                        self.event_source.clone(),
                    );
                    self.copy_fragments.extend(fragments);
                    self.push_output_line(
                        Line::from(Span::styled(row, Style::default().fg(MATH_FG))),
                        cells,
                    );
                    self.logical_line += 1;
                }
            }
            None => {
                // Raw source verbatim across its own lines so nothing is
                // dropped and no broken typesetting is shown.
                self.push_output_line(Line::from(Span::raw("$$".to_string())), vec![None; 2]);
                for raw in latex.lines() {
                    let raw = raw.to_string();
                    let (fragments, cells) = make_copy_fragments(
                        &raw,
                        &mut self.next_fragment_id,
                        self.logical_line,
                        None,
                        self.event_source.clone(),
                    );
                    self.copy_fragments.extend(fragments);
                    self.push_output_line(Line::from(Span::raw(raw)), cells);
                    self.logical_line += 1;
                }
                if latex.is_empty() {
                    // keep an empty body row for an empty display span
                    self.push_output_line(Line::default(), Vec::new());
                }
                self.push_output_line(Line::from(Span::raw("$$".to_string())), vec![None; 2]);
            }
        }
        self.push_output_line(Line::default(), Vec::new());
    }

    fn start(&mut self, tag: Tag) {
        match tag {
            Tag::Paragraph => {}
            Tag::Heading { level, .. } => {
                self.flush_line();
                let hashes = "#".repeat(heading_depth(level));
                self.current.push(Span::styled(
                    format!("{hashes} "),
                    Style::default().fg(HEADING_FG).add_modifier(Modifier::BOLD),
                ));
                self.current_copy
                    .extend(std::iter::repeat_n(None, hashes.len() + 1));
                self.push_style(Style::default().fg(HEADING_FG).add_modifier(Modifier::BOLD));
            }
            Tag::BlockQuote(_) => {
                self.flush_line();
                self.in_block_quote = true;
            }
            Tag::CodeBlock(kind) => {
                self.flush_line();
                self.in_code_block = true;
                if let CodeBlockKind::Fenced(lang) = kind
                    && !lang.is_empty()
                {
                    self.push_output_line(
                        Line::from(Span::styled(
                            format!("```{lang}"),
                            Style::default().fg(CODE_FG).add_modifier(Modifier::DIM),
                        )),
                        vec![None; 3 + UnicodeWidthStr::width(lang.as_ref())],
                    );
                }
            }
            Tag::List(start) => {
                self.flush_line();
                self.list_stack.push(ListState {
                    ordered_index: start,
                });
            }
            Tag::Table(alignments) => {
                self.flush_line();
                self.table = Some(TableState {
                    alignments,
                    ..TableState::default()
                });
            }
            Tag::TableHead => {
                if let Some(table) = &mut self.table {
                    table.in_head = true;
                    table.current_row = Some(TableRow {
                        cells: Vec::new(),
                        is_header: true,
                    });
                }
            }
            Tag::TableRow => {
                if let Some(table) = &mut self.table
                    && table.current_row.is_none()
                {
                    table.current_row = Some(TableRow {
                        cells: Vec::new(),
                        is_header: table.in_head,
                    });
                }
            }
            Tag::TableCell => {
                if let Some(table) = &mut self.table {
                    table.current_cell = Some(TableCell {
                        spans: Vec::new(),
                        copy_cells: Vec::new(),
                    });
                }
            }
            Tag::Item => {
                self.flush_line();
                let depth = self.list_stack.len().saturating_sub(1);
                let indent = "  ".repeat(depth);
                let marker = match self.list_stack.last_mut() {
                    Some(state) => match state.ordered_index {
                        Some(n) => {
                            state.ordered_index = Some(n + 1);
                            format!("{n}. ")
                        }
                        None => "• ".to_string(),
                    },
                    None => "• ".to_string(),
                };
                let prefix = format!("{indent}{marker}");
                self.current_copy
                    .extend(std::iter::repeat_n(None, prefix.width()));
                self.current.push(Span::raw(prefix));
            }
            Tag::Emphasis => self.push_style(Style::default().add_modifier(Modifier::ITALIC)),
            Tag::Strong => self.push_style(Style::default().add_modifier(Modifier::BOLD)),
            Tag::Strikethrough => {
                self.push_style(Style::default().add_modifier(Modifier::CROSSED_OUT));
            }
            Tag::Link { .. } => {
                self.push_style(
                    Style::default()
                        .fg(LINK_FG)
                        .add_modifier(Modifier::UNDERLINED),
                );
            }
            Tag::Image { .. } => self.push_style(Style::default().fg(QUOTE_FG)),
            _ => {}
        }
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph => self.flush_line_then_blank(),
            TagEnd::Heading(_) => {
                self.pop_style();
                self.flush_line_then_blank();
            }
            TagEnd::BlockQuote(_) => {
                self.in_block_quote = false;
                self.flush_line_then_blank();
            }
            TagEnd::CodeBlock => {
                self.in_code_block = false;
                self.flush_line();
                self.push_output_line(
                    Line::from(Span::styled(
                        "```".to_string(),
                        Style::default().fg(CODE_FG).add_modifier(Modifier::DIM),
                    )),
                    vec![None; 3],
                );
                self.push_output_line(Line::default(), Vec::new());
            }
            TagEnd::List(_) => {
                self.list_stack.pop();
                self.flush_line_then_blank();
            }
            TagEnd::Table => {
                if let Some(table) = self.table.take() {
                    self.emit_table(table);
                    self.push_output_line(Line::default(), Vec::new());
                }
            }
            TagEnd::TableHead => {
                if let Some(table) = &mut self.table {
                    if let Some(row) = table.current_row.take() {
                        table.rows.push(row);
                    }
                    table.in_head = false;
                }
            }
            TagEnd::TableRow => {
                if let Some(table) = &mut self.table
                    && let Some(row) = table.current_row.take()
                {
                    table.rows.push(row);
                }
            }
            TagEnd::TableCell => {
                if let Some(table) = &mut self.table
                    && let Some(cell) = table.current_cell.take()
                    && let Some(row) = &mut table.current_row
                {
                    row.cells.push(cell);
                }
            }
            TagEnd::Item => self.flush_line(),
            TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough | TagEnd::Image => {
                self.pop_style();
            }
            TagEnd::Link => {
                self.pop_style();
            }
            _ => {}
        }
    }

    fn text(&mut self, s: String) {
        if self.table.is_some() {
            self.table_text(s);
            return;
        }
        if self.in_code_block {
            for raw in s.split_inclusive('\n') {
                let trimmed_nl = raw.strip_suffix('\n');
                let chunk = trimmed_nl.unwrap_or(raw).to_string();
                if !chunk.is_empty() {
                    let start = self.current.iter().map(|span| span.content.width()).sum();
                    let expanded = expand_tabs(&chunk, start);
                    self.push_semantic_current_source(
                        &chunk,
                        expanded,
                        start,
                        Style::default().fg(CODE_FG).bg(CODE_BG),
                    );
                }
                if trimmed_nl.is_some() {
                    if self.current.is_empty() {
                        self.push_output_line(Line::default(), Vec::new());
                    } else {
                        self.flush_line();
                    }
                }
            }
            return;
        }
        let style = self.current_style();
        // Split on hard newlines (rare in inline content; paragraphs use
        // SoftBreak / HardBreak events) so a stray `\n` in raw HTML
        // doesn't end up inside a span.
        let mut first = true;
        for piece in s.split('\n') {
            if !first {
                if self.current.is_empty() {
                    self.push_output_line(Line::default(), Vec::new());
                } else {
                    self.flush_line();
                }
            }
            if !piece.is_empty() {
                let start = self.current.iter().map(|span| span.content.width()).sum();
                let expanded = expand_tabs(piece, start);
                self.push_semantic_current_source(piece, expanded, start, style);
            }
            first = false;
        }
    }

    fn inline_code(&mut self, s: String) {
        let source = self.event_source.clone();
        let logical_line = self.logical_line;
        let table_cell = self.current_table_coordinates();
        if self.table.is_some() {
            let start = self
                .table
                .as_ref()
                .and_then(|table| table.current_cell.as_ref())
                .map(|cell| cell.spans.iter().map(|span| span.content.width()).sum())
                .unwrap_or(0);
            let expanded = expand_tabs(&s, start);
            let (fragments, cells) = make_copy_fragments_with_tabs(
                &s,
                start,
                &mut self.next_fragment_id,
                logical_line,
                table_cell,
                source,
            );
            self.copy_fragments.extend(fragments);
            if let Some(cell) = self.current_table_cell_mut() {
                cell.copy_cells.extend(cells);
                cell.spans.push(Span::styled(
                    expanded,
                    Style::default().fg(CODE_FG).bg(CODE_BG),
                ));
            }
            return;
        }
        let start = self.current.iter().map(|span| span.content.width()).sum();
        let expanded = expand_tabs(&s, start);
        self.push_semantic_current_source(
            &s,
            expanded,
            start,
            Style::default().fg(CODE_FG).bg(CODE_BG),
        );
    }

    fn horizontal_rule(&mut self) {
        self.flush_line();
        self.push_output_line(
            Line::from(Span::styled("─".repeat(40), Style::default().fg(QUOTE_FG))),
            vec![None; 40],
        );
        self.push_output_line(Line::default(), Vec::new());
    }

    fn push_style(&mut self, style: Style) {
        let merged = self.current_style().patch(style);
        self.style_stack.push(merged);
    }

    fn pop_style(&mut self) {
        self.style_stack.pop();
    }

    fn current_style(&self) -> Style {
        self.style_stack.last().copied().unwrap_or_default()
    }

    fn current_table_cell_mut(&mut self) -> Option<&mut TableCell> {
        self.table.as_mut()?.current_cell.as_mut()
    }

    fn current_table_coordinates(&self) -> Option<(usize, usize)> {
        let table = self.table.as_ref()?;
        Some((table.rows.len(), table.current_row.as_ref()?.cells.len()))
    }

    fn push_semantic_text(&mut self, text: String, style: Style) {
        if self.table.is_some() {
            let source = self.event_source.clone();
            let logical_line = self.logical_line;
            let table_cell = self.current_table_coordinates();
            let (fragments, cells) = make_copy_fragments(
                &text,
                &mut self.next_fragment_id,
                logical_line,
                table_cell,
                source,
            );
            self.copy_fragments.extend(fragments);
            if let Some(cell) = self.current_table_cell_mut() {
                cell.copy_cells.extend(cells);
                cell.spans.push(Span::styled(text, style));
            }
        } else {
            self.push_semantic_current(text, style);
        }
    }

    fn push_semantic_current(&mut self, text: String, style: Style) {
        let table_cell = self.current_table_coordinates();
        let (fragments, cells) = make_copy_fragments(
            &text,
            &mut self.next_fragment_id,
            self.logical_line,
            table_cell,
            self.event_source.clone(),
        );
        self.copy_fragments.extend(fragments);
        self.current_copy.extend(cells);
        self.current.push(Span::styled(text, style));
    }

    fn push_semantic_current_source(
        &mut self,
        semantic: &str,
        rendered: String,
        start: usize,
        style: Style,
    ) {
        let table_cell = self.current_table_coordinates();
        let (fragments, cells) = make_copy_fragments_with_tabs(
            semantic,
            start,
            &mut self.next_fragment_id,
            self.logical_line,
            table_cell,
            self.event_source.clone(),
        );
        self.copy_fragments.extend(fragments);
        self.current_copy.extend(cells);
        self.current.push(Span::styled(rendered, style));
    }

    fn table_text(&mut self, s: String) {
        let style = self.current_style();
        let source = self.event_source.clone();
        let logical_line = self.logical_line;
        let table_cell = self.current_table_coordinates();
        if self.table.is_some() {
            let start = self
                .table
                .as_ref()
                .and_then(|table| table.current_cell.as_ref())
                .map(|cell| cell.spans.iter().map(|span| span.content.width()).sum())
                .unwrap_or(0);
            let text = expand_tabs(&s.replace('\n', " "), start);
            if !text.is_empty() {
                let (fragments, cells) = make_copy_fragments_with_tabs(
                    &s.replace('\n', " "),
                    start,
                    &mut self.next_fragment_id,
                    logical_line,
                    table_cell,
                    source,
                );
                self.copy_fragments.extend(fragments);
                if let Some(cell) = self.current_table_cell_mut() {
                    cell.copy_cells.extend(cells);
                    cell.spans.push(Span::styled(text, style));
                }
            }
        }
    }

    fn emit_table(&mut self, table: TableState) {
        let column_count = table
            .rows
            .iter()
            .map(|row| row.cells.len())
            .max()
            .unwrap_or(0)
            .max(table.alignments.len());
        if column_count == 0 {
            return;
        }

        let widths = table_column_widths(&table, column_count, self.math_width);
        self.push_border("┌", "┬", "┐", '─', &widths);
        for (row_idx, row) in table.rows.iter().enumerate() {
            self.push_table_row(row, &table.alignments, &widths, column_count);
            if row.is_header && table.rows.get(row_idx + 1).is_some() {
                self.push_border("├", "┼", "┤", '─', &widths);
            }
        }
        self.push_border("└", "┴", "┘", '─', &widths);
    }

    fn push_border(
        &mut self,
        left: &str,
        junction: &str,
        right: &str,
        fill: char,
        widths: &[usize],
    ) {
        let mut text = String::new();
        text.push_str(left);
        for (idx, width) in widths.iter().enumerate() {
            text.extend(std::iter::repeat_n(fill, width + 2));
            if idx + 1 == widths.len() {
                text.push_str(right);
            } else {
                text.push_str(junction);
            }
        }
        let width = text.width();
        self.push_output_line(Line::from(Span::raw(text)), vec![None; width]);
    }

    fn push_table_row(
        &mut self,
        row: &TableRow,
        alignments: &[Alignment],
        widths: &[usize],
        column_count: usize,
    ) {
        let wrapped: Vec<Vec<Vec<Span<'static>>>> = (0..column_count)
            .map(|idx| {
                let cell = row.cells.get(idx).cloned().unwrap_or(TableCell {
                    spans: Vec::new(),
                    copy_cells: Vec::new(),
                });
                wrap_spans_to_width(&cell.spans, widths[idx])
            })
            .collect();
        let wrapped_copy: Vec<Vec<Vec<Option<u32>>>> = (0..column_count)
            .map(|idx| {
                let cells = row
                    .cells
                    .get(idx)
                    .map(|cell| cell.copy_cells.as_slice())
                    .unwrap_or_default();
                wrap_copy_cells_for_rows(cells, &wrapped[idx])
            })
            .collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);
        let row_logical_line = self.logical_line;
        for visual_row in 0..height {
            if visual_row > 0 {
                self.pending_copy_newlines = 0;
            }
            let mut spans = Vec::new();
            let mut copy = vec![None];
            spans.push(Span::raw("│"));
            for col in 0..column_count {
                let cell_line = wrapped[col]
                    .get(visual_row)
                    .cloned()
                    .unwrap_or_else(Vec::new);
                let cell_width = spans_width(&cell_line);
                let slack = widths[col].saturating_sub(cell_width);
                let (left_pad, right_pad) =
                    match alignments.get(col).copied().unwrap_or(Alignment::None) {
                        Alignment::Right => (slack, 0),
                        Alignment::Center => (slack / 2, slack - (slack / 2)),
                        Alignment::Left | Alignment::None => (0, slack),
                    };
                spans.push(Span::raw(format!(" {}", " ".repeat(left_pad))));
                copy.extend(std::iter::repeat_n(None, left_pad + 1));
                spans.extend(cell_line);
                copy.extend(
                    wrapped_copy[col]
                        .get(visual_row)
                        .cloned()
                        .unwrap_or_default(),
                );
                spans.push(Span::raw(format!("{} │", " ".repeat(right_pad))));
                copy.extend(std::iter::repeat_n(None, right_pad + 2));
            }
            for fragment_id in copy.iter().flatten().copied() {
                if let Some(fragment) = self.copy_fragments.get_mut(fragment_id as usize) {
                    fragment.logical_line = row_logical_line;
                }
            }
            self.push_output_line(Line::from(spans), copy);
        }
        self.logical_line += 1;
        self.pending_copy_newlines = 1;
    }

    fn flush_line(&mut self) {
        if self.current.is_empty() {
            return;
        }
        let spans = std::mem::take(&mut self.current);
        let mut copy = std::mem::take(&mut self.current_copy);
        let line = if self.in_block_quote {
            let mut with_bar: Vec<Span<'static>> = Vec::with_capacity(spans.len() + 1);
            with_bar.push(Span::styled(
                "│ ".to_string(),
                Style::default().fg(QUOTE_FG),
            ));
            with_bar.extend(spans);
            copy.splice(0..0, [None, None]);
            Line::from(with_bar)
        } else {
            Line::from(spans)
        };
        let width = spans_width(&line.spans);
        copy.resize(width, None);
        self.push_output_line(line, copy);
        self.logical_line += 1;
    }

    fn flush_line_then_blank(&mut self) {
        self.flush_line();
        if !matches!(self.lines.last(), Some(l) if l.spans.is_empty()) {
            self.push_output_line(Line::default(), Vec::new());
        }
    }

    fn push_output_line(&mut self, line: Line<'static>, cells: Vec<Option<u32>>) {
        let has_semantic = cells.iter().any(Option::is_some);
        let is_blank = line.spans.is_empty();
        self.lines.push(line);
        self.copy_cells.push(cells);
        self.copy_newlines_before.push(if has_semantic {
            self.pending_copy_newlines
        } else {
            0
        });
        if has_semantic {
            self.pending_copy_newlines = 1;
        } else if is_blank {
            self.pending_copy_newlines += 1;
        }
    }

    fn finish(mut self) -> RenderedMarkdown {
        self.flush_line();
        // Trim trailing blank lines — the chat pane already insets a
        // gap row between entries, so dangling blanks here just widen
        // the gap.
        while matches!(self.lines.last(), Some(l) if l.spans.is_empty()) {
            self.lines.pop();
            self.copy_cells.pop();
            self.copy_newlines_before.pop();
        }
        if self.lines.is_empty() {
            self.push_output_line(Line::default(), Vec::new());
        }
        let incomplete = vec![false; self.lines.len()];
        RenderedMarkdown {
            lines: self.lines,
            copy_cells: self.copy_cells,
            copy_newlines_before: self.copy_newlines_before,
            copy_incomplete: incomplete,
            copy_fragments: Rc::new(self.copy_fragments),
        }
    }
}

fn table_column_widths(
    table: &TableState,
    column_count: usize,
    available_width: usize,
) -> Vec<usize> {
    let natural: Vec<usize> = (0..column_count)
        .map(|idx| {
            table
                .rows
                .iter()
                .filter_map(|row| row.cells.get(idx))
                .map(|cell| spans_width(&cell.spans))
                .max()
                .unwrap_or(1)
                .max(1)
        })
        .collect();
    let min_table_width = column_count.saturating_mul(3).saturating_add(1);
    let content_budget = available_width.saturating_sub(column_count.saturating_mul(3) + 1);
    if content_budget >= natural.iter().sum::<usize>() {
        return natural;
    }
    if available_width < min_table_width || content_budget < column_count {
        return vec![1; column_count];
    }

    let mut widths = vec![1; column_count];
    let mut remaining = content_budget - column_count;
    while remaining > 0 {
        let mut grown = false;
        for idx in 0..column_count {
            if remaining == 0 {
                break;
            }
            if widths[idx] < natural[idx] {
                widths[idx] += 1;
                remaining -= 1;
                grown = true;
            }
        }
        if !grown {
            break;
        }
    }
    widths
}

fn spans_width(spans: &[Span<'static>]) -> usize {
    spans
        .iter()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .sum()
}

fn make_copy_fragments(
    text: &str,
    next_id: &mut usize,
    logical_line: usize,
    table_cell: Option<(usize, usize)>,
    source: Option<std::ops::Range<usize>>,
) -> (Vec<CopyFragment>, Vec<Option<u32>>) {
    let mut fragments = Vec::new();
    let mut cells = Vec::new();
    for grapheme in semantic_graphemes(text) {
        let id = *next_id;
        *next_id += 1;
        let width = UnicodeWidthStr::width(grapheme.as_str());
        cells.extend(std::iter::repeat_n(Some(id as u32), width));
        fragments.push(CopyFragment {
            id,
            text: grapheme,
            source: source.clone(),
            logical_line,
            table_cell,
        });
    }
    (fragments, cells)
}

fn make_copy_fragments_with_tabs(
    text: &str,
    start_col: usize,
    next_id: &mut usize,
    logical_line: usize,
    table_cell: Option<(usize, usize)>,
    source: Option<std::ops::Range<usize>>,
) -> (Vec<CopyFragment>, Vec<Option<u32>>) {
    let mut fragments = Vec::new();
    let mut cells = Vec::new();
    let mut col = start_col;
    for grapheme in semantic_graphemes(text) {
        let id = *next_id;
        *next_id += 1;
        let width = if grapheme == "\t" {
            TAB_STOP - col % TAB_STOP
        } else {
            grapheme.width()
        };
        cells.extend(std::iter::repeat_n(Some(id as u32), width));
        col += width;
        fragments.push(CopyFragment {
            id,
            text: grapheme,
            source: source.clone(),
            logical_line,
            table_cell,
        });
    }
    (fragments, cells)
}

fn wrap_spans_to_width(spans: &[Span<'static>], width: usize) -> Vec<Vec<Span<'static>>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    let mut current: Vec<Span<'static>> = Vec::new();
    let mut current_width = 0;
    for span in spans {
        let style = span.style;
        for ch in span.content.chars() {
            let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
            if ch == '\n' {
                rows.push(std::mem::take(&mut current));
                current_width = 0;
                continue;
            }
            if current_width > 0 && current_width + ch_width > width {
                rows.push(std::mem::take(&mut current));
                current_width = 0;
            }
            current.push(Span::styled(ch.to_string(), style));
            current_width += ch_width;
            if current_width >= width {
                rows.push(std::mem::take(&mut current));
                current_width = 0;
            }
        }
    }
    if !current.is_empty() || rows.is_empty() {
        rows.push(current);
    }
    rows
}

fn wrap_copy_cells_for_rows(
    cells: &[Option<u32>],
    rows: &[Vec<Span<'static>>],
) -> Vec<Vec<Option<u32>>> {
    let mut offset = 0usize;
    rows.iter()
        .map(|row| {
            let end = (offset + spans_width(row)).min(cells.len());
            let slice = cells[offset..end].to_vec();
            offset = end;
            slice
        })
        .collect()
}

fn heading_depth(level: HeadingLevel) -> usize {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A generous width so display-math layout isn't width-constrained in
    // tests that aren't specifically exercising the too-wide fallback.
    const TEST_WIDTH: usize = 200;

    fn render_to_strings(src: &str) -> Vec<String> {
        render_with_width(src, TEST_WIDTH)
            .into_iter()
            .map(|l| {
                l.spans
                    .into_iter()
                    .map(|s| s.content.into_owned())
                    .collect::<String>()
            })
            .collect()
    }

    fn render_to_strings_width(src: &str, width: usize) -> Vec<String> {
        render_with_width(src, width)
            .into_iter()
            .map(|l| {
                l.spans
                    .into_iter()
                    .map(|s| s.content.into_owned())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn plain_text_round_trips() {
        assert_eq!(render_to_strings("hello world"), vec!["hello world"]);
    }

    #[test]
    fn bold_and_italic_text_keep_visible_content() {
        let s = render_to_strings("**bold** and *italic* and `code`");
        assert_eq!(s.len(), 1);
        assert!(s[0].contains("bold"));
        assert!(s[0].contains("italic"));
        assert!(s[0].contains("code"));
    }

    #[test]
    fn fenced_code_block_includes_fences() {
        let s = render_to_strings("```rust\nfn main() {}\n```");
        assert!(s.iter().any(|l| l.starts_with("```rust")));
        assert!(s.iter().any(|l| l == "```"));
        assert!(s.iter().any(|l| l.contains("fn main()")));
    }

    #[test]
    fn bullet_list_marks_each_item() {
        let s = render_to_strings("- one\n- two\n- three");
        let bullets: Vec<&String> = s.iter().filter(|l| l.contains('•')).collect();
        assert_eq!(bullets.len(), 3);
    }

    #[test]
    fn ordered_list_numbers_items() {
        let s = render_to_strings("1. first\n2. second");
        assert!(s.iter().any(|l| l.starts_with("1. ")));
        assert!(s.iter().any(|l| l.starts_with("2. ")));
    }

    #[test]
    fn heading_prefixed_with_hashes() {
        let s = render_to_strings("# Hello");
        assert!(s.iter().any(|l| l.starts_with("# ")));
    }

    #[test]
    fn block_quote_prefixed_with_bar() {
        let s = render_to_strings("> quoted text");
        assert!(s.iter().any(|l| l.contains('│') && l.contains("quoted")));
    }

    #[test]
    fn table_renders_as_boxed_lines() {
        let s = render_to_strings("| Name | Count |\n| --- | ---: |\n| alpha | 10 |\n| beta | 2 |");
        assert_eq!(
            s,
            vec![
                "┌───────┬───────┐",
                "│ Name  │ Count │",
                "├───────┼───────┤",
                "│ alpha │    10 │",
                "│ beta  │     2 │",
                "└───────┴───────┘",
            ]
        );
    }

    #[test]
    fn table_honors_right_and_center_alignment() {
        let s = render_to_strings("| Right | Center |\n| ---: | :---: |\n| 7 | x |\n| 42 | yy |");
        assert!(s.iter().any(|l| l == "│     7 │   x    │"), "{s:?}");
        assert!(s.iter().any(|l| l == "│    42 │   yy   │"), "{s:?}");
    }

    #[test]
    fn table_preserves_inline_cell_styles() {
        let lines = render_with_width(
            "| Kind | Value |\n| --- | --- |\n| `code` | *em* **strong** [link](https://example.com) $x^2$ |",
            TEST_WIDTH,
        );
        let spans: Vec<_> = lines.into_iter().flat_map(|line| line.spans).collect();
        assert!(
            spans
                .iter()
                .any(|span| span.style.fg == Some(CODE_FG) && span.style.bg == Some(CODE_BG)),
            "code style missing"
        );
        assert!(
            spans
                .iter()
                .any(|span| span.style.add_modifier.contains(Modifier::ITALIC)),
            "italic style missing"
        );
        assert!(
            spans
                .iter()
                .any(|span| span.style.add_modifier.contains(Modifier::BOLD)),
            "bold style missing"
        );
        assert!(
            spans.iter().any(|span| span.style.fg == Some(LINK_FG)
                && span.style.add_modifier.contains(Modifier::UNDERLINED)),
            "link style missing"
        );
        assert!(
            spans.iter().any(|span| span.style.fg == Some(MATH_FG)),
            "math style missing"
        );
    }

    #[test]
    fn narrow_table_wraps_long_cells_to_width() {
        let s = render_to_strings_width(
            "| Key | Description |\n| --- | --- |\n| alpha | abcdefghijklmnop |",
            16,
        );
        assert!(s.len() > 6, "{s:?}");
        assert!(
            s.iter()
                .all(|line| UnicodeWidthStr::width(line.as_str()) <= 16),
            "{s:?}"
        );
        assert!(s.iter().any(|line| line == "│ alpha │ abcd │"), "{s:?}");
        assert!(s.iter().any(|line| line == "│       │ efgh │"), "{s:?}");
    }

    #[test]
    fn empty_input_yields_one_empty_line() {
        assert_eq!(render_with_width("", TEST_WIDTH).len(), 1);
    }

    #[test]
    fn inline_dollar_math_is_typeset() {
        // `$\frac{1}{2}$` can't render on one line, so inline falls back to
        // raw — but `$x^2$` typesets to `x²` inline.
        let s = render_to_strings("value $x^2$ here");
        assert!(s[0].contains("x²"), "{s:?}");
        assert!(!s[0].contains("x^2"));
    }

    #[test]
    fn inline_fraction_falls_back_to_raw_inline() {
        let s = render_to_strings("the half $\\frac{1}{2}$ done");
        // Multi-row inline → raw source preserved verbatim.
        assert!(s.iter().any(|l| l.contains("$\\frac{1}{2}$")), "{s:?}");
    }

    #[test]
    fn display_fraction_typesets_block() {
        let s = render_to_strings("$$\\frac{1}{2}$$");
        let joined = s.join("\n");
        assert!(joined.contains('─'), "stacked rule present: {s:?}");
        assert!(!joined.contains("$$"), "delimiters stripped: {s:?}");
    }

    #[test]
    fn display_integral_typesets_block() {
        let s = render_to_strings("$$\\int_0^1 x^2\\,dx$$");
        let joined = s.join("\n");
        assert!(joined.contains('∫'), "integral sign: {s:?}");
        assert!(joined.contains('²'), "x squared: {s:?}");
        assert!(joined.contains("dx"), "dx: {s:?}");
    }

    #[test]
    fn backslash_paren_inline_detected() {
        let s = render_to_strings("see \\(x^2\\) now");
        assert!(s[0].contains("x²"), "{s:?}");
    }

    #[test]
    fn backslash_bracket_display_detected() {
        let s = render_to_strings("\\[\\frac{1}{2}\\]");
        let joined = s.join("\n");
        assert!(joined.contains('─'), "{s:?}");
    }

    #[test]
    fn unsupported_display_falls_back_to_raw() {
        let s = render_to_strings("$$\\foobar{x}$$");
        let joined = s.join("\n");
        assert!(joined.contains("$$"), "raw delimiters kept: {s:?}");
        assert!(joined.contains("\\foobar{x}"), "raw body kept: {s:?}");
    }

    #[test]
    fn overwide_display_falls_back_to_raw() {
        // width 2 can't fit a fraction → raw source shown.
        let s: Vec<String> = render_with_width("$$\\frac{abc}{def}$$", 2)
            .into_iter()
            .map(|l| {
                l.spans
                    .into_iter()
                    .map(|sp| sp.content.into_owned())
                    .collect::<String>()
            })
            .collect();
        let joined = s.join("\n");
        assert!(joined.contains("$$"), "raw delimiters kept: {s:?}");
        assert!(joined.contains("\\frac{abc}{def}"), "raw body kept: {s:?}");
    }

    #[test]
    fn unclosed_inline_delimiter_stays_raw() {
        // Mid-stream: `$x^2` with no closer must stay literal text, not be
        // interpreted as math (pulldown-cmark requires the closing `$`).
        let s = render_to_strings("partial $x^2 still streaming");
        let joined = s.join("\n");
        assert!(joined.contains("$x^2"), "raw dollar kept: {s:?}");
        assert!(!joined.contains("x²"), "not typeset yet: {s:?}");
    }

    #[test]
    fn unclosed_backslash_paren_stays_raw() {
        // An unclosed `\(` is left for pulldown-cmark to render as text
        // (it treats `\(` as an escaped paren per CommonMark). The point
        // is that it is NOT typeset as math while the closer is missing.
        let s = render_to_strings("partial \\(x^2 still streaming");
        let joined = s.join("\n");
        assert!(joined.contains("x^2"), "raw body kept: {s:?}");
        assert!(!joined.contains("x²"), "not typeset yet: {s:?}");
    }

    #[test]
    fn math_delimiter_inside_code_span_is_literal() {
        let s = render_to_strings("`\\(x\\)` is code");
        let joined = s.join("\n");
        assert!(joined.contains("\\(x\\)"), "code stays literal: {s:?}");
    }

    fn copied(src: &str) -> String {
        let rendered = render_with_provenance(src, 80);
        let mut out = String::new();
        let mut last = None;
        for (row, cells) in rendered.copy_cells.iter().enumerate() {
            let ids = cells.iter().flatten().copied().collect::<Vec<_>>();
            if !ids.is_empty() && !out.is_empty() {
                out.push_str(&"\n".repeat(rendered.copy_newlines_before[row]));
            }
            for id in ids {
                if last == Some(id) {
                    continue;
                }
                out.push_str(&rendered.copy_fragments[id as usize].text);
                last = Some(id);
            }
        }
        out
    }

    #[test]
    fn selection_source_map_survives_wrap_and_viewport_slice() {
        let rendered = render_with_provenance("alpha **wide界** omega", 80);
        let ids = rendered
            .copy_fragments
            .iter()
            .map(|fragment| fragment.id)
            .collect::<Vec<_>>();
        assert_eq!(ids, (0..ids.len()).collect::<Vec<_>>());
        assert_eq!(copied("alpha **wide界** omega"), "alpha wide界 omega");
    }

    #[test]
    fn selection_copies_rendered_semantics_not_raw_markdown() {
        assert_eq!(
            copied("**outer _inner_ outer** / **outer**"),
            "outer inner outer / outer"
        );
    }

    #[test]
    fn selection_decodes_escapes_and_entities() {
        assert_eq!(copied(r"\*literal\* &amp; &#x1F642; �"), "*literal* & 🙂 �");
        assert_eq!(copied("a Vec<T> and <Button>"), "a Vec<T> and <Button>");
        let html = "<pre>\na\n\nb\n</pre>";
        assert_eq!(copied(html), html);
        assert_eq!(render_to_strings(html).join("\n"), html);
    }

    #[test]
    fn selection_links_copy_visible_label_only() {
        assert_eq!(
            copied("[label](https://secret.example) https://visible.example"),
            "label https://visible.example"
        );
    }

    #[test]
    fn selection_code_copies_content_without_delimiters() {
        assert_eq!(
            copied("`a * b`\n\n```rs\nlet x = 1;\n```"),
            "a * b\n\nlet x = 1;"
        );
    }

    #[test]
    fn selection_wrap_and_block_newlines_match_visible_layout() {
        assert_eq!(
            copied("soft\nwrap  \nhard\n\nblock"),
            "soft wrap\nhard\n\nblock"
        );
    }

    #[test]
    fn selection_grapheme_identity_is_width_safe() {
        let values = semantic_graphemes("界 e\u{301} 👩\u{200d}💻 🇺🇸 क्\u{200d}ष 각");
        assert_eq!(
            values,
            vec![
                "界",
                " ",
                "e\u{301}",
                " ",
                "👩\u{200d}💻",
                " ",
                "🇺🇸",
                " ",
                "क्\u{200d}ष",
                " ",
                "각"
            ]
        );
    }

    #[test]
    fn selection_tab_cells_copy_one_tab() {
        assert_eq!(copied("`a\tb`"), "a\tb");
    }

    #[test]
    fn selection_scrolled_mid_message_preserves_semantic_identity() {
        let rendered = render_with_provenance("first\nsecond\nthird", 80);
        let second = rendered
            .copy_fragments
            .iter()
            .find(|fragment| fragment.text == "s")
            .unwrap();
        assert_eq!(second.logical_line, 0); // soft breaks remain one semantic line
        assert!(second.id > 0);
    }

    #[test]
    fn selection_table_fragments_exclude_borders_and_padding() {
        let rendered = render_with_provenance("| A | B |\n|---|---|\n| x | y |", 80);
        let cells = rendered
            .copy_fragments
            .iter()
            .filter_map(|fragment| fragment.table_cell)
            .collect::<Vec<_>>();
        assert!(cells.contains(&(0, 0)) && cells.iter().any(|cell| cell.0 >= 1));
        assert_eq!(copied("| A | B |\n|---|---|\n| x | y |"), "AB\nxy");
        assert_eq!(
            copied("| math |\n|---|\n| $$\\frac{a}{b}$$ |"),
            "math\n$$\\frac{a}{b}$$"
        );
        let inline_math = render_with_provenance("| $a$ | b |\n|---|---|\n| c | d |", 80);
        assert!(
            inline_math
                .copy_fragments
                .iter()
                .any(|fragment| fragment.text == "a" && fragment.table_cell == Some((0, 0)))
        );
    }

    #[test]
    fn selection_unmapped_chrome_never_guesses_source() {
        let text = copied("# **title**\n\n`code`");
        assert_eq!(text, "title\n\ncode");
        assert!(!text.contains('#') && !text.contains('`') && !text.contains('*'));
    }
}
