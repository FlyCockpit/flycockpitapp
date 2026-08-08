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
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Copy provenance emitted from the Markdown event stream.  `text` is exactly
/// what the renderer makes semantic (never a delimiter); source offsets are
/// diagnostic only and are never used to reconstruct clipboard text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CopyFragment {
    pub(crate) id: usize,
    pub(crate) text: String,
    #[allow(dead_code)] // retained for render diagnostics, never extraction
    pub(crate) source: Option<std::ops::Range<usize>>,
    #[allow(dead_code)] // stable semantic identity across viewport slices
    pub(crate) logical_line: usize,
    pub(crate) table_cell: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CopyAtom {
    Fragment(CopyFragment),
    Newline,
}

/// Parse Markdown into semantic clipboard atoms.  This deliberately shares
/// pulldown-cmark's event stream with rendering: formatting/link/code fences
/// are tags and therefore never become copy fragments, while escapes and
/// entities arrive already decoded as visible text.
pub(crate) fn semantic_copy_atoms(src: &str, width: usize) -> Vec<CopyAtom> {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_MATH);
    opts.insert(Options::ENABLE_TABLES);
    let mut atoms = Vec::new();
    let mut id = 0usize;
    let mut logical_line = 0usize;
    let mut table_row = None;
    let mut table_col = 0usize;
    let mut pending_block_break = 0usize;
    let normalized = normalize_backslash_math(src);
    let source_unchanged = normalized == src;
    for (event, range) in Parser::new_ext(&normalized, opts).into_offset_iter() {
        match event {
            Event::Text(text) | Event::Code(text) => {
                if pending_block_break > 0 && !atoms.is_empty() {
                    for _ in 0..pending_block_break {
                        atoms.push(CopyAtom::Newline);
                        logical_line += 1;
                    }
                }
                pending_block_break = 0;
                push_copy_text(
                    &mut atoms,
                    &mut id,
                    &mut logical_line,
                    &text,
                    source_unchanged.then_some(range),
                    table_row.map(|row| (row, table_col)),
                );
            }
            Event::SoftBreak => {
                // The renderer shows a space, but wrapping this space must not
                // manufacture a newline.
                atoms.push(CopyAtom::Fragment(CopyFragment {
                    id,
                    text: " ".into(),
                    source: source_unchanged.then_some(range),
                    logical_line,
                    table_cell: table_row.map(|row| (row, table_col)),
                }));
                id += 1;
            }
            Event::HardBreak => {
                atoms.push(CopyAtom::Newline);
                logical_line += 1;
                pending_block_break = 0;
            }
            Event::Start(Tag::TableHead) => {
                table_row = Some(0);
                table_col = 0;
            }
            Event::Start(Tag::List(_)) => {
                if pending_block_break == 0 && matches!(atoms.last(), Some(CopyAtom::Fragment(_))) {
                    atoms.push(CopyAtom::Newline);
                    logical_line += 1;
                }
            }
            Event::Start(Tag::TableRow) => {
                table_row = Some(table_row.map_or(0, |row| row + 1));
                table_col = 0;
            }
            Event::End(TagEnd::TableCell) => table_col += 1,
            Event::End(TagEnd::Item) => {
                if pending_block_break == 0 {
                    atoms.push(CopyAtom::Newline);
                    logical_line += 1;
                }
            }
            Event::End(TagEnd::TableRow) => {
                atoms.push(CopyAtom::Newline);
                logical_line += 1;
            }
            Event::End(TagEnd::TableHead) => {
                atoms.push(CopyAtom::Newline);
                logical_line += 1;
            }
            Event::End(TagEnd::Table) => {
                table_row = None;
                if matches!(atoms.last(), Some(CopyAtom::Newline)) {
                    atoms.pop();
                    logical_line = logical_line.saturating_sub(1);
                }
                pending_block_break = 2;
            }
            Event::End(TagEnd::Paragraph)
            | Event::End(TagEnd::Heading(_))
            | Event::End(TagEnd::BlockQuote(_)) => pending_block_break = 2,
            Event::End(TagEnd::CodeBlock) => {
                if matches!(atoms.last(), Some(CopyAtom::Newline)) {
                    atoms.pop();
                    logical_line = logical_line.saturating_sub(1);
                }
                pending_block_break = 2;
            }
            Event::End(TagEnd::List(_)) => {
                if matches!(atoms.last(), Some(CopyAtom::Newline)) {
                    atoms.pop();
                    logical_line = logical_line.saturating_sub(1);
                }
                pending_block_break = 2;
            }
            Event::InlineMath(text) => {
                if pending_block_break > 0 && !atoms.is_empty() {
                    for _ in 0..pending_block_break {
                        atoms.push(CopyAtom::Newline);
                        logical_line += 1;
                    }
                }
                pending_block_break = 0;
                let visible =
                    math_render::render_inline(&text).unwrap_or_else(|| format!("${text}$"));
                push_copy_text(
                    &mut atoms,
                    &mut id,
                    &mut logical_line,
                    &visible,
                    source_unchanged.then_some(range),
                    None,
                );
            }
            Event::DisplayMath(text) => {
                if pending_block_break > 0 && !atoms.is_empty() {
                    for _ in 0..pending_block_break {
                        atoms.push(CopyAtom::Newline);
                        logical_line += 1;
                    }
                }
                pending_block_break = 0;
                let visible = math_render::render_display(&text, width)
                    .map(|rows| rows.join("\n"))
                    .unwrap_or_else(|| format!("$$\n{text}\n$$"));
                push_copy_text(
                    &mut atoms,
                    &mut id,
                    &mut logical_line,
                    &visible,
                    source_unchanged.then_some(range),
                    None,
                );
            }
            _ => {}
        }
    }
    while matches!(atoms.last(), Some(CopyAtom::Newline)) {
        atoms.pop();
    }
    atoms
}

fn push_copy_text(
    atoms: &mut Vec<CopyAtom>,
    id: &mut usize,
    logical_line: &mut usize,
    text: &str,
    source: Option<std::ops::Range<usize>>,
    table_cell: Option<(usize, usize)>,
) {
    for (piece_index, piece) in text.split('\n').enumerate() {
        if piece_index > 0 {
            atoms.push(CopyAtom::Newline);
            *logical_line += 1;
        }
        for grapheme in semantic_graphemes(piece) {
            atoms.push(CopyAtom::Fragment(CopyFragment {
                id: *id,
                text: grapheme,
                source: source.clone(),
                logical_line: *logical_line,
                table_cell,
            }));
            *id += 1;
        }
    }
}

/// Small, dependency-free extended-grapheme approximation tailored to cell
/// identity: combining/variation/modifier characters and every ZWJ-linked
/// component stay with their base, as do regional-indicator pairs.
pub(crate) fn semantic_graphemes(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut join_next = false;
    let mut regional_in_last = false;
    for ch in text.chars() {
        let cp = ch as u32;
        let combining = !ch.is_control() && ch.width().unwrap_or(0) == 0
            || (0xFE00..=0xFE0F).contains(&cp)
            || (0x1F3FB..=0x1F3FF).contains(&cp)
            || (0xE0100..=0xE01EF).contains(&cp);
        let regional = (0x1F1E6..=0x1F1FF).contains(&cp);
        if combining || join_next || (regional && regional_in_last) {
            if let Some(last) = out.last_mut() {
                last.push(ch);
            } else {
                out.push(ch.to_string());
            }
        } else {
            out.push(ch.to_string());
        }
        join_next = ch == '\u{200d}';
        regional_in_last = regional && !regional_in_last;
        if !regional {
            regional_in_last = false;
        }
    }
    out
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
    #[cfg(test)]
    {
        RENDER_BYTES.with(|bytes| bytes.set(bytes.get() + src.len()));
        RENDER_CALLS.with(|calls| calls.set(calls.get() + 1));
    }
    if src.is_empty() {
        return vec![Line::default()];
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
    let parser = Parser::new_ext(&normalized, opts);
    let mut emitter = Emitter {
        math_width: width,
        ..Emitter::default()
    };
    for event in parser {
        emitter.handle(event);
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
}

impl Emitter {
    fn handle(&mut self, event: Event) {
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
                if let Some(cell) = self.current_table_cell_mut() {
                    cell.spans
                        .push(Span::styled(typeset, Style::default().fg(MATH_FG)));
                    return;
                }
                self.current
                    .push(Span::styled(typeset, Style::default().fg(MATH_FG)));
            }
            None => {
                // Verbatim raw source, delimiters included, in the normal
                // text style so nothing is dropped.
                let style = self.current_style();
                if let Some(cell) = self.current_table_cell_mut() {
                    cell.spans.push(Span::styled(format!("${latex}$"), style));
                    return;
                }
                self.current.push(Span::styled(format!("${latex}$"), style));
            }
        }
    }

    /// Render a display math span as a multi-line block. Falls back to the
    /// raw `$$…$$` source if unsupported or wider than the viewport.
    fn display_math(&mut self, latex: String) {
        if let Some(cell) = self.current_table_cell_mut() {
            match math_render::render_inline(&latex) {
                Some(typeset) => cell
                    .spans
                    .push(Span::styled(typeset, Style::default().fg(MATH_FG))),
                None => cell.spans.push(Span::styled(
                    format!("$${latex}$$"),
                    Style::default().fg(MATH_FG),
                )),
            }
            return;
        }
        self.flush_line();
        match math_render::render_display(&latex, self.math_width) {
            Some(block) => {
                for row in block {
                    self.lines
                        .push(Line::from(Span::styled(row, Style::default().fg(MATH_FG))));
                }
            }
            None => {
                // Raw source verbatim across its own lines so nothing is
                // dropped and no broken typesetting is shown.
                self.lines.push(Line::from(Span::raw("$$".to_string())));
                for raw in latex.lines() {
                    self.lines.push(Line::from(Span::raw(raw.to_string())));
                }
                if latex.is_empty() {
                    // keep an empty body row for an empty display span
                    self.lines.push(Line::default());
                }
                self.lines.push(Line::from(Span::raw("$$".to_string())));
            }
        }
        self.lines.push(Line::default());
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
                    self.lines.push(Line::from(Span::styled(
                        format!("```{lang}"),
                        Style::default().fg(CODE_FG).add_modifier(Modifier::DIM),
                    )));
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
                    table.current_cell = Some(TableCell { spans: Vec::new() });
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
                self.current.push(Span::raw(format!("{indent}{marker}")));
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
                self.lines.push(Line::from(Span::styled(
                    "```".to_string(),
                    Style::default().fg(CODE_FG).add_modifier(Modifier::DIM),
                )));
                self.lines.push(Line::default());
            }
            TagEnd::List(_) => {
                self.list_stack.pop();
                self.flush_line_then_blank();
            }
            TagEnd::Table => {
                if let Some(table) = self.table.take() {
                    self.emit_table(table);
                    self.lines.push(Line::default());
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
                    self.current.push(Span::styled(
                        expand_tabs(&chunk, start),
                        Style::default().fg(CODE_FG).bg(CODE_BG),
                    ));
                }
                if trimmed_nl.is_some() {
                    if self.current.is_empty() {
                        self.lines.push(Line::default());
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
                self.flush_line();
            }
            if !piece.is_empty() {
                let start = self.current.iter().map(|span| span.content.width()).sum();
                self.current
                    .push(Span::styled(expand_tabs(piece, start), style));
            }
            first = false;
        }
    }

    fn inline_code(&mut self, s: String) {
        if let Some(cell) = self.current_table_cell_mut() {
            let start = cell.spans.iter().map(|span| span.content.width()).sum();
            cell.spans.push(Span::styled(
                expand_tabs(&s, start),
                Style::default().fg(CODE_FG).bg(CODE_BG),
            ));
            return;
        }
        let start = self.current.iter().map(|span| span.content.width()).sum();
        self.current.push(Span::styled(
            expand_tabs(&s, start),
            Style::default().fg(CODE_FG).bg(CODE_BG),
        ));
    }

    fn horizontal_rule(&mut self) {
        self.flush_line();
        self.lines.push(Line::from(Span::styled(
            "─".repeat(40),
            Style::default().fg(QUOTE_FG),
        )));
        self.lines.push(Line::default());
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

    fn table_text(&mut self, s: String) {
        let style = self.current_style();
        if let Some(cell) = self.current_table_cell_mut() {
            let start = cell.spans.iter().map(|span| span.content.width()).sum();
            let text = expand_tabs(&s.replace('\n', " "), start);
            if !text.is_empty() {
                cell.spans.push(Span::styled(text, style));
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
        self.lines.push(Line::from(Span::raw(text)));
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
                let cell = row
                    .cells
                    .get(idx)
                    .cloned()
                    .unwrap_or(TableCell { spans: Vec::new() });
                wrap_spans_to_width(&cell.spans, widths[idx])
            })
            .collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);
        for visual_row in 0..height {
            let mut spans = Vec::new();
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
                spans.extend(cell_line);
                spans.push(Span::raw(format!("{} │", " ".repeat(right_pad))));
            }
            self.lines.push(Line::from(spans));
        }
    }

    fn flush_line(&mut self) {
        if self.current.is_empty() {
            return;
        }
        let spans = std::mem::take(&mut self.current);
        let line = if self.in_block_quote {
            let mut with_bar: Vec<Span<'static>> = Vec::with_capacity(spans.len() + 1);
            with_bar.push(Span::styled(
                "│ ".to_string(),
                Style::default().fg(QUOTE_FG),
            ));
            with_bar.extend(spans);
            Line::from(with_bar)
        } else {
            Line::from(spans)
        };
        self.lines.push(line);
    }

    fn flush_line_then_blank(&mut self) {
        self.flush_line();
        if !matches!(self.lines.last(), Some(l) if l.spans.is_empty()) {
            self.lines.push(Line::default());
        }
    }

    fn finish(mut self) -> Vec<Line<'static>> {
        self.flush_line();
        // Trim trailing blank lines — the chat pane already insets a
        // gap row between entries, so dangling blanks here just widen
        // the gap.
        while matches!(self.lines.last(), Some(l) if l.spans.is_empty()) {
            self.lines.pop();
        }
        if self.lines.is_empty() {
            self.lines.push(Line::default());
        }
        self.lines
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
        semantic_copy_atoms(src, 80)
            .into_iter()
            .map(|atom| match atom {
                CopyAtom::Fragment(fragment) => fragment.text,
                CopyAtom::Newline => "\n".to_string(),
            })
            .collect()
    }

    #[test]
    fn selection_source_map_survives_wrap_and_viewport_slice() {
        let atoms = semantic_copy_atoms("alpha **wide界** omega", 80);
        let ids = atoms
            .iter()
            .filter_map(|atom| match atom {
                CopyAtom::Fragment(fragment) => Some(fragment.id),
                CopyAtom::Newline => None,
            })
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
        let values = semantic_graphemes("界 e\u{301} 👩\u{200d}💻 🇺🇸");
        assert_eq!(
            values,
            vec!["界", " ", "e\u{301}", " ", "👩\u{200d}💻", " ", "🇺🇸"]
        );
    }

    #[test]
    fn selection_tab_cells_copy_one_tab() {
        assert_eq!(copied("`a\tb`"), "a\tb");
    }

    #[test]
    fn selection_scrolled_mid_message_preserves_semantic_identity() {
        let atoms = semantic_copy_atoms("first\nsecond\nthird", 80);
        let second = atoms
            .iter()
            .find_map(|atom| match atom {
                CopyAtom::Fragment(fragment) if fragment.text == "s" => Some(fragment),
                _ => None,
            })
            .unwrap();
        assert_eq!(second.logical_line, 0); // soft breaks remain one semantic line
        assert!(second.id > 0);
    }

    #[test]
    fn selection_table_fragments_exclude_borders_and_padding() {
        let atoms = semantic_copy_atoms("| A | B |\n|---|---|\n| x | y |", 80);
        let cells = atoms
            .iter()
            .filter_map(|atom| match atom {
                CopyAtom::Fragment(fragment) => fragment.table_cell,
                CopyAtom::Newline => None,
            })
            .collect::<Vec<_>>();
        assert!(cells.contains(&(0, 0)) && cells.iter().any(|cell| cell.0 >= 1));
        assert_eq!(copied("| A | B |\n|---|---|\n| x | y |"), "AB\nxy");
    }

    #[test]
    fn selection_unmapped_chrome_never_guesses_source() {
        let text = copied("# **title**\n\n`code`");
        assert_eq!(text, "title\n\ncode");
        assert!(!text.contains('#') && !text.contains('`') && !text.contains('*'));
    }
}
