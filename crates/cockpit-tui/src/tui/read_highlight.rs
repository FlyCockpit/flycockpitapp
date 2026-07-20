//! Tree-sitter-backed display highlighting for captured read/readlock output.

use std::path::Path;

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use tree_sitter::Language as TsLanguage;
use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter};

use crate::tui::theme::{
    METADATA_TEXT, MUTED_COLOR_INDEX, PLAN_YELLOW, SUBAGENT_ORANGE, SUCCESS_TEXT, TOOL_OUTPUT,
};

const HIGHLIGHT_NAMES: &[&str] = &[
    "attribute",
    "comment",
    "constant",
    "constant.builtin",
    "constructor",
    "embedded",
    "function",
    "function.builtin",
    "keyword",
    "module",
    "number",
    "operator",
    "property",
    "punctuation",
    "string",
    "string.special",
    "tag",
    "type",
    "type.builtin",
    "variable",
    "variable.builtin",
    "variable.parameter",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadLanguage {
    Rust,
    TypeScript,
    Tsx,
    JavaScript,
    Jsx,
    Python,
    Go,
    C,
    Cpp,
}

impl ReadLanguage {
    fn from_path(path: &str) -> Option<Self> {
        let path = path
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches(['`', '"', '\'']);
        let ext = Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())?
            .to_ascii_lowercase();
        match ext.as_str() {
            "rs" => Some(Self::Rust),
            "ts" | "mts" | "cts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "js" | "mjs" | "cjs" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            "py" | "pyi" => Some(Self::Python),
            "go" => Some(Self::Go),
            "c" | "h" => Some(Self::C),
            "cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh" => Some(Self::Cpp),
            _ => None,
        }
    }

    fn config(self) -> Option<HighlightConfiguration> {
        let (language, name, highlights, injections, locals): (
            TsLanguage,
            &str,
            String,
            &str,
            &str,
        ) = match self {
            Self::Rust => (
                tree_sitter_rust::LANGUAGE.into(),
                "rust",
                tree_sitter_rust::HIGHLIGHTS_QUERY.to_string(),
                tree_sitter_rust::INJECTIONS_QUERY,
                "",
            ),
            Self::TypeScript => (
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                "typescript",
                tree_sitter_typescript::HIGHLIGHTS_QUERY.to_string(),
                "",
                tree_sitter_typescript::LOCALS_QUERY,
            ),
            Self::Tsx => (
                tree_sitter_typescript::LANGUAGE_TSX.into(),
                "tsx",
                tree_sitter_typescript::HIGHLIGHTS_QUERY.to_string(),
                "",
                tree_sitter_typescript::LOCALS_QUERY,
            ),
            Self::JavaScript => (
                tree_sitter_javascript::LANGUAGE.into(),
                "javascript",
                tree_sitter_javascript::HIGHLIGHT_QUERY.to_string(),
                tree_sitter_javascript::INJECTIONS_QUERY,
                tree_sitter_javascript::LOCALS_QUERY,
            ),
            Self::Jsx => (
                tree_sitter_javascript::LANGUAGE.into(),
                "jsx",
                format!(
                    "{}\n{}",
                    tree_sitter_javascript::HIGHLIGHT_QUERY,
                    tree_sitter_javascript::JSX_HIGHLIGHT_QUERY
                ),
                tree_sitter_javascript::INJECTIONS_QUERY,
                tree_sitter_javascript::LOCALS_QUERY,
            ),
            Self::Python => (
                tree_sitter_python::LANGUAGE.into(),
                "python",
                tree_sitter_python::HIGHLIGHTS_QUERY.to_string(),
                "",
                "",
            ),
            Self::Go => (
                tree_sitter_go::LANGUAGE.into(),
                "go",
                tree_sitter_go::HIGHLIGHTS_QUERY.to_string(),
                "",
                "",
            ),
            Self::C => (
                tree_sitter_c::LANGUAGE.into(),
                "c",
                tree_sitter_c::HIGHLIGHT_QUERY.to_string(),
                "",
                "",
            ),
            Self::Cpp => (
                tree_sitter_cpp::LANGUAGE.into(),
                "cpp",
                tree_sitter_cpp::HIGHLIGHT_QUERY.to_string(),
                "",
                "",
            ),
        };
        let mut config =
            HighlightConfiguration::new(language, name, &highlights, injections, locals).ok()?;
        config.configure(HIGHLIGHT_NAMES);
        Some(config)
    }
}

#[derive(Debug, Clone, Copy)]
struct CodeRange {
    start: usize,
    end: usize,
    style: Style,
}

#[derive(Debug)]
struct ParsedReadLine<'a> {
    number_prefix: Option<&'a str>,
    code: &'a str,
    code_start: usize,
    code_end: usize,
}

pub(crate) fn render_read_output_lines(
    output: &str,
    path_hint: &str,
    base_style: Style,
    syntax: bool,
) -> Vec<Line<'static>> {
    let (parsed, code_source) = parse_read_output(output);
    let ranges = if syntax {
        ReadLanguage::from_path(path_hint)
            .and_then(|lang| highlight_ranges(lang, &code_source, base_style))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    parsed
        .iter()
        .map(|line| {
            let mut spans = vec![Span::styled("    ".to_string(), base_style)];
            if let Some(prefix) = line.number_prefix {
                spans.push(Span::styled(
                    prefix.to_string(),
                    Style::default()
                        .fg(METADATA_TEXT)
                        .add_modifier(Modifier::DIM),
                ));
                spans.extend(styled_code_spans(
                    &code_source,
                    line.code,
                    line.code_start,
                    line.code_end,
                    &ranges,
                    base_style,
                ));
            } else {
                spans.push(Span::styled(line.code.to_string(), base_style));
            }
            Line::from(spans)
        })
        .collect()
}

fn parse_read_output(output: &str) -> (Vec<ParsedReadLine<'_>>, String) {
    let mut parsed = Vec::new();
    let mut code_source = String::new();
    for line in output.split('\n') {
        if let Some((prefix, code)) = split_line_number_prefix(line) {
            let start = code_source.len();
            code_source.push_str(code);
            let end = code_source.len();
            code_source.push('\n');
            parsed.push(ParsedReadLine {
                number_prefix: Some(prefix),
                code,
                code_start: start,
                code_end: end,
            });
        } else {
            parsed.push(ParsedReadLine {
                number_prefix: None,
                code: line,
                code_start: 0,
                code_end: 0,
            });
        }
    }
    (parsed, code_source)
}

fn split_line_number_prefix(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    let leading_ws = line.len().saturating_sub(trimmed.len());
    let digit_len = trimmed
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_len == 0 {
        return None;
    }
    let sep_idx = leading_ws + digit_len;
    let sep = line.as_bytes().get(sep_idx).copied()?;
    if sep != b'|' && sep != b':' {
        return None;
    }
    Some(line.split_at(sep_idx + 1))
}

fn highlight_ranges(lang: ReadLanguage, source: &str, base_style: Style) -> Option<Vec<CodeRange>> {
    let config = lang.config()?;
    let mut highlighter = Highlighter::new();
    let events = highlighter
        .highlight(&config, source.as_bytes(), None, |_| None)
        .ok()?;
    let mut stack = vec![base_style];
    let mut ranges = Vec::new();
    for event in events {
        match event.ok()? {
            HighlightEvent::Source { start, end } => {
                ranges.push(CodeRange {
                    start,
                    end,
                    style: *stack.last().unwrap_or(&base_style),
                });
            }
            HighlightEvent::HighlightStart(highlight) => {
                stack.push(highlight_style(highlight.0, base_style));
            }
            HighlightEvent::HighlightEnd => {
                if stack.len() > 1 {
                    stack.pop();
                }
            }
        }
    }
    Some(ranges)
}

fn highlight_style(index: usize, base_style: Style) -> Style {
    let Some(name) = HIGHLIGHT_NAMES.get(index) else {
        return base_style;
    };
    if *name == "comment" {
        Style::default()
            .fg(Color::Indexed(MUTED_COLOR_INDEX))
            .add_modifier(Modifier::ITALIC)
    } else if name.starts_with("keyword") || name.starts_with("operator") {
        Style::default()
            .fg(PLAN_YELLOW)
            .add_modifier(Modifier::BOLD)
    } else if name.starts_with("string") {
        Style::default().fg(SUCCESS_TEXT)
    } else if name.starts_with("function") || *name == "constructor" {
        Style::default().fg(Color::Cyan)
    } else if name.starts_with("type") || *name == "module" || *name == "tag" {
        Style::default().fg(SUBAGENT_ORANGE)
    } else if name.starts_with("number") || name.starts_with("constant") {
        Style::default().fg(Color::Magenta)
    } else if name.starts_with("property") || name.starts_with("attribute") {
        Style::default().fg(Color::LightBlue)
    } else if name.starts_with("variable") {
        Style::default().fg(TOOL_OUTPUT)
    } else {
        base_style
    }
}

fn styled_code_spans(
    source: &str,
    fallback: &str,
    start: usize,
    end: usize,
    ranges: &[CodeRange],
    base_style: Style,
) -> Vec<Span<'static>> {
    if start == end {
        return vec![Span::styled(fallback.to_string(), base_style)];
    }
    let mut spans = Vec::new();
    let mut cursor = start;
    for range in ranges {
        if range.end <= start || range.start >= end {
            continue;
        }
        let range_start = range.start.max(start);
        let range_end = range.end.min(end);
        if cursor < range_start {
            spans.push(Span::styled(
                source[cursor..range_start].to_string(),
                base_style,
            ));
        }
        if range_start < range_end {
            spans.push(Span::styled(
                source[range_start..range_end].to_string(),
                range.style,
            ));
        }
        cursor = range_end;
    }
    if cursor < end {
        spans.push(Span::styled(source[cursor..end].to_string(), base_style));
    }
    if spans.is_empty() {
        spans.push(Span::styled(fallback.to_string(), base_style));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    #[test]
    fn line_number_prefix_is_styled_distinctly() {
        let lines = render_read_output_lines(
            "1|fn main() {}",
            "main.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );

        assert_eq!(text(&lines[0]), "    1|fn main() {}");
        let number_span = lines[0]
            .spans
            .iter()
            .find(|span| span.content.as_ref() == "1|")
            .expect("number prefix span");
        assert_eq!(number_span.style.fg, Some(METADATA_TEXT));
    }

    #[test]
    fn rust_output_gets_syntax_style_without_rewriting_text() {
        let lines = render_read_output_lines(
            "1|fn main() {\n2|    let name = \"cockpit\";\n3|}",
            "src/main.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );
        let joined = lines.iter().map(text).collect::<Vec<_>>().join("\n");

        assert_eq!(
            joined,
            "    1|fn main() {\n    2|    let name = \"cockpit\";\n    3|}"
        );
        assert!(
            lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .any(|span| span.content.as_ref() == "fn" && span.style.fg == Some(PLAN_YELLOW))
        );
        assert!(
            lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .all(|span| !span.content.contains("\u{1b}"))
        );
    }

    #[test]
    fn unsupported_language_keeps_plain_text_and_line_numbers() {
        let lines = render_read_output_lines(
            "1|plain body",
            "notes.unknown",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );

        assert_eq!(text(&lines[0]), "    1|plain body");
        assert!(lines[0].spans.iter().any(
            |span| span.content.as_ref() == "plain body" && span.style.fg == Some(TOOL_OUTPUT)
        ));
    }

    #[test]
    fn non_numbered_recovery_lines_remain_plain() {
        let lines = render_read_output_lines(
            "Error: `missing.rs` does not exist",
            "missing.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );

        assert_eq!(text(&lines[0]), "    Error: `missing.rs` does not exist");
        assert_eq!(lines[0].spans[1].style.fg, Some(TOOL_OUTPUT));
    }
}
