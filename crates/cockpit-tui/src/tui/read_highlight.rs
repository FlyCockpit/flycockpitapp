//! Tree-sitter-backed display highlighting for captured read/readlock output.

#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::rc::Rc;
use std::sync::{LazyLock, Mutex};

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

const HIGHLIGHT_CACHE_LIMIT: usize = 8;

#[cfg(test)]
thread_local! {
    static GRAMMAR_BUILDS: Cell<usize> = const { Cell::new(0) };
    static HIGHLIGHT_RUNS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
static TEST_HIGHLIGHT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(Mutex::default);

thread_local! {
    static HIGHLIGHT_CACHE: RefCell<HighlightCache> = RefCell::new(HighlightCache::default());
}

#[cfg(test)]
pub(crate) fn reset_highlight_counters() {
    GRAMMAR_BUILDS.with(|builds| builds.set(0));
    HIGHLIGHT_RUNS.with(|runs| runs.set(0));
}

#[cfg(test)]
pub(crate) fn grammar_build_count() -> usize {
    GRAMMAR_BUILDS.with(Cell::get)
}

#[cfg(test)]
pub(crate) fn highlight_run_count() -> usize {
    HIGHLIGHT_RUNS.with(Cell::get)
}

#[cfg(test)]
pub(crate) fn clear_highlight_caches() {
    HIGHLIGHT_CACHE.with(|cache| cache.borrow_mut().clear());
    ReadLanguage::clear_config_caches_for_tests();
}

#[cfg(test)]
pub(crate) fn highlight_test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_HIGHLIGHT_LOCK
        .lock()
        .expect("highlight test lock poisoned")
}

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

#[derive(Default)]
enum CachedConfig {
    #[default]
    Unbuilt,
    Failed,
    Ready(&'static HighlightConfiguration),
}

static RUST_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static TYPESCRIPT_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static TSX_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static JAVASCRIPT_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static JSX_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static PYTHON_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static GO_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static C_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);
static CPP_CONFIG: LazyLock<Mutex<CachedConfig>> = LazyLock::new(Mutex::default);

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

    fn config(self) -> Option<&'static HighlightConfiguration> {
        let mut slot = self
            .config_cell()
            .lock()
            .expect("highlight config cache poisoned");
        match *slot {
            CachedConfig::Ready(config) => Some(config),
            CachedConfig::Failed => None,
            CachedConfig::Unbuilt => match self.build_config() {
                Some(config) => {
                    let config = Box::leak(Box::new(config));
                    *slot = CachedConfig::Ready(config);
                    Some(config)
                }
                None => {
                    *slot = CachedConfig::Failed;
                    None
                }
            },
        }
    }

    fn config_cell(self) -> &'static Mutex<CachedConfig> {
        match self {
            Self::Rust => &RUST_CONFIG,
            Self::TypeScript => &TYPESCRIPT_CONFIG,
            Self::Tsx => &TSX_CONFIG,
            Self::JavaScript => &JAVASCRIPT_CONFIG,
            Self::Jsx => &JSX_CONFIG,
            Self::Python => &PYTHON_CONFIG,
            Self::Go => &GO_CONFIG,
            Self::C => &C_CONFIG,
            Self::Cpp => &CPP_CONFIG,
        }
    }

    fn build_config(self) -> Option<HighlightConfiguration> {
        #[cfg(test)]
        GRAMMAR_BUILDS.with(|builds| builds.set(builds.get() + 1));

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

    #[cfg(test)]
    fn clear_config_caches_for_tests() {
        for cache in [
            &RUST_CONFIG,
            &TYPESCRIPT_CONFIG,
            &TSX_CONFIG,
            &JAVASCRIPT_CONFIG,
            &JSX_CONFIG,
            &PYTHON_CONFIG,
            &GO_CONFIG,
            &C_CONFIG,
            &CPP_CONFIG,
        ] {
            *cache.lock().expect("highlight config cache poisoned") = CachedConfig::Unbuilt;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HighlightCacheKey {
    output_hash: u64,
    path_hint_hash: u64,
    syntax: bool,
}

#[derive(Default)]
struct HighlightCache {
    entries: HashMap<HighlightCacheKey, Rc<Vec<CodeRange>>>,
    insertion_order: VecDeque<HighlightCacheKey>,
}

impl HighlightCache {
    fn get(&self, key: &HighlightCacheKey) -> Option<Rc<Vec<CodeRange>>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: HighlightCacheKey, ranges: Vec<CodeRange>) -> Rc<Vec<CodeRange>> {
        if !self.entries.contains_key(&key) {
            self.insertion_order.push_back(key);
        }
        let ranges = Rc::new(ranges);
        self.entries.insert(key, Rc::clone(&ranges));
        while self.entries.len() > HIGHLIGHT_CACHE_LIMIT {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        ranges
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
    }
}

#[derive(Debug, Clone, Copy)]
struct CodeRange {
    start: usize,
    end: usize,
    highlight: Option<usize>,
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
            .and_then(|lang| {
                cached_highlight_ranges(lang, output, path_hint, &code_source, syntax, base_style)
            })
            .unwrap_or_default()
    } else {
        Rc::new(Vec::new())
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

fn cached_highlight_ranges(
    lang: ReadLanguage,
    output: &str,
    path_hint: &str,
    code_source: &str,
    syntax: bool,
    base_style: Style,
) -> Option<Rc<Vec<CodeRange>>> {
    let key = HighlightCacheKey {
        output_hash: hash_value(output),
        path_hint_hash: hash_value(path_hint),
        syntax,
    };
    HIGHLIGHT_CACHE.with(|cache| {
        if let Some(ranges) = cache.borrow().get(&key) {
            return Some(ranges);
        }
        let ranges = highlight_ranges(lang, code_source, base_style)?;
        Some(cache.borrow_mut().insert(key, ranges))
    })
}

fn hash_value<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
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

fn highlight_ranges(
    lang: ReadLanguage,
    source: &str,
    _base_style: Style,
) -> Option<Vec<CodeRange>> {
    let config = lang.config()?;
    let mut highlighter = Highlighter::new();
    let events = highlighter
        .highlight(config, source.as_bytes(), None, |_| None)
        .ok()?;
    #[cfg(test)]
    HIGHLIGHT_RUNS.with(|runs| runs.set(runs.get() + 1));

    let mut stack = vec![None];
    let mut ranges = Vec::new();
    let mut previous_end = 0;
    for event in events {
        match event.ok()? {
            HighlightEvent::Source { start, end } => {
                debug_assert!(
                    start >= previous_end,
                    "tree-sitter highlight ranges must be sorted and disjoint"
                );
                previous_end = end;
                ranges.push(CodeRange {
                    start,
                    end,
                    highlight: *stack.last().unwrap_or(&None),
                });
            }
            HighlightEvent::HighlightStart(highlight) => {
                stack.push(Some(highlight.0));
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
    let first = ranges.partition_point(|range| range.end <= start);
    for range in &ranges[first..] {
        if range.start >= end {
            break;
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
                range_style(range, base_style),
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

fn range_style(range: &CodeRange, base_style: Style) -> Style {
    range
        .highlight
        .map(|index| highlight_style(index, base_style))
        .unwrap_or(base_style)
}

#[cfg(test)]
fn styled_code_spans_linear(
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
                range_style(range, base_style),
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

    fn span_signature(spans: &[Span<'static>]) -> Vec<(String, Style)> {
        spans
            .iter()
            .map(|span| (span.content.to_string(), span.style))
            .collect()
    }

    fn rust_fixture(line_count: usize) -> String {
        let mut output = String::from("1|fn generated_fixture() {\n");
        for line in 2..line_count {
            output.push_str(&format!(
                "{line}|    let value_{line} = \"cafe {line}\"; // numero {line}\n"
            ));
        }
        output.push_str(&format!("{line_count}|}}\n"));
        output
    }

    #[test]
    fn line_number_prefix_is_styled_distinctly() {
        let _guard = highlight_test_lock();
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
        let _guard = highlight_test_lock();
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
        let _guard = highlight_test_lock();
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
        let _guard = highlight_test_lock();
        let lines = render_read_output_lines(
            "Error: `missing.rs` does not exist",
            "missing.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );

        assert_eq!(text(&lines[0]), "    Error: `missing.rs` does not exist");
        assert_eq!(lines[0].spans[1].style.fg, Some(TOOL_OUTPUT));
    }

    #[test]
    fn grammar_is_compiled_once_per_language() {
        let _guard = highlight_test_lock();
        clear_highlight_caches();
        reset_highlight_counters();

        let output = rust_fixture(12);
        for _ in 0..3 {
            let _ = render_read_output_lines(
                &output,
                "src/main.rs",
                Style::default().fg(TOOL_OUTPUT),
                true,
            );
        }

        assert_eq!(grammar_build_count(), 1);
    }

    #[test]
    fn identical_output_reuses_cached_highlight_ranges() {
        let _guard = highlight_test_lock();
        clear_highlight_caches();
        reset_highlight_counters();

        let output = rust_fixture(12);
        let _ = render_read_output_lines(
            &output,
            "src/main.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );
        let _ = render_read_output_lines(
            &output,
            "src/main.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );

        assert_eq!(highlight_run_count(), 1);
    }

    #[test]
    fn changed_output_recomputes_highlight_ranges() {
        let _guard = highlight_test_lock();
        clear_highlight_caches();
        reset_highlight_counters();

        let output = "1|fn one() {}\n";
        let changed_same_length = "1|fn two() {}\n";
        assert_eq!(output.len(), changed_same_length.len());

        let _ = render_read_output_lines(
            output,
            "src/main.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );
        let _ = render_read_output_lines(
            changed_same_length,
            "src/main.rs",
            Style::default().fg(TOOL_OUTPUT),
            true,
        );

        assert_eq!(highlight_run_count(), 2);
    }

    #[test]
    fn highlight_cache_evicts_in_insertion_order() {
        let _guard = highlight_test_lock();
        clear_highlight_caches();
        reset_highlight_counters();

        let base_style = Style::default().fg(TOOL_OUTPUT);
        let outputs = (0..=HIGHLIGHT_CACHE_LIMIT)
            .map(|idx| format!("1|fn item_{idx}() {{}}\n"))
            .collect::<Vec<_>>();
        for output in &outputs {
            let _ = render_read_output_lines(output, "src/main.rs", base_style, true);
        }
        assert_eq!(highlight_run_count(), HIGHLIGHT_CACHE_LIMIT + 1);

        let _ = render_read_output_lines(
            &outputs[HIGHLIGHT_CACHE_LIMIT],
            "src/main.rs",
            base_style,
            true,
        );
        assert_eq!(
            highlight_run_count(),
            HIGHLIGHT_CACHE_LIMIT + 1,
            "newest entry should still be cached"
        );

        let _ = render_read_output_lines(&outputs[0], "src/main.rs", base_style, true);
        assert_eq!(
            highlight_run_count(),
            HIGHLIGHT_CACHE_LIMIT + 2,
            "oldest entry should have been evicted"
        );
    }

    #[test]
    fn styled_code_spans_output_is_unchanged_by_binary_search() {
        let _guard = highlight_test_lock();
        clear_highlight_caches();
        reset_highlight_counters();

        let output = rust_fixture(220).replace("cafe", "cafe\u{301}");
        let output = output.replace("numero", "numero\u{301}");
        let (parsed, code_source) = parse_read_output(&output);
        let base_style = Style::default().fg(TOOL_OUTPUT);
        let ranges = highlight_ranges(ReadLanguage::Rust, &code_source, base_style)
            .expect("rust highlight ranges");

        let numbered_lines = parsed
            .iter()
            .filter(|line| line.number_prefix.is_some())
            .count();
        assert!(numbered_lines >= 200);

        for line in parsed.iter().filter(|line| line.number_prefix.is_some()) {
            let fast = styled_code_spans(
                &code_source,
                line.code,
                line.code_start,
                line.code_end,
                &ranges,
                base_style,
            );
            let linear = styled_code_spans_linear(
                &code_source,
                line.code,
                line.code_start,
                line.code_end,
                &ranges,
                base_style,
            );
            assert_eq!(span_signature(&fast), span_signature(&linear));
        }
    }

    #[test]
    fn cached_highlight_ranges_reapply_current_base_style() {
        let _guard = highlight_test_lock();
        clear_highlight_caches();
        reset_highlight_counters();

        let output = "1|fn main() {\n2|    plain_identifier;\n3|}\n";
        let red_lines =
            render_read_output_lines(output, "src/main.rs", Style::default().fg(Color::Red), true);
        assert!(
            red_lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .any(|span| span.style.fg == Some(Color::Red))
        );

        let blue_lines = render_read_output_lines(
            output,
            "src/main.rs",
            Style::default().fg(Color::Blue),
            true,
        );

        assert_eq!(highlight_run_count(), 1);
        assert!(
            blue_lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .any(|span| span.style.fg == Some(Color::Blue))
        );
        assert!(
            blue_lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .all(|span| span.style.fg != Some(Color::Red))
        );
    }
}
