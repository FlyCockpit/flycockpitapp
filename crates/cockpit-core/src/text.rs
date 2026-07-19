//! Shared text boundary and truncation helpers.

/// Polyfill for nightly-only `str::floor_char_boundary`.
pub fn floor_char_boundary(s: &str, index: usize) -> usize {
    let mut i = index.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub fn ceil_char_boundary(s: &str, index: usize) -> usize {
    let mut i = index.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

pub fn cap_chars(s: &str, max: usize) -> (String, bool) {
    let mut out = String::new();
    let mut chars = s.chars();
    for _ in 0..max {
        let Some(ch) = chars.next() else {
            return (out, false);
        };
        out.push(ch);
    }
    if chars.next().is_some() {
        out.push_str("...");
        (out, true)
    } else {
        (out, false)
    }
}

pub fn first_line_capped(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or("").trim();
    cap_chars(line, max).0
}

pub fn bounded_snippet(detail: &str, max: usize) -> Option<String> {
    let trimmed = detail.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(cap_chars(trimmed, max).0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgStringMode {
    History,
    Compact { inline_cutoff: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgFormatOptions {
    pub value_limit: usize,
    pub multiline: bool,
    pub string_mode: ArgStringMode,
    pub total_limit: Option<usize>,
}

impl ArgFormatOptions {
    pub fn history(value_limit: usize, multiline: bool) -> Self {
        Self {
            value_limit,
            multiline,
            string_mode: ArgStringMode::History,
            total_limit: None,
        }
    }

    pub fn compact() -> Self {
        Self {
            value_limit: 40,
            multiline: false,
            string_mode: ArgStringMode::Compact { inline_cutoff: 40 },
            total_limit: Some(80),
        }
    }
}

pub fn format_args(v: &serde_json::Value, options: ArgFormatOptions) -> String {
    if let Some(map) = v.as_object() {
        let mut out = String::new();
        let separator = if options.multiline { "\n" } else { ", " };
        for (key, value) in map {
            if !out.is_empty() {
                out.push_str(separator);
            }
            out.push_str(key);
            out.push('=');
            out.push_str(&format_arg_value(value, options));
            if let Some(total_limit) = options.total_limit
                && out.chars().count() > total_limit
            {
                out.push('…');
                break;
            }
        }
        out
    } else {
        format_arg_value(v, options)
    }
}

pub fn format_arg_value(value: &serde_json::Value, options: ArgFormatOptions) -> String {
    match value {
        serde_json::Value::String(s) => format_string_arg_value(s, options),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            bounded_preview(&value.to_string(), options.value_limit)
        }
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            let serialized = value.to_string();
            match options.string_mode {
                ArgStringMode::History => bounded_preview(&serialized, options.value_limit),
                ArgStringMode::Compact { .. } => serialized
                    .chars()
                    .take(options.value_limit)
                    .collect::<String>(),
            }
        }
    }
}

fn format_string_arg_value(s: &str, options: ArgFormatOptions) -> String {
    if let ArgStringMode::Compact { inline_cutoff } = options.string_mode
        && s.len() > inline_cutoff
    {
        return format!("<{}c>", s.len());
    }

    let value_limit = match options.string_mode {
        ArgStringMode::History => options.value_limit.saturating_sub(2),
        ArgStringMode::Compact { .. } => usize::MAX,
    };
    let display = if options.multiline {
        bounded_preview(&sanitize_multiline_string(s), value_limit)
    } else {
        single_line_preview(s, value_limit)
    };
    format!("\"{display}\"")
}

fn sanitize_multiline_string(s: &str) -> String {
    s.chars()
        .map(|ch| match ch {
            '\n' => '\n',
            _ if ch.is_control() => ' ',
            _ => ch,
        })
        .collect()
}

fn sanitize_single_line_string(s: &str) -> String {
    s.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn single_line_preview(s: &str, limit: usize) -> String {
    let mut first = s.lines().next().unwrap_or("").to_string();
    if s.contains('\n') {
        first.push_str(" …");
    }
    bounded_preview(&sanitize_single_line_string(&first), limit)
}

fn bounded_preview(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let take = limit.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

/// One-line summary of a tool call's args for compact display.
pub fn short_args(v: &serde_json::Value) -> String {
    format_args(v, ArgFormatOptions::compact())
}

/// First non-empty trimmed line of `s`, capped at `max_chars`. Used for
/// tool-output snippets and subagent prompt previews.
pub fn first_line(s: &str, max_chars: usize) -> String {
    let first = s.lines().next().unwrap_or("").trim();
    if first.chars().count() > max_chars {
        let truncated: String = first.chars().take(max_chars).collect();
        format!("{truncated}…")
    } else {
        first.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_boundary_never_lands_inside_multibyte_codepoint() {
        let text = "ab😀é中".repeat(3);
        for index in 0..=text.len() {
            let floor = floor_char_boundary(&text, index);
            assert!(
                text.is_char_boundary(floor),
                "floor {floor} for index {index}"
            );
            assert!(floor <= index.min(text.len()));
        }
    }

    #[test]
    fn exact_length_input_is_not_truncated() {
        assert_eq!(cap_chars("abcd", 4), ("abcd".to_string(), false));
    }

    #[test]
    fn one_char_over_cap_appends_marker() {
        assert_eq!(cap_chars("abcde", 4), ("abcd...".to_string(), true));
    }

    #[test]
    fn multibyte_input_truncates_at_char_cap() {
        assert_eq!(cap_chars("é😀中x", 3), ("é😀中...".to_string(), true));
    }

    #[test]
    fn empty_snippet_input_is_none() {
        assert_eq!(bounded_snippet("  \n\t  ", 8), None);
    }

    #[test]
    fn no_newline_first_line_uses_whole_input() {
        assert_eq!(first_line_capped("abcdef", 3), "abc...");
    }

    #[test]
    fn short_args_summarizes_common_json_values() {
        let value = serde_json::json!({
            "path": "src/lib.rs",
            "limit": 3,
            "dry_run": true
        });

        let rendered = short_args(&value);

        assert!(rendered.contains("path=\"src/lib.rs\""));
        assert!(rendered.contains("limit=3"));
        assert!(rendered.contains("dry_run=true"));
    }

    #[test]
    fn one_canonical_arg_formatter() {
        let value = serde_json::json!({
            "script": "mcp.invoke(\"cockpit\", \"rename_session\", {\"name\": \"Test session\"})",
            "dry_run": false,
        });

        let history = format_args(&value, ArgFormatOptions::history(240, false));
        let compact = format_args(&value, ArgFormatOptions::compact());

        assert_eq!(
            history,
            "dry_run=false, script=\"mcp.invoke(\"cockpit\", \"rename_session\", {\"name\": \"Test session\"})\""
        );
        assert_eq!(compact, short_args(&value));
    }

    #[test]
    fn compact_mode_preserves_char_count_elision() {
        let long = "x".repeat(41);
        let inline = "x".repeat(40);
        let value = serde_json::json!({ "body": long });
        let inline_value = serde_json::json!({ "body": inline });

        let compact = format_args(&value, ArgFormatOptions::compact());
        let compact_inline = format_args(&inline_value, ArgFormatOptions::compact());
        let history = format_args(&value, ArgFormatOptions::history(20, false));

        assert_eq!(compact, "body=<41c>");
        assert_eq!(compact_inline, format!("body=\"{}\"", "x".repeat(40)));
        assert_eq!(history, "body=\"xxxxxxxxxxxxxxxxx…\"");
    }

    #[test]
    fn first_line_trims_and_caps() {
        assert_eq!(first_line("  hello world  \nsecond", 20), "hello world");
        assert_eq!(first_line("abcdef", 3), "abc…");
    }
}
