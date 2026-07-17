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

/// One-line summary of a tool call's args for compact display.
pub fn short_args(v: &serde_json::Value) -> String {
    if let Some(map) = v.as_object() {
        let mut out = String::new();
        for (k, val) in map {
            if !out.is_empty() {
                out.push_str(", ");
            }
            let rendered = match val {
                serde_json::Value::String(s) if s.len() <= 40 => format!("{k}=\"{s}\""),
                serde_json::Value::String(s) => format!("{k}=<{}c>", s.len()),
                serde_json::Value::Bool(b) => format!("{k}={b}"),
                serde_json::Value::Number(n) => format!("{k}={n}"),
                other => format!(
                    "{k}={}",
                    other.to_string().chars().take(40).collect::<String>()
                ),
            };
            out.push_str(&rendered);
            if out.chars().count() > 80 {
                out.push('…');
                break;
            }
        }
        out
    } else {
        v.to_string()
    }
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
    fn first_line_trims_and_caps() {
        assert_eq!(first_line("  hello world  \nsecond", 20), "hello world");
        assert_eq!(first_line("abcdef", 3), "abc…");
    }
}
