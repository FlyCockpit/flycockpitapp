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
}
