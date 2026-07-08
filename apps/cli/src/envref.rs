//! Environment-variable references inside config strings.
//!
//! The reference syntax is `$NAME`, matching at:
//!   - the very start of the string, or
//!   - immediately after an ASCII whitespace byte.
//!
//! `NAME` is `[A-Za-z_][A-Za-z0-9_]*`. Anything else (`$$`, `Bearer$X`) is
//! left verbatim. The conservative rule lets users write `Bearer $TOKEN`
//! and `$TOKEN` but not surprise themselves with a `$` that appears in
//! the middle of a literal.
//!
//! [`resolve`] returns the expanded string plus the names of any
//! references whose env var is unset; the TUI uses that list to render a
//! yellow "Environment variable not detected" warning under the input.

use std::env;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolved {
    pub value: String,
    /// References whose `$NAME` wasn't found in the environment, in the
    /// order they appear. Each name is reported once even if referenced
    /// multiple times.
    pub missing: Vec<String>,
    /// All `$NAME` references that the resolver recognized, regardless
    /// of whether they were present. Useful for "this string is dynamic".
    pub referenced: Vec<String>,
}

impl Resolved {
    pub fn has_missing(&self) -> bool {
        !self.missing.is_empty()
    }
}

/// Expand `$VAR` references using `std::env::var`.
pub fn resolve(input: &str) -> Resolved {
    resolve_with(input, |k| env::var(k).ok())
}

/// Same as [`resolve`] but lets the caller supply the lookup function.
/// Exposed so tests don't depend on process env state.
pub fn resolve_with<F>(input: &str, lookup: F) -> Resolved
where
    F: Fn(&str) -> Option<String>,
{
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut missing: Vec<String> = Vec::new();
    let mut referenced: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let at_dollar = bytes[i] == b'$';
        let prev_ok = i == 0 || is_ascii_whitespace(bytes[i - 1]);
        if at_dollar
            && prev_ok
            && let Some((name, rest)) = take_var_name(&bytes[i + 1..])
        {
            if !referenced.iter().any(|n| n.as_str() == name) {
                referenced.push(name.to_string());
            }
            match lookup(name) {
                Some(val) => out.push_str(&val),
                None => {
                    // Missing: keep the literal `$NAME` so a later
                    // re-resolve (after the user exports the var)
                    // works without re-typing.
                    out.push('$');
                    out.push_str(name);
                    if !missing.iter().any(|n| n.as_str() == name) {
                        missing.push(name.to_string());
                    }
                }
            }
            i = bytes.len() - rest.len();
            continue;
        }
        // Default path: copy one UTF-8 char.
        let ch_len = utf8_char_len(bytes[i]);
        out.push_str(&input[i..i + ch_len]);
        i += ch_len;
    }
    Resolved {
        value: out,
        missing,
        referenced,
    }
}

fn take_var_name(rest: &[u8]) -> Option<(&str, &[u8])> {
    if rest.is_empty() {
        return None;
    }
    let first = rest[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let end = rest
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
        .unwrap_or(rest.len());
    let name = std::str::from_utf8(&rest[..end]).ok()?;
    Some((name, &rest[end..]))
}

fn is_ascii_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn utf8_char_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first < 0xC0 {
        // continuation byte — should not happen at this position with
        // well-formed UTF-8, but guard against panics.
        1
    } else if first < 0xE0 {
        2
    } else if first < 0xF0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake<'a>(map: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            map.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn expands_at_string_start() {
        let r = resolve_with("$FOO", fake(&[("FOO", "bar")]));
        assert_eq!(r.value, "bar");
        assert!(r.missing.is_empty());
        assert_eq!(r.referenced, vec!["FOO".to_string()]);
    }

    #[test]
    fn expands_after_whitespace() {
        let r = resolve_with("Bearer $TOKEN", fake(&[("TOKEN", "xyz")]));
        assert_eq!(r.value, "Bearer xyz");
    }

    #[test]
    fn does_not_expand_mid_word() {
        let r = resolve_with("foo$BAR", fake(&[("BAR", "x")]));
        assert_eq!(r.value, "foo$BAR");
        assert!(r.referenced.is_empty());
    }

    #[test]
    fn missing_var_reported_and_literal_kept() {
        let r = resolve_with("$NOPE", fake(&[]));
        assert_eq!(r.value, "$NOPE");
        assert_eq!(r.missing, vec!["NOPE".to_string()]);
    }

    #[test]
    fn missing_var_reported_once_when_referenced_multiple_times() {
        let r = resolve_with("$X $X", fake(&[]));
        assert_eq!(r.value, "$X $X");
        assert_eq!(r.missing, vec!["X".to_string()]);
        assert_eq!(r.referenced, vec!["X".to_string()]);
    }

    #[test]
    fn dollar_followed_by_digit_is_left_alone() {
        let r = resolve_with("$1", fake(&[("1", "x")]));
        assert_eq!(r.value, "$1");
    }

    #[test]
    fn dollar_followed_by_underscore_expands() {
        let r = resolve_with("$_X", fake(&[("_X", "ok")]));
        assert_eq!(r.value, "ok");
    }

    #[test]
    fn double_dollar_is_left_verbatim() {
        // `$$` — the second `$` is preceded by a `$`, which isn't
        // whitespace, so no expansion. Inner `$` is consumed as part of
        // the first attempt's name search which fails (no alpha after it).
        let r = resolve_with("$$FOO", fake(&[("FOO", "bar")]));
        assert_eq!(r.value, "$$FOO");
    }

    #[test]
    fn unicode_passthrough() {
        let r = resolve_with("é$X é", fake(&[("X", "🙂")]));
        assert_eq!(r.value, "é$X é");
        // mid-word $ doesn't expand
    }

    #[test]
    fn newline_then_dollar_expands() {
        let r = resolve_with("a\n$X", fake(&[("X", "ok")]));
        assert_eq!(r.value, "a\nok");
    }

    #[test]
    fn has_missing_helper() {
        let mut r = Resolved::default();
        assert!(!r.has_missing());
        r.missing.push("X".into());
        assert!(r.has_missing());
    }
}
