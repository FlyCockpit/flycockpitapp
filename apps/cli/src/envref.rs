//! Environment-variable references inside config strings.
//!
//! The reference syntax is `$NAME` or `${NAME}`, matching at:
//!   - the very start of the string, or
//!   - immediately after an ASCII whitespace byte.
//!
//! `NAME` is `[A-Za-z_][A-Za-z0-9_]*`. Anything else (`$$`, `Bearer$X`) is
//! left verbatim. The conservative rule lets users write `Bearer $TOKEN`
//! and `$TOKEN` but not surprise themselves with a `$` that appears in
//! the middle of a literal. A leading `~` also expands to the user's home
//! directory so every envref-powered config surface shares the same basic
//! path conveniences.
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
    /// All env references that the resolver recognized, regardless of
    /// whether they were present. Useful for "this string is dynamic".
    pub referenced: Vec<String>,
    /// Syntax errors in env references. Callers that send requests with
    /// resolved values should fail rather than forwarding literals.
    pub errors: Vec<String>,
}

impl Resolved {
    pub fn has_missing(&self) -> bool {
        !self.missing.is_empty()
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Expand `$VAR` and `${VAR}` references using `std::env::var`.
pub fn resolve(input: &str) -> Resolved {
    resolve_with_home(
        input,
        |k| env::var(k).ok(),
        env::var("HOME").ok().as_deref(),
    )
}

/// Same as [`resolve`] but lets the caller supply the lookup function.
/// Exposed so tests don't depend on process env state.
pub fn resolve_with<F>(input: &str, lookup: F) -> Resolved
where
    F: Fn(&str) -> Option<String>,
{
    resolve_with_home(input, lookup, env::var("HOME").ok().as_deref())
}

fn resolve_with_home<F>(input: &str, lookup: F, home: Option<&str>) -> Resolved
where
    F: Fn(&str) -> Option<String>,
{
    let expanded_input = expand_leading_tilde(input, home);
    let input = expanded_input.as_str();
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut missing: Vec<String> = Vec::new();
    let mut referenced: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let at_dollar = bytes[i] == b'$';
        let prev_ok = i == 0 || is_ascii_whitespace(bytes[i - 1]);
        if at_dollar && prev_ok {
            if bytes.get(i + 1) == Some(&b'{') {
                match take_braced_var_name(&bytes[i + 2..], i) {
                    Ok(Some((name, consumed))) => {
                        push_ref(&mut referenced, name);
                        match lookup(name) {
                            Some(val) => out.push_str(&val),
                            None => {
                                out.push_str(&input[i..i + consumed]);
                                push_ref(&mut missing, name);
                            }
                        }
                        i += consumed;
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => errors.push(error),
                }
            } else if let Some((name, rest)) = take_var_name(&bytes[i + 1..]) {
                push_ref(&mut referenced, name);
                match lookup(name) {
                    Some(val) => out.push_str(&val),
                    None => {
                        // Missing: keep the literal `$NAME` so a later
                        // re-resolve (after the user exports the var)
                        // works without re-typing.
                        out.push('$');
                        out.push_str(name);
                        push_ref(&mut missing, name);
                    }
                }
                i = bytes.len() - rest.len();
                continue;
            }
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
        errors,
    }
}

fn expand_leading_tilde(input: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return input.to_string();
    };
    if input == "~" {
        return home.to_string();
    }
    if let Some(rest) = input.strip_prefix("~/") {
        return format!("{home}/{rest}");
    }
    input.to_string()
}

fn push_ref(items: &mut Vec<String>, name: &str) {
    if !items.iter().any(|n| n.as_str() == name) {
        items.push(name.to_string());
    }
}

fn take_braced_var_name(rest: &[u8], offset: usize) -> Result<Option<(&str, usize)>, String> {
    let Some(end) = rest.iter().position(|b| *b == b'}') else {
        return Err(format!(
            "unterminated braced env reference at byte {offset}"
        ));
    };
    let name_bytes = &rest[..end];
    if name_bytes.is_empty() {
        return Err(format!("empty braced env reference at byte {offset}"));
    }
    let name = std::str::from_utf8(name_bytes)
        .map_err(|_| format!("invalid braced env reference at byte {offset}"))?;
    if !valid_var_name(name.as_bytes()) {
        return Err(format!(
            "invalid braced env variable name `{name}` at byte {offset}"
        ));
    }
    Ok(Some((name, end + 3)))
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

fn valid_var_name(name: &[u8]) -> bool {
    let Some((&first, rest)) = name.split_first() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && rest.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
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
    fn expands_braced_var() {
        let r = resolve_with("Bearer ${TOKEN}", fake(&[("TOKEN", "xyz")]));
        assert_eq!(r.value, "Bearer xyz");
        assert_eq!(r.referenced, vec!["TOKEN".to_string()]);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn expands_leading_tilde_with_test_home() {
        let r = resolve_with_home("~/agents", fake(&[]), Some("/home/tester"));
        assert_eq!(r.value, "/home/tester/agents");
    }

    #[test]
    fn unmatched_braced_var_reports_byte_offset() {
        let r = resolve_with("${TOKEN", fake(&[("TOKEN", "xyz")]));
        assert_eq!(r.value, "${TOKEN");
        assert!(r.errors[0].contains("byte 0"), "{:?}", r.errors);
        assert!(r.errors[0].contains("unterminated"), "{:?}", r.errors);
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
