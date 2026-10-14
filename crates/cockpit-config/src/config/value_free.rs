//! Value-free projections of deserialization errors.
//!
//! A serde data error quotes the offending input: `invalid type: string
//! "<value>", expected a map`, `unknown variant `<value>``, `invalid type:
//! integer `1234``. In a credential-bearing document (MCP servers, providers,
//! credential files, hooks) that input is routinely the credential itself. A
//! malformed secret field does not license echoing its bytes into an error
//! chain, a warning or a UI. These helpers keep the error's structure (its
//! category, its expectation, line/column, custom messages) and replace every
//! quoted fragment with `…`.

/// `message` with the contents of every `"…"` and `` `…` `` span replaced.
/// Inside a span a backslash escapes the next character, so an escaped
/// quote (`\"`) never closes the span early and leaks the remainder.
pub fn value_free_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut open: Option<char> = None;
    let mut escaped = false;
    for c in message.chars() {
        match open {
            Some(_) if escaped => escaped = false,
            Some(_) if c == '\\' => escaped = true,
            Some(quote) if c == quote => {
                out.push('…');
                out.push(c);
                open = None;
            }
            Some(_) => {}
            None if c == '"' || c == '`' => {
                out.push(c);
                open = Some(c);
            }
            None => out.push(c),
        }
    }
    if open.is_some() {
        out.push('…');
    }
    out
}

/// serde data-error kinds whose message structure is known: `<kind>: <the
/// offending input>, expected <shape>`. Only the kind and the expected shape
/// are kept.
const SERDE_DATA_ERROR_KINDS: &[&str] = &[
    "invalid type",
    "invalid value",
    "invalid length",
    "unknown variant",
    "unknown field",
    "missing field",
    "duplicate field",
];

/// A value-free `anyhow` error for a JSON (de)serialization failure, built
/// from typed facts only — category, the data-error kind and expected
/// shape when serde reports one, and the line/column — never from the
/// input-bearing message text. A custom deserializer message (which may
/// format the input) is reduced to its category.
pub fn json_error(error: &serde_json::Error) -> anyhow::Error {
    use serde_json::error::Category;
    let category = match error.classify() {
        Category::Io => "read error",
        Category::Syntax => "syntax error",
        Category::Data => "invalid data",
        Category::Eof => "unexpected end of input",
    };
    let mut out = category.to_string();
    if matches!(error.classify(), Category::Data) {
        let message = error.to_string();
        let message = match message.rfind(" at line ") {
            Some(at) => &message[..at],
            None => message.as_str(),
        };
        if let Some(kind) = SERDE_DATA_ERROR_KINDS
            .iter()
            .find(|kind| message.starts_with(**kind))
        {
            out.push_str(": ");
            out.push_str(kind);
            if let Some((_, expected)) = message.rsplit_once(", expected ") {
                out.push_str(", expected ");
                out.push_str(&value_free_message(expected));
            }
        }
    }
    if error.line() > 0 {
        out.push_str(&format!(
            " at line {} column {}",
            error.line(),
            error.column()
        ));
    }
    anyhow::anyhow!(out)
}

/// `serde_json::from_str` whose error is [`json_error`].
pub fn from_str<T: serde::de::DeserializeOwned>(input: &str) -> anyhow::Result<T> {
    serde_json::from_str(input).map_err(|error| json_error(&error))
}

/// `serde_json::from_slice` whose error is [`json_error`].
pub fn from_slice<T: serde::de::DeserializeOwned>(input: &[u8]) -> anyhow::Result<T> {
    serde_json::from_slice(input).map_err(|error| json_error(&error))
}

/// `serde_json::from_value` whose error is [`json_error`].
pub fn from_value<T: serde::de::DeserializeOwned>(input: serde_json::Value) -> anyhow::Result<T> {
    serde_json::from_value(input).map_err(|error| json_error(&error))
}

/// A URL with its credential-bearing parts removed, for `Debug` output:
/// userinfo (`user:password@`) is dropped and the query/fragment (which can
/// carry `?token=…` / `#access_token=…`) are reduced to `?…` / `#…`. Scheme,
/// host, port and path stay diagnosable.
pub fn redacted_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        // Not an absolute URL: keep only up to any query/fragment.
        let end = url.find(['?', '#']).unwrap_or(url.len());
        let mut out = url[..end].to_string();
        if end < url.len() {
            out.push_str(if url[end..].starts_with('?') {
                "?…"
            } else {
                "#…"
            });
        }
        return out;
    };
    let authority_start = scheme_end + 3;
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let after = &rest[authority_end..];
    let path_end = after.find(['?', '#']).unwrap_or(after.len());
    let mut out = format!("{}{}{}", &url[..authority_start], host, &after[..path_end]);
    if path_end < after.len() {
        out.push_str(if after[path_end..].starts_with('?') {
            "?…"
        } else {
            "#…"
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_values_are_removed_and_structure_kept() {
        let message = value_free_message(
            "invalid type: string \"sk-live-sentinel-7f3a\", expected a map at line 1 column 9",
        );
        assert!(!message.contains("sk-live-sentinel-7f3a"), "{message}");
        assert!(
            message.contains("expected a map at line 1 column 9"),
            "{message}"
        );
        let message = value_free_message("invalid type: integer `987654321`, expected a string");
        let escaped = value_free_message(
            r#"invalid type: string "prefix\"inner-sentinel\"suffix", expected a map"#,
        );
        assert!(!escaped.contains("inner-sentinel"), "{escaped}");
        assert!(!message.contains("987654321"), "{message}");
        assert_eq!(
            value_free_message("auth_command must name a non-empty executable"),
            "auth_command must name a non-empty executable"
        );
        let error = serde_json::from_str::<std::collections::BTreeMap<String, String>>(
            r#"{"API_KEY": 1234567890123}"#,
        )
        .unwrap_err();
        assert!(!json_error(&error).to_string().contains("1234567890123"));
    }

    #[test]
    fn redacted_url_drops_userinfo_query_and_fragment() {
        let url = redacted_url(
            "https://user:pw-sentinel@mcp.example.test:8443/v1/sse?key=q-sentinel#frag",
        );
        assert_eq!(url, "https://mcp.example.test:8443/v1/sse?…");
        assert_eq!(redacted_url("/relative/path?token=t"), "/relative/path?…");
    }
}
