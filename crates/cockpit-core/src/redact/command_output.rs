//! Substitution-site novel-secret scrub for freshly captured `!`-command
//! output (GOALS §7; issue #279).
//!
//! [`RedactionTable::scrub`] only replaces literals already registered in
//! the table. A skill `!`-command can surface a *novel* secret the table has
//! never seen — `` !`cat .env` ``, `` !`aws sts get-session-token` `` — and
//! table-based dispatch-time scrubbing then finds nothing to replace. This
//! module closes that gap at the substitution site itself: before the
//! captured output enters context (and with it the provider request and
//! every export), secret-shaped key/value pairs, XML elements, and PEM
//! private-key blocks are replaced with the table's placeholder.
//!
//! Classification is deliberately shape-based and fail-closed: a
//! `KEY=VALUE` pair whose key looks like a secret
//! ([`is_secret_shaped_key`], the same predicate the env / dotenv /
//! structured collectors use) has its value replaced even though the table
//! cannot know the value. Values under the [`NOVEL_SECRET_VALUE_MIN_LEN`]
//! floor stay visible (ports, counts, `yes`/`no` flags), mirroring the
//! `min_secret_length` prune in table building.

use super::{RedactionTable, is_secret_shaped_key};

/// The value-length floor for novel substitution-site redaction. Mirrors
/// the `min_secret_length` default (`RedactConfig::default()`); values at
/// or above it under a secret-shaped key are replaced with the placeholder.
const NOVEL_SECRET_VALUE_MIN_LEN: usize = 8;

impl RedactionTable {
    /// Redact *novel* secret-shaped values in freshly captured `!`-command
    /// output — values this table has no entry for, so [`Self::scrub`]
    /// alone cannot catch them. Recognizes, per line:
    ///
    /// - `KEY=VALUE` assignments (dotenv / shell `env` style), including
    ///   mid-line fragments and `export ` / quoted prefixes, since echoed
    ///   command text quotes assignments inline,
    /// - `KEY: VALUE` / `"KEY": "VALUE",` (YAML / JSON style, quote style
    ///   and a trailing comma preserved),
    /// - `<Tag>VALUE</Tag>` XML elements with secret-shaped tag names,
    /// - `-----BEGIN … PRIVATE KEY-----` … `-----END … PRIVATE KEY-----`
    ///   PEM blocks (the whole block becomes one placeholder),
    ///
    /// when the key/tag is [`is_secret_shaped_key`]-shaped and the value
    /// clears the [`NOVEL_SECRET_VALUE_MIN_LEN`] floor. Keys, structure,
    /// and surrounding text are preserved; only the secret-shaped value
    /// is replaced with this table's placeholder.
    ///
    /// Honors the config-level opt-out exactly like [`Self::scrub`]: a
    /// disabled table returns `body` unchanged. Idempotent: a value already
    /// equal to the placeholder is left alone, so re-scrubbing rendered
    /// output is byte-stable.
    pub(crate) fn scrub_novel_command_output_secrets(&self, body: &str) -> String {
        if self.disabled {
            return body.to_string();
        }
        let mut out = String::with_capacity(body.len());
        let mut in_private_key_block = false;
        for line in body.split_inclusive('\n') {
            let (content, newline) = match line.strip_suffix('\n') {
                Some(content) => (content, "\n"),
                None => (line, ""),
            };
            if in_private_key_block {
                // The whole block collapsed to one placeholder at its BEGIN
                // fence; keep dropping lines (the END fence included) until
                // the block closes.
                if is_private_key_fence(content, "-----END") {
                    in_private_key_block = false;
                }
                continue;
            }
            if is_private_key_fence(content, "-----BEGIN") {
                out.push_str(&self.placeholder);
                out.push_str(newline);
                in_private_key_block = true;
                continue;
            }
            let xml = scrub_secret_shaped_xml(content, &self.placeholder);
            let assignments = scrub_secret_shaped_assignments(&xml, &self.placeholder);
            let pairs = scrub_secret_shaped_colon_pairs(&assignments, &self.placeholder);
            out.push_str(&pairs);
            out.push_str(newline);
        }
        out
    }
}

/// `true` when `line` is a PEM `-----BEGIN`/`-----END` fence for a private
/// key block (RSA / EC / OPENSSH / ENCRYPTED … — every spelling carries the
/// literal `PRIVATE KEY-----`).
fn is_private_key_fence(line: &str, fence: &str) -> bool {
    line.contains(fence) && line.contains("PRIVATE KEY-----")
}

/// Replace the inner text of every `<tag>value</tag>` element on `line`
/// whose tag name is secret-shaped and whose value clears the length floor.
/// Tags without a matching close on the same line are passed through
/// untouched (multi-line XML values are not guessed at).
fn scrub_secret_shaped_xml(line: &str, placeholder: &str) -> String {
    if !line.contains('<') {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        if line.as_bytes()[i] != b'<' {
            // Copy up to (but not including) the next `<`, or the rest of
            // the line if there's no further one.
            let end = line[i + 1..]
                .find('<')
                .map_or(line.len(), |rel| i + 1 + rel);
            out.push_str(&line[i..end]);
            i = end;
            continue;
        }
        // Try to read `<tag>` at `i` and, when the tag is secret-shaped,
        // a `<tag>value</tag>` element with a scrubbable value.
        let after_open = &line[i + 1..];
        if let Some(gt_rel) = after_open.find('>')
            && is_xml_tag_name(&after_open[..gt_rel])
            && is_secret_shaped_key(&after_open[..gt_rel])
        {
            let tag = &after_open[..gt_rel];
            let value_start = i + 1 + gt_rel + 1;
            let close_tag = format!("</{tag}>");
            if let Some(close_rel) = line[value_start..].find(close_tag.as_str()) {
                let value_end = value_start + close_rel;
                let value = &line[value_start..value_end];
                if value.len() >= NOVEL_SECRET_VALUE_MIN_LEN && value != placeholder {
                    out.push_str(&line[i..value_start]);
                    out.push_str(placeholder);
                    i = value_end + close_tag.len();
                    continue;
                }
            }
        }
        // Not a scrubbable element: keep the `<` and continue scanning
        // after it so nested / unrelated markup still gets its own chance.
        out.push('<');
        i += 1;
    }
    out
}

/// XML element names: non-empty, ASCII letters/digits plus `_ . - :` (the
/// colon keeps namespace-prefixed tags like `<aws:SecretAccessKey>`
/// classifiable — `is_secret_shaped_key` splits on it).
fn is_xml_tag_name(tag: &str) -> bool {
    !tag.is_empty()
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ':'))
}

/// Scrub every `KEY=VALUE` assignment on `line` whose key is secret-shaped
/// and whose value clears the length floor — including mid-line fragments,
/// since both command output and echoed command text quote assignments
/// inline (`TOKEN=… ./run.sh`, `echo "DB_PASSWORD=…"`). A boundary char
/// (line start, whitespace, quote, or backtick) must sit immediately
/// before the key, so prose and markup fragments are not reinterpreted as
/// keys. Quoted values lose their quotes; keys and surroundings survive.
fn scrub_secret_shaped_assignments(content: &str, placeholder: &str) -> String {
    if !content.contains('=') {
        return content.to_string();
    }
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while let Some(eq_rel) = content[i..].find('=') {
        let eq = i + eq_rel;
        // The key candidate runs back from `=` over bare key characters.
        let mut key_start = eq;
        while key_start > 0 && is_bare_key_char(bytes[key_start - 1]) {
            key_start -= 1;
        }
        let key = &content[key_start..eq];
        let at_boundary =
            key_start == 0 || matches!(bytes[key_start - 1], b' ' | b'\t' | b'"' | b'\'' | b'`');
        // When the key sits inside a quoted shell string (`echo "KEY=…"`),
        // the value ends at that string's closing quote.
        let opening_quote = match key_start.checked_sub(1).and_then(|idx| bytes.get(idx)) {
            Some(&q @ (b'"' | b'\'')) => Some(q),
            _ => None,
        };
        let mut redacted: Option<(usize, usize)> = None;
        if at_boundary
            && command_output_key_qualifies(key)
            && let Some((value_start, value_end)) =
                assignment_value_span(content, eq + 1, opening_quote)
        {
            let value = &content[value_start..value_end];
            if value.len() >= NOVEL_SECRET_VALUE_MIN_LEN && value != placeholder {
                redacted = Some((value_start, value_end));
            }
        }
        if let Some((value_start, value_end)) = redacted {
            out.push_str(&content[i..value_start]);
            out.push_str(placeholder);
            i = value_end;
        } else {
            out.push_str(&content[i..eq + 1]);
            i = eq + 1;
        }
    }
    out.push_str(&content[i..]);
    out
}

/// The value span `(start, end)` of an assignment whose `=` ends at
/// `after_eq - 1`: leading whitespace is skipped, a value that opens with a
/// quote runs to its closing quote (the span includes both quotes), a value
/// whose key sat inside a quoted shell string (`opening_quote`) runs to
/// that string's closing quote (the quote itself stays outside the span),
/// and a bare value runs to the next whitespace or the end of the line.
/// `None` when there is no value on this line.
fn assignment_value_span(
    content: &str,
    after_eq: usize,
    opening_quote: Option<u8>,
) -> Option<(usize, usize)> {
    let rest = content.get(after_eq..)?;
    let start = after_eq + (rest.len() - rest.trim_start().len());
    let first = *content.as_bytes().get(start)?;
    if first == b'"' || first == b'\'' {
        let close_rel = content[start + 1..].find(first as char)?;
        Some((start, start + 1 + close_rel + 1))
    } else if let Some(quote) = opening_quote {
        let close_rel = content[start..].find(quote as char)?;
        Some((start, start + close_rel))
    } else {
        let end = content[start..]
            .find(char::is_whitespace)
            .map_or(content.len(), |rel| start + rel);
        Some((start, end))
    }
}

/// Scrub a line-anchored `KEY: VALUE` / `"KEY": "VALUE",` pair (YAML / JSON
/// style) whose key is secret-shaped and whose value clears the length
/// floor. Indentation, the quote style, and a JSON trailing comma are
/// preserved in the rebuild.
fn scrub_secret_shaped_colon_pairs(content: &str, placeholder: &str) -> String {
    if !content.contains(':') {
        return content.to_string();
    }
    let indent = content.len() - content.trim_start().len();
    let head = &content[indent..];
    // Key: JSON-style quoted, or a bare token running to the `:`.
    let (key, after_key) = if let Some(rest) = head.strip_prefix('"') {
        let Some(close_rel) = rest.find('"') else {
            return content.to_string();
        };
        (&head[1..1 + close_rel], indent + 1 + close_rel + 1)
    } else {
        let Some(sep_rel) = head.find(':') else {
            return content.to_string();
        };
        (&head[..sep_rel], indent + sep_rel)
    };
    if !command_output_key_qualifies(key) {
        return content.to_string();
    }
    // The separator: the first non-whitespace char after the key must be
    // the `:` itself.
    let after = &content[after_key..];
    let ws = after.len() - after.trim_start().len();
    let sep_at = after_key + ws;
    if !content[sep_at..].starts_with(':') {
        return content.to_string();
    }
    let value_off = sep_at + 1;
    let raw = &content[value_off..];
    let lead_ws = raw.len() - raw.trim_start().len();
    let value_start = value_off + lead_ws;
    let rest = &content[value_start..];
    let trimmed_end = rest.trim_end().len();
    let trailing = &rest[trimmed_end..];
    let mut value_and_close = &rest[..trimmed_end];
    // A JSON member's trailing comma sits outside the value.
    let mut comma = false;
    if let Some(stripped) = value_and_close.strip_suffix(',') {
        value_and_close = stripped.trim_end();
        comma = true;
    }
    // Optional surrounding quotes are preserved in the rebuild.
    let quote = value_and_close
        .chars()
        .next()
        .filter(|c| *c == '"' || *c == '\'');
    let value = match quote {
        Some(q) if value_and_close.len() >= 2 => {
            if !value_and_close.ends_with(q) {
                // Unbalanced quote: don't guess what belongs to the value.
                return content.to_string();
            }
            &value_and_close[1..value_and_close.len() - 1]
        }
        _ => value_and_close,
    };
    if value.len() < NOVEL_SECRET_VALUE_MIN_LEN || value == placeholder {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..value_start]);
    if let Some(q) = quote {
        out.push(q);
    }
    out.push_str(placeholder);
    if let Some(q) = quote {
        out.push(q);
    }
    if comma {
        out.push(',');
    }
    out.push_str(trailing);
    out
}

/// Keys eligible for novel-value redaction: non-empty, starting with an
/// alphanumeric, free of characters that make the "key" a fragment of
/// prose, markup, or a prior assignment rather than a real config key, and
/// secret-shaped. Whitespace is rejected on purpose so prose like
/// `the token: see the docs` never matches.
fn command_output_key_qualifies(key: &str) -> bool {
    !key.is_empty()
        && key.starts_with(|c: char| c.is_ascii_alphanumeric())
        && !key
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\'' | '/' | '\\' | '='))
        && is_secret_shaped_key(key)
}

/// Bare key characters for assignment scan-back: ASCII alphanumerics plus
/// the separators real config keys use (`_`, `.`, `-`, `@`). Multibyte
/// characters stop the scan, so a non-ASCII run before `=` is never sliced
/// or misread as a key.
fn is_bare_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'@')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::RedactConfig;
    use std::path::Path;

    const PH: &str = "[ph]";

    fn table_with_placeholder(placeholder: &str) -> RedactionTable {
        let cfg = RedactConfig {
            placeholder: placeholder.to_string(),
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            ..RedactConfig::default()
        };
        RedactionTable::build(&cfg, Path::new("/")).unwrap()
    }

    #[test]
    fn dotenv_style_assignment_is_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("API_TOKEN=novel-secret-value-123"),
            "API_TOKEN=[ph]"
        );
    }

    #[test]
    fn export_prefix_and_midline_assignment_are_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "export DATABASE_PASSWORD=hunter2-super-secret"
            ),
            "export DATABASE_PASSWORD=[ph]"
        );
        // Mid-line fragments (echoed command text) are caught too; the
        // surrounding shell syntax survives.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "run with AWS_SECRET_ACCESS_KEY=wJalr-secret-987654 now"
            ),
            "run with AWS_SECRET_ACCESS_KEY=[ph] now"
        );
    }

    #[test]
    fn quoted_assignment_value_is_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("echo \"DB_PASSWORD=novel-pw-9f1a2b3c\""),
            "echo \"DB_PASSWORD=[ph]\""
        );
    }

    #[test]
    fn json_member_preserves_quotes_and_comma() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "  \"SecretAccessKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYZ\","
            ),
            "  \"SecretAccessKey\": \"[ph]\","
        );
    }

    #[test]
    fn yaml_colon_pair_is_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("auth-token: gh-this-is-not-a-real-token-42"),
            "auth-token: [ph]"
        );
    }

    #[test]
    fn xml_element_is_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "<SecretAccessKey>wJalr-secret-987654</SecretAccessKey>"
            ),
            "<SecretAccessKey>[ph]</SecretAccessKey>"
        );
        // Namespace-prefixed tags classify via `is_secret_shaped_key`
        // segment splitting.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "<aws:SessionToken>fqeyr-token-1234</aws:SessionToken>"
            ),
            "<aws:SessionToken>[ph]</aws:SessionToken>"
        );
    }

    #[test]
    fn pem_private_key_block_collapses_to_placeholder() {
        let table = table_with_placeholder(PH);
        let body = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAbase64data==\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(table.scrub_novel_command_output_secrets(body), "[ph]\n");
    }

    #[test]
    fn short_values_and_plain_keys_pass_through() {
        let table = table_with_placeholder(PH);
        // Below the length floor: ports, counts, flags stay visible.
        assert_eq!(
            table.scrub_novel_command_output_secrets("GITHUB_TOKEN=abc123"),
            "GITHUB_TOKEN=abc123"
        );
        // Non-secret keys are never touched.
        assert_eq!(
            table.scrub_novel_command_output_secrets("LOG_LEVEL=debug-verbose"),
            "LOG_LEVEL=debug-verbose"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("PORT: 8080"),
            "PORT: 8080"
        );
    }

    #[test]
    fn prose_and_markup_lines_are_not_mangled() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("the token: see the docs for details"),
            "the token: see the docs for details"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("url: https://example.com/x"),
            "url: https://example.com/x"
        );
        // A query-string assignment is not at a key boundary.
        assert_eq!(
            table.scrub_novel_command_output_secrets("fetch https://x.test/?token=abcdefgh1234"),
            "fetch https://x.test/?token=abcdefgh1234"
        );
    }

    #[test]
    fn already_redacted_value_is_idempotent() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("API_TOKEN=[ph]"),
            "API_TOKEN=[ph]"
        );
        let once = table.scrub_novel_command_output_secrets("API_TOKEN=novel-secret-value-123");
        assert_eq!(table.scrub_novel_command_output_secrets(&once), once);
    }

    #[test]
    fn disabled_table_passes_through() {
        let cfg = RedactConfig {
            enabled: false,
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            ..RedactConfig::default()
        };
        let table = RedactionTable::build(&cfg, Path::new("/")).unwrap();
        assert_eq!(
            table.scrub_novel_command_output_secrets("API_TOKEN=novel-secret-value-123"),
            "API_TOKEN=novel-secret-value-123"
        );
    }

    #[test]
    fn table_known_secret_then_novel_pass_is_stable() {
        // Composition order used at the substitution site: `scrub` first
        // (table-known literals become the placeholder), then this pass
        // leaves the already-placeholder value alone.
        let base = table_with_placeholder(PH);
        let table = base
            .with_forced_literal("KNOWNSECRETVALUE123".to_string(), "$test:known".to_string())
            .unwrap();
        let body = "API_TOKEN=KNOWNSECRETVALUE123";
        let once = table.scrub(body);
        assert_eq!(once, "API_TOKEN=[ph]");
        assert_eq!(
            table.scrub_novel_command_output_secrets(&once),
            "API_TOKEN=[ph]"
        );
    }
}
