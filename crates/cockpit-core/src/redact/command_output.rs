//! Substitution-site novel-secret scrub for freshly captured `!`-command
//! output (GOALS §7; issue #279).
//!
//! [`RedactionTable::scrub`] only replaces literals already registered in
//! the table. A skill `!`-command can surface a *novel* secret the table
//! has never seen — `` !`cat .env` ``, `` !`aws sts get-session-token` `` —
//! and table-based dispatch-time scrubbing then finds nothing to replace.
//! This module closes that gap at the substitution site itself: before the
//! captured output enters context (and with it the provider request and
//! every export), everything the output can be *classified* as secret by
//! shape is replaced with the table's placeholder.
//!
//! Recognized shapes, per line of captured output:
//!
//! - keyed: `KEY=VALUE` assignments (dotenv / shell `env` style — spacing
//!   around the `=` included, quoted values included, mid-line fragments
//!   included, and URL-embedded assignments `?token=…` / `&sig=…` /
//!   `/token=…` included), `KEY: VALUE` colon pairs and `"KEY": "VALUE",`
//!   quoted members (YAML / JSON style — quoted members are scanned
//!   *anywhere* on the line, so compact and multi-member JSON is covered,
//!   not just line-anchored pairs), `<Tag>VALUE</Tag>` XML elements with
//!   secret-shaped tag names, and YAML block scalars opened by
//!   `secret_key: |` / `>` (the following, more-indented lines are the
//!   value and are scrubbed there). Credential-bearing header keys
//!   (`Authorization`, `Proxy-Authorization` — see
//!   [`is_secret_shaped_key`]) are secret-shaped keys here too, so
//!   `Authorization: Bearer …` scrubs the whole value, scheme word
//!   included;
//! - keyless: every opaque ≥20-character credential-shaped token **at any
//!   position on the line** — standing alone (the output shape of `gh
//!   auth token`, `aws configure get aws_secret_access_key`, `pass
//!   show`, and `cat token.txt`), embedded in prose (`credential is …`),
//!   or inside a header (`Authorization: Bearer …`) — plus well-known
//!   credential formats anywhere on a line (GitHub `ghp_`… /
//!   `github_pat_`, OpenAI/Anthropic `sk-`, Google `AIza`, Slack `xox?-`,
//!   AWS `AKIA…` access-key ids, and `eyJ…` JWTs). Position never decides
//!   secrecy: the same token is classified identically wherever the
//!   command printed it. Charset composition never decides secrecy
//!   either: a digitless password-manager passphrase (the `pass show` of
//!   an xkcd-style secret), an all-digit key, and a mixed hex key
//!   classify identically — the digit/letter mix is not a gate. The one
//!   remaining charset requirement is token-ness, not composition: the
//!   run must carry at least one alphanumeric character, because every
//!   credential encodes key material in alphanumerics while
//!   punctuation-only runs are `----` / `====` separator decor;
//! - `-----BEGIN … PRIVATE KEY-----` PEM blocks (the whole block becomes
//!   one placeholder).
//!
//! Classification is deliberately shape-based, position- and
//! composition-independent, and fail-closed. Opaque tokens that are *not*
//! secrets — a git SHA from `` !`git rev-parse HEAD` ``, a UUID, a build
//! target triple, a digest, or a ≥20-character compound word / identifier
//! (`well-known-compound-word`) that shares a digitless passphrase's
//! shape — are redacted too, wherever they appear on the line: at this
//! boundary over-redaction costs a placeholder where a hash or a long
//! word used to be, while under-redaction leaks a credential, and the
//! module consistently chooses the former. Absolute paths (which share
//! base64's `/`) are exempted.
//! Values under the [`NOVEL_SECRET_VALUE_MIN_LEN`] floor stay visible
//! (ports, counts, `yes`/`no` flags), mirroring the `min_secret_length`
//! prune in table building — except under [`credential_shaped_key`] keys,
//! which share the table builder's length exemption down to
//! [`MIN_REDACTION_ENTRY_LENGTH`], so a short `*_PASSWORD`/`*_PIN` value
//! first surfaced by a command is scrubbed exactly like one collected from
//! an env file. Multi-line XML element values and multi-line quoted shell
//! strings are passed through untouched rather than guessed at (the value
//! cannot be delimited by shape); PEM and YAML block scalars are the two
//! multi-line shapes with unambiguous fences and are fully covered.
//!
//! Every pass is linear in its line length: quote positions, `>` positions,
//! and close-tag starts are collected in one scan and looked up by binary
//! search, and no pass ever rescans a suffix per character. A trusted
//! workspace's command output is attacker-shaped input at this boundary, so
//! a line of N `<` bytes costs O(N log N), never the O(N²) the per-byte
//! rescans used to.

use std::borrow::Cow;
use std::collections::HashMap;

use super::structured::strip_quotes;
use super::{
    MIN_REDACTION_ENTRY_LENGTH, RedactionTable, credential_shaped_key, is_secret_shaped_key,
};

/// The value-length floor for novel substitution-site redaction. Mirrors
/// the `min_secret_length` default (`RedactConfig::default()`); values at
/// or above it under a secret-shaped key are replaced with the placeholder.
/// Credential-shaped keys are exempt down to
/// [`MIN_REDACTION_ENTRY_LENGTH`] instead (see [`novel_value_min_len`]).
const NOVEL_SECRET_VALUE_MIN_LEN: usize = 8;

/// Minimum total length for the opaque keyless-credential token rule (the
/// `gh auth token` / `aws configure get …` / digitless `pass show`
/// passphrase shape, wherever it appears).
const KEYLESS_TOKEN_MIN_LEN: usize = 20;

/// Minimum total length for a JWT (`eyJ…` with at least two dots).
const JWT_MIN_LEN: usize = 30;

/// The effective value floor for one key or tag: credential-shaped keys
/// share the table builder's `length_exempt` semantics (floor of the hard
/// [`MIN_REDACTION_ENTRY_LENGTH`]), every other secret-shaped key keeps the
/// eight-byte floor.
fn novel_value_min_len(key: &str) -> usize {
    if credential_shaped_key(key) {
        MIN_REDACTION_ENTRY_LENGTH
    } else {
        NOVEL_SECRET_VALUE_MIN_LEN
    }
}

impl RedactionTable {
    /// Redact *novel* secret-shaped values in freshly captured `!`-command
    /// output — values this table has no entry for, so [`Self::scrub`]
    /// alone cannot catch them. See the module docs for the full list of
    /// recognized shapes (keyed assignments and colon pairs including
    /// compact/multi-member JSON, secret-shaped XML elements, YAML block
    /// scalars, keyless opaque tokens at any line position, well-known
    /// credential formats, and PEM private-key blocks). Keys, tags,
    /// structure, and surrounding text are preserved; only the
    /// secret-shaped value is replaced with this table's placeholder.
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
        // YAML block scalar opened by a secret-shaped key: `(key-line
        // indent, value floor)`. The value is the run of following lines
        // indented deeper than the key line.
        let mut block_scalar: Option<(usize, usize)> = None;
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
            if let Some((key_indent, floor)) = block_scalar {
                let indent = content.len() - content.trim_start().len();
                let trimmed = content.trim();
                if trimmed.is_empty() {
                    // Blank lines do not close a YAML block scalar.
                    out.push_str(content);
                    out.push_str(newline);
                    continue;
                }
                if indent > key_indent {
                    if trimmed.len() >= floor && trimmed != self.placeholder {
                        out.push_str(&content[..indent]);
                        out.push_str(&self.placeholder);
                    } else {
                        out.push_str(content);
                    }
                    out.push_str(newline);
                    continue;
                }
                // Dedent closes the block; this line is normal output.
                block_scalar = None;
            }
            let intro = secret_shaped_block_scalar_intro(content);
            let scrubbed = scrub_line(content, &self.placeholder);
            out.push_str(&scrubbed);
            out.push_str(newline);
            if let Some(intro) = intro {
                block_scalar = Some(intro);
            }
        }
        out
    }
}

/// The per-line pass pipeline. Ordering only matters for idempotency (every
/// pass skips a value already equal to the placeholder), and each pass sees
/// only the previous passes' output, so a line can be scrubbed by any one of
/// them independently.
fn scrub_line(content: &str, placeholder: &str) -> String {
    let xml = scrub_secret_shaped_xml(content, placeholder);
    let assignments = scrub_secret_shaped_assignments(&xml, placeholder);
    let members = scrub_secret_shaped_quoted_members(&assignments, placeholder);
    let pairs = scrub_secret_shaped_colon_pairs(&members, placeholder);
    scrub_keyless_credential_tokens(&pairs, placeholder)
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
///
/// Two linear passes: first collect every `>` position and, per close-tag
/// name, the start positions of its `</name>` occurrences; then walk `<`
/// positions once, resolving each candidate's `>` and close tag by binary
/// search over those indexes. No `<` ever rescans the remaining suffix, so
/// a line of N `<` bytes is O(N log N) — the previous per-`<` full-suffix
/// scans made it O(N²) on attacker-controlled output.
fn scrub_secret_shaped_xml(line: &str, placeholder: &str) -> String {
    if !line.contains('<') {
        return line.to_string();
    }
    let gt_positions: Vec<usize> = line.match_indices('>').map(|(idx, _)| idx).collect();
    let mut close_starts: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut search = 0;
    while let Some(rel) = line[search..].find("</") {
        let start = search + rel;
        search = start + 2;
        let gt_idx = gt_positions.partition_point(|&p| p <= start + 1);
        if let Some(&gt) = gt_positions.get(gt_idx) {
            let name = &line[start + 2..gt];
            if is_xml_tag_name(name) {
                close_starts.entry(name).or_default().push(start);
            }
        }
    }
    let mut out = String::with_capacity(line.len());
    let mut copied = 0;
    let mut i = 0;
    while let Some(rel) = line[i..].find('<') {
        let lt = i + rel;
        let gt_idx = gt_positions.partition_point(|&p| p <= lt);
        let Some(&gt) = gt_positions.get(gt_idx) else {
            // No `>` left on the line: no tag can open again.
            break;
        };
        let tag = &line[lt + 1..gt];
        if is_xml_tag_name(tag) && is_secret_shaped_key(tag) {
            let value_start = gt + 1;
            let close_start = close_starts.get(tag).and_then(|starts| {
                let idx = starts.partition_point(|&p| p < value_start);
                starts.get(idx).copied()
            });
            if let Some(close_start) = close_start {
                // `</` + tag + `>`
                let close_end = close_start + tag.len() + 3;
                let value = &line[value_start..close_start];
                if value.len() >= novel_value_min_len(tag) && value != placeholder {
                    out.push_str(&line[copied..value_start]);
                    out.push_str(placeholder);
                    copied = close_end;
                    i = close_end;
                    continue;
                }
            }
        }
        // Not a scrubbable element: keep the `<` and resume scanning right
        // after it, so nested / unrelated markup still gets its own chance
        // (bounded by the find cursor, never a rescanned suffix).
        out.push_str(&line[copied..lt + 1]);
        copied = lt + 1;
        i = lt + 1;
    }
    out.push_str(&line[copied..]);
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
/// spacing around the `=` (`KEY = VALUE`), CLI-flag spellings
/// (`--token=…`, echoed command text), and URL-embedded assignments
/// (`?token=…` / `&sig=…` / `/token=…`, whose value ends at the next
/// `&`/`;`), since both command output and echoed command text quote
/// assignments inline (`TOKEN=… ./run.sh`, `echo "DB_PASSWORD=*"`). A
/// boundary char (line start, whitespace, quote, backtick, `?`, `&`, `;`,
/// `/`, or `-`) must sit before the key, so prose and markup fragments are
/// not reinterpreted as keys. Quoted values lose their quotes; keys and
/// surroundings survive.
fn scrub_secret_shaped_assignments(content: &str, placeholder: &str) -> String {
    if !content.contains('=') {
        return content.to_string();
    }
    let quotes = QuoteIndex::collect(content);
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while let Some(eq_rel) = content[i..].find('=') {
        let eq = i + eq_rel;
        // Spaced `KEY = VALUE`: skip back over whitespace before the key
        // scan-back.
        let mut key_end = eq;
        while key_end > 0 && matches!(bytes[key_end - 1], b' ' | b'\t') {
            key_end -= 1;
        }
        // The key candidate runs back from the `=` over bare key characters.
        let mut key_start = key_end;
        while key_start > 0 && is_bare_key_char(bytes[key_start - 1]) {
            key_start -= 1;
        }
        let key = &content[key_start..key_end];
        // CLI-flag spellings (`--session_token=…`, echoed command text):
        // trim leading dashes so the flag's inner name is the key
        // candidate. Without the trim the scan-back swallows the dashes,
        // `--session_token` fails the alphanumeric-start qualifier, and
        // the `-` entry in the boundary list below can never fire. Keys
        // with *internal* dashes (`aws-secret-access-key`) keep their
        // whole-name classification.
        let key = key.trim_start_matches('-');
        let at_boundary = key_start == 0
            || matches!(
                bytes[key_start - 1],
                b' ' | b'\t' | b'"' | b'\'' | b'`' | b'?' | b'&' | b';' | b'/' | b'-'
            );
        // A key introduced by a URL delimiter sits in a URL: its value
        // ends at the next `&`/`;` (query or matrix parameter), not just
        // at whitespace.
        let query_context =
            key_start > 0 && matches!(bytes[key_start - 1], b'?' | b'&' | b';' | b'/');
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
                assignment_value_span(content, eq + 1, opening_quote, query_context, &quotes)
        {
            let value = &content[value_start..value_end];
            if value.len() >= novel_value_min_len(key) && value != placeholder {
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
/// and a bare value runs to the next whitespace or — in URL context — the
/// next `&`/`;`, or the end of the line. `None` when there is no value on
/// this line. Quote lookups are binary searches over [`QuoteIndex`], never
/// suffix scans, so unclosed quotes cannot make the pass quadratic.
fn assignment_value_span(
    content: &str,
    after_eq: usize,
    opening_quote: Option<u8>,
    query_context: bool,
    quotes: &QuoteIndex,
) -> Option<(usize, usize)> {
    let rest = content.get(after_eq..)?;
    let start = after_eq + (rest.len() - rest.trim_start().len());
    let first = *content.as_bytes().get(start)?;
    if first == b'"' || first == b'\'' {
        let close = quotes.next_of(first, start + 1)?;
        Some((start, close + 1))
    } else if let Some(quote) = opening_quote {
        let close = quotes.next_of(quote, start)?;
        Some((start, close))
    } else {
        let end = if query_context {
            content[start..]
                .find(|c: char| c.is_whitespace() || c == '&' || c == ';')
                .map_or(content.len(), |rel| start + rel)
        } else {
            content[start..]
                .find(char::is_whitespace)
                .map_or(content.len(), |rel| start + rel)
        };
        Some((start, end))
    }
}

/// Scrub every `"KEY": "VALUE"` / `'KEY': 'VALUE'` member whose key is
/// secret-shaped and whose value clears the length floor. Unlike the
/// line-anchored colon-pair parser below, this scans quoted members
/// *anywhere* on the line, which is what compact (`{"k":"v"}`) and
/// multi-member (`{"a":"b","SecretKey":"v"}`) JSON requires. Quote style is
/// preserved; a JSON trailing comma sits outside the value and survives.
/// Quote pairing is naive (escaped quotes are not honored — the same
/// fidelity as every other parser here, and the failure mode is
/// under-classification of a mangled key, never a leak of a well-formed
/// member).
fn scrub_secret_shaped_quoted_members(content: &str, placeholder: &str) -> String {
    let double = scrub_quoted_members_of_kind(content, placeholder, '"');
    scrub_quoted_members_of_kind(&double, placeholder, '\'')
}

/// One quote kind of [`scrub_secret_shaped_quoted_members`]: walk same-kind
/// quote pairs (open, close) in order; when the quoted string is a
/// secret-shaped key, the separator between it and the next quote is a
/// single colon with optional surrounding whitespace, and the string after
/// that separator is a scrubbable value, replace the value.
fn scrub_quoted_members_of_kind(content: &str, placeholder: &str, kind: char) -> String {
    if !content.contains(':') {
        return content.to_string();
    }
    let positions: Vec<usize> = content.match_indices(kind).map(|(idx, _)| idx).collect();
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut k = 0;
    while k + 3 < positions.len() {
        let key_open = positions[k];
        let key_close = positions[k + 1];
        let key = &content[key_open + 1..key_close];
        if command_output_key_qualifies(key) {
            let val_open = positions[k + 2];
            let val_close = positions[k + 3];
            let separator = &content[key_close + 1..val_open];
            let mut parts = separator.split_whitespace();
            if parts.next() == Some(":") && parts.next().is_none() {
                let value = &content[val_open + 1..val_close];
                if value.len() >= novel_value_min_len(key) && value != placeholder {
                    out.push_str(&content[copied..val_open + 1]);
                    out.push_str(placeholder);
                    copied = val_close;
                    k += 4;
                    continue;
                }
            }
        }
        k += 2;
    }
    out.push_str(&content[copied..]);
    out
}

/// Scrub a line-anchored `KEY: VALUE` pair (YAML style, bare or quoted key)
/// whose key is secret-shaped and whose value clears the length floor.
/// Indentation, the quote style, and a JSON trailing comma are preserved in
/// the rebuild. Quoted-key members anywhere on the line are handled by
/// [`scrub_secret_shaped_quoted_members`]; this parser's unique coverage is
/// the bare unquoted key at line start (plain YAML), including one leading
/// YAML list marker (`- key: value`).
fn scrub_secret_shaped_colon_pairs(content: &str, placeholder: &str) -> String {
    if !content.contains(':') {
        return content.to_string();
    }
    let indent = content.len() - content.trim_start().len();
    let mut head = &content[indent..];
    let mut head_off = indent;
    // A YAML list item (`- key: value`) anchors the same pair as a
    // line-start key: skip one `-` list marker plus the whitespace after
    // it. Keys must start with an alphanumeric, so a `-`-prefixed head
    // never qualified before — this only adds coverage.
    if let Some(rest) = head.strip_prefix('-') {
        let ws = rest.len() - rest.trim_start().len();
        let inner = &rest[ws..];
        if !inner.is_empty() && !inner.starts_with('-') {
            head = inner;
            head_off = indent + 1 + ws;
        }
    }
    // Key: JSON-style quoted, or a bare token running to the `:` (with
    // optional spacing before the separator: `auth-token : value`).
    let (key, after_key) = if let Some(rest) = head.strip_prefix('"') {
        let Some(close_rel) = rest.find('"') else {
            return content.to_string();
        };
        (&head[1..1 + close_rel], head_off + 1 + close_rel + 1)
    } else {
        let Some(sep_rel) = head.find(':') else {
            return content.to_string();
        };
        (head[..sep_rel].trim_end(), head_off + sep_rel)
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
    if value.len() < novel_value_min_len(key) || value == placeholder {
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

/// `(key-line indent, value floor)` when `content` opens a YAML block
/// scalar under a secret-shaped key — `password: |`, `db_secret: >-`,
/// `token: |2` — whose value lives on the following, more-indented lines
/// and must be scrubbed there. Chomping/indent indicators (`+`, `-`,
/// digits) may follow the `|`/`>`; anything else is an inline value, not a
/// block, and returns `None`. One leading YAML list marker
/// (`- key: |`) is skipped first, so a list-item block classifies exactly
/// like a line-anchored one (the returned floor indentation stays the key
/// line's own indent, which list-item value lines exceed).
fn secret_shaped_block_scalar_intro(content: &str) -> Option<(usize, usize)> {
    let indent = content.len() - content.trim_start().len();
    let mut trimmed = content.trim_start();
    if let Some(rest) = trimmed.strip_prefix('-') {
        let ws = rest.len() - rest.trim_start().len();
        let inner = &rest[ws..];
        if !inner.is_empty() && !inner.starts_with('-') {
            trimmed = inner;
        }
    }
    let colon = trimmed.find(':')?;
    let key = strip_quotes(trimmed[..colon].trim());
    if !command_output_key_qualifies(key) {
        return None;
    }
    let indicator = trimmed[colon + 1..].trim();
    let mut chars = indicator.chars();
    let first = chars.next()?;
    if first != '|' && first != '>' {
        return None;
    }
    if !chars.all(|c| matches!(c, '+' | '-' | '0'..='9')) {
        return None;
    }
    Some((indent, novel_value_min_len(key)))
}

/// Charset of an opaque credential token: base64 / base64url / hex /
/// AWS-style mixed alnum, password-manager passphrases (digitless word
/// runs included — composition is not a gate), plus percent-encoded
/// blobs. No dots — dotted runs are versions, host names, and file
/// names; JWTs (which need dots) are caught by the `eyJ` prefix rule
/// instead.
fn is_opaque_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '%')
}

/// Scrub keyless secrets: well-known credential formats anywhere on the
/// line, then every opaque credential-shaped token anywhere on the line.
/// The opaque-token rule is position- and composition-independent: a
/// token that would be redacted standing alone — the `gh auth token` /
/// `pass show` output shape — is redacted embedded in prose (`credential
/// is …`) or inside a header (`Authorization: Bearer …`) exactly the
/// same, and a digitless passphrase classifies exactly like a hex key.
/// Neither position nor charset mix ever decides secrecy. See the module
/// docs for the fail-closed stance on hashes and UUIDs.
fn scrub_keyless_credential_tokens(content: &str, placeholder: &str) -> String {
    // Known formats first: they delimit multi-part tokens (a JWT's dot
    // segments are not opaque-run characters) that the embedded run pass
    // would otherwise chop into partial redactions.
    let known = scrub_known_credential_tokens(content, placeholder);
    scrub_embedded_opaque_tokens(&known, placeholder)
}

/// `true` when `token` has the shape of a novel keyless credential: an
/// opaque run of at least [`KEYLESS_TOKEN_MIN_LEN`] characters carrying
/// at least one alphanumeric character, with no non-trailing `=` (that
/// is an assignment, not a bare token; trailing `=` is base64 padding)
/// and not an absolute path (which shares base64's `/`). Two properties
/// are deliberate invariants, not heuristics:
///
/// - **Position never decides secrecy**: the standalone `gh auth token`
///   output, the same token quoted by `pass show`, and the same token
///   embedded in prose or a header all classify identically, so no
///   rendering position can make a credential pass.
/// - **Charset composition never decides secrecy**: a digitless
///   passphrase (`pass show` of an xkcd-style secret), an all-digit key,
///   and a mixed hex key classify identically — the digit/letter mix
///   must not be a bypass, exactly as position was not allowed to be
///   one. The single remaining charset requirement, at least one
///   alphanumeric, is *token-ness* (every credential encodes key
///   material in alphanumerics; punctuation-only runs are `----` /
///   `====` separator decor carrying nothing to leak), a floor of the
///   same kind as the length minimum, not a composition gate.
fn is_novel_opaque_credential(token: &str) -> bool {
    token.len() >= KEYLESS_TOKEN_MIN_LEN
        && !token.contains(char::is_whitespace)
        && token.chars().all(is_opaque_token_char)
        && token.chars().any(|c| c.is_ascii_alphanumeric())
        // A non-trailing `=` makes the span an assignment shape, not a
        // bare token (trailing `=` is base64 padding).
        && !token.trim_end_matches('=').contains('=')
        // Absolute paths share base64's `/`; exempt multi-slash shapes.
        && !(token.starts_with('/') && token.matches('/').count() >= 2)
}

/// Replace every maximal run of opaque token characters that
/// [`is_novel_opaque_credential`] classifies as a credential with the
/// placeholder. Runs are bounded by any non-opaque character (whitespace,
/// quotes, punctuation), so surrounding prose, one layer of `pass show`
/// quotes, and line position all survive untouched — including the
/// whole-line shapes, which are simply runs bounded by the line edges or
/// quotes. Linear in the line: one scan collects the runs and each run is
/// checked once. A run already equal to the placeholder is left alone, so
/// re-scrubbing stays idempotent even for a user-configured opaque-shaped
/// placeholder.
fn scrub_embedded_opaque_tokens(content: &str, placeholder: &str) -> String {
    if content.len() < KEYLESS_TOKEN_MIN_LEN {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut run_start: Option<usize> = None;
    for (idx, ch) in content.char_indices() {
        if is_opaque_token_char(ch) {
            run_start.get_or_insert(idx);
            continue;
        }
        let Some(start) = run_start.take() else {
            continue;
        };
        let run = &content[start..idx];
        if run != placeholder && is_novel_opaque_credential(run) {
            out.push_str(&content[copied..start]);
            out.push_str(placeholder);
            copied = idx;
        }
    }
    if let Some(start) = run_start {
        let run = &content[start..];
        if run != placeholder && is_novel_opaque_credential(run) {
            out.push_str(&content[copied..start]);
            out.push_str(placeholder);
            copied = content.len();
        }
    }
    out.push_str(&content[copied..]);
    out
}

/// Well-known credential token prefixes and the minimum total length
/// (prefix + body) for a match: GitHub PATs, GitHub fine-grained PATs,
/// OpenAI/Anthropic `sk-` keys, Google API keys, and Slack tokens.
const CREDENTIAL_PREFIX_RULES: &[(&str, usize)] = &[
    ("ghp_", 20),
    ("gho_", 20),
    ("ghu_", 20),
    ("ghs_", 20),
    ("ghr_", 20),
    ("github_pat_", 30),
    ("sk-", 25),
    ("AIza", 39),
    ("xoxb-", 20),
    ("xoxp-", 20),
    ("xoxo-", 20),
    ("xoxa-", 20),
    ("xoxr-", 20),
    ("xoxs-", 20),
];

/// Credential word characters for prefix-anchored runs.
fn is_credential_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// JWT characters (base64url segments joined by dots).
fn is_jwt_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// Replace every occurrence of a known credential format on the line with
/// the placeholder. Mid-line coverage is what catches a secret echoed into
/// prose or mixed output (`token is ghp_…`, `Authorization: Bearer eyJ…`).
fn scrub_known_credential_tokens(content: &str, placeholder: &str) -> String {
    let mut current: Option<String> = None;
    for (prefix, min_total) in CREDENTIAL_PREFIX_RULES {
        let source = current.as_deref().unwrap_or(content);
        if let Cow::Owned(scrubbed) =
            scrub_prefixed_token_run(source, placeholder, prefix, *min_total)
        {
            current = Some(scrubbed);
        }
    }
    let source = current.as_deref().unwrap_or(content);
    if let Cow::Owned(scrubbed) = scrub_aws_access_key_ids(source, placeholder) {
        current = Some(scrubbed);
    }
    let source = current.as_deref().unwrap_or(content);
    if let Cow::Owned(scrubbed) = scrub_jwt_tokens(source, placeholder) {
        current = Some(scrubbed);
    }
    current.unwrap_or_else(|| content.to_string())
}

/// Replace every `prefix`-anchored run of credential word characters whose
/// total length clears `min_total` with `placeholder`. The run must start
/// at a token boundary (the preceding character is not a word character),
/// so prose like `task-management` never matches the `sk-` rule. Borrowed
/// (allocation-free) when the prefix is absent.
fn scrub_prefixed_token_run<'a>(
    content: &'a str,
    placeholder: &str,
    prefix: &str,
    min_total: usize,
) -> Cow<'a, str> {
    if !content.contains(prefix) {
        return Cow::Borrowed(content);
    }
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(rel) = content[search..].find(prefix) {
        let start = search + rel;
        let mut end = start;
        for (idx, ch) in content[start..].char_indices() {
            if is_credential_word_char(ch) {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        let at_boundary = start == 0
            || content[..start]
                .chars()
                .next_back()
                .is_some_and(|prev| !is_credential_word_char(prev));
        if at_boundary && end - start >= min_total {
            out.push_str(&content[copied..start]);
            out.push_str(placeholder);
            copied = end;
            search = end;
        } else {
            search = start + 1;
        }
    }
    out.push_str(&content[copied..]);
    Cow::Owned(out)
}

/// AWS access key ids: `AKIA` followed by exactly sixteen uppercase
/// alphanumerics, at a non-alphanumeric boundary on both sides.
fn scrub_aws_access_key_ids<'a>(content: &'a str, placeholder: &str) -> Cow<'a, str> {
    if !content.contains("AKIA") {
        return Cow::Borrowed(content);
    }
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(rel) = content[search..].find("AKIA") {
        let start = search + rel;
        let end = start + 20;
        let bounded = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let matches_shape = end <= bytes.len()
            && bytes[start + 4..end]
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            && (end == bytes.len() || !bytes[end].is_ascii_alphanumeric());
        if bounded && matches_shape {
            out.push_str(&content[copied..start]);
            out.push_str(placeholder);
            copied = end;
            search = end;
        } else {
            search = start + 1;
        }
    }
    out.push_str(&content[copied..]);
    Cow::Owned(out)
}

/// JWTs: an `eyJ`-anchored run of JWT characters containing at least two
/// dots and clearing [`JWT_MIN_LEN`].
fn scrub_jwt_tokens<'a>(content: &'a str, placeholder: &str) -> Cow<'a, str> {
    if !content.contains("eyJ") {
        return Cow::Borrowed(content);
    }
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(rel) = content[search..].find("eyJ") {
        let start = search + rel;
        let mut end = start;
        let mut dots = 0;
        for (idx, ch) in content[start..].char_indices() {
            if is_jwt_char(ch) {
                end = start + idx + ch.len_utf8();
                if ch == '.' {
                    dots += 1;
                }
            } else {
                break;
            }
        }
        let at_boundary = start == 0
            || content[..start]
                .chars()
                .next_back()
                .is_some_and(|prev| !is_jwt_char(prev));
        if at_boundary && dots >= 2 && end - start >= JWT_MIN_LEN {
            out.push_str(&content[copied..start]);
            out.push_str(placeholder);
            copied = end;
            search = end;
        } else {
            search = start + 1;
        }
    }
    out.push_str(&content[copied..]);
    Cow::Owned(out)
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

/// Per-line index of quote characters: collected in one linear scan, looked
/// up by binary search. Replaces the per-assignment suffix scans for
/// closing quotes, which made a line full of unclosed quotes quadratic.
struct QuoteIndex {
    double: Vec<usize>,
    single: Vec<usize>,
}

impl QuoteIndex {
    fn collect(content: &str) -> Self {
        let mut double = Vec::new();
        let mut single = Vec::new();
        for (idx, ch) in content.char_indices() {
            match ch {
                '"' => double.push(idx),
                '\'' => single.push(idx),
                _ => {}
            }
        }
        Self { double, single }
    }

    /// The first quote of `kind` (`"` or `'`) at or after `from`.
    fn next_of(&self, kind: u8, from: usize) -> Option<usize> {
        let positions = if kind == b'"' {
            &self.double
        } else {
            &self.single
        };
        let idx = positions.partition_point(|&p| p < from);
        positions.get(idx).copied()
    }
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

    // Detector-shaped credential samples are assembled at runtime from
    // fragments so the source never contains a contiguous token for the
    // CI secret scanner to flag; the scrubber still sees the assembled
    // token exactly as a command would print it.
    fn github_pat() -> String {
        ["ghp", "_", "16CharMinimumTokenAbCdEfGhIjKlMn"].concat()
    }

    fn aws_secret_access_key() -> String {
        ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"].concat()
    }

    fn aws_access_key_id() -> String {
        ["AKIA", "IOSFODNN7EXAMPLE"].concat()
    }

    fn jwt() -> String {
        [
            "eyJ",
            "hbGciOiJIUzI1NiJ9",
            ".",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            ".",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
        .concat()
    }

    fn git_sha() -> String {
        ["0d1a4b2c8e3f60718293", "a4b5c6d7e8f9a0b1c2d3"].concat()
    }

    // Cycle 3: ordinary keyless password-manager output is digitless (an
    // xkcd-style passphrase), so these too are assembled from fragments so
    // the source never contains the contiguous detector-shaped token.
    fn digitless_passphrase() -> String {
        ["correct", "horse", "battery", "staple"].concat()
    }

    fn hyphenated_passphrase() -> String {
        ["correct-horse", "-battery", "-staple"].concat()
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
            table.scrub_novel_command_output_secrets("export DATABASE_PASSWORD=novel-db-pass-77aa"),
            "export DATABASE_PASSWORD=[ph]"
        );
        // Mid-line fragments (echoed command text) are caught too; the
        // surrounding shell syntax survives.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "run with AWS_SECRET_ACCESS_KEY=novel-aws-key-8842abc now"
            ),
            "run with AWS_SECRET_ACCESS_KEY=[ph] now"
        );
    }

    #[test]
    fn spaced_assignment_is_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("API_TOKEN = novel-secret-value-123"),
            "API_TOKEN = [ph]"
        );
    }

    #[test]
    fn cli_flag_assignment_is_redacted() {
        let table = table_with_placeholder(PH);
        // `--session_token=…` as echoed command text and error markers
        // embed it (`-` is a key boundary char).
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "run ./tool --session_token=novel-cli-token-667788 now"
            ),
            "run ./tool --session_token=[ph] now"
        );
        // Dash-internal keys keep their whole-name classification; the
        // flag's leading dashes are what get trimmed.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "flag --aws-secret-access-key=novelsecret123456789 now"
            ),
            "flag --aws-secret-access-key=[ph] now"
        );
    }

    #[test]
    fn query_string_assignment_is_redacted() {
        let table = table_with_placeholder(PH);
        // The value ends at the next `&`; the rest of the query survives.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "fetch https://x.test/?token=novel-query-token-9911&x=1"
            ),
            "fetch https://x.test/?token=[ph]&x=1"
        );
        // Path-delimited assignment (`/token=…`) is covered too.
        assert_eq!(
            table.scrub_novel_command_output_secrets("https://x.test/v1/token=noveltoken9911abc"),
            "https://x.test/v1/token=[ph]"
        );
    }

    #[test]
    fn quoted_assignment_value_is_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("echo \"DB_PASSWORD=novel-db-pass-9911\""),
            "echo \"DB_PASSWORD=[ph]\""
        );
    }

    #[test]
    fn credential_shaped_short_value_is_redacted() {
        // Credential-shaped keys share the table builder's length
        // exemption: a short `*_PASSWORD` value is scrubbed, not visible.
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("DB_PASSWORD=abc123"),
            "DB_PASSWORD=[ph]"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("ATM_PIN=1234"),
            "ATM_PIN=[ph]"
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
    fn compact_and_multi_member_json_is_redacted() {
        let table = table_with_placeholder(PH);
        // Compact object, no spaces.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "{\"SecretAccessKey\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYZ\",\"Region\":\"us-east-1\"}"
            ),
            "{\"SecretAccessKey\":\"[ph]\",\"Region\":\"us-east-1\"}"
        );
        // Multi-member on one line: the non-secret members survive.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "{\"a\":1,\"api_token\":\"novel-json-token-445566\",\"b\":2}"
            ),
            "{\"a\":1,\"api_token\":\"[ph]\",\"b\":2}"
        );
    }

    #[test]
    fn yaml_colon_pair_is_redacted() {
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("auth-token: novel-yaml-token-33445566"),
            "auth-token: [ph]"
        );
        // Spaced separator: `auth-token : value`.
        assert_eq!(
            table.scrub_novel_command_output_secrets("auth-token : novel-yaml-token-33445566"),
            "auth-token : [ph]"
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
    fn yaml_block_scalar_value_is_redacted() {
        let table = table_with_placeholder(PH);
        // The value lives on the following, more-indented lines (the
        // "multiline value" shape); a dedent closes the block.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "db_password: |\n  hunter2-novel-secret-9f1a\nother: fine\n"
            ),
            "db_password: |\n  [ph]\nother: fine\n"
        );
        // Chomping indicator variant.
        assert_eq!(
            table.scrub_novel_command_output_secrets("secret_value: >-\n  base64styleblob12345\n"),
            "secret_value: >-\n  [ph]\n"
        );
    }

    #[test]
    fn keyless_standalone_token_line_is_redacted() {
        let table = table_with_placeholder(PH);
        // The `gh auth token` shape.
        assert_eq!(
            table.scrub_novel_command_output_secrets(&github_pat()),
            "[ph]"
        );
        // The `aws configure get aws_secret_access_key` shape (40-char
        // base64, possibly containing `/`).
        assert_eq!(
            table.scrub_novel_command_output_secrets(&aws_secret_access_key()),
            "[ph]"
        );
        // One layer of surrounding quotes (the `pass show` shape).
        assert_eq!(
            table.scrub_novel_command_output_secrets("\"novel-passphrase-77aa1234xyz\""),
            "\"[ph]\""
        );
    }

    #[test]
    fn known_credential_formats_are_redacted_midline() {
        let table = table_with_placeholder(PH);
        let line = format!("the token is {} ok", github_pat());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&line),
            "the token is [ph] ok"
        );
        let line = format!("key {} here", aws_access_key_id());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&line),
            "key [ph] here"
        );
        // `Authorization` classifies as a credential-bearing key, so the
        // keyed pass scrubs the whole value — scheme word included —
        // before the format passes ever see it.
        let line = format!("Authorization: Bearer {}", jwt());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&line),
            "Authorization: [ph]"
        );
    }

    #[test]
    fn mixed_prose_unknown_opaque_token_is_redacted() {
        // The position-independence invariant: an unknown opaque
        // credential is redacted wherever the command printed it —
        // embedded in prose, not only as a whole line.
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("credential is novelOpaqueCredential123456"),
            "credential is [ph]"
        );
        // Mid-line AWS secret key (base64 with `/`, not path-anchored).
        let line = format!("the key is {} today", aws_secret_access_key());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&line),
            "the key is [ph] today"
        );
        // One layer of `pass show`-style quotes mid-line: quotes survive.
        assert_eq!(
            table.scrub_novel_command_output_secrets("prints \"novel-passphrase-77aa1234xyz\" now"),
            "prints \"[ph]\" now"
        );
    }

    #[test]
    fn digitless_keyless_passphrase_is_redacted() {
        // Issue #279 cycle 3: charset composition never decides secrecy.
        // The ordinary `pass show` output is a digitless passphrase; it
        // previously passed as "not a credential" for lacking a digit —
        // the same way mixed tokens previously passed for standing in the
        // wrong position (cycle 2). Position and composition are both
        // non-gates now.
        let table = table_with_placeholder(PH);
        // The standalone `pass show` output shape.
        assert_eq!(
            table.scrub_novel_command_output_secrets(&digitless_passphrase()),
            "[ph]"
        );
        // Embedded in prose — position-independent.
        let line = format!("the password is {} ok", digitless_passphrase());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&line),
            "the password is [ph] ok"
        );
        // One layer of quotes (the quoted `pass show` echo shape).
        let quoted = format!("\"{}\"", digitless_passphrase());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&quoted),
            "\"[ph]\""
        );
        // Hyphen-separated passphrase (password-manager generator style):
        // separators are opaque-run characters, so the whole run is the
        // credential.
        assert_eq!(
            table.scrub_novel_command_output_secrets(&hyphenated_passphrase()),
            "[ph]"
        );
    }

    #[test]
    fn all_digit_keyless_run_is_redacted() {
        // Composition independence is symmetric: an all-digit ≥20 run —
        // the account-number / all-digit-password class, the digitless
        // passphrase's mirror image — classifies exactly like a mixed
        // hex key. The table builder already made the same call for known
        // values ("long numeric strings are retained because all-digit
        // API keys and passwords exist"); the novel-secret boundary
        // keeps one invariant, not two.
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("31415926535897932384626433832795028"),
            "[ph]"
        );
    }

    #[test]
    fn authorization_header_value_is_redacted_wholesale() {
        // `Authorization` is a credential-bearing key: the whole value —
        // the auth scheme word included — is the secret (`curl -v` echo
        // shape), so even a short bearer token under the keyless token
        // floor cannot survive under it.
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "Authorization: Bearer novelOpaqueCredential123456"
            ),
            "Authorization: [ph]"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("Authorization: Bearer shortTok1"),
            "Authorization: [ph]"
        );
    }

    #[test]
    fn yaml_list_item_keyed_members_are_redacted() {
        // One leading list marker is skipped, so `- key: value` members
        // classify exactly like line-anchored ones.
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("- password: hunter2-novel-secret-9f"),
            "- password: [ph]"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "- \"db_password\": \"hunter2-novel-secret-9f\""
            ),
            "- \"db_password\": \"[ph]\""
        );
        // Block scalar under a list-item key.
        assert_eq!(
            table.scrub_novel_command_output_secrets(
                "- db_password: |\n    hunter2-novel-secret-9f\n"
            ),
            "- db_password: |\n    [ph]\n"
        );
    }

    #[test]
    fn midline_opaque_identifier_is_redacted_fail_closed() {
        // Position-independent fail-closed: a full git SHA mid-line is
        // shape-identical to a credential and is redacted wherever it
        // appears — the documented over-redaction trade.
        let table = table_with_placeholder(PH);
        let line = format!("merged commit {} into main", git_sha());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&line),
            "merged commit [ph] into main"
        );
    }

    #[test]
    fn short_prose_and_punctuation_decor_stay_visible() {
        // What still keeps ordinary prose and banners safe now that
        // composition stopped being a gate (cycle 3): the length floor —
        // words below the opaque-token floor stay visible, digitless or
        // not — and the token-ness requirement — punctuation-only
        // separator runs (`----` / `====` rules) carry no credential
        // material and stay visible even above the floor. Digitlessness
        // ALONE can no longer keep a ≥20-character run visible; that
        // exact gap let `pass show` passphrases through (see the
        // digitless-passphrase regression tests).
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("unmistakably readable output"),
            "unmistakably readable output"
        );
        // 19 characters: one under the keyless floor.
        assert_eq!(
            table.scrub_novel_command_output_secrets("well-known-compound stays"),
            "well-known-compound stays"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("----------------------------------------"),
            "----------------------------------------"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("========================================"),
            "========================================"
        );
    }

    #[test]
    fn short_values_and_plain_keys_pass_through() {
        let table = table_with_placeholder(PH);
        // Below the length floor for non-credential-shaped keys: ports,
        // counts, flags stay visible.
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
        // Unmatched `<` bytes pass through unchanged.
        assert_eq!(
            table.scrub_novel_command_output_secrets("a < b and c < d"),
            "a < b and c < d"
        );
    }

    #[test]
    fn paths_and_benign_tokens_stay_visible() {
        let table = table_with_placeholder(PH);
        // Absolute paths share base64's `/`; the multi-slash shape is
        // exempted.
        assert_eq!(
            table.scrub_novel_command_output_secrets("/usr/lib/x86_64-linux-gnu/libssl3so12"),
            "/usr/lib/x86_64-linux-gnu/libssl3so12"
        );
        // Dotted runs (versions, host names, file names) are not opaque
        // tokens.
        assert_eq!(
            table.scrub_novel_command_output_secrets("cockpit-v0.1.2-rc3-x86_64"),
            "cockpit-v0.1.2-rc3-x86_64"
        );
        // Prose words containing a prefix (`task-management` vs `sk-`) do
        // not match.
        assert_eq!(
            table.scrub_novel_command_output_secrets("task-management tooling"),
            "task-management tooling"
        );
    }

    #[test]
    fn standalone_hash_and_uuid_are_redacted_fail_closed() {
        // Deliberate fail-closed coverage (module docs): a standalone git
        // SHA or UUID is indistinguishable by shape from a credential, and
        // at this boundary over-redaction is the safe side.
        let table = table_with_placeholder(PH);
        assert_eq!(table.scrub_novel_command_output_secrets(&git_sha()), "[ph]");
        assert_eq!(
            table.scrub_novel_command_output_secrets("123e4567-e89b-42d3-a456-426614174000"),
            "[ph]"
        );
    }

    #[test]
    fn pem_private_key_block_collapses_to_placeholder() {
        let table = table_with_placeholder(PH);
        let body = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAbase64data==\n-----END OPENSSH PRIVATE KEY-----"; // pragma: allowlist secret
        assert_eq!(table.scrub_novel_command_output_secrets(body), "[ph]\n");
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
        let once_keyless = table.scrub_novel_command_output_secrets(&github_pat());
        assert_eq!(
            table.scrub_novel_command_output_secrets(&once_keyless),
            once_keyless
        );
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

    #[test]
    fn pathological_unmatched_angle_line_scrubs_real_elements() {
        // A line of unmatched `<` bytes used to cost O(N^2) (per-`<` full
        // suffix scans); with the index-based passes it is linear-ish, and
        // a real secret-shaped element on the same line still scrubs.
        let table = table_with_placeholder(PH);
        let mut line = "<".repeat(20_000);
        line.push_str("<SecretAccessKey>wJalr-secret-987654</SecretAccessKey>");
        let scrubbed = table.scrub_novel_command_output_secrets(&line);
        assert!(
            scrubbed.starts_with("<<<"),
            "unmatched `<` bytes survive, got {}…",
            &scrubbed[..8]
        );
        assert_eq!(scrubbed.matches('<').count(), 20_000 + 2);
        assert!(scrubbed.contains("<SecretAccessKey>[ph]</SecretAccessKey>"));
    }

    #[test]
    fn unclosed_quote_assignment_barrage_stays_structured() {
        // 2000 unclosed quoted assignments: closing-quote lookups are
        // binary searches over the per-line index, not suffix scans, so
        // the barrage is linear. Each even-indexed key's quoted span runs
        // to the next quote (consuming the following key's `="`), so the
        // even spans collapse and the interleaved filler survives.
        let table = table_with_placeholder(PH);
        let mut line = String::new();
        for n in 0..2_000 {
            line.push_str("MY_TOKEN_");
            line.push_str(&n.to_string());
            line.push_str("=\"filler");
            line.push_str(&n.to_string());
            line.push(' ');
        }
        let scrubbed = table.scrub_novel_command_output_secrets(&line);
        assert!(
            scrubbed.starts_with("MY_TOKEN_0=[ph]filler1 MY_TOKEN_2=[ph]"),
            "got {}…",
            &scrubbed[..64]
        );
        assert!(
            scrubbed.contains("MY_TOKEN_1998=[ph]filler1999 "),
            "got tail {}…",
            &scrubbed[scrubbed.len() - 64..]
        );
        assert!(!scrubbed.contains("filler0"), "got {scrubbed:?}");
    }
}
