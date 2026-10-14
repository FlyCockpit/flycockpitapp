//! Substitution-site novel-secret scrub for freshly captured `!`-command
//! output (GOALS §7; issue #279).
//!
//! The same passes also back ordinary bash, custom-tool and background-job
//! output in [`NovelScrubMode::KeyedNarrow`] (secrets increment I2, see
//! `crate::tools::output_backstop`): keyed forms, well-known credential
//! formats, JWTs, PEM blocks and URL-userinfo passwords only — no keyless
//! opaque-token rule, so git SHAs, UUIDs and digests survive. Everything
//! below describes the skill `!` [`NovelScrubMode::Full`] mode.
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
//! Keyed values are redacted down to the hard [`MIN_REDACTION_ENTRY_LENGTH`]
//! floor for *every* secret-shaped key, not just the `*_PASSWORD`/`*_PIN`
//! family: the key's own shape is the secrecy evidence, so length above the
//! hard floor is token-ness, never a secrecy gate (`GITHUB_TOKEN=abc123`
//! and a bare `password: hunter2` used to cross this boundary under the
//! eight-character collection floor). The two exemptions mirror the table
//! builder's candidate prune exactly, so the boundaries keep one
//! plausibility definition: values below the hard floor (never safe to
//! replace — short strings match unrelated output) and never-scrub
//! literals (`true`/`false`/`null`/`none`/`yes`/`no`/`on`/`off`,
//! case-insensitive) stay visible, so a boolean echo like
//! `DB_PASSWORD=null` is not corrupted into a placeholder. The keyless
//! floor stays 20: without a key there is no secrecy signal except the
//! run's own shape, and below 20 an opaque run shares its shape with
//! ordinary words (`information`, `well-known-compound`) — position and
//! charset composition are non-gates because they carry no signal either
//! way, while sub-20 length carries positive counter-signal.
//! Escaped quotes are honored wherever a quote acts as a delimiter
//! (quoted assignment values, quoted JSON members, quoted colon-pair
//! keys): an embedded `\"` is value text, never the closing delimiter, so
//! `API_TOKEN="ab\"cd"` and `{"API_TOKEN":"ab\"cd"}` are redacted whole —
//! every parser resolves its closing quote through one shared
//! escape-aware index, never a naive next-quote scan.
//!
//! # Backstop contract ([`NovelScrubMode::KeyedNarrow`], secrets I2)
//!
//! The narrow backstop over bash, custom-tool and background-job output
//! GUARANTEES that, for every shape below, the secret value is replaced in
//! the output it appears in AND registered in the session table (so a later
//! echo without the shape is still caught). Each entry has a test in this
//! module's `contract_*` tests:
//!
//! 1. `KEY=value` / `KEY = value` / `export KEY=value` / `KEY="quoted"` /
//!    `KEY='quoted'`, mid-line and URL-embedded (`?token=…`), escape-aware
//!    (`\"` inside a quoted value is value text).
//! 2. JSON members `"key": "value"` anywhere on a line, escape-aware, and
//!    a quoted value split across lines (`"key": "abc` … `xyz"`), joined.
//! 3. YAML `key: value` with the scalar's SEMANTIC value: a `!tag` and a
//!    trailing ` # comment` are not part of it; `key:` followed by the value
//!    on the next indented line; literal `|` and folded `>` block scalars
//!    (each body line, and the joined literal / folded value, with encoded
//!    variants).
//! 4. `<SecretTag>value</SecretTag>` on one line or across lines.
//! 5. URL userinfo passwords `scheme://user:PASS@host` (raw and
//!    percent-decoded; no username or "well-known" exemption).
//! 6. PEM `-----BEGIN … PRIVATE KEY-----` blocks (body lines are redacted
//!    even when the END fence never arrives or the block is cut).
//! 7. JWTs: three non-empty base64url segments whose decoded header is a
//!    JSON object with a string `alg`, wherever they appear.
//! 8. Well-known credential prefixes (`ghp_`, `github_pat_`, `sk-`, `AIza`,
//!    `xox?-`, `AKIA…`).
//! 9. Multi-line shell-quoted values (`TOKEN="abc` … `xyz"`), joined.
//!
//! Bounds (attacker-shaped input): the scan is line-at-a-time and linear
//! in each line (no quadratic path; the JWT pass is one tokenization of the
//! line); a pipe line longer than the intake cap is cut at the cap (its
//! prefix is scanned, the remainder is withheld from the output and marked)
//! and the context after a cut is UNCERTAIN, so the next line's base64 or
//! indented continuation is treated as a value rather than as fresh text;
//! multi-line constructs retain at most `MAX_RETAINED_CONSTRUCT_BYTES` and
//! the pending-registration set at most `MAX_PENDING_FOUND_BYTES` (beyond
//! either, the construct is still REDACTED in output; only a bounded prefix
//! is registered; a joined multi-line value above
//! `MAX_JOINED_REGISTRATION_BYTES` registers per line only); type /
//! reference recursion is capped
//! (`MAX_TYPE_DEPTH`, `MAX_REFERENCE_DEPTH`). Scanning runs on the raw pipe
//! bytes BEFORE head/tail truncation, so a truncated capture never loses
//! the context a later line needs.
//!
//! Registration policy: duplicate observations of one value merge to the
//! STRONGEST policy (length exemption, encoded and case variants are
//! OR-ed); the redaction placeholder itself (or any value containing it) is
//! never registered. A heuristic exemption that exists only to avoid false
//! positives never leaves a value visible: short counts under ordinary keys
//! (`max_tokens: 4096`) and unquoted code-type expressions (`token: String`)
//! are REDACTED in that output but not registered globally.
//!
//! Outside the contract (stated plainly): keyless opaque tokens in narrow
//! mode (git SHAs, UUIDs and digests are work product; the Full `!` mode
//! redacts them); values under keys that are not secret-shaped; secrets
//! the program encrypted, hashed, split, reversed or otherwise transformed
//! before printing; values below the hard `MIN_REDACTION_ENTRY_LENGTH`
//! floor; never-scrub literals (`true`, `null`, …); pure interpolation
//! references (`${API_KEY}`, `${{ secrets.X }}`), which name a source rather
//! than carry a value; and the remainder of a construct beyond the state
//! caps (redacted, but only its bounded prefix is registered).
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
    MIN_REDACTION_ENTRY_LENGTH, NEVER_SCRUB_LITERALS, RedactionTable, credential_shaped_key,
    is_secret_shaped_key,
};

/// Minimum total length for the opaque keyless-credential token rule (the
/// `gh auth token` / `aws configure get …` / digitless `pass show`
/// passphrase shape, wherever it appears).
const KEYLESS_TOKEN_MIN_LEN: usize = 20;

/// Minimum total length for a JWT (`eyJ…` with at least two dots).
const JWT_MIN_LEN: usize = 30;

/// A keyed novel value stays visible (not redacted) when it is below the
/// hard [`MIN_REDACTION_ENTRY_LENGTH`] floor or case-insensitively equals
/// a never-scrub literal. Both exemptions mirror the table builder's
/// candidate prune exactly, so the two boundaries keep one plausibility
/// definition — and above that floor the value's length never gates
/// secrecy (issue #279 cycle 4): the secret-shaped key itself is the
/// secrecy evidence, so `GITHUB_TOKEN=abc123` and a bare
/// `password: hunter2` are scrubbed like any long value. The value-side
/// floor that used to sit here (eight characters for keys outside the
/// `*_PASSWORD`/`*_PIN` family) was the table builder's *collection*
/// cost model — an anti-false-positive bound for installing a persistent
/// pattern that scrubs all traffic — carried into a boundary whose own
/// cost model is the opposite (a placeholder here costs one tool result;
/// a miss leaks a credential).
fn keyed_novel_value_is_visible(value: &str) -> bool {
    value.len() < MIN_REDACTION_ENTRY_LENGTH
        || NEVER_SCRUB_LITERALS
            .iter()
            .any(|lit| value.eq_ignore_ascii_case(lit))
}

/// Which shape families a novel-secret scrub applies.
///
/// - [`NovelScrubMode::Full`] is the skill `!`-command boundary: every shape
///   in the module docs, including the fail-closed keyless opaque-token rule
///   that also redacts git SHAs, UUIDs and digests.
/// - [`NovelScrubMode::KeyedNarrow`] is the backstop for ordinary shell,
///   custom-tool and background-job output, where hashes and UUIDs are the
///   work product and must survive. It keeps the keyed forms (whose key is
///   the secrecy evidence), well-known credential formats, JWTs and PEM
///   private-key blocks, adds URL-userinfo passwords
///   (`scheme://user:PASS@host`), and drops the keyless opaque-token rule.
///   Short all-digit values under keys outside the `*_PIN`/`*_PASSWORD`/
///   `*_PASSWD`/`*_SECRET` family (`"max_tokens": 4096`) are redacted in
///   place but not registered: they are probably counts, and registering
///   them would rewrite unrelated numbers. Values that are only a braced
///   interpolation reference stay visible (`API_KEY=${API_KEY}`,
///   `token: ${{ secrets.GITHUB_TOKEN }}`, `postgres://u:${DB_PASSWORD}@db`):
///   they name a secret's source, and registering them would rewrite every
///   compose file and workflow the agent reads afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NovelScrubMode {
    Full,
    KeyedNarrow,
}

/// Below this length an all-digit keyed value outside the credential-shaped
/// key family is a count or limit in [`NovelScrubMode::KeyedNarrow`].
const NARROW_NUMERIC_VALUE_MIN_LEN: usize = 8;

/// A value a novel-secret scrub replaced, carried back so the caller can
/// register it in the session redaction table. Registration then catches
/// later echoes of the same value (and its encoded / case variants) that no
/// longer carry the shape the scrub keyed on.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ObservedSecret {
    pub(crate) value: String,
    /// Exempt from the table's `min_secret_length` prune: the value's own
    /// format (a known credential prefix, a JWT, a PEM block) or its
    /// credential-shaped key is the secrecy evidence.
    pub(crate) length_exempt: bool,
    /// Register base64 / hex / URL encodings.
    pub(crate) encoded_variants: bool,
    /// Register lower / upper / capitalized spellings.
    pub(crate) case_variants: bool,
}

impl std::fmt::Debug for ObservedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservedSecret")
            .field("value", &format_args!("[REDACTED; {}]", self.value.len()))
            .field("length_exempt", &self.length_exempt)
            .field("encoded_variants", &self.encoded_variants)
            .field("case_variants", &self.case_variants)
            .finish()
    }
}

/// A bounded, deduplicated accumulation of observations (one command's
/// intake, a background job's pending registrations). A value observed
/// again merges to the STRONGEST policy (R11); the total retained value
/// bytes are capped at [`MAX_PENDING_FOUND_BYTES`] — beyond it new values are
/// dropped (their output was already replaced). Linear in what it is fed.
#[derive(Default)]
pub(crate) struct ObservedSet {
    items: Vec<ObservedSecret>,
    index: HashMap<String, usize>,
    bytes: usize,
}

impl ObservedSet {
    pub(crate) fn extend(&mut self, found: impl IntoIterator<Item = ObservedSecret>) {
        for secret in found {
            if let Some(&at) = self.index.get(&secret.value) {
                let existing = &mut self.items[at];
                existing.length_exempt |= secret.length_exempt;
                existing.encoded_variants |= secret.encoded_variants;
                existing.case_variants |= secret.case_variants;
                continue;
            }
            if self.bytes.saturating_add(secret.value.len()) > MAX_PENDING_FOUND_BYTES {
                continue;
            }
            self.bytes += secret.value.len();
            self.index.insert(secret.value.clone(), self.items.len());
            self.items.push(secret);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn take(&mut self) -> Vec<ObservedSecret> {
        self.index.clear();
        self.bytes = 0;
        std::mem::take(&mut self.items)
    }
}

impl ObservedSecret {
    /// A value under a secret-shaped key. The key is the secrecy evidence, so
    /// the value is registered down to the hard [`MIN_REDACTION_ENTRY_LENGTH`]
    /// floor regardless of `min_secret_length`. The backstop registers what it
    /// replaces; a short `password: hunter2` is not silently left unregistered.
    fn keyed(key: &str, value: &str) -> Self {
        let credential = credential_shaped_key(key);
        Self {
            value: strip_matching_quotes(value).to_string(),
            length_exempt: true,
            encoded_variants: true,
            case_variants: credential,
        }
    }

    fn known_format(value: &str) -> Self {
        Self {
            value: value.to_string(),
            length_exempt: true,
            encoded_variants: true,
            case_variants: false,
        }
    }

    fn literal(value: String, length_exempt: bool) -> Self {
        Self {
            value,
            length_exempt,
            encoded_variants: false,
            case_variants: false,
        }
    }
}

/// The result of a novel-secret scrub: the rewritten text plus every value
/// it replaced, deduplicated, in first-seen order.
pub(crate) struct NovelScrubOutput {
    pub(crate) text: String,
    pub(crate) found: Vec<ObservedSecret>,
}

impl std::fmt::Debug for NovelScrubOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NovelScrubOutput")
            .field("text_len", &self.text.len())
            .field("found", &self.found)
            .finish()
    }
}

/// Strip one layer of matching surrounding quotes (`"v"` / `'v'`).
fn strip_matching_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// `true` when `value` (one layer of matching quotes stripped) is nothing but
/// a braced interpolation reference — `${NAME}` or a GitHub Actions
/// `${{ secrets.NAME }}` expression — which names where a secret comes from
/// rather than carrying one. Deliberately strict so no literal can hide
/// behind the shape: the inner text must be a plain identifier (`${NAME}`,
/// no `:-default` / `=default` operator, whose default could be a literal
/// secret) or a dotted identifier path (`${{ secrets.NAME }}`, no operators
/// or quoted literals). A bare `$NAME` is NOT exempt: a literal password may
/// begin with `$`.
fn is_interpolation_reference(value: &str) -> bool {
    let bare = strip_matching_quotes(value);
    if let Some(inner) = bare
        .strip_prefix("${{")
        .and_then(|rest| rest.strip_suffix("}}"))
    {
        let path = inner.trim();
        return !path.is_empty()
            && path.starts_with(|c: char| c.is_ascii_alphabetic())
            && path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    }
    let Some(name) = bare
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Record a replaced keyed value: the raw spelling the output carried, its
/// DECODED form (JSON string escapes for a double-quoted value, doubled
/// `''` for a single-quoted YAML value), and the literal default of any
/// `${NAME:-default}`-style reference. A later plaintext or encoded echo of
/// the decoded value would otherwise survive a table that registered only the
/// escaped spelling.
fn observe_keyed(found: &mut Vec<ObservedSecret>, key: &str, raw: &str, quote: Option<char>) {
    let bare = strip_matching_quotes(raw);
    let quote = quote.or_else(|| {
        let first = raw.chars().next()?;
        (raw.len() >= 2 && matches!(first, '"' | '\'') && raw.ends_with(first)).then_some(first)
    });
    if is_short_count(key, bare) {
        // A short all-digit value under a count-like key (`max_tokens: 4096`)
        // is replaced in this output but not registered session-wide, for the
        // same false-positive reason as code types below.
        return;
    }
    if quote.is_none() && is_code_type_expression(bare) {
        // An UNQUOTED source-code type annotation (`password: String,`) is
        // replaced in this output but never registered session-wide: the
        // false-positive cost of installing `String` as a secret is the only
        // reason for the distinction, so the value is still withheld here.
        // A quoted data string (`{"password":"String"}`) is a value and is
        // registered like any other.
        return;
    }
    found.push(ObservedSecret::keyed(key, bare));
    let decoded = match quote {
        Some('"') if bare.contains('\\') => json_unescape(bare),
        Some('\'') if bare.contains("''") => Some(bare.replace("''", "'")),
        _ => None,
    };
    if let Some(decoded) = decoded.filter(|decoded| decoded != bare) {
        found.push(ObservedSecret::keyed(key, &decoded));
    }
    for default in reference_default_literals(bare) {
        found.push(ObservedSecret::keyed(key, &default));
    }
}

/// Decode JSON string escapes (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`,
/// `\t`, `\uXXXX` including surrogate pairs). `None` for an invalid escape.
pub(super) fn json_unescape(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                let unit = u16::from_str_radix(&hex, 16).ok()?;
                if (0xD800..0xDC00).contains(&unit) {
                    if chars.next()? != '\\' || chars.next()? != 'u' {
                        return None;
                    }
                    let low_hex: String = chars.by_ref().take(4).collect();
                    let low = u16::from_str_radix(&low_hex, 16).ok()?;
                    out.push(char::decode_utf16([unit, low]).next()?.ok()?);
                } else {
                    out.push(char::from_u32(u32::from(unit))?);
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Literal defaults inside shell-style references: `${NAME:-default}` (and
/// `-`, `:=`, `=`, `:+`, `+`, `:?`, `?`), recursively through nested
/// references. The whole reference expression is replaced in the output;
/// its literal default component is registered on its own as well, since a
/// later echo prints only the default.
fn reference_default_literals(value: &str) -> Vec<String> {
    /// Nesting beyond this depth registers nothing further (the whole
    /// expression is still replaced in the output).
    const MAX_REFERENCE_DEPTH: usize = 64;
    let mut out = Vec::new();
    let mut current = value;
    for _ in 0..MAX_REFERENCE_DEPTH {
        let Some(inner) = current
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'))
        else {
            break;
        };
        let name_end = inner
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(inner.len());
        let rest = &inner[name_end..];
        let default = [":-", ":=", ":+", ":?", "-", "=", "+", "?"]
            .iter()
            .find_map(|op| rest.strip_prefix(op));
        match default.filter(|default| !default.is_empty()) {
            Some(default) if default.starts_with("${") => current = default,
            Some(default) => {
                out.push(default.to_string());
                break;
            }
            None => break,
        }
    }
    out
}

/// `true` when a keyed value is a source-code TYPE annotation, not a value:
/// `password: String,` in a Rust struct, `token: string;` in TypeScript,
/// `api_key: Option<SecretString>`. Reading source files through the shell
/// is the core of a coding agent's work; scrubbing and registering `String`
/// as a session-wide secret would rewrite every later file it reads. Only a
/// closed vocabulary of primitive and wrapper type names qualifies (an
/// arbitrary CamelCase word could be a real password), with generic
/// arguments drawn from the same vocabulary or other CamelCase names.
fn is_code_type_expression(value: &str) -> bool {
    const PRIMITIVES: &[&str] = &[
        "String",
        "str",
        "bool",
        "char",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "f32",
        "f64",
        "string",
        "number",
        "boolean",
        "any",
        "unknown",
        "Bytes",
        "PathBuf",
        "Path",
        "Uuid",
        "Value",
        "SecretString",
    ];
    const WRAPPERS: &[&str] = &[
        "Option",
        "Vec",
        "Box",
        "Arc",
        "Rc",
        "Cow",
        "HashMap",
        "BTreeMap",
        "Result",
        "Zeroizing",
        "SecretBox",
        "Mutex",
        "RwLock",
        "Cell",
        "RefCell",
        "Array",
        "Promise",
        "Record",
    ];
    /// Generic nesting beyond this depth is not a recognized type.
    const MAX_TYPE_DEPTH: usize = 16;
    fn bare_type(value: &str) -> &str {
        let value = strip_matching_quotes(value.trim().trim_end_matches([',', ';']).trim());
        let value = value.strip_prefix('&').unwrap_or(value);
        value
            .strip_prefix("'static ")
            .or_else(|| value.strip_prefix("'a "))
            .unwrap_or(value)
            .trim_start_matches("mut ")
            .trim()
    }
    let mut pending: Vec<(&str, usize)> = vec![(bare_type(value), 0)];
    while let Some((value, depth)) = pending.pop() {
        if PRIMITIVES.contains(&value) {
            continue;
        }
        if depth > 0
            && value.starts_with(|c: char| c.is_ascii_uppercase())
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
        {
            continue;
        }
        if depth >= MAX_TYPE_DEPTH {
            return false;
        }
        let Some(open) = value.find('<') else {
            return false;
        };
        let (outer, rest) = value.split_at(open);
        let Some(inner) = rest
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
        else {
            return false;
        };
        if !WRAPPERS.contains(&outer) || inner.is_empty() {
            return false;
        }
        // Split the generic arguments at top-level commas only.
        let mut level = 0usize;
        let mut arg_start = 0usize;
        for (at, c) in inner.char_indices() {
            match c {
                '<' => level += 1,
                '>' => level = level.saturating_sub(1),
                ',' if level == 0 => {
                    pending.push((bare_type(&inner[arg_start..at]), depth + 1));
                    arg_start = at + 1;
                }
                _ => {}
            }
        }
        pending.push((bare_type(&inner[arg_start..]), depth + 1));
    }
    true
}

/// A short all-digit value under a count-like key.
fn is_short_count(key: &str, value: &str) -> bool {
    is_count_like_key(key)
        && !value.is_empty()
        && value.len() < NARROW_NUMERIC_VALUE_MIN_LEN
        && value.bytes().all(|b| b.is_ascii_digit())
}

/// Keys whose short all-digit values are counts or limits (`max_tokens`,
/// `token_count`, `timeout`), never credentials. The secret-shaped key
/// predicate deliberately matches the `tokens` segment, so this narrower
/// list, not the absence of a `_PASSWORD`/`_PIN` suffix, decides the
/// [`NovelScrubMode::KeyedNarrow`] count exemption. A key that also names
/// a password, PIN, secret or key segment is never count-like.
fn is_count_like_key(key: &str) -> bool {
    let segments = super::key_name_segments(key);
    let counting = segments.iter().any(|segment| {
        matches!(
            segment.as_str(),
            "tokens"
                | "count"
                | "counts"
                | "limit"
                | "limits"
                | "max"
                | "min"
                | "size"
                | "length"
                | "ttl"
                | "timeout"
                | "budget"
                | "usage"
                | "total"
                | "expiry"
                | "expires"
                | "lifetime"
        )
    });
    let credential = segments.iter().any(|segment| {
        matches!(
            segment.as_str(),
            "password" | "passwd" | "pin" | "secret" | "passphrase" | "key" | "apikey"
        )
    });
    counting && !credential
}

/// Keyed-value visibility under `mode`: the shared plausibility floor (hard
/// four-byte floor, never-scrub literals), plus the one
/// [`NovelScrubMode::KeyedNarrow`] exemption that carries no value at all — a
/// braced interpolation reference ([`is_interpolation_reference`]). Every
/// other heuristic (code types, short counts) still REPLACES the value and
/// only skips its session-wide registration ([`observe_keyed`]).
fn keyed_value_is_visible(mode: NovelScrubMode, _key: &str, value: &str) -> bool {
    if keyed_novel_value_is_visible(value) {
        return true;
    }
    if mode == NovelScrubMode::KeyedNarrow && is_interpolation_reference(value) {
        return true;
    }
    false
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
        self.scrub_novel_command_output_secrets_with_mode(body, NovelScrubMode::Full)
            .text
    }

    /// [`Self::scrub_novel_command_output_secrets`] under an explicit
    /// [`NovelScrubMode`], also returning every replaced value so the caller
    /// can register it in the session table.
    pub(crate) fn scrub_novel_command_output_secrets_with_mode(
        &self,
        body: &str,
        mode: NovelScrubMode,
    ) -> NovelScrubOutput {
        if self.disabled {
            return NovelScrubOutput {
                text: body.to_string(),
                found: Vec::new(),
            };
        }
        let mut stream = NovelScrubStream::new(&self.placeholder, mode);
        let mut lines: Vec<(Option<String>, &str)> = Vec::new();
        for line in body.split_inclusive('\n') {
            let (content, newline) = match line.strip_suffix('\n') {
                Some(content) => (content, "\n"),
                None => (line, ""),
            };
            lines.push((stream.push_line(content), newline));
        }
        stream.finish();
        // A bounded capture (head + tail around an omission) or a tail slice
        // can start inside a PEM private-key block whose BEGIN fence was
        // dropped. An END fence with no open block is the evidence: the
        // base64 run immediately before it is key material too.
        if stream.mode_scrubs_orphan_pem() {
            redact_orphan_private_key_bodies(&mut lines, &self.placeholder, &mut stream.found);
        }
        let mut out = String::with_capacity(body.len());
        for (text, newline) in &lines {
            // A dropped line (inside a collapsed PEM block or a multiline
            // secret value) disappears together with its newline.
            if let Some(text) = text {
                out.push_str(text);
                out.push_str(newline);
            }
        }
        NovelScrubOutput {
            text: out,
            found: stream.take_found(),
        }
    }
}

/// The open quoted value of a secret-keyed assignment / colon pair that did
/// not close on its own line (a multiline dotenv or YAML quoted value).
#[derive(Clone)]
struct OpenQuote {
    quote: char,
    key: String,
    parts: Vec<String>,
    /// Bytes retained in `parts` (capped by [`MAX_RETAINED_CONSTRUCT_BYTES`]).
    retained: usize,
}

/// An open YAML block scalar under a secret-shaped key.
#[derive(Clone)]
struct OpenBlock {
    key: String,
    key_indent: usize,
    /// `|` (literal: lines joined by newlines) or `>` (folded: by spaces).
    style: char,
    lines: Vec<String>,
    retained: usize,
}

/// A secret-shaped key whose value continues on the NEXT non-blank line
/// (`"password":` / `password:` with nothing after the separator).
#[derive(Clone)]
struct PendingKeyValue {
    key: String,
}

/// An XML element under a secret-shaped tag opened without its closing tag
/// on the same line: its value runs until `</tag>`.
#[derive(Clone)]
struct OpenXml {
    tag: String,
    parts: Vec<String>,
    retained: usize,
}

/// Hard cap on the raw bytes any one open multi-line construct (PEM block,
/// multiline quoted value, block scalar, XML element) retains for
/// registration. Past it the construct's remaining lines are still dropped
/// from the output (withheld) but no longer retained, so endless adversarial
/// output after an opening fence cannot grow scanner memory without bound.
pub(crate) const MAX_RETAINED_CONSTRUCT_BYTES: usize = 256 * 1024;

/// Hard cap on the bytes of observed values one stream accumulates between
/// two `take_found` drains.
const MAX_PENDING_FOUND_BYTES: usize = 1024 * 1024;

/// Upper bound on a JOINED multi-line value registered as one literal (a PEM
/// block, a block scalar, a multi-line quoted or XML value). A credential
/// spanning several lines is far smaller; above this the joined spelling is
/// not registered (each line still is) — registering a quarter-megabyte
/// literal, with its encoded variants, would cost every later scrub and the
/// persisted table without protecting anything a per-line entry does not.
const MAX_JOINED_REGISTRATION_BYTES: usize = 16 * 1024;

/// Single-character stand-in for the configured placeholder while a line is
/// parsed. The real placeholder can contain spaces (the default marker does):
/// substituting it first makes it one opaque token the scalar tokenizers can
/// never split into a "value", so scanner output is never re-observed.
const PLACEHOLDER_SENTINEL: &str = "\u{1}";

/// Line-at-a-time novel-secret scrubber. It carries every multi-line shape's
/// state (PEM private-key blocks, YAML block scalars under secret keys,
/// multiline quoted secret values, keyed values on the next line, multi-line
/// XML elements) across lines, so a caller can scrub output AS IT ARRIVES —
/// background jobs, and the pipe intake of foreground shell / custom-tool
/// capture — and slice, window, evict or head/tail-bound only already
/// scrubbed lines afterwards. All state is bounded
/// ([`MAX_RETAINED_CONSTRUCT_BYTES`], [`MAX_PENDING_FOUND_BYTES`]).
pub(crate) struct NovelScrubStream {
    placeholder: String,
    mode: NovelScrubMode,
    in_private_key_block: bool,
    private_key_lines: Vec<String>,
    private_key_retained: usize,
    block_scalar: Option<OpenBlock>,
    open_quote: Option<OpenQuote>,
    pending_key: Option<PendingKeyValue>,
    open_xml: Option<OpenXml>,
    /// The previous physical line was cut by a reader's line cap: its
    /// discarded remainder could have opened a construct (a PEM BEGIN
    /// fence, a block scalar). Until a line proves otherwise, fail closed.
    uncertain: Option<UncertainContext>,
    found: Vec<ObservedSecret>,
    found_bytes: usize,
}

#[derive(Clone, Copy)]
enum UncertainContext {
    /// After a cut line: base64-only lines are treated as private-key
    /// body, more-indented lines as a block scalar body.
    AfterCutLine { indent: usize },
}

impl NovelScrubStream {
    pub(crate) fn new(placeholder: &str, mode: NovelScrubMode) -> Self {
        Self {
            placeholder: placeholder.to_string(),
            mode,
            in_private_key_block: false,
            private_key_lines: Vec::new(),
            private_key_retained: 0,
            block_scalar: None,
            open_quote: None,
            pending_key: None,
            open_xml: None,
            uncertain: None,
            found: Vec::new(),
            found_bytes: 0,
        }
    }

    fn mode_scrubs_orphan_pem(&self) -> bool {
        true
    }

    /// Scrub one line (without its newline); returns the replacement line,
    /// or `None` when the line is dropped entirely (it lies inside a
    /// collapsed PEM block, a multiline secret value or a secret XML element).
    pub(crate) fn push_line(&mut self, content: &str) -> Option<String> {
        let masked = if self.placeholder.is_empty() {
            content.to_string()
        } else {
            content.replace(&self.placeholder, PLACEHOLDER_SENTINEL)
        };
        let before = self.found.len();
        let out = self.push_masked(&masked);
        self.account_found(before);
        out.map(|line| line.replace(PLACEHOLDER_SENTINEL, &self.placeholder))
    }

    /// [`Self::push_line`] for a physical line a reader CUT at its line cap
    /// (`prefix` is what was kept; the remainder was discarded unseen). The
    /// prefix is scrubbed as an ordinary line, then the stream fails closed
    /// for the context the discarded remainder could have opened.
    pub(crate) fn push_truncated_line(&mut self, prefix: &str) -> Option<String> {
        let indent = prefix.len() - prefix.trim_start().len();
        let tail_could_open_pem = prefix.contains("-----") || prefix.len() > 16;
        let out = self.push_line(prefix);
        if !self.in_private_key_block && tail_could_open_pem {
            self.uncertain = Some(UncertainContext::AfterCutLine { indent });
        }
        out
    }

    fn account_found(&mut self, before: usize) {
        // Bounded and linear in what this line added: keep the new
        // observations while they fit under the cap, drop the rest (the
        // output for every dropped observation was already replaced).
        let mut keep = before;
        for index in before..self.found.len() {
            let len = self.found[index].value.len();
            if self.found_bytes.saturating_add(len) > MAX_PENDING_FOUND_BYTES {
                break;
            }
            self.found_bytes += len;
            keep = index + 1;
        }
        self.found.truncate(keep);
    }

    fn push_masked(&mut self, content: &str) -> Option<String> {
        let placeholder = PLACEHOLDER_SENTINEL;
        if self.in_private_key_block {
            // The whole block collapsed to one placeholder at its BEGIN
            // fence; keep dropping lines (the END fence included) until the
            // block closes. Retention is capped; dropping is not.
            if self.private_key_retained < MAX_RETAINED_CONSTRUCT_BYTES {
                self.private_key_retained += content.len();
                self.private_key_lines.push(content.to_string());
            }
            if is_private_key_fence(content, "-----END") {
                self.in_private_key_block = false;
                self.private_key_retained = 0;
                observe_private_key_block(&mut self.private_key_lines, &mut self.found);
            }
            return None;
        }
        if let Some(open) = self.open_quote.as_mut() {
            // Continuation of a multiline quoted secret value: drop the value
            // text up to its closing quote; the rest of the line is ordinary.
            match closing_quote(content, open.quote) {
                Some(close) => {
                    retain_part(&mut open.parts, &mut open.retained, &content[..close]);
                    let open = self.open_quote.take().expect("open quote");
                    observe_multiline_value(&mut self.found, &open);
                    let rest = &content[close..];
                    return Some(self.scrub_ordinary(rest));
                }
                None => {
                    retain_part(&mut open.parts, &mut open.retained, content);
                    return None;
                }
            }
        }
        if let Some(open) = self.open_xml.as_mut() {
            let close_tag = format!("</{}>", open.tag);
            match content.find(&close_tag) {
                Some(close) => {
                    retain_part(&mut open.parts, &mut open.retained, &content[..close]);
                    let open = self.open_xml.take().expect("open xml");
                    observe_joined_value(&mut self.found, &open.tag, &open.parts, "\n");
                    let rest = &content[close..];
                    return Some(self.scrub_ordinary(rest));
                }
                None => {
                    retain_part(&mut open.parts, &mut open.retained, content);
                    return None;
                }
            }
        }
        if is_private_key_fence(content, "-----BEGIN") {
            self.in_private_key_block = true;
            self.uncertain = None;
            self.private_key_retained = content.len();
            self.private_key_lines.push(content.to_string());
            return Some(placeholder.to_string());
        }
        if let Some(UncertainContext::AfterCutLine { indent: cut_indent }) = self.uncertain {
            let trimmed = content.trim();
            let indent = content.len() - content.trim_start().len();
            if is_private_key_fence(content, "-----END") {
                // The END of a block whose BEGIN was in the discarded part of
                // the cut line: everything since was already withheld.
                self.uncertain = None;
                return None;
            }
            if is_pem_body_line(trimmed) {
                if trimmed.len() >= PRIVATE_KEY_LINE_MIN_LEN {
                    self.found
                        .push(ObservedSecret::literal(trimmed.to_string(), true));
                }
                return Some(format!("{}{placeholder}", &content[..indent]));
            }
            if !trimmed.is_empty() && indent > cut_indent {
                // Could be the body of a block scalar opened in the cut-off
                // remainder: withhold it in this output. Not registered —
                // the context that would make it a secret is unknown.
                return Some(format!("{}{placeholder}", &content[..indent]));
            }
            if !trimmed.is_empty() {
                self.uncertain = None;
            }
        }
        if let Some(block) = self.block_scalar.as_mut() {
            let indent = content.len() - content.trim_start().len();
            let trimmed = content.trim();
            if trimmed.is_empty() {
                // Blank lines do not close a YAML block scalar.
                return Some(content.to_string());
            }
            if indent > block.key_indent {
                if trimmed != placeholder && !keyed_novel_value_is_visible(trimmed) {
                    retain_part(&mut block.lines, &mut block.retained, trimmed);
                    let key = block.key.clone();
                    self.found.push(ObservedSecret::keyed(&key, trimmed));
                    return Some(format!("{}{placeholder}", &content[..indent]));
                }
                return Some(content.to_string());
            }
            // Dedent closes the block; this line is normal output.
            let block = self.block_scalar.take().expect("open block");
            observe_block_scalar(&mut self.found, &block);
        }
        if let Some(pending) = self.pending_key.take() {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                self.pending_key = Some(pending);
                return Some(content.to_string());
            }
            if let Some(out) = self.scrub_next_line_value(content, &pending.key) {
                return Some(out);
            }
        }
        Some(self.scrub_ordinary(content))
    }

    /// The value line after a dangling secret-shaped key: a quoted JSON/YAML
    /// string, or a plain scalar (comments and tags stripped), up to a
    /// trailing comma. `None` when the line is structure (`{`, `[`, `-`, a
    /// block indicator) rather than a scalar value.
    fn scrub_next_line_value(&mut self, content: &str, key: &str) -> Option<String> {
        let indent = content.len() - content.trim_start().len();
        let body = content.trim_end();
        let rest = &body[indent..];
        if rest.starts_with(['{', '[', '-', '|', '>', '}', ']', '<'])
            || looks_like_mapping_key(rest)
        {
            return None;
        }
        let (value_end, quoted) = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => match closing_quote(&rest[1..], q) {
                Some(close) => (close + 2, Some(q)),
                None => return None,
            },
            _ => {
                let end = rest.find(',').unwrap_or(rest.len());
                (end, None)
            }
        };
        let raw = &rest[..value_end];
        let (semantic, _) = yaml_semantic_scalar(raw);
        if semantic.is_empty()
            || keyed_value_is_visible(self.mode, key, strip_matching_quotes(semantic))
        {
            return None;
        }
        observe_keyed(&mut self.found, key, semantic, quoted);
        let mut out = String::with_capacity(content.len());
        out.push_str(&content[..indent]);
        if let Some(q) = quoted {
            out.push(q);
            out.push_str(PLACEHOLDER_SENTINEL);
            out.push(q);
        } else {
            out.push_str(PLACEHOLDER_SENTINEL);
        }
        out.push_str(&rest[value_end..]);
        Some(out)
    }

    /// An ordinary line: the per-line passes, then the constructs this line
    /// opens for the following lines.
    fn scrub_ordinary(&mut self, content: &str) -> String {
        let placeholder = PLACEHOLDER_SENTINEL;
        let intro = secret_shaped_block_scalar_intro(content);
        let pending_key = dangling_secret_key(content);
        let xml_open = secret_xml_open_without_close(content);
        let scrubbed = scrub_line(
            content,
            placeholder,
            self.mode,
            &mut self.found,
            &mut self.open_quote,
        );
        if self.open_quote.is_none() {
            if let Some((indent, key, style)) = intro {
                self.block_scalar = Some(OpenBlock {
                    key,
                    key_indent: indent,
                    style,
                    lines: Vec::new(),
                    retained: 0,
                });
            } else if let Some(key) = pending_key {
                self.pending_key = Some(PendingKeyValue { key });
            } else if let Some((tag, open_end)) = xml_open {
                // Replace everything after the opening tag on this line; the
                // value continues on the next lines until `</tag>`.
                let value_part = content[open_end..].to_string();
                let mut parts = Vec::new();
                let mut retained = 0;
                if !value_part.trim().is_empty() {
                    retain_part(&mut parts, &mut retained, value_part.trim());
                }
                self.open_xml = Some(OpenXml {
                    tag,
                    parts,
                    retained,
                });
                let mut out = content[..open_end].to_string();
                out.push_str(placeholder);
                return out;
            }
        }
        scrubbed
    }

    /// Flush state at end of output: a truncated PEM block or any unclosed
    /// construct is registered from what was captured.
    pub(crate) fn finish(&mut self) {
        let before = self.found.len();
        if !self.private_key_lines.is_empty() {
            observe_private_key_block(&mut self.private_key_lines, &mut self.found);
        }
        self.in_private_key_block = false;
        self.private_key_retained = 0;
        if let Some(open) = self.open_quote.take() {
            observe_multiline_value(&mut self.found, &open);
        }
        if let Some(open) = self.open_xml.take() {
            observe_joined_value(&mut self.found, &open.tag, &open.parts, "\n");
        }
        if let Some(block) = self.block_scalar.take() {
            observe_block_scalar(&mut self.found, &block);
        }
        self.pending_key = None;
        self.uncertain = None;
        self.account_found(before);
    }

    /// Everything replaced so far, one descriptor per value. Duplicate
    /// observations of a value MERGE their policies (strongest wins: length
    /// exemption, encoded and case variants), so a weak first sighting can
    /// never discard a stronger later one. The scanner's own placeholder, any
    /// fragment of it and any value carrying the parse-time placeholder
    /// sentinel are never observations.
    pub(crate) fn take_found(&mut self) -> Vec<ObservedSecret> {
        let placeholder = self.placeholder.clone();
        let found = std::mem::take(&mut self.found);
        self.found_bytes = 0;
        let mut merged: Vec<ObservedSecret> = Vec::with_capacity(found.len());
        let mut index: HashMap<String, usize> = HashMap::new();
        for secret in found {
            if secret.value.is_empty()
                || secret.value.contains(PLACEHOLDER_SENTINEL)
                || placeholder.contains(secret.value.as_str())
            {
                continue;
            }
            match index.get(&secret.value) {
                Some(&at) => {
                    let existing = &mut merged[at];
                    existing.length_exempt |= secret.length_exempt;
                    existing.encoded_variants |= secret.encoded_variants;
                    existing.case_variants |= secret.case_variants;
                }
                None => {
                    index.insert(secret.value.clone(), merged.len());
                    merged.push(secret);
                }
            }
        }
        merged
    }
}

/// Append `part` to a construct's retained parts while it stays under the
/// [`MAX_RETAINED_CONSTRUCT_BYTES`] cap.
fn retain_part(parts: &mut Vec<String>, retained: &mut usize, part: &str) {
    if *retained < MAX_RETAINED_CONSTRUCT_BYTES {
        *retained += part.len();
        parts.push(part.to_string());
    }
}

/// `true` when a line starts a nested mapping entry (`name:` / `name: v` /
/// `"name": v`) — structure, not the scalar value of a dangling key.
fn looks_like_mapping_key(rest: &str) -> bool {
    let key_end = if let Some(q @ ('"' | '\'')) = rest.chars().next() {
        match closing_quote(&rest[1..], q) {
            Some(close) => close + 2,
            None => return false,
        }
    } else {
        rest.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
            .unwrap_or(rest.len())
    };
    key_end > 0
        && rest[key_end..]
            .trim_start()
            .strip_prefix(':')
            .is_some_and(|after| after.is_empty() || after.starts_with(char::is_whitespace))
}

/// `true` for a line that can only be PEM / base64 body text.
fn is_pem_body_line(trimmed: &str) -> bool {
    trimmed.len() >= 16
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

/// Register a closed YAML block scalar: each body line (keyed policy, so
/// encoded variants are registered) plus the scalar's SEMANTIC value —
/// literal style joins lines with newlines, folded style with spaces.
fn observe_block_scalar(found: &mut Vec<ObservedSecret>, block: &OpenBlock) {
    if block.lines.len() > 1 {
        let separator = if block.style == '>' { " " } else { "\n" };
        let joined = block.lines.join(separator);
        if joined.len() <= MAX_JOINED_REGISTRATION_BYTES {
            found.push(ObservedSecret::keyed(&block.key, &joined));
        }
    }
}

/// Register a value assembled from several lines (multi-line XML element).
fn observe_joined_value(found: &mut Vec<ObservedSecret>, key: &str, parts: &[String], sep: &str) {
    let trimmed: Vec<&str> = parts
        .iter()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect();
    if trimmed.is_empty() {
        return;
    }
    let joined = trimmed.join(sep);
    if joined.len() <= MAX_JOINED_REGISTRATION_BYTES
        && !joined.contains('<')
        && !keyed_novel_value_is_visible(&joined)
    {
        found.push(ObservedSecret::keyed(key, &joined));
    }
    for part in &trimmed {
        // Nested markup is withheld with the element but never registered.
        if !part.contains('<') && !keyed_novel_value_is_visible(part) {
            found.push(ObservedSecret::keyed(key, part));
        }
    }
}

/// The secret-shaped key of a line that ENDS with `"key":` / `key:` and no
/// value: its value is on the next non-blank line.
fn dangling_secret_key(content: &str) -> Option<String> {
    let body = content.trim_end();
    let before = body.strip_suffix(':')?.trim_end();
    let key = if let Some(stripped) = before.strip_suffix('"') {
        let open = stripped.rfind('"')?;
        &stripped[open + 1..]
    } else if let Some(stripped) = before.strip_suffix('\'') {
        let open = stripped.rfind('\'')?;
        &stripped[open + 1..]
    } else {
        let start = before
            .rfind(|c: char| c.is_whitespace() || matches!(c, '{' | ',' | '-'))
            .map_or(0, |at| at + 1);
        &before[start..]
    };
    command_output_key_qualifies(key).then(|| key.to_string())
}

/// `(tag, end_of_opening_tag)` for the LAST secret-shaped XML opening tag on
/// the line whose matching closing tag is not on the same line.
fn secret_xml_open_without_close(content: &str) -> Option<(String, usize)> {
    // The LAST markup on the line must be the opening tag (so no `</tag>`
    // follows it), and it must stand at markup position: at the line start,
    // after whitespace or after another tag — never glued to an identifier
    // (`Option<SecretString>` is a type, not an element). One reverse scan
    // and one forward scan: linear in the line.
    let lt = content.rfind('<')?;
    if content[..lt]
        .chars()
        .next_back()
        .is_some_and(|c| !(c.is_whitespace() || c == '>'))
    {
        return None;
    }
    let rest = &content[lt + 1..];
    let gt = rest.find('>')?;
    let tag = &rest[..gt];
    if !is_xml_tag_name(tag) || !is_secret_shaped_key(tag) {
        return None;
    }
    Some((tag.to_string(), lt + 1 + gt + 1))
}

/// The semantic scalar of a plain YAML value: a leading `!tag` and a trailing
/// ` # comment` are stripped. Returns `(semantic, decorated)` where
/// `decorated` tells whether anything was stripped. Quoted values are
/// returned unchanged.
fn yaml_semantic_scalar(raw: &str) -> (&str, bool) {
    let mut value = raw.trim();
    if value.starts_with(['"', '\'']) {
        return (value, false);
    }
    let mut decorated = false;
    if value.starts_with('!') {
        match value.find(char::is_whitespace) {
            Some(space) => {
                value = value[space..].trim_start();
                decorated = true;
            }
            None => return ("", true),
        }
    }
    if let Some(at) = value.find(" #").or_else(|| value.find("\t#")) {
        value = value[..at].trim_end();
        decorated = true;
    }
    (value, decorated)
}

/// Byte offset of the first unescaped closing `quote` on a continuation line
/// (`\"` escapes a double quote; `''` escapes a single quote).
fn closing_quote(content: &str, quote: char) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut i = 0;
    let mut backslashes = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            backslashes += 1;
            i += 1;
            continue;
        }
        if b == quote as u8 {
            if quote == '"' && backslashes % 2 == 1 {
                backslashes = 0;
                i += 1;
                continue;
            }
            if quote == '\'' && bytes.get(i + 1) == Some(&b'\'') {
                i += 2;
                backslashes = 0;
                continue;
            }
            return Some(i);
        }
        backslashes = 0;
        i += 1;
    }
    None
}

/// Register a multiline quoted secret value: the joined value and each
/// distinctive line.
fn observe_multiline_value(found: &mut Vec<ObservedSecret>, open: &OpenQuote) {
    let joined = open.parts.join("\n");
    if joined.len() <= MAX_JOINED_REGISTRATION_BYTES {
        let raw = format!("{q}{joined}{q}", q = open.quote);
        observe_keyed(found, &open.key, &raw, Some(open.quote));
    }
    for part in &open.parts {
        let trimmed = part.trim();
        if trimmed.len() >= MIN_REDACTION_ENTRY_LENGTH {
            found.push(ObservedSecret::literal(trimmed.to_string(), false));
        }
    }
}

/// Replace the base64 run immediately preceding an orphan PEM private-key
/// END fence (one with no open block — its BEGIN fence was cut off), and the
/// fence itself, with the placeholder; register the run's lines.
fn redact_orphan_private_key_bodies(
    lines: &mut [(Option<String>, &str)],
    placeholder: &str,
    found: &mut Vec<ObservedSecret>,
) {
    for end in 0..lines.len() {
        if !lines[end]
            .0
            .as_deref()
            .is_some_and(|line| is_private_key_fence(line, "-----END"))
        {
            continue;
        }
        let mut start = end;
        while start > 0 {
            let Some(candidate) = lines[start - 1].0.as_deref() else {
                break;
            };
            let candidate = candidate.trim();
            let pem_body = !candidate.is_empty()
                && candidate
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
            let pem_header =
                candidate.starts_with("Proc-Type:") || candidate.starts_with("DEK-Info:");
            if !(pem_body || pem_header) {
                break;
            }
            start -= 1;
        }
        let mut block: Vec<String> = lines[start..=end]
            .iter()
            .filter_map(|line| line.0.clone())
            .collect();
        observe_private_key_block(&mut block, found);
        for (index, line) in lines[start..=end].iter_mut().enumerate() {
            line.0 = (index == 0).then(|| placeholder.to_string());
        }
    }
}

/// Minimum length for a single PEM body line registered on its own (a
/// partial echo such as `head -3 id_rsa`). Base64 body lines are 64 wide.
const PRIVATE_KEY_LINE_MIN_LEN: usize = 20;

/// Register a dropped private-key block: the whole block verbatim plus each
/// distinctive body line.
fn observe_private_key_block(lines: &mut Vec<String>, found: &mut Vec<ObservedSecret>) {
    if lines.is_empty() {
        return;
    }
    let joined = lines.join("\n");
    if joined.len() <= MAX_JOINED_REGISTRATION_BYTES {
        found.push(ObservedSecret::literal(joined, true));
    }
    for line in lines.iter() {
        let trimmed = line.trim();
        if trimmed.len() >= PRIVATE_KEY_LINE_MIN_LEN && !trimmed.starts_with("-----") {
            found.push(ObservedSecret::literal(trimmed.to_string(), true));
        }
    }
    lines.clear();
}

/// The per-line pass pipeline. Ordering only matters for idempotency (every
/// pass skips a value already equal to the placeholder), and each pass sees
/// only the previous passes' output, so a line can be scrubbed by any one of
/// them independently.
fn scrub_line(
    content: &str,
    placeholder: &str,
    mode: NovelScrubMode,
    found: &mut Vec<ObservedSecret>,
    open_quote: &mut Option<OpenQuote>,
) -> String {
    let xml = scrub_secret_shaped_xml(content, placeholder, mode, found);
    let assignments = scrub_secret_shaped_assignments(&xml, placeholder, mode, found, open_quote);
    let members = scrub_secret_shaped_quoted_members(&assignments, placeholder, mode, found);
    let flow = scrub_secret_shaped_flow_pairs(&members, placeholder, mode, found);
    let pairs = scrub_secret_shaped_colon_pairs(&flow, placeholder, mode, found, open_quote);
    match mode {
        NovelScrubMode::Full => scrub_keyless_credential_tokens(&pairs, placeholder, found),
        NovelScrubMode::KeyedNarrow => {
            let known = scrub_known_credential_tokens(&pairs, placeholder, found);
            scrub_url_userinfo_passwords(&known, placeholder, found)
        }
    }
}

/// Scrub the password of every `scheme://user:PASS@host` URL on the line
/// (the `DATABASE_URL` / `REDIS_URL` shape, whose key is not secret-shaped).
/// The user name and host survive. The registered value is the whole
/// `user:PASS` userinfo rather than the bare password, so a common password
/// word (`postgres:postgres@`) is not installed as a session-wide pattern on
/// its own while echoes of the same credential pair are still caught.
fn scrub_url_userinfo_passwords(
    content: &str,
    placeholder: &str,
    found: &mut Vec<ObservedSecret>,
) -> String {
    if !content.contains("://") {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(rel) = content[search..].find("://") {
        let sep = search + rel;
        let authority_start = sep + 3;
        search = authority_start;
        // A scheme must precede the separator.
        let has_scheme = content[..sep]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        if !has_scheme {
            continue;
        }
        let authority_len = content[authority_start..]
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '`' | '<' | '>')
            })
            .unwrap_or(content.len() - authority_start);
        let authority_end = authority_start + authority_len;
        let authority = &content[authority_start..authority_end];
        let Some(at) = authority.rfind('@') else {
            continue;
        };
        let userinfo = &authority[..at];
        let Some(colon) = userinfo.find(':') else {
            continue;
        };
        let password = &userinfo[colon + 1..];
        if password.is_empty()
            || password == placeholder
            || keyed_novel_value_is_visible(password)
            || is_interpolation_reference(password)
        {
            search = authority_end;
            continue;
        }
        let user = &userinfo[..colon];
        let password_end = authority_start + at;
        // A username equal to the password is the same secret: withhold the
        // whole userinfo, never print it in the username position.
        let password_start = if user == password {
            authority_start
        } else {
            authority_start + colon + 1
        };
        out.push_str(&content[copied..password_start]);
        if user == password {
            out.push_str(placeholder);
            out.push(':');
        }
        out.push_str(placeholder);
        copied = password_end;
        search = authority_end;
        observe_url_password(found, &userinfo[..colon], password, userinfo);
    }
    out.push_str(&content[copied..]);
    out
}

/// Register a replaced URL-userinfo password: the password as replaced and
/// its percent-DECODED form (what a later bare echo prints), each with
/// encoded variants and down to the hard floor, plus the whole
/// `user:password` pair. There is no vocabulary or username-equality
/// exception: a common word or a reused user name can be the actual
/// credential.
fn observe_url_password(
    found: &mut Vec<ObservedSecret>,
    _user: &str,
    password: &str,
    userinfo: &str,
) {
    // Published defaults (`postgres:postgres@`, `root:root@`): the password is
    // still replaced in this output, but registering the bare word would
    // rewrite every later mention of `postgres` or `root`, so only the
    // `user:password` pair is registered (the R5/R6 policy: redact here,
    // never leave visible, register only what cannot be ordinary text).
    // Equality with the username is NOT an exemption: a novel value used as
    // both is a novel secret.
    const WELL_KNOWN_DEFAULTS: &[&str] = &[
        "password", "postgres", "root", "admin", "guest", "changeme", "example", "test", "user",
        "pass", "mysql", "redis", "secret", "default",
    ];
    found.push(ObservedSecret::literal(userinfo.to_string(), true));
    let decoded = percent_decode(password).unwrap_or_else(|| password.to_string());
    if WELL_KNOWN_DEFAULTS
        .iter()
        .any(|default| decoded.eq_ignore_ascii_case(default))
    {
        return;
    }
    for value in [password.to_string(), decoded] {
        found.push(ObservedSecret {
            value,
            length_exempt: true,
            encoded_variants: true,
            case_variants: false,
        });
    }
}

/// Percent-decode `%XX` escapes; `None` for a malformed escape or a
/// non-UTF-8 result.
fn percent_decode(raw: &str) -> Option<String> {
    if !raw.contains('%') {
        return Some(raw.to_string());
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
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
fn scrub_secret_shaped_xml(
    line: &str,
    placeholder: &str,
    mode: NovelScrubMode,
    found: &mut Vec<ObservedSecret>,
) -> String {
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
                if value != placeholder && !keyed_value_is_visible(mode, tag, value) {
                    observe_keyed(found, tag, value, None);
                    out.push_str(&line[copied..value_start]);
                    out.push_str(placeholder);
                    // Only the inner text is secret: the close tag is
                    // structure and survives, so copy resumes at it while
                    // the scan resumes after it.
                    copied = close_start;
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
/// not reinterpreted as keys. Quoted values (escaped quotes honored — an
/// embedded `\"` is value text, never the closing delimiter) lose their
/// quotes; keys and surroundings survive.
fn scrub_secret_shaped_assignments(
    content: &str,
    placeholder: &str,
    mode: NovelScrubMode,
    found: &mut Vec<ObservedSecret>,
    open_quote: &mut Option<OpenQuote>,
) -> String {
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
        // the value ends at that string's closing quote. A quote that is
        // itself escaped (`\"`) is a literal quote, not a string opener:
        // the shared escape-aware index decides, because a naive byte
        // check would hunt a closing quote that does not exist and drop
        // the whole assignment (leaking a bare value).
        let opening_quote = match key_start.checked_sub(1).and_then(|idx| bytes.get(idx)) {
            Some(&q @ (b'"' | b'\'')) if quotes.is_delimiter(q, key_start - 1) => Some(q),
            _ => None,
        };
        let mut redacted: Option<(usize, usize)> = None;
        if at_boundary && command_output_key_qualifies(key) {
            match assignment_value_span(content, eq + 1, opening_quote, query_context, &quotes) {
                Some((value_start, value_end)) => {
                    let value = &content[value_start..value_end];
                    if value != placeholder && !keyed_value_is_visible(mode, key, value) {
                        observe_keyed(found, key, value, None);
                        redacted = Some((value_start, value_end));
                    }
                }
                None => {
                    // A value that OPENS a quote it does not close on this
                    // line is a multiline quoted value (dotenv `KEY="a` /
                    // `b"`): fail closed — replace the rest of the line and
                    // carry the open quote to the following lines.
                    if let Some((value_start, quote)) = unclosed_quoted_value(content, eq + 1)
                        && open_quote.is_none()
                    {
                        *open_quote = Some(OpenQuote {
                            quote,
                            key: key.to_string(),
                            parts: vec![content[value_start + 1..].to_string()],
                            retained: content.len() - value_start,
                        });
                        out.push_str(&content[i..value_start]);
                        out.push_str(placeholder);
                        return out;
                    }
                }
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
/// quote runs to its first *unescaped* closing quote — an embedded `\"` is
/// value text, never a delimiter (the span includes both quotes), a value
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
    } else if content[start..].starts_with("${") {
        // A shell reference with an operand (`${X:-default value}`) spans to
        // its MATCHING brace, whitespace included; an unclosed one runs to the
        // end of the line (fail closed, never a literal suffix left behind).
        Some((start, matching_reference_end(content, start)))
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

/// End (exclusive) of the `${…}` reference starting at `start`, matching
/// nested `${` openers; the end of the line when it never closes.
fn matching_reference_end(content: &str, start: usize) -> usize {
    let bytes = content.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'{') {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    content.len()
}

/// `(value_start, quote)` when the assignment value at `after_eq` opens a
/// quote with no unescaped closing quote on the rest of the line.
fn unclosed_quoted_value(content: &str, after_eq: usize) -> Option<(usize, char)> {
    let rest = content.get(after_eq..)?;
    let start = after_eq + (rest.len() - rest.trim_start().len());
    let quote = match content.as_bytes().get(start)? {
        b'"' => '"',
        b'\'' => '\'',
        _ => return None,
    };
    closing_quote(&content[start + 1..], quote)
        .is_none()
        .then_some((start, quote))
}

/// Scrub every `"KEY": "VALUE"` / `'KEY': 'VALUE'` member whose key is
/// secret-shaped and whose value clears the length floor. Unlike the
/// line-anchored colon-pair parser below, this scans quoted members
/// *anywhere* on the line, which is what compact (`{"k":"v"}`) and
/// multi-member (`{"a":"b","SecretKey":"v"}`) JSON requires. Quote style is
/// preserved; a JSON trailing comma sits outside the value and survives.
/// Escaped quotes are honored (issue #279 cycle 5): pairing walks unescaped
/// delimiters only, so a well-formed member whose value embeds a literal
/// quote (`{"API_TOKEN":"ab\"cd"}`) is redacted whole instead of closing at
/// the escaped quote and leaking the value's remainder.
fn scrub_secret_shaped_quoted_members(
    content: &str,
    placeholder: &str,
    mode: NovelScrubMode,
    found: &mut Vec<ObservedSecret>,
) -> String {
    let double = scrub_quoted_members_of_kind(content, placeholder, '"', mode, found);
    scrub_quoted_members_of_kind(&double, placeholder, '\'', mode, found)
}

/// One quote kind of [`scrub_secret_shaped_quoted_members`]: walk same-kind
/// unescaped quote pairs (open, close) in order — via [`QuoteIndex`], so an
/// escaped quote is value text, never a delimiter; when the quoted string
/// is a secret-shaped key, the separator between it and the next quote is
/// a single colon with optional surrounding whitespace, and the string
/// after that separator is a scrubbable value, replace the value.
fn scrub_quoted_members_of_kind(
    content: &str,
    placeholder: &str,
    kind: char,
    mode: NovelScrubMode,
    found: &mut Vec<ObservedSecret>,
) -> String {
    if !content.contains(':') {
        return content.to_string();
    }
    let quotes = QuoteIndex::collect(content);
    let positions = quotes.positions_of(kind);
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut k = 0;
    while k + 1 < positions.len() {
        let key_open = positions[k];
        let key_close = positions[k + 1];
        if key_open < copied {
            k += 2;
            continue;
        }
        let key = &content[key_open + 1..key_close];
        if command_output_key_qualifies(key) {
            let after_key = &content[key_close + 1..];
            let sep_ws = after_key.len() - after_key.trim_start().len();
            let after_colon = after_key[sep_ws..].strip_prefix(':');
            if let Some(after_colon) = after_colon {
                let value_ws = after_colon.len() - after_colon.trim_start().len();
                let value_start = key_close + 1 + sep_ws + 1 + value_ws;
                if content[value_start..].starts_with(kind) && k + 3 < positions.len() {
                    // Quoted value: the next quote pair.
                    let val_open = positions[k + 2];
                    let val_close = positions[k + 3];
                    if val_open == value_start {
                        let value = &content[val_open + 1..val_close];
                        if value != placeholder && !keyed_value_is_visible(mode, key, value) {
                            observe_keyed(found, key, &content[val_open..=val_close], Some(kind));
                            out.push_str(&content[copied..val_open + 1]);
                            out.push_str(placeholder);
                            copied = val_close;
                            k += 4;
                            continue;
                        }
                    }
                } else if !content[value_start..].starts_with(['"', '\'', '{', '[']) {
                    // Unquoted scalar member value (`"api_key": 1234567890`):
                    // runs to the next `,` / `}` / `]` / whitespace.
                    let value_end = content[value_start..]
                        .find(|c: char| matches!(c, ',' | '}' | ']') || c.is_whitespace())
                        .map_or(content.len(), |rel| value_start + rel);
                    let value = &content[value_start..value_end];
                    if !value.is_empty()
                        && value != placeholder
                        && !keyed_value_is_visible(mode, key, value)
                    {
                        observe_keyed(found, key, value, None);
                        out.push_str(&content[copied..value_start]);
                        out.push_str(placeholder);
                        copied = value_end;
                    }
                }
            }
        }
        k += 2;
    }
    out.push_str(&content[copied..]);
    out
}

/// Scrub `KEY: VALUE` members of YAML flow mappings (`{API_KEY: v, x: y}`)
/// whose bare key is secret-shaped. A member starts after `{` or `,`; its
/// value runs to the next `,` / `}` (or its closing quote when quoted).
/// Quoted keys are covered by [`scrub_secret_shaped_quoted_members`].
fn scrub_secret_shaped_flow_pairs(
    content: &str,
    placeholder: &str,
    mode: NovelScrubMode,
    found: &mut Vec<ObservedSecret>,
) -> String {
    if !content.contains('{') || !content.contains(':') {
        return content.to_string();
    }
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !matches!(bytes[i], b'{' | b',') {
            i += 1;
            continue;
        }
        let mut key_start = i + 1;
        while key_start < bytes.len() && matches!(bytes[key_start], b' ' | b'\t') {
            key_start += 1;
        }
        let mut key_end = key_start;
        while key_end < bytes.len() && is_bare_key_char(bytes[key_end]) {
            key_end += 1;
        }
        let key = &content[key_start..key_end];
        if key.is_empty()
            || bytes.get(key_end) != Some(&b':')
            || !matches!(bytes.get(key_end + 1), Some(b' ' | b'\t' | b'"' | b'\''))
            || !command_output_key_qualifies(key)
        {
            i += 1;
            continue;
        }
        let mut value_start = key_end + 1;
        while value_start < bytes.len() && matches!(bytes[value_start], b' ' | b'\t') {
            value_start += 1;
        }
        let quote = bytes
            .get(value_start)
            .copied()
            .filter(|b| matches!(b, b'"' | b'\''));
        let value_end = match quote {
            Some(q) => match closing_quote(&content[value_start + 1..], q as char) {
                Some(close) => value_start + 1 + close + 1,
                None => content.len(),
            },
            None => content[value_start..]
                .find([',', '}'])
                .map_or(content.len(), |rel| value_start + rel),
        };
        let raw = content[value_start..value_end].trim_end();
        let value_end = value_start + raw.len();
        if !raw.is_empty()
            && raw != placeholder
            && !keyed_value_is_visible(mode, key, strip_matching_quotes(raw))
            && strip_matching_quotes(raw) != placeholder
        {
            observe_keyed(found, key, raw, quote.map(|q| q as char));
            out.push_str(&content[copied..value_start]);
            out.push_str(placeholder);
            copied = value_end;
            i = value_end;
            continue;
        }
        i += 1;
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
/// YAML list marker (`- key: value`). A quoted value anchors to the end of
/// the (comma-stripped) line rather than pairing quotes — YAML's doubled
/// `''` single-quote escape makes next-quote pairing ambiguous — so
/// escaped quotes inside the value are covered as value text, and a line
/// whose quotes do not balance passes through untouched.
fn scrub_secret_shaped_colon_pairs(
    content: &str,
    placeholder: &str,
    mode: NovelScrubMode,
    found: &mut Vec<ObservedSecret>,
    open_quote: &mut Option<OpenQuote>,
) -> String {
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
    // optional spacing before the separator: `auth-token : value`). The
    // quoted key's closing quote resolves through the shared escape-aware
    // index, so an escaped quote inside the key cannot shift the pair
    // (keys carrying quote characters stay unclassifiable either way, but
    // delimiter resolution is not allowed to be naive anywhere).
    let quotes = QuoteIndex::collect(content);
    let (key, after_key) = if head.starts_with('"') {
        let Some(close) = quotes.next_of(b'"', head_off + 1) else {
            return content.to_string();
        };
        (&content[head_off + 1..close], close + 1)
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
        Some(q) if value_and_close.len() >= 2 && value_and_close.ends_with(q) => {
            &value_and_close[1..value_and_close.len() - 1]
        }
        Some(q) => {
            // The quoted value opens but does not close on this line: a
            // multiline quoted secret. Fail closed — replace the rest of the
            // line and carry the open quote to the following lines.
            if open_quote.is_none() {
                *open_quote = Some(OpenQuote {
                    quote: q,
                    key: key.to_string(),
                    parts: vec![content[value_start + 1..].to_string()],
                    retained: content.len() - value_start,
                });
            }
            let mut out = String::with_capacity(content.len());
            out.push_str(&content[..value_start]);
            out.push_str(placeholder);
            return out;
        }
        None => value_and_close,
    };
    if is_block_scalar_indicator(value) {
        // `password: |` opens a block scalar; its value is on the next lines.
        return content.to_string();
    }
    if quote.is_none() {
        // A plain YAML scalar's SEMANTIC value: `!!str v` / `v # comment`
        // register and replace `v`; the tag and comment stay visible.
        let (semantic, decorated) = yaml_semantic_scalar(value);
        if decorated {
            if semantic.is_empty()
                || semantic == placeholder
                || keyed_value_is_visible(mode, key, semantic)
            {
                return content.to_string();
            }
            observe_keyed(found, key, semantic, None);
            let offset = semantic.as_ptr() as usize - content.as_ptr() as usize;
            let mut out = String::with_capacity(content.len());
            out.push_str(&content[..offset]);
            out.push_str(placeholder);
            out.push_str(&content[offset + semantic.len()..]);
            return out;
        }
    }
    if keyed_value_is_visible(mode, key, value) || value == placeholder {
        return content.to_string();
    }
    observe_keyed(found, key, value, quote);
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

/// The key-line indent when `content` opens a YAML block scalar under a
/// secret-shaped key — `password: |`, `db_secret: >-`,
/// `token: |2` — whose value lives on the following, more-indented lines
/// and must be scrubbed there. Chomping/indent indicators (`+`, `-`,
/// digits) may follow the `|`/`>`; anything else is an inline value, not a
/// block, and returns `None`. One leading YAML list marker
/// (`- key: |`) is skipped first, so a list-item block classifies exactly
/// like a line-anchored one (the returned floor indentation stays the key
/// line's own indent, which list-item value lines exceed).
fn secret_shaped_block_scalar_intro(content: &str) -> Option<(usize, String, char)> {
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
    is_block_scalar_indicator(indicator).then(|| {
        let style = if indicator.starts_with('>') { '>' } else { '|' };
        (indent, key.to_string(), style)
    })
}

/// `|` / `>` with optional chomping/indent indicators and an optional
/// trailing YAML comment (`| # credential`).
fn is_block_scalar_indicator(value: &str) -> bool {
    let value = value.trim();
    let without_comment = match value.find(" #").or_else(|| value.find("\t#")) {
        Some(at) => value[..at].trim_end(),
        None => value,
    };
    let mut chars = without_comment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '|' || first == '>') && chars.all(|c| matches!(c, '+' | '-' | '0'..='9'))
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
fn scrub_keyless_credential_tokens(
    content: &str,
    placeholder: &str,
    found: &mut Vec<ObservedSecret>,
) -> String {
    // Known formats first: they delimit multi-part tokens (a JWT's dot
    // segments are not opaque-run characters) that the embedded run pass
    // would otherwise chop into partial redactions.
    let known = scrub_known_credential_tokens(content, placeholder, found);
    scrub_embedded_opaque_tokens(&known, placeholder, found)
}

/// `true` when `text` contains a keyless credential shape anywhere — the
/// same well-known credential formats, AWS access-key ids, JWTs, and
/// opaque token runs that [`RedactionTable::scrub_novel_command_output_secrets`]
/// scrubs from command output, evaluated over the whole text with no line
/// or position dependence. This is the shape half of the approval-prompt
/// disclosure fence (issue #286): model-controlled typed text that carries
/// any of these shapes must never render in a human prompt.
pub(super) fn contains_keyless_credential_shape(text: &str) -> bool {
    // The sentinel placeholder is one control character. Every shape rule
    // has a minimum length above one, so the sentinel can never equal a
    // scrubbed run, and the scrubbers only ever *replace* (never delete or
    // rewrite) surrounding content. Input therefore differs from scrubbed
    // output exactly when a shape was replaced, and matches byte-for-byte
    // when no shape is present.
    const SENTINEL: &str = "\u{1}";
    scrub_keyless_credential_tokens(text, SENTINEL, &mut Vec::new()) != text
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
        // A run ending at its own trailing `=` whose trimmed body is a
        // secret-shaped key name is the key of an assignment whose value
        // an earlier pass already replaced with the placeholder (the
        // placeholder is not an opaque character, so the key run now
        // ends at its own `=`; a raw `KEY=<value>` run never reaches this
        // check — the non-trailing-`=` rejection below catches it).
        // Keys are structure and survive every scrub. The gate fires
        // ONLY for that key-suffix shape: a keyless credential that
        // merely shares a key's secret-shaped vocabulary
        // (`novel-passphrase-77aa1234xyz`) is a value, not a key, and
        // must still be redacted wherever the command printed it.
        // The leading-dash trim mirrors the assignment pass's CLI-flag
        // spelling (`--aws-secret-access-key=`).
        && !(token.ends_with('=')
            && command_output_key_qualifies(
                token
                    .trim_end_matches('=')
                    .trim_start_matches('-'),
            ))
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
fn scrub_embedded_opaque_tokens(
    content: &str,
    placeholder: &str,
    found: &mut Vec<ObservedSecret>,
) -> String {
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
            found.push(ObservedSecret::known_format(run));
            out.push_str(&content[copied..start]);
            out.push_str(placeholder);
            copied = idx;
        }
    }
    if let Some(start) = run_start {
        let run = &content[start..];
        if run != placeholder && is_novel_opaque_credential(run) {
            found.push(ObservedSecret::known_format(run));
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
fn scrub_known_credential_tokens(
    content: &str,
    placeholder: &str,
    found: &mut Vec<ObservedSecret>,
) -> String {
    let mut current: Option<String> = None;
    for (prefix, min_total) in CREDENTIAL_PREFIX_RULES {
        let source = current.as_deref().unwrap_or(content);
        if let Cow::Owned(scrubbed) =
            scrub_prefixed_token_run(source, placeholder, prefix, *min_total, found)
        {
            current = Some(scrubbed);
        }
    }
    let source = current.as_deref().unwrap_or(content);
    if let Cow::Owned(scrubbed) = scrub_aws_access_key_ids(source, placeholder, found) {
        current = Some(scrubbed);
    }
    let source = current.as_deref().unwrap_or(content);
    if let Cow::Owned(scrubbed) = scrub_jwt_tokens(source, placeholder, found) {
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
    found: &mut Vec<ObservedSecret>,
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
            found.push(ObservedSecret::known_format(&content[start..end]));
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
fn scrub_aws_access_key_ids<'a>(
    content: &'a str,
    placeholder: &str,
    found: &mut Vec<ObservedSecret>,
) -> Cow<'a, str> {
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
            found.push(ObservedSecret::known_format(&content[start..end]));
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

/// Longest JWT candidate run whose header is decoded (bounded decode work).
const JWT_MAX_CANDIDATE_LEN: usize = 16 * 1024;

/// JWTs (JWS compact serialization): a maximal run of base64url-and-dot
/// characters with exactly three non-empty dot-separated segments, clearing
/// [`JWT_MIN_LEN`], whose first segment base64url-DECODES to a JSON object
/// carrying `alg`. The header's JSON spelling is irrelevant — whitespace in
/// `{ "alg": "HS256" }` changes the `eyJ` prefix, never the decoded object.
/// Each run is visited once (one linear tokenization of the line), so a
/// long `eyJeyJ…` run costs O(n), not a rescan per occurrence.
fn scrub_jwt_tokens<'a>(
    content: &'a str,
    placeholder: &str,
    found: &mut Vec<ObservedSecret>,
) -> Cow<'a, str> {
    if !content.contains('.') {
        return Cow::Borrowed(content);
    }
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut run_start: Option<usize> = None;
    let mut handle_run =
        |start: usize, end: usize, out: &mut Option<String>, copied: &mut usize| {
            let run = &content[start..end];
            if is_jwt_candidate(run) {
                found.push(ObservedSecret::known_format(run));
                let buffer = out.get_or_insert_with(|| String::with_capacity(content.len()));
                buffer.push_str(&content[*copied..start]);
                buffer.push_str(placeholder);
                *copied = end;
            }
        };
    for (idx, ch) in content.char_indices() {
        if is_jwt_char(ch) {
            run_start.get_or_insert(idx);
            continue;
        }
        if let Some(start) = run_start.take() {
            handle_run(start, idx, &mut out, &mut copied);
        }
    }
    if let Some(start) = run_start {
        handle_run(start, content.len(), &mut out, &mut copied);
    }
    match out {
        Some(mut buffer) => {
            buffer.push_str(&content[copied..]);
            Cow::Owned(buffer)
        }
        None => Cow::Borrowed(content),
    }
}

/// See [`scrub_jwt_tokens`].
fn is_jwt_candidate(run: &str) -> bool {
    use base64::Engine as _;
    if run.len() < JWT_MIN_LEN || run.len() > JWT_MAX_CANDIDATE_LEN {
        return false;
    }
    let mut segments = run.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return false;
    }
    let Ok(decoded) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header.trim_end_matches('='))
    else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&decoded)
        .ok()
        .is_some_and(|value| value.get("alg").is_some_and(serde_json::Value::is_string))
}

/// Keys eligible for novel-value redaction: non-empty, starting with an
/// alphanumeric, free of characters that make the "key" a fragment of
/// prose, markup, or a prior assignment rather than a real config key, and
/// secret-shaped. Whitespace is rejected on purpose so prose like
/// `the token: see the docs` never matches.
fn command_output_key_qualifies(key: &str) -> bool {
    // A JSON key spelled with escapes (`"API_\u004bEY"`) is classified by
    // what a JSON consumer reads, not by its raw spelling.
    if key.contains('\\') {
        return json_unescape(key).is_some_and(|decoded| {
            !decoded.contains('\\') && command_output_key_qualifies(&decoded)
        });
    }
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
///
/// Delimiter fidelity (issue #279 cycle 5): a quote preceded by an odd
/// number of consecutive backslashes is escaped — a literal quote inside
/// the delimited value (`\"` in JSON and shell double quotes, `\'` in
/// single-quote styles) — and is never recorded as a delimiter; an even
/// backslash run is escaped backslashes followed by a real closing quote.
/// Every parser here that resolves a quote delimiter goes through this
/// index, so none can close a value at an escaped quote and leak its
/// remainder.
struct QuoteIndex {
    double: Vec<usize>,
    single: Vec<usize>,
}

impl QuoteIndex {
    fn collect(content: &str) -> Self {
        let mut double = Vec::new();
        let mut single = Vec::new();
        // Length of the run of consecutive backslashes ending at the last
        // scanned byte; any other byte (quotes included) resets it.
        let mut backslash_run = 0usize;
        for (idx, ch) in content.char_indices() {
            match ch {
                '\\' => backslash_run += 1,
                '"' | '\'' => {
                    if backslash_run % 2 == 0 {
                        if ch == '"' {
                            double.push(idx);
                        } else {
                            single.push(idx);
                        }
                    }
                    backslash_run = 0;
                }
                _ => backslash_run = 0,
            }
        }
        Self { double, single }
    }

    /// All unescaped `kind` quote positions, in order (the pairing pass
    /// walks these as (open, close) pairs).
    fn positions_of(&self, kind: char) -> &[usize] {
        if kind == '"' {
            &self.double
        } else {
            &self.single
        }
    }

    /// The first quote of `kind` (`"` or `'`) at or after `from`.
    fn next_of(&self, kind: u8, from: usize) -> Option<usize> {
        let positions = self.positions_of(kind as char);
        let idx = positions.partition_point(|&p| p < from);
        positions.get(idx).copied()
    }

    /// Whether the quote of `kind` at byte offset `at` is an unescaped
    /// delimiter (an escaped quote is a literal quote, not an opener).
    fn is_delimiter(&self, kind: u8, at: usize) -> bool {
        let positions = self.positions_of(kind as char);
        positions.binary_search(&at).is_ok()
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

    /// The shape half of the approval-prompt disclosure fence (issue #286):
    /// the predicate must fire for every shape the scrubber scrubs, in any
    /// position, and stay quiet for ordinary prose.
    #[test]
    fn contains_keyless_credential_shape_matches_scrubber_shapes() {
        assert!(contains_keyless_credential_shape(&github_pat()));
        assert!(contains_keyless_credential_shape(&aws_access_key_id()));
        assert!(contains_keyless_credential_shape(&jwt()));
        assert!(contains_keyless_credential_shape(&aws_secret_access_key()));
        assert!(contains_keyless_credential_shape(&digitless_passphrase()));
        // Embedded in prose, not only standing alone: position never
        // decides secrecy.
        assert!(contains_keyless_credential_shape(&format!(
            "here is my key {} ok",
            github_pat()
        )));
        // Ordinary prose and multi-line text with no credential shape.
        assert!(!contains_keyless_credential_shape(
            "hello world, type this into the chat box"
        ));
        assert!(!contains_keyless_credential_shape(
            "line one\nline two\nline three"
        ));
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
    fn escaped_quote_in_quoted_value_is_value_text_not_delimiter() {
        // Issue #279 cycle 5: an escaped quote (`\"`) inside a quoted value
        // is value text, never the closing delimiter. Both the quoted
        // assignment parser and the quoted-member pairing used to close the
        // span at the escaped quote and leak the value's remainder
        // (`SECRET"`), which is invisible to the keyless pass below its
        // 20-character floor.
        let table = table_with_placeholder(PH);
        // Quoted assignment value.
        assert_eq!(
            table.scrub_novel_command_output_secrets("API_TOKEN=\"abcd\\\"SECRET\""),
            "API_TOKEN=[ph]"
        );
        // Compact JSON member.
        assert_eq!(
            table.scrub_novel_command_output_secrets("{\"API_TOKEN\":\"abcd\\\"SECRET\"}"),
            "{\"API_TOKEN\":\"[ph]\"}"
        );
        // Single-quoted member (relaxed JSON / `\'`-escaping styles).
        assert_eq!(
            table.scrub_novel_command_output_secrets("{'api_token':'abcd\\'SECRET'}"),
            "{'api_token':'[ph]'}"
        );
        // An escaped backslash before the quote does not escape the quote:
        // the following quote is the real delimiter, and the text after it
        // is not part of the value.
        assert_eq!(
            table.scrub_novel_command_output_secrets("GITHUB_TOKEN=\"ab\\\\\" trailing"),
            "GITHUB_TOKEN=[ph] trailing"
        );
        // An assignment inside a quoted shell echo whose value embeds
        // escaped quotes: the enclosing string's real close delimits.
        assert_eq!(
            table.scrub_novel_command_output_secrets("echo \"DB_PASSWORD=abc\\\"def\\\"ghi\""),
            "echo \"DB_PASSWORD=[ph]\""
        );
        // Line-anchored colon pair: the quoted value anchors to the line
        // end, so the escaped quote inside is covered without pairing.
        assert_eq!(
            table.scrub_novel_command_output_secrets("password: \"abcd\\\"SECRET\""),
            "password: \"[ph]\""
        );
        // An escaped quote before the key is a literal quote, not a string
        // opener: the value stays bare-scoped instead of being dropped for
        // lack of a closing quote (which used to leak the bare value).
        assert_eq!(
            table.scrub_novel_command_output_secrets("echo \\\"DB_PASSWORD=novelsecret123456"),
            "echo \\\"DB_PASSWORD=[ph]"
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
    fn short_keyed_values_are_redacted_plain_keys_pass_through() {
        // Issue #279 cycle 4: the key's shape is the secrecy evidence, so a
        // keyed value is redacted down to the hard MIN_REDACTION_ENTRY_LENGTH
        // floor for every secret-shaped key. `GITHUB_TOKEN=abc123` (6 chars,
        // broad family) and a bare `password: hunter2` (7 chars) used to cross
        // this boundary unchanged under the old eight-character floor.
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("GITHUB_TOKEN=abc123"),
            "GITHUB_TOKEN=[ph]"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("API_TOKEN=abc123"),
            "API_TOKEN=[ph]"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("password: hunter2"),
            "password: [ph]"
        );
        // Below the hard floor a value is never safe to replace (the table
        // builder's own absolute bound), so it stays visible.
        assert_eq!(
            table.scrub_novel_command_output_secrets("GITHUB_TOKEN=abc"),
            "GITHUB_TOKEN=abc"
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
    fn never_scrub_literals_stay_visible_under_secret_shaped_keys() {
        // The table builder's never-scrub prune is mirrored at this
        // boundary: a boolean/keyword echo under a secret-shaped key is
        // config text, not a secret, and must not be corrupted into a
        // placeholder — including under credential-shaped keys, where the
        // old hard-floor-only check redacted `DB_PASSWORD=null`.
        let table = table_with_placeholder(PH);
        assert_eq!(
            table.scrub_novel_command_output_secrets("DB_PASSWORD=null"),
            "DB_PASSWORD=null"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("api_key: true"),
            "api_key: true"
        );
        assert_eq!(
            table.scrub_novel_command_output_secrets("{\"SECRET_TOKEN\": \"false\",}"),
            "{\"SECRET_TOKEN\": \"false\",}"
        );
        // Case-insensitive, like the prune.
        assert_eq!(
            table.scrub_novel_command_output_secrets("db_password: NULL"),
            "db_password: NULL"
        );
        // Block-scalar values share the same exemption.
        assert_eq!(
            table.scrub_novel_command_output_secrets("db_password: |\n  true\n"),
            "db_password: |\n  true\n"
        );
        // A real short secret under the same key is still scrubbed.
        assert_eq!(
            table.scrub_novel_command_output_secrets("db_password: hunter2"),
            "db_password: [ph]"
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

    // ---- NovelScrubMode::KeyedNarrow (secrets I2: bash / custom-tool /
    // background output backstop) ----

    fn narrow(table: &RedactionTable, body: &str) -> NovelScrubOutput {
        table.scrub_novel_command_output_secrets_with_mode(body, NovelScrubMode::KeyedNarrow)
    }

    fn found_values(out: &NovelScrubOutput) -> Vec<&str> {
        out.found
            .iter()
            .map(|secret| secret.value.as_str())
            .collect()
    }

    #[test]
    fn narrow_dotenv_dump_redacts_secret_keys_and_reports_values() {
        let table = table_with_placeholder(PH);
        let stripe = ["zq8Hc2Lm", "N4pR7tV1wX3y"].concat();
        let body = format!(
            "NODE_ENV=production\nSTRIPE_SECRET_KEY={stripe}\nexport DB_PASSWORD=\"hunter2hunter2\"\nPORT=3000\n"
        );
        let out = narrow(&table, &body);
        assert_eq!(
            out.text,
            "NODE_ENV=production\nSTRIPE_SECRET_KEY=[ph]\nexport DB_PASSWORD=[ph]\nPORT=3000\n"
        );
        assert_eq!(found_values(&out), vec![stripe.as_str(), "hunter2hunter2"]);
        // `DB_PASSWORD` is credential-shaped: length-exempt with case variants.
        let password = &out.found[1];
        assert!(password.length_exempt && password.case_variants);
        // Every keyed value is registered down to the hard floor (r2 C5).
        let stripe_secret = &out.found[0];
        assert!(stripe_secret.length_exempt && stripe_secret.encoded_variants);
    }

    #[test]
    fn narrow_json_members_redact_only_secret_shaped_keys() {
        let table = table_with_placeholder(PH);
        let key = ["k9Vt", "Qw2mZx8LpR4s"].concat();
        let body = format!(
            "{{\"name\": \"demo\", \"api_key\": \"{key}\", \"max_tokens\": 4096, \"version\": \"1.2.3\"}}\n  \"max_tokens\": 4096,\n"
        );
        let out = narrow(&table, &body);
        assert!(!out.text.contains(&key), "{}", out.text);
        assert!(out.text.contains("\"api_key\": \"[ph]\""), "{}", out.text);
        assert!(out.text.contains("\"name\": \"demo\""), "{}", out.text);
        assert!(out.text.contains("\"version\": \"1.2.3\""), "{}", out.text);
        // r3: a short count under a token-ish key is redacted here but not
        // registered (only the api key is observed).
        assert!(!out.text.contains("4096"), "{}", out.text);
        assert_eq!(found_values(&out), vec![key.as_str()]);
    }

    #[test]
    fn narrow_mode_keeps_git_shas_uuids_digests_and_plain_assignments() {
        let table = table_with_placeholder(PH);
        let body = format!(
            "commit {sha}\nHEAD={sha}\nid: 123e4567-e89b-42d3-a456-426614174000\nimage@sha256:{digest}\nRUST_LOG=debug\nDATABASE_HOST=db.internal.example\n{sha}  src/main.rs\n",
            sha = git_sha(),
            digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        );
        let out = narrow(&table, &body);
        assert_eq!(out.text, body);
        assert!(out.found.is_empty());
    }

    #[test]
    fn narrow_mode_redacts_pem_blocks_and_registers_block_and_lines() {
        let table = table_with_placeholder(PH);
        let line = "b3BlbnNzaC1rZXktdjEAAAAAbase64dataMoreBase64Data0123"; // pragma: allowlist secret
        let body = format!(
            "before\n-----BEGIN OPENSSH PRIVATE KEY-----\n{line}\n-----END OPENSSH PRIVATE KEY-----\nafter\n" // pragma: allowlist secret
        );
        let out = narrow(&table, &body);
        assert_eq!(out.text, "before\n[ph]\nafter\n");
        let values = found_values(&out);
        assert!(values.contains(&line), "{:?}", out.found);
        assert!(
            values
                .iter()
                .any(|value| value.starts_with("-----BEGIN") && value.contains(line)),
            "whole block registered: {:?}",
            out.found
        );
    }

    #[test]
    fn narrow_mode_redacts_jwts_and_known_prefix_tokens() {
        let table = table_with_placeholder(PH);
        let body = format!(
            "Authorization header was {jwt}\ntoken is {pat} and key {akid}\n",
            jwt = jwt(),
            pat = github_pat(),
            akid = aws_access_key_id(),
        );
        let out = narrow(&table, &body);
        assert_eq!(
            out.text,
            "Authorization header was [ph]\ntoken is [ph] and key [ph]\n"
        );
        let values = found_values(&out);
        for expected in [jwt(), github_pat(), aws_access_key_id()] {
            assert!(values.contains(&expected.as_str()), "{:?}", out.found);
        }
        assert!(out.found.iter().all(|secret| secret.length_exempt));
    }

    #[test]
    fn narrow_mode_redacts_url_userinfo_passwords_and_registers_the_pair() {
        let table = table_with_placeholder(PH);
        let password = ["s3cr", "etPassw0rd"].concat();
        let body = format!(
            "DATABASE_URL=postgres://app:{password}@db.example:5432/app\nsee https://example.com/a:b@c and https://docs.rs/x\n"
        );
        let out = narrow(&table, &body);
        assert_eq!(
            out.text,
            "DATABASE_URL=postgres://app:[ph]@db.example:5432/app\nsee https://example.com/a:b@c and https://docs.rs/x\n"
        );
        // The pair AND the replaced password itself are registered (r2 C6).
        let registered = format!("app:{password}");
        assert_eq!(
            found_values(&out),
            vec![registered.as_str(), password.as_str()]
        );
    }

    /// Braced interpolation references name a secret's source; the narrow
    /// backstop leaves them (and their compose / workflow files) intact and
    /// registers nothing. Anything that could carry a literal — a `:-`
    /// default, a bare `$NAME`, a partial reference — is still scrubbed.
    #[test]
    fn narrow_mode_keeps_interpolation_references_but_scrubs_literals() {
        let table = table_with_placeholder(PH);
        let references = concat!(
            "API_KEY=${API_KEY}\n",
            "  token: ${{ secrets.GITHUB_TOKEN }}\n",
            "{\"client_secret\": \"${CLIENT_SECRET}\"}\n",
            "DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app\n",
        );
        let out = narrow(&table, references);
        assert_eq!(out.text, references);
        assert!(out.found.is_empty(), "{:?}", out.found);

        let literal = ["hunter2", "hunter2"].concat();
        let body = format!(
            "DB_PASSWORD=${{DB_PASSWORD:-{literal}}}\nAPI_TOKEN=${literal}\nAUTH_TOKEN=prefix${{X}}\npostgres://app:${{P:-{literal}}}@db/app\n"
        );
        let out = narrow(&table, &body);
        assert!(!out.text.contains(&literal), "{}", out.text);
        assert!(out.text.contains("AUTH_TOKEN=[ph]"), "{}", out.text);
    }

    #[test]
    fn full_mode_is_unchanged_for_skill_bang_output() {
        // Skill `!`-commands stay on the fail-closed Full mode: a standalone
        // SHA is still redacted there, and the public wrapper is Full.
        let table = table_with_placeholder(PH);
        let full =
            table.scrub_novel_command_output_secrets_with_mode(&git_sha(), NovelScrubMode::Full);
        assert_eq!(full.text, "[ph]");
        assert_eq!(
            full.text,
            table.scrub_novel_command_output_secrets(&git_sha())
        );
    }

    #[test]
    fn observed_values_register_so_later_and_encoded_echoes_are_scrubbed() {
        use base64::Engine as _;
        let table = table_with_placeholder(PH);
        let stripe = ["zq8Hc2Lm", "N4pR7tV1wX3y"].concat();
        let out = narrow(&table, &format!("STRIPE_SECRET_KEY={stripe}\n"));
        let cfg = RedactConfig {
            placeholder: PH.to_string(),
            ..RedactConfig::default()
        };
        let updated = table
            .with_observed_output_secrets(&cfg, &out.found)
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(stripe.as_bytes());
        let later = format!("echo {stripe} | base64 -> {encoded}; commit {}", git_sha());
        let scrubbed = updated.scrub(&later);
        assert!(!scrubbed.contains(&stripe), "{scrubbed}");
        assert!(!scrubbed.contains(&encoded), "{scrubbed}");
        assert!(scrubbed.contains(&git_sha()), "{scrubbed}");
        // Observed values are persisted with the session table (not
        // disk-derived origin-only markers).
        let restored =
            RedactionTable::from_persisted_json(&updated.to_persisted_json().unwrap()).unwrap();
        assert!(!restored.scrub(&later).contains(&stripe));
    }

    /// Secrets r2 C5: a detected keyed value is registered down to the hard
    /// four-byte floor, whatever `min_secret_length` says — the backstop
    /// registers what it replaces. Below the hard floor and never-scrub
    /// literals stay visible and unregistered.
    #[test]
    fn detected_keyed_values_register_down_to_the_hard_floor() {
        let table = table_with_placeholder(PH);
        let cfg = RedactConfig::default();
        let out = narrow(&table, "API_TOKEN=abcde\npassword: hunter2\n");
        assert_eq!(out.text, "API_TOKEN=[ph]\npassword: [ph]\n");
        let addition = table.observed_output_addition(&cfg, &out.found).unwrap();
        for value in ["abcde", "hunter2"] {
            assert!(
                !addition.scrub(value).contains(value),
                "{value} unregistered"
            );
        }
        let short = narrow(&table, "API_TOKEN=abc\nDB_PASSWORD=null\n");
        assert_eq!(short.text, "API_TOKEN=abc\nDB_PASSWORD=null\n");
        assert!(
            table
                .observed_output_addition(&cfg, &short.found)
                .unwrap()
                .is_empty()
        );
        // A short all-digit `password` is a credential, not a count.
        assert_eq!(narrow(&table, "password: 4096\n").text, "password: [ph]\n");
        // r3 (R5/R6 policy): a short count under a token-ish key is redacted
        // in this output but never registered.
        let count = narrow(&table, "max_tokens: 4096\n");
        assert_eq!(count.text, "max_tokens: [ph]\n");
        assert!(count.found.is_empty(), "{:?}", count.found);
    }

    /// Secrets r2 C4: standard keyed spellings a consumer interprets — JSON
    /// escaped keys, numeric members, YAML flow mappings, commented block
    /// scalars, doubled single quotes, multiline quoted dotenv values and
    /// spaced reference defaults — are all scrubbed in narrow mode.
    #[test]
    fn standard_keyed_formats_are_scrubbed_in_narrow_mode() {
        let table = RedactionTable::empty();
        let literal = ["NovelActual515", "Secret78529"].concat();
        let cases = [
            ("dotenv_export", format!("export API_KEY='{literal}'")),
            ("json", format!(r#"{{"API_KEY":"{literal}"}}"#)),
            (
                "json_escaped_key",
                format!(r#"{{"API_\u004bEY":"{literal}"}}"#),
            ),
            (
                "json_numeric_token",
                "{\"api_key\":1234567890123456}".to_string(),
            ),
            ("yaml_flow", format!("{{API_KEY: {literal}}}")),
            (
                "yaml_block_comment",
                format!("API_KEY: | # credential\n  {literal}\n"),
            ),
            (
                "yaml_doubled_quote",
                format!("DB_PASSWORD: 'prefix''{literal}'"),
            ),
            (
                "dotenv_multiline",
                format!("DB_PASSWORD=\"firstline\n{literal}\"\n"),
            ),
            (
                "yaml_multiline",
                format!("password: \"firstline\n  {literal}\"\n"),
            ),
            (
                "reference_default",
                format!("DB_PASSWORD=${{X:-{literal}}}"),
            ),
            (
                "reference_nested",
                format!("DB_PASSWORD=${{X:-${{Y:-{literal}}}}}"),
            ),
            (
                "reference_default_space",
                format!("DB_PASSWORD=${{X:-prefix {literal}}}"),
            ),
            ("url_password", format!("postgres://app:{literal}@db/x")),
            (
                "pem",
                format!("-----BEGIN PRIVATE KEY-----\n{literal}\n-----END PRIVATE KEY-----\n"),
            ),
        ];
        let mut leaks = Vec::new();
        for (name, input) in cases {
            let out = table
                .scrub_novel_command_output_secrets_with_mode(&input, NovelScrubMode::KeyedNarrow);
            if out.text.contains(&literal) || out.text.contains("1234567890123456") {
                leaks.push((name, out.text));
            }
        }
        assert!(leaks.is_empty(), "secret-shape misses: {leaks:?}");
    }

    /// Secrets r2 C4: the multiline value's continuation lines are dropped and
    /// the text after the closing quote is ordinary output again.
    #[test]
    fn multiline_quoted_secret_closes_and_output_resumes() {
        let table = table_with_placeholder(PH);
        let out = narrow(
            &table,
            "DB_PASSWORD=\"line-one-secret\nline-two-secret\" trailing\nNODE_ENV=production\n",
        );
        assert_eq!(
            out.text,
            "DB_PASSWORD=[ph]\n\" trailing\nNODE_ENV=production\n"
        );
        let values = found_values(&out);
        assert!(
            values.contains(&"line-one-secret\nline-two-secret"),
            "{values:?}"
        );
    }

    /// Secrets r2 C7: a capture that lost a PEM block's BEGIN fence (a bounded
    /// head+tail join, a tail slice) still redacts the base64 body that
    /// precedes the orphan END fence.
    #[test]
    fn orphan_private_key_end_fence_redacts_the_preceding_body() {
        let table = table_with_placeholder(PH);
        let body_line = ["b3BlbnNzaC1rZXktdjEAAAAA", "OrphanBody515Line78529"].concat();
        let input = format!(
            "[... 4096 bytes omitted ...]\n{body_line}\n{body_line}xyz\n-----END OPENSSH PRIVATE KEY-----\nafter\n" // pragma: allowlist secret
        );
        let out = narrow(&table, &input);
        assert!(!out.text.contains(&body_line), "{}", out.text);
        assert!(
            out.text.contains("[... 4096 bytes omitted ...]"),
            "{}",
            out.text
        );
        assert!(out.text.ends_with("[ph]\nafter\n"), "{}", out.text);
        assert!(found_values(&out).contains(&body_line.as_str()));
    }

    /// Secrets r2 C7: the line-at-a-time stream carries PEM state across
    /// lines, so a scrubbed-at-intake consumer never stores a body line raw.
    #[test]
    fn novel_scrub_stream_carries_private_key_state_across_lines() {
        let mut stream = NovelScrubStream::new(PH, NovelScrubMode::KeyedNarrow);
        let body_line = ["b3BlbnNzaC1rZXktdjEAAAAA", "StreamBody515Line78529"].concat();
        assert_eq!(
            stream
                .push_line("-----BEGIN OPENSSH PRIVATE KEY-----")
                .as_deref(), // pragma: allowlist secret
            Some(PH)
        );
        assert_eq!(stream.push_line(&body_line), None);
        assert_eq!(stream.push_line("-----END OPENSSH PRIVATE KEY-----"), None);
        assert_eq!(stream.push_line("after").as_deref(), Some("after"));
        let found = stream.take_found();
        assert!(found.iter().any(|secret| secret.value == body_line));
    }
}

#[cfg(test)]
mod codex_r2_probes {
    use super::*;
    #[test]
    fn codex_r2_scalar_format_corpus() {
        let secret = "NovelScalar515Password78529";
        let cases = [
            (
                "json_multiline_string",
                format!("{{\n\"password\":\n\"{secret}\"\n}}"),
            ),
            (
                "xml_multiline",
                format!("<password>\n{secret}\n</password>"),
            ),
            ("yaml_comment", format!("password: {secret} # credential")),
            ("yaml_tag", format!("password: !!str {secret}")),
            (
                "yaml_folded",
                "password: >-\n  NovelScalar515\n  Password78529\n".into(),
            ),
        ];
        let table = RedactionTable::empty();
        let cfg = crate::config::extended::RedactConfig::default();
        let mut failures = Vec::new();
        for (name, input) in cases {
            let result = table
                .scrub_novel_command_output_secrets_with_mode(&input, NovelScrubMode::KeyedNarrow);
            let expected = if name == "yaml_folded" {
                "NovelScalar515 Password78529"
            } else {
                secret
            };
            let addition = table.observed_output_addition(&cfg, &result.found).unwrap();
            let immediate = !result.text.contains(secret);
            let registered = !addition.scrub(expected).contains(expected);
            eprintln!("{name}: immediate={immediate} registered={registered}");
            if !immediate || !registered {
                failures.push(name);
            }
        }
        assert!(
            failures.is_empty(),
            "scalar secrecy/registration failures: {failures:?}"
        );
    }
    #[test]
    fn codex_r2_quoted_type_names_are_values() {
        let table = RedactionTable::empty();
        for input in [
            r#"{"password":"String"}"#,
            r#"DB_PASSWORD="String""#,
            "password: number",
        ] {
            let result = table
                .scrub_novel_command_output_secrets_with_mode(input, NovelScrubMode::KeyedNarrow);
            assert!(
                result.text.contains(table.placeholder()),
                "literal password leaked: {}",
                result.text
            );
        }
    }
    #[test]
    fn codex_r2_username_equal_url_password_registers() {
        let table = RedactionTable::empty();
        let secret = "NovelUrlUser515Secret78529";
        let result = table.scrub_novel_command_output_secrets_with_mode(
            &format!("postgres://{secret}:{secret}@db/x"),
            NovelScrubMode::KeyedNarrow,
        );
        assert!(
            !result.text.contains(&format!(":{secret}@")),
            "password was not replaced"
        );
        let addition = table
            .observed_output_addition(
                &crate::config::extended::RedactConfig::default(),
                &result.found,
            )
            .unwrap();
        assert!(
            !addition.scrub(secret).contains(secret),
            "novel password equals username and remains unregistered"
        );
    }
    #[test]
    fn codex_r2_pem_state_is_bounded() {
        let mut stream = NovelScrubStream::new("[REDACTED]", NovelScrubMode::KeyedNarrow);
        stream.push_line("-----BEGIN PRIVATE KEY-----");
        let line = "A".repeat(1024);
        for _ in 0..4096 {
            assert!(stream.push_line(&line).is_none());
            stream.take_found();
        }
        let retained: usize = stream.private_key_lines.iter().map(String::len).sum();
        eprintln!("private PEM bytes retained beyond ring={retained}");
        assert!(
            retained <= 1024 * 1024,
            "stream retained {retained} raw bytes despite the bounded output ring"
        );
    }
    #[test]
    fn codex_r2_deep_reference_does_not_abort() {
        let depth = 12000;
        let value = format!(
            "DB_PASSWORD={}novel78529{}",
            "${X:-".repeat(depth),
            "}".repeat(depth)
        );
        let result = RedactionTable::empty()
            .scrub_novel_command_output_secrets_with_mode(&value, NovelScrubMode::KeyedNarrow);
        assert!(!result.text.contains("novel78529"));
    }
    #[test]
    fn codex_r2_deep_type_does_not_abort() {
        let depth = 12000;
        let value = format!(
            "password: {}String{}",
            "Option<".repeat(depth),
            ">".repeat(depth)
        );
        let _ = RedactionTable::empty()
            .scrub_novel_command_output_secrets_with_mode(&value, NovelScrubMode::KeyedNarrow);
    }
}

#[cfg(test)]
mod codex_r2_observation_probe {
    use super::*;
    #[test]
    fn codex_r2_duplicate_observation_keeps_strong_keyed_policy() {
        let table = RedactionTable::empty();
        let input = "password=\"abcde\nrestofpassword\"\nAPI_TOKEN=abcde\n";
        let result =
            table.scrub_novel_command_output_secrets_with_mode(input, NovelScrubMode::KeyedNarrow);
        assert!(!result.text.contains("abcde"));
        let addition = table
            .observed_output_addition(
                &crate::config::extended::RedactConfig::default(),
                &result.found,
            )
            .unwrap();
        assert!(
            !addition.scrub("abcde").contains("abcde"),
            "first weaker multiline observation discarded later length-exempt keyed observation"
        );
    }
    #[test]
    fn codex_r2_block_scalar_encoded_echo_is_registered() {
        use base64::Engine as _;
        let table = RedactionTable::empty();
        let secret = "NovelBlock515Secret78529";
        let result = table.scrub_novel_command_output_secrets_with_mode(
            &format!("password: |\n  {secret}\n"),
            NovelScrubMode::KeyedNarrow,
        );
        assert!(!result.text.contains(secret));
        let addition = table
            .observed_output_addition(
                &crate::config::extended::RedactConfig::default(),
                &result.found,
            )
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
        assert!(
            !addition.scrub(&encoded).contains(&encoded),
            "keyed block scalar registered no encoded variants"
        );
    }
}

#[cfg(test)]
mod codex_r2_placeholder_probe {
    use super::*;
    #[test]
    fn codex_r2_default_placeholder_is_idempotent_and_unobserved() {
        let table = RedactionTable::empty();
        let first = table.scrub_novel_command_output_secrets_with_mode(
            "DB_SECRET=NovelPlaceholder515Secret78529",
            NovelScrubMode::KeyedNarrow,
        );
        assert!(first.text.contains(table.placeholder()));
        let second = table
            .scrub_novel_command_output_secrets_with_mode(&first.text, NovelScrubMode::KeyedNarrow);
        assert!(
            second.found.is_empty(),
            "default placeholder fragments became new secret values: {:?}",
            second.found
        );
        assert_eq!(
            first.text, second.text,
            "re-scanning default placeholder grew model output"
        );
    }
}

#[cfg(test)]
mod codex_r2_jwt_probe {
    use super::*;
    use base64::Engine as _;
    #[test]
    fn codex_r2_whitespace_jwt_is_scrubbed() {
        let header = "eyAiYWxnIjogIkhTMjU2IiwgInR5cCI6ICJKV1QiIH0";
        let payload = "eyJzdWIiOiJjb2RleC1yMiIsImlhdCI6MTAwMDAwMH0";
        let signature = "iw6OWn7Ghda1KHT3aZXn4eU6zfGkDmXxxsJAFBwm8dM";
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header)
            .unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(decoded["alg"], "HS256");
        let token = format!("{header}.{payload}.{signature}");
        assert!(!token.starts_with("eyJ"));
        let result = RedactionTable::empty()
            .scrub_novel_command_output_secrets_with_mode(&token, NovelScrubMode::KeyedNarrow);
        assert!(
            !result.text.contains(&token),
            "JSON whitespace in a valid HS256 JWT header bypassed narrow JWT recognition"
        );
    }
}

/// One test per entry of the module-level backstop contract: the value is
/// replaced in that output AND registered (a later plain echo is scrubbed by
/// the resulting table addition).
#[cfg(test)]
mod contract_tests {
    use super::*;

    const SECRET: &str = "Contract515Secret78529";

    fn assert_contract(name: &str, input: &str, registered: &str) {
        let table = RedactionTable::empty();
        let result =
            table.scrub_novel_command_output_secrets_with_mode(input, NovelScrubMode::KeyedNarrow);
        assert!(
            !result.text.contains(registered),
            "{name}: value visible in output: {}",
            result.text
        );
        let addition = table
            .observed_output_addition(
                &crate::config::extended::RedactConfig::default(),
                &result.found,
            )
            .unwrap();
        assert!(
            !addition.scrub(registered).contains(registered),
            "{name}: value not registered"
        );
    }

    #[test]
    fn contract_1_key_value_assignments() {
        for input in [
            format!("API_TOKEN={SECRET}"),
            format!("API_TOKEN = {SECRET}"),
            format!("export API_TOKEN={SECRET}"),
            format!("API_TOKEN=\"{SECRET}\""),
            format!("API_TOKEN='{SECRET}'"),
            format!("see https://h.example/x?token={SECRET}&a=1"),
        ] {
            assert_contract(&input.replace(SECRET, "S"), &input, SECRET);
        }
        assert_contract(
            "escaped",
            r#"API_TOKEN="ab\"Contract515Secret78529""#,
            "ab\"Contract515Secret78529",
        );
    }

    #[test]
    fn contract_2_json_members_including_split_values() {
        assert_contract(
            "json",
            &format!(r#"{{"name":"x","api_key":"{SECRET}"}}"#),
            SECRET,
        );
        assert_contract(
            "json-next-line",
            &format!("{{\n\"password\":\n\"{SECRET}\"\n}}"),
            SECRET,
        );
    }

    #[test]
    fn contract_3_yaml_semantic_scalars_and_block_scalars() {
        assert_contract("comment", &format!("password: {SECRET} # note"), SECRET);
        assert_contract("tag", &format!("password: !!str {SECRET}"), SECRET);
        assert_contract("next-line", &format!("password:\n  {SECRET}\n"), SECRET);
        assert_contract("literal", &format!("password: |\n  {SECRET}\n"), SECRET);
        assert_contract(
            "folded",
            "password: >-\n  Contract515\n  Secret78529\n",
            "Contract515 Secret78529",
        );
    }

    #[test]
    fn contract_4_xml_elements_on_one_or_several_lines() {
        assert_contract("xml", &format!("<password>{SECRET}</password>"), SECRET);
        assert_contract(
            "xml-multiline",
            &format!("<password>\n{SECRET}\n</password>"),
            SECRET,
        );
    }

    #[test]
    fn contract_5_url_userinfo_passwords() {
        assert_contract("url", &format!("postgres://app:{SECRET}@db/x"), SECRET);
        assert_contract(
            "url-same-user",
            &format!("postgres://{SECRET}:{SECRET}@db/x"),
            SECRET,
        );
    }

    #[test]
    fn contract_6_pem_private_key_blocks() {
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Contract515";
        assert_contract(
            "pem",
            &format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            body,
        );
    }

    #[test]
    fn contract_7_jwts_by_decoded_header() {
        // `{ "alg": "HS256", "typ": "JWT" }` (spaced JSON: header is not `eyJ…`).
        let token = "eyAiYWxnIjogIkhTMjU2IiwgInR5cCI6ICJKV1QiIH0.eyJzdWIiOiJjb250cmFjdCJ9.c2lnbmF0dXJlLWNvbnRyYWN0LTUxNQ";
        assert_contract("jwt", &format!("token is {token} here"), token);
    }

    #[test]
    fn contract_8_well_known_prefixes() {
        let token = ["ghp_", "Contract515Secret78529abcdefXYZ1"].concat();
        assert_contract("ghp", &format!("got {token}"), &token);
    }

    #[test]
    fn contract_9_multiline_shell_quoted_values() {
        let input = "TOKEN=\"Contract515\nSecret78529\"\nnext line\n";
        let table = RedactionTable::empty();
        let result =
            table.scrub_novel_command_output_secrets_with_mode(input, NovelScrubMode::KeyedNarrow);
        assert!(!result.text.contains("Contract515"), "{}", result.text);
        assert!(!result.text.contains("Secret78529"), "{}", result.text);
        assert!(result.text.contains("next line"), "{}", result.text);
    }

    // Bounds: a large secret-keyed block scalar (the bounded-capture shape)
    // scans in linear time and registers a bounded set.
    #[test]
    fn contract_bounds_large_block_scalar_scan_is_linear() {
        let mut output = "ordinary benign line\n".repeat(7000);
        output.push_str("password: |\n");
        output.push_str(&"  ordinary scalar filler\n".repeat(20000));
        output.push_str(&format!("  {SECRET}\n"));
        let started = std::time::Instant::now();
        let mut stream = NovelScrubStream::new("[ph]", NovelScrubMode::KeyedNarrow);
        let mut found = ObservedSet::default();
        for line in output.lines() {
            let _ = stream.push_line(line);
            found.extend(stream.take_found());
        }
        stream.finish();
        found.extend(stream.take_found());
        let found = found.take();
        let addition = RedactionTable::empty()
            .observed_output_addition(&crate::config::extended::RedactConfig::default(), &found)
            .unwrap();
        let elapsed = started.elapsed();
        eprintln!(
            "large block scalar: {elapsed:?}, {} observations",
            found.len()
        );
        assert!(!addition.scrub(SECRET).contains(SECRET));
        assert!(found.len() < 16, "{} observations", found.len());
        assert!(elapsed < std::time::Duration::from_secs(20), "{elapsed:?}");
    }

    // Outside the contract, stated: a keyless opaque token in narrow mode is
    // work product (a git SHA) and stays.
    #[test]
    fn contract_excludes_keyless_hashes_in_narrow_mode() {
        let sha = "0d1a4b2c8e3f60718293a4b5c6d7e8f9a0b1c2d3";
        let result = RedactionTable::empty().scrub_novel_command_output_secrets_with_mode(
            &format!("commit {sha}"),
            NovelScrubMode::KeyedNarrow,
        );
        assert!(result.text.contains(sha));
    }

    // Count values under ordinary keys are redacted in place but never
    // registered (R5/R6 policy: never visible, not globally installed).
    #[test]
    fn heuristic_exemptions_redact_without_registering() {
        let table = RedactionTable::empty();
        for input in ["max_tokens: 4096", "password: String,"] {
            let result = table
                .scrub_novel_command_output_secrets_with_mode(input, NovelScrubMode::KeyedNarrow);
            assert!(
                result.text.contains(table.placeholder()),
                "{input}: {}",
                result.text
            );
            assert!(result.found.is_empty(), "{input}: {:?}", result.found);
        }
    }
}
