use super::*;

/// Every env file that matches one of `patterns` (gitignore-style globs)
/// walking **cwd-downward** through subdirectories, plus the user's
/// `extra` paths. Reuses the `ignore` crate's walker rather than a manual
/// recursion: `standard_filters(false)` is on so gitignored / hidden env
/// files (`.env` is hidden by name) are still found, a `.git/`-pruning
/// `filter_entry` keeps the walk out of the repo's object store, and an
/// `Override` whitelist makes the walker yield only the matching files —
/// directories still descend (a directory matching no glob returns
/// `Match::None`, not `Ignore`), so the patterns match at any depth with
/// gitignore semantics.
/// The `.env` walk depth cap for the redaction scan.
///
/// In a git repo: `None` (unbounded) — finding every `.env` for the
/// redaction guarantee outranks speed (priority #1, correctness/safety:
/// never let a secret leak because the scan was capped). Outside a repo,
/// an arbitrary giant directory is the pathological case and `.env` files
/// live near the root in practice, so cap at depth 8. `ignore`'s
/// `WalkBuilder::max_depth` (via `walkdir`) counts the root as depth 0, its
/// direct children as depth 1, and so on — so `Some(8)` yields entries up
/// to eight levels below `cwd` and stops descending past that.
pub(super) fn dotenv_max_depth(in_git_repo: bool) -> Option<usize> {
    if in_git_repo { None } else { Some(8) }
}

pub(super) fn matched_dotenv_paths(
    cwd: &Path,
    patterns: &[String],
    extra: &[PathBuf],
) -> Vec<PathBuf> {
    use ignore::WalkBuilder;
    use ignore::overrides::OverrideBuilder;

    let mut out: Vec<PathBuf> = Vec::new();

    let in_git_repo = crate::git::find_worktree_root(cwd).is_some();
    if !in_git_repo && dotenv_scan_start_is_unbounded(cwd) {
        tracing::debug!(
            cwd = %cwd.display(),
            "redaction `.env` walk skipped from unbounded filesystem start; explicit extra dotenv paths are still honored"
        );
        for p in extra {
            if p.is_file() {
                out.push(p.clone());
            }
        }
        out.sort();
        out.dedup();
        return out;
    }

    // Bound the walk only outside a git repo: inside one we keep the
    // unbounded walk so no `.env` is ever missed (correctness/safety #1).
    let max_depth = dotenv_max_depth(in_git_repo);
    if max_depth.is_some() {
        tracing::debug!(
            "redaction `.env` walk capped at depth 8 (cwd not in a git repo); a deeper `.env` won't be scanned"
        );
    }

    let mut override_builder = OverrideBuilder::new(cwd);
    let mut added_any = false;
    for pat in patterns {
        let pat = pat.trim();
        if pat.is_empty() {
            continue;
        }
        // A leading `!` in an override builder *ignores* (the inverse of
        // gitignore); the redaction patterns are an inclusion list, so a
        // user-typed `!` would silently do the opposite. Keep them as
        // plain whitelist globs.
        if override_builder.add(pat.trim_start_matches('!')).is_ok() {
            added_any = true;
        }
    }
    if added_any && let Ok(overrides) = override_builder.build() {
        let mut builder = WalkBuilder::new(cwd);
        builder
            .standard_filters(false)
            .max_depth(max_depth)
            .overrides(overrides)
            .filter_entry(|entry| {
                // Never descend into the git object store.
                !(entry.file_type().is_some_and(|t| t.is_dir()) && entry.file_name() == ".git")
            });
        for entry in builder.build().flatten() {
            if entry.file_type().is_some_and(|t| t.is_file()) {
                out.push(entry.into_path());
            }
        }
    }

    for p in extra {
        if p.is_file() {
            out.push(p.clone());
        }
    }

    out.sort();
    out.dedup();
    out
}

pub(super) fn dotenv_scan_start_is_unbounded(cwd: &Path) -> bool {
    if cwd.parent().is_none() {
        return true;
    }
    dirs::home_dir().is_some_and(|home| same_path_lexical_or_canonical(cwd, &home))
}

fn same_path_lexical_or_canonical(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Auto-detect a matched env file's format and collect its scrub-candidate
/// string values (§4). Object/map **keys are never** candidates; only leaf
/// string scalars are. Numbers/bools are left to the prune step. The §5
/// inline `# COCKPIT_DISABLE_REDACT` marker excludes the value on its line.
///
/// Detection order (deterministic, content-based — `.env` carries no
/// extension):
///   1. **`KEY=VALUE`** (dotenv) — the most common env-file shape and the
///      only one that is *not* a structured document; tried first so a
///      plain dotenv never gets mis-parsed as one-line TOML/YAML.
///   2. **JSON** — strict, unambiguous; a JSON object/array is never valid
///      dotenv, so trying it after dotenv is safe.
///   3. **TOML** — stricter than YAML (rejects most prose), so it's tried
///      before YAML to avoid YAML's permissive scalar parse swallowing a
///      malformed TOML doc.
///   4. **YAML** — the most permissive parser; last so it's the final
///      fallback for structured content.
///
/// A file that parses as none of these is [`EnvFileScan::Unsupported`].
pub(super) fn collect_env_file_candidates(path: &Path, user_allowlist: &[String]) -> EnvFileScan {
    let Ok(bytes) = std::fs::read(path) else {
        return EnvFileScan::Unreadable;
    };
    let text = String::from_utf8_lossy(&bytes);
    let display = path.display().to_string();

    // (1) KEY=VALUE (dotenv). `parse_dotenv` returns `Some` when at least
    // one valid assignment line is present; stray lines are skipped so they
    // cannot void the rest of a real env file.
    if let Some(entries) = parse_dotenv(&text, &display, user_allowlist) {
        return EnvFileScan::Candidates(entries);
    }

    // Lines bearing the inline disable marker (§5). Used to exclude the
    // marked value from the structured-format candidates, where parsing to
    // a `Value` has already discarded comments.
    let marked = marked_values(&text);

    // (2) JSON — has no comments, so the marker is not honored here.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        let mut out = Vec::new();
        collect_json_strings(&value, &display, false, &mut out);
        return EnvFileScan::Candidates(out);
    }

    // (3) TOML.
    if let Ok(value) = toml::from_str::<toml::Value>(&text) {
        let mut out = Vec::new();
        let mut marked = marked.clone();
        collect_toml_strings(&value, &display, &mut marked, false, &mut out);
        return EnvFileScan::Candidates(out);
    }

    // (4) YAML.
    if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
        let mut out = Vec::new();
        let mut marked = marked;
        collect_yaml_strings(&value, &display, &mut marked, false, &mut out);
        return EnvFileScan::Candidates(out);
    }

    EnvFileScan::Unsupported
}

/// Parse a `KEY=VALUE` (dotenv) document, yielding `(value, "$VAR
/// (file)")` pairs. Returns `Some` when at least one well-formed assignment
/// line is found, even if every matched line is allowlisted or marker-disabled;
/// returns `None` only when zero assignments are found so format detection can
/// fall through to the structured parsers. Honors the §5 inline disable marker,
/// leading-comment doc lines, surrounding quotes, and a leading `export `. A
/// `#` inside a quoted value is *not* treated as a comment.
pub(super) fn parse_dotenv(
    text: &str,
    display: &str,
    user_allowlist: &[String],
) -> Option<Vec<Candidate>> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut matched = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some(eq) = line.find('=') else {
            continue;
        };
        let (name, rest) = line.split_at(eq);
        let name = name.trim();
        if name.is_empty() || !is_valid_env_name(name) {
            continue;
        }
        matched += 1;
        let rest = &rest[1..];
        let (value, disabled) = split_value_and_marker(rest);
        if disabled {
            continue;
        }
        if is_allowlisted(name, user_allowlist) {
            continue;
        }
        out.push(Candidate::prunable(
            value,
            format!("${name} ({display})"),
            credential_shaped_key(name),
        ));
    }
    (matched > 0).then_some(out)
}

/// Whether `name` is a plausible env-var identifier: ASCII alphanumeric
/// plus `_`, not starting with a digit. Used to reject lines that merely
/// happen to contain `=` (e.g. a YAML/JSON fragment) from the dotenv path.
fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Split a dotenv value region (everything right of the first `=`) into
/// the unquoted value and whether the §5 inline disable marker is
/// present. A `#` inside a quoted value is part of the value, not a
/// comment; an unquoted value's first unescaped `#` (preceded by
/// whitespace) starts a trailing comment.
fn split_value_and_marker(rest: &str) -> (String, bool) {
    let rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        // Double-quoted: value runs to the next unescaped `"`.
        if let Some((value, after)) = take_quoted(stripped, '"') {
            return (value, comment_is_marker(after));
        }
        // Unterminated quotes are treated conservatively as secret material.
        return (stripped.trim_end().to_string(), false);
    } else if let Some(stripped) = rest.strip_prefix('\'') {
        // Single-quoted: value runs to the next `'` (no escapes).
        if let Some(end) = stripped.find('\'') {
            let value = stripped[..end].to_string();
            let after = &stripped[end + 1..];
            return (value, comment_is_marker(after));
        }
        // Unterminated quotes are treated conservatively as secret material.
        return (stripped.trim_end().to_string(), false);
    }
    // Unquoted: a trailing comment starts at the first `#` that follows
    // whitespace (so `a#b` is the literal value `a#b`, but `a # c` is the
    // value `a` with comment `c`).
    if let Some(idx) = unquoted_comment_start(rest) {
        let value = rest[..idx].trim_end().to_string();
        let comment = &rest[idx + 1..];
        return (value, comment.trim() == DISABLE_MARKER);
    }
    (rest.trim().to_string(), false)
}

/// Index of the `#` that begins a trailing comment on an unquoted value,
/// or `None` when there's no trailing comment. The `#` must be at the
/// start of the string or preceded by whitespace.
fn unquoted_comment_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            return Some(i);
        }
    }
    None
}

/// Take a quoted-string body up to the next unescaped `quote`, returning
/// the unescaped value and the remainder after the closing quote.
fn take_quoted(s: &str, quote: char) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut escaped = false;
    let mut chars = s.char_indices();
    for (i, c) in chars.by_ref() {
        if escaped {
            value.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == quote {
            return Some((value, &s[i + c.len_utf8()..]));
        } else {
            value.push(c);
        }
    }
    None
}

/// Whether the trailing text after a closed quote is exactly the §5
/// disable-marker comment (`# COCKPIT_DISABLE_REDACT`).
fn comment_is_marker(after: &str) -> bool {
    let after = after.trim();
    after
        .strip_prefix('#')
        .map(|c| c.trim() == DISABLE_MARKER)
        .unwrap_or(false)
}

/// Set of literal scalar values sitting on a line whose trailing comment
/// is exactly the §5 disable marker. Used by the structured-format
/// collectors (TOML/YAML), where the parsed `Value` has already dropped
/// comments, to exclude a marked value from candidacy.
fn marked_values(text: &str) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        let Some(comment_idx) = unquoted_comment_start_in_line(line) else {
            continue;
        };
        let comment = &line[comment_idx + 1..];
        if comment.trim() != DISABLE_MARKER {
            continue;
        }
        // Everything before the comment is the data part; pull the scalar
        // to the right of the first `:`/`=` (TOML/YAML key/value lines).
        let data = line[..comment_idx].trim_end();
        let rhs = data
            .split_once('=')
            .or_else(|| data.split_once(':'))
            .map(|(_, v)| v)
            .unwrap_or(data);
        let scalar = strip_quotes(rhs.trim()).trim();
        if !scalar.is_empty() {
            *out.entry(scalar.to_string()).or_insert(0) += 1;
        }
    }
    out
}

pub(super) fn consume_marked_value(marked: &mut HashMap<String, usize>, value: &str) -> bool {
    let Some(count) = marked.get_mut(value) else {
        return false;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        marked.remove(value);
    }
    true
}

/// Like [`unquoted_comment_start`] but operates on a full line and skips
/// `#` that fall inside a quoted span (so a `#` inside a TOML/YAML quoted
/// string isn't mistaken for a comment).
fn unquoted_comment_start_in_line(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'#' if !in_single && !in_double && (i == 0 || bytes[i - 1].is_ascii_whitespace()) => {
                return Some(i);
            }
            _ => {}
        }
    }
    None
}
