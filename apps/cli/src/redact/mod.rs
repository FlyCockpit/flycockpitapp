//! Secret redaction.
//!
//! Every string the daemon hands to a model provider goes through
//! [`RedactionTable::scrub`]. This is a non-bypassable chokepoint by
//! design — see `the design notes` §7 and `project guidance` "Design rules". The
//! controls below (`scan_environment`, `scan_dotenv`, the env-file
//! patterns) only change *what enters the table*; they never disable
//! `scrub` itself. The single master off-switch is `redact.enabled =
//! false`.
//!
//! Sources of secrets scanned at table-build time:
//!   - `std::env::vars_os()` minus a small "obviously not a secret"
//!     allowlist (`PATH`, `HOME`, `SHELL`, `TERM`, `LANG`, …).
//!   - Env files matched by [`RedactConfig::dotenv_patterns`] — gitignore-
//!     style globs walked **cwd-downward** through subdirectories with the
//!     `ignore` crate's walker (default `[".env", ".env.local"]`). Each
//!     matched file's format is auto-detected (`KEY=VALUE`, JSON, YAML,
//!     TOML); an unsupported/unparseable file contributes no candidates.
//!   - Any paths configured in `redact.extra_dotenv_paths`.
//!   - Private SSH keys under `~/.ssh` (`scan_ssh_keys`, default on): every
//!     regular file whose content starts with a PEM private-key header is
//!     registered as a **forced** (non-prunable) secret, so key material is
//!     never dropped by the prune. Public keys (`*.pub`) are never matched.
//!
//! Candidate values are then **pruned** of things that aren't plausibly
//! secrets (too short, never-scrub literals like `true`/`null`/`on`)
//! before the table is built. Short numeric values are handled by the
//! same length floor, while long numeric strings are retained because
//! all-digit API keys and passwords exist. `denylist` values bypass the
//! prune (forced inclusion); the §5 inline disable marker
//! (`# COCKPIT_DISABLE_REDACT`) excludes a single value from candidacy.
//!
//! Replacement is single-linear-scan multi-pattern via `aho-corasick`.
//! Matches are case-sensitive and substring-aware (so a token embedded
//! in a longer URL is still redacted).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::Result;
use base64::Engine as _;

use crate::config::extended::RedactConfig;

/// Env vars that are *never* treated as secrets even when they would
/// otherwise meet the length threshold. Substrings of these values
/// would be redacted out of every shell pipeline if we let them in,
/// for no security benefit.
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "USERNAME",
    "SHELL",
    "TERM",
    "TERM_PROGRAM",
    "PWD",
    "OLDPWD",
    "DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "HOSTNAME",
    "LOGNAME",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "COLORTERM",
    "OS",
    "OSTYPE",
];

/// Prefix-matched allowlist entries — any env var whose name starts
/// with one of these is skipped. Covers the `LC_*`, `LANG*`, and `XDG_*`
/// families called out in the spec.
const ENV_ALLOWLIST_PREFIXES: &[&str] = &["LC_", "LANG", "XDG_"];

/// Built-in never-scrub literals (case-insensitive). A candidate value
/// equal to one of these is dropped by the prune step — they're config
/// keywords, not secrets, and redacting them would corrupt every prompt
/// that mentions the word. Empty/whitespace-only values are already
/// covered by the `min_secret_length` floor.
const NEVER_SCRUB_LITERALS: &[&str] = &[
    "true", "false", "null", "nil", "none", "yes", "no", "on", "off",
];

/// The exact trimmed content of an inline trailing comment that excludes
/// the value on that line from redaction candidacy (§5). Honored in every
/// comment-supporting format (`KEY=VALUE`, TOML, YAML); JSON has no
/// comments and is therefore exempt.
const DISABLE_MARKER: &str = "COCKPIT_DISABLE_REDACT";

/// Number of encoded variants registered for forced secrets. Keep this
/// fixed and small so a large denylist or SSH key set cannot multiply the
/// matcher without bound.
const MAX_FORCED_SECRET_VARIANTS: usize = 3;

/// PEM private-key opening headers. A file under the SSH dir is treated as a
/// private key — and its content registered as a forced secret — iff its
/// (leading-whitespace-trimmed) content starts with one of these. This is
/// content-based, not name-based: a `*.pub` starts with `ssh-rsa` /
/// `ssh-ed25519` / `ecdsa-…` and so is never matched, while an oddly-named
/// private key still is. Encrypted keys carry the same `BEGIN … PRIVATE KEY`
/// (or `BEGIN ENCRYPTED PRIVATE KEY`) header and are therefore still
/// registered.
const PEM_PRIVATE_KEY_HEADERS: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

/// Shared env-key heuristic for variables that should be treated as
/// sensitive by default. Bash uses the same predicate to remove inherited
/// keys from child environments, while redaction uses it as an env-name
/// signal before value pruning.
pub(crate) fn env_scrub_patterns(name: &str) -> bool {
    const FIXED: &[&str] = &[
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "NODE_OPTIONS",
        "SHELLOPTS",
        "BASHOPTS",
        "GREP_OPTIONS",
        "GREP_COLORS",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ];
    let upper = name.to_ascii_uppercase();
    FIXED.iter().any(|fixed| upper == *fixed)
        || upper.ends_with("_KEY")
        || upper.ends_with("_SECRET")
        || upper.ends_with("_TOKEN")
        || upper.ends_with("_PASSWORD")
        || upper.ends_with("_PASSWD")
        || upper.ends_with("_PIN")
        || upper.ends_with("_PAT")
        || upper.ends_with("_CREDENTIALS")
}

fn credential_shaped_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.ends_with("_PIN")
        || upper.ends_with("_PASSWORD")
        || upper.ends_with("_PASSWD")
        || upper.ends_with("_SECRET")
}

/// `true` when `name` is in the built-in allowlist (exact match or any
/// prefix family) or in the user's per-config `allowlist`.
fn is_allowlisted(name: &str, user_allowlist: &[String]) -> bool {
    if ENV_ALLOWLIST.contains(&name) {
        return true;
    }
    if ENV_ALLOWLIST_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    user_allowlist.iter().any(|a| a == name)
}

/// `true` when `value` should be pruned from the candidate list because
/// it isn't plausibly a secret: shorter than `min_len`, or
/// case-insensitively equals a built-in never-scrub literal
/// (`true`/`false`/`null`/`nil`/`none`/`yes`/`no`/`on`/`off`).
/// Empty/whitespace-only values fall out via the length floor. Numeric
/// values are intentionally not pruned after the length check: ports and
/// common counts remain below the default floor, but long numeric
/// strings can be credentials.
#[cfg(test)]
fn is_pruned(value: &str, min_len: usize) -> bool {
    if value.len() < min_len {
        return true;
    }
    NEVER_SCRUB_LITERALS
        .iter()
        .any(|lit| value.eq_ignore_ascii_case(lit))
}

fn is_pruned_candidate(value: &str, min_len: usize, length_exempt: bool) -> bool {
    if !length_exempt && value.len() < min_len {
        return true;
    }
    NEVER_SCRUB_LITERALS
        .iter()
        .any(|lit| value.eq_ignore_ascii_case(lit))
}

#[derive(Debug)]
struct Candidate {
    value: String,
    origin: String,
    prunable: bool,
    length_exempt: bool,
    register_variants: bool,
    register_case_variants: bool,
}

impl Candidate {
    fn prunable(value: String, origin: String, length_exempt: bool) -> Self {
        Self {
            value,
            origin,
            prunable: true,
            length_exempt,
            register_variants: true,
            register_case_variants: length_exempt,
        }
    }

    fn forced(value: String, origin: String, register_variants: bool) -> Self {
        Self {
            value,
            origin,
            prunable: false,
            length_exempt: true,
            register_variants,
            register_case_variants: false,
        }
    }
}

fn case_secret_variants(value: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(2);
    let lower = value.to_ascii_lowercase();
    if lower != value {
        variants.push(lower);
    }
    let upper = value.to_ascii_uppercase();
    if upper != value {
        variants.push(upper);
    }
    variants.sort();
    variants.dedup();
    variants
}

fn encoded_secret_variants(value: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(MAX_FORCED_SECRET_VARIANTS);
    let bytes = value.as_bytes();
    variants.push(base64::engine::general_purpose::STANDARD.encode(bytes));
    variants.push(hex_encode(bytes));
    variants.push(url_encode(bytes));
    variants.retain(|variant| !variant.is_empty() && variant != value);
    variants.truncate(MAX_FORCED_SECRET_VARIANTS);
    variants
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit((byte >> 4) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit((byte & 0x0f) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

/// A built lookup of `value → origin-name` pairs the next outbound
/// request must be scrubbed against. Hold one per session (cheap to
/// rebuild; small in-memory footprint).
pub struct RedactionTable {
    /// Aho-Corasick search structure; `None` when there's nothing to
    /// scrub or redaction is disabled. Keeping it `Option` lets
    /// [`scrub`] short-circuit without allocating.
    matcher: Option<AhoCorasick>,
    /// Parallel to `matcher`'s pattern list. Used by
    /// `cockpit debug redact` to render `value (from $VAR)` rows.
    origins: Vec<String>,
    /// What every match is replaced with. Distinctive on purpose so
    /// leaks into provider logs are easy to grep for.
    placeholder: String,
    /// `true` when the user disabled redaction at config level. The
    /// scrub call still returns the input unchanged; we keep the flag
    /// so `cockpit debug redact` can say so.
    disabled: bool,
    /// Env files matched but in an unsupported/unparseable format, so
    /// their candidates couldn't be collected (§4). Surfaced once as a
    /// TUI toast so the user knows redaction won't cover those files.
    unsupported_files: Vec<PathBuf>,
}

impl std::fmt::Debug for RedactionTable {
    /// Never print pattern values — they are the secrets this table
    /// exists to hide. Show only counts + flags.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionTable")
            .field("patterns", &self.origins.len())
            .field("disabled", &self.disabled)
            .field("unsupported_files", &self.unsupported_files.len())
            .finish()
    }
}

impl RedactionTable {
    /// Build a table from the OS env + the env files matched under `cwd`.
    /// Honors `enabled`, `scan_environment`, `scan_dotenv`,
    /// `dotenv_patterns`, `extra_dotenv_paths`, and `min_secret_length`.
    pub fn build(cfg: &RedactConfig, cwd: &Path) -> Result<Self> {
        let env: HashMap<String, String> = std::env::vars_os()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        Self::build_with_env(cfg, cwd, &env)
    }

    /// Build a table from the provided session env + the env files matched
    /// under `cwd`. Daemon sessions use this so redaction tracks the immutable
    /// session snapshot instead of the daemon process environment.
    pub fn build_with_env(
        cfg: &RedactConfig,
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> Result<Self> {
        if !cfg.enabled {
            return Ok(Self {
                matcher: None,
                origins: Vec::new(),
                placeholder: cfg.placeholder.clone(),
                disabled: true,
                unsupported_files: Vec::new(),
            });
        }

        // (1) Identify sources + (2) collect candidate values per source.
        // Denylist and private-key entries are forced inclusion. Env and
        // dotenv values remain prunable, except credential-shaped keys bypass
        // only the length floor.
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut unsupported_files: Vec<PathBuf> = Vec::new();

        if cfg.scan_environment {
            for (name, value) in env {
                if is_allowlisted(name, &cfg.allowlist) && !env_scrub_patterns(name) {
                    continue;
                }
                let length_exempt = credential_shaped_key(name);
                candidates.push(Candidate::prunable(
                    value.clone(),
                    format!("${name}"),
                    length_exempt,
                ));
            }
        }

        if cfg.scan_dotenv {
            for path in matched_dotenv_paths(cwd, &cfg.dotenv_patterns, &cfg.extra_dotenv_paths) {
                match collect_env_file_candidates(&path, &cfg.allowlist) {
                    EnvFileScan::Candidates(file_entries) => {
                        for entry in file_entries {
                            candidates.push(entry);
                        }
                    }
                    EnvFileScan::Unsupported => unsupported_files.push(path),
                    EnvFileScan::Unreadable => {}
                }
            }
        }

        // Private SSH keys: each is registered as a forced (non-prunable)
        // secret — key material must never be dropped by the prune step.
        if cfg.scan_ssh_keys {
            for (value, origin) in collect_ssh_key_candidates(cfg.ssh_key_dir.as_deref()) {
                candidates.push(Candidate::forced(value, origin, true));
            }
        }

        if let Some(token) = crate::auth::flycockpit::stored_instance_token_for_redaction() {
            candidates.push(Candidate::forced(
                token,
                "$credentials:flycockpit.instance_token".to_string(),
                true,
            ));
        }

        // (3) Prune: drop candidates that aren't plausibly secrets. The
        // denylist (added below) bypasses this — it's forced inclusion.
        let mut entries: Vec<(String, String)> = Vec::new();
        for candidate in candidates {
            if candidate.prunable
                && is_pruned_candidate(
                    &candidate.value,
                    cfg.min_secret_length,
                    candidate.length_exempt,
                )
            {
                continue;
            }
            if candidate.register_variants {
                for variant in encoded_secret_variants(&candidate.value) {
                    entries.push((variant, candidate.origin.clone()));
                }
            }
            if candidate.register_case_variants {
                for variant in case_secret_variants(&candidate.value) {
                    entries.push((variant, candidate.origin.clone()));
                }
            }
            entries.push((candidate.value, candidate.origin));
        }

        // Denylist: forced inclusion even for short / pruned / allowlisted
        // values.
        for v in &cfg.denylist {
            if v.is_empty() {
                continue;
            }
            let candidate = Candidate::forced(v.clone(), "$denylist".to_string(), true);
            for variant in encoded_secret_variants(&candidate.value) {
                entries.push((variant, candidate.origin.clone()));
            }
            entries.push((candidate.value, candidate.origin));
        }

        // Sort longest-first so that overlapping patterns prefer the
        // longer match (`aho-corasick` with LeftmostLongest does this
        // implicitly, but sorting also gives the debug-dump a stable
        // canonical order).
        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));

        // De-duplicate identical values; we don't want to redact a
        // single value twice (the placeholder would still be right but
        // the origins list would carry stale entries). Sorting by value
        // after length makes duplicates adjacent even when they were
        // collected from non-adjacent sources.
        entries.dedup_by(|a, b| a.0 == b.0);

        if entries.is_empty() {
            return Ok(Self {
                matcher: None,
                origins: Vec::new(),
                placeholder: cfg.placeholder.clone(),
                disabled: false,
                unsupported_files,
            });
        }

        // (4) Build the table from the pruned list.
        let patterns: Vec<&str> = entries.iter().map(|(v, _)| v.as_str()).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(false)
            .build(&patterns)
            .map_err(|e| anyhow::anyhow!("building aho-corasick: {e}"))?;
        let origins = entries.iter().map(|(_, o)| o.clone()).collect();

        Ok(Self {
            matcher: Some(matcher),
            origins,
            placeholder: cfg.placeholder.clone(),
            disabled: false,
            unsupported_files,
        })
    }

    /// Scrub every secret in `body`. Returns the cleaned string. The
    /// no-table-or-disabled path returns the input unchanged without
    /// allocating.
    pub fn scrub(&self, body: &str) -> String {
        let Some(matcher) = self.matcher.as_ref() else {
            return body.to_string();
        };
        matcher.replace_all(body, &vec![self.placeholder.as_str(); self.origins.len()])
    }

    /// `true` when there's nothing to redact and `scrub` will pass
    /// through. Useful for the debug command.
    // Retained for `cockpit debug redact` introspection.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.matcher.is_none()
    }

    /// A no-op table that scrubs nothing — equivalent to a disabled
    /// `RedactConfig`. Used as a fallback when a redaction chokepoint object
    /// is needed but the table couldn't be built (the chokepoint still
    /// *runs* — it just has an empty table), and by tests that need a
    /// chokepoint without actual substitutions.
    pub fn empty() -> Self {
        Self {
            matcher: None,
            origins: Vec::new(),
            placeholder: RedactConfig::default().placeholder,
            disabled: true,
            unsupported_files: Vec::new(),
        }
    }

    // Retained for `cockpit debug redact` introspection.
    #[allow(dead_code)]
    pub fn disabled(&self) -> bool {
        self.disabled
    }

    /// Env files that matched a redaction pattern but couldn't be parsed
    /// in any supported format (§4). The daemon surfaces these once as a
    /// TUI toast: redaction won't cover those files.
    pub fn unsupported_files(&self) -> &[PathBuf] {
        &self.unsupported_files
    }

    /// `(value, origin)` pairs for the debug command. Values themselves
    /// are sensitive — only call this from local `cockpit debug
    /// redact` after the user has explicitly asked.
    // Retained for `cockpit debug redact` introspection.
    #[allow(dead_code)]
    pub fn entries_for_debug(&self) -> Vec<&str> {
        self.origins.iter().map(|s| s.as_str()).collect()
    }
}

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
fn dotenv_max_depth(in_git_repo: bool) -> Option<usize> {
    if in_git_repo { None } else { Some(8) }
}

fn matched_dotenv_paths(cwd: &Path, patterns: &[String], extra: &[PathBuf]) -> Vec<PathBuf> {
    use ignore::WalkBuilder;
    use ignore::overrides::OverrideBuilder;

    let mut out: Vec<PathBuf> = Vec::new();

    // Bound the walk only outside a git repo: inside one we keep the
    // unbounded walk so no `.env` is ever missed (correctness/safety #1).
    let in_git_repo = crate::git::find_worktree_root(cwd).is_some();
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

/// Outcome of scanning one matched env file (§4).
enum EnvFileScan {
    /// Parsed in a supported format; the carried candidates
    /// are scrub candidates (pre-prune).
    Candidates(Vec<Candidate>),
    /// Read but not parseable in any supported format — skip it and toast.
    Unsupported,
    /// Couldn't even read the file (missing / permission). Silent skip.
    Unreadable,
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
fn collect_env_file_candidates(path: &Path, user_allowlist: &[String]) -> EnvFileScan {
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
fn parse_dotenv(text: &str, display: &str, user_allowlist: &[String]) -> Option<Vec<Candidate>> {
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

fn consume_marked_value(marked: &mut HashMap<String, usize>, value: &str) -> bool {
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

/// Recursively collect every leaf string scalar in a JSON document.
/// Object keys are never collected. JSON has no comments, so the §5
/// marker doesn't apply.
fn collect_json_strings(
    value: &serde_json::Value,
    display: &str,
    length_exempt: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        serde_json::Value::String(s) => {
            out.push(Candidate::prunable(
                s.clone(),
                format!("{display} (json)"),
                length_exempt,
            ));
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings(item, display, length_exempt, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                collect_json_strings(v, display, length_exempt || credential_shaped_key(k), out);
            }
        }
        _ => {}
    }
}

/// Recursively collect every leaf string scalar in a TOML document. Table
/// keys are never collected; a value on a line bearing the §5 marker is
/// excluded via `marked`.
fn collect_toml_strings(
    value: &toml::Value,
    display: &str,
    marked: &mut HashMap<String, usize>,
    length_exempt: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        toml::Value::String(s) => {
            if !consume_marked_value(marked, s) {
                out.push(Candidate::prunable(
                    s.clone(),
                    format!("{display} (toml)"),
                    length_exempt,
                ));
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_toml_strings(item, display, marked, length_exempt, out);
            }
        }
        toml::Value::Table(table) => {
            for (k, v) in table {
                collect_toml_strings(
                    v,
                    display,
                    marked,
                    length_exempt || credential_shaped_key(k),
                    out,
                );
            }
        }
        _ => {}
    }
}

/// Recursively collect every leaf string scalar in a YAML document. Map
/// keys are never collected; a value on a line bearing the §5 marker is
/// excluded via `marked`.
fn collect_yaml_strings(
    value: &serde_yaml::Value,
    display: &str,
    marked: &mut HashMap<String, usize>,
    length_exempt: bool,
    out: &mut Vec<Candidate>,
) {
    match value {
        serde_yaml::Value::String(s) => {
            if !consume_marked_value(marked, s) {
                out.push(Candidate::prunable(
                    s.clone(),
                    format!("{display} (yaml)"),
                    length_exempt,
                ));
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_yaml_strings(item, display, marked, length_exempt, out);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                let key_exempt = k.as_str().map(credential_shaped_key).unwrap_or(false);
                collect_yaml_strings(v, display, marked, length_exempt || key_exempt, out);
            }
        }
        _ => {}
    }
}

/// Strip one layer of matching surrounding quotes (`"` or `'`) if present.
fn strip_quotes(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Filenames in the SSH dir that are never private keys and are skipped
/// without reading their content: public keys, the known-hosts cache, the
/// authorized-keys list, and the SSH client `config`. The content check
/// alone already excludes these (none carries a PEM private-key header), but
/// skipping by name avoids reading files we know aren't keys.
fn is_ssh_non_key_name(name: &str) -> bool {
    name.ends_with(".pub")
        || name.starts_with("known_hosts")
        || name == "authorized_keys"
        || name == "config"
}

/// `true` when `content` begins (after leading whitespace) with a PEM
/// private-key header.
fn is_pem_private_key(content: &str) -> bool {
    let trimmed = content.trim_start();
    PEM_PRIVATE_KEY_HEADERS
        .iter()
        .any(|h| trimmed.starts_with(h))
}

/// Collect `(value, origin)` candidates for every private SSH key under the
/// configured dir (`ssh_key_dir` override, else the user's `~/.ssh`). A
/// missing/unreadable dir is skipped silently (no error). For each regular
/// file (symlinks followed to their target) whose content is a PEM private
/// key, the trimmed full key text is registered with origin `$ssh:<file>`;
/// a newline-normalized (`\r\n`→`\n`) variant is added when it differs so a
/// CRLF/LF echo both match. The caller treats these as forced/non-prunable.
fn collect_ssh_key_candidates(ssh_key_dir: Option<&Path>) -> Vec<(String, String)> {
    let dir = match ssh_key_dir {
        Some(d) => d.to_path_buf(),
        None => {
            let Some(home) = dirs::home_dir() else {
                return Vec::new();
            };
            home.join(".ssh")
        }
    };

    let Ok(read_dir) = std::fs::read_dir(&dir) else {
        // Missing / unreadable `~/.ssh` → skip silently.
        return Vec::new();
    };

    let mut out: Vec<(String, String)> = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if is_ssh_non_key_name(&name) {
            continue;
        }
        // `fs::metadata` follows symlinks — we want the target's content if
        // it's a regular file (it's the key *material* being redacted).
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            // Binary / unreadable file: not a PEM key.
            continue;
        };
        if !is_pem_private_key(&content) {
            continue;
        }
        let origin = format!("$ssh:{name}");
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            let normalized = trimmed.replace("\r\n", "\n");
            if normalized != trimmed {
                out.push((normalized.clone(), origin.clone()));
            }
            for line in normalized
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                out.push((line.to_string(), origin.clone()));
            }
            out.push((trimmed, origin));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn enabled_cfg() -> RedactConfig {
        RedactConfig {
            enabled: true,
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            ssh_key_dir: None,
            dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
            extra_dotenv_paths: vec![],
            min_secret_length: 8,
            placeholder: "***REDACT***".into(),
            denylist: vec![],
            allowlist: vec![],
        }
    }

    #[test]
    fn disabled_passes_through() {
        let mut cfg = enabled_cfg();
        cfg.enabled = false;
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert!(t.disabled());
        assert_eq!(t.scrub("sk-secret-token"), "sk-secret-token");
    }

    #[test]
    fn empty_passes_through() {
        let cfg = enabled_cfg();
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert!(t.is_empty());
        assert_eq!(t.scrub("anything goes"), "anything goes");
    }

    #[test]
    fn dotenv_values_redacted() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "API_KEY=sk-super-secret-token-1234\nUSER_VAR=ignored-short\n# comment\nQUOTED=\"another-long-secret-here\"\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        let body = "got sk-super-secret-token-1234 and another-long-secret-here";
        let scrubbed = t.scrub(body);
        assert!(!scrubbed.contains("sk-super-secret-token-1234"));
        assert!(!scrubbed.contains("another-long-secret-here"));
        assert!(scrubbed.contains("***REDACT***"));
    }

    #[test]
    fn dotenv_stray_line_does_not_void_file() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "export DEBUG\nAPI_KEY=sk-super-secret-token-1234\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(t.scrub("sk-super-secret-token-1234"), "***REDACT***");
        assert!(t.unsupported_files().is_empty());
        assert!(!t.is_empty());
    }

    #[test]
    fn dotenv_no_equals_line_skipped_others_kept() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "source ./other.env\nDB_PASSWORD=a-long-secret-value-1234\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(t.scrub("a-long-secret-value-1234"), "***REDACT***");
        assert!(t.unsupported_files().is_empty());
    }

    #[test]
    fn dotenv_invalid_key_line_skipped() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "FOO-BAR=ignored-long-secret-value\nGOOD_KEY=another-long-secret-value\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(t.scrub("another-long-secret-value"), "***REDACT***");
        assert_eq!(
            t.scrub("ignored-long-secret-value"),
            "ignored-long-secret-value"
        );
        assert!(t.unsupported_files().is_empty());
    }

    #[test]
    fn dotenv_only_stray_lines_falls_through_to_unsupported() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "\u{0}\u{1}: [unterminated\n\tno close").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(t.unsupported_files().len(), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn dotenv_allowlisted_assignment_still_detects_dotenv() {
        let entries = parse_dotenv("PATH=/secret/bin\n", "test.env", &[]);
        assert!(matches!(entries, Some(entries) if entries.is_empty()));
    }

    /// `scrub` is deterministic and byte-stable within a session: the same
    /// input scrubbed twice yields identical bytes. This is load-bearing for
    /// prompt caching (prompt `prompt-caching-strategy.md`) — a non-stable
    /// prefix would bust the provider cache every turn. `aho-corasick`
    /// `LeftmostLongest` `replace_all` with a fixed placeholder is
    /// deterministic, and this guards against a regression.
    #[test]
    fn scrub_is_deterministic_within_a_session() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "API_KEY=sk-super-secret-token-1234\nOTHER=another-long-secret-here\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        let body = "prefix sk-super-secret-token-1234 middle another-long-secret-here suffix \
                    sk-super-secret-token-1234 end";
        let first = t.scrub(body);
        // Many repeated passes must all produce byte-identical output.
        for _ in 0..32 {
            assert_eq!(t.scrub(body), first, "scrub output varied across passes");
        }
        // And it actually redacted (not a trivial pass-through).
        assert!(!first.contains("sk-super-secret-token-1234"));
        assert!(first.contains("***REDACT***"));
    }

    #[test]
    fn short_values_skipped() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "SHORT=abc\nLONG=long-enough-value-here\n").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        cfg.min_secret_length = 8;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        // The 3-char value would have created a useless pattern; check
        // that benign substrings aren't replaced.
        assert_eq!(t.scrub("abc def"), "abc def");
        assert_eq!(t.scrub("long-enough-value-here"), "***REDACT***");
    }

    #[test]
    fn short_credential_shaped_key_value_is_redacted() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "MY_PIN=abc\nSHORT=def\n").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        cfg.min_secret_length = 8;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(t.scrub("pin abc"), "pin ***REDACT***");
        assert_eq!(t.scrub("short def"), "short def");
    }

    #[test]
    fn stored_flycockpit_instance_token_is_forced_redaction_candidate() {
        let tmp = tempfile::TempDir::new().unwrap();
        crate::auth::flycockpit::with_redaction_token_override("fci_secret_token_12345", || {
            let mut cfg = RedactConfig::default();
            cfg.min_secret_length = 128;
            let table = RedactionTable::build(&cfg, tmp.path()).unwrap();
            let scrubbed = table.scrub("token=fci_secret_token_12345");
            assert!(!scrubbed.contains("fci_secret_token_12345"));
            assert!(
                scrubbed.contains("**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**")
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_env_values_are_lossy_scanned_without_panic() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let key = "COCKPIT_TEST_NONUNICODE_SECRET";
        let value = OsString::from_vec(b"nonunicode-secret-\xFF-value-1234".to_vec());
        let lossy = value.to_string_lossy().into_owned();
        unsafe {
            std::env::set_var(key, &value);
        }

        let mut cfg = enabled_cfg();
        cfg.scan_environment = true;
        let dir = TempDir::new().unwrap();
        let table = RedactionTable::build(&cfg, dir.path()).unwrap();
        let scrubbed = table.scrub(&format!("value={lossy}"));
        assert!(!scrubbed.contains(&lossy));
        assert!(scrubbed.contains(&cfg.placeholder));

        unsafe {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn env_value_redacts_encoded_variants() {
        let mut cfg = enabled_cfg();
        cfg.scan_environment = true;
        let dir = TempDir::new().unwrap();
        let secret = "env/variant secret 001";
        let env = HashMap::from([("COCKPIT_TEST_VARIANT_TOKEN".to_string(), secret.to_string())]);
        let table = RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();

        let mut body = format!("raw {secret}");
        for variant in encoded_secret_variants(secret) {
            body.push(' ');
            body.push_str(&variant);
        }
        let scrubbed = table.scrub(&body);
        assert!(!scrubbed.contains(secret));
        for variant in encoded_secret_variants(secret) {
            assert!(!scrubbed.contains(&variant));
        }
    }

    #[test]
    fn dotenv_value_redacts_encoded_variants() {
        let dir = TempDir::new().unwrap();
        let secret = "dotenv/variant secret 001";
        std::fs::write(
            dir.path().join(".env"),
            format!(
                "TOKEN={secret}
"
            ),
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let table = RedactionTable::build(&cfg, dir.path()).unwrap();

        let mut body = format!("raw {secret}");
        for variant in encoded_secret_variants(secret) {
            body.push(' ');
            body.push_str(&variant);
        }
        let scrubbed = table.scrub(&body);
        assert!(!scrubbed.contains(secret));
        for variant in encoded_secret_variants(secret) {
            assert!(!scrubbed.contains(&variant));
        }
    }

    #[test]
    fn credential_shaped_values_register_case_variants_only_for_that_key_shape() {
        let mut cfg = enabled_cfg();
        cfg.scan_environment = true;
        let dir = TempDir::new().unwrap();
        let sensitive = "CaseSecretValue123";
        let ordinary = "CaseOrdinaryValue123";
        let env = HashMap::from([
            ("MY_PASSWORD".to_string(), sensitive.to_string()),
            ("NORMAL_NAME".to_string(), ordinary.to_string()),
        ]);
        let table = RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();

        assert_eq!(
            table.scrub(&sensitive.to_ascii_lowercase()),
            cfg.placeholder
        );
        assert_eq!(
            table.scrub(&sensitive.to_ascii_uppercase()),
            cfg.placeholder
        );
        assert_eq!(
            table.scrub(&ordinary.to_ascii_lowercase()),
            ordinary.to_ascii_lowercase()
        );
    }

    #[test]
    fn non_adjacent_duplicate_values_are_deduplicated() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "FIRST=shared/secret/0001
MIDDLE=other/secret/0002
LAST=shared/secret/0001
",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let table = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(table.entries_for_debug().len(), 8);
        assert_eq!(table.scrub("shared/secret/0001"), cfg.placeholder);
        assert_eq!(table.scrub("other/secret/0002"), cfg.placeholder);
    }

    #[test]
    fn denylisted_value_redacts_encoded_variants() {
        let mut cfg = enabled_cfg();
        cfg.min_secret_length = 8;
        cfg.denylist = vec!["a/b".into()];
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        let scrubbed = t.scrub("raw a/b base64 YS9i hex 612f62 url a%2Fb");
        assert!(!scrubbed.contains("YS9i"));
        assert!(!scrubbed.contains("612f62"));
        assert!(!scrubbed.contains("a%2Fb"));
        assert!(!scrubbed.contains(" raw a/b "));
    }

    #[test]
    fn substring_matches() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "TOKEN=embedded-secret-abc\n").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        let scrubbed = t.scrub("the URL is https://api.example.com?t=embedded-secret-abc&u=x");
        assert!(scrubbed.contains("***REDACT***"));
        assert!(!scrubbed.contains("embedded-secret-abc"));
    }

    #[test]
    fn default_placeholder_is_the_explicit_string() {
        // The user-visible placeholder is part of the spec; if anyone
        // edits the default, this test fails on purpose.
        let cfg = RedactConfig::default();
        assert_eq!(
            cfg.placeholder,
            "**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**"
        );
    }

    #[test]
    fn env_var_value_redacted_with_default_placeholder() {
        // Set a dedicated env var and confirm it lands in the table and
        // gets scrubbed to the default placeholder. Use a value name
        // unique enough that prior env state can't fight us.
        let key = "COCKPIT_TEST_SECRET_TOKEN_XYZ";
        let val = "supersecret-token-value-1234";
        // SAFETY: tests run single-threaded enough that env mutation
        // here is acceptable; the same pattern is used elsewhere in the
        // test suite.
        unsafe {
            std::env::set_var(key, val);
        }
        let cfg = RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            ssh_key_dir: None,
            dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
            extra_dotenv_paths: vec![],
            min_secret_length: 8,
            placeholder: RedactConfig::default().placeholder,
            denylist: vec![],
            allowlist: vec![],
        };
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        let scrubbed = t.scrub(&format!("the token is {val} ok"));
        assert!(scrubbed.contains("**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**"));
        assert!(!scrubbed.contains(val));
        unsafe {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn build_with_env_redacts_env_only_secret_without_process_env() {
        let key = "COCKPIT_TEST_SESSION_ONLY_SECRET";
        let val = "session-only-secret-value-1234";
        unsafe {
            std::env::remove_var(key);
        }
        let mut cfg = enabled_cfg();
        cfg.scan_environment = true;
        cfg.scan_dotenv = false;
        cfg.scan_ssh_keys = false;
        cfg.min_secret_length = 8;
        let dir = TempDir::new().unwrap();
        let env = HashMap::from([(key.to_string(), val.to_string())]);
        let table = RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();
        let scrubbed = table.scrub(&format!("secret={val}"));
        assert!(!scrubbed.contains(val));
        assert!(scrubbed.contains(&cfg.placeholder));
    }

    #[test]
    fn short_env_values_not_redacted() {
        let key = "COCKPIT_TEST_SHORT_VALUE";
        let val = "abc";
        unsafe {
            std::env::set_var(key, val);
        }
        let mut cfg = enabled_cfg();
        cfg.scan_environment = true;
        cfg.min_secret_length = 8;
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        // The 3-char value must not contribute a pattern.
        assert_eq!(t.scrub("the value is abc here"), "the value is abc here");
        unsafe {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn allowlisted_path_not_redacted_even_when_long() {
        // PATH is almost always long enough to clear min_secret_length;
        // confirm $PATH (and the LC_/LANG/XDG_ families) are never in
        // the table even with min_secret_length lowered all the way.
        // (Other env vars' values may still be substrings of PATH —
        // that's an inherent property of substring redaction and is
        // covered by `allowlisted_env_var_names_not_in_table`.)
        let mut cfg = enabled_cfg();
        cfg.scan_environment = true;
        cfg.min_secret_length = 1;
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        let origins = t.entries_for_debug();
        for skipped in ["$PATH", "$HOME", "$LANG", "$LC_ALL", "$XDG_RUNTIME_DIR"] {
            assert!(
                !origins.contains(&skipped),
                "expected allowlisted origin `{skipped}` to be absent"
            );
        }
        for name in ["LC_ALL", "LANG", "XDG_RUNTIME_DIR"] {
            assert!(
                is_allowlisted(name, &[]),
                "expected `{name}` to be allowlisted by prefix"
            );
        }
    }

    #[test]
    fn denylisted_value_always_redacted_including_short() {
        let mut cfg = enabled_cfg();
        cfg.scan_environment = false;
        cfg.scan_dotenv = false;
        cfg.min_secret_length = 16; // huge threshold so length can't help
        cfg.denylist = vec!["sek".into()]; // 3 chars — would normally fail
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        let scrubbed = t.scrub("the keyword sek appears here");
        assert!(scrubbed.contains("***REDACT***"));
        assert!(!scrubbed.contains(" sek "));
    }

    #[test]
    fn denylist_overrides_allowlisted_env_var() {
        // Even if the user added FOO to the allowlist, putting its
        // literal value on the denylist forces redaction.
        let mut cfg = enabled_cfg();
        cfg.scan_environment = false;
        cfg.scan_dotenv = false;
        cfg.denylist = vec!["my-allowlisted-value".into()];
        cfg.allowlist = vec!["FOO".into()];
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        let scrubbed = t.scrub("got my-allowlisted-value back");
        assert!(scrubbed.contains("***REDACT***"));
        assert!(!scrubbed.contains("my-allowlisted-value"));
    }

    #[test]
    fn user_allowlist_skips_dotenv_entry() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "USER_TOKEN=very-long-allowed-value\n").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        cfg.allowlist = vec!["USER_TOKEN".into()];
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(
            t.scrub("got very-long-allowed-value"),
            "got very-long-allowed-value"
        );
    }

    #[test]
    fn allowlisted_env_var_names_not_in_table() {
        // The allowlist works by *name*: even with scan_environment
        // on, `$PATH`/`$HOME`/`$SHELL` etc. must not contribute
        // patterns to the matcher. (Substring overlap with other env
        // vars is a separate concern and an inherent property of
        // substring redaction; that's fine — we just don't want PATH
        // itself catalogued.)
        let cfg = RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            ssh_key_dir: None,
            dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
            extra_dotenv_paths: vec![],
            min_secret_length: 1,
            placeholder: "***".into(),
            denylist: vec![],
            allowlist: vec![],
        };
        let dir = TempDir::new().unwrap();
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        let origins = t.entries_for_debug();
        for name in ENV_ALLOWLIST {
            let key = format!("${name}");
            assert!(
                !origins.contains(&key.as_str()),
                "allowlisted env var {name} leaked into the redaction table"
            );
        }
    }

    // ── Prune list (§6.3) ───────────────────────────────────────────────

    #[test]
    fn prune_drops_literals_and_short_values_keeps_long_numeric_secrets() {
        for lit in NEVER_SCRUB_LITERALS {
            assert!(is_pruned(lit, 8), "`{lit}` literal must be pruned");
            assert!(
                is_pruned(&lit.to_uppercase(), 8),
                "`{lit}` literal must be pruned case-insensitively"
            );
        }
        // Short ints / floats stay below the default floor and are pruned.
        assert!(is_pruned("42", 8));
        assert!(is_pruned("5432", 8));
        assert!(is_pruned("3.14", 8));
        // Long numeric values that clear the floor can be credentials.
        assert!(!is_pruned("100000000", 8));
        assert!(!is_pruned("12345678901234567890", 8));
        assert!(!is_pruned("1.234567e89", 8));
        // Too short.
        assert!(is_pruned("short", 8));
        // A plausible secret survives.
        assert!(!is_pruned("sk-long-enough-secret", 8));
    }

    #[test]
    fn never_scrub_literals_not_in_table() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(
            &env_path,
            "DEBUG=true\nFEATURE=off\nCOUNT=4200000\nRATIO=3.14\nSECRET=a-real-long-secret-here\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        cfg.min_secret_length = 8;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        // The literal and short numeric values pass through unscrubbed.
        assert_eq!(t.scrub("true off 4200000 3.14"), "true off 4200000 3.14");
        // The real secret is scrubbed.
        assert_eq!(t.scrub("a-real-long-secret-here"), "***REDACT***");
    }

    #[test]
    fn long_numeric_dotenv_value_is_redacted() {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "NUMERIC_TOKEN=12345678901234567890\n").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(t.scrub("token=12345678901234567890"), "token=***REDACT***");
    }

    #[test]
    fn long_numeric_env_value_is_redacted() {
        let dir = TempDir::new().unwrap();
        let cfg = RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            ssh_key_dir: None,
            dotenv_patterns: crate::config::extended::default_dotenv_patterns(),
            extra_dotenv_paths: vec![],
            min_secret_length: 8,
            placeholder: "***REDACT***".into(),
            denylist: vec![],
            allowlist: vec![],
        };
        let key = "COCKPIT_TEST_NUMERIC_SECRET";
        let val = "98765432109876543210";
        // SAFETY: this mirrors the existing env-mutation tests in this
        // module; the key is unique to this test and removed before return.
        unsafe {
            std::env::set_var(key, val);
        }
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(t.scrub(&format!("token={val}")), "token=***REDACT***");
        unsafe {
            std::env::remove_var(key);
        }
    }

    // ── Format auto-detection (§4) ───────────────────────────────────────

    #[test]
    fn json_leaf_strings_redacted_keys_never() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("config.env");
        std::fs::write(
            &p,
            r#"{"database":{"password":"json-secret-password","port":5432},"flags":["enabled-feature-x"]}"#,
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        // Match the `.env`-suffixed file by an explicit glob.
        cfg.dotenv_patterns = vec!["config.env".into()];
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(t.scrub("json-secret-password"), "***REDACT***");
        // Nested array leaf string is also a candidate.
        assert_eq!(t.scrub("enabled-feature-x"), "***REDACT***");
        // The key `password` is never scrubbed; the int `5432` is pruned.
        assert_eq!(t.scrub("password 5432"), "password 5432");
    }

    #[test]
    fn yaml_leaf_strings_redacted_keys_never() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(
            &p,
            "database:\n  password: yaml-secret-password\n  port: 5432\nname: short\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(t.scrub("yaml-secret-password"), "***REDACT***");
        // Key `password` never scrubbed.
        assert_eq!(t.scrub("password"), "password");
    }

    #[test]
    fn toml_leaf_strings_redacted_keys_never() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(
            &p,
            "[database]\npassword = \"toml-secret-password\"\nport = 5432\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(t.scrub("toml-secret-password"), "***REDACT***");
        assert_eq!(t.scrub("password 5432"), "password 5432");
    }

    #[test]
    fn unsupported_format_is_skipped_and_recorded() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        // Binary-ish / non-parseable content that is neither dotenv,
        // JSON, TOML, nor YAML.
        std::fs::write(&p, "\u{0}\u{1}: [unterminated\n\tno close").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(t.unsupported_files().len(), 1);
        // Nothing scrubbed (no candidates).
        assert!(t.is_empty());
    }

    // ── Inline disable marker (§5) ───────────────────────────────────────

    #[test]
    fn dotenv_marker_excludes_long_value() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(
            &p,
            "# enable debug\nDEBUG=true # COCKPIT_DISABLE_REDACT\nMARKED=a-long-secret-but-disabled # COCKPIT_DISABLE_REDACT\nKEPT=another-long-secret-here\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        // The long marked value is left intact.
        assert_eq!(
            t.scrub("a-long-secret-but-disabled"),
            "a-long-secret-but-disabled"
        );
        // The unmarked secret is still scrubbed.
        assert_eq!(t.scrub("another-long-secret-here"), "***REDACT***");
    }

    #[test]
    fn dotenv_unterminated_quotes_are_scanned_conservatively() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(
            &p,
            r#"TOKEN="unterminated-secret-value-001
OTHER='unterminated-secret-value-002
"#,
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let table = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(
            table.scrub("unterminated-secret-value-001"),
            cfg.placeholder
        );
        assert_eq!(
            table.scrub("unterminated-secret-value-002"),
            cfg.placeholder
        );
        assert!(table.unsupported_files().is_empty());
    }

    #[test]
    fn dotenv_hash_inside_quoted_value_is_not_a_comment() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(&p, "TOKEN=\"value#with#hashes-long\"\n").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(t.scrub("value#with#hashes-long"), "***REDACT***");
    }

    #[test]
    fn structured_disable_marker_is_scoped_to_one_duplicate_value_occurrence() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(
            &p,
            r#"marked = "shared-structured-secret" # COCKPIT_DISABLE_REDACT
kept = "shared-structured-secret"
"#,
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let table = RedactionTable::build(&cfg, dir.path()).unwrap();

        assert_eq!(table.scrub("shared-structured-secret"), cfg.placeholder);
    }

    #[test]
    fn toml_marker_excludes_long_value() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(
            &p,
            "marked = \"toml-marked-long-secret\" # COCKPIT_DISABLE_REDACT\nkept = \"toml-kept-long-secret\"\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(
            t.scrub("toml-marked-long-secret"),
            "toml-marked-long-secret"
        );
        assert_eq!(t.scrub("toml-kept-long-secret"), "***REDACT***");
    }

    #[test]
    fn yaml_marker_excludes_long_value() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join(".env");
        std::fs::write(
            &p,
            "marked: yaml-marked-long-secret # COCKPIT_DISABLE_REDACT\nkept: yaml-kept-long-secret\n",
        )
        .unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(
            t.scrub("yaml-marked-long-secret"),
            "yaml-marked-long-secret"
        );
        assert_eq!(t.scrub("yaml-kept-long-secret"), "***REDACT***");
    }

    #[test]
    fn json_has_no_comment_marker() {
        // JSON is exempt from the marker: a `# COCKPIT_DISABLE_REDACT`
        // would make the doc invalid JSON, so it parses as JSON only
        // without one and every leaf string stays a candidate.
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("c.env");
        std::fs::write(&p, r#"{"token":"json-no-marker-secret"}"#).unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        cfg.dotenv_patterns = vec!["c.env".into()];
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert_eq!(t.scrub("json-no-marker-secret"), "***REDACT***");
    }

    // ── gitignore-pattern matching, cwd-downward (§3) ────────────────────

    #[test]
    fn patterns_match_cwd_downward_across_subdirs() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join(".env"), "ROOT=root-secret-value-long\n").unwrap();
        std::fs::write(root.join("a/.env.local"), "SUB=sub-local-secret-value\n").unwrap();
        std::fs::write(root.join("a/b/.env"), "DEEP=deep-secret-value-here\n").unwrap();
        // A non-matching file is ignored.
        std::fs::write(root.join("a/other.txt"), "OTHER=not-an-env-file-value\n").unwrap();

        let paths = matched_dotenv_paths(
            root,
            &crate::config::extended::default_dotenv_patterns(),
            &[],
        );
        assert!(paths.iter().any(|p| p.ends_with(".env")));
        assert!(paths.iter().any(|p| p.ends_with("a/.env.local")));
        assert!(paths.iter().any(|p| p.ends_with("a/b/.env")));
        assert!(!paths.iter().any(|p| p.ends_with("other.txt")));

        // End-to-end: every matched file's secret is scrubbed.
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        let t = RedactionTable::build(&cfg, root).unwrap();
        for secret in [
            "root-secret-value-long",
            "sub-local-secret-value",
            "deep-secret-value-here",
        ] {
            assert_eq!(
                t.scrub(secret),
                "***REDACT***",
                "expected `{secret}` scrubbed"
            );
        }
        assert_eq!(t.scrub("not-an-env-file-value"), "not-an-env-file-value");
    }

    #[test]
    fn git_object_store_not_descended() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/.env"), "GIT=inside-git-secret-value\n").unwrap();
        std::fs::write(root.join(".env"), "TOP=top-level-secret-value\n").unwrap();
        let paths = matched_dotenv_paths(
            root,
            &crate::config::extended::default_dotenv_patterns(),
            &[],
        );
        assert!(paths.iter().any(|p| p.ends_with(".env")));
        assert!(
            !paths.iter().any(|p| p.to_string_lossy().contains(".git")),
            "must not descend into .git/"
        );
    }

    #[test]
    fn extra_dotenv_paths_still_honored() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        let extra = root.join("custom.secrets");
        std::fs::write(&extra, "EXTRA=extra-path-secret-value\n").unwrap();
        let mut cfg = enabled_cfg();
        cfg.scan_dotenv = true;
        cfg.extra_dotenv_paths = vec![extra];
        let t = RedactionTable::build(&cfg, root).unwrap();
        assert_eq!(t.scrub("extra-path-secret-value"), "***REDACT***");
    }

    #[test]
    fn dotenv_max_depth_caps_outside_repo_unbounded_inside() {
        // Inside a git repo: unbounded so no `.env` is ever missed.
        assert_eq!(dotenv_max_depth(true), None);
        // Outside a repo: capped at depth 8 (the giant-dir pathological
        // case; `.env` files live near the root in practice).
        assert_eq!(dotenv_max_depth(false), Some(8));
    }

    /// Build a temp tree with a `.env` nine directory levels below the root
    /// (`a/b/c/d/e/f/g/h/i/.env`). `walkdir` counts the root as depth 0, so
    /// `a`=1 … `i`=9: the `.env` file itself sits at depth 10's parent — it
    /// is only reachable by descending into `i` (depth 9), past a `max_depth`
    /// of 8. Returns `(TempDir, root)`.
    fn deep_env_tree() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        let deep = root.join("a/b/c/d/e/f/g/h/i");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join(".env"), "DEEP=deep-nested-secret-value\n").unwrap();
        // A shallow `.env` at the root is always in range — sanity anchor.
        std::fs::write(root.join(".env"), "TOP=top-level-secret-value\n").unwrap();
        (dir, root)
    }

    #[test]
    fn walker_depth8_drops_depth9_env() {
        // Simulate the non-repo branch directly (the helper decided depth 8)
        // by walking with `max_depth(Some(8))`.
        use ignore::WalkBuilder;
        use ignore::overrides::OverrideBuilder;

        let (_dir, root) = deep_env_tree();
        let mut ob = OverrideBuilder::new(&root);
        for pat in crate::config::extended::default_dotenv_patterns() {
            ob.add(&pat).unwrap();
        }
        let overrides = ob.build().unwrap();
        let mut builder = WalkBuilder::new(&root);
        builder
            .standard_filters(false)
            .max_depth(Some(8))
            .overrides(overrides);
        let mut found: Vec<PathBuf> = builder
            .build()
            .flatten()
            .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
            .map(|e| e.into_path())
            .collect();
        found.sort();
        // The root `.env` is in range; the depth-9 nested one is not.
        assert!(found.iter().any(|p| p == &root.join(".env")));
        assert!(
            !found.iter().any(|p| p.ends_with("a/b/c/d/e/f/g/h/i/.env")),
            "depth-9 `.env` must be dropped by max_depth(8): {found:?}"
        );
    }

    #[test]
    fn walker_unbounded_finds_depth9_env() {
        // Simulate the in-repo branch directly (unbounded walk).
        use ignore::WalkBuilder;
        use ignore::overrides::OverrideBuilder;

        let (_dir, root) = deep_env_tree();
        let mut ob = OverrideBuilder::new(&root);
        for pat in crate::config::extended::default_dotenv_patterns() {
            ob.add(&pat).unwrap();
        }
        let overrides = ob.build().unwrap();
        let mut builder = WalkBuilder::new(&root);
        builder
            .standard_filters(false)
            .max_depth(None)
            .overrides(overrides);
        let found: Vec<PathBuf> = builder
            .build()
            .flatten()
            .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
            .map(|e| e.into_path())
            .collect();
        assert!(
            found.iter().any(|p| p.ends_with("a/b/c/d/e/f/g/h/i/.env")),
            "unbounded walk must find the depth-9 `.env`: {found:?}"
        );
    }

    // ── Private SSH keys (`scan_ssh_keys`) ───────────────────────────────

    /// A realistic OpenSSH private-key body. The header is what `build`
    /// content-matches on; the body is just enough to clear `min_secret_length`
    /// and exercise multi-line key material.
    const ED25519_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACDfake-key-material-for-test-not-a-real-key-0001AAAAAA\n\
-----END OPENSSH PRIVATE KEY-----";

    const ED25519_PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5fake-public-key-material-001 user@host";

    /// Build a config with only `scan_ssh_keys` on, pointed at `dir` via the
    /// `ssh_key_dir` override so the test never touches the real home.
    fn ssh_cfg(dir: &Path) -> RedactConfig {
        let mut cfg = enabled_cfg();
        cfg.scan_ssh_keys = true;
        cfg.ssh_key_dir = Some(dir.to_path_buf());
        cfg
    }

    #[test]
    fn ssh_private_key_redacted_public_key_not() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE_KEY).unwrap();
        std::fs::write(dir.path().join("id_ed25519.pub"), ED25519_PUBLIC_KEY).unwrap();

        let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

        // The private key body is scrubbed wherever it appears.
        let scrubbed = t.scrub(ED25519_PRIVATE_KEY);
        assert!(
            !scrubbed.contains("fake-key-material-for-test"),
            "private key body must be scrubbed: {scrubbed:?}"
        );
        assert!(scrubbed.contains("***REDACT***"));

        // The sibling public key content is left intact.
        assert_eq!(t.scrub(ED25519_PUBLIC_KEY), ED25519_PUBLIC_KEY);
    }

    #[test]
    fn ssh_private_key_redacted_inside_arbitrary_text() {
        // Simulates a key pasted into a tool result (`cat ~/.ssh/id_ed25519`).
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("id_rsa"), ED25519_PRIVATE_KEY).unwrap();

        let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();
        let body = format!("here is the output:\n{ED25519_PRIVATE_KEY}\n— end of file");
        let scrubbed = t.scrub(&body);
        assert!(!scrubbed.contains("fake-key-material-for-test"));
        assert!(!scrubbed.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(scrubbed.contains("***REDACT***"));
        // Surrounding prose is preserved.
        assert!(scrubbed.contains("here is the output:"));
        assert!(scrubbed.contains("— end of file"));
    }

    #[test]
    fn ssh_non_key_files_not_registered() {
        let dir = TempDir::new().unwrap();
        // None of these carry a PEM private-key header, and all are name-skipped.
        std::fs::write(
            dir.path().join("known_hosts"),
            "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5known-hosts-entry-001\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("authorized_keys"),
            "ssh-rsa AAAAB3NzaC1authorized-keys-entry-value-001 user@host\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config"),
            "Host example\n  HostName example.com-config-value-001\n",
        )
        .unwrap();

        let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();
        // Nothing was registered: the table is empty and content passes through.
        assert!(t.is_empty());
        assert_eq!(
            t.scrub("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5known-hosts-entry-001"),
            "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5known-hosts-entry-001"
        );
    }

    #[test]
    fn ssh_keys_skipped_when_disabled() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE_KEY).unwrap();
        let mut cfg = ssh_cfg(dir.path());
        cfg.scan_ssh_keys = false;
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        // With the source off, the key is not in the table.
        assert!(t.is_empty());
        assert_eq!(t.scrub(ED25519_PRIVATE_KEY), ED25519_PRIVATE_KEY);
    }

    #[test]
    fn ssh_missing_dir_is_silent() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("no-such-ssh-dir");
        let mut cfg = enabled_cfg();
        cfg.scan_ssh_keys = true;
        cfg.ssh_key_dir = Some(missing);
        // Build succeeds (no error) with an empty table.
        let t = RedactionTable::build(&cfg, dir.path()).unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn ssh_encrypted_private_key_still_registered() {
        let dir = TempDir::new().unwrap();
        let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIIFHzBJBgkqhkiG9w0BBQ0wPDencrypted-key-material-for-test-001\n\
-----END ENCRYPTED PRIVATE KEY-----";
        std::fs::write(dir.path().join("encrypted_key"), encrypted).unwrap();
        let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();
        let scrubbed = t.scrub(encrypted);
        assert!(!scrubbed.contains("encrypted-key-material-for-test"));
        assert!(scrubbed.contains("***REDACT***"));
    }

    #[test]
    fn ssh_private_key_lines_are_redacted_individually() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("id_ed25519"), ED25519_PRIVATE_KEY).unwrap();
        let table = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

        for line in ED25519_PRIVATE_KEY.lines().filter(|line| !line.is_empty()) {
            let scrubbed = table.scrub(line);
            assert!(!scrubbed.contains(line));
            assert_eq!(scrubbed, "***REDACT***");
        }
    }

    #[test]
    fn ssh_private_key_crlf_lines_are_redacted_individually() {
        let dir = TempDir::new().unwrap();
        let crlf_key = ED25519_PRIVATE_KEY.replace('\n', "\r\n");
        std::fs::write(dir.path().join("id_ed25519"), &crlf_key).unwrap();
        let table = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

        for line in ED25519_PRIVATE_KEY.lines().filter(|line| !line.is_empty()) {
            let scrubbed = table.scrub(line);
            assert!(!scrubbed.contains(line));
            assert_eq!(scrubbed, "***REDACT***");
        }
    }

    #[test]
    fn ssh_crlf_and_lf_echoes_both_match() {
        // A key on disk with CRLF line endings: both the verbatim CRLF echo
        // and an LF-normalized echo must scrub (the normalized variant is
        // registered alongside the trimmed original).
        let dir = TempDir::new().unwrap();
        let crlf_key = ED25519_PRIVATE_KEY.replace('\n', "\r\n");
        std::fs::write(dir.path().join("id_ed25519"), &crlf_key).unwrap();
        let t = RedactionTable::build(&ssh_cfg(dir.path()), dir.path()).unwrap();

        let lf_echo = ED25519_PRIVATE_KEY; // LF
        assert!(
            !t.scrub(lf_echo).contains("fake-key-material-for-test"),
            "LF echo must scrub"
        );
        assert!(
            !t.scrub(crlf_key.trim())
                .contains("fake-key-material-for-test"),
            "CRLF echo must scrub"
        );
    }

    #[test]
    fn is_pem_private_key_matches_headers_only() {
        for h in PEM_PRIVATE_KEY_HEADERS {
            assert!(is_pem_private_key(&format!("{h}\nbody\n")));
            // Leading whitespace is tolerated.
            assert!(is_pem_private_key(&format!("\n  {h}\nbody\n")));
        }
        assert!(!is_pem_private_key("ssh-ed25519 AAAA... user@host"));
        assert!(!is_pem_private_key("ssh-rsa AAAA..."));
        assert!(!is_pem_private_key("not a key at all"));
    }
}
