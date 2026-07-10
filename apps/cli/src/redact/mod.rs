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

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result};
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PersistedRedactionTable {
    entries: Vec<(String, String)>,
    placeholder: String,
    disabled: bool,
    unsupported_files: Vec<String>,
}

/// A built lookup of `value → origin-name` pairs the next outbound
/// request must be scrubbed against. Hold one per session (cheap to
/// rebuild; small in-memory footprint).
pub struct RedactionTable {
    /// Aho-Corasick search structure; `None` when there's nothing to
    /// scrub or redaction is disabled. Keeping it `Option` lets
    /// [`scrub`] short-circuit without allocating.
    matcher: Option<AhoCorasick>,
    /// Canonical `(value, origin)` entries used to build `matcher`. Stored so
    /// monotonic egress tables can union candidates and compile one matcher.
    entries: Vec<(String, String)>,
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
                entries: Vec::new(),
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

        Self::from_entries(entries, cfg.placeholder.clone(), false, unsupported_files)
    }

    fn from_entries(
        mut entries: Vec<(String, String)>,
        placeholder: String,
        disabled: bool,
        unsupported_files: Vec<PathBuf>,
    ) -> Result<Self> {
        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        entries.dedup_by(|a, b| a.0 == b.0);
        if entries.is_empty() {
            return Ok(Self {
                matcher: None,
                entries,
                origins: Vec::new(),
                placeholder,
                disabled,
                unsupported_files,
            });
        }
        let patterns: Vec<&str> = entries.iter().map(|(v, _)| v.as_str()).collect();
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(false)
            .build(&patterns)
            .map_err(|e| anyhow::anyhow!("building aho-corasick: {e}"))?;
        let origins = entries.iter().map(|(_, o)| o.clone()).collect();
        Ok(Self {
            matcher: Some(matcher),
            entries,
            origins,
            placeholder,
            disabled,
            unsupported_files,
        })
    }

    pub fn union(&self, other: &Self) -> Result<Self> {
        let mut entries = self.entries.clone();
        entries.extend(other.entries.iter().cloned());
        let mut unsupported_files = self.unsupported_files.clone();
        unsupported_files.extend(other.unsupported_files.iter().cloned());
        unsupported_files.sort();
        unsupported_files.dedup();
        Self::from_entries(
            entries,
            self.placeholder.clone(),
            self.disabled && other.disabled,
            unsupported_files,
        )
    }

    /// Serialize this accumulated table for session-local persistence. The
    /// payload intentionally contains literal values: it is stored in the
    /// same private session DB that now stores raw transcript content.
    pub fn to_persisted_json(&self) -> Result<String> {
        let snapshot = PersistedRedactionTable {
            entries: self.entries.clone(),
            placeholder: self.placeholder.clone(),
            disabled: self.disabled,
            unsupported_files: self
                .unsupported_files
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
        };
        serde_json::to_string(&snapshot).context("serializing redaction table")
    }

    /// Rebuild an accumulated table persisted by [`Self::to_persisted_json`].
    pub fn from_persisted_json(json: &str) -> Result<Self> {
        let snapshot: PersistedRedactionTable =
            serde_json::from_str(json).context("deserializing redaction table")?;
        Self::from_entries(
            snapshot.entries,
            snapshot.placeholder,
            snapshot.disabled,
            snapshot
                .unsupported_files
                .into_iter()
                .map(PathBuf::from)
                .collect(),
        )
    }

    /// Scrub every secret in `body`. Returns the cleaned string. The
    /// no-table-or-disabled path returns a borrowed input, and a configured
    /// table with no match also avoids allocating.
    pub fn scrub_cow<'a>(&self, body: &'a str) -> Cow<'a, str> {
        let Some(matcher) = self.matcher.as_ref() else {
            return Cow::Borrowed(body);
        };
        if !matcher.is_match(body) {
            return Cow::Borrowed(body);
        }
        let replacements = vec![self.placeholder.as_str(); self.origins.len()];
        Cow::Owned(matcher.replace_all(body, &replacements))
    }

    /// Scrub every secret in `body`. Returns the cleaned string.
    pub fn scrub(&self, body: &str) -> String {
        self.scrub_cow(body).into_owned()
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
            entries: Vec::new(),
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
mod scrub_fast_path_tests {
    use super::*;

    #[test]
    fn empty_table_scrub_cow_borrows_input() {
        let table = RedactionTable::empty();
        let input = "nothing secret here";
        match table.scrub_cow(input) {
            Cow::Borrowed(got) => assert_eq!(got.as_ptr(), input.as_ptr()),
            Cow::Owned(_) => panic!("empty redaction table should not allocate"),
        }
    }

    fn table_from_env_value(name: &str, value: &str) -> RedactionTable {
        let cfg = RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "[redacted]".to_string(),
            ..RedactConfig::default()
        };
        let env = HashMap::from([(name.to_string(), value.to_string())]);
        RedactionTable::build_with_env(&cfg, Path::new("."), &env).unwrap()
    }

    #[test]
    fn unioned_tables_scrub_values_from_both_inputs() {
        let first = table_from_env_value("FIRST_SECRET", "first-secret-value");
        let second = table_from_env_value("SECOND_SECRET", "second-secret-value");
        let unioned = first.union(&second).unwrap();

        let scrubbed = unioned.scrub("first-secret-value and second-secret-value");
        assert!(!scrubbed.contains("first-secret-value"), "{scrubbed}");
        assert!(!scrubbed.contains("second-secret-value"), "{scrubbed}");
        assert_eq!(scrubbed.matches("[redacted]").count(), 2);
    }

    #[test]
    fn persisted_table_round_trips_entries_and_scrubs() {
        let first = table_from_env_value("FIRST_SECRET", "first-secret-value");
        let second = table_from_env_value("SECOND_SECRET", "second-secret-value");
        let unioned = first.union(&second).unwrap();
        let json = unioned.to_persisted_json().unwrap();
        let restored = RedactionTable::from_persisted_json(&json).unwrap();

        let scrubbed = restored.scrub("first-secret-value and second-secret-value");
        assert!(!scrubbed.contains("first-secret-value"), "{scrubbed}");
        assert!(!scrubbed.contains("second-secret-value"), "{scrubbed}");
        assert_eq!(scrubbed.matches("[redacted]").count(), 2);
    }

    #[test]
    fn empty_table_does_not_scrub_env_shaped_names() {
        let table = RedactionTable::empty();
        for name in [
            "AWS_SECRET_ACCESS_KEY",
            "SERVICE_TOKEN",
            "DATABASE_PASSWORD",
            "CUSTOM_PIN",
            "API_CREDENTIALS",
        ] {
            assert!(env_scrub_patterns(name));
            let input = format!("{name}=not-a-secret-value");
            assert_eq!(table.scrub(&input), input);
        }
    }

    #[test]
    fn unioned_table_is_deterministic_for_unchanged_input() {
        let first = table_from_env_value("FIRST_SECRET", "first-secret-value");
        let second = table_from_env_value("SECOND_SECRET", "second-secret-value");
        let once = first.union(&second).unwrap();
        let twice = once.union(&second).unwrap();
        let input = "first-secret-value / second-secret-value";
        assert_eq!(once.scrub(input), twice.scrub(input));
    }

    #[test]
    fn union_with_scanning_disabled_keeps_old_values_and_adds_no_new_env_values() {
        let first = table_from_env_value("FIRST_SECRET", "first-secret-value");
        let cfg = RedactConfig {
            enabled: true,
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "[redacted]".to_string(),
            ..RedactConfig::default()
        };
        let env = HashMap::from([(
            "SECOND_SECRET".to_string(),
            "second-secret-value".to_string(),
        )]);
        let disabled_source = RedactionTable::build_with_env(&cfg, Path::new("."), &env).unwrap();
        let unioned = first.union(&disabled_source).unwrap();

        let scrubbed = unioned.scrub("first-secret-value and second-secret-value");
        assert!(!scrubbed.contains("first-secret-value"), "{scrubbed}");
        assert!(scrubbed.contains("second-secret-value"), "{scrubbed}");
    }

    #[test]
    fn configured_table_borrows_when_there_is_no_match_and_scrubs_match() {
        let cfg = RedactConfig {
            enabled: true,
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            placeholder: "[redacted]".to_string(),
            denylist: vec!["SECRET".to_string()],
            ..RedactConfig::default()
        };
        let table = RedactionTable::build_with_env(&cfg, Path::new("."), &HashMap::new()).unwrap();
        let clean = "plain text";
        match table.scrub_cow(clean) {
            Cow::Borrowed(got) => assert_eq!(got.as_ptr(), clean.as_ptr()),
            Cow::Owned(_) => panic!("no-match scrub should not allocate"),
        }
        assert_eq!(table.scrub("the SECRET value"), "the [redacted] value");
    }
}

#[cfg(test)]
mod tests;
