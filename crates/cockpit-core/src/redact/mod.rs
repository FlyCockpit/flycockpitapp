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

mod dotenv;
mod ssh;
mod structured;

#[cfg(test)]
use self::dotenv::*;
use self::dotenv::{collect_env_file_candidates, consume_marked_value, matched_dotenv_paths};
use self::ssh::collect_ssh_key_candidates;
#[cfg(test)]
use self::ssh::*;
use self::structured::{
    collect_json_strings, collect_toml_strings, collect_yaml_strings, strip_quotes,
};

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
    // These are literal PEM header strings (never real key material), matched
    // as prefixes to detect keys for redaction. The `allowlist secret` marker
    // tells the CI secret scanner to skip these lines.
    "-----BEGIN OPENSSH PRIVATE KEY-----", // pragma: allowlist secret
    "-----BEGIN RSA PRIVATE KEY-----",     // pragma: allowlist secret
    "-----BEGIN EC PRIVATE KEY-----",      // pragma: allowlist secret
    "-----BEGIN DSA PRIVATE KEY-----",     // pragma: allowlist secret
    "-----BEGIN PRIVATE KEY-----",         // pragma: allowlist secret
    "-----BEGIN ENCRYPTED PRIVATE KEY-----", // pragma: allowlist secret
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
        Self::build_with_env_and_store(cfg, cwd, &env)
    }

    /// Build a table from the provided session env + the env files matched
    /// under `cwd`. Daemon sessions use this so redaction tracks the immutable
    /// session snapshot instead of the daemon process environment.
    #[allow(dead_code)]
    pub fn build_with_env(
        cfg: &RedactConfig,
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> Result<Self> {
        Self::build_with_env_and_secrets(cfg, cwd, env, std::iter::empty())
    }

    /// Production session-env builder. Named secrets are loaded here so the
    /// injected [`Self::build_with_env`] seam remains hermetic for tests.
    pub fn build_with_env_and_store(
        cfg: &RedactConfig,
        cwd: &Path,
        env: &HashMap<String, String>,
    ) -> Result<Self> {
        let stored_secrets = crate::credentials::CredentialStore::open_default()
            .map(|store| {
                store
                    .named_secret_entries()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Self::build_with_env_and_secrets(cfg, cwd, env, stored_secrets)
    }

    /// Hermetic table builder with an injected named-secret source. Production
    /// callers use [`Self::build_with_env`], which reads the credential store;
    /// tests use this seam without touching a developer's credentials.
    pub fn build_with_env_and_secrets(
        cfg: &RedactConfig,
        cwd: &Path,
        env: &HashMap<String, String>,
        stored_secrets: impl IntoIterator<Item = (String, String)>,
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

        for (name, value) in stored_secrets {
            candidates.push(Candidate::forced(value, format!("$secret:{name}"), true));
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
mod scrub_inventory_tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const DOC_REL: &str = "apps/cli/docs/redaction-scrub-sites.md";
    const INVENTORY_START: &str = "<!-- scrub-inventory:start -->";
    const INVENTORY_END: &str = "<!-- scrub-inventory:end -->";
    const EXPECTED_SCRUB_FILES: &[&str] = &[
        "crates/cockpit-core/src/daemon/org_sync.rs",
        "crates/cockpit-core/src/daemon/remote_audit_upload.rs",
        "crates/cockpit-core/src/daemon/server/dispatch.rs",
        "crates/cockpit-core/src/daemon/server/mod.rs",
        "crates/cockpit-core/src/daemon/session_worker/mod.rs",
        "crates/cockpit-core/src/daemon/session_worker/run.rs",
        "crates/cockpit-core/src/embeddings.rs",
        "crates/cockpit-core/src/engine/driver/reports.rs",
        "crates/cockpit-core/src/engine/model/dispatch.rs",
        "crates/cockpit-core/src/engine/model/outbound_guard.rs",
        "crates/cockpit-core/src/engine/model/redact.rs",
        "crates/cockpit-core/src/harness/run.rs",
        "crates/cockpit-core/src/knowledge.rs",
        "crates/cockpit-core/src/redact/mod.rs",
        "crates/cockpit-core/src/session/export/mod.rs",
    ];

    #[test]
    fn scrub_inventory_doc_matches_source_tree() {
        let root = repo_root();
        let expected = set(EXPECTED_SCRUB_FILES);
        let actual = production_scrub_files(&root);
        assert_eq!(
            actual, expected,
            "production scrub file set changed; update {DOC_REL}"
        );

        let doc_paths = doc_inventory_paths(&root.join(DOC_REL));
        assert_eq!(
            doc_paths, expected,
            "{DOC_REL} machine-checked manifest must match the enforced scrub file set"
        );

        for rel in &expected {
            assert!(
                root.join(rel).exists(),
                "{DOC_REL} lists missing path `{rel}`"
            );
        }
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("cockpit-core has a repo root two levels up")
            .to_path_buf()
    }

    fn production_scrub_files(root: &Path) -> BTreeSet<String> {
        let mut files = Vec::new();
        collect_rust_files(&root.join("apps/cli/src"), &mut files);
        collect_rust_files(&root.join("crates"), &mut files);
        files
            .into_iter()
            .filter(|path| !is_test_path(path))
            .filter_map(|path| {
                let source = fs::read_to_string(&path)
                    .unwrap_or_else(|err| panic!("reading `{}`: {err}", path.display()));
                source_has_scrub_entrypoint(&strip_cfg_test_blocks(&source)).then(|| {
                    path.strip_prefix(root)
                        .unwrap_or_else(|err| {
                            panic!(
                                "normalizing `{}` relative to repo root: {err}",
                                path.display()
                            )
                        })
                        .to_string_lossy()
                        .replace('\\', "/")
                })
            })
            .collect()
    }

    fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("reading directory `{}`: {err}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|err| {
                    panic!("reading directory entry in `{}`: {err}", dir.display())
                })
                .path();
            if path.is_dir() {
                collect_rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    fn is_test_path(path: &Path) -> bool {
        path.file_name().is_some_and(|name| name == "tests.rs")
            || path
                .components()
                .any(|component| component.as_os_str() == "tests")
    }

    fn source_has_scrub_entrypoint(source: &str) -> bool {
        [
            ".scrub(",
            "scrub_many(",
            "scrub_cow(",
            "scrub_json_strings(",
            "scrub_event_for_principal(",
            "scrub_history_for_principal(",
        ]
        .iter()
        .any(|needle| source.contains(needle))
    }

    fn strip_cfg_test_blocks(source: &str) -> String {
        let mut kept = String::new();
        let mut pending_cfg_test = false;
        let mut skip_depth: Option<i32> = None;

        for line in source.lines() {
            if let Some(depth) = skip_depth.as_mut() {
                *depth += brace_delta(line);
                if *depth <= 0 {
                    skip_depth = None;
                }
                continue;
            }

            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") {
                pending_cfg_test = true;
                continue;
            }

            if pending_cfg_test {
                pending_cfg_test = false;
                if trimmed.ends_with(';') {
                    continue;
                }
                let depth = brace_delta(line);
                if depth > 0 {
                    skip_depth = Some(depth);
                    continue;
                }
                continue;
            }

            kept.push_str(line);
            kept.push('\n');
        }

        kept
    }

    fn brace_delta(line: &str) -> i32 {
        line.chars().fold(0, |delta, ch| match ch {
            '{' => delta + 1,
            '}' => delta - 1,
            _ => delta,
        })
    }

    fn doc_inventory_paths(path: &Path) -> BTreeSet<String> {
        let doc = fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("reading `{}`: {err}", path.display()));
        let manifest = doc
            .split_once(INVENTORY_START)
            .and_then(|(_, rest)| rest.split_once(INVENTORY_END).map(|(body, _)| body))
            .unwrap_or_else(|| panic!("{DOC_REL} is missing scrub inventory markers"));
        let mut paths = BTreeSet::new();
        for part in manifest.split('`').skip(1).step_by(2) {
            if part.ends_with(".rs") {
                paths.insert(part.to_string());
            }
        }
        paths
    }

    fn set(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| (*path).to_string()).collect()
    }
}

#[cfg(test)]
mod tests;
