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
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result};
use base64::Engine as _;

use crate::config::extended::RedactConfig;

mod dotenv;
mod protected;
pub(crate) mod protected_redaction_history;
// The production key resolver is wired into the daemon / registry / Session
// (required resolver, decision 16) and every item in the module is reachable
// from production or the FakeNativeStore-backed resolver tests, so no dead-code
// allow is needed.
pub(crate) mod secure_key_resolver;
mod ssh;
mod structured;

/// The protected redaction-history key resolver trait, re-exported so the
/// required `Session` resolver parameter (decision 16) is publicly nameable at
/// the daemon-less crate boundary (e.g. `apps/cli`).
pub use protected_redaction_history::RedactionKeyResolver;

/// Start a standalone production key resolver for a daemon-less entry point that
/// still must satisfy the required `Session` resolver (decision 16) — e.g. the
/// read-only `cockpit ask` docs pipeline, which never journals but constructs a
/// `Session`. Returns the owning [`crate::secure_key::SecureKeyActor`] (the
/// caller keeps it alive for the session's lifetime; dropping it drains the
/// actor) alongside the shared resolver.
pub fn start_standalone_redaction_key_resolver(
    db: &crate::db::Db,
) -> anyhow::Result<(
    crate::secure_key::SecureKeyActor,
    std::sync::Arc<dyn RedactionKeyResolver>,
)> {
    let probe = crate::secure_key::probe_platform_keyring();
    let actor = crate::secure_key::SecureKeyActor::start_production_resolved(
        db.clone(),
        std::sync::Arc::new(crate::secure_key::FailClosedReconciler),
        &probe,
        None,
        crate::secure_key::SecretStoreInjected::default(),
    )
    .map_err(|e| anyhow::anyhow!("starting standalone secure-key actor: {e}"))?;
    let resolver = std::sync::Arc::new(secure_key_resolver::SecureKeyResolver::new(actor.handle()));
    Ok((actor, resolver))
}

/// Same as [`start_standalone_redaction_key_resolver`] with an injected probe
/// and KEK directory. Tests must not open the real OS keyring.
pub fn start_standalone_redaction_key_resolver_with(
    db: &crate::db::Db,
    probe: &crate::secure_key::KeyringProbeResult,
    kek_dir: Option<std::path::PathBuf>,
    injected: crate::secure_key::SecretStoreInjected,
) -> anyhow::Result<(
    crate::secure_key::SecureKeyActor,
    std::sync::Arc<dyn RedactionKeyResolver>,
)> {
    let actor = crate::secure_key::SecureKeyActor::start_production_resolved(
        db.clone(),
        std::sync::Arc::new(crate::secure_key::FailClosedReconciler),
        probe,
        kek_dir,
        injected,
    )
    .map_err(|e| anyhow::anyhow!("starting standalone secure-key actor: {e}"))?;
    let resolver = std::sync::Arc::new(secure_key_resolver::SecureKeyResolver::new(actor.handle()));
    Ok((actor, resolver))
}

/// [`FakeNativeStore`](crate::secure_key::fake::FakeNativeStore)-backed standalone
/// resolver for daemon-less **tests** in dependent crates (e.g. `apps/cli`),
/// which cannot reach cockpit-core's `#[cfg(test)]` `MapKeyResolver` helper and
/// must never touch the OS keyring. Returns the owning actor alongside the
/// resolver; the caller keeps the actor alive for the session's lifetime.
pub fn start_fake_redaction_key_resolver(
    db: &crate::db::Db,
) -> anyhow::Result<(
    crate::secure_key::SecureKeyActor,
    std::sync::Arc<dyn RedactionKeyResolver>,
)> {
    let actor = crate::secure_key::SecureKeyActor::start_with_store(
        db.clone(),
        Box::new(crate::secure_key::fake::FakeNativeStore::new()),
        std::sync::Arc::new(crate::secure_key::FailClosedReconciler),
    )
    .map_err(|e| anyhow::anyhow!("starting fake secure-key actor: {e}"))?;
    let resolver = std::sync::Arc::new(secure_key_resolver::SecureKeyResolver::new(actor.handle()));
    Ok((actor, resolver))
}

/// The exact actionable marker rendered for a sealed value on untrusted
/// interactive inference egress with an active exact grant.
///
/// This is a protocol-level instruction, not configurable UI copy. It uses the
/// Unicode em dash and lowercase spelling exactly as specified by
/// `sealed-value-untrusted-inference-marker`.
pub const SEALED_UNTRUSTED_INFERENCE_MARKER_PREFIX: &str =
    "**redacted by cockpit — to use this value, reference sealed value `";
pub const SEALED_UNTRUSTED_INFERENCE_MARKER_SUFFIX: &str = "`**";

/// Render the exact actionable marker for one sealed value id.
///
/// The value id is constrained by the sealed-value contract before it becomes
/// marker text (lowercase letters, digits, `-`, `_`), so the marker cannot be
/// used to inject headings, links, instructions, or code-fence syntax.
pub fn sealed_untrusted_inference_marker(value_id: &str) -> String {
    format!(
        "{SEALED_UNTRUSTED_INFERENCE_MARKER_PREFIX}{value_id}{SEALED_UNTRUSTED_INFERENCE_MARKER_SUFFIX}"
    )
}

/// A typed replacement descriptor for one redaction-table entry.
///
/// `Generic` entries (environment, credential, deny-list, file secrets) render
/// the configured global [`RedactConfig::placeholder`]. `Sealed` entries render
/// the exact actionable [`sealed_untrusted_inference_marker`] so an untrusted
/// model that received a sealed literal in an interactive turn with an active
/// exact grant sees an instruction to use the sealed-value mechanism rather
/// than a content-free denial.
///
/// This is the one redaction architecture: there is no sealed-only regex or
/// second Aho-Corasick pass beside the existing table. Each entry carries its
/// own replacement descriptor, and [`RedactionTable::scrub_cow`] renders the
/// descriptor of the entry (or entries) covering each redacted range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replacement {
    /// The configured global placeholder. Used for every ordinary secret and
    /// for sealed entries whose exact grant is not active on the egress target.
    Generic,
    /// A sealed value with an active exact `(value, version, action)` grant on
    /// the egress target. Renders the actionable marker using the canonical
    /// value id.
    Sealed { value_id: String },
}

impl Replacement {
    /// Resolve this descriptor to its replacement text against a placeholder.
    fn render(&self, placeholder: &str) -> String {
        match self {
            Self::Generic => placeholder.to_string(),
            Self::Sealed { value_id } => sealed_untrusted_inference_marker(value_id),
        }
    }

    /// `true` when this is a sealed-value replacement.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed { .. })
    }
}

/// The typed provenance of an ordinary (non-sealed) redaction entry, attached
/// at the `build*` collector sites where each candidate's origin is known. This
/// is the classification the production journaling chokepoint reads — it never
/// re-parses the diagnostic-origin string. Sealed entries carry their own typed
/// identity ([`EntryClass::Sealed`]) and are summarized as
/// [`SourceClass::Sealed`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OrdinarySource {
    /// A value collected from the OS/session environment-variable scan.
    Environment,
    /// A value collected from a credential-bearing source: a dotenv/env-file, a
    /// private SSH key, a stored named/provider credential, the flycockpit
    /// instance token, or the configured deny-list (all forced secret
    /// inclusions or credential-shaped file values).
    #[default]
    Credential,
    /// A forced contained-leak literal registered via
    /// [`RedactionTable::with_forced_literal`] (the leak-containment adoption
    /// seam on the table side).
    ContainedLeak,
}

/// The typed source class exposed for one matched literal by
/// [`match_sensitive_literals`]. This is the closed classification the
/// journaling chokepoint records; there is no free-form "unknown secret"
/// variant, because journaling is table-match-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceClass {
    /// Environment-variable scan value.
    Environment,
    /// Credential-bearing value (dotenv/env-file, SSH key, stored credential,
    /// instance token, or deny-list).
    Credential,
    /// A sealed literal. `record_id`/`version` are read directly from the typed
    /// [`crate::sealed::identity::SealedRedactionIdentity`] — never parsed from a
    /// diagnostic-origin string. `record_id` is `None` for a legacy (pre-scoping)
    /// session entry keyed by name alone.
    Sealed {
        record_id: Option<crate::sealed::identity::SealedRecordId>,
        version: u32,
    },
    /// A forced contained-leak literal (the `with_forced_literal` path).
    ContainedLeak,
}

/// The classification carried by one redaction-table entry. Typed identity
/// lives on the entry itself — there is no parallel origins/replacements vector
/// to drift out of sync, and egress reads the classification directly instead
/// of parsing a diagnostic-origin string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntryClass {
    /// An ordinary secret (environment, credential, deny-list, file, or
    /// approved-secret-file value). `origin` is the diagnostic label
    /// (`$VAR`, `$denylist`, `$ssh:…`) shown by `cockpit debug redact` and is a
    /// display artifact only; `source` is the typed provenance the journaling
    /// chokepoint reads.
    Ordinary {
        origin: String,
        source: OrdinarySource,
    },
    /// A sealed value, carrying its canonical typed identity. The actionable
    /// sealed marker is an ephemeral per-target decision resolved by
    /// [`RedactionTable::with_sealed_replacements`] from this identity; it is
    /// never frozen into the persisted table.
    Sealed(crate::sealed::identity::SealedRedactionIdentity),
}

impl EntryClass {
    /// The diagnostic origin *string* for `cockpit debug redact` display. For a
    /// sealed entry this is derived from the typed identity — the string is a
    /// display artifact, never re-parsed to recover sealedness.
    fn origin_display(&self) -> String {
        match self {
            EntryClass::Ordinary { origin, .. } => origin.clone(),
            EntryClass::Sealed(identity) => sealed_identity_origin(identity),
        }
    }

    /// The typed source class for this entry, read directly from the typed
    /// classification (never from the origin string). A sealed entry summarizes
    /// its typed identity's `record_id`/`version` into
    /// [`SourceClass::Sealed`]; every ordinary entry maps its
    /// [`OrdinarySource`] one-to-one.
    fn source_class(&self) -> SourceClass {
        match self {
            EntryClass::Ordinary { source, .. } => match source {
                OrdinarySource::Environment => SourceClass::Environment,
                OrdinarySource::Credential => SourceClass::Credential,
                OrdinarySource::ContainedLeak => SourceClass::ContainedLeak,
            },
            EntryClass::Sealed(identity) => SourceClass::Sealed {
                record_id: identity.record_id,
                version: identity.version,
            },
        }
    }
}

/// Derive the canonical redaction-origin string for one sealed identity, for
/// diagnostic display only. A legacy session entry (no record id) renders the
/// pre-scoping `sealed:<name>` form; a scoped entry renders the full grammar.
fn sealed_identity_origin(identity: &crate::sealed::identity::SealedRedactionIdentity) -> String {
    identity.display_origin()
}

/// The canonical value id rendered into the sealed marker (`use_sealed_value`
/// references it): the record id for a scoped entry, or the legacy name for a
/// session entry registered before scoping existed. This is the WIRE text, not
/// the active-set lookup key — the lookup key is version-scoped (see
/// [`sealed_active_key`]).
fn sealed_value_id(identity: &crate::sealed::identity::SealedRedactionIdentity) -> String {
    identity
        .record_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| identity.name.as_str().to_string())
}

/// The VERSION-SCOPED key used to test a sealed entry against the active-grant
/// set (built the same way on the grant side by
/// [`crate::sealed::active_sealed_value_ids`]). A scoped entry keys on
/// `(record_id, version)`; a legacy entry keys on `(name, version)`. Including
/// the version means a grant for one version can never activate a persisted
/// entry sealed at a different version, and — because legacy entries are
/// version 0 while a real grant is version `>= 1` — a scoped grant can never
/// activate a legacy same-name entry of a different record.
fn sealed_active_key(identity: &crate::sealed::identity::SealedRedactionIdentity) -> String {
    match identity.record_id {
        Some(record_id) => crate::sealed::identity::sealed_scoped_active_key(
            &record_id.to_string(),
            identity.version,
        ),
        None => crate::sealed::identity::sealed_legacy_active_key(
            identity.name.as_str(),
            identity.version,
        ),
    }
}

/// One typed redaction-table entry: the literal to match, its typed
/// classification, and the replacement descriptor resolved for the current
/// egress target (always [`Replacement::Generic`] except on a table derived by
/// [`RedactionTable::with_sealed_replacements`]).
#[derive(Clone)]
pub(crate) struct RedactionEntry {
    value: String,
    class: EntryClass,
    replacement: Replacement,
}

impl std::fmt::Debug for RedactionEntry {
    /// `value` is the raw secret literal this entry exists to scrub; never print
    /// it. Show its length plus the (non-secret) typed class and replacement so
    /// diagnostics stay useful.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionEntry")
            .field("value", &format_args!("[REDACTED; {}]", self.value.len()))
            .field("class", &self.class)
            .field("replacement", &self.replacement)
            .finish()
    }
}

impl RedactionEntry {
    fn ordinary(value: String, origin: String, source: OrdinarySource) -> Self {
        Self {
            value,
            class: EntryClass::Ordinary { origin, source },
            replacement: Replacement::Generic,
        }
    }

    fn sealed(value: String, identity: crate::sealed::identity::SealedRedactionIdentity) -> Self {
        Self {
            value,
            class: EntryClass::Sealed(identity),
            replacement: Replacement::Generic,
        }
    }
}

#[cfg(test)]
use self::dotenv::*;
use self::dotenv::{collect_env_file_candidates, consume_marked_value, matched_dotenv_paths};
use self::protected::{ProtectedPaths, is_existing_absolute_path};
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
/// matcher without bound. The four variants are base64, lowercase hex,
/// uppercase hex, and percent/URL encoding (see [`encoded_secret_variants`]).
const MAX_FORCED_SECRET_VARIANTS: usize = 4;

/// Hard lower bound for every redaction pattern. Values below this length can
/// corrupt unrelated output (for example, a timeout rendered as `120s`) and are
/// therefore never safe to register, regardless of their source.
const MIN_REDACTION_ENTRY_LENGTH: usize = 4;

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
const FIXED_SHELL_INJECTION_NAMES: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "NODE_OPTIONS",
    "SHELLOPTS",
    "BASHOPTS",
    "GREP_OPTIONS",
    "GREP_COLORS",
];

pub(crate) fn env_scrub_patterns(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    // Retired sealed child-environment bindings never reach any child.
    if upper.starts_with("SEALED_") {
        return true;
    }
    FIXED_SHELL_INJECTION_NAMES
        .iter()
        .any(|fixed| upper == *fixed)
        || is_secret_shaped_key(name)
}

/// Broad inclusion predicate for key names whose values are likely secrets.
/// This is intentionally wider than [`credential_shaped_key`]: structured
/// config registration uses this to decide whether a value enters the table at
/// all, while `credential_shaped_key` only grants the min-length exemption to a
/// smaller, high-confidence subset.
pub(crate) fn is_secret_shaped_key(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if upper.ends_with("_KEY")
        || upper.ends_with("_SECRET")
        || upper.ends_with("_TOKEN")
        || upper.ends_with("_PASSWORD")
        || upper.ends_with("_PASSWD")
        || upper.ends_with("_PIN")
        || upper.ends_with("_PAT")
        || upper.ends_with("_CREDENTIALS")
        || upper.ends_with("_PASSPHRASE")
    {
        return true;
    }

    let segments = key_name_segments(name);
    if segments.iter().any(|segment| {
        matches!(
            segment.as_str(),
            "password"
                | "passwords"
                | "passwd"
                | "token"
                | "tokens"
                | "secret"
                | "secrets"
                | "credential"
                | "credentials"
                | "passphrase"
                | "passphrases"
        )
    }) {
        return true;
    }
    if segments.iter().any(|segment| segment == "apikey") {
        return true;
    }

    segments.windows(2).any(|window| {
        matches!(
            (window[0].as_str(), window[1].as_str()),
            ("api", "key") | ("private", "key") | ("access", "key")
        )
    })
}

fn key_name_segments(name: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = name.chars().collect();

    for (idx, ch) in chars.iter().copied().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }

        let prev = idx.checked_sub(1).and_then(|prev| chars.get(prev)).copied();
        let next = chars.get(idx + 1).copied();
        let split_camel = ch.is_ascii_uppercase()
            && !current.is_empty()
            && (prev.is_some_and(|prev| prev.is_ascii_lowercase() || prev.is_ascii_digit())
                || next.is_some_and(|next| next.is_ascii_lowercase()));
        if split_camel {
            segments.push(std::mem::take(&mut current));
        }
        current.push(ch.to_ascii_lowercase());
    }

    if !current.is_empty() {
        segments.push(current);
    }
    segments
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

struct Candidate {
    value: String,
    origin: String,
    prunable: bool,
    length_exempt: bool,
    register_variants: bool,
    register_case_variants: bool,
    /// Typed provenance carried to the built entry. Defaults to
    /// [`OrdinarySource::Credential`] because every non-environment collector
    /// (dotenv/env-file, structured env files, SSH keys, stored credentials,
    /// the instance token, and the deny-list) is credential-bearing. The
    /// environment-variable scan overrides this to
    /// [`OrdinarySource::Environment`] at its collector site in
    /// [`RedactionTable::build_with_env_and_secrets`].
    source: OrdinarySource,
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
            source: OrdinarySource::Credential,
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
            source: OrdinarySource::Credential,
        }
    }
}

impl std::fmt::Debug for Candidate {
    /// `value` is the raw secret literal collected for the redaction table;
    /// never print it. Show its length plus the (non-secret) structural fields
    /// so diagnostics stay useful.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate")
            .field("value", &format_args!("[REDACTED; {}]", self.value.len()))
            .field("origin", &self.origin)
            .field("prunable", &self.prunable)
            .field("length_exempt", &self.length_exempt)
            .field("register_variants", &self.register_variants)
            .field("register_case_variants", &self.register_case_variants)
            .field("source", &self.source)
            .finish()
    }
}

fn origin_is_forced(origin: &str) -> bool {
    origin == "$denylist"
        || origin == "$credentials:flycockpit.instance_token"
        || origin.starts_with("$secret:")
        || origin.starts_with("$ssh:")
}

fn origin_is_disk_derived(origin: &str) -> bool {
    origin.starts_with("$ssh:")
        || origin.starts_with("$dotenv:")
        || (origin.starts_with('$') && origin.contains(" (") && origin.ends_with(')'))
}

fn case_secret_variants(value: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(3);
    let lower = value.to_ascii_lowercase();
    if lower != value {
        variants.push(lower.clone());
    }
    let upper = value.to_ascii_uppercase();
    if upper != value {
        variants.push(upper);
    }
    // Capitalized ("Title"-case first letter) echo: the audit (SEC-F3) calls out
    // "all-uppercase or capitalized" echoes, and the fully-upper variant above
    // does not cover a first-letter-only capitalization of an otherwise-lowercase
    // value (e.g. `abc123def` echoed as `Abc123def`). Build it from the lowercase
    // form so it is well-defined regardless of the source value's own casing.
    if let Some(capitalized) = capitalize_first_ascii(&lower)
        && capitalized != value
    {
        variants.push(capitalized);
    }
    variants.sort();
    variants.dedup();
    variants
}

/// Uppercase the first ASCII-alphabetic character of `s` (already lowercased by
/// the caller), leaving the rest untouched. Returns `None` when `s` has no ASCII
/// letter to capitalize, so a purely numeric/symbolic value adds no variant.
fn capitalize_first_ascii(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut capitalized = false;
    for ch in s.chars() {
        if !capitalized && ch.is_ascii_alphabetic() {
            out.push(ch.to_ascii_uppercase());
            capitalized = true;
        } else {
            out.push(ch);
        }
    }
    capitalized.then_some(out)
}

fn encoded_secret_variants(value: &str) -> Vec<String> {
    if value.len() < MIN_REDACTION_ENTRY_LENGTH {
        return Vec::new();
    }

    let mut variants = Vec::with_capacity(MAX_FORCED_SECRET_VARIANTS);
    let bytes = value.as_bytes();
    variants.push(base64::engine::general_purpose::STANDARD.encode(bytes));
    // Register BOTH hex cases. `hex_encode` alone left an uppercase-hex echo of
    // a secret unscrubbed (SEC-F3, gap 2), because the substitution matcher is
    // case-sensitive (`ascii_case_insensitive(false)`). For an all-numeric-nibble
    // value the two encodings coincide and the later value-dedup collapses them.
    variants.push(hex_encode(bytes));
    variants.push(hex_encode_upper(bytes));
    variants.push(url_encode(bytes));
    variants.retain(|variant| !variant.is_empty() && variant != value);
    variants.truncate(MAX_FORCED_SECRET_VARIANTS);
    variants
}

fn hex_encode(bytes: &[u8]) -> String {
    hex_encode_with(bytes, b"0123456789abcdef")
}

fn hex_encode_upper(bytes: &[u8]) -> String {
    hex_encode_with(bytes, b"0123456789ABCDEF")
}

fn hex_encode_with(bytes: &[u8], alphabet: &[u8; 16]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(alphabet[(byte >> 4) as usize] as char);
        out.push(alphabet[(byte & 0x0f) as usize] as char);
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
    /// Typed entries: the literal plus its explicit classification. Pre-release
    /// the representation changes in place (no migration / no back-compat
    /// shim); an entry's sealedness serializes as data, never as a `sealed:`
    /// origin string that egress would have to re-parse.
    entries: Vec<PersistedEntry>,
    /// Origin-only coverage markers for values collected from files on disk.
    /// These deliberately carry no values, so session resume can detect lost
    /// coverage without turning the database into a copy of file secrets.
    #[serde(default)]
    disk_derived_origins: Vec<String>,
    placeholder: String,
    disabled: bool,
    unsupported_files: Vec<String>,
    #[serde(default)]
    protected: Vec<String>,
}

/// One serialized redaction entry: the literal plus its explicit typed
/// classification.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedEntry {
    value: String,
    #[serde(flatten)]
    class: PersistedEntryClass,
}

impl std::fmt::Debug for PersistedEntry {
    /// `value` is the raw secret literal serialized into the persisted table;
    /// never print it. Show its length plus the (non-secret) typed class.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistedEntry")
            .field("value", &format_args!("[REDACTED; {}]", self.value.len()))
            .field("class", &self.class)
            .finish()
    }
}

/// The persisted classification. `Ordinary` carries its diagnostic origin;
/// `Sealed` carries the canonical typed identity fields so egress reads
/// sealedness directly.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
enum PersistedEntryClass {
    Ordinary {
        origin: String,
        /// Typed provenance carried across persistence so the journaling
        /// chokepoint never has to re-derive it from the origin string. Defaults
        /// to `Credential` for robustness against any entry serialized before the
        /// field existed (pre-release: databases are recreated, so this default
        /// only guards in-run round-trips).
        #[serde(default)]
        source: OrdinarySource,
    },
    Sealed {
        scope: String,
        #[serde(default)]
        record_id: Option<String>,
        name: String,
        version: u32,
    },
}

impl PersistedEntry {
    fn from_entry(entry: &RedactionEntry) -> Self {
        let class = match &entry.class {
            EntryClass::Ordinary { origin, source } => PersistedEntryClass::Ordinary {
                origin: origin.clone(),
                source: *source,
            },
            EntryClass::Sealed(identity) => PersistedEntryClass::Sealed {
                scope: identity.scope.as_str().to_string(),
                record_id: identity.record_id.map(|id| id.to_string()),
                name: identity.name.as_str().to_string(),
                version: identity.version,
            },
        };
        Self {
            value: entry.value.clone(),
            class,
        }
    }

    fn into_entry(self) -> Result<RedactionEntry> {
        let class = match self.class {
            PersistedEntryClass::Ordinary { origin, source } => {
                EntryClass::Ordinary { origin, source }
            }
            PersistedEntryClass::Sealed {
                scope,
                record_id,
                name,
                version,
            } => {
                use crate::sealed::identity::{
                    SealedName, SealedRecordId, SealedRedactionIdentity, SealedScopeKind,
                };
                let identity = SealedRedactionIdentity {
                    scope: SealedScopeKind::parse(&scope)
                        .map_err(|e| anyhow::anyhow!("persisted sealed scope: {e}"))?,
                    record_id: record_id
                        .map(|id| SealedRecordId::parse(&id))
                        .transpose()
                        .map_err(|e| anyhow::anyhow!("persisted sealed record id: {e}"))?,
                    name: SealedName::canonical(&name)
                        .map_err(|e| anyhow::anyhow!("persisted sealed name: {e}"))?,
                    version,
                };
                EntryClass::Sealed(identity)
            }
        };
        Ok(RedactionEntry {
            value: self.value,
            class,
            replacement: Replacement::Generic,
        })
    }

    fn origin_display(&self) -> String {
        match &self.class {
            PersistedEntryClass::Ordinary { origin, .. } => origin.clone(),
            // A sealed entry is never disk-derived, so its exact origin string
            // only needs to be non-disk-derived; derive the legacy/scoped form.
            PersistedEntryClass::Sealed {
                record_id, name, ..
            } => match record_id {
                Some(_) => String::new(),
                None => format!("{}{}", crate::sealed::identity::SEALED_ORIGIN_PREFIX, name),
            },
        }
    }
}

/// A built lookup of `value → origin-name` pairs the next outbound
/// request must be scrubbed against. Hold one per session (cheap to
/// rebuild; small in-memory footprint).
pub struct RedactionTable {
    /// Aho-Corasick search structure; `None` when there's nothing to
    /// scrub or redaction is disabled. Keeping it `Option` lets
    /// [`scrub`] short-circuit without allocating.
    ///
    /// Built with [`MatchKind::LeftmostLongest`]: this drives the fast
    /// `is_match` gate and the journaling primitive
    /// [`match_sensitive_literals`] (via `find_iter`), both of which want the
    /// leftmost-longest non-overlapping emit. It is NOT used for substitution —
    /// see `overlap_matcher`.
    matcher: Option<AhoCorasick>,
    /// A second Aho-Corasick over the SAME pattern list, built with
    /// [`MatchKind::Standard`] so [`scrub_cow`] can call `find_overlapping_iter`
    /// and enumerate EVERY occurrence of EVERY registered literal — OVERLAPPING
    /// and SELF-overlapping included. LeftmostLongest cannot do this (its
    /// `replace_all`/`find_iter` emit only non-overlapping matches and resume
    /// past each), which would leak the non-overlapping tail of an overlapping
    /// secret. `AhoCorasick` is `Clone` over an internal `Arc<dyn Automaton>`,
    /// so storing this second matcher costs its automaton memory once; the
    /// `clone()`s in `union`/`enforced`/`with_sealed_replacements` only bump the
    /// Arc. Rebuilt from `entries` like `matcher`; never serialized. `Some`
    /// exactly when `matcher` is `Some` (both built from the same non-empty
    /// pattern list at the same site).
    overlap_matcher: Option<AhoCorasick>,
    /// The single typed entry vector used to build `matcher`, aligned 1:1 with
    /// the matcher's pattern list by construction. There is no parallel
    /// origins/replacements vector to drift: each entry carries its own typed
    /// classification and per-target replacement descriptor.
    entries: Vec<RedactionEntry>,
    /// What every ordinary (`Generic`) match is replaced with. Distinctive on
    /// purpose so leaks into provider logs are easy to grep for. Sealed
    /// entries render [`sealed_untrusted_inference_marker`] instead.
    placeholder: String,
    /// `true` when the user disabled redaction at config level. The
    /// scrub call still returns the input unchanged; we keep the flag
    /// so `cockpit debug redact` can say so.
    disabled: bool,
    /// Env files matched but in an unsupported/unparseable format, so
    /// their candidates couldn't be collected (§4). Surfaced once as a
    /// TUI toast so the user knows redaction won't cover those files.
    unsupported_files: Vec<PathBuf>,
    /// Protected filesystem paths carried across unions and persistence.
    protected: ProtectedPaths,
    /// Forced-secret origins that intentionally override protected paths.
    protected_path_conflicts: Vec<String>,
    /// Test-only fault injection: when set, [`Self::enforced_checked`] returns
    /// an error, so a caller's fail-closed-before-side-effect path (e.g. the
    /// external-harness runner constructing its scrub view before spawning a
    /// subprocess) can be exercised without any environment mutation. This
    /// field only exists in unit-test builds and is compiled out of every
    /// shipped build.
    #[cfg(test)]
    fail_enforced_view: bool,
}

impl std::fmt::Debug for RedactionTable {
    /// Never print pattern values — they are the secrets this table
    /// exists to hide. Show only counts + flags.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionTable")
            .field("patterns", &self.entries.len())
            .field("disabled", &self.disabled)
            .field("unsupported_files", &self.unsupported_files.len())
            .field(
                "protected_path_conflicts",
                &self.protected_path_conflicts.len(),
            )
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
        #[cfg(test)]
        {
            Self::build_with_env(cfg, cwd, &env)
        }
        #[cfg(not(test))]
        {
            Self::build_with_env_and_store(cfg, cwd, &env)
        }
    }

    /// Build a table from the provided session env + the env files matched
    /// under `cwd`. Daemon sessions use this so redaction tracks the immutable
    /// session snapshot instead of the daemon process environment.
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
        Self::build_with_env_and_secrets(cfg, cwd, env, std::iter::empty())
    }

    pub fn build_with_env_and_credential_store(
        cfg: &RedactConfig,
        cwd: &Path,
        env: &HashMap<String, String>,
        store: &crate::credentials::CredentialStore,
    ) -> Result<Self> {
        let mut entries = store
            .named_secret_entries()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        entries.extend(store.provider_credential_entries());
        Self::build_with_env_and_secrets(cfg, cwd, env, entries)
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
        let protected = ProtectedPaths::from_session(cwd, env);
        // `cfg.enabled == false` is a *scrub-time* opt-out, never a reason to
        // skip collection. The table is always built for real so that an
        // untrusted route can enforce it (see [`Self::enforced`]); the
        // `disabled` flag then suppresses substitution on every route that is
        // allowed to honor the opt-out (trusted models, local sinks).
        // Building an empty table here instead would leave the untrusted
        // egress path with nothing to scrub against.

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
                let mut candidate =
                    Candidate::prunable(value.clone(), format!("${name}"), length_exempt);
                // Environment-variable scan is the one collector whose source is
                // not credential-bearing; override the Candidate default here at
                // the collector site (decision 11).
                candidate.source = OrdinarySource::Environment;
                // SEC-F3 gap 1: register case-transformed variants for the whole
                // secret-shaped key family (`*_KEY`/`*_TOKEN`/`*_PAT`/`*_APIKEY`/
                // `*_ACCESS_KEY`/… via `is_secret_shaped_key`), not just the four
                // length-exempt shapes `credential_shaped_key` covers. The matcher
                // is case-sensitive, so without this an all-uppercase or
                // capitalized echo of a `*_KEY`/`*_TOKEN` secret went unscrubbed.
                //
                // This is DECOUPLED from `length_exempt` on purpose: the length
                // exemption stays narrow (`credential_shaped_key`), so broadened
                // families remain subject to the `min_secret_length` prune below.
                // That prune (plus the hard `MIN_REDACTION_ENTRY_LENGTH` floor) is
                // the anti-false-positive floor that keeps a short/low-entropy
                // value — e.g. a 4-char PIN echoing a dictionary word — out of the
                // table, so broadening case variants cannot over-redact common
                // words. `is_secret_shaped_key` is a superset of
                // `credential_shaped_key`, so this only ever ADDS coverage.
                candidate.register_case_variants = is_secret_shaped_key(name);
                candidates.push(candidate);
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

        #[cfg(feature = "remote")]
        if let Some(token) = crate::auth::flycockpit::stored_instance_token_for_redaction() {
            candidates.push(Candidate::forced(
                token,
                "$credentials:flycockpit.instance_token".to_string(),
                true,
            ));
        }

        for (name, value) in stored_secrets {
            let origin = if name.starts_with('$') {
                name.clone()
            } else {
                format!("$secret:{name}")
            };
            candidates.push(Candidate::forced(value.clone(), origin.clone(), true));
            // MCP OAuth records are intentionally stored as one JSON named
            // secret, but the record container is not itself a useful
            // redaction literal. Register every sensitive leaf as well so a
            // refreshed access/refresh token is scrubbed independently of
            // JSON formatting and immediately after owner publication.
            if name.starts_with("mcp:") {
                for (field, secret) in mcp_sensitive_json_values(&value) {
                    candidates.push(Candidate::forced(secret, format!("{origin}.{field}"), true));
                }
            }
        }

        // (3) Prune: drop candidates that aren't plausibly secrets. The
        // denylist (added below) bypasses this — it's forced inclusion. Each
        // built entry carries its collector's typed source (decision 11).
        let mut entries: Vec<(String, String, OrdinarySource)> = Vec::new();
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
                    entries.push((variant, candidate.origin.clone(), candidate.source));
                }
            }
            if candidate.register_case_variants {
                for variant in case_secret_variants(&candidate.value) {
                    entries.push((variant, candidate.origin.clone(), candidate.source));
                }
            }
            entries.push((candidate.value, candidate.origin, candidate.source));
        }

        // Denylist: forced inclusion even for short / pruned / allowlisted
        // values. A deny-list literal is a configured secret with no other
        // provenance, so it classifies as `Credential`.
        for v in &cfg.denylist {
            if v.is_empty() {
                continue;
            }
            let candidate = Candidate::forced(v.clone(), "$denylist".to_string(), true);
            for variant in encoded_secret_variants(&candidate.value) {
                entries.push((variant, candidate.origin.clone(), candidate.source));
            }
            entries.push((candidate.value, candidate.origin, candidate.source));
        }

        Self::from_entries(
            entries,
            cfg.placeholder.clone(),
            !cfg.enabled,
            unsupported_files,
            protected,
        )
    }

    /// Build a table from `(value, origin, source)` triples. Every triple
    /// becomes an [`EntryClass::Ordinary`] entry carrying its typed source;
    /// sealed entries enter through [`Self::with_forced_sealed_literal`], never
    /// here.
    fn from_entries(
        entries: Vec<(String, String, OrdinarySource)>,
        placeholder: String,
        disabled: bool,
        unsupported_files: Vec<PathBuf>,
        protected: ProtectedPaths,
    ) -> Result<Self> {
        let typed = entries
            .into_iter()
            .map(|(value, origin, source)| RedactionEntry::ordinary(value, origin, source))
            .collect();
        Self::from_redaction_entries(typed, placeholder, disabled, unsupported_files, protected)
    }

    /// The single construction funnel for a [`RedactionTable`]. Every builder
    /// (`from_entries`, `union`, `with_forced_literal`,
    /// `with_forced_sealed_literal`, `from_persisted_json`) routes here, so the
    /// entry vector and the matcher's pattern list are 1:1 by construction and
    /// the length invariant cannot be violated by a caller.
    fn from_redaction_entries(
        mut entries: Vec<RedactionEntry>,
        placeholder: String,
        disabled: bool,
        unsupported_files: Vec<PathBuf>,
        protected: ProtectedPaths,
    ) -> Result<Self> {
        entries.retain(|entry| {
            if entry.value.len() < MIN_REDACTION_ENTRY_LENGTH {
                tracing::warn!(
                    origin = %entry.class.origin_display(),
                    min_length = MIN_REDACTION_ENTRY_LENGTH,
                    "dropping redaction entry below the hard minimum length"
                );
                false
            } else {
                true
            }
        });

        let protected_conflicting_origins: HashSet<String> = entries
            .iter()
            .filter(|entry| {
                let origin = entry.class.origin_display();
                !origin_is_forced(&origin)
                    && (protected.contains_value(&entry.value)
                        || is_existing_absolute_path(&entry.value))
            })
            .map(|entry| entry.class.origin_display())
            .collect();
        let mut protected_path_conflicts: Vec<String> = Vec::new();
        entries.retain(|entry| {
            let origin = entry.class.origin_display();
            let conflicts =
                protected.contains_value(&entry.value) || is_existing_absolute_path(&entry.value);
            if origin_is_forced(&origin) {
                if conflicts {
                    protected_path_conflicts.push(origin.clone());
                    tracing::warn!(
                        origin = %origin,
                        "forced redaction entry conflicts with a protected filesystem path"
                    );
                }
                true
            } else {
                !conflicts && !protected_conflicting_origins.contains(&origin)
            }
        });
        protected_path_conflicts.sort();
        protected_path_conflicts.dedup();
        entries.sort_by(|a, b| {
            b.value
                .len()
                .cmp(&a.value.len())
                .then_with(|| a.value.cmp(&b.value))
        });
        entries.dedup_by(|a, b| a.value == b.value);
        // The persisted/base table never carries a `Sealed` replacement: the
        // actionable marker is an ephemeral per-target decision resolved by
        // [`Self::with_sealed_replacements`] at egress time. Freezing it here
        // would bake active authorization into a redaction entry.
        for entry in entries.iter_mut() {
            entry.replacement = Replacement::Generic;
        }
        if entries.is_empty() {
            return Ok(Self {
                matcher: None,
                overlap_matcher: None,
                entries,
                placeholder,
                disabled,
                unsupported_files,
                protected,
                protected_path_conflicts,
                #[cfg(test)]
                fail_enforced_view: false,
            });
        }
        let patterns: Vec<&str> = entries.iter().map(|entry| entry.value.as_str()).collect();
        // Single-vector invariant: the matcher's pattern list is derived from
        // the one entry vector, so their lengths are equal by construction.
        assert_eq!(
            patterns.len(),
            entries.len(),
            "redaction matcher patterns must be 1:1 with typed entries"
        );
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(false)
            .build(&patterns)
            .map_err(|e| anyhow::anyhow!("building aho-corasick: {e}"))?;
        // The substitution matcher over the SAME patterns. `Standard` is the
        // only match kind that supports `find_overlapping_iter`, which
        // `scrub_cow` needs to cover overlapping/self-overlapping literals; its
        // `PatternID`s index `entries` identically to `matcher` (same list,
        // same order). Kept separate from `matcher` so `is_match` and the
        // journaling `find_iter` keep their leftmost-longest semantics.
        let overlap_matcher = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(false)
            .build(&patterns)
            .map_err(|e| anyhow::anyhow!("building aho-corasick (overlap): {e}"))?;
        Ok(Self {
            matcher: Some(matcher),
            overlap_matcher: Some(overlap_matcher),
            entries,
            placeholder,
            disabled,
            unsupported_files,
            protected,
            protected_path_conflicts,
            #[cfg(test)]
            fail_enforced_view: false,
        })
    }

    pub fn union(&self, other: &Self) -> Result<Self> {
        let mut entries = self.entries.clone();
        entries.extend(other.entries.iter().cloned());
        let mut unsupported_files = self.unsupported_files.clone();
        unsupported_files.extend(other.unsupported_files.iter().cloned());
        unsupported_files.sort();
        unsupported_files.dedup();
        let protected = self.protected.union(&other.protected);
        Self::from_redaction_entries(
            entries,
            self.placeholder.clone(),
            self.disabled && other.disabled,
            unsupported_files,
            protected,
        )
    }

    /// Add one caller-supplied ordinary literal to this table.  Sealed-value
    /// storage uses [`Self::with_forced_sealed_literal`] instead so the entry
    /// carries typed identity; this remains for ordinary forced literals.
    pub fn with_forced_literal(&self, value: String, origin: String) -> Result<Self> {
        let mut entries = self.entries.clone();
        // The `with_forced_literal` seam is the leak-containment adoption path
        // (decision 11): its literals classify as `ContainedLeak`.
        entries.push(RedactionEntry::ordinary(
            value,
            origin,
            OrdinarySource::ContainedLeak,
        ));
        Self::from_redaction_entries(
            entries,
            self.placeholder.clone(),
            self.disabled,
            self.unsupported_files.clone(),
            self.protected.clone(),
        )
    }

    /// Add one caller-supplied **sealed** literal, carrying its canonical typed
    /// identity. This is the typed registration API the three live sealed
    /// routes use; the entry's sealedness is stored as classification, never
    /// inferred by parsing a diagnostic-origin string at egress.
    pub fn with_forced_sealed_literal(
        &self,
        value: String,
        identity: crate::sealed::identity::SealedRedactionIdentity,
    ) -> Result<Self> {
        let mut entries = self.entries.clone();
        entries.push(RedactionEntry::sealed(value, identity));
        Self::from_redaction_entries(
            entries,
            self.placeholder.clone(),
            self.disabled,
            self.unsupported_files.clone(),
            self.protected.clone(),
        )
    }

    /// Produce an egress-time derived table where sealed entries whose typed
    /// identity matches an active exact grant render the actionable marker
    /// instead of the generic placeholder.
    ///
    /// `active_sealed_ids` is the set of VERSION-SCOPED keys (see
    /// [`sealed_active_key`]) that have an active exact
    /// `(value, version, action, revision)` grant on the egress target.
    /// Sealedness is read from each entry's [`EntryClass::Sealed`] typed
    /// identity — no diagnostic-origin string is parsed here. Every
    /// sealed entry whose version-scoped key is in the set gets
    /// [`Replacement::Sealed`];
    /// all other entries (ordinary secrets and sealed entries without an active
    /// grant) keep [`Replacement::Generic`].
    ///
    /// This is the single place where active authorization meets the redaction
    /// table. The persisted table never carries `Sealed` replacements, so
    /// authorization is never frozen into a redaction entry. A revoked,
    /// expired, or ungranted sealed value simply does not appear in
    /// `active_sealed_ids` and falls back to the generic placeholder — it
    /// never resurrects a literal and never advertises a stale handle.
    ///
    /// The returned table shares the same matcher and entries; only each
    /// entry's replacement descriptor is rebuilt. This is cheap and deterministic.
    pub fn with_sealed_replacements(
        &self,
        active_sealed_ids: &std::collections::HashSet<String>,
    ) -> Self {
        let entries: Vec<RedactionEntry> = self
            .entries
            .iter()
            .map(|entry| {
                let replacement = match &entry.class {
                    EntryClass::Sealed(identity) => {
                        // Look the entry up by its VERSION-SCOPED key: a scoped
                        // entry matches iff `(record_id, version)` is active; a
                        // legacy entry matches iff `(name, version)` is active.
                        // The version binding stops a grant for one version from
                        // activating a persisted entry sealed at another version,
                        // and a scoped grant from activating a legacy same-name
                        // entry of a different record.
                        let key = sealed_active_key(identity);
                        if active_sealed_ids.contains(&key) {
                            // The rendered marker still references the canonical
                            // value id (bare record id / legacy name) — the key
                            // is only for matching, not for the wire text.
                            Replacement::Sealed {
                                value_id: sealed_value_id(identity),
                            }
                        } else {
                            Replacement::Generic
                        }
                    }
                    EntryClass::Ordinary { .. } => Replacement::Generic,
                };
                RedactionEntry {
                    value: entry.value.clone(),
                    class: entry.class.clone(),
                    replacement,
                }
            })
            .collect();
        Self {
            matcher: self.matcher.clone(),
            // Arc bump only — see the field doc; the automaton is not re-copied.
            overlap_matcher: self.overlap_matcher.clone(),
            entries,
            placeholder: self.placeholder.clone(),
            disabled: self.disabled,
            unsupported_files: self.unsupported_files.clone(),
            protected: self.protected.clone(),
            protected_path_conflicts: self.protected_path_conflicts.clone(),
            #[cfg(test)]
            fail_enforced_view: self.fail_enforced_view,
        }
    }

    /// Register parsed values from one already-approved secret-bearing file.
    /// This does not decide whether a path is secret and never reads any other
    /// path; callers pair it with `SecretPathMatcher` after their read gate.
    pub fn with_approved_secret_file(&self, cfg: &RedactConfig, path: &Path) -> Result<Self> {
        let EnvFileScan::Candidates(candidates) = collect_env_file_candidates(path, &cfg.allowlist)
        else {
            return self.union(&Self::from_entries(
                Vec::new(),
                self.placeholder.clone(),
                self.disabled,
                Vec::new(),
                self.protected.clone(),
            )?);
        };
        let mut entries: Vec<(String, String, OrdinarySource)> = Vec::new();
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
                    entries.push((variant, candidate.origin.clone(), candidate.source));
                }
            }
            if candidate.register_case_variants {
                for variant in case_secret_variants(&candidate.value) {
                    entries.push((variant, candidate.origin.clone(), candidate.source));
                }
            }
            entries.push((candidate.value, candidate.origin, candidate.source));
        }
        let addition = Self::from_entries(
            entries,
            self.placeholder.clone(),
            self.disabled,
            Vec::new(),
            self.protected.clone(),
        )?;
        self.union(&addition)
    }

    /// Serialize this accumulated table for session-local persistence. Disk-derived
    /// values are excluded; their origin-only markers retain resume coverage checks.
    pub fn to_persisted_json(&self) -> Result<String> {
        let mut disk_derived_origins: Vec<String> = self
            .entries
            .iter()
            .map(|entry| entry.class.origin_display())
            .filter(|origin| origin_is_disk_derived(origin))
            .collect();
        disk_derived_origins.sort();
        disk_derived_origins.dedup();
        let snapshot = PersistedRedactionTable {
            entries: self
                .entries
                .iter()
                .filter(|entry| !origin_is_disk_derived(&entry.class.origin_display()))
                .map(PersistedEntry::from_entry)
                .collect(),
            disk_derived_origins,
            placeholder: self.placeholder.clone(),
            disabled: self.disabled,
            unsupported_files: self
                .unsupported_files
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            protected: self.protected.to_persisted(),
        };
        serde_json::to_string(&snapshot).context("serializing redaction table")
    }

    /// Rebuild an accumulated table persisted by [`Self::to_persisted_json`].
    pub fn from_persisted_json(json: &str) -> Result<Self> {
        let snapshot: PersistedRedactionTable =
            serde_json::from_str(json).context("deserializing redaction table")?;
        let mut entries: Vec<RedactionEntry> = Vec::with_capacity(snapshot.entries.len());
        for persisted in snapshot.entries {
            if origin_is_disk_derived(&persisted.origin_display()) {
                continue;
            }
            entries.push(persisted.into_entry()?);
        }
        Self::from_redaction_entries(
            entries,
            snapshot.placeholder,
            snapshot.disabled,
            snapshot
                .unsupported_files
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            ProtectedPaths::from_persisted(snapshot.protected),
        )
    }

    /// Return disk-origin markers without exposing any value. For snapshots
    /// written before origin-only markers existed, recover them from the
    /// legacy disk-derived entries so they are purged on the next persist.
    pub fn persisted_disk_derived_origins(json: &str) -> Result<Vec<String>> {
        let snapshot: PersistedRedactionTable =
            serde_json::from_str(json).context("deserializing redaction table")?;
        let mut origins: Vec<String> = snapshot.disk_derived_origins;
        origins.extend(
            snapshot
                .entries
                .into_iter()
                .map(|entry| entry.origin_display())
                .filter(|origin| origin_is_disk_derived(origin)),
        );
        origins.sort();
        origins.dedup();
        Ok(origins)
    }

    pub fn has_origin(&self, origin: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.class.origin_display() == origin)
    }

    /// Scrub every secret in `body`. Returns the cleaned string. The
    /// no-table-or-disabled path returns a borrowed input, and a configured
    /// table with no match also avoids allocating.
    pub fn scrub_cow<'a>(&self, body: &'a str) -> Cow<'a, str> {
        // The config-level opt-out (`redact.enabled = false`) suppresses
        // substitution even though the entries are present. Only routes
        // entitled to honor the opt-out ever hold a table in this state;
        // untrusted egress holds the [`Self::enforced`] view instead.
        if self.disabled {
            return Cow::Borrowed(body);
        }
        let Some(matcher) = self.matcher.as_ref() else {
            return Cow::Borrowed(body);
        };
        if !matcher.is_match(body) {
            return Cow::Borrowed(body);
        }
        // Enumerate EVERY occurrence of EVERY registered literal, OVERLAPPING
        // and SELF-overlapping included. The `matcher` above is
        // `MatchKind::LeftmostLongest`, whose `replace_all`/`find_iter` emit
        // only NON-overlapping matches and resume PAST each one: when two
        // registered literals overlap (share a run — e.g. `abcdefghij` and
        // `cdefghijWXYZ` in `abcdefghijWXYZ`), or a literal self-overlaps
        // (`aaaa` at `[0,4)` then `[1,5)`), the suppressed occurrence's tail
        // would pass through UN-redacted, leaking a partial secret. So
        // substitution uses `overlap_matcher` (`MatchKind::Standard`) and
        // `find_overlapping_iter`, which yields ALL occurrences — one automaton
        // pass, O(body + matches). Its `PatternID`s index `entries` identically
        // to `matcher` (both built from the same pattern list, same order).
        //
        // `is_match` already gated the no-secret common case to a borrowed
        // return above, so this scan runs only on bodies that carry a secret.
        let overlap_matcher = self
            .overlap_matcher
            .as_ref()
            .expect("overlap_matcher is Some whenever matcher is Some (same build site)");
        let mut spans: Vec<(usize, usize, usize)> = overlap_matcher
            .find_overlapping_iter(body)
            .map(|m| (m.start(), m.end(), m.pattern().as_usize()))
            .collect();
        if spans.is_empty() {
            // `is_match` was true, so this is unreachable in practice (the same
            // patterns drive both). Stay fail-safe: nothing to cover, borrow.
            return Cow::Borrowed(body);
        }
        // Merge STRICTLY-overlapping spans into maximal covered ranges, tracking
        // whether every span in a range came from the SAME entry. Sorting by
        // start makes this a linear sweep; a range absorbs the next span while
        // that span STARTS BEFORE the running end (`<`). Touching-but-disjoint
        // spans (`next.start == end`) are NOT merged: they leave no uncovered
        // gap, and keeping them separate preserves the old `replace_all`
        // behavior for adjacent distinct secrets (two placeholders, and each
        // single entry's own sealed marker) exactly. Every registered-secret
        // byte still lands inside some emitted range, overlaps included.
        spans.sort_unstable_by_key(|&(s, e, _)| (s, e));
        let mut out = String::with_capacity(body.len());
        let mut last_end = 0usize;
        let mut i = 0usize;
        while i < spans.len() {
            let (start, mut end, first_idx) = spans[i];
            let mut single_entry = true;
            let mut j = i + 1;
            while j < spans.len() && spans[j].0 < end {
                if spans[j].1 > end {
                    end = spans[j].1;
                }
                if spans[j].2 != first_idx {
                    single_entry = false;
                }
                j += 1;
            }
            // Verbatim bytes between the previous range and this one. `start` and
            // `end` are match starts/ends of whole literals in valid-UTF-8
            // `body`, hence char boundaries, so these slices never bisect a char.
            out.push_str(&body[last_end..start]);
            // A range from ONE entry renders THAT entry's typed replacement
            // (preserving current behavior — a sealed entry with an active grant
            // still emits its actionable marker). A range spanning MULTIPLE
            // entries is a genuine overlap of DISTINCT secrets; render the
            // conservative GLOBAL placeholder, never a partial sealed marker over
            // a multi-secret blob (the marker would falsely advertise one sealed
            // handle covering bytes that belong to other secrets). The all-
            // `Generic` common case (and the persisted table, always Generic)
            // borrows the placeholder with no per-range allocation.
            let replacement: Cow<str> = if single_entry {
                match &self.entries[first_idx].replacement {
                    Replacement::Generic => Cow::Borrowed(self.placeholder.as_str()),
                    other => Cow::Owned(other.render(&self.placeholder)),
                }
            } else {
                Cow::Borrowed(self.placeholder.as_str())
            };
            out.push_str(&replacement);
            last_end = end;
            i = j;
        }
        out.push_str(&body[last_end..]);
        Cow::Owned(out)
    }
    /// Scrub every secret in `body`. Returns the cleaned string.
    pub fn scrub(&self, body: &str) -> String {
        self.scrub_cow(body).into_owned()
    }

    /// `true` when there's nothing to redact and `scrub` will pass
    /// through. Useful for the debug command.
    // Retained for `cockpit debug redact` introspection.
    pub fn is_empty(&self) -> bool {
        self.disabled || self.matcher.is_none()
    }

    /// This table with the config-level opt-out (`redact.enabled = false`)
    /// ignored, so the collected entries actually substitute.
    ///
    /// This is the untrusted-egress view. `redact.enabled = false` is an
    /// opt-out for routes that stay under the user's control — trusted models
    /// and local sinks — and is never an opt-out for content leaving the
    /// machine to a provider that may retain it. Model trust is the single
    /// control over raw egress: a user who wants raw content to reach a cloud
    /// model marks that model trusted, which releases
    /// [`RedactionTable::empty`] through the custody grant instead.
    ///
    /// A table that is already enforcing is returned unchanged.
    pub fn enforced(&self) -> Self {
        Self {
            matcher: self.matcher.clone(),
            // Arc bump only — see the field doc; the automaton is not re-copied.
            overlap_matcher: self.overlap_matcher.clone(),
            entries: self.entries.clone(),
            placeholder: self.placeholder.clone(),
            disabled: false,
            unsupported_files: self.unsupported_files.clone(),
            protected: self.protected.clone(),
            protected_path_conflicts: self.protected_path_conflicts.clone(),
            #[cfg(test)]
            fail_enforced_view: self.fail_enforced_view,
        }
    }

    /// [`Self::enforced`] wrapped in a `Result`.
    ///
    /// IMPORTANT: in shipped builds this is INFALLIBLE — `enforced()` cannot
    /// fail, so this never returns `Err` in production. It is deliberately NOT
    /// an advertised production fail-closed contract. The `Result` exists so a
    /// caller (the external-harness runner) has a single seam through which a
    /// future fallible scrub-view construction step would fail closed BEFORE
    /// any irreversible side effect (a subprocess spawn), and so that unit
    /// tests can drive that seam to prove the ordering: the scrub view is
    /// built, and on failure the runner is never reached. The failure branch
    /// is reachable only in unit-test builds, where a table is marked via
    /// [`Self::with_forced_enforced_view_failure`].
    pub fn enforced_checked(&self) -> Result<Self> {
        #[cfg(test)]
        if self.fail_enforced_view {
            anyhow::bail!("redaction enforced-view construction failed (injected test fault)");
        }
        Ok(self.enforced())
    }

    /// Test-only: mark this table so [`Self::enforced_checked`] fails, letting a
    /// fail-closed-before-side-effect path be driven with a would-be-bad input.
    #[cfg(test)]
    pub fn with_forced_enforced_view_failure(mut self) -> Self {
        self.fail_enforced_view = true;
        self
    }

    /// [`Self::enforced`] over a shared table, reusing the existing allocation
    /// when the table is already enforcing.
    pub fn enforced_arc(table: std::sync::Arc<Self>) -> std::sync::Arc<Self> {
        if table.disabled {
            std::sync::Arc::new(table.enforced())
        } else {
            table
        }
    }

    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    /// The maximum byte length of any literal this table can match — the
    /// finite `M` a caller needs to bound a truncation-straddle margin.
    ///
    /// Every entry is a fixed literal string matched via `aho-corasick`
    /// (`MatchKind::LeftmostLongest`); there is no regex or otherwise-unbounded
    /// matcher in this architecture, so the longest possible match is exactly the
    /// longest registered literal. Returns `0` for an empty/no-op table (nothing
    /// can match), so a caller computing an `(M - 1)` margin must guard `M <= 1`.
    ///
    /// A stream that was front-truncated before this table's whole-value `scrub`
    /// runs can leave only the SUFFIX of a boundary-straddling secret at the head
    /// of the retained text, which the whole-value match cannot catch. That
    /// surviving suffix is strictly shorter than the secret, hence `< M` bytes, so
    /// dropping `M - 1` leading bytes after scrubbing removes it. See the harness
    /// child-output scrub in `crate::harness::run`.
    pub fn max_match_len(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.value.len())
            .max()
            .unwrap_or(0)
    }

    /// Advance a byte cut forward, starting from `start`, PAST every registered
    /// literal OCCURRENCE that strictly straddles it (`s < cut < s + value.len()`),
    /// to a fixpoint. After it returns `cut`, no registered literal — overlapping
    /// ones included — straddles the front of `body[cut..]`, so a fresh
    /// `scrub(&body[cut..])` cannot leave a boundary-straddling suffix un-redacted.
    ///
    /// This must NOT use the `scrub` matcher's emitted set: `aho-corasick`
    /// leftmost-longest emits only NON-overlapping matches, while the table permits
    /// OVERLAPPING registered literals. Snapping past one emitted match can leave a
    /// DIFFERENT literal (that the emit suppressed) straddling the new cut. So each
    /// registered `entry.value` is checked INDEPENDENTLY for a straddling
    /// occurrence, and `cut` is advanced to the MAXIMUM end of any such occurrence,
    /// iterating until none straddle. `cut` strictly increases each step and is
    /// bounded by `body.len()`, so it converges. A returned value `>= body.len()`
    /// means the whole tail is unsafe and the caller must withhold it (fail-closed).
    ///
    /// Only occurrences within `[cut - (M-1), cut + (M-1)]` (`M = max_match_len`)
    /// can straddle `cut`, so the per-step scan is bounded to that window. The
    /// window is snapped OUTWARD to UTF-8 boundaries so slicing never panics
    /// (widening only adds safe context); returned cuts land on match ends, which
    /// are char boundaries because matches are whole literals in valid-UTF-8 `body`.
    ///
    /// Deliberately independent of the `disabled` opt-out: the harness path calls
    /// this on the [`Self::enforced`] view (never disabled), and the spans are what
    /// a substitution WOULD cover.
    pub fn straddle_fixpoint_cut(&self, body: &str, start: usize) -> usize {
        let mut cut = cockpit_host::text::ceil_char_boundary(body, start);
        let max_match = self.max_match_len();
        if max_match <= 1 || self.matcher.is_none() {
            return cut;
        }
        loop {
            // Occurrences that could straddle `cut` start in `(cut - M, cut)` and
            // end in `(cut, cut + M)`, so they lie within this window. Snap the
            // window outward to char boundaries so the slice is always valid.
            let lo =
                cockpit_host::text::floor_char_boundary(body, cut.saturating_sub(max_match - 1));
            let hi =
                cockpit_host::text::ceil_char_boundary(body, (cut + max_match - 1).min(body.len()));
            let window = &body[lo..hi];
            let mut advanced = cut;
            for entry in &self.entries {
                let value = entry.value.as_str();
                if value.is_empty() {
                    continue;
                }
                // Enumerate EVERY occurrence of `value` in the window, OVERLAPPING
                // included — `str::match_indices` is non-overlapping and would
                // suppress a self-overlapping occurrence (e.g. `aaaa` at `[1,5)`
                // behind `[0,4)`), and the suppressed one can be the occurrence
                // straddling `cut`. Advance the cursor ONE char boundary past each
                // found START, not past the whole match.
                let mut i = 0;
                while let Some(rel) = window[i..].find(value) {
                    let start_in_window = i + rel;
                    let s = lo + start_in_window; // absolute start
                    let e = s + value.len(); // absolute end (matched == value)
                    if s < cut && e > cut {
                        advanced = advanced.max(e);
                    }
                    i = cockpit_host::text::ceil_char_boundary(window, start_in_window + 1);
                    if i >= window.len() {
                        break;
                    }
                }
            }
            if advanced <= cut {
                return cut;
            }
            cut = advanced; // a match end: a char boundary
            if cut >= body.len() {
                return cut;
            }
        }
    }

    /// The BACK-margin mirror of [`Self::straddle_fixpoint_cut`]. Retreat a byte
    /// cut BACKWARD, starting from `start`, BELOW every registered literal
    /// OCCURRENCE that strictly straddles it (`s < cut < s + value.len()`), to a
    /// fixpoint. After it returns `cut`, no registered literal — overlapping ones
    /// included — straddles the END of `body[..cut]`, so scrubbing `body[..cut]`
    /// cannot leave a boundary-straddling PREFIX un-redacted at that end.
    ///
    /// This is the mirror the head/tail-capture geometry needs: when a bounded
    /// drain omits the MIDDLE of a stream, a secret straddling the head→middle
    /// omission leaves only its PREFIX at the END of the retained head, which the
    /// whole-value scrub cannot match. Dropping a back margin down to this cut
    /// removes the prefix without bisecting any fully-retained secret straddling
    /// the margin point (that would re-expose its suffix at the new end).
    ///
    /// Like the forward variant, this checks each registered `entry.value`
    /// INDEPENDENTLY for straddling occurrences (aho-corasick's leftmost-longest
    /// emit suppresses overlaps, so one snap past an emitted match can leave a
    /// different literal straddling), enumerates OVERLAPPING occurrences within
    /// the bounded `[cut - (M-1), cut + (M-1)]` window, and retreats `cut` to the
    /// MINIMUM start of any such occurrence, iterating to a fixpoint. `cut`
    /// strictly decreases each step and is bounded below by `0`, so it converges.
    /// A returned value `0` means the whole head is unsafe and the caller must
    /// withhold it (fail-closed).
    pub fn straddle_fixpoint_cut_back(&self, body: &str, start: usize) -> usize {
        let mut cut = cockpit_host::text::floor_char_boundary(body, start.min(body.len()));
        let max_match = self.max_match_len();
        if max_match <= 1 || self.matcher.is_none() {
            return cut;
        }
        loop {
            // Occurrences that could straddle `cut` start in `(cut - M, cut)` and
            // end in `(cut, cut + M)`, so they lie within this window. Snap the
            // window outward to char boundaries so the slice is always valid.
            let lo =
                cockpit_host::text::floor_char_boundary(body, cut.saturating_sub(max_match - 1));
            let hi =
                cockpit_host::text::ceil_char_boundary(body, (cut + max_match - 1).min(body.len()));
            let window = &body[lo..hi];
            let mut retreated = cut;
            for entry in &self.entries {
                let value = entry.value.as_str();
                if value.is_empty() {
                    continue;
                }
                // Enumerate EVERY occurrence of `value` in the window, OVERLAPPING
                // included (see the forward variant), and retreat past the START of
                // any occurrence straddling `cut`.
                let mut i = 0;
                while let Some(rel) = window[i..].find(value) {
                    let start_in_window = i + rel;
                    let s = lo + start_in_window; // absolute start
                    let e = s + value.len(); // absolute end (matched == value)
                    if s < cut && e > cut {
                        retreated = retreated.min(s);
                    }
                    i = cockpit_host::text::ceil_char_boundary(window, start_in_window + 1);
                    if i >= window.len() {
                        break;
                    }
                }
            }
            if retreated >= cut {
                return cut;
            }
            cut = retreated; // a match start: a char boundary
            if cut == 0 {
                return 0;
            }
        }
    }

    /// A no-op table that scrubs nothing, because it has no entries. Used as
    /// the raw-custody token a trusted route receives, as a fallback when a
    /// redaction chokepoint object is needed but the table couldn't be built
    /// (the chokepoint still *runs* — it just has an empty table), and as the
    /// accumulation base for sealed values and approved secret-file reads.
    ///
    /// `disabled` is **false** here: that flag means "the user set
    /// `redact.enabled = false`" and nothing else. An empty table is a no-op
    /// on its own merits, and marking it disabled would silence every entry
    /// later accumulated onto it via [`Self::with_forced_literal`] /
    /// [`Self::with_approved_secret_file`], which inherit the flag.
    pub fn empty() -> Self {
        Self {
            matcher: None,
            overlap_matcher: None,
            entries: Vec::new(),
            placeholder: RedactConfig::default().placeholder,
            disabled: false,
            unsupported_files: Vec::new(),
            protected: ProtectedPaths::default(),
            protected_path_conflicts: Vec::new(),
            #[cfg(test)]
            fail_enforced_view: false,
        }
    }

    // Retained for `cockpit debug redact` introspection.
    pub fn disabled(&self) -> bool {
        self.disabled
    }

    /// Env files that matched a redaction pattern but couldn't be parsed
    /// in any supported format (§4). The daemon surfaces these once as a
    /// TUI toast: redaction won't cover those files.
    pub fn unsupported_files(&self) -> &[PathBuf] {
        &self.unsupported_files
    }

    /// Diagnostic origin strings for the debug command. Values themselves
    /// are sensitive — only call this from local `cockpit debug
    /// redact` after the user has explicitly asked. Sealed origins are derived
    /// from the typed identity for display only.
    // Retained for `cockpit debug redact` introspection.
    pub fn entries_for_debug(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.class.origin_display())
            .collect()
    }

    /// The canonical typed identities of every sealed entry, read directly from
    /// the typed classification (no diagnostic-origin string parsing). This is
    /// how the historical-redaction inventory reads sealedness after typing.
    pub fn sealed_identities(&self) -> Vec<crate::sealed::identity::SealedRedactionIdentity> {
        self.entries
            .iter()
            .filter_map(|entry| match &entry.class {
                EntryClass::Sealed(identity) => Some(identity.clone()),
                EntryClass::Ordinary { .. } => None,
            })
            .collect()
    }

    /// Forced-secret origins that matched protected filesystem paths.
    pub fn protected_path_conflicts(&self) -> &[String] {
        &self.protected_path_conflicts
    }
}

/// Extract secret-bearing leaves from an MCP named-secret JSON record. Keep
/// this allowlist closed: metadata such as expiry timestamps and issuer URLs
/// must not become redaction literals merely because they live beside tokens.
fn mcp_sensitive_json_values(raw: &str) -> Vec<(String, String)> {
    const SENSITIVE_FIELDS: &[&str] = &[
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "client_secret",
        "api_key",
        "secret",
        "password",
        "private_key",
    ];

    fn walk(value: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, value) in fields {
                    let next = if path.is_empty() {
                        key.to_string()
                    } else {
                        format!("{path}.{key}")
                    };
                    if SENSITIVE_FIELDS
                        .iter()
                        .any(|field| key.eq_ignore_ascii_case(field))
                        && let serde_json::Value::String(secret) = value
                        && !secret.is_empty()
                    {
                        out.push((next.clone(), secret.clone()));
                    }
                    walk(value, &next, out);
                }
            }
            serde_json::Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    walk(value, &format!("{path}[{index}]"), out);
                }
            }
            _ => {}
        }
    }

    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(&value, "", &mut out);
    out
}

/// One distinct redaction-table entry that matched a haystack, carried by
/// [`match_sensitive_literals`]. This is the exact unit the production
/// journaling chokepoint records — no more, no less.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MatchedLiteral {
    /// The matched literal bytes, taken verbatim from the table entry's stored
    /// `value` (not sliced out of the haystack), so the journaled literal is the
    /// canonical secret the table registered.
    pub literal: String,
    /// The typed source class of the matched entry.
    pub source: SourceClass,
    /// The full typed sealed identity when the matched entry is sealed; `None`
    /// for ordinary entries. This is the same identity that
    /// [`SourceClass::Sealed`] summarizes as `record_id`/`version`, exposed
    /// whole for callers that journal the sealed record and version.
    pub sealed_identity: Option<crate::sealed::identity::SealedRedactionIdentity>,
}

impl std::fmt::Debug for MatchedLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the matched secret literal in a diagnostics projection.
        f.debug_struct("MatchedLiteral")
            .field(
                "literal",
                &format_args!("[REDACTED; len {}]", self.literal.len()),
            )
            .field("source", &self.source)
            .field("sealed_identity", &self.sealed_identity)
            .finish()
    }
}

/// Find every DISTINCT redaction-table entry that occurs in `haystack`.
///
/// This is the production, table-match-only journaling primitive (decision 11):
/// the set it returns is *exactly* what downstream layers journal — nothing is
/// classified free-form. It uses the table's existing Aho-Corasick matcher (the
/// same one [`RedactionTable::scrub_cow`] uses), so a match here is a literal the
/// table would also scrub. It performs **no** encryption and **no** DB I/O.
///
/// Each matched entry appears at most once (dedup is by entry, not by
/// occurrence): a literal that occurs many times in `haystack` yields a single
/// [`MatchedLiteral`]. An entry that never occurs yields nothing — a
/// high-entropy string absent from the table is not "classified" here. A table
/// with no matcher (empty or disabled-with-no-entries) yields an empty vector.
///
/// Note: the `disabled` opt-out is intentionally NOT consulted. Journaling runs
/// regardless of `redact.enabled` (that flag opts trusted egress out of live
/// scrubbing only); a caller wanting scrub semantics uses `scrub`/`scrub_cow`.
pub(crate) fn match_sensitive_literals(
    table: &RedactionTable,
    haystack: &str,
) -> Vec<MatchedLiteral> {
    let Some(matcher) = table.matcher.as_ref() else {
        return Vec::new();
    };
    // The matcher's pattern list is 1:1 with `table.entries` by construction
    // (see `from_redaction_entries`), so a `PatternID` indexes `entries`
    // directly. Dedup by that index to return each entry at most once.
    let mut seen = vec![false; table.entries.len()];
    let mut matched = Vec::new();
    for m in matcher.find_iter(haystack) {
        let idx = m.pattern().as_usize();
        if std::mem::replace(&mut seen[idx], true) {
            continue;
        }
        let entry = &table.entries[idx];
        matched.push(MatchedLiteral {
            literal: entry.value.clone(),
            source: entry.class.source_class(),
            sealed_identity: match &entry.class {
                EntryClass::Sealed(identity) => Some(identity.clone()),
                EntryClass::Ordinary { .. } => None,
            },
        });
    }
    matched
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
mod match_helper_tests {
    use super::*;
    use crate::sealed::identity::{
        SealedName, SealedRecordId, SealedRedactionIdentity, SealedScopeKind,
    };

    // Distinct, non-substring literals so leftmost-longest matching is
    // unambiguous and no literal's encoded variant collides with the haystack.
    const ENV_LITERAL: &str = "env-scan-secret-abc123456";
    const CREDENTIAL_LITERAL: &str = "stored-credential-secret-xyz789";
    const SEALED_LITERAL: &str = "sealed-deploy-token-literal-000";
    const LEAK_LITERAL: &str = "contained-leak-literal-value-999";
    const UNMATCHED_HIGH_ENTROPY: &str = "Zq7UnregisteredHighEntropyString42Kv";

    const SEALED_VERSION: u32 = 4;

    /// Build a real table through the production seams with one entry of each
    /// source class: `Environment` (env scan), `Credential` (stored secret),
    /// `Sealed` (typed sealed identity), and `ContainedLeak` (forced literal).
    fn build_table() -> (RedactionTable, SealedRecordId) {
        let cfg = RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "[redacted]".to_string(),
            ..RedactConfig::default()
        };
        let env = HashMap::from([("DEPLOY_TOKEN".to_string(), ENV_LITERAL.to_string())]);
        // A stored named secret classifies as `Credential` (forced inclusion).
        let base = RedactionTable::build_with_env_and_secrets(
            &cfg,
            Path::new("."),
            &env,
            [("stored_api".to_string(), CREDENTIAL_LITERAL.to_string())],
        )
        .unwrap();

        let record_id = SealedRecordId::generate();
        let identity = SealedRedactionIdentity {
            scope: SealedScopeKind::Project,
            record_id: Some(record_id),
            name: SealedName::canonical("deploy_token").unwrap(),
            version: SEALED_VERSION,
        };
        let table = base
            .with_forced_sealed_literal(SEALED_LITERAL.to_string(), identity)
            .unwrap()
            .with_forced_literal(LEAK_LITERAL.to_string(), "$leak:test".to_string())
            .unwrap();
        (table, record_id)
    }

    fn find<'a>(matched: &'a [MatchedLiteral], literal: &str) -> Option<&'a MatchedLiteral> {
        matched.iter().find(|m| m.literal == literal)
    }

    #[test]
    fn returns_distinct_matched_entries_with_typed_source_and_sealed_identity() {
        let (table, record_id) = build_table();
        // Haystack contains some-but-not-all literals (no CREDENTIAL_LITERAL),
        // includes an unregistered high-entropy string, and repeats one literal
        // to prove dedup-by-entry.
        let haystack = format!(
            "start {ENV_LITERAL} then {SEALED_LITERAL} and again {ENV_LITERAL} \
             plus {LEAK_LITERAL} noise {UNMATCHED_HIGH_ENTROPY} end"
        );

        let matched = match_sensitive_literals(&table, &haystack);

        // Exactly the three present entries, each once (env repeated ⇒ still one).
        assert_eq!(matched.len(), 3, "{matched:#?}");

        let env = find(&matched, ENV_LITERAL).expect("env literal matched");
        assert_eq!(env.source, SourceClass::Environment);
        assert_eq!(env.sealed_identity, None);

        let leak = find(&matched, LEAK_LITERAL).expect("leak literal matched");
        assert_eq!(leak.source, SourceClass::ContainedLeak);
        assert_eq!(leak.sealed_identity, None);

        let sealed = find(&matched, SEALED_LITERAL).expect("sealed literal matched");
        assert_eq!(
            sealed.source,
            SourceClass::Sealed {
                record_id: Some(record_id),
                version: SEALED_VERSION
            }
        );
        let identity = sealed
            .sealed_identity
            .as_ref()
            .expect("sealed match carries typed identity");
        assert_eq!(identity.record_id, Some(record_id));
        assert_eq!(identity.version, SEALED_VERSION);
        assert_eq!(identity.name.as_str(), "deploy_token");
        assert_eq!(identity.scope, SealedScopeKind::Project);

        // The credential literal is in the table but absent from the haystack:
        // table-match-only means it is NOT returned.
        assert!(find(&matched, CREDENTIAL_LITERAL).is_none());
        // The high-entropy string is not a table entry: no free-form classification.
        assert!(matched.iter().all(|m| m.literal != UNMATCHED_HIGH_ENTROPY));
    }

    #[test]
    fn credential_literal_is_classified_when_present() {
        let (table, _record_id) = build_table();
        let haystack = format!("only the credential {CREDENTIAL_LITERAL} appears here");

        let matched = match_sensitive_literals(&table, &haystack);

        assert_eq!(matched.len(), 1, "{matched:#?}");
        let cred = &matched[0];
        assert_eq!(cred.literal, CREDENTIAL_LITERAL);
        assert_eq!(cred.source, SourceClass::Credential);
        assert_eq!(cred.sealed_identity, None);
    }

    #[test]
    fn unmatched_high_entropy_string_yields_nothing() {
        let (table, _record_id) = build_table();
        let haystack = format!("noise only {UNMATCHED_HIGH_ENTROPY} here");

        let matched = match_sensitive_literals(&table, &haystack);

        assert!(matched.is_empty(), "{matched:#?}");
    }

    #[test]
    fn empty_table_yields_no_matches() {
        let table = RedactionTable::empty();
        let matched = match_sensitive_literals(&table, "anything at all here");
        assert!(matched.is_empty());
    }
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
    fn forced_origin_predicate_covers_every_forced_construction_site() {
        assert!(origin_is_forced("$denylist"));
        assert!(origin_is_forced("$credentials:flycockpit.instance_token"));
        assert!(origin_is_forced("$secret:openai"));
        assert!(origin_is_forced("$ssh:/home/user/.ssh/id_ed25519"));
        assert!(!origin_is_forced("$PATH"));
        assert!(!origin_is_forced("/tmp/not-an-origin"));
    }

    #[test]
    fn is_secret_shaped_key_matches_secret_family_and_env_superset() {
        for key in [
            "password",
            "PASSWORD",
            "passwd",
            "db_password",
            "token",
            "TOKEN",
            "access_token",
            "secret",
            "SECRET",
            "client_secret",
            "api_key",
            "API_KEY",
            "apiKey",
            "APIKey",
            "apikey",
            "AWSSecretAccessKey",
            "credential",
            "credentials",
            "CREDENTIALS",
            "private_key",
            "secret_key",
            "access_key",
            "AWS_SECRET_ACCESS_KEY",
            "passphrase",
            "PASSPHRASE",
            "ssl_passphrase",
            "SERVICE_KEY",
            "SERVICE_SECRET",
            "SERVICE_TOKEN",
            "SERVICE_PASSWORD",
            "SERVICE_PASSWD",
            "SERVICE_PIN",
            "SERVICE_PAT",
            "SERVICE_CREDENTIALS",
            "SERVICE_PASSPHRASE",
        ] {
            assert!(is_secret_shaped_key(key), "expected `{key}` to match");
        }
    }

    #[test]
    fn is_secret_shaped_key_rejects_plain_and_bare_ambiguous_keys() {
        for key in [
            "name",
            "title",
            "description",
            "id",
            "host",
            "port",
            "url",
            "uri",
            "email",
            "username",
            "user",
            "path",
            "region",
            "bucket",
            "version",
            "enabled",
            "key",
            "pin",
            "pat",
        ] {
            assert!(!is_secret_shaped_key(key), "expected `{key}` to reject");
        }
    }

    #[test]
    fn env_scrub_secret_arm_is_superset_of_old_suffixes() {
        for suffix in [
            "_KEY",
            "_SECRET",
            "_TOKEN",
            "_PASSWORD",
            "_PASSWD",
            "_PIN",
            "_PAT",
            "_CREDENTIALS",
        ] {
            let name = format!("SERVICE{suffix}");
            assert!(env_scrub_patterns(&name), "expected `{name}` to match");
        }

        for old_fixed_secret in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] {
            assert!(
                env_scrub_patterns(old_fixed_secret),
                "expected `{old_fixed_secret}` to keep matching"
            );
            assert!(
                is_secret_shaped_key(old_fixed_secret),
                "expected `{old_fixed_secret}` to match via the unified secret arm"
            );
        }
    }

    #[test]
    fn env_scrub_matches_bare_and_camel_secret_names() {
        for name in [
            "PASSWORD",
            "TOKEN",
            "SECRET",
            "PASSPHRASE",
            "APIKEY",
            "apiKey",
        ] {
            assert!(env_scrub_patterns(name), "expected `{name}` to match");
        }

        let mut cfg = RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 1,
            allowlist: vec!["PASSWORD".to_string(), "apiKey".to_string()],
            placeholder: "[redacted]".to_string(),
            ..RedactConfig::default()
        };
        let dir = tempfile::TempDir::new().unwrap();
        let env = HashMap::from([
            ("PASSWORD".to_string(), "bare-password-value".to_string()),
            ("apiKey".to_string(), "camel-api-key-value".to_string()),
        ]);
        let table = RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();

        assert_eq!(table.scrub("bare-password-value"), cfg.placeholder);
        assert_eq!(table.scrub("camel-api-key-value"), cfg.placeholder);

        cfg.allowlist.clear();
        let table_without_allowlist =
            RedactionTable::build_with_env(&cfg, dir.path(), &env).unwrap();
        assert_eq!(
            table.entries_for_debug(),
            table_without_allowlist.entries_for_debug()
        );
    }

    #[test]
    fn env_scrub_shell_injection_names_unchanged() {
        for name in FIXED_SHELL_INJECTION_NAMES {
            assert!(env_scrub_patterns(name), "expected `{name}` to match");
        }
        assert!(env_scrub_patterns("prompt_command"));
        assert!(!is_secret_shaped_key("PROMPT_COMMAND"));
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
        "apps/cli/src/commands/debug.rs",
        "crates/cockpit-core/src/daemon/fs_api.rs",
        "crates/cockpit-core/src/daemon/org_sync.rs",
        "crates/cockpit-core/src/daemon/remote_audit_upload.rs",
        "crates/cockpit-core/src/daemon/server/mod.rs",
        "crates/cockpit-core/src/daemon/session_worker/mod.rs",
        "crates/cockpit-core/src/daemon/session_worker/run.rs",
        "crates/cockpit-core/src/embeddings.rs",
        "crates/cockpit-core/src/engine/agent/tool_dispatch.rs",
        "crates/cockpit-core/src/engine/driver/mod.rs",
        "crates/cockpit-core/src/engine/model/dispatch.rs",
        "crates/cockpit-core/src/engine/model/mod.rs",
        "crates/cockpit-core/src/engine/model/outbound_guard.rs",
        "crates/cockpit-core/src/engine/model/redact.rs",
        "crates/cockpit-core/src/engine/model_roles.rs",
        "crates/cockpit-core/src/engine/rehydrate.rs",
        "crates/cockpit-core/src/engine/verification/intercept.rs",
        "crates/cockpit-core/src/harness/run.rs",
        "crates/cockpit-core/src/knowledge.rs",
        "crates/cockpit-core/src/mcp/builtin.rs",
        "crates/cockpit-core/src/redact/mod.rs",
        "crates/cockpit-core/src/session/export/mod.rs",
        "crates/cockpit-core/src/session/recording.rs",
        "crates/cockpit-core/src/skills/auto_select/mod.rs",
        "crates/cockpit-core/src/tools/artifact_read.rs",
        "crates/cockpit-core/src/tools/artifact_search.rs",
        "crates/cockpit-core/src/tools/read.rs",
        "crates/cockpit-core/src/tools/skill.rs",
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
        // Exclude test scaffolding: `tests.rs`, any `*_tests.rs` module (e.g.
        // `secret_store_boot_tests.rs`, which is included behind `#[cfg(test)]`
        // but whose body is not itself wrapped in a `#[cfg(test)]` block), and
        // any file under a `tests` directory. The inventory tracks production
        // scrub sites only.
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
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
mod sec_f3_case_and_hex_tests {
    //! Regression tests for audit finding SEC-F3: case-transformed and
    //! uppercase-hex echoes of secrets must be scrubbed for the common secret
    //! key families, while the anti-false-positive length floor is preserved.
    use super::*;
    use tempfile::TempDir;

    /// Hermetic config: env-scan only (no dotenv walk, no SSH-dir read), with a
    /// distinctive placeholder for exact-match assertions.
    fn env_cfg(min_secret_length: usize) -> RedactConfig {
        RedactConfig {
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length,
            placeholder: "***REDACT***".into(),
            ..Default::default()
        }
    }

    fn build(cfg: &RedactConfig, env: &HashMap<String, String>) -> RedactionTable {
        let dir = TempDir::new().unwrap();
        RedactionTable::build_with_env(cfg, dir.path(), env).unwrap()
    }

    /// Gap 1: a `*_API_KEY` / `*_TOKEN` env secret (NOT one of the four
    /// `credential_shaped_key` shapes) must have its all-uppercase and its
    /// capitalized echoes scrubbed. Fails pre-fix: those families received no
    /// case variants, and `case_secret_variants` produced no capitalized form.
    #[test]
    fn secret_family_key_case_echoes_are_scrubbed() {
        let cfg = env_cfg(8);
        // All-lowercase high-entropy value so upper/capitalized are distinct
        // from the raw and from each other.
        let secret = "hunter2secrettokenvalue0099";
        let env = HashMap::from([
            ("SERVICE_API_KEY".to_string(), secret.to_string()),
            ("GITHUB_TOKEN".to_string(), secret.to_string()),
        ]);
        let table = build(&cfg, &env);

        let upper = secret.to_ascii_uppercase();
        let capitalized = capitalize_first_ascii(secret).unwrap();
        assert_ne!(upper, secret);
        assert_ne!(capitalized, secret);

        assert_eq!(table.scrub(&upper), cfg.placeholder, "uppercased echo");
        assert_eq!(
            table.scrub(&capitalized),
            cfg.placeholder,
            "capitalized echo"
        );
        // The lowercased raw itself is of course still scrubbed.
        assert_eq!(table.scrub(secret), cfg.placeholder);
    }

    /// Gap 2: the uppercase-hex encoding of a secret must be scrubbed, alongside
    /// the lowercase-hex encoding. Fails pre-fix: only lowercase hex was
    /// registered.
    #[test]
    fn uppercase_hex_encoding_is_scrubbed() {
        let cfg = env_cfg(8);
        let secret = "hunter2secrettokenvalue0099";
        let env = HashMap::from([("SERVICE_API_KEY".to_string(), secret.to_string())]);
        let table = build(&cfg, &env);

        let hex_lower = hex_encode(secret.as_bytes());
        let hex_upper = hex_encode_upper(secret.as_bytes());
        // Precondition: the value contains a nibble in a..f so the two hex cases
        // actually differ (otherwise the test would be vacuous).
        assert_ne!(hex_lower, hex_upper);

        assert_eq!(
            table.scrub(&format!("token={hex_upper}")),
            "token=***REDACT***",
            "uppercase hex echo"
        );
        assert_eq!(
            table.scrub(&format!("token={hex_lower}")),
            "token=***REDACT***",
            "lowercase hex echo still scrubbed"
        );
    }

    /// Anti-false-positive floor: a `*_KEY` family env var with a short value
    /// below `min_secret_length` (and not one of the length-exempt
    /// `credential_shaped_key` shapes) must NOT enter the table, so none of its
    /// case echoes are over-redacted. This locks in the floor that broadening
    /// case-variant coverage must preserve.
    #[test]
    fn short_secret_family_value_is_not_over_redacted() {
        let cfg = env_cfg(8);
        let env = HashMap::from([
            ("FOO_API_KEY".to_string(), "cat".to_string()),
            ("BAR_TOKEN".to_string(), "test".to_string()),
        ]);
        let table = build(&cfg, &env);

        for probe in ["cat", "CAT", "Cat", "test", "TEST", "Test"] {
            assert_eq!(
                table.scrub(probe),
                probe,
                "short low-entropy value `{probe}` must not be redacted"
            );
        }
    }
}

#[cfg(test)]
mod tests;
