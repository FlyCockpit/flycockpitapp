//! User-configured provider entries in per-provider config files.
//!
//! Layer-wide provider metadata stays in `<CONFIG_DIR>/config.json`.
//! Individual provider entries live in
//! `<CONFIG_DIR>/providers/<provider-id>.json`, where the provider id is the
//! filename stem and the file body is one [`ProviderEntry`] object:
//!
//! ```json
//! {
//!   "name": "OpenCode Zen",
//!   "url": "https://opencode.ai/zen/v1",
//!   "headers": [
//!     { "name": "Authorization", "value": "Bearer $OPENCODE_ZEN_TOKEN" }
//!   ],
//!   "models_fetched_at": "2026-05-26T12:34:56Z",
//!   "favorite": true,
//!   "models": [
//!     {
//!       "id": "claude-opus-4-7",
//!       "name": "Claude Opus 4.7 (via opencode)",
//!       "thinking_modes": ["off", "low", "medium", "high"],
//!       "inputs": { "images": true }
//!     }
//!   ]
//! }
//! ```
//!
//! `name`, `models_fetched_at`, `favorite`, `models`, `thinking_modes`,
//! and `inputs` are all optional. Headers carry `$VAR` references that
//! [`crate::envref`] expands at use-time.
//!
//! Each provider entry (and, as an override, each model entry) may also carry
//! the `cache` / `context` / `shrink` / `timeout` sub-objects and a `backup`
//! reference. `backup` is the per-model backup-fallback target
//! (implementation note): a full `{ "provider": "…",
//! "model": "…" }` that **may name a different provider** than the primary.
//! Resolution is model-level → provider-level → none (no fallback). Example:
//!
//! ```json
//! {
//!   "url": "https://opencode.ai/zen/v1",
//!   "backup": { "provider": "anthropic", "model": "claude-sonnet-4-6" },
//!   "timeout": { "ttft_secs": 120, "idle_secs": 90 }
//! }
//! ```

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::extended::{LlmMode, TextEmbeddedRecovery, deep_merge_value};

const PROVIDERS_DIR: &str = "providers";
const PROVIDER_SKIPPED_KEYS: &[&str] = &[
    "name",
    "allow_insecure_http",
    "models_fetched_at",
    "model_catalog",
    "favorite",
    "credential_ref",
    "auth",
    "trust",
    "location",
    "quality_rank",
    "cost_rank",
    "subagent_invokable",
    "availability",
    "wire_api",
    "backup",
    "mode",
    "inline_think",
    "hint_tool_call_corrections",
    "text_embedded_recovery",
    "thinking_params",
    "capabilities",
    "provider_metadata",
    "last_model_fetch",
];

pub const XAI_MULTI_AGENT_TOOLS_ENTITLEMENT: &str = "xai_multi_agent_tools_beta";

pub fn validate_provider_id_for_filename(provider_id: &str) -> Result<()> {
    if provider_id.is_empty() || provider_id == "." || provider_id == ".." {
        anyhow::bail!("invalid provider id `{provider_id}`");
    }
    if !provider_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        anyhow::bail!("invalid provider id `{provider_id}`");
    }
    Ok(())
}

pub fn provider_file_path_for_config(config_path: &Path, provider_id: &str) -> Result<PathBuf> {
    validate_provider_id_for_filename(provider_id)?;
    let dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(PROVIDERS_DIR);
    let path = dir.join(format!("{provider_id}.json"));
    if path.parent() != Some(dir.as_path()) {
        anyhow::bail!("invalid provider id `{provider_id}`");
    }
    Ok(path)
}

pub fn provider_file_path_for_dir(config_dir: &Path, provider_id: &str) -> Result<PathBuf> {
    validate_provider_id_for_filename(provider_id)?;
    let dir = config_dir.join(PROVIDERS_DIR);
    let path = dir.join(format!("{provider_id}.json"));
    if path.parent() != Some(dir.as_path()) {
        anyhow::bail!("invalid provider id `{provider_id}`");
    }
    Ok(path)
}

pub fn provider_id_from_file_name(path: &Path) -> Option<String> {
    if path.extension().and_then(|s| s.to_str()) != Some("json") {
        return None;
    }
    let id = path.file_stem()?.to_str()?;
    validate_provider_id_for_filename(id).ok()?;
    Some(id.to_string())
}

fn config_path_for_layer_path(path: &Path) -> PathBuf {
    if path.file_name().and_then(|s| s.to_str()) == Some(crate::config::dirs::CONFIG_FILE) {
        return path.to_path_buf();
    }
    if path.extension().and_then(|s| s.to_str()) == Some("json")
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            == Some(PROVIDERS_DIR)
        && let Some(config_dir) = path.parent().and_then(Path::parent)
    {
        return config_dir.join(crate::config::dirs::CONFIG_FILE);
    }
    path.to_path_buf()
}

/// Effective provider config. Global fields are read from layer
/// `config.json`; provider entries are read from sibling `providers/*.json`
/// files. The in-memory shape remains map-based so callers do not need to know
/// about the split on-disk layout.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvidersConfig {
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderEntry>,
    /// Category defaults used by policy-based model selection. Keys are
    /// product categories such as `cheap_code`, `smart_code`, or `reasoning`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub category_defaults: BTreeMap<String, ProviderModelRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_unlisted_models_fetch: Option<OnUnlistedModelsFetch>,
    /// Currently selected model. Written by `/model` and read by the
    /// launch header + status line. Absent when nothing has been picked
    /// yet (e.g. a freshly-scaffolded config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_model: Option<ActiveModelRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveModelRef {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ActiveReasoningEffort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_mode: Option<ThinkingMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderModelRef {
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ModelTrust {
    Trusted,
    #[default]
    Untrusted,
}

impl ModelTrust {
    pub fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelLocation {
    Local,
    Remote,
    PrivateRemote,
}

/// Optional policy restrictions for model selection. Empty lists mean that
/// axis is unrestricted; non-empty lists are exact string allowlists.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelAvailability {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
}

#[allow(dead_code)]
impl ModelAvailability {
    pub fn is_empty(&self) -> bool {
        self.categories.is_empty() && self.roles.is_empty() && self.agents.is_empty()
    }

    fn allows(list: &[String], value: Option<&str>) -> bool {
        list.is_empty() || value.is_some_and(|value| list.iter().any(|item| item == value))
    }

    pub fn permits(&self, category: Option<&str>, role: Option<&str>, agent: Option<&str>) -> bool {
        Self::allows(&self.categories, category)
            && Self::allows(&self.roles, role)
            && Self::allows(&self.agents, agent)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveReasoningEffort {
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderEntry {
    /// Display name. Omit to fall back to the id key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The provider's immutable vendor/template identity: the id of the
    /// [`ProviderTemplate`](crate::providers::ProviderTemplate) this provider
    /// was created from. Unlike the config-map key (which the user may rename
    /// freely — e.g. `anthropic-work` for a second Anthropic connection), this
    /// records the underlying vendor and is what keys the known-frontier
    /// defaults ([`is_frontier_default_provider_template`]). Not user-editable.
    /// Absent on pre-field configs; [`ProviderEntry::effective_template`] falls
    /// back to the map key when it matches a known template id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,

    /// Base URL. The `/models` endpoint is `{url}/models`; chat lives at
    /// `{url}/chat/completions`. Stored without a trailing slash.
    pub url: String,

    /// Explicit opt-in that permits plaintext non-loopback HTTP provider URLs.
    /// Defaults to `false`; loopback/local HTTP is still allowed for local
    /// development without this opt-in.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_insecure_http: bool,

    /// HTTP headers to send on every request. Values may contain `$VAR`
    /// env references.
    #[serde(default)]
    pub headers: Vec<HeaderSpec>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models_fetched_at: Option<DateTime<Utc>>,

    /// Origin of the currently persisted fetched model catalog. Defaults to the
    /// normal live `/models` source; only the Codex OAuth hardcoded fallback is
    /// persisted explicitly.
    #[serde(default, skip_serializing_if = "ProviderModelCatalog::is_live")]
    pub model_catalog: ProviderModelCatalog,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,

    /// Optional pointer to a credential record under
    /// `~/.local/state/cockpit/credentials.json`. The credentials file
    /// stores the raw secret; this field just names the record so the
    /// resolver knows which one to attach. Absent on env-var-only
    /// providers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,

    /// Auth kind. Mostly informational for the UI — actual auth is
    /// driven by `headers` + `credential_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthKind>,

    /// Product-facing trust policy. `trusted` disables outbound request
    /// redaction for models inheriting it; `untrusted` keeps the session
    /// redaction table. Missing trust resolves to `untrusted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<ModelTrust>,

    /// Where this provider runs. Locality is intentionally separate from
    /// trust; a local endpoint is not implicitly trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<ModelLocation>,

    /// Provider-default model quality rank. Higher is better. Missing resolves
    /// to zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_rank: Option<i64>,

    /// Provider-default cost rank. Lower is cheaper. Missing resolves to zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_rank: Option<i64>,

    /// Provider default for whether models may be selected for subagents.
    /// Missing resolves to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_invokable: Option<bool>,

    /// Optional provider-wide availability restrictions. Empty means no
    /// restriction.
    #[serde(default, skip_serializing_if = "ModelAvailability::is_empty")]
    pub availability: ModelAvailability,

    /// Prompt-cache behavior for this provider. Drives the cache-cold
    /// predicate that gates auto-prune (GOALS §10 / `plan.md` T6.f). A
    /// per-model `cache` overrides this. Defaults to `none` because we
    /// do **not** autodetect — explicit config only.
    #[serde(default)]
    pub cache: CacheConfig,

    /// Delegation-shrink behavior for this provider (GOALS §10 /
    /// implementation note). Drives the parent-context
    /// shrink that hides cache-cold cost across a sub-agent delegation. A
    /// per-model `shrink` overrides this. Lives in the same per-model
    /// layer as `cache` so a future per-model context-usage threshold is
    /// an additive field, not a refactor.
    #[serde(default)]
    pub shrink: ShrinkConfig,

    /// Context-management thresholds for this provider: the ctx% / prunable%
    /// figures that gate auto-compact and the ctx%-threshold branch of
    /// auto-prune. A per-model `context` overrides this. Surfaced in the
    /// provider-settings sub-dialog (implementation note).
    #[serde(default)]
    pub context: ContextConfig,

    /// Per-provider auto-prune master switch. `Some(false)` turns the
    /// automatic prune trigger off entirely for every model on this provider
    /// that doesn't pin its own `auto_prune` — both the cache-cold branch and
    /// the ctx%-threshold branch; manual `/prune` is unaffected. `None` means
    /// "inherit" — resolves to on. A per-model `auto_prune` overrides this in
    /// turn. Skipped on serialize so providers that never pin it stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_prune: Option<bool>,

    /// Inference-stream warning thresholds for this provider: the first-token
    /// (TTFT) and idle/inter-token waits that surface a visible slow-stream
    /// warning while continuing to wait on the live connection.
    /// A per-model `timeout` overrides this. No overall wall-clock cap — an
    /// actively-streaming response is never killed. Surfaced in the
    /// model/provider settings sub-dialog.
    #[serde(default)]
    pub timeout: TimeoutConfig,

    /// Provider-level OpenAI-compatible wire endpoint default. A concrete
    /// `completions` or `responses` applies to models that do not pin their
    /// own `wire_api`; `auto` leaves routing to learned state and the
    /// provider-aware conservative default.
    #[serde(default, skip_serializing_if = "WireApi::is_auto")]
    pub wire_api: WireApi,

    /// Per-provider backup-model fallback target
    /// (implementation note). When the primary model fails
    /// a qualifying inference (TTFT/idle timeout, connection error, or
    /// non-retryable 5xx), the turn is retried once on this `(provider, model)`
    /// — which may point to a *different* provider. A per-model `backup`
    /// overrides this; if neither is set there is no fallback (hard-fail per
    /// implementation note). `None` means
    /// "no backup". Skipped on serialize so providers that never pin one stay
    /// clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,

    /// Per-provider LLM-mode override. When set, takes precedence over the
    /// persisted global `llm_mode` for the cache resolved against this
    /// provider; a per-model `mode` overrides this in turn. `None` means
    /// "inherit" — fall through to the global. Skipped on serialize so
    /// providers that never pin a mode stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LlmMode>,

    /// Per-provider inline `<think>` stripping override
    /// (implementation note). The middle tier
    /// of the three-tier resolution (model `inline_think` → this → the global
    /// `inline_think`). When set, takes precedence over the global for every
    /// model on this provider that doesn't pin its own `inline_think`; a
    /// per-model `inline_think` overrides this in turn. `None` means
    /// "inherit" — fall through to the global. Skipped on serialize so
    /// providers that never pin it stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_think: Option<bool>,

    /// Per-provider §12 tool-call-correction hinting override
    /// (implementation note). The middle tier of the
    /// three-tier resolution (model `hint_tool_call_corrections` → this → the
    /// global `hintToolCallCorrections`). When set, takes precedence over the
    /// global for every model on this provider that doesn't pin its own
    /// `hint_tool_call_corrections`; a per-model override wins over this in
    /// turn. `None` means "inherit" — fall through to the global. Skipped on
    /// serialize so providers that never pin it stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_tool_call_corrections: Option<bool>,

    /// Per-provider text-embedded-recovery override
    /// (implementation note). The middle tier of the three-tier
    /// resolution (model `text_embedded_recovery` → this → the global
    /// `textEmbeddedRecovery`). When set, takes precedence over the global for
    /// every model on this provider that doesn't pin its own
    /// `text_embedded_recovery`; a per-model override wins over this in turn.
    /// `None` means "inherit" — fall through to the global. Skipped on serialize
    /// so providers that never pin it stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_embedded_recovery: Option<TextEmbeddedRecovery>,

    /// Per-provider extra-request-body mapping keyed by [`ThinkingMode`]
    /// (implementation note). The middle tier of the
    /// three-tier resolution (model `thinking_params` → this → the
    /// built-in default for the provider id). Each entry is a vendor-key
    /// JSON fragment merged into the outbound chat/completions body when
    /// the active thinking mode matches (e.g. DeepSeek's `thinking` /
    /// `reasoning_effort` controls). An empty/absent map means "inherit"
    /// — fall through to the built-in default. Skipped on serialize so
    /// providers that never pin it stay clean.
    #[serde(default, skip_serializing_if = "ThinkingParams::is_empty")]
    pub thinking_params: ThinkingParams,

    /// Cached model list. Populated by `/fetch-models` (or the wizard).
    #[serde(default)]
    pub models: Vec<ModelEntry>,

    /// Typed provider-wide capability overrides. Model-level capabilities win
    /// when both are present.
    #[serde(default, skip_serializing_if = "ProviderCapabilities::is_empty")]
    pub capabilities: ProviderCapabilities,

    /// Raw provider-owned metadata preserved from upstream/provider files.
    /// This is separate from Cockpit's typed capability projection.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub provider_metadata: Map<String, Value>,

    /// Last `/models` refresh outcome. Redacted, user-visible diagnostics only:
    /// never store bearer tokens, account ids, or headers here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_model_fetch: Option<ModelFetchStatus>,
}

/// A `ThinkingMode` → extra-request-body JSON fragment map
/// (implementation note). The fragment carries
/// vendor-specific keys (e.g. `thinking`, `reasoning_effort`) that the
/// request builder merges into the outbound body in addition to the
/// params cockpit already sets (temperature/max_tokens/messages/tools).
/// A mode with no entry contributes no extra keys for that request.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ThinkingParams(pub BTreeMap<ThinkingMode, Value>);

impl ThinkingParams {
    /// True when no mode has a fragment configured — the "inherit / send
    /// nothing" state. Used as the serde skip predicate and as the
    /// resolver's empty-layer test.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The fragment for `mode`, if this layer defines one.
    pub fn get(&self, mode: ThinkingMode) -> Option<&Value> {
        self.0.get(&mode)
    }
}

/// Context-management thresholds. Set per-provider on [`ProviderEntry`] and
/// optionally overridden per-model on [`ModelEntry`]. Drive the
/// inference-boundary auto-compact and ctx%-threshold auto-prune triggers
/// (implementation note). All three are percentages of the
/// model's `context_length`; when the context window is unknown the
/// ctx%-gated triggers are inert (the cache-cold auto-prune branch still
/// fires).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextConfig {
    /// At or above this ctx% the foreground context is compacted
    /// automatically (the `/compact` machinery runs without a prompt).
    /// Default 80.
    #[serde(default = "default_auto_compact_pct")]
    pub auto_compact_pct: u8,
    /// Above this ctx% (and above `auto_prune_prunable_pct` of prunable
    /// tokens) auto-prune fires even on a warm cache, accepting the cache
    /// bust to reclaim context. Default 50.
    #[serde(default = "default_auto_prune_pct")]
    pub auto_prune_pct: u8,
    /// The prunable-token threshold (as a ctx%) that the ctx%-threshold
    /// auto-prune branch also requires. Default 30.
    #[serde(default = "default_auto_prune_prunable_pct")]
    pub auto_prune_prunable_pct: u8,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            auto_compact_pct: default_auto_compact_pct(),
            auto_prune_pct: default_auto_prune_pct(),
            auto_prune_prunable_pct: default_auto_prune_prunable_pct(),
        }
    }
}

fn default_auto_compact_pct() -> u8 {
    80
}

fn default_auto_prune_pct() -> u8 {
    50
}

fn default_auto_prune_prunable_pct() -> u8 {
    30
}

/// Inference-stream wait-threshold configuration. Set per-provider on
/// [`ProviderEntry`] and optionally overridden per-model on [`ModelEntry`].
/// Two independent thresholds, both in seconds
/// (implementation note):
///
/// - `ttft_secs` — first-token warning: notify if no token arrives within this
///   many seconds of dispatch.
/// - `idle_secs` — idle/inter-token warning: notify if the gap between two
///   streamed tokens exceeds this. Default 90s.
///
/// Without a resolved backup model these thresholds only warn and the stream
/// keeps waiting. With a resolved backup model they are hard timeout points:
/// the primary attempt fails with `timeout_ttft` / `timeout_idle` so backup
/// fallback can answer the turn.
///
/// There is deliberately **no** overall wall-clock cap: a response that keeps
/// producing tokens is never killed for taking long in total.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// First-token (TTFT) threshold in seconds. Default 120.
    #[serde(default = "default_ttft_secs")]
    pub ttft_secs: u64,
    /// Idle / inter-token threshold in seconds. Default 90.
    #[serde(default = "default_idle_secs")]
    pub idle_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            ttft_secs: default_ttft_secs(),
            idle_secs: default_idle_secs(),
        }
    }
}

impl TimeoutConfig {
    /// The first-token ceiling as a [`std::time::Duration`].
    pub fn ttft(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.ttft_secs)
    }

    /// The idle/inter-token ceiling as a [`std::time::Duration`].
    pub fn idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.idle_secs)
    }
}

fn default_ttft_secs() -> u64 {
    120
}

fn default_idle_secs() -> u64 {
    90
}

/// Backup-model fallback target (implementation note). Set
/// per-provider on [`ProviderEntry`] and optionally overridden per-model on
/// [`ModelEntry`]. A full `(provider, model)` reference: the `provider` is a
/// configured provider id (which **may differ** from the primary's provider —
/// the whole point is falling back from a flaky free endpoint to a reliable
/// one), and `model` is a model id that provider serves. There is no global
/// backup (per the user) and no chaining — a single backup only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupConfig {
    /// The backup provider id (a key in the `providers` map). May differ from
    /// the primary's provider.
    pub provider: String,
    /// The backup model id that `provider` serves.
    pub model: String,
}

/// Prompt-cache configuration. Set per-provider on [`ProviderEntry`] and
/// optionally overridden per-model on [`ModelEntry`]. Used only by the
/// cache-cold predicate (GOALS §10) that decides whether auto-prune may
/// fire for free. We **never** autodetect mode — absence means `none`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheConfig {
    #[serde(default)]
    pub mode: CacheMode,
    /// Seconds a cached prefix survives between sends. After this much
    /// idle time the provider has dropped the cache, so pruning is free.
    /// Default 300 (5 min). Only meaningful when `mode != none`.
    #[serde(default = "default_cache_ttl_secs")]
    pub ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            mode: CacheMode::default(),
            ttl_secs: default_cache_ttl_secs(),
        }
    }
}

impl CacheConfig {
    /// `true` when the configured TTL selects Anthropic's 1-hour extended
    /// cache rather than the 5-minute default (prompt
    /// `prompt-caching-strategy.md`, decision 4). The opt-in reuses the
    /// existing `ttl_secs` lever: `>= 3600` → 1-hour automatic caching
    /// (needs the `extended-cache-ttl-2025-04-11` beta header); anything
    /// below → 5-minute per-block caching. No new config field is added.
    pub fn wants_one_hour_ttl(&self) -> bool {
        self.ttl_secs >= 3600
    }
}

fn default_cache_ttl_secs() -> u64 {
    300
}

/// Delegation-shrink configuration. Set per-provider on [`ProviderEntry`]
/// and optionally overridden per-model on [`ModelEntry`]. Controls how the
/// parent context is shrunk while a sub-agent runs so the parent resumes
/// from the cheapest correct context when the cache went cold
/// (implementation note). The TTL itself is reused from
/// [`CacheConfig::ttl_secs`] — this layer adds only the *strategy* and the
/// *margin* (lead time to finish the shrink before the cache would
/// expire).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShrinkConfig {
    /// Which shrink to run on a cold-at-return delegation. Default
    /// `prune` (lossless, cheap, sync); `compact` opts into LLM
    /// summarization (heavier, lossier, saves more).
    #[serde(default)]
    pub strategy: ShrinkStrategy,
    /// Seconds of lead time before the cache TTL elapses at which the
    /// lazy (cache-capable) shrink is kicked off, so it finishes before
    /// the prefix would expire. The lazy trigger fires at
    /// `ttl_secs - margin_secs`. Ignored for no-cache providers (they
    /// shrink eagerly at delegation start). Default 30s.
    #[serde(default = "default_shrink_margin_secs")]
    pub margin_secs: u64,
}

impl Default for ShrinkConfig {
    fn default() -> Self {
        Self {
            strategy: ShrinkStrategy::default(),
            margin_secs: default_shrink_margin_secs(),
        }
    }
}

fn default_shrink_margin_secs() -> u64 {
    30
}

/// The parent-context shrink strategy used across a sub-agent delegation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShrinkStrategy {
    /// Lossless snapshot-dedup via the existing prune action. Cheap,
    /// synchronous, low quality loss — the default (priority #1).
    #[default]
    Prune,
    /// LLM summarization of the parent context (reuses the `/compact`
    /// brief machinery). Heavier and lossier, saves more tokens.
    Compact,
}

/// How a provider caches the prompt prefix. `None` (the default) means
/// no caching — pruning never costs a cache bust there.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CacheMode {
    /// No prompt cache (local Ollama / llama.cpp / raw vLLM / most
    /// OpenRouter routes). Pruning is always free.
    #[default]
    None,
    /// Provider caches a (possibly implicit) prefix subject to a TTL
    /// (Anthropic ephemeral, OpenAI automatic prefix caching, Gemini).
    Ephemeral,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderSpec {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    /// API key carried by an explicit header (Authorization / x-api-key / etc.).
    ApiKey,
    /// OAuth bearer resolved from the credential store at request time.
    OAuth,
    /// No authentication (e.g. a self-hosted ollama server).
    None,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thinking_modes: Vec<ThinkingMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Inputs>,
    /// Maximum tokens this model accepts in a request (context window).
    /// Optional because providers vary on whether `/models` reports it
    /// — populated by `/fetch-models` when the upstream includes it
    /// (OpenRouter, llamafile), set manually otherwise. Drives the
    /// chrome's `N% context (max Mk)` indicator (omitted when `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_length: Option<u32>,
    /// Toggled by `/favorite`. The `/model` picker pins favorites at
    /// the top of the list.
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    /// True for entries added by hand on the provider Edit page (for
    /// providers without a `/models` endpoint). Manual entries survive a
    /// `/models` refetch via [`merge_fetched_models`] and win on an id
    /// collision. Defaults to `false`, so configs written before this
    /// field existed load as non-manual (fetched).
    #[serde(default, skip_serializing_if = "is_false")]
    pub manual: bool,
    /// Model-level trust override. Missing inherits the provider trust, then
    /// defaults to `untrusted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<ModelTrust>,
    /// Model-level locality override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<ModelLocation>,
    /// Model-level quality rank override. Higher is better.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_rank: Option<i64>,
    /// Model-level cost rank override. Lower is cheaper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_rank: Option<i64>,
    /// Model-level subagent availability override. Missing inherits provider
    /// default, then resolves to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_invokable: Option<bool>,
    /// Optional model-specific availability restrictions. Empty means no
    /// restriction.
    #[serde(default, skip_serializing_if = "ModelAvailability::is_empty")]
    pub availability: ModelAvailability,
    /// Per-model prompt-cache override. When set, takes precedence over
    /// the provider-level [`ProviderEntry::cache`] for the cache-cold
    /// predicate (GOALS §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,
    /// Per-model delegation-shrink override. When set, takes precedence
    /// over the provider-level [`ProviderEntry::shrink`]
    /// (implementation note).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shrink: Option<ShrinkConfig>,
    /// Per-model context-threshold override. When set, takes precedence over
    /// the provider-level [`ProviderEntry::context`]
    /// (implementation note).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextConfig>,
    /// Per-model auto-prune master switch. `Some(false)` turns the automatic
    /// prune trigger off entirely for this model — both the cache-cold branch
    /// and the ctx%-threshold branch; manual `/prune` is unaffected. The top
    /// tier of the resolution (this → provider `auto_prune` → on). `None`
    /// means "inherit". Skipped on serialize so models that never pin it stay
    /// clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_prune: Option<bool>,
    /// Per-model inference-stream timeout override. When set, takes precedence
    /// over the provider-level [`ProviderEntry::timeout`]
    /// (implementation note).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<TimeoutConfig>,
    /// Per-model backup-model fallback override. When set, takes precedence over
    /// the provider-level [`ProviderEntry::backup`]
    /// (implementation note). `None` means "inherit the
    /// provider-level backup, if any".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,
    /// Per-model LLM-mode override. When set, takes precedence over the
    /// provider-level [`ProviderEntry::mode`] and the global `llm_mode`.
    /// `None` means "inherit". Skipped on serialize so models that never
    /// pin a mode stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LlmMode>,
    /// How a leading inline `<think>…</think>` block emitted in the regular
    /// content stream (MiniMax-M2 / DeepSeek-R1 / Qwen, which don't use the
    /// `reasoning_content` channel) is **classified**
    /// (implementation note). `None` means
    /// **enabled** (the default): the block COUNTS AS THINKING — split into
    /// the thinking chip and dropped from stored history so it never replays
    /// on a later turn. `Some(false)`: the block COUNTS AS RESPONSE BODY —
    /// left inline as ordinary response text (no chip) and carried forward.
    /// Skipped on serialize when unset so default-on models stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_think: Option<bool>,
    /// Per-model §12 tool-call-correction hinting override
    /// (implementation note). The top tier of the
    /// three-tier resolution (this → provider `hint_tool_call_corrections` →
    /// the global `hintToolCallCorrections`). `Some(true)` enables surfacing
    /// `<repair_note>` lines to the model for this model, `Some(false)`
    /// disables them, `None` means "inherit". Skipped on serialize when unset
    /// so models that never pin it stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_tool_call_corrections: Option<bool>,
    /// Per-model text-embedded-recovery override
    /// (implementation note). The top tier of the three-tier
    /// resolution (this → provider `text_embedded_recovery` → the global
    /// `textEmbeddedRecovery`). `Some(...)` pins the mode for this model,
    /// `None` means "inherit". Skipped on serialize when unset so models that
    /// never pin it stay clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_embedded_recovery: Option<TextEmbeddedRecovery>,
    /// Per-model extra-request-body mapping keyed by [`ThinkingMode`]
    /// (implementation note). The top tier of the
    /// three-tier resolution (this → provider `thinking_params` → the
    /// built-in default for the provider id). When non-empty it takes
    /// precedence over the provider-level map for this model; an empty
    /// map means "inherit". Skipped on serialize when unset so models
    /// that never pin it stay clean.
    #[serde(default, skip_serializing_if = "ThinkingParams::is_empty")]
    pub thinking_params: ThinkingParams,
    /// Per-model wire-API selector (implementation note):
    /// which OpenAI-compatible endpoint to POST — `/chat/completions` vs
    /// `/responses`. A concrete model value wins over provider-level defaults,
    /// learned state, and conservative defaults. `auto` falls through to those
    /// lower layers. Native Anthropic ignores this. Skipped on serialize when
    /// `auto` so configs that never pin it stay clean and survive a `/models`
    /// refresh (a pinned value is preserved by
    /// [`merge_fetched_models`]).
    #[serde(default, skip_serializing_if = "WireApi::is_auto")]
    pub wire_api: WireApi,
    /// Free-form metadata the `/models` endpoint returned but we don't
    /// model explicitly. Preserved verbatim so re-saving doesn't drop
    /// fields the user (or provider) cares about.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,

    /// Typed model capabilities. New provider parsers should populate this
    /// rather than adding more one-off flags.
    #[serde(default, skip_serializing_if = "ModelCapabilities::is_empty")]
    pub capabilities: ModelCapabilities,

    /// Raw upstream model metadata preserved separately from Cockpit-owned
    /// typed projections. `extra` remains as legacy compatibility.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub provider_metadata: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySource {
    Live,
    Manual,
    Fallback,
    Legacy,
    ProviderRule,
    LegacySynthesized,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Supported,
    Unsupported,
    RequiresEntitlement,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityValue {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ReasoningEffortRequestMapping {
    JsonField {
        field: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        values: BTreeMap<String, Value>,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReasoningEffortCapability {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<CapabilityValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_mapping: Option<ReasoningEffortRequestMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CapabilitySource>,
}

impl ReasoningEffortCapability {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
            && self.default.is_none()
            && self.request_mapping.is_none()
            && self.source.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientSideToolsCapability {
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub status: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CapabilitySource>,
}

impl CapabilityStatus {
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

impl ClientSideToolsCapability {
    pub fn is_empty(&self) -> bool {
        self.status.is_unknown() && self.entitlement.is_none() && self.source.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelCapabilities {
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub tool_calling: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub reasoning: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub structured_outputs: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ReasoningEffortCapability>,
    #[serde(default, skip_serializing_if = "ClientSideToolsCapability::is_empty")]
    pub client_side_tools: ClientSideToolsCapability,
}

impl ModelCapabilities {
    pub fn is_empty(&self) -> bool {
        self.tool_calling.is_unknown()
            && self.images.is_none()
            && self.context_tokens.is_none()
            && self.reasoning.is_unknown()
            && self.structured_outputs.is_unknown()
            && self
                .reasoning_effort
                .as_ref()
                .is_none_or(ReasoningEffortCapability::is_empty)
            && self.client_side_tools.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderCapabilities {
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub tool_calling: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub reasoning: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub structured_outputs: CapabilityStatus,
    #[serde(default, skip_serializing_if = "ClientSideToolsCapability::is_empty")]
    pub client_side_tools: ClientSideToolsCapability,
}

impl ProviderCapabilities {
    pub fn is_empty(&self) -> bool {
        self.tool_calling.is_unknown()
            && self.images.is_none()
            && self.context_tokens.is_none()
            && self.reasoning.is_unknown()
            && self.structured_outputs.is_unknown()
            && self.client_side_tools.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelFetchStatusKind {
    Live,
    FailedKeptExisting,
    Fallback,
    Unsupported,
    AuthFailed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelFetchSource {
    Live,
    Fallback,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelFetchStatus {
    pub status: ModelFetchStatusKind,
    pub at: DateTime<Utc>,
    pub source: ModelFetchSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Origin of a persisted provider model catalog.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderModelCatalog {
    /// The provider's live `/models` endpoint supplied the current catalog.
    #[default]
    Live,
    /// The persisted catalog came from Cockpit's built-in Codex fallback list.
    CodexFallback,
}

impl ProviderModelCatalog {
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderModelFetchDisplayState {
    Live,
    Fallback,
    Preserved,
    Failed,
    AuthFailed,
    Unsupported,
}

impl ProviderModelFetchDisplayState {
    pub const ALL: [Self; 6] = [
        Self::Live,
        Self::Fallback,
        Self::Preserved,
        Self::Failed,
        Self::AuthFailed,
        Self::Unsupported,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "Live",
            Self::Fallback => "Fallback",
            Self::Preserved => "Preserved",
            Self::Failed => "Failed",
            Self::AuthFailed => "AuthFailed",
            Self::Unsupported => "Unsupported",
        }
    }
}

pub fn provider_model_fetch_display_state(entry: &ProviderEntry) -> ProviderModelFetchDisplayState {
    match entry.last_model_fetch.as_ref().map(|status| status.status) {
        Some(ModelFetchStatusKind::Live) => ProviderModelFetchDisplayState::Live,
        Some(ModelFetchStatusKind::Fallback) => ProviderModelFetchDisplayState::Fallback,
        Some(ModelFetchStatusKind::FailedKeptExisting) if entry.models.is_empty() => {
            ProviderModelFetchDisplayState::Failed
        }
        Some(ModelFetchStatusKind::FailedKeptExisting) => ProviderModelFetchDisplayState::Preserved,
        Some(ModelFetchStatusKind::AuthFailed) => ProviderModelFetchDisplayState::AuthFailed,
        Some(ModelFetchStatusKind::Unsupported) => ProviderModelFetchDisplayState::Unsupported,
        None if matches!(entry.model_catalog, ProviderModelCatalog::CodexFallback) => {
            ProviderModelFetchDisplayState::Fallback
        }
        None => ProviderModelFetchDisplayState::Live,
    }
}

pub fn model_fetch_reason_display(reason: Option<&str>) -> String {
    let Some(reason) = reason else {
        return "—".to_string();
    };
    let reason = redact_model_fetch_reason(reason);
    if reason.trim().is_empty() {
        "—".to_string()
    } else {
        reason
    }
}

pub fn provider_model_fetch_reason_display(entry: &ProviderEntry) -> String {
    model_fetch_reason_display(
        entry
            .last_model_fetch
            .as_ref()
            .and_then(|status| status.reason.as_deref()),
    )
}

pub fn format_model_fetch_age(fetched_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    let Some(fetched_at) = fetched_at else {
        return "never".to_string();
    };
    let delta = now.signed_duration_since(fetched_at);
    if delta.num_seconds() < 60 {
        return "just now".to_string();
    }
    if delta.num_minutes() < 60 {
        let n = delta.num_minutes();
        return format!("{n} minute{} ago", if n == 1 { "" } else { "s" });
    }
    if delta.num_hours() < 24 {
        let n = delta.num_hours();
        return format!("{n} hour{} ago", if n == 1 { "" } else { "s" });
    }
    if delta.num_hours() < 48 {
        return "yesterday".to_string();
    }
    let n = delta.num_days();
    format!("{n} days ago")
}

/// Which OpenAI-compatible wire endpoint a model speaks.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WireApi {
    /// No explicit pin: name-detect, then self-heal via the fallback. The
    /// default for every model so existing configs are unaffected.
    #[default]
    Auto,
    /// Force the Chat Completions endpoint (`/chat/completions`).
    Completions,
    /// Force the Responses endpoint (`/responses`).
    Responses,
}

impl WireApi {
    /// True for the `Auto` (unpinned) variant — the serde skip predicate and
    /// the resolver's "fall through to auto-detect" test.
    pub fn is_auto(&self) -> bool {
        matches!(self, WireApi::Auto)
    }

    /// Conservative name auto-detect for `Auto` models: a model id beginning
    /// with `gpt-5` (case-insensitive) is responses-only → [`WireApi::Responses`];
    /// everything else → [`WireApi::Completions`] (today's default for every
    /// existing model). Deliberately minimal — the error-driven fallback
    /// corrects any miss, so this list never tries to enumerate every model.
    pub fn detect(model_id: &str) -> WireApi {
        // Byte-compare (panic-free across UTF-8 boundaries; the prefix is pure
        // ASCII so byte equality is exactly the case-insensitive `str` match).
        if model_id.len() >= 5 && model_id.as_bytes()[..5].eq_ignore_ascii_case(b"gpt-5") {
            WireApi::Responses
        } else {
            WireApi::Completions
        }
    }

    /// Provider-aware conservative default. Only the built-in OpenAI provider
    /// keeps the `gpt-5*` → Responses heuristic; arbitrary OpenAI-compatible
    /// endpoints default to Chat Completions.
    pub fn detect_for_provider(provider_id: &str, model_id: &str) -> WireApi {
        match provider_id {
            "openai" => Self::detect(model_id),
            "codex-oauth" | "grok" | "grok-oauth" => WireApi::Responses,
            _ => WireApi::Completions,
        }
    }

    /// The opposite concrete endpoint — the one the error-driven fallback
    /// retries. `Auto` is never the *resolved* endpoint (the resolver always
    /// produces a concrete value first), so it maps to `Responses` defensively.
    pub fn opposite(self) -> WireApi {
        match self {
            WireApi::Responses => WireApi::Completions,
            WireApi::Completions | WireApi::Auto => WireApi::Responses,
        }
    }
}

/// `true` when `base_url`'s host is the native Anthropic Messages endpoint
/// (`api.anthropic.com`). Host-based rather than provider-id-based so renamed
/// Anthropic providers still route natively, while Claude served by
/// OpenRouter/Copilot/etc. remains OpenAI-compatible. Unparseable URLs are
/// never native.
pub fn is_anthropic_native_base_url(base_url: &str) -> bool {
    reqwest::Url::parse(base_url)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h.eq_ignore_ascii_case("api.anthropic.com"))
        })
        .unwrap_or(false)
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// How a freshly fetched `/models` list treats existing configured models that
/// are absent from the upstream response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelMergePolicy {
    /// Keep unlisted configured models. This is the default safe refresh policy.
    KeepUnlisted,
    /// Drop unlisted configured models.
    RemoveUnlisted,
}

pub const KNOWN_FRONTIER_MODEL_IDS: &[&str] = &[
    "claude-fable-5",
    "claude-opus-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "glm-5.2",
    "gpt-5.4",
    "gpt-5.5",
    "gpt-5.6",
    "grok-4.5",
];

/// The standard first-party provider **templates** whose models receive the
/// known-frontier defaults ([`apply_known_frontier_model_defaults`]). These
/// endpoints are known to serve the frontier ids verbatim and to prompt-cache,
/// so the defaults are correct there; the same id served through an
/// aggregator (OpenRouter/Copilot/…) is left alone. Matched against a
/// provider's persisted [`ProviderEntry::template`] identity (with a map-key
/// fallback via [`ProviderEntry::effective_template`]), **not** its config-map
/// key — so a renamed connection like `anthropic-work` still gets the defaults.
pub const FRONTIER_DEFAULT_PROVIDER_IDS: &[&str] =
    &["anthropic", "codex-oauth", "grok-oauth", "openai", "z-ai"];

pub fn is_known_frontier_model_id(model_id: &str) -> bool {
    KNOWN_FRONTIER_MODEL_IDS.contains(&model_id)
}

/// Whether a provider `template` id gates the known-frontier defaults
/// ([`FRONTIER_DEFAULT_PROVIDER_IDS`]). Callers pass the provider's effective
/// template identity ([`ProviderEntry::effective_template`]), not the config-map
/// key, so renaming e.g. `anthropic` to `anthropic-work` keeps the defaults.
pub fn is_frontier_default_provider_template(template: &str) -> bool {
    FRONTIER_DEFAULT_PROVIDER_IDS.contains(&template)
}

/// Merge a freshly-fetched `/models` list into an existing model list,
/// preserving manually-added entries.
///
/// Fetched entries are emitted in upstream order. Existing entries that are not
/// present upstream are either appended or dropped according to the merge
/// policy. Dedupe is by `id`: when a fetched entry matches an existing manual
/// or configured entry, the fetched metadata is used as the base and user-owned
/// fields are carried over.
///
/// User-owned per-model settings survive a `/models` refresh: when a refetched
/// entry collides with an existing entry's id, the fetched metadata is used as
/// the base but the existing entry's overrides are carried over. That includes
/// favorites, manual markers, policy fields, endpoint pins,
/// cache/context/shrink/timeout, auto-prune, backup, mode, inline-think,
/// repair/recovery settings, and thinking params — plus, for manual entries,
/// the hand-set display `name` and `context_length`.
/// The known-frontier defaults ([`apply_known_frontier_model_defaults`]:
/// `mode: frontier`, `auto_prune: off`, `cache: ephemeral`) are applied only to
/// ids that are **newly discovered** by this fetch — i.e. absent from
/// `existing` — and only on the standard first-party providers
/// ([`FRONTIER_DEFAULT_PROVIDER_IDS`]) for ids on the product-approved exact-id
/// list ([`KNOWN_FRONTIER_MODEL_IDS`]). A previously-configured known id is
/// never re-defaulted, so a user who clears e.g. `mode` back to inherit keeps
/// that state across refreshes.
///
/// Policy-aware merge helper for CLI and TUI refreshes. `template` is the
/// refreshed provider's effective template identity
/// ([`ProviderEntry::effective_template`]) and only scopes the known-frontier
/// defaults; pass `None` for providers that map to no known template.
pub fn merge_fetched_models_with_policy(
    template: Option<&str>,
    existing: &[ModelEntry],
    fetched: Vec<ModelEntry>,
    policy: ModelMergePolicy,
) -> Vec<ModelEntry> {
    let mut merged = Vec::new();
    for mut m in fetched {
        if let Some(prev) = existing.iter().find(|e| e.id == m.id) {
            preserve_model_overrides(prev, &mut m);
        } else {
            // Only genuinely newly-discovered ids receive the known-frontier
            // defaults. A previously-configured id keeps whatever the user
            // left it as — including an intentionally-cleared `mode` back to
            // inherit — so a `/models` refresh never re-pins it.
            apply_known_frontier_model_defaults(template, &mut m);
        }
        merged.push(m);
    }
    for old in existing {
        if merged.iter().any(|m| m.id == old.id) {
            continue;
        }
        match policy {
            ModelMergePolicy::KeepUnlisted => merged.push(old.clone()),
            ModelMergePolicy::RemoveUnlisted if old.manual => merged.push(old.clone()),
            ModelMergePolicy::RemoveUnlisted => {}
        }
    }
    merged
}

/// Default a known frontier model on a standard first-party provider to the
/// product-approved frontier settings: `mode: frontier` (top-tier steering),
/// `auto_prune: off` and `cache: ephemeral` (these endpoints all prompt-cache,
/// so automatic pruning would bust a real upstream cache). Each field is only
/// filled in when still unset, so user-pinned values always win. Applied on
/// `/models` merge and on manual model add (z.ai has no `/models` endpoint).
pub fn apply_known_frontier_model_defaults(template: Option<&str>, model: &mut ModelEntry) {
    let Some(template) = template else {
        return;
    };
    if !is_frontier_default_provider_template(template) || !is_known_frontier_model_id(&model.id) {
        return;
    }
    if model.mode.is_none() {
        model.mode = Some(LlmMode::Frontier);
    }
    if model.auto_prune.is_none() {
        model.auto_prune = Some(false);
    }
    if model.cache.is_none() {
        model.cache = Some(CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: default_cache_ttl_secs(),
        });
    }
}

/// Carry an existing entry's user-owned fields onto a colliding fetched entry
/// (which is used as the base). Favorites, manual markers, policy fields,
/// endpoint pins, cache/context/shrink/timeout, auto-prune, backup, mode,
/// inline-think, repair/recovery settings, thinking params, and preserved
/// metadata all survive. For **manual** entries the hand-set display `name`
/// and `context_length` are preserved too (when set) — those are the only
/// metadata fields the UI lets you hand-edit, so a later upstream collision
/// must not silently overwrite them. Non-manual (fetched) entries keep taking
/// upstream `name`/`context_length` on refresh, which is the correct behavior.
fn preserve_model_overrides(existing: &ModelEntry, fetched: &mut ModelEntry) {
    fetched.favorite = existing.favorite;
    fetched.manual = existing.manual;
    // Manual entries own their hand-set display name and context window; keep
    // them (when set) rather than letting the fetched metadata clobber them.
    if existing.manual {
        if existing.name.is_some() {
            fetched.name = existing.name.clone();
        }
        if existing.context_length.is_some() {
            fetched.context_length = existing.context_length;
        }
    }
    if existing.trust.is_some() {
        fetched.trust = existing.trust;
    }
    if existing.location.is_some() {
        fetched.location = existing.location;
    }
    if existing.quality_rank.is_some() {
        fetched.quality_rank = existing.quality_rank;
    }
    if existing.cost_rank.is_some() {
        fetched.cost_rank = existing.cost_rank;
    }
    if existing.subagent_invokable.is_some() {
        fetched.subagent_invokable = existing.subagent_invokable;
    }
    if !existing.availability.is_empty() {
        fetched.availability = existing.availability.clone();
    }
    if !existing.wire_api.is_auto() {
        fetched.wire_api = existing.wire_api;
    }
    if existing.cache.is_some() {
        fetched.cache = existing.cache.clone();
    }
    if existing.shrink.is_some() {
        fetched.shrink = existing.shrink.clone();
    }
    if existing.context.is_some() {
        fetched.context = existing.context.clone();
    }
    if existing.auto_prune.is_some() {
        fetched.auto_prune = existing.auto_prune;
    }
    if existing.timeout.is_some() {
        fetched.timeout = existing.timeout.clone();
    }
    if existing.backup.is_some() {
        fetched.backup = existing.backup.clone();
    }
    if existing.mode.is_some() {
        fetched.mode = existing.mode;
    }
    if existing.inline_think.is_some() {
        fetched.inline_think = existing.inline_think;
    }
    if existing.hint_tool_call_corrections.is_some() {
        fetched.hint_tool_call_corrections = existing.hint_tool_call_corrections;
    }
    if existing.text_embedded_recovery.is_some() {
        fetched.text_embedded_recovery = existing.text_embedded_recovery;
    }
    if !existing.thinking_params.is_empty() {
        fetched.thinking_params = existing.thinking_params.clone();
    }
    if !existing.extra.is_empty() {
        for (key, value) in &existing.extra {
            fetched.extra.insert(key.clone(), value.clone());
            fetched
                .provider_metadata
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    if !existing.capabilities.is_empty() {
        fetched.capabilities = existing.capabilities.clone();
    }
    if !existing.provider_metadata.is_empty() {
        for (key, value) in &existing.provider_metadata {
            fetched.provider_metadata.insert(key.clone(), value.clone());
            fetched.extra.insert(key.clone(), value.clone());
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ThinkingMode {
    Off,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inputs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OnUnlistedModelsFetch {
    Ask,
    Keep,
    Remove,
}

impl ProviderEntry {
    /// Display label: the user-set `name`, falling back to the id key.
    // Provider-list display accessor; retained for the providers UI.
    #[allow(dead_code)]
    pub fn label<'a>(&'a self, id: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(id)
    }

    /// The provider's effective template identity, used to key the
    /// known-frontier defaults. Returns the persisted [`Self::template`] when
    /// present; otherwise falls back to the config-map `key` when that key
    /// itself names a known [`ProviderTemplate`](crate::providers) — which
    /// recovers pre-`template`-field configs that were never renamed (e.g. a
    /// stock `anthropic`). A renamed pre-field config, or a custom provider,
    /// resolves to `None`.
    pub fn effective_template<'a>(&'a self, key: &'a str) -> Option<&'a str> {
        match self.template.as_deref() {
            Some(t) => Some(t),
            None if crate::providers::template_by_id(key).is_some() => Some(key),
            None => None,
        }
    }

    pub fn mark_model_fetch_success(&mut self, catalog: ProviderModelCatalog) {
        let (status, source) = match catalog {
            ProviderModelCatalog::Live => (ModelFetchStatusKind::Live, ModelFetchSource::Live),
            ProviderModelCatalog::CodexFallback => {
                (ModelFetchStatusKind::Fallback, ModelFetchSource::Fallback)
            }
        };
        self.last_model_fetch = Some(ModelFetchStatus {
            status,
            at: Utc::now(),
            source,
            reason: None,
        });
    }

    pub fn mark_model_fetch_unsupported(&mut self) {
        self.last_model_fetch = Some(ModelFetchStatus {
            status: ModelFetchStatusKind::Unsupported,
            at: Utc::now(),
            source: ModelFetchSource::None,
            reason: None,
        });
    }

    pub fn mark_model_fetch_fallback(&mut self, reason: impl Into<String>) {
        self.last_model_fetch = Some(ModelFetchStatus {
            status: ModelFetchStatusKind::Fallback,
            at: Utc::now(),
            source: ModelFetchSource::Fallback,
            reason: Some(redact_model_fetch_reason(reason)),
        });
    }

    pub fn mark_model_fetch_failed_kept_existing(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        let status = if is_model_fetch_auth_failure(&reason) {
            ModelFetchStatusKind::AuthFailed
        } else {
            ModelFetchStatusKind::FailedKeptExisting
        };
        self.last_model_fetch = Some(ModelFetchStatus {
            status,
            at: Utc::now(),
            source: ModelFetchSource::Live,
            reason: Some(redact_model_fetch_reason(reason)),
        });
    }
}

fn is_model_fetch_auth_failure(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains(" returned 401")
        || lower.contains(" returned 403")
        || lower.contains("credentials rejected")
        || lower.contains("subscription auth")
        || lower.contains("authorization for provider")
        || lower.contains("requires an official github token")
        || lower.contains("missing chatgpt-account-id")
}

pub fn redact_model_fetch_reason(reason: impl Into<String>) -> String {
    redact_fetch_status_reason(reason.into())
}

fn redact_fetch_status_reason(reason: String) -> String {
    let collapsed = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = Vec::new();
    let mut redact_next = false;
    for part in collapsed.split(' ') {
        if redact_next {
            out.push("[redacted]".to_string());
            redact_next = false;
            continue;
        }

        let trimmed = part.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']' | '{' | '}' | ':'
            )
        });
        let lower = trimmed.to_ascii_lowercase();
        if lower == "bearer" || lower == "authorization:" || lower == "authorization" {
            out.push(part.to_string());
            redact_next = true;
            continue;
        }

        if looks_like_secret(trimmed) {
            out.push(part.replace(trimmed, "[redacted]"));
        } else {
            out.push(part.to_string());
        }
    }
    out.join(" ").chars().take(240).collect()
}

fn looks_like_secret(value: &str) -> bool {
    value.len() >= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[allow(dead_code)]
pub fn project_reasoning_effort_to_thinking_modes(
    capability: &ReasoningEffortCapability,
) -> Vec<ThinkingMode> {
    let mut out = Vec::new();
    for value in capability.values.iter().map(|v| v.value.as_str()) {
        let Some(mode) = legacy_thinking_mode_for_effort(value) else {
            continue;
        };
        if !out.contains(&mode) {
            out.push(mode);
        }
    }
    out
}

fn legacy_thinking_mode_for_effort(value: &str) -> Option<ThinkingMode> {
    match value.to_ascii_lowercase().as_str() {
        "off" | "none" | "disabled" => Some(ThinkingMode::Off),
        "low" => Some(ThinkingMode::Low),
        "medium" => Some(ThinkingMode::Medium),
        "high" => Some(ThinkingMode::High),
        _ => None,
    }
}

fn reasoning_effort_supports_value(capability: &ReasoningEffortCapability, value: &str) -> bool {
    capability
        .values
        .iter()
        .any(|candidate| candidate.value == value)
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ModelOptimization {
    Quality,
    Cost,
    #[default]
    Balanced,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredModelCapability {
    ToolCalling,
    Images,
    Reasoning,
    StructuredOutputs,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelPolicySelector<'a> {
    Exact(&'a str),
    Trust(ModelTrust),
    Category(&'a str),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ModelPolicyRequest<'a> {
    pub selector: ModelPolicySelector<'a>,
    pub trust: Option<ModelTrust>,
    pub required_capabilities: Vec<RequiredModelCapability>,
    pub min_context_tokens: Option<u32>,
    pub require_subagent_invokable: bool,
    pub trusted_only: bool,
    pub optimize: ModelOptimization,
    pub role: Option<&'a str>,
    pub agent: Option<&'a str>,
}

#[allow(dead_code)]
impl<'a> ModelPolicyRequest<'a> {
    pub fn subagent_category(category: &'a str) -> Self {
        Self {
            selector: ModelPolicySelector::Category(category),
            trust: None,
            required_capabilities: Vec::new(),
            min_context_tokens: None,
            require_subagent_invokable: true,
            trusted_only: false,
            optimize: ModelOptimization::default(),
            role: Some(category),
            agent: None,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModelPolicy {
    pub provider: String,
    pub model: String,
    pub trust: ModelTrust,
    pub location: Option<ModelLocation>,
    pub quality_rank: i64,
    pub cost_rank: i64,
}

#[allow(dead_code)]
impl ResolvedModelPolicy {
    pub fn selector(&self) -> String {
        format!("{}:{}", self.provider, self.model)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelPolicyError {
    MalformedSelector(String),
    UnknownProvider(String),
    UnknownModel {
        provider: String,
        model: String,
    },
    NotSubagentInvokable {
        provider: String,
        model: String,
    },
    Untrusted {
        provider: String,
        model: String,
    },
    MissingCapability {
        provider: String,
        model: String,
        capability: RequiredModelCapability,
    },
    ContextTooSmall {
        provider: String,
        model: String,
        min: u32,
        actual: Option<u32>,
    },
    RestrictedByAvailability {
        provider: String,
        model: String,
    },
    NoEligibleModel(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveModelCapabilities {
    pub tool_calling: CapabilityStatus,
    pub images: Option<bool>,
    pub context_tokens: Option<u32>,
    pub reasoning: CapabilityStatus,
    pub structured_outputs: CapabilityStatus,
}

#[allow(dead_code)]
fn parse_policy_selector(selector: &str) -> Result<(String, String), ModelPolicyError> {
    let selector = selector.trim();
    if let Some((provider, model)) = selector.split_once(':') {
        if provider.trim().is_empty() || model.trim().is_empty() {
            return Err(ModelPolicyError::MalformedSelector(selector.to_string()));
        }
        return Ok((provider.trim().to_string(), model.trim().to_string()));
    }
    if let Some((provider, model)) = crate::config::provider::split_provider_model(selector) {
        return Ok((provider, model));
    }
    Err(ModelPolicyError::MalformedSelector(selector.to_string()))
}

#[allow(dead_code)]
fn capability_satisfied(
    caps: &EffectiveModelCapabilities,
    required: RequiredModelCapability,
) -> bool {
    match required {
        RequiredModelCapability::ToolCalling => {
            matches!(caps.tool_calling, CapabilityStatus::Supported)
        }
        RequiredModelCapability::Images => caps.images == Some(true),
        RequiredModelCapability::Reasoning => matches!(caps.reasoning, CapabilityStatus::Supported),
        RequiredModelCapability::StructuredOutputs => {
            matches!(caps.structured_outputs, CapabilityStatus::Supported)
        }
    }
}

#[allow(dead_code)]
fn sort_policy_candidates(candidates: &mut [ResolvedModelPolicy], optimize: ModelOptimization) {
    candidates.sort_by(|a, b| {
        let rank = match optimize {
            ModelOptimization::Quality | ModelOptimization::Balanced => b
                .quality_rank
                .cmp(&a.quality_rank)
                .then_with(|| a.cost_rank.cmp(&b.cost_rank)),
            ModelOptimization::Cost => a
                .cost_rank
                .cmp(&b.cost_rank)
                .then_with(|| b.quality_rank.cmp(&a.quality_rank)),
        };
        rank.then_with(|| b.trust.is_trusted().cmp(&a.trust.is_trusted()))
            .then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.model.cmp(&b.model))
    });
}

#[allow(dead_code)]
fn policy_selector_label(request: &ModelPolicyRequest<'_>) -> String {
    match request.selector {
        ModelPolicySelector::Exact(selector) => selector.to_string(),
        ModelPolicySelector::Trust(trust) => format!("{trust:?}"),
        ModelPolicySelector::Category(category) => category.to_string(),
    }
}

impl ProvidersConfig {
    /// Resolve the effective prompt-cache config for `(provider, model)`:
    /// the model-level override if present, else the provider-level
    /// config, else the default (`none`). Used by the cache-cold
    /// predicate (GOALS §10).
    pub fn resolve_cache(&self, provider: &str, model: &str) -> CacheConfig {
        let Some(entry) = self.providers.get(provider) else {
            return CacheConfig::default();
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.cache.clone())
            .unwrap_or_else(|| entry.cache.clone())
    }

    /// Resolve the effective auto-prune master switch for
    /// `(provider, model)`: the model-level override if present, else the
    /// provider-level override, else on. `false` turns the automatic prune
    /// trigger off entirely (both the cache-cold and the ctx%-threshold
    /// branch); manual `/prune` is unaffected.
    pub fn resolve_auto_prune(&self, provider: &str, model: &str) -> bool {
        let Some(entry) = self.providers.get(provider) else {
            return true;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.auto_prune)
            .or(entry.auto_prune)
            .unwrap_or(true)
    }

    /// Resolve the effective delegation-shrink config for
    /// `(provider, model)`: the model-level override if present, else the
    /// provider-level config, else the default (`prune`, 30s margin).
    /// Used by the delegation-shrink decision
    /// (implementation note).
    pub fn resolve_shrink(&self, provider: &str, model: &str) -> ShrinkConfig {
        let Some(entry) = self.providers.get(provider) else {
            return ShrinkConfig::default();
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.shrink.clone())
            .unwrap_or_else(|| entry.shrink.clone())
    }

    /// Resolve the effective context-threshold config for
    /// `(provider, model)`: the model-level override if present, else the
    /// provider-level config, else the built-in defaults (80/50/30). Drives
    /// the auto-compact + ctx%-threshold auto-prune triggers
    /// (implementation note).
    pub fn resolve_context(&self, provider: &str, model: &str) -> ContextConfig {
        let Some(entry) = self.providers.get(provider) else {
            return ContextConfig::default();
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.context.clone())
            .unwrap_or_else(|| entry.context.clone())
    }

    /// Resolve the effective inference-stream wait-threshold config for
    /// `(provider, model)`: the model-level override if present, else the
    /// provider-level config, else the built-in defaults (120s TTFT, 90s
    /// idle). Drives the slow-stream warning in
    /// [`crate::engine::model::Model::complete_captured`]
    /// (implementation note).
    pub fn resolve_timeout(&self, provider: &str, model: &str) -> TimeoutConfig {
        let Some(entry) = self.providers.get(provider) else {
            return TimeoutConfig::default();
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.timeout.clone())
            .unwrap_or_else(|| entry.timeout.clone())
    }

    /// Resolve the effective backup-model fallback for `(provider, model)`:
    /// the model-level override if present, else the provider-level config,
    /// else `None` (no fallback → hard-fail per the inference-timeout work).
    /// Drives the per-turn primary-first fallback in the driver
    /// (implementation note). The returned reference may
    /// name a *different* provider than the one passed in.
    pub fn resolve_backup(&self, provider: &str, model: &str) -> Option<BackupConfig> {
        let entry = self.providers.get(provider)?;
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.backup.clone())
            .or_else(|| entry.backup.clone())
    }

    #[allow(dead_code)]
    pub fn model_entry(&self, provider: &str, model: &str) -> Option<&ModelEntry> {
        self.providers
            .get(provider)?
            .models
            .iter()
            .find(|entry| entry.id == model)
    }

    /// Resolve product trust for `(provider, model)`: model override,
    /// provider default, then conservative `untrusted`.
    pub fn resolve_trust(&self, provider: &str, model: &str) -> ModelTrust {
        let Some(entry) = self.providers.get(provider) else {
            return ModelTrust::Untrusted;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.trust)
            .or(entry.trust)
            .unwrap_or(ModelTrust::Untrusted)
    }

    #[allow(dead_code)]
    pub fn resolve_location(&self, provider: &str, model: &str) -> Option<ModelLocation> {
        let entry = self.providers.get(provider)?;
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.location)
            .or(entry.location)
    }

    #[allow(dead_code)]
    pub fn resolve_quality_rank(&self, provider: &str, model: &str) -> i64 {
        let Some(entry) = self.providers.get(provider) else {
            return 0;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.quality_rank)
            .or(entry.quality_rank)
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn resolve_cost_rank(&self, provider: &str, model: &str) -> i64 {
        let Some(entry) = self.providers.get(provider) else {
            return 0;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.cost_rank)
            .or(entry.cost_rank)
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn resolve_subagent_invokable(&self, provider: &str, model: &str) -> bool {
        let Some(entry) = self.providers.get(provider) else {
            return false;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.subagent_invokable)
            .or(entry.subagent_invokable)
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn resolve_capabilities(&self, provider: &str, model: &str) -> EffectiveModelCapabilities {
        let Some(entry) = self.providers.get(provider) else {
            return EffectiveModelCapabilities::default();
        };
        let model_entry = entry.models.iter().find(|m| m.id == model);
        let model_caps = model_entry.map(|m| &m.capabilities);
        let provider_caps = &entry.capabilities;
        let reasoning = model_caps
            .map(|c| c.reasoning)
            .filter(|s| !s.is_unknown())
            .unwrap_or(provider_caps.reasoning);
        let reasoning = if reasoning.is_unknown()
            && model_entry.is_some_and(|m| {
                !m.thinking_modes.is_empty()
                    || m.capabilities
                        .reasoning_effort
                        .as_ref()
                        .is_some_and(|cap| !cap.values.is_empty())
            }) {
            CapabilityStatus::Supported
        } else {
            reasoning
        };
        EffectiveModelCapabilities {
            tool_calling: model_caps
                .map(|c| c.tool_calling)
                .filter(|s| !s.is_unknown())
                .unwrap_or(provider_caps.tool_calling),
            images: model_caps
                .and_then(|c| c.images)
                .or(provider_caps.images)
                .or_else(|| model_entry.and_then(|m| m.inputs.as_ref()?.images)),
            context_tokens: model_caps
                .and_then(|c| c.context_tokens)
                .or(provider_caps.context_tokens)
                .or_else(|| model_entry.and_then(|m| m.context_length)),
            reasoning,
            structured_outputs: model_caps
                .map(|c| c.structured_outputs)
                .filter(|s| !s.is_unknown())
                .unwrap_or(provider_caps.structured_outputs),
        }
    }

    #[allow(dead_code)]
    pub fn resolve_model_policy(
        &self,
        request: &ModelPolicyRequest<'_>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        match request.selector {
            ModelPolicySelector::Exact(selector) => {
                let (provider, model) = parse_policy_selector(selector)?;
                self.resolve_exact_policy(&provider, &model, request)
            }
            ModelPolicySelector::Trust(trust) => {
                self.resolve_best_policy_candidate(request, Some(trust), None)
            }
            ModelPolicySelector::Category(category) => {
                if let Some(default) = self.category_defaults.get(category)
                    && let Ok(resolved) =
                        self.resolve_exact_policy(&default.provider, &default.model, request)
                {
                    return Ok(resolved);
                }
                self.resolve_best_policy_candidate(request, request.trust, Some(category))
            }
        }
    }

    #[allow(dead_code)]
    fn resolve_exact_policy(
        &self,
        provider: &str,
        model: &str,
        request: &ModelPolicyRequest<'_>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        let Some(entry) = self.providers.get(provider) else {
            return Err(ModelPolicyError::UnknownProvider(provider.to_string()));
        };
        let Some(model_entry) = entry.models.iter().find(|m| m.id == model) else {
            return Err(ModelPolicyError::UnknownModel {
                provider: provider.to_string(),
                model: model.to_string(),
            });
        };
        self.check_policy_candidate(provider, model_entry, request)?;
        Ok(self.resolved_policy(provider, model))
    }

    #[allow(dead_code)]
    fn resolve_best_policy_candidate(
        &self,
        request: &ModelPolicyRequest<'_>,
        trust_filter: Option<ModelTrust>,
        category: Option<&str>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        let mut candidates = Vec::new();
        for (provider, entry) in &self.providers {
            for model in &entry.models {
                let effective_trust_filter = trust_filter.or(request.trust);
                if effective_trust_filter
                    .is_some_and(|trust| self.resolve_trust(provider, &model.id) != trust)
                {
                    continue;
                }
                if category.is_some()
                    && !entry
                        .availability
                        .permits(category, request.role, request.agent)
                {
                    continue;
                }
                if category.is_some()
                    && !model
                        .availability
                        .permits(category, request.role, request.agent)
                {
                    continue;
                }
                if self
                    .check_policy_candidate(provider, model, request)
                    .is_ok()
                {
                    candidates.push(self.resolved_policy(provider, &model.id));
                }
            }
        }
        sort_policy_candidates(&mut candidates, request.optimize);
        candidates
            .into_iter()
            .next()
            .ok_or_else(|| ModelPolicyError::NoEligibleModel(policy_selector_label(request)))
    }

    #[allow(dead_code)]
    fn check_policy_candidate(
        &self,
        provider: &str,
        model: &ModelEntry,
        request: &ModelPolicyRequest<'_>,
    ) -> Result<(), ModelPolicyError> {
        if request.require_subagent_invokable
            && !self.resolve_subagent_invokable(provider, &model.id)
        {
            return Err(ModelPolicyError::NotSubagentInvokable {
                provider: provider.to_string(),
                model: model.id.clone(),
            });
        }
        if request.trusted_only && !self.resolve_trust(provider, &model.id).is_trusted() {
            return Err(ModelPolicyError::Untrusted {
                provider: provider.to_string(),
                model: model.id.clone(),
            });
        }
        if !self.providers.get(provider).is_some_and(|entry| {
            entry.availability.permits(
                match request.selector {
                    ModelPolicySelector::Category(category) => Some(category),
                    _ => None,
                },
                request.role,
                request.agent,
            )
        }) || !model.availability.permits(
            match request.selector {
                ModelPolicySelector::Category(category) => Some(category),
                _ => None,
            },
            request.role,
            request.agent,
        ) {
            return Err(ModelPolicyError::RestrictedByAvailability {
                provider: provider.to_string(),
                model: model.id.clone(),
            });
        }
        if request
            .trust
            .is_some_and(|trust| self.resolve_trust(provider, &model.id) != trust)
        {
            return Err(ModelPolicyError::NoEligibleModel(policy_selector_label(
                request,
            )));
        }
        let caps = self.resolve_capabilities(provider, &model.id);
        for capability in &request.required_capabilities {
            if !capability_satisfied(&caps, *capability) {
                return Err(ModelPolicyError::MissingCapability {
                    provider: provider.to_string(),
                    model: model.id.clone(),
                    capability: *capability,
                });
            }
        }
        if let Some(min) = request.min_context_tokens {
            let actual = caps.context_tokens;
            if actual.is_none_or(|actual| actual < min) {
                return Err(ModelPolicyError::ContextTooSmall {
                    provider: provider.to_string(),
                    model: model.id.clone(),
                    min,
                    actual,
                });
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn resolved_policy(&self, provider: &str, model: &str) -> ResolvedModelPolicy {
        ResolvedModelPolicy {
            provider: provider.to_string(),
            model: model.to_string(),
            trust: self.resolve_trust(provider, model),
            location: self.resolve_location(provider, model),
            quality_rank: self.resolve_quality_rank(provider, model),
            cost_rank: self.resolve_cost_rank(provider, model),
        }
    }

    /// Resolve how a leading inline `<think>…</think>` block is **classified**
    /// for `(provider, model)`: the per-model `inline_think` override → the
    /// per-provider `inline_think` override → the `global` default passed in
    /// by the caller (implementation note,
    /// implementation note). `None` at a scope
    /// means "inherit". An unknown provider/model resolves to `global`.
    ///
    /// `true` (ON, the default) — the block COUNTS AS THINKING: it is split
    /// off, shown as the "Thinking…" chip, and dropped from stored history so
    /// the reasoning never re-enters the model's context on a later turn.
    /// `false` (OFF) — the block COUNTS AS RESPONSE BODY: it stays inline as
    /// ordinary response text (no chip) and is carried forward like any other
    /// body text. (Reasoning delivered on the native `reasoning_content`
    /// channel is governed separately — always dropped from the wire — so this
    /// toggle is purely the inline-`<think>` classification switch.)
    pub fn resolve_inline_think(&self, provider: &str, model: &str, global: bool) -> bool {
        let Some(entry) = self.providers.get(provider) else {
            return global;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.inline_think)
            .or(entry.inline_think)
            .unwrap_or(global)
    }

    /// Resolve whether §12 tool-call corrections are surfaced to the model
    /// for `(provider, model)`: the per-model `hint_tool_call_corrections`
    /// override → the per-provider `hint_tool_call_corrections` override → the
    /// `global` default passed in by the caller
    /// (implementation note). `None` at a scope means
    /// "inherit". An unknown provider/model resolves to `global`. Mirrors
    /// [`Self::resolve_inline_think`] field-for-field.
    pub fn resolve_hint_tool_call_corrections(
        &self,
        provider: &str,
        model: &str,
        global: bool,
    ) -> bool {
        let Some(entry) = self.providers.get(provider) else {
            return global;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.hint_tool_call_corrections)
            .or(entry.hint_tool_call_corrections)
            .unwrap_or(global)
    }

    /// Resolve the text-embedded-recovery mode for `(provider, model)`: the
    /// per-model `text_embedded_recovery` override → the per-provider override →
    /// the `global` default passed in by the caller
    /// (implementation note). `None` at a scope means "inherit".
    /// An unknown provider/model resolves to `global`. Mirrors
    /// [`Self::resolve_inline_think`] field-for-field.
    pub fn resolve_text_embedded_recovery(
        &self,
        provider: &str,
        model: &str,
        global: TextEmbeddedRecovery,
    ) -> TextEmbeddedRecovery {
        let Some(entry) = self.providers.get(provider) else {
            return global;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.text_embedded_recovery)
            .or(entry.text_embedded_recovery)
            .unwrap_or(global)
    }

    /// Resolve the extra-request-body fragment for `(provider, model,
    /// mode)`: the per-model `thinking_params` map → the per-provider
    /// `thinking_params` map → the built-in default for the provider id
    /// (implementation note). This mirrors the
    /// `inline_think` three-tier precedence exactly. The first tier that
    /// defines *any* mapping wins for the whole lookup (so a per-model map
    /// that lists only some modes shadows the provider/built-in maps for
    /// every mode — explicit overrides are total, not per-mode merged);
    /// within the winning layer the fragment for `mode` is returned.
    /// `None` means "send no extra keys": either no layer maps anything,
    /// or the winning layer has no entry for the active mode. Nothing here
    /// is keyed on a specific provider string — DeepSeek's mapping lives
    /// entirely in the built-in defaults ([`crate::providers`]).
    pub fn resolve_thinking_params(
        &self,
        provider: &str,
        model: &str,
        mode: ThinkingMode,
    ) -> Option<Value> {
        let entry = self.providers.get(provider);
        // Top tier: a per-model map (if the model pins one).
        if let Some(m) = entry
            .and_then(|e| e.models.iter().find(|m| m.id == model))
            .filter(|m| !m.thinking_params.is_empty())
        {
            return m.thinking_params.get(mode).cloned();
        }
        // Middle tier: a per-provider map.
        if let Some(e) = entry.filter(|e| !e.thinking_params.is_empty()) {
            return e.thinking_params.get(mode).cloned();
        }
        // Bottom tier: the built-in default keyed by provider id.
        crate::providers::builtin_thinking_params(provider, mode)
    }

    /// Resolve the typed model-level reasoning-effort mapping for `(provider,
    /// model)`. When `selected` is absent, a provider-supplied default is used.
    /// Unknown selected values are ignored unless they are the advertised
    /// default, so stale config does not send unsupported request parameters.
    pub fn resolve_reasoning_effort_params(
        &self,
        provider: &str,
        model: &str,
        selected: Option<&str>,
    ) -> Option<Value> {
        let capability = self
            .providers
            .get(provider)?
            .models
            .iter()
            .find(|m| m.id == model)?
            .capabilities
            .reasoning_effort
            .as_ref()
            .filter(|capability| !capability.values.is_empty())?;
        let value = selected
            .filter(|selected| reasoning_effort_supports_value(capability, selected))
            .or(capability.default.as_deref())?;
        let ReasoningEffortRequestMapping::JsonField { field, values } =
            capability.request_mapping.as_ref()?;
        let mapped = values
            .get(value)
            .cloned()
            .unwrap_or_else(|| Value::String(value.to_string()));
        Some(Value::Object(Map::from_iter([(field.clone(), mapped)])))
    }

    pub fn has_reasoning_effort_capability(&self, provider: &str, model: &str) -> bool {
        self.providers
            .get(provider)
            .and_then(|entry| entry.models.iter().find(|m| m.id == model))
            .and_then(|model| model.capabilities.reasoning_effort.as_ref())
            .is_some_and(|capability| !capability.values.is_empty())
    }

    pub fn resolve_active_model_reasoning_params(&self) -> Option<Value> {
        let active = self.active_model.as_ref()?;
        if self.has_reasoning_effort_capability(&active.provider, &active.model) {
            return self.resolve_reasoning_effort_params(
                &active.provider,
                &active.model,
                active
                    .reasoning_effort
                    .as_ref()
                    .map(|effort| effort.value.as_str()),
            );
        }
        let mode = active.thinking_mode?;
        self.resolve_thinking_params(&active.provider, &active.model, mode)
    }

    #[allow(dead_code)]
    pub fn resolve_client_side_tools(
        &self,
        provider: &str,
        model: &str,
        provider_rule: Option<ClientSideToolsCapability>,
    ) -> ClientSideToolsCapability {
        let Some(entry) = self.providers.get(provider) else {
            return provider_rule.unwrap_or_default();
        };
        if let Some(model_capability) = entry
            .models
            .iter()
            .find(|m| m.id == model)
            .map(|m| &m.capabilities.client_side_tools)
            .filter(|capability| !capability.is_empty())
        {
            return model_capability.clone();
        }
        if !entry.capabilities.client_side_tools.is_empty() {
            return entry.capabilities.client_side_tools.clone();
        }
        provider_rule.unwrap_or_default()
    }

    pub fn resolve_effective_client_side_tools(
        &self,
        provider: &str,
        model: &str,
    ) -> ClientSideToolsCapability {
        let provider_rule = self.xai_multi_agent_client_side_tools_rule(provider, model);
        self.resolve_client_side_tools(provider, model, provider_rule)
    }

    pub fn xai_multi_agent_client_side_tools_rule(
        &self,
        provider: &str,
        model: &str,
    ) -> Option<ClientSideToolsCapability> {
        let entry = self.providers.get(provider)?;
        if !is_xai_grok_provider(provider, entry) {
            return None;
        }
        if !model.to_ascii_lowercase().contains("multi-agent") {
            return None;
        }
        Some(ClientSideToolsCapability {
            status: CapabilityStatus::RequiresEntitlement,
            entitlement: Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT.to_string()),
            source: Some(CapabilitySource::ProviderRule),
        })
    }

    /// Resolve the effective LLM mode for `(provider, model)`: the model
    /// `mode` override → the provider `mode` override → the persisted global
    /// `llm_mode` passed in by the caller. `None` at a scope means "inherit"
    /// (implementation note).
    pub fn resolve_mode(&self, provider: &str, model: &str, global: LlmMode) -> LlmMode {
        let Some(entry) = self.providers.get(provider) else {
            return global;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.mode)
            .or(entry.mode)
            .unwrap_or(global)
    }

    /// Resolve configured wire endpoint authority for `(provider, model)`.
    /// Concrete model pins win, then concrete provider defaults; `Auto` means
    /// the caller should consult learned state and conservative defaults.
    pub fn resolve_wire_api(&self, provider: &str, model: &str) -> WireApi {
        let Some(entry) = self.providers.get(provider) else {
            return WireApi::Auto;
        };
        if let Some(wire_api) = entry
            .models
            .iter()
            .find(|m| m.id == model)
            .map(|m| m.wire_api)
            .filter(|w| !w.is_auto())
        {
            return wire_api;
        }
        if !entry.wire_api.is_auto() {
            return entry.wire_api;
        }
        WireApi::Auto
    }

    /// Whether the endpoint is explicitly pinned by model or provider config.
    pub fn is_wire_api_explicit(&self, provider: &str, model: &str) -> bool {
        let Some(entry) = self.providers.get(provider) else {
            return false;
        };
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .is_some_and(|m| !m.wire_api.is_auto())
            || !entry.wire_api.is_auto()
    }
}

/// Read+write a provider config layer while preserving fields cockpit
/// doesn't model. Global provider metadata lives in `config.json`; provider
/// entries live in sibling `providers/*.json` files.
pub struct ConfigDoc {
    pub path: PathBuf,
    raw: Value,
}

impl ConfigDoc {
    /// Load the effective provider config for `cwd` by merging every
    /// applicable config layer from least-specific to most-specific.
    /// `COCKPIT_CONFIG` supplies the only config.json path when set; provider
    /// files live beside that file under `providers/`.
    pub fn load_effective(cwd: &Path) -> ProvidersConfig {
        let paths = crate::config::dirs::config_file_paths_for_load(cwd);
        Self::providers_from_paths(&paths)
    }

    pub(crate) fn providers_from_paths(paths: &[PathBuf]) -> ProvidersConfig {
        let mut merged = Value::Object(Map::new());
        for path in paths {
            if !path.exists() {
                merge_provider_files_for_layer(&mut merged, path);
                continue;
            }
            match Self::load(path) {
                Ok(doc) => {
                    let mut layer = doc.raw.clone();
                    warn_inline_providers_ignored(path, &layer);
                    if let Some(obj) = layer.as_object_mut() {
                        obj.remove("providers");
                    }
                    deep_merge_value(&mut merged, &layer);
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping malformed config layer");
                }
            }
            merge_provider_files_for_layer(&mut merged, path);
        }
        Self {
            path: PathBuf::new(),
            raw: merged,
        }
        .providers()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let path = config_path_for_layer_path(path);
        let raw_str = if path.exists() {
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading config.json at {}", path.display()))?
        } else {
            "{}".to_string()
        };
        let raw: Value = if raw_str.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(&raw_str)
                .with_context(|| format!("parsing config.json at {}", path.display()))?
        };
        let raw = match raw {
            Value::Object(_) => raw,
            other => {
                anyhow::bail!("expected config.json root to be an object, found {other:?}")
            }
        };
        Ok(Self { path, raw })
    }

    /// Extract the typed view of layer-wide provider metadata plus provider
    /// files from this document's sibling `providers/` directory.
    pub fn providers(&self) -> ProvidersConfig {
        let mut cfg = ProvidersConfig::default();
        warn_inline_providers_ignored(&self.path, &self.raw);
        if let Some(s) = self
            .raw
            .get("on_unlisted_models_fetch")
            .and_then(Value::as_str)
            && let Ok(parsed) =
                serde_json::from_value::<OnUnlistedModelsFetch>(Value::String(s.to_string()))
        {
            cfg.on_unlisted_models_fetch = Some(parsed);
        }
        if let Some(v) = self.raw.get("active_model")
            && let Ok(parsed) = serde_json::from_value::<ActiveModelRef>(v.clone())
        {
            cfg.active_model = Some(parsed);
        }
        if let Some(v) = self.raw.get("category_defaults")
            && let Ok(parsed) =
                serde_json::from_value::<BTreeMap<String, ProviderModelRef>>(v.clone())
        {
            cfg.category_defaults = parsed;
        }
        if !self.path.as_os_str().is_empty() {
            load_provider_files_into_config(&self.path, &mut cfg);
        } else if let Some(map) = self.raw.get("providers").and_then(Value::as_object) {
            for (id, v) in map {
                if let Some(obj) = v.as_object()
                    && let Err(e) = reject_legacy_redact_fields(id, obj)
                {
                    tracing::warn!(provider = %id, error = %e, "skipping malformed provider entry");
                    continue;
                }
                if let Ok(entry) = serde_json::from_value::<ProviderEntry>(v.clone()) {
                    cfg.providers.insert(id.clone(), entry);
                }
            }
        }
        cfg
    }

    /// Replace the typed provider layer and persist to disk.
    pub fn write(&mut self, cfg: &ProvidersConfig) -> Result<()> {
        let obj = self.raw.as_object_mut().expect("root is an object");
        obj.remove("providers");
        match cfg.on_unlisted_models_fetch {
            Some(v) => {
                let s = serde_json::to_value(v).context("serializing on_unlisted_models_fetch")?;
                obj.insert("on_unlisted_models_fetch".to_string(), s);
            }
            None => {
                obj.remove("on_unlisted_models_fetch");
            }
        }
        match &cfg.active_model {
            Some(active) => {
                let s = serde_json::to_value(active).context("serializing active_model")?;
                obj.insert("active_model".to_string(), s);
            }
            None => {
                obj.remove("active_model");
            }
        }
        if cfg.category_defaults.is_empty() {
            obj.remove("category_defaults");
        } else {
            let value = serde_json::to_value(&cfg.category_defaults)
                .context("serializing category_defaults")?;
            obj.insert("category_defaults".to_string(), value);
        }
        self.persist_raw()?;
        self.replace_provider_files(&cfg.providers)?;
        Ok(())
    }

    pub fn write_active_model(&mut self, active: Option<&ActiveModelRef>) -> Result<()> {
        let obj = self.raw.as_object_mut().expect("root is an object");
        match active {
            Some(active) => {
                let value = serde_json::to_value(active).context("serializing active_model")?;
                obj.insert("active_model".to_string(), value);
            }
            None => {
                obj.remove("active_model");
            }
        }
        self.persist_raw()
    }

    pub fn write_provider_models(
        &mut self,
        provider_id: &str,
        models: &[ModelEntry],
        models_fetched_at: Option<chrono::DateTime<chrono::Utc>>,
        model_catalog: ProviderModelCatalog,
        last_model_fetch: Option<ModelFetchStatus>,
    ) -> Result<()> {
        let mut provider = self.provider_raw_object(provider_id)?;
        provider.insert(
            "models".to_string(),
            serde_json::to_value(models).context("serializing provider models")?,
        );
        match models_fetched_at.as_ref() {
            Some(ts) => {
                provider.insert(
                    "models_fetched_at".to_string(),
                    serde_json::to_value(ts).context("serializing models_fetched_at")?,
                );
            }
            None => {
                provider.remove("models_fetched_at");
            }
        }
        if model_catalog.is_live() {
            provider.remove("model_catalog");
        } else {
            provider.insert(
                "model_catalog".to_string(),
                serde_json::to_value(model_catalog).context("serializing model_catalog")?,
            );
        }
        match last_model_fetch {
            Some(status) => {
                provider.insert(
                    "last_model_fetch".to_string(),
                    serde_json::to_value(status).context("serializing last_model_fetch")?,
                );
            }
            None => {
                provider.remove("last_model_fetch");
            }
        }
        self.persist_provider_raw(provider_id, provider)
    }

    pub fn write_unlisted_models_policy(
        &mut self,
        on_unlisted_models_fetch: Option<OnUnlistedModelsFetch>,
    ) -> Result<()> {
        let obj = self.raw.as_object_mut().expect("root is an object");
        match on_unlisted_models_fetch {
            Some(v) => {
                let value =
                    serde_json::to_value(v).context("serializing on_unlisted_models_fetch")?;
                obj.insert("on_unlisted_models_fetch".to_string(), value);
            }
            None => {
                obj.remove("on_unlisted_models_fetch");
            }
        }
        self.persist_raw()
    }

    pub fn write_model_favorite(
        &mut self,
        provider_id: &str,
        model_id: &str,
        favorite: bool,
    ) -> Result<()> {
        let mut provider = self.provider_raw_object(provider_id)?;
        let models = provider
            .entry("models".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if !models.is_array() {
            *models = Value::Array(Vec::new());
        }
        let models = models.as_array_mut().expect("models reset to array");
        let mut found = false;
        for model in models.iter_mut() {
            let Some(model_obj) = model.as_object_mut() else {
                continue;
            };
            if model_obj.get("id").and_then(Value::as_str) == Some(model_id) {
                model_obj.insert("favorite".to_string(), Value::Bool(favorite));
                found = true;
                break;
            }
        }
        if !found {
            let mut model = Map::new();
            model.insert("id".to_string(), Value::String(model_id.to_string()));
            model.insert("favorite".to_string(), Value::Bool(favorite));
            models.push(Value::Object(model));
        }
        self.persist_provider_raw(provider_id, provider)
    }

    fn persist_raw(&self) -> Result<()> {
        let pretty = serde_json::to_string_pretty(&self.raw).context("serializing config.json")?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, format!("{pretty}\n"))
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }

    fn provider_raw_object(&self, provider_id: &str) -> Result<Map<String, Value>> {
        let path = provider_file_path_for_config(&self.path, provider_id)?;
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("reading provider config at {}", path.display()))?;
            let value: Value = if raw.trim().is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_str(&raw)
                    .with_context(|| format!("parsing provider config at {}", path.display()))?
            };
            return match value {
                Value::Object(map) => Ok(map),
                other => anyhow::bail!(
                    "expected provider config root to be an object at {}, found {other:?}",
                    path.display()
                ),
            };
        }

        Ok(Map::new())
    }

    fn persist_provider_raw(&self, provider_id: &str, provider: Map<String, Value>) -> Result<()> {
        let path = provider_file_path_for_config(&self.path, provider_id)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pretty = serde_json::to_string_pretty(&Value::Object(provider))
            .context("serializing provider")?;
        std::fs::write(&path, format!("{pretty}\n"))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    fn replace_provider_files(&self, providers: &BTreeMap<String, ProviderEntry>) -> Result<()> {
        let dir = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(PROVIDERS_DIR);
        if dir.exists() {
            for entry in std::fs::read_dir(&dir)
                .with_context(|| format!("reading providers directory {}", dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                let Some(id) = provider_id_from_file_name(&path) else {
                    continue;
                };
                if !providers.contains_key(&id) {
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            return Err(e).with_context(|| format!("removing {}", path.display()));
                        }
                    }
                }
            }
        }
        for (id, entry) in providers {
            validate_provider_id_for_filename(id)?;
            let mut raw = self.provider_raw_object(id)?;
            let serialized = serde_json::to_value(entry).context("serializing provider")?;
            let Value::Object(serialized) = serialized else {
                unreachable!("ProviderEntry serializes to object");
            };
            for key in PROVIDER_SKIPPED_KEYS {
                if !serialized.contains_key(*key) {
                    raw.remove(*key);
                }
            }
            for (key, value) in serialized {
                raw.insert(key, value);
            }
            self.persist_provider_raw(id, raw)?;
        }
        Ok(())
    }
}

pub fn is_xai_grok_provider(provider_id: &str, entry: &ProviderEntry) -> bool {
    let provider_id = provider_id.to_ascii_lowercase();
    provider_id == "grok"
        || provider_id == "grok-oauth"
        || entry
            .credential_ref
            .as_deref()
            .is_some_and(|credential| credential.eq_ignore_ascii_case("grok-oauth"))
        || entry.url.to_ascii_lowercase().contains("api.x.ai")
        || metadata_mentions_xai_grok(&entry.provider_metadata)
        || entry
            .models
            .iter()
            .any(|model| metadata_mentions_xai_grok(&model.provider_metadata))
}

fn metadata_mentions_xai_grok(metadata: &Map<String, Value>) -> bool {
    metadata.values().any(value_mentions_xai_grok)
}

fn value_mentions_xai_grok(value: &Value) -> bool {
    match value {
        Value::String(s) => {
            let s = s.to_ascii_lowercase();
            s.contains("xai") || s.contains("x.ai") || s.contains("grok")
        }
        Value::Array(items) => items.iter().any(value_mentions_xai_grok),
        Value::Object(obj) => obj.values().any(value_mentions_xai_grok),
        _ => false,
    }
}

fn warn_inline_providers_ignored(path: &Path, raw: &Value) {
    if path.as_os_str().is_empty() || raw.get("providers").is_none() {
        return;
    }
    static WARNED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    if !warned
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(path.to_path_buf())
    {
        return;
    }
    tracing::warn!(
        path = %path.display(),
        "inline providers in config.json are no longer read; move providers to providers/<provider-id>.json"
    );
}

fn merge_provider_files_for_layer(merged: &mut Value, config_path: &Path) {
    let Some(config_dir) = config_path.parent() else {
        return;
    };
    let providers_dir = config_dir.join(PROVIDERS_DIR);
    let Ok(entries) = std::fs::read_dir(&providers_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(id) = provider_id_from_file_name(&path) else {
            tracing::warn!(path = %path.display(), "skipping invalid provider config filename");
            continue;
        };
        match load_provider_raw_file(&path) {
            Ok(provider) => {
                let mut layer = Map::new();
                let mut providers = Map::new();
                providers.insert(id, Value::Object(provider));
                layer.insert("providers".to_string(), Value::Object(providers));
                deep_merge_value(merged, &Value::Object(layer));
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    provider = %id,
                    %error,
                    "skipping malformed provider config file"
                );
            }
        }
    }
}

fn load_provider_files_into_config(config_path: &Path, cfg: &mut ProvidersConfig) {
    let mut merged = Value::Object(Map::new());
    merge_provider_files_for_layer(&mut merged, config_path);
    if let Some(map) = merged.get("providers").and_then(Value::as_object) {
        for (id, v) in map {
            if let Some(obj) = v.as_object()
                && let Err(e) = reject_legacy_redact_fields(id, obj)
            {
                tracing::warn!(provider = %id, error = %e, "skipping malformed provider entry");
                continue;
            }
            match serde_json::from_value::<ProviderEntry>(v.clone()) {
                Ok(entry) => {
                    cfg.providers.insert(id.clone(), entry);
                }
                Err(e) => {
                    tracing::warn!(provider = %id, error = %e, "skipping malformed provider entry");
                }
            }
        }
    }
}

fn load_provider_raw_file(path: &Path) -> Result<Map<String, Value>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading provider config at {}", path.display()))?;
    let value: Value = if raw.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(&raw)
            .with_context(|| format!("parsing provider config at {}", path.display()))?
    };
    match value {
        Value::Object(map) => {
            if let Some(id) = provider_id_from_file_name(path) {
                reject_legacy_redact_fields(&id, &map)?;
            }
            Ok(map)
        }
        other => anyhow::bail!(
            "expected provider config root to be an object at {}, found {other:?}",
            path.display()
        ),
    }
}

fn reject_legacy_redact_fields(provider_id: &str, provider: &Map<String, Value>) -> Result<()> {
    if provider.contains_key("redact") {
        anyhow::bail!(
            "provider `{provider_id}` uses legacy `redact`; use `trust: \"trusted\"` to disable outbound redaction or `trust: \"untrusted\"` to keep it enabled"
        );
    }
    if let Some(models) = provider.get("models").and_then(Value::as_array) {
        for model in models {
            let Some(model) = model.as_object() else {
                continue;
            };
            if model.contains_key("redact") {
                let model_id = model
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>");
                anyhow::bail!(
                    "model `{provider_id}:{model_id}` uses legacy `redact`; use `trust: \"trusted\"` to disable outbound redaction or `trust: \"untrusted\"` to keep it enabled"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_provider_file(config_path: &Path, provider_id: &str, json: &str) {
        let path = provider_file_path_for_config(config_path, provider_id).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, json).unwrap();
    }

    fn read_provider_file(config_path: &Path, provider_id: &str) -> Value {
        let path = provider_file_path_for_config(config_path, provider_id).unwrap();
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn round_trips_a_provider_entry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        let mut doc = ConfigDoc::load(&path).unwrap();
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "opencode-zen".to_string(),
            ProviderEntry {
                name: Some("OpenCode Zen".into()),
                template: Some("opencode-zen".into()),
                url: "https://opencode.ai/zen/v1".into(),
                headers: vec![HeaderSpec {
                    name: "Authorization".into(),
                    value: "Bearer $OPENCODE_ZEN_TOKEN".into(),
                }],
                models_fetched_at: None,
                model_catalog: ProviderModelCatalog::Live,
                favorite: Some(true),
                allow_insecure_http: false,
                credential_ref: None,
                auth: Some(AuthKind::ApiKey),
                trust: None,
                location: None,
                quality_rank: None,
                cost_rank: None,
                subagent_invokable: None,
                availability: Default::default(),
                cache: CacheConfig::default(),
                shrink: ShrinkConfig::default(),
                context: ContextConfig::default(),
                auto_prune: None,
                timeout: TimeoutConfig::default(),
                wire_api: WireApi::default(),
                backup: None,
                mode: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                models: vec![ModelEntry {
                    id: "claude-opus-4-7".into(),
                    name: Some("Claude Opus 4.7".into()),
                    thinking_modes: vec![ThinkingMode::Off, ThinkingMode::High],
                    context_length: None,
                    favorite: false,
                    manual: false,
                    trust: None,
                    location: None,
                    quality_rank: None,
                    cost_rank: None,
                    subagent_invokable: None,
                    availability: Default::default(),
                    cache: None,
                    shrink: None,
                    context: None,
                    auto_prune: None,
                    timeout: None,
                    backup: None,
                    mode: None,
                    inline_think: None,
                    hint_tool_call_corrections: None,
                    text_embedded_recovery: None,
                    thinking_params: Default::default(),
                    wire_api: WireApi::default(),
                    inputs: Some(Inputs {
                        images: Some(true),
                        video: None,
                        audio: None,
                    }),
                    extra: Default::default(),
                    capabilities: Default::default(),
                    provider_metadata: Default::default(),
                }],
                capabilities: Default::default(),
                provider_metadata: Default::default(),
                last_model_fetch: None,
            },
        );
        cfg.on_unlisted_models_fetch = Some(OnUnlistedModelsFetch::Ask);
        doc.write(&cfg).unwrap();

        let doc2 = ConfigDoc::load(&path).unwrap();
        let cfg2 = doc2.providers();
        let entry = cfg2.providers.get("opencode-zen").unwrap();
        assert_eq!(entry.url, "https://opencode.ai/zen/v1");
        assert_eq!(entry.headers.len(), 1);
        assert_eq!(entry.favorite, Some(true));
        assert_eq!(entry.models[0].id, "claude-opus-4-7");
        assert_eq!(
            cfg2.on_unlisted_models_fetch,
            Some(OnUnlistedModelsFetch::Ask)
        );
    }

    #[test]
    fn provider_write_removes_stale_skipped_optional_fields_but_keeps_empty_models() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        write_provider_file(
            &path,
            "p",
            r#"{
                "url": "https://example.test/v1",
                "name": "Pretty",
                "allow_insecure_http": true,
                "favorite": true,
                "trust": "trusted",
                "location": "local",
                "quality_rank": 9,
                "cost_rank": 1,
                "subagent_invokable": true,
                "mode": "frontier",
                "inline_think": false,
                "hint_tool_call_corrections": true,
                "text_embedded_recovery": "off",
                "thinking_params": { "high": { "reasoning_effort": "high" } },
                "provider_metadata": { "vendor": "x" },
                "models": [{ "id": "m", "name": "Model Name", "favorite": true }]
            }"#,
        );

        let mut doc = ConfigDoc::load(&path).unwrap();
        let mut cfg = doc.providers();
        let provider = cfg.providers.get_mut("p").unwrap();
        provider.name = None;
        provider.allow_insecure_http = false;
        provider.favorite = None;
        provider.trust = None;
        provider.location = None;
        provider.quality_rank = None;
        provider.cost_rank = None;
        provider.subagent_invokable = None;
        provider.mode = None;
        provider.inline_think = None;
        provider.hint_tool_call_corrections = None;
        provider.text_embedded_recovery = None;
        provider.thinking_params = ThinkingParams::default();
        provider.provider_metadata.clear();
        let model = provider.models.get_mut(0).unwrap();
        model.name = None;
        model.favorite = false;
        provider.models.clear();
        doc.write(&cfg).unwrap();

        let provider_path = provider_file_path_for_config(&path, "p").unwrap();
        let raw: Value =
            serde_json::from_str(&std::fs::read_to_string(provider_path).unwrap()).unwrap();
        let obj = raw.as_object().unwrap();
        for key in [
            "name",
            "allow_insecure_http",
            "favorite",
            "trust",
            "location",
            "quality_rank",
            "cost_rank",
            "subagent_invokable",
            "mode",
            "inline_think",
            "hint_tool_call_corrections",
            "text_embedded_recovery",
            "thinking_params",
            "provider_metadata",
        ] {
            assert!(
                !obj.contains_key(key),
                "stale provider key `{key}` remained: {raw}"
            );
        }
        assert_eq!(obj.get("models"), Some(&Value::Array(vec![])));
    }

    #[test]
    fn preserves_unknown_fields() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(
            &path,
            r#"{"providers":{},"agents":{"foo":"bar"},"misc":[1,2,3]}"#,
        )
        .unwrap();
        let mut doc = ConfigDoc::load(&path).unwrap();
        doc.write(&ProvidersConfig::default()).unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("\"agents\""));
        assert!(on_disk.contains("\"misc\""));
    }

    #[test]
    fn skips_malformed_provider_entry_warning_only() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        write_provider_file(&path, "good", r#"{"url":"https://x"}"#);
        write_provider_file(&path, "bad", "42");
        let doc = ConfigDoc::load(&path).unwrap();
        let cfg = doc.providers();
        assert!(cfg.providers.contains_key("good"));
        assert!(!cfg.providers.contains_key("bad"));
    }

    #[test]
    fn label_falls_back_to_id() {
        let entry = ProviderEntry::default();
        assert_eq!(entry.label("my-id"), "my-id");
        let entry = ProviderEntry {
            name: Some("Pretty".into()),
            ..Default::default()
        };
        assert_eq!(entry.label("ignored"), "Pretty");
    }

    #[test]
    fn cache_defaults_to_none() {
        let entry = ProviderEntry::default();
        assert_eq!(entry.cache.mode, CacheMode::None);
        assert_eq!(entry.cache.ttl_secs, 300);
    }

    #[test]
    fn resolve_cache_prefers_model_override() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            cache: CacheConfig {
                mode: CacheMode::Ephemeral,
                ttl_secs: 600,
            },
            ..ProviderEntry::default()
        };
        entry.models.push(ModelEntry {
            id: "fast".into(),
            name: None,
            thinking_modes: vec![],
            context_length: None,
            favorite: false,
            manual: false,
            trust: None,
            location: None,
            quality_rank: None,
            cost_rank: None,
            subagent_invokable: None,
            availability: Default::default(),
            cache: Some(CacheConfig {
                mode: CacheMode::None,
                ttl_secs: 300,
            }),
            shrink: None,
            context: None,
            auto_prune: None,
            timeout: None,
            backup: None,
            mode: None,
            inline_think: None,
            hint_tool_call_corrections: None,
            text_embedded_recovery: None,
            thinking_params: Default::default(),
            wire_api: WireApi::default(),
            inputs: None,
            extra: Default::default(),
            capabilities: Default::default(),
            provider_metadata: Default::default(),
        });
        cfg.providers.insert("p".into(), entry);

        // Model with an override wins.
        let m = cfg.resolve_cache("p", "fast");
        assert_eq!(m.mode, CacheMode::None);
        // Model without an override inherits the provider config.
        let p = cfg.resolve_cache("p", "other");
        assert_eq!(p.mode, CacheMode::Ephemeral);
        assert_eq!(p.ttl_secs, 600);
        // Unknown provider → default (none).
        assert_eq!(cfg.resolve_cache("nope", "x").mode, CacheMode::None);
    }

    /// The `ttl_secs` lever maps to the Anthropic TTL mode (prompt
    /// `prompt-caching-strategy.md`, decision 4): `>= 3600` selects the
    /// 1-hour extended cache; the default and anything below stay 5-minute.
    #[test]
    fn cache_ttl_selects_one_hour_mode_at_or_above_3600() {
        // Default is 300s → 5-minute.
        assert!(!CacheConfig::default().wants_one_hour_ttl());
        // Just below the threshold → still 5-minute.
        assert!(
            !CacheConfig {
                mode: CacheMode::Ephemeral,
                ttl_secs: 3599,
            }
            .wants_one_hour_ttl()
        );
        // Exactly the threshold → 1-hour.
        assert!(
            CacheConfig {
                mode: CacheMode::Ephemeral,
                ttl_secs: 3600,
            }
            .wants_one_hour_ttl()
        );
        // Well above → 1-hour.
        assert!(
            CacheConfig {
                mode: CacheMode::Ephemeral,
                ttl_secs: 86_400,
            }
            .wants_one_hour_ttl()
        );
    }

    #[test]
    fn context_defaults_are_80_50_30() {
        let c = ContextConfig::default();
        assert_eq!(c.auto_compact_pct, 80);
        assert_eq!(c.auto_prune_pct, 50);
        assert_eq!(c.auto_prune_prunable_pct, 30);
        // Older configs (no `context` key) load with the defaults.
        let entry = ProviderEntry::default();
        assert_eq!(entry.context, ContextConfig::default());
        assert!(entry.mode.is_none());
    }

    #[test]
    fn resolve_context_prefers_model_then_provider_then_default() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            context: ContextConfig {
                auto_compact_pct: 90,
                auto_prune_pct: 60,
                auto_prune_prunable_pct: 40,
            },
            ..ProviderEntry::default()
        };
        let mut pinned = model("pinned", false);
        pinned.context = Some(ContextConfig {
            auto_compact_pct: 70,
            auto_prune_pct: 55,
            auto_prune_prunable_pct: 25,
        });
        entry.models.push(pinned);
        entry.models.push(model("bare", false));
        cfg.providers.insert("p".into(), entry);

        // Model override wins.
        assert_eq!(cfg.resolve_context("p", "pinned").auto_compact_pct, 70);
        // No model override → provider value.
        assert_eq!(cfg.resolve_context("p", "bare").auto_compact_pct, 90);
        assert_eq!(cfg.resolve_context("p", "bare").auto_prune_pct, 60);
        // Unknown provider → built-in default.
        assert_eq!(cfg.resolve_context("nope", "x"), ContextConfig::default());
    }

    #[test]
    fn resolve_timeout_prefers_model_then_provider_then_default() {
        // Stream-timeout resolution: model override → provider value → built-in
        // default (implementation note).
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            timeout: TimeoutConfig {
                ttft_secs: 200,
                idle_secs: 100,
            },
            ..ProviderEntry::default()
        };
        let mut pinned = model("pinned", false);
        pinned.timeout = Some(TimeoutConfig {
            ttft_secs: 45,
            idle_secs: 30,
        });
        entry.models.push(pinned);
        entry.models.push(model("bare", false));
        cfg.providers.insert("p".into(), entry);

        // Model override wins.
        let m = cfg.resolve_timeout("p", "pinned");
        assert_eq!(m.ttft_secs, 45);
        assert_eq!(m.idle_secs, 30);
        // No model override → provider value.
        let p = cfg.resolve_timeout("p", "bare");
        assert_eq!(p.ttft_secs, 200);
        assert_eq!(p.idle_secs, 100);
        // Unknown provider → built-in default (120s TTFT, 90s idle).
        assert_eq!(cfg.resolve_timeout("nope", "x"), TimeoutConfig::default());
        assert_eq!(TimeoutConfig::default().ttft_secs, 120);
        assert_eq!(TimeoutConfig::default().idle_secs, 90);
    }

    #[test]
    fn providers_from_paths_merges_layers_with_project_model_setting_winning() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home").join("config.json");
        let project = tmp.path().join("project").join("config.json");
        std::fs::create_dir_all(home.parent().unwrap()).unwrap();
        std::fs::create_dir_all(project.parent().unwrap()).unwrap();
        std::fs::write(&home, "{}").unwrap();
        std::fs::write(&project, "{}").unwrap();
        write_provider_file(
            &home,
            "p",
            r#"{
                "url": "https://home.example/v1",
                "timeout": { "ttft_secs": 200, "idle_secs": 100 },
                "models": [
                    { "id": "m", "timeout": { "ttft_secs": 80, "idle_secs": 40 } }
                ]
            }"#,
        );
        write_provider_file(
            &project,
            "p",
            r#"{
                "models": [
                    { "id": "m", "timeout": { "ttft_secs": 20, "idle_secs": 10 } }
                ]
            }"#,
        );

        let cfg = ConfigDoc::providers_from_paths(&[home, project]);

        let provider = cfg.providers.get("p").expect("provider survives merge");
        assert_eq!(provider.url, "https://home.example/v1");
        let timeout = cfg.resolve_timeout("p", "m");
        assert_eq!(timeout.ttft_secs, 20);
        assert_eq!(timeout.idle_secs, 10);
    }

    #[test]
    fn providers_from_paths_merges_model_arrays_by_id_without_dropping_home_models() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home").join("config.json");
        let project = tmp.path().join("project").join("config.json");
        std::fs::create_dir_all(home.parent().unwrap()).unwrap();
        std::fs::create_dir_all(project.parent().unwrap()).unwrap();
        std::fs::write(&home, "{}").unwrap();
        std::fs::write(&project, "{}").unwrap();
        write_provider_file(
            &home,
            "p",
            r#"{
                "url": "https://home.example/v1",
                "models": [
                    { "id": "m1", "name": "Model One", "favorite": true },
                    {
                        "id": "m2",
                        "name": "Model Two",
                        "wire_api": "responses",
                        "timeout": { "ttft_secs": 80, "idle_secs": 40 }
                    },
                    { "id": "m3", "name": "Model Three" }
                ]
            }"#,
        );
        write_provider_file(
            &project,
            "p",
            r#"{
                "models": [
                    { "id": "m2", "timeout": { "ttft_secs": 20, "idle_secs": 10 } }
                ]
            }"#,
        );

        let cfg = ConfigDoc::providers_from_paths(&[home, project]);

        let models = &cfg.providers.get("p").expect("provider survives").models;
        assert_eq!(
            models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["m1", "m2", "m3"]
        );
        let m2 = models.iter().find(|m| m.id == "m2").unwrap();
        assert_eq!(m2.name.as_deref(), Some("Model Two"));
        assert_eq!(m2.wire_api, WireApi::Responses);
        let timeout = m2.timeout.as_ref().unwrap();
        assert_eq!(timeout.ttft_secs, 20);
        assert_eq!(timeout.idle_secs, 10);
    }

    #[test]
    fn raw_provider_model_write_preserves_layered_provider_fields() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home").join("config.json");
        let project = tmp.path().join("project").join("config.json");
        std::fs::create_dir_all(home.parent().unwrap()).unwrap();
        std::fs::create_dir_all(project.parent().unwrap()).unwrap();
        std::fs::write(&home, r#"{"on_unlisted_models_fetch": "keep"}"#).unwrap();
        std::fs::write(&project, "{}").unwrap();
        write_provider_file(
            &home,
            "p",
            r#"{
                "url": "https://home.example/v1",
                "headers": [
                    { "name": "Authorization", "value": "Bearer $TOKEN" }
                ],
                "models": [
                    { "id": "old", "name": "Old Model" }
                ]
            }"#,
        );

        let mut fetched = model("new", false);
        fetched.name = Some("New Model".to_string());
        let fetched_at = Utc::now();
        let mut doc = ConfigDoc::load(&project).unwrap();
        doc.write_provider_models(
            "p",
            &[fetched],
            Some(fetched_at),
            ProviderModelCatalog::Live,
            Some(ModelFetchStatus {
                status: ModelFetchStatusKind::Live,
                at: fetched_at,
                source: ModelFetchSource::Live,
                reason: None,
            }),
        )
        .unwrap();

        let raw: Value = serde_json::from_slice(&std::fs::read(&project).unwrap()).unwrap();
        let provider_raw = read_provider_file(&project, "p");
        let provider = provider_raw.as_object().unwrap();
        assert!(!provider.contains_key("url"));
        assert!(!provider.contains_key("headers"));
        assert!(provider.contains_key("models"));
        assert!(provider.contains_key("models_fetched_at"));
        assert!(
            !raw.as_object()
                .unwrap()
                .contains_key("on_unlisted_models_fetch")
        );

        let cfg = ConfigDoc::providers_from_paths(&[home, project]);
        let provider = cfg.providers.get("p").unwrap();
        assert_eq!(provider.url, "https://home.example/v1");
        assert_eq!(provider.headers.len(), 1);
        assert_eq!(
            provider
                .models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["old", "new"]
        );
        assert_eq!(
            cfg.on_unlisted_models_fetch,
            Some(OnUnlistedModelsFetch::Keep)
        );
    }

    #[test]
    fn raw_model_favorite_write_is_partial_model_override() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home").join("config.json");
        let project = tmp.path().join("project").join("config.json");
        std::fs::create_dir_all(home.parent().unwrap()).unwrap();
        std::fs::create_dir_all(project.parent().unwrap()).unwrap();
        std::fs::write(&home, "{}").unwrap();
        std::fs::write(&project, "{}").unwrap();
        write_provider_file(
            &home,
            "p",
            r#"{
                "url": "https://home.example/v1",
                "models": [
                    { "id": "m", "name": "Model M" }
                ]
            }"#,
        );

        let mut doc = ConfigDoc::load(&project).unwrap();
        doc.write_model_favorite("p", "m", true).unwrap();

        let provider_raw = read_provider_file(&project, "p");
        let provider = provider_raw.as_object().unwrap();
        assert!(!provider.contains_key("url"));
        let model = provider
            .get("models")
            .and_then(Value::as_array)
            .and_then(|models| models.first())
            .and_then(Value::as_object)
            .unwrap();
        assert_eq!(model.get("id").and_then(Value::as_str), Some("m"));
        assert_eq!(model.get("favorite").and_then(Value::as_bool), Some(true));
        assert!(!model.contains_key("name"));

        let cfg = ConfigDoc::providers_from_paths(&[home, project]);
        let model = cfg
            .providers
            .get("p")
            .unwrap()
            .models
            .iter()
            .find(|m| m.id == "m")
            .unwrap();
        assert_eq!(model.name.as_deref(), Some("Model M"));
        assert!(model.favorite);
    }

    #[test]
    fn providers_from_paths_appends_new_models_and_empty_overlay_is_noop() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home").join("config.json");
        let project = tmp.path().join("project").join("config.json");
        let empty_project = tmp.path().join("empty-project").join("config.json");
        std::fs::create_dir_all(home.parent().unwrap()).unwrap();
        std::fs::create_dir_all(project.parent().unwrap()).unwrap();
        std::fs::create_dir_all(empty_project.parent().unwrap()).unwrap();
        std::fs::write(&home, "{}").unwrap();
        std::fs::write(&project, "{}").unwrap();
        std::fs::write(&empty_project, "{}").unwrap();
        write_provider_file(
            &home,
            "p",
            r#"{
                "url": "https://home.example/v1",
                "models": [
                    { "id": "m1", "name": "Model One" },
                    { "id": "m2", "name": "Model Two" }
                ]
            }"#,
        );
        write_provider_file(
            &project,
            "p",
            r#"{"models":[{"id":"m3","name":"Model Three"}]}"#,
        );
        write_provider_file(&empty_project, "p", r#"{"models":[]}"#);

        let cfg = ConfigDoc::providers_from_paths(&[home.clone(), project]);
        let models = &cfg.providers.get("p").expect("provider survives").models;
        assert_eq!(
            models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["m1", "m2", "m3"]
        );

        let cfg = ConfigDoc::providers_from_paths(&[home, empty_project]);
        let models = &cfg.providers.get("p").expect("provider survives").models;
        assert_eq!(
            models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["m1", "m2"]
        );
    }

    #[test]
    fn resolve_backup_prefers_model_then_provider_then_none() {
        // Backup-model resolution: model override → provider value → None
        // (implementation note). The backup may name a
        // DIFFERENT provider than the primary.
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            // Provider-level backup points at a different provider.
            backup: Some(BackupConfig {
                provider: "reliable".into(),
                model: "claude-sonnet-4-6".into(),
            }),
            ..ProviderEntry::default()
        };
        let mut pinned = model("pinned", false);
        pinned.backup = Some(BackupConfig {
            provider: "other-reliable".into(),
            model: "gpt-mini".into(),
        });
        entry.models.push(pinned);
        entry.models.push(model("bare", false));
        cfg.providers.insert("flaky".into(), entry);

        // Model override wins (and can name yet another provider).
        let m = cfg.resolve_backup("flaky", "pinned").unwrap();
        assert_eq!(m.provider, "other-reliable");
        assert_eq!(m.model, "gpt-mini");
        // No model override → the provider-level backup (different provider).
        let p = cfg.resolve_backup("flaky", "bare").unwrap();
        assert_eq!(p.provider, "reliable");
        assert_eq!(p.model, "claude-sonnet-4-6");
        // Unknown provider → no backup (hard-fail).
        assert!(cfg.resolve_backup("nope", "x").is_none());
        // A provider with neither tier set → no backup.
        let mut cfg2 = ProvidersConfig::default();
        cfg2.providers.insert(
            "none".into(),
            ProviderEntry {
                url: "https://y".into(),
                models: vec![model("m", false)],
                ..ProviderEntry::default()
            },
        );
        assert!(cfg2.resolve_backup("none", "m").is_none());
    }

    /// An unset `backup` is skipped on serialize at both scopes (configs that
    /// never pin one stay clean), and a configured one round-trips.
    #[test]
    fn backup_skipped_on_serialize_when_unset_and_round_trips() {
        let unset = ProviderEntry::default();
        let json = serde_json::to_string(&unset).unwrap();
        assert!(!json.contains("backup"));
        let unset_model = model("m", false);
        let json = serde_json::to_string(&unset_model).unwrap();
        assert!(!json.contains("backup"));

        let set = ProviderEntry {
            backup: Some(BackupConfig {
                provider: "reliable".into(),
                model: "claude-sonnet-4-6".into(),
            }),
            ..ProviderEntry::default()
        };
        let json = serde_json::to_string(&set).unwrap();
        assert!(json.contains("\"backup\""));
        let back: ProviderEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.backup, set.backup);
    }

    #[test]
    fn resolve_mode_falls_through_model_provider_global() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            mode: Some(LlmMode::Defensive),
            ..ProviderEntry::default()
        };
        let mut pinned = model("pinned", false);
        pinned.mode = Some(LlmMode::Frontier);
        entry.models.push(pinned);
        entry.models.push(model("bare", false));
        cfg.providers.insert("p".into(), entry);

        // Model override beats provider + global.
        assert_eq!(
            cfg.resolve_mode("p", "pinned", LlmMode::Defensive),
            LlmMode::Frontier
        );
        // No model override → provider override beats the global.
        assert_eq!(
            cfg.resolve_mode("p", "bare", LlmMode::Normal),
            LlmMode::Defensive
        );
        // Provider with no mode override → global wins.
        let mut cfg2 = ProvidersConfig::default();
        cfg2.providers.insert(
            "q".into(),
            ProviderEntry {
                url: "https://y".into(),
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                models: vec![model("m", false)],
                ..ProviderEntry::default()
            },
        );
        assert_eq!(
            cfg2.resolve_mode("q", "m", LlmMode::Normal),
            LlmMode::Normal
        );
        // Unknown provider → global.
        assert_eq!(
            cfg.resolve_mode("nope", "x", LlmMode::Normal),
            LlmMode::Normal
        );
    }

    #[test]
    fn mode_undefined_serializes_as_absent() {
        // A model with no `mode`/`context` override omits both keys entirely
        // (parse to a map so the `cache.mode` inner key can't false-match).
        let v: Value = serde_json::to_value(model("x", false)).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("mode"), "undefined mode is absent");
        assert!(!obj.contains_key("context"), "absent context override");
        // A provider with no `mode` override omits the top-level key.
        let entry = ProviderEntry {
            url: "https://x".into(),
            ..ProviderEntry::default()
        };
        let pv: Value = serde_json::to_value(&entry).unwrap();
        assert!(!pv.as_object().unwrap().contains_key("mode"));
        // A pinned model mode serializes its lowercase spelling.
        let mut m = model("x", false);
        m.mode = Some(LlmMode::Frontier);
        let mv: Value = serde_json::to_value(&m).unwrap();
        assert_eq!(mv.get("mode").and_then(Value::as_str), Some("frontier"));
    }

    /// Minimal `ModelEntry` for the merge tests.
    fn model(id: &str, manual: bool) -> ModelEntry {
        ModelEntry {
            id: id.to_string(),
            name: None,
            thinking_modes: vec![],
            inputs: None,
            context_length: None,
            favorite: false,
            manual,
            trust: None,
            location: None,
            quality_rank: None,
            cost_rank: None,
            subagent_invokable: None,
            availability: Default::default(),
            cache: None,
            shrink: None,
            context: None,
            auto_prune: None,
            timeout: None,
            backup: None,
            mode: None,
            inline_think: None,
            hint_tool_call_corrections: None,
            text_embedded_recovery: None,
            thinking_params: Default::default(),
            wire_api: WireApi::default(),
            extra: Default::default(),
            capabilities: Default::default(),
            provider_metadata: Default::default(),
        }
    }

    #[test]
    fn manual_field_defaults_false_when_absent() {
        // A model row written before the `manual` field existed must
        // load as non-manual.
        let m: ModelEntry = serde_json::from_str(r#"{"id":"legacy"}"#).unwrap();
        assert!(!m.manual);
        // And the field is skipped when serializing a non-manual entry.
        let json = serde_json::to_string(&model("x", false)).unwrap();
        assert!(!json.contains("manual"));
        let json = serde_json::to_string(&model("x", true)).unwrap();
        assert!(json.contains("\"manual\":true"));
    }

    #[test]
    fn resolve_inline_think_defaults_on_and_honors_opt_out() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry::default();
        // Default-on: an unset override.
        let default_model = model("default-on", false);
        assert_eq!(default_model.inline_think, None);
        entry.models.push(default_model);
        // Explicit opt-out: raw passthrough.
        let mut off = model("legacy-off", true);
        off.inline_think = Some(false);
        entry.models.push(off);
        // Explicit opt-in (redundant with the default, but resolvable).
        let mut on = model("explicit-on", true);
        on.inline_think = Some(true);
        entry.models.push(on);
        cfg.providers.insert("p".into(), entry);

        // Unset override → falls through to the global default (on here).
        assert!(cfg.resolve_inline_think("p", "default-on", true));
        // Explicit model `false` → disabled (raw passthrough).
        assert!(!cfg.resolve_inline_think("p", "legacy-off", true));
        // Explicit model `true` → enabled.
        assert!(cfg.resolve_inline_think("p", "explicit-on", true));
        // Unknown provider / model → the global default.
        assert!(cfg.resolve_inline_think("nope", "x", true));
        assert!(cfg.resolve_inline_think("p", "ghost", true));
        // With a global default of `false`, unset tiers inherit it.
        assert!(!cfg.resolve_inline_think("p", "default-on", false));
        assert!(!cfg.resolve_inline_think("nope", "x", false));
        // A model `true`/`false` still wins over the global.
        assert!(cfg.resolve_inline_think("p", "explicit-on", false));
        assert!(!cfg.resolve_inline_think("p", "legacy-off", false));

        // `None` is skipped on serialize; `Some(false)` is written.
        let json_on = serde_json::to_string(&model("k", false)).unwrap();
        assert!(!json_on.contains("inline_think"));
        let mut k = model("k", false);
        k.inline_think = Some(false);
        let json_off = serde_json::to_string(&k).unwrap();
        assert!(json_off.contains("\"inline_think\":false"));
    }

    #[test]
    fn trust_defaults_untrusted_and_honors_provider_model_overrides() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            trust: Some(ModelTrust::Trusted),
            ..ProviderEntry::default()
        };
        let default_model = model("default-on", false);
        assert_eq!(default_model.trust, None);
        entry.models.push(default_model.clone());
        let mut untrusted_override = model("untrusted-override", false);
        untrusted_override.trust = Some(ModelTrust::Untrusted);
        entry.models.push(untrusted_override.clone());
        cfg.providers.insert("p".into(), entry);

        assert_eq!(cfg.resolve_trust("p", "default-on"), ModelTrust::Trusted);
        assert_eq!(
            cfg.resolve_trust("p", "untrusted-override"),
            ModelTrust::Untrusted
        );
        assert_eq!(
            cfg.resolve_trust("missing", "default-on"),
            ModelTrust::Untrusted
        );
        assert_eq!(cfg.resolve_trust("p", "missing"), ModelTrust::Trusted);

        let json_default = serde_json::to_string(&default_model).unwrap();
        assert!(!json_default.contains("trust"));
        let json_override = serde_json::to_string(&untrusted_override).unwrap();
        assert!(json_override.contains("\"trust\":\"untrusted\""));
    }

    #[test]
    fn subagent_invokable_defaults_false_and_honors_overrides() {
        let mut cfg = ProvidersConfig::default();
        let mut provider_default = ProviderEntry {
            subagent_invokable: Some(true),
            ..ProviderEntry::default()
        };
        provider_default.models.push(model("inherits", false));
        let mut disabled = model("disabled", false);
        disabled.subagent_invokable = Some(false);
        provider_default.models.push(disabled);
        cfg.providers
            .insert("provider-default".into(), provider_default);
        cfg.providers.insert(
            "unset".into(),
            ProviderEntry {
                models: vec![model("missing", false)],
                ..ProviderEntry::default()
            },
        );

        assert!(cfg.resolve_subagent_invokable("provider-default", "inherits"));
        assert!(!cfg.resolve_subagent_invokable("provider-default", "disabled"));
        assert!(!cfg.resolve_subagent_invokable("unset", "missing"));
        assert!(!cfg.resolve_subagent_invokable("missing", "missing"));
    }

    #[test]
    fn policy_resolver_applies_defaults_filters_and_tie_breaks() {
        let mut cfg = ProvidersConfig::default();
        let mut cheap = model("cheap", false);
        cheap.subagent_invokable = Some(true);
        cheap.quality_rank = Some(5);
        cheap.cost_rank = Some(1);
        cheap.capabilities.tool_calling = CapabilityStatus::Supported;
        cheap.capabilities.context_tokens = Some(32_000);

        let mut reasoning = model("reasoning", false);
        reasoning.subagent_invokable = Some(true);
        reasoning.trust = Some(ModelTrust::Trusted);
        reasoning.quality_rank = Some(10);
        reasoning.cost_rank = Some(5);
        reasoning.thinking_modes = vec![ThinkingMode::High];
        reasoning.capabilities.images = Some(true);
        reasoning.context_length = Some(128_000);

        cfg.providers.insert(
            "a".into(),
            ProviderEntry {
                models: vec![cheap],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "b".into(),
            ProviderEntry {
                models: vec![reasoning],
                ..ProviderEntry::default()
            },
        );

        cfg.category_defaults.insert(
            "cheap_code".into(),
            ProviderModelRef {
                provider: "b".into(),
                model: "reasoning".into(),
            },
        );

        let chosen = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Category("cheap_code"),
                trust: None,
                required_capabilities: vec![],
                min_context_tokens: None,
                require_subagent_invokable: true,
                trusted_only: false,
                optimize: ModelOptimization::Cost,
                role: Some("cheap_code"),
                agent: Some("explore"),
            })
            .unwrap();
        assert_eq!(chosen.selector(), "b:reasoning");

        let chosen = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Trust(ModelTrust::Untrusted),
                trust: None,
                required_capabilities: vec![RequiredModelCapability::ToolCalling],
                min_context_tokens: Some(16_000),
                require_subagent_invokable: true,
                trusted_only: false,
                optimize: ModelOptimization::Quality,
                role: None,
                agent: None,
            })
            .unwrap();
        assert_eq!(chosen.selector(), "a:cheap");

        let chosen = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Category("reasoning"),
                trust: None,
                required_capabilities: vec![
                    RequiredModelCapability::Reasoning,
                    RequiredModelCapability::Images,
                ],
                min_context_tokens: Some(64_000),
                require_subagent_invokable: true,
                trusted_only: true,
                optimize: ModelOptimization::Balanced,
                role: Some("reasoning"),
                agent: Some("deepthink"),
            })
            .unwrap();
        assert_eq!(chosen.selector(), "b:reasoning");

        let err = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Category("strict"),
                trust: None,
                required_capabilities: vec![RequiredModelCapability::StructuredOutputs],
                min_context_tokens: None,
                require_subagent_invokable: true,
                trusted_only: false,
                optimize: ModelOptimization::Balanced,
                role: Some("strict"),
                agent: None,
            })
            .unwrap_err();
        assert!(matches!(err, ModelPolicyError::NoEligibleModel(_)));
    }

    #[test]
    fn mixed_harness_policy_loaded_from_files_covers_trust_and_hidden_models() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        write_provider_file(
            &config_path,
            "mixed",
            r#"{
                "url": "https://mixed.example/v1",
                "trust": "untrusted",
                "models": [
                    { "id": "parent-untrusted", "subagent_invokable": true, "quality_rank": 4, "cost_rank": 1 },
                    { "id": "top-trusted", "trust": "trusted", "quality_rank": 6, "cost_rank": 4 },
                    { "id": "child-trusted", "trust": "trusted", "subagent_invokable": true, "quality_rank": 9, "cost_rank": 3 },
                    { "id": "hidden-trusted", "trust": "trusted", "subagent_invokable": false, "quality_rank": 20, "cost_rank": 1 }
                ]
            }"#,
        );
        let cfg = ConfigDoc::providers_from_paths(&[config_path]);

        let top = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Exact("mixed:top-trusted"),
                trust: Some(ModelTrust::Trusted),
                required_capabilities: vec![],
                min_context_tokens: None,
                require_subagent_invokable: false,
                trusted_only: true,
                optimize: ModelOptimization::Balanced,
                role: Some("top_level"),
                agent: Some("Build"),
            })
            .unwrap();
        assert_eq!(top.selector(), "mixed:top-trusted");

        let child = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Trust(ModelTrust::Trusted),
                trust: Some(ModelTrust::Trusted),
                required_capabilities: vec![],
                min_context_tokens: None,
                require_subagent_invokable: true,
                trusted_only: true,
                optimize: ModelOptimization::Quality,
                role: Some("sensitive_child"),
                agent: Some("builder"),
            })
            .unwrap();
        assert_eq!(child.selector(), "mixed:child-trusted");

        let untrusted_refusal = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Exact("mixed:parent-untrusted"),
                trust: None,
                required_capabilities: vec![],
                min_context_tokens: None,
                require_subagent_invokable: true,
                trusted_only: true,
                optimize: ModelOptimization::Balanced,
                role: Some("utility"),
                agent: Some("explore"),
            })
            .unwrap_err();
        assert!(matches!(
            untrusted_refusal,
            ModelPolicyError::Untrusted { .. }
        ));

        let hidden_refusal = cfg
            .resolve_model_policy(&ModelPolicyRequest {
                selector: ModelPolicySelector::Exact("mixed:hidden-trusted"),
                trust: Some(ModelTrust::Trusted),
                required_capabilities: vec![],
                min_context_tokens: None,
                require_subagent_invokable: true,
                trusted_only: true,
                optimize: ModelOptimization::Quality,
                role: Some("sensitive_child"),
                agent: Some("builder"),
            })
            .unwrap_err();
        assert!(matches!(
            hidden_refusal,
            ModelPolicyError::NotSubagentInvokable { provider, model }
                if provider == "mixed" && model == "hidden-trusted"
        ));
    }

    #[test]
    fn legacy_redact_fields_are_rejected_with_migration_hint() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        write_provider_file(
            &config_path,
            "p",
            r#"{"url":"https://x","models":[{"id":"m","redact":false}]}"#,
        );
        let path = provider_file_path_for_config(&config_path, "p").unwrap();
        let err = load_provider_raw_file(&path).unwrap_err().to_string();
        assert!(err.contains("legacy `redact`"));
        assert!(err.contains("trust"));
    }

    #[test]
    fn resolve_inline_think_three_tier_precedence() {
        let mut cfg = ProvidersConfig::default();

        // Provider with `inline_think = true`, holding three models:
        // one unset, one forcing false, one forcing true.
        let mut prov_on = ProviderEntry {
            inline_think: Some(true),
            ..Default::default()
        };
        prov_on.models.push(model("inherit", false));
        let mut m_off = model("model-off", true);
        m_off.inline_think = Some(false);
        prov_on.models.push(m_off);
        let mut m_on = model("model-on", true);
        m_on.inline_think = Some(true);
        prov_on.models.push(m_on);
        cfg.providers.insert("prov_on".into(), prov_on);

        // Provider with `inline_think = false`, one unset model.
        let mut prov_off = ProviderEntry {
            inline_think: Some(false),
            ..Default::default()
        };
        prov_off.models.push(model("inherit", false));
        cfg.providers.insert("prov_off".into(), prov_off);

        // Provider with NO override (inherits global), one unset model.
        let mut prov_inherit = ProviderEntry::default();
        assert_eq!(prov_inherit.inline_think, None);
        prov_inherit.models.push(model("inherit", false));
        cfg.providers.insert("prov_inherit".into(), prov_inherit);

        // Model wins over provider: model `false` disables despite provider `true`.
        assert!(!cfg.resolve_inline_think("prov_on", "model-off", true));
        // Model `true` enables despite a (hypothetical) lower tier off.
        assert!(cfg.resolve_inline_think("prov_on", "model-on", false));
        // Unset model inherits the provider override (true), ignoring global false.
        assert!(cfg.resolve_inline_think("prov_on", "inherit", false));

        // Provider `false` wins over global `true` when the model is unset.
        assert!(!cfg.resolve_inline_think("prov_off", "inherit", true));

        // Both tiers unset → the global default decides.
        assert!(cfg.resolve_inline_think("prov_inherit", "inherit", true));
        assert!(!cfg.resolve_inline_think("prov_inherit", "inherit", false));
    }

    /// Three-tier precedence for `hint_tool_call_corrections`
    /// (implementation note): model `Some(false)` beats
    /// provider `Some(true)` beats global `true`; `None` falls through.
    #[test]
    fn resolve_hint_tool_call_corrections_three_tier_precedence() {
        let mut cfg = ProvidersConfig::default();

        // Provider `true`, with a model forcing `false`, a model forcing `true`,
        // and an unset model.
        let mut prov_on = ProviderEntry {
            hint_tool_call_corrections: Some(true),
            ..Default::default()
        };
        prov_on.models.push(model("inherit", false));
        let mut m_off = model("model-off", true);
        m_off.hint_tool_call_corrections = Some(false);
        prov_on.models.push(m_off);
        let mut m_on = model("model-on", true);
        m_on.hint_tool_call_corrections = Some(true);
        prov_on.models.push(m_on);
        cfg.providers.insert("prov_on".into(), prov_on);

        // Provider `false`, one unset model.
        let mut prov_off = ProviderEntry {
            hint_tool_call_corrections: Some(false),
            ..Default::default()
        };
        prov_off.models.push(model("inherit", false));
        cfg.providers.insert("prov_off".into(), prov_off);

        // Provider with NO override (inherits global), one unset model.
        let mut prov_inherit = ProviderEntry::default();
        assert_eq!(prov_inherit.hint_tool_call_corrections, None);
        prov_inherit.models.push(model("inherit", false));
        cfg.providers.insert("prov_inherit".into(), prov_inherit);

        // Model `Some(false)` beats provider `Some(true)` beats global `true`.
        assert!(!cfg.resolve_hint_tool_call_corrections("prov_on", "model-off", true));
        // Model `true` enables despite a global `false`.
        assert!(cfg.resolve_hint_tool_call_corrections("prov_on", "model-on", false));
        // Unset model inherits the provider override (true), ignoring global false.
        assert!(cfg.resolve_hint_tool_call_corrections("prov_on", "inherit", false));
        // Provider `false` wins over global `true` when the model is unset.
        assert!(!cfg.resolve_hint_tool_call_corrections("prov_off", "inherit", true));
        // Both tiers unset (`None`) → the global default decides.
        assert!(cfg.resolve_hint_tool_call_corrections("prov_inherit", "inherit", true));
        assert!(!cfg.resolve_hint_tool_call_corrections("prov_inherit", "inherit", false));
        // Unknown provider/model → the global default.
        assert!(cfg.resolve_hint_tool_call_corrections("nope", "x", true));
        assert!(!cfg.resolve_hint_tool_call_corrections("nope", "x", false));

        // `None` is skipped on serialize; `Some(false)` is written.
        let json_unset = serde_json::to_string(&model("k", false)).unwrap();
        assert!(!json_unset.contains("hint_tool_call_corrections"));
        let mut k = model("k", false);
        k.hint_tool_call_corrections = Some(false);
        let json_off = serde_json::to_string(&k).unwrap();
        assert!(json_off.contains("\"hint_tool_call_corrections\":false"));
        // Provider tier too: unset omits the key, `Some` serializes it.
        let entry_unset: Value = serde_json::to_value(ProviderEntry {
            url: "https://x".into(),
            ..ProviderEntry::default()
        })
        .unwrap();
        assert!(
            !entry_unset
                .as_object()
                .unwrap()
                .contains_key("hint_tool_call_corrections")
        );
    }

    /// Three-tier precedence for `text_embedded_recovery`
    /// (implementation note): model override beats provider
    /// override beats the global default; `None` falls through. Mirrors the
    /// `inline_think` / `hint_tool_call_corrections` resolvers.
    #[test]
    fn resolve_text_embedded_recovery_three_tier_precedence() {
        use crate::config::extended::TextEmbeddedRecovery as M;
        let mut cfg = ProvidersConfig::default();

        // Provider pinned `strict`, with a model forcing `off`, a model forcing
        // `available`, and an unset model.
        let mut prov_strict = ProviderEntry {
            text_embedded_recovery: Some(M::Strict),
            ..Default::default()
        };
        prov_strict.models.push(model("inherit", false));
        let mut m_off = model("model-off", true);
        m_off.text_embedded_recovery = Some(M::Off);
        prov_strict.models.push(m_off);
        let mut m_avail = model("model-avail", true);
        m_avail.text_embedded_recovery = Some(M::Available);
        prov_strict.models.push(m_avail);
        cfg.providers.insert("prov_strict".into(), prov_strict);

        // Provider with NO override (inherits global), one unset model.
        let mut prov_inherit = ProviderEntry::default();
        assert_eq!(prov_inherit.text_embedded_recovery, None);
        prov_inherit.models.push(model("inherit", false));
        cfg.providers.insert("prov_inherit".into(), prov_inherit);

        // Model wins over provider: model `off` beats provider `strict`.
        assert_eq!(
            cfg.resolve_text_embedded_recovery("prov_strict", "model-off", M::Available),
            M::Off
        );
        // Model `available` beats provider `strict`.
        assert_eq!(
            cfg.resolve_text_embedded_recovery("prov_strict", "model-avail", M::Off),
            M::Available
        );
        // Unset model inherits the provider override (`strict`), ignoring global.
        assert_eq!(
            cfg.resolve_text_embedded_recovery("prov_strict", "inherit", M::Available),
            M::Strict
        );
        // Both tiers unset (`None`) → the global default decides.
        assert_eq!(
            cfg.resolve_text_embedded_recovery("prov_inherit", "inherit", M::Available),
            M::Available
        );
        assert_eq!(
            cfg.resolve_text_embedded_recovery("prov_inherit", "inherit", M::Off),
            M::Off
        );
        // Unknown provider/model → the global default.
        assert_eq!(
            cfg.resolve_text_embedded_recovery("nope", "x", M::Strict),
            M::Strict
        );

        // `None` is skipped on serialize; `Some(...)` round-trips.
        let json_unset = serde_json::to_string(&model("k", false)).unwrap();
        assert!(!json_unset.contains("text_embedded_recovery"));
        let mut k = model("k", false);
        k.text_embedded_recovery = Some(M::Strict);
        let json_set = serde_json::to_string(&k).unwrap();
        assert!(json_set.contains("\"text_embedded_recovery\":\"strict\""));
        // Round-trips back to the same value.
        let parsed: ModelEntry = serde_json::from_str(&json_set).unwrap();
        assert_eq!(parsed.text_embedded_recovery, Some(M::Strict));
    }

    /// The DeepSeek built-in default mapping (bottom tier) for ALL FOUR
    /// thinking modes (implementation note). `Off`
    /// explicitly emits the disabled form (not omission); every level
    /// enables and sets `reasoning_effort`. The mapping lives in the
    /// built-in provider defaults, surfaced through
    /// `resolve_thinking_params` with no model/provider override configured.
    #[test]
    fn deepseek_builtin_default_maps_all_four_modes() {
        let cfg = ProvidersConfig::default();
        // Nothing configured for `deepseek` — the bottom tier (built-in
        // default keyed by provider id) supplies the fragment.
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Off),
            Some(serde_json::json!({ "thinking": { "type": "disabled" } })),
        );
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Low),
            Some(serde_json::json!({
                "thinking": { "type": "enabled" }, "reasoning_effort": "low"
            })),
        );
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Medium),
            Some(serde_json::json!({
                "thinking": { "type": "enabled" }, "reasoning_effort": "medium"
            })),
        );
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::High),
            Some(serde_json::json!({
                "thinking": { "type": "enabled" }, "reasoning_effort": "high"
            })),
        );
    }

    /// A provider with no built-in mapping and no configured override sends
    /// no extra keys for any mode — every existing provider's request is
    /// byte-for-byte unchanged.
    #[test]
    fn provider_without_mapping_sends_no_extra_params() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("z-ai".into(), ProviderEntry::default());
        for mode in [
            ThinkingMode::Off,
            ThinkingMode::Low,
            ThinkingMode::Medium,
            ThinkingMode::High,
        ] {
            assert_eq!(cfg.resolve_thinking_params("z-ai", "glm-4.6", mode), None);
        }
        // An entirely unknown provider also resolves to nothing.
        assert_eq!(
            cfg.resolve_thinking_params("nope", "whatever", ThinkingMode::High),
            None
        );
    }

    #[test]
    fn resolve_reasoning_effort_params_uses_native_mapping_and_default() {
        let mut cfg = ProvidersConfig::default();
        let mut mapping = BTreeMap::new();
        mapping.insert("minimal".to_string(), serde_json::json!("minimal"));
        mapping.insert("xhigh".to_string(), serde_json::json!("xhigh"));
        cfg.providers.insert(
            "codex".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "gpt-5-codex".into(),
                    capabilities: ModelCapabilities {
                        reasoning_effort: Some(ReasoningEffortCapability {
                            values: vec![
                                CapabilityValue {
                                    value: "minimal".into(),
                                    label: Some("Minimal".into()),
                                    description: None,
                                },
                                CapabilityValue {
                                    value: "xhigh".into(),
                                    label: Some("Extra high".into()),
                                    description: None,
                                },
                            ],
                            default: Some("minimal".into()),
                            request_mapping: Some(ReasoningEffortRequestMapping::JsonField {
                                field: "reasoning_effort".into(),
                                values: mapping,
                            }),
                            source: Some(CapabilitySource::Live),
                        }),
                        ..ModelCapabilities::default()
                    },
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        assert_eq!(
            cfg.resolve_reasoning_effort_params("codex", "gpt-5-codex", None),
            Some(serde_json::json!({ "reasoning_effort": "minimal" }))
        );
        assert_eq!(
            cfg.resolve_reasoning_effort_params("codex", "gpt-5-codex", Some("xhigh")),
            Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
        );
        assert_eq!(
            cfg.resolve_reasoning_effort_params("codex", "gpt-5-codex", Some("stale")),
            Some(serde_json::json!({ "reasoning_effort": "minimal" }))
        );

        cfg.active_model = Some(ActiveModelRef {
            provider: "codex".into(),
            model: "gpt-5-codex".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "xhigh".into(),
            }),
            thinking_mode: Some(ThinkingMode::High),
        });
        assert_eq!(
            cfg.resolve_active_model_reasoning_params(),
            Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
        );
    }

    #[test]
    fn fallback_models_without_effort_values_do_not_resolve_reasoning_params() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "codex".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "fallback".into(),
                    capabilities: ModelCapabilities {
                        reasoning_effort: Some(ReasoningEffortCapability {
                            source: Some(CapabilitySource::Fallback),
                            ..ReasoningEffortCapability::default()
                        }),
                        ..ModelCapabilities::default()
                    },
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        assert!(!cfg.has_reasoning_effort_capability("codex", "fallback"));
        assert_eq!(
            cfg.resolve_reasoning_effort_params("codex", "fallback", Some("high")),
            None
        );
    }

    /// A configured layer that maps only some modes shadows the lower tiers
    /// for EVERY mode: a mode the winning layer doesn't list resolves to
    /// `None` (send nothing) rather than falling through. This is the
    /// "explicit override is total" rule.
    #[test]
    fn configured_layer_with_partial_modes_does_not_fall_through() {
        let mut cfg = ProvidersConfig::default();
        let mut deepseek = ProviderEntry::default();
        deepseek.thinking_params.0.insert(
            ThinkingMode::High,
            serde_json::json!({ "reasoning_effort": "max" }),
        );
        cfg.providers.insert("deepseek".into(), deepseek);

        // High uses the configured provider fragment...
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::High),
            Some(serde_json::json!({ "reasoning_effort": "max" })),
        );
        // ...but Off does NOT fall through to the built-in disabled form,
        // because the provider layer is the winner and lists no Off entry.
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Off),
            None,
        );
    }

    /// Three-tier precedence (per-model → per-provider → built-in default),
    /// mirroring `resolve_inline_think_three_tier_precedence`.
    #[test]
    fn resolve_thinking_params_three_tier_precedence() {
        let mut cfg = ProvidersConfig::default();

        // A `deepseek` provider that pins its own provider-level fragment
        // for High, plus a model that pins its own model-level fragment.
        let mut deepseek = ProviderEntry::default();
        deepseek.thinking_params.0.insert(
            ThinkingMode::High,
            serde_json::json!({ "provider_level": true }),
        );
        let mut pinned = model("pinned", true);
        pinned.thinking_params.0.insert(
            ThinkingMode::High,
            serde_json::json!({ "model_level": true }),
        );
        deepseek.models.push(pinned);
        deepseek.models.push(model("inherit", false));
        cfg.providers.insert("deepseek".into(), deepseek);

        // Top tier: the per-model fragment wins over the provider fragment
        // AND over the built-in DeepSeek default.
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "pinned", ThinkingMode::High),
            Some(serde_json::json!({ "model_level": true })),
        );
        // Middle tier: a model with no map of its own falls to the provider
        // fragment (not the built-in default).
        assert_eq!(
            cfg.resolve_thinking_params("deepseek", "inherit", ThinkingMode::High),
            Some(serde_json::json!({ "provider_level": true })),
        );

        // Bottom tier: a provider with no configured map at all falls to the
        // built-in default keyed by provider id.
        let mut cfg2 = ProvidersConfig::default();
        cfg2.providers
            .insert("deepseek".into(), ProviderEntry::default());
        assert_eq!(
            cfg2.resolve_thinking_params("deepseek", "any", ThinkingMode::High),
            Some(serde_json::json!({
                "thinking": { "type": "enabled" }, "reasoning_effort": "high"
            })),
        );
    }

    /// An unset `thinking_params` map is skipped on serialize at both the
    /// provider and model scope (so configs that never pin it stay clean),
    /// and a configured one round-trips.
    #[test]
    fn thinking_params_skipped_on_serialize_when_empty() {
        let unset = ProviderEntry::default();
        let json = serde_json::to_string(&unset).unwrap();
        assert!(!json.contains("thinking_params"));

        let unset_model = model("m", true);
        let json = serde_json::to_string(&unset_model).unwrap();
        assert!(!json.contains("thinking_params"));

        let mut set = ProviderEntry::default();
        set.thinking_params.0.insert(
            ThinkingMode::Off,
            serde_json::json!({ "thinking": { "type": "disabled" } }),
        );
        let json = serde_json::to_string(&set).unwrap();
        assert!(json.contains("thinking_params"));
        // Round-trips back to the same map.
        let back: ProviderEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thinking_params, set.thinking_params);
    }

    #[test]
    fn provider_inline_think_skipped_on_serialize_when_unset() {
        let unset = ProviderEntry::default();
        let json = serde_json::to_string(&unset).unwrap();
        assert!(!json.contains("inline_think"));
        let set = ProviderEntry {
            inline_think: Some(false),
            ..Default::default()
        };
        let json = serde_json::to_string(&set).unwrap();
        assert!(json.contains("\"inline_think\":false"));
    }

    #[test]
    fn provider_model_catalog_defaults_live_and_serializes_only_for_fallback() {
        let provider = ProviderEntry {
            url: "https://example.test/v1".into(),
            ..ProviderEntry::default()
        };
        let json = serde_json::to_string(&provider).unwrap();
        assert!(
            !json.contains("model_catalog"),
            "live catalog should stay implicit: {json}"
        );

        let provider = ProviderEntry {
            model_catalog: ProviderModelCatalog::CodexFallback,
            ..provider
        };
        let json = serde_json::to_string(&provider).unwrap();
        assert!(
            json.contains("\"model_catalog\":\"codex-fallback\""),
            "{json}"
        );
        let back: ProviderEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.model_catalog, ProviderModelCatalog::CodexFallback);
    }

    #[test]
    fn merge_retains_manual_entry_across_refetch() {
        let existing = vec![model("fetched-old", false), model("hand-added", true)];
        // A refetch returns a fresh fetched list that no longer includes
        // the old fetched id and never knew about the manual one.
        let fetched = vec![model("fetched-new", false)];
        let merged = merge_fetched_models_with_policy(
            Some("p"),
            &existing,
            fetched,
            ModelMergePolicy::KeepUnlisted,
        );

        let ids: Vec<&str> = merged.iter().map(|m| m.id.as_str()).collect();
        // The default safe merge keeps unlisted configured entries and adds
        // the fetched entry.
        assert!(ids.contains(&"hand-added"));
        assert!(ids.contains(&"fetched-old"));
        assert!(ids.contains(&"fetched-new"));
        // The manual entry keeps its manual flag.
        assert!(merged.iter().find(|m| m.id == "hand-added").unwrap().manual);
    }

    #[test]
    fn merge_manual_wins_on_id_collision_no_duplicate() {
        let existing = vec![model("shared", true)];
        // The refetch returns an id that collides with the manual entry.
        let fetched = vec![model("shared", false), model("other", false)];
        let merged = merge_fetched_models_with_policy(
            Some("p"),
            &existing,
            fetched,
            ModelMergePolicy::KeepUnlisted,
        );

        // Exactly one `shared` row, and it's the manual one.
        let shared: Vec<&ModelEntry> = merged.iter().filter(|m| m.id == "shared").collect();
        assert_eq!(shared.len(), 1, "manual entry must dedupe the fetched dup");
        assert!(shared[0].manual);
        // The non-colliding fetched entry is still added.
        assert!(merged.iter().any(|m| m.id == "other" && !m.manual));
    }

    #[test]
    fn merge_policy_remove_drops_unlisted_fetched_entries_but_retains_manual() {
        let existing = vec![model("fetched-old", false), model("hand-added", true)];
        let fetched = vec![model("fetched-new", false)];
        let merged = merge_fetched_models_with_policy(
            Some("p"),
            &existing,
            fetched,
            ModelMergePolicy::RemoveUnlisted,
        );

        let ids: Vec<&str> = merged.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["fetched-new", "hand-added"]);
        assert!(merged.iter().find(|m| m.id == "hand-added").unwrap().manual);
    }

    #[test]
    fn known_frontier_model_ids_are_exact_matches() {
        assert!(is_known_frontier_model_id("gpt-5.4"));
        assert!(is_known_frontier_model_id("gpt-5.5"));
        assert!(is_known_frontier_model_id("gpt-5.6"));
        assert!(is_known_frontier_model_id("glm-5.2"));
        assert!(is_known_frontier_model_id("claude-opus-4-6"));
        assert!(is_known_frontier_model_id("claude-opus-4-7"));
        assert!(is_known_frontier_model_id("claude-opus-4-8"));
        assert!(is_known_frontier_model_id("claude-fable-5"));
        assert!(is_known_frontier_model_id("grok-4.5"));
        assert!(!is_known_frontier_model_id("gpt-5.5-mini"));
        assert!(!is_known_frontier_model_id("grok-4.5-fast"));
        assert!(!is_known_frontier_model_id("openai/gpt-5.5"));
        assert!(!is_known_frontier_model_id("claude-opus-4-5-20251101"));
        assert!(!is_known_frontier_model_id("kimi-for-coding"));
    }

    /// The frontier-defaults gate is an exact-**template** match. A renamed
    /// connection keeps its template identity (so the gate stays keyed to the
    /// vendor, not the config-map key), but an unrelated template id is not a
    /// member.
    #[test]
    fn frontier_default_provider_ids_are_exact_matches() {
        assert!(is_frontier_default_provider_template("anthropic"));
        assert!(is_frontier_default_provider_template("codex-oauth"));
        assert!(is_frontier_default_provider_template("openai"));
        assert!(is_frontier_default_provider_template("grok-oauth"));
        assert!(is_frontier_default_provider_template("z-ai"));
        // A config-map key rename is not a template, so it is not a member —
        // the caller resolves the template identity before consulting the gate.
        assert!(!is_frontier_default_provider_template("anthropic-work"));
        assert!(!is_frontier_default_provider_template("openrouter"));
    }

    /// Frontier defaults are applied only to ids this fetch newly discovers.
    /// Pre-existing ids keep whatever mode they had (here both are pinned);
    /// only the genuinely-new known id (`glm-5.2`) is defaulted to frontier,
    /// and non-known new ids are left alone.
    #[test]
    fn merge_defaults_known_fetched_models_to_frontier_only_when_newly_discovered() {
        let mut existing_normal = model("gpt-5.5", false);
        existing_normal.mode = Some(LlmMode::Normal);
        let mut existing_defensive = model("claude-opus-4-7", false);
        existing_defensive.mode = Some(LlmMode::Defensive);

        let fetched = vec![
            model("glm-5.2", false),
            model("gpt-5.5", false),
            model("claude-opus-4-7", false),
            model("gpt-5.5-mini", false),
            model("ordinary", false),
        ];
        let merged = merge_fetched_models_with_policy(
            Some("codex-oauth"),
            &[existing_normal, existing_defensive],
            fetched,
            ModelMergePolicy::RemoveUnlisted,
        );
        let mode_for = |id: &str| merged.iter().find(|m| m.id == id).and_then(|m| m.mode);

        // Newly-discovered known id → frontier default.
        assert_eq!(mode_for("glm-5.2"), Some(LlmMode::Frontier));
        // Pre-existing ids keep their pinned modes (no re-default).
        assert_eq!(mode_for("gpt-5.5"), Some(LlmMode::Normal));
        assert_eq!(mode_for("claude-opus-4-7"), Some(LlmMode::Defensive));
        // New but non-known ids are untouched.
        assert_eq!(mode_for("gpt-5.5-mini"), None);
        assert_eq!(mode_for("ordinary"), None);
    }

    /// An existing known-frontier id whose `mode` the user cleared back to
    /// inherit stays `None` after a `/models` re-merge — the frontier default
    /// is not re-applied to already-configured ids.
    #[test]
    fn merge_does_not_repin_cleared_mode_on_existing_known_frontier_id() {
        // gpt-5.5 already configured with mode explicitly cleared to inherit.
        let existing = model("gpt-5.5", false);
        assert_eq!(existing.mode, None);

        let merged = merge_fetched_models_with_policy(
            Some("codex-oauth"),
            &[existing],
            vec![model("gpt-5.5", false)],
            ModelMergePolicy::KeepUnlisted,
        );

        let out = merged.iter().find(|m| m.id == "gpt-5.5").unwrap();
        assert_eq!(out.mode, None, "cleared mode must survive a refresh");
    }

    /// A manual entry's hand-set display name and context window survive an
    /// upstream `/models` collision, while a non-manual entry in the same merge
    /// takes the fresh upstream name/context_length.
    #[test]
    fn merge_preserves_manual_name_and_context_length_across_refresh() {
        let mut manual = model("hand", true);
        manual.name = Some("My Handle".to_string());
        manual.context_length = Some(8_192);
        let non_manual = model("auto", false);

        let mut fetched_manual = model("hand", false);
        fetched_manual.name = Some("Upstream Hand".to_string());
        fetched_manual.context_length = Some(200_000);
        let mut fetched_non_manual = model("auto", false);
        fetched_non_manual.name = Some("Upstream Auto".to_string());
        fetched_non_manual.context_length = Some(128_000);

        let merged = merge_fetched_models_with_policy(
            Some("p"),
            &[manual, non_manual],
            vec![fetched_manual, fetched_non_manual],
            ModelMergePolicy::KeepUnlisted,
        );
        let by_id = |id: &str| merged.iter().find(|m| m.id == id).unwrap();

        // Manual entry keeps its hand-set name + context window.
        let hand = by_id("hand");
        assert!(hand.manual);
        assert_eq!(hand.name.as_deref(), Some("My Handle"));
        assert_eq!(hand.context_length, Some(8_192));

        // Non-manual entry takes the fresh upstream metadata.
        let auto = by_id("auto");
        assert!(!auto.manual);
        assert_eq!(auto.name.as_deref(), Some("Upstream Auto"));
        assert_eq!(auto.context_length, Some(128_000));
    }

    /// The frontier defaults are provider-scoped: the same known id fetched
    /// from an aggregator (OpenRouter etc.) is left completely alone.
    #[test]
    fn frontier_defaults_do_not_apply_outside_the_standard_providers() {
        let merged = merge_fetched_models_with_policy(
            Some("openrouter"),
            &[],
            vec![model("gpt-5.5", false), model("claude-fable-5", false)],
            ModelMergePolicy::KeepUnlisted,
        );
        for m in &merged {
            assert_eq!(m.mode, None, "{}", m.id);
            assert_eq!(m.auto_prune, None, "{}", m.id);
            assert_eq!(m.cache, None, "{}", m.id);
        }
    }

    /// Discovered known-frontier models on the standard providers get the
    /// full default set: frontier mode, auto-prune off, ephemeral cache —
    /// each only when the field is still unset.
    #[test]
    fn frontier_defaults_set_auto_prune_off_and_ephemeral_cache() {
        let mut pinned = model("claude-fable-5", false);
        pinned.auto_prune = Some(true);
        pinned.cache = Some(CacheConfig {
            mode: CacheMode::None,
            ttl_secs: 60,
        });

        let merged = merge_fetched_models_with_policy(
            Some("anthropic"),
            &[pinned.clone()],
            vec![
                model("claude-fable-5", false),
                model("claude-opus-4-8", false),
                model("claude-haiku-4-5-20251001", false),
            ],
            ModelMergePolicy::KeepUnlisted,
        );
        let by_id = |id: &str| merged.iter().find(|m| m.id == id).unwrap();

        // Fresh known id → all three defaults.
        let opus = by_id("claude-opus-4-8");
        assert_eq!(opus.mode, Some(LlmMode::Frontier));
        assert_eq!(opus.auto_prune, Some(false));
        assert_eq!(
            opus.cache,
            Some(CacheConfig {
                mode: CacheMode::Ephemeral,
                ttl_secs: 300,
            })
        );

        // A pre-existing known id is never re-defaulted: its pinned values
        // survive and its unset `mode` stays `None` (no re-pin to frontier).
        let fable = by_id("claude-fable-5");
        assert_eq!(fable.auto_prune, Some(true));
        assert_eq!(fable.cache, pinned.cache);
        assert_eq!(fable.mode, None);

        // Non-frontier ids on the same provider stay untouched.
        let haiku = by_id("claude-haiku-4-5-20251001");
        assert_eq!(haiku.mode, None);
        assert_eq!(haiku.auto_prune, None);
        assert_eq!(haiku.cache, None);
    }

    /// The plain OpenAI API-key template and the SuperGrok OAuth template both
    /// serve their frontier ids verbatim and prompt-cache, so a fresh known id
    /// discovered on either gets the frontier defaults.
    #[test]
    fn merge_applies_frontier_defaults_for_openai_and_grok_templates() {
        for (template, id) in [("openai", "gpt-5.6"), ("grok-oauth", "grok-4.5")] {
            let merged = merge_fetched_models_with_policy(
                Some(template),
                &[],
                vec![model(id, false)],
                ModelMergePolicy::KeepUnlisted,
            );
            let m = merged.iter().find(|m| m.id == id).unwrap();
            assert_eq!(m.mode, Some(LlmMode::Frontier), "{template}/{id} mode");
            assert_eq!(m.auto_prune, Some(false), "{template}/{id} auto_prune");
            assert_eq!(
                m.cache.as_ref().map(|c| c.mode),
                Some(CacheMode::Ephemeral),
                "{template}/{id} cache"
            );
        }
    }

    /// `effective_template` prefers the stored `template`, otherwise falls back
    /// to the config-map key when that key itself names a known template — and
    /// resolves to `None` for a renamed/custom provider with no stored template.
    #[test]
    fn effective_template_prefers_stored_then_falls_back_to_known_key() {
        // Stored template wins even under a renamed key.
        let renamed = ProviderEntry {
            template: Some("anthropic".into()),
            url: "https://x".into(),
            ..ProviderEntry::default()
        };
        assert_eq!(
            renamed.effective_template("anthropic-work"),
            Some("anthropic")
        );

        // Pre-`template` config whose key still names a known template.
        let legacy = ProviderEntry {
            url: "https://x".into(),
            ..ProviderEntry::default()
        };
        assert_eq!(legacy.effective_template("anthropic"), Some("anthropic"));

        // Custom provider with no stored template and a non-template key.
        let custom = ProviderEntry {
            url: "https://x".into(),
            ..ProviderEntry::default()
        };
        assert_eq!(custom.effective_template("my-endpoint"), None);
    }

    /// A renamed first-party connection (custom key, stored `template`) still
    /// gets the frontier defaults, while a genuinely custom provider (no
    /// template, non-template key) does not.
    #[test]
    fn frontier_defaults_follow_template_identity_not_the_config_key() {
        // Second Anthropic connection under a custom key.
        let work = ProviderEntry {
            template: Some("anthropic".into()),
            url: "https://api.anthropic.com".into(),
            ..ProviderEntry::default()
        };
        let merged = merge_fetched_models_with_policy(
            work.effective_template("anthropic-work"),
            &[],
            vec![model("claude-opus-4-8", false)],
            ModelMergePolicy::KeepUnlisted,
        );
        assert_eq!(
            merged
                .iter()
                .find(|m| m.id == "claude-opus-4-8")
                .unwrap()
                .mode,
            Some(LlmMode::Frontier),
        );

        // Custom provider that merely serves a known id gets nothing.
        let custom = ProviderEntry {
            url: "https://example.com".into(),
            ..ProviderEntry::default()
        };
        let merged = merge_fetched_models_with_policy(
            custom.effective_template("my-endpoint"),
            &[],
            vec![model("claude-opus-4-8", false)],
            ModelMergePolicy::KeepUnlisted,
        );
        let m = merged.iter().find(|m| m.id == "claude-opus-4-8").unwrap();
        assert_eq!(m.mode, None);
        assert_eq!(m.auto_prune, None);
        assert_eq!(m.cache, None);
    }

    #[test]
    fn resolve_auto_prune_prefers_model_then_provider_then_on() {
        let mut cfg = ProvidersConfig::default();
        let mut off_model = model("frontier-ish", false);
        off_model.auto_prune = Some(false);
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                url: "https://x".into(),
                auto_prune: Some(true),
                models: vec![off_model, model("bare", false)],
                ..ProviderEntry::default()
            },
        );

        // Model override wins over the provider value.
        assert!(!cfg.resolve_auto_prune("p", "frontier-ish"));
        // Bare model inherits the provider override.
        assert!(cfg.resolve_auto_prune("p", "bare"));
        // Unknown provider/model resolves to on.
        assert!(cfg.resolve_auto_prune("nope", "x"));

        // Provider-level off applies to models without their own pin.
        cfg.providers.get_mut("p").unwrap().auto_prune = Some(false);
        assert!(!cfg.resolve_auto_prune("p", "bare"));
    }

    #[test]
    fn fetched_known_frontier_model_gets_model_mode_even_with_provider_mode() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "codex-oauth".into(),
            ProviderEntry {
                url: "https://x".into(),
                mode: Some(LlmMode::Defensive),
                models: merge_fetched_models_with_policy(
                    Some("codex-oauth"),
                    &[],
                    vec![model("gpt-5.5", false)],
                    ModelMergePolicy::KeepUnlisted,
                ),
                ..ProviderEntry::default()
            },
        );

        let row = &cfg.providers["codex-oauth"].models[0];
        assert_eq!(row.mode, Some(LlmMode::Frontier));
        assert_eq!(
            cfg.resolve_mode("codex-oauth", "gpt-5.5", LlmMode::Normal),
            LlmMode::Frontier
        );
    }

    #[test]
    fn merge_preserves_model_override_fields_on_matching_fetched_id() {
        let mut existing = model("shared", true);
        existing.favorite = true;
        existing.cache = Some(CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 3600,
        });
        existing.context = Some(ContextConfig {
            auto_compact_pct: 70,
            auto_prune_pct: 45,
            auto_prune_prunable_pct: 20,
        });
        existing.timeout = Some(TimeoutConfig {
            ttft_secs: 77,
            idle_secs: 55,
        });
        existing.backup = Some(BackupConfig {
            provider: "paid".to_string(),
            model: "backup".to_string(),
        });
        existing.trust = Some(ModelTrust::Trusted);
        existing.location = Some(ModelLocation::Local);
        existing.quality_rank = Some(12);
        existing.cost_rank = Some(-2);
        existing.subagent_invokable = Some(true);
        existing.availability.categories = vec!["reasoning".to_string()];
        existing.inline_think = Some(false);
        existing.hint_tool_call_corrections = Some(false);
        existing.wire_api = WireApi::Responses;
        existing.auto_prune = Some(false);

        let mut fetched = model("shared", false);
        fetched.name = Some("Fresh remote name".to_string());
        fetched.context_length = Some(123_456);

        let merged = merge_fetched_models_with_policy(
            Some("p"),
            &[existing.clone()],
            vec![fetched],
            ModelMergePolicy::RemoveUnlisted,
        );

        assert_eq!(merged.len(), 1);
        let out = &merged[0];
        assert_eq!(out.name.as_deref(), Some("Fresh remote name"));
        assert_eq!(out.context_length, Some(123_456));
        assert!(out.manual);
        assert!(out.favorite);
        assert_eq!(out.cache, existing.cache);
        assert_eq!(out.context, existing.context);
        assert_eq!(out.timeout, existing.timeout);
        assert_eq!(out.backup, existing.backup);
        assert_eq!(out.trust, Some(ModelTrust::Trusted));
        assert_eq!(out.location, Some(ModelLocation::Local));
        assert_eq!(out.quality_rank, Some(12));
        assert_eq!(out.cost_rank, Some(-2));
        assert_eq!(out.subagent_invokable, Some(true));
        assert_eq!(out.availability.categories, vec!["reasoning"]);
        assert_eq!(out.inline_think, Some(false));
        assert_eq!(out.hint_tool_call_corrections, Some(false));
        assert_eq!(out.wire_api, WireApi::Responses);
        assert_eq!(out.auto_prune, Some(false));
    }

    // --- wire-API endpoint routing (implementation note)

    /// Layer 2 name auto-detect: `gpt-5*` (case-insensitive) is responses-only;
    /// everything else (including `gpt-4o`, `gpt-50`, a too-short id) is
    /// completions — today's default for every existing model.
    #[test]
    fn wire_api_detect_heuristic_is_gpt5_prefix_case_insensitive() {
        use WireApi::{Completions, Responses};
        assert_eq!(WireApi::detect("gpt-5"), Responses);
        assert_eq!(WireApi::detect("gpt-5.4-mini"), Responses);
        assert_eq!(WireApi::detect("gpt-5o"), Responses);
        // Case-insensitive on the prefix.
        assert_eq!(WireApi::detect("GPT-5.4-mini"), Responses);
        assert_eq!(WireApi::detect("Gpt-5"), Responses);
        // Everything else → completions.
        assert_eq!(WireApi::detect("gpt-4o-mini"), Completions);
        assert_eq!(WireApi::detect("claude-opus-4-7"), Completions);
        assert_eq!(WireApi::detect("glm-4.6"), Completions);
        // A non-`gpt-5` id that merely shares a shorter prefix is completions.
        assert_eq!(WireApi::detect("gpt-4"), Completions);
        // Too-short ids never panic and default to completions.
        assert_eq!(WireApi::detect("gpt"), Completions);
        assert_eq!(WireApi::detect(""), Completions);
    }

    #[test]
    fn grok_providers_default_to_responses_wire_api() {
        assert_eq!(
            WireApi::detect_for_provider("grok", "grok-4.3"),
            WireApi::Responses
        );
        assert_eq!(
            WireApi::detect_for_provider("grok-oauth", "grok-4.3"),
            WireApi::Responses
        );
    }

    #[test]
    fn codex_oauth_defaults_to_responses_wire_api() {
        assert_eq!(
            WireApi::detect_for_provider("codex-oauth", "gpt-5.5"),
            WireApi::Responses
        );
    }

    /// `opposite` is the bidirectional swap target the fallback retries.
    #[test]
    fn wire_api_opposite_is_bidirectional() {
        assert_eq!(WireApi::Responses.opposite(), WireApi::Completions);
        assert_eq!(WireApi::Completions.opposite(), WireApi::Responses);
        // `Auto` is never the resolved value; defensively → Responses.
        assert_eq!(WireApi::Auto.opposite(), WireApi::Responses);
    }

    /// Layer 1 (explicit config) wins over layer 2 (auto-detect): a pinned
    /// `completions`/`responses` is returned verbatim; an `auto` (or unknown
    /// provider/model) returns `Auto` so the build path falls through to
    /// `detect`.
    #[test]
    fn resolve_wire_api_explicit_config_wins() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            ..ProviderEntry::default()
        };
        // A `gpt-5` model that the heuristic would route to responses, but is
        // explicitly pinned to completions: the pin must win.
        let mut pinned = model("gpt-5.4-mini", false);
        pinned.wire_api = WireApi::Completions;
        entry.models.push(pinned);
        // A model left on `auto`.
        entry.models.push(model("gpt-4o", false));
        cfg.providers.insert("p".into(), entry);

        // Explicit pin returned verbatim (caller will NOT auto-detect).
        assert_eq!(
            cfg.resolve_wire_api("p", "gpt-5.4-mini"),
            WireApi::Completions
        );
        // `auto` model → Auto (caller auto-detects).
        assert_eq!(cfg.resolve_wire_api("p", "gpt-4o"), WireApi::Auto);
        // Unknown model / provider → Auto.
        assert_eq!(cfg.resolve_wire_api("p", "missing"), WireApi::Auto);
        assert_eq!(cfg.resolve_wire_api("nope", "x"), WireApi::Auto);
        assert!(!cfg.is_wire_api_explicit("p", "gpt-4o"));
        assert!(cfg.is_wire_api_explicit("p", "gpt-5.4-mini"));
    }

    #[test]
    fn resolve_wire_api_provider_default_between_model_and_auto() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            wire_api: WireApi::Completions,
            ..ProviderEntry::default()
        };
        entry.models.push(model("inherits", false));
        let mut pinned = model("pins-responses", false);
        pinned.wire_api = WireApi::Responses;
        entry.models.push(pinned);
        cfg.providers.insert("p".into(), entry);

        assert_eq!(cfg.resolve_wire_api("p", "inherits"), WireApi::Completions);
        assert_eq!(
            cfg.resolve_wire_api("p", "pins-responses"),
            WireApi::Responses
        );
        assert_eq!(cfg.resolve_wire_api("p", "missing"), WireApi::Completions);
        assert!(cfg.is_wire_api_explicit("p", "inherits"));
    }

    /// `auto` is the serde default and is skipped on serialize, so configs that
    /// never pin it stay clean and load unchanged; a pinned value round-trips.
    #[test]
    fn wire_api_defaults_auto_and_skips_serialize() {
        // Default + skip.
        let m = model("x", false);
        assert_eq!(m.wire_api, WireApi::Auto);
        let json = serde_json::to_string(&m).unwrap();
        assert!(
            !json.contains("wire_api"),
            "auto must not serialize: {json}"
        );
        // Legacy row without the field loads as auto.
        let legacy: ModelEntry = serde_json::from_str(r#"{"id":"legacy"}"#).unwrap();
        assert_eq!(legacy.wire_api, WireApi::Auto);
        // A pin serializes its lowercase spelling and round-trips.
        let mut pinned = model("y", false);
        pinned.wire_api = WireApi::Responses;
        let json = serde_json::to_string(&pinned).unwrap();
        assert!(json.contains("\"wire_api\":\"responses\""), "{json}");
        let back: ModelEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.wire_api, WireApi::Responses);

        let provider = ProviderEntry {
            url: "https://example.test/v1".into(),
            ..ProviderEntry::default()
        };
        let json = serde_json::to_string(&provider).unwrap();
        assert!(
            !json.contains("wire_api"),
            "provider auto must not serialize: {json}"
        );
        let legacy: ProviderEntry =
            serde_json::from_str(r#"{"url":"https://example.test/v1"}"#).unwrap();
        assert_eq!(legacy.wire_api, WireApi::Auto);
    }

    #[test]
    fn allow_insecure_http_defaults_false_skips_false_and_persists_true() {
        let legacy: ProviderEntry =
            serde_json::from_str(r#"{"url":"https://example.test/v1"}"#).unwrap();
        assert!(!legacy.allow_insecure_http);

        let provider = ProviderEntry {
            url: "https://example.test/v1".into(),
            ..ProviderEntry::default()
        };
        let json = serde_json::to_string(&provider).unwrap();
        assert!(
            !json.contains("allow_insecure_http"),
            "false opt-in must not serialize: {json}"
        );

        let provider = ProviderEntry {
            allow_insecure_http: true,
            ..provider
        };
        let json = serde_json::to_string(&provider).unwrap();
        assert!(
            json.contains("\"allow_insecure_http\":true"),
            "true opt-in must serialize: {json}"
        );
        let back: ProviderEntry = serde_json::from_str(&json).unwrap();
        assert!(back.allow_insecure_http);
        assert_eq!(back.url, "https://example.test/v1");
    }

    /// A user-or-fallback-pinned `wire_api` survives a `/models` refresh: the
    /// refetched (always-`auto`) entry inherits the prior pin instead of
    /// resetting it.
    #[test]
    fn merge_preserves_pinned_wire_api_across_refetch() {
        let mut prev = model("gpt-5.4-mini", false);
        prev.wire_api = WireApi::Responses; // self-healed last session
        let existing = vec![prev];
        // The refetch returns the same id, freshly `auto` (upstream never
        // carries wire_api), plus a new unrelated model.
        let fetched = vec![model("gpt-5.4-mini", false), model("gpt-4o", false)];
        let merged = merge_fetched_models_with_policy(
            Some("p"),
            &existing,
            fetched,
            ModelMergePolicy::KeepUnlisted,
        );

        let healed = merged.iter().find(|m| m.id == "gpt-5.4-mini").unwrap();
        assert_eq!(
            healed.wire_api,
            WireApi::Responses,
            "a pinned endpoint must survive a /models refresh"
        );
        // An unpinned new model stays auto.
        let fresh = merged.iter().find(|m| m.id == "gpt-4o").unwrap();
        assert_eq!(fresh.wire_api, WireApi::Auto);
    }

    #[test]
    fn capability_enum_serde_names_are_stable() {
        assert_eq!(
            serde_json::to_value(CapabilitySource::ProviderRule).unwrap(),
            serde_json::json!("provider_rule")
        );
        assert_eq!(
            serde_json::to_value(CapabilitySource::LegacySynthesized).unwrap(),
            serde_json::json!("legacy_synthesized")
        );
        assert_eq!(
            serde_json::to_value(CapabilityStatus::RequiresEntitlement).unwrap(),
            serde_json::json!("requires_entitlement")
        );
        assert_eq!(
            serde_json::to_value(ModelFetchStatusKind::FailedKeptExisting).unwrap(),
            serde_json::json!("failed_kept_existing")
        );
    }

    #[test]
    fn provider_and_model_capability_schema_round_trips() {
        let raw = r#"{
            "url": "https://example.test/v1",
            "provider_metadata": { "organization": "xai" },
            "capabilities": {
              "client_side_tools": {
                "status": "requires_entitlement",
                "entitlement": "supergrok",
                "source": "provider_rule"
              }
            },
            "last_model_fetch": {
              "status": "failed_kept_existing",
              "at": "2026-06-18T00:00:00Z",
              "source": "live",
              "reason": "http 503"
            },
            "models": [{
              "id": "gpt-5-mini",
              "capabilities": {
                "reasoning_effort": {
                  "values": [
                    { "value": "minimal", "label": "Minimal" },
                    { "value": "xhigh", "description": "extra high" }
                  ],
                  "default": "minimal",
                  "request_mapping": {
                    "type": "json_field",
                    "field": "reasoning_effort",
                    "values": { "minimal": "minimal", "xhigh": "xhigh" }
                  },
                  "source": "live"
                },
                "client_side_tools": { "status": "supported", "source": "live" }
              },
              "provider_metadata": { "owned_by": "openai" },
              "extra": { "legacy": true }
            }]
        }"#;
        let entry: ProviderEntry = serde_json::from_str(raw).unwrap();
        assert_eq!(
            entry.capabilities.client_side_tools.status,
            CapabilityStatus::RequiresEntitlement
        );
        assert_eq!(
            entry.last_model_fetch.as_ref().unwrap().status,
            ModelFetchStatusKind::FailedKeptExisting
        );
        let model = &entry.models[0];
        assert_eq!(
            model
                .capabilities
                .reasoning_effort
                .as_ref()
                .unwrap()
                .default
                .as_deref(),
            Some("minimal")
        );
        assert_eq!(
            model
                .provider_metadata
                .get("owned_by")
                .and_then(Value::as_str),
            Some("openai")
        );
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProviderEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.models[0].capabilities, model.capabilities);
        assert_eq!(back.provider_metadata, entry.provider_metadata);
    }

    #[test]
    fn legacy_configs_load_with_unknown_default_capability_state() {
        let model: ModelEntry = serde_json::from_str(
            r#"{"id":"legacy","thinking_modes":["off","high"],"inputs":{"images":true}}"#,
        )
        .unwrap();
        assert_eq!(
            model.thinking_modes,
            vec![ThinkingMode::Off, ThinkingMode::High]
        );
        assert!(model.capabilities.is_empty());
        assert!(model.provider_metadata.is_empty());

        let provider: ProviderEntry =
            serde_json::from_str(r#"{"url":"https://example.test/v1"}"#).unwrap();
        assert!(provider.capabilities.is_empty());
        assert!(provider.last_model_fetch.is_none());
        assert!(provider.provider_metadata.is_empty());
    }

    #[test]
    fn reasoning_effort_projection_is_documented_compatibility_only() {
        let capability = ReasoningEffortCapability {
            values: vec![
                CapabilityValue {
                    value: "off".into(),
                    ..Default::default()
                },
                CapabilityValue {
                    value: "minimal".into(),
                    ..Default::default()
                },
                CapabilityValue {
                    value: "low".into(),
                    ..Default::default()
                },
                CapabilityValue {
                    value: "xhigh".into(),
                    ..Default::default()
                },
                CapabilityValue {
                    value: "high".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            project_reasoning_effort_to_thinking_modes(&capability),
            vec![ThinkingMode::Off, ThinkingMode::Low, ThinkingMode::High]
        );
    }

    #[test]
    fn client_side_tools_resolution_precedence() {
        let mut cfg = ProvidersConfig::default();
        let mut provider = ProviderEntry {
            url: "https://example.test/v1".into(),
            capabilities: ProviderCapabilities {
                client_side_tools: ClientSideToolsCapability {
                    status: CapabilityStatus::RequiresEntitlement,
                    entitlement: Some("provider-plan".into()),
                    source: Some(CapabilitySource::ProviderRule),
                },
                ..ProviderCapabilities::default()
            },
            ..ProviderEntry::default()
        };
        let mut model_override = model("model-override", false);
        model_override.capabilities.client_side_tools = ClientSideToolsCapability {
            status: CapabilityStatus::Supported,
            entitlement: None,
            source: Some(CapabilitySource::Manual),
        };
        provider.models.push(model_override);
        provider.models.push(model("provider-override", false));
        cfg.providers.insert("p".into(), provider);

        let rule = ClientSideToolsCapability {
            status: CapabilityStatus::Unsupported,
            entitlement: None,
            source: Some(CapabilitySource::ProviderRule),
        };
        assert_eq!(
            cfg.resolve_client_side_tools("p", "model-override", Some(rule.clone()))
                .status,
            CapabilityStatus::Supported
        );
        let inherited = cfg.resolve_client_side_tools("p", "provider-override", Some(rule.clone()));
        assert_eq!(inherited.status, CapabilityStatus::RequiresEntitlement);
        assert_eq!(inherited.entitlement.as_deref(), Some("provider-plan"));
        assert_eq!(
            cfg.resolve_client_side_tools("missing", "x", Some(rule))
                .status,
            CapabilityStatus::Unsupported
        );
        assert!(
            cfg.resolve_client_side_tools("missing", "x", None)
                .is_empty()
        );
    }

    #[test]
    fn xai_multi_agent_provider_rule_requires_entitlement() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "grok-oauth".into(),
            ProviderEntry {
                url: "https://api.x.ai/v1".into(),
                ..ProviderEntry::default()
            },
        );

        let capability =
            cfg.resolve_effective_client_side_tools("grok-oauth", "grok-4.20-multi-agent-0309");
        assert_eq!(capability.status, CapabilityStatus::RequiresEntitlement);
        assert_eq!(
            capability.entitlement.as_deref(),
            Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT)
        );
        assert_eq!(capability.source, Some(CapabilitySource::ProviderRule));

        assert!(
            cfg.resolve_effective_client_side_tools("grok-oauth", "grok-4.3")
                .is_empty()
        );
    }

    #[test]
    fn xai_multi_agent_detection_uses_layered_provider_evidence() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "custom-url".into(),
            ProviderEntry {
                url: "https://api.x.ai/v1".into(),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "custom-credential".into(),
            ProviderEntry {
                url: "https://example.test/v1".into(),
                credential_ref: Some("grok-oauth".into()),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "custom-metadata".into(),
            ProviderEntry {
                url: "https://example.test/v1".into(),
                provider_metadata: serde_json::json!({ "provider": "xAI" })
                    .as_object()
                    .unwrap()
                    .clone(),
                ..ProviderEntry::default()
            },
        );

        for provider_id in ["custom-url", "custom-credential", "custom-metadata"] {
            assert_eq!(
                cfg.resolve_effective_client_side_tools(provider_id, "grok-build-multi-agent")
                    .status,
                CapabilityStatus::RequiresEntitlement,
                "{provider_id} should be recognized as xAI/Grok"
            );
        }
    }

    #[test]
    fn xai_multi_agent_manual_capabilities_override_provider_rule() {
        let mut cfg = ProvidersConfig::default();
        let mut provider = ProviderEntry {
            url: "https://api.x.ai/v1".into(),
            capabilities: ProviderCapabilities {
                client_side_tools: ClientSideToolsCapability {
                    status: CapabilityStatus::Supported,
                    entitlement: Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT.into()),
                    source: Some(CapabilitySource::Manual),
                },
                ..ProviderCapabilities::default()
            },
            ..ProviderEntry::default()
        };
        let mut model_override = model("grok-4.20-multi-agent-0309", false);
        model_override.capabilities.client_side_tools = ClientSideToolsCapability {
            status: CapabilityStatus::RequiresEntitlement,
            entitlement: Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT.into()),
            source: Some(CapabilitySource::Manual),
        };
        provider.models.push(model_override);
        provider.models.push(model("grok-build-multi-agent", false));
        cfg.providers.insert("grok".into(), provider);

        assert_eq!(
            cfg.resolve_effective_client_side_tools("grok", "grok-build-multi-agent")
                .status,
            CapabilityStatus::Supported
        );
        assert_eq!(
            cfg.resolve_effective_client_side_tools("grok", "grok-4.20-multi-agent-0309")
                .status,
            CapabilityStatus::RequiresEntitlement
        );
    }

    #[test]
    fn model_fetch_failure_status_classifies_auth_and_redacts_reason() {
        let mut provider = ProviderEntry::default();
        provider.mark_model_fetch_failed_kept_existing(
            "https://api.example.test/v1/models returned 401 — credentials rejected. Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456",
        );

        let status = provider.last_model_fetch.unwrap();
        assert_eq!(status.status, ModelFetchStatusKind::AuthFailed);
        let reason = status.reason.unwrap();
        assert!(reason.contains("credentials rejected"));
        assert!(reason.contains("[redacted]"));
        assert!(!reason.contains("sk-test-token"));

        let mut provider = ProviderEntry::default();
        provider.mark_model_fetch_failed_kept_existing(
            "https://api.example.test/v1/models returned 503",
        );
        assert_eq!(
            provider.last_model_fetch.unwrap().status,
            ModelFetchStatusKind::FailedKeptExisting
        );
    }

    #[test]
    fn model_fetch_fallback_status_records_redacted_reason() {
        let mut provider = ProviderEntry::default();
        provider.mark_model_fetch_fallback(
            "https://api.example.test/v1/models returned 503. Authorization: sk-test-token-abcdefghijklmnopqrstuvwxyz123456",
        );

        let status = provider.last_model_fetch.unwrap();
        assert_eq!(status.status, ModelFetchStatusKind::Fallback);
        assert_eq!(status.source, ModelFetchSource::Fallback);
        let reason = status.reason.unwrap();
        assert!(reason.contains("returned 503"));
        assert!(reason.contains("[redacted]"));
        assert!(!reason.contains("sk-test-token"));
    }

    #[test]
    fn merge_preserves_existing_capabilities_and_provider_metadata() {
        let mut existing = model("gpt-5", false);
        existing.capabilities.client_side_tools = ClientSideToolsCapability {
            status: CapabilityStatus::Supported,
            entitlement: None,
            source: Some(CapabilitySource::Manual),
        };
        existing
            .provider_metadata
            .insert("existing".into(), serde_json::json!(true));
        existing
            .extra
            .insert("legacy_only".into(), serde_json::json!("kept"));
        let mut fetched = model("gpt-5", false);
        fetched
            .provider_metadata
            .insert("upstream".into(), serde_json::json!(true));
        fetched
            .extra
            .insert("upstream".into(), serde_json::json!(true));

        let merged = merge_fetched_models_with_policy(
            Some("p"),
            &[existing],
            vec![fetched],
            ModelMergePolicy::KeepUnlisted,
        );
        let model = &merged[0];
        assert_eq!(
            model.capabilities.client_side_tools.status,
            CapabilityStatus::Supported
        );
        assert_eq!(
            model.provider_metadata.get("existing"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            model.provider_metadata.get("upstream"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            model.provider_metadata.get("legacy_only"),
            Some(&serde_json::json!("kept"))
        );
        assert_eq!(model.extra.get("existing"), Some(&serde_json::json!(true)));
        assert_eq!(
            model.extra.get("legacy_only"),
            Some(&serde_json::json!("kept"))
        );
        assert_eq!(model.extra.get("upstream"), Some(&serde_json::json!(true)));
    }
}
