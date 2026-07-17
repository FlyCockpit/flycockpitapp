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
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::config::extended::{LlmMode, TextEmbeddedRecovery};
use crate::config::merge::deep_merge_value;

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
    "embeddings",
    "availability",
    "wire_api",
    "backup",
    "mode",
    "inline_think",
    "hint_tool_call_corrections",
    "text_embedded_recovery",
    "thinking_params",
    "system_prompt",
    "capabilities",
    "provider_metadata",
    "last_model_fetch",
];

const KNOWN_PROVIDER_TEMPLATE_IDS: &[&str] = &[
    "openai-compatible",
    "openai",
    "codex-oauth",
    "grok",
    "grok-oauth",
    "z-ai",
    "minimax",
    "opencode-zen",
    "copilot",
    "openrouter",
    "deepseek",
    "anthropic",
    "xiaomi-mimo",
];

fn known_provider_template_id(id: &str) -> bool {
    KNOWN_PROVIDER_TEMPLATE_IDS.contains(&id)
}

fn builtin_thinking_params(provider: &str, mode: ThinkingMode) -> Option<Value> {
    match provider {
        "deepseek" => Some(match mode {
            ThinkingMode::Off => json!({ "thinking": { "type": "disabled" } }),
            ThinkingMode::Low => {
                json!({ "thinking": { "type": "enabled" }, "reasoning_effort": "low" })
            }
            ThinkingMode::Medium => {
                json!({ "thinking": { "type": "enabled" }, "reasoning_effort": "medium" })
            }
            ThinkingMode::High => {
                json!({ "thinking": { "type": "enabled" }, "reasoning_effort": "high" })
            }
        }),
        _ => None,
    }
}

pub const XAI_MULTI_AGENT_TOOLS_ENTITLEMENT: &str = "xai_multi_agent_tools_beta";
pub const MODEL_SYSTEM_PROMPT_MAX_BYTES: usize = 1024 * 1024;

pub fn normalize_model_system_prompt(value: &str) -> Option<&str> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

pub fn model_system_prompt_too_large(value: &str) -> bool {
    value.len() > MODEL_SYSTEM_PROMPT_MAX_BYTES
}

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

mod fetch_status;
mod io;

#[allow(unused_imports)]
pub use fetch_status::{
    ProviderModelFetchDisplayState, format_model_fetch_age, model_fetch_reason_display,
    provider_model_fetch_display_state, provider_model_fetch_reason_display,
};
pub use io::{ConfigDoc, is_xai_grok_provider};

pub use io::{load_effective_call_count, load_provider_raw_file, reset_load_effective_call_count};

/// Effective provider config. Global fields are read from layer
/// `config.json`; provider entries are read from sibling `providers/*.json`
/// files. The in-memory shape remains map-based so callers do not need to know
/// about the split on-disk layout.
#[allow(unused_imports)]
pub use crate::config::model_policy::{
    EffectiveModelCapabilities, EmbeddingModelResolutionError, ModelOptimization, ModelPolicyError,
    ModelPolicyRequest, ModelPolicySelector, RequiredModelCapability, ResolvedEmbeddingModel,
    ResolvedModelPolicy,
};

#[allow(unused_imports)]
pub use crate::config::model_defaults::{
    COPILOT_MODEL_MODE_DEFAULTS, FRONTIER_DEFAULT_PROVIDER_IDS, KNOWN_FRONTIER_MODEL_IDS,
    apply_copilot_model_mode_defaults, apply_known_frontier_model_defaults,
    apply_template_model_defaults, copilot_default_mode_for_model_id,
    is_frontier_default_provider_template, is_known_frontier_model_id,
};

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

    /// Provider default for whether models support OpenAI-compatible embeddings.
    /// Missing resolves to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<bool>,

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

default_const!(default_auto_compact_pct, u8, 80);

default_const!(default_auto_prune_pct, u8, 50);

default_const!(default_auto_prune_prunable_pct, u8, 30);

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

default_const!(default_ttft_secs, u64, 120);

default_const!(default_idle_secs, u64, 90);

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

default_const!(default_cache_ttl_secs, u64, 300);

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

default_const!(default_shrink_margin_secs, u64, 30);

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
    /// Model-level embeddings support override. Missing inherits provider
    /// default, then resolves to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<bool>,
    /// Expected embedding vector dimensions for this model. When set, the
    /// OpenAI-compatible embedder rejects mismatched responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimensions: Option<u32>,
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
    /// User-authored model-specific system instructions. Empty and
    /// whitespace-only effective values are treated as unset by callers; the
    /// raw value is preserved byte-for-byte when non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
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

    /// User-authored capability assertions. These sit above fetched/default
    /// [`ModelCapabilities`] in the resolver and survive `/models` refreshes.
    /// Missing fields mean "auto" — use detection/defaults, and serialize
    /// nothing.
    #[serde(default, skip_serializing_if = "ModelCapabilityOverrides::is_empty")]
    pub capability_overrides: ModelCapabilityOverrides,

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
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum ReasoningEffortRequestMapping {
    JsonField {
        field: String,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        values: BTreeMap<String, Value>,
    },
    /// Anthropic's current native adaptive-thinking request shape. `values`
    /// optionally maps Cockpit's advertised selector to Anthropic's effort
    /// vocabulary (for example `xhigh` to `max`).
    AnthropicAdaptive {
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        values: BTreeMap<String, String>,
    },
    /// Anthropic's older fixed-budget thinking request shape. Budgets are
    /// derived deterministically from the resolved output limit.
    AnthropicManual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningEffortWire {
    OpenAiCompatible,
    AnthropicNative,
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
    pub embeddings: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimensions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
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
            && self.embeddings.is_none()
            && self.embedding_dimensions.is_none()
            && self.context_tokens.is_none()
            && self.max_output_tokens.is_none()
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
pub struct ModelCapabilityOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calling: Option<CapabilityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimensions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<CapabilityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_outputs: Option<CapabilityStatus>,
}

impl ModelCapabilityOverrides {
    pub fn is_empty(&self) -> bool {
        self.tool_calling.is_none()
            && self.images.is_none()
            && self.embeddings.is_none()
            && self.embedding_dimensions.is_none()
            && self.context_tokens.is_none()
            && self.max_output_tokens.is_none()
            && self.reasoning.is_none()
            && self.structured_outputs.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderCapabilities {
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub tool_calling: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimensions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
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
            && self.embeddings.is_none()
            && self.embedding_dimensions.is_none()
            && self.context_tokens.is_none()
            && self.max_output_tokens.is_none()
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
/// repair/recovery settings, thinking params, and capability overrides — plus,
/// for manual entries, the hand-set display `name` and `context_length`.
/// Template-scoped model defaults ([`apply_template_model_defaults`]) are
/// applied only to ids that are **newly discovered** by this fetch — i.e. absent
/// from `existing`. Standard first-party providers get frontier defaults for
/// ids on [`KNOWN_FRONTIER_MODEL_IDS`]; GitHub Copilot gets its own exact-id
/// mode table ([`COPILOT_MODEL_MODE_DEFAULTS`]). A previously-configured known
/// id is never re-defaulted, so a user who clears e.g. `mode` back to inherit
/// keeps that state across refreshes.
///
/// Policy-aware merge helper for CLI and TUI refreshes. `template` is the
/// refreshed provider's effective template identity
/// ([`ProviderEntry::effective_template`]) and only scopes template-specific
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
            // Only genuinely newly-discovered ids receive template-scoped
            // defaults. A previously-configured id keeps whatever the user
            // left it as — including an intentionally-cleared `mode` back to
            // inherit — so a `/models` refresh never re-pins it.
            apply_template_model_defaults(template, &mut m);
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

/// Carry an existing entry's user-owned fields onto a colliding fetched entry
/// (which is used as the base). Favorites, manual markers, policy fields,
/// endpoint pins, cache/context/shrink/timeout, auto-prune, backup, mode,
/// inline-think, repair/recovery settings, thinking params, capability
/// overrides, and preserved metadata all survive. For **manual** entries the
/// hand-set display `name`
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
    if existing.embeddings.is_some() {
        fetched.embeddings = existing.embeddings;
    }
    if existing.embedding_dimensions.is_some() {
        fetched.embedding_dimensions = existing.embedding_dimensions;
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
    if existing.system_prompt.is_some() {
        fetched.system_prompt = existing.system_prompt.clone();
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
    if !existing.capability_overrides.is_empty() {
        fetched.capability_overrides = existing.capability_overrides.clone();
    }
    if !existing.capabilities.client_side_tools.is_empty()
        && existing.capabilities.client_side_tools.source == Some(CapabilitySource::Manual)
    {
        fetched.capabilities.client_side_tools = existing.capabilities.client_side_tools.clone();
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
            None if known_provider_template_id(key) => Some(key),
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

pub fn manual_thinking_budget(max_tokens: u64, effort: &str) -> Result<u64> {
    let percent = match effort {
        "low" => 25,
        "medium" => 50,
        "high" => 75,
        "xhigh" => 85,
        _ => anyhow::bail!("unsupported manual Anthropic effort `{effort}`"),
    };
    let reserve = (max_tokens / 5 + u64::from(!max_tokens.is_multiple_of(5))).max(1_024);
    let cap = max_tokens.checked_sub(reserve).with_context(|| {
        format!(
            "Anthropic max_tokens={max_tokens} cannot reserve {reserve} tokens for the final answer"
        )
    })?;
    if cap < 1_024 {
        anyhow::bail!(
            "Anthropic max_tokens={max_tokens} is too small for manual thinking: at least 1024 thinking tokens and a {reserve}-token completion reserve are required"
        );
    }
    let fractional = (max_tokens / 100) * percent + ((max_tokens % 100) * percent) / 100;
    Ok(fractional.max(1_024).min(cap))
}

pub fn validate_reasoning_effort_capability(
    capability: &ReasoningEffortCapability,
    wire: ReasoningEffortWire,
    max_tokens: Option<u64>,
) -> Result<()> {
    if capability.values.is_empty() {
        return Ok(());
    }
    if let Some(default) = capability.default.as_deref()
        && !reasoning_effort_supports_value(capability, default)
    {
        anyhow::bail!("reasoning default `{default}` is not in the advertised values");
    }
    let mapping = capability
        .request_mapping
        .as_ref()
        .context("reasoning effort is advertised without a request mapping")?;
    match (wire, mapping) {
        (
            ReasoningEffortWire::OpenAiCompatible,
            ReasoningEffortRequestMapping::JsonField { field, .. },
        ) => {
            if field.trim().is_empty() {
                anyhow::bail!("reasoning JSON-field mapping has an empty field name");
            }
        }
        (
            ReasoningEffortWire::AnthropicNative,
            ReasoningEffortRequestMapping::AnthropicAdaptive { values },
        ) => {
            for (source, target) in values {
                if !reasoning_effort_supports_value(capability, source) {
                    anyhow::bail!(
                        "adaptive Anthropic effort mapping contains unadvertised source `{source}`"
                    );
                }
                if target.trim().is_empty() {
                    anyhow::bail!(
                        "adaptive Anthropic effort mapping for `{source}` has an empty target"
                    );
                }
            }
            for advertised in &capability.values {
                let target = values
                    .get(&advertised.value)
                    .map(String::as_str)
                    .unwrap_or(&advertised.value);
                if !matches!(target, "low" | "medium" | "high" | "max") {
                    anyhow::bail!(
                        "adaptive Anthropic effort `{}` resolves to unsupported target `{target}`; expected low, medium, high, or max",
                        advertised.value
                    );
                }
            }
        }
        (ReasoningEffortWire::AnthropicNative, ReasoningEffortRequestMapping::AnthropicManual) => {
            let max_tokens = max_tokens.context(
                "manual Anthropic reasoning mapping requires an explicit max output token limit",
            )?;
            for value in &capability.values {
                manual_thinking_budget(max_tokens, &value.value)?;
            }
        }
        (
            ReasoningEffortWire::AnthropicNative,
            ReasoningEffortRequestMapping::JsonField { field, .. },
        ) => {
            anyhow::bail!(
                "native Anthropic reasoning cannot use JSON field `{field}`; configure an anthropic_adaptive or anthropic_manual mapping"
            );
        }
        (ReasoningEffortWire::OpenAiCompatible, _) => {
            anyhow::bail!(
                "Anthropic-native reasoning mapping cannot be used on an OpenAI-compatible wire"
            );
        }
    }
    Ok(())
}

/// Resolve Anthropic's required output limit without guessing from context
/// size. Live catalog metadata wins, followed by a user-authored model
/// override and then an explicit provider default.
pub fn resolve_anthropic_max_tokens(entry: &ProviderEntry, model_id: &str) -> Option<u64> {
    let model = entry.models.iter().find(|model| model.id == model_id);
    model
        .and_then(|model| model.capabilities.max_output_tokens)
        .or_else(|| model.and_then(|model| model.capability_overrides.max_output_tokens))
        .or(entry.capabilities.max_output_tokens)
        .filter(|value| *value > 0)
        .map(u64::from)
}

pub fn validate_anthropic_model_configuration(
    entry: &ProviderEntry,
    model_id: &str,
) -> Result<u64> {
    let max_tokens = resolve_anthropic_max_tokens(entry, model_id).with_context(|| {
        format!(
            "native Anthropic model `{model_id}` has no output limit; fetch catalog metadata or configure model/provider capabilities.max_output_tokens"
        )
    })?;
    if let Some(capability) = entry
        .models
        .iter()
        .find(|model| model.id == model_id)
        .and_then(|model| model.capabilities.reasoning_effort.as_ref())
        && let Err(error) = validate_reasoning_effort_capability(
            capability,
            ReasoningEffortWire::AnthropicNative,
            Some(max_tokens),
        )
    {
        anyhow::bail!("invalid native Anthropic model `{model_id}` capability: {error:#}");
    }
    Ok(max_tokens)
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
    pub fn resolve_model_system_prompt(&self, provider: &str, model: &str) -> Option<&str> {
        self.providers
            .get(provider)
            .and_then(|entry| entry.models.iter().find(|m| m.id == model))
            .and_then(|m| m.system_prompt.as_deref())
            .and_then(normalize_model_system_prompt)
            .filter(|value| !model_system_prompt_too_large(value))
    }

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
        builtin_thinking_params(provider, mode)
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
        self.resolve_reasoning_effort_params_for_wire(
            provider,
            model,
            selected,
            ReasoningEffortWire::OpenAiCompatible,
            None,
        )
        .ok()
        .flatten()
    }

    /// Resolve a typed reasoning mapping for the concrete provider wire.
    /// Native Anthropic mappings are deliberately rejected on OpenAI-compatible
    /// wires and vice versa, so a Claude model id never controls serialization.
    pub fn resolve_reasoning_effort_params_for_wire(
        &self,
        provider: &str,
        model: &str,
        selected: Option<&str>,
        wire: ReasoningEffortWire,
        max_tokens: Option<u64>,
    ) -> Result<Option<Value>> {
        let capability = self
            .providers
            .get(provider)
            .with_context(|| format!("provider `{provider}` is not configured"))?
            .models
            .iter()
            .find(|m| m.id == model)
            .with_context(|| format!("model `{provider}/{model}` is not in the catalog"))?
            .capabilities
            .reasoning_effort
            .as_ref()
            .filter(|capability| !capability.values.is_empty());
        let Some(capability) = capability else {
            return Ok(None);
        };
        let value = match selected {
            Some(selected) if reasoning_effort_supports_value(capability, selected) => {
                Some(selected)
            }
            Some(selected) => {
                anyhow::bail!(
                    "selected reasoning effort `{selected}` is not advertised by `{provider}/{model}`"
                );
            }
            None => capability.default.as_deref(),
        };
        let Some(value) = value else {
            return Ok(None);
        };
        validate_reasoning_effort_capability(capability, wire, max_tokens)?;
        let mapping = capability
            .request_mapping
            .as_ref()
            .context("reasoning effort is advertised without a request mapping")?;
        let params = match mapping {
            ReasoningEffortRequestMapping::JsonField { field, values } => {
                let mapped = values
                    .get(value)
                    .cloned()
                    .unwrap_or_else(|| Value::String(value.to_string()));
                Value::Object(Map::from_iter([(field.clone(), mapped)]))
            }
            ReasoningEffortRequestMapping::AnthropicAdaptive { values } => {
                let effort = values.get(value).map(String::as_str).unwrap_or(value);
                serde_json::json!({
                    "thinking": { "type": "adaptive" },
                    "output_config": { "effort": effort },
                })
            }
            ReasoningEffortRequestMapping::AnthropicManual => {
                let budget = manual_thinking_budget(
                    max_tokens.context("manual Anthropic thinking requires max_tokens")?,
                    value,
                )?;
                serde_json::json!({
                    "thinking": { "type": "enabled", "budget_tokens": budget },
                })
            }
        };
        Ok(Some(params))
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

#[cfg(test)]
mod tests;
