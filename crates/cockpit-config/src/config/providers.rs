//! User-configured provider entries in per-provider config files.
//!
//! Layer-wide provider metadata stays in the selected config file:
//! `config.json` by default, or the filename supplied by `COCKPIT_CONFIG`.
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
//! and `inputs` are all optional. Header values are opaque config strings;
//! the CLI expands `$VAR` and `$secret:<name>` references at use-time.
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

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::config::extended::{ComputerUseMode, TextEmbeddedRecovery};
use crate::config::files::{ConfigMutationLock, atomic_write, remove_file_nofollow};
use crate::config::merge::deep_merge_value;

fn deserialize_nonempty_string<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom("string must not be empty"));
    }
    Ok(value)
}

const PROVIDERS_DIR: &str = "providers";
const PROVIDER_SKIPPED_KEYS: &[&str] = &[
    "name",
    "allow_insecure_http",
    "models_fetched_at",
    "model_catalog",
    "favorite",
    "credential_ref",
    "auth",
    "auth_command",
    "oauth",
    "trust",
    "location",
    "quality_rank",
    "cost_rank",
    "subagent_invokable",
    "can_delegate",
    "computer_use",
    "allow_computer_guidance_proposals",
    "embeddings",
    "availability",
    "wire_api",
    "backup",
    "mode",
    "inline_think",
    "default_thinking_mode",
    "hint_tool_call_corrections",
    "text_embedded_recovery",
    "thinking_params",
    "system_prompt",
    "capabilities",
    "provider_metadata",
    "last_model_fetch",
    "usage_probe",
    "model_field_patches",
    "model_order",
    "model_membership",
];

/// Canonical JSON budget for one authored provider layer, shared by raw
/// writers and daemon edit ingress. Composition does not consume this budget.
pub const MAX_AUTHORED_PROVIDER_ENTRY_BYTES: usize = 256 * 1024;

/// Expected validation failures from the common prospective/durable serializer.
/// Keep these typed through anyhow contexts so RPCs can distinguish quota
/// rejection (before writing) from an actual filesystem or serialization fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderWriteValidationError {
    AuthoredEntryTooLarge,
    DocumentTooLarge,
}

impl std::fmt::Display for ProviderWriteValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AuthoredEntryTooLarge => {
                "authored provider entry exceeds maximum length; no provider configuration was written"
            }
            Self::DocumentTooLarge => {
                "serialized provider/config layer exceeds the readable byte limit; no provider configuration was written"
            }
        })
    }
}

impl std::error::Error for ProviderWriteValidationError {}

const MODEL_WIZARD_MODEL_FIELD_KEYS: &[&str] = &[
    "trust",
    "subagent_invokable",
    "can_delegate",
    "default_thinking_mode",
    "mode",
    "system_prompt",
    "capability_overrides",
];

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

fn config_path_for_layer_path(path: &Path) -> Result<PathBuf> {
    let explicit = crate::config::dirs::explicit_config_override()?;
    // An explicit config file can itself be placed in a providers directory.
    if let Some(target) = explicit.as_ref()
        && (path == target || crate::config::dirs::same_logical_path(path, target))
    {
        return Ok(target.clone());
    }
    if path.extension().and_then(|s| s.to_str()) == Some("json")
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            == Some(PROVIDERS_DIR)
        && let Some(config_dir) = path.parent().and_then(Path::parent)
    {
        // Provider selectors return a sibling path. Preserve the operator's
        // config filename when recovering its owning layer, including when
        // the sibling was canonicalized through a directory alias.
        if let Some(target) = explicit
            && target
                .parent()
                .is_some_and(|parent| crate::config::dirs::same_logical_path(config_dir, parent))
        {
            return Ok(target);
        }
        return Ok(config_dir.join(crate::config::dirs::CONFIG_FILE));
    }
    Ok(path.to_path_buf())
}

mod fetch_status;
mod io;

#[allow(unused_imports)]
pub use fetch_status::{
    ProviderModelFetchDisplayState, format_model_fetch_age, model_fetch_reason_display,
    provider_model_fetch_display_state, provider_model_fetch_reason_display,
};
pub use io::{
    ActiveModelWriteMode, ConfigDoc, RetainedProviderModelFavoriteLock,
    RetainedProviderModelFavoritePostWriteVerifier, RetainedProviderModelFavoritePreWriteVerifier,
    RetainedProviderModelFavoriteTarget, RetainedProviderModelFavoriteWriteError,
    RetainedProviderModelFavoriteWriteReceipt, RetainedProviderModelSource, is_xai_grok_provider,
    retained_provider_model_source_from_workspace_layer_snapshots,
};

pub(crate) use io::next_load_effective_generation;
pub use io::{load_effective_call_count, load_provider_raw_file, reset_load_effective_call_count};

/// The one authoritative effective-default mutation API. Nothing else in the
/// workspace may write `active_model`.
pub use crate::config::effective_default::{
    DefaultUpdateAuthorityBinding, EffectiveDefaultError, EffectiveDefaultMutationResult,
    EffectiveDefaultScope, JournalDiagnostic, JournalRecovery, RecoveredOutcome, RecoveredSink,
    RecoveredTransaction, ResolvedTarget, SessionCompensation, SessionDefaultParticipant,
    SessionRevisionAuthority, TransactionCorrelation, journal_diagnostics, journal_path_for_layer,
    mutate_effective_default, recover_all_effective_default_journals,
    recover_effective_default_journal, recover_layer_journals,
    resolve_effective_default_write_target,
};

#[cfg(any(test, feature = "test-support"))]
pub use crate::config::effective_default::{EffectiveDefaultCrashPoint, set_crash_inject};

/// Effective provider config. Global fields are read from layer
/// `config.json`; provider entries are read from sibling `providers/*.json`
/// files. The in-memory shape remains map-based so callers do not need to know
/// about the split on-disk layout.
#[allow(unused_imports)]
pub use crate::config::model_policy::{
    AvailabilityScope, EffectiveCapabilitySource, EffectiveModelCapabilities,
    EmbeddingModelResolutionError, FailoverCustody, HarnessCustodyTrust, ModelCustody,
    ModelOptimization, ModelPolicyCriteria, ModelPolicyError, ModelPolicySelector,
    NonSensitiveModelPolicyRequest, RedactedRendering, RequiredModelCapability,
    RequiredModelCapabilityOutcome, ResolvedEmbeddingModel, ResolvedInputCapability,
    ResolvedModelPolicy, ResolvedSensitiveModelPolicy, RoutingDiagnostics,
    SensitiveModelPolicyRequest, SensitivePayload, TrustedCustodyGrant,
    required_model_capability_outcome,
};

#[allow(unused_imports)]
pub use crate::config::model_defaults::{
    FRONTIER_DEFAULT_PROVIDER_IDS, KNOWN_FRONTIER_MODEL_IDS, apply_known_frontier_model_defaults,
    apply_template_model_defaults, is_frontier_default_provider_template,
    is_known_frontier_model_id,
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
    /// Runtime-only config snapshot generation stamped by session/TUI loaders.
    /// Not persisted. Used by [`Self::resolve_capabilities`] so late results
    /// are generation-keyed without every call site inventing a generation.
    #[serde(skip)]
    pub resolution_generation: u64,
}

impl ProvidersConfig {
    /// Stamp the authoritative config generation used by capability resolution.
    pub fn with_resolution_generation(mut self, generation: u64) -> Self {
        self.resolution_generation = generation;
        self
    }

    /// Stamp the authoritative config generation used by capability resolution.
    pub fn set_resolution_generation(&mut self, generation: u64) {
        self.resolution_generation = generation;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveModelRef {
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub provider: String,
    #[serde(deserialize_with = "deserialize_nonempty_string")]
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ActiveReasoningEffort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_mode: Option<ThinkingMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_retention: Option<PromptCacheRetention>,
}

impl ActiveModelRef {
    /// Validate invariants that Serde enforces at the wire/config boundary.
    ///
    /// The fields remain public because this is also a configuration DTO, so
    /// in-process protocol clients can construct a value without running its
    /// deserializer. Callers accepting typed values across a trust boundary
    /// must use this check before applying them.
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.provider.is_empty() {
            return Err("active model provider must not be empty");
        }
        if self.model.is_empty() {
            return Err("active model model must not be empty");
        }
        if let Some(effort) = &self.reasoning_effort {
            effort.validate()?;
        }
        Ok(())
    }
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ActiveReasoningEffort {
    pub value: String,
}

impl ActiveReasoningEffort {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.value.is_empty() {
            return Err("active reasoning effort must not be empty");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ActiveReasoningEffort {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            value: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self { value: wire.value };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
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
    /// Absent entries are custom providers; the mutable config-map key never
    /// establishes immutable vendor identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,

    /// Optional declarative API usage probe. When absent, built-in templates
    /// may supply their own default probe. The probe always reuses this
    /// provider's resolved inference headers; it never stores a credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_probe: Option<UsageProbeSpec>,

    /// Base URL. The `/models` endpoint is `{url}/models`; chat lives at
    /// `{url}/chat/completions`. Stored without a trailing slash.
    /// Provider files that only overlay models (favorites, names) omit this
    /// and inherit the URL from a lower layer or leave it empty.
    #[serde(default)]
    pub url: String,

    /// Explicit opt-in that permits plaintext non-loopback HTTP provider URLs.
    /// Defaults to `false`; loopback/local HTTP is still allowed for local
    /// development without this opt-in.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_insecure_http: bool,

    /// HTTP headers to send on every request. Values may contain opaque
    /// `$VAR` environment references or `$secret:<name>` credential-store
    /// references; this crate deliberately preserves both verbatim.
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

    /// External authentication command, expressed as an argv vector (program
    /// followed by arguments). The command is accepted only from a global
    /// user provider layer. Project/workspace layers strip this field before
    /// merging, so merely opening a repository can never authorize process
    /// execution. Each argv item supports the same `${VAR}`, `$VAR`, and
    /// `$secret:<name>` references as provider headers.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_nonempty_argv"
    )]
    pub auth_command: Option<Vec<String>>,

    /// Declarative OAuth flow for custom subscription providers. Unlike
    /// `auth_command`, this contains only data: Cockpit owns the device-code
    /// or PKCE exchange, persists the returned token document in the
    /// credential store, and renders selected response fields into headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthDescriptor>,

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

    /// Provider default for whether models may delegate to subagents.
    /// Missing resolves to true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can_delegate: Option<bool>,

    /// Provider default for computer-use reachability. Missing is neutral
    /// until final resolution, where all-unset resolves to disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_use: Option<ComputerUseMode>,

    /// Provider-layer opt-in for typed computer-use guidance proposals.
    /// `absent | enabled | disabled`; missing is neutral during cross-layer
    /// resolution (see
    /// `cockpit_core::computer::guidance::resolve_enablement`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_computer_guidance_proposals: Option<bool>,

    /// Provider default legacy thinking mode for OpenAI-compatible models
    /// that expose `thinking_modes` but not typed reasoning-effort controls.
    /// Active model selections still win at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_thinking_mode: Option<ThinkingMode>,

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

    /// Native Anthropic Messages API features accepted by this provider.
    /// These vendor-specific request extensions are opt-in so an
    /// Anthropic-compatible gateway receives only the portable Messages wire
    /// unless its configuration explicitly enables them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<AnthropicFeatures>,

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

    /// Provider-level request-wire default. A concrete value applies to models
    /// that do not pin their own `wire_api`; `auto` inherits the selected
    /// provider template's default (or Chat Completions for custom providers).
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

    /// This layer owns a complete catalog, including deliberate removals and
    /// budget trimming. Partial hand-authored model overlays still merge by ID.
    #[serde(default, skip_serializing_if = "is_false")]
    pub models_replace: bool,

    /// Sparse edits over this layer's merged model rows. Settings saves retain
    /// inherited fields in their owning layers instead of copying composed rows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_field_patches: Vec<ModelEntryFieldPatch>,

    /// Explicit complete membership/order after applying this layer's edits.
    /// `Some([])` removes all inherited models; absence preserves merge-by-ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_model_order"
    )]
    pub model_order: Option<Vec<String>>,

    /// Sparse membership intent for large composed catalogs. Tombstones prevent
    /// inherited deletions from returning; placements never copy inherited rows.
    #[serde(default, skip_serializing_if = "ModelMembershipPatch::is_empty")]
    pub model_membership: ModelMembershipPatch,

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
/// fires). The shadow margin is also expressed in percentage points.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextConfig {
    /// Explicit ctx% line where the foreground context is compacted
    /// automatically (the `/compact` machinery runs without a prompt).
    /// When unset, the driver resolves a mode/toolbox-aware default.
    #[serde(default)]
    pub auto_compact_pct: Option<u8>,
    /// At or above this ctx% the root agent is nudged to request its own
    /// compaction when the self-compaction tool is available. Default 60.
    #[serde(default = "default_compact_nudge_pct")]
    pub compact_nudge_pct: u8,
    /// Number of most-recent complete user/assistant exchanges retained
    /// verbatim after compaction. `0` keeps only the handoff. Default 4.
    #[serde(default = "default_compact_keep_recent_turns")]
    pub compact_keep_recent_turns: usize,
    /// Whether to pre-draft a compaction brief near the automatic threshold.
    /// Default true.
    #[serde(default = "default_compact_shadow")]
    pub compact_shadow: bool,
    /// How many percentage points before `auto_compact_pct` shadow drafting
    /// becomes eligible. Default 10.
    #[serde(default = "default_compact_shadow_margin_pct")]
    pub compact_shadow_margin_pct: u8,
    /// Keep a durable rolling compaction brief current at every completed root
    /// turn. Unlike `compact_shadow`, this is not gated on context pressure or
    /// a provider cache lifetime. Default true.
    #[serde(default = "default_rolling_precompaction")]
    pub rolling_precompaction: bool,
    /// Rebuild the rolling brief from the complete history after this many
    /// summarized turns. `0` disables cadence rebuilds. Default 24.
    #[serde(default = "default_rolling_precompaction_rebuild_turns")]
    pub rolling_precompaction_rebuild_turns: usize,
    /// Time without activity after which an attach is considered a resume from
    /// away. `0` disables the away classification. Default 15 minutes.
    #[serde(default = "default_idle_window_secs")]
    pub idle_window_secs: u64,
    /// Optional cache refresh while the user is away. `auto` is deliberately
    /// observed-hit gated: a provider is never pinged until it has reported a
    /// real cached input read for this endpoint. Default `auto`.
    #[serde(default)]
    pub keep_warm: KeepWarmMode,
    /// Policy used when an away resume has an exact rolling snapshot.
    #[serde(default)]
    pub resume_default: ResumeDefault,
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
            auto_compact_pct: None,
            compact_nudge_pct: default_compact_nudge_pct(),
            compact_keep_recent_turns: default_compact_keep_recent_turns(),
            compact_shadow: default_compact_shadow(),
            compact_shadow_margin_pct: default_compact_shadow_margin_pct(),
            rolling_precompaction: default_rolling_precompaction(),
            rolling_precompaction_rebuild_turns: default_rolling_precompaction_rebuild_turns(),
            idle_window_secs: default_idle_window_secs(),
            keep_warm: KeepWarmMode::default(),
            resume_default: ResumeDefault::default(),
            auto_prune_pct: default_auto_prune_pct(),
            auto_prune_prunable_pct: default_auto_prune_prunable_pct(),
        }
    }
}

default_const!(default_compact_nudge_pct, u8, 60);

default_const!(default_compact_keep_recent_turns, usize, 4);

default_const!(default_compact_shadow, bool, true);

default_const!(default_compact_shadow_margin_pct, u8, 10);

default_const!(default_rolling_precompaction, bool, true);

default_const!(default_rolling_precompaction_rebuild_turns, usize, 24);

default_const!(default_idle_window_secs, u64, 15 * 60);

/// Cache refresh policy during the configured idle window. This is a cost
/// optimization only; it never changes resume or context-correctness behavior.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeepWarmMode {
    /// Refresh only after this exact endpoint has reported a cache hit.
    #[default]
    Auto,
    /// Never schedule a cache refresh.
    Off,
}

/// Default action for an away resume with an exact rolling snapshot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResumeDefault {
    Full,
    Compacted,
    #[default]
    Ask,
}

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
/// These thresholds warn and then hard-fail the current attempt with
/// `timeout_ttft` / `timeout_idle`. That unified default keeps failover
/// available for both interactive turns and delegated children instead of
/// letting a stalled stream wait forever.
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

/// Native Anthropic Messages-wire features accepted by a provider.
///
/// Custom Anthropic-compatible endpoints default to both fields disabled.
/// The first-party Anthropic template materializes both as enabled when it
/// creates a provider entry.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnthropicFeatures {
    /// Enable Anthropic `cache_control` request blocks.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prompt_caching: bool,

    /// Enable Anthropic beta headers, including extended cache TTL and
    /// computer-use contracts.
    #[serde(default, skip_serializing_if = "is_false")]
    pub betas: bool,
}

impl AnthropicFeatures {
    pub const fn first_party() -> Self {
        Self {
            prompt_caching: true,
            betas: true,
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.prompt_caching && !self.betas
    }
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

/// Curated retention knowledge for a provider cache. `Observed` intentionally
/// makes no TTL claim: aggregators and compatible endpoints can route each
/// request to a different upstream, so cache hits are the only safe signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheRetentionProfile {
    None,
    KnownFloor {
        secs: u64,
    },
    Observed,
    /// An aggregator can vary its upstream between otherwise identical
    /// requests. Pin provider routing/ordering before expecting locality.
    AggregatorObserved,
}

impl CacheRetentionProfile {
    pub fn known_floor_secs(self) -> Option<u64> {
        match self {
            Self::KnownFloor { secs } => Some(secs),
            Self::None | Self::Observed | Self::AggregatorObserved => None,
        }
    }

    pub fn is_aggregator(self) -> bool {
        matches!(self, Self::AggregatorObserved)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderSpec {
    pub name: String,
    pub value: String,
}

// Header values are literal credentials (`Authorization: Bearer …`):
// diagnostics get the header name only. `ProviderEntry`, `ProvidersConfig`
// and every config document derive `Debug` through this.
impl std::fmt::Debug for HeaderSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeaderSpec")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A provider usage endpoint that can be fetched without vendor-specific
/// Rust code. `endpoint` is either an absolute URL or a root-relative path;
/// root-relative paths are resolved against the provider URL's origin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageProbeSpec {
    pub endpoint: Cow<'static, str>,
    #[serde(default)]
    pub method: UsageProbeMethod,
    pub fields: Cow<'static, [UsageProbeField]>,
}

/// HTTP method for a declarative usage probe. The initial declarative probe
/// contract intentionally supports only GET.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UsageProbeMethod {
    #[default]
    Get,
}

/// One JSON Pointer extraction from a declarative usage response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageProbeField {
    pub pointer: Cow<'static, str>,
    pub label: Cow<'static, str>,
    pub kind: UsageProbeFieldKind,
}

/// Rendering target for an extracted declarative usage field.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageProbeFieldKind {
    Credits,
    RequestsRemaining,
    Percent,
    Text,
}

/// OAuth flows supported by the declarative provider runner.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthFlowKind {
    DeviceCode,
    PkceBrowser,
}

/// Pure-data description of a custom provider's OAuth endpoints and token
/// projection. Header values interpolate top-level token-response fields with
/// `{field_name}` placeholders, for example `Bearer {access_token}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthDescriptor {
    pub flow: OAuthFlowKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_endpoint: Option<String>,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_endpoint: Option<String>,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    pub headers: Vec<OAuthHeaderMapping>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthHeaderMapping {
    pub name: String,
    pub value: String,
}

// The value is a template that may embed a literal credential: name only.
impl std::fmt::Debug for OAuthHeaderMapping {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthHeaderMapping")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl OAuthDescriptor {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.client_id.is_empty() || self.token_endpoint.is_empty() {
            return Err("OAuth client_id and token_endpoint must not be empty");
        }
        match self.flow {
            OAuthFlowKind::DeviceCode
                if self.device_endpoint.as_deref().unwrap_or("").is_empty() =>
            {
                return Err("device-code OAuth requires device_endpoint");
            }
            OAuthFlowKind::PkceBrowser
                if self.authorize_endpoint.as_deref().unwrap_or("").is_empty()
                    || self.redirect_uri.as_deref().unwrap_or("").is_empty() =>
            {
                return Err("PKCE browser OAuth requires authorize_endpoint and redirect_uri");
            }
            _ => {}
        }
        if self.headers.is_empty()
            || self
                .headers
                .iter()
                .any(|header| header.name.is_empty() || header.value.is_empty())
        {
            return Err("OAuth headers must contain non-empty name/value mappings");
        }
        let mut normalized_header_names = std::collections::BTreeSet::new();
        for header in &self.headers {
            if reqwest::header::HeaderName::from_bytes(header.name.as_bytes()).is_err()
                || reqwest::header::HeaderValue::from_str(&header.value).is_err()
            {
                return Err("OAuth headers must contain valid HTTP header mappings");
            }
            if !normalized_header_names.insert(header.name.to_ascii_lowercase()) {
                return Err("OAuth headers must not contain duplicate names");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHeaderConfigError {
    provider_id: String,
}

impl ProviderHeaderConfigError {
    pub const CODE: &'static str = "provider_header_invalid";

    pub fn new(provider_id: &str) -> Self {
        Self {
            provider_id: provider_id.to_string(),
        }
    }

    pub fn code(&self) -> &'static str {
        Self::CODE
    }
}

impl std::fmt::Display for ProviderHeaderConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Provider '{}' has invalid or duplicate HTTP header configuration; edit provider headers before retrying.",
            self.provider_id
        )
    }
}

impl std::error::Error for ProviderHeaderConfigError {}

/// Validate literal header rows without resolving any secret-bearing values.
/// Empty values are valid suppression markers; names and nonempty literal
/// values use the exact parser used by request dispatch.
pub fn validate_provider_headers(
    provider_id: &str,
    headers: &[HeaderSpec],
) -> Result<(), ProviderHeaderConfigError> {
    let mut names = std::collections::BTreeSet::new();
    for header in headers {
        let normalized = header.name.to_ascii_lowercase();
        if !names.insert(normalized.clone())
            || reqwest::header::HeaderName::from_bytes(header.name.as_bytes()).is_err()
            || reqwest::header::HeaderValue::from_str(&header.value).is_err()
        {
            return Err(ProviderHeaderConfigError::new(provider_id));
        }
    }
    Ok(())
}

/// Header names are user-controlled and cannot decide whether a value is
/// sensitive. Only a small set of protocol metadata headers may contain
/// literals; every other non-empty value must be a structurally valid deferred
/// reference (optionally prefixed by a conventional auth scheme). This keeps
/// a custom `x-auth` header from bypassing the protection used by
/// `Authorization` and `x-api-key`.
pub fn is_safe_provider_header_reference(name: &str, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return true;
    }
    // These fields are public protocol metadata, so a conventional literal is
    // useful and safe (for example `anthropic-version: 2023-06-01`).  A `$`
    // is never just waved through, though: config interpolation only expands
    // whole deferred references, and accepting arbitrary dollar-containing
    // text here would create a second, weaker header grammar.
    let public_metadata = matches!(
        name,
        "accept" | "content-type" | "user-agent" | "anthropic-version" | "x-goog-api-client"
    );
    if public_metadata && !value.contains('$') {
        return true;
    }
    let reference = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .or_else(|| value.strip_prefix("Token "))
        .or_else(|| value.strip_prefix("token "))
        .or_else(|| value.strip_prefix("Basic "))
        .or_else(|| value.strip_prefix("basic "))
        .unwrap_or(value)
        .trim();
    valid_header_reference(reference)
}

fn valid_header_reference(value: &str) -> bool {
    if let Some(name) = value.strip_prefix("$secret:") {
        return !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    }
    if let Some(name) = value
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        return valid_env_name(name);
    }
    value.strip_prefix('$').is_some_and(valid_env_name)
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    /// API key carried by an explicit header (Authorization / x-api-key / etc.).
    ApiKey,
    /// OAuth bearer resolved from the credential store at request time.
    #[serde(rename = "oauth")]
    OAuth,
    /// Bearer token and optional headers returned by `auth_command`.
    Command,
    /// No authentication (e.g. a self-hosted ollama server).
    None,
}

fn deserialize_optional_nonempty_argv<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Vec<String>>::deserialize(deserializer)?;
    if value.as_ref().is_some_and(|argv| {
        argv.is_empty() || argv.first().is_some_and(|program| program.is_empty())
    }) {
        return Err(serde::de::Error::custom(
            "auth_command must contain a non-empty executable",
        ));
    }
    Ok(value)
}

/// An owned field edit or complete image for one model. Unchanged composed
/// values never need to fit an edit request or be copied into the editing layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntryFieldPatch {
    pub id: String,
    /// A newly inserted/full-replacement row owns its complete image, including
    /// absence of fields that a hidden lower row with this ID might contain.
    #[serde(default, skip_serializing_if = "is_false")]
    pub replace: bool,
    #[serde(deserialize_with = "deserialize_model_field_set")]
    pub set: BTreeMap<String, Value>,
    #[serde(deserialize_with = "deserialize_model_field_remove")]
    pub remove: Vec<String>,
}

/// Move an existing row after an ID, or to the beginning when `after` is absent.
/// Missing rows in a later lower-layer refresh are never recreated by a move.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelPlacement {
    pub id: String,
    pub after: Option<String>,
}

impl ModelPlacement {
    pub fn apply(&self, order: &mut Vec<String>, strict: bool) -> Result<()> {
        anyhow::ensure!(
            self.after.as_ref() != Some(&self.id),
            "model order placement refers to itself"
        );
        let Some(index) = order.iter().position(|id| id == &self.id) else {
            anyhow::ensure!(!strict, "model order placement has no existing row");
            return Ok(());
        };
        let destination = match &self.after {
            None => 0,
            Some(anchor) => match order.iter().position(|id| id == anchor) {
                Some(anchor_index) => anchor_index + usize::from(anchor_index < index),
                None => {
                    anyhow::ensure!(!strict, "model order placement has no existing anchor");
                    order.len() - 1
                }
            },
        };
        let id = order.remove(index);
        order.insert(destination, id);
        Ok(())
    }

    /// Compare insertion forests with schedules that can use temporary
    /// anchors. Once a row is placed, its order relative to every stationary
    /// or already placed row is final; not-yet-placed rows can still serve as
    /// cheap anchors and move away later.
    pub fn between(before: &[String], after: &[String]) -> Vec<Self> {
        if before == after || after.is_empty() {
            return Vec::new();
        }
        let framing = Self::framing_bytes();
        let indexes = after
            .iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect::<BTreeMap<_, _>>();
        let initial = before.iter().map(|id| indexes[id]).collect::<Vec<_>>();
        let costs = after
            .iter()
            .map(|id| serde_json::to_vec(id).expect("string serializes").len())
            .collect::<Vec<_>>();
        let row_weighted = Self::row_weighted_pins(&initial, &costs);
        let anchor_cost = costs.iter().copied().min().unwrap_or(4).min(4);
        let lower_bound = row_weighted
            .iter()
            .map(|index| costs[*index] + framing + 1 + anchor_cost)
            .sum::<usize>();
        // Even an arbitrary placement program must move the complement of a
        // common subsequence and pay these ID/framing bytes. If that alone is
        // oversized, skip the forest search; the caller can still choose full
        // order, whose framing is smaller, or reject the exact charged edit.
        if lower_bound > MAX_AUTHORED_PROVIDER_ENTRY_BYTES {
            let pinned = row_weighted
                .iter()
                .map(|index| after[*index].as_str())
                .collect();
            return Self::for_pinned_order(after, &pinned);
        }
        let mut best =
            Self::insertion_forest_between(before, after, &std::collections::BTreeSet::new());
        let mut best_bytes = serde_json::to_vec(&best)
            .expect("placements serialize")
            .len();
        let pinned = best
            .iter()
            .map(|placement| indexes[&placement.id])
            .collect::<std::collections::BTreeSet<_>>();
        let mut pin_sets = vec![pinned];
        if !pin_sets.contains(&row_weighted) {
            pin_sets.push(row_weighted);
        }
        for pinned in pin_sets {
            let desired = pinned.iter().copied().collect::<Vec<_>>();
            let mut by_cost = desired.clone();
            by_cost.sort_by_key(|index| (costs[*index], *index));
            let schedules = [
                desired.clone(),
                desired.into_iter().rev().collect(),
                by_cost.clone(),
                by_cost.into_iter().rev().collect(),
            ];
            for schedule in schedules {
                for allow_scaffolds in [false, true] {
                    let mut pending = std::collections::VecDeque::from(schedule.clone());
                    let mut current = initial.clone();
                    let mut fixed = (0..after.len())
                        .filter(|index| !pinned.contains(index))
                        .collect::<std::collections::BTreeSet<_>>();
                    let mut placed = vec![false; after.len()];
                    let mut program = Vec::with_capacity(pinned.len());
                    let mut program_bytes = 2usize;
                    let mut exceeded = false;
                    while let Some(row) = pending.pop_front() {
                        let source = current
                            .iter()
                            .position(|id| *id == row)
                            .expect("existing row");
                        current.remove(source);
                        let anchor = loop {
                            let predecessor = fixed.range(..row).next_back();
                            let successor = fixed.range(row..).next().copied();
                            let start = predecessor.map_or(0, |id| {
                                current
                                    .iter()
                                    .position(|candidate| candidate == id)
                                    .expect("fixed predecessor")
                                    + 1
                            });
                            let end = successor.map_or(current.len(), |id| {
                                current
                                    .iter()
                                    .position(|candidate| *candidate == id)
                                    .expect("fixed successor")
                            });
                            let mut anchor = start.checked_sub(1);
                            let mut anchor_cost = anchor.map_or(4, |index| costs[current[index]]);
                            for (index, id) in current.iter().enumerate().take(end).skip(start) {
                                if costs[*id] < anchor_cost {
                                    anchor = Some(index);
                                    anchor_cost = costs[*id];
                                }
                            }
                            // A stationary successor can be a cheap temporary
                            // handle, then move back after this row. Keep each
                            // ID single-use: an already placed row stays fixed.
                            if allow_scaffolds
                                && let Some(successor) = successor
                                && !placed[successor]
                                && costs[successor] < anchor_cost
                            {
                                fixed.remove(&successor);
                                pending.push_back(successor);
                                continue;
                            }
                            break anchor;
                        };
                        // Charge prefixes before cloning long anchor strings.
                        // A prefix already as large as the incumbent cannot win.
                        let operation_bytes = framing
                            + costs[row]
                            + anchor.map_or(4, |index| costs[current[index]])
                            + usize::from(!program.is_empty());
                        if program_bytes.saturating_add(operation_bytes) >= best_bytes {
                            exceeded = true;
                            break;
                        }
                        program_bytes += operation_bytes;
                        program.push(Self {
                            id: after[row].clone(),
                            after: anchor.map(|index| after[current[index]].clone()),
                        });
                        current.insert(anchor.map_or(0, |index| index + 1), row);
                        fixed.insert(row);
                        placed[row] = true;
                    }
                    if exceeded {
                        continue;
                    }
                    let bytes = serde_json::to_vec(&program)
                        .expect("placements serialize")
                        .len();
                    if bytes < best_bytes {
                        best = program;
                        best_bytes = bytes;
                    }
                }
            }
        }
        Self::refine_small_program(before, after, &std::collections::BTreeSet::new(), best)
    }

    /// Choose an insertion forest or temporary-anchor program while retaining every required
    /// durable pin. Request encodings need not determine new durable pins.
    pub fn between_with_pins(
        before: &[String],
        after: &[String],
        required: &std::collections::BTreeSet<&str>,
    ) -> Vec<Self> {
        let indexes = after
            .iter()
            .enumerate()
            .filter(|(_, id)| required.contains(id.as_str()))
            .map(|(index, _)| index)
            .collect();
        let program = Self::insertion_forest_between(before, after, &indexes);
        Self::refine_small_program(before, after, required, program)
    }

    // Eagerly optimize small inventories. Large inventories keep the fast
    // forest/schedule incumbent; admission uses find_fitting with the actual
    // remaining byte budget, without this eager-optimization size threshold.
    fn refine_small_program(
        before: &[String],
        after: &[String],
        required: &std::collections::BTreeSet<&str>,
        mut program: Vec<Self>,
    ) -> Vec<Self> {
        if after.len() <= 8 {
            loop {
                let bytes = serde_json::to_vec(&program)
                    .expect("placements serialize")
                    .len();
                let found = Self::find_fitting(before, after, required, bytes - 1, |_| {
                    Ok::<_, std::convert::Infallible>(true)
                })
                .expect("infallible acceptance");
                let Some(better) = found else { break };
                program = better;
            }
        }
        program
    }

    /// Exhaustive, byte-bounded admission of unique-ID move programs, including
    /// cyclic temporary handles and required no-op pins. No schedule, pin-set,
    /// row-count or search-node limit can turn a fitting program into rejection.
    /// The caller supplies the real request/raw-layer budget and validates each
    /// final candidate. Fast encodings should be tried first.
    ///
    /// A moved row can never move again: its relative order with every other
    /// moved row must already be final. Prune only that necessary condition,
    /// exact prefix bytes, and a weighted common-subsequence lower bound on
    /// remaining moves. Iterative DFS retains O(n) search state (plus ID bytes),
    /// rather than a permutation frontier or catalog-sized recursion stack.
    /// Worst-case search time is exponential; it is used only after fast
    /// candidates fail the actual budget, or to refine small inventories.
    pub fn find_fitting<E>(
        before: &[String],
        after: &[String],
        required: &std::collections::BTreeSet<&str>,
        max_bytes: usize,
        mut accept: impl FnMut(&[Self]) -> std::result::Result<bool, E>,
    ) -> std::result::Result<Option<Vec<Self>>, E> {
        let ranks = after
            .iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect::<BTreeMap<_, _>>();
        if ranks.len() != after.len() || before.len() != after.len() {
            return Ok(None);
        }
        let Some(mut current) = before
            .iter()
            .map(|id| ranks.get(id).copied())
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(None);
        };
        if current
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != after.len()
        {
            return Ok(None);
        }
        let costs = after
            .iter()
            .map(|id| serde_json::to_vec(id).expect("string serializes").len())
            .collect::<Vec<_>>();
        let required = after
            .iter()
            .map(|id| required.contains(id.as_str()))
            .collect::<Vec<_>>();
        let anchor_floor = costs.iter().copied().min().unwrap_or(4).min(4);
        let minimum = costs
            .iter()
            .map(|cost| cost + Self::framing_bytes() + anchor_floor + 1)
            .collect::<Vec<_>>();
        // Required pins already consume these bytes in EVERY program. A row
        // whose additional minimum cost exceeds the budget must remain
        // stationary. This is a proof, never a heuristic choice of pin set.
        let required_bytes = minimum
            .iter()
            .zip(&required)
            .filter(|(_, required)| **required)
            .map(|(bytes, _)| bytes)
            .sum::<usize>();
        let mut stationary = minimum
            .iter()
            .zip(&required)
            .map(|(bytes, required)| {
                !required
                    && 1usize.saturating_add(required_bytes).saturating_add(*bytes) > max_bytes
            })
            .collect::<Vec<_>>();
        let unused = vec![false; after.len()];
        let floor = Self::remaining_move_floor(&current, &unused, &stationary, &required, &costs);
        if 1usize.saturating_add(floor).max(2) > max_bytes {
            return Ok(None);
        }
        // Only expensive rows inside the changed span can make these extra
        // proofs useful. Do not rescan a catalog-sized unchanged prefix for
        // every optional row before trying its few cheap temporary handles.
        if let (Some(first), Some(last)) = (
            current
                .iter()
                .enumerate()
                .position(|(index, row)| index != *row),
            current
                .iter()
                .enumerate()
                .rposition(|(index, row)| index != *row),
        ) {
            let slack = max_bytes.saturating_sub(1usize.saturating_add(floor));
            for (row, &is_required) in required.iter().enumerate().take(last + 1).skip(first) {
                if is_required || stationary[row] || minimum[row] <= slack {
                    continue;
                }
                let mut constrained = required.clone();
                constrained[row] = true;
                let floor = Self::remaining_move_floor(
                    &current,
                    &unused,
                    &stationary,
                    &constrained,
                    &costs,
                );
                if 1usize.saturating_add(floor) > max_bytes {
                    stationary[row] = true;
                }
            }
        }
        let mut rows = (0..after.len()).collect::<Vec<_>>();
        rows.sort_by_key(|&row| (costs[row], row));
        // Try cheap handles before scanning a potentially huge unchanged
        // prefix. Candidate ordering changes no admissible schedule or bound.
        let mut anchors = std::iter::once(None)
            .chain((0..after.len()).map(Some))
            .collect::<Vec<_>>();
        anchors.sort_by_key(|anchor| (anchor.map_or(4, |row| costs[row]), *anchor));
        let mut used = vec![false; after.len()];
        let mut program = Vec::new();
        struct Frame {
            cursor: usize,
            bytes: usize,
            undo: Option<(usize, usize)>,
        }
        let mut stack = vec![Frame {
            cursor: 0,
            bytes: 2,
            undo: None,
        }];
        while let Some(frame) = stack.last_mut() {
            if frame.cursor == 0 {
                let remaining =
                    Self::remaining_move_floor(&current, &used, &stationary, &required, &costs);
                let floor = frame
                    .bytes
                    .saturating_add(remaining)
                    .saturating_sub(usize::from(program.is_empty() && remaining > 0));
                if floor > max_bytes {
                    frame.cursor = rows.len() * (rows.len() + 1);
                } else if current.iter().copied().eq(0..after.len())
                    && required
                        .iter()
                        .zip(&used)
                        .all(|(required, used)| !required || *used)
                    && accept(&program)?
                {
                    return Ok(Some(program));
                }
            }
            if frame.cursor == rows.len() * (rows.len() + 1) {
                let frame = stack.pop().expect("existing frame");
                if let Some((row, source)) = frame.undo {
                    let destination = current.iter().position(|&id| id == row).expect("moved row");
                    current.remove(destination);
                    current.insert(source, row);
                    used[row] = false;
                    program.pop();
                }
                continue;
            }
            let row = rows[frame.cursor / (rows.len() + 1)];
            let anchor = anchors[frame.cursor % anchors.len()];
            frame.cursor += 1;
            if used[row] || stationary[row] {
                frame.cursor = frame.cursor.div_ceil(rows.len() + 1) * (rows.len() + 1);
                continue;
            }
            if anchor == Some(row) {
                continue;
            }
            let bytes = frame.bytes
                + Self::framing_bytes()
                + costs[row]
                + anchor.map_or(4, |id| costs[id])
                + usize::from(!program.is_empty());
            if bytes > max_bytes {
                continue;
            }
            let source = current
                .iter()
                .position(|&id| id == row)
                .expect("existing row");
            let destination = anchor.map_or(0, |id| {
                let index = current
                    .iter()
                    .position(|&candidate| candidate == id)
                    .expect("existing anchor");
                index + usize::from(index < source)
            });
            if source == destination && !required[row] {
                continue;
            }
            current.remove(source);
            current.insert(destination, row);
            used[row] = true;
            let mut previous = None;
            let mut valid = true;
            for &id in current.iter().filter(|&&id| used[id]) {
                if previous.is_some_and(|prior| prior > id) {
                    valid = false;
                    break;
                }
                previous = Some(id);
            }
            if valid {
                program.push(Self {
                    id: after[row].clone(),
                    after: anchor.map(|id| after[id].clone()),
                });
                stack.push(Frame {
                    cursor: 0,
                    bytes,
                    undo: Some((row, source)),
                });
            } else {
                current.remove(destination);
                current.insert(source, row);
                used[row] = false;
            }
        }
        Ok(None)
    }

    fn remaining_move_floor(
        current: &[usize],
        used: &[bool],
        stationary: &[bool],
        required: &[bool],
        costs: &[usize],
    ) -> usize {
        let fixed = used
            .iter()
            .zip(stationary)
            .map(|(used, stationary)| *used || *stationary)
            .collect::<Vec<_>>();
        let mut previous = None;
        let mut gaps = vec![[(usize::MAX, usize::MAX); 2]];
        for &row in current {
            if fixed[row] {
                if previous.is_some_and(|prior| prior > row) {
                    return usize::MAX;
                }
                previous = Some(row);
                gaps.push([(usize::MAX, usize::MAX); 2]);
            } else {
                let cheapest = gaps.last_mut().expect("current gap");
                let candidate = (costs[row], row);
                if candidate < cheapest[0] {
                    cheapest[1] = cheapest[0];
                    cheapest[0] = candidate;
                } else if candidate < cheapest[1] {
                    cheapest[1] = candidate;
                }
            }
        }
        // A future anchor is either still unmoved in this physical gap, or has
        // already moved to a final position before this row in the target gap.
        // Null is possible only before every fixed row. This also accounts for
        // cyclic handles: a still-unmoved anchor may have a LATER target rank.
        let mut minimum = vec![0usize; current.len()];
        let mut gap = 0;
        let mut predecessor_cost = 4;
        let mut future_cost = usize::MAX;
        let mut total = 0;
        for (row, &cost) in costs.iter().enumerate() {
            if fixed[row] {
                gap += 1;
                predecessor_cost = cost;
                future_cost = usize::MAX;
            } else {
                let cheapest = gaps[gap];
                let current_cost = if cheapest[0].1 == row {
                    cheapest[1].0
                } else {
                    cheapest[0].0
                };
                let anchor = predecessor_cost.min(current_cost).min(future_cost);
                minimum[row] = cost + Self::framing_bytes() + anchor + 1;
                total += minimum[row];
                future_cost = future_cost.min(cost);
            }
        }
        // Rows that never move form a common subsequence containing every
        // already fixed row and excluding outstanding required pins. A bonus
        // greater than all optional weights forces all fixed rows into its LIS.
        let bonus = total + 1;
        let mut prefixes = vec![0usize; current.len() + 1];
        let mut best = 0;
        let mut fixed_count = 0;
        for &row in current {
            if required[row] && !used[row] {
                continue;
            }
            let weight = if fixed[row] {
                fixed_count += 1;
                bonus
            } else {
                minimum[row]
            };
            let mut prior = 0;
            let mut slot = row;
            while slot > 0 {
                prior = prior.max(prefixes[slot]);
                slot &= slot - 1;
            }
            let candidate = prior + weight;
            best = best.max(candidate);
            slot = row + 1;
            while slot < prefixes.len() {
                prefixes[slot] = prefixes[slot].max(candidate);
                slot += slot & slot.wrapping_neg();
            }
        }
        total - (best - fixed_count * bonus)
    }

    fn framing_bytes() -> usize {
        serde_json::to_vec(&Self {
            id: String::new(),
            after: None,
        })
        .expect("placement serializes")
        .len()
            - 2
            - 4
    }

    // Temporary anchors can change which rows are cheapest to move. Keep a
    // second common subsequence weighted without desired-predecessor costs.
    fn row_weighted_pins(initial: &[usize], costs: &[usize]) -> std::collections::BTreeSet<usize> {
        let mut positions = vec![0; initial.len()];
        for (position, &index) in initial.iter().enumerate() {
            positions[index] = position;
        }
        let anchor_cost = costs.iter().copied().min().unwrap_or(4).min(4);
        let framing = Self::framing_bytes() + 1;
        let mut prefixes = vec![(0usize, None); initial.len() + 1];
        let mut previous = vec![None; initial.len()];
        for (index, &cost) in costs.iter().enumerate() {
            let mut best = (0, None);
            let mut slot = positions[index];
            while slot > 0 {
                if prefixes[slot].0 > best.0 {
                    best = prefixes[slot];
                }
                slot &= slot - 1;
            }
            previous[index] = best.1;
            let candidate = (best.0 + cost + framing + anchor_cost, Some(index));
            slot = positions[index] + 1;
            while slot < prefixes.len() {
                if candidate.0 > prefixes[slot].0 {
                    prefixes[slot] = candidate;
                }
                slot += slot & slot.wrapping_neg();
            }
        }
        let mut best = (0, None);
        let mut slot = initial.len();
        while slot > 0 {
            if prefixes[slot].0 > best.0 {
                best = prefixes[slot];
            }
            slot &= slot - 1;
        }
        let mut stable = std::collections::BTreeSet::new();
        let mut cursor = best.1;
        while let Some(index) = cursor {
            stable.insert(index);
            cursor = previous[index];
        }
        (0..initial.len())
            .filter(|index| !stable.contains(index))
            .collect()
    }

    /// Minimize serialized bytes over insertion forests and stable common
    /// subsequences. Each movable gap can repeat any preceding anchor in that
    /// gap; reverse prepends and non-immediate anchors are ordinary candidates.
    fn insertion_forest_between(
        before: &[String],
        after: &[String],
        required: &std::collections::BTreeSet<usize>,
    ) -> Vec<Self> {
        if before == after && required.is_empty() {
            return Vec::new();
        }
        let positions = before
            .iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect::<BTreeMap<_, _>>();
        let ranks = after.iter().map(|id| positions[id]).collect::<Vec<_>>();
        let costs = after
            .iter()
            .map(|id| serde_json::to_vec(id).expect("string serializes").len())
            .collect::<Vec<_>>();
        // A state keeps its last stationary row. Extending its movable gap
        // charges the moved ID and cheapest preceding anchor, including JSON
        // escaping and the comma. Stabilizing a row is possible exactly when
        // its original position follows the previous stationary row.
        // State zero is the virtual start anchor, serialized as null.
        let overhead = Self::framing_bytes() + 1;
        let mut states = vec![(0usize, 0usize, 4usize)];
        let mut remaining = ranks
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = Vec::with_capacity(after.len());
        for (index, (&position, &cost)) in ranks.iter().zip(&costs).enumerate() {
            let mut best = (usize::MAX, 0);
            for &(state, bytes, _) in &states {
                if !required.contains(&index)
                    && (state == 0 || ranks[state - 1] < position)
                    && bytes < best.0
                {
                    best = (bytes, state);
                }
            }
            previous.push(best.1);
            for (_, bytes, anchor) in &mut states {
                *bytes += overhead + cost + *anchor;
                *anchor = (*anchor).min(cost);
            }
            if !required.contains(&index) {
                states.push((index + 1, best.0, cost));
            }
            remaining.remove(&position);
            // States with the same next remaining original position have the
            // same eligibility for EVERY future stationary row. Within that
            // class, a cheaper state with a cheaper anchor dominates forever.
            // This avoids quadratic scans of a long otherwise unchanged prefix
            // when one cheap row is moved across a large catalog.
            let bucket = |state: usize| {
                if state == 0 {
                    remaining.first().copied()
                } else {
                    remaining
                        .range((
                            std::ops::Bound::Excluded(ranks[state - 1]),
                            std::ops::Bound::Unbounded,
                        ))
                        .next()
                        .copied()
                }
                .unwrap_or(usize::MAX)
            };
            let mut choices = BTreeMap::<(usize, usize), (usize, usize)>::new();
            for &(state, bytes, anchor) in &states {
                let choice = choices
                    .entry((bucket(state), anchor))
                    .or_insert((bytes, state));
                if bytes < choice.0 {
                    *choice = (bytes, state);
                }
            }
            let mut keep = std::collections::BTreeSet::new();
            let mut prior_bucket = None;
            let mut least_bytes = usize::MAX;
            for ((bucket, _), (bytes, state)) in choices {
                if prior_bucket != Some(bucket) {
                    least_bytes = usize::MAX;
                    prior_bucket = Some(bucket);
                }
                if bytes < least_bytes {
                    keep.insert(state);
                    least_bytes = bytes;
                }
            }
            states.retain(|(state, _, _)| keep.contains(state));
        }
        let mut state = states
            .iter()
            .min_by_key(|(_, bytes, _)| *bytes)
            .expect("start state")
            .0;
        let mut stable = std::collections::BTreeSet::new();
        while state != 0 {
            stable.insert(after[state - 1].as_str());
            state = previous[state - 1];
        }
        let pinned = after
            .iter()
            .map(String::as_str)
            .filter(|id| !stable.contains(id))
            .collect();
        Self::for_pinned_order(after, &pinned)
    }

    /// Re-encode every specified pin without removing any of them. Each gap
    /// between unpinned rows forms an ordered insertion tree. A row can use the
    /// cheapest preceding anchor in that gap, and siblings are inserted in
    /// reverse order. This includes repeated prepends and non-immediate anchors.
    /// Work/storage are linear in the order and its serialized ID bytes, aside
    /// from the pin-set lookups. No recursion grows with a provider catalog.
    pub fn for_pinned_order(
        order: &[String],
        pinned: &std::collections::BTreeSet<&str>,
    ) -> Vec<Self> {
        if pinned.is_empty() {
            return Vec::new();
        }
        let costs = order
            .iter()
            .map(|id| serde_json::to_vec(id).expect("string serializes").len())
            .collect::<Vec<_>>();
        let mut placements = Vec::with_capacity(pinned.len());
        let mut start = 0;
        while start < order.len() {
            if !pinned.contains(order[start].as_str()) {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < order.len() && pinned.contains(order[end].as_str()) {
                end += 1;
            }
            // Node zero is the stationary predecessor (or the beginning).
            let root = start.checked_sub(1);
            let mut cheapest = 0;
            let mut cheapest_cost = root.map_or(4, |index| costs[index]);
            let mut children = vec![Vec::new(); end - start + 1];
            let mut parents = vec![0; end - start];
            for (index, &cost) in costs.iter().enumerate().take(end).skip(start) {
                let node = index - start + 1;
                parents[node - 1] = cheapest;
                children[cheapest].push(node);
                if cost < cheapest_cost {
                    cheapest = node;
                    cheapest_cost = cost;
                }
            }
            let mut pending = std::mem::take(&mut children[0]);
            while let Some(node) = pending.pop() {
                let parent = parents[node - 1];
                placements.push(Self {
                    id: order[start + node - 1].clone(),
                    after: if parent == 0 {
                        root.map(|index| order[index].clone())
                    } else {
                        Some(order[start + parent - 1].clone())
                    },
                });
                pending.append(&mut children[node]);
            }
            start = end;
        }
        placements
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(try_from = "RawModelMembershipPatch")]
pub struct ModelMembershipPatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deletes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placements: Vec<ModelPlacement>,
}

#[derive(Deserialize)]
struct RawModelMembershipPatch {
    #[serde(default)]
    deletes: Vec<String>,
    #[serde(default)]
    placements: Vec<ModelPlacement>,
}

impl TryFrom<RawModelMembershipPatch> for ModelMembershipPatch {
    type Error = &'static str;
    fn try_from(raw: RawModelMembershipPatch) -> std::result::Result<Self, Self::Error> {
        let deletes = raw
            .deletes
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        let placements = raw
            .placements
            .iter()
            .map(|p| &p.id)
            .collect::<std::collections::BTreeSet<_>>();
        if deletes.len() != raw.deletes.len()
            || placements.len() != raw.placements.len()
            || raw
                .placements
                .iter()
                .any(|p| deletes.contains(&p.id) || p.after.as_ref() == Some(&p.id))
        {
            return Err("invalid model membership operations");
        }
        Ok(Self {
            deletes: raw.deletes,
            placements: raw.placements,
        })
    }
}

impl ModelMembershipPatch {
    pub fn is_empty(&self) -> bool {
        self.deletes.is_empty() && self.placements.is_empty()
    }
}

fn deserialize_model_order<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<String>>, D::Error> {
    let order = Option::<Vec<String>>::deserialize(deserializer)?;
    if let Some(order) = &order {
        let ids = order.iter().collect::<std::collections::BTreeSet<_>>();
        if ids.len() != order.len() {
            return Err(serde::de::Error::custom(
                "model order contains duplicate ids",
            ));
        }
    }
    Ok(order)
}

fn deserialize_model_field_set<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, Value>, D::Error> {
    let set = BTreeMap::<String, Value>::deserialize(deserializer)?;
    if set.contains_key("id") {
        return Err(serde::de::Error::custom(
            "model field patch cannot change id",
        ));
    }
    Ok(set)
}

fn deserialize_model_field_remove<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error> {
    let remove = Vec::<String>::deserialize(deserializer)?;
    if remove.iter().any(|key| key == "id") {
        return Err(serde::de::Error::custom(
            "model field patch cannot remove id",
        ));
    }
    Ok(remove)
}

impl ModelEntryFieldPatch {
    pub fn between(before: &ModelEntry, after: &ModelEntry) -> Result<Self> {
        anyhow::ensure!(before.id == after.id, "model field patch cannot change id");
        let before = serde_json::to_value(before)?;
        let after = serde_json::to_value(after)?;
        let before = before.as_object().expect("model is an object");
        let after = after.as_object().expect("model is an object");
        Ok(Self {
            id: after["id"].as_str().expect("model id").into(),
            replace: false,
            set: after
                .iter()
                .filter(|(key, value)| before.get(*key) != Some(*value))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            remove: before
                .keys()
                .filter(|key| !after.contains_key(*key))
                .cloned()
                .collect(),
        })
    }

    pub fn apply_value(&self, model: &mut Value) -> Result<()> {
        anyhow::ensure!(
            model.get("id").and_then(Value::as_str) == Some(self.id.as_str())
                && !self.set.contains_key("id")
                && !self.remove.iter().any(|key| key == "id"),
            "model field patch identity mismatch"
        );
        if self.replace {
            *model = serde_json::json!({"id": self.id});
        }
        let object = model.as_object_mut().expect("model id requires an object");
        for key in &self.remove {
            object.remove(key);
        }
        for (key, value) in &self.set {
            object.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    /// Evict touched values from the authored row before storing the field
    /// delta. An owned large value must have one durable copy, not old + new.
    pub fn evict_authored_fields(&self, model: &mut ModelEntry) -> Result<()> {
        anyhow::ensure!(model.id == self.id, "model field patch identity mismatch");
        let mut raw = serde_json::to_value(&*model)?;
        let object = raw.as_object_mut().expect("model is an object");
        for key in self.set.keys().chain(self.remove.iter()) {
            object.remove(key);
        }
        *model = serde_json::from_value(raw)?;
        Ok(())
    }

    pub fn replacement(model: &ModelEntry) -> Result<Self> {
        let baseline = ModelEntry {
            id: model.id.clone(),
            ..Default::default()
        };
        let mut patch = Self::between(&baseline, model)?;
        patch.replace = true;
        Ok(patch)
    }

    /// Compose a later owner edit without retaining overwritten values.
    pub fn extend(&mut self, next: &Self) {
        if next.replace {
            *self = next.clone();
            return;
        }
        for key in &next.remove {
            self.set.remove(key);
            if !self.remove.contains(key) {
                self.remove.push(key.clone());
            }
        }
        for (key, value) in &next.set {
            self.remove.retain(|old| old != key);
            self.set.insert(key.clone(), value.clone());
        }
    }
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
    /// Model-level delegation permission override. Missing inherits provider
    /// default, then resolves to true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can_delegate: Option<bool>,
    /// Model-level computer-use reachability override. Missing inherits
    /// provider policy within the catalog layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_use: Option<ComputerUseMode>,
    /// Model-layer opt-in for typed computer-use guidance proposals.
    /// `absent | enabled | disabled`; missing is neutral during cross-layer
    /// resolution (see
    /// `cockpit_core::computer::guidance::resolve_enablement`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_computer_guidance_proposals: Option<bool>,
    /// Model-level default legacy thinking mode for OpenAI-compatible models.
    /// Active model selections still win at runtime; missing inherits the
    /// provider default and then falls back to no extra thinking params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_thinking_mode: Option<ThinkingMode>,
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
    /// Who selected [`Self::wire_api`].  A missing value means a user pin:
    /// hand-authored configs write only `wire_api`, and the user-configured
    /// default is skipped on serialize.  Endpoint recovery
    /// and probing instead record `recovered`, which is a durable hint rather
    /// than an authority over a fresh live catalog.
    #[serde(default, skip_serializing_if = "WireApiProvenance::is_user_configured")]
    pub wire_api_provenance: WireApiProvenance,
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
    Probed,
    Fallback,
    ProviderRule,
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromptCacheRetention {
    #[default]
    Default,
    Extended,
}

impl PromptCacheRetention {
    pub const EXTENDED_WIRE_VALUE: &'static str = "24h";

    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }

    pub fn as_label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Extended => "extended",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityValue {
    #[serde(deserialize_with = "deserialize_nonempty_string")]
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
    /// An OpenAI-compatible JSON object path. This is distinct from
    /// [`Self::JsonField`] so catalog-derived mappings can faithfully model
    /// APIs such as Responses' `reasoning.effort` without overloading dotted
    /// field names or relying on provider-specific request-builder branches.
    JsonPath {
        path: Vec<String>,
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

/// A request mapping which is valid only for one OpenAI-compatible endpoint.
/// Live catalogs can expose one effort vocabulary on multiple endpoints even
/// when each endpoint requires a different request shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointReasoningEffortRequestMapping {
    pub wire_api: WireApi,
    pub request_mapping: ReasoningEffortRequestMapping,
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
    /// Endpoint-scoped catalog mappings. `request_mapping` remains the
    /// backwards-compatible endpoint-agnostic configuration form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_request_mappings: Vec<EndpointReasoningEffortRequestMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CapabilitySource>,
}

impl ReasoningEffortCapability {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
            && self.default.is_none()
            && self.request_mapping.is_none()
            && self.endpoint_request_mappings.is_empty()
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComputerUseContract {
    Anthropic20251124,
    Anthropic20250124,
    OpenAiResponses,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputerUseCapability {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ComputerUseContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CapabilitySource>,
}

impl ComputerUseCapability {
    pub fn is_empty(&self) -> bool {
        self.contract.is_none() && self.source.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelCapabilities {
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub tool_calling: CapabilityStatus,
    /// Image *input* for chat/multimodal understanding. Independent of audio,
    /// video, generation output, and computer-use eligibility.
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub image_input: CapabilityStatus,
    /// Audio *input*. Independent of image/video and of transcription tooling.
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub audio_input: CapabilityStatus,
    /// Video *input*. Independent of image/audio and of extraction tooling.
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub video_input: CapabilityStatus,
    /// OpenAI-compatible audio-transcription endpoint support. This is an
    /// egress/tool capability, independent of chat audio input.
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub transcription: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimensions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens_source: Option<CapabilitySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens_source: Option<CapabilitySource>,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub reasoning: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub structured_outputs: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub prompt_cache_retention: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ReasoningEffortCapability>,
    /// Concrete OpenAI-compatible endpoints advertised by the provider's
    /// live model catalog. Configuration pins still take precedence; when
    /// unset Cockpit uses this to choose the provider-declared route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_wire_apis: Vec<WireApi>,
    #[serde(default, skip_serializing_if = "ClientSideToolsCapability::is_empty")]
    pub client_side_tools: ClientSideToolsCapability,
    #[serde(default, skip_serializing_if = "ComputerUseCapability::is_empty")]
    pub computer_use: ComputerUseCapability,
}

impl ModelCapabilities {
    pub fn preferred_wire_api(&self) -> Option<WireApi> {
        if self.supported_wire_apis.contains(&WireApi::Responses) {
            Some(WireApi::Responses)
        } else if self.supported_wire_apis.contains(&WireApi::Completions) {
            Some(WireApi::Completions)
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tool_calling.is_unknown()
            && self.image_input.is_unknown()
            && self.audio_input.is_unknown()
            && self.video_input.is_unknown()
            && self.transcription.is_unknown()
            && self.embeddings.is_none()
            && self.embedding_dimensions.is_none()
            && self.context_tokens.is_none()
            && self.context_tokens_source.is_none()
            && self.max_output_tokens.is_none()
            && self.max_output_tokens_source.is_none()
            && self.reasoning.is_unknown()
            && self.structured_outputs.is_unknown()
            && self.prompt_cache_retention.is_unknown()
            && self
                .reasoning_effort
                .as_ref()
                .is_none_or(ReasoningEffortCapability::is_empty)
            && self.supported_wire_apis.is_empty()
            && self.client_side_tools.is_empty()
            && self.computer_use.is_empty()
    }
}

/// Manual per-model capability assertions. Only Auto (absent), Supported, or
/// Unsupported — `RequiresEntitlement` is detected metadata, never a manual
/// override. Missing fields mean Auto and serialize nothing.
///
/// Status override fields reject `requires_entitlement` (and other non-manual
/// statuses) at deserialize time so bad configs cannot assert entitlement.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelCapabilityOverrides {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub tool_calling: Option<CapabilityStatus>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub image_input: Option<CapabilityStatus>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub audio_input: Option<CapabilityStatus>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub video_input: Option<CapabilityStatus>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub transcription: Option<CapabilityStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimensions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub reasoning: Option<CapabilityStatus>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub structured_outputs: Option<CapabilityStatus>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_manual_capability_override"
    )]
    pub prompt_cache_retention: Option<CapabilityStatus>,
}

/// Manual overrides accept only Supported / Unsupported (or absent = Auto).
/// `RequiresEntitlement` and `Unknown` are rejected so detected metadata cannot
/// be smuggled in as a user override via config.
fn deserialize_manual_capability_override<'de, D>(
    deserializer: D,
) -> Result<Option<CapabilityStatus>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<CapabilityStatus>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(CapabilityStatus::Supported) => Ok(Some(CapabilityStatus::Supported)),
        Some(CapabilityStatus::Unsupported) => Ok(Some(CapabilityStatus::Unsupported)),
        Some(CapabilityStatus::RequiresEntitlement) => Err(serde::de::Error::custom(
            "manual capability overrides cannot be requires_entitlement; use auto (omit) or supported/unsupported",
        )),
        Some(CapabilityStatus::Unknown) => Err(serde::de::Error::custom(
            "manual capability overrides cannot be unknown; omit the field for Auto",
        )),
    }
}

impl ModelCapabilityOverrides {
    pub fn is_empty(&self) -> bool {
        self.tool_calling.is_none()
            && self.image_input.is_none()
            && self.audio_input.is_none()
            && self.video_input.is_none()
            && self.transcription.is_none()
            && self.embeddings.is_none()
            && self.embedding_dimensions.is_none()
            && self.context_tokens.is_none()
            && self.max_output_tokens.is_none()
            && self.reasoning.is_none()
            && self.structured_outputs.is_none()
            && self.prompt_cache_retention.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderCapabilities {
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub tool_calling: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub image_input: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub audio_input: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub video_input: CapabilityStatus,
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub transcription: CapabilityStatus,
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
    #[serde(default, skip_serializing_if = "CapabilityStatus::is_unknown")]
    pub prompt_cache_retention: CapabilityStatus,
    #[serde(default, skip_serializing_if = "ClientSideToolsCapability::is_empty")]
    pub client_side_tools: ClientSideToolsCapability,
    #[serde(default, skip_serializing_if = "ComputerUseCapability::is_empty")]
    pub computer_use: ComputerUseCapability,
}

impl ProviderCapabilities {
    pub fn is_empty(&self) -> bool {
        self.tool_calling.is_unknown()
            && self.image_input.is_unknown()
            && self.audio_input.is_unknown()
            && self.video_input.is_unknown()
            && self.transcription.is_unknown()
            && self.embeddings.is_none()
            && self.embedding_dimensions.is_none()
            && self.context_tokens.is_none()
            && self.max_output_tokens.is_none()
            && self.reasoning.is_unknown()
            && self.structured_outputs.is_unknown()
            && self.prompt_cache_retention.is_unknown()
            && self.client_side_tools.is_empty()
            && self.computer_use.is_empty()
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

/// Evidence supplied by the fetch owner, never inferred from diagnostic prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFetchFailure {
    CredentialsRejected,
    Other,
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

/// Which request wire a model speaks.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WireApi {
    /// No explicit pin. Resolution falls back to the provider template default
    /// (or Chat Completions for a custom provider).
    #[default]
    Auto,
    /// Force the Chat Completions endpoint (`/chat/completions`).
    Completions,
    /// Force the Responses endpoint (`/responses`).
    Responses,
    /// Force Anthropic's native Messages endpoint (`/v1/messages`).
    Anthropic,
}

/// Authority of a concrete model-level [`WireApi`] value.
///
/// A recovered endpoint is persisted so a model missing from a catalog still
/// benefits from a successful fallback after restart.  It is intentionally
/// lower priority than an endpoint advertised by a later live catalog.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WireApiProvenance {
    /// An endpoint configured by the user (the default when a config carries
    /// a concrete `wire_api` without provenance).
    #[default]
    UserConfigured,
    /// An endpoint learned from an approved endpoint fallback or deep probe.
    Recovered,
}

impl WireApiProvenance {
    pub fn is_user_configured(&self) -> bool {
        matches!(self, Self::UserConfigured)
    }
}

impl WireApi {
    /// True for the `Auto` (unpinned) variant — the serde skip predicate and
    /// effective-resolution fallback.
    pub fn is_auto(&self) -> bool {
        matches!(self, WireApi::Auto)
    }

    /// The opposite concrete endpoint — the one the error-driven fallback
    /// retries. `Auto` is never the *resolved* endpoint (the resolver always
    /// produces a concrete value first), so it maps to `Responses` defensively.
    pub fn opposite(self) -> WireApi {
        match self {
            WireApi::Responses => WireApi::Completions,
            WireApi::Completions | WireApi::Auto | WireApi::Anthropic => WireApi::Responses,
        }
    }
}

/// The built-in template default used when a provider entry leaves
/// [`ProviderEntry::wire_api`] unset. This deliberately depends on immutable
/// template identity only: map keys and URLs are user-controlled and never
/// participate in wire selection.
pub fn default_wire_api_for_template(template: Option<&str>) -> WireApi {
    match template {
        Some(template) if template.eq_ignore_ascii_case("anthropic") => WireApi::Anthropic,
        Some(template)
            if matches!(
                template.to_ascii_lowercase().as_str(),
                "openai" | "codex-oauth" | "grok" | "grok-oauth"
            ) =>
        {
            WireApi::Responses
        }
        _ => WireApi::Completions,
    }
}

/// `true` when `base_url`'s HOST is GitHub Copilot's API host
/// (`githubcopilot.com` or any `*.githubcopilot.com` subdomain, e.g.
/// `api.githubcopilot.com`). Host-based rather than substring so a look-alike
/// URL like `https://api.githubcopilot.com.evil.example/v1` (host ends in
/// `.evil.example`) or one carrying `githubcopilot.com` only in the path is
/// NOT matched — substring matching would otherwise mis-classify it as Copilot
/// and inject the ambient `GH_TOKEN`/`GITHUB_TOKEN` toward an attacker host.
/// Unparseable URLs never match. Custom/renamed Copilot connections still match
/// via the template/credential predicates, not this host check.
pub fn is_copilot_host_url(base_url: &str) -> bool {
    reqwest::Url::parse(base_url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| {
                let h = h.to_ascii_lowercase();
                h == "githubcopilot.com" || h.ends_with(".githubcopilot.com")
            })
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

/// Normalize a fetched catalog after credential scrubbing. The first row for
/// each exact model ID wins; distinct IDs retain their upstream order.
/// Use this before counting, previewing or persisting a fetched inventory.
pub fn coalesce_fetched_models(mut models: Vec<ModelEntry>) -> Vec<ModelEntry> {
    let mut seen = std::collections::HashSet::new();
    models.retain(|model| seen.insert(model.id.clone()));
    models
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
/// cache/context/shrink/timeout, auto-prune, backup, inline-think,
/// repair/recovery settings, thinking params, and capability overrides — plus,
/// for manual entries, the hand-set display `name` and `context_length`.
/// Template-scoped model defaults ([`apply_template_model_defaults`]) are
/// applied only to ids that are **newly discovered** by this fetch — i.e. absent
/// from `existing`. Standard first-party providers get frontier defaults for
/// ids on [`KNOWN_FRONTIER_MODEL_IDS`]; GitHub Copilot gets its own exact-id
/// auto-prune and ephemeral-cache defaults. A previously-configured known
/// id is never re-defaulted, so a user who clears e.g. `auto_prune` back to
/// inherit keeps that state across refreshes.
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
    for mut m in coalesce_fetched_models(fetched) {
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
    if existing.can_delegate.is_some() {
        fetched.can_delegate = existing.can_delegate;
    }
    if existing.computer_use.is_some() {
        fetched.computer_use = existing.computer_use;
    }
    if existing.default_thinking_mode.is_some() {
        fetched.default_thinking_mode = existing.default_thinking_mode;
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
    if !existing.wire_api.is_auto() && existing.wire_api_provenance.is_user_configured() {
        fetched.wire_api = existing.wire_api;
        fetched.wire_api_provenance = existing.wire_api_provenance;
    } else if !existing.wire_api.is_auto()
        && matches!(existing.wire_api_provenance, WireApiProvenance::Recovered)
        && fetched.wire_api.is_auto()
        && preferred_catalog_wire_api(&fetched.capabilities).is_none()
    {
        // Keep a learned endpoint only while the refetch gives us no stronger
        // information. A live endpoint catalog must be able to correct stale
        // recovery state from a prior session.
        fetched.wire_api = existing.wire_api;
        fetched.wire_api_provenance = existing.wire_api_provenance;
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
    if existing.capabilities.context_tokens_source == Some(CapabilitySource::Probed) {
        fetched.capabilities.context_tokens = existing.capabilities.context_tokens;
        fetched.capabilities.context_tokens_source = existing.capabilities.context_tokens_source;
    }
    if existing.capabilities.max_output_tokens_source == Some(CapabilitySource::Probed) {
        fetched.capabilities.max_output_tokens = existing.capabilities.max_output_tokens;
        fetched.capabilities.max_output_tokens_source =
            existing.capabilities.max_output_tokens_source;
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

impl ThinkingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
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
    /// present. The config-map `key` is deliberately ignored: it is mutable
    /// and cannot prove registry provenance.
    pub fn effective_template(&self, _key: &str) -> Option<&str> {
        self.template.as_deref()
    }

    /// Resolve native Anthropic extensions from the provider's explicit gate.
    /// A missing or empty gate disables both extensions. First-party defaults
    /// are materialized when the Anthropic template creates the entry.
    pub fn effective_anthropic_features(&self) -> AnthropicFeatures {
        self.anthropic.unwrap_or_default()
    }

    /// Resolve the effective request wire for one model on this provider.
    ///
    /// Model pins win over a provider pin; an unpinned provider inherits its
    /// immutable template default. URLs, provider ids, model names, live
    /// catalog metadata, and learned endpoint state never participate.
    pub fn resolve_wire_api(&self, provider_id: &str, model_id: &str) -> WireApi {
        if let Some(wire_api) = self
            .models
            .iter()
            .find(|model| model.id == model_id)
            .filter(|model| model.wire_api_provenance.is_user_configured())
            .map(|model| model.wire_api)
            .filter(|wire_api| !wire_api.is_auto())
        {
            return wire_api;
        }
        if !self.wire_api.is_auto() {
            return self.wire_api;
        }
        let template = self.effective_template(provider_id).unwrap_or(provider_id);
        default_wire_api_for_template(Some(template))
    }

    /// Whether this entry is GitHub Copilot, including renamed connections.
    /// Keep this aligned with the provider registry's Copilot matcher: the
    /// persisted template is the strongest identity, while credential and URL
    /// recognition retain compatibility for older/custom connections.
    pub fn is_copilot_identity(&self, provider_id: &str) -> bool {
        provider_id.eq_ignore_ascii_case("copilot")
            || self
                .effective_template(provider_id)
                .is_some_and(|template| template.eq_ignore_ascii_case("copilot"))
            || self
                .credential_ref
                .as_deref()
                .is_some_and(|credential| credential.eq_ignore_ascii_case("copilot"))
            || is_copilot_host_url(&self.url)
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

    pub fn mark_model_fetch_failed_kept_existing(
        &mut self,
        reason: impl Into<String>,
        failure: ModelFetchFailure,
    ) {
        let status = match failure {
            ModelFetchFailure::CredentialsRejected => ModelFetchStatusKind::AuthFailed,
            ModelFetchFailure::Other => ModelFetchStatusKind::FailedKeptExisting,
        };
        self.last_model_fetch = Some(ModelFetchStatus {
            status,
            at: Utc::now(),
            source: ModelFetchSource::Live,
            reason: Some(redact_model_fetch_reason(reason)),
        });
    }
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

fn reasoning_effort_supports_value(capability: &ReasoningEffortCapability, value: &str) -> bool {
    capability
        .values
        .iter()
        .any(|candidate| candidate.value == value)
}

/// Clamp an OpenAI-compatible `reasoning[_.]effort` wire value to what rig's
/// typed `ReasoningEffort` can express.
///
/// rig (0.42) accepts `none|minimal|low|medium|high|xhigh|max` and rejects the
/// entire `additional_params` payload *before send* for any other value.
/// Copilot's catalog advertises an `ultra` tier above `max` that rig cannot
/// encode, so a model selected/dispatched at `ultra` would fail every request.
/// `ultra` is the "above the ceiling" tier, so it clamps to the wire ceiling
/// `max` (still a selectable UI tier; now dispatches at maximum effort). This is
/// the single OpenAI-compatible chokepoint — it also covers the raw fall-through
/// value used when a catalog/user mapping has no explicit entry.
fn clamp_openai_reasoning_effort_wire_value(mapped: Value) -> Value {
    if mapped == Value::String("ultra".to_string()) {
        Value::String("max".to_string())
    } else {
        mapped
    }
}

fn json_at_path(path: &[String], value: Value) -> Value {
    debug_assert!(!path.is_empty());
    let mut nested = value;
    for segment in path.iter().rev() {
        nested = Value::Object(Map::from_iter([(segment.clone(), nested)]));
    }
    nested
}

fn preferred_catalog_wire_api(capabilities: &ModelCapabilities) -> Option<WireApi> {
    // `/responses` is the newer, more expressive OpenAI-compatible endpoint.
    // Prefer it whenever the live catalog advertises support, while retaining
    // completions for catalogs that advertise only that legacy endpoint.
    capabilities.preferred_wire_api()
}

fn reasoning_effort_mapping_for_wire(
    capability: &ReasoningEffortCapability,
    wire_api: Option<WireApi>,
) -> Option<&ReasoningEffortRequestMapping> {
    wire_api
        .and_then(|wire_api| {
            capability
                .endpoint_request_mappings
                .iter()
                .find(|mapping| mapping.wire_api == wire_api)
                .map(|mapping| &mapping.request_mapping)
        })
        .or(capability.request_mapping.as_ref())
}

impl ReasoningEffortCapability {
    /// Whether this capability can truthfully be offered on `wire_api`.
    /// Endpoint-agnostic legacy mappings work everywhere; scoped catalog
    /// mappings work only on their declared endpoint.
    pub fn supports_wire_api(&self, wire_api: WireApi) -> bool {
        !self.values.is_empty() && reasoning_effort_mapping_for_wire(self, Some(wire_api)).is_some()
    }
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
            ReasoningEffortWire::OpenAiCompatible,
            ReasoningEffortRequestMapping::JsonPath { path, .. },
        ) => {
            if path.is_empty() || path.iter().any(|segment| segment.trim().is_empty()) {
                anyhow::bail!("reasoning JSON-path mapping has an empty path segment");
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
        (
            ReasoningEffortWire::AnthropicNative,
            ReasoningEffortRequestMapping::JsonPath { path, .. },
        ) => {
            anyhow::bail!(
                "native Anthropic reasoning cannot use JSON path `{}`; configure an anthropic_adaptive or anthropic_manual mapping",
                path.join(".")
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

    /// Resolve curated prompt-cache retention knowledge for one endpoint.
    ///
    /// Explicit cache configuration still decides whether cache use is
    /// possible. This profile only expresses what Cockpit can safely know
    /// about retention: OpenAI has an approximate 30-minute floor, Anthropic
    /// uses the configured 5-minute/1-hour retention, and Gemini's configured
    /// TTL is explicit. OpenRouter-style routes and all unknown compatible
    /// providers remain observed-only.
    pub fn resolve_cache_retention_profile(
        &self,
        provider: &str,
        model: &str,
    ) -> CacheRetentionProfile {
        let cache = self.resolve_cache(provider, model);
        if cache.mode == CacheMode::None {
            return CacheRetentionProfile::None;
        }

        // Provider map keys are user-renamable connection labels. Curated
        // retention knowledge belongs only to the immutable template identity;
        // custom endpoints never inherit a vendor profile from a chosen name.
        let Some(template) = self
            .providers
            .get(provider)
            .and_then(|entry| entry.effective_template(provider))
        else {
            return CacheRetentionProfile::Observed;
        };
        match template.to_ascii_lowercase().as_str() {
            "openai" | "chatgpt" | "codex" => CacheRetentionProfile::KnownFloor { secs: 30 * 60 },
            "anthropic" | "claude" | "gemini" | "google" => CacheRetentionProfile::KnownFloor {
                secs: cache.ttl_secs,
            },
            "openrouter" => CacheRetentionProfile::AggregatorObserved,
            _ => CacheRetentionProfile::Observed,
        }
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
    /// provider-level config, else the built-in defaults (60/4/50/30). Drives
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

    /// Resolve the explicitly configured first fallback for `(provider,
    /// model)`: the model-level override if present, else the provider-level
    /// config, else `None`. Delegated turns now continue with a bounded
    /// chained walk over other `subagent_invokable` models after this explicit
    /// backup. That deliberately overturns the old single-backup rule: a user
    /// with one dead invokable model otherwise got no unattended failover and a
    /// multi-minute stall. The returned reference may name a different
    /// provider than the one passed in.
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
        self.providers
            .get(provider)
            .and_then(|entry| {
                entry
                    .models
                    .iter()
                    .find(|m| m.id == model)
                    .and_then(|m| m.trust)
            })
            .unwrap_or_else(|| self.provider_trust_default(provider))
    }

    pub fn provider_trust_default(&self, provider: &str) -> ModelTrust {
        self.providers
            .get(provider)
            .and_then(|entry| entry.trust)
            .unwrap_or(ModelTrust::Untrusted)
    }

    pub fn provider_subagent_invokable_default(&self, provider: &str) -> bool {
        self.providers
            .get(provider)
            .and_then(|entry| entry.subagent_invokable)
            .unwrap_or(false)
    }

    pub fn provider_can_delegate_default(&self, provider: &str) -> bool {
        self.providers
            .get(provider)
            .and_then(|entry| entry.can_delegate)
            .unwrap_or(true)
    }

    pub fn provider_default_thinking_mode_default(&self, provider: &str) -> Option<ThinkingMode> {
        self.providers
            .get(provider)
            .and_then(|entry| entry.default_thinking_mode)
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
        self.model_entry(provider, model)
            .and_then(|m| m.subagent_invokable)
            .unwrap_or_else(|| self.provider_subagent_invokable_default(provider))
    }

    pub fn resolve_can_delegate(&self, provider: &str, model: &str) -> bool {
        self.model_entry(provider, model)
            .and_then(|m| m.can_delegate)
            .unwrap_or_else(|| self.provider_can_delegate_default(provider))
    }

    pub fn resolve_computer_use_catalog(
        &self,
        provider: &str,
        model: &str,
    ) -> Option<ComputerUseMode> {
        let entry = self.providers.get(provider)?;
        entry
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.computer_use)
            .or(entry.computer_use)
    }

    pub fn resolve_computer_use_effective(
        &self,
        provider: &str,
        model: &str,
        configured: Option<ComputerUseMode>,
        display_cap: Option<ComputerUseMode>,
    ) -> ComputerUseMode {
        let tiers = [
            self.resolve_computer_use_catalog(provider, model),
            configured,
            display_cap,
        ];
        ComputerUseMode::most_restrictive(tiers.into_iter().flatten())
            .unwrap_or(ComputerUseMode::Disabled)
    }

    pub fn resolve_default_thinking_mode(
        &self,
        provider: &str,
        model: &str,
    ) -> Option<ThinkingMode> {
        self.model_entry(provider, model)
            .and_then(|m| m.default_thinking_mode)
            .or_else(|| self.provider_default_thinking_mode_default(provider))
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
        self.resolve_reasoning_effort_params_for_openai_endpoint(
            provider, model, selected, wire, None, max_tokens,
        )
    }

    /// Resolve a typed reasoning mapping for a concrete OpenAI-compatible
    /// endpoint. Endpoint-scoped mappings are never reused on a different
    /// route, including an error-recovery alternate.
    pub fn resolve_reasoning_effort_params_for_openai_endpoint(
        &self,
        provider: &str,
        model: &str,
        selected: Option<&str>,
        wire: ReasoningEffortWire,
        wire_api: Option<WireApi>,
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
        let mapping = reasoning_effort_mapping_for_wire(capability, wire_api);
        if matches!(wire, ReasoningEffortWire::OpenAiCompatible) && mapping.is_none() {
            return Ok(None);
        }
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
        let mapping =
            mapping.context("reasoning effort is advertised without a request mapping")?;
        // Reuse the public validator for the selected mapping. This also
        // validates user-configured endpoint mappings without pretending they
        // are safe on another endpoint.
        let mut validation_capability = capability.clone();
        validation_capability.request_mapping = Some(mapping.clone());
        validation_capability.endpoint_request_mappings.clear();
        validate_reasoning_effort_capability(&validation_capability, wire, max_tokens)?;
        let params = match mapping {
            ReasoningEffortRequestMapping::JsonField { field, values } => {
                let mapped = values
                    .get(value)
                    .cloned()
                    .unwrap_or_else(|| Value::String(value.to_string()));
                let mapped = clamp_openai_reasoning_effort_wire_value(mapped);
                Value::Object(Map::from_iter([(field.clone(), mapped)]))
            }
            ReasoningEffortRequestMapping::JsonPath { path, values } => {
                let mapped = values
                    .get(value)
                    .cloned()
                    .unwrap_or_else(|| Value::String(value.to_string()));
                let mapped = clamp_openai_reasoning_effort_wire_value(mapped);
                json_at_path(path, mapped)
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
            let wire_api = self.resolve_wire_api(&active.provider, &active.model);
            return self
                .resolve_reasoning_effort_params_for_openai_endpoint(
                    &active.provider,
                    &active.model,
                    active
                        .reasoning_effort
                        .as_ref()
                        .map(|effort| effort.value.as_str()),
                    ReasoningEffortWire::OpenAiCompatible,
                    Some(wire_api),
                    None,
                )
                .ok()
                .flatten();
        }
        let mode = active
            .thinking_mode
            .or_else(|| self.resolve_default_thinking_mode(&active.provider, &active.model))?;
        self.resolve_thinking_params(&active.provider, &active.model, mode)
    }

    pub fn resolve_prompt_cache_retention(
        &self,
        provider: &str,
        model: &str,
        selected: Option<PromptCacheRetention>,
    ) -> Option<&'static str> {
        if !matches!(selected, Some(PromptCacheRetention::Extended)) {
            return None;
        }
        let caps =
            self.resolve_effective_model_capabilities(provider, model, self.resolution_generation);
        matches!(caps.prompt_cache_retention, CapabilityStatus::Supported)
            .then_some(PromptCacheRetention::EXTENDED_WIRE_VALUE)
    }

    pub fn resolve_active_model_prompt_cache_retention(
        &self,
        override_value: Option<PromptCacheRetention>,
    ) -> Option<&'static str> {
        let active = self.active_model.as_ref()?;
        let selected = override_value.or(active.prompt_cache_retention);
        self.resolve_prompt_cache_retention(&active.provider, &active.model, selected)
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

    /// Resolve the effective request wire for `(provider, model)`.
    ///
    /// Explicit model and provider configuration win. An unset entry then
    /// inherits its immutable template default; a custom or unknown provider
    /// defaults to Chat Completions. URLs, mutable provider ids, model names,
    /// live catalog metadata, and learned endpoint state never participate.
    pub fn resolve_wire_api(&self, provider: &str, model: &str) -> WireApi {
        let Some(entry) = self.providers.get(provider) else {
            return WireApi::Completions;
        };
        entry.resolve_wire_api(provider, model)
    }

    /// Whether the effective wire for `(provider, model)` is pinned in config
    /// rather than left on the conservative auto default. Template/provider
    /// defaults and catalog metadata do not count as explicit pins.
    pub fn is_wire_api_explicit(&self, provider: &str, model: &str) -> bool {
        let Some(entry) = self.providers.get(provider) else {
            return false;
        };
        if let Some(model_entry) = entry.models.iter().find(|m| m.id == model) {
            if model_entry.wire_api_provenance.is_user_configured()
                && !model_entry.wire_api.is_auto()
            {
                return true;
            }
        }
        !entry.wire_api.is_auto()
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod value_free_debug_tests {
    use super::*;

    /// Secrets r2 C1: literal header and OAuth header-template values never
    /// print through provider config Debug.
    #[test]
    fn header_debug_does_not_print_values() {
        let secret = ["NovelDebug515", "Secret78529"].concat();
        let header = HeaderSpec {
            name: "Authorization".into(),
            value: format!("Bearer {secret}"),
        };
        let mapping = OAuthHeaderMapping {
            name: "X-Api-Key".into(),
            value: secret.clone(),
        };
        for rendered in [format!("{header:?}"), format!("{mapping:#?}")] {
            assert!(!rendered.contains(&secret), "{rendered}");
        }
        assert!(format!("{header:?}").contains("Authorization"));
    }
}
