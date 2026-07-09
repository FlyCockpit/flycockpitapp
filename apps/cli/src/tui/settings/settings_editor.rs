//! The shared per-model / per-provider settings sub-dialog
//! (implementation note).
//!
//! Both the model-settings and provider-settings sub-pages edit the shared
//! settings field list through one [`SettingsEditor`]. The differences are the
//! scope ([`SettingsScope`]) and a few scope-specific rows:
//!
//! - **Provider scope** edits the concrete `context` / `cache` / `shrink`
//!   / `timeout` / `wire_api` values on the [`ProviderEntry`] (always present),
//!   plus provider-only transport security, backup fallback, `mode`,
//!   `inline_think`, and tool-call-correction hinting settings.
//! - **Model scope** edits the `Option<…>` overrides on a single
//!   [`ModelEntry`]: each config group is either overridden (present) or
//!   inherits the provider value. Editing a field sets the override; `x`
//!   clears it back to inherit. Provider-only transport security is omitted.
//!
//! The fields, in row order:
//!
//!   1. Allow insecure HTTP (provider scope only)
//!   2. Trust policy (trusted | untrusted | inherit)
//!   3. Locality (local | private remote | remote | unset)
//!   4. Quality rank
//!   5. Cost rank
//!   6. Subagent available
//!   7. Auto-compact ctx % (default 80)
//!   8. Auto-prune (on | off | inherit; default on) — the master switch for
//!      automatic pruning; off protects the provider prompt cache entirely
//!   9. Auto-prune ctx % (default 50)
//!   10. Auto-prune prunable % (default 30)
//!   11. Cache time (seconds) (default 300)
//!   12. Cache mode (none | ephemeral)
//!   13. Shrink strategy (prune | compact)
//!   14. First-token threshold (seconds)
//!   15. Idle threshold (seconds)
//!   16. Wire API (auto | completions | responses; hidden for native Anthropic)
//!   17. xAI multi-agent tools beta access (on | off; xAI/Grok providers only)
//!   18. Backup model (provider:model)
//!   19. Mode (defensive | normal | frontier | inherit)
//!   20. Inline `<think>` (on | off | inherit) — the inline-`<think>`
//!       reasoning-extraction toggle, a tri-state at **both** scopes (model
//!       override → provider override → global default,
//!       implementation note).
//!   21. Hint tool-call corrections (on | off | inherit)
//!
//! Percentages, cache time, and timeout thresholds are inline numeric text edits
//! (`Enter` opens the edit, validated/clamped on commit). Cache mode, shrink
//! strategy, wire API, mode, inline think, hint corrections, and provider-only
//! transport security cycle in place on `Enter`; backup model is a text edit. A
//! bottom-of-list `[save changes]` row (and the `s` accelerator) commits to
//! disk and stays; Back (`Esc`/`h`/`←`) writes the working state into the parent
//! [`EditState`]'s entry and auto-commits it (no edit is ever dropped).

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

use crate::config::extended::LlmMode;
use crate::config::providers::{
    BackupConfig, CacheConfig, CacheMode, CapabilitySource, CapabilityStatus,
    ClientSideToolsCapability, ContextConfig, ModelEntry, ModelLocation, ModelTrust, ProviderEntry,
    ShrinkConfig, ShrinkStrategy, TimeoutConfig, WireApi, XAI_MULTI_AGENT_TOOLS_ENTITLEMENT,
    is_anthropic_native_base_url, is_xai_grok_provider,
};
use crate::tui::textfield::TextField;

/// Which scope the editor is bound to.
#[derive(Clone)]
pub(super) enum SettingsScope {
    /// Editing a single model's `Option<…>` overrides. Carries the model id
    /// so the writeback can target the right row.
    Model { model_id: String },
    /// Editing the provider's concrete values.
    Provider,
}

/// The editable provider/model fields, in row order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum SettingsField {
    /// Provider-only opt-in for plaintext non-loopback HTTP base URLs.
    AllowInsecureHttp,
    TrustPolicy,
    Location,
    QualityRank,
    CostRank,
    SubagentInvokable,
    AutoCompactPct,
    /// Auto-prune master switch (on | off | inherit). `off` disables the
    /// automatic prune trigger entirely — both branches; manual `/prune`
    /// still works. Tri-state at both scopes (model → provider → on).
    AutoPruneEnabled,
    AutoPrunePct,
    AutoPrunePrunablePct,
    CacheTtlSecs,
    CacheMode,
    ShrinkStrategy,
    /// Inference first-token (TTFT) timeout in seconds
    /// (implementation note).
    TimeoutTtftSecs,
    /// Inference idle/inter-token timeout in seconds.
    TimeoutIdleSecs,
    /// OpenAI-compatible wire endpoint selector (`auto` / Chat Completions /
    /// Responses). Hidden for native Anthropic providers.
    WireApi,
    /// Backup-model fallback target as `provider:model`
    /// (implementation note). Free-text edit; empty clears
    /// it (no fallback).
    Backup,
    Mode,
    /// Per-model inline-`<think>` extraction toggle. Model scope only.
    InlineThink,
    /// Per-tier §12 tool-call-correction hinting toggle
    /// (implementation note). Tri-state at both tiers,
    /// mirroring `InlineThink`.
    HintToolCallCorrections,
    /// xAI/Grok multi-agent client-side tool entitlement opt-in. Stored in the
    /// generic `capabilities.client_side_tools` structure.
    XaiMultiAgentToolsBeta,
}

impl SettingsField {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::AllowInsecureHttp => "Allow insecure HTTP",
            Self::TrustPolicy => "Trust policy",
            Self::Location => "Locality",
            Self::QualityRank => "Quality rank",
            Self::CostRank => "Cost rank",
            Self::SubagentInvokable => "Subagent available",
            Self::AutoCompactPct => "Auto-compact ctx %",
            Self::AutoPruneEnabled => "Auto-prune",
            Self::AutoPrunePct => "Auto-prune ctx %",
            Self::AutoPrunePrunablePct => "Auto-prune prunable %",
            Self::CacheTtlSecs => "Cache time (seconds)",
            Self::CacheMode => "Cache mode",
            Self::ShrinkStrategy => "Shrink strategy",
            Self::TimeoutTtftSecs => "First-token threshold (s)",
            Self::TimeoutIdleSecs => "Idle threshold (s)",
            Self::WireApi => "Wire API",
            Self::Backup => "Backup model (provider:model)",
            Self::Mode => "Mode",
            Self::InlineThink => "Extract inline <think> tags",
            Self::HintToolCallCorrections => "Hint tool-call corrections",
            Self::XaiMultiAgentToolsBeta => "I have xAI beta access for Grok multi-agent tools",
        }
    }

    /// True for the inline numeric text-edit fields (the rest cycle).
    fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::AutoCompactPct
                | Self::AutoPrunePct
                | Self::AutoPrunePrunablePct
                | Self::CacheTtlSecs
                | Self::TimeoutTtftSecs
                | Self::TimeoutIdleSecs
                | Self::QualityRank
                | Self::CostRank
        )
    }

    /// Which config group this field belongs to (for the model-scope
    /// override-present tracking).
    fn group(self) -> SettingsGroup {
        match self {
            Self::AllowInsecureHttp => SettingsGroup::TransportSecurity,
            Self::TrustPolicy => SettingsGroup::TrustPolicy,
            Self::Location => SettingsGroup::Location,
            Self::QualityRank => SettingsGroup::QualityRank,
            Self::CostRank => SettingsGroup::CostRank,
            Self::SubagentInvokable => SettingsGroup::SubagentInvokable,
            Self::AutoCompactPct | Self::AutoPrunePct | Self::AutoPrunePrunablePct => {
                SettingsGroup::Context
            }
            Self::AutoPruneEnabled => SettingsGroup::AutoPrune,
            Self::CacheTtlSecs | Self::CacheMode => SettingsGroup::Cache,
            Self::ShrinkStrategy => SettingsGroup::Shrink,
            Self::TimeoutTtftSecs | Self::TimeoutIdleSecs => SettingsGroup::Timeout,
            Self::WireApi => SettingsGroup::WireApi,
            Self::Backup => SettingsGroup::Backup,
            Self::Mode => SettingsGroup::Mode,
            Self::InlineThink => SettingsGroup::InlineThink,
            Self::HintToolCallCorrections => SettingsGroup::HintToolCallCorrections,
            Self::XaiMultiAgentToolsBeta => SettingsGroup::XaiMultiAgentToolsBeta,
        }
    }

    /// True for the free-text edit fields (currently only the backup model).
    fn is_text(self) -> bool {
        matches!(self, Self::Backup)
    }

    fn help(self) -> Option<&'static str> {
        match self {
            Self::InlineThink => Some(
                "extract strips literal <think> blocks from assistant text, stores them as reasoning, and leaves display to Interface -> Thinking display. It does not request more reasoning from the model.",
            ),
            Self::Mode => Some(
                "Steering tier for new turns: defensive (weaker models, explicit guidance), normal (strong models, terse), frontier (top-tier models, high autonomy). inherit falls through to the provider, then the global llm mode. Separate from Interface -> Thinking display.",
            ),
            Self::AutoPruneEnabled => Some(
                "Master switch for automatic context pruning (lossless dedup of stale tool results). off never auto-prunes, protecting the provider's prompt cache; manual /prune still works. inherit falls through to the provider, then on.",
            ),
            Self::AutoCompactPct => Some(
                "At or above this % of the context window, the conversation is auto-compacted (LLM summarization, same as /compact). Unrelated to the prune thresholds below.",
            ),
            Self::AutoPrunePct => Some(
                "Warm-cache prune threshold: above this ctx% (and the prunable % below), auto-prune fires even though it breaks the warm prompt cache. When the cache is cold or Cache mode is none, auto-prune ignores these thresholds — set Auto-prune off to stop it entirely.",
            ),
            Self::AutoPrunePrunablePct => Some(
                "Second warm-cache condition: prunable tokens must also exceed this % of the context window before the warm-cache prune fires.",
            ),
            Self::CacheTtlSecs => Some(
                "Seconds the provider keeps the cached prompt prefix between requests; after expiry pruning is free. 3600+ opts native Anthropic into the 1-hour extended cache.",
            ),
            Self::CacheMode => Some(
                "Whether this endpoint caches the prompt prefix. none means pruning is treated as always free, so auto-prune may fire at any boundary; ephemeral protects a warm cache (Anthropic, OpenAI/Codex, and z.ai all cache — use ephemeral there).",
            ),
            Self::ShrinkStrategy => Some(
                "How the parent context is shrunk while a subagent runs: prune (lossless dedup) or compact (LLM summarization; heavier, saves more). Separate from the Auto-prune/Auto-compact triggers above.",
            ),
            Self::WireApi => Some(
                "Provider request endpoint: auto uses the learned/default endpoint; completions uses /chat/completions; responses uses /responses.",
            ),
            Self::Backup => Some(
                "Fallback request target used after inference thresholds; leave blank for no backup.",
            ),
            Self::TrustPolicy => Some(
                "Trusted models may receive unsanitized prompts and tool results; untrusted models keep outbound redaction.",
            ),
            Self::Location => {
                Some("Locality is routing metadata only; local and trusted are separate decisions.")
            }
            Self::QualityRank => {
                Some("Higher quality rank is preferred when policy selectors optimize for quality.")
            }
            Self::CostRank => {
                Some("Lower cost rank is preferred when policy selectors optimize for cost.")
            }
            Self::SubagentInvokable => {
                Some("Controls whether this provider/model can be selected for subagent routing.")
            }
            Self::TimeoutTtftSecs | Self::TimeoutIdleSecs => Some(
                "Inference request thresholds. Without a backup they show a warning and keep waiting; with a backup they trigger fallback.",
            ),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum SettingsGroup {
    TransportSecurity,
    TrustPolicy,
    Location,
    QualityRank,
    CostRank,
    SubagentInvokable,
    Context,
    AutoPrune,
    Cache,
    Shrink,
    Timeout,
    WireApi,
    Backup,
    Mode,
    InlineThink,
    HintToolCallCorrections,
    XaiMultiAgentToolsBeta,
}

/// The model/provider settings sub-dialog state.
pub(super) struct SettingsEditor {
    pub(super) scope: SettingsScope,
    pub(super) cursor: usize,
    /// Working concrete values. For model scope these are seeded from the
    /// override-or-provider-or-default chain so an inherited field shows its
    /// effective value; editing a field flips the group's `present` flag.
    context: ContextConfig,
    /// Auto-prune master switch. `None` = inherit (provider scope: global
    /// default on; model scope: provider, then on); `Some(true/false)` pins
    /// it. Cycles on→off→inherit. Tracks its own override via `is_some()`,
    /// mirroring `inline_think`.
    auto_prune: Option<bool>,
    cache: CacheConfig,
    shrink: ShrinkConfig,
    /// Working inference-stream timeouts (TTFT + idle), seeded from the
    /// override-or-provider-or-default chain
    /// (implementation note).
    timeout: TimeoutConfig,
    wire_api: WireApi,
    /// Backup-model fallback target (implementation note).
    /// `None` = no backup (provider scope) / inherit the provider backup (model
    /// scope); `Some` pins a `(provider, model)`. Tracks its own override via
    /// `is_some()` like `mode`. Edited as free text `provider:model`.
    backup: Option<BackupConfig>,
    /// `None` = mode undefined (inherit). Cycles
    /// undefined→defensive→normal→frontier→undefined.
    mode: Option<LlmMode>,
    /// Per-model inline-`<think>` override (model scope only). `None` =
    /// inherit the default (on); `Some(true/false)` pins it. Cycles
    /// on→off→default. Tracks its own override via `is_some()`.
    inline_think: Option<bool>,
    /// Per-tier §12 tool-call-correction hinting override
    /// (implementation note). `None` = inherit the lower
    /// tier (default off); `Some(true/false)` pins it. Cycles
    /// on→off→default(inherit). Tracks its own override via `is_some()`,
    /// mirroring `inline_think`.
    hint_tool_call_corrections: Option<bool>,
    /// Effective xAI/Grok multi-agent tool entitlement toggle for the current
    /// scope. Provider `off` means no manual override; model `off` is an
    /// explicit disagreement with a possible provider-wide `on`.
    xai_multi_agent_tools_beta: bool,
    xai_multi_agent_tools_beta_present: bool,
    show_xai_multi_agent_tools_beta: bool,
    /// Provider-level transport-security opt-in. Only rendered and written in
    /// provider scope.
    allow_insecure_http: bool,
    trust: Option<ModelTrust>,
    location: Option<ModelLocation>,
    quality_rank: Option<i64>,
    cost_rank: Option<i64>,
    subagent_invokable: Option<bool>,
    provider_trust_confirm_pending: bool,
    provider_trust_confirm_ready_at: Option<Instant>,
    provider_trust_confirm_lockout: Duration,
    /// Per-group "is this overridden on the model" flags. Always true for
    /// provider scope (the values are concrete). `mode` tracks override via
    /// `mode.is_some()` directly, so it has no flag here.
    context_present: bool,
    cache_present: bool,
    shrink_present: bool,
    timeout_present: bool,
    wire_api_present: bool,
    show_wire_api: bool,
    /// The derived, ordered field list for this editor. Computed once at
    /// construction from `scope` / `show_wire_api` /
    /// `show_xai_multi_agent_tools_beta` — the only inputs that shape it, all
    /// of which are fixed for the editor's lifetime — so per-keystroke and
    /// per-frame accessors (`field_count`, `selected_field`, the render loop)
    /// borrow this slice instead of reallocating.
    fields: Vec<SettingsField>,
    /// Inline numeric edit buffer; `Some` while a numeric field is open.
    pub(super) editing: Option<SettingsField>,
    pub(super) buf: TextField,
    /// Transient validation status shown under the rows.
    pub(super) status: Option<String>,
}

impl SettingsEditor {
    /// Build the editor for a provider's concrete values.
    pub(super) fn for_provider(provider_id: &str, entry: &ProviderEntry) -> Self {
        let xai_multi_agent_tools_beta =
            tools_entitlement_enabled(&entry.capabilities.client_side_tools);
        let show_wire_api = !is_anthropic_native_base_url(&entry.url);
        let show_xai_multi_agent_tools_beta = is_xai_grok_provider(provider_id, entry);
        Self {
            scope: SettingsScope::Provider,
            cursor: 0,
            context: entry.context.clone(),
            auto_prune: entry.auto_prune,
            cache: entry.cache.clone(),
            shrink: entry.shrink.clone(),
            timeout: entry.timeout.clone(),
            wire_api: entry.wire_api,
            backup: entry.backup.clone(),
            mode: entry.mode,
            // Provider-tier inline-`<think>` override (tri-state: inherit
            // global / on / off), mirroring the `mode` tri-state.
            inline_think: entry.inline_think,
            // Provider-tier hint-tool-call-corrections override (tri-state),
            // mirroring `inline_think`.
            hint_tool_call_corrections: entry.hint_tool_call_corrections,
            xai_multi_agent_tools_beta,
            xai_multi_agent_tools_beta_present: !entry.capabilities.client_side_tools.is_empty(),
            show_xai_multi_agent_tools_beta,
            allow_insecure_http: entry.allow_insecure_http,
            trust: entry.trust,
            location: entry.location,
            quality_rank: entry.quality_rank,
            cost_rank: entry.cost_rank,
            subagent_invokable: entry.subagent_invokable,
            provider_trust_confirm_pending: false,
            provider_trust_confirm_ready_at: None,
            provider_trust_confirm_lockout: Duration::ZERO,
            context_present: true,
            cache_present: true,
            shrink_present: true,
            timeout_present: true,
            wire_api_present: true,
            show_wire_api,
            fields: Self::derive_fields(false, show_wire_api, show_xai_multi_agent_tools_beta),
            editing: None,
            buf: TextField::default(),
            status: None,
        }
    }

    pub(super) fn with_trust_confirm_lockout_ms(mut self, lockout_ms: u64) -> Self {
        self.provider_trust_confirm_lockout = Duration::from_millis(lockout_ms);
        self
    }

    /// Build the editor for a single model's overrides. Working values are
    /// seeded from the override if present, else the provider value, so an
    /// inherited field shows its effective (inherited) value.
    pub(super) fn for_model(provider_id: &str, entry: &ProviderEntry, model_id: &str) -> Self {
        let model = entry.models.iter().find(|m| m.id == model_id);
        let context = model
            .and_then(|m| m.context.clone())
            .unwrap_or_else(|| entry.context.clone());
        let cache = model
            .and_then(|m| m.cache.clone())
            .unwrap_or_else(|| entry.cache.clone());
        let shrink = model
            .and_then(|m| m.shrink.clone())
            .unwrap_or_else(|| entry.shrink.clone());
        let timeout = model
            .and_then(|m| m.timeout.clone())
            .unwrap_or_else(|| entry.timeout.clone());
        let wire_api = model
            .map(|m| m.wire_api)
            .filter(|w| !w.is_auto())
            .or_else(|| (!entry.wire_api.is_auto()).then_some(entry.wire_api))
            .unwrap_or(WireApi::Auto);
        let mode = model.and_then(|m| m.mode);
        let model_client_side_tools = model.map(|m| &m.capabilities.client_side_tools);
        let xai_multi_agent_tools_beta_present =
            model_client_side_tools.is_some_and(|capability| !capability.is_empty());
        let effective_client_side_tools = model_client_side_tools
            .filter(|capability| !capability.is_empty())
            .unwrap_or(&entry.capabilities.client_side_tools);
        let xai_multi_agent_tools_beta = tools_entitlement_enabled(effective_client_side_tools);
        let show_wire_api = !is_anthropic_native_base_url(&entry.url);
        let show_xai_multi_agent_tools_beta = is_xai_grok_provider(provider_id, entry);
        Self {
            scope: SettingsScope::Model {
                model_id: model_id.to_string(),
            },
            cursor: 0,
            context,
            // Auto-prune tracks its override via `is_some()` (like `mode`):
            // seed from the model's own override only, so an unset model
            // shows "inherit".
            auto_prune: model.and_then(|m| m.auto_prune),
            cache,
            shrink,
            timeout,
            wire_api,
            // Backup tracks its override via `is_some()` (like `mode`): seed
            // from the model's own override only, not the inherited provider
            // value, so an unset model shows "inherit".
            backup: model.and_then(|m| m.backup.clone()),
            mode,
            inline_think: model.and_then(|m| m.inline_think),
            hint_tool_call_corrections: model.and_then(|m| m.hint_tool_call_corrections),
            xai_multi_agent_tools_beta,
            xai_multi_agent_tools_beta_present,
            show_xai_multi_agent_tools_beta,
            allow_insecure_http: entry.allow_insecure_http,
            trust: model.and_then(|m| m.trust),
            location: model.and_then(|m| m.location),
            quality_rank: model.and_then(|m| m.quality_rank),
            cost_rank: model.and_then(|m| m.cost_rank),
            subagent_invokable: model.and_then(|m| m.subagent_invokable),
            provider_trust_confirm_pending: false,
            provider_trust_confirm_ready_at: None,
            provider_trust_confirm_lockout: Duration::ZERO,
            context_present: model.is_some_and(|m| m.context.is_some()),
            cache_present: model.is_some_and(|m| m.cache.is_some()),
            shrink_present: model.is_some_and(|m| m.shrink.is_some()),
            timeout_present: model.is_some_and(|m| m.timeout.is_some()),
            wire_api_present: model.is_some_and(|m| !m.wire_api.is_auto()),
            show_wire_api,
            fields: Self::derive_fields(true, show_wire_api, show_xai_multi_agent_tools_beta),
            editing: None,
            buf: TextField::default(),
            status: None,
        }
    }

    fn is_model_scope(&self) -> bool {
        matches!(self.scope, SettingsScope::Model { .. })
    }

    pub(super) fn shows_xai_multi_agent_tools_beta(&self) -> bool {
        self.show_xai_multi_agent_tools_beta
    }

    /// The ordered field list for this editor. Cached at construction (see
    /// [`Self::derive_fields`]) and borrowed here, since the inputs that shape
    /// it are fixed for the editor's lifetime. Provider scope leads with the
    /// provider-only transport security row (`AllowInsecureHttp`); model scope
    /// omits it. The wire-API row is hidden for native Anthropic providers, and
    /// the xAI multi-agent tools opt-in only appears for xAI/Grok providers.
    pub(super) fn fields(&self) -> &[SettingsField] {
        &self.fields
    }

    /// Build the ordered field list from the three inputs that shape it. Called
    /// once per constructor; the result is cached in the `fields` field. Keeping
    /// the derivation in one place means a new row is added once, not once per
    /// scope/flag variant.
    fn derive_fields(
        is_model_scope: bool,
        show_wire_api: bool,
        show_xai_multi_agent_tools_beta: bool,
    ) -> Vec<SettingsField> {
        use SettingsField::*;
        let mut fields = Vec::with_capacity(21);
        // Provider-only transport security opt-in leads the list; model scope
        // cannot override it.
        if !is_model_scope {
            fields.push(AllowInsecureHttp);
        }
        fields.extend([
            TrustPolicy,
            Location,
            QualityRank,
            CostRank,
            SubagentInvokable,
            AutoCompactPct,
            AutoPruneEnabled,
            AutoPrunePct,
            AutoPrunePrunablePct,
            CacheTtlSecs,
            CacheMode,
            ShrinkStrategy,
            TimeoutTtftSecs,
            TimeoutIdleSecs,
        ]);
        // Wire API precedes the xAI opt-in; both sit between the timeout rows
        // and the backup/mode tail.
        if show_wire_api {
            fields.push(WireApi);
        }
        if show_xai_multi_agent_tools_beta {
            fields.push(XaiMultiAgentToolsBeta);
        }
        fields.extend([Backup, Mode, InlineThink, HintToolCallCorrections]);
        fields
    }

    /// Number of editable field rows in the current scope.
    fn field_count(&self) -> usize {
        self.fields().len()
    }

    /// The `[save changes]` row index — one past the last field row.
    pub(super) fn save_idx(&self) -> usize {
        self.field_count()
    }

    /// Total selectable rows: the fields plus the `[save changes]` row.
    fn row_count(&self) -> usize {
        self.field_count() + 1
    }

    /// True when the cursor is on the `[save changes]` row (not a field).
    pub(super) fn on_save_row(&self) -> bool {
        self.cursor == self.save_idx()
    }

    /// The field at a row index (clamped to the last on overflow).
    fn field_at(&self, row: usize) -> SettingsField {
        let fields = self.fields();
        fields[row.min(fields.len() - 1)]
    }

    /// Whether a field's group is currently an active override (model scope)
    /// — drives the "inherited" dimming. Always true for provider scope.
    pub(super) fn is_overridden(&self, field: SettingsField) -> bool {
        if !self.is_model_scope() {
            return true;
        }
        match field.group() {
            SettingsGroup::TransportSecurity => true,
            SettingsGroup::TrustPolicy => self.trust.is_some(),
            SettingsGroup::Location => self.location.is_some(),
            SettingsGroup::QualityRank => self.quality_rank.is_some(),
            SettingsGroup::CostRank => self.cost_rank.is_some(),
            SettingsGroup::SubagentInvokable => self.subagent_invokable.is_some(),
            SettingsGroup::Context => self.context_present,
            SettingsGroup::AutoPrune => self.auto_prune.is_some(),
            SettingsGroup::Cache => self.cache_present,
            SettingsGroup::Shrink => self.shrink_present,
            SettingsGroup::Timeout => self.timeout_present,
            SettingsGroup::WireApi => self.wire_api_present,
            SettingsGroup::Backup => self.backup.is_some(),
            SettingsGroup::Mode => self.mode.is_some(),
            SettingsGroup::InlineThink => self.inline_think.is_some(),
            SettingsGroup::HintToolCallCorrections => self.hint_tool_call_corrections.is_some(),
            SettingsGroup::XaiMultiAgentToolsBeta => self.xai_multi_agent_tools_beta_present,
        }
    }

    pub(super) fn selected_field(&self) -> Option<SettingsField> {
        self.fields().get(self.cursor).copied()
    }

    pub(super) fn selected_help(&self) -> Option<&'static str> {
        self.selected_field().and_then(SettingsField::help)
    }

    /// The display value for a row (the working value, formatted).
    pub(super) fn value_str(&self, field: SettingsField) -> String {
        match field {
            SettingsField::AllowInsecureHttp => {
                if self.allow_insecure_http {
                    "on".to_string()
                } else {
                    "off".to_string()
                }
            }
            SettingsField::TrustPolicy => match self.trust {
                Some(ModelTrust::Trusted) => "trusted".to_string(),
                Some(ModelTrust::Untrusted) => "untrusted".to_string(),
                None if self.is_model_scope() => "inherit".to_string(),
                None => "untrusted (default)".to_string(),
            },
            SettingsField::Location => match self.location {
                Some(ModelLocation::Local) => "local".to_string(),
                Some(ModelLocation::Remote) => "remote".to_string(),
                Some(ModelLocation::PrivateRemote) => "private remote".to_string(),
                None => "unset".to_string(),
            },
            SettingsField::QualityRank => self
                .quality_rank
                .map(|v| v.to_string())
                .unwrap_or_else(|| "0 (default)".to_string()),
            SettingsField::CostRank => self
                .cost_rank
                .map(|v| v.to_string())
                .unwrap_or_else(|| "0 (default)".to_string()),
            SettingsField::SubagentInvokable => match self.subagent_invokable {
                Some(true) => "on".to_string(),
                Some(false) => "off".to_string(),
                None if self.is_model_scope() => "inherit".to_string(),
                None => "off (default)".to_string(),
            },
            SettingsField::AutoCompactPct => format!("{}%", self.context.auto_compact_pct),
            SettingsField::AutoPruneEnabled => match self.auto_prune {
                Some(true) => "on".to_string(),
                Some(false) => "off".to_string(),
                None if self.is_model_scope() => "inherit".to_string(),
                None => "on (default)".to_string(),
            },
            SettingsField::AutoPrunePct => format!("{}%", self.context.auto_prune_pct),
            SettingsField::AutoPrunePrunablePct => {
                format!("{}%", self.context.auto_prune_prunable_pct)
            }
            SettingsField::CacheTtlSecs => format!("{}s", self.cache.ttl_secs),
            SettingsField::CacheMode => match self.cache.mode {
                CacheMode::None => "none".to_string(),
                CacheMode::Ephemeral => "ephemeral".to_string(),
            },
            SettingsField::ShrinkStrategy => match self.shrink.strategy {
                ShrinkStrategy::Prune => "prune".to_string(),
                ShrinkStrategy::Compact => "compact".to_string(),
            },
            SettingsField::TimeoutTtftSecs => format!("{}s", self.timeout.ttft_secs),
            SettingsField::TimeoutIdleSecs => format!("{}s", self.timeout.idle_secs),
            SettingsField::WireApi => {
                if self.is_model_scope() && !self.wire_api_present {
                    if self.wire_api.is_auto() {
                        "auto (inherit)".to_string()
                    } else {
                        format!("{} (inherit)", wire_api_label(self.wire_api))
                    }
                } else {
                    wire_api_label(self.wire_api).to_string()
                }
            }
            SettingsField::Backup => match &self.backup {
                Some(b) => format!("{}:{}", b.provider, b.model),
                None => "none".to_string(),
            },
            SettingsField::Mode => match self.mode {
                Some(LlmMode::Defensive) => "defensive".to_string(),
                Some(LlmMode::Normal) => "normal".to_string(),
                Some(LlmMode::Frontier) => "frontier".to_string(),
                None if self.is_model_scope() => "inherit".to_string(),
                None => "inherit (global llm mode)".to_string(),
            },
            SettingsField::InlineThink => match self.inline_think {
                Some(true) => "extract".to_string(),
                Some(false) => "leave inline".to_string(),
                None if self.is_model_scope() => "inherit provider/default".to_string(),
                None => "inherit default".to_string(),
            },
            SettingsField::HintToolCallCorrections => match self.hint_tool_call_corrections {
                Some(true) => "on".to_string(),
                Some(false) => "off".to_string(),
                None => "inherit".to_string(),
            },
            SettingsField::XaiMultiAgentToolsBeta => {
                if self.xai_multi_agent_tools_beta {
                    "on".to_string()
                } else {
                    "off".to_string()
                }
            }
        }
    }

    fn mark_present(&mut self, field: SettingsField) {
        match field.group() {
            SettingsGroup::TransportSecurity => {}
            SettingsGroup::TrustPolicy
            | SettingsGroup::Location
            | SettingsGroup::QualityRank
            | SettingsGroup::CostRank
            | SettingsGroup::SubagentInvokable => {}
            SettingsGroup::Context => self.context_present = true,
            SettingsGroup::Cache => self.cache_present = true,
            SettingsGroup::Shrink => self.shrink_present = true,
            SettingsGroup::Timeout => self.timeout_present = true,
            SettingsGroup::WireApi => self.wire_api_present = true,
            // Backup / Mode / AutoPrune / InlineThink /
            // HintToolCallCorrections track presence via their `Option`.
            SettingsGroup::Backup
            | SettingsGroup::Mode
            | SettingsGroup::AutoPrune
            | SettingsGroup::InlineThink
            | SettingsGroup::HintToolCallCorrections => {}
            SettingsGroup::XaiMultiAgentToolsBeta => self.xai_multi_agent_tools_beta_present = true,
        }
    }

    /// Clear the field's group back to inherit (model scope only). On
    /// provider scope this is a no-op (no inherit state).
    fn clear_override(&mut self, field: SettingsField) {
        if !self.is_model_scope() {
            self.status = Some("provider settings can't inherit (model scope only)".to_string());
            return;
        }
        match field.group() {
            SettingsGroup::TransportSecurity => {
                self.status = Some("provider transport setting cannot inherit".to_string());
            }
            SettingsGroup::TrustPolicy => self.trust = None,
            SettingsGroup::Location => self.location = None,
            SettingsGroup::QualityRank => self.quality_rank = None,
            SettingsGroup::CostRank => self.cost_rank = None,
            SettingsGroup::SubagentInvokable => self.subagent_invokable = None,
            SettingsGroup::Context => self.context_present = false,
            SettingsGroup::Cache => self.cache_present = false,
            SettingsGroup::Shrink => self.shrink_present = false,
            SettingsGroup::Timeout => self.timeout_present = false,
            SettingsGroup::WireApi => {
                self.wire_api_present = false;
                self.wire_api = WireApi::Auto;
            }
            SettingsGroup::Backup => self.backup = None,
            SettingsGroup::Mode => self.mode = None,
            SettingsGroup::AutoPrune => self.auto_prune = None,
            SettingsGroup::InlineThink => self.inline_think = None,
            SettingsGroup::HintToolCallCorrections => self.hint_tool_call_corrections = None,
            SettingsGroup::XaiMultiAgentToolsBeta => {
                self.xai_multi_agent_tools_beta_present = false;
                self.xai_multi_agent_tools_beta = false;
            }
        }
        self.status = Some("cleared to inherit".to_string());
    }

    /// Cycle a non-numeric field in place.
    fn cycle(&mut self, field: SettingsField) {
        match field {
            SettingsField::AllowInsecureHttp => {
                if self.is_model_scope() {
                    self.status = Some("provider setting only".to_string());
                } else {
                    self.allow_insecure_http = !self.allow_insecure_http;
                }
            }
            SettingsField::TrustPolicy => {
                if self.is_model_scope() {
                    self.trust = match self.trust {
                        None => Some(ModelTrust::Trusted),
                        Some(ModelTrust::Trusted) => Some(ModelTrust::Untrusted),
                        Some(ModelTrust::Untrusted) => None,
                    };
                    self.status = if self.trust == Some(ModelTrust::Trusted) {
                        Some(
                            "trusted models may receive unsanitized prompts and tool results"
                                .to_string(),
                        )
                    } else {
                        None
                    };
                    return;
                }
                match self.trust {
                    Some(ModelTrust::Trusted) => {
                        self.trust = None;
                        self.provider_trust_confirm_pending = false;
                        self.provider_trust_confirm_ready_at = None;
                        self.status = None;
                    }
                    _ if self.provider_trust_confirm_pending => {
                        if self
                            .provider_trust_confirm_ready_at
                            .is_some_and(|ready_at| Instant::now() < ready_at)
                        {
                            self.status = Some(
                                "wait before confirming provider trust; future fetched models inherit unredacted access"
                                    .to_string(),
                            );
                            return;
                        }
                        self.trust = Some(ModelTrust::Trusted);
                        self.provider_trust_confirm_pending = false;
                        self.provider_trust_confirm_ready_at = None;
                        self.status = Some(
                            "provider trusted: future fetched models inherit unredacted access"
                                .to_string(),
                        );
                    }
                    _ => {
                        self.provider_trust_confirm_pending = true;
                        self.provider_trust_confirm_ready_at =
                            Some(Instant::now() + self.provider_trust_confirm_lockout);
                        self.status = Some(
                            "press Enter again to mark the provider trusted; future fetched models inherit unredacted access"
                                .to_string(),
                        );
                    }
                }
                return;
            }
            SettingsField::Location => {
                self.location = match self.location {
                    None => Some(ModelLocation::Local),
                    Some(ModelLocation::Local) => Some(ModelLocation::PrivateRemote),
                    Some(ModelLocation::PrivateRemote) => Some(ModelLocation::Remote),
                    Some(ModelLocation::Remote) => None,
                };
            }
            SettingsField::SubagentInvokable => {
                self.subagent_invokable = if self.is_model_scope() {
                    match self.subagent_invokable {
                        None => Some(true),
                        Some(true) => Some(false),
                        Some(false) => None,
                    }
                } else {
                    match self.subagent_invokable {
                        Some(true) => None,
                        _ => Some(true),
                    }
                };
            }
            SettingsField::AutoPruneEnabled => {
                // on → off → inherit(None) → on
                self.auto_prune = match self.auto_prune {
                    Some(true) => Some(false),
                    Some(false) => None,
                    None => Some(true),
                };
            }
            SettingsField::CacheMode => {
                self.cache.mode = match self.cache.mode {
                    CacheMode::None => CacheMode::Ephemeral,
                    CacheMode::Ephemeral => CacheMode::None,
                };
                self.mark_present(field);
            }
            SettingsField::ShrinkStrategy => {
                self.shrink.strategy = match self.shrink.strategy {
                    ShrinkStrategy::Prune => ShrinkStrategy::Compact,
                    ShrinkStrategy::Compact => ShrinkStrategy::Prune,
                };
                self.mark_present(field);
            }
            SettingsField::WireApi => {
                if self.is_model_scope() {
                    match (self.wire_api_present, self.wire_api) {
                        (true, WireApi::Completions) => {
                            self.wire_api = WireApi::Responses;
                            self.wire_api_present = true;
                        }
                        (true, WireApi::Responses) => {
                            self.wire_api = WireApi::Auto;
                            self.wire_api_present = false;
                        }
                        _ => {
                            self.wire_api = WireApi::Completions;
                            self.wire_api_present = true;
                        }
                    }
                } else {
                    self.wire_api = match self.wire_api {
                        WireApi::Auto => WireApi::Completions,
                        WireApi::Completions => WireApi::Responses,
                        WireApi::Responses => WireApi::Auto,
                    };
                    self.wire_api_present = true;
                }
            }
            SettingsField::Mode => {
                // inherit → defensive → normal → frontier → inherit
                self.mode = match self.mode {
                    Some(LlmMode::Defensive) => Some(LlmMode::Normal),
                    Some(LlmMode::Normal) => Some(LlmMode::Frontier),
                    Some(LlmMode::Frontier) => None,
                    None => Some(LlmMode::Defensive),
                };
            }
            SettingsField::InlineThink => {
                // on → off → default(inherit) → on
                self.inline_think = match self.inline_think {
                    Some(true) => Some(false),
                    Some(false) => None,
                    None => Some(true),
                };
            }
            SettingsField::HintToolCallCorrections => {
                // on → off → default(inherit) → on
                self.hint_tool_call_corrections = match self.hint_tool_call_corrections {
                    Some(true) => Some(false),
                    Some(false) => None,
                    None => Some(true),
                };
            }
            SettingsField::XaiMultiAgentToolsBeta => {
                self.xai_multi_agent_tools_beta = !self.xai_multi_agent_tools_beta;
                self.xai_multi_agent_tools_beta_present =
                    self.is_model_scope() || self.xai_multi_agent_tools_beta;
            }
            _ => {}
        }
        self.status = None;
    }

    fn begin_numeric_edit(&mut self, field: SettingsField) {
        let current = match field {
            SettingsField::QualityRank => self.quality_rank.unwrap_or(0).to_string(),
            SettingsField::CostRank => self.cost_rank.unwrap_or(0).to_string(),
            SettingsField::AutoCompactPct => self.context.auto_compact_pct.to_string(),
            SettingsField::AutoPrunePct => self.context.auto_prune_pct.to_string(),
            SettingsField::AutoPrunePrunablePct => self.context.auto_prune_prunable_pct.to_string(),
            SettingsField::CacheTtlSecs => self.cache.ttl_secs.to_string(),
            SettingsField::TimeoutTtftSecs => self.timeout.ttft_secs.to_string(),
            SettingsField::TimeoutIdleSecs => self.timeout.idle_secs.to_string(),
            _ => String::new(),
        };
        self.buf = TextField::new(current);
        self.editing = Some(field);
        self.status = None;
    }

    /// Open the free-text edit for the backup-model field, seeded with the
    /// current `provider:model` (empty when unset).
    fn begin_text_edit(&mut self, field: SettingsField) {
        let current = match field {
            SettingsField::Backup => match &self.backup {
                Some(b) => format!("{}:{}", b.provider, b.model),
                None => String::new(),
            },
            _ => String::new(),
        };
        self.buf = TextField::new(current);
        self.editing = Some(field);
        self.status = None;
    }

    /// Validate + commit the backup-model free-text edit. An empty value clears
    /// the backup (no fallback / inherit); otherwise it must be `provider:model`
    /// with both halves non-empty (rejected inline on a bad shape — the field
    /// stays open).
    fn commit_text_edit(&mut self) {
        let Some(field) = self.editing else {
            return;
        };
        if field != SettingsField::Backup {
            return;
        }
        let raw = self.buf.text().trim();
        if raw.is_empty() {
            // Clear the backup (no fallback at this scope / inherit on model).
            self.backup = None;
            self.editing = None;
            self.status = None;
            return;
        }
        match raw.split_once(':') {
            Some((provider, model)) if !provider.trim().is_empty() && !model.trim().is_empty() => {
                self.backup = Some(BackupConfig {
                    provider: provider.trim().to_string(),
                    model: model.trim().to_string(),
                });
                self.editing = None;
                self.status = None;
            }
            _ => {
                self.status = Some("must be provider:model (or empty to clear)".to_string());
            }
        }
    }

    /// Validate + commit the numeric edit buffer. Percentages clamp to
    /// 0–100; the cache time and the TTFT / idle timeouts accept any
    /// non-negative integer (seconds). Non-numeric input is rejected inline
    /// (the field stays open).
    fn commit_numeric_edit(&mut self) {
        let Some(field) = self.editing else {
            return;
        };
        let raw = self.buf.text().trim();
        if matches!(field, SettingsField::QualityRank | SettingsField::CostRank) {
            let parsed: i64 = match raw.parse() {
                Ok(n) => n,
                Err(_) => {
                    self.status = Some("must be a signed number".to_string());
                    return;
                }
            };
            match field {
                SettingsField::QualityRank => self.quality_rank = Some(parsed),
                SettingsField::CostRank => self.cost_rank = Some(parsed),
                _ => {}
            }
            self.editing = None;
            self.status = None;
            return;
        }
        let parsed: u64 = match raw.parse() {
            Ok(n) => n,
            Err(_) => {
                self.status = Some("must be a number".to_string());
                return;
            }
        };
        match field {
            SettingsField::AutoCompactPct => {
                self.context.auto_compact_pct = parsed.min(100) as u8;
                self.mark_present(field);
            }
            SettingsField::AutoPrunePct => {
                self.context.auto_prune_pct = parsed.min(100) as u8;
                self.mark_present(field);
            }
            SettingsField::AutoPrunePrunablePct => {
                self.context.auto_prune_prunable_pct = parsed.min(100) as u8;
                self.mark_present(field);
            }
            SettingsField::CacheTtlSecs => {
                self.cache.ttl_secs = parsed;
                self.mark_present(field);
            }
            SettingsField::TimeoutTtftSecs => {
                self.timeout.ttft_secs = parsed;
                self.mark_present(field);
            }
            SettingsField::TimeoutIdleSecs => {
                self.timeout.idle_secs = parsed;
                self.mark_present(field);
            }
            _ => {}
        }
        self.editing = None;
        // Coherence note for the two prune/compact ctx-% thresholds: auto-prune
        // is meant to fire below auto-compact. If the prune ctx% lands at or
        // above the compact ctx%, compaction triggers first and the prune
        // threshold is probably unintended — the values are still valid, so we
        // warn rather than reject. Other numeric fields just clear the status.
        if matches!(
            field,
            SettingsField::AutoPrunePct | SettingsField::AutoCompactPct
        ) && self.context.auto_prune_pct >= self.context.auto_compact_pct
        {
            self.status = Some(
                "note: auto-prune ctx % ≥ auto-compact ctx % — compaction will trigger first"
                    .to_string(),
            );
        } else {
            self.status = None;
        }
    }

    /// The inline numeric edit buffer when a field is open, else `None`
    /// (browsing rows has no text field).
    pub(super) fn active_text_field(&mut self) -> Option<&mut TextField> {
        self.editing.is_some().then_some(&mut self.buf)
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> SettingsResult {
        // Inline numeric / text edit owns input until Enter/Esc.
        if let Some(field) = self.editing {
            match key.code {
                KeyCode::Enter => {
                    if field.is_text() {
                        self.commit_text_edit();
                    } else {
                        self.commit_numeric_edit();
                    }
                }
                KeyCode::Esc => {
                    self.editing = None;
                    self.status = None;
                }
                _ => {
                    self.buf.handle_key(key);
                }
            }
            return SettingsResult::Stay;
        }

        match key.code {
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                self.provider_trust_confirm_pending = false;
                SettingsResult::Back
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, self.row_count());
                self.provider_trust_confirm_pending = false;
                self.status = None;
                SettingsResult::Stay
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.cursor = crate::tui::nav::wrap_next(self.cursor, self.row_count());
                self.provider_trust_confirm_pending = false;
                self.status = None;
                SettingsResult::Stay
            }
            // `s` accelerator: commit (only when not on a field that would
            // otherwise consume it — fields here don't take text in browse
            // mode, so `s` is always free as the accelerator).
            KeyCode::Char('s') => SettingsResult::Save,
            KeyCode::Char('x') if !self.on_save_row() => {
                self.clear_override(self.field_at(self.cursor));
                self.provider_trust_confirm_pending = false;
                SettingsResult::Stay
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if self.on_save_row() {
                    return SettingsResult::Save;
                }
                let field = self.field_at(self.cursor);
                if field == SettingsField::TrustPolicy
                    && matches!(self.scope, SettingsScope::Provider)
                    && matches!(key.kind, KeyEventKind::Repeat)
                {
                    return SettingsResult::Stay;
                }
                if field.is_numeric() {
                    self.begin_numeric_edit(field);
                } else if field.is_text() {
                    self.begin_text_edit(field);
                } else {
                    self.cycle(field);
                }
                SettingsResult::Stay
            }
            _ => SettingsResult::Stay,
        }
    }

    /// Write the working state back into `entry`, respecting the scope's
    /// override semantics. Called on Back so the parent Edit page carries the
    /// edits (committed to disk by the caller).
    pub(super) fn write_into(&self, entry: &mut ProviderEntry) {
        match &self.scope {
            SettingsScope::Provider => {
                entry.context = self.context.clone();
                entry.auto_prune = self.auto_prune;
                entry.cache = self.cache.clone();
                entry.shrink = self.shrink.clone();
                entry.timeout = self.timeout.clone();
                entry.wire_api = self.wire_api;
                entry.backup = self.backup.clone();
                entry.mode = self.mode;
                entry.inline_think = self.inline_think;
                entry.hint_tool_call_corrections = self.hint_tool_call_corrections;
                entry.trust = self.trust;
                entry.location = self.location;
                entry.quality_rank = self.quality_rank;
                entry.cost_rank = self.cost_rank;
                entry.subagent_invokable = self.subagent_invokable;
                if self.show_xai_multi_agent_tools_beta {
                    entry.capabilities.client_side_tools = if self.xai_multi_agent_tools_beta {
                        tools_supported_capability()
                    } else {
                        ClientSideToolsCapability::default()
                    };
                }
                entry.allow_insecure_http = self.allow_insecure_http;
            }
            SettingsScope::Model { model_id } => {
                // Ensure the row exists (it always should — the editor was
                // opened from it), then set the Option overrides per group.
                if let Some(m) = entry.models.iter_mut().find(|m| &m.id == model_id) {
                    apply_model_overrides(m, self);
                }
            }
        }
    }
}

/// Apply the editor's working state to a model row's `Option<…>` override
/// fields: a present group writes `Some(value)`, an absent group writes
/// `None` (inherit). `mode` writes its `Option` directly.
fn apply_model_overrides(m: &mut ModelEntry, e: &SettingsEditor) {
    m.context = if e.context_present {
        Some(e.context.clone())
    } else {
        None
    };
    m.cache = if e.cache_present {
        Some(e.cache.clone())
    } else {
        None
    };
    m.shrink = if e.shrink_present {
        Some(e.shrink.clone())
    } else {
        None
    };
    m.timeout = if e.timeout_present {
        Some(e.timeout.clone())
    } else {
        None
    };
    m.wire_api = if e.wire_api_present {
        e.wire_api
    } else {
        WireApi::Auto
    };
    // Backup tracks presence via its `Option` directly (like `mode`).
    m.backup = e.backup.clone();
    m.mode = e.mode;
    m.auto_prune = e.auto_prune;
    m.trust = e.trust;
    m.location = e.location;
    m.quality_rank = e.quality_rank;
    m.cost_rank = e.cost_rank;
    m.subagent_invokable = e.subagent_invokable;
    m.inline_think = e.inline_think;
    m.hint_tool_call_corrections = e.hint_tool_call_corrections;
    if e.show_xai_multi_agent_tools_beta {
        m.capabilities.client_side_tools = if e.xai_multi_agent_tools_beta_present {
            if e.xai_multi_agent_tools_beta {
                tools_supported_capability()
            } else {
                tools_requires_entitlement_capability()
            }
        } else {
            ClientSideToolsCapability::default()
        };
    }
}

fn tools_entitlement_enabled(capability: &ClientSideToolsCapability) -> bool {
    matches!(capability.status, CapabilityStatus::Supported)
}

fn tools_supported_capability() -> ClientSideToolsCapability {
    ClientSideToolsCapability {
        status: CapabilityStatus::Supported,
        entitlement: Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT.to_string()),
        source: Some(CapabilitySource::Manual),
    }
}

fn tools_requires_entitlement_capability() -> ClientSideToolsCapability {
    ClientSideToolsCapability {
        status: CapabilityStatus::RequiresEntitlement,
        entitlement: Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT.to_string()),
        source: Some(CapabilitySource::Manual),
    }
}

fn wire_api_label(wire_api: WireApi) -> &'static str {
    match wire_api {
        WireApi::Auto => "auto",
        WireApi::Completions => "completions",
        WireApi::Responses => "responses",
    }
}

pub(super) enum SettingsResult {
    Stay,
    Back,
    /// `[save changes]` row / `s` accelerator: write the working state into
    /// the parent entry and commit to disk, staying on the page.
    Save,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_with_model() -> ProviderEntry {
        let mut entry = ProviderEntry {
            url: "https://x".into(),
            context: ContextConfig {
                auto_compact_pct: 85,
                auto_prune_pct: 55,
                auto_prune_prunable_pct: 35,
            },
            ..ProviderEntry::default()
        };
        entry.models.push(ModelEntry {
            id: "m1".into(),
            name: None,
            thinking_modes: vec![],
            inputs: None,
            context_length: Some(100_000),
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
            wire_api: Default::default(),
            extra: Default::default(),
            capabilities: Default::default(),
            provider_metadata: Default::default(),
        });
        entry
    }

    fn press(code: KeyCode) -> KeyEvent {
        use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn repeat(code: KeyCode) -> KeyEvent {
        use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Repeat,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn timeout_fields_use_threshold_labels() {
        assert_eq!(
            SettingsField::TimeoutTtftSecs.label(),
            "First-token threshold (s)"
        );
        assert_eq!(SettingsField::TimeoutIdleSecs.label(), "Idle threshold (s)");
    }

    #[test]
    fn provider_scope_shows_insecure_http_opt_in_default_off_and_writes_back() {
        let entry = provider_with_model();
        assert!(!entry.allow_insecure_http);

        let mut e = SettingsEditor::for_provider("p", &entry);
        assert_eq!(e.fields().first(), Some(&SettingsField::AllowInsecureHttp));
        assert_eq!(e.value_str(SettingsField::AllowInsecureHttp), "off");
        assert!(e.is_overridden(SettingsField::AllowInsecureHttp));

        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::AllowInsecureHttp)
            .unwrap();
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::AllowInsecureHttp), "on");

        let mut written = entry.clone();
        e.write_into(&mut written);
        assert!(written.allow_insecure_http);
        assert_eq!(written.url, entry.url);
        assert_eq!(written.headers, entry.headers);
    }

    #[test]
    fn model_scope_does_not_show_insecure_http_opt_in() {
        let entry = provider_with_model();
        let e = SettingsEditor::for_model("p", &entry, "m1");
        assert!(!e.fields().contains(&SettingsField::AllowInsecureHttp));
    }

    #[test]
    fn model_scope_seeds_from_inherited_then_overrides_on_edit() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_model("p", &entry, "m1");
        // Inherited (no override yet) — shows the provider value, dimmed.
        assert_eq!(e.value_str(SettingsField::AutoCompactPct), "85%");
        assert!(!e.is_overridden(SettingsField::AutoCompactPct));
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::AutoCompactPct)
            .unwrap();
        // Edit the auto-compact %: open, type, commit.
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("70".to_string());
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::AutoCompactPct), "70%");
        assert!(e.is_overridden(SettingsField::AutoCompactPct));
        // Writeback sets the model override.
        let mut entry2 = entry.clone();
        e.write_into(&mut entry2);
        let m = entry2.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.context.as_ref().unwrap().auto_compact_pct, 70);
    }

    #[test]
    fn percentage_clamps_to_100_and_rejects_non_numeric() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_provider("p", &entry);
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::AutoCompactPct)
            .unwrap();
        // Over 100 clamps.
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("250".to_string());
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::AutoCompactPct), "100%");
        // Non-numeric is rejected (field stays open, value unchanged).
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("abc".to_string());
        e.handle_key(press(KeyCode::Enter));
        assert!(e.editing.is_some(), "field stays open on bad input");
        assert!(e.status.as_deref().unwrap_or("").contains("number"));
    }

    #[test]
    fn prune_ge_compact_warns_but_commits_and_coherent_value_clears() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_provider("p", &entry);
        // Provider auto-compact starts at 85; set prune to 90 (≥ compact).
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::AutoPrunePct)
            .unwrap();
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("90".to_string());
        e.handle_key(press(KeyCode::Enter));
        // Commit succeeded and closed the edit.
        assert!(e.editing.is_none(), "coherence warning still commits");
        assert_eq!(e.value_str(SettingsField::AutoPrunePct), "90%");
        // …but a warning is surfaced.
        assert!(
            e.status
                .as_deref()
                .unwrap_or("")
                .contains("compaction will trigger first"),
            "expected coherence warning, got {:?}",
            e.status
        );

        // Now bring prune back below compact — status clears.
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("40".to_string());
        e.handle_key(press(KeyCode::Enter));
        assert!(e.editing.is_none());
        assert_eq!(e.value_str(SettingsField::AutoPrunePct), "40%");
        assert_eq!(e.status, None, "coherent value clears the warning");
    }

    #[test]
    fn mode_cycles_defensive_normal_frontier_inherit() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_provider("p", &entry);
        // Move to the Mode row (computed from the field order).
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::Mode)
            .unwrap();
        assert_eq!(
            e.value_str(SettingsField::Mode),
            "inherit (global llm mode)"
        );
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::Mode), "defensive");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::Mode), "normal");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::Mode), "frontier");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(
            e.value_str(SettingsField::Mode),
            "inherit (global llm mode)"
        );
        // Writeback: inherit → None.
        let mut entry2 = entry.clone();
        e.write_into(&mut entry2);
        assert!(entry2.mode.is_none());
    }

    /// Auto-prune master-switch row: tri-state at both scopes, tracked via
    /// its own Option (no context-group coupling), written back per scope.
    #[test]
    fn auto_prune_row_cycles_and_writes_back() {
        let entry = provider_with_model();

        // Provider scope: on(default/inherit) → on → off → inherit.
        let mut e = SettingsEditor::for_provider("p", &entry);
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::AutoPruneEnabled)
            .unwrap();
        assert_eq!(e.value_str(SettingsField::AutoPruneEnabled), "on (default)");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::AutoPruneEnabled), "on");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::AutoPruneEnabled), "off");
        let mut entry2 = entry.clone();
        e.write_into(&mut entry2);
        assert_eq!(entry2.auto_prune, Some(false));

        // Model scope: unset shows inherit and is dimmed; cycling to off
        // pins the override; clearing with `x` returns to inherit. The
        // context-group pct rows are untouched by the switch.
        let mut e = SettingsEditor::for_model("p", &entry, "m1");
        assert_eq!(e.value_str(SettingsField::AutoPruneEnabled), "inherit");
        assert!(!e.is_overridden(SettingsField::AutoPruneEnabled));
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::AutoPruneEnabled)
            .unwrap();
        e.handle_key(press(KeyCode::Enter)); // on
        e.handle_key(press(KeyCode::Enter)); // off
        assert!(e.is_overridden(SettingsField::AutoPruneEnabled));
        let mut entry3 = entry.clone();
        e.write_into(&mut entry3);
        let m = entry3.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.auto_prune, Some(false));
        assert!(m.context.is_none(), "switch must not pin the ctx% group");

        e.handle_key(press(KeyCode::Char('x')));
        assert!(!e.is_overridden(SettingsField::AutoPruneEnabled));
        let mut entry4 = entry.clone();
        e.write_into(&mut entry4);
        let m = entry4.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.auto_prune, None);
    }

    #[test]
    fn inline_think_model_scope_tri_state_cycles() {
        let entry = provider_with_model();

        // Model scope: the row is present as the last field.
        let mut e = SettingsEditor::for_model("p", &entry, "m1");
        assert_eq!(e.field_count(), 19);
        assert_eq!(
            *e.fields().last().unwrap(),
            SettingsField::HintToolCallCorrections
        );
        assert!(e.fields().contains(&SettingsField::InlineThink));
        // Default (unset override) shows explicit inherit wording and is dimmed.
        assert_eq!(
            e.value_str(SettingsField::InlineThink),
            "inherit provider/default"
        );
        assert!(!e.is_overridden(SettingsField::InlineThink));

        // Move to the inline-`<think>` row and cycle on→off→inherit.
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::InlineThink)
            .unwrap();
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::InlineThink), "extract");
        assert!(e.is_overridden(SettingsField::InlineThink));
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::InlineThink), "leave inline");
        // Writeback pins the explicit opt-out on the model row.
        let mut entry_off = entry.clone();
        e.write_into(&mut entry_off);
        let m = entry_off.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.inline_think, Some(false));

        // Cycle once more → back to inherit (None).
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(
            e.value_str(SettingsField::InlineThink),
            "inherit provider/default"
        );
        assert!(!e.is_overridden(SettingsField::InlineThink));
        let mut entry_default = entry.clone();
        e.write_into(&mut entry_default);
        let m = entry_default.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.inline_think, None, "inherit writes None");
    }

    #[test]
    fn inline_think_provider_scope_tri_state_cycles_and_writes_back() {
        let entry = provider_with_model();
        // Provider scope now also shows the inline-`<think>` tri-state row,
        // mirroring the `mode` tri-state.
        let mut prov = SettingsEditor::for_provider("p", &entry);
        assert!(prov.fields().contains(&SettingsField::InlineThink));
        assert_eq!(prov.field_count(), 20);
        // Seeded from the provider's (unset) override → inherit default.
        assert_eq!(
            prov.value_str(SettingsField::InlineThink),
            "inherit default"
        );

        // Cycle to "leave inline" and write it back onto the provider entry.
        prov.cursor = prov
            .fields()
            .iter()
            .position(|f| *f == SettingsField::InlineThink)
            .unwrap();
        prov.handle_key(press(KeyCode::Enter)); // inherit → on
        assert_eq!(prov.value_str(SettingsField::InlineThink), "extract");
        prov.handle_key(press(KeyCode::Enter)); // extract → leave inline
        assert_eq!(prov.value_str(SettingsField::InlineThink), "leave inline");
        let mut entry_off = entry.clone();
        prov.write_into(&mut entry_off);
        assert_eq!(entry_off.inline_think, Some(false));

        // Cycle back to inherit → None on writeback.
        prov.handle_key(press(KeyCode::Enter)); // leave inline → inherit default
        assert_eq!(
            prov.value_str(SettingsField::InlineThink),
            "inherit default"
        );
        let help = prov.selected_help().expect("inline think help");
        assert!(help.contains("extract strips literal <think> blocks"));
        assert!(help.contains("stores them as reasoning"));
        assert!(help.contains("Interface -> Thinking display"));
        assert!(help.contains("does not request more reasoning"));
    }

    #[test]
    fn provider_trust_confirm_ignores_repeat_and_honors_lockout() {
        let entry = provider_with_model();
        let mut provider =
            SettingsEditor::for_provider("p", &entry).with_trust_confirm_lockout_ms(60_000);
        provider.cursor = provider
            .fields()
            .iter()
            .position(|f| *f == SettingsField::TrustPolicy)
            .unwrap();

        provider.handle_key(press(KeyCode::Enter));
        provider.handle_key(repeat(KeyCode::Enter));
        assert_ne!(provider.value_str(SettingsField::TrustPolicy), "trusted");

        provider.handle_key(press(KeyCode::Enter));
        assert_ne!(provider.value_str(SettingsField::TrustPolicy), "trusted");
        assert!(provider.status.as_deref().unwrap_or("").contains("wait"));
    }

    #[test]
    fn trust_policy_rows_write_provider_and_model_policy() {
        let entry = provider_with_model();
        let mut provider = SettingsEditor::for_provider("p", &entry);
        assert!(provider.fields().contains(&SettingsField::TrustPolicy));
        assert_eq!(
            provider.value_str(SettingsField::TrustPolicy),
            "untrusted (default)"
        );
        provider.cursor = provider
            .fields()
            .iter()
            .position(|f| *f == SettingsField::TrustPolicy)
            .unwrap();
        provider.handle_key(press(KeyCode::Enter));
        assert_eq!(
            provider.value_str(SettingsField::TrustPolicy),
            "untrusted (default)"
        );
        assert!(
            provider
                .status
                .as_deref()
                .unwrap_or("")
                .contains("press Enter again")
        );
        provider.handle_key(press(KeyCode::Enter));
        assert_eq!(provider.value_str(SettingsField::TrustPolicy), "trusted");
        let mut provider_written = entry.clone();
        provider.write_into(&mut provider_written);
        assert_eq!(provider_written.trust, Some(ModelTrust::Trusted));

        let mut e = SettingsEditor::for_model("p", &entry, "m1");
        assert!(e.fields().contains(&SettingsField::TrustPolicy));
        assert_eq!(e.value_str(SettingsField::TrustPolicy), "inherit");
        assert!(!e.is_overridden(SettingsField::TrustPolicy));

        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::TrustPolicy)
            .unwrap();
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::TrustPolicy), "trusted");
        assert!(e.is_overridden(SettingsField::TrustPolicy));
        assert!(e.status.as_deref().unwrap_or("").contains("unsanitized"));
        let mut entry_off = entry.clone();
        e.write_into(&mut entry_off);
        let m = entry_off.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.trust, Some(ModelTrust::Trusted));

        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::TrustPolicy), "untrusted");
        let mut entry_untrusted = entry.clone();
        e.write_into(&mut entry_untrusted);
        let m = entry_untrusted
            .models
            .iter()
            .find(|m| m.id == "m1")
            .unwrap();
        assert_eq!(m.trust, Some(ModelTrust::Untrusted));
    }

    #[test]
    fn hint_tool_call_corrections_model_scope_tri_state_round_trips() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_model("p", &entry, "m1");
        // Default (unset override) shows "inherit" and is dimmed.
        assert_eq!(
            e.value_str(SettingsField::HintToolCallCorrections),
            "inherit"
        );
        assert!(!e.is_overridden(SettingsField::HintToolCallCorrections));

        // Cycle inherit→on→off and pin the explicit opt-out.
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::HintToolCallCorrections)
            .unwrap();
        e.handle_key(press(KeyCode::Enter)); // inherit → on
        assert_eq!(e.value_str(SettingsField::HintToolCallCorrections), "on");
        assert!(e.is_overridden(SettingsField::HintToolCallCorrections));
        e.handle_key(press(KeyCode::Enter)); // on → off
        assert_eq!(e.value_str(SettingsField::HintToolCallCorrections), "off");
        let mut entry_off = entry.clone();
        e.write_into(&mut entry_off);
        let m = entry_off.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.hint_tool_call_corrections, Some(false));

        // Cycle once more → inherit (None on writeback).
        e.handle_key(press(KeyCode::Enter)); // off → inherit
        assert_eq!(
            e.value_str(SettingsField::HintToolCallCorrections),
            "inherit"
        );
        let mut entry_default = entry.clone();
        e.write_into(&mut entry_default);
        let m = entry_default.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.hint_tool_call_corrections, None, "inherit writes None");
    }

    #[test]
    fn hint_tool_call_corrections_provider_scope_round_trips() {
        let entry = provider_with_model();
        let mut prov = SettingsEditor::for_provider("p", &entry);
        assert!(
            prov.fields()
                .contains(&SettingsField::HintToolCallCorrections)
        );
        assert_eq!(
            prov.value_str(SettingsField::HintToolCallCorrections),
            "inherit"
        );
        prov.cursor = prov
            .fields()
            .iter()
            .position(|f| *f == SettingsField::HintToolCallCorrections)
            .unwrap();
        prov.handle_key(press(KeyCode::Enter)); // inherit → on
        let mut entry_on = entry.clone();
        prov.write_into(&mut entry_on);
        assert_eq!(entry_on.hint_tool_call_corrections, Some(true));

        prov.handle_key(press(KeyCode::Enter)); // on → off
        prov.handle_key(press(KeyCode::Enter)); // off → inherit
        let mut entry_inherit = entry.clone();
        prov.write_into(&mut entry_inherit);
        assert_eq!(entry_inherit.hint_tool_call_corrections, None);
    }

    #[test]
    fn backup_text_edit_sets_clears_and_validates() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_provider("p", &entry);
        // Move to the Backup row.
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::Backup)
            .unwrap();
        // Unset shows "none".
        assert_eq!(e.value_str(SettingsField::Backup), "none");

        // Open the text edit, type a valid `provider:model`, commit.
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("reliable:claude-sonnet-4-6".to_string());
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(
            e.value_str(SettingsField::Backup),
            "reliable:claude-sonnet-4-6"
        );
        assert!(e.is_overridden(SettingsField::Backup));
        // Writeback pins it onto the provider entry.
        let mut entry_set = entry.clone();
        e.write_into(&mut entry_set);
        let b = entry_set.backup.as_ref().unwrap();
        assert_eq!(b.provider, "reliable");
        assert_eq!(b.model, "claude-sonnet-4-6");

        // A bad shape is rejected inline (field stays open, value unchanged).
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("no-colon".to_string());
        e.handle_key(press(KeyCode::Enter));
        assert!(e.editing.is_some(), "bad shape keeps the field open");
        assert!(e.status.as_deref().unwrap_or("").contains("provider:model"));
        e.handle_key(press(KeyCode::Esc));

        // Empty commit clears the backup (no fallback).
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new(String::new());
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::Backup), "none");
        let mut entry_clear = entry.clone();
        e.write_into(&mut entry_clear);
        assert!(entry_clear.backup.is_none());
    }

    #[test]
    fn backup_model_scope_seeds_from_own_override_only() {
        // Model scope: backup tracks its override via the Option (like `mode`),
        // seeded from the model's OWN backup, not the inherited provider one.
        let mut entry = provider_with_model();
        entry.backup = Some(BackupConfig {
            provider: "prov-level".into(),
            model: "prov-model".into(),
        });
        let e = SettingsEditor::for_model("p", &entry, "m1");
        // The model has no own backup → shows "none" and is NOT marked
        // overridden (it inherits the provider backup at resolve time).
        assert_eq!(e.value_str(SettingsField::Backup), "none");
        assert!(!e.is_overridden(SettingsField::Backup));
    }

    #[test]
    fn xai_provider_entitlement_toggle_writes_generic_capability() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_provider("grok-oauth", &entry);
        assert!(e.fields().contains(&SettingsField::XaiMultiAgentToolsBeta));
        assert_eq!(e.value_str(SettingsField::XaiMultiAgentToolsBeta), "off");

        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::XaiMultiAgentToolsBeta)
            .unwrap();
        e.handle_key(press(KeyCode::Enter));

        let mut written = entry.clone();
        e.write_into(&mut written);
        let capability = &written.capabilities.client_side_tools;
        assert_eq!(capability.status, CapabilityStatus::Supported);
        assert_eq!(capability.source, Some(CapabilitySource::Manual));
        assert_eq!(
            capability.entitlement.as_deref(),
            Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT)
        );

        e.handle_key(press(KeyCode::Enter));
        let mut cleared = entry.clone();
        e.write_into(&mut cleared);
        assert!(cleared.capabilities.client_side_tools.is_empty());
    }

    #[test]
    fn xai_model_entitlement_override_can_disagree_with_provider() {
        let mut entry = provider_with_model();
        entry.capabilities.client_side_tools = tools_supported_capability();
        let mut e = SettingsEditor::for_model("grok", &entry, "m1");
        assert_eq!(e.value_str(SettingsField::XaiMultiAgentToolsBeta), "on");
        assert!(!e.is_overridden(SettingsField::XaiMultiAgentToolsBeta));

        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::XaiMultiAgentToolsBeta)
            .unwrap();
        e.handle_key(press(KeyCode::Enter));

        let mut written = entry.clone();
        e.write_into(&mut written);
        let capability = &written
            .models
            .iter()
            .find(|m| m.id == "m1")
            .unwrap()
            .capabilities
            .client_side_tools;
        assert_eq!(capability.status, CapabilityStatus::RequiresEntitlement);
        assert_eq!(capability.source, Some(CapabilitySource::Manual));
        assert_eq!(
            capability.entitlement.as_deref(),
            Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT)
        );
    }

    #[test]
    fn non_xai_settings_preserve_generic_client_side_tool_capabilities() {
        let mut entry = provider_with_model();
        entry.capabilities.client_side_tools = ClientSideToolsCapability {
            status: CapabilityStatus::Unsupported,
            entitlement: None,
            source: Some(CapabilitySource::Live),
        };
        entry.models[0].capabilities.client_side_tools = ClientSideToolsCapability {
            status: CapabilityStatus::Supported,
            entitlement: None,
            source: Some(CapabilitySource::Live),
        };

        let provider = SettingsEditor::for_provider("p", &entry);
        let mut provider_written = entry.clone();
        provider.write_into(&mut provider_written);
        assert_eq!(
            provider_written.capabilities.client_side_tools,
            entry.capabilities.client_side_tools
        );

        let model = SettingsEditor::for_model("p", &entry, "m1");
        let mut model_written = entry.clone();
        model.write_into(&mut model_written);
        assert_eq!(
            model_written.models[0].capabilities.client_side_tools,
            entry.models[0].capabilities.client_side_tools
        );
    }

    #[test]
    fn provider_scope_wire_api_cycles_and_writes_back() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_provider("p", &entry);
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::WireApi)
            .unwrap();
        assert_eq!(e.value_str(SettingsField::WireApi), "auto");

        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::WireApi), "completions");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::WireApi), "responses");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::WireApi), "auto");

        e.handle_key(press(KeyCode::Enter));
        let mut entry2 = entry.clone();
        e.write_into(&mut entry2);
        assert_eq!(entry2.wire_api, WireApi::Completions);
    }

    #[test]
    fn model_scope_wire_api_inherits_then_cycles_and_clears_pin() {
        let mut entry = provider_with_model();
        entry.wire_api = WireApi::Responses;
        let mut e = SettingsEditor::for_model("p", &entry, "m1");
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::WireApi)
            .unwrap();

        assert_eq!(e.value_str(SettingsField::WireApi), "responses (inherit)");
        assert!(!e.is_overridden(SettingsField::WireApi));

        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::WireApi), "completions");
        assert!(e.is_overridden(SettingsField::WireApi));
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::WireApi), "responses");
        e.handle_key(press(KeyCode::Enter));
        assert_eq!(e.value_str(SettingsField::WireApi), "auto (inherit)");
        assert!(!e.is_overridden(SettingsField::WireApi));

        e.handle_key(press(KeyCode::Enter));
        let mut pinned = entry.clone();
        e.write_into(&mut pinned);
        let m = pinned.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.wire_api, WireApi::Completions);

        e.handle_key(press(KeyCode::Char('x')));
        let mut inherited = entry.clone();
        e.write_into(&mut inherited);
        let m = inherited.models.iter().find(|m| m.id == "m1").unwrap();
        assert_eq!(m.wire_api, WireApi::Auto);
    }

    #[test]
    fn wire_api_hidden_for_native_anthropic_provider() {
        let mut entry = provider_with_model();
        entry.url = "https://api.anthropic.com/v1".into();

        let provider = SettingsEditor::for_provider("p", &entry);
        assert!(!provider.fields().contains(&SettingsField::WireApi));

        let model = SettingsEditor::for_model("p", &entry, "m1");
        assert!(!model.fields().contains(&SettingsField::WireApi));
    }

    #[test]
    fn model_scope_clear_resets_to_inherit() {
        let entry = provider_with_model();
        let mut e = SettingsEditor::for_model("p", &entry, "m1");
        e.cursor = e
            .fields()
            .iter()
            .position(|f| *f == SettingsField::AutoCompactPct)
            .unwrap();
        // Override the auto-compact %.
        e.handle_key(press(KeyCode::Enter));
        e.buf = TextField::new("70".to_string());
        e.handle_key(press(KeyCode::Enter));
        assert!(e.is_overridden(SettingsField::AutoCompactPct));
        // Clear it back to inherit with `x`.
        e.handle_key(press(KeyCode::Char('x')));
        assert!(!e.is_overridden(SettingsField::AutoCompactPct));
        let mut entry2 = entry.clone();
        e.write_into(&mut entry2);
        let m = entry2.models.iter().find(|m| m.id == "m1").unwrap();
        assert!(m.context.is_none(), "cleared override writes None");
    }

    #[test]
    fn field_lists_match_expected_for_every_scope_and_flag_variant() {
        use SettingsField::*;
        // Independent oracle: the single canonical maximal ordering, each row
        // tagged with the condition under which it appears. `derive_fields`
        // (the single source of truth, cached per editor and returned by
        // `fields()`) must equal this table filtered by scope + the two
        // visibility flags, for every one of the eight variants — this pins row
        // order and membership so a future row can't silently go missing from
        // one variant.
        //
        // (field, provider_only, wire_api_only, xai_only)
        let canonical: &[(SettingsField, bool, bool, bool)] = &[
            (AllowInsecureHttp, true, false, false),
            (TrustPolicy, false, false, false),
            (Location, false, false, false),
            (QualityRank, false, false, false),
            (CostRank, false, false, false),
            (SubagentInvokable, false, false, false),
            (AutoCompactPct, false, false, false),
            (AutoPruneEnabled, false, false, false),
            (AutoPrunePct, false, false, false),
            (AutoPrunePrunablePct, false, false, false),
            (CacheTtlSecs, false, false, false),
            (CacheMode, false, false, false),
            (ShrinkStrategy, false, false, false),
            (TimeoutTtftSecs, false, false, false),
            (TimeoutIdleSecs, false, false, false),
            (WireApi, false, true, false),
            (XaiMultiAgentToolsBeta, false, false, true),
            (Backup, false, false, false),
            (Mode, false, false, false),
            (InlineThink, false, false, false),
            (HintToolCallCorrections, false, false, false),
        ];

        // Drive the visibility flags directly so the assertion covers all eight
        // combinations regardless of provider detection.
        for is_model in [false, true] {
            for wire in [false, true] {
                for xai in [false, true] {
                    let expected: Vec<SettingsField> = canonical
                        .iter()
                        .filter(|(_, provider_only, wire_only, xai_only)| {
                            (!provider_only || !is_model)
                                && (!wire_only || wire)
                                && (!xai_only || xai)
                        })
                        .map(|(f, ..)| *f)
                        .collect();

                    assert_eq!(
                        SettingsEditor::derive_fields(is_model, wire, xai),
                        expected,
                        "mismatch for is_model={is_model} wire={wire} xai={xai}"
                    );
                }
            }
        }
    }
}
