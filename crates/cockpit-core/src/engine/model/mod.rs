//! Provider-side completion model dispatch.
//!
//! `CompletionModel` in rig isn't object-safe (associated types +
//! `impl Trait` returns + `Self` in return position), so we can't hold a
//! `Box<dyn CompletionModel>`. The pattern upstream now recommends is an
//! enum dispatch — see rig's `examples/enum_dispatch.rs`. We ship two
//! variants: `OpenAi` (every OpenAI-compatible endpoint in the user's
//! [`crate::providers`] templates — including Claude reached via
//! OpenRouter/Copilot/etc.) and `Anthropic` (the native
//! `api.anthropic.com` endpoint, which gets rig's provider-concrete
//! per-block prompt caching, prompt `prompt-caching-strategy.md`).
//!
//! Routing: a build site picks the native Anthropic path **only** when
//! the resolved base URL's host is `api.anthropic.com` (see
//! [`is_anthropic_native`]). Claude models served by any other host stay
//! on the OpenAI-compat path — they're not native Anthropic endpoints and
//! don't accept inline cache breakpoints.
//!
//! Authentication: we delegate to
//! [`crate::providers::models_fetch::resolve_provider_request`], the
//! same resolver `/models` fetches use. For most providers that's just
//! `$VAR` expansion over the configured `Authorization` header; for
//! GitHub Copilot it also honors the documented env-var sources
//! (`COPILOT_GITHUB_TOKEN`/`GH_TOKEN`/`GITHUB_TOKEN`/`GITHUB_COPILOT_API_TOKEN`)
//! and the `COPILOT_API_URL` base-URL override. The OpenAI-compat path
//! hands rig the bearer token; the native Anthropic path reads the
//! resolved `x-api-key` header and lets rig set `anthropic-version`
//! itself (plus the extended-cache beta header on the 1h opt-in).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::{future::BoxFuture, future::Shared};
use rig::client::CompletionClient;
use rig::completion::Completion;
use rig::message::{
    Message, Reasoning, ReasoningContent, ToolChoice, ToolResultContent, UserContent,
};
use rig::streaming::StreamedAssistantContent;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::engine::agent::TurnEvent;
use crate::engine::retry;

pub(crate) type PreDrainFuture = Shared<BoxFuture<'static, std::result::Result<(), String>>>;

mod build;
mod dispatch;
mod failure;
mod http_client;
mod outbound_guard;
mod redact;
pub(crate) mod rig_boundary;
mod wire;
pub(crate) mod wire_schema;

#[allow(unused_imports)]
pub use build::ModelParams;
#[allow(unused_imports)]
pub use build::{
    UTILITY_BACKGROUND_TIMEOUT, UTILITY_MAX_TOKENS_CAP, UTILITY_TURN_BLOCKING_TIMEOUT,
    UtilityBudgetClass, UtilityCallSite,
};
#[allow(unused_imports)]
pub use dispatch::TandemOutcome;
#[allow(unused_imports)]
pub use failure::{
    InferenceCancelled, InferenceErrorClass, InferenceFailure, InferenceGated, InferencePhase,
    InferenceTiming, as_inference_failure, auth_failure_kind, failure_engages_backup, is_cancelled,
    is_gated,
};
#[allow(unused_imports)]
pub use http_client::UsageAliasHttpClient;
pub(crate) use outbound_guard::OutboundGuard;
#[allow(unused_imports)]
pub use wire::{EndpointRecoveryContext, EndpointRecoveryPrompt};

#[allow(unused_imports)]
use build::*;
#[allow(unused_imports)]
use dispatch::*;
#[allow(unused_imports)]
use failure::*;
#[allow(unused_imports)]
use http_client::*;
#[allow(unused_imports)]
use outbound_guard::*;
#[allow(unused_imports)]
use redact::*;
#[allow(unused_imports)]
use rig_boundary::*;
#[allow(unused_imports)]
use wire::*;

#[cfg(test)]
thread_local! {
    static PREPARE_HISTORY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SCRUB_MESSAGE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_request_prep_counts() {
    PREPARE_HISTORY_CALLS.with(|calls| calls.set(0));
    SCRUB_MESSAGE_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn request_prep_counts() -> (usize, usize) {
    (
        PREPARE_HISTORY_CALLS.with(std::cell::Cell::get),
        SCRUB_MESSAGE_CALLS.with(std::cell::Cell::get),
    )
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedCompletionRequest {
    pub system: String,
    pub history: Vec<Message>,
    pub prompt: Message,
    pub captured: serde_json::Value,
}

/// When set (by `--debug-last-message`), every call to [`Model::complete`]
/// writes a pretty-printed JSON dump of the outbound request to this
/// path before invoking rig. The file is overwritten each turn.
///
/// Holds the *target file path*, not just a flag — the resolver does
/// the `cwd/.lastmessage` join once at startup so we don't depend on
/// `std::env::current_dir()` from inside the agent task.
static DEBUG_LAST_MESSAGE_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Plumb `--debug-last-message` into the engine. Idempotent — second
/// calls are no-ops because `OnceLock::set` returns `Err` once set.
/// Called from `main.rs` before any agent loop starts.
pub fn enable_debug_last_message(path: PathBuf) {
    let _ = DEBUG_LAST_MESSAGE_PATH.set(path);
}

fn debug_last_message_path() -> Option<&'static Path> {
    DEBUG_LAST_MESSAGE_PATH.get().map(PathBuf::as_path)
}

use crate::config::providers::{
    ActiveModelRef, CapabilityStatus, ClientSideToolsCapability, ModelLocation, ProviderEntry,
    ProvidersConfig,
};
use crate::db::session_log::InferenceRequestStatus;
use crate::engine::message::{AssistantContent, OneOrMany, ToolDefinition};
use crate::providers::models_fetch;
use crate::redact::RedactionTable;
use crate::tokens::TokenUsage;
use rig::completion::GetTokenUsage;

/// The aggregated result of one streaming completion attempt: the
/// `message_id`, the assistant content, and the (optional) provider-
/// reported usage. Shared by the provider-flavor arms of
/// [`Model::complete_captured`] and the generic [`drain_completion_stream`]
/// helper they both call.
type CompleteOut = (
    Option<String>,
    OneOrMany<AssistantContent>,
    Option<TokenUsage>,
);

#[derive(Debug, Clone)]
pub struct LiveWireApiState {
    configured: crate::config::providers::WireApi,
    explicit: bool,
    session_confirmed: HashMap<String, crate::config::providers::WireApi>,
}

impl LiveWireApiState {
    fn new(configured: crate::config::providers::WireApi, explicit: bool) -> Self {
        Self {
            configured,
            explicit,
            session_confirmed: HashMap::new(),
        }
    }
}

pub(crate) type LiveWireApi = Arc<Mutex<LiveWireApiState>>;

/// One concrete provider-flavor of completion model. Add variants here
/// as we wire more providers.
#[derive(Clone)]
pub enum Model {
    /// OpenAI-compatible chat-completions endpoint. Used for the
    /// generic openai-compatible template and every vendor that exposes
    /// `/v1/chat/completions` (z.ai, MiniMax, OpenCode Zen, Ollama,
    /// OpenRouter, …). The model id is what the provider's API
    /// expects (e.g. `claude-opus-4-7`, `glm-4.6`, `gpt-4o-mini`).
    OpenAi {
        client: OpenAiCompatClient,
        model_id: String,
        /// The configured provider id this model was built from (a key in the
        /// `providers` map), distinct from the coarse wire-flavor
        /// [`Self::provider_label`]. Used to resolve the per-`(provider, model)`
        /// backup fallback (implementation note) exactly,
        /// regardless of any plan-level model override.
        provider_id: String,
        /// Known upper bound for utility `max_tokens`, resolved from model or
        /// provider max-output/context capability metadata when available.
        utility_token_limit: Option<u64>,
        /// The *resolved concrete* wire endpoint to try first
        /// (implementation note): `Completions` or
        /// `Responses`, never `Auto` (the build path resolves config →
        /// name-detect into a concrete value). The dispatch path retries the
        /// opposite endpoint once on a `unsupported_api_for_model` 400 (layer
        /// 3) and, on success, persists the corrected value via `config_path`.
        wire_api: crate::config::providers::WireApi,
        /// Config file path for self-healing endpoint persistence
        /// (implementation note). When set (production
        /// build sites that know the session cwd, via [`Self::with_config_path`]),
        /// a successful endpoint fallback pins the resolved `wire_api` for this
        /// `(provider_id, model_id)` back into config — the same persistence
        /// path that caches the fetched `/models` list — so the cost is paid at
        /// most once. `None` (tests / utility models) skips the persist; the
        /// fallback itself still works.
        config_path: Option<PathBuf>,
        /// Live per-session endpoint state. The build-time `wire_api` remains
        /// the diagnostic/default endpoint, but dispatch resolves through this
        /// cell every turn so a confirmed self-heal and turn-boundary config
        /// refresh apply without rebuilding the model.
        live_wire_api: LiveWireApi,
        /// Resolved inference-stream timeouts (TTFT + idle) for this
        /// `(provider, model)`
        /// (implementation note).
        /// Resolved once at build time (model → provider → default) and
        /// applied per-chunk in [`drain_completion_stream`].
        timeout: crate::config::providers::TimeoutConfig,
        /// True when this `(provider, model)` resolves a backup target. In that
        /// case stream wait thresholds are terminal so the outer backup wrapper
        /// can retry on the backup; otherwise they only warn and keep waiting.
        hard_timeout_on_stall: bool,
        /// Resolved client-side tool capability for this `(provider, model)`.
        /// OpenAI-compatible providers include Grok/xAI, whose multi-agent
        /// Responses models require a provider entitlement before tools are
        /// accepted.
        client_side_tools: ClientSideToolsCapability,
        /// Whether this resolved provider/model is trusted by config.
        trusted: bool,
        /// Resolved model locality metadata, used for routing audit/export.
        location: Option<ModelLocation>,
        /// Resolved quality rank metadata, used for routing audit/export.
        quality_rank: i64,
        /// Resolved cost rank metadata, used for routing audit/export.
        cost_rank: i64,
        /// Whether this resolved provider/model may be selected for subagents.
        subagent_invokable: bool,
        /// Whether this resolved provider/model may delegate to subagents.
        can_delegate: bool,
        /// Live session trusted-only flag. Checked immediately before every
        /// provider dispatch so `/trusted-only` applies to already-built
        /// active, backup, tandem, and utility model handles.
        trusted_only: Arc<AtomicBool>,
        /// Daemon-wide graceful-shutdown gate
        /// (`daemon-graceful-drain-shutdown.md`). Every outbound provider
        /// request consults it; once the daemon begins draining it refuses
        /// new dispatches with [`InferenceGated`]. A model built outside the
        /// daemon (tests, the auto-title / skill-select utility paths) gets
        /// the default never-draining gate. The registry installs the
        /// daemon's shared gate via [`Model::with_shutdown_gate`].
        gate: crate::daemon::shutdown::ShutdownSignal,
        /// The session redaction table before per-model redaction policy is
        /// applied. Backup and utility model construction uses this table so
        /// each target `(provider, model)` resolves its own trust setting.
        session_redact: Arc<RedactionTable>,
        /// The effective outbound-provider redaction table. For trusted
        /// model rows (`trust: "trusted"`), this is an empty table, so stored
        /// debug/request payloads are exact-as-sent and may contain secrets.
        redact: Arc<RedactionTable>,
    },
    /// Native ChatGPT/Codex subscription Responses endpoint. This is distinct
    /// from the generic OpenAI-compatible arm because the ChatGPT backend
    /// requires top-level `instructions` on `/responses`, plus ChatGPT account
    /// OAuth headers resolved by Cockpit's provider credential path.
    ChatGpt {
        model: ChatGptResponsesModel,
        model_id: String,
        /// The configured provider id this model was built from.
        provider_id: String,
        /// Known upper bound for utility `max_tokens`, resolved from model or
        /// provider max-output/context capability metadata when available.
        utility_token_limit: Option<u64>,
        /// Resolved base URL, kept for the retry TCP probe.
        base_url: String,
        /// Resolved inference-stream timeouts (TTFT + idle).
        timeout: crate::config::providers::TimeoutConfig,
        /// Same backup-gated stream-timeout behavior as [`Model::OpenAi`].
        hard_timeout_on_stall: bool,
        /// Same trusted marker as [`Model::OpenAi`].
        trusted: bool,
        /// Same routing-audit locality metadata as [`Model::OpenAi`].
        location: Option<ModelLocation>,
        /// Same routing-audit quality rank metadata as [`Model::OpenAi`].
        quality_rank: i64,
        /// Same routing-audit cost rank metadata as [`Model::OpenAi`].
        cost_rank: i64,
        /// Same routing-audit subagent availability metadata as [`Model::OpenAi`].
        subagent_invokable: bool,
        /// Same routing-audit delegation permission metadata as [`Model::OpenAi`].
        can_delegate: bool,
        /// Same live trusted-only flag as [`Model::OpenAi`].
        trusted_only: Arc<AtomicBool>,
        /// Same daemon graceful-shutdown gate as [`Model::OpenAi`].
        gate: crate::daemon::shutdown::ShutdownSignal,
        /// Same session redaction table as [`Model::OpenAi`].
        session_redact: Arc<RedactionTable>,
        /// Same effective outbound-provider redaction table as [`Model::OpenAi`].
        redact: Arc<RedactionTable>,
    },
    /// Native Anthropic Messages endpoint (`api.anthropic.com`). Routed
    /// here only when the resolved base URL host is `api.anthropic.com`
    /// (see [`is_anthropic_native`]); Claude served by any other host
    /// stays on [`Model::OpenAi`]. The stored `model` already has rig's
    /// per-block prompt caching enabled (5-min `with_prompt_caching()` or,
    /// on the 1h opt-in, top-level `with_automatic_caching_1h()`) — see
    /// [`build_anthropic_model`]. It's `Clone`, so the per-attempt closure
    /// builds a fresh caching-enabled agent each turn, which re-applies the
    /// last-message cache marker over the grown history.
    Anthropic {
        model: AnthropicCompletionModel,
        model_id: String,
        /// The configured provider id this model was built from. Same role as
        /// on [`Model::OpenAi`] — exact per-`(provider, model)` backup
        /// resolution (implementation note).
        provider_id: String,
        /// Explicit output limit resolved from catalog metadata, a model
        /// override, or a provider default. Native Anthropic rejects requests
        /// without this field, so construction fails before this can be absent.
        max_tokens: u64,
        /// Resolved base URL, kept for the retry TCP probe (the rig
        /// `CompletionModel` doesn't expose its client's base URL).
        base_url: String,
        /// Resolved inference-stream timeouts (TTFT + idle). Same role as
        /// on [`Model::OpenAi`].
        timeout: crate::config::providers::TimeoutConfig,
        /// Same backup-gated stream-timeout behavior as [`Model::OpenAi`].
        hard_timeout_on_stall: bool,
        /// Same trusted marker as [`Model::OpenAi`].
        trusted: bool,
        /// Same routing-audit locality metadata as [`Model::OpenAi`].
        location: Option<ModelLocation>,
        /// Same routing-audit quality rank metadata as [`Model::OpenAi`].
        quality_rank: i64,
        /// Same routing-audit cost rank metadata as [`Model::OpenAi`].
        cost_rank: i64,
        /// Same routing-audit subagent availability metadata as [`Model::OpenAi`].
        subagent_invokable: bool,
        /// Same routing-audit delegation permission metadata as [`Model::OpenAi`].
        can_delegate: bool,
        /// Same live trusted-only flag as [`Model::OpenAi`].
        trusted_only: Arc<AtomicBool>,
        /// Same daemon graceful-shutdown gate as [`Model::OpenAi`].
        gate: crate::daemon::shutdown::ShutdownSignal,
        /// Same session redaction table as [`Model::OpenAi`].
        session_redact: Arc<RedactionTable>,
        /// Same effective outbound-provider redaction table as [`Model::OpenAi`].
        redact: Arc<RedactionTable>,
    },
}

impl Model {
    /// The shared inference-dispatch gate for this model. The single seam
    /// both [`Self::complete_captured`] and [`Self::text_completion`]
    /// consult before any provider round-trip.
    fn gate(&self) -> &crate::daemon::shutdown::ShutdownSignal {
        match self {
            Model::OpenAi { gate, .. } => gate,
            Model::ChatGpt { gate, .. } => gate,
            Model::Anthropic { gate, .. } => gate,
        }
    }

    /// Whether this resolved provider/model is trusted by provider config.
    pub fn is_trusted(&self) -> bool {
        match self {
            Model::OpenAi { trusted, .. }
            | Model::ChatGpt { trusted, .. }
            | Model::Anthropic { trusted, .. } => *trusted,
        }
    }

    pub fn routing_metadata_json(&self, requested_selector: Option<&str>) -> serde_json::Value {
        self.routing_metadata_json_with_fallback_decision(requested_selector, "none")
    }

    pub fn routing_metadata_json_with_fallback_decision(
        &self,
        requested_selector: Option<&str>,
        fallback_decision: &str,
    ) -> serde_json::Value {
        let trust = if self.is_trusted() {
            "trusted"
        } else {
            "untrusted"
        };
        let location = self.routing_location().map(|location| match location {
            ModelLocation::Local => "local",
            ModelLocation::Remote => "remote",
            ModelLocation::PrivateRemote => "private_remote",
        });
        serde_json::json!({
            "requested_selector": requested_selector.unwrap_or("active"),
            "resolved_provider": self.provider_id(),
            "resolved_model": self.model_id_ref(),
            "trust": trust,
            "trusted": self.is_trusted(),
            "location": location,
            "quality_rank": self.quality_rank(),
            "cost_rank": self.cost_rank(),
            "optimization_mode": "exact",
            "fallback_decision": fallback_decision,
            "matched_capabilities": [],
            "subagent_invokable": self.subagent_invokable(),
            "can_delegate": self.can_delegate(),
            "trusted_only": self.trusted_only_enabled(),
        })
    }

    fn routing_location(&self) -> Option<ModelLocation> {
        match self {
            Model::OpenAi { location, .. }
            | Model::ChatGpt { location, .. }
            | Model::Anthropic { location, .. } => *location,
        }
    }

    fn quality_rank(&self) -> i64 {
        match self {
            Model::OpenAi { quality_rank, .. }
            | Model::ChatGpt { quality_rank, .. }
            | Model::Anthropic { quality_rank, .. } => *quality_rank,
        }
    }

    fn cost_rank(&self) -> i64 {
        match self {
            Model::OpenAi { cost_rank, .. }
            | Model::ChatGpt { cost_rank, .. }
            | Model::Anthropic { cost_rank, .. } => *cost_rank,
        }
    }

    fn subagent_invokable(&self) -> bool {
        match self {
            Model::OpenAi {
                subagent_invokable, ..
            }
            | Model::ChatGpt {
                subagent_invokable, ..
            }
            | Model::Anthropic {
                subagent_invokable, ..
            } => *subagent_invokable,
        }
    }

    pub(crate) fn can_delegate(&self) -> bool {
        match self {
            Model::OpenAi { can_delegate, .. }
            | Model::ChatGpt { can_delegate, .. }
            | Model::Anthropic { can_delegate, .. } => *can_delegate,
        }
    }

    /// Whether the live session trusted-only flag is currently active.
    pub fn trusted_only_enabled(&self) -> bool {
        self.trusted_only_flag().load(Ordering::Relaxed)
    }

    /// Clone the live trusted-only flag carried by this model.
    pub fn trusted_only_flag(&self) -> Arc<AtomicBool> {
        match self {
            Model::OpenAi { trusted_only, .. }
            | Model::ChatGpt { trusted_only, .. }
            | Model::Anthropic { trusted_only, .. } => trusted_only.clone(),
        }
    }

    fn trusted_only_violation(provider_id: &str, model_id: &str) -> anyhow::Error {
        outbound_guard::trusted_only_violation(provider_id, model_id)
    }

    fn outbound_guard(&self) -> OutboundGuard {
        OutboundGuard::new(
            self.provider_id(),
            self.model_id_ref(),
            self.trusted_only_flag(),
            self.is_trusted(),
            self.redact_table(),
        )
    }

    fn ensure_trusted_only_build_allowed(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        trusted_only: &Arc<AtomicBool>,
    ) -> Result<bool> {
        let trusted = cfg.resolve_trust(provider_id, model_id).is_trusted();
        if trusted_only.load(Ordering::Relaxed) && !trusted {
            return Err(Self::trusted_only_violation(provider_id, model_id));
        }
        Ok(trusted)
    }

    /// The effective outbound-provider redaction table. A disabled session
    /// config, `/toggle-redaction`, or a trusted model resolves to a no-op
    /// table here, so the chokepoint still runs and simply passes text through
    /// for provider dispatch.
    fn redact(&self) -> &RedactionTable {
        match self {
            Model::OpenAi { redact, .. } => redact,
            Model::ChatGpt { redact, .. } => redact,
            Model::Anthropic { redact, .. } => redact,
        }
    }

    /// The resolved inference-stream timeouts (TTFT + idle) for this model
    /// (implementation note).
    fn timeout(&self) -> &crate::config::providers::TimeoutConfig {
        match self {
            Model::OpenAi { timeout, .. } => timeout,
            Model::ChatGpt { timeout, .. } => timeout,
            Model::Anthropic { timeout, .. } => timeout,
        }
    }

    /// Whether stream TTFT/idle threshold expiry should hard-abort this
    /// attempt so backup fallback can engage.
    fn hard_timeout_on_stall(&self) -> bool {
        match self {
            Model::OpenAi {
                hard_timeout_on_stall,
                ..
            }
            | Model::ChatGpt {
                hard_timeout_on_stall,
                ..
            }
            | Model::Anthropic {
                hard_timeout_on_stall,
                ..
            } => *hard_timeout_on_stall,
        }
    }

    /// A clone of this model's daemon graceful-shutdown gate. The backup model
    /// the per-turn fallback builds (implementation note)
    /// inherits the *same* gate as the primary so a drain that began mid-turn
    /// still refuses the fallback dispatch — the fallback must not slip past
    /// the drain authority just because it took a different build path.
    pub fn shutdown_gate(&self) -> crate::daemon::shutdown::ShutdownSignal {
        match self {
            Model::OpenAi { gate, .. } => gate.clone(),
            Model::ChatGpt { gate, .. } => gate.clone(),
            Model::Anthropic { gate, .. } => gate.clone(),
        }
    }

    /// A clone of this model's effective outbound-provider redaction table.
    #[allow(dead_code)]
    pub fn redact_table(&self) -> Arc<RedactionTable> {
        match self {
            Model::OpenAi { redact, .. } => redact.clone(),
            Model::ChatGpt { redact, .. } => redact.clone(),
            Model::Anthropic { redact, .. } => redact.clone(),
        }
    }

    /// A clone of the session redaction table before model-level redaction
    /// policy is applied. Backup and utility model builders use this value so
    /// different target models resolve their own trust settings.
    pub fn session_redact_table(&self) -> Arc<RedactionTable> {
        match self {
            Model::OpenAi { session_redact, .. } => session_redact.clone(),
            Model::ChatGpt { session_redact, .. } => session_redact.clone(),
            Model::Anthropic { session_redact, .. } => session_redact.clone(),
        }
    }

    pub fn effective_redact_table_for(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        session_table: Arc<RedactionTable>,
    ) -> Arc<RedactionTable> {
        if cfg.resolve_trust(provider_id, model_id).is_trusted() {
            Arc::new(RedactionTable::empty())
        } else {
            session_table
        }
    }

    /// Replace the redaction table carried by this model. The
    /// driver calls this at idle turn boundaries so the next provider request
    /// uses the freshly rebuilt table while any in-flight request keeps the
    /// table it started with. This legacy setter installs the same table as
    /// both the session and effective table.
    pub fn set_redact_table_for_config(
        &mut self,
        providers: &ProvidersConfig,
        table: Arc<RedactionTable>,
    ) {
        let effective = Self::effective_redact_table_for(
            providers,
            self.provider_id(),
            self.model_id_ref(),
            table.clone(),
        );
        match self {
            Model::OpenAi {
                session_redact,
                redact,
                ..
            }
            | Model::ChatGpt {
                session_redact,
                redact,
                ..
            }
            | Model::Anthropic {
                session_redact,
                redact,
                ..
            } => {
                *session_redact = table;
                *redact = effective;
            }
        }
    }

    /// The configured provider id this model was built from (a key in the
    /// `providers` map). The exact lookup key for the per-`(provider, model)`
    /// backup fallback (implementation note) — distinct from
    /// the coarse wire-flavor [`Self::provider_label`].
    pub fn provider_id(&self) -> &str {
        match self {
            Model::OpenAi { provider_id, .. } => provider_id,
            Model::ChatGpt { provider_id, .. } => provider_id,
            Model::Anthropic { provider_id, .. } => provider_id,
        }
    }

    fn needs_responses_tool_identity_normalization(&self, endpoint_recovery_enabled: bool) -> bool {
        match self {
            Model::OpenAi { client, .. } => {
                let endpoint = self.resolve_live_wire_api_for_base_url(client.base_url());
                matches!(endpoint, crate::config::providers::WireApi::Responses)
                    || (!self.is_live_wire_api_explicit() && endpoint_recovery_enabled)
            }
            Model::ChatGpt { .. } => true,
            Model::Anthropic { .. } => false,
        }
    }

    /// The model id this model was built for (e.g. `glm-4.6`). The second half
    /// of the backup-resolution key.
    pub fn model_id_ref(&self) -> &str {
        self.model_id()
    }

    pub fn is_anthropic_native_wire(&self) -> bool {
        matches!(self, Model::Anthropic { .. })
    }

    pub fn resolved_max_tokens(&self) -> Option<u64> {
        match self {
            Model::Anthropic { max_tokens, .. } => Some(*max_tokens),
            Model::OpenAi { .. } | Model::ChatGpt { .. } => None,
        }
    }

    pub fn utility_token_limit(&self) -> Option<u64> {
        match self {
            Model::OpenAi {
                utility_token_limit,
                ..
            }
            | Model::ChatGpt {
                utility_token_limit,
                ..
            } => *utility_token_limit,
            Model::Anthropic { max_tokens, .. } => Some(*max_tokens),
        }
    }

    pub fn utility_params_for(
        &self,
        site: UtilityCallSite,
        mut params: ModelParams,
    ) -> ModelParams {
        let cap = self
            .utility_token_limit()
            .map_or(UTILITY_MAX_TOKENS_CAP, |limit| {
                UTILITY_MAX_TOKENS_CAP.min(limit)
            });
        params.max_tokens = Some(
            params
                .max_tokens
                .map_or(cap, |requested| requested.min(cap)),
        );
        if site.pins_temperature_zero() {
            params.temperature = Some(0.0);
        }
        params
    }

    /// Resolve the active config's reasoning selection for this model using
    /// the model's concrete wire family, never its provider or model name.
    pub fn resolve_reasoning_params(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
    ) -> Option<serde_json::Value> {
        let active = providers.active_model.as_ref()?;
        if providers.has_reasoning_effort_capability(self.provider_id(), self.model_id_ref()) {
            let selected = active
                .reasoning_effort
                .as_ref()
                .filter(|_| {
                    active.provider == self.provider_id() && active.model == self.model_id_ref()
                })
                .map(|effort| effort.value.as_str());
            let wire = if self.is_anthropic_native_wire() {
                crate::config::providers::ReasoningEffortWire::AnthropicNative
            } else {
                crate::config::providers::ReasoningEffortWire::OpenAiCompatible
            };
            return match providers.resolve_reasoning_effort_params_for_wire(
                self.provider_id(),
                self.model_id_ref(),
                selected,
                wire,
                self.resolved_max_tokens(),
            ) {
                Ok(params) => params,
                Err(error) => {
                    tracing::warn!(
                        provider = self.provider_id(),
                        model = self.model_id_ref(),
                        %error,
                        "dropping invalid reasoning-effort request parameters"
                    );
                    None
                }
            };
        }
        if self.is_anthropic_native_wire() {
            if active.reasoning_effort.is_some() || active.thinking_mode.is_some() {
                tracing::warn!(
                    provider = self.provider_id(),
                    model = self.model_id_ref(),
                    "dropping unsupported legacy reasoning controls on native Anthropic wire"
                );
            }
            return None;
        }
        let mode = active
            .thinking_mode
            .filter(|_| {
                active.provider == self.provider_id() && active.model == self.model_id_ref()
            })
            .or_else(|| {
                providers.resolve_default_thinking_mode(self.provider_id(), self.model_id_ref())
            })?;
        providers.resolve_thinking_params(self.provider_id(), self.model_id_ref(), mode)
    }

    /// Provider wire API family used by diagnostics/export. This is not a
    /// routing decision; it reports the concrete endpoint family carried by
    /// the built model.
    pub fn wire_api_label(&self) -> &'static str {
        match self {
            Model::OpenAi { wire_api, .. } => match wire_api {
                crate::config::providers::WireApi::Auto => "auto",
                crate::config::providers::WireApi::Completions => "completions",
                crate::config::providers::WireApi::Responses => "responses",
            },
            Model::ChatGpt { .. } => "responses",
            Model::Anthropic { .. } => "messages",
        }
    }

    pub(crate) fn current_wire_api(&self) -> crate::config::providers::WireApi {
        match self {
            Model::OpenAi { client, .. } => {
                self.resolve_live_wire_api_for_base_url(client.base_url())
            }
            Model::ChatGpt { .. } => crate::config::providers::WireApi::Responses,
            Model::Anthropic { .. } => crate::config::providers::WireApi::Completions,
        }
    }

    /// The config file path this model self-heals its wire-API endpoint into
    /// (implementation note), if one was installed via
    /// [`Self::with_config_path`]. `None` on the native Anthropic arm (the
    /// selector doesn't apply) and on models built without a known cwd. Used to
    /// propagate the persist target onto a backup model so it self-heals too.
    pub fn config_path(&self) -> Option<&Path> {
        match self {
            Model::OpenAi { config_path, .. } => config_path.as_deref(),
            Model::ChatGpt { .. } => None,
            Model::Anthropic { .. } => None,
        }
    }

    pub(crate) fn refresh_wire_api_config(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
    ) {
        let Model::OpenAi {
            provider_id,
            model_id,
            live_wire_api,
            ..
        } = self
        else {
            return;
        };
        let mut state = live_wire_api
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.configured = providers.resolve_wire_api(provider_id, model_id);
        state.explicit = providers.is_wire_api_explicit(provider_id, model_id);
    }

    pub(crate) fn with_live_wire_api(mut self, donor: &Self) -> Self {
        let Model::OpenAi {
            live_wire_api: fresh_live_wire_api,
            ..
        } = &mut self
        else {
            return self;
        };
        let Model::OpenAi {
            live_wire_api: donor_live_wire_api,
            ..
        } = donor
        else {
            return self;
        };
        let (configured, explicit) = {
            let fresh_state = fresh_live_wire_api
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (fresh_state.configured, fresh_state.explicit)
        };
        {
            let mut donor_state = donor_live_wire_api
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            donor_state.configured = configured;
            donor_state.explicit = explicit;
        }
        *fresh_live_wire_api = donor_live_wire_api.clone();
        self
    }

    pub(crate) fn resolve_live_wire_api_for_base_url(
        &self,
        base_url: &str,
    ) -> crate::config::providers::WireApi {
        match self {
            Model::OpenAi {
                provider_id,
                model_id,
                wire_api,
                live_wire_api,
                ..
            } => {
                let state = live_wire_api
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.explicit && !state.configured.is_auto() {
                    return state.configured;
                }
                let normalized = normalize_probe_base_url(base_url);
                if let Some(endpoint) = state.session_confirmed.get(&normalized) {
                    return *endpoint;
                }
                drop(state);
                if let Some(learned) = learned_working_endpoint(provider_id, model_id, base_url) {
                    return learned;
                }
                if !wire_api.is_auto() {
                    *wire_api
                } else {
                    crate::config::providers::WireApi::detect_for_provider(provider_id, model_id)
                }
            }
            Model::ChatGpt { .. } => crate::config::providers::WireApi::Responses,
            Model::Anthropic { .. } => crate::config::providers::WireApi::Completions,
        }
    }

    fn is_live_wire_api_explicit(&self) -> bool {
        match self {
            Model::OpenAi { live_wire_api, .. } => {
                live_wire_api
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .explicit
            }
            Model::ChatGpt { .. } | Model::Anthropic { .. } => true,
        }
    }

    pub(crate) fn confirmed_wire_api_for_base_url(
        &self,
        base_url: &str,
    ) -> Option<crate::config::providers::WireApi> {
        let Model::OpenAi { live_wire_api, .. } = self else {
            return None;
        };
        live_wire_api
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .session_confirmed
            .get(&normalize_probe_base_url(base_url))
            .copied()
    }

    pub(crate) fn confirm_wire_api_for_base_url(
        &self,
        base_url: &str,
        endpoint: crate::config::providers::WireApi,
    ) {
        let Model::OpenAi { live_wire_api, .. } = self else {
            return;
        };
        if endpoint.is_auto() {
            return;
        }
        live_wire_api
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .session_confirmed
            .insert(normalize_probe_base_url(base_url), endpoint);
    }

    /// Install the daemon's shared shutdown gate, replacing the default
    /// never-draining one. Called by the registry when it builds a worker's
    /// model so the model dispatches through the daemon's central drain
    /// authority. Consuming-builder style so the registry can wrap the
    /// model in an `Arc` immediately after.
    pub fn with_shutdown_gate(mut self, signal: crate::daemon::shutdown::ShutdownSignal) -> Self {
        match &mut self {
            Model::OpenAi { gate, .. } => *gate = signal,
            Model::ChatGpt { gate, .. } => *gate = signal,
            Model::Anthropic { gate, .. } => *gate = signal,
        }
        self
    }

    /// Install the config file path used to self-heal the wire-API endpoint
    /// (implementation note). Set by production build
    /// sites that know the session cwd so a successful endpoint fallback pins
    /// the resolved `wire_api` back into config. A no-op on the native
    /// Anthropic arm (the selector doesn't apply there). Consuming-builder
    /// style to match [`Self::with_shutdown_gate`].
    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        if let Model::OpenAi { config_path, .. } = &mut self {
            *config_path = Some(path);
        }
        self
    }
}

#[cfg(test)]
mod tests;
