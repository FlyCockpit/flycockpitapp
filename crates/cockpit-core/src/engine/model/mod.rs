//! Provider-side completion model dispatch.
//!
//! Host-owned inference boundary (rig 0.42): Cockpit builds
//! [`rig::completion::CompletionRequest`] values via
//! `CompletionModel::completion_request` and streams or sends them. Rig
//! owns transport, SSE parsing, and message types; Cockpit owns the tool
//! loop, multi-agent driver, redaction, retry, and wire-API recovery.
//! There is no Rig `Agent` / `AgentRunner` on this path — tools are
//! advertised as `ToolDefinition`s on the request and executed by
//! Cockpit's `ToolBox`.
//!
//! `CompletionModel` in rig isn't object-safe (associated types +
//! `impl Trait` returns + `Self` in return position), so we can't hold a
//! `Box<dyn CompletionModel>`. The pattern upstream recommends is enum
//! dispatch — see rig's `examples/enum_dispatch.rs` and
//! `examples/manual_tool_calls`. Variants: `OpenAi` (every OpenAI-
//! compatible endpoint in the user's [`crate::providers`] templates —
//! including Claude reached via OpenRouter/Copilot/etc.), `ChatGpt`
//! (native ChatGPT/Codex Responses), and `Anthropic` (native
//! `api.anthropic.com`, which gets rig's provider-concrete per-block
//! prompt caching, prompt `prompt-caching-strategy.md`).
//!
//! Routing: a build site picks the wire solely from the resolved
//! `ProviderEntry.wire_api`. Provider ids, model names, and base URLs never
//! select a request wire.
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

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use futures::future::{BoxFuture, Shared};
use rig::{
    client::CompletionClient,
    message::{
        DocumentSourceKind, Message, Reasoning, ReasoningContent, ToolChoice, ToolResultContent,
        UserContent,
    },
    streaming::StreamedAssistantContent,
};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    config::providers::{ModelPolicyError, RedactedRendering, ResolvedSensitiveModelPolicy},
    engine::{agent::TurnEvent, retry},
};

pub(crate) type PreDrainFuture = Shared<BoxFuture<'static, std::result::Result<(), String>>>;

/// Renders a model request through the session redaction table for one
/// untrusted target. There is deliberately no raw variant: an untrusted
/// custody class has no raw-byte conversion, so the only way a configured
/// target ever sees raw bytes is a `Trusted` route's grant.
pub(crate) struct SessionRedactionRendering(Arc<RedactionTable>);

impl SessionRedactionRendering {
    /// Wrap the session table for one untrusted target. The table is taken in
    /// its *enforced* view: `redact.enabled = false` is an opt-out for trusted
    /// routes only and must not reach an untrusted rendering. The field is
    /// private so no caller can install a non-enforcing table.
    pub(crate) fn new(session_table: &Arc<RedactionTable>) -> Self {
        Self(RedactionTable::enforced_arc(session_table.clone()))
    }
}

impl RedactedRendering for SessionRedactionRendering {
    fn render_redacted(&self, _provider: &str, _model: &str, source: &str) -> String {
        self.0.scrub(source)
    }
}

mod build;
mod dispatch;
mod display_dispatch;
mod failure;
mod http_client;
mod outbound_guard;
pub(crate) mod redact;
pub(crate) mod rig_boundary;
mod wire;
pub(crate) mod wire_schema;

pub(crate) use display_dispatch::{
    DisplayAttemptSlot, DisplayClockFactory, assistant_display_complete_turn_event,
    finish_open_display_classifier,
};

#[allow(unused_imports)]
pub use build::EndpointRecoveryAdditionalParams;
#[allow(unused_imports)]
pub use build::ModelParams;
#[allow(unused_imports)]
pub use build::{
    UTILITY_BACKGROUND_TIMEOUT, UTILITY_MAX_TOKENS_CAP, UTILITY_TURN_BLOCKING_TIMEOUT,
    UtilityBudgetClass, UtilityCallSite,
};
#[allow(unused_imports)]
pub use dispatch::TandemOutcome;
#[cfg(feature = "test-support")]
pub(crate) use dispatch::drain_items_for_response_performance_e2e;
#[allow(unused_imports)]
pub(crate) use dispatch::terminal_inference_failure;
#[allow(unused_imports)]
pub use failure::{
    InferenceCancelled, InferenceErrorClass, InferenceFailure, InferenceGated, InferencePhase,
    InferenceTiming, LateUserSteerDeferred, PROVIDER_DETAIL_OMITTED, ProviderRecoverySignal,
    SafeProviderDetail, as_inference_failure, auth_failure_kind, cancellation_phase,
    failure_engages_backup, is_cancelled, is_gated, is_late_user_steer_deferred,
    safe_completion_error_detail, safe_provider_detail,
};
pub(crate) use failure::{log_utility_model_failure, safe_inference_error_detail};
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
    pub single_handoff: bool,
}

/// The explicit provider-cache boundary for an agent completion.
///
/// `stable_prefix` is constructed when an agent is spawned and must remain
/// byte-identical until that agent is rebuilt or re-postured for model
/// failover. `volatile_messages` is the complete per-turn history, including
/// host-injected time, guidance, skill-catalog, and nudge messages, plus
/// tool-result history such as explicit knowledge searches.
/// Keeping the pair at the request boundary prevents a future injector from
/// accidentally folding volatile state back into the provider preamble.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AgentPromptParts<'a> {
    pub(crate) stable_prefix: &'a str,
    pub(crate) volatile_messages: &'a [Message],
}

impl<'a> AgentPromptParts<'a> {
    pub(crate) fn new(stable_prefix: &'a str, volatile_messages: &'a [Message]) -> Self {
        Self {
            stable_prefix,
            volatile_messages,
        }
    }
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

use crate::{
    config::providers::{
        ActiveModelRef, CapabilityStatus, ClientSideToolsCapability, ModelLocation, ProviderEntry,
        ProvidersConfig,
    },
    db::session_log::InferenceRequestStatus,
    engine::message::{AssistantContent, ToolDefinition},
    providers::models_fetch,
    redact::RedactionTable,
    tokens::TokenUsage,
};

/// The aggregated result of one streaming completion attempt: the
/// `message_id`, the assistant content, and the (optional) provider-
/// reported usage. Shared by the provider-flavor arms of
/// [`Model::complete_captured`] and the generic [`drain_completion_stream`]
/// helper they both call.
type CompleteOut = (Option<String>, Vec<AssistantContent>, Option<TokenUsage>);

tokio::task_local! {
    static NATIVE_COMPUTER_ITEMS: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>;
    static NATIVE_COMPUTER_CONTINUATIONS: std::sync::Mutex<NativeComputerContinuationState>;
}

#[derive(Default)]
struct NativeComputerContinuationState {
    pending: Option<Vec<serde_json::Value>>,
    /// Latched immediately before a request containing the continuation is
    /// handed to the HTTP transport. It deliberately survives clearing the
    /// pending batch so every retry/fallback layer can fail terminally on an
    /// ambiguous send result.
    dispatched: bool,
}

/// Scope a native-computer live turn: continuation injection **and** wire
/// advertisement. Compact, shrink, and warm-resolver completions must not
/// enter this scope — `geometry.is_some()` on cloned [`ModelParams`] is not a
/// sufficient advertisement gate without it.
pub(crate) async fn with_native_computer_continuations<F>(
    continuations: Vec<serde_json::Value>,
    future: F,
) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    let fut: std::pin::Pin<Box<dyn std::future::Future<Output = F::Output> + Send + '_>> =
        Box::pin(future);
    NATIVE_COMPUTER_CONTINUATIONS
        .scope(
            std::sync::Mutex::new(NativeComputerContinuationState {
                pending: Some(continuations),
                dispatched: false,
            }),
            fut,
        )
        .await
}

/// Whether the current task is assembling a coordinator-backed live-loop
/// request ([`with_native_computer_continuations`]). Native `computer` /
/// `computer_call` may be declared on the wire only when this is true **and**
/// opened geometry is present on the request-local params.
pub(crate) fn native_computer_live_turn_active() -> bool {
    NATIVE_COMPUTER_CONTINUATIONS
        .try_with(|_| true)
        .unwrap_or(false)
}

#[cfg(test)]
pub(crate) fn with_native_computer_live_turn_sync<R>(f: impl FnOnce() -> R) -> R {
    NATIVE_COMPUTER_CONTINUATIONS.sync_scope(
        std::sync::Mutex::new(NativeComputerContinuationState::default()),
        f,
    )
}

#[derive(Clone, Copy)]
pub(super) enum NativeComputerContinuationWire {
    OpenAiResponses,
    AnthropicMessages,
}

/// Consume the transient continuation batch for its one permitted provider
/// request. A batch is deliberately not cloned: retries and backup-model
/// attempts must never receive another provider's call/output IDs or pixels.
pub(super) fn take_native_computer_continuations(
    wire: NativeComputerContinuationWire,
) -> Vec<serde_json::Value> {
    NATIVE_COMPUTER_CONTINUATIONS
        .try_with(|slot| {
            let Ok(mut slot) = slot.lock() else {
                return Vec::new();
            };
            let compatible = slot.pending.as_ref().is_some_and(|items| match wire {
                NativeComputerContinuationWire::OpenAiResponses => {
                    !items.is_empty()
                        && items.iter().all(|item| {
                            matches!(
                                item.get("type").and_then(serde_json::Value::as_str),
                                Some("computer_call" | "computer_call_output")
                            )
                        })
                }
                NativeComputerContinuationWire::AnthropicMessages => {
                    let tool_use_ids = items
                        .iter()
                        .filter(|item| {
                            item.get("type").and_then(serde_json::Value::as_str) == Some("tool_use")
                        })
                        .filter_map(|item| item.get("id").and_then(serde_json::Value::as_str))
                        .collect::<Vec<_>>();
                    let tool_results = items
                        .iter()
                        .filter(|item| {
                            item.get("type").and_then(serde_json::Value::as_str)
                                == Some("tool_result")
                        })
                        .collect::<Vec<_>>();
                    !tool_use_ids.is_empty()
                        && !tool_results.is_empty()
                        && items.iter().all(|item| {
                            matches!(
                                item.get("type").and_then(serde_json::Value::as_str),
                                Some("tool_use" | "tool_result")
                            )
                        })
                        && tool_results.iter().all(|item| {
                            item.get("tool_use_id")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|id| tool_use_ids.contains(&id))
                        })
                }
            });
            if compatible {
                let items = slot.pending.take().unwrap_or_default();
                if !items.is_empty() {
                    slot.dispatched = true;
                }
                items
            } else {
                Vec::new()
            }
        })
        .unwrap_or_default()
}

/// Abandon an unconsumed native continuation before any retry/fallback can
/// cross the provider boundary with stale provider-specific state.
pub(crate) fn clear_native_computer_continuations() {
    let _ = NATIVE_COMPUTER_CONTINUATIONS.try_with(|slot| {
        if let Ok(mut slot) = slot.lock() {
            slot.pending = None;
        }
    });
}

/// Whether this logical provider turn has handed off a request containing a
/// native computer continuation. Any later error is terminal because the
/// provider's acceptance state is unknowable and the input action must never
/// be followed by a retry/fallback that lacks its matching result.
pub(crate) fn native_computer_continuation_was_dispatched() -> bool {
    NATIVE_COMPUTER_CONTINUATIONS
        .try_with(|slot| slot.lock().is_ok_and(|slot| slot.dispatched))
        .unwrap_or(false)
}

pub(crate) async fn capture_native_computer_items<F>(
    sink: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    future: F,
) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    let fut: std::pin::Pin<Box<dyn std::future::Future<Output = F::Output> + Send + '_>> =
        Box::pin(future);
    NATIVE_COMPUTER_ITEMS.scope(sink, fut).await
}

pub(crate) fn retain_native_computer_item(item: serde_json::Value) {
    let _ = NATIVE_COMPUTER_ITEMS.try_with(|sink| {
        if let Ok(mut items) = sink.lock() {
            let item_type = item.get("type").and_then(serde_json::Value::as_str);
            let item_id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(serde_json::Value::as_str);
            let duplicate = items.iter().any(|existing| {
                let existing_type = existing.get("type").and_then(serde_json::Value::as_str);
                let existing_id = existing
                    .get("call_id")
                    .or_else(|| existing.get("id"))
                    .and_then(serde_json::Value::as_str);
                item_type == existing_type
                    && match (item_id, existing_id) {
                        (Some(item_id), Some(existing_id)) => item_id == existing_id,
                        (None, None) => existing == &item,
                        _ => false,
                    }
            });
            if !duplicate {
                items.push(item);
            }
        }
    });
}

fn native_computer_item_is_addressable(item: &serde_json::Value) -> bool {
    item.get("call_id")
        .or_else(|| item.get("id"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| !id.is_empty())
}

/// Whether the current provider turn retained at least one native computer
/// item that can actually be addressed on the wire. An OpenAI `computer_call`
/// / Anthropic `tool_use` without `call_id`/`id` is still captured for
/// extraction, but it cannot produce a `computer_call_output` / `tool_result`
/// continuation — so it must not trigger `TurnOutcome::Continue`.
pub(crate) fn has_retained_native_computer_items() -> bool {
    NATIVE_COMPUTER_ITEMS
        .try_with(|sink| {
            sink.lock()
                .is_ok_and(|items| items.iter().any(native_computer_item_is_addressable))
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct LiveWireApiState {
    explicit: bool,
    session_confirmed: HashMap<String, crate::config::providers::WireApi>,
}

impl LiveWireApiState {
    fn new(explicit: bool) -> Self {
        Self {
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
        /// Command-credential generation that authenticated this model's
        /// outbound requests. Retained so a 401/403 can be bound to the
        /// credential actually sent rather than whatever is cached later.
        #[cfg(not(test))]
        command_credential_generation: Option<u64>,
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
        /// Per-session endpoint-recovery state. The concrete `wire_api` stays
        /// immutable for this model instance; a config change takes effect by
        /// rebuilding at the turn boundary, including across `Model` variants.
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
    /// Responses endpoint. The same request serializer serves generic
    /// Responses providers and ChatGPT/Codex; Codex-only headers remain bound
    /// to the resolved Codex credential path.
    ChatGpt {
        model: ChatGptResponsesModel,
        model_id: String,
        /// The configured provider id this model was built from.
        provider_id: String,
        #[cfg(not(test))]
        command_credential_generation: Option<u64>,
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
        /// Same daemon graceful-shutdown gate as [`Model::OpenAi`].
        gate: crate::daemon::shutdown::ShutdownSignal,
        /// Same session redaction table as [`Model::OpenAi`].
        session_redact: Arc<RedactionTable>,
        /// Same effective outbound-provider redaction table as [`Model::OpenAi`].
        redact: Arc<RedactionTable>,
    },
    /// Native Anthropic Messages endpoint. Routed here only by
    /// `wire_api = anthropic`. The stored `model` already has rig's
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
        #[cfg(not(test))]
        command_credential_generation: Option<u64>,
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

    fn outbound_guard(&self) -> OutboundGuard {
        OutboundGuard::new(self.redact_table())
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

    /// Scrub diagnostic text using this model's resolved custody policy
    /// without exposing the underlying redaction table.
    pub(crate) fn scrub_diagnostic(&self, text: &str) -> String {
        self.redact().scrub(text)
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

    /// Route a configured target's custody before building or re-tabling a
    /// model for it.
    ///
    /// This is the one call that turns a `(provider, model)` pair into a
    /// custody decision on the model-construction path. It goes through the
    /// typed request API, so the decision arrives as a
    /// [`ResolvedSensitiveModelPolicy`] — a value that either carries a
    /// [`TrustedCustodyGrant`] or does not. There is no boolean to pass around
    /// and no string-keyed trust lookup on this path to reach instead.
    pub fn configured_custody_route(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        session_table: &Arc<RedactionTable>,
    ) -> std::result::Result<ResolvedSensitiveModelPolicy, ModelPolicyError> {
        cfg.route_configured_model_custody(
            provider_id,
            model_id,
            // Custody never consults harness posture; this path has no
            // posture to report.
            Arc::new(SessionRedactionRendering::new(session_table)),
        )
    }

    /// The redaction table a model built for `(provider_id, model_id)` must
    /// carry, given the custody `route` already resolved for it.
    ///
    /// Raw custody — the empty table — is released **only** by a
    /// [`TrustedCustodyGrant`] minted for this exact `(provider, model)`.
    /// A route resolved under untrusted custody carries no grant, and a grant
    /// minted for some other target does not authorize this one, so both fall
    /// closed to the session table. Nothing here consults trust by name, so a
    /// caller that never routed custody cannot obtain the raw table at all.
    ///
    /// The untrusted branch takes the session table's *enforced* view, so the
    /// config-level opt-out `redact.enabled = false` cannot reach this sink.
    /// That opt-out is honored for trusted routes only: model trust is the
    /// single control over what leaves the machine raw, and a route without a
    /// grant is always scrubbed against the real table.
    pub fn effective_redact_table_for(
        route: &ResolvedSensitiveModelPolicy,
        provider_id: &str,
        model_id: &str,
        session_table: Arc<RedactionTable>,
    ) -> Arc<RedactionTable> {
        let raw_released = route
            .trusted_custody_grant()
            .is_some_and(|grant| grant.provider() == provider_id && grant.model() == model_id);
        if raw_released {
            Arc::new(RedactionTable::empty())
        } else {
            RedactionTable::enforced_arc(session_table)
        }
    }

    /// The redaction table for a configured target, falling closed when custody
    /// cannot be routed for it (unknown provider, or a payload/custody
    /// disagreement). An unroutable target never gets raw bytes.
    pub fn effective_redact_table_for_configured(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        session_table: Arc<RedactionTable>,
    ) -> Arc<RedactionTable> {
        match Self::configured_custody_route(cfg, provider_id, model_id, &session_table) {
            Ok(route) => {
                Self::effective_redact_table_for(&route, provider_id, model_id, session_table)
            }
            // No custody route means no grant, so this target is treated as
            // untrusted — which means the enforced table, not the session
            // table as configured. Returning it unenforced would let
            // `redact.enabled = false` send raw bytes to precisely the targets
            // we could not classify.
            Err(_) => RedactionTable::enforced_arc(session_table),
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
        let effective = Self::effective_redact_table_for_configured(
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

    /// The command credential generation sent by this model, if command
    /// authentication constructed it. This is deliberately model-owned:
    /// rejections can arrive after another request has refreshed the shared
    /// credential store.
    #[cfg(not(test))]
    pub(crate) fn command_credential_generation(&self) -> Option<u64> {
        match self {
            Model::OpenAi {
                command_credential_generation,
                ..
            }
            | Model::ChatGpt {
                command_credential_generation,
                ..
            }
            | Model::Anthropic {
                command_credential_generation,
                ..
            } => *command_credential_generation,
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
        // Utility completions never own a coordinator or a live-loop
        // injection path. Drop inherited opened geometry so compact-adjacent
        // warm resolvers cannot re-advertise `computer` / `computer_call`.
        params.detach_inherited_native_computer();
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
        self.resolve_reasoning_params_for_endpoint(providers, self.current_wire_api())
    }

    /// Resolve the selected reasoning control for a concrete endpoint. The
    /// endpoint-recovery retry uses this for the alternate route, so catalog
    /// mappings never leak across wire APIs.
    pub fn resolve_reasoning_params_for_endpoint(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
        endpoint: crate::config::providers::WireApi,
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
            let endpoint = (!self.is_anthropic_native_wire()).then_some(endpoint);
            return match providers.resolve_reasoning_effort_params_for_openai_endpoint(
                self.provider_id(),
                self.model_id_ref(),
                selected,
                wire,
                endpoint,
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

    /// Parameters to use if OpenAI-compatible endpoint recovery retries the
    /// opposite route. Native providers never perform that recovery.
    pub fn endpoint_recovery_reasoning_params(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
    ) -> Option<EndpointRecoveryAdditionalParams> {
        matches!(self, Model::OpenAi { .. }).then(|| EndpointRecoveryAdditionalParams {
            primary_wire_api: self.current_wire_api(),
            alternate: self.resolve_reasoning_params_for_endpoint(
                providers,
                self.current_wire_api().opposite(),
            ),
        })
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
                crate::config::providers::WireApi::Anthropic => "anthropic",
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
            Model::Anthropic { .. } => crate::config::providers::WireApi::Anthropic,
        }
    }

    /// Whether this model's currently selected provider protocol can carry the
    /// configured native-computer contract. In particular, OpenAI-compatible
    /// models support native computer use only on Responses; an endpoint that
    /// is configured, confirmed, or recovered to Chat Completions must not
    /// open or retain a coordinator.
    pub(crate) fn supports_native_computer_contract(
        &self,
        contract: crate::computer::ComputerToolContract,
    ) -> bool {
        match (self, contract) {
            (Model::OpenAi { .. }, crate::computer::ComputerToolContract::OpenAiResponses) => {
                self.current_wire_api() == crate::config::providers::WireApi::Responses
            }
            (Model::ChatGpt { .. }, crate::computer::ComputerToolContract::OpenAiResponses) => true,
            (
                Model::Anthropic { .. },
                crate::computer::ComputerToolContract::Anthropic20251124
                | crate::computer::ComputerToolContract::Anthropic20250124,
            ) => true,
            _ => false,
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
        let explicit = {
            let fresh_state = fresh_live_wire_api
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            fresh_state.explicit
        };
        {
            let mut donor_state = donor_live_wire_api
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            donor_state.explicit = explicit;
        }
        *fresh_live_wire_api = donor_live_wire_api.clone();
        self
    }

    pub(crate) fn resolve_live_wire_api_for_base_url(
        &self,
        _base_url: &str,
    ) -> crate::config::providers::WireApi {
        match self {
            Model::OpenAi { wire_api, .. } => {
                if wire_api.is_auto() {
                    crate::config::providers::WireApi::Completions
                } else {
                    *wire_api
                }
            }
            Model::ChatGpt { .. } => crate::config::providers::WireApi::Responses,
            Model::Anthropic { .. } => crate::config::providers::WireApi::Anthropic,
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
