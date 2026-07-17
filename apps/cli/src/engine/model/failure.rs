use super::*;

/// Sentinel error returned by [`Model::complete_captured`] when the
/// in-flight inference was aborted by a user ctrl+c (a `CancelTurn`
/// request). Distinct from a provider/transport failure so the driver
/// can unwind the turn cleanly (back to idle) rather than logging it as
/// a real error. Downcast through the `anyhow` chain to detect it.
#[derive(Debug, thiserror::Error)]
#[error("inference cancelled by user")]
pub struct InferenceCancelled;

/// Returns `true` when `err`'s chain carries an [`InferenceCancelled`]
/// sentinel — i.e. the turn was aborted by the user, not a real failure.
pub fn is_cancelled(err: &anyhow::Error) -> bool {
    err.downcast_ref::<InferenceCancelled>().is_some()
}

/// Sentinel returned at the inference-dispatch chokepoint when the daemon
/// has begun draining (`daemon-graceful-drain-shutdown.md`): no *new*
/// provider request may go out once shutdown starts. In-flight calls that
/// already passed the gate run to completion; this only blocks calls that
/// would start after the drain began. Distinct from a transport failure so
/// the driver unwinds the turn cleanly rather than logging a real error.
#[derive(Debug, thiserror::Error)]
#[error("inference refused: daemon is shutting down")]
pub struct InferenceGated;

/// Returns `true` when `err`'s chain carries an [`InferenceGated`] sentinel
/// — i.e. the call was refused because the daemon began draining.
pub fn is_gated(err: &anyhow::Error) -> bool {
    err.downcast_ref::<InferenceGated>().is_some()
}

/// The furthest lifecycle phase a turn's inference reached before it
/// settled (implementation note).
/// Recorded on every failure event + the dispatch-time record so an export
/// answers "stalled before vs after dispatch / before vs after first token"
/// as a lookup, not an inference from missing UI text. Data/export only —
/// never enters model context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferencePhase {
    /// Pre-dispatch assembly (redaction, request build). The provider was
    /// never contacted.
    Prep,
    /// The streaming request was dispatched; no token has arrived yet.
    Dispatched,
    /// The first token arrived (TTFT satisfied); mid-stream.
    FirstToken,
    /// Tokens are actively streaming (at least one inter-token gap seen).
    Streaming,
}

impl InferencePhase {
    /// Stable string form for the session-DB event + export record.
    pub fn as_str(self) -> &'static str {
        match self {
            InferencePhase::Prep => "prep",
            InferencePhase::Dispatched => "dispatched",
            InferencePhase::FirstToken => "first_token",
            InferencePhase::Streaming => "streaming",
        }
    }

    /// Monotonic rank used to track the *furthest* phase reached across
    /// (possibly multiple) retry attempts via an [`AtomicU8`].
    pub(super) fn rank(self) -> u8 {
        match self {
            InferencePhase::Prep => 0,
            InferencePhase::Dispatched => 1,
            InferencePhase::FirstToken => 2,
            InferencePhase::Streaming => 3,
        }
    }

    /// Inverse of [`Self::rank`].
    pub(super) fn from_rank(rank: u8) -> Self {
        match rank {
            0 => InferencePhase::Prep,
            1 => InferencePhase::Dispatched,
            2 => InferencePhase::FirstToken,
            _ => InferencePhase::Streaming,
        }
    }
}

/// Advance the shared furthest-phase tracker to `phase` if it is further
/// along than the current value (never regresses — a retry that fails at
/// dispatch must not undo a prior attempt that reached `first_token`).
pub(super) fn bump_phase(tracker: &std::sync::atomic::AtomicU8, phase: InferencePhase) {
    tracker.fetch_max(phase.rank(), std::sync::atomic::Ordering::SeqCst);
}

/// Why a turn's inference failed
/// (implementation note). Recorded on
/// the failure event + the terminal dispatch-time record. Data/export only.
///
/// Note `cancelled` is **not** a variant here: a ctrl+c unwind keeps its
/// dedicated [`InferenceCancelled`] sentinel and never becomes an
/// [`InferenceFailure`], so it can't reach this taxonomy. The DB-side
/// `cancelled` *status* ([`crate::db::session_log::InferenceRequestStatus`])
/// is recorded directly on the cancel path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceErrorClass {
    /// No first token within the configured TTFT ceiling.
    TimeoutTtft,
    /// Inter-token gap exceeded the configured idle ceiling.
    TimeoutIdle,
    /// Connection / transport failure with no HTTP status.
    Network,
    /// Non-retryable HTTP response, carrying the status code.
    Http(u16),
}

impl InferenceErrorClass {
    /// Stable string form: `timeout_ttft` / `timeout_idle` / `network` /
    /// `http_<status>`.
    pub fn as_str(&self) -> String {
        match self {
            InferenceErrorClass::TimeoutTtft => "timeout_ttft".to_string(),
            InferenceErrorClass::TimeoutIdle => "timeout_idle".to_string(),
            InferenceErrorClass::Network => "network".to_string(),
            InferenceErrorClass::Http(status) => format!("http_{status}"),
        }
    }
}

/// A well-typed, terminal inference failure — the clean hard-fail seam a
/// future per-model-backup-fallback
/// (implementation note) intercepts *before* the
/// failure reaches the user. A TTFT / idle timeout produces one directly
/// (it never loops through the transient-retry path); a non-retryable
/// transport / HTTP failure is mapped into one after the retry layer gives
/// up. Carries everything the inline error + the failure event need:
/// provider/model, the phase reached, the error class, and elapsed-ms since
/// dispatch.
#[derive(Debug, Clone, thiserror::Error)]
#[error("inference failed ({class}) for {provider}/{model} after {elapsed_ms}ms at phase {phase}")]
pub struct InferenceFailure {
    pub provider: String,
    pub model: String,
    pub phase: String,
    pub class: String,
    pub elapsed_ms: u64,
    /// Human-readable underlying reason (the source error's message), shown
    /// in the inline error alongside provider/model. Empty for a pure
    /// timeout (the class + ceiling already say everything).
    pub detail: String,
}

/// Returns the [`InferenceFailure`] in `err`'s chain, if any — the seam the
/// per-model-backup-fallback path matches on to intercept before the user sees
/// it (implementation note).
pub fn as_inference_failure(err: &anyhow::Error) -> Option<&InferenceFailure> {
    err.downcast_ref::<InferenceFailure>()
}

/// Classify only failures for which the TUI can offer credential or
/// entitlement recovery. HTTP 429 remains a rate-limit error.
pub fn auth_failure_kind(
    failure: &InferenceFailure,
) -> Option<crate::daemon::proto::AuthFailureKind> {
    use crate::daemon::proto::AuthFailureKind;

    let detail = failure.detail.to_ascii_lowercase();
    if detail.contains("subscription auth expired")
        || detail.contains("oauth token expired")
        || detail.contains("oauth credential expired")
        || detail.contains("oauth token was revoked")
    {
        return Some(AuthFailureKind::OAuthExpired {
            provider: failure.provider.clone(),
        });
    }
    if failure.class == "missing_tool_entitlement" {
        let feature = failure
            .detail
            .split('`')
            .nth(1)
            .filter(|feature| !feature.trim().is_empty())
            .unwrap_or("client_side_tools")
            .to_string();
        return Some(AuthFailureKind::MissingEntitlement { feature });
    }
    if failure.class == "provider_not_configured" {
        return Some(AuthFailureKind::ProviderNotConfigured);
    }
    match failure
        .class
        .strip_prefix("http_")
        .and_then(|value| value.parse::<u16>().ok())
    {
        Some(status @ (401 | 403)) => Some(AuthFailureKind::CredentialsRejected { status }),
        _ => None,
    }
}

/// Whether a terminal [`InferenceFailure`] (identified by its stable `class`
/// string) engages the configured backup model
/// (implementation note).
///
/// The trigger set is: **TTFT/idle timeouts, connection errors, and
/// non-retryable 5xx** — failures a *different* model can plausibly answer.
/// Specifically:
///
/// - `timeout_ttft` / `timeout_idle` → **fall back** (the endpoint never
///   produced / stalled).
/// - `network` → **fall back** (connection/transport failure with no usable
///   HTTP status).
/// - `http_5xx` → **fall back** (non-retryable server fault). Note `429`/`503`
///   never reach this seam as a failure: the retry layer
///   ([`crate::engine::retry`]) treats them as retry-after/retryable and loops
///   on the *same* model (the right endpoint, just throttled), so a rate-limit
///   is retried first and only a *different* terminal class surfaces here.
/// - any other `http_4xx` (`400`/`401`/`403`/`404`…) → **hard-fail, no
///   fallback** — request/auth/config errors a different model won't fix.
///
/// Operates on the `class` string so the driver can decide from the typed
/// [`InferenceFailure`] without re-deriving the taxonomy.
pub fn failure_engages_backup(class: &str) -> bool {
    match class {
        "timeout_ttft"
        | "timeout_idle"
        | "network"
        | "missing_tool_entitlement"
        | "client_side_tools_unsupported" => true,
        other => other
            .strip_prefix("http_")
            .and_then(|s| s.parse::<u16>().ok())
            // 5xx → fall back; every 4xx (and anything else) hard-fails.
            .map(|status| (500..=599).contains(&status))
            .unwrap_or(false),
    }
}

/// Per-turn phase timings for a *successful* inference, in milliseconds from
/// dispatch (implementation note #5).
/// The dispatch instant is the zero point; `first_token_ms` is `None` when
/// the stream produced no chunk before finishing (a rare empty completion).
/// Recorded into the dispatch-time record's terminal payload so an export
/// answers "how long to first token / total" as a lookup. The failure path
/// carries its own elapsed-ms on [`InferenceFailure`].
#[derive(Debug, Clone, Copy, Default)]
pub struct InferenceTiming {
    /// Milliseconds from dispatch to the first streamed chunk, if any.
    pub first_token_ms: Option<u64>,
    /// Milliseconds from dispatch to stream completion.
    pub completed_ms: u64,
}

/// Sentinel embedded in a [`rig::completion::CompletionError`] carrying a
/// stream-timeout verdict so it crosses the retry boundary fail-fast (the
/// retry taxonomy classifies `RequestError` as `FailFast`). Distinct from
/// [`AttemptCancelled`] so `complete_captured` can map it to a
/// `timeout_ttft` / `timeout_idle` [`InferenceFailure`] rather than a
/// cancellation.
#[derive(Debug, thiserror::Error)]
#[error("inference stream timed out ({0})")]
struct StreamTimeout(&'static str);

/// Build the TTFT-timeout sentinel as a `CompletionError`.
pub(super) fn ttft_timeout() -> rig::completion::CompletionError {
    rig::completion::CompletionError::RequestError(Box::new(StreamTimeout("timeout_ttft")))
}

/// Build the idle-timeout sentinel as a `CompletionError`.
pub(super) fn idle_timeout() -> rig::completion::CompletionError {
    rig::completion::CompletionError::RequestError(Box::new(StreamTimeout("timeout_idle")))
}

/// Detect the [`StreamTimeout`] sentinel, returning its kind tag when present.
pub(super) fn stream_timeout_kind(err: &rig::completion::CompletionError) -> Option<&'static str> {
    if let rig::completion::CompletionError::RequestError(inner) = err {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(inner.as_ref());
        while let Some(e) = current {
            if let Some(st) = e.downcast_ref::<StreamTimeout>() {
                return Some(st.0);
            }
            current = e.source();
        }
    }
    None
}

/// Classify a terminal [`rig::completion::CompletionError`] into the
/// failure taxonomy recorded on the event + dispatch-time record
/// (implementation note). Our own
/// [`StreamTimeout`] sentinels map to `timeout_ttft` / `timeout_idle`; an
/// HTTP status maps to `http_<status>`; everything else on the transport
/// path is `network`. The cancellation sentinel is handled before this is
/// called, so it never produces `Cancelled` here (that class is reserved for
/// the dispatch-time record's cancel transition).
pub(super) fn classify_inference_failure(
    err: &rig::completion::CompletionError,
) -> InferenceErrorClass {
    if let Some(kind) = stream_timeout_kind(err) {
        return match kind {
            "timeout_ttft" => InferenceErrorClass::TimeoutTtft,
            _ => InferenceErrorClass::TimeoutIdle,
        };
    }
    if let Some(status) = http_status_of(err) {
        return InferenceErrorClass::Http(status);
    }
    InferenceErrorClass::Network
}

/// Extract the HTTP status code an error carries, if any — for the
/// `http_<status>` failure class. Mirrors the status surfaces the retry
/// taxonomy reads (`src/engine/retry.rs`): rig's status variants plus a
/// status-carrying inner `reqwest::Error`.
fn http_status_of(err: &rig::completion::CompletionError) -> Option<u16> {
    if let rig::completion::CompletionError::ProviderError(message) = err {
        // rig's streaming OpenAI-compatible path converts a non-success
        // response into `ProviderError` and preserves the concrete status in
        // this stable leading phrase. Keep the parse deliberately narrow so
        // digits from an arbitrary provider body cannot become a status.
        let digits = message
            .strip_prefix("Invalid status code ")?
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        return digits
            .parse::<u16>()
            .ok()
            .filter(|status| (100..=599).contains(status));
    }
    let rig::completion::CompletionError::HttpError(http_err) = err else {
        return None;
    };
    use rig::http_client::Error as H;
    match http_err {
        H::InvalidStatusCode(status) | H::InvalidStatusCodeWithMessage(status, _) => {
            Some(status.as_u16())
        }
        H::Instance(boxed) => {
            let mut current: Option<&(dyn std::error::Error + 'static)> = Some(boxed.as_ref());
            while let Some(e) = current {
                if let Some(re) = e.downcast_ref::<reqwest::Error>() {
                    return re.status().map(|s| s.as_u16());
                }
                current = e.source();
            }
            None
        }
        _ => None,
    }
}

/// The provider error `code` that signals a model is not served over the
/// endpoint that was tried — the narrow trigger for the bidirectional
/// endpoint-swap fallback (implementation note).
const UNSUPPORTED_API_CODE: &str = "unsupported_api_for_model";

/// `true` when `err` is the `unsupported_api_for_model` signal — an OpenAI-
/// compatible 400 whose JSON body carries `"code":"unsupported_api_for_model"`
/// (implementation note). rig surfaces this as the
/// first stream item: a [`CompletionError::ProviderError`] whose string is the
/// `to_string()` of the underlying `InvalidStatusCodeWithMessage(400, body)`,
/// so the body (with the `code`) is embedded in the message. We match on the
/// `code` substring — **not** merely the 400 status — so other 400s (bad
/// request, context length, auth) never trigger an endpoint retry. The
/// `HttpError(InvalidStatusCodeWithMessage(..))` shape is also matched
/// defensively in case a transport-layer path ever surfaces it directly.
fn is_unsupported_api_error(err: &rig::completion::CompletionError) -> bool {
    match err {
        rig::completion::CompletionError::ProviderError(msg) => msg.contains(UNSUPPORTED_API_CODE),
        rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(status, body),
        ) => status.as_u16() == 400 && body.contains(UNSUPPORTED_API_CODE),
        _ => false,
    }
}

pub(super) fn is_endpoint_mismatch_error(err: &rig::completion::CompletionError) -> bool {
    if is_unsupported_api_error(err) {
        return true;
    }
    match err {
        rig::completion::CompletionError::ProviderError(msg) => {
            let lower = msg.to_ascii_lowercase();
            lower.contains("method not allowed")
                || lower.contains("unknown route")
                || lower.contains("unknown path")
                || lower.contains("unknown endpoint")
                || lower.contains("no route")
                || lower.contains("no path")
                || lower.contains("route not found")
                || lower.contains("path not found")
                || lower.contains("endpoint not found")
        }
        rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(status, body),
        ) => {
            let code = status.as_u16();
            if code == 404 || code == 405 || (code == 400 && body.contains(UNSUPPORTED_API_CODE)) {
                return true;
            }
            let lower = body.to_ascii_lowercase();
            lower.contains("unknown route")
                || lower.contains("unknown path")
                || lower.contains("no route")
                || lower.contains("route not found")
        }
        rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCode(status),
        ) => matches!(status.as_u16(), 404 | 405),
        _ => false,
    }
}

/// Persist a self-healed wire-API endpoint back into config
/// (implementation note): pin `resolved` (a concrete
/// `completions`/`responses`, never `auto`) onto the `(provider_id, model_id)`
/// model entry, reusing the same read-modify-write `ConfigDoc` path that caches
/// the fetched `/models` list. Only the `wire_api` field is touched — every
/// other field on the entry is preserved. When the model isn't yet listed in
/// config (e.g. a manually-typed id never fetched) the entry is created so the
/// pin survives the next `/models` refresh
/// ([`crate::config::providers::merge_fetched_models`] carries it over).
/// Best-effort: a self-heal that can't be persisted still served the turn
/// correctly, so any IO error is logged, never propagated into the live turn.
pub(super) fn persist_wire_api(
    config_path: &Path,
    provider_id: &str,
    model_id: &str,
    resolved: crate::config::providers::WireApi,
) {
    use crate::config::providers::{ConfigDoc, ModelEntry};
    let mut doc = match ConfigDoc::load(config_path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "persist wire_api: loading config failed");
            return;
        }
    };
    let mut cfg = doc.providers();
    let Some(entry) = cfg.providers.get_mut(provider_id) else {
        // No such provider in config: nothing to pin to. (A model can only be
        // dispatched from a configured provider, so this is defensive.)
        return;
    };
    if let Some(model) = entry.models.iter_mut().find(|m| m.id == model_id) {
        if model.wire_api == resolved {
            return; // already pinned — no write.
        }
        model.wire_api = resolved;
    } else {
        entry.models.push(ModelEntry {
            id: model_id.to_string(),
            wire_api: resolved,
            // Mark manual so the pin survives a refetch as a standalone entry
            // even if the provider's `/models` never lists this id.
            manual: true,
            ..ModelEntry::default()
        });
    }
    if let Err(e) = doc.write(&cfg) {
        tracing::warn!(error = %e, "persist wire_api: writing config failed");
    }
}

/// Human-readable detail for the inline error. A pure timeout needs none
/// (the class + ceiling already say everything); a network / HTTP failure
/// carries the underlying message so the user sees *what* failed.
pub(super) fn failure_detail(
    err: &rig::completion::CompletionError,
    class: &InferenceErrorClass,
) -> String {
    match class {
        InferenceErrorClass::TimeoutTtft | InferenceErrorClass::TimeoutIdle => String::new(),
        _ => err.to_string(),
    }
}

pub(super) fn provider_rejected_xai_multi_agent_tools(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("client-side tools")
        && detail.contains("multi-agent")
        && detail.contains("beta access")
}

/// Sentinel embedded in a [`rig::completion::CompletionError`] when a
/// retry *attempt* is aborted by ctrl+c (as opposed to a transport
/// failure). It is wrapped in `RequestError`, which the retry taxonomy
/// classifies fail-fast, so [`retry::with_retry`] returns at once
/// instead of retrying; `complete_captured` then maps it to
/// [`InferenceCancelled`].
#[derive(Debug, thiserror::Error)]
#[error("inference attempt cancelled by user")]
struct AttemptCancelled;

/// Build the cancellation sentinel as a `CompletionError`.
pub(super) fn attempt_cancelled() -> rig::completion::CompletionError {
    rig::completion::CompletionError::RequestError(Box::new(AttemptCancelled))
}

/// Detect the [`AttemptCancelled`] sentinel in a `CompletionError`.
pub(super) fn is_attempt_cancelled(err: &rig::completion::CompletionError) -> bool {
    if let rig::completion::CompletionError::RequestError(inner) = err {
        // Walk the boxed error chain for the marker.
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(inner.as_ref());
        while let Some(e) = current {
            if e.downcast_ref::<AttemptCancelled>().is_some() {
                return true;
            }
            current = e.source();
        }
    }
    false
}
